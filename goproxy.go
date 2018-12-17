package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/bestmethod/go-logger"
	"github.com/gorilla/mux"
	"github.com/haisum/recaptcha"
	"github.com/leonelquinteros/gorand"
	"github.com/yookoala/gofast"
	"golang.org/x/crypto/acme/autocert"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/smtp"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

type config struct {
	BindAddress    string
	TlsEnabled     bool
	TlsBindAddress string
	Rule           []rule
	LogRequests    bool
	log            *Logger.Logger
}

type rule struct {
	Job                   string
	Domain                string
	Path                  string
	Regex                 bool
	RewriteHostHeader     string
	Target                string
	StatusCode            int
	AcceptSelfSigned      bool
	remote                *url.URL
	proxy                 *httputil.ReverseProxy
	r                     *mux.Router
	FastcgiAddress        string
	Form                  string
	FormTargetPath        string
	FormRules             form
	FormFile              string
	FormSubmittedVariable string
	ReCaptchaSecret       string
}

type form struct {
	Variable    []variable
	Destination []destination
}

type variable struct {
	PostField    string
	VariableName string
	Required     bool
	RegexMatch   string
	RegexError   string
}

type destination struct {
	Username string
	Password string
	AwsS3    string
	AwsSqs   string
	Host     string
	From     string
	To       string
}

func checkMatchPath(path string, confPath string, regex bool) (ret bool, err error) {
	if len(confPath) > 0 {
		if confPath[0] == '^' || regex == true {
			match, err := regexp.MatchString(confPath, path)
			if err != nil {
				err = errors.New(fmt.Sprintf("regex error: %s", err))
			}
			if match == true {
				ret = true
			}
		} else if strings.HasPrefix(path, confPath) || confPath == "" {
			ret = true
		}
	} else {
		ret = true
	}
	return
}

func (c *config) findHostOffset(host string, path string) int {
	h := strings.Split(host, ":")[0]
	for i := range c.Rule {
		if c.Rule[i].Domain[0] == '^' || c.Rule[i].Regex == true {
			match, err := regexp.MatchString(c.Rule[i].Domain, h)
			if err != nil {
				return -1
			}
			if match == true {
				found, err := checkMatchPath(path, c.Rule[i].Path, c.Rule[i].Regex)
				if err != nil {
					return -1
				}
				if found == true {
					return i
				}
			}
		} else if c.Rule[i].Domain == h {
			found, err := checkMatchPath(path, c.Rule[i].Path, c.Rule[i].Regex)
			if err != nil {
				return -1
			}
			if found == true {
				return i
			}
		}
	}
	return -1
}

func (c *config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyMatch := c.findHostOffset(r.Host, r.URL.Path)
	if proxyMatch != -1 {
		if c.Rule[proxyMatch].Job == "proxy" {
			if c.LogRequests == true {
				c.log.Info("Client=%s Host=%s Path=%s Mod=Proxy Target=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, c.Rule[proxyMatch].Target, proxyMatch)
			}
			handler := c.Rule[proxyMatch].r
			handler.ServeHTTP(w, r)
		} else if c.Rule[proxyMatch].Job == "serve" {
			if c.LogRequests == true {
				c.log.Info("Client=%s Host=%s Path=%s Mod=Serve Target=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, c.Rule[proxyMatch].Target, proxyMatch)
			}
			handler := c.Rule[proxyMatch].r
			handler.ServeHTTP(w, r)
		} else {
			if c.LogRequests == true {
				c.log.Info("Client=%s Host=%s Path=%s Mod=Redirect Target=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, c.Rule[proxyMatch].Target, proxyMatch)
			}
			http.Redirect(w, r, c.Rule[proxyMatch].Target, c.Rule[proxyMatch].StatusCode)
		}
	} else {
		if c.LogRequests == true {
			c.log.Info("Client=%s Host=%s Path=%s Mod=Forbidden StatusCode=403", r.RemoteAddr, r.Host, r.URL.Path)
		}
		http.Error(w, "Forbidden", 403)
	}
}

func main() {

	// init config
	var c config

	// setup logger
	c.log = new(Logger.Logger)
	err := c.log.Init("", "goproxy", Logger.LEVEL_DEBUG|Logger.LEVEL_INFO|Logger.LEVEL_WARN, Logger.LEVEL_CRITICAL|Logger.LEVEL_ERROR, Logger.LEVEL_NONE)
	if err != nil {
		fmt.Println("CRITICAL: Could not initialize logger: ", err)
		os.Exit(1)
	}

	// check os args
	if len(os.Args) != 2 {
		fmt.Println("Usage: %s {config file}", os.Args[0])
		os.Exit(1)
	}

	// check file existence for config file
	if _, err := os.Stat(os.Args[1]); os.IsNotExist(err) {
		c.log.Fatalf(2, "Config file does not exist: %s, err: %s", os.Args[1], err)
	}

	// load config
	if _, err := toml.DecodeFile(os.Args[1], &c); err != nil {
		c.log.Fatalf(3, "Cannot load config file, err: %s", err)
	}

	// start main
	c.main()
}

func (c *config) main() {
	var err error

	for i := range c.Rule {
		if len(c.Rule[i].FormTargetPath) > 0 {
			if c.Rule[i].FormTargetPath[0] == '/' && len(c.Rule[i].FormTargetPath) > 1 {
				c.Rule[i].FormTargetPath = c.Rule[i].FormTargetPath[1:]
			} else if c.Rule[i].FormTargetPath[0] == '/' {
				c.Rule[i].FormTargetPath = ""
			}
		}
		if c.Rule[i].Form != "" {
			if _, err := toml.DecodeFile(c.Rule[i].Form, &c.Rule[i].FormRules); err != nil {
				c.log.Fatalf(3, "Cannot load config file, err: %s", err)
			}
		}
		if c.Rule[i].Job == "proxy" {
			c.Rule[i].remote, err = url.Parse(c.Rule[i].Target)
			if err != nil {
				c.log.Fatalf(6, "Cannot create remote handle: %s", err)
			}
			c.Rule[i].proxy = httputil.NewSingleHostReverseProxy(c.Rule[i].remote)
			if c.Rule[i].AcceptSelfSigned == true {
				c.Rule[i].proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			}
			c.Rule[i].r = mux.NewRouter()
			if len(c.Rule[i].Path) == 0 {
				c.Rule[i].r.HandleFunc(fmt.Sprintf("/%s", "{rest:.*}"), c.handler(c.Rule[i].proxy))
			} else if len(c.Rule[i].Path) > 0 && c.Rule[i].Path[0] == '/' {
				c.Rule[i].r.HandleFunc(fmt.Sprintf("%s", c.Rule[i].Path), c.handler(c.Rule[i].proxy))
				c.Rule[i].r.HandleFunc(fmt.Sprintf("%s/%s", c.Rule[i].Path, "{rest:.*}"), c.handler(c.Rule[i].proxy))
			} else {
				c.Rule[i].r.HandleFunc(fmt.Sprintf("/%s", c.Rule[i].Path), c.handler(c.Rule[i].proxy))
				c.Rule[i].r.HandleFunc(fmt.Sprintf("/%s/%s", c.Rule[i].Path, "{rest:.*}"), c.handler(c.Rule[i].proxy))
			}
		} else if c.Rule[i].Job == "serve" && c.Rule[i].FastcgiAddress == "" {
			c.Rule[i].r = mux.NewRouter()
			if len(c.Rule[i].Path) == 0 {
				c.Rule[i].r.Handle(fmt.Sprintf("/%s", c.Rule[i].FormTargetPath), FormHandler(c.Rule[i].FormRules, c.Rule[i].FormFile, c.Rule[i].FormSubmittedVariable, c.Rule[i].ReCaptchaSecret))
				c.Rule[i].r.Handle(fmt.Sprintf("/%s", "{rest:.*}"), http.FileServer(http.Dir(c.Rule[i].Target)))
			} else if len(c.Rule[i].Path) > 0 && c.Rule[i].Path[0] == '/' {
				c.Rule[i].r.Handle(fmt.Sprintf("%s/%s", c.Rule[i].Path, c.Rule[i].FormTargetPath), FormHandler(c.Rule[i].FormRules, c.Rule[i].FormFile, c.Rule[i].FormSubmittedVariable, c.Rule[i].ReCaptchaSecret))
				c.Rule[i].r.Handle(c.Rule[i].Path, http.StripPrefix(c.Rule[i].Path, http.FileServer(http.Dir(c.Rule[i].Target))))
				c.Rule[i].r.Handle(fmt.Sprintf("%s/%s", c.Rule[i].Path, "{rest:.*}"), http.StripPrefix(c.Rule[i].Path, http.FileServer(http.Dir(c.Rule[i].Target))))
			} else {
				c.Rule[i].r.Handle(fmt.Sprintf("/%s/%s", c.Rule[i].Path, c.Rule[i].FormTargetPath), FormHandler(c.Rule[i].FormRules, c.Rule[i].FormFile, c.Rule[i].FormSubmittedVariable, c.Rule[i].ReCaptchaSecret))
				c.Rule[i].r.Handle(fmt.Sprintf("/%s", c.Rule[i].Path), http.StripPrefix(c.Rule[i].Path, http.FileServer(http.Dir(c.Rule[i].Target))))
				c.Rule[i].r.Handle(fmt.Sprintf("/%s/%s", c.Rule[i].Path, "{rest:.*}"), http.StripPrefix(c.Rule[i].Path, http.FileServer(http.Dir(c.Rule[i].Target))))
			}
		} else if c.Rule[i].Job == "serve" {
			c.Rule[i].r = mux.NewRouter()
			fca := strings.Split(c.Rule[i].FastcgiAddress, ":")
			connFactory := gofast.SimpleConnFactory(fca[0], strings.Join(fca[1:], ":"))
			fastcgiHandler := gofast.NewHandler(gofast.NewPHPFS(c.Rule[i].Target)(gofast.BasicSession), gofast.SimpleClientFactory(connFactory, 0))
			if len(c.Rule[i].Path) == 0 {
				c.Rule[i].r.Handle(fmt.Sprintf("/%s", "{rest:.*}"), FileServer(c.Rule[i].Target, fastcgiHandler))
			} else if len(c.Rule[i].Path) > 0 && c.Rule[i].Path[0] == '/' {
				c.Rule[i].r.Handle(c.Rule[i].Path, http.StripPrefix(c.Rule[i].Path, FileServer(c.Rule[i].Target, fastcgiHandler)))
				c.Rule[i].r.Handle(fmt.Sprintf("%s/%s", c.Rule[i].Path, "{rest:.*}"), http.StripPrefix(c.Rule[i].Path, FileServer(c.Rule[i].Target, fastcgiHandler)))
			} else {
				c.Rule[i].r.Handle(fmt.Sprintf("/%s", c.Rule[i].Path), http.StripPrefix(c.Rule[i].Path, FileServer(c.Rule[i].Target, fastcgiHandler)))
				c.Rule[i].r.Handle(fmt.Sprintf("/%s/%s", c.Rule[i].Path, "{rest:.*}"), http.StripPrefix(c.Rule[i].Path, FileServer(c.Rule[i].Target, fastcgiHandler)))
			}
		}
	}
	c.startListener()
}

func (c *config) startListener() {
	var err error
	if c.TlsEnabled == true {
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache("certs"),
		}

		server := &http.Server{
			Addr:    c.TlsBindAddress,
			Handler: c,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}
		c.log.Info("Starting webserver v1.4")
		go c.ListenServeWrapper(c.BindAddress, certManager.HTTPHandler(nil))
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 5)
		}
	} else {
		c.log.Info("Starting webserver v1.4")
		err = http.ListenAndServe(c.BindAddress, c)
		if err != nil {
			c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 4)
		}
	}
}

func (c *config) handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		loc := c.findHostOffset(r.Host, r.URL.Path)
		r.URL.Path = mux.Vars(r)["rest"]
		if c.Rule[loc].RewriteHostHeader != "" {
			r.Host = c.Rule[loc].RewriteHostHeader
		}
		p.ServeHTTP(w, r)
	}
}

func (c *config) ListenServeWrapper(addr string, handler http.Handler) {
	err := http.ListenAndServe(addr, handler)
	if err != nil {
		c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 4)
	}
}

func FormHandler(f form, file string, subvar string, recaptcha string) http.Handler {
	h := formHandler{f, file, subvar, recaptcha}
	return h
}

type formHandler struct {
	f      form
	file   string
	subvar string
	recaptcha string
}

func (f formHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := template.New("form")
	contents, err := ioutil.ReadFile(f.file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	t, err = t.Parse(string(contents))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	var content string
	m := make(map[string]interface{})
	if r.PostFormValue(f.subvar) != "" {
		for _, rule := range f.f.Variable {
			postField := r.PostFormValue(rule.PostField)
			m[rule.VariableName] = postField
			if rule.Required == true && len(postField) == 0 {
				m["fail"] = true
				m["reason"] = "Field `" + rule.PostField + "` cannot be empty"
			} else {
				if rule.RegexMatch != "" {
					re := regexp.MustCompile(rule.RegexMatch)
					if re.MatchString(postField) == false {
						m["fail"] = true
						m["reason"] = rule.RegexError
					}
				}
			}
			content = fmt.Sprintf("%s : %s\n",rule.PostField,postField)
		}
		if f.recaptcha != "" {
			rc := recaptcha.R{
				Secret: f.recaptcha,
			}
			if rc.Verify(*r) == false {
				m["fail"] = true
				m["reason"] = "Failed human verification captcha!"
			}
		}
		if m["fail"] == nil {
			for _, d := range f.f.Destination {
				if d.AwsS3 != "" {
					uuidb, _ := gorand.UUIDv4()
					uuid, _ := gorand.MarshalUUID(uuidb)
					as := strings.Split(d.AwsS3,";")
					sess := session.Must(session.NewSession(&aws.Config{
						Region: aws.String(as[0]),
						Credentials: credentials.NewStaticCredentials(d.Username,d.Password,""),
					}))
					uploader := s3manager.NewUploader(sess)

					f := strings.NewReader(content)

					_, err := uploader.Upload(&s3manager.UploadInput{
						Bucket: aws.String(strings.Join(as[1:],";")),
						Key:    aws.String(uuid),
						Body: f,
					})
					if err != nil {
						m["fail"] = true;
						m["reason"] = fmt.Sprintf("Failed to store message: %s",err.Error())
					} else {
						m["success"] = true;
					}
				}
				if d.AwsSqs != "" {
					as := strings.Split(d.AwsS3,";")
					sess := session.Must(session.NewSession(&aws.Config{
						Region: aws.String(as[0]),
						Credentials: credentials.NewStaticCredentials(d.Username,d.Password,""),
					}))
					svc := sqs.New(sess)
					res, err := svc.GetQueueUrl(&sqs.GetQueueUrlInput{QueueName:aws.String(strings.Join(as[1:],";"))})
					if err != nil {
						m["fail"] = true;
						m["reason"] = fmt.Sprintf("Failed to queue message: %s",err.Error())
					} else {
						_, err = svc.SendMessage(&sqs.SendMessageInput{MessageBody:aws.String(content),QueueUrl:res.QueueUrl})
						if err != nil {
							m["fail"] = true;
							m["reason"] = fmt.Sprintf("Failed to queue message: %s",err.Error())
						} else {
							m["success"] = true;
						}
					}
				}
				if d.Host != "" {
					from := d.From
					auth := smtp.PlainAuth(d.Username, d.Username, d.Password, d.Host)
					err := smtp.SendMail(
						d.Host, // server address
						auth, // authentication
						from, // sender's address
						[]string{d.To}, // recipients' address
						[]byte(content),                   // message body
					)
					if err != nil {
						m["fail"] = true;
						m["reason"] = fmt.Sprintf("Failed to send email: %s",err.Error())
					} else {
						m["success"] = true;
					}
				}
			}
		}
	}
	err = t.Execute(w, &m)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// FASTCGI-PHP HANDLERS

type fileHandler struct {
	root       string
	cgiHandler http.Handler
}

func FileServer(root string, handler http.Handler) http.Handler {
	return &fileHandler{root, handler}
}

func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	//fmt.Printf("ROOT: '%s' PATH: '%s' ",f.root,upath)
	if upath[len(upath)-1] == '/' {
		//fmt.Println("cgiHandler")
		f.cgiHandler.ServeHTTP(w, r)
		return
	}
	psplit := strings.Split(upath, "/")
	for _, nItem := range psplit {
		if strings.Contains(nItem, "?") {
			nItem = strings.Split(nItem, "?")[0]
		}
		if strings.HasSuffix(nItem, ".php") {
			//fmt.Println("cgiHandler")
			f.cgiHandler.ServeHTTP(w, r)
			return
		}
	}
	//fmt.Println("http.ServeFile")
	http.ServeFile(w, r, path.Join(f.root, path.Clean(upath)))
}
