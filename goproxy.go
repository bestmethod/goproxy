package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/bestmethod/go-logger"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
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
	Job               string
	Domain            string
	Path              string
	Regex             bool
	RewriteHostHeader string
	Target            string
	StatusCode        int
	AcceptSelfSigned  bool
	remote            *url.URL
	proxy             *httputil.ReverseProxy
	r                 *mux.Router
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
				c.log.Info("Client=%s Host=%s Path=%s Mod=Proxy Target=%s", r.RemoteAddr, r.Host, r.URL.Path, c.Rule[proxyMatch].Target)
			}
			handler := c.Rule[proxyMatch].r
			handler.ServeHTTP(w, r)
		} else {
			if c.LogRequests == true {
				c.log.Info("Client=%s Host=%s Path=%s Mod=Redirect Target=%s", r.RemoteAddr, r.Host, r.URL.Path, c.Rule[proxyMatch].Target)
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
	c.log.Init("", "goproxy", Logger.LEVEL_DEBUG|Logger.LEVEL_INFO|Logger.LEVEL_WARN, Logger.LEVEL_CRITICAL|Logger.LEVEL_ERROR, Logger.LEVEL_NONE)

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
			if len(c.Rule[i].Path) > 0 && c.Rule[i].Path[0] == '/' {
				c.Rule[i].r.HandleFunc(fmt.Sprintf("%s", c.Rule[i].Path), c.handler(c.Rule[i].proxy))
				c.Rule[i].r.HandleFunc(fmt.Sprintf("%s/%s", c.Rule[i].Path, "{rest:.*}"), c.handler(c.Rule[i].proxy))
			} else {
				c.Rule[i].r.HandleFunc(fmt.Sprintf("/%s", c.Rule[i].Path), c.handler(c.Rule[i].proxy))
				c.Rule[i].r.HandleFunc(fmt.Sprintf("/%s/%s", c.Rule[i].Path, "{rest:.*}"), c.handler(c.Rule[i].proxy))
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
		c.log.Info("Starting webserver v1.2")
		go c.ListenServeWrapper(c.BindAddress, certManager.HTTPHandler(nil))
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 5)
		}
	} else {
		c.log.Info("Starting webserver v1.2")
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
