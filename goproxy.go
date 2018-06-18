package main

import (
	"github.com/bestmethod/go-logger"
	"net/url"
	"net/http/httputil"
	"os"
	"fmt"
	"github.com/BurntSushi/toml"
	"net/http"
	"crypto/tls"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"
	"strings"
	"regexp"
)

type config struct {
	BindAddress string
	TlsEnabled bool
	TlsBindAddress string
	Rule []rule
	LogRequests bool
	log *Logger.Logger
}

type rule struct {
	Job string
	Domain string
	Regex bool
	Target string
	StatusCode int
	AcceptSelfSigned bool
	remote *url.URL
	proxy *httputil.ReverseProxy
	r *mux.Router
}

func (c *config) findHostOffset(host string) int {
	h := strings.Split(host,":")[0]
	for i := range c.Rule {
		if c.Rule[i].Domain[0] == '^' || c.Rule[i].Regex == true {
			match, err := regexp.MatchString(c.Rule[i].Domain, h)
			if err != nil {
				return -1
			}
			if match == true {
				return i
			}
		} else if c.Rule[i].Domain == h {
			return i
		}
	}
	return -1
}

func (c *config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyMatch := c.findHostOffset(r.Host)
	if proxyMatch != -1 {
		if c.LogRequests == true {
			c.log.Info("Client=%s Host=%s Path=%s Mod=Proxy Target=%s",r.RemoteAddr,r.Host,r.URL.Path,c.Rule[proxyMatch].Job)
		}
		if c.Rule[proxyMatch].Job == "proxy" {
			handler := c.Rule[proxyMatch].r
			handler.ServeHTTP(w, r)
		} else {
			http.Redirect(w, r, c.Rule[proxyMatch].Target, c.Rule[proxyMatch].StatusCode)
		}
	} else {
		c.log.Info("Client=%s Host=%s Path=%s Mod=Forbidden StatusCode=403",r.RemoteAddr,r.Host,r.URL.Path)
		http.Error(w, "Forbidden", 403)
	}
}

func main() {

	// init config
	var c config

	// setup logger
	c.log = new(Logger.Logger)
	c.log.Init("","goproxy",Logger.LEVEL_DEBUG|Logger.LEVEL_INFO|Logger.LEVEL_WARN,Logger.LEVEL_CRITICAL|Logger.LEVEL_ERROR,Logger.LEVEL_NONE)

	// check os args
	if len(os.Args) != 2 {
		fmt.Println("Usage: %s {config file}",os.Args[0])
		os.Exit(1)
	}

	// check file existence for config file
	if _, err := os.Stat(os.Args[1]); os.IsNotExist(err) {
		c.log.Fatalf(2,"Config file does not exist: %s, err: %s",os.Args[1],err)
	}

	// load config
	if _, err := toml.DecodeFile(os.Args[1], &c); err != nil {
		c.log.Fatalf(3,"Cannot load config file, err: %s",err)
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
			c.Rule[i].r.HandleFunc("/{rest:.*}", c.handler(c.Rule[i].proxy))
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
		c.log.Info("Starting webserver v1.1")
		go c.ListenServeWrapper(c.BindAddress, certManager.HTTPHandler(nil))
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 5)
		}
	} else {
		c.log.Info("Starting webserver v1.1")
		err = http.ListenAndServe(c.BindAddress,c)
		if err != nil {
			c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 4)
		}
	}
}

func (c *config) handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = mux.Vars(r)["rest"]
		p.ServeHTTP(w, r)
	}
}

func (c *config) ListenServeWrapper(addr string, handler http.Handler) {
	err := http.ListenAndServe(addr, handler)
	if err != nil {
		c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 4)
	}
}
