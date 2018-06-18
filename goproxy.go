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
	Proxy []proxy
	Redirect []redirect
	LogRequests bool
	log *Logger.Logger
}

type proxy struct {
	Domain string
	Regex bool
	Target string
	AcceptSelfSigned bool
	remote *url.URL
	proxy *httputil.ReverseProxy
	r *mux.Router
}

type redirect struct {
	Domain string
	Regex bool
	Target string
	StatusCode int
}

func (c *config) findProxyHostOffset(host string) int {
	h := strings.Split(host,":")[0]
	for i := range c.Proxy {
		if c.Proxy[i].Domain[0] == '^' || c.Proxy[i].Regex == true {
			match, err := regexp.MatchString(c.Proxy[i].Domain, h)
			if err != nil {
				return -1
			}
			if match == true {
				return i
			}
		} else if c.Proxy[i].Domain == h {
			return i
		}
	}
	return -1
}

func (c *config) findRedirectHostOffset(host string) int {
	h := strings.Split(host,":")[0]
	for i := range c.Redirect {
		if c.Redirect[i].Domain[0] == '^' || c.Redirect[i].Regex == true {
			match, err := regexp.MatchString(c.Redirect[i].Domain, h)
			if err != nil {
				return -1
			}
			if match == true {
				return i
			}
		} else if c.Redirect[i].Domain == h {
			return i
		}
	}
	return -1
}

func (c *config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyMatch := c.findProxyHostOffset(r.Host)
	if proxyMatch != -1 {
		if c.LogRequests == true {
			c.log.Info("Client=%s Host=%s Path=%s Mod=Proxy Target=%s",r.RemoteAddr,r.Host,r.URL.Path,c.Proxy[proxyMatch].Target)
		}
		handler := c.Proxy[proxyMatch].r
		handler.ServeHTTP(w,r)
	} else {
		redirectMatch := c.findRedirectHostOffset(r.Host)
		if redirectMatch != -1 {
			if c.LogRequests == true {
				c.log.Info("Client=%s Host=%s Path=%s Mod=Redirect StatusCode=%v Target=%s",r.RemoteAddr,r.Host,r.URL.Path,c.Redirect[redirectMatch].StatusCode,c.Redirect[redirectMatch].Target)
			}
			http.Redirect(w, r, c.Redirect[redirectMatch].Target, c.Redirect[redirectMatch].StatusCode)
		} else {
			c.log.Info("Client=%s Host=%s Path=%s Mod=Forbidden StatusCode=403",r.RemoteAddr,r.Host,r.URL.Path)
			http.Error(w, "Forbidden", 403)
		}
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
	for i := range c.Proxy {
		c.Proxy[i].remote, err = url.Parse(c.Proxy[i].Target)
		if err != nil {
			c.log.Fatalf(6,"Cannot create remote handle: %s",err)
		}
		c.Proxy[i].proxy = httputil.NewSingleHostReverseProxy(c.Proxy[i].remote)
		if c.Proxy[i].AcceptSelfSigned == true {
			c.Proxy[i].proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
		c.Proxy[i].r = mux.NewRouter()
		c.Proxy[i].r.HandleFunc("/{rest:.*}", c.handler(c.Proxy[i].proxy))
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
