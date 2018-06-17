package main

import (
	"os"
	"github.com/bestmethod/go-logger"
	"fmt"
	"github.com/BurntSushi/toml"
	"net/http"
	"strings"
	"golang.org/x/crypto/acme/autocert"
	"crypto/tls"
	"net/http/httputil"
	"github.com/gorilla/mux"
	"net/url"
)

type config struct {
	BindAddress string
	TlsEnabled bool
	TlsBindAddress string
	Domain []domain
	LogProxyRequests bool
	log *Logger.Logger
	hs *HostSwitch
}

type domain struct {
	Name string
	Target string
	remote *url.URL
	proxy *httputil.ReverseProxy
	AcceptSelfSigned bool
}

type HostSwitchMapper map[string]http.Handler

type HostSwitch struct {
	HostSwitchMap map[string]http.Handler
	LogProxyRequests bool
	log *Logger.Logger
}

func (hs HostSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler := hs.HostSwitchMap[strings.Split(r.Host,":")[0]]; handler != nil {
		if hs.LogProxyRequests == true {
			hs.log.Info("Client=%s Host=%s Path=%s",r.RemoteAddr,r.Host,r.URL.Path)
		}
		handler.ServeHTTP(w, r)
	} else {
		if hs.LogProxyRequests == true {
			hs.log.Info("Client=%s Host=%s Path=%s [403] Forbidden",r.RemoteAddr,r.Host,r.URL.Path)
		}
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
	hs := make(HostSwitchMapper)
	var err error
	for i, domain := range c.Domain {
		c.Domain[i].remote, err = url.Parse(domain.Target)
		if err != nil {
			c.log.Fatalf(4,"Cannot create remote handle: %s",err)
		}
		c.Domain[i].proxy = httputil.NewSingleHostReverseProxy(c.Domain[i].remote)
		if domain.AcceptSelfSigned == true {
			c.Domain[i].proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
		r := mux.NewRouter()
		r.HandleFunc("/{rest:.*}", handler(c.Domain[i].proxy))
		hs[domain.Name] = r
	}
	hsm := HostSwitch{}
	c.hs = &hsm
	c.hs.HostSwitchMap = hs
	c.hs.log = c.log
	c.hs.LogProxyRequests = c.LogProxyRequests
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
			Handler: c.hs,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}
		c.log.Info("Starting webserver v1.0")
		go http.ListenAndServe(c.BindAddress, certManager.HTTPHandler(nil))
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 4)
		}
	} else {
		c.log.Info("Starting webserver v1.0")
		err = http.ListenAndServe(c.BindAddress,c.hs)
		if err != nil {
			c.log.Fatal(fmt.Sprintf("Could not run webserver: %s", err), 4)
		}
	}
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = mux.Vars(r)["rest"]
		p.ServeHTTP(w, r)
	}
}