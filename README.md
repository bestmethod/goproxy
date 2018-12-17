# Simple 'goproxy' http(s) proxy

### Usage:

```
$ goproxy config.toml
```

### See example config.toml for details

### Get compiled binary from:
##### https://gitlab.com/bestmethod/goproxy/-/jobs

### Features
* support for proxy and redirects
* very small and simple to use
* if using TLS (https), auto-cert gets lets-encrypt certificates automatically
* multiple domain proxy forwarding
* detailed logging if required
* custom target forward path (see last config.toml example)
* wildcard domains (well, regex, even better)
* add custom default action using wild regex grab
* custom listen forward path for proxy
* rewrite host header during requests
* static website hosting
* basic php website hosting using fastcgi (NOTE: if the website relies on .htaccess files for URL rewrites or other such voodoo, this will not work - clue in the BASIC)

### Note
Rules are evaluated top to bottom. If a match is found, that rule will be executed.

### Future features
* add support for custom behaviours for http requests when https is enabled

### Version
###### 1.4
