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

### Future features:
* custom listen forward path for proxy

### Version
###### 1.1
