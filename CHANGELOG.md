## 1.1
* initial stable release

## 1.2
* support for paths added, can now redirect/proxy domain.com/path to domain2.com/newpath
* added support for rewriteHostHeader for proxy

## 1.3
* fixed issue where there is no path on source/target and Path="" resulted in incorrect routing (404)

## 1.4
* added option to serve static files
* added option to serve static files and send .php files through fastcgi
* add option for serving email forms on static websites (since most static websites have an email form)
