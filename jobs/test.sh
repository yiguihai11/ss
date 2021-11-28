#!/bin/bash
set -e

bash jobs/upx.sh
chmod -R +x usr/bin usr/sbin
./usr/bin/ipt2socks --version
./usr/bin/kcptun-server --version
./usr/bin/obfs-server --help
./usr/sbin/nginx -V
./usr/bin/php -v
./usr/sbin/php-fpm -v
./usr/bin/qrencode -V
#upx3.95 --best --ultra-brute -v usr/bin/ssmanager usr/bin/ssserver usr/bin/ssurl
./usr/bin/ssmanager -V
./usr/bin/ssserver -V
./usr/bin/ssurl -V
./usr/bin/ssr-redir -h
./usr/bin/v2ray-plugin -version
./usr/bin/ss-tool
