#!/bin/bash
set -e

bash jobs/push.sh

./usr/bin/ipt2socks --version
./usr/bin/kcptun-server --version
./usr/bin/obfs-server --help
./usr/sbin/nginx -V
./usr/bin/php -v
./usr/sbin/php-fpm -v
./usr/bin/qrencode -V
./usr/bin/sslocal -V
./usr/bin/trojan -v
./usr/bin/ssmanager -V
./usr/bin/ssserver -V
./usr/bin/ssurl -V
./usr/bin/ssr-local -h
./usr/bin/v2ray-plugin -version
./usr/bin/v2ray version
./usr/bin/tun2socks -version
./usr/bin/ss-tool
./usr/bin/jq -V
