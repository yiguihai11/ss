#!/bin/bash
set -e

bash jobs/upx.sh
bash jobs/push.sh

chmod -R +x usr/bin usr/sbin
: <<EOF
ipt2socks_old=a
ipt2socks=a
kcptun_old=a
kcptun=a
v2ray_plugin_old=a
v2ray_plugin=a
qrencode_old=a
qrencode=a
simple_obfs_old=a
simple_obfs=a
php_old=a
php=a
php_info=a
nginx_quic_old=a
nginx_quic=a
nginx_quic_info=a
shadowsocks_rust_old=a
shadowsocks_rust=a
EOF

i=0
command="upx --best --lzma --color -f -v"
if [ "$ipt2socks" != 'false' ] && [ "$ipt2socks_old" ]; then
	$command usr/bin/ipt2socks
	((i = i + 1))
fi
if [ "$kcptun" != 'false' ] && [ "$kcptun_old" ]; then
	$command usr/bin/kcptun-server
	((i = i + 1))
fi
if [ "$simple_obfs" != 'false' ] && [ "$simple_obfs_old" ]; then
	$command usr/bin/obfs-server
	((i = i + 1))
fi
if [ "$php" != 'false' ] && [ "$php_old" ]; then
	$command usr/bin/php usr/sbin/php-fpm
	((i = i + 1))
fi
if [ "$nginx_quic" != 'false' ] && [ "$nginx_quic_old" ]; then
	$command usr/sbin/nginx
	((i = i + 1))
fi
if [ "$qrencode" != 'false' ] && [ "$qrencode_old" ]; then
	$command usr/bin/qrencode
	((i = i + 1))
fi
if [ "$shadowsocks_rust" != 'false' ] && [ "$shadowsocks_rust_old" ]; then
	$command usr/bin/ssmanager usr/bin/ssserver usr/bin/ssurl
	((i = i + 1))
fi
if [ "$shadowsocksr_libev" != 'false' ] && [ "$shadowsocksr_libev_old" ]; then
	$command usr/bin/ssr-redir
	((i = i + 1))
fi
if [ "$v2ray_plugin" != 'false' ] && [ "$v2ray_plugin_old" ]; then
	$command usr/bin/v2ray-plugin
	((i = i + 1))
fi
if [ "${i:=0}" -gt 0 ]; then
	git add usr/bin usr/sbin
	git commit -m "压缩完成"
	git push origin HEAD:${CI_COMMIT_REF_NAME}
fi
