#!/bin/bash
set -e
[ "$update" ] && exit 0
apt-get -qq update
apt-get --yes install --no-install-recommends wget curl jq ca-certificates libdigest-sha-perl binutils
uname -r
strings /lib/x86_64-linux-gnu/libm.so.6 | grep GLIBC_
source version/version

i=0
ss_main_old=${ss_main:?}
now=($(shasum -a1 src/manager.sh))
if [ "${ss_main:=0}" != "${now:=0}" ] && [ "${ss_main:=0}" != 0 ]; then
	ss_main="$now"
	((i = i + 1))
else
	unset -v ss_main
fi

ss_tool_old=${ss_tool:?}
now=($(shasum -a1 src/main.c))
if [ "${ss_tool:=0}" != "${now:=0}" ] && [ "${ss_tool:=0}" != 0 ]; then
	ss_tool="$now"
	((i = i + 1))
else
	unset -v ss_tool
fi

ipt2socks_old=${ipt2socks:?}
now=$(wget -qO- https://api.github.com/repos/zfl9/ipt2socks/commits/master | jq -r '.sha')
if [ "${ipt2socks:=0}" != "${now:=0}" ] && [ "${ipt2socks:=0}" != 0 ]; then
	ipt2socks="$now"
	((i = i + 1))
else
	unset -v ipt2socks
fi

kcptun_old=${kcptun:?}
now=$(wget -qO- https://api.github.com/repos/xtaci/kcptun/commits/master | jq -r '.sha')
if [ "${kcptun:=0}" != "${now:=0}" ] && [ "${kcptun:=0}" != 0 ]; then
	kcptun="$now"
	((i = i + 1))
else
	unset -v kcptun
fi

v2ray_plugin_old=${v2ray_plugin:?}
now=$(wget -qO- https://api.github.com/repos/teddysun/v2ray-plugin/commits/master | jq -r '.sha')
if [ "${v2ray_plugin:=0}" != "${now:=0}" ] && [ "${v2ray_plugin:=0}" != 0 ]; then
	v2ray_plugin="$now"
	((i = i + 1))
else
	unset -v v2ray_plugin
fi

qrencode_old=${qrencode:?}
now=$(wget -qO- https://api.github.com/repos/fukuchi/libqrencode/commits/master | jq -r '.sha')
if [ "${qrencode:=0}" != "${now:=0}" ] && [ "${qrencode:=0}" != 0 ]; then
	qrencode="$now"
	((i = i + 1))
else
	unset -v qrencode
fi

simple_obfs_old=${simple_obfs:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocks/simple-obfs/commits/master | jq -r '.sha')
if [ "${simple_obfs:=0}" != "${now:=0}" ] && [ "${simple_obfs:=0}" != 0 ]; then
	simple_obfs="$now"
	((i = i + 1))
else
	unset -v simple_obfs
fi

shadowsocksr_libev_old=${shadowsocksr_libev:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocksrr/shadowsocksr-libev/commits/master | jq -r '.sha')
if [ "${shadowsocksr_libev:=0}" != "${now:=0}" ] && [ "${shadowsocksr_libev:=0}" != 0 ]; then
	shadowsocksr_libev="$now"
	((i = i + 1))
else
	unset -v shadowsocksr_libev
fi

php_old=${php:?}
now=$(curl -L -s -q https://www.php.net/downloads.php | grep -oP 'php\-\d+\.\d+\.\d+\.tar.gz' | head -n 1)
if [ "${php:=0}" != "${now/.tar.gz/}" ] && [ "${php:=0}" != 0 ]; then
	php="${now/.tar.gz/}"
	php_info="$(echo "<tr><td>php</td><td><a href=\"https://www.php.net/downloads.php\">${now/.tar.gz/}</a></td></tr>" | base64)"
	((i = i + 1))
else
	unset -v php
fi

nginx_quic_old=${nginx_quic:?}
data=$(curl --silent --location --cookie "$(curl --silent https://hg.nginx.org/nginx-quic | grep cookie | cut -d'"' -f2 | xargs echo -n)" https://hg.nginx.org/nginx-quic | grep "/nginx-quic/rev/" | grep -e "[0-9a-f]\{12\}" | head -n1)
now=$(echo $data | cut -d'"' -f2 | grep -oP '[0-9a-f]{12}')
if [ "${nginx_quic:=0}" != "${now:=0}" ] && [ "${nginx_quic:=0}" != 0 ]; then
	nginx_quic="$now"
	nginx_quic_info="$(echo "<tr><td><a href=\"https://quic.nginx.org\">nginx-quic</a></td><td><a href=\"https://hg.nginx.org/nginx-quic/rev/$now\">$(echo $data | cut -d'>' -f2 | cut -d'<' -f1)</a></td></tr>" | base64)"
	((i = i + 1))
else
	unset -v nginx_quic
fi

shadowsocks_rust_old=${shadowsocks_rust:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/commits/master | jq -r '.sha')
if [ "${shadowsocks_rust:=0}" != "${now:=0}" ] && [ "${shadowsocks_rust:=0}" != 0 ]; then
	shadowsocks_rust="$now"
	((i = i + 1))
else
	unset -v shadowsocks_rust
fi

kcptun_android_old=${kcptun_android:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocks/kcptun-android/commits/master | jq -r '.sha')
if [ "${kcptun_android:=0}" != "${now:=0}" ] && [ "${kcptun_android:=0}" != 0 ]; then
	kcptun_android="$now"
	((i = i + 1))
else
	unset -v kcptun_android
fi

: <<'EOF'
shadowsocks_android_old=${shadowsocks_android:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-android/commits/master | jq -r '.sha')
if [ "${shadowsocks_android:=0}" != "${now:=0}" ] && [ "${shadowsocks_android:=0}" != 0 ]; then
	shadowsocks_android="$now"
	((i = i + 1))
else
	unset -v shadowsocks_android
fi
EOF

if [ "${i:=0}" -gt 0 ]; then
	curl -X POST \
		-F "token=$ci_token" \
		-F "ref=${CI_BUILD_REF_NAME:?}" \
		-F "variables[CI_DEBUG_TRACE]=false" \
		-F "variables[update]=true" \
		-F "variables[ss_main_old]=${ss_main_old:=false}" \
		-F "variables[ss_main]=${ss_main:=false}" \
		-F "variables[ss_tool_old]=${ss_tool_old:=false}" \
		-F "variables[ss_tool]=${ss_tool:=false}" \
		-F "variables[ipt2socks_old]=${ipt2socks_old:=false}" \
		-F "variables[ipt2socks]=${ipt2socks:=false}" \
		-F "variables[kcptun_old]=${kcptun_old:=false}" \
		-F "variables[kcptun]=${kcptun:=false}" \
		-F "variables[v2ray_plugin_old]=${v2ray_plugin_old:=false}" \
		-F "variables[v2ray_plugin]=${v2ray_plugin:=false}" \
		-F "variables[qrencode_old]=${qrencode_old:=false}" \
		-F "variables[qrencode]=${qrencode:=false}" \
		-F "variables[simple_obfs_old]=${simple_obfs_old:=false}" \
		-F "variables[simple_obfs]=${simple_obfs:=false}" \
		-F "variables[shadowsocksr_libev_old]=${shadowsocksr_libev_old:=false}" \
		-F "variables[shadowsocksr_libev]=${shadowsocksr_libev:=false}" \
		-F "variables[php_old]=${php_old:=false}" \
		-F "variables[php]=${php:=false}" \
		-F "variables[php_info]=${php_info}" \
		-F "variables[nginx_quic_old]=${nginx_quic_old:=false}" \
		-F "variables[nginx_quic]=${nginx_quic:=false}" \
		-F "variables[nginx_quic_info]=${nginx_quic_info}" \
		-F "variables[shadowsocks_rust_old]=${shadowsocks_rust_old:=false}" \
		-F "variables[shadowsocks_rust]=${shadowsocks_rust:=false}" \
		-F "variables[kcptun_android_old]=${kcptun_android_old:=false}" \
		-F "variables[kcptun_android]=${kcptun_android:=false}" \
		https://gitlab.com/api/v4/projects/${CI_PROJECT_ID:?}/trigger/pipeline
	: <<'EOF'
		-F "variables[shadowsocks_android_old]=${shadowsocks_android_old:=false}" \
		-F "variables[shadowsocks_android]=${shadowsocks_android:=false}" \
EOF
fi
