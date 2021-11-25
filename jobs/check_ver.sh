#!/bin/bash
set -e
[ "$update" ] && exit 0
echo $my_access_token
exit 0
apt-get -qq update
apt-get --yes install --no-install-recommends wget curl jq ca-certificates libdigest-sha-perl
source version/version

ss_main_old=${ss_main:?}
now=($(shasum -a1 src/manager.sh))
[ "$ss_main" != "${now:=0}" ] && ss_main="$now"

ss_tool_old=${ss_tool:?}
now=($(shasum -a1 src/main.c))
[ "$ss_tool" != "${now:=0}" ] && ss_tool="$now"

ipt2socks_old=${ipt2socks:?}
now=$(wget -qO- https://api.github.com/repos/zfl9/ipt2socks/commits/master | jq -r '.sha')
[ "$ipt2socks" != "${now:=0}" ] && ipt2socks="$now"

kcptun_old=${kcptun:?}
now=$(wget -qO- https://api.github.com/repos/xtaci/kcptun/commits/master | jq -r '.sha')
[ "$kcptun" != "${now:=0}" ] && kcptun="$now"

v2ray_plugin_old=${v2ray_plugin:?}
now=$(wget -qO- https://api.github.com/repos/teddysun/v2ray-plugin/commits/master | jq -r '.sha')
[ "$v2ray_plugin" != "${now:=0}" ] && v2ray_plugin="$now"

qrencode_old=${qrencode:?}
now=$(wget -qO- https://api.github.com/repos/fukuchi/libqrencode/commits/master | jq -r '.sha')
[ "$qrencode" != "${now:=0}" ] && qrencode="$now"

simple_obfs_old=${simple_obfs:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocks/simple-obfs/commits/master | jq -r '.sha')
[ "$simple_obfs" != "${now:=0}" ] && simple_obfs="$now"

shadowsocksr_libev_old=${shadowsocksr_libev:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocksrr/shadowsocksr-libev/commits/master | jq -r '.sha')
[ "$shadowsocksr_libev" != "${now:=0}" ] && shadowsocksr_libev="$now"

php_old=${php:?}
now=$(wget -qO- https://www.php.net/downloads.php | grep -oP 'php\-\d+\.\d+\.\d+\.tar.gz' | head -n 1)
if [ "$php" != ${now/.tar.gz/} ]; then
	php="${now/.tar.gz/}"
	php_info="$(echo "<tr><td>php</td><td><a href=\"https://www.php.net/downloads.php\">${now/.tar.gz/}</a></td></tr>" | base64)"
fi

nginx_quic_old=${nginx_quic:?}
data=$(curl --silent --location --cookie "$(curl --silent https://hg.nginx.org/nginx-quic | grep cookie | cut -d'"' -f2 | xargs echo -n)" https://hg.nginx.org/nginx-quic | grep "/nginx-quic/rev/" | grep -e "[0-9a-f]\{12\}" | head -n1)
now=$(echo $data | cut -d'"' -f2 | grep -oP '[0-9a-f]{12}')
if [ "$nginx_quic" != "${now:=0}" ]; then
	nginx_quic="$now"
	nginx_quic_info="$(echo "<tr><td><a href=\"https://quic.nginx.org\">nginx-quic</a></td><td><a href=\"https://hg.nginx.org/nginx-quic/rev/$now\">$(echo $data | cut -d'>' -f2 | cut -d'<' -f1)</a></td></tr>" | base64)"
fi

shadowsocks_rust_old=${shadowsocks_rust:?}
now=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/commits/master | jq -r '.sha')
[ "$shadowsocks_rust" != "${now:=0}" ] && shadowsocks_rust="$now"

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
	-F "variables[php_info_old]=${php_info_old}" \
	-F "variables[php_info]=${php_info}" \
	-F "variables[nginx_quic_old]=${nginx_quic_old:=false}" \
	-F "variables[nginx_quic]=${nginx_quic:=false}" \
	-F "variables[nginx_quic_info_old]=${nginx_quic_info_old}" \
	-F "variables[nginx_quic_info]=${nginx_quic_info}" \
	-F "variables[shadowsocks_rust_old]=${shadowsocks_rust_old:=false}" \
	-F "variables[shadowsocks_rust]=${shadowsocks_rust:=false}" \
	https://gitlab.com/api/v4/projects/${CI_PROJECT_ID:?}/trigger/pipeline
