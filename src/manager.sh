#!/bin/bash
# shellcheck source=/dev/null
# shellcheck disable=SC2030,SC2031

NOW_PID=$$
HOME_DIR=/etc/ssmanager
export PATH=${PATH}:${HOME_DIR}/usr/bin:${HOME_DIR}/usr/sbin:${PWD}
export PYTHONIOENCODING=utf-8
export LANG=en_US.UTF-8 #dialog乱码https://jaminzhang.github.io/linux/Change-Linux-System-Locale-Envs/

Encryption_method_no=(
	plain
	none
)

Encryption_method_aead=(
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

Encryption_method_extra=(
	aes-128-ccm
	aes-256-ccm
	aes-128-gcm-siv
	aes-256-gcm-siv
	xchacha20-ietf-poly1305
)

Encryption_method_2022=(
	2022-blake3-aes-128-gcm
	2022-blake3-aes-256-gcm
	2022-blake3-chacha20-poly1305
)

Encryption_method_2022_extra=(
	2022-blake3-chacha8-poly1305
)

Encryption_method_list=(
	"${Encryption_method_no[@]}"
	"${Encryption_method_aead[@]}"
	"${Encryption_method_extra[@]}"
	"${Encryption_method_2022[@]}"
	"${Encryption_method_2022_extra[@]}"
)

Generate_random_numbers() (
	min=$1
	max=$(($2 - min + 1))
	num=$((RANDOM + 1000000000)) #增加一个10位的数再求余
	printf '%d' $((num % max + min))
)

Generate_random_uuid() {
	unset -v userid
	userid=$(grep -E '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' /proc/sys/kernel/random/uuid)
	if [ -z "$userid" ]; then
		Prompt "UUID $userid ?"
		Exit
	fi
}

Introduction_bar() (
	while IFS= read -r c; do
		printf "\e[1;33m#\e[0m"
	done <<EOF
$(fold -w1)
EOF
	echo
)

Introduction() (
	if [ "$exist_rich" ]; then
		echo
		${python:-python3} <<-EOF
			from rich.console import Console
			from rich.panel import Panel
			from rich import box
			console = Console()
			console.print(Panel.fit("[b]$*[/b]", box=box.HEAVY_EDGE, style="yellow"))
		EOF
	else
		cat >&1 <<-EOF

			$(printf '%s' "$*" | Introduction_bar)
			$1
			$(printf '%s' "$*" | Introduction_bar)

		EOF
	fi
)

Prompt_bar() (
	while IFS= read -r c; do
		printf "\e[1;32m-\e[0m"
	done <<EOF
$(fold -w1)
EOF
	echo
)

Prompt() (
	if [ "$exist_rich" ]; then
		echo
		${python:-python3} <<-EOF
			from rich.console import Console
			from rich.panel import Panel
			from rich import box
			console = Console()
			console.print(Panel.fit("[b][i]$*[/i][/b]", box=box.HORIZONTALS, style="green"))
		EOF
	else
		cat >&1 <<-EOF

			$(printf '%s' "$*" | Prompt_bar)
			$1
			$(printf '%s' "$*" | Prompt_bar)

		EOF
	fi
)

# 判断命令是否存在
command_exists() {
	#type -P $@
	command -v "$@" >/dev/null 2>&1
}

#浮点数大小比较用于版本比对
#https://www.codegrepper.com/code-examples/shell/how+to+compare+float+values+in+shell+script
numCompare() {
	return "$(echo | awk "{ print ($1 >= $2)?0 : 1 }")"
}

#https://stackoverflow.com/a/808740
is_number() {
	[ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null
}

ip_is_private() {
	if [ "$1" ]; then
		local iip
		iip=$(
			${python:-python3} <<-EOF
				from ipaddress import ip_address
				if not ip_address("$1").is_global:
				  print(0)
			EOF
		)
		return "${iip:-1}"
	fi
}

# 按任意键继续
Press_any_key_to_continue() {
	if [ "${Language:=zh-CN}" = "en-US" ]; then
		read -n 1 -r -s -p $'Press any key to start...or Press Ctrl+C to cancel\n'
	else
		read -n 1 -r -s -p $'请按任意键继续或 Ctrl + C 退出\n'
	fi
}

Curl_get_files() {
	if ! curl -L -s -q --retry 5 --retry-delay 10 --retry-max-time 60 --output "$1" "$2"; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Download $1 failed."
		else
			Prompt "下载 $1 文件时失败！"
		fi
		rm -f "$1"
		Exit
	fi
}

Wget_get_files() {
	if ! wget --no-check-certificate -q -c -t2 -T8 -O "$1" "$2"; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Download $1 failed."
		else
			Prompt "下载 $1 文件时失败！"
		fi
		rm -f "$1"
		Exit
	fi
}

Downloader() {
	${python:-python3} <<-EOF
		import os.path
		import sys
		from concurrent.futures import as_completed, ThreadPoolExecutor
		import signal
		from functools import partial
		from threading import Event
		from typing import Iterable
		from urllib.request import urlopen

		from rich.progress import (
		    BarColumn,
		    DownloadColumn,
		    Progress,
		    TaskID,
		    TextColumn,
		    TimeRemainingColumn,
		    TransferSpeedColumn,
		)

		progress = Progress(
		    TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
		    BarColumn(bar_width=None),
		    "[progress.percentage]{task.percentage:>3.1f}%",
		    "•",
		    DownloadColumn(),
		    "•",
		    TransferSpeedColumn(),
		    "•",
		    TimeRemainingColumn(),
		)

		done_event = Event()


		def handle_sigint(signum, frame):
		    done_event.set()


		signal.signal(signal.SIGINT, handle_sigint)


		def copy_url(task_id: TaskID, url: str, path: str) -> None:
		    """Copy data from a url to a local file."""
		    progress.console.log(f"Requesting {url}")
		    response = urlopen(url)
		    # This will break if the response doesn't contain content length
		    progress.update(task_id, total=int(response.info()["Content-length"]))
		    with open(path, "wb") as dest_file:
		        progress.start_task(task_id)
		        for data in iter(partial(response.read, 32768), b""):
		            dest_file.write(data)
		            progress.update(task_id, advance=len(data))
		            if done_event.is_set():
		                return
		    progress.console.log(f"Downloaded {path}")


		def download(urls: str):
		    """Download multuple files to the given directory."""

		    with progress:
		        with ThreadPoolExecutor(max_workers=4) as pool:
		            for url in urls.split(' '):
		                url, dest_path = url.split('+')
		                filename = dest_path.split("/")[-1]
		                task_id = progress.add_task("download",
		                                            filename=filename,
		                                            start=False)
		                pool.submit(copy_url, task_id, url, dest_path)
		download("$@")
	EOF
}

Url_encode_pipe() {
	local LANG=C
	local c
	while IFS= read -r c; do
		case $c in [a-zA-Z0-9.~_-])
			printf '%s' "$c"
			continue
			;;
		esac
		printf '%s' "$c" | od -An -tx1 | tr ' ' % | tr -d '\n'
	done <<EOF
$(fold -w1)
EOF
}

Url_encode() (
	printf '%s' "$*" | Url_encode_pipe
)

Url_decode() {
	: "${*//+/ }"
	echo -e "${_//%/\\x}"
}

#https://stackoverflow.com/questions/238073/how-to-add-a-progress-bar-to-a-shell-script
Progress_Bar() {
	_progress=$((100 * $1 / $2))
	_done=$((_progress * 4 / 10))
	_left=$((40 - _done))

	_fill=$(printf "%${_done}s")
	_empty=$(printf "%${_left}s")

	#[ ${#3} -gt 20 ] && run="${3:0:20}..." || run=$3

	printf "\r${3:=Progress} [${_progress}%%]|${_fill// /◉}${_empty// /◯}"
	[ ${_progress:-100} -eq 100 ] && echo
}

Address_lookup() {
	unset -v addr my_ipv4 my_ipv6
	local cur_time last_time tb_addr
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Prompt "Loading ..."
	else
		Prompt "请稍等 ..."
	fi
	if [ "$ipv4" ]; then
		if ip_is_private "$ipv4"; then
			my_ipv4=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' "http://v4.ipv6-test.com/api/myip.php")
		else
			my_ipv4="$ipv4"
		fi
		if [ "$my_ipv4" ]; then
			unset -v ipv6
		else
			unset -v my_ipv4
		fi
	fi
	if [ "$ipv6" ]; then
		if ip_is_private "$ipv6"; then
			my_ipv6=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' "http://v6.ipv6-test.com/api/myip.php")
		else
			my_ipv6="$ipv6"
		fi
		if [ "$my_ipv6" ]; then
			unset -v ipv4
		else
			unset -v my_ipv6
		fi
	fi
	if [ -z "${my_ipv4:-$my_ipv6}" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Failed to get IP address!"
		else
			Prompt "获取IP地址失败！"
		fi
		Exit
	fi
	if [ ! -s /tmp/myaddr ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://ipapi.co/json | jq -r '.city + ", " +.region + ", " + .country_name')
		else
			addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://myip.ipip.net)
			if [ "$addr" ]; then
				addr=${addr##*\来\自\于}
				addr=${addr:1}
				if [[ $addr == *"台湾"* ]]; then
					addr=${addr//中国/中华民国}
					addr=${addr//台湾省/台湾}
				fi
			else
				#https://wangshengxian.com/article/details/article_id/37.html
				tb_addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' "https://ip.taobao.com/outGetIpInfo?ip=${my_ipv4:-$my_ipv6}&accessKey=alibaba-inc")
				if [ "$tb_addr" ]; then
					case $(echo "$tb_addr" | jq -r '.code') in
					0)
						if [ "$(echo "$tb_addr" | jq -r '.data.region')" = "台湾" ]; then
							tb_addr=${tb_addr//中国/中华民国}
							tb_addr=${tb_addr//CN/TW}
						fi
						addr=$(echo "$tb_addr" | jq -r '.data.country + " " +.data.region + " " + .data.country_id')
						;;
					1)
						Prompt "服务器异常"
						;;
					2)
						Prompt "请求参数异常"
						;;
					3)
						Prompt "服务器繁忙"
						;;
					4)
						Prompt "个人qps超出"
						;;
					esac
				fi
			fi
		fi
		[ "$addr" ] && echo "$addr" >/tmp/myaddr
	else
		addr=$(</tmp/myaddr)
		cur_time=$(date +%s)
		last_time=$(date -r /tmp/myaddr +%s)
		#一天后删除重新获取地址
		if [ $((cur_time - last_time)) -gt 86400 ]; then
			rm -f /tmp/myaddr
		fi
	fi
	if [ -z "$addr" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Failed to get attribution location!"
		else
			Prompt "获取归属地位置失败！"
		fi
		Exit
	fi
}

Parsing_User() {
	unset -v server_port password method plugin plugin_opts used_traffic total reset_day reset_type expire_timestamp upload_limit download_limit user_id
	IFS='|'
	for l in $1; do
		case ${l%^*} in
		server_port)
			server_port=${l#*^}
			;;
		password)
			password=${l#*^}
			;;
		method)
			method=${l#*^}
			;;
		plugin)
			plugin=${l#*^}
			;;
		plugin_opts)
			plugin_opts=${l#*^}
			;;
		used_traffic)
			used_traffic=${l#*^}
			;;
		total)
			total=${l#*^}
			;;
		reset_day)
			reset_day=${l#*^}
			;;
		reset_type)
			reset_type=${l#*^}
			;;
		expire_timestamp)
			expire_timestamp=${l#*^}
			;;
		upload_limit)
			upload_limit=${l#*^}
			;;
		download_limit)
			download_limit=${l#*^}
			;;
		user_id)
			user_id=${l#*^}
			;;
		esac
	done
}

Parsing_plugin_opts() (
	if [ "$1" ] && [ "$2" ]; then
		IFS=';'
		for l in $1; do
			if [ "${l%=*}" = "$2" ]; then
				printf '%s' "${l#*=}"
			fi
		done
	fi
)

Traffic() {
	local i=${1:-0}
	if [ "$i" -lt 1024 ]; then
		printf '%d B' "$i"
	elif [ "$i" -lt $((1024 ** 2)) ]; then
		awk 'BEGIN{printf "%.2f KB",('"$i"' / 1024)}'
	elif [ "$i" -lt $((1024 ** 3)) ]; then
		awk 'BEGIN{printf "%.2f MB",('"$i"' / (1024 ^ 2))}'
	elif [ "$i" -lt $((1024 ** 4)) ]; then
		awk 'BEGIN{printf "%.2f GB",('"$i"' / (1024 ^ 3))}'
	elif [ "$i" -lt $((1024 ** 5)) ]; then
		awk 'BEGIN{printf "%.2f TB",('"$i"' / (1024 ^ 4))}'
	elif [ "$i" -lt $((1024 ** 6)) ]; then
		awk 'BEGIN{printf "%.2f PB",('"$i"' / (1024 ^ 5))}'
	elif [ "$i" -lt $((1024 ** 7)) ]; then
		awk 'BEGIN{printf "%.2f EB",('"$i"' / (1024 ^ 6))}'
	elif [ "$i" -lt $((1024 ** 8)) ]; then
		awk 'BEGIN{printf "%.2f ZB",('"$i"' / (1024 ^ 7))}'
	elif [ "$i" -lt $((1024 ** 9)) ]; then
		awk 'BEGIN{printf "%.2f YB",('"$i"' / (1024 ^ 8))}'
	elif [ "$i" -lt $((1024 ** 10)) ]; then
		awk 'BEGIN{printf "%.2f BB",('"$i"' / (1024 ^ 9))}'
	fi
}

Used_traffic() (
	cs=8
	while true; do
		((cs--))
		[ ${cs:-0} -eq 0 ] && break
		if [ "$2" ] && [ -s "$2" ]; then
			aa=$(<"${2}")
		else
			aa=$(ss-tool /tmp/ss-manager.socket ping 2>/dev/null)
		fi
		if [ -z "$aa" ]; then
			sleep 0.5
			continue
		fi
		b=${aa##*\{}
		c=${b%%\}*}
		IFS=','
		for i in ${c//\"/}; do
			IFS=' '
			for j in $i; do
				if [ "${j%\:*}" = "$1" ]; then
					if is_number "${j#*\:}"; then
						printf '%d' "${j#*\:}"
						break 3
					fi
				fi
			done
		done
	done
)

Create_certificate() {
	unset -v ca_type eab_kid eab_hmac_key tls_common_name tls_key tls_cert
	tls_key="$HOME_DIR"/ssl/server.key
	tls_cert="$HOME_DIR"/ssl/server.cer
	until [ -s $tls_key ] || [ -s $tls_cert ]; do
		if [ -z "$nginx_on" ] && ss -ln state listening '( sport = :80 )' | grep -q ':80 '; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Prompt "Network port 80 is occupied by other processes!"
			else
				Prompt "80端口被其它进程占用！"
			fi
			Exit
		fi
		echo
		if [ -x "${HOME:?}"/.acme.sh/acme.sh ]; then
			"${HOME:?}"/.acme.sh/acme.sh --upgrade
		else
			wget --no-check-certificate -O - https://get.acme.sh | sh
		fi
		while true; do
			cat <<EOF
1. Let’s Encrypt (推荐/Recommend)
2. ZeroSSL
EOF
			read -rp $'请选择/Please select \e[95m1-2\e[0m: ' action
			case $action in
			1)
				ca_type='letsencrypt'
				break
				;;
			2)
				ca_type='zerossl'
				break
				;;
			esac
		done
		if [ "$ca_type" = "zerossl" ]; then
			Introduction "https://github.com/acmesh-official/acme.sh/wiki/ZeroSSL.com-CA"
			until [ "$eab_kid" ] && [ "$eab_hmac_key" ]; do
				read -rp "EAB KID: " eab_kid
				read -rp "EAB HMAC Key: " eab_hmac_key
			done
			"${HOME:?}"/.acme.sh/acme.sh --register-account --server "$ca_type" --eab-kid "$eab_kid" --eab-hmac-key "$eab_hmac_key"
		fi
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Please enter your domain name to apply for a certificate"
		else
			Introduction "请输入域名以申请证书"
		fi
		until [ "$tls_common_name" ]; do
			read -rp "(${mr:=默认}: example.com): " tls_common_name
			if ! echo "$tls_common_name" | grep -qoE '^([a-zA-Z0-9](([a-zA-Z0-9-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
				unset -v tls_common_name
			fi
		done
		local mode1 mode2 my_server_ip fal
		if [ "$nginx_on" ]; then
			mode1="--webroot"
			mode2="${HOME_DIR}/web"
		else
			mode1="--standalone"
			Address_lookup
			if [ "$ipv4" ] && [ "$internet4" ]; then
				my_server_ip=$(ping -4 -c1 -W1 -q -n "$tls_common_name" | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\1/p')
			elif [ "$ipv6" ] && [ "$internet6" ]; then
				my_server_ip=$(ping -6 -c1 -W1 -q -n "$tls_common_name" | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\1/p')
			fi
			if [ "$my_server_ip" ]; then
				if [ "${my_ipv4:-$my_ipv6}" = "$my_server_ip" ]; then
					if iptables -w -t filter -C INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset >/dev/null 2>&1; then
						disable_cdn_firewall
						fal=on
					fi
				else
					Prompt "你的服务器IP(${my_ipv4:-$my_ipv6})与域名解析到的IP(${my_server_ip})不对应！如果使用了Cloudflare的CDN你需要暂时关闭代理状态"
					Exit
				fi
			else
				Prompt "获取IP地址失败！"
				Exit
			fi
		fi
		if "${HOME:?}"/.acme.sh/acme.sh --issue --domain "$tls_common_name" $mode1 $mode2 -k ec-256 --server $ca_type --force; then
			if "${HOME:?}"/.acme.sh/acme.sh --install-cert --domain "$tls_common_name" --cert-file $tls_cert --key-file $tls_key --ca-file ${HOME_DIR:?}/ssl/ca.cer --fullchain-file ${HOME_DIR:?}/ssl/fullchain.cer --ecc --server $ca_type --force; then
				Prompt "$tls_common_name"
			else
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Prompt "Failed to install certificate!"
				else
					Prompt "安装证书失败！"
				fi
				Exit
			fi
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Prompt "Failed to issue certificate!"
			else
				Prompt "签发证书失败!"
			fi
			Exit
		fi
		Check_permissions
		[ "$fal" = "on" ] && enable_cdn_firewall
	done
	if [ ! -s $tls_key ] || [ ! -s $tls_cert ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "The certificate file could not be found!"
		else
			Prompt "无法找到证书文件! "
		fi
		Exit
	fi
	tls_common_name=$(openssl x509 -noout -subject -in $tls_cert | cut -d'=' -f3)
	tls_common_name=${tls_common_name// /}
	[ -z "$tls_common_name" ] && Exit
}

Check_permissions() (
	#因为php-fpm是使用nobody运行的无法访问root权限文件所以每次改动以下文件都要修改回访问权限
	for i in $HOME_DIR/port.list $HOME_DIR/ssl/server.cer $HOME_DIR/conf/config.ini; do
		if [ -f $i ]; then
			if [ -f $HOME_DIR/web/subscriptions.php ]; then
				[ "$(stat -c "%U:%G" $i)" != "nobody:root" ] && chown nobody $i
			else
				[ "$(stat -c "%U:%G" $i)" != "root:root" ] && chown root $i
			fi
		fi
	done
)

Local_IP() {
	local cs=5 i4 i6
	while true; do
		((cs--))
		if [ ${cs:-0} -eq 0 ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Prompt "Failed to get IP address!"
			else
				Prompt "获取IP地址失败！"
			fi
			Exit
		else
			i4=$(ip -4 -o route get to 8.8.8.8 2>/dev/null)
			i6=$(ip -6 -o route get to 2001:4860:4860::8888 2>/dev/null)
			if [ "$i4" ]; then
				ipv4=$(echo "$i4" | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
				#https://unix.stackexchange.com/questions/14961/how-to-find-out-which-interface-am-i-using-for-connecting-to-the-internet
				internet4=$(echo "$i4" | grep -Po '(?<=(dev ))(\S+)')
			fi
			if [ "$i6" ]; then
				ipv6=$(echo "$i6" | sed -n 's/.*src \([^ ]*\).*/\1/p')
				internet6=$(echo "$i6" | grep -Po '(?<=(dev ))(\S+)')
			fi
			if [ "$ipv4" ] && [ "$internet4" ]; then
				unset -v ipv6 internet6
			fi
			if [ "$ipv6" ] && [ "$internet6" ]; then
				unset -v ipv4 internet4
			fi
			if [ "${ipv4:-$ipv6}" ]; then
				break
			else
				sleep 1
			fi
		fi
	done
}

Python_Build() {
	pushd /tmp || exit
	apt-get -qq install -y --no-install-recommends build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev
	local ver
	#ver=$(wget -q -O- --no-check-certificate https://www.python.org/downloads/source/ | grep 'Latest Python' | grep -oP '\d+\.\d+\.\d+' | head -n 1)
	ver=3.6.15
	Wget_get_files Python-${ver}.tgz https://www.python.org/ftp/python/${ver}/Python-${ver}.tgz
	if ! tar xf Python-${ver}.tgz; then
		Prompt "The archive Python-${ver}.tgz failed to decompress"
	fi
	rm -f Python-${ver}.tgz
	cd Python-${ver} || exit
	./configure --enable-ipv6 "$1" --prefix=$HOME_DIR/python
	if ! make -j2; then
		Prompt "Failed to compile Python-${ver}"
	fi
	if ! make altinstall; then
		Prompt "Failed to install Python-${ver}"
	fi
	rm -rf /tmp/Python-${ver}
	strip $HOME_DIR/python/bin/python${ver%.*}
	$HOME_DIR/python/bin/python${ver%.*} -V
	rm -f $HOME_DIR/python/bin/python
	ln -s $HOME_DIR/python/bin/python${ver%.*} $HOME_DIR/python/bin/python
	ln -s $HOME_DIR/python/bin/pip${ver%.*} $HOME_DIR/python/bin/pip
	popd || exit
}

Check() {
	if [ ${UID:=65534} -ne 0 ]; then
		Prompt "You must run this script as root!"
		Exit
	fi
	if [ "$(uname -m)" != 'x86_64' ]; then
		Prompt "System architecture does not support!"
	fi
	if ! command_exists apt; then
		Prompt "The script does not support the package manager in this operating system."
		Exit
	fi
	#https://qastack.cn/ubuntu/481/how-do-i-find-the-package-that-provides-a-file
	local az=0 package_list sorted_arr i2 time_sync
	declare -a package_list=(systemctl wget curl ss pkill socat jq openssl shasum iptables ipset git python3 pip3 ping vim gpg logger setcap)
	for i in "${package_list[@]}"; do
		if ! command_exists "$i"; then
			case $i in
			ss)
				i2="iproute2"
				;;
			pkill)
				i2="procps"
				;;
			shasum)
				i2="libdigest-sha-perl"
				;;
			pip3)
				i2="python3-pip"
				;;
			systemctl)
				i2="systemd"
				;;
			ping)
				i2="iputils-ping"
				;;
			gpg)
				i2="gnupg"
				;;
			logger)
				i2="bsdutils"
				;;
			setcap)
				i2="libcap2-bin"
				;;
			*)
				i2="$i"
				;;
			esac
			sorted_arr+=("$i2")
		fi
	done
	if [ "${#sorted_arr[*]}" -ge 1 ]; then
		if [ -z "$(find / -type f -name 'libapt-inst.s*')" ]; then
			apt-get -qq install -y --no-install-recommends apt-utils 1>/dev/null
		fi
		#https://brettterpstra.com/2015/03/17/shell-tricks-sort-a-bash-array-by-length/ 重新排列数组
		IFS=$'\n' GLOBIGNORE='*' mapfile -t sorted_arr < <(printf '%s\n' "${sorted_arr[@]}" | awk '{ print length($0) " " $0; }' | sort -n | cut -d ' ' -f 2-)
		for i in "${sorted_arr[@]}"; do
			((az++))
			[ "$az" -le 1 ] && clear
			#echo $(((az * 100 / ${#package_list2[*]} * 100) / 100)) | whiptail --gauge "Please wait while installing" 6 60 0
			Progress_Bar "$az" ${#sorted_arr[*]} "Installing $i"
			if ! DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends "$i" 1>/dev/null; then
				Prompt "There is an exception when installing the program!"
				Exit
			fi
			#[ $az -eq ${#package_list2[*]} ] && clear
		done
		if command_exists timedatectl; then
			time_sync=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' "https://ip.taobao.com/outGetIpInfo?ip=${SSH_CLIENT%% *}&accessKey=alibaba-inc")
			if [ "$time_sync" ]; then
				case $(echo "$time_sync" | jq -r '.code') in
				0)
					if [ "$(echo "$time_sync" | jq -r '.data.country_id')" = "CN" ]; then
						timedatectl set-timezone "Asia/Taipei"
						timedatectl set-ntp true
					fi
					;;
				esac
			fi
		fi
	fi
	if [ ! -d $HOME_DIR ]; then
		mkdir -p $HOME_DIR || Exit
	fi
	for i in conf usr ssl web pid; do
		if [ ! -d $HOME_DIR/$i ]; then
			mkdir -p $HOME_DIR/$i || Exit
		fi
	done
	for i in bin conf etc html lib php sbin fastcgi_temp client_body_temp; do
		if [ ! -d $HOME_DIR/usr/$i ]; then
			mkdir -p $HOME_DIR/usr/$i || Exit
		fi
	done
	if [ -s $HOME_DIR/conf/config.ini ]; then
		source ${HOME_DIR:?}/conf/config.ini
	fi
	if [ -z "$URL" ]; then
		local test1 test2
		Prompt "Network environment being tested..."
		if [[ "$(ping -c1 -W1 -q -n gitlab.com | grep -oE '([0-9]+\.){3}[0-9]+?')" != +(127.0.0.1|0.0.0.0) ]]; then
			test1=0
		else
			test1=1
		fi
		if [ "$(curl -s -o /dev/null -w '%{response_code}' --connect-timeout 5 --resolve gitlab.com:443:172.65.251.78 https://gitlab.com/yiguihai/ss/-/raw/dev/README.md)" = 200 ]; then
			test2=0
		else
			test2=1
		fi
		#搜索github CDN加速 https://segmentfault.com/a/1190000038298623
		if [ $((test1 + test2)) -eq 0 ]; then
			URL="https://gitlab.com/yiguihai/ss/-/raw/dev"
		else
			URL="https://glcdn.githack.com/yiguihai/ss/-/raw/dev"
		fi
	fi
	if [ ! -s $HOME_DIR/conf/config.ini ]; then
		Wget_get_files $HOME_DIR/conf/config.ini $URL/conf/config.ini
		if [ "$Language" ]; then
			sed -i "/^Language=/s/=.*/=$Language/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Dialog" ]; then
			sed -i "/^Dialog=/s/=.*/=$Dialog/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Subscribe" ]; then
			sed -i "/^Subscribe=/s/=.*/=$Subscribe/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Nginx_Switch" ]; then
			sed -i "/^Nginx_Switch=/s/=.*/=$Nginx_Switch/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Sni_Filtering" ]; then
			sed -i "/^Sni_Filtering=/s/=.*/=$Sni_Filtering/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Block_China" ]; then
			sed -i "/^Block_China=/s/=.*/=$Block_China/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Firewall_Service" ]; then
			sed -i "/^Firewall_Service=/s/=.*/=$Firewall_Service/" $HOME_DIR/conf/config.ini
		fi
		if [ "$URL" ]; then
			echo "URL=$URL" >>$HOME_DIR/conf/config.ini
		else
			Prompt "Unable to get download node!"
			Exit
		fi
		Check_permissions
	fi
	local python_ver
	python_ver=$(python3 -V)
	#最低python版本要求https://pypi.org/project/rich/#data
	#IFS='.' read -r -a ver <<< "${python_ver#* }"
	#if [ ${ver[0]} -le 3 ] && [ ${ver[1]} -lt 6 ]; then
	if ! numCompare "${python_ver#* }" 3.6.2; then
		python="$HOME_DIR/python/bin/python"
		pip="$HOME_DIR/python/bin/pip"
		if [ ! -x $python ] || [ ! -x $pip ]; then
			Prompt "Python ${python_ver#* } <= 3.6.2 will now start compiling the latest version"
			Introduction "Enable Profile Guided Optimization (PGO) using PROFILE_TASK"
			read -rp "(disabled by default). [Y/n]" eos
			if [[ $eos =~ ^[Yy]$ ]]; then
				eos="--enable-optimizations"
			else
				unset -v eos
			fi
			Python_Build $eos
		fi
	fi
	Local_IP
	if ! ${python:-python3} -c "import rich" 2>/dev/null; then
		${python:-python3} -m pip install -q --upgrade pip
		if ! ${python:-python3} -m pip install -q rich; then
			Prompt "Unable to install rich module!"
			Exit
		fi
	fi
	if ${python:-python3} -c "import rich" 2>/dev/null; then
		exist_rich=yes
	else
		unset -v exist_rich
	fi
	if [ ! -s $HOME_DIR/conf/update.log ]; then
		Wget_get_files $HOME_DIR/conf/update.log $URL/version/update
	fi
	local dl=() Binary_file_list=()
	Binary_file_list+=("${HOME_DIR:?}/usr/bin/kcptun.sh")
	Binary_file_list+=("${HOME_DIR:?}/usr/bin/curl")
	while IFS= read -r line || [ -n "$line" ]; do
		Binary_file_list+=("${line##* }")
	done <"${HOME_DIR:?}"/conf/update.log
	for x in "${Binary_file_list[@]}"; do
		if [ ! -f "$x" ] || [ ! -x "$x" ]; then
			dl+=("$URL/usr/bin/${x##*/}+$x")
		fi
	done
	if [ "${#dl[@]}" -gt 0 ]; then
		Downloader "${dl[@]}"
	fi
	for x in "${Binary_file_list[@]}"; do
		if [ ! -f "$x" ]; then
			Prompt "File $x Download failed!"
			Exit
		fi
		if [ ! -x "$x" ]; then
			chmod +x "$x"
		fi
		if [ "${x##*/}" = "ss-main" ] && [ ! -L /usr/local/bin/"${x##*/}" ]; then
			rm -f /usr/local/bin/"${x##*/}"
			ln -s "$x" /usr/local/bin/"${x##*/}"
		fi
	done
	ss_ver="$(ssmanager -V 2>/dev/null)"
	if [ -z "$ss_ver" ]; then
		{ ss_ver=$(ssmanager -V 2>&1 >&3 3>&-); } 3>&1
	fi
	ss_ver="${ss_ver##* }"
	ss_ver="${ss_ver//[$'\t\r\n ']/}"
	#ss_ver=$(echo "$ss_ver" | grep -oP '(\d*\.\d+){1,2}')
	if [ ! -s $HOME_DIR/conf/server_block.acl ]; then
		Wget_get_files $HOME_DIR/conf/server_block.acl $URL/acl/server_block.acl
	fi
	if [ ! -s $HOME_DIR/conf/log4rs.yaml ]; then
		Wget_get_files $HOME_DIR/conf/log4rs.yaml $URL/conf/log4rs.yaml
	fi
	if [ ! -s /etc/systemd/system/ss-main.service ]; then
		Wget_get_files /etc/systemd/system/ss-main.service $URL/init.d/ss-main.service
		chmod 0644 /etc/systemd/system/ss-main.service
		systemctl enable ss-main.service
		systemctl daemon-reload
		systemctl reset-failed
		#systemctl --type=service
	fi
}

Author() {
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		echo -e "=========== \033[1mShadowsocks-rust\033[0m Multiport Management by \033[$(Generate_random_numbers 1 7);$(Generate_random_numbers 30 37);$(Generate_random_numbers 40 47)m爱翻墙的红杏\033[0m ==========="
	else
		echo -e "=========== \033[1mShadowsocks-rust\033[0m 多端口管理脚本 by \033[$(Generate_random_numbers 1 7);$(Generate_random_numbers 30 37);$(Generate_random_numbers 40 47)m爱翻墙的红杏\033[0m ==========="
	fi
}

Status() {
	if pgrep -F /run/ss-manager.pid >/dev/null 2>&1; then
		if pgrep -F /run/ss-daemon.pid >/dev/null 2>&1; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				#status="\033[1;37;42mRuning\033[0m"
				statusr="[green]Runing[/green]"
			else
				#status="\033[1;37;42m运行中\033[0m"
				statusr="[green]运行中[/green]"
			fi
			runing=true
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				#status="\033[1;37;43mThe daemon is not running\033[0m"
				statusr="[yellow]The daemon is not running[/yellow]"
			else
				#status="\033[1;37;43m守护脚本未运行\033[0m"
				statusr="[yellow]守护脚本未运行[/yellow]"
			fi
			Stop
		fi
	else
		if [ "$ss_ver" ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				#status="\033[1;37;41mStopped\033[0m"
				statusr="[red]Stopped[/red]"
			else
				#status="\033[1;37;41m未运行\033[0m"
				statusr="[red]未运行[/red]"
			fi
			runing=false
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				#status="\033[1;37;41mSystem incompatibility\033[0m"
				statusr="[red]System incompatibility[/red]"
			else
				#status="\033[1;37;41m系统或版本不兼容\033[0m"
				statusr="[red]系统或版本不兼容[/red]"
			fi
			force_uninstall=true
		fi
	fi
	: <<'EOF'
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		echo -e "Service Status: $status"
	else
		echo -e "服务状态: $status"
	fi
EOF
}

Obfs_plugin() {
	unset -v obfs
	local obfs_rust=(http tls)
	if [ "$Dialog" = 'enable' ]; then
		obfs=$(
			#https://stackoverflow.com/a/29912133
			declare -a array
			j=1
			k=1
			for i in "${obfs_rust[@]}"; do
				array[$j]=$k
				((k++))
				array[j + 1]=$i
				((j = (j + 2)))
			done
			dialog --clear \
				--erase-on-exit \
				--backtitle "插件" \
				--title "simple-obfs" \
				--ok-label "确定" \
				--no-cancel \
				--menu "请选择流量混淆方式" \
				0 0 0 \
				"${array[@]}" \
				2>&1 >/dev/tty
		)
		obfs=${obfs_rust[obfs - 1]}
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Which network traffic obfuscation you'd select"
		else
			Introduction "请选择流量混淆方式"
		fi
		select obfs in "${obfs_rust[@]}"; do
			if [ "$obfs" ]; then
				Prompt "$obfs"
				break
			fi
		done
	fi
}

V2ray_plugin() {
	Create_certificate

	unset -v v2ray_mode
	local mode_list=(websocket-http websocket-tls quic-tls grpc grpc-tls)
	if [ "$Dialog" = "enable" ]; then
		v2ray_mode=$(
			#https://stackoverflow.com/a/29912133
			declare -a array
			j=1
			k=1
			for i in "${mode_list[@]}"; do
				array[$j]=$k
				((k++))
				array[j + 1]=$i
				((j = (j + 2)))
			done
			dialog --clear \
				--erase-on-exit \
				--backtitle "插件" \
				--title "v2ray-plugin" \
				--ok-label "确定" \
				--no-cancel \
				--menu "请选择传输模式" \
				0 0 0 \
				"${array[@]}" \
				2>&1 >/dev/tty
		)
		v2ray_mode=${mode_list[v2ray_mode - 1]}
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Which Transport mode you'd select"
		else
			Introduction "请选择传输模式"
		fi
		select v2ray_mode in "${mode_list[@]}"; do
			if [ "$v2ray_mode" ]; then
				Prompt "$v2ray_mode"
				break
			fi
		done

	fi

	unset -v v2ray_path v2ray_servicename
	local v2ray_paths
	v2ray_paths=$(shasum -a1 /proc/sys/kernel/random/uuid)
	if [[ $v2ray_mode =~ "websocket-" ]]; then
		until [ "$v2ray_path" ]; do
			if [ "$Dialog" = "enable" ]; then
				v2ray_path=$(
					dialog --title "v2ray-plugin" \
						--backtitle "插件" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--no-cancel \
						--inputbox "请输入一个监听路径(url path): " \
						0 0 "${v2ray_paths%% *}" \
						2>&1 >/dev/tty
				)
			else
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "URL path for websocket"
				else
					Introduction "请输入一个监听路径(url path):"
				fi
				read -rp "(${mr:=默认}: ${v2ray_paths%% *}): " v2ray_path
				[ -z "$v2ray_path" ] && v2ray_path=${v2ray_paths%% *}
				#[ "${v2ray_path:0:1}" != "/" ] && v2ray_path="/$v2ray_path"
				Prompt "$v2ray_path"
			fi
			if ! echo "$v2ray_path" | grep -qoE '^[A-Za-z0-9]+$'; then
				unset -v v2ray_path
			fi
		done
	fi
	if [[ $v2ray_mode =~ "grpc" ]]; then
		until [ "$v2ray_servicename" ]; do
			if [ "$Dialog" = "enable" ]; then
				v2ray_servicename=$(
					dialog --title "v2ray-plugin" \
						--backtitle "插件" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--colors \
						--no-cancel \
						--inputbox "请输入gRPC服务的名称: " \
						0 0 "${v2ray_paths%% *}" \
						2>&1 >/dev/tty
				)
			else
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Service name for grpc"
				else
					Introduction "请输入gRPC服务的名称"
				fi
				read -rp "(${mr:=默认}: ${v2ray_paths%% *}): " v2ray_servicename
				[ -z "$v2ray_servicename" ] && v2ray_servicename=${v2ray_paths%% *}
				Prompt "$v2ray_servicename"
				if ! echo "$v2ray_servicename" | grep -qoE '^[A-Za-z0-9]+$'; then
					unset -v v2ray_servicename
				fi
			fi
		done
	fi
}

Kcptun_plugin() {
	Introduction "key"
	unset -v kcp_key
	read -rp "(${mr:=默认}: $password): " kcp_key
	[ -z "$kcp_key" ] && kcp_key="$password"
	Prompt "$kcp_key"

	unset -v kcp_crypt
	Introduction "crypt"
	local crypt_list=(aes aes-128 aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor sm4 none)
	select kcp_crypt in "${crypt_list[@]}"; do
		if [ "$kcp_crypt" ]; then
			Prompt "$kcp_crypt"
			break
		fi
	done

	unset -v kcp_mode
	Introduction "mode"
	local mode_list=(fast3 fast2 fast normal manual)
	select kcp_mode in "${mode_list[@]}"; do
		if [ "$kcp_mode" ]; then
			Prompt "$kcp_mode"
			break
		fi
	done

	unset -v kcp_mtu
	Introduction "mtu"
	read -rp "(${mr:=默认}: 1350): " kcp_mtu
	! is_number "$kcp_mtu" && kcp_mtu=1350
	Prompt "$kcp_mtu"

	unset -v kcp_sndwnd
	Introduction "sndwnd"
	read -rp "(${mr:=默认}: 512): " kcp_sndwnd
	! is_number "$kcp_sndwnd" && kcp_sndwnd=512
	Prompt "$kcp_sndwnd"

	unset -v kcp_rcvwnd
	Introduction "rcvwnd"
	read -rp "(${mr:=默认}: 512): " kcp_rcvwnd
	! is_number "$kcp_rcvwnd" && kcp_rcvwnd=512
	Prompt "$kcp_rcvwnd"

	unset -v kcp_datashard
	Introduction "datashard,ds"
	read -rp "(${mr:=默认}: 10): " kcp_datashard
	! is_number "$kcp_datashard" && kcp_datashard=10
	Prompt "$kcp_datashard"

	unset -v kcp_parityshard
	Introduction "parityshard,ps"
	read -rp "(${mr:=默认}: 3): " kcp_parityshard
	! is_number "$kcp_parityshard" && kcp_parityshard=3
	Prompt "$kcp_parityshard"

	unset -v kcp_dscp
	Introduction "dscp"
	read -rp "(${mr:=默认}: 0): " kcp_dscp
	! is_number "$kcp_dscp" && kcp_dscp=0
	Prompt "$kcp_dscp"

	unset -v kcp_nocomp
	Introduction "nocomp"
	select kcp_nocomp in true false; do
		if [ "$kcp_nocomp" ]; then
			Prompt "$kcp_nocomp"
			break
		fi
	done

	unset -v extra_parameters
	if [ "$kcp_mode" != "manual" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "After setting the basic parameters, do you need to set additional hidden parameters? [Y/n]"
		else
			Introduction "基础参数设置完成，你是否需要设置额外的隐藏参数? [Y/n]"
		fi
		read -rp "(${mr:=默认}: N): " extra_parameters
	fi
	if [[ $extra_parameters =~ ^[Yy]$ || $kcp_mode == "manual" ]]; then
		unset -v kcp_acknodelay
		Introduction "acknodelay"
		select kcp_acknodelay in true false; do
			if [ "$kcp_acknodelay" ]; then
				Prompt "$kcp_acknodelay"
				break
			fi
		done

		unset -v kcp_nodelay
		Introduction "nodelay"
		select kcp_nodelay in 0 1; do
			! is_number "$kcp_nodelay" && kcp_nodelay=0
			if [ "$kcp_nodelay" -ge 0 ] && [ "$kcp_nodelay" -le 1 ]; then
				Prompt "$kcp_nodelay"
				break
			fi
		done

		unset -v kcp_interval
		Introduction "interval"
		read -rp "(${mr:=默认}: 30): " kcp_interval
		! is_number "$kcp_interval" && kcp_interval=30
		Prompt "$kcp_interval"

		unset -v kcp_resend
		Introduction "resend"
		select kcp_resend in 0 1 2; do
			! is_number "$kcp_resend" && kcp_resend=2
			if [ "$kcp_resend" -ge 0 ] && [ "$kcp_resend" -le 2 ]; then
				Prompt "$kcp_resend"
				break
			fi
		done

		unset -v kcp_nc
		Introduction "nc"
		select kcp_nc in 0 1; do
			! is_number "$kcp_nc" && kcp_nc=1
			if [ "$kcp_nc" -ge 0 ] && [ "$kcp_nc" -le 1 ]; then
				Prompt "$kcp_nc"
				break
			fi
		done
	fi
	echo
}

Kcptun_plugin2() {
	unset -v kcp_crypt
	local crypt_list=(aes aes-128 aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor sm4 none)
	kcp_crypt=$(
		#https://stackoverflow.com/a/29912133
		declare -a array
		j=1
		k=1
		for i in "${crypt_list[@]}"; do
			array[$j]=$k
			((k++))
			array[j + 1]=$i
			((j = (j + 2)))
		done
		dialog --clear \
			--erase-on-exit \
			--backtitle "插件" \
			--title "kcptun" \
			--ok-label "确定" \
			--no-cancel \
			--default-item 13 \
			--menu "crypt" \
			0 0 0 \
			"${array[@]}" \
			2>&1 >/dev/tty
	)
	kcp_crypt=${crypt_list[kcp_crypt - 1]}
	unset -v kcp_mode
	local mode_list=(fast3 fast2 fast normal manual)
	kcp_mode=$(
		#https://stackoverflow.com/a/29912133
		declare -a array
		j=1
		k=1
		for i in "${mode_list[@]}"; do
			array[$j]=$k
			((k++))
			array[j + 1]=$i
			((j = (j + 2)))
		done
		dialog --clear \
			--erase-on-exit \
			--backtitle "插件" \
			--title "kcptun" \
			--ok-label "确定" \
			--no-cancel \
			--default-item 3 \
			--menu "mode" \
			0 0 0 \
			"${array[@]}" \
			2>&1 >/dev/tty
	)
	kcp_mode=${mode_list[kcp_mode - 1]}

	unset -v kcp_key kcp_mtu kcp_sndwnd kcp_rcvwnd kcp_datashard kcp_parityshard kcp_dscp
	# open fd
	exec 3>&1

	#https://stackoverflow.com/a/30248980
	IFS=$'\n' read -r -d '' kcp_key kcp_mtu kcp_sndwnd kcp_rcvwnd kcp_datashard kcp_parityshard kcp_dscp < <(dialog --clear \
		--erase-on-exit \
		--backtitle "插件" \
		--title "kcptun" \
		--ok-label "确定" \
		--no-cancel \
		--separate-widget $'\n' \
		--form "参数介绍 https://github.com/xtaci/kcptun#usage" \
		0 0 0 \
		"key:" 1 1 "$password" 1 25 35 0 \
		"mtu:" 2 1 1350 2 25 35 0 \
		"sndwnd:" 3 1 512 3 25 35 0 \
		"rcvwnd:" 4 1 512 4 25 35 0 \
		"datashard,ds:" 5 1 10 5 25 35 0 \
		"parityshard,ps:" 6 1 3 6 25 35 0 \
		"dscp:" 7 1 0 7 25 35 0 \
		2>&1 >/dev/tty)
	unset -v kcp_nocomp
	if dialog --clear --erase-on-exit \
		--title "kcptun" \
		--backtitle "插件" --yes-label "true" --no-label "false" --yesno "nocomp" 7 50; then
		kcp_nocomp="true"
	else
		kcp_nocomp="false"
	fi
	unset -v extra_parameters kcp_acknodelay kcp_nodelay kcp_interval kcp_resend kcp_nc
	if [ "$kcp_mode" != "manual" ]; then
		if dialog --clear --erase-on-exit --title "kcptun" --backtitle "插件" --yes-label "确定" --no-label "取消" --defaultno --yesno "基础参数设置完成，你是否需要设置额外的隐藏参数?" 7 50; then
			extra_parameters="Y"
		fi
	fi
	if [[ $extra_parameters =~ ^[Yy]$ || $kcp_mode == "manual" ]]; then
		if dialog --clear --erase-on-exit --title "kcptun" \
			--backtitle "插件" --yes-label "true" --no-label "false" --defaultno --yesno "acknodelay" 7 50; then
			kcp_acknodelay="true"
		else
			kcp_acknodelay="false"
		fi
		IFS=$'\n' read -r -d '' kcp_nodelay kcp_interval kcp_resend kcp_nc < <(dialog --clear \
			--erase-on-exit \
			--backtitle "插件" \
			--title "kcptun" \
			--ok-label "确定" \
			--no-cancel \
			--separate-widget $'\n' \
			--form "参数介绍 https://github.com/xtaci/kcptun#usage" \
			0 0 0 \
			"nodelay:" 1 1 0 1 25 35 0 \
			"interval:" 2 1 30 2 25 35 0 \
			"resend:" 3 1 2 3 25 35 0 \
			"nc:" 4 1 1 4 25 35 0 \
			2>&1 >/dev/tty)
	fi
	# close fd
	exec 3>&-
}

TimePickerDialog() {
	local expire_date expire_calendar expire_time
	while true; do
		#默认在当前日期+3天后
		if [ "$Dialog" = "enable" ]; then
			IFS='/' read -r -a expire_calendar <<<"$(
				dialog --title "使用期限" \
					--backtitle "访问控制" \
					--ok-label "确定" \
					--clear \
					--erase-on-exit \
					--no-cancel \
					--calendar "日期选择(单击选择&方向键调节):" \
					0 0 "$(date -d '+3 days' +'%d')" "$(date -d '+3 days' +'%m')" "$(date -d '+3 days' +'%Y')" \
					2>&1 >/dev/tty
			)"
			expire_time=$(
				dialog --title "使用期限" \
					--backtitle "访问控制" \
					--ok-label "确定" \
					--clear \
					--erase-on-exit \
					--no-cancel \
					--timebox "时间选择(单击选择&方向键调节):" \
					0 0 "$(date +'%H')" "$(date +'%M')" "$(date +'%S')" \
					2>&1 >/dev/tty
			)
			expire_timestamp=$(date -d "${expire_calendar[2]}-${expire_calendar[1]}-${expire_calendar[0]} $expire_time" +%s)
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter the port usage period. E.g.: $(date -d '+3 days' +'%Y-%m-%d %H:%M:%S') or $(date -d '+3 days' +'%Y/%m/%d')"
			else
				Introduction "请输入端口使用期限。如: $(date -d '+3 days' +'%Y-%m-%d %H:%M:%S')或$(date -d '+3 days' +'%Y/%m/%d')"
			fi
			read -rp "(${mr:=默认}: 0): " expire_date
			expire_timestamp=$(date -d "${expire_date:=error}" +%s 2>/dev/null)
		fi
		if ! is_number "$expire_timestamp" || [ "$expire_timestamp" -le 0 ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Prompt "No time limit on use"
			else
				Prompt "无时间使用限制"
			fi
			unset -v expire_timestamp
		else
			Prompt "$(date +'%Y-%m-%d %H:%M:%S' -d @"${expire_timestamp}")"
		fi
		break
	done
}

Speed_limit_input() {
	while true; do
		if [ "$Dialog" = "enable" ]; then
			#https://cloud.tencent.com/developer/article/1409664 一般只能限制网卡发送的数据包，不能限制网卡接收的数据包，所以可以通过改变发送次序来控制传输速率。Linux流量控制主要是在输出接口排列时进行处理和实现的。
			#脚本中实现上传限速是因为插件与ssserver在本地进行了转发。
			: <<'EOF'
#https://www.cnblogs.com/yrxing/p/14951947.html
控制入口流量
使用 TC 进行入口限流，需要把流量重定向到 ifb 虚拟网卡，然后在控制 ifb 的输出流量
# 开启 ifb 虚拟网卡
modprobe ifb numifbs=1
ip link set ifb0 up

# 将 eth0 流量重定向到 ifb0
tc qdisc add dev eth0 ingress handle ffff:
tc filter add dev eth0 parent ffff: protocol ip prio 0 u32 match u32 0 0 flowid ffff: action mirred egress redirect dev ifb0

# 然后就是限制 ifb0 的输出就可以了
# ......
EOF
			if [ "$add_plugin" ] && [ "$plugin" ]; then
				exec 3>&1
				IFS=$'\n' read -r -d '' upload_limit download_limit < <(dialog --clear \
					--erase-on-exit \
					--backtitle "访问控制" \
					--title "端口限速" \
					--ok-label "确定" \
					--no-cancel \
					--separate-widget $'\n' \
					--form "不需要使用限速的可以直接回车跳过。" \
					0 0 0 \
					"上传 (KB/s):" 1 1 0 1 20 15 0 \
					"下载 (KB/s):" 2 1 0 2 20 15 0 \
					2>&1 >/dev/tty)
				exec 3>&-
			else
				download_limit=$(
					dialog --title "端口限速" \
						--backtitle "访问控制" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--colors \
						--no-cancel \
						--inputbox "下载 (\Z5KB/s\Zn): " \
						0 0 0 \
						2>&1 >/dev/tty
				)
			fi
		else
			if [ "$add_plugin" ] && [ "$plugin" ]; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Please enter the port upload speed limit (KB/s)"
				else
					Introduction "请输入端口上传速度的限制值 (KB/s)"
				fi
				read -rp "(${mr:=默认}: 0): " upload_limit
				if ! is_number "$upload_limit" || [ "$upload_limit" -le 0 ]; then
					upload_limit=0
					if [ ${Language:=zh-CN} = 'en-US' ]; then
						Prompt "Uplink speed is not limited"
					else
						Prompt "上行速度未限制"
					fi
				fi
			fi
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter the port download speed limit (KB/s)"
			else
				Introduction "请输入端口下载速度的限制值 (KB/s)"
			fi
			read -rp "(${mr:=默认}: 0): " download_limit
			if ! is_number "$download_limit" || [ "$download_limit" -le 0 ]; then
				download_limit=0
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Prompt "Unrestricted downlink speed"
				else
					Prompt "下行速度未限制"
				fi
			fi
		fi
		if [ "${upload_limit:-0}" -gt 0 ] && [ "${download_limit:-0}" -gt 0 ]; then
			Prompt "▲ ${upload_limit:-0} KB/s | ▼ ${download_limit:-0} KB/s"
		else
			if [ "${upload_limit:-0}" -gt 0 ]; then
				Prompt "▲ ${upload_limit:-0} KB/s"
			fi
			if [ "${download_limit:-0}" -gt 0 ]; then
				Prompt "▼ ${download_limit:-0} KB/s"
			fi
		fi
		break
	done
}

Shadowsocks_info_input() {
	unset -v server_port password method plugin
	local sport
	while true; do
		sport=$(Generate_random_numbers 1024 65535)
		if [ "$Dialog" = "enable" ]; then
			server_port=$(
				dialog --title "端口" \
					--backtitle "Shadowsocks" \
					--ok-label "确定" \
					--clear \
					--erase-on-exit \
					--no-cancel \
					--inputbox "请输入Shadowsocks远程端口:" \
					0 0 "$sport" \
					2>&1 >/dev/tty
			)
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter a port"
			else
				Introduction "请输入Shadowsocks远程端口"
			fi
			read -rp "(${mr:=默认}: $sport): " -n5 server_port
			[ -z "$server_port" ] && server_port=$sport
		fi

		if is_number "$server_port" && [ "$server_port" -gt 0 ] && [ "$server_port" -le 65535 ]; then
			if is_number "$(Used_traffic "$server_port")"; then
				if [ "$Dialog" = "enable" ]; then
					dialog --title "提示" \
						--backtitle "Shadowsocks" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--no-cancel \
						--msgbox "端口正常使用中！" \
						0 0
				else
					if [ ${Language:=zh-CN} = 'en-US' ]; then
						Prompt "The port is in normal use!"
					else
						Prompt "端口正常使用中！"
					fi
				fi
				unset -v server_port
				continue
			fi
			if ss -ln state listening "( sport = :$server_port )" | grep -q ":$server_port "; then
				if [ "$Dialog" = "enable" ]; then
					dialog --title "提示" \
						--backtitle "Shadowsocks" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--no-cancel \
						--msgbox "端口被其它进程占用！" \
						0 0
				else
					if [ ${Language:=zh-CN} = 'en-US' ]; then
						Prompt "The port is occupied by another process!"
					else
						Prompt "端口被其它进程占用！"
					fi
				fi
				unset -v server_port
				continue
			fi
			if [ -s $HOME_DIR/port.list ]; then
				while IFS= read -r line || [ -n "$line" ]; do
					IFS='|'
					for l in $line; do
						if [ "${l#*^}" = "$server_port" ]; then
							if [ "$Dialog" = "enable" ]; then
								dialog --title "提示" \
									--backtitle "Shadowsocks" \
									--ok-label "确定" \
									--clear \
									--erase-on-exit \
									--no-cancel \
									--msgbox "端口已存在于端口列表中！" \
									0 0
							else
								if [ ${Language:=zh-CN} = 'en-US' ]; then
									Prompt "The port already exists in the port list!"
								else
									Prompt "端口已存在于端口列表中！"
								fi
							fi
							unset -v server_port
							continue 3
						fi
					done
				done <$HOME_DIR/port.list
			fi
			if [ "$server_port" ]; then
				Prompt "$server_port"
				break
			fi
		fi
	done
	if [ "$Dialog" = "enable" ]; then
		method=$(
			#https://stackoverflow.com/a/29912133
			declare -a array
			j=1
			k=1
			for i in "${Encryption_method_list[@]}"; do
				array[$j]=$k
				((k++))
				array[j + 1]=$i
				((j = (j + 2)))
			done
			dialog --clear \
				--erase-on-exit \
				--backtitle "Shadowsocks" \
				--title "加密方式" \
				--ok-label "确定" \
				--no-cancel \
				--default-item 2 \
				--menu "请选择Shadowsocks加密方式" \
				0 0 0 \
				"${array[@]}" \
				2>&1 >/dev/tty
		)
		method=${Encryption_method_list[method - 1]}
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Which cipher you'd select"
		else
			Introduction "请选择Shadowsocks加密方式"
		fi
		select method in "${Encryption_method_list[@]}"; do
			if [ "$method" ]; then
				Prompt "$method"
				break
			fi
		done
	fi
	local ciphertext spass cipher2022=0
	ciphertext=$(base64 -w0 /proc/sys/kernel/random/uuid)
	spass=${ciphertext:0:16}
	for i in "${Encryption_method_2022[@]}" "${Encryption_method_2022_extra[@]}"; do
		if [ "$i" = "$method" ]; then
			#32字节然后base64编码
			ciphertext=$(</proc/sys/kernel/random/uuid)
			if [ "$i" = "2022-blake3-aes-128-gcm" ]; then
				password=$(echo "${ciphertext:0:15}" | base64 -w0)
			else
				password=$(echo "${ciphertext:0:31}" | base64 -w0)
			fi
			cipher2022=1
			if [ "$Dialog" = "enable" ]; then
				dialog --title "提示" \
					--backtitle "Shadowsocks" \
					--ok-label "确定" \
					--clear \
					--erase-on-exit \
					--no-cancel \
					--msgbox "此加密方式的密码由本脚本生成暂时不提供自定义密码！" \
					0 0
			else
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Prompt "The password for this encryption method is generated by this script and no custom passwords are provided for now!"
				else
					Prompt "此加密方式的密码由本脚本生成暂时不提供自定义密码！"
				fi
			fi
		fi
	done
	if [ "$Dialog" = "enable" ]; then
		if [ "$cipher2022" -eq 0 ]; then
			until [ "$password" ]; do
				password=$(dialog --title "密码" \
					--backtitle "Shadowsocks" \
					--ok-label "确定" \
					--clear \
					--erase-on-exit \
					--insecure \
					--no-cancel \
					--passwordbox "请输入Shadowsocks密码:" \
					0 0 "$spass" \
					2>&1 >/dev/tty)
			done
		fi
	else
		if [ "$cipher2022" -eq 0 ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter a password"
			else
				Introduction "请输入Shadowsocks密码"
			fi
			read -rp "(${mr:=默认}: $spass): " password
			[ -z "$password" ] && password=$spass
			Prompt "$password"
		fi
	fi
	local add_flow_limit
	if [ "$Dialog" = "enable" ]; then
		if dialog --clear --erase-on-exit --title "流量" \
			--backtitle "Shadowsocks" --yes-label "确定" --no-label "取消" --defaultno --yesno "需要限制这个端口的可用流量吗?" 7 50; then
			add_flow_limit="Y"
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Do you need to limit the traffic available on this port? [Y/n]"
		else
			Introduction "需要限制这个端口的可用流量吗? [Y/n]"
		fi
		read -rp "(${mr:=默认}: N): " add_flow_limit
	fi
	if [[ $add_flow_limit =~ ^[Yy]$ ]]; then
		while true; do
			if [ "$Dialog" = "enable" ]; then
				total=$(
					dialog --title "流量" \
						--backtitle "Shadowsocks" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--colors \
						--no-cancel \
						--inputbox "请输入端口流量配额 (\Z5MB\Zn): " \
						0 0 0 \
						2>&1 >/dev/tty
				)
			else
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Please enter a value for the traffic limit (MB)"
				else
					Introduction "请输入端口流量配额 (MB)"
				fi
				read -rp "(${mr:=默认}: 0): " total
			fi
			if ! is_number "$total" || [ "$total" -lt 0 ]; then
				total=0
			fi
			break
		done
		if [ "$total" -gt 0 ]; then
			Prompt "$total MB"
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Prompt "Unlimited traffic"
			else
				Prompt "流量未限制"
			fi
		fi
	else
		total=0
	fi
	local add_auto_reset reset_type_list tips3 tips4
	if [ "$Dialog" = "enable" ]; then
		if dialog --clear --erase-on-exit --title "流量" \
			--backtitle "Shadowsocks" --yes-label "确定" --no-label "取消" --defaultno --yesno "需要自动清空端口的流量记录值吗?" 7 50; then
			add_auto_reset="Y"
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Do you need to clear port traffic logs automatically? [Y/n]"
		else
			Introduction "需要自动清空端口的流量记录值吗? [Y/n]"
		fi
		read -rp "(${mr:=默认}: N): " add_auto_reset
	fi
	if [[ $add_auto_reset =~ ^[Yy]$ ]]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			reset_type_list=(
				specify
				periodic
			)
		else
			reset_type_list=(
				固定日期
				周期性
			)
		fi
		if [ "$Dialog" = "enable" ]; then
			reset_type=$(
				#https://stackoverflow.com/a/29912133
				declare -a array
				j=1
				k=1
				for i in "${reset_type_list[@]}"; do
					array[$j]=$k
					((k++))
					array[j + 1]=$i
					((j = (j + 2)))
				done
				dialog --clear \
					--erase-on-exit \
					--backtitle "Shadowsocks" \
					--title "流量" \
					--ok-label "确定" \
					--no-cancel \
					--menu "请选择端口流量重置类型" \
					0 0 0 \
					"${array[@]}" \
					2>&1 >/dev/tty
			)
			reset_type=${reset_type_list[reset_type - 1]}
		else
			Introduction "请选择端口流量重置类型"
			select reset_type in "${reset_type_list[@]}"; do
				if [ "$reset_type" ]; then
					Prompt "$reset_type"
					break
				fi
			done
		fi
		if [ "$reset_type" = "specify" ] || [ "$reset_type" = "固定日期" ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				tips3="On what day of the month do you clear the traffic records of this port?"
			else
				tips3="每月的几号清理这个端口的流量记录?"
			fi
			reset_type="specify"
		elif [ "$reset_type" = "periodic" ] || [ "$reset_type" = "周期性" ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				tips3="How many days per month do you clear the traffic records of this port?"
			else
				tips3="每月间隔几日清理这个端口的流量记录？"
			fi
			reset_type="periodic"
		fi
		while true; do
			if [ "$Dialog" = "enable" ]; then
				reset_day=$(
					dialog --title "流量" \
						--backtitle "Shadowsocks" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--colors \
						--no-cancel \
						--inputbox "$tips3" \
						0 0 1 \
						2>&1 >/dev/tty
				)
			else
				Introduction "$tips3"
				read -rp "(${mr:=默认}: 1): " reset_day
				[ -z "$reset_day" ] && reset_day=1
			fi
			if is_number "$reset_day" && [ "$reset_day" -gt 0 ] && [ "$reset_day" -le 31 ]; then
				break
			fi
		done
		if [ "$reset_day" ]; then
			if [ "$reset_type" = "specify" ]; then
				tips4="$reset_day"
			elif [ "$reset_type" = "periodic" ]; then
				tips4="$(eval "echo {$reset_day..31..$reset_day}")"
			fi
		fi
		if [ "$Dialog" = "enable" ]; then
			dialog --title "提示" \
				--backtitle "Shadowsocks" \
				--ok-label "确定" \
				--clear \
				--erase-on-exit \
				--no-cancel \
				--msgbox "$tips4" \
				0 0
		else
			Prompt "$tips4"
		fi
		: <<'EOF'
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No automatic clearing of port traffic log values"
		else
			Prompt "不自动清空端口流量记录值"
		fi
EOF
	fi
	local add_plugin
	if [ "$Dialog" = "enable" ]; then
		if dialog --clear --erase-on-exit --title "插件" \
			--backtitle "Shadowsocks" --yes-label "确定" --no-label "取消" --defaultno --yesno "需要加装插件吗?" 7 50; then
			add_plugin="Y"
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Do you need to add a plugin? [Y/n]"
		else
			Introduction "需要加装插件吗? [Y/n]"
		fi
		read -rp "(${mr:=默认}: N): " add_plugin
	fi
	if [[ $add_plugin =~ ^[Yy]$ ]]; then
		plugin_list=(simple-obfs kcptun v2ray-plugin)
		if [ "$Dialog" = "enable" ]; then
			plugin=$(
				#https://stackoverflow.com/a/29912133
				declare -a array
				j=1
				k=1
				for i in "${plugin_list[@]}"; do
					array[$j]=$k
					((k++))
					array[j + 1]=$i
					((j = (j + 2)))
				done
				dialog --clear \
					--erase-on-exit \
					--backtitle "Shadowsocks" \
					--title "插件" \
					--ok-label "确定" \
					--no-cancel \
					--menu "请选择需要加装的插件" \
					0 0 0 \
					"${array[@]}" \
					2>&1 >/dev/tty
			)
			plugin=${plugin_list[plugin - 1]}
		else
			Introduction "请选择需要加装的插件"
			select plugin in "${plugin_list[@]}"; do
				if [ "$plugin" ]; then
					Prompt "$plugin"
					break
				fi
			done
		fi
		if [ "$plugin" = 'simple-obfs' ]; then
			Obfs_plugin
		elif [ "$plugin" = 'kcptun' ]; then
			if [ "$Dialog" = "enable" ]; then
				Kcptun_plugin2
			else
				Kcptun_plugin
			fi
		elif [ "$plugin" = 'v2ray-plugin' ]; then
			V2ray_plugin
		fi
		: <<'EOF'
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No plug-in"
		else
			Prompt "未加装插件"
		fi
EOF
	fi
	local add_speed_limit
	if [ "$Dialog" = "enable" ]; then
		if dialog --clear --erase-on-exit --title "限速" \
			--backtitle "Shadowsocks" --yes-label "确定" --no-label "取消" --defaultno --yesno "需要限制这个端口的网速吗?" 7 50; then
			add_speed_limit="Y"
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Do you need to limit the internet speed on this port? [Y/n]"
		else
			Introduction "需要限制这个端口的网速吗? [Y/n]"
		fi
		read -rp "(${mr:=默认}: N): " add_speed_limit
	fi
	if [[ $add_speed_limit =~ ^[Yy]$ ]]; then
		Speed_limit_input
	else
		upload_limit=0
		download_limit=0
		: <<'EOF'
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Port network speed is not limited"
		else
			Prompt "端口网速未限制"
		fi
EOF
	fi
	local add_date_limit
	if [ "$Dialog" = "enable" ]; then
		if dialog --clear --erase-on-exit --title "使用期限" \
			--backtitle "访问控制" --yes-label "确定" --no-label "取消" --defaultno --yesno "需要设置指定日期后删除这个端口吗?" 7 50; then
			add_date_limit="Y"
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Do you need to set a specific date to delete this port afterwards? [Y/n]"
		else
			Introduction "需要设置指定日期后删除这个端口吗? [Y/n]"
		fi
		read -rp "(${mr:=默认}: N): " add_date_limit
	fi
	if [[ $add_date_limit =~ ^[Yy]$ ]]; then
		TimePickerDialog
	fi
}

Interface_Traffic() (
	i=0
	while IFS= read -r line; do
		((i++))
		[ "$i" -le 2 ] && continue
		#unset -v Inter Receive Transmit
		IFS=' '
		x=0
		for l in $line; do
			((x++))
			case $x in
			1)
				Inter=$l
				;;
			2)
				Receive=$l
				;;
			10)
				Transmit=$l
				break
				;;
			esac
		done
		if [ "$Inter" = "${1}:" ]; then
			echo "${Inter%:*}" "$Receive" "$Transmit"
			break
		fi
	done </proc/net/dev
)

Client_Quantity() (
	i=0
	while IFS= read -r line; do
		((i++))
		[ "$i" -le 1 ] && continue #仅跳出当前循环
		unset -v recv send local_address foreign_address
		IFS=' '
		x=0
		for l in $line; do
			((x++))
			case $x in
			1)
				#recv=$l
				;;
			2)
				#send=$l
				;;
			3)
				local_address=$l
				;;
			4)
				foreign_address=$l
				break
				;;
			esac
		done
		if [ "${local_address##*:}" = "$1" ]; then
			array_reme+=("${foreign_address%:*}")
		fi
	done <"$net_file"
	IFS=' ' read -r -a uniq <<<"$(printf '%s\n' "${array_reme[@]}" | sort -u | tr '\n' ' ')"
	if [ "${#uniq[*]}" -ge 1 ]; then
		printf '%d' "${#uniq[@]}"
	fi
)

User_list_display() {
	local plugin_opt color temp_file net_file client_file serial port tz a1 a2 a3 a4 a5 a6 a7 a8 a9 quantity flow used status total expire_timestamp upload_limit download_limit up down b1=0 b2=0 b3=0
	if [ ${runing:-false} = true ]; then
		while true; do
			clear
			temp_file='/dev/shm/sslist.tmp'
			net_file='/dev/shm/ssnet.tmp'
			client_file=${HOME_DIR:?}/ss_traffic.stat
			if [ -s $HOME_DIR/port.list ]; then
				ss -tn state established >"$net_file"
				serial=0
				#修复无法读取到最后一行的历史问题 https://stackoverflow.com/a/12916758
				while IFS= read -r line || [ -n "$line" ]; do
					Parsing_User "$line"
					if [ "$server_port" ]; then
						if [[ $plugin != "kcptun.sh" && $plugin_opts != *quic* ]]; then
							quantity=$(Client_Quantity "$server_port")
							((b3 = b3 + quantity))
						else
							quantity='[yellow]X'
						fi
						flow=$(Used_traffic "$server_port" "$client_file")
						((serial++))
						if is_number "$flow" && [ "${flow:=0}" -ge 0 ]; then
							if [ ${Language:=zh-CN} = 'en-US' ]; then
								status='[green]Normal'
							else
								status='[green]正常'
							fi
							tz=no
							((b1++))
						else
							if [ ${Language:=zh-CN} = 'en-US' ]; then
								status='[red]Close'
							else
								status='[red]停止'
							fi
							tz=yes
						fi
						used=$((${flow:=0} + ${used_traffic:=0}))
						((b2 = b2 + used))
						if [ "$plugin" = "obfs-server" ]; then
							plugin='simple-obfs'
							plugin_opt=$(Parsing_plugin_opts "$plugin_opts" "obfs")
						elif [ "$plugin" = "kcptun.sh" ]; then
							plugin='kcptun'
							plugin_opt=$(Parsing_plugin_opts "$plugin_opts" "mode")
						elif [ "$plugin" = "v2ray-plugin" ]; then
							plugin='v2ray'
							case $plugin_opts in
							*'mode=grpc;tls;'*)
								plugin_opt='grpcs'
								;;
							*'mode=grpc;'*)
								plugin_opt='grpc'
								;;
							*'mode=quic;'*)
								plugin_opt='quic'
								;;
							*'server;tls;'*)
								plugin_opt='wss'
								;;
							*)
								plugin_opt='ws'
								;;
							esac
						fi
						[ -z "$total" ] && total=0
						if [ $total -gt 0 ]; then
							if [ $used -le "$total" ]; then
								color=$((used * 100 / total))
								if [ "$color" -ge 75 ] && [ "$color" -le 100 ]; then
									color="[red]$color %"
								elif [ "$color" -ge 50 ] && [ "$color" -le 75 ]; then
									color="[yellow]$color %"
								elif [ "$color" -ge 25 ] && [ "$color" -le 50 ]; then
									color="[green]$color %"
								elif [ "$color" -ge 0 ] && [ "$color" -le 25 ]; then
									color="[blue]$color %"
								fi
							else
								color="[red]??"
							fi
						fi
						if [ "$tz" = "yes" ]; then
							a1="[italic strike bold red]${serial:-0}"
							a2="[strike bold red]${server_port:-0}"
							if [ $total -eq 0 ]; then
								a4="[strike bold red]$(Traffic $used)"
							else
								a4="[strike bold red]$(Traffic $used) / $(Traffic $total)"
							fi
						else
							a1="[italic]${serial:-0}"
							a2="${server_port:-0}"
							if [ $total -eq 0 ]; then
								a4="$(Traffic $used)"
							else
								a4="$(Traffic $used) / $(Traffic $total)"
							fi
						fi
						if [ "$plugin_opt" ]; then
							a3="${plugin}[white bold]/[#00ffff]${plugin_opt}"
						else
							a3="$plugin"
						fi
						#a5="${color:-∞}"
						a5="$color"
						a6="$expire_timestamp"
						if [ "${a6:-0}" -gt 0 ]; then
							a6=$(date +'%Y/%m/%d %H:%M:%S' -d @"${a6}")
						fi
						#因为用户输入的时候是用kB为记录单位和函数需要以B为输入值所以需要转换
						if [ "${upload_limit:-0}" -gt 0 ]; then
							up="[bold green]▲[/bold green] $(Traffic $((${upload_limit:-0} * 1024)))/s"
						fi
						if [ "${download_limit:-0}" -gt 0 ]; then
							down="[bold yellow]▼[/bold yellow] $(Traffic $((${download_limit:-0} * 1024)))/s"
						fi
						if [ "$up" ] && [ "$down" ]; then
							a7="${up} [bold]|[/bold] ${down}"
						else
							a7="${up}${down}"
						fi
						a8="$quantity"
						a9="$status"
						echo "$a1,$a2,$a3,$a4,$a5,$a6,$a7,$a8,$a9" >>"$temp_file"
					fi
					unset -v quantity flow used status color tz plugin_opt a1 a2 a3 a4 a5 a6 a7 a8 a9 up down
				done <$HOME_DIR/port.list
			fi
			if [ -s "$temp_file" ] && is_number "$b1"; then
				echo "[b][u]$b1,,,[b][u]$(Traffic $b2),,,,[b][u]$b3," >>"$temp_file"
				unset -v b1 b2 b3
			fi
			${python:-python3} <<-EOF
				from rich.console import Console
				from rich.columns import Columns
				from rich.panel import Panel
				from rich.table import Table
				from os import path, remove
				console = Console()
				def menu1():
				  if "${Language:=zh-CN}" == 'en-US':
				    return f"1. Add a Port->>\n2. Delete a Port\n3. Activate a port\n4. Forcing a Port offline\n5. Empty traffic"
				  else:
				    return f"1. 添加端口\n2. 删除端口\n3. 激活端口\n4. 离线端口\n5. 清空流量"
				if path.exists("$temp_file") and path.getsize("$temp_file") > 0:
				  if "${Language:=zh-CN}" == 'zh-CN':
				    table = Table(title="用户列表", caption="$(TZ='Asia/Shanghai' date +%Y年%m月%d日\ %X)", show_lines=True)
				    table.add_column("序号", justify="left", no_wrap=True)
				    table.add_column("端口", justify="center", style="#66ccff")
				    table.add_column("传输插件", justify="center", style="#ee82ee", no_wrap=True)
				    table.add_column("流量", justify="center")
				    table.add_column("使用率", justify="center")
				    table.add_column("过期时间", justify="center")
				    table.add_column("限速", justify="center")
				    table.add_column("连接数", justify="center")
				    table.add_column("状态", justify="right")
				  else:
				    table = Table(title="User List", caption="$(date +'%A %B %d %T %y')", show_lines=True)
				    table.add_column("Top", justify="left", no_wrap=True)
				    table.add_column("Port", justify="center", style="#66ccff")
				    table.add_column("Plug-in", justify="center", style="#ee82ee", no_wrap=True)
				    table.add_column("Network traffic", justify="center")
				    table.add_column("Usage rate", justify="center")
				    table.add_column("Expiration time", justify="center")
				    table.add_column("Speed limit", justify="center")
				    table.add_column("Client", justify="center")
				    table.add_column("Status", justify="right")
				  with open("$temp_file", 'r', encoding='utf8') as fd:
				    for lines in fd.read().splitlines():
				      a, b, c, d, e, f, g, h, i = lines.split(',')
				      table.add_row(a, b, c, d, e, f, g, h, i)
				  remove("$net_file")
				  remove("$temp_file")
				  console.print(table, justify="center")
				if "${Language:=zh-CN}" == 'en-US':
				  title1 = [Panel(menu1(), expand=True, title="Menu")]
				else:
				  title1 = [Panel(menu1(), expand=True, title="菜单")]
				console.print(Columns(title1))
			EOF
			#rm -f "$net_file" "$temp_file"
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				read -rp $'Please enter a number \e[95m1-5\e[0m: ' -n1 action
			else
				read -rp $'请选择 \e[95m1-5\e[0m: ' -n1 action
			fi
			echo
			case $action in
			1)
				Add_user
				Reload_tc_limit
				;;
			2)
				Delete_users Delete
				Reload_tc_limit
				;;
			3)
				while true; do
					if [ ${Language:=zh-CN} = 'en-US' ]; then
						Introduction "Please enter the port to be activated"
					else
						Introduction "请输入需要激活的端口"
					fi
					read -rn5 port
					if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
						Upload_users "$port"
						Reload_tc_limit
						break
					fi
				done
				;;
			4)
				Delete_users Offline
				Reload_tc_limit
				;;
			5)
				Delete_users Empty
				Reload_tc_limit
				;;
			*)
				break
				;;
			esac
		done
	else
		if [ "${Language:=zh-CN}" = "en-US" ]; then
			Prompt "Service is stopped please start running first!"
		else
			Prompt "服务已停止请先启动运行!"
		fi
		Press_any_key_to_continue
	fi
}

Add_user() {
	Generate_random_uuid
	Address_lookup
	Shadowsocks_info_input
	if [ "$Dialog" = "enable" ]; then
		if ! dialog --clear --erase-on-exit --title "确认" \
			--backtitle "完成" --yes-label "确定" --no-label "取消" --yesno "输入已完成如输入错误请按取消结束本次操作！" 0 0; then
			Exit
		fi
	else
		Press_any_key_to_continue
	fi
	clear
	local userinfo traffic1 timestamp qrv4 qrv6 name plugin_url ss_info=() ss_link=() err_code=0
	if [ "$my_ipv4" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			ss_info+=("Your_Server_IP(IPv4)+$my_ipv4")
		else
			ss_info+=("服务器(IPv4)+$my_ipv4")
		fi
	fi
	if [ "$my_ipv6" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			ss_info+=("Your_Server_IP(IPv6)+$my_ipv6")
		else
			ss_info+=("服务器(IPv6)+$my_ipv6")
		fi
	fi
	if [ "$my_ipv4" ] || [ "$my_ipv6" ]; then
		userinfo="$(echo -n "$method:$password" | base64 -w0 | sed 's/=//g; s/+/-/g; s/\//_/g')"
		#websafe-base64-encode-utf8 不兼容标准的的base64
		#https://www.liaoxuefeng.com/wiki/1016959663602400/1017684507717184
	fi
	name=$(Url_encode "$addr")
	if [ "${Language:=zh-CN}" = 'en-US' ]; then
		ss_info+=("Your_Server_Port+$server_port")
		ss_info+=("Your_Password+$password")
		ss_info+=("Your_Encryption_Method+$method")
	else
		ss_info+=("远程端口+$server_port")
		ss_info+=("密码+$password")
		ss_info+=("加密方式+$method")
	fi
	case $plugin in
	simple-obfs)
		if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\",\"plugin\":\"obfs-server\",\"plugin_opts\":\"obfs=$obfs\"}" >/dev/null; then
			echo "server_port^$server_port|password^$password|method^$method|plugin^obfs-server|plugin_opts^obfs=$obfs|used_traffic^0|total^$((total * 1048576))|reset_day^$reset_day|reset_type^$reset_type|expire_timestamp^$expire_timestamp|upload_limit^$upload_limit|download_limit^$download_limit|user_id^$userid" >>$HOME_DIR/port.list
		else
			err_code=1
		fi
		plugin_url="/?plugin=$(Url_encode "obfs-local;obfs=$obfs;obfs-host=pull.free.video.10010.com")"
		;;
	kcptun)
		local kcp_nocomps kcp_acknodelays
		[ "$kcp_nocomp" = "true" ] && kcp_nocomps=';nocomp'             #除安卓版kcptun客户端外其它客户端需要将插件参数配置为nocomp=true强烈推荐使用订阅方式获取节点账号
		[ "$kcp_acknodelay" = "true" ] && kcp_acknodelays=';acknodelay' #这里也是如上所述
		if [[ $extra_parameters =~ ^[Yy]$ ]]; then
			if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun.sh\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays\"}" >/dev/null; then
				echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun.sh|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays|used_traffic^0|total^$((total * 1048576))|reset_day^$reset_day|reset_type^$reset_type|expire_timestamp^$expire_timestamp|upload_limit^$upload_limit|download_limit^$download_limit|user_id^$userid" >>$HOME_DIR/port.list
			else
				err_code=1
			fi
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays")"
		else
			if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun.sh\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps\"}" >/dev/null; then
				echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun.sh|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps|used_traffic^0|total^$((total * 1048576))|reset_day^$reset_day|reset_type^$reset_type|expire_timestamp^$expire_timestamp|upload_limit^$upload_limit|download_limit^$download_limit|user_id^$userid" >>$HOME_DIR/port.list
			else
				err_code=1
			fi
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps")"
		fi
		;;
	v2ray-plugin)
		local v2ray_modes v2ray_certraw v2ray_client qui
		v2ray_certraw=$(sed '1d;$d' $tls_cert)
		case $v2ray_mode in
		websocket-http)
			v2ray_modes="server;path=$v2ray_path;host=$tls_common_name"
			v2ray_client="path=$v2ray_path;host=$tls_common_name"
			;;
		websocket-tls)
			v2ray_modes="server;tls;path=$v2ray_path;host=$tls_common_name;key=$tls_key;cert=$tls_cert"
			v2ray_client="tls;path=$v2ray_path;host=$tls_common_name;certRaw=$v2ray_certraw"
			;;
		quic-tls)
			v2ray_modes="server;mode=quic;host=$tls_common_name;key=$tls_key;cert=$tls_cert"
			v2ray_client="mode=quic;host=$tls_common_name;certRaw=$v2ray_certraw"
			qui='tcp_only'
			;;
		grpc)
			v2ray_modes="server;mode=grpc;host=$tls_common_name;serviceName=$v2ray_servicename"
			v2ray_client="mode=grpc;host=$tls_common_name;serviceName=$v2ray_servicename"
			;;
		grpc-tls)
			v2ray_modes="server;mode=grpc;tls;host=$tls_common_name;serviceName=$v2ray_servicename;key=$tls_key;cert=$tls_cert"
			v2ray_client="tls;mode=grpc;host=$tls_common_name;serviceName=$v2ray_servicename;certRaw=$v2ray_certraw"
			;;
		esac
		if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"${qui:=tcp_and_udp}\",\"plugin\":\"v2ray-plugin\",\"plugin_opts\":\"$v2ray_modes\"}" >/dev/null; then
			echo "server_port^$server_port|password^$password|method^$method|plugin^v2ray-plugin|plugin_opts^$v2ray_modes|used_traffic^0|total^$((total * 1048576))|reset_day^$reset_day|reset_type^$reset_type|expire_timestamp^$expire_timestamp|upload_limit^$upload_limit|download_limit^$download_limit|user_id^$userid" >>$HOME_DIR/port.list
		else
			err_code=1
		fi
		plugin_url="/?plugin=$(Url_encode "v2ray-plugin;$v2ray_client")"
		;;
	*)
		if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\"}" >/dev/null; then
			echo "server_port^$server_port|password^$password|method^$method|plugin^|plugin_opts^|used_traffic^0|total^$((total * 1048576))|reset_day^$reset_day|reset_type^$reset_type|expire_timestamp^$expire_timestamp|upload_limit^$upload_limit|download_limit^$download_limit|user_id^$userid" >>$HOME_DIR/port.list
		else
			err_code=1
		fi
		;;
	esac
	Check_permissions
	if [ "$plugin" ]; then
		if [ "${Language:=zh-CN}" == 'en-US' ]; then
			ss_info+=("Your_Transport_Plugin+$plugin")
		else
			ss_info+=("传输插件+$plugin")
		fi
	fi
	if is_number "$total" && [ "$total" -gt 0 ]; then
		traffic1=$(Traffic $((total * 1048576)))
		if [ "${Language:=zh-CN}" == 'en-US' ]; then
			ss_info+=("Available_traffic+${traffic1// //}")
		else
			ss_info+=("可用流量+${traffic1// //}")
		fi
	fi
	if is_number "$expire_timestamp" && [ "$expire_timestamp" -gt 0 ]; then
		timestamp=$(date +'%Y/%m/%d %H:%M:%S' -d @"${expire_timestamp}" 2>/dev/null)
		if [ "${Language:=zh-CN}" == 'en-US' ]; then
			ss_info+=("Expiration_time+${timestamp// /-}")
		else
			ss_info+=("过期时间+${timestamp// /-}")
		fi
	fi
	if [ "${upload_limit:-0}" -gt 0 ]; then
		if [ "${Language:=zh-CN}" = 'en-US' ]; then
			ss_info+=("Uplink_speed_imit+${upload_limit}KB/s")
		else
			ss_info+=("上行速度限制+${upload_limit}KB/s")
		fi
	fi
	if [ "${download_limit:-0}" -gt 0 ]; then
		if [ "${Language:=zh-CN}" = 'en-US' ]; then
			ss_info+=("Downstream_speed_limit+${download_limit}KB/s")
		else
			ss_info+=("下行速度限制+${download_limit}KB/s")
		fi
	fi
	if [ "$plugin" ]; then
		if [ "$userinfo" ] && [ "$my_ipv4" ]; then
			qrv4="ss://$userinfo@$my_ipv4:$server_port$plugin_url#$name"
			ss_link+=("$qrv4")
		fi
		if [ "$userinfo" ] && [ "$my_ipv6" ]; then
			qrv6="ss://$userinfo@[${my_ipv6}]:$server_port$plugin_url#$name"
			ss_link+=("$qrv6")
		fi
	else
		if [ "$userinfo" ] && [ "$my_ipv4" ]; then
			qrv4="ss://$userinfo@$my_ipv4:$server_port#$name"
			ss_link+=("$qrv4")
		fi
		if [ "$userinfo" ] && [ "$my_ipv6" ]; then
			qrv6="ss://$userinfo@[${my_ipv6}]:$server_port#$name"
			ss_link+=("$qrv6")
		fi
	fi
	if [ "$err_code" -eq 0 ]; then
		${python:-python3} <<-EOF
			    #-*-coding:utf-8 -*-
				from rich import print as rprint
				from rich.console import group
				from rich.panel import Panel
				from rich.table import Table
				from random import choice
				from os import get_terminal_size
				from os.path import exists

				list1 = ['#66ccff', '#ee82ee', '#39c5bb', '#ffc0cb', '#ffff00', '#ee0000', '#00ffcc', '#9999ff', '#ff4004', '#3399ff', '#0080ff', '#006666']

				ss_message = Table.grid(padding=1)
				ss_message.add_column(style="bold", justify="left")
				ss_message.add_column(no_wrap=True, style="bold red")
				arr = "${ss_info[@]}"
				list2 = []
				for ss in arr.split(' '):
				  color = 'bold ' + choice(list1)
				  key, val = ss.split('+')
				  ss_message.add_row(
				    key.replace('_', ' '),
				    '[bold ' + color + ']' + val
				  )

				@group()
				def get_panels():
				    color = 'bold ' + choice(list1)
				    yield Panel(ss_message, style=color)
				    arr = "${ss_link[@]}"      
				    for link in arr.split(' '):
				      #color = 'italic bold on ' + choice(list1)
				      color = 'bold ' + choice(list1)
				      #https://xrlin.github.io/使用textwrap模块进行字符串的指定宽度输出/
				      if len(link) <= get_terminal_size().columns:
				        yield Panel(link, style=color)
				      else:
				        list2.append(link)
				    tips1 = "强烈推荐使用订阅功能！"
				    tips2 = "Android客户端和插件下载地址: https://gitlab.com/yiguihai/ss/-/wikis/客户端下载"
				    if exists("$HOME_DIR/web/subscriptions.php"):
				      yield Panel(tips2)
				    else:
				      yield Panel(tips1+tips2)
				if "${Language:=zh-CN}" == 'zh-CN':
				  rprint(Panel(get_panels(), title="配置信息", subtitle="以上信息请拿笔记好！"))
				else:
				  rprint(Panel(get_panels(), title="Configuration Information", subtitle="Please take note of the above information!"))
				for x in list2:
				  print('\n\033[4;1;35m'+x+'\033[0m')
		EOF
		if [ "$v2ray_modes" ] && [ "$v2ray_modes" != "quic-tls" ]; then
			Reload_nginx
		fi
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Do you still need to display QR codes and client profiles?"
		else
			Introduction "需要显示二维码和客户端配置文件吗？ [Y/n]"
		fi
		read -rp "(${mr:=默认}: N): " qrv
		if [[ $qrv =~ ^[Yy]$ ]]; then
			clear
			local temp_file
			temp_file=$(mktemp)
			if [ "$qrv4" ]; then
				ssurl -d "$qrv4" 1>"$temp_file"
				${python:-python3} -m rich.json "$temp_file"
				qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv4"
			fi
			if [ "$qrv6" ]; then
				ssurl -d "$qrv6" 1>"$temp_file"
				${python:-python3} -m rich.json "$temp_file"
				qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv6"
			fi
			rm -f "$temp_file"
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "An unknown error has occurred!"
		else
			Prompt "出现未知错误！"
		fi
	fi
	Press_any_key_to_continue
}

Delete_users() {
	if [ -s $HOME_DIR/port.list ]; then
		local temp_file pz1 pz2 flow port
		is_number "$2" && port=$2
		until [ "$port" ]; do
			if [ "$1" = "Offline" ]; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Please enter the port of the user who needs to be forced offline"
				else
					Introduction "请输入需要离线的端口"
				fi
			elif [ "$1" = "Delete" ]; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Please enter the user port to be deleted"
				else
					Introduction "请输入需要删除的端口"
				fi
			elif [ "$1" = "Empty" ]; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Please enter the port that needs to be cleared of traffic"
				else
					Introduction "请输入需要清空流量的端口"
				fi
			fi
			read -rn5 port
			if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
				break
			else
				unset -v port
			fi
		done
		temp_file='/dev/shm/ssdel.tmp'
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			if is_number "$server_port" && is_number $total; then
				if [ "$server_port" -eq "$port" ]; then
					flow=$(Used_traffic "$server_port")
					used_traffic=$((${flow:=0} + ${used_traffic:=0}))
					unset -v flow
					ss-tool /tmp/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
					rm -f ${HOME_DIR}/pid/shadowsocks-server-"${port}".pid ${HOME_DIR}/pid/shadowsocks-server-"${port}".json
					pz1=$plugin
					pz2=$plugin_opts
					if [ "$1" = "Delete" ]; then
						continue
					fi
					if [ "$1" = "Empty" ] || [ "$3" = "Zero" ]; then
						used_traffic=0
					fi
				fi
				if [ "$server_port" ] && [ "$password" ] && [ "$method" ]; then
					echo "server_port^$server_port|password^$password|method^$method|plugin^$plugin|plugin_opts^$plugin_opts|used_traffic^$used_traffic|total^$total|reset_day^$reset_day|reset_type^$reset_type|expire_timestamp^$expire_timestamp|upload_limit^$upload_limit|download_limit^$download_limit|user_id^$user_id" >>"$temp_file"
				fi
			fi
		done <$HOME_DIR/port.list
		rm -f $HOME_DIR/port.list
		if [ -s $temp_file ]; then
			mv -f "$temp_file" $HOME_DIR/port.list
			echo
			Check_permissions
			if [[ $pz1 == "v2ray-plugin" && $pz2 != *quic* ]]; then
				Reload_nginx
			fi
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No port list file found"
		else
			Prompt "没有找到端口列表文件"
		fi
		Press_any_key_to_continue
	fi
}

Save_traffic() {
	if [ -s $HOME_DIR/port.list ]; then
		local temp_file flow port array3 array4 array5 aa
		is_number "$1" && port=$1
		temp_file='/dev/shm/ssflow.tmp'
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			if is_number "$server_port" && is_number $total; then
				if [ "$1" != "all" ] && [ -z "$port" ]; then
					if [ -s $HOME_DIR/ss_traffic.stat ]; then
						flow=$(Used_traffic "$server_port" ${HOME_DIR:?}/ss_traffic.stat)
					fi
					used_traffic=$((${flow:=0} + ${used_traffic:=0}))
					unset -v flow
					if [ "$1" = "check" ]; then
						if is_number "$reset_day" && [ "$reset_day" -gt 0 ] && [ "$reset_type" ]; then
							if [ "$reset_type" = "specify" ] && [ "$(date +'%d')" -eq "$reset_day" ]; then
								used_traffic=0
								array4+=("$server_port")
							fi
							if [ "$reset_type" = "periodic" ]; then
								IFS=' ' read -r -a array5 <<<"$(eval "echo {$reset_day..31..$reset_day}")"
								for i in "${array5[@]}"; do
									if [ "$reset_day" -eq "$i" ]; then
										used_traffic=0
										array4+=("$server_port")
									fi
								done
							fi
						fi
					fi
				else
					used_traffic=${used_traffic:=0}
				fi
				if [ "$port" ] && [ "$server_port" -eq "$port" ]; then
					used_traffic=0
				fi
				if [ "$1" = "all" ]; then
					used_traffic=0
					array3+=("$server_port")
				fi
				if [ "$server_port" ] && [ "$password" ] && [ "$method" ]; then
					echo "server_port^$server_port|password^$password|method^$method|plugin^$plugin|plugin_opts^$plugin_opts|used_traffic^$used_traffic|total^$total|reset_day^$reset_day|reset_type^$reset_type|expire_timestamp^$expire_timestamp|upload_limit^$upload_limit|download_limit^$download_limit|user_id^$user_id" >>"$temp_file"
				fi
			fi
		done <$HOME_DIR/port.list
		rm -f $HOME_DIR/port.list
		if [ -s $temp_file ]; then
			mv -f "$temp_file" $HOME_DIR/port.list
		fi
		if [ "$port" ]; then
			Delete_users Offline "$port" Zero
			Upload_users "$port"
		fi
		if [ "$1" = "all" ] && [ "${#array3[*]}" -ge 1 ]; then
			for i in "${array3[@]}"; do
				Delete_users Offline "$i" Zero
			done
			Upload_users
		fi
		if [ "$1" = "check" ] && [ "${#array4[*]}" -ge 1 ]; then
			#在这个循环体中不能使用i作为变量只能用别的
			for aa in "${array4[@]}"; do
				Delete_users Offline "$aa" Zero #因为这个函数因为重新定义了全局变量i
				Upload_users "$aa"              #这里会拿到错误的i变量
			done
			#被坑了好久解决方法是定义i为函数局部变量local懒得弄只能换成aa了
		fi
	fi
}

Upload_users() {
	if [ -s $HOME_DIR/port.list ]; then
		local using sy sy2 sorted_arr
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			[ "$1" ] && [ "$1" != "$server_port" ] && continue
			using=$(Used_traffic "$server_port")
			if is_number "$server_port" && is_number "$total" && [ -z "$using" ] && [ "$password" ] && [ "$method" ]; then
				for ii in "${Encryption_method_list[@]}"; do
					if [ "$ii" = "$method" ]; then
						if [ "$plugin" ] && [ "$plugin_opts" ]; then
							if [[ $plugin == "kcptun.sh" || $plugin_opts == *quic* ]]; then
								if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null; then
									sorted_arr+=("${server_port}")
								fi
							else
								if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null; then
									sorted_arr+=("${server_port}")
								fi
							fi
						else
							if ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\"}" >/dev/null; then
								sorted_arr+=("${server_port}")
							fi
						fi
					fi
				done
			fi
			unset -v using
		done <$HOME_DIR/port.list
		sy="${#sorted_arr[@]}"
		sy2=0
		while [ "$sy" -gt 0 ]; do
			for i in "${sorted_arr[@]}"; do
				if [ -s "${HOME_DIR}/pid/shadowsocks-server-${i}.pid" ]; then
					if pgrep -F ${HOME_DIR}/pid/shadowsocks-server-"${i}".pid >/dev/null 2>&1; then
						((sy--))
						((sy2++))
					fi
				fi
			done
			if [ "$sy" -gt 0 ]; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Progress_Bar "$sy2" ${#sorted_arr[*]} "Waiting $sy"
				else
					Progress_Bar "$sy2" ${#sorted_arr[*]} "请稍等 $sy"
				fi
			else
				break
			fi
		done
		echo
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No port list file found! Please add a user port first."
		else
			Prompt "没有找到端口列表文件！请先添加端口。"
		fi
		Press_any_key_to_continue
	fi
}

Daemon() {
	Check
	if [ -r /run/ss-daemon.pid ]; then
		pkill -F /run/ss-daemon.pid 2>/dev/null
	fi
	echo $NOW_PID >/run/ss-daemon.pid
	local flow pid1 pid2 array1 array2 #warp_check=on
	if [ -r /run/ss-manager.pid ] && [ -r /run/ss-daemon.pid ]; then
		read -r pid1 </run/ss-manager.pid
		read -r pid2 </run/ss-daemon.pid
		if is_number "$pid1" && is_number "$pid2"; then
			while true; do
				if [ -d /proc/"${pid1:?}" ] && [ -d /proc/"${pid2:?}" ] && [ -S /tmp/ss-manager.socket ]; then
					ss-tool /tmp/ss-manager.socket ping >${HOME_DIR:?}/ss_traffic.stat
					if [ -s ${HOME_DIR:?}/port.list ]; then
						if [ "$(date +'%H%M')" -eq 0 ]; then
							if [ "$(date +'%M%S')" -le 5 ]; then
								Save_traffic check
								while true; do
									[ "$(date +'%M%S')" -gt 5 ] && break
									sleep 1
								done
								continue
							fi
						fi
						while IFS= read -r line || [ -n "$line" ]; do
							Parsing_User "$line"
							flow=$(Used_traffic "$server_port")
							if is_number "$server_port" && is_number "$flow"; then
								flow=$((flow + ${used_traffic:=0}))
								if is_number $total && [ $total -gt 0 ]; then
									if [ "$flow" -ge $total ]; then
										array1+=("$server_port")
									fi
								fi
								if is_number "$expire_timestamp" && [ "$expire_timestamp" -gt 0 ]; then
									if [ "$(date +%s)" -ge "$expire_timestamp" ]; then
										array2+=("$server_port")
									fi
								fi
								unset -v flow
							fi
						done <${HOME_DIR:?}/port.list
					fi
					if [ "${#array1[*]}" -ge 1 ]; then
						for i in "${array1[@]}"; do
							#Delete_users Delete "$i"
							Delete_users Offline "$i"
							logger -it ss-main -p daemon.warning "端口 $i 流量已用完"
						done
						Reload_tc_limit
						unset -v array1
					fi
					if [ "${#array2[*]}" -ge 1 ]; then
						for i in "${array2[@]}"; do
							#Delete_users Delete "$i"
							Delete_users Offline "$i"
							logger -it ss-main -p daemon.warning "端口 $i 已过期"
						done
						Reload_tc_limit
						unset -v array2
					fi
					: <<'EOF'
				if [ "$warp_check" = "on" ]; then
					keeplive_warp
				fi
EOF
					sleep 1
				else
					Stop
					break
				fi
			done
		fi
	fi
}

Start() {
	Local_IP
	if [ ${runing:-false} = true ]; then
		if [ "${Language:=zh-CN}" = "en-US" ]; then
			Prompt "Please stop first when the service is running!"
		else
			Prompt "服务运行中请先停止运行!"
		fi
		Press_any_key_to_continue
	else
		local acl_file="${HOME_DIR:?}/conf/server_block.acl" cs=60 #6秒启动超时与重试 https://github.com/shadowsocks/shadowsocks-rust/issues/587
		if [ "$ipv6" ] && [ "$internet6" ]; then
			local first_v6='-6'
		fi
		rm -f /tmp/shadowsock*.log
		if [ "$Block_China" = "enable" ]; then
			if [ ! -s ${HOME_DIR:?}/conf/block_china-list.acl ]; then
				get_china_ips
			fi
			acl_file="${HOME_DIR:?}/conf/block_china-list.acl"
		fi
		ssmanager \
			--manager-address /tmp/ss-manager.socket \
			--manager-server-mode standalone \
			--manager-server-working-directory ${HOME_DIR:?}/pid \
			--outbound-bind-interface "${internet4:-$internet6}" \
			--outbound-bind-addr "${ipv4:-$ipv6}" \
			--server-host "${ipv4:-$ipv6}" \
			--daemonize-pid /run/ss-manager.pid \
			--daemonize $first_v6 \
			--acl ${acl_file:?} \
			--log-config $HOME_DIR/conf/log4rs.yaml \
			--log-without-time \
			-vvv
		while true; do
			((cs--))
			if [ ${cs:-0} -eq 0 ]; then
				if [ "${Language:=zh-CN}" = "en-US" ]; then
					Prompt "Timeout to start ssmanager!"
				else
					Prompt "启动ssmanager超时!"
				fi
				Stop
				Exit
			else
				if ss-tool /tmp/ss-manager.socket ping >/dev/null 2>&1; then
					break
				else
					sleep 0.1
				fi
			fi
		done
		if [ -S /tmp/ss-manager.socket ] && [ -s /run/ss-manager.pid ]; then
			Save_traffic
			Upload_users
			(setsid ss-main daemon >/dev/null 2>&1 &)
			cs=30 #3秒超时，需要等待后台守护脚本启动完成
			until [ -s /run/ss-daemon.pid ]; do
				((cs--))
				if [ ${cs:-0} -eq 0 ]; then
					if [ "${Language:=zh-CN}" = "en-US" ]; then
						Prompt "Daemon start timeout!"
					else
						Prompt "守护脚本启动超时!"
					fi
					Stop
					Exit
				else
					sleep 0.1
				fi
			done
			Reload_nginx
			Reload_tc_limit
		else
			Stop
			Exit
		fi
	fi
}

Stop() {
	for i in /run/ss-daemon.pid /run/ss-manager.pid "${HOME_DIR}"/pid/shadowsocks-server-*.pid; do
		[ -s "$i" ] && read -r kpid <"$i"
		if [ -d /proc/"${kpid:=lzbx}" ]; then
			kill "$kpid"
			if [ -f "$i" ]; then
				rm -f "$i"
			fi
		fi
	done
	Stop_tc_limit
	rm -f /run/ss-daemon.pid /run/ss-manager.pid ${HOME_DIR}/pid/*
}

Update_core() {
	local temp_file temp_file2 update cur_time last_time
	temp_file=$(mktemp) temp_file2=$(mktemp)
	Wget_get_files "$temp_file" $URL/version/update
	#sed -i "s=*bin=$HOME_DIR/usr/bin=" $temp_file
	! shasum -a512 -c "$temp_file" >>"$temp_file2" && update=true || update=false
	sed -i 's/: /,/g' "$temp_file2"
	${python:-python3} <<-EOF
		from rich.console import Console
		from rich.table import Table
		from rich import box
		from os.path import split
		if "${Language:=zh-CN}" == 'zh-CN':
		  table = Table(title="程序升级列表", box=box.ASCII_DOUBLE_HEAD, show_lines=True)
		  table.add_column("文件路径", justify="left", no_wrap=True)
		  table.add_column("更新状态", justify="right")
		else:
		  table = Table(title="Upgrade List", show_lines=True)
		  table.add_column("Binary program path", justify="left", no_wrap=True)
		  table.add_column("Upgrade Status", justify="right")
		with open("$temp_file2", 'r', encoding='utf8') as fd:
		  for lines in fd.read().splitlines():   
		    a, b = lines.split(',')
		    if 'OK' in b:
		      b = '[bold green]' + b
		    elif 'FAILED' in b:
		      b = '[bold yellow]' + b
		    a = '[bold]' + split(a)[0] + '/[#39c5bb]' + split(a)[1]
		    table.add_row(a, b)    
		console = Console()
		console.print(table, justify="left")
	EOF
	rm -f "$temp_file" "$temp_file2"
	if $update; then
		cp -f ${HOME_DIR:?}/conf/sni.ini /tmp/sni.rule 2>/dev/null
		rm -rf ${HOME_DIR:?}/usr/* ${HOME_DIR:?}/conf
		mv -f /tmp/sni.rule ${HOME_DIR:?}/conf/sni.ini 2>/dev/null
		Check
		if [ "$Subscribe" = "enable" ]; then
			rm -f ${HOME_DIR?}/web/subscriptions.php
		fi
		if [ "$Nginx_Switch" = "enable" ]; then
			Reload_nginx
		fi
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Please restart all services of this script manually to apply the update."
		else
			Prompt "请手动重启本脚本的所有服务以应用更新。"
		fi
		Exit
	else
		cur_time=$(date +%s)
		last_time=$(date -r $HOME_DIR/conf/update.log +%s)
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No updates found! (Updated $(((cur_time - last_time) / 86400)) days ago.)"
		else
			Prompt "未发现任何更新！(更新于 $(((cur_time - last_time) / 86400)) 天前)"
		fi
	fi
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		echo -e "\e[1mHelp and Feedback: \e[0m\e[1;34mhttps://gitlab.com/yiguihai/ss\e[0m\n"
	else
		echo -e "\e[1m帮助与反馈: \e[0m\e[1;34mhttps://gitlab.com/yiguihai/ss\e[0m\n"
	fi
	Press_any_key_to_continue
}

Check_from() {
	#https://stackoverflow.com/a/2230513
	if [ "${SSH_CLIENT%% *}" = "${ipv4:-$ipv6}" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "The operation has been terminated"
		else
			Prompt "该操作已被终止"
		fi
		Exit
	fi
}

Uninstall() {
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Are you sure you want to uninstall?"
	else
		Introduction "确定要卸载吗?"
	fi
	local Verification_Code delete
	Verification_Code=$(base64 -w0 /proc/sys/kernel/random/uuid)
	Verification_Code=${Verification_Code:0:8}
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		read -rp "Please enter the verification code $Verification_Code " delete
	else
		read -rp "请输入验证码 $Verification_Code " delete
	fi
	if [ "$delete" = "$Verification_Code" ]; then
		systemctl stop ss-main.service
		systemctl disable ss-main.service
		rm -f /etc/systemd/system/ss-main.service
		systemctl daemon-reload
		systemctl reset-failed
		Stop
		Close_traffic_forward
		rm -rf $HOME_DIR
		rm -f "$0"
		rm -f /usr/local/bin/ss-main
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Uninstallation is complete! (It is better to reboot the system)"
		else
			Prompt "已卸载！(最好重启一下)"
		fi
		Exit
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Canceled operation..."
		else
			Prompt "已取消操作..."
		fi
	fi
	Exit
}

Free_SS() {
	local share_date share_dest _ss=() _trojan=() _ssr=() _vmess=() _list=()
	share_date=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' "https://freefq.com/m/free-ss/" | grep -Po '\/m\/free-ss\/(\d*){4}\/(\d*){1,2}\/(\d*){1,2}\/ss.html' | head -n 1)
	share_dest=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://freefq.com"${share_date}" | grep -Po 'https://www.freefq.com/d/file/free-ss/(\d*){4,8}/([a-z0-9])+.htm')
	if [ "$share_dest" ]; then
		IFS=$'\n'
		for i in $(wget -qO- -t2 -T3 -U 'curl/7.65.0' "${share_dest}" | grep -oE "(trojan|ss|ssr|vmess)://.*" | sed -e 's/<[^>]*>//'); do
			i=$(Url_decode "$i")
			case ${i%%://*} in
			ss)
				_ss+=("$i")
				;;
			trojan)
				_trojan+=("$i")
				;;
			ssr)
				_ssr+=("$i")
				;;
			vmess)
				_vmess+=("$i")
				;;
			esac
		done
		if [ ${#_ss[*]} -gt 0 ]; then
			echo "SS: ${#_ss[@]}"
			_list+=(ss)
		fi
		if [ ${#_ss[*]} -gt 0 ]; then
			echo "SSR: ${#_ssr[@]}"
			_list+=(ssr)
		fi
		if [ ${#_trojan[*]} -gt 0 ]; then
			echo "Trojan: ${#_trojan[@]}"
			_list+=(trojan)
		fi
		if [ ${#_vmess[*]} -gt 0 ]; then
			echo "V2ray: ${#_vmess[@]}"
			_list+=(v2ray)
		fi
		if [ ${#_list[@]} -gt 0 ]; then
			select list in "${_list[@]}"; do
				if [ "$list" = "ss" ]; then
					for i in "${_ss[@]}"; do
						echo "$i"
					done
					break
				fi
				if [ "$list" = "ssr" ]; then
					for i in "${_ssr[@]}"; do
						echo "$i"
					done
					break
				fi
				if [ "$list" = "trojan" ]; then
					for i in "${_trojan[@]}"; do
						echo "$i"
					done
					break
				fi
				if [ "$list" = "v2ray" ]; then
					for i in "${_vmess[@]}"; do
						echo "$i"
					done
					break
				fi
			done
		else
			Prompt "未发现任何共享账号链接!"
		fi
	fi
}

Shadowsocks_Link_Decode() {
	local link
	read -rp "请输入ss://链接: " link
	[[ $link != "ss://"* || -z $link ]] || {
		link=$(Url_decode "$link")
		if ssurl -d "$link" 1>/tmp/sslocal.json; then
			server=$(jq -r '.server' /tmp/sslocal.json)
			if [ -z "$server" ] || [ "$server" = "null" ]; then
				server=$(jq -r '.servers[].server' /tmp/sslocal.json)
			fi
			${python:-python3} -m rich.json /tmp/sslocal.json
		fi
	}
}

ShadowsocksR_Link_Decode() {
	local link a b server_port protocol method obfs password other obfsparam protoparam #remarks group
	read -rp "请输入ssr://链接: " link
	[[ $link != "ssr://"* || -z $link ]] || {
		link=$(Url_decode "$link")
		a=${link#ssr\:\/\/}
		b=$(echo "$a" | base64 -d 2>&-)
		i=0
		IFS=':'
		for c in ${b%\/}; do
			((i++))
			case $i in
			1)
				server=$c
				;;
			2)
				server_port=$c
				;;
			3)
				protocol=$c
				;;
			4)
				method=$c
				;;
			5)
				obfs=$c
				;;
			6)
				password=$(echo "${c%\/\?*}" | base64 -d 2>&-) #再解一次base64被坑了好久
				other=${c#*\/\?}
				;;
			esac
		done
		IFS='&'
		for d in $other; do
			case ${d%\=*} in
			obfsparam)
				obfsparam=$(echo "${d#*\=}" | base64 -d 2>&-)
				;;
			protoparam)
				protoparam=$(echo "${d#*\=}" | base64 -d 2>&-)
				;;
			remarks)
				#remarks=${d#*\=} #不解码了不规范的命名会乱码
				break
				;;
			group)
				#group=${d#*\=}
				break
				;;
			esac
		done
		if is_number "$server_port" && [ "$server_port" -gt 0 ] && [ "$server_port" -le 65535 ]; then
			cat >/tmp/ssr-local.json <<EOF
{
    "server":"$server",
    "server_port":$server_port,
    "method":"$method",
    "password":"$password",
    "protocol":"$protocol",
    "protocol_param":"$protoparam",
    "obfs":"$obfs",
    "obfs_param":"$obfsparam",
    "user":"nobody",
    "fast_open":false,
    "nameserver":"1.1.1.1",
    "mode":"tcp_and_udp",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "timeout":30
}
EOF
			${python:-python3} -m rich.json /tmp/ssr-local.json
		fi
		#tcp_only
	}
}

Trojan_Link_Decode() {
	local link a password b c server_port d sni #remarks
	read -rp "请输入trojan://链接: " link
	[[ $link != "trojan://"* || -z $link ]] || {
		link=$(Url_decode "$link")
		a=${link#trojan\:\/\/}
		#remarks=${a#*#}
		password=${a%@*}
		b=${a#*@}
		b=${b%#*}
		c=${b%\?*}
		server=${c%:*}
		server_port=${c#*:}
		d=${b#*\?}
		sni=${d#sni\=}
		if is_number "$server_port" && [ "$server_port" -gt 0 ] && [ "$server_port" -le 65535 ]; then
			cat >/tmp/trojan-client.json <<EOF
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "$server",
    "remote_port": ${server_port:-0},
    "password": [
        "$password"
    ],
    "log_level": 1,
    "ssl": {
        "verify": false,
        "verify_hostname": false,
        "cert": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "sni": "$sni",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
EOF
			${python:-python3} -m rich.json /tmp/trojan-client.json
		fi
	}
}

V2ray_Link_Decode() {
	local link a alterId host id network path scy port servername tls jqr
	read -rp "请输入vmess://链接: " link
	[[ $link != "vmess://"* || -z $link ]] || {
		link=$(Url_decode "$link")
		a=${link#vmess\:\/\/}
		a=$(echo "$a" | base64 -d 2>&-)
		jqr="$HOME_DIR/usr/bin/jq"
		server=$(echo "$a" | $jqr -er 'select(.add != null)|.add')
		alterId=$(echo "$a" | $jqr -er 'select(.aid != null)|.aid')
		host=$(echo "$a" | $jqr -er 'select(.host != null)|.host')
		id=$(echo "$a" | $jqr -er 'select(.id != null)|.id')
		network=$(echo "$a" | $jqr -er 'select(.net != null)|.net')
		path=$(echo "$a" | $jqr -er 'select(.path != null)|.path')
		scy=$(echo "$a" | $jqr -er 'select(.scy != null)|.scy')
		port=$(echo "$a" | $jqr -er 'select(.port != null)|.port')
		servername=$(echo "$a" | $jqr -er 'select(.sni != null)|.sni')
		tls=$(echo "$a" | $jqr -er 'select(.tls != null)|.tls')
		if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
			cat >/tmp/v2ray-client.json <<EOF
{
    "log":{
        "loglevel":"none"
    },
    "inbounds":[
        {
            "listen":"127.0.0.1",
            "port":1080,
            "protocol":"socks",
            "settings":{
                "auth":"noauth",
                "udp":true
            }
        }
    ],
    "outbounds":[
        {
            "protocol":"vmess",
            "settings":{
                "vnext":[
                    {
                        "address":"$server",
                        "port":$port,
                        "users":[
                            {
                                "id":"$id",
                                "security":"${scy:-auto}",
                                "alterId":$alterId
                            }
                        ]
                    }
                ]
            },
            "streamSettings":{
                "network":"$network",
                "security":"$tls",
                "tlsSettings":{
                    "allowInsecure":true,
                    "serverName":"$servername"
                },
                "wsSettings":{
                    "headers":{
                        "Host":"$host"
                    },
                    "path":"$path"
                }
            }
        }
    ]
}
EOF
			${python:-python3} -m rich.json /tmp/v2ray-client.json
		fi
	}
}

Close_traffic_forward() {
	if iptables -w -t mangle -C OUTPUT -o "$internet4" -j SHADOWSOCKS_v4 2>/dev/null; then
		iptables -w -t mangle -D OUTPUT -o "${internet4:?}" -j SHADOWSOCKS_v4
		iptables -w -t mangle -F SHADOWSOCKS_v4
		iptables -w -t mangle -X SHADOWSOCKS_v4
		ipset destroy traffic_forward_v4
		ipset destroy bypass_ips_v4
		ip -4 rule del fwmark 0x2233 table 123
	fi
	if ip6tables -w -t mangle -C OUTPUT -o "$internet6" -j SHADOWSOCKS_v6 2>/dev/null; then
		ip6tables -w -t mangle -D OUTPUT -o "${internet6:?}" -j SHADOWSOCKS_v6
		ip6tables -w -t mangle -F SHADOWSOCKS_v6
		ip6tables -w -t mangle -X SHADOWSOCKS_v6
		ipset destroy traffic_forward_v6
		ipset destroy bypass_ips_v6
		ip -6 rule del fwmark 0x2233 table 123
	fi
	for i in sslocal ssr-local trojan v2ray tun2socks; do
		if [ "$i" = "v2ray" ]; then
			kpid=$(pgrep -F /tmp/v2ray-client.pid 2>/dev/null)
		else
			kpid=$(pgrep $i)
		fi
		if [ -d /proc/"${kpid:=lzbx}" ]; then
			kill $kpid
		fi
		unset -v kpid
	done
	if command_exists warp-cli; then
		warp-cli --accept-tos disconnect 1>/dev/null
	fi
}

Start_tun2socks() {
	(setsid tun2socks --device tun://tun0 --proxy "$1" -loglevel silent >/dev/null 2>&1 &)
	Tun_Check
	#规则灵感来源于tproxy透明代理，(发现很多教程都教你删除服务器默认路由改为指向tun0。不要乱改路由表的默认指向不然会连接不上服务器只能控制面板重启，本地机器当我没说)可以Google搜索策略路由。如果只是单纯的网段代理甚至只用ip route规则都可以搞定了。个人愚见
	#Linux下ip route、ip rule、iptables的关系（转） - EasonJim - 博客园 https://www.cnblogs.com/EasonJim/p/8424731.html (以前的我也觉得这三个很恐怖不敢涉足理解后觉得这些工具特别牛逼可玩性太强了)
	#ip tuntap add mode tun tun0 如果不能创建tun0网卡手动创建
	ip -4 addr add 172.19.0.1/30 dev tun0 #随便分配一个私网地址(这个私网地址抄安卓Shadowsocks的)
	#ip -6 addr add fdfe:dcba:9876::1/126 dev tun0
	ip link set dev tun0 up                                   #把tun0网卡拉起来
	ip -4 rule add fwmark 0x2233 table 123                    #所有打有2233标记的流量都流入123号路由表
	ip -4 route add table 123 default via 172.19.0.1 dev tun0 #表示在123号路由表添加一条默认路由到达网卡tun0地址为172.19.0.1的规则
	#ip -4 route add table 123 default dev tun0 #一样
	#ip route list table all
	Proxy_Check 4
}

Tun_Check() {
	local cs=6
	while true; do
		((cs--))
		if [ ${cs:-0} -eq 0 ]; then
			Prompt "没有成功创建tun0网卡!"
			Exit
		else
			if ip route list dev tun0 >/dev/null 2>&1 && ip link show tun0 >/dev/null 2>&1; then
				break
			else
				sleep 0.5
			fi
		fi
	done
}

Proxy_Check() {
	Tun_Check
	if [ "$1" -eq 4 ]; then
		Introduction "正在进行IPv4网络测试..."
	elif [ "$1" -eq 6 ]; then
		Introduction "正在进行IPv6网络测试..."
	fi
	check_tcp=0
	check_udp=0
	local ip_addr #check_google=0
	#https://everything.curl.dev/usingcurl/verbose/writeout
	if [ "$($HOME_DIR/usr/bin/curl --silent --output /dev/null --write-out '%{response_code}' --connect-timeout 3 --max-time 3 --interface tun0 -"${1:=4}" --url 'https://cp.cloudflare.com/generate_204')" -eq 204 ]; then
		check_tcp=1
		Prompt "TCP协议正常"
		ip_addr=$($HOME_DIR/usr/bin/curl --silent --connect-timeout 3 --max-time 3 --interface tun0 -${1:=4} --url 'https://myip.ipip.net')
		if [ "$ip_addr" ]; then
			Prompt "$ip_addr"
		fi
		: <<'EOF'
		#https://stackoverflow.com/a/28356429
		if [[ "$($HOME_DIR/usr/bin/curl --silent --output /dev/null --write-out '%{response_code}' --connect-timeout 3 --max-time 3 --interface tun0 -${1:=4} --url https://www.google.com)" != +(200|301|302) ]]; then
			#check_google=1
			Prompt "连接到Google出现异常!"
		fi
EOF
	else
		Prompt "TCP协议不支持!"
	fi
	if [ "$($HOME_DIR/usr/bin/curl --silent --output /dev/null --write-out '%{response_code}' --http3 --connect-timeout 3 --max-time 3 --interface tun0 -${1:=4} --url 'https://cp.cloudflare.com/generate_204')" -eq 204 ]; then
		check_udp=1
		Prompt "UDP协议正常"
	else
		Prompt "UDP协议不支持!"
	fi
	if [ $((check_tcp + check_udp)) -le 0 ]; then
		Prompt "无法连接到代理服务器!"
		Close_traffic_forward
		error_code=1
	else
		if [ "$server" ]; then
			ping -c5 -W5 -n -I "${internet4:-$internet6}" "$server"
			echo
		fi
	fi
}

Start_traffic_forward_v4() {
	iptables -w -t mangle -N SHADOWSOCKS_v4
	ipset create traffic_forward_v4 hash:net family inet
	ipset create bypass_ips_v4 hash:net family inet
	#iptables -w -t mangle -A SHADOWSOCKS_v4 -p tcp -j LOG --log-prefix='[netfilter] '
	#grep 'netfilter' /var/log/kern.log
	iptables -w -t mangle -A SHADOWSOCKS_v4 -m set --match-set bypass_ips_v4 dst -j RETURN
	#iptables -w -t mangle -A SHADOWSOCKS_v4 -m owner --uid-owner nobody -j ACCEPT
	if [ "$check_udp" -eq 0 ] && [ "$check_tcp" -eq 1 ]; then
		iptables -w -t mangle -A SHADOWSOCKS_v4 -p tcp -m set --match-set traffic_forward_v4 dst -j MARK --set-mark 0x2233 #打上2233标记让它进入123表
	elif [ "$check_udp" -eq 1 ] && [ "$check_tcp" -eq 0 ]; then
		iptables -w -t mangle -A SHADOWSOCKS_v4 -p udp -m set --match-set traffic_forward_v4 dst -j MARK --set-mark 0x2233
	else
		iptables -w -t mangle -A SHADOWSOCKS_v4 -m set --match-set traffic_forward_v4 dst -j MARK --set-mark 0x2233
	fi
	iptables -w -t mangle -A OUTPUT -o "${internet4:?}" -j SHADOWSOCKS_v4
	ipset add bypass_ips_v4 127.0.0.1/8
	ipset add bypass_ips_v4 224.0.0.0/4
	ipset add bypass_ips_v4 255.255.255.255/32
	#iptables -w -t nat -A OUTPUT -p tcp -m multiport --dport 80,443 -m set --match-set cdn_only4 dst -j DNAT --to-destination 172.67.1.113 #优选IP
	#iptables -vxn -t nat -L OUTPUT --line-number
	#curl https://ip.cn/cdn-cgi/trace/
}

Start_traffic_forward_v6() {
	ip6tables -w -t mangle -N SHADOWSOCKS_v6
	ipset create traffic_forward_v6 hash:net family inet6
	ipset create bypass_ips_v6 hash:net family inet6
	ip6tables -w -t mangle -A SHADOWSOCKS_v6 -m set --match-set bypass_ips_v6 dst -j RETURN
	#ip6tables -w -t mangle -A SHADOWSOCKS_v6 -m mark --mark 0x2234 -j RETURN
	ip6tables -w -t mangle -A SHADOWSOCKS_v6 -m set --match-set traffic_forward_v6 dst -j MARK
	ip6tables -w -t mangle -A OUTPUT -o "${internet6:?}" -j SHADOWSOCKS_v6
	ipset add bypass_ips_v6 ::1/128
}

enable_ecn() {
	# enable BBRv2 ECN response:
	echo 1 >/sys/module/tcp_bbr2/parameters/ecn_enable
	# enable BBRv2 ECN response at any RTT:
	echo 0 >/sys/module/tcp_bbr2/parameters/ecn_max_rtt_us
	case $(sysctl -nbe net.ipv4.tcp_ecn) in
	0)
		# negotiate TCP ECN for active and passive connections:
		sysctl -w net.ipv4.tcp_ecn=1
		sysctl -w net.ipv4.tcp_ecn_fallback=1
		;;
	1 | 2)
		Prompt "ECN support has been turned on"
		;;
	*)
		Prompt "Unknown error"
		;;
	esac
}

kernel_install() {
	local answer xtab netf hav_xt
	if [ "$kernel_ver" != "5.13.12" ]; then
		hav_xt=$(find / -type l -name 'libxtables.so.*')
		if [ -L "$hav_xt" ]; then
			#https://github.com/netblue30/firejail/issues/2232
			#https://my.oschina.net/u/3888259/blog/4414015
			iptables -vxn -t mangle -L OUTPUT --line-number 1>/dev/null || update-alternatives --set iptables /usr/sbin/iptables-legacy
			ip6tables -vxn -t mangle -L OUTPUT --line-number 1>/dev/null || update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
			local dl=("${URL:?}/backups/linux-headers-5.13.12_5.13.12-1_amd64_${hav_xt##*\.}.deb+/tmp/linux-header.deb")
			dl+=("${URL:?}/backups/linux-image-5.13.12_5.13.12-1_amd64_${hav_xt##*\.}.deb+/tmp/linux-image.deb")
			dl+=("${URL:?}/backups/linux-libc-dev_5.13.12-1_amd64_${hav_xt##*\.}.deb+/tmp/linux-libc.deb")
			dl+=("${URL:?}/backups/libxt_tls_${hav_xt##*\.}.so+/tmp/libxt_tls.so")
			dl+=("${URL:?}/backups/xt_tls_${hav_xt##*\.}.ko+/tmp/xt_tls.ko")
			Downloader "${dl[@]}"
			for i in linux-header.deb linux-image.deb linux-libc.deb; do
				if [ -s "/tmp/$i" ]; then
					dpkg --install "/tmp/$i"
				else
					Prompt "Download $i failed."
					Exit
				fi
			done
			if [ -s /tmp/libxt_tls.so ] && [ -s /tmp/xt_tls.ko ]; then
				xtab=$(find / -type d -name "xtables")
				netf=$(find / -type d -name "netfilter" | grep -E "modules\/[0-9]+.[0-9]+.[0-9]+\/kernel\/net\/netfilter")
				if [ -d "$xtab" ] && [ -d "$netf" ]; then
					install -D -v -m 644 /tmp/libxt_tls.so "$xtab"
					install -D -v -m 644 /tmp/xt_tls.ko "$netf"
				fi
			fi
			cat >/etc/modules-load.d/bbr.conf <<EOF
tcp_bbr
tcp_bbr2
EOF
			#https://github.com/Lochnair/xt_tls/issues/33
			#echo 'xt_tls' >/etc/modules-load.d/xt_tls.conf
			dpkg --list | grep -E --ignore-case --color 'linux-image|linux-headers|linux-libc' #|awk '{print $2}'
			#https://juejin.cn/post/6844904034072018952
			update-grub
			Introduction "安装新内核之后需要重启! 需要现在重启吗? [Y/n]"
			read -rp "(${mr:=默认}: Y): " answer
			if [ "$answer" = "${answer#[Nn]}" ]; then
				reboot
			fi
		else
			Prompt "Installation not supported."
		fi
	else
		Prompt "BBRv2 kernel is installed."
	fi
}

kernel_tcp_congestion_control() {
	local tcc dq array1 array2
	if ! lsmod | grep -q tcp_bbr; then
		modprobe tcp_bbr
	fi
	if ! lsmod | grep -q tcp_bbr2; then
		modprobe tcp_bbr2
	fi
	Introduction "TCP拥塞控制算法"
	#IFS=' ' read -r -a array <<<"$(sysctl -nbe net.ipv4.tcp_available_congestion_control)"
	array1=(
		advanced
		bic
		cubic
		westwood
		htcp
		hstcp
		hybla
		vegas
		nv
		scalable
		lp
		veno
		yeah
		illinois
		dctcp
		cdg
		bbr
		bbr2
	)
	select tcc in "${array1[@]}"; do
		if [ "$tcc" ]; then
			sysctl -w net.ipv4.tcp_congestion_control="$tcc"
			if [ "$(sysctl -nbe net.ipv4.tcp_congestion_control)" = "$tcc" ]; then
				Prompt "$tcc"
				break
			fi
		fi
	done
	if [ "$tcc" = "bbr2" ] && [ "$(sysctl -nbe net.ipv4.tcp_ecn)" = 0 ]; then
		Introduction "打开 ECN 支持 [Y/n]"
		read -r action
		if [[ $action =~ ^[Yy]$ ]]; then
			enable_ecn
		fi
	fi
	Introduction "队列规则"
	array2=(
		pfifo_fast
		cbq
		htb
		hfsc
		atm
		prio
		multiq
		red
		sfb
		sfq
		teql
		tbf
		cbs
		etf
		taprio
		gred
		dsmark
		netem
		drr
		mqprio
		skbprio
		choke
		qfq
		codel
		fq_codel
		cake
		fq
		hhf
		pie
		ingress
		plug
	)
	select dq in "${array2[@]}"; do
		if [ "$dq" ]; then
			sysctl -w net.core.default_qdisc="$dq"
			if [ "$(sysctl -nbe net.core.default_qdisc)" = "$dq" ]; then
				Prompt "$dq"
				break
			fi
		fi
	done
	cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=$dq
net.ipv4.tcp_congestion_control=$tcc
EOF
	systemctl restart systemd-sysctl
}

kernel_uninstall() {
	#https://www.cyberciti.biz/faq/ubuntu-18-04-remove-all-unused-old-kernels/
	local args
	read -ra args < <(dpkg --list | grep -E --ignore-case 'linux-image|linux-headers|linux-libc' | grep -v "$kernel_ver" | awk '/ii/{ print $2}')
	if [ "${args[@]}" ]; then
		apt -qq autoremove --purge
		apt -qq remove "${args[@]}" --purge
	fi
}

Start_nginx_program() {
	Create_certificate
	local dl=()
	if [ ! -f $HOME_DIR/usr/bin/nginx ] || [ ! -x $HOME_DIR/usr/bin/nginx ]; then
		dl+=("$URL/usr/sbin/nginx+$HOME_DIR/usr/bin/nginx")
	fi
	if [ ! -f $HOME_DIR/usr/bin/php-fpm ] || [ ! -x $HOME_DIR/usr/bin/php-fpm ]; then
		dl+=("$URL/usr/sbin/php-fpm+$HOME_DIR/usr/bin/php-fpm")
	fi
	if [ ! -d $HOME_DIR/usr/logs ]; then
		mkdir -p $HOME_DIR/usr/logs
	else
		rm -rf $HOME_DIR/usr/logs/*
	fi
	if [ ! -f $HOME_DIR/conf/cdn_only.conf ]; then
		touch $HOME_DIR/conf/cdn_only.conf
	fi
	if [ -s $HOME_DIR/port.list ]; then
		echo >$HOME_DIR/conf/v2ray_list.conf
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			if [[ $plugin == "v2ray-plugin" && $plugin_opts != *quic* ]]; then
				unset -v v2_protocols v2_protocols2
				if [[ $plugin_opts == *tls* ]]; then
					local v2_protocols='https'
					local v2_protocols2='grpcs'
				else
					local v2_protocols='http'
					local v2_protocols2='grpc'
				fi
				if [[ $plugin_opts == *grpc* ]]; then
					#if [ "$v2_protocols2" = "grpcs" ]; then
					#https://www.v2fly.org/config/transport/grpc.html#grpcobject
					cat >>$HOME_DIR/conf/v2ray_list.conf <<-EOF

						location /$(Parsing_plugin_opts "$plugin_opts" "serviceName")/Tun {
						    include    v2safe.conf;
						    grpc_pass ${v2_protocols2}://${ipv4:-[$ipv6]}:${server_port};
						}
						    
					EOF
					#fi
				else
					cat >>$HOME_DIR/conf/v2ray_list.conf <<-EOF

						location /$(Parsing_plugin_opts "$plugin_opts" "path") {
						    #include    v2safe.conf;
						    proxy_pass ${v2_protocols}://${ipv4:-[$ipv6]}:${server_port};
						    include    proxy.conf;
						}
						    
					EOF
				fi
			fi
		done <$HOME_DIR/port.list
		sed -i "/^Nginx_Switch=/s/=.*/=enable/" $HOME_DIR/conf/config.ini
	else
		Prompt "没有找到端口列表文件"
		Exit
	fi
	if [ -z "$tls_common_name" ]; then
		Prompt "无法获取域名信息！"
		Exit
	fi
	if [ ! -s $HOME_DIR/conf/mime.types ]; then
		dl+=("$URL/usr/conf/mime.types+$HOME_DIR/conf/mime.types")
	fi
	if [ "$Subscribe" = "enable" ] && [ ! -s $HOME_DIR/web/subscriptions.php ]; then
		dl+=("$URL/src/subscriptions.php+$HOME_DIR/web/subscriptions.php")
	fi
	for i in v2safe.conf add_header.conf v2ray-plugin.conf proxy.conf nginx.conf general.conf fastcgi_params.conf php-fpm.conf www.conf; do
		if [ ! -s $HOME_DIR/conf/$i ]; then
			dl+=("$URL/conf/$i+$HOME_DIR/conf/$i")
		fi
	done
	for i in 50x.html index.html; do
		if [ ! -s $HOME_DIR/web/$i ]; then
			dl+=("$URL/usr/html/$i+$HOME_DIR/web/$i")
		fi
	done
	if [ "${#dl[@]}" -gt 0 ]; then
		Downloader "${dl[@]}"
		chmod +x "$HOME_DIR"/usr/bin/nginx "$HOME_DIR"/usr/bin/php-fpm
	fi
	for i in "${dl[@]}"; do
		if [ ! -f "${i##*+}" ]; then
			Prompt "文件 ${i##*+} 下载失败！"
			Exit
		fi
	done
	sed -i "/server_name/c\    server_name         $tls_common_name;" $HOME_DIR/conf/v2ray-plugin.conf
	#groupadd web
	#useradd -g web nginx -M -s /sbin/nologin
	if [ "$1" = "reload" ]; then
		if nginx -c $HOME_DIR/conf/nginx.conf -t >/dev/null 2>&1; then
			#Nginx动态加载配置，查询配置中的PID文件向其发送reload信号。
			if ! nginx -s reload -c $HOME_DIR/conf/nginx.conf; then
				Prompt "Nginx热重启失败!"
				Exit
			fi
		else
			Prompt "请检查Nginx配置是否有误"
			Exit
		fi
	else
		if nginx -c $HOME_DIR/conf/nginx.conf -t; then
			if nginx -c $HOME_DIR/conf/nginx.conf; then
				if php-fpm -n -y $HOME_DIR/conf/php-fpm.conf -R; then
					Prompt "现在可以访问你的域名 https://$tls_common_name 了"
				else
					Prompt "请检查PHP-FPM配置是否有误"
					Exit
				fi
			else
				Prompt "启动Nginx时出现未知错误"
				Exit
			fi
		else
			Prompt "请检查Nginx配置是否有误"
			Exit
		fi
	fi
}

Reload_nginx() {
	if pgrep -F /run/nginx.pid >/dev/null 2>&1; then
		Start_nginx_program reload
	else
		if [ "$Nginx_Switch" = "enable" ]; then
			if ! ss -ln state listening '( sport = :80 or sport = :443 )' | grep -q ':80 \|:443 '; then
				Start_nginx_program
			else
				Prompt "80或443端口被其它进程占用！"
			fi
		fi
	fi
}

getmodule_install() {
	if ! modinfo xt_tls >/dev/null 2>&1; then
		Prompt "正在探测所有模块，请稍等..."
		depmod -a
	fi
	if ! lsmod | grep -q xt_tls; then
		if ! modprobe xt_tls; then
			Prompt "无法载入xt_tls扩展模块！请检查支持此扩展的BBR内核是否正确安装"
			Exit
		fi
		#iptables -m tls -h
	fi
	if [ ! -s $HOME_DIR/conf/sni.ini ]; then
		Wget_get_files $HOME_DIR/conf/sni.ini $URL/acl/sni.acl
	fi
}

enable_filter() {
	iptables -w -t filter -A OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
	ip6tables -w -t filter -A OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
	local cum=0
	if [ -w /proc/net/xt_tls/hostset/blacklist ]; then
		while IFS= read -r line || [ -n "$line" ]; do
			if [ "${line::1}" != "#" ] && [ "${line::1}" != ";" ]; then
				if echo +"${line}" >/proc/net/xt_tls/hostset/blacklist; then
					((cum++))
				fi
			fi
		done <$HOME_DIR/conf/sni.ini
		Prompt "共加载 $cum 条审计规则！"
		sed -i "/^Sni_Filtering=/s/=.*/=enable/" $HOME_DIR/conf/config.ini
	else
		Prompt "xt_tls模块出现未知错误！"
	fi
}

: <<'EOF'
keeplive_warp() {
	#收集几个地址，帮你确认是否连接到互联网 https://meta.appinn.net/t/topic/28925/8
	local warp_listen_addr cs=5
	warp_listen_addr=$(ss -lntp | grep 'warp-svc' | awk -F' ' '{print $4}')
	if [ "$warp_listen_addr" ]; then
		while true; do
			((cs--))
			if [ ${cs:-0} -eq 0 ]; then
				logger -it ss-main -p daemon.err "warp-cli网络测试超时!"
				warp_check=off
				break
			else
				if [ "$(curl -s -o /dev/null -w '%{response_code}' --connect-timeout 1 --max-time 2 -x socks5://"${warp_listen_addr:=127.0.0.1:1080}" 'http://cp.cloudflare.com/generate_204')" -eq 204 ]; then
					break
				else
					systemctl restart warp-svc
					sleep 2
				fi
			fi
		done
	fi
}
EOF

disable_filter() {
	echo / >/proc/net/xt_tls/hostset/blacklist
	iptables -w -t filter -D OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
	ip6tables -w -t filter -D OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
	sed -i "/^Sni_Filtering=/s/=.*/=disable/" $HOME_DIR/conf/config.ini
}

get_cdn_ips() {
	if [ ! -s /tmp/ips4 ] || [ ! -s /tmp/ips6 ]; then
		Wget_get_files /tmp/ips4 https://www.cloudflare.com/ips-v4
		Wget_get_files /tmp/ips6 https://www.cloudflare.com/ips-v6
	fi
}

get_china_ips() {
	local dl=() chv4 chv6
	chv4=$(curl --silent --connect-timeout 5 --location https://bgp.space/china.html | grep -oP '([0-9]+\.){3}[0-9]+?\/[0-9]{1,2}' | grep -Ev '^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\.')
	if [ -z "$chv4" ]; then
		chv4=$(curl --silent --connect-timeout 5 --location https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt | grep -oP '([0-9]+\.){3}[0-9]+?\/[0-9]{1,2}')
	fi
	chv6=$(curl --silent --connect-timeout 5 --location https://bgp.space/china6.html | grep -oP '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\/[0-9]{1,3}' | grep -Ev '^::')
	if [ -z "$chv4" ] || [ -z "$chv6" ]; then
		dl+=("http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest+/tmp/delegated-apnic-latest")
		Downloader "${dl[@]}"
	fi
	#https://www.jianshu.com/p/3b850fb77142
	if [ -z "$chv4" ]; then
		chv4=$(awk -F '|' '/CN/&&/ipv4/ {print $4 "/" 32-log($5)/log(2)}' /tmp/delegated-apnic-latest)
	fi
	if [ -z "$chv6" ]; then
		chv6=$(awk -F '|' '/CN/&&/ipv6/ {print $4 "/" 32-log($5)/log(2)}' /tmp/delegated-apnic-latest)
	fi
	if [ "$chv4" ] && [ "$chv6" ]; then
		if [ -s ${HOME_DIR:?}/conf/server_block.acl ]; then
			cat >${HOME_DIR:?}/conf/block_china-list.acl <<EOF
$(cat ${HOME_DIR:?}/conf/server_block.acl)
$chv4
$chv6
EOF
		else
			cat >${HOME_DIR:?}/conf/block_china-list.acl <<EOF
[accept_all]
[outbound_block_list]
$chv4
$chv6
EOF
		fi
	else
		return 1
	fi
}

enable_cdn_firewall() {
	ipset create cdn_only4 hash:net family inet
	ipset create cdn_only6 hash:net family inet6
	while IFS= read -r line || [ -n "$line" ]; do
		[ "$line" ] && ipset add cdn_only4 "$line"
	done </tmp/ips4
	while IFS= read -r line || [ -n "$line" ]; do
		[ "$line" ] && ipset add cdn_only6 "$line"
	done </tmp/ips6
	iptables -w -t filter -A INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset #禁止非CDN来源访问(tcp连接重置)
	ip6tables -w -t filter -A INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only6 src -j REJECT --reject-with tcp-reset
}

disable_cdn_firewall() {
	iptables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset
	ip6tables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only6 src -j REJECT --reject-with tcp-reset
	ipset destroy cdn_only4
	ipset destroy cdn_only6
}

Advanced_features() {
	while true; do
		clear
		unset -v server
		local ngx pfm error_code=0
		if [ -s /run/nginx.pid ]; then
			read -r ngx </run/nginx.pid
		fi
		if [ -d /proc/"${ngx:=lzbx}" ]; then
			if [ -s $HOME_DIR/ssl/fullchain.cer ]; then
				if ! openssl x509 -checkend 86400 -noout -in $HOME_DIR/ssl/fullchain.cer >/dev/null; then
					if [ ${Language:=zh-CN} = 'en-US' ]; then
						#echo -e '\033[7;31;43mCertificate has expired or will do so within 24 hours!\033[0m'
						notice="Certificate has expired or will do so within 24 hours!"
					else
						#echo -e '\033[7;31;43m证书已过期或将在24小时内过期!\033[0m'
						notice="证书已过期或将在24小时内过期!"
					fi
				fi
			fi
			#echo -e "\033[1mnginx\033[0m is running as pid \033[7m$ngx\033[0m"
			nginx_on="enable"
		else
			unset -v nginx_on ngx
		fi
		if [ -s /run/php-fpm.pid ]; then
			read -r pfm </run/php-fpm.pid
		fi
		if [ -d /proc/"${pfm:=lzbx}" ]; then
			#echo -e "\033[1mphp-fpm\033[0m is running as pid \033[7m$pfm\033[0m"
			phpfpm_on="enable"
		else
			unset -v phpfpm_on pfm
		fi
		${python:-python3} <<-EOF
			from rich.console import Console
			from rich.columns import Columns
			from rich.panel import Panel
			def run1():
			  if "$nginx_on" == 'enable':
			    return f"[green]运行中[/green]"
			  else:
			    return f"[yellow]已停止[/yellow]"
			def run2():
			  if "$phpfpm_on" == 'enable':
			    return f"[green]运行中[/green]"
			  else:
			    return f"[yellow]已停止[/yellow]"
			def notification():
			    return f"${notice:=None}"
			def menu1():
			    return f"1. 打开代理\n2. 关闭代理\n3. 代理测试\n4. 获取共享节点\n5. 添加IP地址\n6. 添加Google网段\n7. 添加Cloudflare网段\n8. 清空IP列表\n9. 查看IP列表\n10. 查看iptables规则链状态\n11. 80,443端口流量代理"
			def menu2():
			    return f"12. 开启Nginx\n13. 关闭Nginx\n14. 重新申请证书\n15. 更换网站模板\n16. 仅限通过CDN访问\n17. 订阅开关"
			def menu3():
			    return f"18. 输入交互"
			def menu4():
			    return f"19. BBR内核管理\n20. SNI阻断屏蔽\n21. 禁止访问中国地址"
			console = Console()
			title1 = [Panel(run1(), expand=True, title="Nginx", subtitle="${ngx:-0}")]
			title2 = [Panel(run2(), expand=True, title="PHP-FPM", subtitle="${pfm:-0}")]
			if "${notice:=None}" == 'None':
			  console.print(Columns(title1+title2))
			else:
			  if "${Language:=zh-CN}" == 'en-US':
			    title3 = [Panel(notification(), expand=True, title="Notice")]
			  else:
			    title3 = [Panel(notification(), expand=True, title="事件通知")]
			  console.print(Columns(title1+title2+title3))
			title4 = [Panel(menu1(), expand=True, title="服务器发出流量代理")]
			title5 = [Panel(menu2(), expand=True, title="CDN中转+Nginx分流")]
			title6 = [Panel(menu3(), expand=True, title="脚本设置")]
			title7 = [Panel(menu4(), expand=True, title="访问控制")]
			console.print(Columns(title4+title5+title6+title7))
		EOF
		: <<'EOF'
—————————————— 服务器发出流量代理 ——————————————
1. 打开代理
2. 关闭代理
3. 代理测试
4. 添加IP地址
5. 添加Google网段
6. 添加Cloudflare网段
7. 清空IP列表
8. 查看IP列表
9. 查看iptables规则链状态
10. 80,443端口流量代理
—————————————— CDN中转+Nginx分流 ——————————————
11. 开启Nginx
12. 关闭Nginx
13. 重新申请证书
14. 更换网站模板
15. 仅限通过CDN访问
16. 订阅开关
—————————————— 脚本设置 ——————————————
17. 输入交互
—————————————— 访问控制 ——————————————
18. BBR内核管理
19. SNI阻断屏蔽
20. 禁止访问中国大陆地址
EOF
		read -rp $'请选择 \e[95m1-21\e[0m: ' -n2 action
		echo
		case $action in
		1)
			if [ "$internet6" ] && [ -z "$internet4" ]; then
				Prompt "仅支持IPv4!"
				Exit
			fi
			for i in sslocal ssr-local trojan v2ray tun2socks jq; do
				if [ ! -f $HOME_DIR/usr/bin/$i ] || [ ! -x $HOME_DIR/usr/bin/$i ]; then
					Wget_get_files $HOME_DIR/usr/bin/$i $URL/usr/bin/$i
					chmod +x $HOME_DIR/usr/bin/$i
				fi
			done
			cat <<EOF
收集到的一些免费分享节点网站
https://lncn.org/
https://m.ssrtool.us/free_ssr
https://github.com/aiboboxx/v2rayfree
流量转发到的代理或端口。
  1. ss  $([ "$(pgrep sslocal)" ] && echo '(active)')
  2. ssr $([ "$(pgrep ssr-local)" ] && echo '(active)')
  3. trojan $([ "$(pgrep trojan)" ] && echo '(active)')
  4. v2ray $([ "$(pgrep -F /tmp/v2ray-client.pid 2>/dev/null)" ] && echo '(active)')
  5. warp $(ss -lntp | grep -q 'warp-svc' && echo '(active)')
EOF
			read -rp $'请选择 \e[95m1-5\e[0m: ' -n1 action
			echo
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 4 ] && {
				Close_traffic_forward 2>/dev/null
				if [ "$action" -eq 1 ]; then
					Shadowsocks_Link_Decode
					[ ! -s /tmp/sslocal.json ] && error_code=1
				elif [ "$action" -eq 2 ]; then
					ShadowsocksR_Link_Decode
					[ ! -s /tmp/ssr-local.json ] && error_code=1
				elif [ "$action" -eq 3 ]; then
					Trojan_Link_Decode
					[ ! -s /tmp/trojan-client.json ] && error_code=1
				elif [ "$action" -eq 4 ]; then
					V2ray_Link_Decode
					[ ! -s /tmp/v2ray-client.json ] && error_code=1
				fi
				if [ "$server" ] && [ "$server" != "null" ] && [ "$error_code" -eq 0 ]; then
					server=$(ping -c1 -W1 -q -n "$server" | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\1/p')
					if [ "$server" ]; then
						if [[ $server == *":"* ]]; then
							Prompt "仅支持IPv4!"
							error_code=1
						fi
					else
						Prompt "获取IP地址失败！"
						error_code=1
					fi
				fi
				if [ "$server" ] && [ "$server" != "null" ] && [ "$error_code" -eq 0 ]; then
					#setcap也可以改变运行uid
					#start-stop-daemon --start --chuid nobody --exec /usr/bin/id -- -G
					#start-stop-daemon --start --background --make-pidfile --pidfile $PID --exec $DAEMON -- $DAEMON_OPTS "\"$COMMAND\""
					#https://stackoverflow.com/a/2523838
					case $action in
					1)
						if sslocal --config /tmp/sslocal.json --local-addr 127.0.0.1:1080 --daemonize --daemonize-pid /tmp/sslocal.pid -U; then
							Start_tun2socks 'socks5://127.0.0.1:1080'
							if [ "$error_code" -eq 0 ]; then
								Start_traffic_forward_v4
								ipset add bypass_ips_v4 "$server"
							fi
							rm -f /tmp/sslocal.json
						else
							Prompt "启动sslocal失败！"
							Exit
						fi
						;;
					2)
						if ssr-local -c /tmp/ssr-local.json -f /run/ssr-local.pid; then
							Start_tun2socks 'socks5://127.0.0.1:1080'
							if [ "$error_code" -eq 0 ]; then
								Start_traffic_forward_v4
								ipset add bypass_ips_v4 "$server"
							fi
							rm -f /tmp/ssr-local.json
						else
							Prompt "启动ssr-local失败！"
							Exit
						fi
						;;
					3)
						if ${HOME_DIR}/usr/bin/trojan --config /tmp/trojan-client.json -t; then
							if start-stop-daemon --start --background --make-pidfile --pidfile /tmp/trojan-client.pid --chuid nobody --exec ${HOME_DIR}/usr/bin/trojan -- --config /tmp/trojan-client.json --log /dev/null; then
								Start_tun2socks 'socks5://127.0.0.1:1080'
								if [ "$error_code" -eq 0 ]; then
									Start_traffic_forward_v4
									ipset add bypass_ips_v4 "$server"
								fi
								rm -f /tmp/trojan-client.json
							else
								Prompt "启动trojan失败！"
								Exit
							fi
						else
							Prompt "请检查trojan配置是否有误！"
							Exit
						fi
						;;
					4)
						if ${HOME_DIR}/usr/bin/v2ray test -c /tmp/v2ray-client.json; then
							if start-stop-daemon --start --background --make-pidfile --pidfile /tmp/v2ray-client.pid --chuid nobody --exec ${HOME_DIR}/usr/bin/v2ray -- run -c /tmp/v2ray-client.json; then
								Start_tun2socks 'socks5://127.0.0.1:1080'
								if [ "$error_code" -eq 0 ]; then
									Start_traffic_forward_v4
									ipset add bypass_ips_v4 "$server"
								fi
								rm -f /tmp/v2ray-client.json
							else
								Prompt "启动v2ray失败！"
								Exit
							fi
						else
							Prompt "请检查v2ray配置是否有误！"
							Exit
						fi
						;;
					esac
				fi
			}
			if [ "${action:-0}" -eq 5 ]; then
				if ! command_exists warp-cli; then
					source /etc/os-release
					if [ -z "$VERSION_CODENAME" ]; then
						VERSION_CODENAME="$(awk -F"[)(]+" '/VERSION=/ {print $2}' /etc/os-release)"
					fi
					if [ "$VERSION_CODENAME" ]; then
						Introduction "安装cloudflare-warp"
						apt-get -qq install -y --no-install-recommends apt-transport-https ca-certificates >/dev/null
						curl --silent --no-buffer https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
						echo "deb http://pkg.cloudflareclient.com/ $VERSION_CODENAME main" | tee /etc/apt/sources.list.d/cloudflare-client.list
						echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $VERSION_CODENAME main" | tee /etc/apt/sources.list.d/cloudflare-client.list
						apt update -qqy >/dev/null 2>&1
						DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends cloudflare-warp 1>/dev/null
						if ! command_exists warp-cli; then
							Prompt "无法安装cloudflare-warp可能不支持你的系统https://pkg.cloudflareclient.com/install"
							Exit
						fi
						#systemctl enable warp-svc.service
					else
						Prompt "无法获取系统开发代号名"
						Exit
					fi
				fi
				Close_traffic_forward 2>/dev/null
				while true; do
					if ! warp-cli --accept-tos network 1>/dev/null; then
						systemctl restart warp-svc
						sleep 1
						if ! warp-cli --accept-tos network 1>/dev/null; then
							Prompt "启动warp-cli失败！"
							Exit
						fi
					else
						if warp-cli --accept-tos account | grep -q 'Error\|Missing registration.'; then
							yes | warp-cli --accept-tos register
						else
							break
						fi
					fi
				done
				#注意: 这个代理不能添加Cloudflare网段代理，因为它会自动直连这些IP段造成本地回环无法访问使用了这个CDN的网站
				#https://developers.cloudflare.com/warp-client/setting-up/linux
				warp-cli --accept-tos set-mode proxy
				warp-cli --accept-tos set-proxy-port 1080
				warp-cli --accept-tos connect
				#warp-cli --accept-tos enable-always-on
				Start_tun2socks 'socks5://127.0.0.1:1080'
				if [ "$error_code" -eq 0 ]; then
					Start_traffic_forward_v4
					#https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall#warp-ingress-ip
					#iptables -w -t mangle -R SHADOWSOCKS_v4 2 -p tcp -m set --match-set traffic_forward_v4 dst -j MARK --set-mark 0x2233
					ipset add bypass_ips_v4 "$(warp-cli --accept-tos warp-stats | grep 'Endpoints' | grep -oE '([0-9]+\.){3}[0-9]+?')/24"
				fi
				#warp-cli --accept-tos warp-stats
			fi
			;;
		2)
			Close_traffic_forward
			;;
		3)
			if [ "$ipv4" ] && [ "$internet4" ]; then
				Proxy_Check 4
			elif [ "$ipv6" ] && [ "$internet6" ]; then
				Proxy_Check 6
			fi
			;;
		4)
			Free_SS
			;;
		5)
			read -rp "请输入IP地址: " aip
			if [[ $aip == *":"* ]]; then
				Prompt "仅支持IPv4!"
				Exit
				#ipset add traffic_forward_v6 "$aip"
			else
				ipset add traffic_forward_v4 "$aip"
			fi
			;;
		6)
			#https://support.google.com/a/answer/10026322?hl=zh-Hans#
			#IFS=$'\n'
			local google_ipv4_ranges google_ipv6_ranges
			if iptables -w -t mangle -C OUTPUT -o "$internet4" -j SHADOWSOCKS_v4 2>/dev/null; then
				google_ipv4_ranges=$(curl --silent --connect-timeout 5 https://www.gstatic.com/ipranges/goog.json | jq -r '.prefixes[].ipv4Prefix' | tr '\n' '@') && {
					IFS='@'
					for i in $google_ipv4_ranges; do
						[ "$i" = "null" ] || [ "$i" = "8.8.4.0/24" ] || [ "$i" = "8.8.8.0/24" ] && continue
						[ "$i" ] && ipset add traffic_forward_v4 "$i"
					done
				}
			fi
			if ip6tables -w -t mangle -C OUTPUT -o "$internet6" -j SHADOWSOCKS_v6 2>/dev/null; then
				google_ipv6_ranges=$(curl --silent --connect-timeout 5 https://www.gstatic.com/ipranges/goog.json | jq -r '.prefixes[].ipv6Prefix' | tr '\n' '@') && {
					IFS='@'
					for i in $google_ipv6_ranges; do
						[ "$i" = "null" ] || [ "$i" = "2001:4860::/32" ] && continue
						[ "$i" ] && ipset add traffic_forward_v6 "$i"
					done
				}
			fi
			;;
		7)
			local cloudflare_ipv4_ranges cloudflare_ipv6_ranges
			if iptables -w -t mangle -C OUTPUT -o "$internet4" -j SHADOWSOCKS_v4 2>/dev/null; then
				cloudflare_ipv4_ranges=$(curl --silent --connect-timeout 5 https://www.cloudflare.com/ips-v4 | grep -oE '([0-9]+\.){3}[0-9]+?\/[0-9]+?' | tr '\n' '@') && {
					IFS='@'
					for i in $cloudflare_ipv4_ranges; do
						[ "$i" = "null" ] && continue
						[ "$i" ] && ipset add traffic_forward_v4 "$i"
					done
				}
			fi
			if ip6tables -w -t mangle -C OUTPUT -o "$internet6" -j SHADOWSOCKS_v6 2>/dev/null; then
				cloudflare_ipv6_ranges=$(curl --silent --connect-timeout 5 https://www.cloudflare.com/ips-v6 | grep -oE '([a-f0-9:]+:+)+\/[0-9]+' | tr '\n' '@') && {
					IFS='@'
					for i in $cloudflare_ipv6_ranges; do
						[ "$i" = "null" ] && continue
						[ "$i" ] && ipset add traffic_forward_v6 "$i"
					done
				}
			fi
			;;
		8)
			ipset flush traffic_forward_v4 2>/dev/null
			ipset flush traffic_forward_v6 2>/dev/null
			;;
		9)
			ipset list traffic_forward_v4 2>/dev/null
			ipset list traffic_forward_v6 2>/dev/null
			;;
		10)
			iptables -vxn -t mangle -L SHADOWSOCKS_v4 --line-number 2>/dev/null
			ip6tables -vxn -t mangle -L SHADOWSOCKS_v6 --line-number 2>/dev/null
			;;
		11)
			if iptables -w -t mangle -C OUTPUT -o "$internet4" -j SHADOWSOCKS_v4 2>/dev/null; then
				if iptables -w -t mangle -C SHADOWSOCKS_v4 -m set --match-set traffic_forward_v4 dst -j MARK --set-mark 0x2233 2>/dev/null; then
					iptables -w -t mangle -R SHADOWSOCKS_v4 2 -p tcp -m multiport --dport 80,443 -j MARK --set-mark 0x2233
					iptables -w -t mangle -I SHADOWSOCKS_v4 3 -p udp -m multiport --dport 80,443 -j MARK --set-mark 0x2233
				else
					iptables -w -t mangle -R SHADOWSOCKS_v4 2 -p tcp -m multiport --dport 80,443 -j MARK --set-mark 0x2233
				fi
			fi
			;;
		12)
			if [ -z "$nginx_on" ]; then
				#if ! netstat -ln | grep 'LISTEN' | grep -q ':80 \|:443 '; then
				if ! ss -ln state listening '( sport = :80 or sport = :443 )' | grep -q ':80 \|:443 '; then
					if [ "$Firewall_Service" = "enable" ]; then
						disable_cdn_firewall 2>/dev/null
						enable_cdn_firewall 2>/dev/null
					fi
					Start_nginx_program
				else
					Prompt "80或443端口被其它进程占用！"
				fi
			else
				Prompt "服务运行中请先停止运行!"
			fi
			;;
		13)
			pkill -F /run/nginx.pid && rm -f /run/nginx.pid
			pkill -F /run/php-fpm.pid && rm -f /run/php-fpm.pid
			sed -i "/^Nginx_Switch=/s/=.*/=disable/" $HOME_DIR/conf/config.ini
			if [ "$Firewall_Service" = "enable" ]; then
				disable_cdn_firewall 2>/dev/null
			fi
			;;
		14)
			local cert_a1="" cert_a2="" cert_a3=""
			cert_a1=$(openssl x509 -dates -noout -in $HOME_DIR/ssl/fullchain.cer 2>/dev/null)
			if [ "$cert_a1" ]; then
				cert_a2=${cert_a1%notAfter*}
				cert_a3=${cert_a2#*notBefore=}
				Prompt "证书申请时间: $(date -d "${cert_a3% *}" +'%Y/%m/%d %H:%M:%S')  证书过期时间: $(date -d "${cert_a1#*notAfter=}" +'%Y-%m-%d %H:%M:%S')"
			fi
			#openssl x509 -enddate -noout -in $HOME_DIR/ssl/fullchain.cer #过期日
			Introduction "确定要更新吗? [Y/n]"
			read -rp "(${mr:=默认}: N): " delete
			if [[ $delete =~ ^[Yy]$ ]]; then
				rm -f $HOME_DIR/ssl/*
				Create_certificate
			else
				Prompt "已取消操作..."
			fi
			;;
		15)
			if [ "$nginx_on" ]; then
				Create_certificate
				cat <<EOF
为防止伪装站点千篇一律，特意准备了以下模板。
1. Speedtest-X
2. Mikutap
3. Flappy Winnie
4. FlappyFrog
5. bao
6. ninja
7. X Prober
8. 爱特文件管理器
9. 创建测速文件(不占用实际空间)
EOF
				read -rp $'请选择 \e[95m1-9\e[0m: ' -n1 action
				echo
				is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 8 ] && {
					rm -rf $HOME_DIR/web
					case $action in
					1)
						git clone --depth 1 https://github.com/BadApple9/speedtest-x $HOME_DIR/web
						;;
					2)
						git clone --depth 1 https://github.com/HFIProgramming/mikutap $HOME_DIR/web
						;;
					3)
						git clone --depth 1 https://github.com/hahaxixi/hahaxixi.github.io $HOME_DIR/web
						;;
					4)
						git clone --depth 1 https://github.com/hahaxixi/FlappyFrog $HOME_DIR/web
						;;
					5)
						git clone --depth 1 https://github.com/hahaxixi/bao $HOME_DIR/web
						;;
					6)
						git clone --depth 1 https://github.com/hahaxixi/ninja $HOME_DIR/web
						;;
					7)
						mkdir -p $HOME_DIR/web && Wget_get_files $HOME_DIR/web/index.php https://github.com/kmvan/x-prober/raw/master/dist/prober.php
						;;
					8)
						git clone --depth 1 https://github.com/xiaoqidun/phpcp $HOME_DIR/web
						;;
					esac
				}
				is_number "$action" && [ "$action" -eq 9 ] && {
					local size filename
					read -rp $'文件大小 \e[95mMB\e[0m: ' size
					read -rp $'请输入名称+文件后缀，例如\e[95m200.swf\e[0m: ' filename
					if is_number "$size" && [ "$filename" ]; then
						dd if=/dev/zero of=$HOME_DIR/web/"$filename" bs=1M seek="${size:-0}" count=0
						if [ -f $HOME_DIR/web/"$filename" ]; then
							Prompt "你的测速文件地址为 https://$tls_common_name/$filename"
						fi
					fi
				}
				if [ -d $HOME_DIR/web ]; then
					chown -R nobody $HOME_DIR/web
				fi
				Reload_nginx
			else
				Prompt "使用此功能需要先开启Nginx"
			fi
			;;
		16)
			if [ "$nginx_on" ]; then
				Create_certificate
				cat <<EOF
为了Nginx服务器安全仅允许CDN的来源IP访问Nginx上架设的网页与反向代理。(目前仅支持Cloudflare)
1. 开启WAF防火墙 $([ -s $HOME_DIR/conf/cdn_only.conf ] && echo "(true)")
2. 关闭WAF防火墙
3. 启用iptables防护 $(iptables -w -t filter -C INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset >/dev/null 2>&1 && echo "(true)")
4. 取消iptables防护
EOF
				read -rp $'请选择 \e[95m1-4\e[0m: ' -n1 action
				is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 4 ] && {
					get_cdn_ips
					case $action in
					1)
						rm -f $HOME_DIR/conf/cdn_only.conf
						: <<'EOF'
if (\$http_cf_ipcountry = "") {
  return 403;
}
if (\$http_cf_connecting_ip = "") {
  return 403;
}
EOF
						echo -e "$(</tmp/ips4)\n$(</tmp/ips6)" | while IFS= read -r line; do
							[ "$line" ] && echo "allow   $line;" >>$HOME_DIR/conf/cdn_only.conf
						done
						echo "deny    all;" >>$HOME_DIR/conf/cdn_only.conf
						rm -f /tmp/ips4 /tmp/ips6
						Reload_nginx
						;;
					2)
						rm -f $HOME_DIR/conf/cdn_only.conf
						Reload_nginx
						;;
					3)
						if enable_cdn_firewall; then
							sed -i "/^Firewall_Service=/s/=.*/=enable/" $HOME_DIR/conf/config.ini
							Prompt "iptables规则添加完毕！"
						fi
						;;
					4)
						if disable_cdn_firewall; then
							sed -i "/^Firewall_Service=/s/=.*/=disable/" $HOME_DIR/conf/config.ini
							Prompt "iptables规则清理完成！"
						fi
						;;
					esac
				}
				echo
			else
				Prompt "使用此功能需要先开启Nginx"
			fi
			;;
		17)
			if [ "$nginx_on" ]; then
				Create_certificate
				cat <<EOF
需要客户端支持服务器订阅功能。
1. 开启订阅 $([ -s $HOME_DIR/web/subscriptions.php ] && echo "(true)")
2. 关闭订阅
EOF

				read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
				echo
				is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 2 ] && {
					case $action in
					1)
						Wget_get_files $HOME_DIR/web/subscriptions.php $URL/src/subscriptions.php
						Prompt "你的订阅地址为 https://$tls_common_name/subscriptions.php"
						cat <<EOF
如果你的访问受到ISP干扰还可以使用以下地址进行加速访问
https://proxy.freecdn.workers.dev/?url=https://$tls_common_name/subscriptions.php
支持传入参数
https://gitlab.com/yiguihai/ss/-/wikis/订阅管理
EOF
						Subscribe=enable
						;;
					2)
						rm -f $HOME_DIR/web/subscriptions.php
						Subscribe=disable
						;;
					esac
					if [ "$Subscribe" ]; then
						sed -i "/^Subscribe=/s/=.*/=$Subscribe/" $HOME_DIR/conf/config.ini
						Check_permissions
					fi
				}
			else
				Prompt "使用此功能需要先开启Nginx"
			fi
			;;
		18)
			if command_exists dialog; then
				local ver
				ver=$(dialog --version)
				#if [ "${ver:9:1}" -le 1 ] && [ "${ver:11:1}" -lt 3 ]; then
				if [ "${ver##*-}" -lt 20201126 ]; then
					apt-get purge -y --auto-remove dialog
				fi
			fi
			if ! command_exists dialog; then
				Introduction "安装dialog"
				Wget_get_files /tmp/dialog_amd64.deb http://snapshot.debian.org/archive/debian/20210103T024108Z/pool/main/d/dialog/dialog_1.3-20201126-1_amd64.deb
				#https://packages.debian.org/
				Wget_get_files /tmp/libtinfo6_amd64.deb http://ftp.us.debian.org/debian/pool/main/n/ncurses/libtinfo6_6.2+20201114-2_amd64.deb
				Wget_get_files /tmp/libncursesw6_amd64.deb http://ftp.us.debian.org/debian/pool/main/n/ncurses/libncursesw6_6.2+20201114-2_amd64.deb
				if ! DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/libtinfo6_amd64.deb /tmp/libncursesw6_amd64.deb /tmp/dialog_amd64.deb 1>/dev/null; then
					Prompt "无法安装dialog"
					Exit
				fi
				rm -f /tmp/dialog_amd64.deb /tmp/libncursesw6_amd64.deb /tmp/libtinfo6_amd64.deb
			fi
			#https://codychen.me/2020/29/linux-shell-的圖形互動式介面-dialog/
			cat <<EOF
Linux Dialog 是可以在 Terminal 上快速建立圖形交互介面的工具，功能十分強大、方便。本脚本用于"添加端口"时的图形化输入交互。
  1. default $([ "$Dialog" = "disable" ] && echo "(true)")
  2. dialog $([ "$Dialog" = "enable" ] && echo "(true)")
EOF
			read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
			echo
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 2 ] && {
				case $action in
				1)
					Dialog=disable
					;;
				2)
					Dialog=enable
					;;
				esac
				if [ "$action" ]; then
					sed -i "/^Dialog=/s/=.*/=$Dialog/" $HOME_DIR/conf/config.ini
					Check_permissions
				fi
			}
			;;
		19)
			: <<'EOF'
/etc/debian_version
/etc/issue
/proc/version
3.10.0-957.21.2.
3 – This is the main kernel version
.10 – This is the major release version
.0 – This is the minor revision level
-957 – This is the level of patches and bug fixes
EOF
			source /etc/os-release
			kernel_ver=$(uname -r | grep -oE '[0-9]+([.]?[0-9]+)+' | head -n1)
			local BIT CPU
			#https://www.cyberciti.biz/faq/how-do-i-know-if-my-linux-is-32-bit-or-64-bit/
			BIT=$(getconf LONG_BIT)
			if [ "$(grep -o -w 'lm' /proc/cpuinfo | sort -u)" = "lm" ]; then
				CPU=64
			else
				CPU=32
			fi
			#if [ -d /proc/xen ]; then
			#Prompt "Xen virtualization is not supported"
			#Exit
			#fi
			if [ ! -d /proc/vz ]; then
				if [ "${BIT:-32}" -eq 64 ] && [ "${CPU:-32}" -eq 64 ]; then
					if [ "${ID?}" = "debian" ] || [ "${ID?}" = "ubuntu" ]; then
						cat <<EOF
==================================================
* OS - $PRETTY_NAME
* Version - $VERSION_ID
* Kernel - $(uname -mrs)
==================================================
  1. 安装支持BBRv2的内核
  2. 切换加速算法($(sysctl -nbe net.ipv4.tcp_congestion_control)+$(sysctl -nbe net.core.default_qdisc))
  3. 卸载旧内核
EOF
						read -rp $'请选择 \e[95m1-3\e[0m: ' -n1 action
						echo
						case $action in
						1)
							kernel_install
							;;
						2)
							if [ "$kernel_ver" = "5.13.12" ]; then
								kernel_tcp_congestion_control
							else
								Prompt "请先安装BBR内核"
							fi
							;;
						3)
							if [ "$kernel_ver" = "5.13.12" ]; then
								kernel_uninstall
							else
								Prompt "先安装BBR内核重启过后再卸载旧内核"
							fi
							;;
						esac
					else
						Prompt "Unsupported systems $ID"
					fi
				else
					Prompt "Only 64-bit is supported"
				fi
			else
				Prompt "OpenVZ virtualization is not supported"
			fi
			;;
		20)
			getmodule_install
			cat <<EOF
xt_tls is an extension for netfilter/IPtables that allows you to filter traffic based on TLS hostnames.
GFW同款过滤工具←_←ECH加密遥遥无期...打不过就加入你墙我也墙满足你变态的控制欲。来啊互相伤害啊！
  1. 开启SNI过滤$(iptables -w -t filter -C OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset >/dev/null 2>&1 && echo "(true)")
  2. 关闭SNI过滤
  3. 编辑过滤规则
  4. 查看阻断统计
  5. 查看日志记录
  6. 清理日志记录
EOF
			read -rp $'请选择 \e[95m1-6\e[0m: ' -n1 action
			echo
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 6 ] && {
				case $action in
				1)
					enable_filter
					;;
				2)
					disable_filter
					;;
				3)
					vim ${HOME_DIR:?}/conf/sni.ini
					;;
				4)
					if [ -r /proc/net/xt_tls/hostset/blacklist ]; then
						local temp_file
						temp_file='/dev/shm/sssni.tmp'
						cp -f /proc/net/xt_tls/hostset/blacklist "$temp_file"
						${python:-python3} <<-EOF
							from rich.console import Console
							from rich.table import Table
							from rich import box
							table = Table(title="审计规则表", box=box.ASCII, show_lines=True)
							table.add_column("拦截次数", justify="left", no_wrap=True)
							table.add_column("匹配域名", justify="right")
							with open("$temp_file", 'r', encoding='utf8') as fd:
							  for lines in fd.read().splitlines():
							    #https://blog.csdn.net/qq523176585/article/details/83003346
							    a, b = [x for x in lines.split(' ') if x]
							    if int(a) > 0:
							      a = '[bold red]' + a
							      b = '[bold yellow underline]' + b
							    else:
							      b = '[bold blue underline]' + b
							    table.add_row(a, b)
							console = Console()
							console.print(table, justify="left")
						EOF
						rm -f "$temp_file"
					fi
					;;
				5)
					dmesg -w
					#journalctl --grep=xt_tls
					;;
				6)
					#https://unix.stackexchange.com/a/457902
					journalctl --rotate
					journalctl --vacuum-time=1s
					journalctl --flush
					for i in syslog messages kern.log; do
						if [ -s /var/log/$i ]; then
							cat /dev/null >/var/log/"$i"
						fi
					done
					#https://www.gnutoolbox.com/clearing-dmesg-logs/
					dmesg -c
					;;
				esac
			}
			;;
		21)
			cat <<EOF
通过ACL访问控制可以阻止访问中国大陆的IP地址，相当于强制客户端开启[绕过中国大陆地址]与阻止一些服务器被墙的安全问题
理论依据 https://github.com/shadowsocks/shadowsocks-org/issues/184#issuecomment-927275836
  1. 开启 $([ "$Block_China" = "enable" ] && echo "(true)")
  2. 关闭
EOF
			read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
			echo
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 2 ] && {
				case $action in
				1)
					Block_China=enable
					;;
				2)
					Block_China=disable
					;;
				esac
				if [ "$action" ]; then
					Prompt "需要重启脚本服务以应用本次修改"
					sed -i "/^Block_China=/s/=.*/=$Block_China/" $HOME_DIR/conf/config.ini
					Check_permissions

				fi
			}
			;;
		*)
			break
			;;
		esac
		Press_any_key_to_continue
	done
}

Start_tc_limit() {
	#https://tonydeng.github.io/sdn-handbook/linux/tc.html
	#https://wiki.archlinux.org/title/advanced_traffic_control
	local i pid_file sspid local_address local_port internet
	if [ -s ${HOME_DIR:?}/port.list ]; then
		for i in lo $internet4 $internet6; do
			tc qdisc add dev "$i" root handle 1: htb default 30
			tc class add dev "$i" parent 1: classid 1:1 htb rate 1Gbit burst 15k
		done
		i=1
		#tc qdisc add dev lo root handle 2: cbq avpkt 1000 bandwidth 10Gbit #根队列
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			if is_number "$server_port" && is_number $total && is_number $upload_limit && is_number $download_limit; then
				pid_file=${HOME_DIR}/pid/shadowsocks-server-${server_port}.pid
				if [ -s "$pid_file" ]; then
					read -r sspid <"$pid_file"
				fi
				if [ -d /proc/"${sspid:=lzbx}" ]; then
					local_address=$(ss -lntp | grep "pid=${sspid:=lzbx}" | awk -F' ' '{print $4}')
					local_port="${local_address##*:}"
					if is_number "$local_port" && [ "$local_port" -gt 0 ] && [ "$local_port" -le 65535 ]; then
						if [ "${local_address%:*}" = '::1' ] || [ "${local_address%:*}" = '127.0.0.1' ]; then
							internet='lo'
						else
							internet="${internet4:?}"
						fi
						if [ "$upload_limit" -gt 0 ] || [ "$download_limit" -gt 0 ]; then
							((i++))
						fi
						if [ "$plugin" ] && [ "$plugin_opts" ]; then
							if [ "$upload_limit" -gt 0 ]; then
								tc class add dev "${internet:?}" parent 1:1 classid 1:"$i" htb rate "$((upload_limit * 8))"kbit burst 15k
								tc qdisc add dev "${internet:?}" parent 1:"$i" handle "$i": sfq perturb 10
								tc filter add dev "${internet:?}" parent 1: protocol ip u32 match ip protocol 6 0xff match ip dport "${local_port:?}" 0xffff flowid 1:"$i" #上传速度限制
								if [ "$ipv6" ] && [ "$internet6" ]; then
									tc filter add dev "${internet:?}" parent 1: protocol ipv6 u32 match ip6 protocol 6 0xff match ip6 dport "${local_port:?}" 0xffff flowid 1:"$i" #IPv6
								fi
								((i = i + 1))
							fi
						fi
						if [ "$download_limit" -gt 0 ]; then
							tc class add dev "${internet:?}" parent 1:1 classid 1:"$i" htb rate "$((download_limit * 8))"kbit burst 15k
							tc qdisc add dev "${internet:?}" parent 1:"$i" handle "$i": sfq perturb 10
							tc filter add dev "${internet:?}" parent 1: protocol ip u32 match ip protocol 6 0xff match ip sport "${local_port:?}" 0xffff flowid 1:"$i" #下载速度限制
							if [ "$ipv6" ] && [ "$internet6" ]; then
								tc filter add dev "${internet:?}" parent 1: protocol ipv6 u32 match ip6 protocol 6 0xff match ip6 sport "${local_port:?}" 0xffff flowid 1:"$i" #IPv6
							fi
							((i = i + 1))
						fi
					else
						Prompt "配置 ${server_port} 端口限速规则时失败！${local_port}"
					fi
				fi
				unset -v pid_file sspid local_address local_port
			fi
			if [ "$i" -ge 9999 ]; then
				break #最大9999如果超出了就再新绑定一个根队列不过基本不可能有这么多用户
			fi
		done <${HOME_DIR:?}/port.list
	fi
}

Stop_tc_limit() {
	for i in lo $internet4 $internet6; do
		tc qdisc del root dev "$i" 2>/dev/null
	done
}

Reload_tc_limit() {
	Stop_tc_limit
	Start_tc_limit
}

Language() {
	cat <<EOF
  1. English (US)
  2. Chinese (PRC)
EOF
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		read -rp $'请选择需要切换的语言 [\e[95m1-2\e[0m]:' -n1 un_select
	else
		read -rp $'Please enter a number [\e[95m1-2\e[0m]:' -n1 un_select
	fi
	echo
	case $un_select in
	1)
		Language="en-US"
		;;
	2)
		Language="zh-CN"
		;;
	esac
	if [ "$Language" ]; then
		sed -i "/^Language=/s/=.*/=$Language/" $HOME_DIR/conf/config.ini
		Check_permissions
	fi
}

Exit() {
	kill -9 $NOW_PID
}

Check
if [ "$1" = "daemon" ]; then
	Daemon
elif [ "$1" = "start" ]; then
	Start
	if [ "$Sni_Filtering" = "enable" ]; then
		getmodule_install
		enable_filter
	fi
	if [ "$Firewall_Service" = "enable" ]; then
		get_cdn_ips
		enable_cdn_firewall
	fi
elif [ "$1" = "restart" ]; then
	Stop
	Start
elif [ "$1" = "stop" ]; then
	Stop
else
	if [ "$1" = "debug" ]; then
		set -o xtrace || set -e
	fi
	while true; do
		clear
		#Author
		Status
		${python:-python3} <<-EOF
			from random import randint
			from rich.console import Console
			from rich.columns import Columns
			from rich.text import Text
			from rich.highlighter import Highlighter
			from rich.panel import Panel
			from rich import box
			class RainbowHighlighter(Highlighter):
			    def highlight(self, text):
			        for index in range(len(text)):
			            text.stylize(f"color({randint(16, 255)})", index, index + 1)
			def runing():
			  if "${Language:=zh-CN}" == 'en-US':
			    return f"[b]Service Status[/b]\n${statusr}"
			  else:
			    return f"[b]服务状态[/b]\n${statusr}"
			def menu1():
			  if "${Language:=zh-CN}" == 'en-US':
			    return f"1. User Management->>\n2. Turn on service\n3. Close service\n4. Uninstallation\n5. Upgrade\n6. 更换语言\n7. Advanced Features->>"
			  else:
			    return f"1. 用户列表->>\n2. 启动运行\n3. 停止运行\n4. 卸载删除\n5. 版本更新\n6. Language\n7. 高级功能->>"
			console = Console()
			rainbow = RainbowHighlighter()
			text = Text()
			text.append("Shadowsocks-rust", style="bold #dea584")
			#text.append(" v${ss_ver##* }", style="bold italic #ee82ee")
			ss_ver = "${ss_ver}"
			if len(ss_ver) > 3:
			  text.append(" v${ss_ver}", style="bold italic #ee82ee")
			if "${Language:=zh-CN}" == 'en-US':
			  text.append(" Multiport Management")
			else:
			  text.append(" 多端口管理脚本")
			text.append(" By")
			text.append(rainbow(" 爱翻墙的红杏"))
			console.print(Panel.fit(text, box=box.HORIZONTALS))
			title1 = [Panel(runing(), expand=True)]
			console.print(Columns(title1))
			if "${Language:=zh-CN}" == 'en-US':
			  title2 = [Panel(menu1(), expand=True, title="Menu")]
			else:
			  title2 = [Panel(menu1(), expand=True, title="菜单")]
			console.print(Columns(title2))
		EOF
		[ $force_uninstall ] && Uninstall
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			: <<'EOF'
  1. User Management->>
  2. Turn on service 
  3. Close service
  4. Uninstallation
  5. Upgrade
  6. 更换语言
  7. Advanced Features->>
EOF
			read -rp $'Please enter a number [\e[95m1-7\e[0m]:' -n1 action
			mr="Default"
		else
			: <<'EOF'
  1. 用户列表->>
  2. 启动运行
  3. 停止运行
  4. 卸载删除
  5. 版本更新
  6. Language
  7. 高级功能->>
EOF
			read -rp $'请选择 [\e[95m1-7\e[0m]: ' -n1 action
		fi
		echo
		case $action in
		1)
			User_list_display
			;;
		2)
			Start
			;;
		3)
			Check_from
			Stop
			;;
		4)
			Check_from
			Uninstall
			;;
		5)
			Update_core
			;;
		6)
			Language
			;;
		7)
			Advanced_features
			;;
		*)
			break
			;;
		esac
	done
fi
