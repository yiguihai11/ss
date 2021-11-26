#!/bin/bash
# shellcheck source=/dev/null

NOW_PID=$$
HOME_DIR=/etc/ssmanager
export PATH=${PATH}:${HOME_DIR}/usr/bin:${HOME_DIR}/usr/sbin:${PWD}

Encryption_method_list=(
	plain
	none
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
	aes-128-ccm
	aes-256-ccm
	aes-128-gcm-siv
	aes-256-gcm-siv
	xchacha20-ietf-poly1305
	sm4-gcm
	sm4-ccm
)

Generate_random_numbers() (
	min=$1
	max=$(($2 - min + 1))
	num=$((RANDOM + 1000000000)) #增加一个10位的数再求余
	printf '%d' $((num % max + min))
)

Introduction_bar() (
	while IFS= read -r c; do
		printf "\e[1;33m#\e[0m"
	done <<EOF
$(fold -w1)
EOF
	echo
)

Introduction() (
	cat >&1 <<-EOF

		$(printf '%s' "$*" | Introduction_bar)
		$1
		$(printf '%s' "$*" | Introduction_bar)

	EOF
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
	cat >&1 <<-EOF

		$(printf '%s' "$*" | Prompt_bar)
		$1
		$(printf '%s' "$*" | Prompt_bar)

	EOF
)

# 判断命令是否存在
command_exists() {
	#type -P $@
	command -v "$@" >/dev/null 2>&1
}

#https://stackoverflow.com/a/808740
is_number() {
	[ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null
}

# 按任意键继续
Press_any_key_to_continue() {
	if [ "${Language:=zh-CN}" = "en-US" ]; then
		read -n 1 -r -s -p $'Press any key to start...or Press Ctrl+C to cancel'
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
	python3 <<-EOF
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
	unset -v addr
	local cur_time last_time tb_addr
	if [ ! -s /tmp/myaddr ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Loading ..."
		else
			Prompt "请稍等 ..."
		fi
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://ipapi.co/json | jq -r '.city + ", " +.region + ", " + .country_name')
		else
			addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://myip.ipip.net)
			if [ "$addr" ]; then
				addr=${addr##*\来\自\于}
				addr=${addr:1}
				if [[ $addr == *"台湾"* ]]; then
					addr=${addr/中国/中华民国}
					addr=${addr/台湾省/台湾}
				fi
			else
				#https://wangshengxian.com/article/details/article_id/37.html
				tb_addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' "https://ip.taobao.com/outGetIpInfo?ip=${ipv4:-$ipv6}&accessKey=alibaba-inc")
				if [ "$tb_addr" ]; then
					case $(echo "$tb_addr" | jq -r '.code') in
					0)
						if [ "$(echo "$tb_addr" | jq -r '.data.region')" = "台湾" ]; then
							tb_addr=${tb_addr/中国/中华民国}
							tb_addr=${tb_addr/CN/TW}
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
	unset -v server_port password method plugin plugin_opts total upload_limit download_limit
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
		total)
			total=${l#*^}
			;;
		upload_limit)
			upload_limit=${l#*^}
			;;
		download_limit)
			download_limit=${l#*^}
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
	if [ "$2" ] && [ -s "$2" ]; then
		a=$(<"${2}")
	else
		a=$(ss-tool /tmp/ss-manager.socket ping 2>/dev/null)
	fi
	b=${a##*\{}
	c=${b%%\}*}
	IFS=','
	for i in ${c//\"/}; do
		IFS=' '
		for j in $i; do
			if [ "${j%\:*}" = "$1" ]; then
				is_number "${j#*\:}" && printf '%d' "${j#*\:}"
			fi
		done
	done
)

Create_certificate() {
	unset -v ca_type eab_kid eab_hmac_key tls_common_name tls_key tls_cert
	tls_key="$HOME_DIR"/ssl/server.key
	tls_cert="$HOME_DIR"/ssl/server.cer
	until [ -s $tls_key ] || [ -s $tls_cert ]; do
		if [ -z "$nginx_on" ] && [ "$(ss -lnH state listening '( sport = :80 )')" ]; then
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
		if "${HOME:?}"/.acme.sh/acme.sh --issue --domain "$tls_common_name" "${nginx_on:=--standalone}" -k ec-256 --server "$ca_type" --force; then
			if "${HOME:?}"/.acme.sh/acme.sh --install-cert --domain "$tls_common_name" --cert-file "$tls_cert" --key-file "$tls_key" --ca-file ${HOME_DIR:?}/ssl/ca.cer --fullchain-file ${HOME_DIR:?}/ssl/fullchain.cer --ecc --server "$ca_type" --force; then
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
	done
	if [ ! -s $tls_key ] || [ ! -s $tls_cert ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "The certificate file could not be found!"
		else
			Prompt "无法找到证书文件! "
		fi
		Exit
	fi
	tls_common_name=$(openssl x509 -noout -subject -in $tls_cert | cut -d' ' -f3)
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
	source ${HOME_DIR:?}/conf/config.ini
	local cs=5 i4 i6
	while true; do
		((cs--))
		if [ ${cs:-0} -eq 0 ]; then
			if [ ${Language:=en-US} = 'zh-CN' ]; then
				Prompt "获取IP地址失败！"
			else
				Prompt "Failed to get IP address!"
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
			if [ "$ipv4" ] && [ "$Protocol" = "ipv4" ]; then
				unset -v ipv6
			elif [ "$ipv6" ] && [ "$Protocol" = "ipv6" ]; then
				unset -v ipv4
			elif [ "$ipv4" ]; then
				Protocol=ipv4
				unset -v ipv6
			elif [ "$ipv6" ]; then
				Protocol=ipv6
				unset -v ipv4
			else
				unset -v ipv4 ipv6
			fi
			[ "$ipv4" ] || [ "$ipv6" ] && break
			sleep 1
		fi
	done
	python3 <<-EOF
		from ipaddress import ip_address
		from subprocess import run
		if not ip_address("${ipv4:-$ipv6}").is_global:
		  if "${Language:=en-US}" == 'zh-CN':
		    print('\n从本机获取到的IP \033[1;41m ${ipv4:-$ipv6} \033[0m 不是公网地址')
		  else:
		    print('\nThe IP \033[1;41m ${ipv4:-$ipv6} \033[0m obtained from this machine is not a public address!')
		  run("kill $NOW_PID", shell=True, check=True, capture_output=True, timeout=2,universal_newlines=True)
	EOF
}

Check() {
	if [ ${UID:=65534} -ne 0 ]; then
		Prompt "You must run this script as root!"
		Exit
	fi
	if command_exists apt; then
		common_install='apt-get -qq install -y --no-install-recommends'
		common_remove='apt-get purge -y --auto-remove'
	else
		Prompt "The script does not support the package manager in this operating system."
		Exit
	fi
	#https://qastack.cn/ubuntu/481/how-do-i-find-the-package-that-provides-a-file
	local az=0 package_list sorted_arr
	declare -a package_list=(systemctl wget curl ss pkill socat jq openssl shasum iptables ipset git python3 pip3 ping vim gpg)
	#if ! command_exists debconf; then
	#$common_install apt-utils 1>/dev/null
	#fi
	for i in "${package_list[@]}"; do
		if ! command_exists "$i"; then
			case $i in
			ss)
				i="iproute2"
				;;
			pkill)
				i="psmisc"
				;;
			shasum)
				i="libdigest-sha-perl"
				;;
			pip3)
				i="python3-pip"
				;;
			systemctl)
				i="systemd"
				;;
			ping)
				i="iputils-ping"
				;;
			gpg)
				i="gnupg"
				;;
			*)
				i="$i"
				;;
			esac
			sorted_arr+=("$i")
		fi
	done
	if [ "${#sorted_arr[*]}" -ge 1 ]; then
		#https://brettterpstra.com/2015/03/17/shell-tricks-sort-a-bash-array-by-length/ 重新排列数组
		IFS=$'\n' GLOBIGNORE='*' mapfile -t sorted_arr < <(printf '%s\n' "${sorted_arr[@]}" | awk '{ print length($0) " " $0; }' | sort -n | cut -d ' ' -f 2-)
		for i in "${sorted_arr[@]}"; do
			((az++))
			[ "$az" -le 1 ] && clear
			#echo $(((az * 100 / ${#package_list2[*]} * 100) / 100)) | whiptail --gauge "Please wait while installing" 6 60 0
			Progress_Bar "$az" ${#sorted_arr[*]} "Installing $i"
			if ! $common_install "$i" 1>/dev/null; then
				Prompt "There is an exception when installing the program!"
				Exit
			fi
			#[ $az -eq ${#package_list2[*]} ] && clear
		done
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
		if [[ "$(ping -c1 -W1 -q -n raw.githubusercontent.com | grep -oE '([0-9]+\.){3}[0-9]+?')" != +(127.0.0.1|0.0.0.0) ]]; then
			test1=0
		else
			test1=1
		fi
		if [ "$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --resolve raw.githubusercontent.com:443:185.199.109.133 https://raw.githubusercontent.com/yiguihai/shadowsocks_install/dev/README.md)" = 200 ]; then
			test2=0
		else
			test2=1
		fi
		#搜索github CDN加速 https://segmentfault.com/a/1190000038298623
		if [ $((test1 + test2)) -eq 0 ]; then
			URL="https://github.com/yiguihai/shadowsocks_install/raw/dev"
		else
			URL="https://cdn.jsdelivr.net/gh/yiguihai/shadowsocks_install@dev"
		fi
	fi
	if [ ! -s $HOME_DIR/conf/config.ini ]; then
		Wget_get_files $HOME_DIR/conf/config.ini $URL/conf/config.ini
		if [ "$Language" ]; then
			sed -i "/^Language=/s/=.*/=$Language/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Protocol" ]; then
			sed -i "/^Protocol=/s/=.*/=$Protocol/" $HOME_DIR/conf/config.ini
		fi
		if [ "$Dialog" ]; then
			sed -i "/^Dialog=/s/=.*/=$Dialog/" $HOME_DIR/conf/config.ini
		fi
		if [ "$URL" ]; then
			echo "URL=$URL" >>$HOME_DIR/conf/config.ini
		else
			Prompt "Unable to get download node!"
			Exit
		fi
		Check_permissions
	fi
	Local_IP
	if ! python3 -c "import rich" 2>/dev/null; then
		if ! pip3 install -q rich; then
			Prompt "Unable to install rich module!"
			Exit
		fi
	fi
	if [ ! -s $HOME_DIR/conf/update.log ]; then
		Wget_get_files $HOME_DIR/conf/update.log $URL/version/update
	fi
	local dl=() Binary_file_list=("${HOME_DIR:?}/usr/bin/kcptun.sh")
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
	if [ ! -s $HOME_DIR/conf/server_block.acl ]; then
		Wget_get_files $HOME_DIR/conf/server_block.acl $URL/acl/server_block.acl
	fi
	if [ ! -s /etc/systemd/system/ss-main.service ]; then
		Wget_get_files /etc/systemd/system/ss-main.service $URL/init.d/ss-main.service
		chmod 0644 /etc/systemd/system/ss-main.service
		systemctl enable ss-main.service
		systemctl daemon-reload
		systemctl reset-failed
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
	local ssm dae status xz
	if [ -s /run/ss-manager.pid ]; then
		read -r ssm </run/ss-manager.pid
	fi
	if [ -d /proc/"${ssm:=lzbx}" ]; then
		if [ -s /run/ss-daemon.pid ]; then
			read -r dae </run/ss-daemon.pid
		fi
		if [ -d /proc/"${dae:=lzbx}" ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				status="\033[1;37;42mRuning\033[0m"
			else
				status="\033[1;37;42m运行中\033[0m"
			fi
			runing=true
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				status="\033[1;37;43mThe daemon is not running\033[0m"
			else
				status="\033[1;37;43m守护脚本未运行\033[0m"
			fi
			Stop
		fi
	else
		if [[ "$(ssmanager -V)" == "shadowsocks"* ]]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				status="\033[1;37;41mStopped\033[0m"
			else
				status="\033[1;37;41m未运行\033[0m"
			fi
			runing=false
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				status="\033[1;37;41mSystem incompatibility\033[0m"

			else
				status="\033[1;37;41m系统或版本不兼容\033[0m"
			fi
			xz=true
		fi
	fi
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		echo -e "Service Status: $status"
	else
		echo -e "服务状态: $status"
	fi
	[ $xz ] && Uninstall
}

Obfs_plugin() {
	unset -v obfs
	local obfs_rust=(http tls)
	if [ "${Dialog:=disable}" = 'enable' ]; then
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
				15 40 4 \
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
	if [ ${Dialog:=disable} = 'enable' ]; then
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
				15 40 4 \
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
			if [ ${Dialog:=disable} = 'enable' ]; then
				v2ray_path=$(
					dialog --title "v2ray-plugin" \
						--backtitle "插件" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--no-cancel \
						--inputbox "请输入一个监听路径(url path): " \
						10 50 "${v2ray_paths%% *}" \
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
			if [ ${Dialog:=disable} = 'enable' ]; then
				v2ray_servicename=$(
					dialog --title "v2ray-plugin" \
						--backtitle "插件" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--colors \
						--no-cancel \
						--inputbox "请输入gRPC服务的名称: " \
						10 50 "${v2ray_paths%% *}" \
						2>&1 >/dev/tty
				)
			else
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Service name for grpc"
				else
					Introduction "请输入gRPC服务的名称:"
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
	read -r kcp_key
	[ -z "$kcp_key" ] && kcp_key="$password"
	[ -z "$kcp_key" ] && kcp_key="it's a secrect"
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
	read -rp "(${mr:=默认}: 1024): " kcp_sndwnd
	! is_number "$kcp_sndwnd" && kcp_sndwnd=1024
	Prompt "$kcp_sndwnd"

	unset -v kcp_rcvwnd
	Introduction "rcvwnd"
	read -rp "(${mr:=默认}: 1024): " kcp_rcvwnd
	! is_number "$kcp_rcvwnd" && kcp_rcvwnd=1024
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
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "After setting the basic parameters, do you need to set additional hidden parameters? [Y/n]"
	else
		Introduction "基础参数设置完成，你是否需要设置额外的隐藏参数? [Y/n]"
	fi
	read -rp "(${mr:=默认}: N): " extra_parameters
	if [[ $extra_parameters =~ ^[Yy]$ ]]; then
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
		read -rp "(${mr:=默认}: 0): " kcp_nodelay
		! is_number "$kcp_nodelay" && kcp_nodelay=0
		Prompt "$kcp_nodelay"

		unset -v kcp_interval
		Introduction "interval"
		read -rp "(${mr:=默认}: 30): " kcp_interval
		! is_number "$kcp_interval" && kcp_interval=30
		Prompt "$kcp_interval"

		unset -v kcp_resend
		Introduction "resend"
		read -rp "(${mr:=默认}: 2): " kcp_resend
		! is_number "$kcp_resend" && kcp_resend=2
		Prompt "$kcp_resend"

		unset -v kcp_nc
		Introduction "nc"
		read -rp "(${mr:=默认}: 1): " kcp_nc
		! is_number "$kcp_nc" && kcp_nc=1
		Prompt "$kcp_nc"
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
			15 40 4 \
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
			15 40 4 \
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
		25 60 16 \
		"key:" 1 1 "$password" 1 25 25 30 \
		"mtu:" 2 1 1350 2 25 25 30 \
		"sndwnd:" 3 1 128 3 25 25 30 \
		"rcvwnd:" 4 1 512 4 25 25 30 \
		"datashard,ds:" 5 1 10 5 25 25 30 \
		"parityshard,ps:" 6 1 3 6 25 25 30 \
		"dscp:" 7 1 0 7 25 25 30 \
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
	if dialog --clear --erase-on-exit --title "kcptun" --backtitle "插件" --yes-label "确定" --no-label "取消" --defaultno --yesno "基础参数设置完成，你是否需要设置额外的隐藏参数?" 7 50; then
		extra_parameters="Y"
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
			25 60 16 \
			"nodelay:" 1 1 0 1 25 25 30 \
			"interval:" 2 1 30 2 25 25 30 \
			"resend:" 3 1 2 3 25 25 30 \
			"nc:" 4 1 1 4 25 25 30 \
			2>&1 >/dev/tty)
	fi
	# close fd
	exec 3>&-
}

Speed_limit_input() {
	while true; do
		if [ ${Dialog:=disable} = 'enable' ]; then
			#https://cloud.tencent.com/developer/article/1409664 一般只能限制网卡发送的数据包，不能限制网卡接收的数据包，所以可以通过改变发送次序来控制传输速率。Linux流量控制主要是在输出接口排列时进行处理和实现的。
			#脚本中实现上传限速是因为插件与ssserver在本地进行了转发。
			: <<EOF
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
					--form "不需要使用限速的可以直接回车跳过，上传可以稍微调大一点数值不要设置太小因为实际传输有损耗会低于限速带宽。" \
					25 60 16 \
					"上传 (KB/s):" 1 1 0 1 25 25 30 \
					"下载 (KB/s):" 2 1 0 2 25 25 30 \
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
						10 50 0 \
						2>&1 >/dev/tty
				)
			fi
		else
			if [ "$add_plugin" ] && [ "$plugin" ]; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Please enter the port upload speed limit (KB/s): "
				else
					Introduction "请输入端口上传速度的限制值 (KB/s): "
				fi
				read -rp "(${mr:=默认}: 0): " upload_limit
			fi
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter the port download speed limit (KB/s): "
			else
				Introduction "请输入端口下载速度的限制值 (KB/s): "
			fi
			read -rp "(${mr:=默认}: 0): " download_limit
		fi
		if ! is_number "$upload_limit" || [ "$upload_limit" -le 0 ]; then
			upload_limit=0
		fi
		if ! is_number "$download_limit" || [ "$download_limit" -le 0 ]; then
			download_limit=0
		fi
		if [ "$upload_limit" -gt 0 ] && [ "$download_limit" -gt 0 ]; then
			Prompt "▲ $upload_limit KB/s | ▼ $download_limit KB/s"
		else
			if [ "$upload_limit" -gt 0 ]; then
				Prompt "▲ $upload_limit KB/s"
			fi
			if [ "$download_limit" -gt 0 ]; then
				Prompt "▼ $download_limit KB/s"
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
		if [ ${Dialog:=disable} = 'enable' ]; then
			server_port=$(
				dialog --title "端口" \
					--backtitle "Shadowsocks" \
					--ok-label "确定" \
					--clear \
					--erase-on-exit \
					--no-cancel \
					--inputbox "请输入Shadowsocks远程端口:" \
					10 50 "$sport" \
					2>&1 >/dev/tty
			)
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter a port"
			else
				Introduction "请输入Shadowsocks远程端口:"
			fi
			read -rp "(${mr:=默认}: $sport): " -n5 server_port
			[ -z "$server_port" ] && server_port=$sport
		fi

		if is_number "$server_port" && [ "$server_port" -gt 0 ] && [ "$server_port" -le 65535 ]; then
			if is_number "$(Used_traffic "$server_port")"; then
				if [ ${Dialog:=disable} = 'enable' ]; then
					dialog --title "提示" \
						--backtitle "Shadowsocks" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--no-cancel \
						--msgbox "端口正常使用中！" \
						6 20
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
			if [ "$(ss -lnH state listening "( sport = :$server_port )")" ]; then
				if [ ${Dialog:=disable} = 'enable' ]; then
					dialog --title "提示" \
						--backtitle "Shadowsocks" \
						--ok-label "确定" \
						--clear \
						--erase-on-exit \
						--no-cancel \
						--msgbox "端口被其它进程占用！" \
						6 20
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
							if [ ${Dialog:=disable} = 'enable' ]; then
								dialog --title "提示" \
									--backtitle "Shadowsocks" \
									--ok-label "确定" \
									--clear \
									--erase-on-exit \
									--no-cancel \
									--msgbox "端口已存在于端口列表中！" \
									6 20
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
	local ciphertext spass
	ciphertext=$(base64 -w0 /proc/sys/kernel/random/uuid)
	spass=${ciphertext:0:16}
	if [ ${Dialog:=disable} = 'enable' ]; then
		until [ "$password" ]; do
			password=$(dialog --title "密码" \
				--backtitle "Shadowsocks" \
				--ok-label "确定" \
				--clear \
				--erase-on-exit \
				--insecure \
				--no-cancel \
				--passwordbox "请输入Shadowsocks密码:" \
				10 50 "$spass" \
				2>&1 >/dev/tty)
		done
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Please enter a password"
		else
			Introduction "请输入Shadowsocks密码:"
		fi
		read -rp "(${mr:=默认}: $spass): " password
		[ -z "$password" ] && password=$spass
		Prompt "$password"
	fi
	if [ ${Dialog:=disable} = 'enable' ]; then
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
				15 40 4 \
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

	while true; do
		if [ ${Dialog:=disable} = 'enable' ]; then
			total=$(
				dialog --title "流量" \
					--backtitle "Shadowsocks" \
					--ok-label "确定" \
					--clear \
					--erase-on-exit \
					--colors \
					--no-cancel \
					--inputbox "请输入端口流量配额 (\Z5MB\Zn): " \
					10 50 1024 \
					2>&1 >/dev/tty
			)
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter a value for the traffic limit (MB): "
			else
				Introduction "请输入端口流量配额 (MB): "
			fi
			read -rp "(${mr:=默认}: 1024): " total
		fi
		if ! is_number "$total" || [ "$total" -le 0 ]; then
			total=1024
		fi
		if is_number "$total" && [ "$total" -gt 0 ]; then
			Prompt "$total MB"
			break
		fi
	done

	local add_plugin
	if [ ${Dialog:=disable} = 'enable' ]; then
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
		if [ ${Dialog:=disable} = 'enable' ]; then
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
					15 40 4 \
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
			if [ ${Dialog:=disable} = 'enable' ]; then
				Kcptun_plugin2
			else
				Kcptun_plugin
			fi
		elif [ "$plugin" = 'v2ray-plugin' ]; then
			V2ray_plugin
		fi
	fi
	Speed_limit_input
}

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
	local plugin_opt color temp_file net_file client_file serial port tz a1 a2 a3 a4 a5 a6 a7 a8 quantity used status total upload_limit download_limit up down
	while true; do
		clear
		temp_file='/dev/shm/sslist.tmp'
		net_file='/dev/shm/ssnet.tmp'
		client_file='/dev/shm/ssuser.tmp'
		if [ -s $HOME_DIR/port.list ]; then
			ss -tn state established >"$net_file"
			ss-tool /tmp/ss-manager.socket ping >"$client_file" 2>/dev/null
			serial=0
			#修复无法读取到最后一行的历史问题 https://stackoverflow.com/a/12916758
			while IFS= read -r line || [ -n "$line" ]; do
				Parsing_User "$line"
				if [ "$server_port" ]; then
					if [[ $plugin != "kcptun.sh" && $plugin_opts != *quic* ]]; then
						quantity=$(Client_Quantity "$server_port")
					else
						if [ ${Language:=zh-CN} = 'en-US' ]; then
							quantity='[yellow]Not supported'
						else
							quantity='[yellow]不支持'
						fi
					fi
					used=$(Used_traffic "$server_port" "$client_file")
					((serial++))
					if [ "$used" ] && [ "$used" -ge 0 ]; then
						if [ ${Language:=zh-CN} = 'en-US' ]; then
							status='[green]Normal'
						else
							status='[green]正常'
						fi
						tz=no
					else
						if [ ${Language:=zh-CN} = 'en-US' ]; then
							status='[red]Close'
						else
							status='[red]停止'
						fi
						used=0
						tz=yes
					fi
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
							plugin_opt='grpc-tls'
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
					if [ "$tz" = "yes" ]; then
						a1="[italic strike bold red]${serial:-0}"
						a2="[strike bold red]${server_port:-0}"
						a4="[strike bold red]$(Traffic $used) / $(Traffic $total)"
					else
						a1="[italic]${serial:-0}"
						a2="${server_port:-0}"
						a4="$(Traffic $used) / $(Traffic $total)"
					fi
					if [ "$plugin_opt" ]; then
						a3="${plugin}[white bold]/[#00ffff]${plugin_opt}"
					else
						a3="$plugin"
					fi
					a5="${color:-0}"
					#因为用户输入的时候是用kB为记录单位和函数需要以B为输入值所以需要转换
					if [ "${upload_limit:-0}" -gt 0 ]; then
						up="[bold green]▲[/bold green] $(Traffic $((${upload_limit:-0} * 1024)))/s"
					fi
					if [ "${download_limit:-0}" -gt 0 ]; then
						down="[bold yellow]▼[/bold yellow] $(Traffic $((${download_limit:-0} * 1024)))/s"
					fi
					if [ "$up" ] && [ "$down" ]; then
						a6="${up} [bold]|[/bold] ${down}"
					else
						a6="${up}${down}"
					fi
					a7="$quantity"
					a8="$status"
					echo "$a1,$a2,$a3,$a4,$a5,$a6,$a7,$a8" >>"$temp_file"
				fi
				unset -v quantity used status color tz plugin_opt a1 a2 a3 a4 a5 a6 a7 a8 up down
			done <$HOME_DIR/port.list
			python3 <<-EOF
				from rich.console import Console
				from rich.table import Table
				if "${Language:=zh-CN}" == 'zh-CN':
				  table = Table(title="用户列表", caption="$(TZ='Asia/Shanghai' date +%Y年%m月%d日\ %X)", show_lines=True)
				  table.add_column("序号", justify="left", no_wrap=True)
				  table.add_column("端口", justify="center", style="#66ccff")
				  table.add_column("传输插件", justify="center", style="#ee82ee", no_wrap=True)
				  table.add_column("流量", justify="center")
				  table.add_column("使用率", justify="center")
				  table.add_column("限速", justify="center")
				  table.add_column("客户端", justify="center")
				  table.add_column("状态", justify="right")
				else:
				  table = Table(title="User List", caption="$(date +'%A %B %d %T %y')", show_lines=True)
				  table.add_column("Top", justify="left", no_wrap=True)
				  table.add_column("Port", justify="center", style="#66ccff")
				  table.add_column("Plug-in", justify="center", style="#ee82ee", no_wrap=True)
				  table.add_column("Network traffic", justify="center")
				  table.add_column("Usage rate", justify="center")
				  table.add_column("Speed limit", justify="center")
				  table.add_column("Client", justify="center")
				  table.add_column("Status", justify="right")
				with open("$temp_file", 'r') as fd:
				  for lines in fd.read().splitlines():   
				    a, b, c, d, e, f, g, h = lines.split(',')
				    table.add_row(a, b, c, d, e, f, g, h)    
				console = Console()
				console.print(table, justify="center")
			EOF
		fi
		rm -f "$net_file" "$client_file" "$temp_file"
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			cat <<EOF
1. Add a Port
2. Delete a Port
3. Activate a port
4. Forcing a Port offline
EOF
			read -rp $'Please enter a number \e[95m1-3\e[0m: ' -n1 action
		else
			cat <<EOF
1. 添加端口
2. 删除端口
3. 激活端口
4. 离线端口
EOF
			read -rp $'请选择 \e[95m1-3\e[0m: ' -n1 action
		fi
		echo
		case $action in
		1)
			Add_user
			Reload_tc_limit
			;;
		2)
			Delete_users
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
			Forced_offline
			Reload_tc_limit
			;;
		*)
			break
			;;
		esac
	done
}

Add_user() {
	Address_lookup
	Shadowsocks_info_input
	if [ ${Dialog:=disable} = 'enable' ]; then
		if ! dialog --clear --erase-on-exit --title "确认" \
			--backtitle "完成" --yes-label "确定" --no-label "取消" --yesno "输入已完成如输入错误请按取消结束本次操作！" 7 50; then
			Exit
		fi
	else
		Press_any_key_to_continue
	fi
	clear
	local userinfo qrv4 qrv6 name plugin_url ss_info=() ss_link=()
	if [ "$ipv4" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			ss_info+=("Your_Server_IP(IPv4)+$ipv4")
		else
			ss_info+=("服务器(IPv4)+$ipv4")
		fi
	fi
	if [ "$ipv6" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			ss_info+=("Your_Server_IP\(IPv6\)+$ipv6")
		else
			ss_info+=("服务器\(IPv6\)+$ipv6")
		fi
	fi
	if [ "$ipv4" ] || [ "$ipv6" ]; then
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
		ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\",\"plugin\":\"obfs-server\",\"plugin_opts\":\"obfs=$obfs\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^obfs-server|plugin_opts^obfs=$obfs|total^$((total * 1048576))|upload_limit^$upload_limit|download_limit^$download_limit" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "obfs-local;obfs=$obfs;obfs-host=checkappexec.microsoft.com")"
		;;
	kcptun)
		local kcp_nocomps kcp_acknodelays
		[ "$kcp_nocomp" = "true" ] && kcp_nocomps=';nocomp'
		[ "$kcp_acknodelay" = "true" ] && kcp_acknodelays=';acknodelay'
		if [[ $extra_parameters =~ ^[Yy]$ ]]; then
			ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun.sh\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun.sh|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays|total^$((total * 1048576))|upload_limit^$upload_limit|download_limit^$download_limit" >>$HOME_DIR/port.list
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays")"
		else
			ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun.sh\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun.sh|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps|total^$((total * 1048576))|upload_limit^$upload_limit|download_limit^$download_limit" >>$HOME_DIR/port.list
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
		ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"${qui:=tcp_and_udp}\",\"plugin\":\"v2ray-plugin\",\"plugin_opts\":\"$v2ray_modes\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^v2ray-plugin|plugin_opts^$v2ray_modes|total^$((total * 1048576))|upload_limit^$upload_limit|download_limit^$download_limit" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "v2ray-plugin;$v2ray_client")"
		;;
	*)
		ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^|plugin_opts^|total^$((total * 1048576))|upload_limit^$upload_limit|download_limit^$download_limit" >>$HOME_DIR/port.list
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
		if [ "$userinfo" ] && [ "$ipv4" ]; then
			qrv4="ss://$userinfo@$ipv4:$server_port$plugin_url#$name"
			ss_link+=("$qrv4")
		fi
		if [ "$userinfo" ] && [ "$ipv6" ]; then
			qrv6="ss://$userinfo@[${ipv6}]:$server_port$plugin_url#$name"
			ss_link+=("$qrv6")
		fi
	else
		if [ "$userinfo" ] && [ "$ipv4" ]; then
			qrv4="ss://$userinfo@$ipv4:$server_port#$name"
			ss_link+=("$qrv4")
		fi
		if [ "$userinfo" ] && [ "$ipv6" ]; then
			qrv6="ss://$userinfo@[${ipv6}]:$server_port#$name"
			ss_link+=("$qrv6")
		fi
	fi
	python3 <<-EOF
		from rich import print as rprint
		from rich.console import group
		from rich.panel import Panel
		from rich.table import Table
		from random import choice
		from os import get_terminal_size

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
		if "${Language:=zh-CN}" == 'zh-CN':
		  rprint(Panel(get_panels(), title="配置信息", subtitle="以上信息请拿笔记好！"))
		else:
		  rprint(Panel(get_panels(), title="Configuration Information", subtitle="Please take note of the above information!"))
		for x in list2:
		  print('\033[4;1;35m'+x+'\033[0m')
	EOF
	Prompt "Android客户端和插件 https://github.com/yiguihai/shadowsocks_install/wiki/客户端下载"
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
			python3 -m rich.json "$temp_file"
			qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv4"
		fi
		if [ "$qrv6" ]; then
			ssurl -d "$qrv6" 1>"$temp_file"
			python3 -m rich.json "$temp_file"
			qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv6"
		fi
		rm -f "$temp_file"
	fi
	Press_any_key_to_continue
}

Delete_users() {
	if [ -s $HOME_DIR/port.list ]; then
		port=$1
		until [ "$port" ]; do
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter the user port to be deleted"
			else
				Introduction "请输入需要删除的端口"
			fi
			read -rn5 port
			if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
				break
			else
				unset -v port
			fi
		done
		local temp_file pz1 pz2
		temp_file='/dev/shm/ssdel.tmp'
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			if is_number "$server_port" && is_number $total; then
				if [[ $server_port -ne $port && $server_port -gt 0 && $server_port -lt 65535 && $password && $method && $total -gt 0 ]]; then
					echo "server_port^$server_port|password^$password|method^$method|plugin^$plugin|plugin_opts^$plugin_opts|total^$total|upload_limit^$upload_limit|download_limit^$download_limit" >>"$temp_file"
				fi
				if [ "$server_port" -eq "$port" ]; then
					ss-tool /tmp/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
					rm -f ${HOME_DIR}/pid/shadowsocks-server-"${port}".pid ${HOME_DIR}/pid/shadowsocks-server-"${port}".json
					pz1=$plugin
					pz2=$plugin_opts
				fi
			fi
		done <$HOME_DIR/port.list
		mv -f "$temp_file" $HOME_DIR/port.list
		echo
		Check_permissions
		if [[ $pz1 == "v2ray-plugin" && $pz2 != *quic* ]]; then
			Reload_nginx
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

Upload_users() {
	if [ -s $HOME_DIR/port.list ]; then
		local using client_file sy sspid sorted_arr
		client_file='/dev/shm/ssupload.tmp'
		ss-tool /tmp/ss-manager.socket ping >"$client_file" 2>/dev/null
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			[ "$1" ] && [ "$1" != "$server_port" ] && continue
			using=$(Used_traffic "$server_port" "$client_file")
			if is_number "$server_port" && is_number "$total" && [ -z "$using" ] && [ "$password" ] && [ "$method" ]; then
				if [ "$plugin" ] && [ "$plugin_opts" ]; then
					if [[ $plugin == "kcptun.sh" || $plugin_opts == *quic* ]]; then
						ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
					else
						ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
					fi
				else
					ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\"}" >/dev/null
				fi
				sorted_arr+=("${server_port}")
			fi
			unset -v using
		done <$HOME_DIR/port.list
		rm -f "$client_file"
		sy="${#sorted_arr[@]}"
		while [ "$sy" -gt 0 ]; do
			for i in "${sorted_arr[@]}"; do
				if [ -s "${HOME_DIR}/pid/shadowsocks-server-${i}.pid" ]; then
					read -r sspid <"${HOME_DIR}/pid/shadowsocks-server-${i}.pid"
					if [ -d /proc/"${sspid:=lzbx}" ]; then
						((sy--))
					fi
				fi
			done
			if [ "$sy" -gt 0 ]; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					printf '\rWaiting %d' "$sy"
				else
					printf '\r请稍等 %d' "$sy"
				fi
			else
				break
			fi
		done
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No port list file found! Please add a user port first."
		else
			Prompt "没有找到端口列表文件！请先添加端口。"
		fi
		Press_any_key_to_continue
	fi
}

Forced_offline() {
	while true; do
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Please enter the port of the user who needs to be forced offline"
		else
			Introduction "请输入需要离线的端口"
		fi
		read -rn5 port
		if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
			ss-tool /tmp/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
			break
		fi
	done
}

Daemon() {
	if [ -r /run/ss-daemon.pid ]; then
		pkill -F /run/ss-daemon.pid 2>/dev/null
	fi
	echo $NOW_PID >/run/ss-daemon.pid
	local flow pid1 pid2 client_file
	if [ -r /run/ss-manager.pid ] && [ -r /run/ss-daemon.pid ]; then
		read -r pid1 </run/ss-manager.pid
		read -r pid2 </run/ss-daemon.pid
		if is_number "$pid1" && is_number "$pid2"; then
			while [ -d /proc/"${pid1:?}" ] && [ -d /proc/"${pid2:?}" ]; do
				if [ -s ${HOME_DIR:?}/port.list ]; then
					client_file='/dev/shm/ssdaenon.tmp'
					ss-tool /tmp/ss-manager.socket ping >"$client_file" 2>/dev/null
					while IFS= read -r line || [ -n "$line" ]; do
						Parsing_User "$line"
						flow=$(Used_traffic "$server_port" "$client_file")
						if is_number "$server_port" && is_number "$flow" && is_number $total; then
							if [ "${flow:-0}" -ge ${total:-0} ]; then
								Delete_users "$server_port" >/dev/null
							fi
							unset -v flow
						fi
					done <${HOME_DIR:?}/port.list
				fi
				sleep 1
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
		local cs=60 #6秒启动超时与重试 https://github.com/shadowsocks/shadowsocks-rust/issues/587
		[ "$ipv6" ] && local first_v6='-6'
		ssmanager \
			--acl ${HOME_DIR:?}/conf/server_block.acl \
			--manager-address /tmp/ss-manager.socket \
			--manager-server-mode standalone \
			--manager-server-working-directory ${HOME_DIR:?}/pid \
			--server-host "${ipv4:-$ipv6}" \
			--outbound-bind-addr "${ipv4:-$ipv6}" \
			--daemonize-pid /run/ss-manager.pid \
			--daemonize $first_v6
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
				fi
				sleep 0.1
			fi
		done
		if [ -S /tmp/ss-manager.socket ] && [ -s /run/ss-manager.pid ]; then
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
	for i in "${HOME_DIR}"/pid/shadowsocks-server-*.pid /run/ss-manager.pid /run/ss-daemon.pid; do
		[ -s "$i" ] && read -r kpid <"$i"
		if [ -d /proc/"${kpid:=lzbx}" ]; then
			kill "$kpid"
			rm -f "$i"
			if [ -s "${HOME_DIR}/pid/shadowsocks-server-${kpid}.json" ]; then
				rm -f ${HOME_DIR}/pid/shadowsocks-server-${kpid}.json
			fi
		fi
	done
	Stop_tc_limit
}

Update_core() {
	local temp_file temp_file2 update cur_time last_time
	temp_file=$(mktemp) temp_file2=$(mktemp)
	Wget_get_files "$temp_file" $URL/version/update
	#sed -i "s=*bin=$HOME_DIR/usr/bin=" $temp_file
	! shasum -a512 -c "$temp_file" >>"$temp_file2" && update=true || update=false
	sed -i 's/: /,/g' "$temp_file2"
	python3 <<-EOF
		from rich.console import Console
		from rich.table import Table
		if "${Language:=zh-CN}" == 'zh-CN':
		  table = Table(title="程序升级列表", show_lines=True)
		  table.add_column("文件路径", justify="left", no_wrap=True)
		  table.add_column("更新状态", justify="right")
		else:
		  table = Table(title="Upgrade List", show_lines=True)
		  table.add_column("Binary program path", justify="left", no_wrap=True)
		  table.add_column("Upgrade Status", justify="right")
		with open("$temp_file2", 'r') as fd:
		  for lines in fd.read().splitlines():   
		    a, b = lines.split(',')
		    if 'OK' in b:
		      b = '[bold green]' + b
		    elif 'FAILED' in b:
		      b = '[bold yellow]' + b
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
		echo -e "\e[1mHelp and Feedback: \e[0m\e[1;34mhttps://github.com/yiguihai/shadowsocks_install\e[0m\n"
	else
		echo -e "\e[1m帮助与反馈: \e[0m\e[1;34mhttps://github.com/yiguihai/shadowsocks_install\e[0m\n"
	fi
	Press_any_key_to_continue
}

Uninstall() {
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Are you sure you want to uninstall? [Y/n]"
	else
		Introduction "确定要卸载吗? [Y/n]"
	fi
	read -rp "(${mr:=默认}: N): " delete
	if [[ $delete =~ ^[Yy]$ ]]; then
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
			Prompt "已取消操作..."
		else
			Prompt "Canceled operation..."
		fi
	fi
	Exit
}

ShadowsocksR_Link_Decode() {
	local link a b server_port protocol method obfs password other obfsparam protoparam #remarks group
	read -rp "请输入SSR链接: " link
	[[ $link != "ssr://"* || -z $link ]] && Exit
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
	cat >/tmp/ssr-redir.conf <<EOF
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
    "mode":"tcp_only",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "timeout":30
}
EOF
	python3 -m rich.json /tmp/ssr-redir.conf
}

Close_traffic_forward() {
	iptables -w -t nat -D OUTPUT -j SHADOWSOCKS
	iptables -w -t nat -F SHADOWSOCKS
	iptables -w -t nat -X SHADOWSOCKS
	ipset destroy traffic_forward
	ipset destroy bypass_lan
	if [ -s /run/ssr-redir.pid ]; then
		pkill -F /run/ssr-redir.pid
		rm -f /run/ssr-redir.pid
	fi
	local ipt
	ipt=$(pgrep ipt2socks)
	if [ "$ipt" ]; then
		kill "$ipt"
	fi
	warp-cli disconnect
}

Start_traffic_forward() {
	iptables -w -t nat -N SHADOWSOCKS
	ipset create traffic_forward hash:net
	ipset create bypass_lan hash:net
	#iptables -w -t nat -A SHADOWSOCKS -m owner --uid-owner nobody -j ACCEPT
	#iptables -w -t nat -A SHADOWSOCKS -p tcp -j LOG --log-prefix='[netfilter] '
	#grep 'netfilter' /var/log/kern.log
	iptables -w -t nat -A SHADOWSOCKS -m set --match-set bypass_lan dst -j RETURN
	iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set traffic_forward dst -j REDIRECT --to-ports "${1:-60080}"
	iptables -w -t nat -A OUTPUT -j SHADOWSOCKS
	ipset add bypass_lan 127.0.0.1/8
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
	local releases_url="https://github.com/yiguihai/shadowsocks_install/releases/download/kernel" answer
	if [ "$kernel_ver" != "5.13.12" ]; then
		#https://github.com/netblue30/firejail/issues/2232
		#https://my.oschina.net/u/3888259/blog/4414015
		iptables -vxn -t nat -L OUTPUT --line-number 1>/dev/null || update-alternatives --set iptables /usr/sbin/iptables-legacy
		ip6tables -vxn -t nat -L OUTPUT --line-number 1>/dev/null || update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
		local dl=("${releases_url}/linux-headers-5.13.12_5.13.12-1_amd64.deb+/tmp/linux-header.deb")
		dl+=("${releases_url}/linux-image-5.13.12_5.13.12-1_amd64.deb+/tmp/linux-image.deb")
		dl+=("${releases_url}/linux-libc-dev_5.13.12-1_amd64.deb+/tmp/linux-libc.deb")
		dl+=("${releases_url}/libxt_tls.so+/tmp/libxt_tls.so")
		dl+=("${releases_url}/xt_tls.ko+/tmp/xt_tls.ko")
		Downloader "${dl[@]}"
		for i in linux-header.deb linux-image.deb linux-libc.deb; do
			if [ -s "/tmp/$i" ]; then
				dpkg --install "/tmp/$i"
			else
				Prompt "Download $i failed."
				Exit
			fi
		done
		install -D -v -m 644 /tmp/libxt_tls.so /usr/lib/x86_64-linux-gnu/xtables
		install -D -v -m 644 /tmp/xt_tls.ko /usr/lib/modules/5.13.12/kernel/net/netfilter
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
						    include    v2safe.conf;
						    proxy_pass ${v2_protocols}://${ipv4:-[$ipv6]}:${server_port};
						    include    proxy.conf;
						}
						    
					EOF
				fi
			fi
		done <$HOME_DIR/port.list
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
	local ngx
	if [ -s /run/nginx.pid ]; then
		read -r ngx </run/nginx.pid
	fi
	if [ -d /proc/"${ngx:=lzbx}" ]; then
		Start_nginx_program reload
	fi
}

Advanced_features() {
	local two=0
	while true; do
		((two++))
		if [ "$two" -le 1 ]; then
			#免费节点
			#https://lncn.org/
			#https://m.ssrtool.us/free_ssr
			for i in ssr-redir ipt2socks; do
				if [ ! -f $HOME_DIR/usr/bin/$i ] || [ ! -x $HOME_DIR/usr/bin/$i ]; then
					Wget_get_files $HOME_DIR/usr/bin/$i $URL/usr/bin/$i
					chmod +x $HOME_DIR/usr/bin/$i
				fi
			done
			if ! command_exists warp-cli; then
				Introduction "安装cloudflare-warp"
				#https://pkg.cloudflareclient.com/install
				curl --silent --no-buffer https://pkg.cloudflareclient.com/pubkey.gpg | apt-key add -
				source /etc/os-release
				echo "deb http://pkg.cloudflareclient.com/ $VERSION_CODENAME main" | tee /etc/apt/sources.list.d/cloudflare-client.list
				apt update -qqy >/dev/null 2>&1
				if $common_install cloudflare-warp 1>/dev/null; then
					yes | warp-cli register
				else
					Prompt "无法安装cloudflare-warp"
					Exit
				fi
			fi
		fi
		local ngx pfm
		if [ -s /run/nginx.pid ]; then
			read -r ngx </run/nginx.pid
		fi
		if [ -d /proc/"${ngx:=lzbx}" ]; then
			if [ -s $HOME_DIR/ssl/fullchain.cer ]; then
				if ! openssl x509 -checkend 86400 -noout -in $HOME_DIR/ssl/fullchain.cer >/dev/null; then
					if [ ${Language:=zh-CN} = 'en-US' ]; then
						echo -e '\033[7;31;43mCertificate has expired or will do so within 24 hours!\033[0m'
					else
						echo -e '\033[7;31;43m证书已过期或将在24小时内过期!\033[0m'
					fi
				fi
			fi
			echo -e "\033[1mnginx\033[0m is running as pid \033[7m$ngx\033[0m"
			nginx_on="--webroot ${HOME_DIR}/ssl"
		else
			nginx_on="--standalone"
		fi
		if [ -s /run/php-fpm.pid ]; then
			read -r pfm </run/php-fpm.pid
		fi
		if [ -d /proc/"${pfm:=lzbx}" ]; then
			echo -e "\033[1mphp-fpm\033[0m is running as pid \033[7m$pfm\033[0m"
		fi
		cat <<EOF
—————————————— 服务器发出流量代理 ——————————————
1. 打开代理
2. 关闭代理
3. SSR链接解析
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
16. 订阅管理
—————————————— 脚本设置 ——————————————
17. 双栈切换
18. 输入交互
—————————————— 访问控制 ——————————————
19. BBR内核管理
20. SNI阻断屏蔽
EOF
		read -rp $'请选择 \e[95m1-20\e[0m: ' -n2 action
		echo
		case $action in
		1)
			local ret_code
			ret_code=$(curl --silent --output /dev/null --write-out '%{http_code}' --connect-timeout 2 --max-time 4 --url https://www.google.com)
			#https://stackoverflow.com/a/28356429
			if [[ ${ret_code:-0} != +(200|301|302) ]]; then
				echo -e '\033[7;31;43m无法访问Google请尝试切换或者关闭代理！\033[0m'
			fi
			cat <<EOF
流量转发到的代理或端口。仅支持IPv4
  1. ssr $([ "$(pgrep ssr-redir)" ] && echo '(active)')
  2. warp-cli
EOF
			read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
			echo
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 2 ] && {
				Close_traffic_forward 2>/dev/null
				case $action in
				1)
					ShadowsocksR_Link_Decode
					[ ! -s /tmp/ssr-redir.conf ] && Exit
					ssr-redir -c /tmp/ssr-redir.conf -f /run/ssr-redir.pid || Exit
					rm -f /tmp/ssr-redir.conf
					Start_traffic_forward 1080
					ipset add bypass_lan "$server"
					;;
				2)
					#https://developers.cloudflare.com/warp-client/setting-up/linux
					warp-cli set-mode proxy
					warp-cli set-proxy-port 1080
					warp-cli connect
					#warp-cli enable-always-on
					local cs=3
					while true; do
						((cs--))
						if [ ${cs:-0} -eq 0 ]; then
							Prompt "启动warp-cli超时!"
							Exit
						else
							if curl --connect-timeout 1 --max-time 2 -x socks5://127.0.0.1:1080 'https://www.cloudflare.com/cdn-cgi/trace/' 2>/dev/null; then
								setsid ipt2socks --redirect 1>/dev/null &
								Start_traffic_forward
								echo
								warp-cli warp-stats
								break
							fi
							sleep 1
						fi
					done
					;;
				esac
			}
			;;
		2)
			Close_traffic_forward
			;;
		3)
			ShadowsocksR_Link_Decode
			;;
		4)
			read -rp "请输入IP地址: " aip
			ipset add traffic_forward "$aip"
			;;
		5)
			#https://support.google.com/a/answer/10026322?hl=zh-Hans#
			#IFS=$'\n'
			local google_ipv4_ranges
			google_ipv4_ranges=$(curl --silent --connect-timeout 5 https://www.gstatic.com/ipranges/goog.json | jq -r '.prefixes[].ipv4Prefix' | tr '\n' '@') && {
				IFS='@'
				for i in $google_ipv4_ranges; do
					[ "$i" = "null" ] || [ "$i" = "8.8.4.0/24" ] || [ "$i" = "8.8.8.0/24" ] && continue
					[ "$i" ] && ipset add traffic_forward "$i"
				done
			}
			;;
		6)
			local cloudflare_ipv4_ranges
			cloudflare_ipv4_ranges=$(curl --silent --connect-timeout 5 https://www.cloudflare.com/ips-v4 | grep -oE '([0-9]+\.){3}[0-9]+?\/[0-9]+?' | tr '\n' '@') && {
				IFS='@'
				for i in $cloudflare_ipv4_ranges; do
					[ "$i" = "null" ] && continue
					[ "$i" ] && ipset add traffic_forward "$i"
				done
			}
			;;
		7)
			ipset flush traffic_forward
			;;
		8)
			ipset list traffic_forward
			;;
		9)
			iptables -vxn -t nat -L SHADOWSOCKS --line-number
			;;
		10)
			local rports
			rports="$(iptables -n -t nat -L SHADOWSOCKS --line-number | grep 'redir ports')"
			iptables -w -t nat -R SHADOWSOCKS 2 -p tcp -m multiport --dport 80,443 -j REDIRECT --to-ports "${rports##* }"
			;;
		11)
			if [ "$nginx_on" = "--standalone" ]; then
				#if ! netstat -ln | grep 'LISTEN' | grep -q ':80 \|:443 '; then
				if [ -z "$(ss -lnH state listening '( sport = :80 or sport = :443 )')" ]; then
					Start_nginx_program
				else
					Prompt "80或443端口被其它进程占用！"
				fi
			else
				Prompt "服务运行中请先停止运行!"
			fi
			;;
		12)
			pkill -F /run/nginx.pid && rm -f /run/nginx.pid
			pkill -F /run/php-fpm.pid && rm -f /run/php-fpm.pid
			;;
		13)
			openssl x509 -dates -noout -in $HOME_DIR/ssl/fullchain.cer
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
		14)
			cat <<EOF
为防止伪装站点千篇一律，特意准备了以下模板(更换模板后因清空了web文件夹订阅程序需要重新开启)
1. Speedtest-X
2. Mikutap
3. Flappy Winnie
4. FlappyFrog
5. bao
6. ninja
7. X Prober
8. 爱特文件管理器
EOF
			read -rp $'请选择 \e[95m1-8\e[0m: ' -n1 action
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
				if [ -d $HOME_DIR/web ]; then
					chown -R nobody $HOME_DIR/web
				fi
			}
			;;
		15)
			cat <<EOF
为了Nginx服务器安全仅允许CDN的来源IP访问Nginx上架设的网页与反向代理。(目前仅支持Cloudflare)
1. 开启WAF防火墙 $([ -s $HOME_DIR/conf/cdn_only.conf ] && echo "(true)")
2. 关闭WAF防火墙
3. 启用iptables防护 $(iptables -w -t filter -C INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset >/dev/null 2>&1 && echo "(true)")
4. 取消iptables防护
EOF
			read -rp $'请选择 \e[95m1-4\e[0m: ' -n1 action
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 4 ] && {
				if [ ! -s /tmp/ips4 ] || [ ! -s /tmp/ips6 ]; then
					Wget_get_files /tmp/ips4 https://www.cloudflare.com/ips-v4
					Wget_get_files /tmp/ips6 https://www.cloudflare.com/ips-v6
				fi
				case $action in
				1)
					rm -f $HOME_DIR/conf/cdn_only.conf
					: <<EOF
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
					Prompt "需要重启Nginx后生效"
					;;
				2)
					rm -f $HOME_DIR/conf/cdn_only.conf
					Prompt "需要重启Nginx后生效"
					;;
				3)
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
					Prompt "iptables规则添加完毕！"
					;;
				4)
					iptables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset
					ip6tables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only6 src -j REJECT --reject-with tcp-reset
					ipset destroy cdn_only4
					ipset destroy cdn_only6
					Prompt "iptables规则清理完成！"
					;;
				esac
			}
			;;
		16)
			if [[ $nginx_on != "--standalone" ]]; then
				Create_certificate
				cat <<EOF
需要客户端支持服务器订阅功能。(更新订阅程序需要关闭后再开启)
1. 开启订阅 $([ -s $HOME_DIR/web/subscriptions.php ] && echo "(true)")
2. 关闭订阅 $([ ! -s $HOME_DIR/web/subscriptions.php ] && echo "(true)")
EOF

				read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
				is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 2 ] && {
					case $action in
					1)
						Wget_get_files $HOME_DIR/web/subscriptions.php $URL/src/subscriptions.php
						Prompt "你的订阅地址为 https://$tls_common_name/subscriptions.php"
						cat <<EOF
如果你的访问受到ISP干扰还可以使用以下地址进行加速访问
https://proxy.freecdn.workers.dev/?url=https://$tls_common_name/subscriptions.php
支持传入参数
https://github.com/yiguihai/shadowsocks_install/wiki/订阅管理
EOF
						;;
					2)
						rm -f $HOME_DIR/web/subscriptions.php
						;;
					esac
					Check_permissions
				}
			else
				Prompt "使用此功能需要先开启Nginx"
			fi
			;;
		17)
			cat <<EOF
simple-obfs混淆插件无法同时监听IPv4和IPv6所以做了一个取舍，
使用前确保你的服务器支持选择的互联网协议版本！
  1. IPv4 $([ "$Protocol" = "ipv4" ] && echo "(true)")
  2. IPv6 $([ "$Protocol" = "ipv6" ] && echo "(true)")
EOF
			read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 2 ] && {
				case $action in
				1)
					Protocol=ipv4
					;;
				2)
					Protocol=ipv6
					;;
				esac
				if [ "$action" ]; then
					sed -i "/^Protocol=/s/=.*/=$Protocol/" $HOME_DIR/conf/config.ini
					Check_permissions
					Prompt "请重启本脚本的所有服务以完成切换。"
				fi
			}
			;;
		18)
			if command_exists dialog; then
				local ver
				ver=$(dialog --version)
				#if [ "${ver:9:1}" -le 1 ] && [ "${ver:11:1}" -lt 3 ]; then
				if [ "${ver##*-}" -lt 20201126 ]; then
					$common_remove dialog
				fi
			fi
			if ! command_exists dialog; then
				Introduction "安装dialog"
				Wget_get_files /tmp/dialog_amd64.deb https://proxy.freecdn.workers.dev/?url=http://snapshot.debian.org/archive/debian/20210103T024108Z/pool/main/d/dialog/dialog_1.3-20201126-1_amd64.deb
				if ! $common_install /tmp/dialog_amd64.deb 1>/dev/null; then
					Prompt "无法安装dialog"
					Exit
				fi
				rm -f /tmp/dialog_amd64.deb
			fi
			#https://codychen.me/2020/29/linux-shell-的圖形互動式介面-dialog/
			cat <<EOF
Linux Dialog 是可以在 Terminal 上快速建立圖形交互介面的工具，功能十分強大、方便。本脚本用于"添加端口"时的图形化输入交互。
  1. default $([ "$Dialog" = "disable" ] && echo "(true)")
  2. dialog $([ "$Dialog" = "enable" ] && echo "(true)")
EOF
			read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
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
			: <<EOF
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
					#https://stackoverflow.com/questions/21157435/bash-string-compare-to-multiple-correct-values
					if [[ $ID == @(debian|ubuntu) ]]; then
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
						Prompt "Unsupported systems"
					fi
				else
					Prompt "Only 64-bit is supported"
				fi
			else
				Prompt "OpenVZ virtualization is not supported"
			fi
			;;
		20)
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
					iptables -w -t filter -A OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
					ip6tables -w -t filter -A OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
					local cum
					if [ -w /proc/net/xt_tls/hostset/blacklist ]; then
						while IFS= read -r line || [ -n "$line" ]; do
							if [ "${line::1}" != "#" ] && [ "${line::1}" != ";" ]; then
								if echo +"${line}" >/proc/net/xt_tls/hostset/blacklist; then
									((cum++))
								fi
							fi
						done <$HOME_DIR/conf/sni.ini
						Prompt "共加载 $cum 条过滤规则！"
					else
						Prompt "出现未知错误！"
					fi
					;;
				2)
					echo / >/proc/net/xt_tls/hostset/blacklist
					iptables -w -t filter -D OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
					ip6tables -w -t filter -D OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j REJECT --reject-with tcp-reset
					;;
				3)
					vim ${HOME_DIR:?}/conf/sni.ini
					;;
				4)
					if [ -r /proc/net/xt_tls/hostset/blacklist ]; then
						local temp_file
						temp_file='/dev/shm/sssni.tmp'
						cp -f /proc/net/xt_tls/hostset/blacklist "$temp_file"
						python3 <<-EOF
							from rich.console import Console
							from rich.table import Table
							table = Table(title="审计规则表", show_lines=True)
							table.add_column("拦截次数", justify="left", no_wrap=True)
							table.add_column("匹配域名", justify="right")
							with open("$temp_file", 'r') as fd:
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
		*)
			break
			;;
		esac
		Press_any_key_to_continue
		clear
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
					if [ "$upload_limit" -gt 0 ] || [ "$download_limit" -gt 0 ]; then
						((i++))
					fi
					local_address=$(ss -lntpH | grep "pid=${sspid:=lzbx}" | awk -F' ' '{print $4}')
					local_port="${local_address##*:}"
					if [ "${local_address%:*}" = "$ipv4" ]; then
						internet=${internet4:?}
					elif [ "${local_address%:*}" = "$ipv6" ]; then
						internet=${internet6:?}
					else
						internet='lo'
					fi
					if [ "$plugin" ] && [ "$plugin_opts" ]; then
						if [ "$upload_limit" -gt 0 ]; then
							tc class add dev ${internet:?} parent 1:1 classid 1:"$i" htb rate "$((upload_limit * 8))"kbit burst 15k
							tc qdisc add dev ${internet:?} parent 1:"$i" handle "$i": sfq perturb 10
							tc filter add dev ${internet:?} parent 1: protocol ip u32 match ip protocol 6 0xff match ip dport "${local_port:?}" 0xffff flowid 1:"$i"     #上传速度限制
							tc filter add dev ${internet:?} parent 1: protocol ipv6 u32 match ip6 protocol 6 0xff match ip6 dport "${local_port:?}" 0xffff flowid 1:"$i" #IPv6
							((i = i + 1))
						fi
					fi
					if [ "$download_limit" -gt 0 ]; then
						tc class add dev ${internet:?} parent 1:1 classid 1:"$i" htb rate "$((download_limit * 8))"kbit burst 15k
						tc qdisc add dev ${internet:?} parent 1:"$i" handle "$i": sfq perturb 10
						tc filter add dev ${internet:?} parent 1: protocol ip u32 match ip protocol 6 0xff match ip sport "${local_port:?}" 0xffff flowid 1:"$i"     #下载速度限制
						tc filter add dev ${internet:?} parent 1: protocol ipv6 u32 match ip6 protocol 6 0xff match ip6 sport "${local_port:?}" 0xffff flowid 1:"$i" #IPv6
						((i = i + 1))
					fi
				fi
				unset -v pid_file local_address local_port
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

if [ "$1" = "daemon" ]; then
	Daemon
elif [ "$1" = "start" ]; then
	Start
elif [ "$1" = "restart" ]; then
	Stop
	Start
elif [ "$1" = "stop" ]; then
	Stop
else
	first=0
	while true; do
		((first++))
		[ "$first" -le 1 ] && Check
		clear
		Author
		Status
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			cat <<EOF
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
			cat <<EOF
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
			Stop
			;;
		4)
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
