#!/bin/bash
export PATH=$PATH:${CI_PROJECT_DIR}/usr/bin
chmod +x ${CI_PROJECT_DIR}/usr/bin/*
kill $(cat cloudflare/test.pid) 2>/dev/null
rm -rf cloudflare ip.txt ss-local.json
touch ip.txt ss-local.json
apt-get -qqy update
apt-get --yes install --no-install-recommends \
	git \
	ca-certificates \
	curl
git clone --depth 1 https://github.com/ip-scanner/cloudflare cloudflare
cd cloudflare
rm -rf .git
for i in *.txt; do
	x=0
	while IFS= read -r line || [ -n "$line" ]; do
		if [ $x -ge 3 ]; then
			break
		fi
		sslocal --local-addr 127.0.0.1:1081 --password "MzNiMzA4M2QtNjU5ZC00ZDY0LTg3YWUtNTA1M2JlNgo=" --encrypt-method 2022-blake3-chacha20-poly1305 --plugin v2ray-plugin --plugin-opts "path=f846917c6e48f0727a2e894fc5cc3440c3265415;host=mikutap.ml;tls" --server-addr ${line}:443 --daemonize --daemonize-pid test.pid
		sleep 1
		ret=$(curl -4 -s -o /dev/null -w '%{response_code}' --connect-timeout 5 -x socks5://127.0.0.1:1081 https://wap.baidu.com)
		if [ "${ret:-0}" -eq 200 ]; then
			echo $i $line ✔
			echo "$i $line" >>${CI_PROJECT_DIR}/ip.txt
			cat >>${CI_PROJECT_DIR}/ss-local.json <<EOF
		{
            "disabled": false,
            "address": "$line",
            "port": 443,
            "method": "2022-blake3-chacha20-poly1305",
            "password": "MzNiMzA4M2QtNjU5ZC00ZDY0LTg3YWUtNTA1M2JlNgo=",
            "plugin": "v2ray-plugin",
            "plugin_opts": "path=f846917c6e48f0727a2e894fc5cc3440c3265415;host=mikutap.ml;tls",
            "timeout": 7200,
            "tcp_weight": 1.0,
            "udp_weight": 0.1,
        },
        {
            "disabled": false,
            "address": "$line",
            "port": 80,
            "method": "2022-blake3-aes-128-gcm",
            "password": "NTMzNzg2NmYtODcxYS00Cg==",
            "plugin": "v2ray-plugin",
            "plugin_opts": "path=36bb3effb2db35abbdf3aa205115c5d7aa120997;host=mikutap.ml",
            "timeout": 7200,
            "tcp_weight": 1.0,
            "udp_weight": 0.1,
        },
EOF
		fi
		kill $(cat test.pid) 2>/dev/null
		rm -f test.pid
		sleep 1
		((x++))
	done <"$i"
done
echo "测试已完成！"
