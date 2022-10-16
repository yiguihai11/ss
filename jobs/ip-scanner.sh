#!/bin/bash
export PATH=$PATH:${CI_PROJECT_DIR}/usr/bin
bash jobs/push.sh
chmod +x ${CI_PROJECT_DIR}/usr/bin/*
apt-get -qqy update
apt-get --yes install --no-install-recommends \
	git \
	ca-certificates \
	curl
git clone --depth 1 https://github.com/ip-scanner/cloudflare cloudflare
cd cloudflare
rm -rf .git

numCompare() {
	return $(echo | awk "{ print ($1 >= $2)?0 : 1 }")
}
Traffic() {
	local i=${1%.*}
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

Check() {
	response_code=$(curl -4 -s -o /dev/null -w '%{response_code}' --connect-timeout 3 --max-time 6 --resolve cp.cloudflare.com:443:$line https://cp.cloudflare.com/generate_204)
	if [ ${response_code:=000} -eq 204 ]; then
		IFS='|' read -r -a array <<<"$(curl -4 -s -o /dev/null -w '%{response_code}|%{content_type}|%{speed_download}' --user-agent "MAUI WAP Browser" --connect-timeout 5 --max-time 15 --resolve mikutap.ml:443:$line https://mikutap.ml/50.png)"
		if [ ${array[0]:-0} -eq 200 ] && [ "${array[1]:=xxx}" = "image/png" ]; then
			echo "$line" >>${CI_PROJECT_DIR}/ip.log
			speed_download=$(Traffic ${array[2]:-0})
			echo "$line ${speed_download:-0}/s"
			echo "${i%.*}, ${line}, ${speed_download% *}, ${speed_download#* }" >>${CI_PROJECT_DIR}/ip2.csv
			#下载速度小于3MB/s的都可以滚了
			if numCompare ${speed_download% *} 3 && [ "${speed_download#* }" = "MB" ]; then
				echo "${i%.*}, ${line}, ${speed_download% *}, ${speed_download#* }" >>${CI_PROJECT_DIR}/best_ip.csv
			fi
		fi
	fi
}
#有些IP国外畅通却屏蔽了国内的地址连接只能排除了,顺带一提：用小火箭可以很方便的筛选出来
block_proxy_list=(
	"112.74.93.147"
	"8.210.97.53"
	"8.210.67.251"
	"8.218.8.205"
	"8.210.159.196"
	"8.218.57.225"
	"47.52.78.112"
	"47.52.101.237"
	"47.57.245.232"
	"47.91.207.96"
	"47.242.28.250"
	"47.242.33.105"
	"47.242.209.173"
	"47.242.204.235"
	"47.242.193.142"
	"47.243.146.249"
	"47.242.254.50"
	"47.243.74.153"
	"47.243.245.195"
)
for i in *.txt; do
	for ((f = 0; f < ${#block_proxy_list[@]}; f++)); do
		if [ "${i%% -*}" = "${block_proxy_list[$f]}" ]; then
			continue 2
		fi
	done
	if [[ $i != *"中国"* ]]; then
		continue
	fi
	echo ${i%.*}
	x=0
	while IFS= read -r line || [ -n "$line" ]; do
		for ((f = 0; f < ${#block_proxy_list[@]}; f++)); do
			if [ "${line:-xxx}" = "${block_proxy_list[$f]}" ]; then
				continue 2
			fi
		done
		((x++))
		if [ $x -le 100 ]; then
			Check &
			xx+=(${!})
		else
			break
		fi
		if [ ${#xx[*]} -ge 10 ]; then
			while true; do
				m=0
				for num in ${xx[@]}; do
					if [ -d /proc/"${num:-000}" ]; then
						((m++))
					fi
				done
				if [ $m -gt 0 ]; then
					sleep 1
				else
					break
				fi
			done
			xx=()
		fi
	done <"$i"
done
sort -r -n -k 3 -t , ${CI_PROJECT_DIR}/best_ip.csv >${CI_PROJECT_DIR}/conf/best_ip.csv
sed -i '1i\ISP & Location, Address, Download, Unit' ${CI_PROJECT_DIR}/ip2.csv ${CI_PROJECT_DIR}/conf/best_ip.csv
echo "测试完成！"
git add ${CI_PROJECT_DIR}/conf/best_ip.csv
git commit -m "更新优选IP"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
