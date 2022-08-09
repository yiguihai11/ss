#!/bin/bash
export PATH=$PATH:${CI_PROJECT_DIR}/usr/bin
chmod +x ${CI_PROJECT_DIR}/usr/bin/*
kill $(cat cloudflare/test.pid) 2>/dev/null
rm -rf cloudflare
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
    sslocal --local-addr 127.0.0.1:1081 --password "MzNiMzA4M2QtNjU5ZC00ZDY0LTg3YWUtNTA1M2JlNgo=" --encrypt-method 2022-blake3-chacha20-poly1305 --plugin v2ray-plugin --plugin-opts "path=f846917c6e48f0727a2e894fc5cc3440c3265415;host=mikutap.ml;tls;certRaw=MIIETTCCAzWgAwIBAgISBK28xMxx+s\/YIURlQNcMPIu2MA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMjA3MzAyMzA3NDNaFw0yMjEwMjgyMzA3NDJaMBUxEzARBgNVBAMTCm1pa3V0YXAubWwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQSmP9FwagQJzlQAd2pSMbvek+boCeF8WjxfFvD3gUSG8Xe449\/efxjK1x9+\/GLpfHFAQrA0PFJNC9E8W7WOWevo4ICQzCCAj8wDgYDVR0PAQH\/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS+WZcRrEuPPRUcLp2I\/MMN9VZ\/dTAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAVBgNVHREEDjAMggptaWt1dGFwLm1sMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBAgYKKwYBBAHWeQIEAgSB8wSB8ADuAHUAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAGCUZSBtQAABAMARjBEAiBBVRxMdurdN+uWcNCbuJtudQXjDpoahRN2dAwcFBT5XAIgYy9aVyJv20vGqAo2bCfyaUB8pcd0qmOqMn5G8DgeJz4AdQBByMqx3yJGShDGoToJQodeTjGLGwPr60vHaPCQYpYG9gAAAYJRlIPWAAAEAwBGMEQCIFLZYUm6985XmZg+DJBGfD6szMoQRgBga3be8mrYAE1uAiAfXlJosIZB9JtIzmV2DI8Ocg6Cx+tHw7pgQVGTfo15ezANBgkqhkiG9w0BAQsFAAOCAQEAogGB+XDCTYpf6FOyR5zhPqApXrXBIWtiRpwpKmDbth3GBeM+r6MpqQ65v5IRhnw6nimXMffFjNyDWggdrQRTFunokLIpEoAdeQRahJlUQyY626GTn42pUahSs1lNLcp6187Am2o7mk15k8v2gWsbxKA4zg52iDCPq\/YY4O+iwKrEIlLzgJlQcKMsobAewdBywEN98boBZ3qy05Grh5nXAyLQIXUTF+dXRn3fIlYRL3sm3xrHHrQeUWlmOBZdsAbupFkqJ+ke\/t9Jrd61nduyQnFsEhdpqEgIgaYTsvxY1+HcS9f0Mn6Rb8LcJjikgUWpnz6SCOesvkrtdev7J9d2yQ\\=\\=" --server-addr ${line}:443 --daemonize --daemonize-pid test.pid
    sleep 1
    ret=$(curl -4 -s -o /dev/null -w '%{response_code}' --connect-timeout 5 -x socks5://127.0.0.1:1081 https://wap.baidu.com)
    if [ "${ret:-0}" -eq 200 ]; then
		echo $i $line ✔
	fi
	kill $(cat test.pid) 2>/dev/null
	rm -f test.pid
	sleep 1
	((x++))
  done <"$i"
done
echo "测试完成！"