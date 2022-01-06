#!/bin/bash
set -e

apt-get -qq update
apt-get --yes install --no-install-recommends git ca-certificates
git clone --depth 1 https://github.com/teddysun/v2ray-plugin.git /tmp/v2ray-plugin
cd /tmp/v2ray-plugin
go get -d ./...
env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.VERSION=$(date -u +%Y%m%d) -s -w" -o v2ray-plugin
bash ${CI_PROJECT_DIR}/jobs/push.sh
mv -vf v2ray-plugin ${CI_PROJECT_DIR}/usr/bin/v2ray-plugin
echo "<tr><td>v2ray-plugin</td><td><a href="https://github.com/teddysun/v2ray-plugin/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR}/temp/upgrade.log
cd ${CI_PROJECT_DIR:?}
sed -i "s/${v2ray_plugin_old:?}/${v2ray_plugin:?}/g" version/version
git add usr/bin/v2ray-plugin version/version temp/upgrade.log
git commit -m "更新v2ray-plugin插件"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
