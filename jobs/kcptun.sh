#!/bin/bash
set -e

apt-get -qq update
apt-get --yes install --no-install-recommends git ca-certificates
git clone --depth 1 https://github.com/xtaci/kcptun.git /tmp/kcptun
cd /tmp/kcptun/server
env GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -mod=vendor -ldflags "-X main.VERSION=$(date -u +%Y%m%d) -s -w" -o kcptun-server
bash ${CI_PROJECT_DIR}/jobs/push.sh
mv -vf kcptun-server ${CI_PROJECT_DIR}/usr/bin/kcptun-server
echo "<tr><td>kcptun</td><td><a href="https://github.com/xtaci/kcptun/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR}/temp/upgrade.log
cd ${CI_PROJECT_DIR:?}
sed -i "s/${kcptun_old:?}/${kcptun:?}/g" version/version
git add usr/bin/kcptun-server version/version temp/upgrade.log
git commit -m "更新kcptun插件"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME:?}
