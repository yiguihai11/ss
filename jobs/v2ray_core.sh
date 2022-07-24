#!/bin/bash
set -e

apt-get -qqy update
apt-get --yes install --no-install-recommends \
	git \
	ca-certificates \
	autoconf \
	libtool \
	libev-dev \
	cmake \
	autoconf \
	automake \
	build-essential \
	gcc \
	m4 \
	binutils \
	pkg-config \
	wget \
	curl
git clone --depth 1 https://github.com/v2fly/v2ray-core.git /tmp/v2ray-core
cd /tmp/v2ray-core
echo Get project dependencies
go mod download
echo Build V2Ray
mkdir -p build_assets
env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -v -o build_assets/v2ray -trimpath -ldflags "-s -w -buildid=" ./main
bash ${CI_PROJECT_DIR}/jobs/push.sh
mv -vf build_assets/v2ray ${CI_PROJECT_DIR}/usr/bin/v2ray
echo "<tr><td>v2ray</td><td><a href="https://github.com/v2fly/v2ray-core/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR}/temp/upgrade.log
cd ${CI_PROJECT_DIR:?}
sed -i "s/${v2ray_core_old:?}/${v2ray_core:?}/g" version/version
git add usr/bin/v2ray version/version temp/upgrade.log
git commit -m "更新v2ray流量转发工具"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
