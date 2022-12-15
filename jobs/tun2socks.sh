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
	pkg-config
git clone --depth 1 https://github.com/xjasonlyu/tun2socks.git /tmp/tun2socks
cd /tmp/tun2socks
sed -i 's/CGO_ENABLED := 0/CGO_ENABLED := 1/g' Makefile
make linux-amd64
bash ${CI_PROJECT_DIR}/jobs/push.sh
mv -vf build/tun2socks-linux-amd64 ${CI_PROJECT_DIR}/usr/bin/tun2socks
echo "<tr><td>tun2socks</td><td><a href="https://github.com/xjasonlyu/tun2socks/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR}/temp/upgrade.log
cd ${CI_PROJECT_DIR:?}
sed -i "s/${tun2socks_old:?}/${tun2socks:?}/g" version/version
git add usr/bin/tun2socks version/version temp/upgrade.log
git commit -m "更新tun2socks流量转发工具"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
