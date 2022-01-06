#!/bin/bash
set -e

apt-get -qq update
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
git clone --depth 1 https://github.com/fukuchi/libqrencode /tmp/libqrencode
cd /tmp/libqrencode
./autogen.sh
./configure --without-png --enable-shared=no --prefix=/etc/ssmanager/usr
make
make install
strip /etc/ssmanager/usr/bin/qrencode
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td>libqrencode</td><td><a href="https://github.com/fukuchi/libqrencode/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf /etc/ssmanager/usr/bin/qrencode ${CI_PROJECT_DIR}/usr/bin
cd ${CI_PROJECT_DIR:?}
sed -i "s/${qrencode_old:?}/${qrencode:?}/g" version/version
git add usr/bin/qrencode version/version temp/upgrade.log
git commit -m "更新libqrencode"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
