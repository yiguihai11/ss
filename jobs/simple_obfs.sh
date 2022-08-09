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
git clone --depth 1 https://github.com/shadowsocks/simple-obfs /tmp/simple-obfs
cd /tmp/simple-obfs
git submodule update --init
./autogen.sh
#https://www.cnblogs.com/z16166/p/13192665.html
env LDFLAGS=-no-pie ./configure \
	--disable-documentation \
	--prefix=/etc/ssmanager/usr
find ./ -name "Makefile" -type f -exec sed -i 's/-lev/-l:libev.a/g' {} +
make
make install
strip /etc/ssmanager/usr/bin/obfs-server
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td>simple-obfs</td><td><a href="https://github.com/shadowsocks/simple-obfs/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf /etc/ssmanager/usr/bin/obfs-server ${CI_PROJECT_DIR}/usr/bin
cd ${CI_PROJECT_DIR:?}
sed -i "s/${simple_obfs_old:?}/${simple_obfs:?}/g" version/version
git add usr/bin/obfs-server version/version temp/upgrade.log
git commit -m "更新simple-obfs"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
