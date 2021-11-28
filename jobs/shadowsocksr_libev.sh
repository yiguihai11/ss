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
	pkg-config \
	wget \
	libpcre3 \
	libpcre3-dev
cd /tmp
#git clone --depth 1 https://github.com/ARMmbed/mbedtls
#cd mbedtls
#ssr源码只兼容到这一版本mbedtls
wget --quiet --continue https://github.com/ARMmbed/mbedtls/archive/refs/tags/v2.26.0.tar.gz
tar xzf v2.26.0.tar.gz
cd mbedtls-2.26.0
make no_test
make install DESTDIR=/usr/local
git clone --depth 1 https://github.com/shadowsocksrr/shadowsocksr-libev
cd shadowsocksr-libev
#https://github.com/shadowsocksrr/shadowsocksr-libev/issues/40#issuecomment-413930246
patch -p0 <${CI_PROJECT_DIR}/patch/shadowsocksr-libev.patch
./autogen.sh
./configure --disable-documentation --with-crypto-library=mbedtls --prefix=/etc/ssmanager/usr
find ./ -name "Makefile" -type f -exec sed -i 's/-lmbedcrypto -lm -lpcre/-l:libmbedcrypto.a -lm -l:libpcre.a/g' {} +
make
make install
strip /etc/ssmanager/usr/bin/ss-redir
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td>shadowsocksr-libev</td><td><a href="https://github.com/shadowsocksrr/shadowsocksr-libev/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf /etc/ssmanager/usr/bin/ss-redir ${CI_PROJECT_DIR}/usr/bin/ssr-redir
cd ${CI_PROJECT_DIR:?}
sed -i "s/${shadowsocksr_libev_old:?}/${shadowsocksr_libev:?}/g" version/version
git add usr/bin/obfs-server version/version temp/upgrade.log
git commit -m "更新shadowsocksr-libev"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME:?}
