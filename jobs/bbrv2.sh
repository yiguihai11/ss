#!/bin/bash
set -e
apt-get -qq update
apt-get --yes install --no-install-recommends \
build-essential \
libncurses5-dev \
gcc \
libssl-dev \
grub2 \
bc \
bison \
flex \
git \
libelf-dev \
libxtables-dev \
ca-certificates \
rsync \
apt-utils \
grsync \
libtool \
libev-dev \
cmake \
autoconf \
automake \
m4 \
binutils \
pkg-config \
wget \
libpcre3 \
libpcre3-dev \
cpio \
kmod
git clone -b v2alpha --depth 1 https://github.com/google/bbr.git build/google-bbr
if [ -s backups/.config ]; then
	cp -vf backups/.config build/google-bbr/.config
elif [ -s /boot/config-$(uname -r) ]; then
	cp -vf /boot/config-$(uname -r) build/google-bbr/.config
fi
cd build/google-bbr
make olddefconfig
scripts/config --disable MODULE_SIG
scripts/config --disable CONFIG_MODULE_SIG_ALL
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --disable DEBUG_INFO
make -j2 deb-pkg
git clone --depth 1 https://github.com/Lochnair/xt_tls.git
patch -p0 <${CI_PROJECT_DIR:?}/patch/xt_tls.patch
cd xt_tls && make IDIR=${CI_PROJECT_DIR:?}/build/google-bbr/kernel/net/netfilter/ KDIR=${CI_PROJECT_DIR:?}/build/google-bbr
${CI_PROJECT_DIR:?}/build/google-bbr/scripts/sign-file sha512 ${CI_PROJECT_DIR:?}/build/google-bbr/certs/signing_key.pem ${CI_PROJECT_DIR:?}/build/google-bbr/certs/signing_key.x509 src/xt_tls.ko
mv -vf ipt/libxt_tls.so ${CI_PROJECT_DIR:?}/build/google-bbr
mv -vf src/xt_tls.ko ${CI_PROJECT_DIR:?}/build/google-bbr
