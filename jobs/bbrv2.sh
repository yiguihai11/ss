#!/bin/bash
set -e
apt-get -qq update
apt-get --yes install --no-install-recommends build-essential libncurses5-dev gcc libssl-dev grub2 bc bison flex git libelf-dev libxtables-dev
git clone -b v2alpha --depth 1 https://github.com/google/bbr.git /tmp/build/google-bbr
if [ -s ${CI_PROJECT_DIR:?}/backups/.config ]; then
	cp -vf ${CI_PROJECT_DIR:?}/backups/.config /tmp/build/google-bbr/.config
elif [ -s /boot/config-$(uname -r) ]; then
	cp -vf /boot/config-$(uname -r) /tmp/build/google-bbr/.config
fi
cd /tmp/build/google-bbr
make olddefconfig
scripts/config --disable MODULE_SIG
scripts/config --disable CONFIG_MODULE_SIG_ALL
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --disable DEBUG_INFO
make -j2 deb-pkg
git clone --depth 1 https://github.com/Lochnair/xt_tls /tmp/xt_tls
cd /tmp && patch -p0 <${CI_PROJECT_DIR:?}/patch/xt_tls.patch
cd xt_tls && make IDIR=/tmp/build/google-bbr/kernel/net/netfilter/ KDIR=/tmp/build/google-bbr
/tmp/build/google-bbr/scripts/sign-file sha512 /tmp/build/google-bbr/certs/signing_key.pem /tmp/build/google-bbr/certs/signing_key.x509 src/xt_tls.ko
mv -vf ipt/libxt_tls.so /tmp/build/google-bbr
mv -vf src/xt_tls.ko /tmp/build/google-bbr
