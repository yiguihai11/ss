#!/bin/bash
set -e
apt-get -qqy update
apt-get --yes install --no-install-recommends \
	build-essential \
	libncurses5-dev \
	gcc \
	libssl-dev \
	grub2 \
	bc \
	bison \
	flex \
	fakeroot \
	git \
	libelf-dev \
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

if [ "$PLATFORM" = "debian:jessie" ]; then
	apt-get --yes install --no-install-recommends iptables-dev
elif [ "$PLATFORM" = "ubuntu:16.04" ]; then
	apt-get --yes install --no-install-recommends libxtables11 iptables-dev
else
	apt-get --yes install --no-install-recommends libxtables*
fi
hav_xt=$(find / -type l -name 'libxtables.so.*')
hav_xt2=$(find / -type f -name 'xtables.h')
if [ -L "$hav_xt" ] && [ -f "$hav_xt2" ]; then
	echo "$PLATFORM $hav_xt $hav_xt2"
	git clone -b v2alpha --depth 1 https://github.com/google/bbr.git /tmp/build/google-bbr
	if [ -s backups/.config ]; then
		cp -vf backups/.config /tmp/build/google-bbr/.config
	elif [ -s /boot/config-$(uname -r) ]; then
		cp -vf /boot/config-$(uname -r) /tmp/build/google-bbr/.config
	fi
	cd /tmp/build/google-bbr
	make olddefconfig
	scripts/config --disable MODULE_SIG
	scripts/config --disable CONFIG_MODULE_SIG_ALL
	scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
	scripts/config --disable DEBUG_INFO
	make -j8 deb-pkg
	git clone --depth 1 https://github.com/Lochnair/xt_tls.git
	patch -p0 <${CI_PROJECT_DIR:?}/patch/xt_tls.patch
	cd xt_tls && make IDIR=/tmp/build/google-bbr/kernel/net/netfilter/ KDIR=/tmp/build/google-bbr
	/tmp/build/google-bbr/scripts/sign-file sha512 /tmp/build/google-bbr/certs/signing_key.pem /tmp/build/google-bbr/certs/signing_key.x509 src/xt_tls.ko
	cd ${CI_PROJECT_DIR}
	bash ${CI_PROJECT_DIR}/jobs/push.sh
: <<'EOF'
	read -r -a array <<<$(find /tmp/build/ -type f \( -name "*.deb" -o -name "libxt_tls.so" -o -name "xt_tls.ko" \))
	for i in ${array[*]}; do
		if [ -s $i ]; then
			mv_file="${i%.*}_${hav_xt##*\.}.${i##*.}"
			cp -vf "$i" "$mv_file"
			cp -vf "$mv_file" ${CI_PROJECT_DIR:?}/backups
		fi
	done
EOF
	for i in $(find /tmp/build/ -type f \( -name "*.deb" -o -name "libxt_tls.so" -o -name "xt_tls.ko" \)); do
		if [ -s $i ]; then
			mv_file="${i%.*}_${hav_xt##*\.}.${i##*.}"
			cp -vf "$i" "$mv_file"
			cp -vf "$mv_file" ${CI_PROJECT_DIR:?}/backups
		fi
	done
	git add backups
	git commit -m "更新bbr内核"
	git push origin HEAD:${CI_COMMIT_REF_NAME:?}
else
	echo "没有正确安装好编译依赖！"
	exit 127
fi
