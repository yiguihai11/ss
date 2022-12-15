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
	kmod \
	binutils \
	bzip2 \
	flex \
	python3 \
	perl \
	make \
	unzip \
	gawk \
	subversion \
	libz-dev

git clone --depth 1 https://github.com/HandsomeMod/HandsomeMod /tmp/build/HandsomeMod
cd /tmp/build/HandsomeMod
./scripts/feeds update -a
./scripts/feeds install -a
#export FORCE_UNSAFE_CONFIGURE=1
cp -vf ${CI_PROJECT_DIR:?}/backups/.config.msm8916 .config
make FORCE_UNSAFE_CONFIGURE=1
mv -f build_dir/target-aarch64_cortex-a53+neon_musl/linux-msm89xx_msm8916/ ${CI_PROJECT_DIR:?}/tmp
