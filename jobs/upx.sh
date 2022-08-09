#!/bin/bash
set -e

apt-get -qqy update
apt-get --yes install --no-install-recommends \
	git \
	wget \
	ca-certificates \
	build-essential \
	gcc \
	binutils \
	gettext \
	autoconf \
	libtool \
	automake \
	cmake \
	libev-dev \
	zlib1g-dev \
	libz-dev
cd /tmp
wget --quiet --continue http://www.oberhumer.com/opensource/ucl/download/ucl-1.03.tar.gz
tar xzf ucl-1.03.tar.gz
cd ucl-1.03
#https://blog.csdn.net/qq_34905587/article/details/106663453
./configure CPPFLAGS="$CPPFLAGS -std=c90 -fPIC"
make
make install
make clean
git clone --depth 1 https://github.com/upx/upx.git /tmp/upx
cd /tmp/upx
git submodule update --init --recursive
make all
strip src/upx.out
mv -f src/upx.out /usr/local/bin/upx
make clean
upx -V
upx -h
: <<'EOF'
wget --quiet https://github.com/upx/upx/releases/download/v3.95/upx-3.95-amd64_linux.tar.xz
tar xvf upx-3.95-amd64_linux.tar.xz
mv -vf upx-3.95-amd64_linux/upx /usr/local/bin/upx3.95
EOF
