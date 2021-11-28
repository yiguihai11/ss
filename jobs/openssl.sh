#!/bin/bash
set -e

apt-get -qq update
apt-get --yes install --no-install-recommends \
	git \
	wget \
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

cd /tmp
latest_version="$(wget -qO- https://www.openssl.org/source/ | grep -oP 'openssl\-\d+\.\d+\.\d+\w+\.tar\.gz' | head -n1)"
wget --quiet --continue https://www.openssl.org/source/${latest_version}
tar xzf ${latest_version}
rm -f ${latest_version}
mv ${latest_version/.tar.gz/} openssl
cd openssl
./Configure \
	no-shared \
	linux-x86_64
make
make install_sw
make distclean
