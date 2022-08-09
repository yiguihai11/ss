#!/bin/bash
set -e

apt-get -qqy update
apt-get --yes install --no-install-recommends \
	git \
	curl \
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
latest_version="$(wget --no-check-certificate -qO- https://www.openssl.org/source/ | grep -oP 'openssl\-\d+\.\d+\.\d+\w+\.tar\.gz' | head -n1)"
wget --no-check-certificate --quiet --continue https://www.openssl.org/source/${latest_version}
tar xzf ${latest_version}
rm -f ${latest_version}
mv ${latest_version/.tar.gz/} openssl
cd openssl
./Configure LIST
if [ -z "$1" ]; then
	./Configure no-shared linux-x86_64
else
	./Configure no-shared linux-x86_64 --prefix=$1
fi
make -j2
make install_sw
