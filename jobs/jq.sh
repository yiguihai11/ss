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
	pkg-config \
	bison \
	byacc
git clone --depth 1 https://github.com/stedolan/jq /tmp/jq
cd /tmp/jq
git submodule update --init # if building from git to get oniguruma
autoreconf -fi              # if building from git
./configure --with-oniguruma=builtin --prefix=/etc/ssmanager/usr
make
make check
make install
strip /etc/ssmanager/usr/bin/jq
