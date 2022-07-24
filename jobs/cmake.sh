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
	wget \
	curl
cmake --version
dl_url="$(wget --no-check-certificate -qO- https://cmake.org/download/ | grep "linux-x86_64.sh" | grep -oE 'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)' | head -n1)"
latest_version="${dl_url##*/}"
#wget --no-check-certificate --quiet --continue "$dl_url"
curl -O -J -L "$dl_url"
bash ${latest_version} --skip-license --prefix=/usr
cmake --version
