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
	wget
cd /tmp
#https://stackoverflow.com/a/3809435
dl_url="$(wget -qO- https://www.boost.org/users/download/ | grep 'unix' | grep -oE 'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)' | grep 'tar.gz')"
latest_version="${dl_url##*/}"
wget --quiet --continue ${dl_url}
tar xzf ${latest_version}
rm -f ${latest_version}
cd ${latest_version%%\.*}
#https://www.boost.org/doc/libs/1_78_0/tools/build/doc/html/index.html#bbv2.installation
./bootstrap.sh
./b2 -j2 install
rm -rf ${latest_version} ${latest_version%%\.*}
