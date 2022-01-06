#!/bin/bash
set -e

#https://www.electrosoftcloud.com/en/install-python-3-on-debian9/
#https://blog.csdn.net/lkgCSDN/article/details/84403329
bash jobs/openssl.sh "/etc/ssmanager/usr"
apt-get -qq update
apt-get --yes install --no-install-recommends build-essential zlib1g-dev libffi-dev wget
python_ver=$(wget -q -O- --no-check-certificate https://www.python.org/downloads/source/|grep 'Latest Python'|grep -oP '\d+\.\d+\.\d+'|head -n 1)
wget -q --no-check-certificate --continue https://www.python.org/ftp/python/${python_ver}/Python-${python_ver}.tgz
tar xf Python-${python_ver}.tgz
rm -f Python-${python_ver}.tgz
cd Python-${python_ver}
./configure --enable-ipv6 --with-ssl-default-suites=openssl --with-openssl=/etc/ssmanager/usr --prefix=/etc/ssmanager/usr
make -j2
make altinstall
ls -al /etc/ssmanager/usr/bin
strip /etc/ssmanager/usr/bin/python${python_ver%.*} /etc/ssmanager/usr/bin/openssl
/etc/ssmanager/usr/bin/python${python_ver%.*} -V
tar zcf ${CI_PROJECT_DIR}/Python-${python_ver}.tar.gz /etc/ssmanager/usr
