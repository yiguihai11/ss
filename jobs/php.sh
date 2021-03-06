#!/bin/bash
set -e

apt-get -qqy update
apt-get --yes install --no-install-recommends \
python3 \
libpython3-dev

cd /tmp
curl -L -s -q --output ${php}.tar.gz https://www.php.net/distributions/${php}.tar.gz
tar xzf ${php}.tar.gz
rm -f ${php}.tar.gz
#编译依赖库
git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
cd libxml2
autoreconf -vfi
./configure --enable-shared=no
make
make install
git clone --depth 1 https://github.com/kkos/oniguruma
cd oniguruma
./autogen.sh
./configure --enable-shared=no
make
make install
git clone --depth 1 https://github.com/curl/curl.git
cd curl
autoreconf -vfi
./configure --with-openssl --enable-shared=no
make
make install
cd /tmp/$php
./buildconf
./configure \
	--with-curl \
	--with-openssl \
	--enable-mbstring \
	--enable-fpm \
	--enable-sockets \
	--without-sqlite3 \
	--without-pdo-sqlite \
	--enable-shared=no \
	--prefix=/etc/ssmanager/usr
#patch -p0 Makefile < ${CI_PROJECT_DIR}/patch/Makefile_php.patch
make
make install
make clean
strip /etc/ssmanager/usr/sbin/php-fpm /etc/ssmanager/usr/bin/php
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "$php_info" | base64 -d >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf /etc/ssmanager/usr ${CI_PROJECT_DIR:?}/php
cd ${CI_PROJECT_DIR:?}
cp -vf php/bin/php usr/bin
cp -vf php/sbin/php-fpm usr/sbin
sed -i "s/${php_old:?}/${php:?}/g" version/version
git add usr/sbin/php-fpm usr/bin/php version/version temp/upgrade.log
git commit -m "更新php"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
