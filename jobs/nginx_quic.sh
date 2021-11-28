#!/bin/bash
set -e

bash jobs/upx.sh
apt-get -qq update
apt-get --yes install --no-install-recommends git ca-certificates build-essential gcc binutils
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
	libpcre3 \
	libpcre3-dev
git clone --recursive https://github.com/google/ngx_brotli /tmp/ngx_brotli
cd /tmp/ngx_brotli && git submodule update --init
cd /tmp
git clone --depth 1 https://boringssl.googlesource.com/boringssl
mkdir boringssl/build
cd boringssl/build
cmake ..
make
hg clone -b quic https://hg.nginx.org/nginx-quic /tmp/nginx-quic
cd /tmp/nginx-quic
./auto/configure \
	--prefix=/etc/ssmanager/usr \
	--user=nobody \
	--group=root \
	--with-pcre \
	--with-stream \
	--with-pcre-jit \
	--with-threads \
	--with-http_stub_status_module \
	--with-http_dav_module \
	--with-http_ssl_module \
	--with-stream_ssl_module \
	--with-stream_ssl_preread_module \
	--with-http_v2_module \
	--with-http_v3_module \
	--add-module=/tmp/ngx_brotli \
	--with-cc-opt="-Wno-error=type-limits -I../boringssl/include" \
	--with-ld-opt="-L../boringssl/build/ssl -L../boringssl/build/crypto"
find ./ -name "Makefile" -type f -exec sed -i 's/-lpcre/-l:libpcre.a/g' {} +
make
make install
make clean
strip /etc/ssmanager/usr/sbin/nginx
bash ${CI_PROJECT_DIR:?}/jobs/push.sh
echo "$nginx_quic_info" | base64 -d >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf /etc/ssmanager/usr ${CI_PROJECT_DIR:?}/nginx
cd ${CI_PROJECT_DIR:?}
sed -i "s/${nginx_quic_old:?}/${nginx_quic:?}/g" version/version
cp -vf nginx/sbin/nginx usr/sbin/nginx
git add usr/sbin/nginx version/version temp/upgrade.log
git commit -m "更新nginx-quic"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME:?}
