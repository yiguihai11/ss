#!/bin/bash
set -e

bash ${CI_PROJECT_DIR}/jobs/openssl.sh
bash ${CI_PROJECT_DIR}/jobs/cmake.sh
source ${CI_PROJECT_DIR}/jobs/rust.sh
git clone --depth 1 --recursive https://github.com/cloudflare/quiche
cd quiche
cargo build --package quiche --release --features ffi,pkg-config-meta,qlog
mkdir quiche/deps/boringssl/src/lib
ln -vnf $(find target/release -name libcrypto.a -o -name libssl.a) quiche/deps/boringssl/src/lib/
cd ..
#git clone --depth 1 https://github.com/curl/curl
#cd curl
wget https://curl.se/download/curl-7.81.0.tar.gz
tar zxf curl-7.81.0.tar.gz
cd curl-7.81.0
autoreconf -fi
./configure LDFLAGS="-Wl,-rpath,$PWD/../quiche/target/release" --with-openssl=$PWD/../quiche/quiche/deps/boringssl/src --with-quiche=$PWD/../quiche/target/release --prefix=${CI_PROJECT_DIR}/curl --enable-static=yes --enable-shared=no --enable-proxy
find ./ -name "Makefile" -type f -exec sed -i 's/-lquiche/-l:libquiche.a/g' {} +
find ./ -name "Makefile" -type f -exec sed -i 's/-lcurl/-l:libcurl.a/g' {} +
make -j2
make install
strip ${CI_PROJECT_DIR}/curl/bin/curl
ldd ${CI_PROJECT_DIR}/curl/bin/curl
#bash ${CI_PROJECT_DIR}/jobs/debug.sh
bash ${CI_PROJECT_DIR}/jobs/upx.sh
upx --best --lzma --color -f -v ${CI_PROJECT_DIR}/curl/bin/curl
