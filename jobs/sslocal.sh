#!/bin/bash
set -e
source jobs/golang.sh
if [[ "$PLATFORM" == "arm-"* ]]; then
   go_arch='arm'
elif [[ "$PLATFORM" == "aarch64-"* ]];then
   go_arch='arm64'
fi
source jobs/ndk.sh
ln -s ${NDK_PREFIX}/lib/${PLATFORM}/${API}/libc.a ${NDK_PREFIX}/lib/${PLATFORM}/${API}/libpthread.a
ln -s ${NDK_PREFIX}/lib/${PLATFORM}/${API}/libc.so ${NDK_PREFIX}/lib/${PLATFORM}/${API}/libpthread.so
bash jobs/rust.sh

apt-get --yes install --no-install-recommends zip xz-utils wget
wget https://nodejs.org/dist/v16.16.0/node-v${NODEJS_VER}-linux-x64.tar.xz
tar xf node-v${NODEJS_VER}-linux-x64.tar.xz
export PATH=$PATH:$(pwd)/node-v${NODEJS_VER}-linux-x64/bin
npm install --global yarn
git clone --depth 1 --recurse-submodules https://github.com/cloudreve/Cloudreve.git
cd Cloudreve/assets
export CI=false
yarn install
yarn run build
cd build
find . -name "*.map" -type f -delete
# 返回项目主目录打包静态资源
cd ../../
zip -r - assets/build >assets.zip
# 获得当前版本号、Commit
export COMMIT_SHA=$(git rev-parse --short HEAD)
export VERSION=$(git describe --tags)
env AR=$TOOLCHAIN/bin/llvm-ar CC=${PLATFORM}${API}-clang CXX=${PLATFORM}${API}-clang++ LD=$TOOLCHAIN/bin/ld GO111MODULE=on CGO_ENABLED=1 GOOS=android GOARCH=$go_arch go build -a -o cloudreve -ldflags "-s -w -X 'github.com/cloudreve/Cloudreve/v3/pkg/conf.BackendVersion=$VERSION' -X 'github.com/cloudreve/Cloudreve/v3/pkg/conf.LastCommit=$COMMIT_SHA'"
ls
cd ..

git clone --depth 1 https://github.com/teddysun/v2ray-plugin.git
cd v2ray-plugin
go get -d ./...
env AR=$TOOLCHAIN/bin/llvm-ar CC=${PLATFORM}${API}-clang CXX=${PLATFORM}${API}-clang++ LD=$TOOLCHAIN/bin/ld GO111MODULE=on CGO_ENABLED=1 GOOS=android GOARCH=$go_arch go build -ldflags "-X main.VERSION=$(date -u +%Y%m%d) -s -w" -o v2ray-plugin
file v2ray-plugin
$PLATFORM-readelf -d v2ray-plugin
cd ..

git clone --depth 1 https://github.com/xtaci/kcptun.git
cd kcptun/client
env AR=$TOOLCHAIN/bin/llvm-ar CC=${PLATFORM}${API}-clang CXX=${PLATFORM}${API}-clang++ LD=$TOOLCHAIN/bin/ld GO111MODULE=on CGO_ENABLED=1 GOOS=android GOARCH=$go_arch go build -mod=vendor -ldflags "-X main.VERSION=$(date -u +%Y%m%d) -s -w" -o kcptun-client
cd ${CI_PROJECT_DIR:?}

git clone --depth 1 https://github.com/XIU2/CloudflareSpeedTest
cd CloudflareSpeedTest
go get -d ./...
env AR=$TOOLCHAIN/bin/llvm-ar CC=${PLATFORM}${API}-clang CXX=${PLATFORM}${API}-clang++ LD=$TOOLCHAIN/bin/ld GO111MODULE=on CGO_ENABLED=1 GOOS=android GOARCH=$go_arch go build -ldflags "-X main.VERSION=$(date -u +%Y%m%d) -s -w"
cd ..


wget http://dist.schmorp.de/libev/libev-4.33.tar.gz
tar zxvf libev-4.33.tar.gz
rm -rf libev-4.33.tar.gz
cd libev-4.33
chmod +x autogen.sh
./autogen.sh
env CC=${PLATFORM}${API}-clang CXX=${PLATFORM}${API}-clang++ LD=$TOOLCHAIN/bin/ld ./configure --host=${PLATFORM} --prefix=$NDK_PREFIX
make
make install
cd ..
git clone --depth 1 https://github.com/shadowsocks/simple-obfs
cd simple-obfs
git submodule update --init
./autogen.sh
#https://www.cnblogs.com/z16166/p/13192665.html
env CC=${PLATFORM}${API}-clang CXX=${PLATFORM}${API}-clang++ LD=$TOOLCHAIN/bin/ld ./configure --host=${PLATFORM} --disable-documentation
find ./ -name "Makefile" -type f -exec sed -i 's/-lev/-l:libev.a/g' {} +
make
$PLATFORM-strip src/obfs-local
cd ..

latest_version="$(wget --no-check-certificate -qO- https://www.openssl.org/source/ | grep -oP 'openssl\-\d+\.\d+\.\d+\w+\.tar\.gz' | head -n1)"
wget --no-check-certificate --quiet --continue https://www.openssl.org/source/${latest_version}
tar xzf ${latest_version}
rm -f ${latest_version}
mv ${latest_version/.tar.gz/} openssl
cd openssl
./Configure LIST
./Configure -llog android-arm64 --prefix=$NDK_PREFIX
make -j2
make install_sw
cd ..
git clone --depth 1 https://github.com/pymumu/smartdns
patch -p0 <${CI_PROJECT_DIR:?}/patch/smartdns.patch
cd smartdns
make CC=${PLATFORM}${API}-clang CXX=${PLATFORM}${API}-clang++ LD=$TOOLCHAIN/bin/ld
$PLATFORM-strip src/smartdns
$PLATFORM-readelf -d src/smartdns

ls -l $TOOLCHAIN/bin
source $HOME/.cargo/env
export PATH=$PATH:$HOME/.cargo/bin
rustup override set nightly
rustup target add $PLATFORM
export CARGO_HTTP_MULTIPLEXING=false
git clone --depth 1 https://github.com/shadowsocks/shadowsocks-rust
cd shadowsocks-rust
patch -p0 crates/shadowsocks-service/Cargo.toml ${CI_PROJECT_DIR:?}/patch/Cargo.toml.patch
cargo update --manifest-path Cargo.toml
cargo update --manifest-path crates/shadowsocks/Cargo.toml
cargo update --manifest-path crates/shadowsocks-service/Cargo.toml
cargo update --manifest-path crates/shadowsocks-tools/Cargo.toml
#touch /tmp/keepalive
#bash jobs/debug.sh
export AR=$TOOLCHAIN/bin/llvm-ar
export CC=$TOOLCHAIN/bin/${PLATFORM}${API}-clang
export AS=$CC
export CXX=$TOOLCHAIN/bin/${PLATFORM}${API}-clang++
export LD=$TOOLCHAIN/bin/ld
export RANLIB=$TOOLCHAIN/bin/llvm-ranlib
export STRIP=$TOOLCHAIN/bin/llvm-strip
if [[ "$PLATFORM" == "arm-"* ]]; then
  export CC=$TOOLCHAIN/bin/armv7a-linux-androideabi${API}-clang
  export CXX=$TOOLCHAIN/bin/armv7a-linux-androideabi${API}-clang++
fi
if [[ "$PLATFORM" == "aarch64-"* ]]; then
  env RUSTFLAGS="-C linker=$CC" cargo build --target "$PLATFORM" --release --features "local-tun local-dns local-tunnel aead-cipher-2022 armv8 neon"
else
  env RUSTFLAGS="-C linker=$CC" cargo build --target "$PLATFORM" --release --features "local-tun local-dns local-tunnel aead-cipher-2022"
fi
file target/$PLATFORM/release/sslocal
$PLATFORM-readelf -d target/$PLATFORM/release/sslocal

cat >${CI_PROJECT_DIR:?}/acl/bypass-china.acl <<EOF
[proxy_all]

[bypass_list]
$(curl -s -L https://bgp.space/china.html | grep -oP '([0-9]+\.){3}[0-9]+?\/[0-9]{1,2}')
$(curl -s -L https://bgp.space/china6.html | grep -oP '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\/[0-9]{1,3}')
EOF
#upx --lzma --color -f -v target/$PLATFORM/release/sslocal
#$PLATFORM-strip target/$PLATFORM/release/sslocal

