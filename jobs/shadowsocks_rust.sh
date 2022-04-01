#!/bin/bash
set -e

apt-get -qqy update
apt-get --yes install --no-install-recommends git ca-certificates build-essential gcc binutils
source $HOME/.cargo/env
export PATH=$PATH:$HOME/.cargo/bin
rustup update
rustup install nightly
rustc --version
rustup target add x86_64-unknown-linux-gnu
git clone --depth 1 https://github.com/shadowsocks/shadowsocks-rust.git /tmp/shadowsocks-rust
cd /tmp/shadowsocks-rust
env CARGO_HTTP_MULTIPLEXING=false cargo +nightly build --release --target x86_64-unknown-linux-gnu --features "local-tun aead-cipher-extra"
#env CARGO_HTTP_MULTIPLEXING=false cargo build --release --target x86_64-unknown-linux-gnu --features "aead-cipher-extra"
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td>shadowsocks-rust</td><td><a href="https://github.com/shadowsocks/shadowsocks-rust/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
list=(ssurl sslocal ssmanager ssserver)
for i in ${list[@]}; do
	strip target/x86_64-unknown-linux-gnu/release/$i
	cp -vf target/x86_64-unknown-linux-gnu/release/$i ${CI_PROJECT_DIR:?}/usr/bin
done
cd ${CI_PROJECT_DIR:?}
sed -i "s/${shadowsocks_rust_old:?}/${shadowsocks_rust:?}/g" version/version
git add usr/bin/ss* version/version temp/upgrade.log
git commit -m "更新shadowsocks-rust核心程序"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
