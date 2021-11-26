#!/bin/bash
set -e

apt-get -qq update
apt-get --yes install --no-install-recommends git ca-certificates build-essential gcc binutils
rustup update
rustup install nightly
rustc --version
rustup target add x86_64-unknown-linux-gnu
git clone --depth 1 https://github.com/shadowsocks/shadowsocks-rust.git /tmp/shadowsocks-rust
cd /tmp/shadowsocks-rust
echo "<tr><td>shadowsocks-rust</td><td><a href="https://github.com/shadowsocks/shadowsocks-rust/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
env CARGO_HTTP_MULTIPLEXING=false cargo +nightly build --release --target x86_64-unknown-linux-gnu --features "local-redir aead-cipher-extra"
list=(ssurl ssmanager ssserver)
for i in ${list[@]}; do
	strip target/x86_64-unknown-linux-gnu/release/$i
	cp -vf target/x86_64-unknown-linux-gnu/release/$i ${CI_PROJECT_DIR:?}/usr/bin
done
cd ${CI_PROJECT_DIR:?}
bash jobs/push.sh
sed -i "s/${shadowsocks_rust_old:?}/${shadowsocks_rust:?}/g" version/version
git add usr/bin/ss* version/version temp/upgrade.log
git commit -m "更新shadowsocks-rust核心程序"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME:?}
