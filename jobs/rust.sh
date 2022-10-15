#!/bin/bash
set -e
apt-get -qqy update
apt-get --quiet install --yes wget curl tar unzip lib32stdc++6 lib32z1 git ca-certificates autoconf libtool libev-dev cmake autoconf automake build-essential gcc m4 binutils pkg-config

#https://stackoverflow.com/a/49676568
#https://rust-lang.github.io/rustup/installation/index.html#choosing-where-to-install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain ${1:-stable} -y
source $HOME/.cargo/env
export PATH=$PATH:$HOME/.cargo/bin
rustc --version
rustup --help
cargo help
rustup target list
