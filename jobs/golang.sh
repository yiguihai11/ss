#!/bin/bash
set -e
apt-get -qq update
apt-get --quiet install --yes wget tar ca-certificates

cd /tmp
latest_version="$(wget -qO- https://golang.org/dl/ | grep 'download downloadBox' | grep -oP '\d+\.\d+(\.\d+)?' | head -n 1)"
echo "Downloading latest Go for AMD64: ${latest_version}"
wget --quiet --continue https://dl.google.com/go/go${latest_version}.linux-amd64.tar.gz
tar -C /usr/local -xzf go${latest_version}.linux-amd64.tar.gz
rm -f go${latest_version}.linux-amd64.tar.gz
#必须更改变量，不然调用go编译器报错
export GOROOT=/usr/local/go
export GOTOOLDIR=/usr/local/go/pkg/tool/linux_amd64
ln -sf /usr/local/go/bin/go /usr/bin/go
go version
go env
