#!/bin/bash
set -e
apt-get -qq update
apt-get --yes install --no-install-recommends gzip wget xz-utils
bash jobs/golang.sh
go install mvdan.cc/sh/v3/cmd/shfmt@latest
$(go env GOPATH)/bin/shfmt -version
scversion="stable" # or "v0.4.7", or "latest"
wget -qO- "https://github.com/koalaman/shellcheck/releases/download/${scversion?}/shellcheck-${scversion?}.linux.x86_64.tar.xz" | tar -xJv
cp "shellcheck-${scversion}/shellcheck" /usr/bin/
shellcheck --version
bash jobs/push.sh
$(go env GOPATH)/bin/shfmt -l -s -w src/manager.sh
shellcheck --shell=bash src/manager.sh
gzexe src/manager.sh
mv -vf src/manager.sh usr/bin/ss-main
mv -vf src/manager.sh~ src/manager.sh
sed -i "s/${ss_main_old:?}/${ss_main:?}/g" version/version
git add src/manager.sh usr/bin/ss-main version/version
git commit -m "更新ss-main管理脚本"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
