#!/bin/bash
set -e
apt-get -qq update
apt-get --yes install --no-install-recommends shellcheck gzip
go install mvdan.cc/sh/v3/cmd/shfmt@latest
$(go env GOPATH)/bin/shfmt -version
$(go env GOPATH)/bin/shfmt -l -s -w src/manager.sh
shellcheck --shell=bash src/manager.sh
gzexe src/manager.sh
mv -vf src/manager.sh usr/bin/ss-main
mv -vf src/manager.sh~ src/manager.sh
sed -i "s/$ss_main_old/$ss_main/g" version/version
git add src/manager.sh usr/bin/ss-main version/version
git commit -m "更新ss-main管理脚本"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME}
