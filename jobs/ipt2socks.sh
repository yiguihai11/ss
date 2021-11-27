#!/bin/bash
set -e

apt-get -qq update
apt-get --yes install --no-install-recommends git ca-certificates build-essential gcc binutils
git clone --depth 1 https://github.com/zfl9/ipt2socks /tmp/ipt2socks
cd /tmp/ipt2socks
make
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td>ipt2socks</td><td><a href="https://github.com/zfl9/ipt2socks/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf ipt2socks ${CI_PROJECT_DIR}/usr/bin
cd ${CI_PROJECT_DIR:?}
sed -i "s/${ipt2socks_old:?}/${ipt2socks:?}/g" version/version
git add usr/bin/ipt2socks version/version temp/upgrade.log
git commit -m "更新ipt2socks"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME:?}
