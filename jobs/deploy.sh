#!/bin/bash
set -e

apt-get -qqy update
apt-get --yes install --no-install-recommends git ca-certificates libdigest-sha-perl curl coreutils
bash jobs/push.sh
bash src/make_readme.sh
shasum -a512 \
	usr/bin/v2ray-plugin \
	usr/bin/kcptun-server \
	usr/bin/obfs-server \
	usr/bin/qrencode \
	usr/bin/ss-main \
	usr/bin/ssmanager \
	usr/bin/ssserver \
	usr/bin/ss-tool \
	usr/bin/ssurl \
	>version/update
sed -i "s/usr/\/etc\/ssmanager\/usr/g" version/update
git add README.md temp/* version/* usr/*
#git commit -m "$GITLAB_USER_NAME $CI_RUNNER_EXECUTABLE_ARCH"
git commit -m "计划更新"
git push origin HEAD:${CI_COMMIT_REF_NAME}
