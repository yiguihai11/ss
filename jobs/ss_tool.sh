#!/bin/bash
set -e
apt-get -qq update
apt-get --yes install --no-install-recommends build-essential gcc git
bash jobs/push.sh
gcc -s -fPIE -O3 -o usr/bin/ss-tool src/main.c
sed -i "s/${ss_tool_old:?}/${ss_tool:?}/g" version/version
git add usr/bin/ss-tool version/version
git commit -m "更新ss-tool"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME}
