#!/bin/bash
set -e
apt-get -qqy update
apt-get -qqy --yes install --no-install-recommends git ca-certificates

cd ${CI_PROJECT_DIR:?}
https_url="${CI_SERVER_PROTOCOL:=https}://${GITLAB_USER_LOGIN:?}:${my_access_token:?}@${CI_REPOSITORY_URL#*@}"
#git config --global http.sslVerify false
#git config --global user.email "$GITLAB_USER_EMAIL"
git config --global user.email "gitlab-bot@gitlab.com"
#git config --global user.name "$GITLAB_USER_LOGIN"
git config --global user.name "gitlab-bot"
git remote -v
git remote set-url origin "$https_url"
git pull ${https_url:?} ${CI_COMMIT_REF_NAME:?} --ff-only #--allow-unrelated-histories
