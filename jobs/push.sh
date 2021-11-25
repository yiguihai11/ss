#!/bin/bash
set -e
apt-get -qq update
apt-get -qq --yes install --no-install-recommends git ca-certificates
#git config --global http.sslVerify false
git config --global user.email "$GITLAB_USER_EMAIL"
git config --global user.name "$GITLAB_USER_LOGIN"
git remote set-url origin "${CI_SERVER_PROTOCOL:=https}://${GITLAB_USER_LOGIN:?}:${my_access_token:?}@${CI_REPOSITORY_URL#*@}"
