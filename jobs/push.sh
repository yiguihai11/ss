#!/bin/bash
set -e
apt-get -qq update
apt-get --yes install --no-install-recommends git
git config --global user.email "$GITLAB_USER_EMAIL"
git config --global user.name "$GITLAB_USER_LOGIN"
cru=${CI_REPOSITORY_URL#*@}
git remote set-url origin ${CI_SERVER_PROTOCOL:=https}://${GITLAB_USER_LOGIN:?}:${my_access_token:?}@${cru:?}
