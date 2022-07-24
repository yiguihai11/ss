#!/bin/bash
set -e
apt-get --yes install --no-install-recommends \
	openssh-client \
	openssh-server \
	git
#https://forum.gitlab.com/t/git-push-from-inside-a-gitlab-runner/30554/5
eval $(ssh-agent -s)
echo "${SSH_PRIVATE_KEY}" | tr -d '\r' | ssh-add - >/dev/null
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "$SSH_PUBLIC_KEY" >>~/.ssh/id_rsa.pub
if [ -f /.dockerenv ]; then
	echo -e "Host *\n\tStrictHostKeyChecking no\n\n" >~/.ssh/config
fi
ssh -T git@gitlab.com
git config --global user.email "$GITLAB_USER_EMAIL"
git config --global user.name "$GITLAB_USER_LOGIN"
git remote set-url origin git@${CI_SERVER_HOST}:${CI_PROJECT_PATH}.git
