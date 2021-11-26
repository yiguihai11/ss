#!/bin/bash
set -e

bash jobs/push.sh
git checkout --orphan new_branch
git add -A
git commit -am "Initial commit"
git branch -D ${CI_COMMIT_REF_NAME:?}
git branch -m ${CI_COMMIT_REF_NAME:?}
git push -f origin ${CI_COMMIT_REF_NAME:?}
