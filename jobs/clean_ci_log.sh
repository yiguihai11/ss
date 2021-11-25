#!/bin/bash
set -e
apt-get -qq update
apt-get --yes install --no-install-recommends curl

#https://qa.1r1g.com/sf/ask/3734890491/
for PIPELINE in $(curl --header "PRIVATE-TOKEN: $my_access_token" "https://gitlab.com/api/v4/projects/${CI_PROJECT_ID:?}/pipelines?per_page=100&sort=asc" | jq '.[].id'); do
	if [ "$PIPELINE" -ne ${CI_PIPELINE_ID:-0} ]; then
		echo "Deleting pipeline $PIPELINE"
		curl --header "PRIVATE-TOKEN: $my_access_token" --request "DELETE" "https://gitlab.com/api/v4/projects/${CI_PROJECT_ID:?}/pipelines/$PIPELINE"
	fi
done
