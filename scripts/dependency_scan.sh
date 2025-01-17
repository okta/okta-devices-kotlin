#!/bin/bash

start_scan=false
if echo "${BRANCH}" | grep -Eq "(^master$|^([0-9]+\.[0-9]*[13579])$)"; then
start_scan=true
elif echo "${BRANCH}" | grep -Eq "(^release$|^preview$|^([0-9]+\.[0-9]+)-(pf|lc|pb|tf)[0-9]+$)"; then
start_scan=true
else
start_scan=false
fi

if [[ "$start_scan" = false ]]; then
echo 'Not a release or master. dependency-scan skipped'
exit 0
fi

#####
## Build Environment Setup
#####
java17_0

#####
## Execute Dependency Scanning
#####
REPO_DIR=$(git rev-parse --git-dir | sed 's/.git//g')

dependency_scan --configuration-matching=implementation
