#!/usr/bin/env bash

script_full_path=$(dirname "$0")

cd $script_full_path

git -c user.name=test -c user.email=test@test.com stash
git clean -f
git -c http.sslVerify=false pull origin main
git submodule init
git -c http.sslVerify=false submodule update --remote