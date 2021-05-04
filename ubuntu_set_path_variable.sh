#!/usr/bin/env bash

FOLDER_PATH=$PWD
USER_VAR=$USER
PHP_VAR="7.2"

echo "START \"update UBUNTU\"" \
&& apt update -y \
&& echo "" \
&& echo "\"install tzdata\"" \
&& apt-get -y install tzdata \
&& echo "" \
&& apt install -y git php${PHP_VAR} vim php${PHP_VAR}-curl php${PHP_VAR}-dom php${PHP_VAR}-mbstring \
&& echo "" \
&& echo "" \
&& echo "" \
&& php -v \
&& "mkdir /tools ; cd /tools" \
&& "extract everything to /tools and rename it to pan-os-php" \
&& echo "" \
&& "INSTALLATION via GIT" \
&& "git clone https://github.com/PaloAltoNetworks/pan-os-php.git" \
&& echo "" \
&& echo "" \
&& "cd ${FOLDER_PATH}" \
&& echo "" \
&& echo "\"set path variables\"" \
&& echo "include_path = '${FOLDER_PATH}'" | sudo tee -a /etc/php/${PHP_VAR}/cli/php.ini \
&& echo "" \
&& echo "set user bash profile"   \
&& cat ${FOLDER_PATH}/utils/alias.sh >> /${USER_VAR}/.bashrc \
&& chmod -R 777 ${FOLDER_PATH} \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "END script"
