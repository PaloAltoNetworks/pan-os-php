#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR=$USER
USER_VAR="root"
PHP_VAR="8.1"

echo "START \"install PAN-OS-PHP on UBUNTU\"" \
&& apt update -y \
&& echo "" \
&& echo "\"install tzdata\"" \
&& apt-get -y install tzdata bash-completion \
&& echo "" \
&& apt install -y git php${PHP_VAR} vim php${PHP_VAR}-curl php${PHP_VAR}-dom php${PHP_VAR}-mbstring php${PHP_VAR}-bcmath \
&& echo "" \
&& echo "" \
&& echo "" \
&& php -v \
&& mkdir -p /tools ; cd /tools \
&& echo "extract everything to /tools and rename it to pan-os-php" \
&& echo "" \
&& echo "INSTALLATION via GIT" \
&& GIT_SSL_NO_VERIFY=true git clone https://github.com/PaloAltoNetworks/pan-os-php.git \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "\"set path variables\"" \
&& echo "include_path = '${FOLDER_PATH}'" | tee -a /etc/php/${PHP_VAR}/cli/php.ini \
&& echo "" \
&& echo "set user bash profile"   \
&& cat ${FOLDER_PATH}/utils/alias.sh >> /${USER_VAR}/.bashrc \
&& chmod -R 777 ${FOLDER_PATH} \
&& echo "" \
&& cat ${FOLDER_PATH}/utils/bash_autocompletion/enable_bash.txt >> /${USER_VAR}/.bashrc \
&& echo "" \
&& cp ${FOLDER_PATH}/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "END script"
