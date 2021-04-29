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
&& apt install -y git php vim php-curl php-dom php-mbstring python3.7 python3-pip iputils-ping traceroute \
&& echo "" \
&& echo "" \
&& apt install -y perl \
&& cpan install List::MoreUtils \
&& echo "" \
&& echo "" \
&& php -v \
&& "mkdir /tools ; cd /tools" \
&& "extract everything to /tools and rename it to Expedition-Converter" \
&& echo "" \
&& "INSTALLATION via GIT" \
&& "git clone https://spring.paloaltonetworks.com/swaschkut/Expedition-Converter.git" \
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
&& php -r "require('lib/pan_php_framework.php');print \"Expedition-Converter LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "END script"
