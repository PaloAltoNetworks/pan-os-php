#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR="/home/"$USER
PHP_VAR="8.1"

PHPINI="/etc/php/${PHP_VAR}/cli/php.ini"
check="include_path = '${FOLDER_PATH}'"

echo "START \"install PAN-OS-PHP on UBUNTU\"" \
&& apt update -y --fix-missing\
&& echo "" \
&& echo "\"install tzdata\"" \
&& apt-get -y install tzdata bash-completion \
&& echo "" \
&& apt install -y git php${PHP_VAR} vim php${PHP_VAR}-curl php${PHP_VAR}-dom php${PHP_VAR}-mbstring php${PHP_VAR}-bcmath php${PHP_VAR}-yaml \
&& echo "" \
&& apt install -y python3 python3-pandas python3-xlsxwriter python3-netaddr python3-requests \
&& echo "" \
&& apt install -y jq \
&& echo "" \
&& echo "" \
&& php -v \
&& mkdir -p /tools ; cd /tools \
&& echo "extract everything to /tools and rename it to pan-os-php" \
&& echo "" \
&& rm -rf pan-os-php \
&& echo "INSTALLATION via GIT" \
&& GIT_SSL_NO_VERIFY=true git clone https://github.com/PaloAltoNetworks/pan-os-php.git \
&& echo "" \
&& echo "set path variables"

if grep -Fxq "$check" ${PHPINI}
  then
    echo "" \
    && echo "already available in: ${PHPINI}"
  else
    echo "" \
    && echo $check >> ${PHPINI} \
    && echo "set in: ${PHPINI}"
  fi

echo "" \
&& ln -sf ${FOLDER_PATH}/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php \
&& echo "" \
&& cd ${FOLDER_PATH} \
&& GIT_SSL_NO_VERIFY=true git submodule init \
&& GIT_SSL_NO_VERIFY=true git submodule update --remote \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "you need to run now with your none priviledge user the following command:" \
&& echo "sh /tools/pan-os-php/set_alias_usage.sh" \
&& echo "" \
&& echo "END script"
