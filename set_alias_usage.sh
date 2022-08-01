#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR==$(whoami)

if [ "${USER_VAR}" == "root" ]; then
    USER_FOLDER_PATH="/"${USER_VAR}
else
    USER_FOLDER_PATH="/home/"${USER_VAR}
fi

cat ${USER_FOLDER_PATH}

echo "START \"PAN-OS-PHP variables on UBUNTU\"" \
&& echo "" \
&& echo "" \
&& echo "set user bash profile"   \
&& cat ${FOLDER_PATH}/utils/alias.sh >> ${USER_FOLDER_PATH}/.bashrc \
&& echo "" \
&& cat ${FOLDER_PATH}/utils/bash_autocompletion/enable_bash.txt >> ${USER_FOLDER_PATH}/.bashrc \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "END script"