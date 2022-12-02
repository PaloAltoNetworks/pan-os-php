#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"

file=$(realpath "$0")
FOLDER_PATH="${file%/*}"

USER_VAR=$(whoami)
echo "USER: ${USER_VAR}"

if [ "${USER_VAR}" != "root" ]; then
    USER_FOLDER_PATH="/home/"${USER_VAR}
else
    USER_FOLDER_PATH="/"${USER_VAR}
fi


echo "USER FOLDERPATH: ${USER_FOLDER_PATH}"
echo "SCRIPT FOLDERPATH: ${FOLDER_PATH}"

echo "bashrc: ${USER_FOLDER_PATH}/.bashrc"

echo "START \"PAN-OS-PHP variables on UBUNTU\"" \
&& echo "" \
&& echo "" \
&& echo "set user bash profile"   \
&& cat ${FOLDER_PATH}/utils/alias.sh >> ${USER_FOLDER_PATH}/.bashrc \
&& echo "" \
&& cat ${FOLDER_PATH}/utils/bash_autocompletion/enable_bash.txt >> ${USER_FOLDER_PATH}/.bashrc \
&& echo "" \
&& ln -s ${FOLDER_PATH}/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php \
&& echo "check if everything is successfully installed" \
&& php -r "require('${FOLDER_PATH}/lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "END script"