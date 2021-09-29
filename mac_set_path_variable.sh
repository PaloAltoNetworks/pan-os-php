#!/usr/bin/env bash

FOLDER_PATH=$PWD


#echo "START \"set path variables\"" \
#&& echo "check if everything is successfully installed" \
#&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
#&& echo "" \
#&& echo "" \
#&& echo "" \
#&& echo "" \
#&& echo "prepare php.ini and set include path" \
#&& sudo cp -f /etc/php.ini.default /etc/php.ini \
#&& sudo chmod u+w /etc/php.ini \


check="source ${FOLDER_PATH}/utils/alias.sh"


echo "START \"set user bash profile\""   \
&& echo "" \
&& php -v \
&& echo "" \
&& echo "set $check" \
&& echo ""

array=( ".profile" ".bash_profile" ".zshrc" )

for filecheck in "${array[@]}"
do
	if grep -Fxq "$check" "$HOME/$filecheck"
  then
    echo "already available in: $filecheck"
  else
    echo $check >> ~/$filecheck \
    && echo "set in: $filecheck"
  fi
done

echo "" \
&& echo "END script"
