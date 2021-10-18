#!/usr/bin/env bash

FOLDER_PATH=$PWD


#&& echo "prepare php.ini and set include path" \
#&& sudo cp -f /etc/php.ini.default /etc/php.ini \
#&& sudo chmod u+w /etc/php.ini \



PHPINI=`php -i | grep "Loaded Configuration File"`

SEARCH="Loaded Configuration File => "
REPLACE=""

PHPINI=${PHPINI/Loaded Configuration File => }

check="include_path = '${FOLDER_PATH}'"


#&& echo "include_path = '${FOLDER_PATH}'" | tee -a ${PHPINI}

echo "" \
&& php -v \
&& echo "" \
&& echo "---------------------" \
&& echo "" \
&& echo "START \"set php.ini include_path\""
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
&& echo "---------------------" \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "---------------------" \
&& echo ""

check="source ${FOLDER_PATH}/utils/alias.sh"


echo "START \"set user bash profile\""   \
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
