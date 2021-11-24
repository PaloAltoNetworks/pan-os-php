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

#"${string//,/$'\n'}"

CHECKSED=${check/\//'\/'}

#CHECKSED="$check" | sed -r 's/[\/]+/\\\//g'

#&& echo "include_path = '${FOLDER_PATH}'" | tee -a ${PHPINI}

echo "" \
&& php -v \
&& echo "" \
&& echo "---------------------" \
&& echo "" \
&& echo "START \"check php.ini include_path\"" \
&& echo "remove $check" \
&& echo "SED: |"$CHECKSED"|"


if grep -Fxq "$check" ${PHPINI}
  then
    echo "" \
    && echo "available in: ${PHPINI}" \
    && echo "check how to remove" \
    && sed "s/$CHECKSED// ${PHPINI}" \
    && echo ""
  else
    echo "" \
    && echo "not available in: ${PHPINI}"
  fi

echo "" \
&& echo "---------------------" \
&& echo ""

check="source ${FOLDER_PATH}/utils/alias.sh"


echo "START \"check user bash profile\""   \
&& echo "" \
&& echo "remove $check" \
&& echo ""

array=( ".profile" ".bash_profile" ".zshrc" )


for filecheck in "${array[@]}"
do
	if grep -Fxq "$check" "$HOME/$filecheck"
  then
    echo "available in: $filecheck" \
    && echo "check how to remove" \
    && sed "s|$check| $HOME/$filecheck|" \
    && echo ""
  else
    echo "" \
    && echo "not available in: $filecheck"
  fi
done

echo "" \
&& echo "END script"
