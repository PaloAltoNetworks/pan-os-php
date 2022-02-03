#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR=$USER
USER_FOLDER_PATH="/Users/"$USER
PHP_VAR="8.0"

echo "START \"install script for MACOS\"" \
&& echo "" \
&& echo "\"install HOMEBREW\"" \
&& echo "https://osxdaily.com/2018/03/07/how-install-homebrew-mac-os/" \
&& /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "\"install bash_autocompletion\"" \
&& brew install bash-completion \
&& echo "" \
&& echo "" \
&& echo "if [ -f $(brew --prefix)/etc/bash_completion ]; then" \
&& echo ". $(brew --prefix)/etc/bash_completion" \
&& echo "fi" \
&& echo "" \
&& echo "" \
&& echo "install php and other php modules via HOMEBREW" \
&& echo "https://postsrc.com/posts/how-to-install-php-8-on-macos-big-sur-using-homebrew" \
&& brew install php@${PHP_VAR} \
&& echo "what about php-curl  php-dom php-mbstring php-bcmath" \
&& echo "" \
&& php -v \
&& echo "" \
&& echo "" \
&& echo "install GIT" \
&& brew install git \
&& echo "" \
&& echo "" \
&& mkdir -p /tools ; cd /tools \
&& echo "extract everything to /tools and rename it to pan-os-php" \
&& echo "" \
&& echo "INSTALLATION via GIT" \
&& GIT_SSL_NO_VERIFY=true git clone https://github.com/PaloAltoNetworks/pan-os-php.git \
&& echo "" \
&& chmod -R 777 ${FOLDER_PATH} \
&& echo "" \
&& cp ${FOLDER_PATH}/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "\"install BASH5\"" \
&& brew install bash \
&& echo "chsh -s /usr/local/bin/bash" \
&& echo "cat /etc/shells" \
&& echo "" \
&& echo "$(brew --prefix)/bin/bash | sudo tee -a /private/etc/shells /usr/local/bin/bash" \
&& echo "chpass -s /usr/local/bin/bash ${USER_VAR}" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "set user bash profile"   \
&& cat ${FOLDER_PATH}/utils/alias.sh >> ${USER_FOLDER_PATH}/.bashrc \
&& echo "" \
&& cat ${FOLDER_PATH}/utils/bash_autocompletion/enable_bash.txt >> ${USER_FOLDER_PATH}/.bashrc \
&& echo "" \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "END script"
