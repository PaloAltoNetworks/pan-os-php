#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR="root"
PHP_VAR="7.4"

echo "START \"update CENTOS\"" \
&& yum -y update \
&& echo "" \
&& echo "\"install tzdata\"" \
&& yum -y update tzdata \
&& yum -y install bash-completion bash-completion-extras \
&& echo "" \
&& yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
&& yum -y install http://rpms.remirepo.net/enterprise/remi-release-7.rpm \
&& yum -y install yum-utils \
&& yum-config-manager --enable remi-php56 \
&& echo "" \
&& echo "" \
&& yum -y install php php-cli php-fpm php-json php-intl php-curl php-dom php-mbstring php-bcmath && yum clean all \
&& php -v \
&& echo "" \
&& echo "" \
&& yum -y install git \
&& echo "" \
&& mkdir -p /tools ; cd /tools \
&& echo "extract everything to /tools and rename it to pan-os-php" \
&& echo "" \
&& echo "INSTALLATION via GIT" \
&& GIT_SSL_NO_VERIFY=true git clone https://github.com/PaloAltoNetworks/pan-os-php.git \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "\"set path variables\"" \
&& echo "include_path = '${FOLDER_PATH}'" | tee -a /etc/php.ini \
&& echo "" \
&& echo "set user bash profile"   \
&& cat ${FOLDER_PATH}/utils/alias.sh >> /${USER_VAR}/.bashrc \
&& chmod -R 777 ${FOLDER_PATH} \
&& echo "" \
&& cat ${FOLDER_PATH}/utils/bash_autocompletion/enable_bash.txt >> /${USER_VAR}/.bashrc \
&& echo "" \
&& cp ${FOLDER_PATH}/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php \
&& echo "" \
&& yum -y install curl \
&& yum -y groupinstall "Development Tools" \
&& curl -O https://ftp.gnu.org/gnu/bash/bash-5.0.tar.gz \
&& tar xvf bash-5.0.tar.gz \
&& cd bash-5.0 && ./configure && make && make install \
&& echo "" \
&& ech "cp /usr/local/bin/bash /bin/bash" \
&& echo "" \
&& echo '/usr/local/bin/bash' >> /etc/shells \
&& chsh -s /usr/local/bin/bash \
&& echo "" \
&& echo "" \
&& echo "check if everything is successfully installed" \
&& php -r "require('lib/pan_php_framework.php');print \"PAN-OS-PHP LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "" \
&& echo "END script"
