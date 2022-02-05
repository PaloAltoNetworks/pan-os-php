#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR="/root"

PHPINI="/etc/php.ini"
check="include_path = '${FOLDER_PATH}'"

echo "START \"install PAN-OS-PHP on CENTOS\"" \
&& yum -y update \
&& echo "" \
&& echo "\"install tzdata\"" \
&& yum -y update tzdata \
&& yum -y install bash-completion \
&& echo "" \
&& echo "" \
&& dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
&& dnf -y install https://rpms.remirepo.net/enterprise/remi-release-8.rpm \
&& dnf -y install yum-utils \
&& dnf -y module reset php \
&& dnf -y module install php:remi-8.0 \
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
&& rm -rf pan-os-php \
&& echo "INSTALLATION via GIT" \
&& GIT_SSL_NO_VERIFY=true git clone https://github.com/PaloAltoNetworks/pan-os-php.git \
&& echo "" \
&& echo "\"set path variables\""

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
&& echo "" \
&& cp ${FOLDER_PATH}/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php \
&& echo "" \
&& echo "" \
&& yum -y install curl \
&& yum -y groupinstall "Development Tools" \
&& curl -O https://ftp.gnu.org/gnu/bash/bash-5.0.tar.gz \
&& tar xvf bash-5.0.tar.gz \
&& cd bash-5.0 && ./configure && make && make install \
&& echo "" \
&& echo "THIS IS NOT WORKING for CENTOS install script" \
&& echo "yes | cp /usr/local/bin/bash /bin/bash" \
&& echo "" \
&& dnf -y install util-linux-user \
&& echo '/usr/local/bin/bash' >> /etc/shells \
&& chsh -s /usr/local/bin/bash \
&& echo "" \
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
