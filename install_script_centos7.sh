#!/usr/bin/env bash

FOLDER_PATH="/tools/pan-os-php"
USER_VAR="/home/"$USER

PHPINI="/etc/php.ini"
check="include_path = '${FOLDER_PATH}'"

echo "START \"install PAN-OS-PHP on CENTOS\"" \
&& yum -y update \
&& echo "" \
&& echo "\"install tzdata\"" \
&& yum -y update tzdata \
&& yum -y install bash-completion \
&& echo "" \
&& yum -y install epel-release \
&& echo "" \
&& echo "vi /etc/yum.repos.d/epel.repo" \
&& echo "comment meta-link; uncomment base" \
&& echo "" \
&& yum -y install http://rpms.remirepo.net/enterprise/remi-release-7.rpm

echo "" \
&& yum -y install yum-utils \
&& yum-config-manager --enable remi-php74 \
&& echo "" \
&& echo "" \
&& yum -y install php php-cli php-fpm php-json php-intl php-curl php-dom php-mbstring php-bcmath php-yaml && yum clean all \
&& php -v \
&& echo "" \
&& echo "" \
&& yum -y install git \
&& echo "" \
&& mkdir -p /tools \
&& cd /tools \
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
&& curl -O --insecure https://ftp.gnu.org/gnu/bash/bash-5.0.tar.gz \
&& tar xvf bash-5.0.tar.gz \
&& cd bash-5.0 && ./configure && make && make install \
&& echo "" \
&& echo "change bash" \
&& echo "" \
&& echo '/usr/local/bin/bash' >> /etc/shells \
&& chsh -s /usr/local/bin/bash \
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
&& echo "" \
&& echo " and for CENTOS7" \
&& echo "chsh -s /usr/local/bin/bash" \
&& echo "" \
&& echo "END script"