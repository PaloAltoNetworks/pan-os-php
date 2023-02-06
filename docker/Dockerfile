ARG IMAGE=ubuntu:20.04
FROM ${IMAGE}

ARG php_var="7.4"
ARG user_var="root"

SHELL ["/bin/bash", "-c"]

RUN DEBIAN_FRONTEND=noninteractive apt-get update --fix-missing

RUN DEBIAN_FRONTEND=noninteractive apt-get install --yes --fix-missing \
    tzdata \
    git \
    bash-completion

RUN DEBIAN_FRONTEND=noninteractive apt-get install --yes --fix-missing \
    php$php_var \
    php$php_var-curl \
    php$php_var-dom \
    php$php_var-mbstring \
    php$php_var-bcmath \
    php$php_var-yaml

RUN DEBIAN_FRONTEND=noninteractive apt-get install --yes --fix-missing \
    python3 \
    python3-pandas \
    python3-xlsxwriter \
    python3-netaddr \
    python3-requests

RUN DEBIAN_FRONTEND=noninteractive apt-get install --yes --fix-missing jq

WORKDIR /tools/pan-os-php

COPY appid-toolbox ./appid-toolbox
COPY lib ./lib
COPY phpseclib ./phpseclib
COPY git-php ./git-php
COPY utils ./utils
COPY tests ./tests
COPY iron-skillet ./iron-skillet


# PHP library of pan-os-php
RUN echo 'include_path = "/usr/share/php:/tools/pan-os-php"' >> /etc/php/$php_var/cli/php.ini
RUN chmod -R 777 /tools/pan-os-php

# UTIL alias for pan-os-php
RUN cat /tools/pan-os-php/utils/alias.sh >> /$user_var/.bashrc
RUN cat /tools/pan-os-php/utils/bash_autocompletion/enable_bash.txt >> /$user_var/.bashrc


RUN ln -sf /tools/pan-os-php/utils/bash_autocompletion/pan-os-php.sh /usr/share/bash-completion/completions/pan-os-php

RUN git config --global user.email=test@test.com user.name=test

# Entrypoint script
WORKDIR /scripts
COPY docker/entrypoint.sh .

# Working dir for the app
VOLUME /share
WORKDIR /share

ENTRYPOINT [ "/bin/bash", "/scripts/entrypoint.sh" ]
