FROM ubuntu:20.04


SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update -y --fix-missing
RUN apt-get install -y tzdata


RUN apt-get install -y php php-curl php-dom php-mbstring


RUN mkdir /tools; mkdir /tools/pan-os-php;

COPY appid-toolbox /tools/pan-os-php/appid-toolbox
COPY lib /tools/pan-os-php/lib
COPY phpseclib /tools/pan-os-php/phpseclib
COPY utils /tools/pan-os-php/utils


# PHP library of pan-os-php
RUN echo 'include_path = "/usr/share/php:/tools/pan-os-php"' >> /etc/php/7.4/cli/php.ini
RUN chmod -R 777 /tools/pan-os-php

# UTIL alias for pan-os-php
RUN cat /tools/pan-os-php/utils/alias.sh >> /root/.bashrc