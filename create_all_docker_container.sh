

TAGNAME='latest'


echo "create all \"PAN-OS-PHP docker container\" - pan-os-php/-cli/-api" \
&& echo "" \
&& docker build -t swaschkut/pan-os-php:${TAGNAME} -f docker/Dockerfile . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-amd:${TAGNAME} -f docker/Dockerfile . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-cli:${TAGNAME} -f docker/Dockerfile-php . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-api:${TAGNAME} -f docker/Dockerfile-API . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-arm:${TAGNAME} -f docker/Dockerfile_arm64v8_full . \
&& echo ""