

TAGNAME='latest'


echo "create all \"PAN-OS-PHP docker container\" - pan-os-php/-cli/-api" \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-amd:${TAGNAME} -f docker/Dockerfile-main_amd . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-cli-amd:${TAGNAME} -f docker/Dockerfile-php_amd . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-api-amd:${TAGNAME} -f docker/Dockerfile-API_amd . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-arm:${TAGNAME} -f docker/Dockerfile-main_arm64v8 . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-cli-arm:${TAGNAME} -f docker/Dockerfile-php_arm64v8 . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-api-arm:${TAGNAME} -f docker/Dockerfile-API_arm64v8 . \
&& echo ""