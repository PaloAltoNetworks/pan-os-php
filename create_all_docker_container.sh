




echo "create all \"PAN-OS-PHP docker container\" - pan-os-php/-cli/-api" \
&& docker build -t swaschkut/pan-os-php -f docker/Dockerfile . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-cli -f docker/Dockerfile-php . \
&& echo "" \
&& docker build -t swaschkut/pan-os-php-api -f docker/Dockerfile-API . \
&& echo ""