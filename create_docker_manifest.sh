

TAGNAME='latest'


#&& echo "" \
#&& docker manifest rm swaschkut/pan-os-php \

echo "create manifest for  \"PAN-OS-PHP docker container\" - pan-os-php - amd/arm" \
&& echo "" \
&& docker manifest create swaschkut/pan-os-php swaschkut/pan-os-php-amd \
&& echo "" \
&& docker manifest create swaschkut/pan-os-php -a swaschkut/pan-os-php-arm \
&& echo "" \
&& docker manifest push swaschkut/pan-os-php