

TAGNAME='latest'


echo "create manifest for  \"PAN-OS-PHP docker container\" - pan-os-php - amd/arm" \
&& echo "" \
&& docker manifest rm swaschkut/pan-os-php-manifest \
&& echo "" \
&& docker manifest create swaschkut/pan-os-php-manifest swaschkut/pan-os-php-amd \
&& echo "" \
&& docker manifest create swaschkut/pan-os-php-manifest -a swaschkut/pan-os-php-arm \
&& echo "" \
&& docker manifest push swaschkut/pan-os-php-manifest