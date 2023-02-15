

TYPE='-api'
TYPE='-cli'
TYPE=''
#&& echo "" \
#&& docker manifest rm swaschkut/pan-os-php \

echo "create manifest for  \"PAN-OS-PHP docker container\" - pan-os-php - amd/arm" \
&& echo "" \
&& echo "" \
&& echo "" \
&& docker manifest create swaschkut/pan-os-php${TYPE}:develop swaschkut/pan-os-php${TYPE}-amd:develop \
&& echo "" \
&& docker manifest create swaschkut/pan-os-php${TYPE}:develop -a swaschkut/pan-os-php${TYPE}-arm:develop \
&& echo "" \
&& echo "" \
&& echo "" \
&& docker manifest push swaschkut/pan-os-php${TYPE}:develop