#! /bin/bash

# If no arguments are passed to the container, execute a bash shell, else execute
# pan-os-php and pass the arguments to it 

if [[ -z $@ ]]
then
    exec /bin/bash
else
    exec php -r "require_once('/tools/pan-os-php/utils/pan-os-php.php');" "$@"
fi
