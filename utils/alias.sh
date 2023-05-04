
#alias pa_migration-parser='php -r "require_once '"'"'parser/migration_parser.php'"'"';" $@'
#alias pa_migration-discovery='php -r "require_once '"'"'parser/migration-discovery.php'"'"';" $@'
#alias pa_panorama-2-fawkes='php -r "require_once '"'"'parser/panorama2fawkes.php'"'"';" $@'


#alias pa_docker-migration-parser='docker run --name converter --rm -v ${PWD}:/expedition-converter -it swaschkut/expedition-converter php /tools/converter/parser/migration_parser.php'
#alias pa_docker-migration-parser2='docker run  --name converter --rm -v ${PWD}:/expedition-converter -it swaschkut/expedition-converter'
alias pa_docker-panosphp='docker run --name panosphp --rm -v $PWD:/share -it swaschkut/pan-os-php:latest'



alias pan-os-php='php -r "require_once '"'"'utils/pan-os-php.php'"'"';" $@'
##########################################################################################
##########################################################################################
##########################################################################################


#APPID TOOLBOX
#alias pa_appidtoolbox-report-generator='php -r "require_once '"'"'appid-toolbox/report-generator.php'"'"';" $@'
#alias pa_appidtoolbox-rule-activation='php -r "require_once '"'"'appid-toolbox/rule-activation.php'"'"';" $@'
#alias pa_appidtoolbox-rule-cleaner='php -r "require_once '"'"'appid-toolbox/rule-cleaner.php'"'"';" $@'
#alias pa_appidtoolbox-rule-cloner='php -r "require_once '"'"'appid-toolbox/rule-cloner.php'"'"';" $@'
#alias pa_appidtoolbox-rule-marker='php -r "require_once '"'"'appid-toolbox/rule-marker.php'"'"';" $@'


#DEVELOP
alias pa_ckp-exclude='php -r "require_once '"'"'utils/develop/checkpoint-exclude.php'"'"';" $@'

alias pa_csv-import='php -r "require_once '"'"'utils/develop/csv-import.php'"'"';" $@'


alias pa_ike='php -r "require_once '"'"'utils/develop/ike.php'"'"';" $@'


#license / software / commit-config / reset-config / get_user_info / sendGARP / software-remove / systemlog / traffic-log

alias pa_config-reset='php -r "require_once '"'"'utils/develop/reset-config.php'"'"';" $@'
alias pa_get-system-user-info='php -r "require_once '"'"'utils/develop/pan_get_user_info.php'"'"';" $@'
