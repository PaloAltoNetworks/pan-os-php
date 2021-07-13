
alias pa_migration-parser='php -r "require_once '"'"'parser/migration_parser.php'"'"';" $@'
alias pa_migration-discovery='php -r "require_once '"'"'parser/migration-discovery.php'"'"';" $@'
alias pa_panorama-2-fawkes='php -r "require_once '"'"'parser/panorama2fawkes.php'"'"';" $@'


alias pa_docker-migration-parser='docker run -v ${PWD}:/expedition-converter -it expedition-converter_php php /tools/Expedition-Converter/parser/migration_parser.php'


alias pa_rule-edit='php -r "require_once '"'"'utils/rules-edit.php'"'"';" $@'
alias pa_rule-merger='php -r "require_once '"'"'utils/rule-merger.php'"'"';" $@'
alias pa_rule-stats='php -r "require_once '"'"'utils/rules-stats.php'"'"';" $@'

alias pa_address-edit='php -r "require_once '"'"'utils/address-edit.php'"'"';" $@'
alias pa_address-merger='php -r "require_once '"'"'utils/address-merger.php'"'"';" $@'
alias pa_addressgroup-merger='php -r "require_once '"'"'utils/addressgroup-merger.php'"'"';" $@'

alias pa_service-edit='php -r "require_once '"'"'utils/service-edit.php'"'"';" $@'
alias pa_service-merger='php -r "require_once '"'"'utils/service-merger.php'"'"';" $@'
alias pa_servicegroup-merger='php -r "require_once '"'"'utils/servicegroup-merger.php'"'"';" $@'

alias pa_tag-edit='php -r "require_once '"'"'utils/tag-edit.php'"'"';" $@'
alias pa_tag-merger='php -r "require_once '"'"'utils/tag-merger.php'"'"';" $@'

alias pa_schedule-edit='php -r "require_once '"'"'utils/schedule-edit.php'"'"';" $@'
alias pa_application-edit='php -r "require_once '"'"'utils/application-edit.php'"'"';" $@'

alias pa_upload-config='php -r "require_once '"'"'utils/upload-config.php'"'"';" $@'
alias pa_override-finder='php -r "require_once '"'"'utils/override-finder.php'"'"';" $@'
alias pa_userid-mgr='php -r "require_once '"'"'utils/userid-mgr.php'"'"';" $@'
alias pa_register-ip-mgr='php -r "require_once '"'"'utils/register-ip-mgr.php'"'"';" $@'

alias pa_key-manager='php -r "require_once '"'"'utils/key-manager.php'"'"';" $@'

alias pa_ckp-exclude='php -r "require_once '"'"'utils/checkpoint-exclude.php'"'"';" $@'

alias pa_download-predefined='php -r "require_once '"'"'utils/download_predefined.php'"'"';" $@'
alias pa_diff='php -r "require_once '"'"'utils/pan-diff.php'"'"';" $@'
alias pa_config-size='php -r "require_once '"'"'utils/pan_config-size.php'"'"';" $@'
alias pa_panos-xml-issue-detector='php -r "require_once '"'"'utils/panos-xml-issue-detector.php'"'"';" $@'
alias pa_appid-enabler='php -r "require_once '"'"'utils/appid-enabler.php'"'"';" $@'

alias pa_xml-op-json='php -r "require_once '"'"'utils/panXML_op_JSON.php'"'"';" $@'

alias pa_appidtoolbox-report-generator='php -r "require_once '"'"'appid-toolbox/report-generator.php'"'"';" $@'
alias pa_appidtoolbox-rule-activation='php -r "require_once '"'"'appid-toolbox/rule-activation.php'"'"';" $@'
alias pa_appidtoolbox-rule-cleaner='php -r "require_once '"'"'appid-toolbox/rule-cleaner.php'"'"';" $@'
alias pa_appidtoolbox-rule-cloner='php -r "require_once '"'"'appid-toolbox/rule-cloner.php'"'"';" $@'
alias pa_appidtoolbox-rule-marker='php -r "require_once '"'"'appid-toolbox/rule-marker.php'"'"';" $@'


alias pa_securityprofile-edit='php -r "require_once '"'"'utils/securityprofile-edit.php'"'"';" $@'
alias pa_securityprofilegroup-edit='php -r "require_once '"'"'utils/securityprofilegroup-edit.php'"'"';" $@'

alias pa_vsys='php -r "require_once '"'"'utils/vsys-edit.php'"'"';" $@'

alias pa_device-edit='php -r "require_once '"'"'utils/device-edit.php'"'"';" $@'
alias pa_zone-edit='php -r "require_once '"'"'utils/zone-edit.php'"'"';" $@'
alias pa_interface-edit='php -r "require_once '"'"'utils/interface-edit.php'"'"';" $@'
alias pa_routing-edit='php -r "require_once '"'"'utils/routing-edit.php'"'"';" $@'
alias pa_vwire-edit='php -r "require_once '"'"'utils/vwire-edit.php'"'"';" $@'


alias pa_ike='php -r "require_once '"'"'utils/develop/ike.php'"'"';" $@'



alias pa_ssh-connector='php -r "require_once '"'"'utils/develop/ssh_connector.php'"'"';" $@'

alias pa_bpa-generator='php -r "require_once '"'"'utils/bpa-generator.php'"'"';" $@'
