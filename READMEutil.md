UTIL
============

**You hate scripting ?** 

 - pan-os-php type=rule / type=address / type=service / type=tag
 [utils/doc](/utils/doc/help.html)

Utility script 'pan-os-php type=rule' is a swiss knife to edit rules and takes advantage of PAN-OS-PHP
 library from a single CLI query, ie :

Do you want to enable log at start for rule going to DMZ zone and that has only object group 'Webfarms' as a destination ?

    pan-os-php type=rule in=api://fw1.mycompany.com actions=logStart-Enable 'filter=(to has dmz) and (dst has.only Webfarms)'

You are not sure about your filter and want to see rules before making changes ? Use action 'display' :

    pan-os-php type=rule  in=api://fw1.mycompany.com actions=display 'filter=(to has dmz) and (dst has.only Webfarms)'

Change all rules using Application + Any service to application default ?

    pan-os-php type=rule in=api://fw1.mycompany.com actions=service-Set-AppDefault 'filter=!(app is.any) and (service is.any)'

Move post-SecurityRules with source zone 'dmz' or source object 'Admin-networks' to pre-Security rule ?

    pan-os-php type=rule  in=api://panorama.mycompany.com actions=invertPreAndPost 'filter=((from has dmz) or (source has Admin-networks) and (rule is.postrule))'

Want to know what actions are supported ?

    pan-os-php type=rule listActions
    pan-os-php type=rule listFilters

**UTIL plugin** 

The UTIL scripts rules-edit/address-edit/service-edit/tag-edit can be easily and flexible extend by writing your own plugin:

- pan-os-php type=rule actions plugin example:
```php
    RuleCallContext::$supportedActions[] = Array(
        'name' => 'schedule_remove_update_desc',
        'MainFunction' => function(RuleCallContext $context)
        {
            /*
             * @var securityRule $rule
             */
            $rule = $context->object;
    
            if( !$rule->isSecurityRule() )
                return false;
            if(  $rule->schedule() == null )
                return false;
    
            $schedule_name = $rule->schedule();
            $rule->removeSchedule();
            $old_desc = $rule->description();
            $rule->setDescription( $old_desc." | remove schedule: ".$schedule_name );
    
            if( $context->isAPI )
                $rule->API_sync();
        }
    );
```

- pan-os-php type=rule filter plugin example:
```php
RQuery::$defaultFilters['rule']['description']['operators']['is.geq'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;

        return strlen($rule->description() )  >= $context->value;
    },
    'arg' => true
    )
);
```

- plugin usage from above for rule:

    rules-edit.php  in=api://panorama.mycompany.com loadplugin=your_plugin_file.php ['actions=YOUR_PLUGIN_ACTION_NAME'] ['filter=(YOUR_PLUGIN_FILTER_NAME)']

**UTIL usage via PAN-OS XML API** 
- PAN-OS API-KEYs are stored automatically at file: '.panconfkeystore' in your Systems User folder at the first time using a script with connection type API
- or you can manage your API-KEY store with UTIL script pan-os-php type=key-manager:
```php
    pan-os-php type=key-manager add=MGMT-IP
    pan-os-php type=key-manager delete=MGMT-IP
```


**Available UTIL scripts, provided by Alias:**
---
These UTIL scripts can help to manipulate/improve PAN-OS config files or help automating the daily work. 
- **pan-os-php type=**
  - address
  - address-merger
  - addressgroup-merger
  - appid-enabler
  - application
  - bpa-generator
  - config-size
  - device
  - diff
  - download-predefined
  - interface
  - key-manager
  - override-finder
  - register-ip-mgr
  - routing
  - rule
  - rule-merger
  - schedule
  - securityprofile
  - securityprofilegroup
  - service
  - service-merger
  - servicegroup-merger
  - stats
  - tag
  - tag-merger
  - threat
  - upload
  - userid-mgr
  - virtualwire
  - xml-issue
  - xml-op-json
  - zone

APP-ID ToolBox
---
These script are available since 2016 and were the first automatic Palo Alto Networks APP-id migration tools.
- pa_appidtoolbox-report-generator
- pa_appidtoolbox-rule-activation
- pa_appidtoolbox-rule-cleaner
- pa_appidtoolbox-rule-cloner
- pa_appidtoolbox-rule-marker

UTIL scripts under Development
---
The scripts under Development contain complete variable usage. From downloading software and license to remove old software on firewall devices.
But also parts for future automation like system-log or traffic-log are available.
Please remind yourself about the additional argument 'shadow-json', to display the output in JSON format instead of human text readable format.

- pa_ckp-exclude
- pa_ike
- pa_ssh-connector
- pa_license
- pa_software-preparation
- pa_software-downloader
- pa_config-commit
- pa_config-reset
- pa_get_system-user-info
- pa_software-remove
- pa_system-log
- pa_traffic-log

[Documentation](utils/doc/software-download.md) for air gap usage of pa_license / pa_software-downloader script