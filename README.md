pan-os-php
================


PAN-OS-PHP is a PHP library aimed at making PANOS config changes easy (and XML free ;), 
maintainable and allowing complex scenarios like rule merging, unused object tracking,
conversion of checkpoint exclusion groups, massive rule editing, AppID conversion … . 
It will work seamlessly on PAN-OS local xml config file or PAN-OS API.

**Homepage** : download latest sources on [GitHub](https://github.com/PaloAltoNetworks/pan-os-php).
Windows package with PHP binaries here: [Git PAN-OS-PHP Windows Package](https://github.com/PaloAltoNetworks/pan-os-php-windows-package)

**Requirements** :
 - PHP 7.4 with curl module [ tested with PHP 5.5 / 5.6 / 7.3 / 7.4 / 8.0 / 8.1 ]
 - php-curl php-dom php-mbstring php-bcmath

**Usage**: include the file lib/pan_php_framework.php in your own script to load the necessary classes.
```php
    require_once "lib/pan_php_framework.php";
```

File tree:
* **/lib/** contains library files source code
* **/utils/** contains ready to run scripts, more information in [utils/README](/utils/README.md)
* **/doc/index.html**  has all classes documentations
* **/example-xxx.php** are examples about using this library

SUPPORT
============
This tool is provided "AS IS" and is community supported.
Please also check the [LICENSE](https://github.com/PaloAltoNetworks/pan-os-php/blob/main/LICENSE) file.

For help, it is always possible to open a GIT issue for this repository, or reaching out to [Palo Alto Networks LIVE community page](https://live.paloaltonetworks.com/t5/api-articles/pan-os-php-scripting-library-and-utilities/ta-p/404396).

Usage
============

With less than 20 lines of code, you should be able to solve most of your needs. Brief overview:

Available arguments for your script:
- in=file.xml or in=api://192.168.10.1
- out=file_output.xml [not needed if connection is API]
- location=vsys1 [default if not used; FW->'vsys1' / Panorama->'shared' ]

Loading a config from a file / API candidate config for PAN-OS Firewall or Panorama:
```php
    require_once "lib/pan_php_framework.php";    
    require_once "utils/lib/UTIL.php";
    
    $util = new UTIL("custom", $argv, __FILE__);
    $util->utilInit();
    
    $util->load_config();
    $util->location_filter();

    $pan = $util->pan;    
```

Delete unused objects from a config :
```php
    foreach($pan->addressStore->addressObjects() as $object )
      if( $object->countReferences() == 0 )
        $pan->addressStore->remove($object);
```

Want to know where an object is used ?
```php
    $object = $pan->addressStore->find('H-WebServer4');
    foreach( $object->getReferences() as $ref )
       PH::print_stdout( $ref->toString() );
```

Replace that object by another one :
```php
    $object->replaceMeGlobally($anotherObject);
```

Want to add security profile group 'Block-Forward-Critical-High' in rules which have destination zone 'External' and
 source zone 'DMZ'?
```php
    foreach( $pan->securityRules->rules() as $rule )
       if( $rule->from->has('DMZ') && $rule->to->has('External') )
           $rule->setSecurityProfileGroup('Block-Forward-Critical-High');
```

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



Docker build
============

There are Dockerfiles available with OS: Ubuntu20/22 and CentOS 7/8

* **MacOS** : [run on MacOS terminal]
	```bash
	cd [pan-os-php Root folder]
	docker build -t pan-os-php -f docker/Dockerfile .
	cd [go to the Folder you like to share with the Container]
	docker run -v ${PWD}:/share -it pan-os-php
	```

* **WINDOWS** : [run on Windows terminal]
	```bash
	cd [pan-os-php Root folder]
	docker build -t pan-os-php -f docker/Dockerfile .
	cd [go to the Folder you like to share with the Container]
	docker run -v %CD%:/share -it pan-os-php
	```

Docker PAN-OS-PHP API and UI
============
final production Container:
   ```bash
    cd [pan-os-php Root folder]
    docker build -t pan-os-php:latest -f docker/Dockerfile-API .
    docker run -d -p 8082:80 pan-os-php:latest
   ```
local Development Container:
   ```bash
   docker run -d -p 8082:80 --mount type=bind,source="[absolute_ROOTFOLDER]/pan-os-php",target=/var/www/html -v [absolute_ROOTFOLDER]/pan-os-php/var/docker/uploads.ini:/usr/local/etc/php/conf.d/uploads.ini php:apache
   ```

PAN-OS-PHP UI is available at: (which triggers next PAN-OS-PHP API)
   ```bash
   http://localhost:8082/utils/develop/ui
   ```
To get it working on your own PAN-OS Firewall / Panorama config files,
please upload your config files via PAN-OS-PHP UI (URL above)

It is also now possible to start using it with the previous uploaded file via PAN-OS-PHP API:
http://localhost:8082/utils/develop/api/v1/tool.php/address?in=YOUR_CONFIG_FILE.xml


The PAN-OS-PHP API is right now under development, but please feel free to try it out:
   ```bash
   http://localhost:8082/utils/develop/api/v1/tool.php
   ```

The following "RESTAPI" routes are available:
- /stats


- /address
- /service
- /tag
- /rule
- /securityprofile
- /securityprofilegroup
- /schedule

- /applicaton
- /threat

- /device


- /zone
- /interface
- /routing
- /virtualwire

- /key-manager

- /address-merger
- /addressgroup-merger
- /service-merger
- /servicegroup-merger
- /tag-merger
- /rule-merger

- /override-finder
- /diff
- /upload
- /xml-issue
- /appid-enabler
- /config-size
- /download-predefined
- /register-ip-mgr
- /userid-mgr
- /xml-op-json
- /bpa-generator

PAN-OS-PHP API is NOT working yet with PAN-OS XML API but it is possible to run it against PAN-OS FW and Panorama offline configuration files, and manipulate in the same way as on PAN-OS-PHP ClI:
   ```bash
   ClI: pan-os-php type=address help
   API: http://localhost:8082/utils/develop/api/v1/tool.php/address?help
   ```
   ```bash
   CLI: pan-os-php type=address listactions
   API: http://localhost:8082/utils/develop/api/v1/tool.php/address?listactions
   ```
