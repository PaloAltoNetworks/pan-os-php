
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