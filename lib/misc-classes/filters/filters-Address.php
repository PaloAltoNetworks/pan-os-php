<?php

// <editor-fold desc=" ***** Address filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['address']['refcount']['operators']['>,<,=,!'] = array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.unused'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.unused.recursive'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        return $object->objectIsUnusedRecursive();

    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.group'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->isGroup() == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.region'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->isRegion() == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.dynamic'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( $context->object->isGroup() )
            return $context->object->isDynamic() == TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.tmp'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->isTmpAddr() == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-range'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() )
            return $context->object->isType_ipRange() == TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-netmask'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() )
            return $context->object->isType_ipNetmask() == TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.fqdn'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() )
            return $context->object->isType_FQDN() == TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-wildcard'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() )
            return $context->object->isType_ipWildcard() == TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ipv4'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            if( $object->isType_FQDN() )
            {
                #PH::print_stdout( "SKIPPED: object is FQDN");
                return false;
            }

            if( strpos( $object->value(), ":") !== false )
                return false;

            $addr_value = $object->value();

            if( $object->isType_ipRange() )
            {
                $ip_range = explode( "-", $object->value() );
                $addr_value = $ip_range[0];
            }

            if( substr_count( $addr_value, '.' ) == 3 )
            {
                #check that all four octects are ipv4
                $tmp_addr_value = explode( "/", $addr_value );
                $tmp_addr_array =  explode( ".", $tmp_addr_value[0]);

                foreach( $tmp_addr_array as $occtet )
                {
                    if( $occtet >= 0 && $occtet <= 255 )
                        continue;
                    else
                        derr( "this is not a valid IPv4 address [".$addr_value."]" );
                }

                return true;
            }
        }
        else #howto check if group is IPv4 only
        {
            #PH::print_stdout( "object: ".$object->name()." is group. not supported yet" );
            return false;
        }


    },
    'arg' => false
);

RQuery::$defaultFilters['address']['object']['operators']['is.ipv6'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            if( $object->isType_FQDN() )
            {
                #PH::print_stdout( "SKIPPED: object is FQDN");
                return false;
            }

            $addr_value = $object->value();

            if( $object->isType_ipRange() )
            {
                $ip_range = explode( "-", $object->value() );
                $addr_value = $ip_range[0];
            }

            $ip_range = explode( "/", $addr_value );
            $addr_value = $ip_range[0];

            #if( strpos( $addr_value, ":") !== false )
            #if (preg_match("/^[0-9a-f:]+$/",$addr_value)) // IPv6 section
            if(filter_var($addr_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            {
                #check that ipv6
                return true;
            }
        }
        else #howto check if group is IPv6 only
        {
            #PH::print_stdout( "object: ".$object->name()." is group. not supported yet" );
            return false;
        }


    },
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['overrides.upper.level'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $location = PH::findLocationObjectOrDie($context->object);
        if( $location->isFirewall() || $location->isPanorama() || $location->isVirtualSystem() )
            return FALSE;

        $store = $context->object->owner;

        if( isset($store->parentCentralStore) && $store->parentCentralStore !== null )
        {
            $store = $store->parentCentralStore;
            $find = $store->find($context->object->name());

            return $find !== null;
        }
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['overriden.at.lower.level'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $location = PH::findLocationObjectOrDie($object);
        if( $location->isFirewall() || $location->isVirtualSystem() )
            return FALSE;

        if( $location->isPanorama() )
            $locations = $location->deviceGroups;
        else
        {
            $locations = $location->childDeviceGroups(TRUE);
        }

        foreach( $locations as $deviceGroup )
        {
            if( $deviceGroup->addressStore->find($object->name(), null, FALSE) !== null )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.member.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $addressGroup = $context->object->owner->find($context->value);

        if( $addressGroup === null )
            return FALSE;

        if( $addressGroup->has($context->object) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.recursive.member.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $addressGroup = $context->object->owner->find($context->value);

        if( $addressGroup === null )
            return FALSE;

        if( !$context->object->isGroup() )
        {
            if( $addressGroup->hasObjectRecursive($context->object) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp-in-grp-test-1)',
        'input' => 'input/panorama-8.0-merger.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['eq'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% new test 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['eq.nocase'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% new test 2)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['contains'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% -)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        if( strpos($value, '$$value$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() )
                $replace = str_replace(array('.', '/'), array('\.', '\/'), $object->value());

            $value = str_replace('$$value$$', $replace, $value);

        }
        if( strpos($value, '$$ipv4$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';

            $replace = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';
            $value = str_replace('$$ipv4$$', $replace, $value);
        }
        if( strpos($value, '$$ipv6$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';

            $replace = '[0-9a-f]{1,4}_([0-9a-f]{0,4}_){1,6}[0-9a-f]{1,4}';
            $value = str_replace('$$ipv6$$', $replace, $value);
        }
        if( strpos($value, '$$value.no-netmask$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && $object->isType_ipNetmask() )
                $replace = str_replace('.', '\.', $object->getNetworkValue());

            $value = str_replace('$$value.no-netmask$$', $replace, $value);
        }
        if( strpos($value, '$$netmask$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && $object->isType_ipNetmask() )
                $replace = $object->getNetworkMask();

            $value = str_replace('$$netmask$$', $replace, $value);
        }
        if( strpos($value, '$$netmask.blank32$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && $object->isType_ipNetmask() )
            {
                $netmask = $object->getNetworkMask();
                if( $netmask != 32 )
                    $replace = $object->getNetworkMask();
            }

            $value = str_replace('$$netmask.blank32$$', $replace, $value);
        }

        if( strlen($value) == 0 )
            return FALSE;
        if( strpos($value, '//') !== FALSE )
            return FALSE;

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'possible variables to bring in as argument: $$value$$ / $$ipv4$$ / $$ipv6$$ / $$value.no-netmask$$ / $$netmask$$ / $$netmask.blank32$$',
    'ci' => array(
        'fString' => '(%PROP% /n-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['is.in.file'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        return isset($list[$object->name()]);
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['address']['netmask']['operators']['>,<,=,!'] = array(
    'eval' => '!$object->isGroup() && $object->isType_ipNetmask() && $object->getNetworkMask() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['members.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->isGroup() && !\$object->isDynamic() && \$object->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->tags->hasTag($context->value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has.nocase'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->tags->hasTag($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% test)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has.regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        foreach( $context->object->tags->tags() as $tag )
        {
            $matching = preg_match($context->value, $tag->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /grp/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $owner = $context->object->owner->owner;
        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }
        if( strtolower($context->value) == strtolower($owner->name()) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% shared)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $name = $context->object->getLocationString();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /shared/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['is.child.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $address_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "AddressStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:");
            PH::print_stdout( " - shared");
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout("");
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($address_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $address_location )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is child the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['is.parent.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $address_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "AddressStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
        {
            PH::print_stdout( "ERROR: filter location is.child.of is not working against a firewall configuration");
            return FALSE;
        }

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:");
            PH::print_stdout( " - shared");
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout("");
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($address_location) )
            return TRUE;

        if( $address_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $address_location )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is parent the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocation']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocation();

        #print_r( $reflocation_array );


        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }
        if( $owner->isPanorama() )
        {
            $DG = $owner->findDeviceGroup($context->value);
            if( $DG == null )
            {
                $test = new UTIL("custom", array(), 0, "");
                $test->configType = "panorama";
                $test->locationNotFound($context->value, null, $owner);
            }
        }


        foreach( $reflocation_array as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                return TRUE;
        }


        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocation']['operators']['is.only'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $owner = $context->object->owner->owner;
        $reflocations = $context->object->getReferencesLocation();

        /*
                $DG = $owner->findDeviceGroup( $context->value );
                if( $DG == null )
                {
                    $test = new UTIL( "custom", array(), 0, "" );
                    $test->locationNotFound( $context->value, null, $owner );
                }
        */

        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }

        $return = FALSE;
        foreach( $reflocations as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                $return = TRUE;
        }

        if( count($reflocations) == 1 && $return )
            return TRUE;
        else
            return FALSE;

    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% rulestore )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reftype']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesTypeValidation($value);

        $reftype = $context->object->getReferencesType();

        if( array_key_exists($value, $reftype) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refobjectname']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $reference_array = $object->getReferences();

        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) == "AddressGroup" && $refobject->name() == $context->value )
                return TRUE;
        }


        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches refobjectname',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refobjectname']['operators']['is.only'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reference_array = $object->getReferences();

        $return = FALSE;
        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) != "AddressGroup" )
                $return = FALSE;

            if( get_class( $refobject ) == "AddressGroup" && $refobject->name() == $context->value )
                $return = TRUE;

        }

        return $return;

    },
    'arg' => TRUE,
    'help' => 'returns TRUE if RUE if object name matches only refobjectname',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refobjectname']['operators']['is.recursive'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $reference_array = $object->getReferencesRecursive();

        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) == "AddressGroup" && $refobject->name() == $context->value )
                return TRUE;
        }


        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches refobjectname',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['string.eq'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( $object->isAddress() )
        {
            if( $object->type() == 'ip-range' || $object->type() == 'ip-netmask' )
            {
                if( $object->value() == $context->value )
                    return TRUE;
            }
        }
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.match.exact'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $values = explode(',', $context->value);


        if( !isset($context->cachedValueMapping) )
        {
            $mapping = new IP4Map();

            $count = 0;
            foreach( $values as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                    derr("empty network/IP name provided for argument #$count");
                $mapping->addMap(IP4Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $object->getIP4Mapping()->equals($mapping);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.included-in'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isAddress() && ( $object->isTmpAddr() || $object->isType_FQDN() ) )
            return null;

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;

        $values = explode(',', $context->value);
        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $object->getIP4Mapping()->includedInOtherMap($mapping) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isAddress() )
        {
            if( $object->isType_FQDN()  )
                return null;
            elseif( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;

        $values = explode(',', $context->value);
        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $mapping->includedInOtherMap($object->getIP4Mapping()) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full-or-partial'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isAddress() )
        {
            if( $object->isType_FQDN()  )
                return null;
            elseif( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;

        $values = explode(',', $context->value);
        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $mapping->includedInOtherMap($object->getIP4Mapping()) != 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['string.regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $regex = $context->value;

        if( $object->isGroup() )
            return null;

        if( $object->isAddress() )
        {
            if( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isType_ipNetmask() || $object->isType_ipRange() || $object->isType_FQDN() )
        {
            if( $object->isType_ipRange() || $object->isType_FQDN() )
            {
                $addr_value = $object->value();
            }
            else
                $addr_value = $object->getNetworkValue();

            $matching = preg_match($context->value, $addr_value);
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;

        }

        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['address']['value']['operators']['is.included-in.name'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isGroup()  )
        {
            return null;
        }


        if( $object->isType_ipNetmask() || $object->isType_ipRange() || $object->isType_FQDN() || $object->isType_TMP() )
        {
            $name = $object->name();
            if(  $object->isType_ipRange())
            {
                $addr_value = $object->value();
                $addr_value = explode( '-', $addr_value);
                $addr_value = $addr_value[0];
            }
            elseif( $object->isType_FQDN() || $object->isType_TMP() )
                $addr_value = $object->value();
            else
                $addr_value = $object->getNetworkValue();

            if( !empty( $addr_value ) && strpos(strtolower($name), strtolower($addr_value) ) !== FALSE )
            {
                $tmpPos = strpos( $name, $addr_value );
                $tmpPos += strlen( $addr_value);
                $substr = substr($name, $tmpPos, 1); //returns b
                if( is_numeric( $substr ) )
                    return FALSE;

                return true;
            }
        }

        return false;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['value']['operators']['is.in.file'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as  $line)
            {
                $line = trim($line);
                if(strlen($line) == 0)
                    continue;
                $list[$line] = true;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        if( !$object->isGroup() )
        {
            //TODO: if not IPv4 -  return false
            if( $object->getNetworkMask() == '32' )
                $addr_value = $object->getNetworkValue();
            else
                $addr_value = $object->value();

            return isset($list[ $addr_value ]);
            //TODO: if IPv6 check
        }
        else
            return false;

    },
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['has.wrong.network'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( !$object->isType_ipNetmask() )
            return null;

        $value = $object->getNetworkValue();
        $netmask = $object->getNetworkMask();

        if( $netmask == '32' )
            return null;

        $calc_network = CIDR::cidr2network( $value, $netmask );

        if( $value != $calc_network )
            return true;

        return null;
    },
    'arg' => false
);

RQuery::$defaultFilters['address']['description']['operators']['regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        $matching = preg_match($value, $object->description());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['description']['operators']['is.empty'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($object->description()) == 0 )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>