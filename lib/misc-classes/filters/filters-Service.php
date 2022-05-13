<?php

// <editor-fold desc=" ***** Service filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['service']['refcount']['operators']['>,<,=,!'] = array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['object']['operators']['is.unused'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['object']['operators']['is.unused.recursive'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;

        return $object->objectIsUnusedRecursive();

    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['object']['operators']['is.member.of'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $serviceGroup = $context->object->owner->find($context->value);

        if( $serviceGroup === null )
            return FALSE;

        if( $serviceGroup->hasObjectRecursive($context->object) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE
);
RQuery::$defaultFilters['service']['object']['operators']['is.recursive.member.of'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $serviceGroup = $context->object->owner->find($context->value);

        if( $serviceGroup === null )
            return FALSE;

        if( !$context->object->isGroup() )
        {
            if( $serviceGroup->hasObjectRecursive($context->object) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp-in-grp-srv)',
        'input' => 'input/panorama-8.0-merger.xml'
    )
);
RQuery::$defaultFilters['service']['name']['operators']['is.in.file'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
RQuery::$defaultFilters['service']['object']['operators']['is.group'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return $context->object->isGroup();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['object']['operators']['is.tcp'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        return $context->object->isTcp();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['object']['operators']['is.udp'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        return $context->object->isUdp();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['object']['operators']['is.tmp'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return $context->object->isTmpSrv();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['object']['operators']['has.srcport'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        if( !$context->object->isService() )
            return FALSE;

        if( $context->object->getSourcePort() !== "" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['service']['name']['operators']['eq'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% tcp-80)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['name']['operators']['eq.nocase'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% udp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['name']['operators']['contains'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% udp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['name']['operators']['regex'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /tcp/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['members.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->isGroup() && \$object->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['tag']['operators']['has'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return $context->object->tags->hasTag($context->value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['service']['tag']['operators']['has.nocase'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        return $context->object->tags->hasTag($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% test )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['tag']['operators']['has.regex'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
RQuery::$defaultFilters['service']['tag.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['description']['operators']['regex'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( !$object->isService() )
            return null;

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
RQuery::$defaultFilters['service']['description']['operators']['is.empty'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( !$object->isService() )
            return null;


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
RQuery::$defaultFilters['service']['location']['operators']['is'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
RQuery::$defaultFilters['service']['location']['operators']['regex'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
RQuery::$defaultFilters['service']['location']['operators']['is.child.of'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $service_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "ServiceStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout();
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($service_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $service_location )
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
RQuery::$defaultFilters['service']['location']['operators']['is.parent.of'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $service_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "ServiceStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
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
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout( "\n" );
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($service_location) )
            return TRUE;

        if( $service_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $service_location )
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
RQuery::$defaultFilters['service']['reflocation']['operators']['is'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocation();

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
                $test = new UTIL("custom", array(), 0,"");
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
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['reflocation']['operators']['is.only'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $owner = $context->object->owner->owner;
        $reflocations = $context->object->getReferencesLocation();

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
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['refstore']['operators']['is'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
RQuery::$defaultFilters['service']['reftype']['operators']['is'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
RQuery::$defaultFilters['service']['value']['operators']['string.eq'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( $object->isService() )
        {
            if( $object->getDestPort() == $context->value )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 80)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['value']['operators']['>,<,=,!'] = array(
    'eval' => '!$object->isGroup() && $object->getDestPort() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['value']['operators']['is.single.port'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        if( strpos($object->getDestPort(), ",") !== FALSE )
            return FALSE;

        if( strpos($object->getDestPort(), "-") !== FALSE )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['value']['operators']['is.port.range'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        if( strpos($object->getDestPort(), "-") !== FALSE )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['value']['operators']['is.comma.separated'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        if( strpos($object->getDestPort(), ",") !== FALSE )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['value']['operators']['regex'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;


        $matching = preg_match($value, $object->getDestPort());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /tcp/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

###########
RQuery::$defaultFilters['service']['sourceport.value']['operators']['string.eq'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( $object->isService() )
        {
            if( $object->getSourcePort() == $context->value )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 80)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['sourceport.value']['operators']['>,<,=,!'] = array(
    'eval' => '!$object->isGroup() && $object->getSourcePort() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['sourceport.value']['operators']['is.single.port'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        if( strpos($object->getSourcePort(), ",") !== FALSE )
            return FALSE;

        if( strpos($object->getSourcePort(), "-") !== FALSE )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['sourceport.value']['operators']['is.port.range'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        if( strpos($object->getSourcePort(), "-") !== FALSE )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['sourceport.value']['operators']['is.comma.separated'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;

        if( strpos($object->getSourcePort(), ",") !== FALSE )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['sourceport.value']['operators']['regex'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->isTmpSrv() )
            return FALSE;

        if( $object->isGroup() )
            return FALSE;


        $matching = preg_match($value, $object->getSourcePort());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /tcp/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
#################
RQuery::$defaultFilters['service']['value.length']['operators']['>,<,=,!'] = array(
    'eval' => '!$object->isGroup() && strlen($object->getDestPort()) !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['service']['object']['operators']['overrides.upper.level'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
RQuery::$defaultFilters['service']['object']['operators']['overriden.at.lower.level'] = array(
    'Function' => function (ServiceRQueryContext $context) {
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
            if( $deviceGroup->serviceStore->find($object->name(), null, FALSE) !== null )
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
RQuery::$defaultFilters['service']['timeout']['operators']['is.set'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( !$object->isService() )
            return null;


        if( $object->getTimeout() != '' )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['service']['timeout.value']['operators']['>,<,=,!'] = array(
    'eval' => '!$object->isGroup() && $object->getTimeout() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['service']['port.count']['operators']['>,<,=,!'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $counter = $context->value;
        $service = $context->object;

        $calculatedCounter = $context->ServiceCount( $service, "both");

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $calculatedCounter." ".$operator." ".$counter;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['port.tcp.count']['operators']['>,<,=,!'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $counter = $context->value;
        $service = $context->object;

        $calculatedCounter = $context->ServiceCount( $service, "tcp");

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $calculatedCounter." ".$operator." ".$counter;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['service']['port.udp.count']['operators']['>,<,=,!'] = array(
    'Function' => function (ServiceRQueryContext $context) {
        $counter = $context->value;
        $service = $context->object;

        $calculatedCounter = $context->ServiceCount( $service, "udp");

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $calculatedCounter." ".$operator." ".$counter;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>