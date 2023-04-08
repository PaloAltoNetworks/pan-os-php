<?php

// <editor-fold desc=" ***** Zone filters *****" defaultstate="collapsed" >

/*
RQuery::$defaultFilters['device']['name']['operators']['eq.nocase'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['device']['name']['operators']['contains'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
*/
RQuery::$defaultFilters['device']['name']['operators']['eq'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['device']['name']['operators']['regex'] = array(
    'Function' => function (DeviceRQueryContext $context) {
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
        'fString' => '(%PROP% /-group/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['device']['name']['operators']['is.in.file'] = array(
    'Function' => function (DeviceRQueryContext $context) {
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

RQuery::$defaultFilters['device']['name']['operators']['is.child.of'] = array(
    'Function' => function (DeviceRQueryContext $context) {

        $object = $context->object;
        $value = $context->value;

        $sub = $context->object->owner;
        while( get_class($sub) == "RuleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) !== "PanoramaConf" )
            derr("filter location is.child.of is only working against a panorama configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name()  );
            }
            PH::print_stdout();
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($object->name()) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $object->name() )
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

RQuery::$defaultFilters['device']['templatestack']['operators']['has.member'] = array(
    'Function' => function (DeviceRQueryContext $context) {

        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "TemplateStack" )
            return false;

        $used_templates = $context->object->templates;
        foreach( $used_templates as $template )
        {
            if( $template->name() == $context->value )
                return true;
        }
        return false;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['template']['operators']['has-multi-vsys'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "Template" )
            return false;

        $vsyses = $object->deviceConfiguration->getVirtualSystems();
        if( count($vsyses) > 1 )
            return TRUE;

        return false;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['manageddevice']['operators']['with-no-dg'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var ManagedDevice $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "ManagedDevice" )
            return false;

        $DG = $object->getDeviceGroup();
        if( $DG === "" )
            return TRUE;

        return false;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['devicegroup']['operators']['has.vsys'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var DeviceGroup $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "DeviceGroup" )
            return false;

        $DGdevices = $object->getDevicesInGroup();
        foreach( $DGdevices as $key => $device )
        {
            if( isset($device['vsyslist']) )
            {
                if( isset( $device['vsyslist'][$context->value] ) )
                    return TRUE;
                else
                    return FALSE;
            }
            else
            {
                if( $context->value == "vsys1")
                    return TRUE;
                else
                    return FALSE;
            }
        }

        return null;
    },
    'arg' => True,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);


// </editor-fold>