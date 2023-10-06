<?php

// <editor-fold desc=" ***** Static Route filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['static-route']['name']['operators']['eq'] = Array(
    'Function' => function(StaticRouteRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['static-route']['virtualrouter-name']['operators']['eq'] = Array(
    'Function' => function(StaticRouteRQueryContext $context )
    {
        return $context->object->owner->name() == $context->value;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['static-route']['nexthop-ip']['operators']['is.set'] = Array(
    'Function' => function(StaticRouteRQueryContext $context )
    {
        return $context->object->nexthopIP() !== null;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['static-route']['nexthop-vr']['operators']['is.set'] = Array(
    'Function' => function(StaticRouteRQueryContext $context )
    {
        return $context->object->nexthopVR() !== null;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['static-route']['nexthop-interface']['operators']['is.set'] = Array(
    'Function' => function(StaticRouteRQueryContext $context )
    {
        return $context->object->nexthopInterface() !== null;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['static-route']['destination']['operators']['ip4.includes-full'] = array(
    'Function' => function (StaticRouteRQueryContext $context) {
        $object = $context->object;


        if( $context->value === "RFC1918" )
        {
            $values = array();
            $values[] = "10.0.0.0/8";
            $values[] = "172.16.0.0/12";
            $values[] = "192.168.0.0/16";
        }
        else
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

        if( $mapping->includedInOtherMap($object->destinationIP4Map()) == 1 )
            return true;

        return false;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>