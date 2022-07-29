<?php

// <editor-fold desc=" ***** DHCP filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['dhcp']['name']['operators']['eq'] = Array(
    'Function' => function(DHCPRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);



// </editor-fold>