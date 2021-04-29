<?php

// <editor-fold desc=" ***** Routing filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['routing']['name']['operators']['eq'] = Array(
    'Function' => function(RoutingRQueryContext $context )
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