<?php

// <editor-fold desc=" ***** VirtualWire filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['virtualwire']['name']['operators']['eq'] = Array(
    'Function' => function(VirtualWireRQueryContext $context )
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