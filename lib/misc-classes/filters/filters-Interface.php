<?php

// <editor-fold desc=" ***** Interface filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['interface']['name']['operators']['eq'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
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