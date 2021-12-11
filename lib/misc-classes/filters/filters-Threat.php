<?php

// <editor-fold desc=" ***** Threat filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['threat']['name']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['threatname']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->threatname() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['severity']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->severity() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['default-action']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        if( $context->value == 'null' )
            return $context->object->defaultAction() == null;
        else
            return $context->object->defaultAction() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['category']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
            return $context->object->category() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

// </editor-fold>