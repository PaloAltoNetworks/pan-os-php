<?php

// <editor-fold desc=" ***** Application filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['app']['name']['operators']['eq'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['app']['characteristic']['operators']['has'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        $app = $context->object;

        if( $app->isContainer() )
            return null;

        $sanitizedValue = strtolower($context->value);
        if( $app->_characteristics[$sanitizedValue] === TRUE )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% evasive) ',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['application']['name']['operators']['eq'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['application']['characteristic']['operators']['has'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        $app = $context->object;

        if( $app->isContainer() )
            return null;

        $sanitizedValue = strtolower($context->value);
        if( $app->_characteristics[$sanitizedValue] === TRUE )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% evasive) ',
        'input' => 'input/panorama-8.0.xml'
    )
);


RQuery::$defaultFilters['application']['object']['operators']['is.predefined'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->type == "predefined" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['object']['operators']['is.application-group'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->type == "application-group" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['object']['operators']['is.application-filter'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->type == "application-filter" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['object']['operators']['is.application-custom'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->type == "application-custom" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['object']['operators']['is.tmp'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->type == "tmp" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['tcp_secure']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->tcp_secure) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['udp_secure']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->udp_secure) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['subcategory']['operators']['is.ip-protocol'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->subCategory == "ip-protocol" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['subcategory']['operators']['eq'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->subCategory == $context->value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['type']['operators']['eq'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->type == $context->value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['tcp']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->tcp) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['udp']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->udp) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['timeout']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->udp) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['timeout']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->timeout) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['tcp_timeout']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->tcp_timeout) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['tcp_half_closed_timeout']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->tcp_half_closed_timeout) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['tcp_time_wait_timeout']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->tcp_time_wait_timeout) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['udp_timeout']['operators']['is.set'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->udp_timeout) )
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