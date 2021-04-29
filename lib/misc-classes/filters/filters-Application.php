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


// </editor-fold>