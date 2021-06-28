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
RQuery::$defaultFilters['device']['templatestack']['operators']['has.member'] = array(
    'Function' => function (DeviceRQueryContext $context) {

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

// </editor-fold>