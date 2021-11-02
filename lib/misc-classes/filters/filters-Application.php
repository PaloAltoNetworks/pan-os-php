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

//Todo: introduce filter
//      app-id is.disabled

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
RQuery::$defaultFilters['application']['name']['operators']['regex'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        /*
        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }*/

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /tcp/)',
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
        if( $context->object->isPredefined() )
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
        if( $context->object->isApplicationGroup() )
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
        if( $context->object->isApplicationFilter() )
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
        if( $context->object->isApplicationCustom() )
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
        if( $context->object->isTmp() )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['object']['operators']['is.container'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( $context->object->isContainer() )
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
RQuery::$defaultFilters['application']['tcp']['operators']['has'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->tcp) )
        {
            foreach( $context->object->tcp as &$port )
            {
                if( $port[0] == "single" )
                    if( isset( $port[1] ) && $port[1] == $context->value )
                        return TRUE;
                    elseif( $port[0] == "range" )
                    {
                        //range missing
                    }
            }
        }

        if( isset( $context->object->tcp_secure) )
        {
            foreach( $context->object->tcp_secure as &$port )
            {
                if( $port[0] == "single" )
                    if( isset( $port[1] ) && $port[1] == $context->value )
                        return TRUE;
                    elseif( $port[0] == "range" )
                    {
                        //range missing
                    }
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
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
RQuery::$defaultFilters['application']['udp']['operators']['has'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( isset( $context->object->udp) )
        {
            foreach( $context->object->udp as &$port )
            {
                if( $port[0] == "single" )
                    if( isset( $port[1] ) && $port[1] == $context->value )
                        return TRUE;
                elseif( $port[0] == "range" )
                {
                    //range missing
                }
            }
        }

        if( isset( $context->object->udp_secure) )
        {
            foreach( $context->object->udp_secure as &$port )
            {
                if( $port[0] == "single" )
                    if( isset( $port[1] ) && $port[1] == $context->value )
                        return TRUE;
                    elseif( $port[0] == "range" )
                    {
                        //range missing
                    }
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
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

RQuery::$defaultFilters['application']['object']['operators']['has.member'] = array(
    'Function' => function (ApplicationRQueryContext $context) {
        if( !$context->object->isApplicationGroup() &&  !$context->object->isContainer())
            return FALSE;

        if( isset( $context->object->udp_timeout) )
            return TRUE;

        $member = $context->object->owner->find( $context->value );
        if( $member !== null)
        {
            $references = $member->getReferences();
            foreach( $references as $ref )
            {
                /** @var ReferenceableObject $ref */
                if( get_class( $ref->owner ) == "AppStore" )
                {
                    if( $ref === $context->object )
                        return TRUE;
                }
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['application']['risk']['operators']['>,<,=,!'] = array(
    'eval' => '$object->risk !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

// </editor-fold>