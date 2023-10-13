<?php

RQuery::$defaultFilters['certificate']['name']['operators']['eq'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% new test 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate']['name']['operators']['eq.nocase'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% new test 2)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate']['name']['operators']['contains'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% -)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['certificate']['publickey-algorithm']['operators']['is.rsa'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        if( !$context->object->hasPublicKey() )
            return FALSE;

        if( $context->object->getPkeyAlgorithm() == "rsa" )
            return TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate']['publickey-algorithm']['operators']['is.ec'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        if( !$context->object->hasPublicKey() )
            return FALSE;

        if( $context->object->getPkeyAlgorithm() == "ec" )
            return TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['certificate']['publickey-hash']['operators']['is.sha1'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        if( !$context->object->hasPublicKey() )
            return FALSE;

        if( $context->object->getPkeyHash() == "sha1" )
            return TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate']['publickey-hash']['operators']['is.sha256'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        if( !$context->object->hasPublicKey() )
            return FALSE;

        if( $context->object->getPkeyHash() == "sha256" )
            return TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate']['publickey-hash']['operators']['is.sha384'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        if( !$context->object->hasPublicKey() )
            return FALSE;

        if( $context->object->getPkeyHash() == "sha384" )
            return TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate']['publickey-hash']['operators']['is.sha512'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        if( !$context->object->hasPublicKey() )
            return FALSE;

        if( $context->object->getPkeyHash() == "sha512" )
            return TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate']['publickey-hash']['operators']['>,<,=,!'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        $object = $context->object;
        $arg = $context->value;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        if( !$context->object->hasPublicKey() )
            return FALSE;

        $hashvalue = $context->object->getPkeyHash();
        $hashvalue = str_replace( "sha", "", $hashvalue );

        $hashvaluesearch = $arg;
        if( strpos( $hashvaluesearch, "sha" ) !== FALSE )
        {
            $hashvaluesearch = str_replace( "sha", "", $hashvaluesearch );
        }

        $operator_string = $hashvalue." ".$operator." ".$hashvaluesearch;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => true,
    'help' => 'returns TRUE if object hash value matches "publickey-hash >= 256" || "publickey-hash < sha256"',
    'ci' => array(
    'fString' => '(%PROP% 5)',
    'input' => 'input/panorama-8.0.xml'
)
);
RQuery::$defaultFilters['certificate']['publickey-length']['operators']['>,<,=,!'] = array(
    'eval' => '$object->hasPublicKey() && $object->getPkeyBits() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['certificate']['expired']['operators']['>,<,=,!'] = array(
    'Function' => function (CertificateRQueryContext $context) {
        $object = $context->object;


        $timestamp_value = strtotime($object->notValidafter);
        if( $context->value == 0 )
            $filter_timestamp = $context->value;
        else
            $filter_timestamp = strtotime($context->value);
        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $timestamp_value." ".$operator." ".$filter_timestamp;
        print "|".$operator_string."|\n";
        if( $operator == '==' && $timestamp_value == 0 )
        {
            return true;
        }
        elseif( $timestamp_value != 0 && eval("return $operator_string;" ) )
        {
            return true;
        }

        return false;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european] / 21 September 2021 / -90 days',
);