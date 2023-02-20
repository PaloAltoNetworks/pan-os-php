<?php

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

RQuery::$defaultFilters['certificate']['publickey-length']['operators']['>,<,=,!'] = array(
    'eval' => '$object->hasPublicKey() && $object->getPkeyBits() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);