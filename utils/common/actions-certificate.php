<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */



CertificateCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( CertificateCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();

        $algorithm = "";
        $privateKey = "";
        $privateKeyLen = "";


        $notValidbefore = "";
        $notValidafter = "";

        $publicKeyLen = "";
        $publicKeyAlgorithm = "";
        $publicKeyHash = "";

        if( $object->algorithm != null )
            $algorithm = "Algorithm: ".$object->algorithm;

        if( $object->notValidbefore != null )
            $notValidbefore = " | not Valid before: ".$object->notValidbefore;
        if( $object->notValidafter != null )
            $notValidafter = "after: ".$object->notValidafter;

        if( $object->privateKey != null )
        {
            $privateKey = $object->privateKey;
            $privateKeyLen = "       - "."privateKey length: ".$object->privateKeyLen;
            #$privateKeyAlgorithm = " | algorithm: ".$object->privateKeyAlgorithm;
            #$prviateKeyHash = " |  hash: ".$object->privateKeyHash;
        }

        if( $object->publicKey != null )
        {
            $publicKey = $object->publicKey;
            $publicKeyLen = "       - "."publicKey length: ".$object->publicKeyLen;
            $publicKeyAlgorithm = " | algorithm: ".$object->publicKeyAlgorithm;
            $publicKeyHash = " |  hash: ".$object->publicKeyHash;
        }
        //not-valid-before
        //not-valid-after

        PH::print_stdout( "       - ".$algorithm.$notValidbefore." - ".$notValidafter );
        PH::print_stdout( $privateKeyLen);
        #PH::print_stdout( $privateKeyLen.$privateKeyAlgorithm.$prviateKeyHash );
        PH::print_stdout( $publicKeyLen.$publicKeyAlgorithm.$publicKeyHash );
    },
);

/*
//introduce exporttoexcel

"Name","Subject","Issuer","CA","Key","Expires","Status","Algorithm","Usage","Cloud Secret Name"
"demo1234567","CN = test.test.de","CN = test.test.de","Yes","true","Oct 11 23:24:44 2024 GMT","valid","RSA","",""
 */
