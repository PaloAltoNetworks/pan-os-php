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

CertificateCallContext::$supportedActions['exportToExcel'] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (CertificateCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (CertificateCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (CertificateCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;



        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th>';
        $headers .= '<th>Algorithm</th><th>not Valid before</th><th>not Valid after</th>';



        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var DHCP $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction((string)$count);

                if( get_class($object->owner->owner) == "PANConf" )
                {
                    if( isset($object->owner->owner->owner) && $object->owner->owner->owner !== null && (get_class($object->owner->owner->owner) == "Template" || get_class($context->subSystem->owner) == "TemplateStack" ) )
                    {
                        $lines .= $context->encloseFunction($object->owner->owner->owner->name());
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                    else
                    {
                        $lines .= $context->encloseFunction("---");
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                }
                elseif( isset($object->owner->owner) && $object->owner->owner !== null && (get_class($object->owner->owner) == "Template" || get_class($context->subSystem->owner) == "TemplateStack" ) )
                {
                    $lines .= $context->encloseFunction($object->owner->owner->name());
                    $lines .= $context->encloseFunction($object->owner->name());
                }


                $lines .= $context->encloseFunction($object->name());

                $algorithm = "";
                if( $object->algorithm != null )
                    $algorithm = $object->algorithm;
                $lines .= $context->encloseFunction($algorithm);

                $notValidbefore = "";
                if( $object->notValidbefore != null )
                    $notValidbefore = $object->notValidbefore;
                $lines .= $context->encloseFunction($notValidbefore);

                $notValidafter = "";
                if( $object->notValidafter != null )
                    $notValidafter = $object->notValidafter;
                $lines .= $context->encloseFunction($notValidafter);


                $lines .= "</tr>\n";

            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);

    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'))
);