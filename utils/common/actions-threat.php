<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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


ThreatCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ThreatCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);



ThreatCallContext::$supportedActions[] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (ThreatCallContext $context) {
        $context->counter_spyware = 0;
        $context->counter_vulnerability = 0;

    },
    'MainFunction' => function (ThreatCallContext $context) {
        $threat = $context->object;

        PH::print_stdout( $context->padding . "* " . get_class($threat) . " '{$threat->name()}' " );

        PH::print_stdout( "          - Threatname: '{$threat->threatname()}'  category: '{$threat->category()}' severity: '{$threat->severity()}'  default-action: '{$threat->defaultAction()}'" );

        PH::$JSON_TMP['sub']['object'][$threat->name()]['name'] = $threat->name();
        PH::$JSON_TMP['sub']['object'][$threat->name()]['type'] = get_class($threat);
        PH::$JSON_TMP['sub']['object'][$threat->name()]['category'] = $threat->category();
        PH::$JSON_TMP['sub']['object'][$threat->name()]['severity'] = $threat->severity();
        PH::$JSON_TMP['sub']['object'][$threat->name()]['default-action'] = $threat->defaultAction();

        if( $threat->type() == "vulnerability" )
            $context->counter_vulnerability++;
        elseif( $threat->type() == "spyware" )
            $context->counter_spyware++;

    },
    'GlobalFinishFunction' => function (ThreatCallContext $context) {
        PH::print_stdout("spyware: ".$context->counter_spyware );
        PH::print_stdout("vulnerability: ".$context->counter_vulnerability );

        PH::$JSON_TMP['sub']['summary']['spyware'] = $context->counter_spyware;
        PH::$JSON_TMP['sub']['summary']['vulnerability'] = $context->counter_vulnerability;
    }
);

ThreatCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (ThreatCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (ThreatCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (ThreatCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        $lines = '';
        $encloseFunction = function ($value, $nowrap = TRUE) {
            if( is_string($value) )
                $output = htmlspecialchars($value);
            elseif( is_array($value) )
            {
                $output = '';
                $first = TRUE;
                foreach( $value as $subValue )
                {
                    if( !$first )
                    {
                        $output .= '<br />';
                    }
                    else
                        $first = FALSE;

                    if( is_string($subValue) )
                        $output .= htmlspecialchars($subValue);
                    else
                        $output .= htmlspecialchars($subValue->name());
                }
            }
            else
                derr('unsupported');

            if( $nowrap )
                return '<td style="white-space: nowrap">' . $output . '</td>';

            return '<td>' . $output . '</td>';
        };


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        $headers = '<th>location</th><th>type</th><th>name</th><th>Threatname</th><th>category</th><th>severity</th><th>default-action</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Threat $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $encloseFunction(PH::getLocationString($object));

                $lines .= $encloseFunction(get_class($object));

                $lines .= $encloseFunction($object->name());

                $lines .= $encloseFunction($object->threatname());

                $lines .= $encloseFunction($object->category());

                $lines .= $encloseFunction($object->severity());

                $lines .= $encloseFunction($object->defaultAction());

                if( $addWhereUsed )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $encloseFunction($refTextArray);
                }

                $lines .= "</tr>\n";
            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html-export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/jquery-1.11.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n")
    )
);