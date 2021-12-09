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



set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

PH::print_stdout(  "\n*************************************************");
PH::print_stdout(  "**************** FILTER TESTERS *****************");

PH::processCliArgs();

if( ini_get('safe_mode') )
{
    derr("SAFE MODE IS ACTIVE");
}

########################################################################################################################
########################################################################################################################
if( !isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if( strpos($configInput, "api://") !== FALSE )
    $api_ip_address = substr($configInput, 6);
else
    derr('"in" argument must be of type API [in=api://192.168.55.208]');

if( isset(PH::$args['upload']) )
{
    $cli = "php ../utils/upload-config.php in=input/panorama-8.0.xml out=api://{$api_ip_address} loadAfterUpload injectUserAdmin2  2>&1";
    PH::print_stdout( " * Executing CLI: {$cli}" );

    $output = array();
    $retValue = 0;

    exec($cli, $output, $retValue);

    foreach( $output as $line )
    {
        $string = '   ##  ';
        $string .= $line;
        PH::print_stdout( $string );
    }

    if( $retValue != 0 )
        derr("CLI exit with error code '{$retValue}'");
    PH::print_stdout( "" );
}

//$api_ip_address = "192.168.55.208";

function display_error_usage_exit($msg)
{
    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
        fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    #display_usage_and_exit(true);
}

########################################################################################################################
########################################################################################################################


function runCommand($bin, &$stream, $force = TRUE, $command = '')
{
    $stream = '';

    $bin .= $force ? " 2>&1" : '';

    $descriptorSpec = array
    (
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );

    $pipes = array();

    $process = proc_open($bin, $descriptorSpec, $pipes);

    if( $process !== FALSE )
    {
        fwrite($pipes[0], $command);
        fclose($pipes[0]);

        $stream = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $stream += stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        return proc_close($process);
    }
    else
        return -1;

}

$totalFilterCount = 0;
$totalFilterWithCiCount = 0;

foreach( RQuery::$defaultFilters as $type => &$filtersByField )
{
    foreach( $filtersByField as $fieldName => &$filtersByOperator )
    {
        foreach( $filtersByOperator['operators'] as $operator => &$filter )
        {
            $totalFilterCount++;

            if( !isset($filter['ci']) )
                continue;

            $totalFilterWithCiCount++;

            if( $operator == '>,<,=,!' )
                $operator = '<';

            PH::print_stdout( "\n\n\n *** Processing filter: {$type} / ({$fieldName} {$operator})" );

            $ci = &$filter['ci'];

            $filterString = str_replace('%PROP%', "{$fieldName} {$operator}", $ci['fString']);


            if( $type == 'rule' )
                $util = '../utils/rules-edit.php';
            elseif( $type == 'address' )
                $util = '../utils/address-edit.php';
            elseif( $type == 'service' )
                $util = '../utils/service-edit.php';
            elseif( $type == 'tag' )
                $util = '../utils/tag-edit.php';
            elseif( $type == 'zone' )
                $util = '../utils/zone-edit.php';
            elseif( $type == 'securityprofile' )
            {
                PH::print_stdout( "******* SKIPPED for now *******" );
                continue;
            }
            elseif( $type == 'app' )
            {
                PH::print_stdout( "******* SKIPPED for now *******" );
                continue;
            }
            elseif( $type == 'interface' )
            {
                PH::print_stdout( "******* SKIPPED for now *******" );
                continue;
            }
            elseif( $type == 'virtual-wire' )
            {
                PH::print_stdout( "******* SKIPPED for now *******" );
                continue;
            }
            elseif( $type == 'routing' )
            {
                PH::print_stdout( "******* SKIPPED for now *******" );
                continue;
            }
            elseif( $type == 'device' )
            {
                PH::print_stdout( "******* SKIPPED for now *******" );
                continue;
            }
            else
            {
                derr('unsupported');
            }

            $location = 'any';
            $output = '/dev/null';
            $ruletype = 'any';


            $cli = "php $util in=api://{$api_ip_address} location={$location} actions=display 'filter={$filterString}'";

            if( $type == 'rule' )
                $cli .= " ruletype={$ruletype}";

            $cli .= ' debugapi ';

            $cli .= ' 2>&1';

            PH::print_stdout( " * Executing CLI: {$cli}" );

            $output = array();
            $retValue = 0;

            exec($cli, $output, $retValue);

            foreach( $output as $line )
            {
                $string = '   ##  ';
                $string .= $line;
                PH::print_stdout( $string );
            }

            if( $retValue != 0 )
                derr("CLI exit with error code '{$retValue}'");

            PH::print_stdout( "" );

        }
    }
}

PH::print_stdout( "\n*****  *****" );
PH::print_stdout( " - Processed {$totalFilterCount} filters" );
PH::print_stdout( " - Found {$totalFilterWithCiCount} that are CI enabled" );

PH::print_stdout( "" );
PH::print_stdout( "\n*********** FINISHED TESTING FILTERS ************" );
PH::print_stdout( "*************************************************\n" );




