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
require_once dirname(__FILE__) . "/../lib/pan_php_framework.php";

PH::print_stdout("\n*************************************************");
PH::print_stdout("**************** ACTION TESTERS *****************\n");

PH::processCliArgs();

if( ini_get('safe_mode') )
{
    derr("SAFE MODE IS ACTIVE");
}


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

$totalActionCount = 0;

$missingActionArgCount = 0;

$totalActionWithCiCount = 0;
$missing_actions = array();


$pathString = dirname(__FILE__)."/../utils/lib";
$JSONarray = file_get_contents( $pathString."/util_action_filter.json");
$json_a = json_decode($JSONarray, true);

foreach( $json_a as $type => $UTILtype )
{
    #if( $type !== "rule" )
    #    continue;

    $ci = array();
    $ci['input'] = 'input/panorama-8.0.xml';

    foreach( $UTILtype['action'] as $actionName => &$action )
    {
        $totalActionCount++;

        if( $type == "address" && ($actionName == 'value-set-reverse-dns' ||
            $actionName == 'value-set-ip-for-fqdn' )
        )
            continue;

        if( $type == "rule" && ($actionName == 'position-move-to-bottom' ||
            $actionName == 'position-move-to-top' )
        )
            continue;


        if( isset($action['args']) )
        {
            $missingActionArgCount++;
            $missing_actionsArgument[$type][] = $actionName;
            continue;
        }



        if( !isset($action['ci']) )
        {
            $missing_actions[$type][] = $actionName;
            #continue;
        }

        $totalActionWithCiCount++;

        print "check TYPE: " . $type . " action: " . $actionName . "\n";


        if( $type == 'rule' )
            $util = '../utils/pan-os-php.php type=rule';
        elseif( $type == 'address' )
            $util = '../utils/pan-os-php.php type=address';
        elseif( $type == 'service' )
            $util = '../utils/pan-os-php.php type=service';
        elseif( $type == 'tag' )
            $util = '../utils/pan-os-php.php type=tag';
        elseif( $type == 'zone' )
            $util = '../utils/pan-os-php.php type=zone';
        elseif( $type == 'schedule' )
            $util = '../utils/pan-os-php.php type=schedule';
        #elseif( $type == 'application' )
        #    $util = '../utils/application-edit.php';

        elseif( $type == 'securityprofile' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'securityprofilegroup' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'app' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'application' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'interface' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'virtualwire' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'routing' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'device' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        elseif( $type == 'threat' )
        {
            PH::print_stdout("******* SKIPPED for now *******");
            continue;
        }
        else
        {
            derr('unsupported');
        }


        $location = 'any';
        $output = '/dev/null';
        $ruletype = 'any';


        $cli = "php $util in={$ci['input']} out={$output} location={$location} 'actions={$actionName}'";

        if( $type == 'rule' )
            $cli .= " ruletype={$ruletype}";

        $cli .= ' shadow-ignoreinvalidaddressobjects';
        $cli .= ' 2>&1';

        PH::print_stdout(" * Executing CLI: {$cli}");

        $output = array();
        $retValue = 0;

        exec($cli, $output, $retValue);

        foreach( $output as $line )
        {
            $string = '   ##  ';
            $string .= $line;
            PH::print_stdout($string);
        }

        if( $retValue != 0 )
            derr("CLI exit with error code '{$retValue}'");

        PH::print_stdout("");

    }
}

PH::print_stdout("\n*****  *****");
PH::print_stdout(" - Processed {$totalActionCount} actions");
PH::print_stdout(" - Found {$totalActionWithCiCount} that are CI enabled");
PH::print_stdout(" - Found {$missingActionArgCount} that are missing because of actions argument available");


PH::print_stdout("\n");
PH::print_stdout(" - the following actions has no test argument:");
print_r($missing_actions);

PH::print_stdout("\n");
PH::print_stdout(" - the following actions are not tested:");
print_r($missing_actionsArgument);

PH::print_stdout("");
PH::print_stdout("\n*********** FINISHED TESTING FILTERS ************");
PH::print_stdout("*************************************************\n");




