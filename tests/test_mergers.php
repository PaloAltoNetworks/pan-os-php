<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

echo "\n*************************************************\n";
echo "**************** MERGER TESTERS *****************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

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

#$totalFilterCount = 0;
#$totalFilterWithCiCount = 0;

$test_merger = array('address', 'service', 'addressgroup', 'servicegroup', 'tag');

foreach( $test_merger as $merger )
{
    #$ci['input'] = 'input/panorama-8.0-merger.xml';
    $ci['input'] = 'input/panorama-10.0-merger.xml';

    echo "\n\n\n *** Processing merger: {$merger} \n";

    $dupalgorithm_array = array();
    if( $merger == 'address' )
    {
        $util = '../utils/address-merger.php';
        $dupalgorithm_array[] = 'SameAddress';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'Whereused';
    }
    elseif( $merger == 'addressgroup' )
    {
        $util = '../utils/addressgroup-merger.php';
        $dupalgorithm_array[] = 'SameMembers';
        $dupalgorithm_array[] = 'SameIP4Mapping';
        $dupalgorithm_array[] = 'Whereused';

    }
    elseif( $merger == 'service' )
    {
        $util = '../utils/service-merger.php';
        $dupalgorithm_array[] = 'SamePorts';
        $dupalgorithm_array[] = 'Whereused';
    }
    elseif( $merger == 'servicegroup' )
    {
        $util = '../utils/servicegroup-merger.php';
        $dupalgorithm_array[] = 'SameMembers';
        $dupalgorithm_array[] = 'SamePortMapping';
        $dupalgorithm_array[] = 'Whereused';
    }
    elseif( $merger == 'tag' )
    {
        $util = '../utils/tag-merger.php';
        $dupalgorithm_array[] = 'SameColor';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'WhereUsed';
    }

    else
        derr('unsupported');

    $array = array("", "allowMergingWithUpperLevel");
    foreach( $array as $allowmergingwithupperlevel )
    {
        foreach( $dupalgorithm_array as $dupalgorithm )
        {
            $location = 'any';
            $output = '/dev/null';

            $cli = "php $util in={$ci['input']} out={$output} location={$location} {$allowmergingwithupperlevel}";

            #if( $merger != 'address' )
                $cli .= " DupAlgorithm={$dupalgorithm}";

            $cli .= ' 2>&1';

            echo " * Executing CLI: {$cli}\n";

            $output = array();
            $retValue = 0;

            exec($cli, $output, $retValue);

            foreach( $output as $line )
            {
                echo '   ##  ';
                echo $line;
                echo "\n";
            }

            if( $retValue != 0 )
                derr("CLI exit with error code '{$retValue}'");

            echo "\n";
        }
    }


}

echo "\n*****  *****\n";
#echo " - Processed {$totalFilterCount} filters\n";
#echo " - Found {$totalFilterWithCiCount} that are CI enabled\n";

echo "\n";
echo "\n*********** FINISHED TESTING MERGERS ************\n";
echo "*************************************************\n\n";




