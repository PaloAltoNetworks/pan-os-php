<?php
/**
 * ISC License
 *
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

require_once("lib/pan_php_framework.php");

PH::print_stdout( "*************************************************");
PH::print_stdout(   "**************** FILTER TESTERS *****************");




PH::processCliArgs();

if( ini_get('safe_mode') ){
    derr("SAFE MODE IS ACTIVE");
}



function runCommand($bin, &$stream, $force = true, $command = '')
{
    $stream = '';

    $bin .= $force ? " 2>&1" : '';

    $descriptorSpec = array
    (
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );

    $pipes = Array();

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



$location = 'vsys1';
$output = '/dev/null';
$serial = '0123456789';

$dirname = dirname(__FILE__);

/*
$cli_array[] = "php ".$dirname."/../rule-marker.php     in=orig/stage00.xml  out=input/stage05.xml location={$location}";
$cli_array[] = "php ".$dirname."/../rule-cloner.php     in=input/stage05.xml out=input/stage10.xml location={$location} serial={$serial}";
$cli_array[] = "php ".$dirname."/../rule-activation.php in=input/stage10.xml out={$output}         location={$location}";
$cli_array[] = "php ".$dirname."/../rule-activation.php in=input/stage10.xml out=input/stage15.xml location={$location} confirm";
$cli_array[] = "php ".$dirname."/../rule-cleaner.php    in=input/stage15.xml out={$output}         location={$location} serial={$serial}";
$cli_array[] = "php ".$dirname."/../rule-cleaner.php    in=input/stage15.xml out=input/stage20.xml location={$location} serial={$serial} confirm";
*/

$cli_array[] = "php ".$dirname."/../../utils/pan-os-php.php type=appid-toolbox phase=rule-marker  in=orig/stage00.xml  out=input/stage05.xml location={$location}";
$cli_array[] = "php ".$dirname."/../../utils/pan-os-php.php type=appid-toolbox phase=rule-cloner  in=input/stage05.xml out=input/stage10.xml location={$location} serial={$serial}";
$cli_array[] = "php ".$dirname."/../../utils/pan-os-php.php type=appid-toolbox phase=rule-activation in=input/stage10.xml out={$output}         location={$location}";
$cli_array[] = "php ".$dirname."/../../utils/pan-os-php.php type=appid-toolbox phase=rule-activation in=input/stage10.xml out=input/stage15.xml location={$location} confirm";
$cli_array[] = "php ".$dirname."/../../utils/pan-os-php.php type=appid-toolbox phase=rule-cleaner  in=input/stage15.xml out={$output}         location={$location} serial={$serial}";
$cli_array[] = "php ".$dirname."/../../utils/pan-os-php.php type=appid-toolbox phase=rule-cleaner  in=input/stage15.xml out=input/stage20.xml location={$location} serial={$serial} confirm";

foreach( $cli_array as $cli )
{
            $cli .= ' 2>&1';

            PH::print_stdout( " * Executing CLI: {$cli}" );

            $output = Array();
            $retValue = 0;

            exec($cli, $output, $retValue);

            foreach($output as $line)
            {
                $string =  '   ##  ';
                $string .= $line;
                PH::print_stdout( $string );
            }

            if( $retValue != 0 )
                derr("CLI exit with error code '{$retValue}'");

    PH::print_stdout(  "");
}


PH::print_stdout(  "*****  *****");
#PH::print_stdout(  " - Processed {$totalFilterCount} filters");
#PH::print_stdout(  " - Found {$totalFilterWithCiCount} that are CI enabled");
PH::print_stdout(  "*****  *****");




$output_folder = "input";
$compare_folder = "compare";

$stage_array = array('stage05', 'stage10', 'stage15', 'stage20');

foreach( $stage_array as $item )
{
    $output = Array();
    $retValue = 0;


    //this is related to .travis.yml and for travis CI testing
    if( getenv("CI") !== false )
    {
        #$cli = 'php -r "require( \'pan-diff.php file1='.$compare_folder.'/'.$item.'.xml file2='.$output_folder.'/'.$item.'.xml\' );"';
        $cli = "php ../../utils/pan-os-php.php type=diff file1=${compare_folder}/${item}.xml file2=${output_folder}/${item}.xml";
    }
    else
        $cli = "php ../../utils/pan-os-php.php type=diff file1=${compare_folder}/${item}.xml file2=${output_folder}/${item}.xml";

    $cli .= "  2>&1";

    PH::print_stdout(  " * Executing CLI: {$cli}");

    exec($cli, $output, $retValue );

    $counter = 0;
    foreach($output as $line)
    {
        $string = '   ##  ';
        $string .= $line;
        PH::print_stdout( $string );
        $counter++;
    }

    //$counter == 11 - if exactly no diff
    //$counter == 14 - one diff example rule-activation new tag - <entry name="appid#activated#20180216"/>
    if( $counter > 16 )
        derr("DIFF available for file '{$item}.xml' ");

    if( $retValue != 0 )
        derr("CLI exit with error code '{$retValue}'");

    PH::print_stdout(  "");
}












PH::print_stdout(  "");
PH::print_stdout(  "\n*********** FINISHED TESTING FILTERS ************");
PH::print_stdout(    "*************************************************");




