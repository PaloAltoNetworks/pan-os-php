<?php

echo "\n*************************************************\n";
echo   "**************** FILTER TESTERS *****************\n\n";

require_once("lib/pan_php_framework.php");


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


$cli_array[] = "php ../rule-marker.php     in=orig/stage00.xml  out=input/stage05.xml location={$location}";
$cli_array[] = "php ../rule-cloner.php     in=input/stage05.xml out=input/stage10.xml location={$location} serial={$serial}";
$cli_array[] = "php ../rule-activation.php in=input/stage10.xml out={$output}         location={$location}";
$cli_array[] = "php ../rule-activation.php in=input/stage10.xml out=input/stage15.xml location={$location} confirm";
$cli_array[] = "php ../rule-cleaner.php    in=input/stage15.xml out={$output}         location={$location} serial={$serial}";
$cli_array[] = "php ../rule-cleaner.php    in=input/stage15.xml out=input/stage20.xml location={$location} serial={$serial} confirm";



foreach( $cli_array as $cli )
{
            $cli .= ' 2>&1';

            echo " * Executing CLI: {$cli}\n";

            $output = Array();
            $retValue = 0;

            exec($cli, $output, $retValue);

            foreach($output as $line)
            {
                echo '   ##  '; echo $line; echo "\n";
            }

            if( $retValue != 0 )
                derr("CLI exit with error code '{$retValue}'");

            echo "\n";
}


echo "\n*****  *****\n";
#echo " - Processed {$totalFilterCount} filters\n";
#echo " - Found {$totalFilterWithCiCount} that are CI enabled\n";
echo "\n*****  *****\n";




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
        $cli = "php ../../utils/pan-diff.php file1=${compare_folder}/${item}.xml file2=${output_folder}/${item}.xml";
    }
    else
        $cli = "php ../../utils/pan-diff.php file1=${compare_folder}/${item}.xml file2=${output_folder}/${item}.xml";

    $cli .= "  2>&1";

    echo " * Executing CLI: {$cli}\n";

    exec($cli, $output, $retValue );

    $counter = 0;
    foreach($output as $line)
    {
        echo '   ##  '; echo $line; echo "\n";
        $counter++;
    }

    //$counter == 11 - if exactly no diff
    //$counter == 14 - one diff example rule-activation new tag - <entry name="appid#activated#20180216"/>
    if( $counter > 15 )
        derr("DIFF available for file '{$item}.xml' ");

    if( $retValue != 0 )
        derr("CLI exit with error code '{$retValue}'");

    echo "\n";
}












echo "\n";
echo "\n*********** FINISHED TESTING FILTERS ************\n";
echo   "*************************************************\n\n";




