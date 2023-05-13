<?php


# optimisation need
# get two config files
# file1=
#file2=

#run per file:
#pan-os-php type=rule 'actions=display:ResolveAddressSummary|resolveservicesummary' in=file1  shadow-json | tee after_rule.json

#then start comparing JSON files from below



// load PAN-OS-PHP library
require_once("lib/pan_php_framework.php");
require_once "utils/lib/UTIL.php";


PH::print_stdout();
PH::print_stdout("*********** START OF SCRIPT " . basename(__FILE__) . " ************");
PH::print_stdout();


$supportedArguments = array();
//PREDEFINED arguments:
#$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=filename.xml | api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
#$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');

$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


//YOUR OWN arguments if needed
$supportedArguments['jsonfile1'] = array('niceName' => 'ARGUMENT1', 'shortHelp' => 'an argument you like to use in your script');
$supportedArguments['jsonfile2'] = array('niceName' => 'Optional_Argument2', 'shortHelp' => 'an argument you like to define here');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] argument1 [optional_argument2]";


$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);


PH::processCliArgs();

#$util->utilInit();


#$util->load_config();
#$util->location_filter();


/** @var PANConf|PanoramaConf $pan */
#$pan = $util->pan;


/** @var VirtualSystem|DeviceGroup $sub */
#$sub = $util->sub;

/** @var string $location */
#$location = $util->location;

/** @var boolean $apiMode */
#$apiMode = $util->apiMode;

/** @var array $args */
#$args = PH::$args;


PH::print_stdout();
#PH::print_stdout("    **********     **********");
PH::print_stdout();

/*********************************
 * *
 * *  START WRITING YOUR CODE HERE
 * *
 * * List of available variables:
 *
 * * $pan : PANConf or PanoramaConf object
 * * $location : string with location name or undefined if not provided on CLI
 * * $sub : DeviceGroup or VirtualSystem found after looking from cli 'location' argument
 * * $apiMode : if config file was downloaded from API directly
 * * $args : array with all CLI arguments processed by PAN-OS-PHP
 * *
 */

$ruleDiff = false;

$file1_name = PH::$args['jsonfile1'];
$file2_name = PH::$args['jsonfile2'];

/*
$json_file1_name = "/tmp/".$file1_name.".json";
$json_file2_name = "/tmp/".$file2_name.".json";

$cli1 = "php ".dirname(__FILE__)."/../../utils/pan-os-php.php type=rule 'actions=display:ResolveAddressSummary|resolveservicesummary' in=".$file1_name." shadow-json | tee ".$json_file1_name;
PH::print_stdout( "run command: '".$cli1."'" );
PH::print_stdout("this will take some time");
$retValue = null;
exec($cli1, $output, $retValue);
foreach( $output as $line )
{
    $string = '   ##  ';
    $string .= $line;
    PH::print_stdout( $string );
}

if( $retValue != 0 )
    derr("CLI exit with error code '{$retValue}'");

PH::print_stdout();


$cli2 = "php ".dirname(__FILE__)."/../../utils/pan-os-php.php type=rule 'actions=display:ResolveAddressSummary|resolveservicesummary' in=".$file2_name." shadow-json | tee ".$json_file2_name;
PH::print_stdout( "run command: '".$cli2."'" );
PH::print_stdout("this will take some time");
$retValue = null;
exec($cli2, $output, $retValue);
foreach( $output as $line )
{
    $string = '   ##  ';
    $string .= $line;
    PH::print_stdout( $string );
}

if( $retValue != 0 )
    derr("CLI exit with error code '{$retValue}'");
*/
PH::print_stdout();

$file1 = file_get_contents($file1_name);
$file2 = file_get_contents($file2_name);

#$file1 = file_get_contents($json_file1_name);
#$file2 = file_get_contents($json_file2_name);

$array1 = json_decode($file1, true);
$array2 = json_decode($file2, true );



$tmp1 = $array1['PANConf']['0']['sub']['object'];
$tmp2 = $array2['PANConf']['0']['sub']['object'];
foreach( $tmp1 as $key => $rule )
{
    if( isset($tmp2[$key]) )
        $rule2 = $tmp2[$key];
    else
        derr( "rule in jsonfile2 not found: ".$key );

    $type = 'resolved';
    $type = 'unresolved';

    $diff_src = array();
    $field = 'src_resolved_sum';
    if( isset($rule[$field]) && isset($rule2[$field]) )
    {
        $src1 = $rule[$field][$type];
        $src2 = $rule2[$field][$type];
        $diff_src = array_diff_recursive($src1, $src2);
    }


    $diff_dst = array();
    $field = 'dst_resolved_sum';
    if( isset($rule[$field]) && isset($rule2[$field]) )
    {
        $dst1 = $rule[$field][$type];
        $dst2 = $rule2[$field][$type];
        $diff_dst = array_diff_recursive($dst1, $dst2);
    }


    $diff_srv = array();
    $field = 'srv_resolved_sum';
    if( isset($rule[$field]) && isset($rule2[$field]) )
    {
        $srv1 = $rule[$field];
        $srv2 = $rule2[$field];
        $diff_srv = array_diff_recursive( $srv1, $srv2 );
    }


    if( !empty($diff_src) || !empty($diff_dst) || !empty($diff_srv) )
    {
        $ruleDiff = True;

        PH::print_stdout();
        PH::print_stdout( "Rule diff found: ".$key);
        if( !empty($diff_src) )
        {
            PH::print_stdout("source");
            PH::print_stdout();
            PH::print_stdout("file1");
            print_r($src1);
            PH::print_stdout("file2");
            print_r($src2);
        }

        if( !empty($diff_dst) )
        {
            PH::print_stdout("destination");
            PH::print_stdout();
            PH::print_stdout("file1");
            print_r($dst1);
            PH::print_stdout("file2");
            print_r($dst2);
        }

        if( !empty($diff_srv) )
        {
            PH::print_stdout("service");
            PH::print_stdout();
            PH::print_stdout("file1");
            print_r($srv1);
            PH::print_stdout("file2");
            print_r($srv2);
        }
    }
}

if( !$ruleDiff )
{
    PH::print_stdout();
    PH::print_stdout();
    PH::print_stdout(" no Rule diff for SRC / DST / SRV");
    PH::print_stdout();
    PH::print_stdout();
}


#$util->save_our_work();
PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************");
PH::print_stdout();



function array_diff_recursive($arr1, $arr2)
{
    $outputDiff = [];

    foreach ($arr1 as $key => $value)
    {
        //if the key exists in the second array, recursively call this function
        //if it is an array, otherwise check if the value is in arr2
        if (array_key_exists($key, $arr2))
        {
            if (is_array($value))
            {
                $recursiveDiff = array_diff_recursive($value, $arr2[$key]);

                if (count($recursiveDiff))
                {
                    $outputDiff[$key] = $recursiveDiff;
                }
            }
            else if (!in_array($value, $arr2))
            {
                $outputDiff[$key] = $value;
            }
        }
        //if the key is not in the second array, check if the value is in
        //the second array (this is a quirk of how array_diff works)
        else if (!in_array($value, $arr2))
        {
            $outputDiff[$key] = $value;
        }
    }

    return $outputDiff;
}