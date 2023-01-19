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

require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$displayAttributeName = false;

$supportedArguments = Array();
#$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
#$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file1'] = Array('niceName' => 'file1', 'shortHelp' => 'orig file');
$supportedArguments['file2'] = Array('niceName' => 'file1', 'shortHelp' => 'new file');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
#$util->utilInit();
PH::processCliArgs();

##########################################
##########################################

#$util->load_config();
#$util->location_filter();

#$pan = $util->pan;
#$connector = $pan->connector;

$diffCheck1passed = true;
$diffCheck2passed = true;
$diffCheck3passed = true;
########################################################################################################################
//file1
if( !isset(PH::$args['file1']) )
    $util->display_error_usage_exit('"file1" is missing from arguments');
$file1 = PH::$args['file1'];
if( !file_exists($file1) )
    derr( "FILE: ". $file1. " not available", null, false);
if( !is_string($file1) || strlen($file1) < 1 )
    $util->display_error_usage_exit('"file1" argument is not a valid string');

PH::print_stdout( "Opening ORIGINAL '{$file1}' XML file... ");
$doc1 = new DOMDocument();
if( $doc1->load($file1) === FALSE )
    derr('Error while parsing xml:' . libxml_get_last_error()->message , null, false);


//file2
if( !isset(PH::$args['file2']) )
    $util->display_error_usage_exit('"file2" is missing from arguments');
$file2 = PH::$args['file2'];
if( !file_exists($file2) )
    derr( "FILE: ". $file2. " not available", null, false);
if( !is_string($file2) || strlen($file2) < 1 )
    $util->display_error_usage_exit('"file1" argument is not a valid string');

PH::print_stdout( "Opening COMPARE '{$file2}' XML file... ");
$doc2 = new DOMDocument();
if( $doc2->load($file2) === FALSE )
    derr('Error while parsing xml:' . libxml_get_last_error()->message, null, false);

########################################################################################################################


//send file1 / file2 combined elements to DIFF util
//todo: this is full DIFF - but only rule order must be checked
$argv = array();
#$argc = array();
PH::$args = array();
PH::$argv = array();

$argv[] = basename(__FILE__);
$argv[] = "file1=".$file1;
$argv[] = "file2=".$file2;
$argv[] = "shadow-json";
if( isset(PH::$args['filter']) )
    $argv[] = "filter=".PH::$args['filter'];

$util = new DIFF("diff", $argv, $argc,__FILE__." type=diff");

PH::$shadow_json = FALSE;
PH::print_stdout( "\n\n####################################################################\n\n");
PH::print_stdout( "\n-------------------------------------------");
PH::print_stdout( "-------------------------------------------");
PH::print_stdout( "check full XML diff");

if( isset( PH::$JSON_OUT['log'] ) )
    print_r( PH::$JSON_OUT['log'] );
PH::print_stdout( "\n#####\n");


$diffCounter = 0;
if( isset( PH::$JSON_OUT['diff'] ) )
{
    $diffCounter = count(PH::$JSON_OUT['diff']);
    #PH::print_stdout( "diff counter: ".$diffCounter );
}


if( $diffCounter > 0 )
{
    $diffCheck1passed = false;
    PH::print_stdout( "- XML diff FAILED" );
}
else
    PH::print_stdout( "- XML diff PASSED" );


########################################################################################################################

$output = shell_exec('php '.dirname(__FILE__).'/diff_ruleorder_check.php file1='.$file1." file2=".$file2);

$newlineCounter = 0;
if( $output !== null )
    $newlineCounter = substr_count( $output, "\n" );

PH::print_stdout( "\n-------------------------------------------");
PH::print_stdout( "-------------------------------------------");
PH::print_stdout( "check security rule order of combined pre-/post-rulebase");
PH::print_stdout( $output );

PH::print_stdout( "\n#####\n");
if( $newlineCounter > 0 )
{
    $diffCheck2passed = false;
    PH::print_stdout( "- security rule order check FAILED" );
}
else
    PH::print_stdout( "- security rule order check PASSED" );

########################################################################################################################
PH::print_stdout( "\n-------------------------------------------");
PH::print_stdout( "-------------------------------------------");
PH::print_stdout( "check for unused address objects");
PH::print_stdout( "\n#####\n");
PH::print_stdout( "- TBD - not implemented yet");
//Todo: run custom script
// - load pushed config if policy
// - load address/ address-group
// - load rulebase / pre-rulebase / post-rulebase


#$util = new UTIL( "custom", $argv, $argc, __FILE__ );
PH::$shadow_json = FALSE;

// - get unused address
// - check if unused count diff between file1 and file2

########################################################################################################################

PH::print_stdout( "\n####################################################################\n");
PH::print_stdout( "- Final Result:" );
if( $diffCheck1passed && $diffCheck2passed && $diffCheck3passed )
{

    PH::print_stdout(  );
    PH::print_stdout( "    PASS" );

    /*
    PH::print_stdout(  );
    PH::print_stdout( "    ####  #####  ####  ####");
    PH::print_stdout( "    #  #  #   #  #     #");
    PH::print_stdout( "    ####  #####  ####  ####");
    PH::print_stdout( "    #     #   #     #     #");
    PH::print_stdout( "    #     #   #  ####  ####");
    /*
    PH::print_stdout(  );
    PH::print_stdout( "    ****  *****  ****  ****");
    PH::print_stdout( "    *  *  *   *  *     *");
    PH::print_stdout( "    ****  *****  ****  ****");
    PH::print_stdout( "    *     *   *     *     *");
    PH::print_stdout( "    *     *   *  ****  ****");
    */
}
    
else
{
    PH::print_stdout();

    PH::print_stdout( "    FAIL" );

    /*
    PH::print_stdout( "    ####  #####  #  #");
    PH::print_stdout( "    #     #   #  #  #");
    PH::print_stdout( "    ####  #####  #  #");
    PH::print_stdout( "    #     #   #  #  #");
    PH::print_stdout( "    #     #   #  #  ####");
*/
    /*
    PH::print_stdout();
    PH::print_stdout( "    ****  *****  *  *");
    PH::print_stdout( "    *     *   *  *  *");
    PH::print_stdout( "    ***   *****  *  *");
    PH::print_stdout( "    *     *   *  *  *");
    PH::print_stdout( "    *     *   *  *  ****");
    */
}

PH::print_stdout( "\n####################################################################\n");
########################################################################################################################
PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################

