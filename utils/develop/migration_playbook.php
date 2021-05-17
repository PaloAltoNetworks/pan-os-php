<?php

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

require_once("utils/common/actions.php");
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

require_once("parser/lib/CONVERTER.php");
require_once("parser/lib/PARSER.php");
require_once("parser/lib/SHAREDNEW.php");

###############################################################################
//migration playbook arguments
###############################################################################
//NEEDED??????     please input a JSON or something else which define all part for the playbook

PH::processCliArgs();

if( isset(PH::$args['vendor']) )
{
    $vendor = PH::$args['vendor'];
}

if( isset(PH::$args['file']) )
{
    $file = PH::$args['file'];
}

if( isset(PH::$args['in']) )
{
    $input = PH::$args['in'];
}

//define out to save the final file into this file
if( isset(PH::$args['out']) )
{
    $output = PH::$args['out'];
}
###############################################################################
###############################################################################
$pa_migration_parser = "parser";
$pa_address_edit = "address";
$pa_service_edit = "service";
$pa_tag_edit = "tag";
$pa_zone_edit = "zone";
$pa_rule_edit = "rule";
$pa_rule_stats = "stats";

$pa_address_merger = "address-merger";
$pa_addressgroup_merger = "addressgroup-merger";
$pa_service_merger = "service-merger";
$pa_servicegroup_merger = "servicegroup-merger";
$pa_tag_merger = "tag-merger";

###############################################################################
//MIGRATION PLAYBOOK
###############################################################################
//interactive script needed:
//1) ask for type of script
//2) ask for all supported arguments and continue there:


$command_array = array();
$command_array[] = array( $pa_migration_parser, "vendor=".$vendor, "file=".$file, "stats" );
$command_array[] = array( $pa_rule_stats );
$command_array[] = array( $pa_address_edit, "location=vsys1", "actions=display", "filter=(object is.unused.recursive)", "stats" );
#$command_array[] = array( $pa_address_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_addressgroup_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_service_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_servicegroup_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_tag_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );

/*
pa_address-edit  in=fixed.xml out=improved.xml location=any actions=replace-IP-by-MT-like-Object  shadow-ignoreInvalidAddressObjects 'filter=(object is.tmp)' | tee log_transform_IP_to_Object.txt
pa_address-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee address-merger.txt
pa_addressgroup-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee addressgroup-merger.txt
pa_service-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee service-merger.txt
pa_servicegroup-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee servicegroup-merger.txt
 */


###############################################################################
//VARIABLE DECLARATION
###############################################################################
$stage_name = "stage";






###############################################################################
//EXECUTION
###############################################################################


$out = "";
$in = "";



foreach( $command_array as $key => $command )
{
    PH::$args = array();
    PH::$argv = array();
    PH::$argv[0] = $argv[0];
    PH::$argv[0] = "";

    $script = $command[0];
    unset( $command[0] );
    $arg_string = "";



    foreach( $command as $argument )
        PH::$argv[] = $argument;



    ###############################################################################
    //IN / OUT specificaiton
    ###############################################################################
    if( $key == 0 && $script == $pa_migration_parser )
        $out_counter = 0;
    elseif( $key > 0 )
    {
        $in = $out;

        if( $script != $pa_rule_stats )
            $out_counter++;
    }


    if( $script != $pa_migration_parser )
        PH::$argv[] = "in=".$in;

    if( $script != $pa_rule_stats )
    {
        $out = $stage_name.$out_counter.".xml";
        PH::$argv[] = "out=".$out;
    }





    if( $script == $pa_rule_edit )
    {
        $tool = "pa_rule-edit";
        print_tool_usage( $tool, PH::$argv );
        $util = new RULEUTIL($script, $argv, $tool);
    }
    elseif( $script == $pa_migration_parser )
    {
        $tool = "pa_migration-parser";
        print_tool_usage( $tool, PH::$argv );
        $converter = new CONVERTER(  );
    }
    elseif( $script == $pa_rule_stats )
    {
        $tool = "pa_rule-stats";
        print_tool_usage( $tool, PH::$argv );
        $stats = new STATSUTIL( $script, $argv, $tool );
    }
    elseif( $script == $pa_rule_edit )
    {
        $tool = "pa_rule-edit";
        print_tool_usage( $tool, PH::$argv );
        $util = new RULEUTIL($script, $argv, $tool);
    }
    else
    {
        $tool = "pa_".$script."-edit";
        print_tool_usage( $tool, PH::$argv );
        $util = new UTIL($script, $argv, $tool );
    }

    print "\n";
    print "############################################################################\n";
    print "\n";

}

if( isset(PH::$args['out']) )
{
//now save the latest out= from the foreach loop "$out" into "$output" file;
    copy( $out, $output );
}




function print_tool_usage( $tool, $argv )
{
    print "\n".PH::boldText( "[ ".$tool. " ".implode( " ", $argv )." ]" )."\n\n";
}