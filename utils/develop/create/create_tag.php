<?php
/**
 * Created by PhpStorm.
 * User: swaschkut
 * Date: 4/19/16
 * Time: 9:12 AM
 */


print "\n***********************************************\n";
print "************ CREATE-TAG UTILITY ****************\n\n";


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] or in=INPUTFILE.xml out=OUTFILE.xml";

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

$util->load_config();
$util->location_filter();

$pan = $util->pan;


foreach( $util->objectsLocation as $location)
{
    if( $location === "shared" )
        $sub = $pan;
    else
        $sub = $pan->findVirtualSystem($location);



#LIMIT 10000 for vsys / another 100000 for shared level
    for( $i = 1; $i<10000; $i++ )
    {
        $name = "tag.".$i;
        print "create tag ".$name."\n";


        //VSYS
        if( $util->configInput['type'] == 'api' )
            $tmp_tag = $sub->tagStore->API_createTag( $name );
        else
            $tmp_tag = $sub->tagStore->createTag( $name );

        /*
        //SHARED
        if( $util->configInput['type'] == 'api' )
            $tmp_tag = $pan->tagStore->API_createTag( $name );
        else
            $tmp_tag = $pan->tagStore->createTag( $name );
        */

    }
}




##############################################

print "\n\n\n";

$util->save_our_work();



print "\n\n************ END OF CREATE-TAG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
