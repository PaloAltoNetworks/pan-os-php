<?php
/**
 * Created by PhpStorm.
 * User: swaschkut
 * Date: 3/21/17
 * Time: 7:57 AM
 */

require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['xpath'] = Array('niceName' => 'xpath', 'shortHelp' => 'specify the xpath to get the value defined on this config');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "\"xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-server\"\n".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

$util->load_config();
#$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


########################################################################################################################


if( !isset( PH::$args['xpath'] ) )
    $util->display_error_usage_exit('"xpath" argument is not set: example "xpath=/config/devices/entry[@name=\'localhost.localdomain\']/deviceconfig/system/update-server"');
else
    $xpath = PH::$args['xpath'];


########################################################################################################################
if( $connector !==  null )
{
    $connector->refreshSystemInfos();

    PH::print_stdout( "" );
    PH::print_stdout( "##########################################" );
    PH::print_stdout( 'MASTER device serial: '.$connector->info_serial );
    PH::print_stdout( "" );

    PH::$JSON_TMP['serial'] = $connector->info_serial;
    PH::print_stdout(PH::$JSON_TMP, false, "master device");
    PH::$JSON_TMP = array();

    if( $util->configType == 'panos' )
    {
        if( $connector->serial != "" )
        {
            $fw_con = $connector->cloneForPanoramaManagedDevice($connector->serial);
            $fw_con->refreshSystemInfos();
            if( $util->debugAPI )
                $fw_con->setShowApiCalls( $util->debugAPI );

            getXpathDisplay( $xpath, $util, $connector->serial);
        }
        else
        {
            $connector->refreshSystemInfos();
            getXpathDisplay( $xpath, $util, $connector->info_serial);
        }
    }
    elseif( $util->configType == 'panorama' )
    {
        $device_serials = $connector->panorama_getConnectedFirewallsSerials();

        $i=0;
        foreach( $device_serials as $child )
        {
            $fw_con = $connector->cloneForPanoramaManagedDevice($child['serial']);
            $fw_con->refreshSystemInfos();
            if( $util->debugAPI )
                $fw_con->setShowApiCalls( $util->debugAPI );

            $string = " - SERIAL: ".$child['serial'];
            $string .= "  -  ".$child['hostname']." - ";
            $string .= $fw_con->info_mgmtip;

            PH::print_stdout( $string );
            $i++;

            getXpathDisplay( $xpath, $util, $child['serial']);
        }
    }
}
else
    getXpathDisplay( $xpath, $util, "");





//use class
PH::print_stdout(PH::$JSON_TMP, false, "serials");
PH::$JSON_TMP = array();

$util->endOfScript();

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
########################################################################################################################
function getXpathDisplay( $xpath, $util, $serial)
{
    PH::$JSON_TMP[$serial]['serial'] = $serial;
    //check Xpath
    $xpathResult = DH::findXPath( $xpath, $util->xmlDoc);
    PH::print_stdout( "   * XPATH: ".$xpath );
    PH::$JSON_TMP[$serial]['xpath'] = $xpath;

    foreach( $xpathResult as $xpath1 )
    {
        $newdoc = new DOMDocument;
        $node = $newdoc->importNode($xpath1, true);
        $newdoc->appendChild($node);
        PH::print_stdout( "   * VALUE: ".$newdoc->saveXML( $newdoc->documentElement ) );
        PH::$JSON_TMP[$serial]['value'] = $newdoc->saveXML( $newdoc->documentElement );
    }

    if( count($xpathResult) == 0 )
    {
        PH::print_stdout( "   * VALUE: not set" );
        PH::$JSON_TMP[$serial]['value'] = "---";
    }


    PH::print_stdout( "" );
}