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

$fullxpath = false;


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['nodefilter'] = Array('niceName' => 'nodefilter', 'shortHelp' => 'specify the nodefilter to get all xPath within this configuration file');
$supportedArguments['fullxpath'] = Array('niceName' => 'fullxpath', 'shortHelp' => 'display full xpath for templates');

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

/** @var PANConf|PanoramaConf|FawkesConf $pan */
$pan = $util->pan;
$connector = $pan->connector;

$xmldoc = $util->pan->xmldoc;

########################################################################################################################

if( !isset( PH::$args['nodefilter'] ) )
    $util->display_error_usage_exit('"nodefilter" argument is not set: example "certificate"');
else
    $qualifiedNodeName = PH::$args['nodefilter'];

if( isset( PH::$args['fullxpath'] ) )
    $fullxpath = true;

########################################################################################################################


$nodeList = $xmldoc->getElementsByTagName($qualifiedNodeName);
$nodeArray = iterator_to_array($nodeList);

$templateEntryArray = array();
foreach( $nodeArray as $item )
{
    $text = DH::elementToPanXPath( $item );
    $replace_template = "/config/devices/entry[@name='localhost.localdomain']/template/";

    if( strpos( $text, $replace_template ) !== FALSE )
    {
        $tmpArray['xpath'] = $text;
        $text = str_replace( $replace_template, "", $text );


        $templateXpathArray = explode( "/", $text );
        //"entry[@name='CALEPA-TMS-PAN_Template01']"
        $templateName = str_replace( "entry[@name='", "", $templateXpathArray[0] );
        $templateName = str_replace( "']", "", $templateName );

        $replace = "entry[@name='".$templateName."']";
        $text = str_replace( $replace, "", $text );

        $tmpArray['text'] = $text;

        $templateEntryArray[ 'template'][ $templateName ][] = $tmpArray;

    }
    else
        $templateEntryArray[ 'misc'][] = $text;
}


    if( isset( $templateEntryArray['template'] ) )
    {
        foreach( $templateEntryArray['template'] as $templateName => $templateEntry )
        {
            PH::print_stdout( "" );
            PH::print_stdout( "TEMPLATE: ".$templateName );
            foreach( $templateEntry as $item )
            {
                PH::print_stdout( "  - ". $item['text'] );
                if( $fullxpath )
                    PH::print_stdout( "     |". $item['xpath']."|" );
            }

        }
    }

    if( isset( $templateEntryArray['misc'] ) )
    {
        PH::print_stdout( "MISC:" );

        foreach( $templateEntryArray['misc'] as $miscEntry )
        {
                PH::print_stdout( "  - ". $miscEntry );
        }
    }


    PH::print_stdout( "" );





$util->endOfScript();

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
########################################################################################################################