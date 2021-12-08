<?php
/**
 * Created by PhpStorm.
 * User: swaschkut
 * Date: 4/19/16
 * Time: 9:12 AM
 */


print "\n***********************************************\n";
print "************ CREATE-INTERFACE UTILITY ****************\n\n";


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
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
    "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n" .
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


///////////////////////////////////////////////////////

$sub = $pan->findVirtualSystem($util->objectsLocation);

$zone_array = array();



$tmp_ip = "192.168";

$tmp_ethernetIf = $pan->network->ethernetIfStore->findOrCreate( 'ethernet1/1' );

//validate interface type; only layer3 is working


//TODO: findings
// max. 255 secondary IP addresses are allowed

for( $i = 1; $i<10; $i++ )
{
    for( $ii = 1; $ii<50; $ii++ )
    {
        //IP   A.B.C.D => A.B. == 192.168
        //C => i
        //D => ii
        $IP = $tmp_ip .".". $i .".". $ii . "/32";
        print "add IP: " . $IP . " to ethernet Interface: " . $tmp_ethernetIf->name() . "\n";


        if( $util->configInput['type'] == 'api' )
        {
            $tmp_ethernetIf->API_addIPv4Address($IP);
        }
        else
        {
            $tmp_ethernetIf->addIPv4Address($IP);
        }
    }
}


##############################################

print "\n\n\n";

// save our work !!!
$util->save_our_work();



print "\n\n************ END OF CREATE-INTERFACE UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
