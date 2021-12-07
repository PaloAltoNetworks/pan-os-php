<?php

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
#$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');


########################################################################
########################################################################

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
    "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n" .
    "php ".basename(__FILE__)." help          : more help messages\n";

##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

$pan = $util->pan;
$inputConnector = $pan->connector;



if( $util->configInput['type'] !== 'api' )
    derr('only API connection supported');

########################################################################################################################
$inputConnector->refreshSystemInfos();

print "\n\n##########################################\n";

if( $util->configType == 'panorama' )
{
    print 'PANORAMA serial: '.$inputConnector->info_serial."\n\n";


    $config_pan_candidate = $inputConnector->getCandidateConfig();
    $config_pan_candidate->save( $inputConnector->info_serial."_PANORAMA.xml" );


########################################################################################################################
    $device_serials = $inputConnector->panorama_getConnectedFirewallsSerials();

    foreach( $device_serials as $child )
    {
        print "##########################################\n";

        $fw_con = $inputConnector->cloneForPanoramaManagedDevice($child['serial']);
        $fw_con->refreshSystemInfos();
        $fw_con->setShowApiCalls($debugAPI);

        downloadFWconfig( $fw_con, $child['hostname'] );
    }
}
elseif( $util->configType == 'panos' )
{
    #print 'PANOS serial: '.$inputConnector->info_serial."\n\n";

    downloadFWconfig( $inputConnector, $inputConnector->info_hostname );
}



print "\n\n##########################################\n";

function downloadFWconfig( $fw_con, $hostname)
{
    print 'FIREWALL serial: ' . $fw_con->info_serial . "\n\n";

    $config_candidate = $fw_con->getCandidateConfig();
    ##########SAVE config
    $pan = new PANConf();
    $pan->load_from_domxml($config_candidate);
    $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW.xml");



    $config_pushed = $fw_con->getPanoramaPushedConfig();
    if( $config_pushed->nodeType == XML_DOCUMENT_NODE )
        $found = DH::findFirstElement('config', $config_pushed);

    if( $found !== false )
    {
        ##########SAVE config
        $pan = new PANConf();
        $pan->load_from_domxml($config_pushed);
        $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW_panorama-pushed.xml");
    }

}