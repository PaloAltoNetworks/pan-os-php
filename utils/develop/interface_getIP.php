<?php

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";


PH::print_stdout( "" );
PH::print_stdout( "***********************************************" );
PH::print_stdout( "************ interface getIP for specific Zone UTILITY ****************" );
PH::print_stdout( "" );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['zone'] = Array('niceName' => 'test', 'shortHelp' => 'zone filter for interface information');
$supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[Panorama-MGMT-IP] [zone] " .
    "
     - for Firewalls where Interfaces or other config is from Panorama Device-Group / Template please use in=api://FW-MGMT-ip/merged-config";

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();
$util->load_config();

#if( $util->pan->isFirewall() )
#    derr( "only PAN-OS Panorama is supported" );

if( !$util->apiMode )
    derr( "only PAN-OS API connection is supported" );

$inputConnector = $util->pan->connector;
$cycleConnectedFirewalls = FALSE;

if( isset(PH::$args['cycleconnectedfirewalls']) )
    $cycleConnectedFirewalls = TRUE;

if( isset(PH::$args['zone']) )
    $zoneName = PH::$args['zone'];
else
    derr( "argument 'zone' missing" );

$array = array();

if( $cycleConnectedFirewalls && $util->pan->isPanorama() )
{
    $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();

    foreach( $firewallSerials as $fw )
    {
        $argv = array();
        $argc = array();
        PH::$args = array();
        PH::$argv = array();

        $argv[0] = "test";
        $argv[] = "in=api://".$fw['serial']."@".$inputConnector->info_mgmtip."/merged-config";

        #PH::resetCliArgs( $argv );
        $util2 = new UTIL("custom", $argv, $argc, __FILE__);
        $util2->utilInit();
        $util2->load_config();

        getIntIP( $util2->pan, $zoneName, $array );
    }
}
elseif( $util->pan->isFirewall() )
{
    $pan = $util->pan;

    getIntIP( $util->pan, $zoneName, $array );
}

PH::print_stdout( "--------------------------------------------------------------------------------" );
PH::print_stdout( "--------------------------------------------------------------------------------" );
PH::print_stdout( "--------------------------------------------------------------------------------" );
#print json_encode( $array, JSON_PRETTY_PRINT );
#print_r( $array );
foreach( $array as $device => $interface )
{
    foreach( $interface as $int )
        PH::print_stdout( $device.",".$int['name'].",".$int['ip'] );
}




function getIntIP( $pan, $zoneName, &$array )
{
    /** @var PANConf $pan */
    $inputConnector = $pan->connector;

    $inputConnector->refreshSystemInfos( true );

    $vsys = $pan->findVirtualSystem("vsys1");
    $zoneInternet = $vsys->zoneStore->find($zoneName);

    if( $zoneInternet === null )
        derr( "Zone: ".$zoneName." not found\n", null, false );

    $zoneInterfaces = $zoneInternet->attachedInterfaces->getAll();
    #print "count: ".count($zoneInterfaces)."\n";
    foreach( $zoneInterfaces as $zoneInterface )
    {
        $ip_info = "---";

        /** @var EthernetInterface $zoneInterface */
        if( $zoneInterface->isEthernetType() )
        {
            $IP = $zoneInterface->getLayer3IPAddresses();
            if( isset( $IP[0] ) )
                $ip_info = $IP[0];
        }

        $array[ $inputConnector->info_hostname ][ $zoneInterface->name() ]['name'] = $zoneInterface->name();
        $array[ $inputConnector->info_hostname ][ $zoneInterface->name() ]['ip'] = $ip_info;

        PH::print_stdout( "" );
        PH::print_stdout( $inputConnector->info_hostname.",".$zoneInterface->name().",".$ip_info );
        PH::print_stdout( "--------------------------------------------------------------------------------" );
    }
}