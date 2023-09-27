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

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";


PH::print_stdout();
PH::print_stdout( "***********************************************" );
PH::print_stdout( "************ interface getIP for specific Zone UTILITY ****************" );
PH::print_stdout();


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['zone'] = Array('niceName' => 'test', 'shortHelp' => 'zone filter for interface information');
$supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[Panorama-MGMT-IP] [zone] " .
    "
     - for Firewalls where Interfaces or other config is from Panorama Device-Group / Template please use in=api://FW-MGMT-ip/merged-config";

try
{
    $util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);
    $util->useException();
    $util->utilInit();
    $util->load_config();
}
catch(Exception $e)
{
    PH::print_stdout("          ***** API Error occured : ".$e->getMessage() );
    exit();
}



#if( $util->pan->isFirewall() )
#    derr( "only PAN-OS Panorama is supported" );

if( !$util->apiMode )
    derr( "only PAN-OS API connection is supported" );

$inputConnector = $util->pan->connector;
$panoramaMGMTip = $inputConnector->info_mgmtip;
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
        //must be fixed value from above $panoramaMGMTip, if not ->refreshSystemInfos later on is updating to FW MGMT IP
        $argv[] = "in=api://".$fw['serial']."@".$panoramaMGMTip."/merged-config";

        PH::print_stdout( "--------------------------------------------------------------------------------" );

        try
        {
            #PH::resetCliArgs( $argv );
            $util2 = new UTIL("custom", $argv, $argc, __FILE__);
            $util2->useException();
            $util2->utilInit();
            $util2->load_config();

            getIntIP( $util2->pan, $zoneName, $array );
        }
        catch(Exception $e)
        {
            PH::print_stdout("          ***** API Error occured : ".$e->getMessage() );

            $array[ $fw['serial'] ][ "error" ]['name'] = "error";
            $array[ $fw['serial'] ][ "error" ]['ip'] = "connection";

            PH::print_stdout();
            PH::print_stdout( $fw['serial'].",error,connection" );
            PH::print_stdout( "--------------------------------------------------------------------------------" );
        }
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

if( PH::$shadow_json )
    print json_encode( $array, JSON_PRETTY_PRINT );
    #print json_encode( $array, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
else
{
    #print_r( $array );
    foreach( $array as $device => $interface )
    {
        foreach( $interface as $int )
            PH::print_stdout( $device.",".$int['name'].",".$int['ip'] );
    }
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

        PH::print_stdout();
        PH::print_stdout( $inputConnector->info_hostname.",".$zoneInterface->name().",".$ip_info );
        PH::print_stdout( "--------------------------------------------------------------------------------" );
    }
}