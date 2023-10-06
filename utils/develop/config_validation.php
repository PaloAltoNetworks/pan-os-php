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
PH::print_stdout( "************ config validation UTILITY ****************" );
PH::print_stdout();


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['zonelist'] = Array('niceName' => 'test', 'shortHelp' => 'zonelist filter ');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1 or location={DGname}:excludeMaindg [only childDGs of {DGname}] or location={DGname}:includechilddgs [{DGname} + all childDGs]', 'argDesc' => 'sub1[,sub2]');
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

    $util->location_filter();
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

$argument = array();
if( isset(PH::$args['zonelist']) )
    $argument = explode( ",", PH::$args['zonelist']);

else
    derr( "argument 'argument' missing" );


$array = array();

if( $cycleConnectedFirewalls && $util->pan->isPanorama() )
{
    #print_r($util->objectsLocation);

    $devices_array = array();
    if( count($util->objectsLocation) == 1 )
    {
        $dg = $util->pan->findDeviceGroup($util->objectsLocation[0]);
        $devices_array = $dg->getDevicesInGroup(true);
    }
    else
    {
        foreach( $util->objectsLocation as $location )
        {
            $dg = $util->pan->findDeviceGroup($location);
            $tmp_devices_array = $dg->getDevicesInGroup(false);
            $devices_array = array_merge( $devices_array, $tmp_devices_array );
        }
    }



    foreach($devices_array as $key => $device)
    {
        #print "name: ".$device['serial']."\n";
        #print "name: ".$key."\n";
        PH::print_stdout( "FW-serial: ".$device['serial']." in scope");
    }

    $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();

    foreach( $firewallSerials as $fw )
    {
        if( !in_array( $fw['serial'], array_keys($devices_array)  ) )
        {
            #PH::print_stdout( "FW-serial: ".$fw['serial']." not in location scope - skipped");
            continue;
        }


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

            config_validation( $util2->pan, $argument, $array );
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

    config_validation( $util->pan, $argument, $array );
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
    foreach( $array as $device => $allvsys )
    {
        #print_r($allvsys);
        foreach( $allvsys as $vsys => $zones )
        {
            #print_r($zones);
            foreach( $zones as $key => $zone )
                PH::print_stdout( $device.",".$vsys.",".$zone );
        }
    }

}





function config_validation( $pan, $argument, &$array )
{
    $zone_array = $argument;

    /** @var PANConf $pan */
    $inputConnector2 = $pan->connector;

    $inputConnector2->refreshSystemInfos( true );

    //todo: what about multi-vsys?
    #$vsys = $pan->findVirtualSystem("vsys1");
    $all_vsys = $pan->getVirtualSystems();
    foreach($all_vsys as $vsys)
    {
        foreach( $zone_array as $zoneName )
        {
            $zoneInternet = $vsys->zoneStore->find($zoneName);

            if( $zoneInternet === null )
            {
                $array[ $inputConnector2->info_hostname ][ $vsys->name() ][] = $zoneName;

                PH::print_stdout();
                PH::print_stdout( $inputConnector2->info_hostname.", ".$vsys->name().", ".$zoneName." not available" );
                PH::print_stdout( "--------------------------------------------------------------------------------" );
            }
        }
    }
}