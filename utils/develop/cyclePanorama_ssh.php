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
PH::print_stdout( "************ cycle Panorama ssh-connector UTILITY ****************" );
PH::print_stdout();


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['command'] = Array('niceName' => 'test', 'shortHelp' => 'cli command');
$supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');
$supportedArguments['user'] = Array('niceName' => 'user', 'shortHelp' => 'user');
$supportedArguments['password'] = Array('niceName' => 'password', 'shortHelp' => 'password');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[Panorama-MGMT-IP] [command] " .
    "
     - send CLI command via Panorama to all connected firewalls, by using argument cycleconnectedfirewalls";

$mainPanoramaIP = "";
$user = "";
$password = "";

try
{

    $util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);
    #$util->useException();
    $util->utilInit();
    #$util->load_config();



    $mainPanoramaIP = PH::$args['in'];
    $tmp = explode("api://", $mainPanoramaIP);
    $mainPanoramaIP = $tmp[1];
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
$cycleConnectedFirewalls = TRUE;

if( isset(PH::$args['command']) )

if( isset(PH::$args['cycleconnectedfirewalls']) )
    $cycleConnectedFirewalls = TRUE;

if( isset(PH::$args['command']) )
    $command = PH::$args['command'];
else
    derr( "argument 'command' missing" );

if( isset(PH::$args['out']) )
    $outputfile = PH::$args['out'];
else
    derr( "argument 'out' missing" );

if( isset(PH::$args['user']) )
    $user = PH::$args['user'];
else
    derr( "argument 'user' missing" );

if( isset(PH::$args['password']) )
    $password = PH::$args['password'];
else
    derr( "argument 'password' missing" );

$array = array();

if( $cycleConnectedFirewalls && $util->pan->isPanorama() )
{
    $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();


    foreach( $firewallSerials as $fw )
    {
        ssh_connector($fw, $user, $password, $outputfile);
    }
}
elseif( $util->pan->isFirewall() )
{
    #$mgmt
    #ssh_connector($fw);
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


function ssh_connector($fw, $user, $password, $outputfile)
{
    $argv = array();
    $argc = array();
    PH::$args = array();
    PH::$argv = array();


    $argv[0] = "test";
    $argv[] = "in=".$user."@".$fw['ip-address'];
    $argv[] = "out=".$outputfile;
    $argv[] = "command=show system info";
    $argv[] = "password=".$password;
    $argv[] = "timeout=10";

    PH::print_stdout( "--------------------------------------------------------------------------------" );

    try
    {
        $util2 = new SSH_CONNECTOR__("ssh-connector", $argv, $argc, __FILE__);
        $util2->useException();
    }
    catch(Exception $e)
    {
        PH::print_stdout("          ***** API Error occured : ".$e->getMessage() );

        PH::print_stdout();
        PH::print_stdout( "--------------------------------------------------------------------------------" );
    }
}

