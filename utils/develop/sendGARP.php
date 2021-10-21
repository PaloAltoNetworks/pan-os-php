<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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



###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ gratuitous ARP UTILITY ****************\n\n";


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

require_once dirname(__FILE__)."/../../phpseclib/Net/SSH2.php";
require_once dirname(__FILE__)."/../../phpseclib/Crypt/RSA.php";



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['user'] = array('niceName' => 'user', 'shortHelp' => 'can be used in combination with "add" argument to use specific Username provided as an argument.', 'argDesc' => '[USERNAME]');
$supportedArguments['pw'] = array('niceName' => 'pw', 'shortHelp' => 'can be used in combination with "add" argument to use specific Password provided as an argument.', 'argDesc' => '[PASSWORD]');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] file=[csv_text file] [out=]";

PH::processCliArgs();

if( isset(PH::$args['in']) )
{
    $configInput = PH::$args['in'];
    $configInput = str_replace( "api://", "", $configInput);
}
else
    derr( "argument 'in' is needed" );

if( isset(PH::$args['user']) )
    $user = PH::$args['user'];
else
    derr( "argument 'user' is needed" );

if( isset(PH::$args['pw']) )
    $password = PH::$args['pw'];
else
    derr( "argument 'pw' is needed" );

$argv2 = array();
PH::$args = array();
PH::$argv = array();
$argv2[] = "key-manager";
$argv2[] = "add=".$configInput;
$argv2[] = "user=".$user;
$argv2[] = "pw=".$password;
$argc2 = count($argv2);


$util = new KEYMANGER( "key-manager", $argv2, $argc2, __FILE__ );

PH::$args = array();
PH::$argv = array();



$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments );
$util->utilInit();
$util->load_config();

if( !$util->pan->isFirewall() )
    derr( "only PAN-OS FW is supported" );

$inputConnector = $util->pan->connector;



#$cmd = "<show><interface>all</interface></show>";
#$response = $inputConnector->sendOpRequest( $cmd );
##$xmlDoc = new DOMDocument();
##$xmlDoc->loadXML($response);
##echo $response->saveXML();

$interfaces = $util->pan->network->getAllInterfaces();
$commands = array();
$interfaceIP = array();

foreach($interfaces as $int)
{
    /** @var EthernetInterface $int */
    $name = $int->name();

    if( $int->type() !== "layer2" )
        $ips = $int->getLayer3IPAddresses();
    else
        $ips = array();

    foreach( $ips as $key => $ip )
    {
        $intIP = explode("/",$ip );
        $intIP = $intIP[0];

        if( $key == 0)
            $interfaceIP[ $name ] = $intIP;
        $commands[] = "test arp gratuitous ip ".$intIP." interface ".$name;
    }
}




$cmd = "<show><arp><entry name = 'all'/></arp></show>";
$response = $inputConnector->sendOpRequest( $cmd );
#$xmlDoc = new DOMDocument();
#$xmlDoc->loadXML($response);
#echo $response->saveXML();

$result = DH::findFirstElement( "result", $response);
$entries = DH::findFirstElement( "entries", $result);
foreach( $entries->childNodes as $entry )
{
    if( $entry->nodeType != XML_ELEMENT_NODE )
        continue;

    $ip = DH::findFirstElement( "ip", $entry);
    $interface = DH::findFirstElement( "interface", $entry);

    $intIP = $interfaceIP[ $interface->textContent ];
    $intIP = explode("/",$intIP );
    $intIP = $intIP[0];

    $commands[] = "ping source ".$intIP." count 2 host ".$ip->textContent;
}


print_r( $commands );




##############################################
##############################################
$output_string = "";
$ssh = new RUNSSH( $configInput, $user, $password, $commands, $output_string );

print $output_string;
##############################################
##############################################

