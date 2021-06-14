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


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

require_once dirname(__FILE__)."/../utils/lib/UTIL.php";


$actions = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['cmd'] = array('niceName' => 'cmd', 'shortHelp' => 'PAN-OS XML API - command');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['shadow-json'] = array('niceName' => 'shadow-JSON', 'shortHelp' => 'print out ONLY JSON string');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api://[MGMT-IP] [cycleconnectedFirewalls] [actions=enable]";

if( !PH::$shadow_json )
{
    print "\n********************************************************\n";
    print "************ PAN OP - XML to JSON UTILITY ****************\n\n";
}

$util = new UTIL("custom", $argv, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################
#$util->load_config();
#$util->location_filter();
#$pan = $util->pan;

#$xmlDoc = $util->xmlDoc;
$configInput = $util->configInput;


$connector = $util->pan->connector;

if( isset(PH::$args['cmd'] ) )
{
    $cmd = PH::$args['cmd'];

    if( $configInput['type'] == 'api' )
    {
        $response = $connector->sendOpRequest($cmd, FALSE);

        $response->preserveWhiteSpace = false;
        $response->formatOutput = true;

        $xml_string = $response->saveXML($response->documentElement);
    }
    else
    {
        $xml_string = "<response status=\"error\"><error>pan-os-php - this script is working only in API mode</error></response>";
    }
}
else
    $xml_string = "<response status=\"error\"><error>pan-os-php - cmd argument not found</error></response>";


if( !PH::$shadow_json )
{
    print "\n\n\n";
    print "XML response: \n";
    print $xml_string . "\n";
}

$xml = simplexml_load_string($xml_string);
$json =  json_encode($xml, JSON_PRETTY_PRINT);

if( !PH::$shadow_json )
{
    print "\n\n\n";
    print "JSON:\n";
}
print $json;


##########################################
##########################################
if( !PH::$shadow_json )
{
    print "\n\n\n";
}

$util->save_our_work();

if( !PH::$shadow_json )
{
    print "\n\n************ END PAN OP - XML to JSON UTILITY ************\n";
    print     "**********************************************************\n";
    print "\n\n";
}
