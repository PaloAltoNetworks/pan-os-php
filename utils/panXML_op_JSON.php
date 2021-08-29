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
$supportedArguments['shadow-json'] = array('niceName' => 'shadow-JSON', 'shortHelp' => 'display ONLY JSON string');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for bpa generator');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api://[MGMT-IP] [cycleconnectedFirewalls] [actions=enable]";

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

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

if( isset(PH::$args['cycleconnectedfirewalls']) )
    $cycleConnectedFirewalls = TRUE;
else
    $cycleConnectedFirewalls = FALSE;

if( isset(PH::$args['cmd'] ) )
{
    $cmd = PH::$args['cmd'];

    if( $configInput['type'] == 'api' )
    {
        if( $cycleConnectedFirewalls && $configType == 'panorama' )
        {
            $xml_string = "";

            $firewallSerials = $connector->panorama_getConnectedFirewallsSerials();

            $countFW = 0;
            foreach( $firewallSerials as $fw )
            {
                $countFW++;
                PH::print_stdout( " ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **" );
                $tmpConnector = $inputConnector->cloneForPanoramaManagedDevice($fw['serial']);

                if( $util->debugAPI )
                    $tmpConnector->setShowApiCalls(TRUE);

                $response = $tmpConnector->sendOpRequest($cmd, FALSE);

                $response->preserveWhiteSpace = false;
                $response->formatOutput = true;

                $xml_string .= $response->saveXML($response->documentElement);
            }
        }
        else
        {
            $response = $connector->sendOpRequest($cmd, FALSE);

            $response->preserveWhiteSpace = false;
            $response->formatOutput = true;

            $xml_string = $response->saveXML($response->documentElement);
        }

    }
    else
    {
        $xml_string = "<response status=\"error\"><error>pan-os-php - this script is working only in API mode</error></response>";
    }
}
else
    $xml_string = "<response status=\"error\"><error>pan-os-php - cmd argument not found</error></response>";


PH::print_stdout("");
PH::print_stdout( "XML response:");
PH::print_stdout( $xml_string );

$xml = simplexml_load_string($xml_string);
$json =  json_encode($xml, JSON_PRETTY_PRINT);

PH::print_stdout("");
PH::print_stdout( "JSON:");
//this is the original JSON, so pring it out
print $json ;


##########################################
##########################################
PH::print_stdout("");

$util->save_our_work();

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
