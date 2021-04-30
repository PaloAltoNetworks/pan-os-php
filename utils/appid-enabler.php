<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";


function disable_appid($actions, $xmlDoc1, $configInput, $Connector)
{
    $tmp_application_status = DH::findXPath('/config/shared/application-status/entry', $xmlDoc1);

    if( $tmp_application_status->length == 0 )
    {
        //THIS is a NON available XPATH | TODO: swaschkut 20190115 validate it!!!
        $tmp_application_status = DH::findXPath('/config/devices/entry/vsys/entry/application-status/entry', $xmlDoc1);
        if( $tmp_application_status->length == 0 )
            print PH::boldText("\nNO disabled APP-IDs available\n");
    }


    foreach( $tmp_application_status as $app_status )
    {
        print "----------------\n";
        print "name: " . DH::findAttribute('name', $app_status) . "\n";


        if( $actions == 'display' )
            print " - status: " . DH::findAttribute('status', $app_status);
        elseif( $actions == 'enable' )
        {
            $apiArgs = array();
            $apiArgs['type'] = 'op';
            $apiArgs['cmd'] = '<request><set-application-status-recursive><application>' . DH::findAttribute('name', $app_status) . '</application><status>enabled</status></set-application-status-recursive></request>';

            if( $configInput['type'] == 'api' )
            {
                $response = $Connector->sendRequest($apiArgs);
                print " - status: enable";
            }
            else
            {
                //Todo: remove the entry in the XML, then offline mode should be supported
                derr("this script is working only in API mode\n");
            }

        }

        print "\n";
    }
}

$actions = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');
$supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each disabled app-id. ie: actions=display / actions=enable', 'argDesc' => 'action:arg1[,arg2]');

$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api://[MGMT-IP] [cycleconnectedFirewalls] [actions=enable]";

if( !PH::$shadow_json )
{
    print "\n***********************************************\n";
    print "************ APP-ID ENABLE UTILITY ****************\n\n";
}

$util = new UTIL("custom", $argv, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################

if( isset(PH::$args['cycleconnectedfirewalls']) )
    $cycleConnectedFirewalls = TRUE;
else
    $cycleConnectedFirewalls = FALSE;

if( !isset(PH::$args['actions']) || strtolower(PH::$args['actions']) == 'display' )
    $actions = 'display';
elseif( strtolower(PH::$args['actions']) == 'enable' )
    $actions = 'enable';

##########################################

if( $cycleConnectedFirewalls && $util->configType == 'panorama' )
{
    $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();

    $countFW = 0;
    foreach( $firewallSerials as $fw )
    {
        $countFW++;
        print " ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **\n";
        $tmpConnector = $inputConnector->cloneForPanoramaManagedDevice($fw['serial']);

        if( $debugAPI )
            $tmpConnector->setShowApiCalls(TRUE);
        $util->xmlDoc = $tmpConnector->getCandidateConfig();

        disable_appid($actions, $util->xmlDoc, $util->configInput, $tmpConnector);
    }
}
else
{
    $util->load_config();
    disable_appid($actions, $util->xmlDoc, $util->configInput, $util->pan->connector);
}

##########################################
##########################################
if( !PH::$shadow_json )
{
    print "\n\n\n";
}

$util->save_our_work();

if( !PH::$shadow_json )
{
    print "\n\n************ END OF APP-ID ENABLE UTILITY ************\n";
    print     "**************************************************\n";
    print "\n\n";
}
