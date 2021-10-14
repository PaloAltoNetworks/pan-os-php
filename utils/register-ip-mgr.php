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

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");


$supportedArguments = array();
$supportedArguments[] = array('niceName' => 'Actions', 'shortHelp' => 'type of action you want to perform against API', 'argDesc' => 'display');
$supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'the target PANOS device ie: in=api://1.2.3.4', 'argDesc' => 'api://[hostname or IP]');
$supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'defines the VSYS target of the UserID request', 'argDesc' => 'vsys1[,vsys2,...]');
$supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');


$supportedArguments[] = array('niceName' => 'records', 'shortHelp' => 'list of userid records to register/unregister in API', 'argDesc' => '10.0.0.1,domain\user2/10.2.3.4,domain\user3');
$supportedArguments[] = array('niceName' => 'recordFile', 'shortHelp' => 'use a text file rather than CLI to input UserID records', 'argDesc' => 'users.txt');


$usageMsg = PH::boldText('USAGE EXAMPLES: ') . "\n - php " . basename(__FILE__) . " in=api://1.2.3.4 action=register location=vsys1 records=10.0.0.1,domain\\user2/10.2.3.4,domain\\user3"
    . "\n - php " . basename(__FILE__) . " in=api://1.2.3.4 action=register location=vsys1 recordFile=users.txt";



$util = new UTIL("custom", $argv, __FILE__, $supportedArguments, $usageMsg);

$util->prepareSupportedArgumentsArray();

$util->utilInit();


$util->inDebugapiArgument();

$util->inputValidation();

$util->location_provided();


PH::print_stdout( " - Connected to API at {$util->pan->connector->apihost} / {$util->pan->connector->info_hostname}");
PH::print_stdout( " - PANOS version: {$util->pan->connector->info_PANOS_version}");
PH::print_stdout( " - PANOS model: {$util->pan->connector->info_model}");
PH::print_stdout( "");


if( !isset(PH::$args['actions']) )
    display_error_usage_exit("no 'action' was defined");


$action = strtolower(PH::$args['actions']);

if( $action == 'display' || $action == 'unregister-unused' )
{
    PH::print_stdout( " - action is '$action'");
    PH::print_stdout( "");

    $unregister_array = array();

    $util->pan->load_from_domxml($util->xmlDoc);

    if( $util->configType == 'panos' )
        $virtualsystems = $util->pan->getVirtualSystems();
    elseif( $util->configType == 'panorama' )
        $virtualsystems = $util->pan->getDeviceGroups();



    foreach( $virtualsystems as $sub )
    {
        $unregister_array[$sub->name()] = array();

        PH::print_stdout( "##################################" );
        PH::print_stdout( PH::boldText(" - " . $sub->name() ) );

        $register_ip_array = $util->pan->connector->register_getIp($sub->name());
        PH::print_stdout( "     - registered-ips: [" . count($register_ip_array) . "]");

        foreach( $register_ip_array as $ip => $reg )
        {
            $first_value = reset($reg); // First Element's Value
            $first_key = key($reg); // First Element's Key

            PH::print_stdout( "          " . $ip . " - " . $first_key );
        }

        if( $util->configType == 'panos' )
            $vsys = $util->pan->findVirtualSystem($sub->name());
        else
            $vsys = $sub;

        $address_groups = $vsys->addressStore->addressGroups();

        $shared_address_groups = $util->pan->addressStore->addressGroups();

        $address_groups = array_merge($shared_address_groups, $address_groups);
        PH::print_stdout( "     - DAGs: ");

        $dynamicAddressGroup_array = array();
        foreach( $address_groups as $addressGroup )
        {
            if( $addressGroup->isDynamic() )
            {
                $tags = $addressGroup->tags->tags();

                PH::print_stdout( "          " . $addressGroup->name() . " filter: " . $addressGroup->filter );

                $dynamicAddressGroup_array = $util->pan->connector->dynamicAddressGroup_get( $sub->name(), $util->configType );
                if( isset($dynamicAddressGroup_array[$addressGroup->name()]) )
                {
                    foreach( $dynamicAddressGroup_array[$addressGroup->name()] as $key => $members )
                    {
                        if( $key != 'name' )
                            PH::print_stdout( "           - " . $key );
                    }
                }
            }
        }


        PH::print_stdout( "----------------------------------");
        PH::print_stdout( "VALIDATION:");

        if( empty($register_ip_array) )
        {
            PH::print_stdout( "nothing registered");
        }
        else
        {
            foreach( $register_ip_array as $ip => $reg )
            {
                $first_value = reset($reg); // First Element's Value
                $first_key = key($reg); // First Element's Key

                if( empty($dynamicAddressGroup_array) )
                {
                    $unregister_array[$sub->name()][$ip] = $reg;
                    #PH::print_stdout( "unregister: ".$ip );
                }

                foreach( $dynamicAddressGroup_array as $key => $group )
                {
                    #PH::print_stdout( "KEY: ".$key );
                    #print_r( $group );
                    if( !isset($group[$ip]) )
                    {
                        $unregister_array[$sub->name()][$ip] = $reg;
                        #PH::print_stdout( "unregister: ".$ip );
                    }
                    else
                    {
                        #PH::print_stdout( "unset: ".$ip );
                        unset($unregister_array[$sub->name()][$ip]);
                        break;
                    }
                }
            }
        }


        PH::print_stdout( "possible IPs for UNREGISTER:");
        #print_r( $unregister_array );
        foreach( $unregister_array[$sub->name()] as $unregister_ip => $tags )
        {
            PH::print_stdout( " - " . $unregister_ip );
        }

        PH::print_stdout( "DAGs can be deleted (because they are not used in Ruleset):" );
        foreach( $dynamicAddressGroup_array as $key => $group )
        {
            if( count($group) <= 1 )
                PH::print_stdout( " - " . $key );
        }
    }
}
elseif( $action == 'fakeregister' )
{
    $numberOfIPs = 20;
    $tag = 'fake';
    $startingIP = ip2long('10.0.0.0');

    $records = array();


    PH::print_stdout( "  - Generating {$numberOfIPs} fake records starting at IP " . long2ip($startingIP) . "... " );
    for( $i = 1; $i <= $numberOfIPs; $i++ )
    {
        $records[long2ip($startingIP + $i)] = array($tag);
    }

    PH::print_stdout( " - now sending records to API ... ");
    $util->pan->connector->register_sendUpdate($records, null, 'vsys1');
}
else
    derr("action '{$action}' is not supported");


if( $action == 'unregister-unused' )
{
    foreach( $virtualsystems as $sub )
    {
        PH::print_stdout( " - now sending records to API ... ");
        $util->pan->connector->register_sendUpdate(null, $unregister_array[$sub->name()], $sub->name());
    }
}


PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
