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
require_once(dirname(__FILE__) . '/common/misc.php');


PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

$debugAPI = FALSE;

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

prepareSupportedArgumentsArray($supportedArguments);

PH::processCliArgs();

// check that only supported arguments were provided
foreach( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
        display_error_usage_exit("unsupported argument provided: '$index'");
}

if( isset(PH::$args['help']) )
    display_usage_and_exit();


if( !isset(PH::$args['in']) )
    display_error_usage_exit(' "in=" argument is missing');


if( isset(PH::$args['debugapi']) )
{
    $debugAPI = TRUE;
}

//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod(PH::$args['in'], TRUE);
$xmlDoc = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");
    exit(1);
}


/** @var PanAPIConnector $connector */
$connector = null;

if( $configInput['type'] == 'file' )
{
    derr("Only API method is supported for input, please fix your 'in' argument");

}
elseif( $configInput['type'] == 'api' )
{
    if( $debugAPI )
        $configInput['connector']->setShowApiCalls(TRUE);
    PH::print_stdout( " - Downloading config from API... ");
    $xmlDoc = $configInput['connector']->getCandidateConfig();

}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult = DH::findXPath('/config/devices/entry/vsys', $xmlDoc);
if( $xpathResult === FALSE )
    derr('XPath error happened');
if( $xpathResult->length < 1 )
    $configType = 'panorama';
else
    $configType = 'panos';
unset($xpathResult);


if( $configType == 'panos' )
    $pan = new PANConf();
else
    $pan = new PanoramaConf();

PH::print_stdout( " - Detected platform type is '{$configType}'");

if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];
$connector = $pan->connector;
// </editor-fold>

// </editor-fold>

PH::print_stdout( " - Connected to API at {$connector->apihost} / {$connector->info_hostname}");
PH::print_stdout( " - PANOS version: {$connector->info_PANOS_version}");
PH::print_stdout( " - PANOS model: {$connector->info_model}");
PH::print_stdout( "");


if( !isset(PH::$args['actions']) )
    display_error_usage_exit("no 'action' was defined");

$location = 'vsys1';
if( !isset(PH::$args['location']) )
    PH::print_stdout( " - no 'location' was provided, using default VSYS1");
else
{
    $location = PH::$args['location'];
    PH::print_stdout( " - location '{$location}' was provided");
}

#if( $configType != 'panos' )
#    derr( "This Tool is made for PANOS - Panorama is not working" );


$action = strtolower(PH::$args['actions']);

if( $action == 'display' || $action == 'unregister-unused' )
{
    PH::print_stdout( " - action is '$action'");
    PH::print_stdout( "");

    $unregister_array = array();

    $pan->load_from_domxml($xmlDoc);

    if( $configType == 'panos' )
        $virtualsystems = $pan->getVirtualSystems();
    elseif( $configType == 'panorama' )
        $virtualsystems = $pan->getDeviceGroups();



    foreach( $virtualsystems as $sub )
    {
        $unregister_array[$sub->name()] = array();

        PH::print_stdout( "##################################" );
        PH::print_stdout( PH::boldText(" - " . $sub->name() ) );

        $register_ip_array = $connector->register_getIp($sub->name());
        PH::print_stdout( "     - registered-ips: [" . count($register_ip_array) . "]");

        foreach( $register_ip_array as $ip => $reg )
        {
            $first_value = reset($reg); // First Element's Value
            $first_key = key($reg); // First Element's Key

            PH::print_stdout( "          " . $ip . " - " . $first_key );
        }

        if( $configType == 'panos' )
            $vsys = $pan->findVirtualSystem($sub->name());
        else
            $vsys = $sub;

        $address_groups = $vsys->addressStore->addressGroups();

        $shared_address_groups = $pan->addressStore->addressGroups();

        $address_groups = array_merge($shared_address_groups, $address_groups);
        PH::print_stdout( "     - DAGs: ");
        /*
        foreach( $shared_address_groups as $addressGroup)
        {
            if( $addressGroup->isDynamic() )
            {
                PH::print_stdout( "          ".$addressGroup->name()." filter: ".$addressGroup->filter );
            }
        }
        */
        $dynamicAddressGroup_array = array();
        foreach( $address_groups as $addressGroup )
        {
            if( $addressGroup->isDynamic() )
            {
                $tags = $addressGroup->tags->tags();

                PH::print_stdout( "          " . $addressGroup->name() . " filter: " . $addressGroup->filter );

                $dynamicAddressGroup_array = $connector->dynamicAddressGroup_get( $sub->name(), $configType );
                if( isset($dynamicAddressGroup_array[$addressGroup->name()]) )
                    foreach( $dynamicAddressGroup_array[$addressGroup->name()] as $key => $members )
                    {
                        if( $key != 'name' )
                        {
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
            #PH::print_stdout( "which registered-ip can be deleted because:");
            #PH::print_stdout( "  - no DAG for tag is available");
            #PH::print_stdout( "  - DAG is not used, so no registered-ip for DAG");


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
    $connector->register_sendUpdate($records, null, 'vsys1');


}
else
    derr("action '{$action}' is not supported");


if( $action == 'unregister-unused' )
{
    foreach( $virtualsystems as $sub )
    {
        PH::print_stdout( " - now sending records to API ... ");
        $connector->register_sendUpdate(null, $unregister_array[$sub->name()], $sub->name());
    }
}


PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");

