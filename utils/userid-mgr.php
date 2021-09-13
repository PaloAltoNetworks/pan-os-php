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

PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() );

$debugAPI = FALSE;

$supportedArguments = array();
$supportedArguments[] = array('niceName' => 'Action', 'shortHelp' => 'type of action you want to perform against API', 'argDesc' => 'register|unregister|fakeregister');
$supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'the target PANOS device ie: in=api://1.2.3.4', 'argDesc' => 'api://[hostname or IP]');
$supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'defines the VSYS target of the UserID request', 'argDesc' => 'vsys1[,vsys2,...]');
$supportedArguments[] = array('niceName' => 'records', 'shortHelp' => 'list of userid records to register/unregister in API', 'argDesc' => '10.0.0.1,domain\user2/10.2.3.4,domain\user3');
$supportedArguments[] = array('niceName' => 'recordFile', 'shortHelp' => 'use a text file rather than CLI to input UserID records', 'argDesc' => 'users.txt');
$supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');

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
    $connector = $configInput['connector'];
    if( $debugAPI )
        $connector->setShowApiCalls(TRUE);
}
else
    derr('method not supported yet');
// </editor-fold>

PH::print_stdout( " - Connected to API at {$connector->apihost} / {$connector->info_hostname}");
PH::print_stdout( " - PANOS version: {$connector->info_PANOS_version}");
PH::print_stdout( " - PANOS model: {$connector->info_model}");
PH::print_stdout( "");


if( !isset(PH::$args['action']) )
    display_error_usage_exit("no 'action' was defined");

$location = 'vsys1';
if( !isset(PH::$args['location']) )
    PH::print_stdout( " - no 'location' was provided, using default VSYS1");
else
{
    $location = PH::$args['location'];
    PH::print_stdout( " - location '{$location}' was provided");
}


$action = strtolower(PH::$args['action']);

if( $action == 'register' || $action == 'unregister' )
{
    PH::print_stdout( " - action is '$action'");
    $records = array();

    if( isset(PH::$args['records']) )
    {
        PH::print_stdout( " - a list of 'records' was provided on CLI, now parsing it...");
        $explode = explode('/', PH::$args['records']);
        foreach( $explode as $record )
        {
            $lrecord = explode(',', $record);
            if( count($lrecord) != 2 )
                display_error_usage_exit("the following record does not have the right syntax: '{$record}'");
            $username = trim($lrecord[1]);
            $ipaddress = trim($lrecord[0]);

            if( strlen($username) < 1 )
                display_error_usage_exit("blank username in record '{$record}'");

            if( strlen($ipaddress) < 1 )
                display_error_usage_exit("blank IP in record '{$record}'");

            if( isset($records[$ipaddress]) && $records[$ipaddress] != $username )
                display_error_usage_exit("record '{$ipaddress}\\{$username}' conflicts with '{$ipaddress}\\{$records[$ipaddress]}'");

            if( !filter_var($ipaddress, FILTER_VALIDATE_IP) )
                display_error_usage_exit("IP address '{$ipaddress}' is not valid in record '{$record}'");

            $records[$ipaddress] = $username;
        }


    }
    elseif( isset(PH::$args['recordfile']) )
    {
        PH::print_stdout( " - record file was provided, now parsing it...");

        $explode = file_get_contents(PH::$args['recordfile']);
        $explode = explode("\n", $explode);

        foreach( $explode as $record )
        {
            if( strlen(trim($record)) < 1 )
                continue; // this is an empty line

            $lrecord = explode(',', $record);
            if( count($lrecord) != 2 )
                display_error_usage_exit("the following record does not have the right syntax: '{$record}'");
            $username = trim($lrecord[1]);
            $ipaddress = trim($lrecord[0]);

            if( strlen($username) < 1 )
                display_error_usage_exit("blank username in record '{$record}'");

            if( strlen($ipaddress) < 1 )
                display_error_usage_exit("blank IP in record '{$record}'");

            if( isset($records[$ipaddress]) && $records[$ipaddress] != $username )
                display_error_usage_exit("record '{$ipaddress}\\{$username}' conflicts with '{$ipaddress}\\{$records[$ipaddress]}'");

            if( !filter_var($ipaddress, FILTER_VALIDATE_IP) )
                display_error_usage_exit("IP address '{$ipaddress}' is not valid in record '{$record}'");

            $records[$ipaddress] = $username;
        }


    }
    else
        derr("you need to provide 'records' or 'recordfile' argument");

    $count = count($records);
    PH::print_stdout( " - found {$count} records:");
    foreach( $records as $ip => $user )
    {
        PH::print_stdout( "   - " . str_pad($ip, 16) . " / {$user}");
    }

    PH::print_stdout( " - now sending records to API ... ");
    if( $action == 'register' )
        $connector->userIDLogin(array_keys($records), $records, $location);
    else
        $connector->userIDLogout(array_keys($records), $records, $location);



}
elseif( $action == 'fakeregister' )
{
    $numberOfIPs = 500;
    $userPrefix = 'acme\\Bob_';
    $startingIP = ip2long('10.0.0.0');

    $records = array();


    PH::print_stdout( "  - Generating {$numberOfIPs} fake records starting at IP " . long2ip($startingIP) . "... ");
    for( $i = 1; $i <= $numberOfIPs; $i++ )
    {
        $records[long2ip($startingIP + $i)] = $userPrefix . $i;
    }



    PH::print_stdout( " - now sending records to API ... ");
    $connector->userIDLogin(array_keys($records), $records, $location);


}
else
    derr("action '{$action}' is not supported");


PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");

