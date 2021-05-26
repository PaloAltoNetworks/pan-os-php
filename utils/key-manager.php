<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


echo "\n***********************************************\n";
echo "*********** " . basename(__FILE__) . " UTILITY **************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once(dirname(__FILE__) . '/common/misc.php');


$supportedArguments = array();
$supportedArguments[] = array('niceName' => 'delete', 'shortHelp' => 'Clears API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = array('niceName' => 'add', 'shortHelp' => 'Adds API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = array('niceName' => 'test', 'shortHelp' => 'Tests API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = array('niceName' => 'apikey', 'shortHelp' => 'can be used in combination with add argument to use specific API key provided as an argument.', 'argDesc' => '[API Key]');
$supportedArguments[] = array('niceName' => 'hiddenpw', 'shortHelp' => 'Use this if the entered password should not be displayed.');
$supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');

$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " [delete=hostOrIP] [add=hostOrIP] [test=hostOrIP] [hiddenPW]";

prepareSupportedArgumentsArray($supportedArguments);
PH::processCliArgs();

// check that only supported arguments were provided
foreach( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

echo " - loading keystore from file in user home directory... ";
PanAPIConnector::loadConnectorsFromUserHome();
echo "OK!\n";

echo "\n";

$noArgProvided = TRUE;

if( isset(PH::$args['nohiddenpw']) )
    $hiddenPW = FALSE;
else
    $hiddenPW = TRUE;

if( isset(PH::$args['debugapi']) )
    $debugAPI = TRUE;
else
    $debugAPI = FALSE;

if( isset(PH::$args['delete']) )
{
    $noArgProvided = FALSE;
    $deleteHost = PH::$args['delete'];
    echo " - requested to delete Host/IP '{$deleteHost}'\n";
    if( !is_string($deleteHost) )
        derr("argument of 'delete' must be a string , wrong input provided");

    $foundConnector = FALSE;
    foreach( PanAPIConnector::$savedConnectors as $cIndex => $connector )
    {
        if( $connector->apihost == $deleteHost )
        {
            $foundConnector = TRUE;
            echo " - found and deleted\n\n";
            unset(PanAPIConnector::$savedConnectors[$cIndex]);
            PanAPIConnector::saveConnectorsToUserHome();
        }
    }
    if( !$foundConnector )
        echo "\n\n **WARNING** no host or IP named '{$deleteHost}' was found so it could not be deleted\n\n";
}

if( isset(PH::$args['add']) )
{
    $noArgProvided = FALSE;
    $addHost = PH::$args['add'];
    echo " - requested to add Host/IP '{$addHost}'\n";

    if( !isset(PH::$args['apikey']) )
        PanAPIConnector::findOrCreateConnectorFromHost($addHost, null, TRUE, TRUE, $hiddenPW, $debugAPI);
    else
        PanAPIConnector::findOrCreateConnectorFromHost($addHost, PH::$args['apikey']);
}

if( isset(PH::$args['test']) )
{
    $noArgProvided = FALSE;
    $checkHost = PH::$args['test'];

    if( $checkHost == 'any' || $checkHost == 'all' )
    {
        foreach( PanAPIConnector::$savedConnectors as $connector )
        {
            $checkHost = $connector->apihost;
            echo " - requested to test Host/IP '{$checkHost}'\n";

            PH::enableExceptionSupport();
            try
            {
                if( !isset(PH::$args['apikey']) )
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, null, TRUE, TRUE, $hiddenPW, $debugAPI);
                else
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, PH::$args['apikey']);

                $connector->testConnectivity();
            } catch(Exception $e)
            {
                PH::disableExceptionSupport();
                print "   ***** API Error occured : " . $e->getMessage() . "\n\n";
            }

            PH::disableExceptionSupport();
            print "\n";
        }
    }
    else
    {
        echo " - requested to test Host/IP '{$checkHost}'\n";
        if( !isset(PH::$args['apikey']) )
            $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, null, TRUE, TRUE, $hiddenPW, $debugAPI);
        else
            $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, PH::$args['apikey']);

        $connector->testConnectivity();

        print "\n";
    }
}

$keyCount = count(PanAPIConnector::$savedConnectors);
echo "Listing available keys:\n";

$connectorList = array();
foreach( PanAPIConnector::$savedConnectors as $connector )
{
    $connectorList[$connector->apihost] = $connector;
}
ksort($connectorList);

foreach( $connectorList as $connector )
{
    $key = $connector->apikey;
    if( strlen($key) > 24 )
        $key = substr($key, 0, 12) . '...' . substr($key, strlen($key) - 12);
    $host = str_pad($connector->apihost, 15, ' ', STR_PAD_RIGHT);

    echo " - Host {$host}: key={$key}\n";
}

if( $noArgProvided )
{
    print "\n";
    display_usage_and_exit();
}

echo "\n************* END OF SCRIPT " . basename(__FILE__) . " ************\n\n";



