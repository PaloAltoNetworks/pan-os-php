<?php
/********************************************************************************************
 
 	This sample script will connect to a live firewall and do some live changes. 

*********************************************************************************************/


// load 'PAN Configurator' library
require_once("../lib/pan_php_framework.php");
require_once "utils/lib/UTIL.php";

$argv = array();
$argv[] = basename(__FILE__);
$argv[] = "in=api://192.168.50.10";
$argv[] = "debugapi";

##################################################
# Template usage
##################################################
$supportedArguments = array();

$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] argument1 [optional_argument2]";


$util = new UTIL("custom", $argv, $argc,__FILE__, $supportedArguments, $usageMsg );

$util->utilInit();

$util->load_config();
$util->location_filter();


/** @var PANConf|PanoramaConf $pan */
$pan = $util->pan;


/** @var VirtualSystem|DeviceGroup $sub */
$sub = $util->sub;

/** @var string $location */
$location = $util->location;

/** @var boolean $apiMode */
$apiMode = $util->apiMode;

/** @var array $args */
$args = PH::$args;

##################################################################
##################################################################

// Did we find VSYS1 ?
$vsys1 = $pan->findVirtualSystem('vsys1');
if( $vsys1 === null )
{
	derr("vsys1 was not found ? Exit\n");
}

PH::print_stdout();
PH::print_stdout("***********************************************" );
PH::print_stdout();

//display rules
$vsys1->securityRules->display();

// look for an object named 'User-Networks'
$object = $vsys1->addressStore->find('User-Networks');
if( $object === null )
	derr("Error: object not found\n");

// want to know xpath of an object ?
PH::print_stdout("displaying XPATH of object named ".$object->name()." : ".$object->getXPath() );

// let's rename it in API
$object->API_setName('another-name');

$rule = $vsys1->securityRules->find('Mail Server');
if( $rule === null )
	derr("Error: rule nor found\n");

// add an object to this rule Source through API
$rule->source->API_add($object);

// set Destination to Any
$rule->destination->API_setAny();

// remove object from another rule Source
$rule = $vsys1->securityRules->find('Exception SSH for Dev');
if( $rule === null )
	derr("Error: rule nor found\n");
$rule->source->API_remove($object);

// uplaod config directly to the device !!!
//$panc->API_uploadConfig('test-config1.xml');


// display some statiscs for debug and exit program!
PH::print_stdout();
PH::print_stdout("***********************************************" );
$vsys1->display_statistics();



