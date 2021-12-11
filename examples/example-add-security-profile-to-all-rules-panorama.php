<?php

/*****************************************************************************
 *
 *	This script will list all rules in DeviceGroup referenced in $targetDG
 * and force them into using profile group referenced in $targetProfile
 *
 *
*****************************************************************************/

// load PAN-OS-PHP library
require_once("../lib/pan_php_framework.php");

// input and output files
$origfile = "sample-configs/panorama-example.xml";
$outputfile = "output.xml";

$targetDG = 'Perimeter-FWs';
$targetProfile = 'Shared Production Profile';

// We're going to load a PANConf object (PANConf is for PANOS Firewall,
//	PanoramaConf is obviously for Panorama which is covered in another example)
$panc = new PanoramaConf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$dg = $panc->findDeviceGroup($targetDG);
if( $dg === null )
{
	derr("DeviceGroup {$targetDG} was not found ? Exit\n");
}

PH::print_stdout("" );
PH::print_stdout("***********************************************" );
PH::print_stdout("" );


// Going after each pre-Security rules to add a profile
foreach( $dg->securityRules->rules() as $rule )
{
    PH::print_stdout( "Rule '".$rule->name()."' modified" );
    $rule->setSecurityProfileGroup($targetProfile);
}


PH::print_stdout("" );
PH::print_stdout("***********************************************" );



$panc->save_to_file($outputfile);

//display some statistics
$panc->display_statistics();



//more debugging infos

memory_and_gc('end');



