<?php

/*****************************************************************************
*
*	 This script is doing basic use PAN-OS-PHP API.
*		
*	It will load a sample PANOS config and make some rules and object 
*	editing.
*
*****************************************************************************/

// load PAN-OS-PHP library
require_once("../lib/pan_php_framework.php");

// input and output files
$origfile = "sample-configs/panos-example-2.xml";
$outputfile = "output.xml";


// We're going to load a PANConf object (PANConf is for PANOS Firewall,
//	PanoramaConf is obviously for Panorama which is covered in another example)
$panc = new PANconf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$vsys1 = $panc->findVirtualSystem('vsys1');
if( $vsys1 === null )
{
	derr("vsys1 was not found ? Exit\n");
}

PH::print_stdout( "***********************************************" );

// look for an object named server-4-address
$addressObject = $vsys1->addressStore->find('server-4-address');
// display the list of objects that are using this
$addressObject->display_references();

PH::print_stdout();

// look for an object called client-2-address
$anotherObject = $vsys1->addressStore->find('client-2-address');
// display the list of objects that are using this
$anotherObject->display_references();

PH::print_stdout( "After replacement" );

// Let's replace this object by another one everywhere
$addressObject->replaceMeGlobally($anotherObject);

$addressObject->display_references();
PH::print_stdout();
$anotherObject->display_references();





PH::print_stdout( "\n***********************************************" );


//display some statistics
$vsys1->display_statistics();




//more debugging infos

memory_and_gc('end');


