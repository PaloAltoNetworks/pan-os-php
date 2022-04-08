<?php

// load 'PAN Configurator' library
require_once("../lib/pan_php_framework.php");

/***************************************************************

 

****************************************************************/


// input and ouput xml files
$inputfile = 'sample-configs/panorama-example.xml';
$outputfile = 'output.xml';


// Create a new PanoramaConf object
$p = new PanoramaConf();
// and load it from a XML file
$p->load_from_file($inputfile);

PH::print_stdout();
PH::print_stdout("***********************************************" );
PH::print_stdout();



// variable to count unused objects
$countUnused = 0;

// we put all central stores in an array

// first the Shared one
$centralstores[] = $p->addressStore;

foreach( $p->deviceGroups as $dv )
	$centralstores[] = $dv->addressStore;


foreach( $centralstores as $store )
{
    PH::print_stdout( "-- Handling store '".$store->toString()."'" );
	$objects = $store->all();

	foreach( $objects as $o)
	{
		$classname = get_class($o);
		if( $classname == "Address" )
		{
			// If it's a tmp object , we ignore it
			if( $o->isTmpAddr() )
			{
				continue;
			}
			if( $o->countReferences() == 0 )
			{
                PH::print_stdout( "unused object found: ".$o->toString() );
				$countUnused++;
			}
		}
		elseif( $classname == "AddressGroup" )
		{
			if( $o->countReferences() == 0 )
			{
                PH::print_stdout( "unused object found: ".$o->toString() );
				$countUnused++;
			}
		}
		else
			derr("this class of object is not supported!");
	}

    PH::print_stdout();
}

PH::print_stdout();
PH::print_stdout();
PH::print_stdout( "Found $countUnused unused objects");
PH::print_stdout();

// display some statiscs for debug and exit program!
PH::print_stdout();
PH::print_stdout();
PH::print_stdout("***********************************************" );
$p->display_statistics();



