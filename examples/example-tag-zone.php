<?php

// load 'PAN Configurator' library
require_once("../lib/pan_php_framework.php");

/********************************************************************************************
 
 	This sample script will look for all rules inside a Panorama config and search for
 	tags Outgoing or Incoming.
 	
 	When Outgoing is found, it will edit the rule to put FromZone = internal and
 							     ToZone = external
 							     
 	When Incoming is found, it will edit the rule to put FromZone = extern and
 							     ToZone = internal						     

*********************************************************************************************/



// input and ouput xml files
$inputfile = 'sample-configs/panorama-example.xml';
$outputfile = 'output.xml';


// Create a new PanoramaConf object
$p = new PanoramaConf();
// and load it from a XML file
$p->load_from_file($inputfile);
PH::print_stdout( "\n***********************************************" );


// below starts the real stuff

// we need to find references of Zones 'internal' and 'external'. they will be used later
$internal = $p->zoneStore->find('internal');
$external = $p->zoneStore->find('external');

if( !$internal )
	derr("We didn't find zone 'internal', is there a problem?");
if( !$external )
	derr("We didn't find zone 'external', is there a problem?");


// We are looking for a tag called "Outgoing" , to be used later, same for Incoming tag
$outgoing = $p->tagStore->find('Outgoing');
if( !$outgoing )
	derr("We didn't find tag Outgoing, is there a problem?");

// We are looking for a tag called "Incoming"
$incoming = $p->tagStore->find('Incoming');
if( !$incoming )
	derr("We didn't find tag Incoming, is there a problem?");


/*****************************************
 Let's process rules with Outgoing tag
******************************************/

// How many times is this tag used globally ?
$countref = $outgoing->countReferences();
PH::print_stdout( "Tag named '".$outgoing->name()."' is used in $countref places" );

// But we need to filter these references to extract SecurityRule only
$list = $outgoing->findAssociatedSecurityRules();
// how many references left after filtering?
$countref = count($list);
$total = $countref;
PH::print_stdout( "Tag named '".$outgoing->name()."' is used in $countref SecurityRules" );

// Now we need to look at each rule and change it's source and destination zones
foreach ($list as $rule)
{
    // PH::print_stdout( rulename for debug, comment them if you want
    PH::print_stdout( "     Rule named '".$rule->name()."' from DeviceGroup '".$rule->owner->name()."' with tag '".$incoming->name()."' has the following Zones:" );
    PH::print_stdout( "        From: ".$rule->from->toString_inline()."" );
    PH::print_stdout( "        To:   ".$rule->to->toString_inline()."" );
    
    // now we check if each rule has internal in source zone and external in destination zone
    if( ! $rule->from->hasZone($internal) )
    {
    	    PH::print_stdout( "          This rule needs source zone to be added" );
    	    $rule->from->addZone($internal);
    	    PH::print_stdout( "          Updated From: ".$rule->from->toString_inline()."" );
    }
    if( ! $rule->to->hasZone($external) )
    {
    	    PH::print_stdout( "          This rule needs destination zone to be added" );
    	    $rule->to->addZone($external);
    	    PH::print_stdout( "          Updated To: ".$rule->to->toString_inline()."" );
    }
    
    PH::print_stdout( "" );
    
}


/*****************************************
 Now rules with Incoming Tag
******************************************/
// How many times is this tag used globally ?
$countref = $incoming->countReferences();
$total += $countref;
PH::print_stdout( "Tag named '".$incoming->name()."' is used in $countref places" );

// But we need to filter these references to extract SecurityRule only
$list = $incoming->findAssociatedSecurityRules();
// how many references left after filtering?
$countref = count($list);
PH::print_stdout( "Tag named '".$incoming->name()."' is used in $countref SecurityRules" );

// Now we need to look at each rule and change it's source and destination zones
foreach ($list as $rule)
{
    // PH::print_stdout( rulename for debug, comment them if you want
    PH::print_stdout( "     Rule named '".$rule->name()."' from DeviceGroup '".$rule->owner->name()."' with tag '".$incoming->name()."' has the following Zones:" );
    PH::print_stdout( "        From: ".$rule->from->toString_inline()."" );
    PH::print_stdout( "        To:   ".$rule->to->toString_inline()."" );
    
    // now we check if each rule has internal in source zone and external in destination zone
    if( ! $rule->from->hasZone($external) )
    {
    	    PH::print_stdout( "          This rule needs needs source zone to be added" );
    	    $rule->from->addZone($external);
    	    PH::print_stdout( "          Updated From: ".$rule->from->toString_inline()."" );
    }
    if( ! $rule->to->hasZone($internal) )
    {
    	    PH::print_stdout( "          This rule needs needs destination zone to be added" );
    	    $rule->to->addZone($internal);
    	    PH::print_stdout( "          Updated To: ".$rule->to->toString_inline()."" );
    }
    
    PH::print_stdout( "" );
    
}


PH::print_stdout( "We have edited a total of $total SecurityRules" );


// save resulting configuration file to output.xml
$p->save_to_file($outputfile);


// display some statiscs for debug and exit program!
PH::print_stdout( "\n\n***********************************************" );
$p->display_statistics();

memory_and_gc('end');


