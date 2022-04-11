<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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
require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();


PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

//Todo: 2019016 on failure change back config;
//uption: get candidate config first, if error, upload candidate config again

//Todo: are subinterfaces needed please add
//example: array(100,200) => ae5.100, ae5.200 and ae6.100, ae6.200
$vlan_array = array( 100, 200,300,400,500);
//no subinterfaces
#$vlan_array = array();


///////////////////////////////////////////////////////
///////////////////////////////////////////////////////
$ae_solution = false;    //set to yes if AE interfaces should be used
//this can not be done on VM-Series

if( $ae_solution )
{
//////////////////////////////
//Todo: if AE is set to true; define Interfaces and AE


///
//Interface for AE
//example: array(9,10) => ethernet1/9 and ethernet1/10
    $int1_array = array('1/9','1/10');
    $int2_array = array('1/11','1/12');

//AE must be two
//example: array(5,6) => ae5 and ae6
    $ae_array = array( 5, 6 );



    //DO NOT CHANGE
    $ae_interface_prefix = "ae";
    $tmp_int_type = "aggregate-group";
}
else
{
//////////////////////////////
//Todo: if AE is set to false; define Interface in $int1_array
//
    $int1_array = array('1/8','1/9');
    $int2_array = null;
    $ae_array = array( 0 );





    //DO NOT CHANGE
    $ae_interface_prefix = "ethernet";
    $tmp_int_type = "virtual-wire";
}


$vw_interface_prefix = "vw";

///////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 " .
    "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n".
    "php ".basename(__FILE__)." help          : more help messages\n";

##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

$util->load_config();
#$util->location_filter();

$pan = $util->pan;

$connector = $pan->connector;

$sub = $pan->findVirtualSystem( $util->objectsLocation);


///////////////////////////////////////////////////////
///////////////////////////////////////////////////////
//CUSTOM variable validation

//working solution for firewall API, also if different vsys
//Todo: more validation needed for offline files if interface, virtual-wire aso already exist [pan-c framework related]

//Todo: extend for Panorama DG (location)[security rule part] and template[interfaces, virtual-wire, zone]


if( $util->configType == 'panorama' )
    derr( 'Panorama configuration extension for virtual-wire is NOT yet supported' );

if( $ae_solution && $pan->connector->info_model == "PA-VM" )
    derr( 'PA-VM do not support aggregate-group interface' );


///////////////////////////////////////////////////////
///////////////////////////////////////////////////////

foreach( $ae_array as $key => $i )
{
    if( $tmp_int_type == "aggregate-group" )
    {
        $name2 = $ae_interface_prefix.$i;
        $tmp_int_type2 = "virtual-wire";

        print "create Ethernet Aggregate ".$name2." first.\n";


        if( $util->configInput['type'] == 'api' )
        {
            $tmp_VirtualWireIf2 = $pan->network->aggregateEthernetIfStore->API_newEthernetIf($name2, $tmp_int_type2);
            if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf2->name() ) )
                $sub->importedInterfaces->API_addInterface( $tmp_VirtualWireIf2 );
        }
        else
        {
            $tmp_VirtualWireIf2 = $pan->network->aggregateEthernetIfStore->newEthernetIf($name2, $tmp_int_type2);
            if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf2->name() ) )
                $sub->importedInterfaces->addInterface( $tmp_VirtualWireIf2 );
        }

        print "import ".$tmp_VirtualWireIf2->type()." Interface ".$tmp_VirtualWireIf2->name()." to vsys ".$sub->name()."\n";

        print "zone: ".$vw_interface_prefix."_".$name2." as type: ".$tmp_VirtualWireIf2->type()." created\n";
        $zone = $sub->zoneStore->newZone( $vw_interface_prefix."_".$name2, $tmp_VirtualWireIf2->type() );
        $zone->attachedInterfaces->addInterface( $tmp_VirtualWireIf2 );

        if( $util->configInput['type'] == 'api' )
        {
            print "API: zoneStore sync\n";
            $zone->API_sync();
        }



        
        if ( $key == 1)
            $int_array = $int2_array;
        else
            $int_array = $int1_array;

        foreach( $int_array as $ii )
        {
            $name = "ethernet" . $ii;

            print "create ".$tmp_int_type." | " . $name . " Interface with AE: " . $name2 . "\n";
            if( $util->configInput['type'] == 'api' )
            {
                $tmp_VirtualWireIf = $pan->network->ethernetIfStore->API_newEthernetIf($name, $tmp_int_type, $name2);
                if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf->name() ) )
                    $sub->importedInterfaces->API_addInterface( $tmp_VirtualWireIf );
            }

            else
            {
                $tmp_VirtualWireIf = $pan->network->ethernetIfStore->newEthernetIf($name, $tmp_int_type, $name2);

                if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf->name() ) )
                    $sub->importedInterfaces->addInterface( $tmp_VirtualWireIf );
            }


            //NO vsys import needed (possible) for aggreagte-group ethernet interfaces
        }
    }
    else
    {
        //$name missing how to proceed?

        if ( $key == 1)
            $int_array = $int2_array;
        else
            $int_array = $int1_array;

        $interface_array = array();

        foreach( $int_array as $ii )
        {
            $name = $ae_interface_prefix . $ii;

            print "create ".$tmp_int_type." ".$name." Interface\n";


            if( $util->configInput['type'] == 'api' )
            {
                $tmp_VirtualWireIf = $pan->network->ethernetIfStore->API_newEthernetIf($name, $tmp_int_type);
                if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf->name() ) )
                    $sub->importedInterfaces->API_addInterface( $tmp_VirtualWireIf );
            }
            else
            {
                $tmp_VirtualWireIf = $pan->network->ethernetIfStore->newEthernetIf($name, $tmp_int_type);
                if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf->name() ) )
                    $sub->importedInterfaces->addInterface( $tmp_VirtualWireIf );
            }

            print "import ".$tmp_VirtualWireIf->type()." ".$name." Interface ".$tmp_VirtualWireIf->name()." to vsys ".$sub->name()."\n";

            $interface_array[] = $tmp_VirtualWireIf;

            print "create zone: ".$vw_interface_prefix."_".$name." as type: ".$tmp_VirtualWireIf->type()."\n";
            $tmp_int_name = str_replace( "/", "_", $name );
            $zone = $sub->zoneStore->newZone( $vw_interface_prefix."_".$tmp_int_name, $tmp_VirtualWireIf->type() );
            $zone->attachedInterfaces->addInterface( $tmp_VirtualWireIf );

            if( $util->configInput['type'] == 'api' )
            {
                print "API: zoneStore sync\n";
                $zone->API_sync();
            }
        }
    }



    foreach( $vlan_array as $vlan )
    {
        if( $tmp_VirtualWireIf->type() !== "aggregate-group" )
        {
            //this is for example for virtual-wire subinterfaces

            foreach( $interface_array as $tmp_VirtualWireIf )
            {
                print "create Subinterface ".$tmp_VirtualWireIf->type()." interface: ".$tmp_VirtualWireIf->name().".".$vlan." - added to vsys: ".$sub->name()."\n";
                $tmp_int_name = str_replace( "/", "_", $tmp_VirtualWireIf->name() );
                $zone_name = $vw_interface_prefix."_".$tmp_int_name."-".$vlan;


                if( $util->configInput['type'] == 'api' )
                {
                    $newInt = $tmp_VirtualWireIf->API_addSubInterface( $vlan);
                    if( !$sub->importedInterfaces->hasInterfaceNamed( $newInt->name() ) )
                        $sub->importedInterfaces->API_addInterface( $newInt );
                }
                else
                {
                    $newInt = $tmp_VirtualWireIf->addSubInterface( $vlan);
                    if( !$sub->importedInterfaces->hasInterfaceNamed( $newInt->name() ) )
                        $sub->importedInterfaces->addInterface( $newInt );
                }

                print "create zone: ".$zone_name." as type: ".$tmp_VirtualWireIf->type()."\n";
                $zone = $sub->zoneStore->newZone( $zone_name, $tmp_VirtualWireIf->type() );
                $zone->attachedInterfaces->addInterface( $newInt );

                if( $util->configInput['type'] == 'api' )
                {
                    print "API: zone sync\n";
                    $zone->API_sync();
                }
            }

        }
        elseif( $tmp_VirtualWireIf2->type() !== "aggregate-ethernet" )
        {
            print "create Subinterface ".$tmp_VirtualWireIf2->type()." interface: ".$tmp_VirtualWireIf2->name().".".$vlan." - added to vsys: ".$sub->name()."\n";
            $zone_name = $vw_interface_prefix."_".$tmp_VirtualWireIf2->name()."-".$vlan;
            print "create zone: ".$zone_name." as type: ".$tmp_VirtualWireIf2->type()."\n";

            if( $util->configInput['type'] == 'api' )
            {
                $newInt = $tmp_VirtualWireIf2->API_addSubInterface( $vlan);
                if( !$sub->importedInterfaces->hasInterfaceNamed( $newInt->name() ) )
                    $sub->importedInterfaces->API_addInterface( $newInt );
            }
            else
            {
                $newInt = $tmp_VirtualWireIf2->addSubInterface( $vlan);
                if( !$sub->importedInterfaces->hasInterfaceNamed( $newInt->name() ) )
                    $sub->importedInterfaces->addInterface( $newInt );
            }

            $zone = $sub->zoneStore->newZone( $zone_name, $tmp_VirtualWireIf2->type() );
            $zone->attachedInterfaces->addInterface( $newInt );

            if( $util->configInput['type'] == 'api' )
            {
                print "API: zoneStore sync\n";
                $zone->API_sync();
            }
        }
    }
}






if( $tmp_int_type == "aggregate-group" )
{
    $name = $ae_interface_prefix."_".$ae_array[0]."-".$ae_array[1];

    print "search for: ".$ae_interface_prefix . $ae_array[0] . "\n";
    print "search for: ".$ae_interface_prefix . $ae_array[1] . "\n";
    $int_ae1 = $pan->network->aggregateEthernetIfStore->findOrCreate($ae_interface_prefix . $ae_array[0]);
    $int_ae2 = $pan->network->aggregateEthernetIfStore->findOrCreate($ae_interface_prefix . $ae_array[1]);
}
elseif( $tmp_int_type == "virtual-wire" )
{
    $tmp_int1_name = str_replace( "/", "_", $int1_array[0] );
    $tmp_int2_name = str_replace( "/", "_", $int1_array[1] );
    $name = $ae_interface_prefix."_".$tmp_int1_name."-".$tmp_int2_name;

    print "search for: ".$ae_interface_prefix . $int1_array[0] . "\n";
    print "search for: ".$ae_interface_prefix . $int1_array[1] . "\n";
    $int_ae1 = $pan->network->aggregateEthernetIfStore->findOrCreate($ae_interface_prefix . $int1_array[0]);
    $int_ae2 = $pan->network->aggregateEthernetIfStore->findOrCreate($ae_interface_prefix . $int1_array[1]);
}
$name = str_replace( "ethernet", "eth", $name );


print "create Virtual Wire: ".$name." Interface\n";

if( $util->configInput['type'] == 'api' )
{
    $tmp_VirtualWireIf = $pan->network->virtualWireStore->API_newVirtualWire( $name );
}
else
{
    $tmp_VirtualWireIf = $pan->network->virtualWireStore->newVirtualWire( $name );
    //Todo: add vlan / default - this is master virtual-wire
    //is it needed?
    //if nothing is set then default => default is equal to 0
}



print "add interfaces: " . $int_ae1->name() . " and " . $int_ae2->name() . " to Virtual Wire: " . $name . " Interface\n";
if( $util->configInput['type'] == 'api' )
{
    $tmp_VirtualWireIf->API_setInterface('interface1', $int_ae1);
    $tmp_VirtualWireIf->API_setInterface('interface2', $int_ae2);
}
else
{
    $tmp_VirtualWireIf->setInterface('interface1', $int_ae1);
    $tmp_VirtualWireIf->setInterface('interface2', $int_ae2);
}





print "search interfacename: ".$int_ae1->name()."\n";
print "search interfacename: ".$int_ae2->name()."\n";
$zone_ae1 = $sub->zoneStore->findZoneMatchingInterfaceName( $int_ae1->name() );
$zone_ae2 = $sub->zoneStore->findZoneMatchingInterfaceName( $int_ae2->name() );

if( $tmp_int_type == "aggregate-group" )
{
    $tmp_rule1_name = $int_ae1->name()."-".$int_ae2->name();
    $tmp_rule2_name = $int_ae2->name()."-".$int_ae1->name();
}
elseif( $tmp_int_type == "virtual-wire" )
{
    $tmp_int1_name = str_replace( "/", "_", $int_ae1->name() );
    $tmp_int2_name = str_replace( "/", "_", $int_ae2->name() );
    $tmp_rule1_name = $tmp_int1_name."-".$tmp_int2_name;
    $tmp_rule2_name = $tmp_int2_name."-".$tmp_int1_name;
}

$tmp_rule1_name = str_replace( "ethernet", "eth", $tmp_rule1_name );
$tmp_rule2_name = str_replace( "ethernet", "eth", $tmp_rule2_name );

print "create rule: ".$tmp_rule1_name." and add zones from/to\n";
$sec_rule1 = $sub->securityRules->newSecurityRule( $tmp_rule1_name );
$sec_rule1->from->addZone( $zone_ae1 );
$sec_rule1->to->addZone( $zone_ae2 );

print "create rule: ".$tmp_rule2_name." and add zones from/to\n";
$sec_rule2 = $sub->securityRules->newSecurityRule( $tmp_rule2_name );
$sec_rule2->from->addZone( $zone_ae2 );
$sec_rule2->to->addZone( $zone_ae1 );

if( $util->configInput['type'] == 'api' )
{
    print "API: rule1 / rule2 sync\n";
    $sec_rule1->API_sync();
    $sec_rule2->API_sync();
}



foreach( $vlan_array as $vlan )
{
    if( $tmp_int_type == "aggregate-group" )
        $vw_name = $ae_interface_prefix."_".$ae_array[0]."-".$ae_array[1]."_".$vlan;
    elseif( $tmp_int_type == "virtual-wire" )
    {
        $tmp_int1_name = str_replace( "/", "_", $int1_array[0] );
        $tmp_int2_name = str_replace( "/", "_", $int1_array[1] );
        $vw_name = $ae_interface_prefix."_".$tmp_int1_name."-".$vlan."_".$tmp_int2_name."-".$vlan;
    }
    $vw_name = str_replace( "ethernet", "eth", $vw_name );

    print "create Virtual Wire: ".$name." Interface\n";

    if( $util->configInput['type'] == 'api' )
    {
        $tmp_VirtualWireSubIf = $pan->network->virtualWireStore->API_newVirtualWire( $vw_name );
        //Todo: nothing for sub-interfaces you ar enot allowed to set anything
    }
    else
    {
        $tmp_VirtualWireSubIf = $pan->network->virtualWireStore->newVirtualWire( $vw_name );
        //Todo: nothing for sub-interfaces you ar enot allowed to set anything
    }


    foreach( $ae_array as $key => $i )
    {
        if( $tmp_int_type == "aggregate-group" )
        {
            $tmp_int1_name = $ae_interface_prefix . $ae_array[0] . "." . $vlan;
            $tmp_int2_name = $ae_interface_prefix . $ae_array[1] . "." . $vlan;
        }
        else
        {
            $tmp_int1_name = $ae_interface_prefix . $int1_array[0] . "." . $vlan;
            $tmp_int2_name = $ae_interface_prefix . $int1_array[1] . "." . $vlan;
        }
        print "search for: ".$tmp_int1_name."\n";
        print "search for: ".$tmp_int2_name."\n";
        $int_subae1 = $pan->network->ethernetIfStore->findOrCreate($tmp_int1_name);
        $int_subae2 = $pan->network->ethernetIfStore->findOrCreate($tmp_int2_name);


        print "add interfaces: " . $int_subae1->name() . " and " . $int_subae2->name() . " to Virtual Wire: " . $vw_name . " Interface\n";
        if( $util->configInput['type'] == 'api' )
        {
            $tmp_VirtualWireSubIf->API_setInterface('interface1', $int_subae1);
            $tmp_VirtualWireSubIf->API_setInterface('interface2', $int_subae2);
        }
        else
        {
            $tmp_VirtualWireSubIf->setInterface('interface1', $int_subae1);
            $tmp_VirtualWireSubIf->setInterface('interface2', $int_subae2);
        }




        $zone_subae1 = $sub->zoneStore->findZoneMatchingInterfaceName( $int_subae1->name() );
        $zone_subae2 = $sub->zoneStore->findZoneMatchingInterfaceName( $int_subae2->name() );

        if( $tmp_int_type == "aggregate-group" )
        {
            $tmp_rule1_name = $int_subae1->name()."-".$int_subae2->name();
            $tmp_rule2_name = $int_subae2->name()."-".$int_subae1->name();
        }
        elseif( $tmp_int_type == "virtual-wire" )
        {
            $tmp_int1_name = str_replace( "/", "_", $int_subae1->name() );
            $tmp_int2_name = str_replace( "/", "_", $int_subae2->name() );
            $tmp_rule1_name = $tmp_int1_name."-".$tmp_int2_name;
            $tmp_rule2_name = $tmp_int2_name."-".$tmp_int1_name;
        }

        $tmp_rule1_name = str_replace( "ethernet", "eth", $tmp_rule1_name );
        $tmp_rule2_name = str_replace( "ethernet", "eth", $tmp_rule2_name );

        print "create rule: ".$tmp_rule1_name." and add zones from/to\n";
        $sec_rule1 = $sub->securityRules->newSecurityRule( $tmp_rule1_name );
        $sec_rule1->from->addZone( $zone_subae1 );
        $sec_rule1->to->addZone( $zone_subae2 );

        print "create rule: ".$tmp_rule2_name." and add zones from/to\n";
        $sec_rule2 = $sub->securityRules->newSecurityRule( $tmp_rule2_name );
        $sec_rule2->from->addZone( $zone_subae2 );
        $sec_rule2->to->addZone( $zone_subae1 );

        if( $util->configInput['type'] == 'api' )
        {
            print "API: rule1 / rule2 sync\n";
            $sec_rule1->API_sync();
            $sec_rule2->API_sync();
        }
    }
}





##############################################

print "\n\n\n";

// save our work !!!
$util->save_our_work();



print "\n\n************ END OF CREATE-INTERFACE UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
