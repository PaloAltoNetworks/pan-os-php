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

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");


PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] or in=INPUTFILE.xml out=OUTFILE.xml";

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

$util->load_config();
$util->location_filter();

$pan = $util->pan;

/*
PH::processCliArgs();

foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if(isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if (!is_string($configOutput) || strlen($configOutput) < 1)
        display_error_usage_exit('"out" argument is not a valid string');
}

if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

if( isset(PH::$args['folder'])  )
{
    $offline_folder = PH::$args['folder'];
}


################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, true);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( ! $xmlDoc1->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{

    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    print " - Downloading config from API... ";

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        print " - 'loadPanoramaPushedConfig' was requested, downloading it through API...";
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    $hostname = $configInput['connector']->info_hostname;

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );

    print "OK!\n";

}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult1 = DH::findXPath('/config/devices/entry/vsys', $xmlDoc1);
if( $xpathResult1 === FALSE )
    derr('XPath error happened');
if( $xpathResult1->length <1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length <1 )
        $configType = 'panorama';
    else
        $configType = 'pushed_panorama';
}
else
    $configType = 'panos';
unset($xpathResult1);

print " - Detected platform type is '{$configType}'\n";

############## actual not used

if( $configType == 'panos' )
    $pan = new PANConf();
elseif( $configType == 'panorama' )
    $pan = new PanoramaConf();



if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];






// </editor-fold>

################


//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $objectslocation = PH::$args['location'];
    if( !is_string($objectslocation) || strlen($objectslocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'panorama' )
    {
        print " - No 'location' provided so using default ='shared'\n";
        $objectslocation = 'shared';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
}



##########################################
##########################################

$pan->load_from_domxml($xmlDoc1);

*/
##############

$sub = $pan->findVirtualSystem($util->objectsLocation[0]);

$zone_array = array();

//LOOPBACK
/*
for( $i = 15; $i<18; $i++ )
{
    $name = "loopback.".$i;
    print "create loopback ".$name."\n";

    $tmp_loopbackIf = $pan->network->loopbackIfStore->newLoopbackIf( $name );
    $tmp_loopbackIf->owner = null;



    if( $util->configInput['type'] == 'api' )
    {
        $pan->network->loopbackIfStore->API_addLoopbackIf( $tmp_loopbackIf );
        $sub->importedInterfaces->API_addInterface( $tmp_loopbackIf );
    }
    else
    {
        $pan->network->loopbackIfStore->addLoopbackIf( $tmp_loopbackIf );
        $sub->importedInterfaces->addInterface( $tmp_loopbackIf );
    }


    print "loopback interface: ".$name." - added to vsys: ".$sub->name()."\n";

}
*/



for( $i = 5; $i<7; $i++ )
{
    $name = "ethernet1/".$i;
    print "create VirtualWire ".$name."\n";


    #$tmp_int_type = "virtual-wire";
    $tmp_int_type = "layer3";
    #$tmp_int_type = "layer2";
    #$tmp_int_type = "aggregate-group";

    $tmp_VirtualWireIf2 = null;
    if( $tmp_int_type == "aggregate-group" )
    {
        $name2 = "ae".$i;
        $tmp_int_type2 = "layer3";
        print "you need to creat Ethernet aggregate first\n";
        if( $util->configInput['type'] == 'api' )
            $tmp_VirtualWireIf2 = $pan->network->aggregateEthernetIfStore->API_newEthernetIf($name2, $tmp_int_type2);
        else
            $tmp_VirtualWireIf2 = $pan->network->aggregateEthernetIfStore->newEthernetIf($name2, $tmp_int_type2);


        if( $util->configInput['type'] == 'api' )
        {
            $tmp_VirtualWireIf = $pan->network->ethernetIfStore->API_newEthernetIf($name, $tmp_int_type, $name2);
        }
        else
        {
            $tmp_VirtualWireIf = $pan->network->ethernetIfStore->newEthernetIf($name, $tmp_int_type, $name2);
        }
    }
    else
    {
        if( $util->configInput['type'] == 'api' )
        {
            $tmp_VirtualWireIf = $pan->network->ethernetIfStore->API_newEthernetIf($name, $tmp_int_type);
        }
        else
        {
            $tmp_VirtualWireIf = $pan->network->ethernetIfStore->newEthernetIf($name, $tmp_int_type);
        }
    }








    if( $util->configInput['type'] == 'api' )
    {
        #$pan->network->ethernetIfStore->API_addEthernetIf( $tmp_VirtualWireIf );
        if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf->name() ) )
            $sub->importedInterfaces->API_addInterface( $tmp_VirtualWireIf );
    }
    else
    {
        #$pan->network->ethernetIfStore->addEthernetIf( $tmp_VirtualWireIf );
        if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_VirtualWireIf->name() ) )
            $sub->importedInterfaces->addInterface( $tmp_VirtualWireIf );
    }

    if( $tmp_VirtualWireIf->type() !== "aggregate-group" )
    {
        print "Subinterface Ethernet interface: ".$name." - added to vsys: ".$sub->name()."\n";

        if( $util->configInput['type'] == 'api' )
        {
            $tmp_VirtualWireIf->API_addSubInterface( "100");
        }
        else
        {
            $tmp_VirtualWireIf->addSubInterface( "100");

        }
    }

    if( $tmp_VirtualWireIf2 !== null && $tmp_VirtualWireIf2->type() !== "aggregate-ethernet" )
    {
        print "Subinterface Ethernet interface: ".$name." - added to vsys: ".$sub->name()."\n";

        if( $util->configInput['type'] == 'api' )
        {
            $tmp_VirtualWireIf2->API_addSubInterface( "100");
        }
        else
        {
            $tmp_VirtualWireIf2->addSubInterface( "100");

        }
    }

}


$name = "test0815";
print "create VirtualWire ".$name."\n";




if( $util->configInput['type'] == 'api' )
{
    $tmp_VirtualWireIf = $pan->network->virtualWireStore->API_newVirtualWire( $name );
}
else
{
    $tmp_VirtualWireIf = $pan->network->virtualWireStore->newVirtualWire( $name );
}




$eth1_name = "ethernet1/7";
$eth2_name = "ethernet1/8";
print "create VirtualWire Ethernet ".$eth1_name."\n";
print "create VirtualWire Ethernet ".$eth2_name."\n";
//Todo: newEthernetIf run also addEthernetif

if( $util->configInput['type'] == 'api' )
{
    $tmp_vw_int1 = $pan->network->ethernetIfStore->API_newEthernetIf( $eth1_name, 'virtual-wire' );
    $tmp_vw_int2 = $pan->network->ethernetIfStore->API_newEthernetIf( $eth2_name, 'virtual-wire' );
}
else
{
    $tmp_vw_int1 = $pan->network->ethernetIfStore->newEthernetIf( $eth1_name, 'virtual-wire' );
    $tmp_vw_int2 = $pan->network->ethernetIfStore->newEthernetIf( $eth2_name, 'virtual-wire' );
}



print "VirtualWire Ethernet interface: ".$eth1_name." - added to vsys: ".$sub->name()."\n";
print "VirtualWire Ethernet interface: ".$eth2_name." - added to vsys: ".$sub->name()."\n";
if( $util->configInput['type'] == 'api' )
{
    if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_vw_int1->name() ) )
        $sub->importedInterfaces->API_addInterface( $tmp_vw_int1 );

    if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_vw_int2->name() ) )
        $sub->importedInterfaces->API_addInterface( $tmp_vw_int2 );
}
else
{
    if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_vw_int1->name() ) )
        $sub->importedInterfaces->addInterface( $tmp_vw_int1 );

    if( !$sub->importedInterfaces->hasInterfaceNamed( $tmp_vw_int2->name() ) )
        $sub->importedInterfaces->addInterface( $tmp_vw_int2 );
}


print "VirtualWire Ethernet interface: ".$eth1_name." - added to VirtualWire: ".$tmp_VirtualWireIf->name()."\n";
print "VirtualWire Ethernet interface: ".$eth2_name." - added to VirtualWire: ".$tmp_VirtualWireIf->name()."\n";
if( $util->configInput['type'] == 'api' )
{
    $tmp_VirtualWireIf->API_setInterface( 'interface1', $tmp_vw_int1 );
    $tmp_VirtualWireIf->API_setInterface( 'interface2', $tmp_vw_int2 );
}
else
{
    $tmp_VirtualWireIf->setInterface( 'interface1', $tmp_vw_int1 );
    $tmp_VirtualWireIf->setInterface( 'interface2', $tmp_vw_int2 );
}


if( $util->configInput['type'] == 'api' )
{
    $tmp_vw_int1->API_addSubInterface( "100");
    $tmp_vw_int2->API_addSubInterface( "100");
}
else
{
    $tmp_vw_int1->addSubInterface( "100");
    $tmp_vw_int2->addSubInterface( "100");

}



##############################################

print "\n\n\n";

// save our work !!!
if( $util->configOutput !== null )
{
    if( $util->configOutput != '/dev/null' )
    {
        $pan->save_to_file($util->configOutput);
    }
}



print "\n\n************ END OF CREATE-INTERFACE UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
