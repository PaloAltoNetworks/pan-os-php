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


###################################################################################
###################################################################################
//Todo: possible to bring this in via argument
//CUSTOM variables for the script

//BOTH PROFILES MUST BE available if API
$log_profile = "LoggingtoPanorama";
$secprofgroup_name = "SecurityProfileGroup";

$singleObject = false;

$delimiter = "Service_Definition";

$rulename_prefix = "policy-";
$rulename_counter = 1;


###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ VMware VRNI UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['csv'] = Array('niceName' => 'CSV', 'shortHelp' => 'VMware VNIX in CSV format');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['zone'] = Array('niceName' => 'Zone', 'shortHelp' => 'Zone used for from and to');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] csv=[csv_text file] [out=]";

function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars,"",$str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}


$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

if( isset(PH::$args['csv'])  )
    $file = PH::$args['csv'];
else
    derr( "argument csv not set" );

if( isset(PH::$args['zone'])  )
{
    $from_zone = PH::$args['zone'];
    $to_zone = $from_zone;
}


$util->load_config();
$util->location_filter();

$pan = $util->pan;


if( $util->configType == 'panos' )
{
    // Did we find VSYS1 ?
    $v = $pan->findVirtualSystem( $util->objectsLocation[0] );
    if( $v === null )
        derr( $util->objectsLocation[0]." was not found ? Exit\n");
}
elseif( $util->configType == 'panorama' )
{
    $v = $pan->findDeviceGroup( $util->objectsLocation[0] );
    if( $v == null )
        $v = $pan->createDeviceGroup( $util->objectsLocation[0] );
}
elseif( $util->configType == 'fawkes' )
{
    $v = $pan->findContainer( $util->objectsLocation[0] );
    if( $v == null )
        $v = $pan->createContainer( $util->objectsLocation[0] );
}


##########################################

$file_content = file( $file ) or die("Unable to open file!");
$servicecount = 0;

foreach( $file_content as $line )
{
    if( strpos( $line, $delimiter) !== false )
    {
        $line = strip_hidden_chars( $line );

        print "\n\nline|".$line."|\n";

        $tmp_array = explode( ",", $line );
        foreach( $tmp_array as $key => $entry )
        {
            if( !empty( $entry ) )
            {
                #print "ENTRY: |" . $entry . "|\n";

                if( strpos($entry, $delimiter) != FALSE )
                    $entry = explode($delimiter . "_", $entry)[1];

                if( $key == 0 )
                {
                    $rulename = $rulename_prefix . $rulename_counter;

                    $tmp_rule = $v->securityRules->find( $rulename );
                    if( $tmp_rule != null )
                    {
                        mwarning( "SecurityRule: ".$rulename." is already available, skip adding " );
                        continue;
                    }

                    $tmp_rule = $v->securityRules->newSecurityRule($rulename);
                    print " * create SecurityRule: " . $rulename . "\n";


                    //DEFAULT settings
                    // for ZONES [from]
                    $tmp_from_zone = $v->zoneStore->find( $from_zone );
                    if( $tmp_from_zone == null )
                    {
                        if( $util->configType == 'panos' && $util->configInput['type'] == 'api')
                        {
                            $tmp_from_zone = $v->zoneStore->newZone($from_zone, "layer3");
                            $tmp_from_zone->API_sync();
                        }
                        else
                            $tmp_from_zone = $v->zoneStore->findorCreate( $from_zone );
                    }
                    print " * add from Zone: ".$from_zone."\n";
                    $tmp_rule->from->addZone( $tmp_from_zone);

                    // for ZONES [to]
                    $tmp_to_zone = $v->zoneStore->find( $to_zone );
                    if( $tmp_to_zone == null )
                    {
                        if( $util->configType == 'panos' && $util->configInput['type'] == 'api')
                        {
                            $tmp_to_zone = $v->zoneStore->newZone($to_zone, "layer3");
                            $tmp_to_zone->API_sync();
                        }
                        else
                            $tmp_to_zone = $v->zoneStore->findorCreate( $from_zone );
                    }
                    print " * add to Zone: ".$to_zone."\n";
                    $tmp_rule->to->addZone( $tmp_to_zone);

                    // for logprof
                    print " * add log forwarding profile: ".$log_profile."\n";
                    $tmp_rule->setLogSetting( $log_profile );

                    // for securityprofilegroup
                    print " * add security profile group: ".$secprofgroup_name."\n";
                    $tmp_rule->setSecurityProfileGroup( $secprofgroup_name );
                    //END DEFAULT settings

                    //add source address object
                    $tmp_address = $v->addressStore->find( $entry );
                    print "   - source add: ".$entry."\n";
                    if( $tmp_address == null )
                    {
                        print "     - create object: ".$entry."\n";
                        $tmp_address = $v->addressStore->newAddressGroup( $entry );
                        if( $util->configInput['type'] == 'api' )
                            $tmp_address->API_sync();
                    }
                    $tmp_rule->source->addObject($tmp_address);
                }
                elseif( $key == 1 )
                {
                    //add destionation address object
                    $tmp_address = $v->addressStore->find( $entry );
                    print "   - destination add: ".$entry."\n";
                    if( $tmp_address == null )
                    {
                        print "     - create object: ".$entry."\n";
                        $tmp_address = $v->addressStore->newAddressGroup( $entry );
                        if( $util->configInput['type'] == 'api' )
                            $tmp_address->API_sync();
                    }

                    $tmp_rule->destination->addObject($tmp_address);
                }
                elseif( $key == 2 )
                {
                    $tmp_service_array = explode( " ", $entry );
                    $service_string = "";
                    foreach( $tmp_service_array as $keyservice => $service )
                    {
                        if( strpos( $service, "]" ) != false  )
                            continue;

                        if( is_numeric($service) or strpos( $service, "-" ) != false )
                        {
                            if( $service_string == "" )
                                $service_string .= $service;
                            else
                                $service_string .= ",".$service;
                        }
                    }
                }
                elseif( $key == 3 )
                {
                    $entry = strtolower( $entry );

                    //Todo: with foreach loop it can be that to many objects are created

                    $tmp_service_array = array();
                    if( $singleObject )
                        $tmp_service_array = explode( ",", $service_string );
                    else
                        $tmp_service_array[] = $service_string;



                    foreach( $tmp_service_array as $service_string )
                    {
                        $servicename = $entry."-".str_replace( ",", "_", $service_string);

                        if( strlen( $servicename) > 60 )
                        {
                            $servicename = "service_dummy_name_" . $servicecount;
                            $servicecount++;
                        }

                        //count ,
                        /*
                        $cut = 100; //str length of 660
                        $cut = 130; //str length of 869
                        $cut = 150; //str length of 952
                        $cut = 160; //str length of 1018
                        $cut = 180; //str length of 1144
                        */
                        $cut = 180;
                        if( substr_count( $service_string, ",") > $cut )
                        {
                            $dummy_array = explode( ",", $service_string );
                            $i = 1;
                            $string = "";
                            foreach( $dummy_array as $key => $item )
                            {
                                if( $key / ( $cut*$i ) < 1  )
                                {
                                    if( $string == "")
                                        $string .= $item;
                                    else
                                        $string .= ",".$item;
                                }
                                else
                                {
                                    $string .= ",".$item;
                                    $dummy1[$i] = $string;

                                    $servicename2 = $servicename."_".$i;

                                    $tmp_service = $v->serviceStore->find( $servicename2 );
                                    print "   - service add: ".$servicename2."\n";
                                    if( $tmp_service == null )
                                    {
                                        print "     - create service: ".$servicename2."\n";
                                        $tmp_service = $v->serviceStore->newService( $servicename2, $entry, $string);
                                        if( $util->configInput['type'] == 'api' )
                                            $tmp_service->API_sync();
                                    }
                                    $tmp_rule->services->add( $tmp_service );

                                    $string = "";
                                    $i++;
                                }
                            }
                        }

                        else
                        {
                            $tmp_service = $v->serviceStore->find( $servicename );
                            print "   - service add: ".$servicename."\n";
                            if( $tmp_service == null )
                            {
                                print "     - create service: ".$servicename."\n";
                                $tmp_service = $v->serviceStore->newService( $servicename, $entry, $service_string);
                                if( $util->configInput['type'] == 'api' )
                                    $tmp_service->API_sync();
                            }
                            $tmp_rule->services->add( $tmp_service );
                        }


                    }
                }
            }
        }

        if( $util->configInput['type'] == 'api' )
            $tmp_rule->API_sync();


        $rulename_counter++;
    }
}


print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF VMware VRNI UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
