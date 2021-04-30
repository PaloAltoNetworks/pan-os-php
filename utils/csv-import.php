<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";

$createObjects = FALSE;

$actions = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each disabled app-id. ie: actions=display / actions=enable', 'argDesc' => 'action:arg1[,arg2]');
$supportedArguments['csv'] = array('niceName' => 'CSV', 'shortHelp' => 'CSV file with HEADER');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');

$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] [cycleconnectedFirewalls] [actions=enable]";

if( !PH::$shadow_json )
{
    print "\n***********************************************\n";
    print "************ APP-ID ENABLE UTILITY ****************\n\n";
}

$util = new UTIL("custom", $argv, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################


if( !isset(PH::$args['actions']) || strtolower(PH::$args['actions']) == 'display' )
    $actions = 'display';
elseif( strtolower(PH::$args['actions']) == 'import' )
    $actions = 'import';


if( isset(PH::$args['csv']) )
    $csvfile = PH::$args['csv'];
else
    derr("argument csv not set");


##########################################


$util->load_config();
$util->location_filter();

$pan = $util->pan;

if( $actions == "display" )
{
    $errormsg = "";


    $stringarray = CsvParser::parseFile($csvfile, $errormsg);

    if( $stringarray !== FALSE )
    {

        foreach( $stringarray as $rule )
        {
            print_r($rule);
            if( $util->configType == "panorama" )
            {
                if( isset($rule['Name']) )
                {
                    //Todo is it not better to define the DG location via script start as argument?
                    //$util->objectsLocation
                    #$rule_location = $pan->findDeviceGroup( $rule['Location']);

                    $rule_location = $pan->findDeviceGroup($util->objectsLocation[0]);
                    if( $rule_location === null )
                    {
                        $rule_location = $pan->createDeviceGroup($util->objectsLocation[0]);
                        #derr("DG: ".$rule['Location']." was not found ? Exit\n");
                    }
                }
                else
                    derr("this script expect in CSV HEADER a field called 'Location' to get the Panorama DG Name from");
            }
            else
            {
                $rule_location = $pan->findVirtualSystem($util->objectsLocation[0]);
                if( $rule_location === null )
                {
                    derr($util->objectsLocation[0] . " vsys1 was not found ? Exit\n");
                }
            }

            $secrule = null;
            if( isset($rule['Name']) )
            {
                $rulename = $rule['Name'];
                $secrule = $rule_location->securityRules->find($rulename);
                if( $secrule != null )
                {
                    mwarning("SecurityRule: " . $rulename . " is already available, skip adding ");
                    continue;
                }

                $secrule = $rule_location->securityRules->newSecurityRule($rulename);
                print "\n * create SecurityRule: " . $rulename . "\n";

            }

            else
                derr("this script expect in CSV HEADER a field called 'Name' to get the Rulename from");


            if( $secrule !== null )
            {
                if( isset($rule['Tags']) )
                {
                    $name = $rule['Tags'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name != "" )
                        {
                            $tmp_tag = $rule_location->tagStore->find($name);
                            if( $tmp_tag == null )
                            {
                                if( $createObjects )
                                {
                                    $tmp_tag = $rule_location->tagStore->findorCreate($name);
                                    if( $util->configInput['type'] == 'api' )
                                        $tmp_tag->API_sync();
                                }
                                mwarning("TAG: '" . $name . "' not found", null, FALSE);
                            }

                            if( $tmp_tag != null )
                            {
                                print "  - add Tag: " . $name . "\n";
                                $secrule->tags->addTag($tmp_tag);
                            }
                        }
                    }
                }


                //[Type] => universal
                if( isset($rule['Type']) )
                {
                    if( $rule['Type'] == "universal" )
                    {
                        //do nothing
                    }
                    else
                        $rule->setType($rule['Type']);
                }


                //[Source Zone] => any
                if( isset($rule['Source Zone']) )
                {
                    $name = $rule['Source Zone'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            print "   - from Zone set ANY\n";
                            $secrule->from->setAny();
                        }
                        else
                        {
                            $tmp_from_zone = $rule_location->zoneStore->find($name);
                            if( $tmp_from_zone == null )
                            {
                                if( $createObjects )
                                {
                                    if( $util->configType == 'panos' )
                                    {
                                        $tmp_from_zone = $rule_location->zoneStore->newZone($name, "layer3");
                                        if( $util->configInput['type'] == 'api' )
                                            $tmp_from_zone->API_sync();
                                    }
                                    else
                                        $tmp_from_zone = $rule_location->zoneStore->findorCreate($name);
                                }
                                mwarning("Zone: " . $name . " not found", null, FALSE);
                            }

                            if( $tmp_from_zone != null )
                            {
                                print "   - add from Zone: " . $name . "\n";
                                $secrule->from->addZone($tmp_from_zone);
                            }
                        }
                    }
                }

                //[Source Address] => old-12.45.123.149
                if( isset($rule['Source Address']) )
                {
                    $name = $rule['Source Address'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            print "   - source set ANY\n";
                            $secrule->source->setAny();
                        }
                        else
                        {
                            $tmp_address = $rule_location->addressStore->find($name);

                            if( $tmp_address == null )
                            {
                                if( $createObjects )
                                {
                                    $tmp_address = $rule_location->addressStore->newAddress($name, "ip-netmask", "1.1.1.1/32");
                                    if( $util->configInput['type'] == 'api' )
                                        $tmp_address->API_sync();
                                }
                                mwarning("address object: " . $name . " not found", null, FALSE);
                            }

                            if( $tmp_address != null )
                            {
                                print "   - source add: " . $name . "\n";
                                $secrule->source->addObject($tmp_address);
                            }
                        }
                    }
                }


                //[Destination Zone] => any
                if( isset($rule['Destination Zone']) )
                {
                    $name = $rule['Destination Zone'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            print "   - to Zone set ANY\n";
                            $secrule->to->setAny();
                        }
                        else
                        {
                            $tmp_to_zone = $rule_location->zoneStore->find($name);
                            if( $tmp_to_zone == null )
                            {
                                if( $createObjects )
                                {
                                    if( $util->configType == 'panos' )
                                    {
                                        $tmp_to_zone = $rule_location->zoneStore->newZone($name, "layer3");
                                        if( $util->configInput['type'] == 'api' )
                                            $tmp_to_zone->API_sync();
                                    }
                                    else
                                        $tmp_from_zone = $rule_location->zoneStore->findorCreate($name);
                                }
                                mwarning("Zone: " . $name . " not found", null, FALSE);
                            }
                            if( $tmp_to_zone != null )
                            {
                                print "   - add to Zone: " . $name . "\n";
                                $secrule->to->addZone($tmp_to_zone);
                            }
                        }
                    }
                }

                //[Destination Address] => gcp-10.54.25.57
                if( isset($rule['Destination Address']) )
                {
                    $name = $rule['Destination Address'];

                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            print "   - destination set ANY\n";
                            $secrule->destination->setAny();
                        }
                        else
                        {
                            $tmp_address = $rule_location->addressStore->find($name);

                            if( $tmp_address == null )
                            {
                                if( $createObjects )
                                {
                                    $tmp_address = $rule_location->addressStore->newAddress($name, "ip-netmask", "1.1.1.1/32");
                                    if( $util->configInput['type'] == 'api' )
                                        $tmp_address->API_sync();
                                }
                                mwarning("address object: " . $name . " not found", null, FALSE);
                            }
                            if( $tmp_address != null )
                            {
                                print "   - destination add: " . $name . "\n";
                                $secrule->destination->addObject($tmp_address);
                            }
                        }
                    }

                }

                //[Application] => any
                //[Service] => application-default
                if( isset($rule['Service']) )
                {
                    $name = $rule['Service'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name != "any" && $name != "application-default" )
                        {
                            $tmp_service = $rule_location->serviceStore->find($name);

                            if( $tmp_service == null )
                            {
                                mwarning("service object: " . $name . " not found", null, FALSE);
                            }
                            else
                            {
                                print "   - service add: " . $name . "\n";
                                $secrule->services->add($tmp_service);
                            }
                        }
                        elseif( $name == "any" )
                        {
                            print "   - service set any\n";
                            $secrule->services->setAny();
                        }

                        elseif( $name == "application-default" )
                        {
                            print "   - service set application-default\n";
                            $secrule->services->setApplicationDefault();
                        }

                    }
                }

                if( isset($rule['Application']) )
                {
                    //application add
                    $name = $rule['Application'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name != "any" )
                        {
                            $tmp_app = $pan->appStore->find($name);

                            if( $tmp_app == null )
                            {
                                mwarning("appID: '" . $name . "' not found\n", null, FALSE);
                            }
                            else
                            {
                                print "   - appID add: " . $name . "\n";
                                $secrule->apps->addApp($tmp_app);
                            }
                        }
                        #elseif( $name == "any" )

                    }
                }


                //[Action] => allow

                if( isset($rule['Action']) )
                {
                    $name = $rule['Action'];
                    print "   - add Rule action to: " . $name . "\n";
                    $secrule->setAction($name);
                }


                //[Profile] => none
                if( isset($rule['Profile']) )
                {
                    $name = $rule['Profile'];

                    if( $name != "none" )
                    {
                        print " * add security profile group: " . $name . "\n";
                        $secrule->setSecurityProfileGroup($name);
                    }
                }

                //[Options] => Traffic log sent at session end
                if( isset($rule['Options']) )
                {
                    $name = $rule['Options'];

                    if( $name == "Traffic log sent at session end" )
                    {
                        //default
                    }
                    else
                    {
                        //Todo: implementation needed
                        mwarning("'Options' setting: " . $name . " not supported yet", null, FALSE);
                    }
                }


                //#######################################################################################
                //#######################################################################################
                //#######################################################################################
                //TODO: IMPLEMENTATION NEEDED
                //[Source User] => any
                if( isset($rule['Source User']) )
                {
                    $name = $rule['Source User'];
                    if( $name != "any" )
                    {
                        //Todo: implementation needed
                        mwarning("'Source User' - not supported yet");
                    }

                }
                //[Source HIP Profile] => any

                if( isset($rule['Source HIP Profile']) )
                {
                    $name = $rule['Source HIP Profile'];
                    if( $name != "any" )
                    {
                        //Todo: implementation needed
                        mwarning("'Source HIP Profile' - not supported yet");
                    }
                }
                //#######################################################################################
                //#######################################################################################
                //#######################################################################################


                if( $util->configInput['type'] == 'api' )
                    $secrule->API_sync();
            }
        }
    }

    else
    {
        derr($errormsg);
    }
}


##########################################
##########################################
if( !PH::$shadow_json )
{
    print "\n\n\n";
}

$util->save_our_work();

if( !PH::$shadow_json )
{
    print "\n\n************ END OF APP-ID ENABLE UTILITY ************\n";
    print     "**************************************************\n";
    print "\n\n";
}
