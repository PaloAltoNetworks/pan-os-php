<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


print "\n***********************************************\n";
print "************ COMMIT-CONFIG UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");


function display_usage_and_exit($shortMessage = FALSE)
{
    global $argv;
    print PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml location=vsys1 " .
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";
    print "php " . basename(__FILE__) . " help          : more help messages\n";


    if( !$shortMessage )
    {
        print PH::boldText("\nListing available arguments\n\n");

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            print " - " . PH::boldText($arg['niceName']);
            if( isset($arg['argDesc']) )
                print '=' . $arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']) )
                print "\n     " . $arg['shortHelp'];
            print "\n\n";
        }

        print "\n\n";
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(TRUE);
}


print "\n";

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = FALSE;
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = FALSE;


$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['template'] = array('niceName' => 'template', 'shortHelp' => 'Panorama template');
$supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
$supportedArguments['folder'] = array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


PH::processCliArgs();

foreach( PH::$args as $index => &$arg )
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


if( !isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if( isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if( !is_string($configOutput) || strlen($configOutput) < 1 )
        display_error_usage_exit('"out" argument is not a valid string');
}

if( isset(PH::$args['debugapi']) )
{
    $debugAPI = TRUE;
}

if( isset(PH::$args['folder']) )
{
    $offline_folder = PH::$args['folder'];
}

if( isset(PH::$args['template']) )
{
    $template = PH::$args['template'];
}

################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, TRUE);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");
    exit(1);
}

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( !$xmlDoc1->load($configInput['filename'], XML_PARSE_BIG_LINES) )
        derr("error while reading xml config file");

}
elseif( $configInput['type'] == 'api' )
{

    if( $debugAPI )
        $configInput['connector']->setShowApiCalls(TRUE);
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
if( $xpathResult1->length < 1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length < 1 )
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
if( isset(PH::$args['location']) )
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
$zone_array = array();
$interface_wo_vsys = array();

$pan->load_from_domxml($xmlDoc1);

if( $configType == 'panorama' )
{
    if( !isset(PH::$args['template']) )
        derr('"template" is missing from arguments');
}
else
    $template = "all";


if( ($template == 'all' || $template == "any") && $configType == 'panorama' )
    $template_array = $pan->templates;
else
    $template_array = explode(",", $template);


foreach( $template_array as $template )
{
    if( $objectslocation == "all" || $objectslocation == "any" || is_object($objectslocation) )
    {
        if( $configType == 'panos' )
            $tmp_location_array = $pan->virtualSystems;
        elseif( $configType == 'panorama' )
        {
            if( !is_object($template) )
                $template = $pan->findTemplate($template);

            $tmp_location_array = $template->deviceConfiguration->virtualSystems;
        }
    }
    else
        $tmp_location_array = explode(",", $objectslocation);


##############
//print "\n#######################################################################################################################\n";
    //DISPLAY
    print "\n\n----------------------\n";
    if( is_object($template) )
        print "TEMPLATE: " . PH::boldText($template->name()) . "\n";

    foreach( $tmp_location_array as $objectslocation )
    {
        if( is_object($objectslocation) )
            $sub = $objectslocation;
        else
        {
            if( $configType == 'panos' )
                $sub = $pan->findVirtualSystem($objectslocation);
            elseif( $configType == 'panorama' )
            {
                if( !is_object($template) )
                    $template = $pan->findTemplate($template);

                $sub = $template->deviceConfiguration->findVirtualSystem($objectslocation);
            }
        }

        if( $sub != null )
        {


            print "\n\nVSYS name: " . $sub->name() . " - *" . $sub->alternativeName() . "*\n";

            foreach( $sub->importedInterfaces as $interfacecontainer )
            {
                if( is_a($interfacecontainer, 'NetworkPropertiesContainer') )
                {
                    foreach( $interfacecontainer->getAllInterfaces() as $interface )
                    {
                        $tmp_vsys = $interfacecontainer->findVsysInterfaceOwner($interface->name());
                        if( $tmp_vsys != null )
                        {
                            if( $tmp_vsys->name() == $sub->name() )
                            {
                                print "\n  - " . $interface->type . " - ";
                                if( $interface->type == "layer3" )
                                {
                                    if( $interface->isSubInterface() )
                                        print "subinterface - ";
                                    else
                                        print "count subinterface: " . $interface->countSubInterfaces() . " - ";
                                }
                                elseif( $interface->type == "aggregate-group" )
                                {
                                    #$interface->
                                }

                                print $interface->name() . ", ip-addresse(s): ";
                                if( $interface->type == "layer3" )
                                {
                                    foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                                        print $ip_address . ",";
                                }
                                elseif( $interface->type == "tunnel" )
                                {
                                    foreach( $interface->getIPv4Addresses() as $ip_address )
                                        print $ip_address . ",";
                                }
                            }
                        }
                        else
                            $interface_wo_vsys[$interface->name()] = $interface;
                    }
                }
            }
        }

    }
}

print "\n\nall interfaces NOT attached to an vsys:\n";
foreach( $interface_wo_vsys as $interface )
{
    print "\n  - " . $interface->type . " - ";
    if( $interface->type == "layer3" )
    {
        if( $interface->isSubInterface() )
            print "subinterface - ";
        else
            print "count subinterface: " . $interface->countSubInterfaces() . " - ";
    }
    elseif( $interface->type == "aggregate-group" )
    {
        #$interface->
    }

    print $interface->name() . ", ip-address(es): ";
    if( $interface->type == "layer3" )
    {
        foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
            print $ip_address . ",";
    }
    elseif( $interface->type == "tunnel" )
    {
        foreach( $interface->getIPv4Addresses() as $ip_address )
            print $ip_address . ",";
    }

    #print "\n";
}


##############################################

print "\n\n\n";

// save our work !!!
if( $configOutput !== null )
{
    if( $configOutput != '/dev/null' )
    {
        $pan->save_to_file($configOutput);
    }
}


print "\n\n************ END OF COMMIT-CONFIG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
