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



###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ PULSE UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");
#require_once ( "parser/lib/CONVERTER.php");

$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = Array('niceName' => 'FILE', 'shortHelp' => 'PULSE XML config file');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=[PAN-OS base config file] file=[PULSE xml config file] [out=]";


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

if( isset(PH::$args['file'])  )
    $file = PH::$args['file'];
else
    derr( "argument file not set" );



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

//Todo: read XML file:
$xml = new DOMDocument;
$xml->load( $file );



$addressObjectArray = array();
$addressMissingObjects = array();

$serviceObjectArray = array();
$serviceMissingObjects = array();

$userObjectArray = array();
$userMissingObjects = array();

$policyGroupObjectArray = array();
$policyGroupMissingObjects = array();

$missingURL = array();


#######################################################
//FIND OBJECTS




$xml = DH::findFirstElementOrCreate('configuration', $xml );
$xml = DH::findFirstElementOrCreate('users', $xml );
$xml = DH::findFirstElementOrCreate('resource-policies', $xml );
$xml = DH::findFirstElementOrCreate('network-connect-policies', $xml );

$xml_acl = DH::findFirstElementOrCreate('network-connect-acls', $xml );
$xml_split = DH::findFirstElementOrCreate('network-connect-split-tunneling-networks', $xml );

foreach( $xml_acl->childNodes as $acl )
{
    if( $acl->nodeType != XML_ELEMENT_NODE ) continue;

    $appName = $acl->nodeName;

    $counter = 0;
    $name = "";
    $tag = "";
    $tmp_tag = null;
    $description = "";
    $tmp_rule = null;

    $xml_acl_action = DH::findFirstElementOrCreate('action', $acl );
    $action = $xml_acl_action->nodeValue;

    if( $action == "rules" )
    {
        $tmp = DH::findFirstElement( 'rules', $acl );
        if( $tmp !== false )
        {
            $tmp = DH::findFirstElement( 'rule', $tmp );
            if( $tmp !== false )
            {
                $tmp = DH::findFirstElement( 'action', $tmp );
                if( $tmp !== false )
                    $action = $tmp->nodeValue;
            }
        }
    }

    $protocol = "";
    foreach( $acl->childNodes as $acl_entries )
    {
        if( $acl_entries->nodeType != XML_ELEMENT_NODE ) continue;

        $nodeName = $acl_entries->nodeName;

        $service = null;


        #print "NODE: ". $nodeName."\n";

        if( $nodeName == "name" )
        {
            $name = $acl_entries->nodeValue;

            //name + counter
            //tag = name
            $tmp_tag = $v->tagStore->find( $name );
            if( $tmp_tag == null )
                $tmp_tag = $v->tagStore->createTag( $name );
        }
        elseif( $nodeName == "description" )
        {
            $description = $acl_entries->nodeValue;
        }
        elseif( $nodeName == "resource" )
        {
            if( $counter == 0 )
                $name_end = $name;
            else
                $name_end = $name."_".$counter;
            $counter++;
            //create rule

            $resource = $acl_entries->nodeValue;

            #print "\n".$resource."\n";
            if( strpos( $resource, "//" ) !== false )
            {
                $service = 'any';

                $resource = str_replace( "//", "", $resource );
                $resource_array = explode( ":", $resource);
                $protocol = $resource_array[0];
                $ip = $resource_array[1];

                if( isset( $resource_array[2] ) )
                    $service = $resource_array[2];
            }
            else
            {
                $resource_array = explode( ":", $resource);
                $ip = $resource_array[0];
            }


            if( strpos( $service, "," ) !== false )
                $service = explode( ",", $service);

            print " * create Rule: ".$name_end."\n";
            $tmp_rule = $v->securityRules->newSecurityRule( $name_end );
            $tmp_rule->setAction( $action);
            if( $tmp_tag != null )
                $tmp_rule->tags->addTag( $tmp_tag );

            /*
            print "IP: ".$ip."\n";
            print "PROTOCOL: ".$protocol."\n";
            print "SERVICE: ";
            */

            if( strpos( $ip, "/" ) !== false )
            {
                $ip_name = str_replace( "/", "m", $ip );
            }
            else
                $ip_name = $ip;

            if( $ip_name == "*" )
            {
                print "   - set Destination to ANY\n";
            }
            else
            {
                $tmp_address = $v->addressStore->find( $ip_name );
                if( $tmp_address == null )
                    $tmp_address = $v->addressStore->newAddress( $ip_name, 'ip-netmask', $ip );

                print "   - add Destination: ".$tmp_address->name()."\n";
                $tmp_rule->destination->addObject( $tmp_address );
            }



            if( $protocol !== "icmp" && $protocol != "" )
            {
                if( is_array( $service ) )
                {
                    foreach( $service as $srv )
                    {
                        #print $srv;
                        if( $srv == "" || $srv == "*" )
                            $srv = "1-65535";
                        $tmp_service = $v->serviceStore->find( $protocol."_".$srv );
                        if( $tmp_service == null )
                            $tmp_service = $v->serviceStore->newService( $protocol."_".$srv, $protocol, $srv );

                        print "   - add Service: ".$tmp_service->name()."\n";
                        $tmp_rule->services->add($tmp_service);
                    }
                }
                else
                {
                    #print $service;
                    if( $service == "" || $service == "*")
                        $service = "1-65535";
                    $tmp_service = $v->serviceStore->find( $protocol."_".$service );
                    if( $tmp_service == null )
                        $tmp_service = $v->serviceStore->newService( $protocol."_".$service, $protocol, $service );

                    print "   - add Service: ".$tmp_service->name()."\n";
                    $tmp_rule->services->add($tmp_service);
                }
            }
            elseif( $protocol == "" )
            {
                print "   - set Service to ANY\n";
            }
            elseif( $protocol == "icmp" )
            {
                print "   - set Application to ICMP\n";

                $tmp_app = $v->appStore->findOrCreate( 'icmp');
                $tmp_rule->apps->addApp( $tmp_app);

                $tmp_app = $v->appStore->findOrCreate( 'ping');
                $tmp_rule->apps->addApp( $tmp_app);

                $tmp_app = $v->appStore->findOrCreate( 'traceroute');
                $tmp_rule->apps->addApp( $tmp_app);
            }

            print "   - add Description\n";
            $tmp_rule->setDescription( $description );


            print "\n";


        }
        elseif( $nodeName == "resources-v6" )
        {

        }
        elseif( $nodeName == "apply" )
        {

        }
        elseif( $nodeName == "roles" )
        {

        }
        elseif( $nodeName == "action" )
        {
            #$action = $acl_entries->nodeValue;

            #
        }
        elseif( $nodeName == "rules" )
        {

        }
        else
        {
            print "NODE: ".$nodeName." not handled\n";
        }

        #var_dump( $acl_entries );

    }


}



function print_xml_info( $appx3, $print = false )
{
    $appName3 = $appx3->nodeName;

    if( $print )
        print "|13:|" . $appName3 . "\n";

    $newdoc = new DOMDocument;
    $node = $newdoc->importNode($appx3, TRUE);
    $newdoc->appendChild($node);
    $html = $newdoc->saveHTML();

    if( $print )
        print "|" . $html . "|\n";
}


function truncate_names($longString) {
    global $source;
    $variable = strlen($longString);

    if ($variable < 63) {
        return $longString;
    } else {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = 63 - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if ($salida != $longString) {
            //Todo: swaschkut - xml attribute adding needed
            #add_log('warning', 'Names Normalization', 'Object Name exceeded >63 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
        }
        return $salida;
    }
}

function normalizeNames($nameToNormalize) {
    $nameToNormalize = trim($nameToNormalize);
    //$nameToNormalize = preg_replace('/(.*) (&#x2013;) (.*)/i', '$0 --> $1 - $3', $nameToNormalize);
    //$nameToNormalize = preg_replace("/&#x2013;/", "-", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\/]+/", "_", $nameToNormalize);
    $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_. ]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\s]+/", " ", $nameToNormalize);

    $nameToNormalize = preg_replace("/^[-]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/^[_]+/", "", $nameToNormalize);

    $nameToNormalize = preg_replace('/\(|\)/','',$nameToNormalize);

    return $nameToNormalize;
}
##################################################################



$configInput = array();
$configInput['type'] = 'file';
$configInput['filename'] = $util->configInput;

//Todo: find alternative way to get rule_merging
#CONVERTER::rule_merging( $v, $configInput, true, false, false, "tag", array( "1", "3" ) );


print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF PULSE UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
