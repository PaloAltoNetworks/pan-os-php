<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

//Todo:
/*
 - print all DG / template incl. size - does not matter how big
- same for multi-vsys - print all vsys - also if size of vsys is 100kB
 */

print "\n***********************************************\n";
print "************ PAN-OS config size ****************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";


$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['minkilobyte'] = Array('niceName' => 'MinKilobyte', 'shortHelp' => 'the amount of kB, where script start displaying XML information');
$supportedArguments['padlength'] = Array('niceName' => 'PadLength', 'shortHelp' => 'this is extending the padding for the middle line');
$supportedArguments['showalldg'] = Array('niceName' => 'ShowAllDG', 'shortHelp' => 'display all DG / template also if size is smaller as MinKiloByte');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] [out=]";


$util = new UTIL( "custom", $argv, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################
$pad_length = 60;
if( isset(PH::$args['minkilobyte'])  )
{
    $minKiloByte = PH::$args['minkilobyte'];
    if( $minKiloByte <= 5 )
        $pad_length = 80;
}
else
{
    $minKiloByte = 1000;
}
#$minKiloByte = $minKiloByte*1000;
print " - display only XML content which is greater then: ".$minKiloByte."kB\n";

if( isset(PH::$args['padlength'])  )
    $pad_length = PH::$args['padlength'];

if( isset(PH::$args['showalldg'])  )
    $showalldg = true;
else
    $showalldg = false;

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
//Todo start writing here

$util->xmlDoc->preserveWhiteSpace = false;
$util->xmlDoc->formatOutput = true;

$lineReturn = false;
$indentingXml = -1;
$indentingXmlIncreament = 0;

$xml = &DH::dom_to_xml( $util->xmlDoc );
$xml_reduced = &DH::dom_to_xml( $util->xmlDoc, $indentingXml, $lineReturn, -1, $indentingXmlIncreament );

$len_xml = strlen( $xml );
$len_xml_reduced = strlen( $xml_reduced );

#print "\nLENGTH str:".$len_xml." [ reduced: ".$len_xml_reduced." | overhead: ".($len_xml-$len_xml_reduced)." ]\n";
print "\nLENGTH str:".$len_xml_reduced." [xml overhead: ".($len_xml-$len_xml_reduced)." ]\n";

print_length( $util->xmlDoc );


function print_length( $xmlRoot, $depth = -1, $padding = "", $previousNode = "" )
{
    global $minKiloByte;
    global $pad_length;
    global $util;
    global $showalldg;
    global $lineReturn;
    global $indentingXml;
    global $indentingXmlIncreament;

    $depth++;
    foreach( $xmlRoot->childNodes as $node )
    {
        if ($node->nodeType != XML_ELEMENT_NODE)
            continue;

        $nodeName = $node->nodeName;
        $nodeValue = $node->nodeValue;

        $xml = &DH::dom_to_xml( $node );
        $xml_reduced = &DH::dom_to_xml( $node, $indentingXml, $lineReturn, -1, $indentingXmlIncreament );

        $length2 = strlen( $xml );
        $length2 = round( $length2/1000 );

        $length_reduced = strlen( $xml_reduced );
        $length_reduced = round( $length_reduced/1000 );

        if( $depth <= 1
            || $length2 > $minKiloByte
            || ( ( $previousNode == "device-group" || $previousNode == "template" || $previousNode == "container" ) && $showalldg )
        )
        {
            #print "\n";
            #print $padding.$depth."<".$nodeName.">";

            if( $depth > 2 && $depth < 5 )
                print $padding."----------------------------------------------------------------------------------------\n";


            if( $nodeName == "entry" )
            {
                $attname = DH::findAttribute('name', $node);
                $nodeName = $nodeName." name=".$attname;

                if( $util->configType != 'panos' && $depth == 4 )
                {
                    if( $util->configType == 'fawkes' )
                        $v = $util->pan->findContainer( $attname );
                    else
                        $v = $util->pan->findDeviceGroup( $attname );

                    #print "DG name: ".$v->name()."\n";
                    #$v->display_statistics();
                }
            }

            #print str_pad( $padding.$depth."<".$nodeName.">", $pad_length);
            print str_pad( $padding."<".$nodeName.">", $pad_length);


            #print " | LENGTH: ".$length1." - strlen:" .$length2. "\n";
            #print " | " .$padding.str_pad( $length2. " kB [red:".$length_reduced." kB | overh:".($length2-$length_reduced)."kB]" , 10, " ", STR_PAD_LEFT)."\n";
            print " | " .$padding.str_pad( $length_reduced. "kB [xml overhead:".($length2-$length_reduced)."kB]" , 10, " ", STR_PAD_LEFT)."\n";

            if( $depth == 3 )
                $previousNode = $nodeName;

            print_length( $node, $depth++, str_pad( $padding, strlen($padding)+5 ), $nodeName );
            $depth--;
        }

    }
}
##########################################

#print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF PAN-OS config size ************\n";
print     "**************************************************\n";
print "\n\n";
