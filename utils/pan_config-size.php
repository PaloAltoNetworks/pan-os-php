<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

//Todo:
/*
 - display all DG / template incl. size - does not matter how big
- same for multi-vsys - display all vsys - also if size of vsys is 100kB
 */


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

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
PH::print_stdout( " - display only XML content which is greater then: ".$minKiloByte."kB");

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
$len_overhead = $len_xml-$len_xml_reduced;
$len_overhead_percent = round( ( $len_overhead / $len_xml ) * 100, 0);

#PH::print_stdout( "\nLENGTH str:".$len_xml." [ reduced: ".$len_xml_reduced." | overhead: ".($len_xml-$len_xml_reduced)." ]");





PH::print_stdout( "LENGTH str:".$len_xml_reduced." [xml overhead: ".($len_overhead)." (".$len_overhead_percent."%) ]");

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
            #PH::print_stdout( "");
            #PH::print_stdout( $padding.$depth."<".$nodeName.">");

            if( $depth > 2 && $depth < 5 )
                PH::print_stdout( $padding."----------------------------------------------------------------------------------------");


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
                }
            }

            $string = str_pad( $padding."<".$nodeName.">", $pad_length);


            $length2_overhead = $length2-$length_reduced;
            $length2_overhead_percent = round( ( $length2_overhead / $length2 ) * 100, 0);
            PH::print_stdout( $string." | " .$padding.str_pad( $length_reduced. "kB [xml overhead:".($length2_overhead)."kB (".$length2_overhead_percent."%)]" , 10, " ", STR_PAD_LEFT));

            if( $depth == 3 )
                $previousNode = $nodeName;

            print_length( $node, $depth++, str_pad( $padding, strlen($padding)+5 ), $nodeName );
            $depth--;
        }

    }
}
##########################################


$util->save_our_work();


$filesize = filesize( $util->configInput['filename'] );
PH::print_stdout("");
$reduce_percent = round( ($len_xml_reduced/$filesize)*100 );
PH::print_stdout( "The size of your original file is ".convert($filesize )." [100%]. It can be reduces to ".convert($len_xml_reduced)." [".$reduce_percent."%] (which is a reduction of ".convert($filesize-$len_xml_reduced)." [".(100-$reduce_percent)."%])");
PH::print_stdout( PH::boldText( "Please be aware of that PAN-OS is automatically adding the xml overhead again during the next configuration load to the device" ) );

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
