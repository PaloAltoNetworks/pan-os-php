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

require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$displayAttributeName = false;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
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


########################################################################################################################

$subName = "Corporate-PBR-Global";
$subName = "vsys1";


$tagName= "CheckPoint";
$tagName= "SVEN";
########################################################################################################################

$shared_addressStroe = $pan->addressStore;

#$destDG = $pan->findDeviceGroup( $subName );
$destDG = $pan->findVirtualSystem( $subName );

$destAddressStore = $destDG->addressStore;

$sharedAddressGroupXmlroot = $pan->addressStore->addressGroupRoot;
$destAddressGroupXmlroot = $destDG->addressStore->addressGroupRoot;
if( $destAddressGroupXmlroot === null )
    $destAddressGroupXmlroot = DH::findFirstElementOrCreate( "address-group", $destDG->xmlroot);


$sharedAddressXmlroot = $pan->addressStore->addressRoot;
$destAddressXmlroot = $destDG->addressStore->addressRoot;
if( $destAddressXmlroot === null )
    $destAddressXmlroot = DH::findFirstElementOrCreate( "address", $destDG->xmlroot);

if( $sharedAddressGroupXmlroot !== null && $sharedAddressGroupXmlroot !== FALSE )
    foreach( $sharedAddressGroupXmlroot->childNodes as $obj )
    {
        if( $obj->nodeType != XML_ELEMENT_NODE )
            continue;

        $tagXML = DH::findFirstElement('tag', $obj);
        if( $tagXML === FALSE )
            continue;

        $move = FALSE;
        foreach( $tagXML->childNodes as $tag )
        {
            if( $tag->nodeType != XML_ELEMENT_NODE )
                continue;
            if( $tag->nodeValue == $tagName )
                $move = TRUE;
        }

        if( $move )
        {
            DH::DEBUGprintDOMDocument( $obj );

            $tmp_node = $obj->cloneNode( true);
            $destAddressGroupXmlroot->appendChild( $tmp_node );

            $sharedAddressGroupXmlroot->removeChild($obj);
        }
    }

if( $sharedAddressXmlroot !== null && $sharedAddressXmlroot !== FALSE )
    foreach( $sharedAddressXmlroot->childNodes as $obj )
    {
        if( $obj->nodeType != XML_ELEMENT_NODE )
            continue;

        DH::DEBUGprintDOMDocument( $obj );

        print "NAME: ".DH::findAttribute( 'name', $obj )."\n";
        if( $obj->nodeType != XML_ELEMENT_NODE )
            continue;

        $tagXML = DH::findFirstElement('tag', $obj);
        if( $tagXML === FALSE )
            continue;

        $move = FALSE;
        foreach( $tagXML->childNodes as $tag )
        {
            if( $tag->nodeType != XML_ELEMENT_NODE )
                continue;
            PH::print_stdout( $tag->nodeValue );
            if( $tag->nodeValue == $tagName )
                $move = TRUE;
        }

        if( $move )
        {


            $tmp_node = $obj->cloneNode( true);
            $destAddressXmlroot->appendChild( $tmp_node );
            #$destAddressXmlroot->appendChild( $obj );

            $sharedAddressXmlroot->removeChild( $obj );
        }
    }





$util->save_our_work();

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
