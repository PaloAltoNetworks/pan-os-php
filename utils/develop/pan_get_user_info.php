<?php
/**
 * ISC License
 *
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
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] file=[csv_text file] [out=]";


$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################


$util->load_config();
$util->location_filter();

$pan = $util->pan;

$connector = $pan->connector;


$apiArgs = array();
$apiArgs['type'] = 'config';
$apiArgs['action'] = 'get';
$apiArgs['xpath'] = '/config/mgt-config/users';


if( $util->configInput['type'] == 'api' )
    $response = $connector->sendRequest($apiArgs);
else
{
    //Todo: remove the entry in the XML, then offline mode should be supported
    derr("this script is working only in API mode\n");
}

print "\n";


$cursor = DH::findXPathSingleEntryOrDie('/response', $response);
$cursor = DH::findFirstElement('result', $cursor);

$cursor = DH::findFirstElement('users', $cursor);

foreach( $cursor->childNodes as $user )
{
    if( $user->nodeType != XML_ELEMENT_NODE ) continue;

    $appName = $user->nodeName;

    print "\nNAME: '".PH::boldText( $user->getAttribute('name') )."'\n";

    foreach( $user->childNodes as $node )
    {
        if( $node->nodeType != XML_ELEMENT_NODE )
            continue;

        if( $node->nodeName === "authentication-profile" )
        {
            print "AUTHENTICATION-PROFILE: '".PH::boldText( $node->textContent )."'\n";
        }
        elseif( $node->nodeName === "permissions" )
        {
            //role-based
            $cursor = DH::findFirstElement('role-based', $node);

            foreach( $cursor->childNodes as $node2 )
            {
                if( $node2->nodeType != XML_ELEMENT_NODE )
                    continue;

                print "ROLE: '".PH::boldText( $node2->nodeName )."'\n";
            }
        }
    }
    print "\n-----------------\n";
}

print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF PAN-OS USER INFO UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
