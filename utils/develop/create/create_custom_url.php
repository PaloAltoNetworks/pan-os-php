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
$supportedArguments['custom_url_category'] = Array('niceName' => 'custom URL Category Name', 'shortHelp' => 'specify the custom URL category name');
$supportedArguments['url_file'] = Array('niceName' => 'custom URL import file', 'shortHelp' => 'specify the custom URL import file');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
    "custom_url_category=test\n".
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


///////////////////////////////////////////////////////

//Todo: no longer working on PAN-OS 10


if( !isset( PH::$args['custom_url_category'] ) )
    $util->display_error_usage_exit('"custom_url_category" argument is not set');
else
    $custom_url_categroy = PH::$args['custom_url_category'];



if( isset( PH::$args['url_file'] ) )
{
    ####
    #read from file
    $text = file_get_contents( PH::$args['url_file'] );

    if( $text === false )
        derr("cannot open file '".PH::$args['url_file']."'");

    $lines = explode("\n", $text);
    foreach( $lines as  $line)
    {
        $line = trim($line);
        if(strlen($line) == 0)
            continue;
        $list[$line] = $line;
    }
    ###
    print_r( $list );



    #///////////////////////////////////////////////////
    $zone_array = array();

    $str_list = "";
    $str_list .= "<list>";
    foreach( $list as $item )
    {
        $str_list .= "<member>".$item."</member>";

    }
    $str_list .= "</list>";
}
else
{
    $zone_array = array();


    $list = "";
    $list .= "<list>";
    for( $i = 1; $i<100; $i++ )
    #for( $i = 150000; $i<300000; $i++ )
    {
        $list .= "<member>www.test".$i.".de</member>";

    }
    $list .= "</list>";
}




$apiArgs = Array();
$apiArgs['type'] = 'config';
$apiArgs['action'] = 'set';



if( $util->configType == 'panos' )
    $apiArgs['xpath'] = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\''.$util->objectsLocation.'\']/profiles/custom-url-category/entry[@name=\''.$custom_url_categroy.'\']';
elseif( $util->configType == 'panorama' )
    $apiArgs['xpath'] = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\''.$util->objectsLocation.'\']/profiles/custom-url-category/entry[@name=\''.$custom_url_categroy.'\']';


$apiArgs['element'] = $list;

if( $util->configInput['type'] == 'api' )
    $response = $pan->connector->sendRequest($apiArgs);
else
    derr( "this script is working only in API mode\n" );

##############################################

PH::print_stdout( "" );

// save our work !!!
$util->save_our_work();


PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
