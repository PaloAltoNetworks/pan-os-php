<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

#TODO: 20170918
# - Panorama - how to delete all DG informations? circle through all DG + shared
# - PANOS + Panroama | delete DEVICE related stuff
# delete specific with filter for DG
# delete specific with filter for template


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


########################################################################
########################################################################

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
    "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n" .
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
///

print "####################################################################################################################################\n";
print "####################################################################################################################################\n";
print "####################################################################################################################################\n";

if( $util->configType == 'panos' )
{
    if( $util->objectsLocation == 'shared' )
    {
        $xpath = "/config/shared";
        $element = "<entry name='shared'>";
    }
    else
    {
        $xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $util->objectsLocation . "']";
        $element = "<entry name='" . $util->objectsLocation . "'>";
    }

    $xpath_network = "/config/devices/entry[@name='localhost.localdomain']/network";
}
else
{
    if( $util->objectsLocation == 'shared' )
    {
        #derr('location=shared is not supported yet');
        $xpath = "/config/shared";
        $element = "<entry name='shared'>";
    }
    else
    {
        #$xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$objectsLocation."']";
        $xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$util->objectsLocation."']";
        $element = "<entry name='".$util->objectsLocation."'>";
        #element="<entry name='".$objectsLoation."'><devices><entry name='".$fw_test_serial."'/></devices>";

        $xpath_network = "/config/devices/entry[@name='localhost.localdomain']/network";
        $xpath_network = "";
    }

}


/*
 * #former config
#Problem: delete all XML information => problem with merger script now;
$tmp_cleanup = array();

$tmp_cleanup[] = "security";
$tmp_cleanup[] = "application-override";
$tmp_cleanup[] = "decryption";
$tmp_cleanup[] = "captive-portal";
$tmp_cleanup[] = "pbf";
$tmp_cleanup[] = "qos";
$tmp_cleanup[] = "dos";
$tmp_cleanup[] = "nat";

foreach( $tmp_cleanup as $ruletype )
{
    if( $util->configType == 'panos' )
        $cleanup[] = "rulebase/".$ruletype."/rules";
    else
    {
        if( $util->objectsLocation != 'shared' )
        {
            $cleanup[] = "pre-rulebase/".$ruletype."/rules";
            $cleanup[] = "post-rulebase/".$ruletype."/rules";
        }

    }
}
*/


$cleanup = array();

$cleanup[] = "address";
$cleanup[] = "address-group";
$cleanup[] = "service";
$cleanup[] = "service-group";
$cleanup[] = "tag";


$cleanup[] = "application";
$cleanup[] = "application-group";
$cleanup[] = "application-filter";

$cleanup[] = "zone";
$cleanup[] = "schedule";
$cleanup[] = "reports";


if( $util->configType == 'panos' )
    $cleanup[] = "rulebase";
else
{
    if( $util->objectsLocation != 'shared' )
    {
        $cleanup[] = "pre-rulebase";
        $cleanup[] = "post-rulebase";
    }

}


$cleanup_network = array();

#$cleanup_network[] = "interface/ethernet";
$cleanup_network[] = "interface";
$cleanup_network[] = "virtual-router";
$cleanup_network[] = "profiles";
$cleanup_network[] = "ike";
$cleanup_network[] = "qos";
$cleanup_network[] = "tunnel";
$cleanup_network[] = "virtual-wire";



/*
foreach( $cleanup as $entry )
{
    print "     "."*** delete each member from ".$entry." \n";
    $element .= "<".$entry."/>";
}
*/


$element .= "</entry>";


foreach( $cleanup as $entry )
{
    $tmp_xpath = $xpath;

    $tmp_xpath .= "/".$entry;
    #$element = "<address>";

    $apiArgs = Array();
    $apiArgs['type'] = 'config';
    $apiArgs['action'] = 'delete';
    $apiArgs['xpath'] = &$tmp_xpath;
    #$apiArgs['element'] = &$element;

    print "     "."*** delete each member from ".$entry." \n";

    if( $util->configInput['type'] == 'api' )
        $response = $pan->connector->sendRequest($apiArgs);
}


foreach( $cleanup_network as $entry )
{
    $tmp_xpath = $xpath_network;

    $tmp_xpath .= "/".$entry;
    #$element = "<address>";

    $apiArgs = Array();
    $apiArgs['type'] = 'config';
    $apiArgs['action'] = 'delete';
    $apiArgs['xpath'] = &$tmp_xpath;
    #$apiArgs['element'] = &$element;

    print "     "."*** delete each member from ".$entry." \n";

    if( $util->configInput['type'] == 'api' )
        $response = $pan->connector->sendRequest($apiArgs);
}



#former config
#Problem: delete also zones
/*
 *
$apiArgs = Array();
$apiArgs['type'] = 'config';
$apiArgs['action'] = 'edit';
$apiArgs['xpath'] = &$xpath;
$apiArgs['element'] = &$element;


if( $configInput['type'] == 'api' )
    $response = $pan->connector->sendRequest($apiArgs);
*/



// save our work !!!
$util->save_our_work();



print "\n\n************ END OF RESET-CONFIG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
