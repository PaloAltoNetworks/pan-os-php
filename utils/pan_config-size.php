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

/*


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['minkilobyte'] = Array('niceName' => 'MinKilobyte', 'shortHelp' => 'the amount of kB, where script start displaying XML information');
$supportedArguments['padlength'] = Array('niceName' => 'PadLength', 'shortHelp' => 'this is extending the padding for the middle line');
$supportedArguments['showalldg'] = Array('niceName' => 'ShowAllDG', 'shortHelp' => 'display all DG / template also if size is smaller as MinKiloByte');




$util = new UTIL( "custom", $argv, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();
*/

$util = new CONFIGSIZE( "config-size", $argv, __FILE__ );

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
