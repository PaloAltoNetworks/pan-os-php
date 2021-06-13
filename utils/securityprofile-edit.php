<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

print "\n***********************************************\n";
print   "*********** SECURITYPROFILE-EDIT UTILITY **************\n\n";


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

require_once dirname(__FILE__)."/../utils/lib/UTIL.php";

/*
$supportedArguments = array();

$supportedArguments['securityprofiletype'] = Array('niceName' => 'securityProfileType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: securityprofiletype=any  securityprofiletype=security,nat', 'argDesc' => 'all|any|security|nat|decryption|pbf|qos|dos|appoverride');
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['listactions'] = Array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
$supportedArguments['listfilters'] = Array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
$supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters rules based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator value)');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['stats'] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
$supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');
$supportedArguments['loadplugin'] = Array('niceName' => 'loadPlugin', 'shortHelp' => 'a PHP file which contains a plugin to expand capabilities of this script');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['expedition'] = Array('niceName' => 'expedition', 'shortHelp' => 'only used if called from Expedition Tool');
*/


print "\n";

$util = new SECURITYPROFILEUTIL("securityprofile", $argv, __FILE__);


print "\n\n*********** END OF SECURITYPROFILE-EDIT UTILITY **********\n";
print     "**************************************************\n";
print "\n\n";
