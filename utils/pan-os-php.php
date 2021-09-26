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



set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";

PH::processCliArgs();

$supportedUTILTypes = array(
    "address", "service", "tag", "schedule", "application", "threat", "securityprofilegroup",
    "rule",
    "securityprofile",
    "stats",
    "device",
    "routing", "zone", "interface", "virtualwire"
    );
//Todo: all merger script need to be optimized to only a single class call
//$merger = new MERGER($utilType, $argv, $PHP_FILE, $supportedArguments, $usageMsg);
$supportedMERGERTypes = array(
    "address-merger",
    "service-merger",
    "tag-merger"
    );
//Todo: not supported scripts:
/*
 * appid-enabler
 * bpa-generator
 * checkpoint-exclude
 * csv-import
 * download-predefined
 * grp-static-to-dynamic
 * key-manager
 * override-finder
 * pan-diff
 * pan-config-size
 * panos-xml-issue-detector
 * panXML_op_JSON
 * register-ip-mgr
 * upload-config
 * userid-mgr
 */

$supportedArguments = array();
$usageMsg = PH::boldText('USAGE: ') . "php " . __FILE__ . " in=[filename]|[api://IP]|[api://serial@IP] type=address";

asort($supportedUTILTypes);
$typeUTIL = new UTIL("custom", $argv, __FILE__, $supportedArguments, $usageMsg);
$typeUTIL->supportedArguments['type'] = array('niceName' => 'type', 'shortHelp' => 'specify which type of PAN-OS-PHP UTIL script you like to use', 'argDesc' => implode("|", $supportedUTILTypes ));
$typeUTIL->supportedArguments['version'] = array('niceName' => 'version', 'shortHelp' => 'display actual installed PAN-OS-PHP framework version');


if( isset(PH::$args['version']) )
    exit();
elseif( !isset(PH::$args['type']) )
{
    $typeUTIL->display_error_usage_exit('"type" is missing from arguments');
}
elseif( isset(PH::$args['type']) )
{
    //find type argument
    $type = PH::$args['type'];

    //check if type argument is supported
    if( !in_array( $type, $supportedUTILTypes ) )
        $typeUTIL->display_usage_and_exit();


    //remove type argument from PHP $argv
    $array_key =  array_search("type=".$type, $argv,true)."\n";
    array_splice($argv, intval($array_key), 1);

    //set internal variables to empty array
    PH::$args = array();
    PH::$argv = array();

    PH::print_stdout("");
    PH::print_stdout("***********************************************");
    PH::print_stdout("*********** " . strtoupper( $type ) . " UTILITY **************");
    PH::print_stdout("");

    if( $type == "rule" )
        $util = new RULEUTIL($type, $argv, __FILE__." type=".$type);

    elseif( $type == "stats" )
        $util = new STATSUTIL( $type, $argv, __FILE__." type=".$type);

    elseif( $type == "securityprofile" )
        $util = new SECURITYPROFILEUTIL($type, $argv, __FILE__." type=".$type);

    elseif( $type == "routing" | $type == "zone" | $type == "interface" | $type == "virtualwire" )
        $util = new NETWORKUTIL($type, $argv, __FILE__." type=".$type);

    elseif( $type == "device" )
        $util = new DEVICEUTIL($type, $argv, __FILE__." type=".$type);

    else
        $util = new UTIL($type, $argv, __FILE__." type=".$type);

    PH::print_stdout("");
    PH::print_stdout("************* END OF SCRIPT " . strtoupper( $type ) . " ************" );
    PH::print_stdout("");

}
