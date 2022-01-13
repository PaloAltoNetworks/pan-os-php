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
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";

require_once dirname(__FILE__)."/../utils/lib/MAXMIND__.php";
require_once dirname(__FILE__)."/../utils/lib/PLAYBOOK__.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL_GET_ACTION_FILTER.php";
require_once dirname(__FILE__)."/../utils/lib/IRONSKILLET_UPDATE__.php";

PH::processCliArgs();

//Todo: API not supported scripts:
//custom
/*
 * csv-import

 * util get action filter
*/

//open
/*
 * checkpoint-exclude
 * grp-static-to-dynamic //very old; create action for pa_address-edit
 */

//Todo: more JSON support needed
/*
 * appid-enabler
 * override-finder
 * pan-diff
 * all object merger
 * upload
 * xmlissue
 * pan-config-size
 * bpa-generator
 * panXML_op_JSON
 * register-ip-mgr
 * userid-mgr
 */
$PHP_FILE = __FILE__;

$supportedArguments = array();
$usageMsg = PH::boldText('USAGE: ') . "php " . $PHP_FILE . " in=[filename]|[api://IP]|[api://serial@IP] type=address";

asort(PH::$supportedUTILTypes);
$typeUTIL = new UTIL("custom", $argv, $argc, $PHP_FILE, $supportedArguments, $usageMsg);
$typeUTIL->supportedArguments['type'] = array('niceName' => 'type', 'shortHelp' => 'specify which type of PAN-OS-PHP UTIL script you like to use', 'argDesc' => implode("|", PH::$supportedUTILTypes ));
$typeUTIL->supportedArguments['version'] = array('niceName' => 'version', 'shortHelp' => 'display actual installed PAN-OS-PHP framework version');


if( isset(PH::$args['version']) )
{
    PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() . " [".PH::frameworkInstalledOS()."]" );
    PH::print_stdout( " - ".dirname($PHP_FILE) );
    PH::print_stdout( " - PHP version: " . phpversion() );

    PH::$JSON_TMP['version'] = PH::frameworkVersion();
    PH::$JSON_TMP['os'] = PH::frameworkInstalledOS();
    PH::$JSON_TMP['folder'] = dirname($PHP_FILE);
    PH::$JSON_TMP['php-version'] = phpversion();

    PH::print_stdout( PH::$JSON_TMP, false, 'pan-os-php' );
    PH::$JSON_TMP = array();
    if( PH::$shadow_json )
    {
        PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
        print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
    }

    exit();
}
elseif( !isset(PH::$args['type']) )
{
    foreach( PH::$supportedUTILTypes as $type )
        PH::$JSON_TMP[] = $type;
    PH::print_stdout( PH::$JSON_TMP, false, 'type' );

    mwarning( '"type" is missing from arguments', null, false );
    $typeUTIL->display_usage_and_exit();
}
elseif( isset(PH::$args['type']) )
{
    //find type argument
    $type = PH::$args['type'];

    //check if type argument is supported
    if( !in_array( $type, PH::$supportedUTILTypes ) )
        $typeUTIL->display_usage_and_exit();


    //remove type argument from PHP $argv
    $array_key =  array_search("type=".$type, $argv,true)."\n";
    array_splice($argv, intval($array_key), 1);

    //set internal variables to empty array
    PH::$args = array();
    PH::$argv = array();

    $util = PH::callPANOSPHP( $type, $argv, $argc, $PHP_FILE );

    #$util->endOfScript();
}
