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

require_once("utils/common/actions.php");
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

###############################################################################
//PLAYBOOK
###############################################################################
//example of an JSON file syntax
$JSONarray =
'{
    "command": [
    [
        "device",
        "actions=logforwardingprofile-create-bp:true"
    ],
    [
        "device",
        "actions=securityprofile-create-alert-only:true"
    ],
    [
        "device",
        "actions=zoneprotectionprofile-create-bp"
    ],
    [
        "zone",
        "actions=zpp-Set:Recommended_Zone_Protection"
    ],
    [
        "zone",
        "actions=logSetting-Set:default"
    ],
    [
        "rule",
        "actions=logSetting-disable"
    ],
    [
        "rule",
        "actions=logsetting-set:default"
    ],
    [
        "rule",
        "actions=securityProfile-Group-Set:Alert-Only",
        "filter=!(secprof is.set) and (action is.allow)"
    ],
    [
        "rule",
        "actions=securityProfile-Profile-Set:vulnerability,Alert-Only-VP",
        "filter=(secprof type.is.profile) and !(secprof vuln-profile.is.set) and (action is.allow) and !(rule is.disabled)"
    ],
    [
        "rule",
        "actions=securityProfile-Profile-Set:spyware,Alert-Only-AS",
        "filter=(secprof type.is.profile) and !(secprof as-profile.is.set) and (action is.allow) and !(rule is.disabled)"
    ],
    [
        "rule",
        "actions=securityProfile-Profile-Set:virus,Alert-Only-AV",
        "filter=(secprof type.is.profile) and !(secprof av-profile.is.set) and (action is.allow) and !(rule is.disabled)"
    ],
    [
        "rule",
        "actions=securityProfile-Profile-Set:url-filtering,Alert-Only-URL",
        "filter=(secprof type.is.profile) and !(secprof url-profile.is.set) and (action is.allow) and !(rule is.disabled)"
    ],
    [
        "rule",
        "actions=securityProfile-Profile-Set:file-blocking,Alert-Only-FB",
        "filter=(secprof type.is.profile) and !(secprof file-profile.is.set) and (action is.allow) and !(rule is.disabled)"
    ],
    [
        "rule",
        "actions=securityProfile-Profile-Set:wildfire,Alert-Only-WF",
        "filter=(secprof type.is.profile) and !(secprof wf-profile.is.set) and (action is.allow) and !(rule is.disabled)"
    ],
    [
        "rule",
        "actions=securityProfile-Remove",
        "filter=(secprof is.set) and !(action is.allow)"
    ],
    [
        "rule",
        "actions=logstart-Disable"
    ],
    [
        "rule",
        "actions=logend-Enable"
    ],
    [
        "device",
        "actions=cleanuprule-create-bp:default"
    ]
],
    "in": "/Users/swaschkut/Downloads/ASA-Config-initial-10_0-fw.xml",
    "out": "final.xml",
    "stagename": "staging/visibility-"
}';

###############################################################################
//playbook arguments
###############################################################################
PH::processCliArgs();

$PHP_FILE = __FILE__;

if( isset(PH::$args['in']) )
    $input = PH::$args['in'];

//define out to save the final file into this file
if( isset(PH::$args['out']) )
    $output = PH::$args['out'];

if( isset(PH::$args['json']) )
{
    $jsonFile = PH::$args['json'];
    $filedata = file_get_contents($jsonFile);
    $details = json_decode( $filedata, true );

    if( !isset(PH::$args['in']) )
        $input = $details['in'];

    if( !isset(PH::$args['out']) )
        $output = $details['out'];

    $command_array = $details['command'];
    $stage_name = $details['stagename'];
}
else
{
    $details = json_decode($JSONarray, true);

    if( !isset(PH::$args['in']) )
        $input = $details['in'];

    if( !isset(PH::$args['out']) )
        $output = $details['out'];

    $command_array = $details['command'];
    $stage_name = $details['stagename'];
}

###############################################################################
//EXECUTION
###############################################################################
$out = "";
$in = "";

foreach( $command_array as $key => $command )
{
    $arguments = array();

    $script = $command[0];
    unset( $command[0] );
    $arg_string = "";


    foreach( $command as $arg )
        $arguments[] = $arg;

    ###############################################################################
    //IN / OUT specification
    ###############################################################################
    if( $key == 0 )
    {
        $out_counter = 0;
        $in = $input;
    }
    elseif( $key > 0 )
    {
        $in = $out;
        $out_counter = $out_counter+10;
    }
    $out = $stage_name.$out_counter.".xml";


    $arguments[] = "in=".$in;
    $arguments[] = "out=".$out;


    PH::resetCliArgs( $arguments);

    $tool = "pan-os-php type=".$script;
    PH::print_stdout("");
    PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
    PH::print_stdout("");
    $util = PH::callPANOSPHP( $script, PH::$argv, $argc, $PHP_FILE );

    PH::print_stdout("");
    PH::print_stdout( "############################################################################");
    PH::print_stdout("");
}

if( isset(PH::$args['out']) )
{
    //now save the latest out= from the foreach loop "$out" into "$output" file;
    PH::print_stdout("FINAL step: copy final configuration to: ".$output);
    PH::print_stdout("");
    PH::print_stdout( "############################################################################");
    copy( $out, $output );
}