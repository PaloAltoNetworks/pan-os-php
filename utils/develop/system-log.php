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

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";


PH::print_stdout( "" );
PH::print_stdout( "***********************************************" );
PH::print_stdout(   "*********** ".basename(__FILE__)." UTILITY **********" );
PH::print_stdout( "" );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'vsys1|shared|dg1');
$supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters logs based on a query. ie: 'filter=( (subtype eq auth) and ( receive_time geq !TIME! ) )'", 'argDesc' => '(field operator value)');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['stats'] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
$supportedArguments['hours'] = Array('niceName' => 'Hours', 'shortHelp' => 'display log for the last few hours');
$supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api://192.168.55.100 location=shared [Actions=display] ['Filter=(subtype eq pppoe)'] ...";

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();
#$util->load_config();

if( !$util->pan->isFirewall() )
    derr( "only PAN-OS FW is supported" );

if( !$util->apiMode && !$offline_config_test )
    derr( "only PAN-OS API connection is supported" );

$inputConnector = $util->pan->connector;

########################################################################################################################

if( isset(PH::$args['hours']) )
    $hours = PH::$args['hours'];
else
    $hours = 0.25;
PH::print_stdout( " - argument 'hours' set to '{$hours}'" );

date_default_timezone_set("Europe/Berlin");
$time = time() - ($hours * 3600);
$time = date('Y/m/d H:i:s', $time);


if( isset(PH::$args['filter']) )
{
    $query = "(".PH::$args['filter'].")";
    $query = str_replace( "!TIME!", "'".$time."'", $query );
}
else
{
    $query = '';
}


########################################################################################################################

$inputConnector->refreshSystemInfos();
$inputConnector->setShowApiCalls( $util->debugAPI );


$apiArgs = Array();
$apiArgs['type'] = 'log';
$apiArgs['log-type'] = 'system';
$apiArgs['query'] = $query;


$output = $inputConnector->getLog($apiArgs);


PH::print_stdout( "" );
PH::print_stdout( "##########################################" );
PH::print_stdout( "system log filter: '".$query."'" );
PH::print_stdout( "" );

if( !empty($output) )
{
    /*
    PH::print_stdout( "PPPoE was successfully established during the last ".$hours."h:" );
    PH::print_stdout( "" );
    */

    foreach( $output as $log )
    {
        /*
        $opaque = explode(',', $log['opaque']);
        $ipaddress = explode(':', $opaque[3]);

        PH::print_stdout( "time: " . $log['receive_time'] . " - ipaddress: " . $ipaddress[1] );
        */
        #print_r( $log );
        PH::print_stdout(  " - ".http_build_query($log,'',' | ') );
        PH::print_stdout( "" );
        PH::$JSON_OUT['system-log'][] = $log;
    }
}
else
{
    PH::print_stdout( "nothing found" );
    PH::print_stdout( "" );
    PH::$JSON_OUT['system-log'] = array();
}

PH::print_stdout( "##########################################" );
PH::print_stdout( "" );


$util->endOfScript();

