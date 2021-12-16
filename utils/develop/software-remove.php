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

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to "display" or "delete" installed and uploaded SW / content / anti-virus / wildfirew', 'argDesc' => 'action:arg1');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['xpath'] = Array('niceName' => 'xpath', 'shortHelp' => 'specify the xpath to get the value defined on this config');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "actions=display\n".
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


if( isset(PH::$args['actions']) )
{
    $actions = PH::$args['actions'];
    if( $actions !== "display" && $actions !== "delete" )
    {
        $util->display_error_usage_exit('"actions" argument only support "display" or "delete" ');
    }
}
else
    $actions = 'display';


########################################################################################################################

$queries['software'] = '&type=op&action=complete&xpath=/operations/request/system/software/install/version';
$queries['wildfire'] = '&type=op&action=complete&xpath=/operations/request/wildfire/upgrade/install/file';
$queries['anti-virus'] = '&type=op&action=complete&xpath=/operations/request/anti-virus/upgrade/install/file';
$queries['content'] = '&type=op&action=complete&xpath=/operations/request/content/upgrade/install/file';


######################################################################################################



########################################################################################################################
$connector->refreshSystemInfos();

PH::print_stdout( "" );
PH::print_stdout( "##########################################" );
PH::print_stdout( 'MASTER device serial: '.$connector->info_serial );
PH::print_stdout( "" );

PH::$JSON_TMP['serial'] = $connector->info_serial;
PH::print_stdout(PH::$JSON_TMP, false, "master device");
PH::$JSON_TMP = array();


if( $util->configType == 'panos' )
{
    if( $connector->serial != "" )
    {
        $fw_con = $connector->cloneForPanoramaManagedDevice($connector->serial);
        $fw_con->refreshSystemInfos();
        if( $util->debugAPI )
            $fw_con->setShowApiCalls( $util->debugAPI );

        checkInstallation( $fw_con, $queries);
    }
    else
    {
        $connector->refreshSystemInfos();

        checkInstallation( $connector, $queries);
    }
}
elseif( $util->configType == 'panorama' )
{
    $device_serials = $connector->panorama_getConnectedFirewallsSerials();

    //Todo: missing stuff, delete old content from Panorama
    //1) direct for Panorama
    //2) on Panorama for FWs

    $i=0;
    foreach( $device_serials as $child )
    {
        $fw_con = $connector->cloneForPanoramaManagedDevice($child['serial']);
        $fw_con->refreshSystemInfos();
        if( $util->debugAPI )
            $fw_con->setShowApiCalls( $util->debugAPI );

        $string = " - SERIAL: ".$child['serial'];
        $string .= "  -  ".$child['hostname']." - ";
        $string .= $fw_con->info_mgmtip;

        PH::print_stdout( $string );
        $i++;


        //only direct FW connect possible to use for getting correct info
        $direct_fw_con = new PanAPIConnector( $fw_con->info_mgmtip, $connector->apikey);
        $direct_fw_con->refreshSystemInfos();
        if( $util->debugAPI )
            $direct_fw_con->setShowApiCalls( $util->debugAPI );

        checkInstallation( $direct_fw_con, $queries);
    }
}

//use class
PH::print_stdout(PH::$JSON_TMP, false, "serials");
PH::$JSON_TMP = array();

$util->endOfScript();

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
########################################################################################################################

function checkInstallation( $connector, $queries)
{
    global $actions;

    foreach( $queries as $key => $query )
    {
        PH::print_stdout("");
        PH::print_stdout("-------------------------------");
        PH::print_stdout("Display uploaded part for: ".$key);
        PH::print_stdout("");

        $string = " - installed: ";

        $key2 = "update";
        if( $key === 'content' )
            $version = $connector->info_app_version;
        elseif( $key === "software" )
        {
            $version = $connector->info_PANOS_version;
            $key2 = "version";
        }

        elseif( $key === "anti-virus" )
            $version = $connector->info_av_version;
        elseif( $key === "wildfire" )
            $version= $connector->info_wildfire_version;

        PH::print_stdout( $string.$version );
        PH::print_stdout("");

        #$queries['content'] = '&type=op&action=complete&xpath=/operations/request/content/upgrade/install/file';
        $ret= $connector->sendRequest($query);

        #$tmp_ret = $ret->saveXML();
        #print $tmp_ret."\n";

        $ret = DH::findFirstElement("response", $ret);
        if( $ret !== false )
            $ret = DH::findFirstElement("completions", $ret);

        if( $ret !== false )
        {
            PH::print_stdout(" - uploaded:");
            foreach( $ret->childNodes as $completion )
            {
                $value = DH::findAttribute('value', $completion);
                PH::print_stdout( "   - ".$value );

                //DO not delete main SW version
                $mainSWversion = "";
                if( strpos( $version, "." ) !== false && strpos( $version, "pan" ) === false )
                {
                    $version_array = explode( ".", $version );
                    $mainSWversion = $version_array[0].".".$version_array[1].".0";
                }
                if( $actions === 'delete' && strpos( $value, $version ) === FALSE && ( $mainSWversion === "" || strpos( $value, $mainSWversion ) === FALSE ) )
                {
                    PH::enableExceptionSupport();
                    try
                    {
                        PH::print_stdout( "     * try to delete:".$value );
                        //api/?type=op&cmd=<delete><content><update></update></content></delete>
                        $cmd = '<delete><'.$key.'><'.$key2.'>'.$value.'</'.$key2.'></'.$key.'></delete>';
                        $res = $connector->sendOpRequest($cmd, TRUE);
                        $tmp_ret = $res->saveXML();
                        PH::print_stdout( "       * ".$tmp_ret );
                    }
                    catch(Exception $e)
                    {
                        PH::disableExceptionSupport();

                        PH::print_stdout("          ***** API Error occured : ".$e->getMessage() );
                    }
                }
            }
        }
    }
}