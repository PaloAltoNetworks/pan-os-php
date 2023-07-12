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

require_once("lib/pan_php_framework.php");


function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit();
}

PH::processCliArgs();


function display_usage_and_exit($shortMessage = FALSE)
{
    global $argv;
    print PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml location=vsys1 " .
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";
    print "php " . basename(__FILE__) . " help          : more help messages\n";


    if( !$shortMessage )
    {
        print PH::boldText("\nListing available arguments\n\n");

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            print " - " . PH::boldText($arg['niceName']);
            if( isset($arg['argDesc']) )
                print '=' . $arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']) )
                print "\n     " . $arg['shortHelp'];
            print "\n\n";
        }

        print "\n\n";
    }

    exit(1);
}


$file = '';
$debug = FALSE;
$pad = "     ";


$start = FALSE;
$start2 = FALSE;
$tmp_start2_value = "";
$tmp_start2 = "";


$master_array = array();


/*
$file_output = 'data.txt';
$file_s_nat = 's_nats.txt';
$file_proxy_nat = 'proxy_nats.txt';


$fp = fopen( $file_output, 'w');
$fp_s_nat = fopen( $file_s_nat, 'w');
$fp_proxy_nat = fopen( $file_proxy_nat, 'w');
$fp_servicegroup = fopen( "servicegroup.txt", 'w');
*/

function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars, "", $str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}

function get_string_between($string, $start, $end)
{
    $string = " " . $string;
    $ini = strpos($string, $start);
    if( $ini == 0 )
        return "";
    $ini += strlen($start);
    $len = strpos($string, $end, $ini) - $ini;

    return substr($string, $ini, $len);
}


function strpos_arr($haystack, $needle)
{
    if( !is_array($needle) ) $needle = array($needle);
    foreach( $needle as $what )
    {
        if( ($pos = strpos($haystack, $what)) !== FALSE ) return $pos;
    }
    return FALSE;
}


#############################################

$debugapi = FALSE;
$debug = FALSE;
$configOutput = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = array('niceName' => 'file', 'shortHelp' => 'sophos API file');


$warning = 0;

PH::processCliArgs();

foreach( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}

if( !isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if( isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if( !is_string($configOutput) || strlen($configOutput) < 1 )
        display_error_usage_exit('"out" argument is not a valid string');
}

if( isset(PH::$args['debugapi']) )
{
    $debugapi = TRUE;
    $debug = TRUE;
}


################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, TRUE);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");
    exit(1);
}

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( !$xmlDoc1->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif( $configInput['type'] == 'api' )
{
    derr('API support is not yet available');
    if( $debugapi )
        $configInput['connector']->setShowApiCalls(TRUE);
    print " - Downloading config from API... ";

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        print " - 'loadPanoramaPushedConfig' was requested, downloading it through API...";
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    $hostname = $configInput['connector']->info_hostname;

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );

    print "OK!\n";

}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult1 = DH::findXPath('/config/devices/entry/vsys', $xmlDoc1);
if( $xpathResult1 === FALSE )
    derr('XPath error happened');
if( $xpathResult1->length < 1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length < 1 )
        $configType = 'panorama';
    else
        $configType = 'pushed_panorama';
}
else
    $configType = 'panos';
unset($xpathResult1);

print " - Detected platform type is '{$configType}'\n";

############## actual not used

if( $configType == 'panos' )
    $pan = new PANConf();
elseif( $configType == 'panorama' )
    $pan = new PanoramaConf();


if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];


// </editor-fold>

################


//
// Location provided in CLI ?
//
if( isset(PH::$args['location']) )
{
    $objectslocation = PH::$args['location'];
    if( !is_string($objectslocation) || strlen($objectslocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'panorama' )
    {
        print " - No 'location' provided so using default ='shared'\n";
        $objectslocation = 'shared';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
}


$pan->load_from_domxml($xmlDoc1);

// Did we find VSYS1 ?
$v = $pan->findVirtualSystem('vsys1');
if( $v === null )
{
    derr("vsys1 was not found ? Exit\n");
}

########################################################################
########################################################################


#if( isset(PH::$args['file']) )
#    $file = PH::$args['file'];


if( isset(PH::$args['debug']) )
    $debug = TRUE;

#$file = 'sip-qfw-afw1.txt';

$folder = "etc";
$file = "pf.conf";


$file_content = file($folder . "/" . $file) or die("Unable to open file!");

$i = 0;
$j = 0;
$k = 0;
$rule_array = array();
$network_array = array();
$service_array = array();
$tmp_string = "";
$description = "";


$variable_array = array();


$new_file_content = array();
foreach( $file_content as $line )
{
    /*
     # include common tables file
        include "/etc/pf.d/pf.tables"

        ### include common macros
        include "/etc/firewall/common/common.include"

        # Tables
        table <smartcloud> persist file "/etc/firewall/common/tables/smartcloud.table"
        table <google> persist file "/etc/firewall/common/tables/google.table"
        table <leaddesk> persist file "/etc/firewall/common/tables/leaddesk.table"
     */

    if( strpos($line, "#") === 0 )
        continue;

    if( strpos($line, "include \"/") !== FALSE )
    {

        $new_line = str_replace("include \"/", "", $line);
        $new_line = str_replace("\"", "", $new_line);
        print $new_line . "\n";
        $new_line = strip_hidden_chars($new_line);
        $file_content1 = file($new_line) or die("Unable to open file!");

        $new_file_content = array_merge($new_file_content, $file_content1);

    }
}

$new_file_content = array_merge($new_file_content, $file_content);


$fp = fopen('tmp_all.txt', 'w');
fwrite($fp, print_r($new_file_content, TRUE));
fclose($fp);


foreach( $new_file_content as $line )
{


    $line = strip_hidden_chars($line);
    $line = str_replace(" \\", "", $line);    #|-> \
    $line = str_replace("\\\"", "", $line);   #|->\"
    $line = str_replace("\"", "", $line);     #|->"
    $line = str_replace("\\'", "", $line);    #|->\'


    $tmp_rule = array();
    if( strpos($line, "pass ") !== FALSE || strpos($line, "block ") !== FALSE )
    {
        //rule:|pass in log quick on $lan_if proto tcp from $videxio_clients to $ext_videxio_phonebook_host port $ext_videxio_phonebook_tcp_port keep state|


        if( strpos($line, " to ") === FALSE )
        {
            $from = get_string_between($line, " from ", " nat-to ");
        }

        if( strpos($line, " proto ") !== FALSE )
        {
            $interface = get_string_between($line, " on ", " proto ");
            $proto = get_string_between($line, " proto ", " from ");
            $from = get_string_between($line, " from ", " to ");
            $to = get_string_between($line, " to ", " port ");
        }
        elseif( strpos($line, " port ") !== FALSE )
        {
            $interface = get_string_between($line, " on ", " from ");
            $proto = "NOT SET";
            $from = get_string_between($line, " from ", " to ");

            if( strpos($line, " keep ") !== FALSE )
                $to = get_string_between($line, " to ", " keep");
            else
            {
                $pos_to = strpos($line, " to ");
                $to = substr($line, $pos_to);
            }


        }
        else
        {
            $interface = get_string_between($line, " on ", " from ");
            $proto = "NOT SET";
            $from = get_string_between($line, " from ", " to ");
            $to = get_string_between($line, " to ", " port ");

        }


        //special case needed if no keep is available
        if( strpos($line, " port ") === FALSE )
        {
            $port = "NO PORT defined";
        }
        elseif( strpos($line, " keep ") !== FALSE )
        {
            $port = get_string_between($line, " port ", " keep ");
        }
        elseif( strpos($line, " reply-to ") !== FALSE )
        {
            $port = get_string_between($line, " port ", " reply-to ");
        }
        elseif( strpos($line, " nat-to ") !== FALSE )
        {
            $port = get_string_between($line, " port ", " nat-to ");
        }
        elseif( strpos($line, " divert-to ") !== FALSE )
        {
            $port = get_string_between($line, " port ", " divert-to ");
        }
        elseif( strpos($line, " rdr-to ") !== FALSE )
        {
            $port = get_string_between($line, " port ", " rdr-to ");
        }
        else
        {
            $start_pos = strpos($line, " port ");
            $port = substr($line, $start_pos + 6);


            /*
            if( strpos( $port, "," ) !== false )
                print "multipe ports, ".$port."|\n";
            if( strpos( $port, ":" ) !== false )
                print "port range, ".$port."|\n";
            if( strpos( $port, "$" ) !== false )
                print "VARIABLE, ".$port."|\n";

            if( strpos( $port, "," ) === false && strpos( $port, ":" ) === false && strpos( $port, "$" ) === false)
                print "defined:|".$port."|\n";
            */
        }


        #print "rule:|".$line."|\n";

        $action = 'not set';
        if( strpos($line, "pass ") !== FALSE )
            $action = 'allow';
        elseif( strpos($line, "block ") !== FALSE )
            $action = 'deny';

        $tmp_rule['action'] = $action;

        if( strpos($interface, "$") !== FALSE )
        {
            #print "INTERFACE VARIABLE: ".$interface."\n";
            $interface = str_replace("{", "", $interface);
            $interface = str_replace("}", "", $interface);
            if( isset($variable_array[substr($interface, 1)]) )
            {
                $interface = $variable_array[substr($interface, 1)];
                #print "VARIABLE ".substr( $interface, 1 )." for interface: ".$interface."\n";
            }
            else
            {
                print "NOT found VARIABLE: " . substr($interface, 1) . "\n";

                //Todo: check if two interface need to be added
                //derr( "" );
            }
        }
        $tmp_rule['interface'] = $interface;

        $tmp_rule['proto'] = $proto;

        if( strpos($from, "$") !== FALSE )
        {
            #print "FROM VARIABLE: |".$from."|\n";
            $from = str_replace("{", "", $from);
            $from = str_replace("}", "", $from);
            if( isset($variable_array[substr($from, 1)]) )
            {
                $from = $variable_array[substr($from, 1)];
                #print "VARIABLE ".substr( $from, 1 )." for from: ".$from."\n";
            }
            else
            {
                print "NOT found VARIABLE: " . substr($from, 1) . "\n";
                #print_r($tmp_rule);

                #if( $from !== "$" )
                #derr( "" );
            }
        }
        $tmp_rule['from'] = $from;

        $tmp_rule['to'] = $to;
        $tmp_rule['port'] = $port;
        $tmp_rule['description'] = $description;

        $rule_array[] = $tmp_rule;
        print_r($tmp_rule);
    }
    else
    {

        #print "start: ".$start."\n";
        if( $start && strpos($line, ", ") !== FALSE )
        {
            $tmp_string .= $line;
            if( strpos($line, "}") !== FALSE )
            {
                $start = FALSE;
                print $tmp_string . "\n";
                //todo: where to save network object line
                //segum_instgwrec_eth={ 10.100.50.191, 10.100.50.192, 10.100.50.221, 10.100.50.222, 10.100.50.223, 10.100.50.224, 10.100.50.225, 10.100.50.226, 10.100.50.241, 10.100.5.....


                $tmp_variable = explode("=", $tmp_string);

                if( isset($variable_array[$tmp_variable[0]]) && ($variable_array[$tmp_variable[0]] != $tmp_variable[1]) )
                    derr("variable: " . $tmp_variable[0] . " already set. with value: " . $variable_array[$tmp_variable[0]] . "| new value= " . $tmp_variable[1]);
                else
                {
                    print "add variable: " . $tmp_variable[0] . " with value: " . $tmp_variable[1] . "\n";
                    $variable_array[$tmp_variable[0]] = $tmp_variable[1];
                }
            }


        }

        if( strpos($line, "={") !== FALSE && strpos($line, "}") === FALSE )
        {
            $start = TRUE;
            $tmp_string = $line;
        }
        /*
        elseif( strpos( $line, ", " ) !== false )
        {
            //do nothing, everything done befor
        }
        */
        elseif( strpos($line, "=") !== FALSE && strpos($line, "{") !== FALSE && strpos($line, "}") !== FALSE )
        {
            //Todo:
            //network or service variable check needed
            print "line|" . $line . "|\n";
            /*
             line|segum_dmz_xbn_db_clients={10.100.50.170, 10.100.50.180, 10.100.50.80, 10.100.50.190, 10.100.50.221, 10.100.50.230, 10.100.50.241}|
             */

            $tmp_variable = explode("=", $line);

            if( isset($variable_array[$tmp_variable[0]]) && ($variable_array[$tmp_variable[0]] != $tmp_variable[1]) )
                derr("variable: " . $tmp_variable[0] . " already set. with value: " . $variable_array[$tmp_variable[0]] . "| new value= " . $tmp_variable[1]);
            else
            {
                print "add variable: " . $tmp_variable[0] . " with value: " . $tmp_variable[1] . "\n";
                $variable_array[$tmp_variable[0]] = $tmp_variable[1];
            }


        }
        elseif( strpos($line, "=") !== FALSE && strpos($line, "{") === FALSE && strpos($line, "}") === FALSE )
        {
            //Todo:
            //single object or interface
            print "line|" . $line . "|\n";


            $tmp_variable = explode("=", $line);

            if( isset($variable_array[$tmp_variable[0]]) && ($variable_array[$tmp_variable[0]] != $tmp_variable[1]) )
                derr("variable: " . $tmp_variable[0] . " already set. with value: " . $variable_array[$tmp_variable[0]] . "| new value= " . $tmp_variable[1]);
            else
            {
                print "add variable: " . $tmp_variable[0] . " with value: " . $tmp_variable[1] . "\n";
                $variable_array[$tmp_variable[0]] = $tmp_variable[1];
            }


            /*
             line|ext_if=em1|
            line|ext_carp=carp3|
            line|lan_if=vlan6|
            line|lan_carp=carp6|
            line|dmz_if=vlan50|
            line|dmz_carp=carp50|
            line|#guest_if=em1|
            line|#guest_carp=carp1|
            line|pfsync_if=em0|
            line|wlan_guest_if=vlan210|
            line|wlan_vpn_if=vlan212|
            line|new_asa_if=vlan690|
            line|proxy_if=vlan601|
            line|segum_dmz_receiver_if=vlan611|
            line|net_mcsbn=172.30.40.0/24|
            line|net_france_domen=10.40.144.0/23|
            line|dmz_gumpekulla=10.100.50.0/24|
            line|wlan_guest_net=10.21.0.0/23|
            line|wlan_vpn_net=10.21.2.0/23|
            line|ibm_smartcloud=<smartcloud>|
            line|google=<google>|
            line|segum_xbn_net=172.29.4.0/24|
            line|secol_xbn_net=172.27.4.0/24|
            line|fw0=172.30.31.117|
            line|fw1=172.30.31.118|
            line|coreamqp_secol=172.30.21.239|
            line|coreamqp_segum=172.30.40.239|
            line|segum_myhotel=172.30.40.59|
            line|secol_myhotel=172.30.21.59|
             */
        }
        elseif( strpos($line, "# ") !== FALSE || strpos($line, "#") !== FALSE )
        {
            $description = $line;
            //nothing else to do
        }
        elseif( strpos($line, "# ----") !== FALSE || strpos($line, "#----") !== FALSE )
        {
            //nothing to do
            print "line|" . $line . "|\n";
        }
        elseif( $line == "###" || $line == "#" || strpos($line, "include") !== FALSE || strpos($line, "anchor") !== FALSE )
        {
            //nothing to do
        }

        elseif( $line !== "" )
        {
            if( $debug )
                print "line|" . $line . "|\n";
        }
    }


    /*
    if( strpos( $line, "net_backbone" ) !== false )
    {
        if( strpos( $line, "=" ) !== false && strpos( $line, "{" ) !== false && strpos( $line, "}" ) !== false )
            print "FOUND\n";

        print "line: ".$line."\n";
        print_r( $variable_array[ "net_backbone" ] );

        derr( "" );
    }
*/

}


foreach( $network_array as $rule )
{
    //generate network
}


foreach( $service_array as $rule )
{
    //generate service
}


#print_r( $rule_array );
foreach( $rule_array as $rule )
{

    /*
    if( $rule['proto'] !== 'tcp' && $rule['proto'] !== 'udp' )
    {
        print "|-".$rule['proto']."-|\n";
        print "count:|".strlen( $rule['proto'] )."|\n";
        mwarning( "proto???" , null, false);
        print_r($rule);
    }
    */

    #print_r($rule);
}


print "########################################################\n\n";
print "PF configuration exported\n\n";
print "########################################################\n\n";


##############################################

print "\n\n\n";


// save our work !!!
if( $configOutput !== null )
{
    if( $configOutput != '/dev/null' )
    {
        $pan->save_to_file($configOutput);
    }
}





