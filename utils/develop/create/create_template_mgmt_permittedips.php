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
require_once dirname(__FILE__) . "/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__) . "/../../../utils/lib/UTIL.php";

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();


PH::print_stdout("PAN-OS-PHP version: " . PH::frameworkVersion());


$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['template'] = array('niceName' => 'template', 'shortHelp' => 'specify if you want to limit your query to a TEMPLATE. By default template=any for Panorama', 'argDesc' => 'template');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
$supportedArguments['folder'] = array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');

$usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml location=vsys1 " .
    "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n" .
    "php " . basename(__FILE__) . " help          : more help messages\n";

##############

$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################

$util->load_config();
#$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


///////////////////////////////////////////////////////

if( $pan->isFirewall() )
{
    $str = "";
    $tmp_name = "Firewall";
}

elseif( $pan->isPanorama() )
{
    if( isset(PH::$args['template']) )
        $template_name = PH::$args['template'];
    else
        derr( "argument 'template=TEMPLATENAME' missing " );

    $template = $pan->findTemplate( $template_name );
    if( $template === null )
    {
        PH::print_stdout();
        PH::print_stdout("   * available templates:");
        foreach( $pan->getTemplates() as $temp )
            PH::print_stdout( "    - ".$temp->name() );

        derr( "template name: '".$template_name."' not found in configuration", null, false );
    }

    $str = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']";
    $tmp_name = "Template ".$template_name;
}

$tmp_additional = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/permitted-ip";



$tmp_ip = "192.168";
$thirdOctet = 255;
$fourthOctet = 255;

for( $i = 1; $i < $thirdOctet; $i++ )
{
    $tmp_value = "";
    for( $ii = 1; $ii < $fourthOctet; $ii++ )
    {
        //IP   A.B.C.D => A.B. == 192.168
        //C => i
        //D => ii
        $IP = $tmp_ip . "." . $i . "." . $ii . "";
        PH::print_stdout( "   - add IP: " . $IP . " to ".$tmp_name." mgmt permitted IPs" );


        $xpath = $str;
        $xpath .= $tmp_additional;

        $tmp_value .="<entry name='{$IP}'/>";
    }
    $connector->sendSetRequest($xpath, $tmp_value);
}


##############################################

print "\n\n\n";

// save our work !!!
$util->save_our_work();


print "\n\n************ END OF CREATE-INTERFACE UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
