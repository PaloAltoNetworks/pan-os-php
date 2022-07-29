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

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

function display_usage_and_exit($shortMessage = FALSE)
{
    global $argv;
    PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml location=vsys1 " .
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']");
    PH::print_stdout( "php " . basename(__FILE__) . " help          : more help messages");


    if( !$shortMessage )
    {
        PH::print_stdout( PH::boldText("\nListing available arguments") );

        global $supportedArguments;

        ksort($supportedArguments);
        $text = "";
        foreach( $supportedArguments as &$arg )
        {
            $text .= " - " . PH::boldText($arg['niceName']);
            if( isset($arg['argDesc']) )
                $text .= '=' . $arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']) )
                $text .= "\n     " . $arg['shortHelp'];
            PH::print_stdout( $text);
        }

        PH::print_stdout();
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
        fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(TRUE);
}


PH::print_stdout();

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = FALSE;
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = FALSE;


$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['template'] = array('niceName' => 'template', 'shortHelp' => 'Panorama template');
$supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
$supportedArguments['folder'] = array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


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
    $debugAPI = TRUE;
}

if( isset(PH::$args['folder']) )
{
    $offline_folder = PH::$args['folder'];
}

if( isset(PH::$args['template']) )
{
    $template = PH::$args['template'];
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
    if( !$xmlDoc1->load($configInput['filename'], XML_PARSE_BIG_LINES) )
        derr("error while reading xml config file");

}
elseif( $configInput['type'] == 'api' )
{

    if( $debugAPI )
        $configInput['connector']->setShowApiCalls(TRUE);
    PH::print_stdout( " - Downloading config from API... ");

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        PH::print_stdout( " - 'loadPanoramaPushedConfig' was requested, downloading it through API...");
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    $hostname = $configInput['connector']->info_hostname;

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );



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

PH::print_stdout( " - Detected platform type is '{$configType}'");

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
        PH::print_stdout( " - No 'location' provided so using default ='vsys1'");
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'panorama' )
    {
        PH::print_stdout( " - No 'location' provided so using default ='shared'");
        $objectslocation = 'shared';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        PH::print_stdout( " - No 'location' provided so using default ='vsys1'");
        $objectslocation = 'vsys1';
    }
}


##########################################
##########################################
/*
$pan->load_from_domxml($xmlDoc1);

if( $configType == 'panorama' )
{
    if( ! isset(PH::$args['template']) )
    {
        derr( '"template" is missing from arguments' );
    }
}

##############

if( $configType == 'panos' )
{
    $sub = $pan->findVirtualSystem($objectslocation);
}
elseif( $configType == 'panorama' )
{
    $template = $pan->findTemplate( $template );

    $pan = $template->deviceConfiguration;
}
*/

##########################################
##########################################
$zone_array = array();


$pan->load_from_domxml($xmlDoc1);

if( $configType == 'panorama' )
{
    if( !isset(PH::$args['template']) )
        derr('"template" is missing from arguments');
}
else
    $template = "all";


if( ($template == 'all' || $template == "any") && $configType == 'panorama' )
    $template_array = $pan->templates;
else
    $template_array = explode(",", $template);


foreach( $template_array as $template )
{
    if( $objectslocation == "all" || $objectslocation == "any" || is_object($objectslocation) )
    {
        if( $configType == 'panos' )
            $tmp_location_array = $pan->virtualSystems;
        elseif( $configType == 'panorama' )
        {
            if( !is_object($template) )
                $template = $pan->findTemplate($template);

            $tmp_location_array = $template->deviceConfiguration->virtualSystems;
        }
    }
    else
        $tmp_location_array = explode(",", $objectslocation);


##############
//PH::print_stdout( "#######################################################################################################################");
    //DISPLAY
    PH::print_stdout( "----------------------");
    if( is_object($template) )
        PH::print_stdout( "TEMPLATE: " . PH::boldText($template->name()) );

    foreach( $tmp_location_array as $objectslocation )
    {
        if( is_object($objectslocation) )
            $sub = $objectslocation;
        else
        {
            if( $configType == 'panos' )
                $sub = $pan->findVirtualSystem($objectslocation);
            elseif( $configType == 'panorama' )
            {
                if( !is_object($template) )
                    $template = $pan->findTemplate($template);

                $sub = $template->deviceConfiguration->findVirtualSystem($objectslocation);
            }
        }

        if( $sub != null )
        {
            //todo: improvments needed so that output contains only IKE/IPsec information to specific VSYS

            PH::print_stdout( "");
            PH::print_stdout( "------------------------------------------------");
            PH::print_stdout( "VSYS: " . $sub->name() );

            $IKE = $sub->owner->network->ikeCryptoProfileStore->ikeCryptoProfil();
            if( count($IKE) > 0 )
                PH::print_stdout( PH::boldText("IKE - Phase 1") );

            foreach( $IKE as $ikeCryptoProfil )
            {
                PH::print_stdout( " - ".$ikeCryptoProfil->name() );
                $text = "hash: " . $ikeCryptoProfil->hash . " - dhgroup: " . $ikeCryptoProfil->dhgroup . " - encryption: " . $ikeCryptoProfil->encryption . " - ";
                if( $ikeCryptoProfil->lifetime_seconds != "" )
                    $text .= $ikeCryptoProfil->lifetime_seconds . " seconds";
                elseif( $ikeCryptoProfil->lifetime_minutes != "" )
                    $text .= $ikeCryptoProfil->lifetime_minutes . " minutes";
                elseif( $ikeCryptoProfil->lifetime_hours != "" )
                    $text .= $ikeCryptoProfil->lifetime_hours . " hours";
                elseif( $ikeCryptoProfil->lifetime_days != "" )
                    $text .= $ikeCryptoProfil->lifetime_days . " days";

                PH::print_stdout($text);
            }


            $ipsec = $sub->owner->network->ipsecCryptoProfileStore->ipsecCryptoProfil();
            if( count($ipsec) > 0 )
            {
                PH::print_stdout();
                PH::print_stdout( PH::boldText("IPSEC - Phase 2"));
            }

            foreach( $ipsec as $ipsecCryptoProfil )
            {
                PH::print_stdout( " - ".$ipsecCryptoProfil->name() . " - protocol: " . $ipsecCryptoProfil->ipsecProtocol );
                $text = "encryption: " . $ipsecCryptoProfil->encryption . " - authentication: " . $ipsecCryptoProfil->authentication . " - dhgroup: " . $ipsecCryptoProfil->dhgroup;

                if( $ipsecCryptoProfil->lifetime_seconds != "" )
                    $text .= " - lifetime: " . $ipsecCryptoProfil->lifetime_seconds . " seconds";
                elseif( $ipsecCryptoProfil->lifetime_minutes != "" )
                    $text .= " - lifetime: " . $ipsecCryptoProfil->lifetime_minutes . " minutes";
                elseif( $ipsecCryptoProfil->lifetime_hours != "" )
                    $text .= " - lifetime: " . $ipsecCryptoProfil->lifetime_hours . " hours";
                elseif( $ipsecCryptoProfil->lifetime_days != "" )
                    $text .= " - lifetime: " . $ipsecCryptoProfil->lifetime_days . " days";


                if( $ipsecCryptoProfil->lifesize_kb != "" )
                    $text .= " - lifesize: " . $ipsecCryptoProfil->lifesize_kb . " kb";
                elseif( $ipsecCryptoProfil->lifesize_mb != "" )
                    $text .= " - lifesize: " . $ipsecCryptoProfil->lifesize_mb . " mb";
                elseif( $ipsecCryptoProfil->lifesize_gb != "" )
                    $text .= " - lifesize: " . $ipsecCryptoProfil->lifesize_gb . " gb";
                elseif( $ipsecCryptoProfil->lifesize_tb != "" )
                    $text .= " - lifesize: " . $ipsecCryptoProfil->lifesize_tb . " tb";

                PH::print_stdout($text);
            }


            $ikeGateways = $sub->owner->network->ikeGatewayStore->gateways();
            if( count($ikeGateways) > 0 )
            {
                PH::print_stdout();
                PH::print_stdout( PH::boldText("IKE GATEWAY") );
            }


            foreach( $ikeGateways as $gateway )
            {
                $text = " - "."Gateway: " . str_pad($gateway->name(), 25) . " ";

                $text .= "-preSharedKey: " . $gateway->preSharedKey . " ";

                $text .= "-version: " . $gateway->version . " ";

                $text .= "-proposal: " . str_pad($gateway->proposal, 25) . " ";

                $text .= "-exchange-mode: " . str_pad($gateway->exchangemode, 25);
                PH::print_stdout($text);

                $text = "                                   ";
                $text .= "-localAddress: " . $gateway->localAddress . " ";
                $text .= "-localInterface: " . $gateway->localInterface . " ";
                $text .= "-peerAddress: " . $gateway->peerAddress . " ";
                $text .= "-localID: " . $gateway->localID . " ";
                $text .= "-peerID: " . $gateway->peerID . " ";

                $text .= "-NatTraversal: " . $gateway->natTraversal . " ";
                $text .= "-fragmentation: " . $gateway->fragmentation . " ";

                $text .= "-disabled: " . $gateway->disabled;
                PH::print_stdout($text);
            }


            $ipsecTunnel = $sub->owner->network->ipsecTunnelStore->tunnels();
            if( count($ipsecTunnel) > 0 )
            {
                PH::print_stdout();
                PH::print_stdout( PH::boldText("IPSEC tunnel") );
            }


            foreach( $ipsecTunnel as $tunnel )
            {
                $text = " - "."Tunnel: " . str_pad($tunnel->name(), 25) . " - IKE Gateway: " . $tunnel->gateway;
                $text .= " - interface: " . $tunnel->interface . " - proposal: " . $tunnel->proposal;
                $text .= " -disabled: " . $tunnel->disabled;
                PH::print_stdout($text);

                foreach( $tunnel->proxyIdList() as $proxyId )
                {
                    $text = "  - Name: " . $proxyId['name'] . " - ";
                    $text .= "local: " . $proxyId['local'] . " - ";
                    $text .= "remote: " . $proxyId['remote'] . " - ";
                    $text .= "protocol: " . $proxyId['protocol']['type'] . " - ";
                    $text .= "local-port: " . $proxyId['protocol']['localport'] . " - ";
                    $text .= "remote-port: " . $proxyId['protocol']['remoteport'] . " - ";
                    $text .= "type: " . $proxyId['type'];
                    PH::print_stdout($text);
                }
            }

            $greTunnel = $sub->owner->network->greTunnelStore->tunnels();
            if( count($greTunnel) > 0 )
            {
                PH::print_stdout();
                PH::print_stdout( PH::boldText("GRE tunnel") );
            }


            foreach( $greTunnel as $tunnel )
            {
                $text = " - "."Tunnel: " . str_pad($tunnel->name(), 25);

                foreach( $tunnel->tunnelInterface->interfaces() as $interface )
                    $text .= " - tunnelinterface: " .$interface->name() ;
                foreach( $tunnel->localInterface->interfaces() as $interface )
                    $text .= " - localinterface: " .$interface->name() ;

                $text .= " -disabled: " . $tunnel->disabled;
                PH::print_stdout($text);
            }

        }
    }
}

##############################################

PH::print_stdout();

// save our work !!!
if( $configOutput !== null )
{
    if( $configOutput != '/dev/null' )
    {
        $pan->save_to_file($configOutput);
    }
}


PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
