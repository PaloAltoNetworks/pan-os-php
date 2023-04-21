<?php

// load PAN-OS-PHP library
require_once("lib/pan_php_framework.php");
require_once "utils/lib/UTIL.php";


PH::print_stdout();
PH::print_stdout("*********** START OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout();


$supportedArguments = array();
//PREDEFINED arguments:
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=filename.xml | api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');

$supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
$supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');

$supportedArguments['shadow-disableoutputformatting'] = array('niceName' => 'shadow-disableoutputformatting', 'shortHelp' => 'XML output in offline config is not in cleaned PHP DOMDocument structure');
$supportedArguments['shadow-enablexmlduplicatesdeletion']= array('niceName' => 'shadow-enablexmlduplicatesdeletion', 'shortHelp' => 'if duplicate objects are available, keep only one object of the same name');
$supportedArguments['shadow-ignoreinvalidaddressobjects']= array('niceName' => 'shadow-ignoreinvalidaddressobjects', 'shortHelp' => 'PAN-OS allow to have invalid address objects available, like object without value or type');
$supportedArguments['shadow-apikeynohidden'] = array('niceName' => 'shadow-apikeynohidden', 'shortHelp' => 'send API-KEY in clear text via URL. this is needed for all PAN-OS version <9.0 if API mode is used. ');
$supportedArguments['shadow-apikeynosave']= array('niceName' => 'shadow-apikeynosave', 'shortHelp' => 'do not store API key in .panconfkeystore file');
$supportedArguments['shadow-displaycurlrequest']= array('niceName' => 'shadow-displaycurlrequest', 'shortHelp' => 'display curl information if running in API mode');
$supportedArguments['shadow-reducexml']= array('niceName' => 'shadow-reducexml', 'shortHelp' => 'store reduced XML, without newline and remove blank characters in offline mode');
$supportedArguments['shadow-json']= array('niceName' => 'shadow-json', 'shortHelp' => 'BETA command to display output on stdout not in text but in JSON format');

//YOUR OWN arguments if needed
$supportedArguments['argument1'] = array('niceName' => 'ARGUMENT1', 'shortHelp' => 'an argument you like to use in your script');
$supportedArguments['optional_argument2'] = array('niceName' => 'Optional_Argument2', 'shortHelp' => 'an argument you like to define here');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] argument1 [optional_argument2]";


$util = new UTIL("custom", $argv, $argc,__FILE__, $supportedArguments, $usageMsg );

$util->utilInit();

$util->load_config();
$util->location_filter();


/** @var PANConf|PanoramaConf $pan */
$pan = $util->pan;


/** @var VirtualSystem|DeviceGroup $sub */
$sub = $util->sub;

/** @var string $location */
$location = $util->location;

/** @var boolean $apiMode */
$apiMode = $util->apiMode;

/** @var array $args */
$args = PH::$args;

PH::print_stdout();
PH::print_stdout( "    **********     **********" );
PH::print_stdout();

/*********************************
 * *
 * *  START WRITING YOUR CODE HERE
 * *
 * * List of available variables:
 *
 * * $pan : PANConf or PanoramaConf object
 * * $location : string with location name or undefined if not provided on CLI
 * * $sub : DeviceGroup or VirtualSystem found after looking from cli 'location' argument
 * * $apiMode : if config file was downloaded from API directly
 * * $args : array with all CLI arguments processed by PAN-OS-PHP
 * *
 */


########################################################################################################################

$fileName = "export.txt";



$configFile = file('./'.$fileName, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

$data = array();

/*
$obj_array = array( "schedObj", "zoneObj", "addrObj", "svcObj", "so_", "userObj", "userGroupObj", "uo_", "bwObj", "cfsUrlListObj", "policy", "iface" );

foreach( $obj_array as $obj_string )
    $$obj_string = array();
*/

$schedObj = array();
$zoneObj = array();

$addrObj = array();
$addrObjV6 = array();
$addrObjFqdn = array();

$svcObj = array();
$so = array();
$userObj = array();
$userGroupObj = array();
$uo = array();
$bwObj = array();
$cfsUrlListObj = array();
$policy = array();
$iface = array();


foreach( $configFile as $line => $names_line )
{
    /*
    foreach( $obj_array as $obj_string )
    {
        if( strpos( $names_line, $obj_string ) !== False )
        {
            array_push($obj_string , $names_line);
        }
        else
            $data[] = $names_line;

    }
    */

    if( strpos( $names_line, "schedObj" ) !== False )
        $schedObj[] = $names_line;
    elseif( strpos( $names_line, "zoneObj" ) !== False )
        $zoneObj[] = $names_line;



    elseif( strpos( $names_line, "addrObjV6" ) === 0 )
    {
        $names_line = str_replace( "addrObjV6", "", $names_line);
        $addrObjV6[] = $names_line;
    }
    elseif( strpos( $names_line, "addrObjFqdn" ) === 0 )
    {
        $names_line = str_replace( "addrObjFqdn", "", $names_line);
        $addrObjFqdn[] = $names_line;
    }
    //addrObj
    elseif( strpos( $names_line, "addrObj" ) === 0 )
    {
        $names_line = str_replace( "addrObj", "", $names_line);
        $addrObj[] = $names_line;
    }

    //svcObj
    elseif( strpos( $names_line, "svcObj" ) === 0 )
        $svcObj[] = $names_line;


    //so_
    elseif( strpos( $names_line, "so_" ) !== False )
    {
        $so[] = $names_line;
        $names_line = str_replace( "addrObj", "", $names_line);
    }

    //userObj
    elseif( strpos( $names_line, "userObj" ) !== False )
        $userObj[] = $names_line;
    //userGroupObj
    elseif( strpos( $names_line, "userGroupObj" ) !== False )
        $userGroupObj[] = $names_line;
    //uo_
    elseif( strpos( $names_line, "uo_" ) !== False )
        $uo[] = $names_line;
    //bwObj
    elseif( strpos( $names_line, "bwObj" ) !== False )
        $bwObj[] = $names_line;
    //cfsUrlListObj
    elseif( strpos( $names_line, "cfsUrlListObj" ) !== False )
        $cfsUrlListObj[] = $names_line;
    //policy
    elseif( strpos( $names_line, "policy" ) === 0 )
        $policy[] = $names_line;
    //iface_
    elseif( strpos( $names_line, "iface_" ) !== False )
        $iface[] = $names_line;
    else
        $data[] = $names_line;

}

#print_r($addrObj);

$new_array = array();

$addrTypeArray = array('addrObj', 'addrObjV6', 'addrObjFqdn');
foreach( $addrTypeArray as $type )
{
    foreach( $$type as $addr )
    {
        if( strpos( $addr, "Id_" ) !== False )
        {
            $tmp_name = explode( "Id_", $addr );
            if( $tmp_name[0] === "" )
                $id = explode( "=", $tmp_name[1] )[0];
        }

        $addr = str_replace("_".$id, "", $addr);
        $tmp_array = explode( "=", $addr );

        #$new_array[$type][$id][] = $addr;
        $key = $tmp_array[0];
        if($key == "")
            $key = "value";
        $new_array[$type][$id][$key] = $tmp_array[1];
    }
}


foreach( $new_array['addrObj'] as $addr )
{
    #print_r($addr);
    /*
    [Id] => OSTENSJO-VPN01
    [IdDisp] => OSTENSJO-VPN01
    [Type] => 1
    [Zone] => DMZ
    [Properties] => 14
    [TimeCreated] => 1646117792
    [TimeUpdated] => 1646117792
    [Ip1] => 79.160.81.151
    [Ip2] => 255.255.255.255
    [InstanceId] => 312
     */

    $name = urldecode($addr['Id']);

    $value = $addr['Ip1'];
    $netmask = CIDR::netmask2cidr( $addr['Ip2'] );
    if( $netmask == "" )
        $value = $value;
    else
        $value = $value."/".$netmask;
    $sub->addressStore->newAddress( $name, 'ip-netmask', $value );
}


foreach( $new_array['addrObjFqdn'] as $addr )
{
    #print_r($addr);
/*
    [Id] => ShipNet%20FTP
    [Type] => 8192
    [Zone] => WAN
    [Properties] => 14
    [InstanceId] => 300
    [TimeCreated] => 1642064577
    [TimeUpdated] => 1642064577
    [value] => ftp.shipnet.no
    [IsManualTTL] => off
    [ManualTTLSetting] => 0
 */
    $name = urldecode($addr['Id']);

    $value = $addr['value'];
    $sub->addressStore->newAddress( $name, 'fqdn', $value );
}

foreach( $new_array['addrObjV6'] as $addr )
{
    #print_r($addr);
    /*
     */
    $name = urldecode($addr['Id']);

    /*
    $value = $addr['value'];
    $sub->addressStore->newAddress( $name, 'fqdn', $value );
    */
}

###############################################################################
$svc_array = array();
foreach( $svcObj as $obj )
{
    if( strpos( $obj, "Id_" ) !== False )
    {
        $tmp_name = explode( "Id_", $obj );
        $id = explode( "=", $tmp_name[1] )[0];
    }

    $obj = str_replace("_".$id, "", $obj);
    $tmp_array = explode( "=", $obj );

    #$new_array[$type][$id][] = $addr;
    $key = $tmp_array[0];
    if($key == "")
        $key = "value";
    $svc_array[$id][$key] = $tmp_array[1];
}
#print_r($svc_array);

foreach($svc_array as $svc)
{
    #print_r( $svc );
    /*
    [svcObjId] => SMTP%20TLS
    [svcObjType] => 1
    [svcObjProperties] => 14
    [svcObjInstanceId] => 33
    [svcObjTimeCreated] => 1637155933
    [svcObjTimeUpdated] => 1637155933
    [svcObjIpType] => 6
    [svcObjPort1] => 587
    [svcObjPort2] => 587
    [svcObjManagement] => 0
    [svcObjHigherPrecedence] => off
     */
    $name = urldecode($svc['svcObjId']);

    $description_prot = false;
    $protocol = "tcp";
    if( $svc['svcObjIpType'] == 6 )
        $protocol = "tcp";
    elseif( $svc['svcObjIpType'] == 17 )
        $protocol = "udp";
    elseif( $svc['svcObjIpType'] == 0 )
    {
        $name = "tmp-".$name;
        $protocol = "tcp";
    }
    else
    {
        $name = "tmp-".$name;
        $protocol = "tcp";
        #print_r($svc);
        #exit();
        $description_prot = true;
    }

    if( $svc['svcObjPort1'] == $svc['svcObjPort2'] )
        $value = $svc['svcObjPort1'];
    else
        $value = $svc['svcObjPort1']."-".$svc['svcObjPort2'];

    $tmpservice = $sub->serviceStore->newService( $name, $protocol, $value );
    if( $description_prot )
        $tmpservice->setDescription( "protocol-id:{".$svc['svcObjIpType']."}" );
}

foreach( $so as $obj )
{
    if( strpos( $obj, "Id_" ) !== False )
    {
        $tmp_name = explode( "Id_", $obj );
        if( $tmp_name[0] === "" )
            $id = explode( "=", $tmp_name[1] )[0];
    }

    $obj = str_replace("_".$id, "", $obj);
    $tmp_array = explode( "=", $obj );

    #$new_array[$type][$id][] = $addr;
    $key = $tmp_array[0];
    if($key == "")
        $key = "value";
    $new_array[$id][$key] = $tmp_array[1];
}

###############################################################################
#print_r($policy);

$policy_array = array();
foreach( $policy as $arrayKey => $pol )
{
    if( strpos( $pol, "Action_" ) !== False )
    {
        $tmp_name = explode( "Action_", $pol );
        $id = explode( "=", $tmp_name[1] )[0];
    }
    elseif( strpos( $pol, "V6_" ) !== False )
        continue;

    $pol = str_replace("_".$id, "", $pol);
    $tmp_array = explode( "=", $pol );

    #$new_array[$type][$id][] = $addr;
    $key = $tmp_array[0];
    if($key == "")
        $key = "value";
    $policy_array['v4'][$id][$key] = $tmp_array[1];
    unset( $policy[$arrayKey] );
}


foreach( $policy as $pol )
{
    if( strpos( $pol, "ActionV6_" ) !== False )
    {
        $tmp_name = explode( "ActionV6_", $pol );
        $id = explode( "=", $tmp_name[1] )[0];
    }

    $pol = str_replace("_".$id, "", $pol);
    $tmp_array = explode( "=", $pol );

    #$new_array[$type][$id][] = $addr;
    $key = $tmp_array[0];
    if($key == "")
        $key = "value";
    $policy_array['v6'][$id][$key] = $tmp_array[1];
}


#print_r($new_array);

#print_r($policy_array);


########################################################################################################################



$util->save_our_work();
PH::print_stdout();
PH::print_stdout( "************* END OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout();

