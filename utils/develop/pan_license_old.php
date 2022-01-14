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

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

function display_usage_and_exit($shortMessage = FALSE)
{
    print PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=[USER]@[MGMT-IP]" . "\n";
    print "php " . basename(__FILE__) . " help          : more help messages\n";
    print PH::boldText("\nExamples:\n");
    print " - php " . basename(__FILE__) . " in=swaschkut@shorts tool=sfdown case=[TAC#]'\n";

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

    print "\n";
    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(FALSE);
}


$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debug'] = array('niceName' => 'debug', 'shortHelp' => 'to debug connection to Palo Alto Networks license server');
$supportedArguments['debugapi'] = array('niceName' => 'debugapi', 'shortHelp' => 'debug API connection to PAN-OS device');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['serial'] = array('niceName' => 'serial', 'shortHelp' => 'the serial# of a Palo Alto Networks device');
$supportedArguments['folder'] = array('niceName' => 'folder', 'shortHelp' => 'the folder where to download all the license keys - default is the serial#');

PH::processCliArgs();

#####################################################
//CHANGE VARIABLES BASED ON FILTERS

$debugAPI = false;
$debug = false;

$input_file_name = dirname(__FILE__)."/software/software_downloader_devices.txt";

#####################################################
#####################################################
//FIXED VARIABLE VALUES

$data = array( 'Content-Type: application/x-www-form-urlencoded');

$protocol = 'https://';
$url = 'updates.paloaltonetworks.com';


//AUTHENTICATION BASIC
#$authtype = "BASIC";
#$user = PH::decrypt( PH::$softwareupdate_user_encrypt, PH::$softwareupdate_key  )[0];
#$pw = PH::decrypt( PH::$softwareupdate_pw_encrypt, PH::$softwareupdate_key  )[0];
#$site = '/license/LicenseService2.asmx/licenseit';


//AUTHENTICATION DIGIST
$authtype = "DIGEST";
#$user = PH::decrypt( PH::$license_user_encrypt_digest, PH::$license_key_digest  )[0];
#$pw = PH::decrypt( PH::$license_pw_encrypt__digest, PH::$license_key_digest  )[0];
$user = PH::decrypt( PH::$update_user_encrypt_digest, PH::$update_key_digest  )[0];
$pw = PH::decrypt( PH::$update_pw_encrypt_digest, PH::$update_key_digest  )[0];
$site = '/licensesvc/licenseservice.asmx/licenseit2';




$folder = '';
$authcode = '';
$uuid = '';
$cpuid = '';
$osversion = '';
$vmtype = '';
#####################################################
#####################################################

function curl_request($url, $fields = array(), $data = '', $authType = "BASIC" )
{
    global $user;
    global $pw;
    global $debug;
    if ($debug === true)
        print "\n-----" . __FUNCTION__ . "\n";

    $curl = curl_init();


    curl_setopt($curl, CURLOPT_HTTPHEADER, $data);

    curl_setopt($curl, CURLOPT_URL, $url);
    if ( $fields != '' )
        curl_setopt($curl, CURLOPT_POSTFIELDS, $fields);

    if( $authType == "BASIC" )
        curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    else
        curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);

    curl_setopt($curl, CURLOPT_USERPWD, $user . ":" . $pw);

    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($curl, CURLOPT_TIMEOUT, 15);
    if( $debug === true)
    {
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_VERBOSE, true);
    }
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

    $response = curl_exec($curl);
    curl_close($curl);

    #error_handling( $url, $system, $host, $response);

    return $response;
}


if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}



if( isset(PH::$args['in']) )
{
    $configInput = PH::$args['in'];
    #display_error_usage_exit('"in" is missing from arguments');

    if( !is_string($configInput) || strlen($configInput) < 1 )
        display_error_usage_exit('"in" argument is not a valid string');
}



if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

if( isset(PH::$args['debug'])  )
{
    $debug = true;
}

if( isset(PH::$args['in']) )
{
    $configInput = PH::processIOMethod($configInput, true);

    if( $configInput['status'] == 'fail' )
    {
        fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
    }

    /** @var $inputConnector PanAPIConnector */
    $inputConnector = null;
    $xmlDoc = new DOMDocument();

    if ( $configInput['type'] == 'api'  )
    {
        if($debugAPI)
            $configInput['connector']->setShowApiCalls(true);
        print " - Downloading config from API... ";
        $xmlDoc = $configInput['connector']->getCandidateConfig();
        print "OK!\n";
    }
    else
        derr('not supported yet');

    //
// Determine if PANOS or Panorama
//
    $xpathResult = DH::findXPath('/config/devices/entry/vsys', $xmlDoc);
    if( $xpathResult === FALSE )
        derr('XPath error happened');
    if( $xpathResult->length <1 )
        $configType = 'panorama';
    else
        $configType = 'panos';
    unset($xpathResult);


    if( $configType == 'panos' )
        $pan = new PANConf();
    else
        $pan = new PanoramaConf();

    print " - Detected platform type is '{$configType}'\n";

    if( $configInput['type'] == 'api' )
    {
        $pan->connector = $configInput['connector'];
        $inputConnector = $pan->connector;
    }
}
else
{
    $configInput['type'] = '';
}






if ( $configInput['type'] == 'api'  )
{
    if( $configType == 'panos' )
    {
        $serial = $inputConnector->info_serial;

        if( isset( $serial ) )
            $tmp = array( 'serial' => $serial
            );

        #print_r( $tmp );

        if( !isset($serial_array[ $serial ]) )
            $serial_array[ $serial ] = $tmp;
    }
    elseif( $configType == 'panorama' )
    {

        $serial = $inputConnector->info_serial;

        if( isset( $serial ) )
            $tmp = array( 'serial' => $serial
            );

        #print_r( $tmp );

        if( !isset($serial_array[ $serial ]) )
            $serial_array[ $serial ] = $tmp;

        $device_serials = $inputConnector->panorama_getConnectedFirewallsSerials();

        #if( count($device_serials) == 0 )
        #    derr( "no firewalls connected to this Panorama" );

        $i=0;
        foreach( $device_serials as $child )
        {
            if( isset( $child['serial'] ) )
                $tmp = array( 'serial' => $child['serial']
                );

            #print_r( $tmp );

            if( !isset($serial_array[ $child['serial'] ]) )
                $serial_array[ $child['serial'] ] = $tmp;
        }
    }
}
elseif( isset(PH::$args['serial']) )
{
    if( isset(PH::$args['serial']) )
    {
        $serial_array1 = explode( ',', PH::$args['serial']);

        foreach( $serial_array1 as $item )
        {
            $tmp = array( 'serial' => $item
            );

            if( !isset($serial_array[ $item ]) )
                $serial_array[ $item ] = $tmp;
        }

        if( $debug )
            print_r($serial_array);
    }
    else
    {
        derr('no serial available, please use: php pan_license.php serial=xxxx');
    }
}
elseif( file_exists($input_file_name) )
{
    $content = file_get_contents($input_file_name);


    $dom = new DOMDocument;
    $dom->loadXML($content);
    if( !$dom )
    {
        echo 'problems by parsing the document';
        exit;
    }

    $res = DH::findFirstElement('response', $dom);
    if( $res === FALSE )
        derr('cannot find <result>:' . DH::dom_to_xml($dom, 0, TRUE, 2));

    $res = DH::findFirstElement('result', $res);
    if( $res === FALSE )
        derr('cannot find <result>:' . DH::dom_to_xml($dom, 0, TRUE, 2));
    $res = DH::findFirstElement('devices', $res);
    if( $res === FALSE )
        derr('cannot find <devices>');


    foreach( $res->childNodes as $entry )
    {
        if( $entry->nodeType != XML_ELEMENT_NODE )
            continue;

        $serial = DH::findFirstElement('serial', $entry);
        if( $res === FALSE )
            derr('cannot find <serial>:' . DH::dom_to_xml($entry, 0, TRUE, 2));


        if( isset( $serial ) )
            $tmp = array( 'serial' => $serial->textContent
            );

        #print_r( $tmp );

        if( !isset($serial_array[ $serial->textContent ]) )
            $serial_array[ $serial->textContent ] = $tmp;
    }
}
elseif( ! isset(PH::$args['serial']) )
    display_error_usage_exit('"serial" is missing from arguments');



if( isset(PH::$args['folder']) )
{
    $folder = PH::$args['folder']."/";
}


foreach($serial_array as $serial_key => $serial)
{
    #$fields = 'serial='.$serial_key.'&authCode='.$authcode.'&uuid='.$uuid.'&cpuid='.$cpuid;


    $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'license-apikey' );
    $apikey = $connector->apikey;


    #create folder if not exist
    #if (!file_exists( 'license/'.$folder.$serial_key))
    if (!file_exists( dirname(__FILE__).'/license/'.$folder.$serial_key) || file_exists( dirname(__FILE__).'/license/'.$folder.$serial_key) )
    {
        if (!file_exists( dirname(__FILE__).'/license/'.$folder.$serial_key) )
            mkdir(dirname(__FILE__).'/license/' . $folder . $serial_key, 0777, TRUE);


        $fields = 'serial=' . $serial_key . '&authCode=' . $authcode . '&uuid=' . $uuid . '&cpuid=' . $cpuid . '&currentOSVersion=' . $osversion . '&vmtype=' . $vmtype . '&apikey=' . $apikey;
        if( $debug )
            print "curlRequest: |".$fields."|\n";
        $curl_response = curl_request($protocol . $url . $site, $fields, $data, $authtype);

        if( $debug )
            print "curlResponse: |".$curl_response . "|\n";

        if( $curl_response == '' )
            derr("empty string | no server response\n");

        if( strpos($curl_response, "502 Bad Gateway") !== FALSE )
            derr("SERVER response: '502 Bad Gateway'\n");

        if( strpos($curl_response, "Unauthorized: Access is denied due to invalid credentials.") !== FALSE )
            derr("SERVER response: 'Unauthorized: Access is denied due to invalid credentials.'\n");

        if( strpos($curl_response, "Invalid API Key") !== FALSE )
            derr("SERVER response: 'Invalid API Key'\n");

        if( strpos($curl_response, "Serial Number doesn't belong to this support account.") !== FALSE )
            derr("SERVER response: 'Serial Number doesn't belong to this support account. Use different License API key'");

        $xmlDoc = new DOMDocument();
        $xmlDoc->loadXML($curl_response);


        if( $debug )
            echo $xmlDoc->saveXML();

        print "\n######################################\n\n";
        print "Available licenses for Device serial#: " . $serial_key . "\n\n";


        $x = $xmlDoc->documentElement;
        foreach( $x->childNodes as $item )
        {
            /** @var DOMElement $node */
            if( $item->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $item->nodeName == 'licenseRet' )
            {
                $feature = '';
                $key = '';

                foreach( $item->childNodes as $item2 )
                {
                    /** @var DOMElement $node */
                    if( $item->nodeType != XML_ELEMENT_NODE )
                        continue;

                    if( $item2->nodeName == 'lfid' )
                        $lfid = $item2->nodeValue;

                    if( $item2->nodeName == 'partid' )
                        $partid = $item2->nodeValue;

                    if( $item2->nodeName == 'feature' )
                        $feature = $item2->nodeValue;

                    if( $item2->nodeName == 'feature_desc' )
                        $feature_desc = $item2->nodeValue;

                    if( $item2->nodeName == 'key' )
                        $key = $item2->nodeValue;

                    if( $item2->nodeName == 'authcode' )
                        $authcode = $item2->nodeValue;

                    if( $item2->nodeName == 'type' )
                        $type = $item2->nodeValue;

                    if( $item2->nodeName == 'regDate' )
                        $regdate = $item2->nodeValue;

                    if( $item2->nodeName == 'startDate' )
                        $startdate = $item2->nodeValue;

                    if( $item2->nodeName == 'expiration' )
                        $expiration = $item2->nodeValue;


                    if( $item2->nodeName != '#text' )
                    {
                        #print $item2->nodeName . " = " . $item2->nodeValue . "\n";
                    }
                }

                if( $feature != '' && $key != '' )
                {
                    print "   " . str_pad($feature_desc, 70, ' ') . " - " . str_pad($partid, 25) . " - " . $expiration . "\n";

                    $feature_name = str_replace(' ', '_', $feature);
                    $file_name = $serial_key . "-" . $feature_name . ".key.txt";

                    $license_folder = dirname(__FILE__).'/license/' . $folder . $serial_key . '/';


                    print "    - license files will be saved in: " . $license_folder . $file_name . "\n";

                    $file = fopen($license_folder . $file_name, "w") or die("Unable to open file!");
                    fwrite($file, $key);
                    fclose($file);


                    if( isset(PH::$args['in']) )
                    {
                        installLicense($inputConnector, $configType, $key, $serial_key);
                    }
                }
            }
        }
    }
    else
    {
        $dir = dirname(__FILE__).'/license/'.$folder.$serial_key;
        //read filenames from dir

        $files = scandir($dir);
        foreach( $files as $file )
        {
            if( $file == "." | $file == ".." )
                continue;

            $file_name = $dir."/".$file;

            print "    - FILE:".$file_name."\n";

            $content = file_get_contents($file_name);
            #print $content."\n";

           if( isset(PH::$args['in']) )
           {
               installLicense($inputConnector, $configType, $content, $serial_key);
           }
        }
    }


    print "\n######################################\n\n";

}

function installLicense( $inputConnector, $configType, $key, $serial_key )
{
    $response = null;
    PH::enableExceptionSupport();
    try
    {
        $cmd = "<request><license><install>".$key."</install></license></request>";

        if( $configType == 'panos' )
        {
            $response = $inputConnector->sendOpRequest( $cmd );
        }
        elseif( $inputConnector->info_serial === $serial_key )
        {
            //Panorama itself
            $response = $inputConnector->sendOpRequest( $cmd );
        }
        elseif( $configType == 'panorama' )
        {
            $fw_con = $inputConnector->cloneForPanoramaManagedDevice( $serial_key );
            //check if connected
            $response = $fw_con->sendOpRequest( $cmd );
        }

    }
    catch(Exception $e)
    {
        PH::disableExceptionSupport();

        if( strpos( $e->getMessage(), "<response status=\"success\">" ) === false )
        {
            print "   ***** API Error occured : ".$e->getMessage()."\n\n";
        }
        else
            print "    - Successfully installed license key\n\n\n";
    }

    PH::disableExceptionSupport();

    if( $response !== null )
    {
        $text = $response->saveXML();
        if( strpos( $text, "<msg><line>Successfully installed license key</line></msg>" ) === false )
        {
            #print "   ***** API Error occured : ".$e->getMessage()."\n\n";
        }
        else
            print "    - Successfully installed license key\n\n\n";
    }
}

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
