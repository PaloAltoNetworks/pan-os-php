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


//Todo: global variables
$generate_zip = TRUE;
$bpa_key = null;
$filename_prefix = date('Ymd_hi_');
$sleep_seconds = 5;


//FIXED VARIABLES
$bpa_url = 'https://bpa.paloaltonetworks.com/api/v1/';

function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars, "", $str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}

//needed for download
function send_bpa_api($url, $type = "GET", $config = null, $system_info = null, $license = null, $clock = null, $generate_zip = FALSE)
{
    global $bpa_key;
    global $util;

    $curl = curl_init();

    if( $type == "GET" )
    {
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "GET");
        $data = array("Authorization: Token $bpa_key");
    }
    else
    {
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        $data = array("Authorization: Token $bpa_key", "Content-Type: multipart/form-data");

        if( $generate_zip )
        {
            print " - generate_zip_bundle\n";
            $generate_zip_value = 'true';
        }
        else
            $generate_zip_value = 'false';


        $fields = array('xml' => $config, 'system_info' => $system_info, 'license_info' => $license, 'system_time' => $clock, 'generate_zip_bundle' => $generate_zip_value);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $fields);
    }

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($curl, CURLOPT_ENCODING, "");
    curl_setopt($curl, CURLOPT_MAXREDIRS, 0);
    curl_setopt($curl, CURLOPT_TIMEOUT, 0);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, TRUE);
    curl_setopt($curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $data);


    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);

    if( $util->debugAPI === TRUE )
    {
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($curl, CURLOPT_VERBOSE, TRUE);
    }


    #PH::enableExceptionSupport();
    try
    {
        $response = curl_exec($curl);

        if( $type == "POST" )
        {
            $reply = json_decode($response, TRUE);
            $response = $reply['task_id'];
        }
    } catch(Exception $e)
    {
        #PH::disableExceptionSupport();
        // Write exception code later
        echo "Exception (): " . $e->getMessage() . "\n";
    }

    curl_close($curl);
    //print_r($reply);

    return $response;

}


function request_bpa($connector)
{
    global $bpa_url;
    global $generate_zip;
    global $filename_prefix;
    global $sleep_seconds;


    $connector->refreshSystemInfos(TRUE);
    $connector->show_config();
    $connector->request_license_info();
    $connector->show_clock();

    $response_start = "<response status=\"success\">";
    $response_end = "</response>";

    $config = $response_start;
    $config .= strip_hidden_chars( $connector->show_config_raw->saveHTML() );
    $config .= $response_end;

    $system_info = $response_start;
    $system_info .= strip_hidden_chars( $connector->show_system_info_raw->saveHTML() );
    $system_info .= $response_end;

    $license = $response_start;
    $license .= strip_hidden_chars( $connector->request_license_info_raw->saveHTML() );
    $license .= $response_end;

    $clock = $response_start;
    $clock .= strip_hidden_chars( $connector->show_clock_raw->saveHTML() );
    $clock .= $response_end;

    // Submit job to BPA API
    echo "\n - Attempting to generate BPA for {$connector->info_hostname}\n";

    $result[$connector->info_serial] = send_bpa_api($bpa_url . 'create/', "POST", $config, $system_info, $license, $clock, $generate_zip);
    //Array( [ #SERIAL ] => TASKID )


    #echo "Pausing to allow processing. sleep " . $sleep_seconds . " seconds\n";
    #sleep($sleep_seconds);

    #print_r( $result );


    // get results from BPA API
    $loop = TRUE;
    while( $loop )
    {
        if( isset($result[$connector->info_serial]) )
        {
            echo "\n - Checking " . $connector->info_hostname . " job ID " . $result[$connector->info_serial] . "\n";
            $reply = send_bpa_api($bpa_url . 'results/' . $result[$connector->info_serial] . '/', "GET");
            $parsed_reply = json_decode($reply, TRUE);
            #print_r( $parsed_reply );
            if( $parsed_reply['status'] == 'processing' )
            {
                echo "  * Sleep for another " . $sleep_seconds . " seconds\n";
                sleep($sleep_seconds);
                continue;
            }
            elseif( $parsed_reply['status'] == "complete" )
            {
                $loop = FALSE;  // Exit outer while loop
                // Got BPA is JSON format in $reply
                print "  * store JSON response into: ".$filename_prefix . $connector->info_serial . ".json\n";
                file_put_contents($filename_prefix . $connector->info_serial . '.json', $reply);
                if( $generate_zip )
                {
                    //Todo: swaschkut 20210350 ZIP download no longer working WHY???
                    print " - Downloading zip for " . $connector->info_hostname . " job ID " . $result[$connector->info_serial] . "\n";
                    $reply = send_bpa_api($bpa_url . 'results/' . $result[$connector->info_serial] . '/download/', "GET");

                    print "  * ZIP file content length: ".strlen( $reply )."\n";

                    print "  * store ZIP response into: ".$filename_prefix . $connector->info_serial . ".zip\n";
                    file_put_contents($filename_prefix . $connector->info_serial . '.zip', $reply);

                    if( strpos( $reply, "Could not find report bundle") !== false )
                    {
                        print PH::boldText( "\n\n##########################################\n\n" );
                        print PH::boldText( "report bundle not found on BPA server\n" );
                        print PH::boldText( "\n\n##########################################\n" );

                    }
                }
            }
            elseif ($parsed_reply['status'] == 'error') {
                $loop = false;  // Exit outer while loop
                //print_r($parsed_reply);
                echo $reply . "\n";
            }
            else
            {
                print_r($parsed_reply);
                derr("something went wrong");
            }
        }

    }
}

$actions = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');
$supportedArguments['bpakey'] = array('niceName' => 'bpaKey', 'shortHelp' => 'BPA API Key, this can be requested via bpa@paloaltonetworks.com');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] [cycleconnectedFirewalls] bpakey=[BPA-API-KEY]";

if( !PH::$shadow_json )
{
    print "\n***********************************************\n";
    print "************ GENERATE BPA UTILITY ****************\n\n";
}

$util = new UTIL("custom", $argv, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################

if( isset(PH::$args['cycleconnectedfirewalls']) )
    $cycleConnectedFirewalls = TRUE;
else
    $cycleConnectedFirewalls = FALSE;


if( isset(PH::$args['bpakey']) )
{
    $bpa_key = PH::$args['bpakey'];
    //Todo: add this to .panconfkeystore

    //bpa.paloaltonetworks.com
}
else
{
    //Todo: check if available via .panconfigkeystore
    derr("argument 'bpakey=' is missing");
}

##########################################

print " - request info from Device\n";
request_bpa($util->pan->connector);


if( $cycleConnectedFirewalls && $configType == 'panorama' )
{
    $firewallSerials = $util->pan->connector->panorama_getConnectedFirewallsSerials();

    $countFW = 0;
    foreach( $firewallSerials as $fw )
    {
        $countFW++;
        print " ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **\n";
        $tmpConnector = $inputConnector->cloneForPanoramaManagedDevice($fw['serial']);

        if( $util->debugAPI )
            $tmpConnector->setShowApiCalls(TRUE);

        request_bpa($tmpConnector);
    }
}

##########################################
##########################################
if( !PH::$shadow_json )
{
    print "\n\n\n";

    #$util->save_our_work();

    print "\n\n************ END OF GENERATE BPA UTILITY ************\n";
    print     "**************************************************\n";
    print "\n\n";
}
