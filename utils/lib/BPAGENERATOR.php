<?php


class BPAGENERATOR extends UTIL
{
    //Todo: global variables
    public $generate_zip = TRUE;
    public $bpa_key = null;
    public $filename_prefix = null;
    public $sleep_seconds = 5;

    public $bpa_url = 'https://bpa.paloaltonetworks.com/api/v1/';



    public function utilStart()
    {
        $this->filename_prefix = date('Ymd_hi_');

        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] [cycleconnectedFirewalls] bpa-apikey=[BPA-API-KEY]";

        $this->prepareSupportedArgumentsArray();

        $this->utilInit();

        $this->main();


        $this->endOfScript();
    }

    public function main()
    {
        if( isset(PH::$args['cycleconnectedfirewalls']) )
            $cycleConnectedFirewalls = TRUE;
        else
            $cycleConnectedFirewalls = FALSE;


        if( isset(PH::$args['bpa-apikey']) )
        {
            $this->bpa_key = PH::$args['bpa-apikey'];
            //store key in .panconfkeystore
            $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'bpa-apikey', $this->bpa_key );
        }
        else
        {
            //check if available via .panconfigkeystore
            $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'bpa-apikey' );
            $this->bpa_key = $connector->apikey;
        }

        ##########################################

        PH::print_stdout( " - request info from Device" );
        $this->request_bpa($this->pan->connector);


        if( $cycleConnectedFirewalls && $this->configType == 'panorama' )
        {
            $firewallSerials = $this->pan->connector->panorama_getConnectedFirewallsSerials();

            $countFW = 0;
            foreach( $firewallSerials as $fw )
            {
                $countFW++;
                PH::print_stdout(" ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **" );
                $tmpConnector = $this->pan->connector->cloneForPanoramaManagedDevice($fw['serial']);

                if( $this->debugAPI )
                    $tmpConnector->setShowApiCalls(TRUE);

                $this->request_bpa($tmpConnector);
            }
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for bpa generator');
        $this->supportedArguments['bpa-apikey'] = array('niceName' => 'bpa-APIKey', 'shortHelp' => 'BPA API Key, this can be requested via bpa@paloaltonetworks.com');
    }

    function strip_hidden_chars($str)
    {
        $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

        $str = str_replace($chars, "", $str);

        #return preg_replace('/\s+/',' ',$str);
        return $str;
    }

//needed for download
    function send_bpa_api($url, $type = "GET", $config = null, $system_info = null, $license = null, $clock = null )
    {
        $curl = curl_init();

        if( $type == "GET" )
        {
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "GET");
            $data = array("Authorization: Token $this->bpa_key");
        }
        else
        {
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
            $data = array("Authorization: Token $this->bpa_key", "Content-Type: multipart/form-data");

            if( $this->generate_zip )
            {
                PH::print_stdout( " - generate_zip_bundle" );
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

        if( $this->debugAPI === TRUE )
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
            PH::print_stdout( "Exception (): " . $e->getMessage() );
        }

        curl_close($curl);
        //print_r($reply);

        return $response;

    }


    function request_bpa($connector)
    {
        $connector->refreshSystemInfos(TRUE);
        $connector->show_config();
        $connector->request_license_info();
        $connector->show_clock();

        $response_start = "<response status=\"success\">";
        $response_end = "</response>";

        $config = $response_start;
        $config .= $this->strip_hidden_chars( $connector->show_config_raw->saveHTML() );
        $config .= $response_end;

        $system_info = $response_start;
        $system_info .= $this->strip_hidden_chars( $connector->show_system_info_raw->saveHTML() );
        $system_info .= $response_end;

        $license = $response_start;
        $license .= $this->strip_hidden_chars( $connector->request_license_info_raw->saveHTML() );
        $license .= $response_end;

        $clock = $response_start;
        $clock .= $this->strip_hidden_chars( $connector->show_clock_raw->saveHTML() );
        $clock .= $response_end;

        // Submit job to BPA API
        PH::print_stdout("");
        PH::print_stdout( " - Attempting to generate BPA for {$connector->info_hostname}" );

        $result[$connector->info_serial] = $this->send_bpa_api($this->bpa_url . 'create/', "POST", $config, $system_info, $license, $clock);
        //Array( [ #SERIAL ] => TASKID )


        #PH::print_stdout( "Pausing to allow processing. sleep " . $this->sleep_seconds . " seconds" );
        #sleep($this->sleep_seconds);

        #print_r( $result );


        // get results from BPA API
        $loop = TRUE;
        while( $loop )
        {
            if( isset($result[$connector->info_serial]) )
            {
                PH::print_stdout("");
                PH::print_stdout( " - Checking " . $connector->info_hostname . " job ID " . $result[$connector->info_serial] );
                $reply = $this->send_bpa_api($this->bpa_url . 'results/' . $result[$connector->info_serial] . '/', "GET");
                $parsed_reply = json_decode($reply, TRUE);
                #print_r( $parsed_reply );
                if( $parsed_reply['status'] == 'processing' )
                {
                    PH::print_stdout( "  * Sleep for another " . $this->sleep_seconds . " seconds" );
                    sleep($this->sleep_seconds);
                    continue;
                }
                elseif( $parsed_reply['status'] == "complete" )
                {
                    $loop = FALSE;  // Exit outer while loop
                    // Got BPA is JSON format in $reply
                    PH::print_stdout( "  * store JSON response into: ".$this->filename_prefix . $connector->info_serial . ".json" );
                    file_put_contents($this->filename_prefix . $connector->info_serial . '.json', $reply);
                    if( $this->generate_zip )
                    {
                        //Todo: swaschkut 20210350 ZIP download no longer working WHY???
                        PH::print_stdout( " - Downloading zip for " . $connector->info_hostname . " job ID " . $result[$connector->info_serial] );
                        $reply = $this->send_bpa_api($this->bpa_url . 'results/' . $result[$connector->info_serial] . '/download/', "GET");

                        PH::print_stdout( "  * ZIP file content length: ".strlen( $reply ) );

                        PH::print_stdout( "  * store ZIP response into: ".$this->filename_prefix . $connector->info_serial . ".zip" );
                        file_put_contents($this->filename_prefix . $connector->info_serial . '.zip', $reply);

                        if( strpos( $reply, "Could not find report bundle") !== false )
                        {
                            PH::print_stdout( PH::boldText( "##########################################" ) );
                            PH::print_stdout( PH::boldText( "report bundle not found on BPA server" ) );
                            PH::print_stdout( PH::boldText( "##########################################" ) );

                        }
                    }
                }
                elseif ($parsed_reply['status'] == 'error') {
                    $loop = false;  // Exit outer while loop
                    //print_r($parsed_reply);
                    PH::print_stdout( $reply );
                }
                else
                {
                    print_r($parsed_reply);
                    derr("something went wrong");
                }
            }
        }
    }

}