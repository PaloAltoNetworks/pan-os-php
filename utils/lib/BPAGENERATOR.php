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

        if( $this->projectFolder !== null )
            $this->filename_prefix = $this->projectFolder."/".$this->filename_prefix;

        $this->main();


        
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
        if( $this->configInput['type'] !== 'api' )
        {
            $this->request_bpa(null, PH::$args['in']);
        }
        else
        {
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

    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for bpa generator');
        $this->supportedArguments['bpa-apikey'] = array('niceName' => 'bpa-APIKey', 'shortHelp' => 'BPA API Key, this can be requested via bpa@paloaltonetworks.com');
        $this->supportedArguments['projectfolder'] = Array('niceName' => 'projectFolder', 'shortHelp' => 'define the projectfolder', 'argDesc' => 'projectfolder=[DIRECTORY]');
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
            if( $this->debugAPI )
                print_r($fields);
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
                if( $reply === null )
                {
                    PH::print_stdout( "RESPONSE: ".$response);
                    derr( "invalid JSON file provided", null, FALSE );
                }

                if( isset( $reply['task_id'] ) )
                    $response = $reply['task_id'];
                else
                {
                    print_r( $reply );
                    derr( "'task_id' - not found", null, FALSE );
                }

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


    function request_bpa($connector, $tsf_config = null)
    {
        if ($connector !== null) {
            $connector->refreshSystemInfos(TRUE);
            $connector->show_config();
            $connector->request_license_info();
            $connector->show_clock();
        }
        else
        {
            if( !empty($this->projectFolder) )
                $TSFfile = $this->projectFolder."/techsupport.txt";
            else
                $TSFfile = "techsupport.txt";
            if( file_exists($TSFfile) )
            {
                PH::print_stdout( " - read device info from file: ".$TSFfile );
                $techSupportFileString = file_get_contents($TSFfile);


                $systeminfoArray = $this->get_systemInfo_from_TSF($techSupportFileString);
                #print_r($systeminfoArray);

                $licenseinfoArray = $this->get_license_from_TSF($techSupportFileString);
                #print_r( $licenseinfoArray );
            }
            else
            {
                PH::print_stdout( " - no file called ".$TSFfile." found - using dummy Device information for hostname, serial, licenses" );
                $systeminfoArray = array();
                $licenseinfoArray = array();
            }
        }


        $response_start = "<response status=\"success\">";
        $response_end = "</response>";

        $config = $response_start;
        if ($connector !== null)
            $config .= $this->strip_hidden_chars($connector->show_config_raw->saveHTML());
        else {
            if ($tsf_config === null)
                derr("problem with your tsf XML extracted config file");
            $xmlString = file_get_contents($tsf_config);

            $newdoc = new DOMDocument;
            $newdoc->loadXML($xmlString, XML_PARSE_BIG_LINES);

            $lineReturn = TRUE;
            $indentingXmlIncreament = 1;
            $indentingXml = 0;
            $xml = &DH::dom_to_xml($newdoc->documentElement, $indentingXml, $lineReturn, -1, $indentingXmlIncreament);
            $config .= '<result>'.$xml.'</result>';
        }
        $config .= $response_end;

        $system_info = $response_start;
        if ($connector !== null)
            $system_info .= $this->strip_hidden_chars($connector->show_system_info_raw->saveHTML());
        else
        {
            if( !empty($systeminfoArray) )
            {
                $system_info .= '<result><system>';
                foreach( $systeminfoArray as $key => $system)
                {
                    $system_info .= '<'.$key.'>'.$system.'</'.$key.'>';
                    if( $key == "hostname" )
                        $dummy_hostname = $system;
                    elseif( $key == "serial" )
                        $dummy_serial = $system;

                }
                $system_info .= '</system></result>';
            }
            else
            {
                $dummy_serial = "012345678901";
                $dummy_hostname = "PAN-OS-PHP_dummy_DEVICE";
                $dummy_model = "PA-HW";
                $dummy_familie = "HW";
                $system_info .= '<result><system><hostname>'.$dummy_hostname.'</hostname><ip-address>192.168.1.254</ip-address><public-ip-address>unknown</public-ip-address><netmask>255.255.255.0</netmask><default-gateway>192.168.1.1</default-gateway><is-dhcp>no</is-dhcp><ipv6-address>unknown</ipv6-address><ipv6-link-local-address>fe80::ea98:6dff:feb0:2600/64</ipv6-link-local-address><mac-address>aa:bb:cc:dd:ee:ff</mac-address><time>Thu Oct 12 11:26:46 2023</time><uptime>365 days, 23:59:59</uptime><devicename>'.$dummy_hostname.'</devicename><family>'.$dummy_familie.'</family><model>'.$dummy_model.'</model><serial>'.$dummy_serial.'</serial><cloud-mode>non-cloud</cloud-mode><sw-version>10.1.6-h3</sw-version><global-protect-client-package-version>0.0.0</global-protect-client-package-version><device-dictionary-version>97-438</device-dictionary-version><device-dictionary-release-date>2023/10/05 23:45:14 CEST</device-dictionary-release-date><app-version>8763-8333</app-version><app-release-date>2023/10/11 18:04:41 CEST</app-release-date><av-version>4602-5120</av-version><av-release-date>2023/10/11 13:22:49 CEST</av-release-date><threat-version>8763-8333</threat-version><threat-release-date>2023/10/11 18:04:41 CEST</threat-release-date><wf-private-version>0</wf-private-version><wf-private-release-date>unknown</wf-private-release-date><url-db>paloaltonetworks</url-db><wildfire-version>811345-815141</wildfire-version><wildfire-release-date>2023/10/12 11:12:44 CEST</wildfire-release-date><wildfire-rt>Disabled</wildfire-rt><url-filtering-version>20231012.20145</url-filtering-version><global-protect-datafile-version>unknown</global-protect-datafile-version><global-protect-datafile-release-date>unknown</global-protect-datafile-release-date><global-protect-clientless-vpn-version>0</global-protect-clientless-vpn-version><logdb-version>10.1.2</logdb-version><plugin_versions><entry name="dlp" version="1.0.3"><pkginfo>dlp-1.0.3</pkginfo></entry></plugin_versions><platform-family>220</platform-family><vpn-disable-mode>off</vpn-disable-mode><multi-vsys>off</multi-vsys><operational-mode>normal</operational-mode><device-certificate-status>None</device-certificate-status></system></result>';
            }
        }

        $system_info .= $response_end;

        $license = $response_start;
        if ($connector !== null)
            $license .= $this->strip_hidden_chars($connector->request_license_info_raw->saveHTML());
        else
        {
            if( isset($licenseinfoArray['licenses']) )
            {
                $license .= '<result><licenses>';
                foreach( $licenseinfoArray['licenses'] as $licenseString)
                {
                    $license .= '<entry>';
                    $license .= '<feature>'.$licenseString['Feature'].'</feature>';
                    $license .= '<description>'.$licenseString['Description'].'</description>';
                    $license .= '<serial>' . $licenseString['Serial'] . '</serial>';
                    $license .= '<issued>'.$licenseString['Issued'].'</issued>';
                    $license .= '<expires>'.$licenseString['Expires'].'</expires>';
                    $license .= '<expired>'.$licenseString['Expired?'].'</expired>';
                    $license .= '<authcode></authcode>';
                    $license .= '</entry>';
                }
                $license .= '</licenses></result>';
            }
            else
            {
                $license_issue = "August 24, 2020";
                $license_expire = "January 09, 2029";
                $license .= '<result><licenses><entry><feature>DNS Security</feature><description>Palo Alto Networks DNS Security License</description><serial>' . $dummy_serial . '</serial><issued>'.$license_issue.'</issued><expires>'.$license_expire.'</expires><expired>no</expired><authcode></authcode></entry><entry><feature>Threat Prevention</feature><description>Threat Prevention</description><serial>'.$dummy_serial.'</serial><issued>'.$license_issue.'</issued><expires>'.$license_expire.'</expires><expired>no</expired><authcode></authcode></entry><entry><feature>SD WAN</feature><description>License to enable SD WAN feature</description><serial>'.$dummy_serial.'</serial><issued>'.$license_issue.'</issued><expires>'.$license_expire.'</expires><expired>no</expired><authcode></authcode></entry><entry><feature>WildFire License</feature><description>WildFire signature feed, integrated WildFire logs, WildFire API</description><serial>'.$dummy_serial.'</serial><issued>'.$license_issue.'</issued><expires>'.$license_expire.'</expires><expired>no</expired><authcode></authcode></entry><entry><feature>Standard</feature><description>10 x 5 phone support; repair and replace hardware service</description><serial>'.$dummy_serial.'</serial><issued>'.$license_issue.'</issued><expires>'.$license_expire.'</expires><expired>no</expired><authcode></authcode></entry><entry><feature>PAN-DB URL Filtering</feature><description>Palo Alto Networks URL Filtering License</description><serial>'.$dummy_serial.'</serial><issued>'.$license_issue.'</issued><expires>'.$license_expire.'</expires><expired>no</expired><authcode></authcode></entry><entry><feature>GlobalProtect Gateway</feature><description>GlobalProtect Gateway License</description><serial>'.$dummy_serial.'</serial><issued>'.$license_issue.'</issued><expires>'.$license_expire.'</expires><expired>no</expired><authcode></authcode></entry></licenses></result>';
            }
        }
        $license .= $response_end;

        $clock = $response_start;
        if( $connector !== null )
            $clock .= $this->strip_hidden_chars( $connector->show_clock_raw->saveHTML() );
        else
        {
            if( isset($systeminfoArray['time']) )
                $clock .= "<result>".$systeminfoArray['time']."</result>";
            else
                $clock .= "<result>Thu Oct 12 11:26:50 CEST 2023</result>";
        }

        $clock .= $response_end;

        // Submit job to BPA API
        PH::print_stdout();
        if( $connector !== null )
            PH::print_stdout( " - Attempting to generate BPA for {$connector->info_hostname}" );
        else
            PH::print_stdout( " - Attempting to generate BPA for TSF running-config.xml" );

        if( $connector !== null )
            $result[$connector->info_serial] = $this->send_bpa_api($this->bpa_url . 'create/', "POST", $config, $system_info, $license, $clock);
        else
            $result[$dummy_serial] = $this->send_bpa_api($this->bpa_url . 'create/', "POST", $config, $system_info, $license, $clock);
        //Array( [ #SERIAL ] => TASKID )


        #PH::print_stdout( "Pausing to allow processing. sleep " . $this->sleep_seconds . " seconds" );
        #sleep($this->sleep_seconds);

        #print_r( $result );


        // get results from BPA API
        $loop = TRUE;
        while( $loop )
        {
            if( $connector !== null )
            {
                $serial = $connector->info_serial;
                $hostname = $connector->info_hostname;
            }

            else
            {
                $serial = $dummy_serial;
                $hostname = $dummy_hostname;
            }


            if( isset($result[$serial]) )
            {
                PH::print_stdout();
                PH::print_stdout( " - Checking " . $hostname . " job ID " . $result[$serial] );
                $reply = $this->send_bpa_api($this->bpa_url . 'results/' . $result[$serial] . '/', "GET");
                $parsed_reply = json_decode($reply, TRUE);
                if( $parsed_reply === null )
                    derr( "invalid JSON file provided", null, FALSE );
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
                    PH::print_stdout( "  * store JSON response into: ".$this->filename_prefix . $serial . ".json" );
                    file_put_contents($this->filename_prefix . $serial . '.json', $reply);
                    if( $this->generate_zip )
                    {
                        //Todo: swaschkut 20210350 ZIP download no longer working WHY???
                        PH::print_stdout( " - Downloading zip for " . $hostname . " job ID " . $result[$serial] );
                        $reply = $this->send_bpa_api($this->bpa_url . 'results/' . $result[$serial] . '/download/', "GET");

                        PH::print_stdout( "  * ZIP file content length: ".strlen( $reply ) );

                        PH::print_stdout( "  * store ZIP response into: ".$this->filename_prefix . $serial . ".zip" );
                        file_put_contents($this->filename_prefix . $serial . '.zip', $reply);

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

    private function get_systemInfo_from_TSF($techSupportFileString)
    {
        $needle1 = "> show system info";
        $needle2 = "> show system files";
        $systeminfo = PH::find_string_between($techSupportFileString, $needle1, $needle2);

        $tmpArray = explode(PHP_EOL, $systeminfo);

        $systeminfoArray = array();
        foreach( $tmpArray as $entry )
        {
            if( empty($entry) )
                continue;

            $exploded = explode( ": ", $entry );
            $systeminfoArray[$exploded[0]] = $exploded[1];
        }

        return $systeminfoArray;
    }

    private function get_license_from_TSF( $techSupportFileString)
    {
        $needle1 = "> request license info";
        $needle2 = "> show system setting logging";
        $licenseinfo = PH::find_string_between($techSupportFileString, $needle1, $needle2);
        #print $licenseinfo."\n";
        $tmpArray = explode(PHP_EOL, $licenseinfo);
        #print_r($tmpArray);

        $licenseinfoArray = array();
        $licenseinfoArray['time'] = "";
        $licenseinfoArray['licenses'] = array();
        foreach( $tmpArray as $entry ) {
            if (empty($entry))
                continue;

            if (strpos($entry, "Current ") !== FALSE)
                $licenseinfoArray['time'] = $entry;
            elseif (strpos($entry, "License entry:") !== FALSE)
            {
                $licArray = array();
                $endFound = false;
            }
            else
            {
                $exploded = explode( ": ", $entry );
                $licArray[$exploded[0]] = $exploded[1];

                if (strpos($entry, "Expired?:") !== FALSE)
                    $licenseinfoArray['licenses'][] = $licArray;
            }
        }

        return $licenseinfoArray;
    }

}