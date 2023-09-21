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

class SOFTWARE_DOWNLOAD extends UTIL
{
    public $utilType = null;

    #####################################################
    #####################################################
    //FIXED VARIABLE VALUES
    public $user = null;
    public $pw = null;

    public $data = array( 'Content-Type: application/x-www-form-urlencoded');
    public $site_fix = '/Updates/UpdateService2.asmx/';

    public $protocol = 'https://';
    public $url = 'updates.paloaltonetworks.com';

    public $debug = false;
    public $debugAPI = false;
    public $filter = array();
    public $site_array = array();
    public $folder = null;


    public function utilStart()
    {
        $this->prepareSupportedArgumentsArray();


        $this->utilInit();


        $this->main();


        
    }

    public function main()
    {
        #####################################################
        //CHANGE VARIABLES BASED ON FILTERS


        $this->filter['All'] = false;//[=false => download only latest]
        $this->filter['SWVersionInfo'] = false;
        $this->filter['SignatureVersionInfo'] = true;
        $this->filter['only_releaseNotes'] = false;

        $this->filter['upload'] = true;
        $this->filter['install'] = true;

        //filter=(download all) and (download software) and (download signature) and (download only_releasnotes)'


        #####################################################

        $this->folder = dirname(__FILE__)."/software";
        $this->folder_latest = "latest";

        $input_file_name = dirname(__FILE__)."/software/software_downloader_devices.txt";

        #####################################################
        #####################################################
        //FIXED VARIABLE VALUES

        $this->user = PH::decrypt( PH::$softwareupdate_user_encrypt, PH::$softwareupdate_key  )[0];
        $this->pw = PH::decrypt( PH::$softwareupdate_pw_encrypt, PH::$softwareupdate_key  )[0];

/*
        $data = array( 'Content-Type: application/x-www-form-urlencoded');
        $site_fix = '/Updates/UpdateService2.asmx/';


        $protocol = 'https://';
        $url = 'updates.paloaltonetworks.com';
*/

        $this->site_array['panos']['CheckForSoftwareUpdate'] = array();
        $this->site_array['panos']['CheckForSignatureUpdate'] = array();
        $this->site_array['panos']['CheckForWildfireUpdate'] = array();
        $this->site_array['panos']['CheckForVirusUpdate'] = array();

        $this->site_array['panos']['CheckForSignatureUpdate']['featureName'] = 'contents';
        $this->site_array['panos']['CheckForWildfireUpdate']['featureName'] = 'wildfire';
        $this->site_array['panos']['CheckForVirusUpdate']['featureName'] = 'virus';




        //only direct Panorama

        $this->site_array['panorama']['CheckForSoftwareUpdate'] = array();
        $this->site_array['panorama']['CheckForSignatureUpdate'] = array();
        $this->site_array['panorama']['CheckForWildfireUpdate'] = array();
        $this->site_array['panorama']['CheckForVirusUpdate'] = array();

        $this->site_array['panorama']['CheckForSignatureUpdate']['featureName'] = 'contents';
        $this->site_array['panorama']['CheckForWildfireUpdate']['featureName'] = 'wildfire';
        $this->site_array['panorama']['CheckForVirusUpdate']['featureName'] = 'virus';


        /*
        //MISSING part
        //Panorama-> Device Deployment -> Dynamic Updates

        //$site_array['panorama']['GetSWLibrary'] = array();
        $site_array['panorama']['GetSILibrary'] = array();
        $site_array['panorama']['GetWFDeploy2'] = array();
        $site_array['panorama']['GetSVLibrary'] = array();


        $site_array['panorama']['GetSILibrary']['featureName'] = 'contents';
        $site_array['panorama']['GetWFDeploy2']['featureName'] = 'wildfire';
        $site_array['panorama']['GetSVLibrary']['featureName'] = 'virus';
        */


        $filtered_out = "      [FILTERED OUT]\n\n";

        #####################################################
        #####################################################






        if( isset(PH::$args['in']) )
        {
            $configInput = PH::$args['in'];
            #display_error_usage_exit('"in" is missing from arguments');

            if( !is_string($configInput) || strlen($configInput) < 1 )
                display_error_usage_exit('"in" argument is not a valid string');
        }



        if( isset(PH::$args['debugapi'])  )
        {
            $this->debugAPI = true;
            $this->debug = true;
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
                if($this->debugAPI)
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
                if( isset($inputConnector->info_model) )
                    $tmp = array('platform' => $inputConnector->info_model, 'serial' => $inputConnector->info_serial, 'currentversion' => $inputConnector->info_PANOS_version,
                        'apps' => $inputConnector->info_app_version, 'contents' => $inputConnector->info_threat_version, 'virus' => $inputConnector->info_av_version, 'wildfire' => $inputConnector->info_wildfire_version,
                        'uuid' => $inputConnector->info_vmuuid, 'cpuid' => $inputConnector->info_vmcpuid
                    );

                #print_r( $tmp );

                if( !isset($device_array[$inputConnector->info_serial]) )
                    $device_array[$inputConnector->info_serial] = $tmp;
            }
            elseif( $configType == 'panorama' )
            {
                if( isset($inputConnector->info_model) )
                    $tmp = array('platform' => $inputConnector->info_model, 'serial' => $inputConnector->info_serial, 'currentversion' => $inputConnector->info_PANOS_version,
                        'apps' => $inputConnector->info_app_version, 'contents' => $inputConnector->info_threat_version, 'virus' => $inputConnector->info_av_version, 'wildfire' => $inputConnector->info_wildfire_version,
                        'uuid' => $inputConnector->info_vmuuid, 'cpuid' => $inputConnector->info_vmcpuid
                    );

                #print_r( $tmp );

                if( !isset($device_array[$inputConnector->info_serial]) )
                    $device_array[$inputConnector->info_serial] = $tmp;
                #derr("panorama not supported yet");
            }
        }
        elseif( isset(PH::$args['serial']) )
        {

            $inputSerial = PH::$args['serial'];
            if( !is_string($inputSerial) || strlen($inputSerial) < 1 )
                display_error_usage_exit('"serial" argument is not a valid string');

            if( ! isset(PH::$args['model']) )
                display_error_usage_exit('"model" is missing from arguments');
            $inputmodel = PH::$args['model'];
            if( !is_string($inputmodel) || strlen($inputmodel) < 1 )
                display_error_usage_exit('"model" argument is not a valid string');

            $device_array[$inputSerial] = array( 'platform' => $inputmodel, 'serial' => $inputSerial, 'currentversion' => '7.1.5',
                'apps' => '656-3818', 'contents' => '553-3107', 'virus' => '1845-2324', 'wildfire' => '0-0',
                'uuid' => '', 'cpuid' => ''
            );

            $tmp = $device_array[$inputSerial];
        }
        elseif( file_exists($input_file_name) )
        {
            $content = file_get_contents($input_file_name);


            $dom = new DOMDocument;
            $dom->loadXML($content, XML_PARSE_BIG_LINES);
            if (!$dom) {
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


            foreach( $res->childNodes as $entry)
            {
                if( $entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $serial = DH::findFirstElement('serial', $entry);
                if( $res === FALSE )
                    derr('cannot find <serial>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $model = DH::findFirstElement('model', $entry);
                if( $res === FALSE )
                    derr('cannot find <model>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $sw_version = DH::findFirstElement('sw-version', $entry);
                if( $res === FALSE )
                    derr('cannot find <sw-version>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $app_version = DH::findFirstElement('app-version', $entry);
                if( $res === FALSE )
                    derr('cannot find <app-version>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $av_version = DH::findFirstElement('av-version', $entry);
                if( $res === FALSE )
                    derr('cannot find <av-version>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $wildfire_version = DH::findFirstElement('wildfire-version', $entry);
                if( $res === FALSE )
                    derr('cannot find <wildfire-version>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $threat_version = DH::findFirstElement('threat-version', $entry);
                if( $res === FALSE )
                    derr('cannot find <threat-version>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $uuid = DH::findFirstElement('uuid', $entry);
                if( $res === FALSE )
                    derr('cannot find <uuid>:' . DH::dom_to_xml($entry, 0, TRUE, 2));

                $cpuid = DH::findFirstElement('cpuid', $entry);
                if( $res === FALSE )
                    derr('cannot find <cpuid>:' . DH::dom_to_xml($entry, 0, TRUE, 2));


                if( isset( $model ) )
                    $tmp = array('platform' => $model->textContent, 'serial' => $serial->textContent, 'currentversion' => $sw_version->textContent,
                        'apps' => $app_version->textContent, 'contents' => $threat_version->textContent, 'virus' => $av_version->textContent, 'wildfire' => $wildfire_version->textContent,
                        'uuid' => $uuid->textContent, 'cpuid' => $cpuid->textContent
                    );

                #print_r( $tmp );

                if( !isset($device_array[ $serial->textContent ]) )
                    $device_array[ $serial->textContent ] = $tmp;
            }
        }
        elseif( ! isset(PH::$args['serial']) )
            display_error_usage_exit('"serial" is missing from arguments');





#create folder if not exist
        if( !file_exists( $this->folder) )
        {
            if( !mkdir($this->folder, 0777, TRUE) && !is_dir($this->folder) )
            {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $this->folder));
            }
        }
#create folder if not exist
        if( !file_exists( $this->folder."/".$this->folder_latest) )
        {
            if( !mkdir($concurrentDirectory = $this->folder . "/" . $this->folder_latest, 0777, TRUE) && !is_dir($concurrentDirectory) )
            {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
            }
        }


        $url_array = array();
        foreach($device_array as $device)
        {
            print "\n\nCheckSoftware for serial: ".$device['serial']."\n";
            print_r($device);

            if( $tmp['platform'] != "Panorama" )
            {
                foreach( $this->site_array['panos'] as $key => $site )
                {
                    $fields = 'serialnumber='.$device['serial'];

                    if( isset( $site['featureName'] ) )
                        $fields .= '&featureName='.$site['featureName'];

                    if( $key == 'CheckForSoftwareUpdate' )
                        $fields .= '&platform='.$device['platform'].'&currentVersion='.$device['currentversion'];
                    elseif( $key == 'CheckForWildfireUpdate' )
                        $fields .= '&currentSignatureVersion=apps:'.$device['apps'].';contents:'.$device['contents'].';virus:'.$device['virus'].';wildfire:'.$device['wildfire'];
                    elseif( $key == 'CheckForVirusUpdate' )
                    {
                        #print "I am here\n";
                        $fields .= '&currentSignatureVersion=apps:'.$device['apps'].';contents:'.$device['contents'].';virus:'.$device['virus'];
                    }

                    elseif( $key == 'CheckForSignatureUpdate' )
                    {
                        $fields .= '&currentSignatureVersion=apps:'.$device['apps'].';contents:'.$device['contents'];
                        #$fields .= '&currentSignatureVersion=apps:'.$device['apps'].';contents:'.$device['contents'].';virus:'.$device['virus'];
                    }


                    if( isset( $site['featureName'] ) )
                        $fields .= '&currentOSVersion='.$device['currentversion'];

                    $fields .= '&uuid='.$device['uuid'].'&cpuid='.$device['cpuid'];

                    $this->diff_dynamic_content( $key, $fields, $device, $url_array);

                }
            }
            else
            {
                foreach( $this->site_array['panorama'] as $key => $site )
                {
                    $fields = 'serialnumber='.$device['serial'];

                    if( isset( $site['featureName'] ) )
                        $fields .= '&featureName='.$site['featureName'];

                    if( $key == 'CheckForSoftwareUpdate' )
                        $fields .= '&platform='.$device['platform'].'&currentVersion='.$device['currentversion'];
                    elseif( $key == 'CheckForWildfireUpdate' )
                        $fields .= '&currentSignatureVersion=apps:'.$device['apps'].';contents:'.$device['contents'].';virus:'.$device['virus'].';wildfire:'.$device['wildfire'];
                    elseif( $key == 'CheckForVirusUpdate' )
                        $fields .= '&currentSignatureVersion=apps:'.$device['apps'].';contents:'.$device['contents'].';virus:'.$device['virus'];
                    elseif( $key == 'CheckForSignatureUpdate' )
                        $fields .= '&currentSignatureVersion=apps:'.$device['apps'].';contents:'.$device['contents'];

                    $fields .= '&currentOSVersion='.$device['currentversion'];

                    $fields .= '&uuid='.$device['uuid'].'&cpuid='.$device['cpuid'];

                    //start with Panorama validation here:
                    //why do Panorama download not only latest, why all?
                    $this->diff_dynamic_content( $key, $fields, $device, $url_array);
                }
            }


        }




        #print_r( $url_array );


        //check for each device serial
        foreach( $url_array as $key_serial => $array )
        {
            print "\n\nDownload Software for serial: ".$key_serial."\n";
            #print_r( $url_array[ $key_serial ] );

            #print_r( $array );

            //check for different software
            foreach( $array as $key1 => $different_sw )
            {
                $upload_counter = 0;
                if( $this->filter['install'] )
                    $upload_counter = 1;

                print "\n\n########################################################\n\n";
                print "- ".$key1."\n\n";
                print "########################################################\n\n";

                //download software
                #print_r( $different_sw );
                #exit;
                foreach( $different_sw as $key2 => $versioninfo )
                {
                    print "  - ".$key2."\n";
                    if( empty( $versioninfo ) )
                    {
                        mwarning( "versioninfo is empty" );
                        continue;
                    }


                    if( $key2 == "SWVersionInfo" )
                    {
                        if( $this->filter['All'] && $this->filter['SWVersionInfo'] )
                        {
                            $allrelease = $versioninfo;
                            foreach( $allrelease as $versioninfo )
                            {
                                $this->download_preparation( $versioninfo, $key1 );
                            }

                        }
                        else
                            print $filtered_out;
                    }

                    if( $key2 == "SignatureVersionInfo" )
                    {
                        //what about
                        if( $this->filter['All'] && $this->filter['SignatureVersionInfo']  )
                        {
                            $allrelease = $versioninfo;
                            foreach( $allrelease as $versioninfo )
                            {
                                if( $upload_counter == 0 )
                                    $this->download_preparation( $versioninfo, $key1, true );
                                #elseif(  $upload_counter < 2 )
                                else
                                    $this->download_preparation( $versioninfo, $key1 );

                                if ( $configInput['type'] == 'api' && $this->filter['upload']  && $upload_counter < 4 )
                                {
                                    $this->install_software($inputConnector, $versioninfo, $key1, $this->filter['install'], $device);
                                    $upload_counter ++;
                                }
                            }

                        }
                        else
                            print $filtered_out;
                    }

                    if( $key2 == "LatestSoftwareVersionInfo" )
                    {
                        if( $this->filter['SWVersionInfo'] )
                        {
                            $this->download_preparation( $versioninfo, $key1, true );
                            //install software
                            if ( $configInput['type'] == 'api' && $this->filter['upload']  )
                            {
                                $this->install_software($inputConnector, $versioninfo, $key1, $this->filter['install'], $device);
                            }
                        }
                        else
                            print $filtered_out;
                    }

                    if( $key2 == "LatestSignatureVersionInfo" )
                    {
                        if( $this->filter['SignatureVersionInfo'] )
                        {
                            $this->download_preparation($versioninfo, $key1, TRUE);
                            //install dynamic updates
                            if ( $configInput['type'] == 'api' && $this->filter['upload']  )
                            {
                                $this->install_software($inputConnector, $versioninfo, $key1, $this->filter['install'], $device );
                            }
                        }
                        else
                            print $filtered_out;

                    }
                }
            }
        }




    }

    //duplicate code check UTIL::
    public function display_usage_and_exit($shortMessage = false, $warningString = "")
    {
        print PH::boldText("USAGE: ")."php ".basename(__FILE__)." serial=[DEVICE-Serial#] model=[DEVICE-MODEL]\n";
        print PH::boldText("\nExamples:\n");
        print " - php ".basename(__FILE__)." serial=0123456789 model=PA-200\n";
        print PH::boldText("\nFOR AUTOMATION please first run:\n");
        print " - php pan_software_download_preparation in=api://[DEVICE MGMT IP]\n\n";

        if( !empty($warningString) )
            mwarning( $warningString, null, false );
        exit(1);
    }

    public function display_error_usage_exit($msg)
    {
        fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
        display_usage_and_exit(true, $msg);
    }

    public function curl_request($url, $fields = array(), $data = '', $authType = "BASIC" )
    {
        if ($this->debug === true)
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

        curl_setopt($curl, CURLOPT_USERPWD, $this->user . ":" . $this->pw);

        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        if( $this->debug === true)
        {
            curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($curl, CURLOPT_VERBOSE, true);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($curl);
        curl_close($curl);

        return $response;
    }

    public function curl_request_upload($url, $fields = array(), $data = '' )
    {
        if ($this->debug === true)
            print "\n-----" . __FUNCTION__ . "\n";

        $curl = curl_init();

        curl_setopt($curl, CURLOPT_URL, $url);

        if ( !empty( $fields ) )
        {
            // Create a CURLFile object
            $data = array();
            $data['file'] = new CURLFile($this->folder.'/'.$fields['file_name'],'multipart/form-data',$fields['file_name']);

            curl_setopt($curl, CURLOPT_POST,true );
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        }

        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        #curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        if( $this->debug === true)
        {
            curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($curl, CURLOPT_VERBOSE, true);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($curl);
        curl_close($curl);

        return $response;
    }


    public function download_file( $extern_url, $local_file)
    {
        //another test
        PH::enableExceptionSupport();
        try {
            $file = fopen ($extern_url, 'rb');

            if ($file === false) {
                // Handle the error
                echo "URL: '".$extern_url."'' not available right now\n";
            }

            if ($file) {
                $newf = fopen ($local_file, 'wb');
                if ($newf) {
                    while(!feof($file)) {
                        fwrite($newf, fread($file, 1024 * 8), 1024 * 8);
                    }
                }
            }
            if ($file) {
                fclose($file);
            }
            if ($newf) {
                fclose($newf);
            }

        } catch (Exception $e) {
            // Handle exception
            PH::disableExceptionSupport();
            print "Error: ".$e->getMessage()."\n";
        }
    }

    public function download_preparation( $versioninfo, $key1, $latest = false)
    {
        $release_notes_available = false;

        if( empty( $versioninfo ) )
        {
            return null;
        }
        elseif( $this->debug )
            print_r( $versioninfo );


        #if( isset($versioninfo['product']) && ( $versioninfo['product'] != "panos" || $versioninfo['product'] != "panorama" ) )
        if( isset($versioninfo['product']) && $versioninfo['product'] == "vpnclient" )
            return null;


        if( isset($versioninfo['ReleaseNotesFileName']) && file_exists( $this->folder."/".$versioninfo['ReleaseNotesFileName'] )  )
        {
            echo "      - file ".$this->folder."/".$versioninfo['ReleaseNotesFileName']." already exist.\n";
            $release_notes_available = true;
        }

        if( isset($versioninfo['ReleaseNotesFileName']) && file_exists( $this->folder . "/" . $versioninfo['FileName'] ) )
        {
            echo "      - file ".$this->folder . "/" . $versioninfo['FileName']." already exist.\n\n";
        }
        else
        {
            if(  $versioninfo['ReleaseNotesFileName'] != 'EMPTY')
            {
                if( !$release_notes_available )
                {
                    echo "      - download file ".$this->folder."/".$versioninfo['ReleaseNotesFileName']."\n";
                    $this->download_file($versioninfo['ReleaseNotesURL'], $this->folder . "/" . $versioninfo['ReleaseNotesFileName']);
                }
            }
            else
                echo "      - ERROR: ".$versioninfo['VersionNumber']." ReleaseNotesFileName not available - download NOT POSSIBLE \n";


            if( !$this->filter['only_releaseNotes'] )
            {
                echo "      - download file ".$this->folder . "/" . $versioninfo['FileName']."\n\n";
                $this->download_file($versioninfo['downloadURL'], $this->folder . "/" . $versioninfo['FileName']);
            }



            if( $latest )
            {
                if(  $versioninfo['ReleaseNotesFileName'] != 'EMPTY')
                    $this->copy_file($this->folder . "/" . $versioninfo['ReleaseNotesFileName'], $this->folder . "/".$this->folder_latest."/" . $key1 . ".html");
                if( !$this->filter['only_releaseNotes'] )
                    $this->copy_file($this->folder . "/" . $versioninfo['FileName'], $this->folder . "/".$this->folder_latest."/" . $key1);
            }

        }
    }

    public function copy_file( $file, $newfile)
    {
        if( !copy($file,$newfile) )
            echo "      [ERROR] failed to copy $file";
        else
            echo "      - copied $file into $newfile\n";
    }


    public function get_software( $item, $search_product = false )
    {

        $LatestSignatureVersionInfo_array = array();

        $downloadURL =  "";
        $FileName = "";
        $ReleaseNotesURL = "";
        $ReleaseNotesFileName = "";
        $product = "";


        $res = DH::findFirstElement('downloadURL', $item);
        if( $res === FALSE )
            derr('cannot find <downloadURL>:' . DH::dom_to_xml($item, 0, TRUE, 2));
        $downloadURL = $res->textContent;

        $res = DH::findFirstElement('FileName', $item);
        if( $res === FALSE )
            derr('cannot find <FileName>:' . DH::dom_to_xml($item, 0, TRUE, 2));
        $FileName = $res->textContent;

        $res = DH::findFirstElement('ReleaseNotesURL', $item);
        if( $res === FALSE )
            derr('cannot find <ReleaseNotesURL>:' . DH::dom_to_xml($item, 0, TRUE, 2));
        $ReleaseNotesURL = $res->textContent;

        $res = DH::findFirstElement('ReleaseNotesFileName', $item);
        if( $res === FALSE )
            derr('cannot find <ReleaseNotesFileName>:' . DH::dom_to_xml($item, 0, TRUE, 2));
        $ReleaseNotesFileName = $res->textContent;

        $res = DH::findFirstElement('VersionNumber', $item);
        if( $res === FALSE )
            derr('cannot find <VersionNumber>:' . DH::dom_to_xml($item, 0, TRUE, 2));
        $VersionNumber = $res->textContent;

        if( $search_product )
        {
            $res = DH::findFirstElement('Product', $item);
            if( $res === FALSE )
                derr('cannot find <Product>:' . DH::dom_to_xml($item, 0, TRUE, 2));
            $product = $res->textContent;
        }

        //FIX because for new release no ReleaseNotesFilenName is available
        if( $ReleaseNotesFileName == "" )
        {
            $version_explode = explode( ".", $VersionNumber);

            $ReleaseNotesFileName = 'EMPTY';
            $ReleaseNotesFileName = "https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/pdf/pan-os/".$version_explode[0]."-".$version_explode[1]."/pan-os-release-notes/pan-os-release-notes.pdf";
            $ReleaseNotesFileName = 'EMPTY';
        }


        if( $downloadURL !=  "" && $FileName != "" && $ReleaseNotesURL != "" && $ReleaseNotesFileName != "" )
        {
            $LatestSignatureVersionInfo_array['downloadURL'] = $downloadURL;
            $LatestSignatureVersionInfo_array['FileName'] = $FileName;
            $LatestSignatureVersionInfo_array['ReleaseNotesURL'] = $ReleaseNotesURL;
            $LatestSignatureVersionInfo_array['ReleaseNotesFileName'] = $ReleaseNotesFileName;
            $LatestSignatureVersionInfo_array['VersionNumber'] = $VersionNumber;
            $LatestSignatureVersionInfo_array['product'] = $product;
        }

        return $LatestSignatureVersionInfo_array;
    }

    public function install_software( $inputConnector, $versioninfo, $key1, $install, $device)
    {
        /*
         other possible categories
            Content— category=, url-database | signed-url-database>
            category=license
        */


        $query = "";
        $file_available = false;

        if( file_exists( $this->folder . "/" . $versioninfo['FileName'] ) )
        {
            echo "\n  - ".$key1."\n";
            echo "      - upload file ".$this->folder . "/" . $versioninfo['FileName']."\n\n";

            #$filecontent = file_get_contents($this->folder . "/" . $versioninfo['FileName']);
        }

        ######################################################################################################
        //FIREWALL and local Panorama
        if( $key1 == 'CheckForSoftwareUpdate' )
            $category = 'software';
        elseif( $key1 == 'CheckForWildfireUpdate' )
            $category = 'wildfire';
        elseif( $key1 == 'CheckForVirusUpdate' )
            $category = 'anti-virus';
        elseif( $key1 == 'CheckForSignatureUpdate' )
            $category = 'content';


        if( $key1 == 'CheckForSoftwareUpdate' )
            $query = '&type=op&action=complete&xpath=/operations/request/system/software/install/version';
        elseif( $key1 == 'CheckForWildfireUpdate' )
            $query = '&type=op&action=complete&xpath=/operations/request/wildfire/upgrade/install/file';
        elseif( $key1 == 'CheckForVirusUpdate' )
            $query = '&type=op&action=complete&xpath=/operations/request/anti-virus/upgrade/install/file';
        elseif( $key1 == 'CheckForSignatureUpdate' )
            $query = '&type=op&action=complete&xpath=/operations/request/content/upgrade/install/file';

        ######################################################################################################
        //PANORAMA Device Deployment
        /*
         $site_array['panorama']['GetSWLibrary'] = array();
        $site_array['panorama']['GetWFDeploy2'] = array();
        $site_array['panorama']['GetSVLibrary'] = array();
        $site_array['panorama']['GetSILibrary'] = array();
         */

        if( $key1 == 'GetSWLibrary' )
            $category = 'software';
        elseif( $key1 == 'GetWFDeploy2' )
            $category = 'wildfire';
        elseif( $key1 == 'GetSVLibrary' )
            $category = 'anti-virus';
        elseif( $key1 == 'GetSILibrary' )
            $category = 'content';


        if( $key1 == 'GetSWLibrary' )
            $query = '&type=op&action=complete&xpath=/operations/request/system/software/install/version';
        elseif( $key1 == 'GetWFDeploy2' )
            $query = '&type=op&action=complete&xpath=/operations/request/wildfire/upgrade/install/file';
        elseif( $key1 == 'GetSVLibrary' )
            $query = '&type=op&action=complete&xpath=/operations/request/anti-virus/upgrade/install/file';
        elseif( $key1 == 'GetSILibrary' )
            $query = '&type=op&action=complete&xpath=/operations/request/content/upgrade/install/file';

        //Todo: check how to continue;
        if( $query == "" )
        {
            mwarning( "it is Panorama - upload not yet possible" );
            print "no installation possible yet, fix it\n";
            return null;
        }

        ######################################################################################################

        $ret= $inputConnector->sendRequest($query);
        $tmp_ret = $ret->saveXML( $ret );

        if( strpos( $tmp_ret, $versioninfo['FileName'] ) !== FALSE )
        {
            $file_available = true;
        }

        /*
         <response status="success"><completions>
            <completion value="panupv2-all-apps-8218-5815.tgz" help-string="2019/12/17 15:00:03    38525.5K"/>
            <completion value="panupv2-all-apps-8219-5824.tgz" help-string="2019/12/18 15:00:14    38581.3K"/>
            <completion value="panupv2-all-apps-8224-5855" help-string="2020/01/09 13:54:57    38698.7K"/>
            <completion value="panupv2-all-apps-8224-5855.tgz" help-string="2020/01/09 15:00:23    38698.7K"/>
            <completion value="panupv2-all-contents-8222-5846" help-string="2020/01/09 14:47:20    46840.6K"/>
        </completions></response>
         */

        if( $key1 != 'CheckForSoftwareUpdate' )
        {
            if( !$file_available )
            {
                //TODO: pan-c related usage
                #$inputConnector->sendRequest( $params, true, $file_content, $versioninfo['FileName'] );


                $file_content = file_get_contents( $this->folder."/".$versioninfo['FileName'] );

                $post = array('file_name' => $versioninfo['FileName'],'file_content'=>$file_content);

                $url = "https://".$inputConnector->info_mgmtip."/api?key=".$inputConnector->apikey."&type=import&category=".$category;

                /* this is if uploaded via GUI to Dynamic Updates
                <upload>
                <content>
                    <path>/opt/pancfg/tmp/sw-images/uiUpSw03wdRU</path>
                    <name>panupv2-all-contents-8222-5846</name>
                </content>
                </upload>
                 */

                /* this is if uploaded via GUI to Device Deployment
                <upload><deploy>
                <content>
                  <path>/opt/pancfg/tmp/sw-images/uiUpSwgiYMaP</path>
                  <name>panupv2-all-contents-8223-5849</name>
                </content>
                </deploy></upload>
                 */

                print "DEBUG UPLOAD url: ".$url."\n";

                #$params['type'] = 'import';
                #$params['category'] = $category;
                $response = $this->curl_request_upload( $url, $post, $this->data );

                print "UPLOAD response: ".$response."\n";

                if( strpos( $response, "error" ) !== FALSE )
                    derr( "something wrong" );


            }
            else
            {
                print "\n\n";
                print "NO UPLOAD needed - FILE: ".PH::boldText( $versioninfo['FileName'] )." already available on DEVICE\n";
                print "\n\n";
            }



            #############################################################################################################################
            //INSTALLATION
            $cmd = "<request><".$category."><upgrade><install>";
            $cmd .= "<file>".$versioninfo['FileName']."</file>";

            $cmd .= "<commit>yes</commit>";
            if( $category != "wildfire" && $category != "anti-virus" )
                $cmd .= "<skip-content-validity-check>yes</skip-content-validity-check>";

            $cmd .= "</install></upgrade></".$category."></request>";


            if( $install )
            {
                $alreadyAvailable = false;
                if( $category == 'content' && ( strlen( $device[ 'contents'] ) > 3 ) && ( strpos( $cmd, $device[ 'contents'] ) !== false ) )
                {
                    $alreadyAvailable = true;
                }
                elseif( $category == 'wildfire' && ( strlen( $device[ 'wildfire'] ) > 3 ) && ( strpos( $cmd, $device[ 'wildfire'] ) !== false ) )
                {
                    $alreadyAvailable = true;
                }
                elseif( $category == 'anti-virus' && ( strlen( $device[ 'virus'] ) > 3 ) && ( strpos( $cmd, $device[ 'virus'] ) !== false ) )
                {
                    $alreadyAvailable = true;
                }

                if( !$alreadyAvailable )
                {
                    print "DEBUG INSTALL: ". $cmd."\n";

                    $response = $inputConnector->sendOpRequest( $cmd );
                    print "INSTALL: ".$response->saveXML( $response )."\n";


                    $cursor = DH::findXPathSingleEntryOrDie('/result', $response);
                    if( $cursor === FALSE )
                        derr("unsupported API answer");

                    $cursor = DH::findFirstElement('job', $cursor);

                    if( $cursor === FALSE )
                        derr("unsupported API answer, no JOB ID found");

                    $jobid = $cursor->textContent;

                    while( TRUE )
                    {
                        sleep(1);
                        $query = '&type=op&cmd=<show><jobs><id>' . $jobid . '</id></jobs></show>';
                        $ret= $inputConnector->sendRequest($query);
                        #print DH::dom_to_xml($ret, 0, true, 5);

                        $cursor = DH::findFirstElement('result', DH::findXPathSingleEntryOrDie('/response', $ret));

                        if( $cursor === FALSE )
                            derr("unsupported API answer", $ret);

                        $jobcur = DH::findFirstElement('job', $cursor);

                        if( $jobcur === FALSE )
                            derr("unsupported API answer", $ret);

                        $percent = DH::findFirstElement('progress', $jobcur);

                        if( $percent == FALSE )
                            derr("unsupported API answer", $cursor);

                        if( $percent->textContent != '100' && strpos( $percent->textContent, ":" ) === false )
                        {
                            print $percent->textContent."% - ";
                            sleep(9);
                            continue;
                        }

                        $cursor = DH::findFirstElement('result', $jobcur);

                        if( $cursor === FALSE )
                            derr("unsupported API answer", $ret);

                        $report = $cursor;

                        $cursor = DH::findFirstElement('job', $jobcur);
                        $cursor = DH::findFirstElement('details', $jobcur);

                        print "\n\n".$cursor->textContent."\n";

                        break;

                    }
                }
                else
                {
                    print "\n\n";
                    print "NO INSTALLATION needed - FILE: ".PH::boldText( $versioninfo['FileName'] )." already installed on DEVICE\n";
                    print "\n\n";
                }
            }
            else
            {
                print "no installation\n";
                print "DEBUG INSTALL: ". $cmd."\n";
            }

        }
        else
        {
            print "Software upload and installation not yet supported\n";
            /*
            //TODO: check that base image is available for upload
            $params['type'] = 'import';
            $params['category'] = $category;

            $file_content = file_get_contents( $folder."/".$versioninfo['FileName'] );



            $post = array('file_name' => $versioninfo['FileName'],'file_content'=>$file_content);

            $url = "https://".$inputConnector->info_mgmtip."/api?key=".$inputConnector->apikey."&type=import&category=".$category;

            $response = $this->curl_request_upload( $url, $post, $data );
            print "UPLOAD: ".$response."\n";
            */
        }



    }

    public function diff_dynamic_content( $key, $fields, $device, &$url_array )
    {
        if( $this->debug )
        {
            print "URL: ".$this->protocol.$this->url.$this->site_fix.$key."\n";
            print "POST fiels: ".$fields."\n";
        }

        $curl_response = $this->curl_request( $this->protocol.$this->url.$this->site_fix.$key, $fields, $this->data, "BASIC");

        if( $this->debug )
            print $curl_response."\n";

        $file_name = "PAN_".$key.".xml";

        $file = fopen( $this->folder.'/'.$file_name, "w") or die("Unable to open file!");
        fwrite($file, $curl_response);
        fclose($file);


        if( $curl_response == '')
            derr("empty string\n");


        $xmlDoc = new DOMDocument();
        $xmlDoc->loadXML($curl_response, XML_PARSE_BIG_LINES);


        $x = $xmlDoc->documentElement;

        foreach ($x->childNodes AS $item)
        {
            $search_product = false;
            if( $item->nodeName == 'AllSWVersionInfo' || $item->nodeName == 'LatestSoftwareVersionInfo' )
                $search_product = true;

            if( $item->nodeName == 'AllSWVersionInfo' || $item->nodeName == 'AllSignatureVersionInfo' )
            {
                $i=0;
                foreach( $item->childNodes AS $item2 )
                {
                    if( $item2->nodeName == 'SWVersionInfo' || $item2->nodeName == 'SignatureVersionInfo' )
                    {
                        $url_array[$device['serial']][$key][$item2->nodeName][$i] = $this->get_software($item2, $search_product);
                        $i++;
                    }
                }
            }

            if( $item->nodeName == 'LatestSoftwareVersionInfo' || $item->nodeName == 'LatestSignatureVersionInfo' )
                $url_array[$device['serial']][$key][$item->nodeName] = $this->get_software( $item, $search_product );
        }
    }

}