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


class SOFTWARE_PREPARATION__
{
    public $utilType = null;

    function __construct( $argv, $argc )
    {
        $this->main( $argv, $argc );
    }
    
    
    public function utilStart()
    {
        $this->prepareSupportedArgumentsArray();


        $this->utilInit();


        $this->main();


        $this->endOfScript();
    }

    public function main( $argv, $argc)
    {
        $tmp_ph = new PH($argv, $argc);

        PH::print_stdout("");
        PH::print_stdout("***********************************************");
        PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
        PH::print_stdout("");

        PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );
        PH::processCliArgs();

        $debugAPI = false;

        if( ! isset(PH::$args['in']) )
            $this->display_error_usage_exit('"in" is missing from arguments');
        $configInput = PH::$args['in'];
        if( !is_string($configInput) || strlen($configInput) < 1 )
            $this->display_error_usage_exit('"in" argument is not a valid string');


        if( isset(PH::$args['debugapi'])  )
        {
            $debugAPI = true;
        }



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



########################################################################################################################



########################################################################################################################
        $inputConnector->refreshSystemInfos();


        print "\n\n##########################################\n";
        print 'MASTER device serial: '.$inputConnector->info_serial."\n\n";


        $device_array = array();
        $new_device_array = array();
        $old_device_array = array();

        $stringStart = "<?xml version=\"1.0\"?>
<response status=\"success\">
  <result>
    <devices>
";

        $string = "";
        if( $configType == 'panos' )
        {
            if( $inputConnector->serial != "" )
            {
                $fw_con = $inputConnector->cloneForPanoramaManagedDevice($inputConnector->serial);
                $fw_con->refreshSystemInfos();

                $string .= $this->print_string( $fw_con );
                $new_device_array[ $fw_con->info_serial ] = $this->print_string( $inputConnector );
            }
            else
            {
                $inputConnector->refreshSystemInfos();

                $string .= $this->print_string( $inputConnector );
                $new_device_array[ $inputConnector->info_serial ] = $this->print_string( $inputConnector );
            }
        }
        elseif( $configType == 'panorama' )
        {
            $string .= $this->print_string( $inputConnector );
            $new_device_array[ $inputConnector->info_serial ] = $this->print_string( $inputConnector );

            $device_serials = $inputConnector->panorama_getConnectedFirewallsSerials();

            $i=0;
            foreach( $device_serials as $child )
            {
                $fw_con = $inputConnector->cloneForPanoramaManagedDevice($child['serial']);
                $fw_con->refreshSystemInfos();

                $string .= $this->print_string( $fw_con );
                $new_device_array[ $fw_con->info_serial ] = $this->print_string( $fw_con );
            }
        }

        $stringEnd = "    </devices>
  </result>
</response>
";




        $input_file_name = dirname(__FILE__)."/software/software_downloader_devices.txt";
        if( !file_exists($input_file_name) )
        {
            file_put_contents($input_file_name, $stringStart.$string.$stringEnd);
        }
        else{
            $content = file_get_contents($input_file_name);

            $dom = new DOMDocument;
            $dom->loadXML($content);
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


            $string_old = "";
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


                $string_old .= "      <entry name=\"".$serial->textContent."\">\n";
                $string_old .= "        <serial>".$serial->textContent."</serial>\n";
                $string_old .= "        <sw-version>".$sw_version->textContent."</sw-version>>\n";

                $string_old .= "        <model>".$model->textContent."</model>\n";

                $string_old .= "        <uuid>" . $uuid->textContent . "</uuid>\n";
                $string_old .= "        <cpuid>" . $cpuid->textContent . "</cpuid>\n";

                $string_old .= "        <app-version>".$app_version->textContent."</app-version>\n";
                $string_old .= "        <av-version>".$av_version->textContent."</av-version>\n";
                $string_old .= "        <wildfire-version>".$wildfire_version->textContent."</wildfire-version>\n";
                $string_old .= "        <threat-version>".$threat_version->textContent."</threat-version>\n";
                $string_old .= "      </entry>\n";


                $old_device_array[ $serial->textContent ] = $serial->textContent;
            }


            if( count($new_device_array) == 0 )
                derr( "no firewalls connected to this Panorama" );

            $string = "";
            foreach( $new_device_array as $key => $serial )
            {

                if( isset( $old_device_array[ $key ] ) )
                {
                    unset( $new_device_array[ $key ] );
                    print "- SKIPPED - Serial already added: ".$key."\n";
                }
                else
                {
                    #$string .= $new_device_array[ $key ];
                    $string .= $serial;
                    print "Serial added: ".$key."\n";
                }

            }

            file_put_contents($input_file_name, $stringStart.$string_old.$string.$stringEnd);
            print "\n\n";
        }

    }

    function display_usage_and_exit($shortMessage = false)
    {
        global $argv;
        print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://[MGMT-IP] \n";
        print PH::boldText("\nExamples:\n");
        print " - php ".basename(__FILE__)." in=api://192.168.50.10\n";


        exit(1);
    }

    function display_error_usage_exit($msg)
    {
        fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
        $this->display_usage_and_exit(true);
    }

    function print_string( $inputConnector )
    {
        $string = "      <entry name=\"".$inputConnector->info_serial."\">\n";
        $string .= "        <serial>".$inputConnector->info_serial."</serial>\n";
        $string .= "        <sw-version>".$inputConnector->info_PANOS_version."</sw-version>>\n";
        $string .= "        <model>".$inputConnector->info_model."</model>\n";

        $string .= "        <uuid>" . $inputConnector->info_vmuuid . "</uuid>\n";
        $string .= "        <cpuid>" . $inputConnector->info_vmcpuid . "</cpuid>\n";

        $string .= "        <app-version>".$inputConnector->info_app_version."</app-version>\n";
        $string .= "        <av-version>".$inputConnector->info_av_version."</av-version>\n";
        $string .= "        <wildfire-version>".$inputConnector->info_wildfire_version."</wildfire-version>\n";
        $string .= "        <threat-version>".$inputConnector->info_threat_version."</threat-version>\n";
        $string .= "      </entry>\n";

        return $string;
    }
    
}