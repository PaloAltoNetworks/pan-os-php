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

class CONFIG_DOWNLOAD_ALL__ extends UTIL
{
    public $utilType = null;

    public function utilStart()
    {
        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
#$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
            "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n" .
            "php ".basename(__FILE__)." help          : more help messages\n";

        $this->prepareSupportedArgumentsArray();

        $this->utilInit();

        $this->main();


        $this->endOfScript();
    }

    public function main( )
    {

        $pan = $this->pan;
        $inputConnector = $pan->connector;



        if( $this->configInput['type'] !== 'api' )
            derr('only API connection supported');

########################################################################################################################
        $inputConnector->refreshSystemInfos();

        print "\n\n##########################################\n";

        if( $this->configType == 'panorama' )
        {
            print 'PANORAMA serial: '.$inputConnector->info_serial."\n\n";


            $config_pan_candidate = $inputConnector->getCandidateConfig();
            $config_pan_candidate->save( $inputConnector->info_serial."_PANORAMA.xml" );


########################################################################################################################
            $device_serials = $inputConnector->panorama_getConnectedFirewallsSerials();

            foreach( $device_serials as $child )
            {
                print "##########################################\n";

                $fw_con = $inputConnector->cloneForPanoramaManagedDevice($child['serial']);
                $fw_con->refreshSystemInfos();
                $fw_con->setShowApiCalls($this->debugAPI);

                $this->downloadFWconfig( $fw_con, $child['hostname'] );
            }
        }
        elseif( $this->configType == 'panos' )
        {
            #print 'PANOS serial: '.$inputConnector->info_serial."\n\n";

            $this->downloadFWconfig( $inputConnector, $inputConnector->info_hostname );
        }

    }

    function downloadFWconfig( $fw_con, $hostname)
    {
        print 'FIREWALL serial: ' . $fw_con->info_serial . "\n\n";

        $config_candidate = $fw_con->getCandidateConfig();
        ##########SAVE config
        $pan = new PANConf();
        $pan->load_from_domxml($config_candidate);
        $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW.xml");



        $config_pushed = $fw_con->getPanoramaPushedConfig();
        if( $config_pushed->nodeType == XML_DOCUMENT_NODE )
            $found = DH::findFirstElement('config', $config_pushed);

        if( $found !== false )
        {
            ##########SAVE config
            $pan = new PANConf();
            $pan->load_from_domxml($config_pushed);
            $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW_panorama-pushed.xml");
        }

    }

}