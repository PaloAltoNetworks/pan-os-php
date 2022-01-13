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

class SOFTWAREREMOVE extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to "display" or "delete" installed and uploaded SW / content / anti-virus / wildfirew', 'argDesc' => 'action:arg1');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['xpath'] = array('niceName' => 'xpath', 'shortHelp' => 'specify the xpath to get the value defined on this config');


        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml " .
            "actions=display\n" .
            "php " . basename(__FILE__) . " help          : more help messages\n";

        $this->prepareSupportedArgumentsArray();


        $this->utilInit();


        $this->main();


        $this->endOfScript();
    }
    
    public function main()
    {
        $pan = $this->pan;
        $connector = $pan->connector;
    
    
        if( isset(PH::$args['actions']) )
        {
            $actions = PH::$args['actions'];
            if( $actions !== "display" && $actions !== "delete" )
            {
                $this->display_error_usage_exit('"actions" argument only support "display" or "delete" ');
            }
        }
        else
            $actions = 'display';
    
    
        ########################################################################################################################
    
        $queries['software'] = '&type=op&action=complete&xpath=/operations/request/system/software/install/version';
        $queries['wildfire'] = '&type=op&action=complete&xpath=/operations/request/wildfire/upgrade/install/file';
        $queries['anti-virus'] = '&type=op&action=complete&xpath=/operations/request/anti-virus/upgrade/install/file';
        $queries['content'] = '&type=op&action=complete&xpath=/operations/request/content/upgrade/install/file';
    
        ########################################################################################################################
        $connector->refreshSystemInfos();
    
        PH::print_stdout("");
        PH::print_stdout("##########################################");
        PH::print_stdout('MASTER device serial: ' . $connector->info_serial);
        PH::print_stdout("");
    
        PH::$JSON_TMP['serial'] = $connector->info_serial;
        PH::print_stdout(PH::$JSON_TMP, FALSE, "master device");
        PH::$JSON_TMP = array();
    
    
        if( $this->configType == 'panos' )
        {
            if( $connector->serial != "" )
            {
                $fw_con = $connector->cloneForPanoramaManagedDevice($connector->serial);
                $fw_con->refreshSystemInfos();
                if( $this->debugAPI )
                    $fw_con->setShowApiCalls($this->debugAPI);

                $this->checkInstallation($fw_con, $queries);
            }
            else
            {
                $connector->refreshSystemInfos();

                $this->checkInstallation($connector, $queries);
            }
        }
        elseif( $this->configType == 'panorama' )
        {
            $device_serials = $connector->panorama_getConnectedFirewallsSerials();
    
            //Todo: missing stuff, delete old content from Panorama
            //1) direct for Panorama
            //2) on Panorama for FWs
    
            $i = 0;
            foreach( $device_serials as $child )
            {
                $fw_con = $connector->cloneForPanoramaManagedDevice($child['serial']);
                $fw_con->refreshSystemInfos();
                if( $this->debugAPI )
                    $fw_con->setShowApiCalls($this->debugAPI);
    
                $string = " - SERIAL: " . $child['serial'];
                $string .= "  -  " . $child['hostname'] . " - ";
                $string .= $fw_con->info_mgmtip;
    
                PH::print_stdout($string);
                $i++;
    
    
                //only direct FW connect possible to use for getting correct info
                $direct_fw_con = new PanAPIConnector($fw_con->info_mgmtip, $connector->apikey);
                $direct_fw_con->refreshSystemInfos();
                if( $this->debugAPI )
                    $direct_fw_con->setShowApiCalls($this->debugAPI);
    
                $this->checkInstallation($direct_fw_con, $queries);
            }
        }
    
        //use class
        PH::print_stdout(PH::$JSON_TMP, FALSE, "serials");
        PH::$JSON_TMP = array();

    }

    public function checkInstallation($connector, $queries)
    {
        global $actions;

        foreach( $queries as $key => $query )
        {
            PH::print_stdout("");
            PH::print_stdout("-------------------------------");
            PH::print_stdout("Display uploaded part for: " . $key);
            PH::print_stdout("");

            $string = " - installed: ";

            $key2 = "update";
            if( $key === 'content' )
                $version = $connector->info_app_version;
            elseif( $key === "software" )
            {
                $version = $connector->info_PANOS_version;
                $key2 = "version";
            }

            elseif( $key === "anti-virus" )
                $version = $connector->info_av_version;
            elseif( $key === "wildfire" )
                $version = $connector->info_wildfire_version;

            PH::print_stdout($string . $version);
            PH::print_stdout("");

            #$queries['content'] = '&type=op&action=complete&xpath=/operations/request/content/upgrade/install/file';
            $ret = $connector->sendRequest($query);

            #$tmp_ret = $ret->saveXML();
            #print $tmp_ret."\n";

            $ret = DH::findFirstElement("response", $ret);
            if( $ret !== FALSE )
                $ret = DH::findFirstElement("completions", $ret);

            if( $ret !== FALSE )
            {
                PH::print_stdout(" - uploaded:");
                foreach( $ret->childNodes as $completion )
                {
                    $value = DH::findAttribute('value', $completion);
                    PH::print_stdout("   - " . $value);

                    //DO not delete main SW version
                    $mainSWversion = "";
                    if( strpos($version, ".") !== FALSE && strpos($version, "pan") === FALSE )
                    {
                        $version_array = explode(".", $version);
                        $mainSWversion = $version_array[0] . "." . $version_array[1] . ".0";
                    }
                    if( $actions === 'delete' && strpos($value, $version) === FALSE && ($mainSWversion === "" || strpos($value, $mainSWversion) === FALSE) )
                    {
                        PH::enableExceptionSupport();
                        try
                        {
                            PH::print_stdout("     * try to delete:" . $value);
                            //api/?type=op&cmd=<delete><content><update></update></content></delete>
                            $cmd = '<delete><' . $key . '><' . $key2 . '>' . $value . '</' . $key2 . '></' . $key . '></delete>';
                            $res = $connector->sendOpRequest($cmd, TRUE);
                            $tmp_ret = $res->saveXML();
                            PH::print_stdout("       * " . $tmp_ret);
                        } catch(Exception $e)
                        {
                            PH::disableExceptionSupport();

                            PH::print_stdout("          ***** API Error occured : " . $e->getMessage());
                        }
                    }
                }
            }
        }
    }

}