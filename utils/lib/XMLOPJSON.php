<?php


class XMLOPJSON extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api://[MGMT-IP] [cycleconnectedFirewalls] [actions=enable]";

        #$this->prepareSupportedArgumentsArray();
        #PH::processCliArgs();

        #$this->arg_validation();
        $this->utilInit();

        $this->main();


        ##########################################
        ##########################################
        PH::print_stdout("");

        $this->save_our_work();


        $this->endOfScript();
    }

    public function main()
    {
        $connector = $this->pan->connector;

        if( isset(PH::$args['cycleconnectedfirewalls']) )
            $cycleConnectedFirewalls = TRUE;
        else
            $cycleConnectedFirewalls = FALSE;

        if( isset(PH::$args['cmd'] ) )
        {
            $cmd = PH::$args['cmd'];

            if( $this->configInput['type'] == 'api' )
            {
                if( $cycleConnectedFirewalls && $this->configType == 'panorama' )
                {
                    $xml_string = "";

                    $firewallSerials = $connector->panorama_getConnectedFirewallsSerials();

                    $countFW = 0;
                    foreach( $firewallSerials as $fw )
                    {
                        $countFW++;
                        PH::print_stdout( " ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **" );
                        $tmpConnector = $connector->cloneForPanoramaManagedDevice($fw['serial']);

                        if( $this->debugAPI )
                            $tmpConnector->setShowApiCalls(TRUE);

                        $response = $tmpConnector->sendOpRequest($cmd, FALSE);

                        $response->preserveWhiteSpace = false;
                        $response->formatOutput = true;

                        $xml_string .= $response->saveXML($response->documentElement);
                    }
                }
                else
                {
                    $response = $connector->sendOpRequest($cmd, FALSE);

                    $response->preserveWhiteSpace = false;
                    $response->formatOutput = true;

                    $xml_string = $response->saveXML($response->documentElement);
                }
            }
            else
            {
                $xml_string = "<response status=\"error\"><error>pan-os-php - this script is working only in API mode</error></response>";
            }
        }
        else
            $xml_string = "<response status=\"error\"><error>pan-os-php - cmd argument not found</error></response>";


        PH::print_stdout("");
        PH::print_stdout( "XML response:");
        PH::print_stdout( $xml_string );

        $xml = simplexml_load_string($xml_string);
        $json =  json_encode($xml, JSON_PRETTY_PRINT);

        PH::print_stdout("");
        PH::print_stdout( "JSON:");

        //this is the original JSON, so print it out
        print $json ;

    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['cmd'] = array('niceName' => 'cmd', 'shortHelp' => 'PAN-OS XML API - command');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['shadow-json'] = array('niceName' => 'shadow-JSON', 'shortHelp' => 'display ONLY JSON string');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for bpa generator');
    }

}