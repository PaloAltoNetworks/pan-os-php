<?php


class APPIDENABLER extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api://[MGMT-IP] [cycleconnectedFirewalls] [actions=enable]";

        $this->prepareSupportedArgumentsArray();

        $this->utilInit();

        $this->main();


        $this->endOfScript();
    }

    public function main()
    {
        $actions = null;

        ##########################################
        ##########################################

        if( isset(PH::$args['cycleconnectedfirewalls']) )
            $cycleConnectedFirewalls = TRUE;
        else
            $cycleConnectedFirewalls = FALSE;

        if( !isset(PH::$args['actions']) || strtolower(PH::$args['actions']) == 'display' )
            $actions = 'display';
        elseif( strtolower(PH::$args['actions']) == 'enable' )
            $actions = 'enable';

        ##########################################

        if( $cycleConnectedFirewalls && $this->configType == 'panorama' )
        {
            $firewallSerials = $this->pan->connector->panorama_getConnectedFirewallsSerials();

            $countFW = 0;
            foreach( $firewallSerials as $fw )
            {
                $countFW++;
                PH::print_stdout( " ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **" );
                $tmpConnector = $this->pan->connector->cloneForPanoramaManagedDevice($fw['serial']);

                if( $this->debugAPI )
                    $tmpConnector->setShowApiCalls(TRUE);
                $this->xmlDoc = $tmpConnector->getCandidateConfig();

                $this->disable_appid($actions, $this->xmlDoc, $this->configInput, $tmpConnector);
            }
        }
        else
        {
            $this->load_config();
            $this->disable_appid($actions, $this->xmlDoc, $this->configInput, $this->pan->connector);
        }

        ##########################################
        ##########################################
        if( !PH::$shadow_json )
            PH::print_stdout( "" );

        $this->save_our_work();
    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');
        $this->supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each disabled app-id. ie: actions=display / actions=enable', 'argDesc' => 'action:arg1[,arg2]');
    }

    function disable_appid($actions, $xmlDoc1, $configInput, $Connector)
    {
        $tmp_application_status = DH::findXPath('/config/shared/application-status/entry', $xmlDoc1);

        if( $tmp_application_status->length == 0 )
        {
            //THIS is a NON available XPATH | TODO: swaschkut 20190115 validate it!!!
            $tmp_application_status = DH::findXPath('/config/devices/entry/vsys/entry/application-status/entry', $xmlDoc1);
            if( $tmp_application_status->length == 0 )
                PH::print_stdout( PH::boldText("\nNO disabled APP-IDs available\n") );
        }


        foreach( $tmp_application_status as $app_status )
        {
            PH::print_stdout( "----------------" );
            PH::print_stdout( "name: " . DH::findAttribute('name', $app_status) );


            if( $actions == 'display' )
                PH::print_stdout( " - status: " . DH::findAttribute('status', $app_status) );
            elseif( $actions == 'enable' )
            {
                $apiArgs = array();
                $apiArgs['type'] = 'op';
                $apiArgs['cmd'] = '<request><set-application-status-recursive><application>' . DH::findAttribute('name', $app_status) . '</application><status>enabled</status></set-application-status-recursive></request>';

                if( $configInput['type'] == 'api' )
                {
                    $response = $Connector->sendRequest($apiArgs);
                    $text = " - status: enable";
                }
                else
                {
                    //Todo: remove the entry in the XML, then offline mode should be supported
                    derr("this script is working only in API mode\n");
                }

            }

            PH::print_stdout( $text );
        }
    }
}