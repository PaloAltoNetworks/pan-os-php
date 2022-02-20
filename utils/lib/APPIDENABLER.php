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

class APPIDENABLER extends UTIL
{
    public $cycleConnectedFirewalls = FALSE;
    public $actions = 'display';

    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api://[MGMT-IP] [cycleconnectedFirewalls] [actions=enable]";

        $this->prepareSupportedArgumentsArray();

        $this->utilInit();

        $this->main();

        $this->save_our_work();

        
    }

    public function main()
    {
        ##########################################
        ##########################################

        if( isset(PH::$args['cycleconnectedfirewalls']) )
            $this->cycleConnectedFirewalls = TRUE;

        if( !isset(PH::$args['actions']) || strtolower(PH::$args['actions']) == 'display' )
            $this->actions = 'display';
        elseif( strtolower(PH::$args['actions']) == 'enable' )
            $this->actions = 'enable';

        ##########################################

        if( $this->cycleConnectedFirewalls && $this->configType == 'panorama' )
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

                $this->disable_appid( $tmpConnector);
            }
        }
        else
        {
            $this->load_config();
            $this->disable_appid( $this->pan->connector);
        }

        ##########################################
        ##########################################
        if( !PH::$shadow_json )
            PH::print_stdout( "" );


    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');
        $this->supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each disabled app-id. ie: actions=display / actions=enable', 'argDesc' => 'action:arg1[,arg2]');
    }

    function disable_appid( $Connector)
    {
        $tmp_application_status = DH::findXPath('/config/shared/application-status/entry', $this->xmlDoc);

        if( $tmp_application_status->length == 0 )
        {
            //THIS is a NON available XPATH | TODO: swaschkut 20190115 validate it!!!
            $tmp_application_status = DH::findXPath('/config/devices/entry/vsys/entry/application-status/entry', $this->xmlDoc);
            if( $tmp_application_status->length == 0 )
                PH::print_stdout( PH::boldText("\nNO disabled APP-IDs available\n") );
        }

        foreach( $tmp_application_status as $app_status )
        {
            PH::print_stdout( "----------------" );
            PH::print_stdout( "name: " . DH::findAttribute('name', $app_status) );

            $text = "";

            if( $this->actions == 'display' )
                PH::print_stdout( " - status: " . DH::findAttribute('status', $app_status) );
            elseif( $this->actions == 'enable' )
            {
                $apiArgs = array();
                $apiArgs['type'] = 'op';
                $apiArgs['cmd'] = '<request><set-application-status-recursive><application>' . DH::findAttribute('name', $app_status) . '</application><status>enabled</status></set-application-status-recursive></request>';

                if( $this->configInput['type'] == 'api' )
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