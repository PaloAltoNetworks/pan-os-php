<?php


class REGISTERIP extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE EXAMPLES: ') . "\n - php " . basename(__FILE__) . " in=api://1.2.3.4 actions=register location=vsys1 records=10.0.0.1,domain\\user2/10.2.3.4,domain\\user3"
            . "\n - php " . basename(__FILE__) . " in=api://1.2.3.4 actions=register location=vsys1 recordFile=users.txt";
        
        
        $this->prepareSupportedArgumentsArray();
        
        
        $this->utilInit();


        $this->main();


        $this->endOfScript();
    }

    public function main()
    {

        PH::print_stdout( " - Connected to API at {$this->pan->connector->apihost} / {$this->pan->connector->info_hostname}");
        PH::print_stdout( " - PANOS version: {$this->pan->connector->info_PANOS_version}");
        PH::print_stdout( " - PANOS model: {$this->pan->connector->info_model}");
        PH::print_stdout( "");


        if( !isset(PH::$args['actions']) )
            display_error_usage_exit("no 'action' was defined");


        $action = strtolower(PH::$args['actions']);

        if( $action == 'display' || $action == 'unregister-unused' )
        {
            PH::print_stdout( " - action is '$action'");
            PH::print_stdout( "");

            $unregister_array = array();

            $this->pan->load_from_domxml($this->xmlDoc);

            if( $this->configType == 'panos' )
                $virtualsystems = $this->pan->getVirtualSystems();
            elseif( $this->configType == 'panorama' )
                $virtualsystems = $this->pan->getDeviceGroups();



            foreach( $virtualsystems as $sub )
            {
                $unregister_array[$sub->name()] = array();

                PH::print_stdout( "##################################" );
                PH::print_stdout( PH::boldText(" - " . $sub->name() ) );

                $register_ip_array = $this->pan->connector->register_getIp($sub->name());
                PH::print_stdout( "     - registered-ips: [" . count($register_ip_array) . "]");

                foreach( $register_ip_array as $ip => $reg )
                {
                    $first_value = reset($reg); // First Element's Value
                    $first_key = key($reg); // First Element's Key

                    PH::print_stdout( "          " . $ip . " - " . $first_key );
                }

                if( $this->configType == 'panos' )
                    $vsys = $this->pan->findVirtualSystem($sub->name());
                else
                    $vsys = $sub;

                $address_groups = $vsys->addressStore->addressGroups();

                $shared_address_groups = $this->pan->addressStore->addressGroups();

                $address_groups = array_merge($shared_address_groups, $address_groups);
                PH::print_stdout( "     - DAGs: ");

                $dynamicAddressGroup_array = array();
                foreach( $address_groups as $addressGroup )
                {
                    if( $addressGroup->isDynamic() )
                    {
                        $tags = $addressGroup->tags->tags();

                        PH::print_stdout( "          " . $addressGroup->name() . " filter: " . $addressGroup->filter );

                        $dynamicAddressGroup_array = $this->pan->connector->dynamicAddressGroup_get( $sub->name(), $this->configType );
                        if( isset($dynamicAddressGroup_array[$addressGroup->name()]) )
                        {
                            foreach( $dynamicAddressGroup_array[$addressGroup->name()] as $key => $members )
                            {
                                if( $key != 'name' )
                                    PH::print_stdout( "           - " . $key );
                            }
                        }
                    }
                }


                PH::print_stdout( "----------------------------------");
                PH::print_stdout( "VALIDATION:");

                if( empty($register_ip_array) )
                {
                    PH::print_stdout( "nothing registered");
                }
                else
                {
                    foreach( $register_ip_array as $ip => $reg )
                    {
                        $first_value = reset($reg); // First Element's Value
                        $first_key = key($reg); // First Element's Key

                        if( empty($dynamicAddressGroup_array) )
                        {
                            $unregister_array[$sub->name()][$ip] = $reg;
                            #PH::print_stdout( "unregister: ".$ip );
                        }

                        foreach( $dynamicAddressGroup_array as $key => $group )
                        {
                            #PH::print_stdout( "KEY: ".$key );
                            #print_r( $group );
                            if( !isset($group[$ip]) )
                            {
                                $unregister_array[$sub->name()][$ip] = $reg;
                                #PH::print_stdout( "unregister: ".$ip );
                            }
                            else
                            {
                                #PH::print_stdout( "unset: ".$ip );
                                unset($unregister_array[$sub->name()][$ip]);
                                break;
                            }
                        }
                    }
                }


                PH::print_stdout( "possible IPs for UNREGISTER:");
                #print_r( $unregister_array );
                foreach( $unregister_array[$sub->name()] as $unregister_ip => $tags )
                {
                    PH::print_stdout( " - " . $unregister_ip );
                }

                PH::print_stdout( "DAGs can be deleted (because they are not used in Ruleset):" );
                foreach( $dynamicAddressGroup_array as $key => $group )
                {
                    if( count($group) <= 1 )
                        PH::print_stdout( " - " . $key );
                }
            }
        }
        elseif( $action == 'fakeregister' )
        {
            $numberOfIPs = 20;
            $tag = 'fake';
            $startingIP = ip2long('10.0.0.0');

            $records = array();


            PH::print_stdout( "  - Generating {$numberOfIPs} fake records starting at IP " . long2ip($startingIP) . "... " );
            for( $i = 1; $i <= $numberOfIPs; $i++ )
            {
                $records[long2ip($startingIP + $i)] = array($tag);
            }

            PH::print_stdout( " - now sending records to API ... ");
            $this->pan->connector->register_sendUpdate($records, null, 'vsys1');
        }
        else
            derr("actions '{$action}' is not supported");


        if( $action == 'unregister-unused' )
        {
            foreach( $virtualsystems as $sub )
            {
                PH::print_stdout( " - now sending records to API ... ");
                $this->pan->connector->register_sendUpdate(null, $unregister_array[$sub->name()], $sub->name());
            }
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments[] = array('niceName' => 'Actions', 'shortHelp' => 'type of action you want to perform against API', 'argDesc' => 'display|unregister-unused|fakeregister');
        $this->supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'the target PANOS device ie: in=api://1.2.3.4', 'argDesc' => 'api://[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'defines the VSYS target of the UserID request', 'argDesc' => 'vsys1[,vsys2,...]');
        $this->supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');


        #$this->supportedArguments[] = array('niceName' => 'records', 'shortHelp' => 'list of userid records to register/unregister in API', 'argDesc' => '10.0.0.1,domain\user2/10.2.3.4,domain\user3');
        #$this->supportedArguments[] = array('niceName' => 'recordFile', 'shortHelp' => 'use a text file rather than CLI to input UserID records', 'argDesc' => 'users.txt');
    }

}