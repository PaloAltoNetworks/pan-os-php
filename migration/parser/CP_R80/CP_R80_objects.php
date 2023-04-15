<?php


trait CP_R80_objects
{
    //##########################################################################
//print out all available ARRAY information from JSON
    function print_object_array($array, $padding)
    {
        /*
        * @param VirtualSystem $v
        */

        if( count($array) == 1 )
            $array = $array[0];

        #print_r( $array );
        print "count: " . count($array)."\n";



        if( !is_array($array) )
            $array = array();

        $type_array = array();

        foreach( $array as $subarray )
        {
            #print_r( $subarray );

            /*
            if( isset( $subarray['type'] ) )
            {
                $name = $subarray['type'];

                if( isset( $type_array[$name] ) )
                {
                    if( $type_array[$name] != $name )
                        print "check this\n";
                }
                else
                    $type_array[$name] = $name;
            }
            */

            if( isset($subarray['type']) )
            {
                $name = $subarray['type'];
                $this->objectArray[$name][$subarray['uid']] = $subarray;
            }
        }

        #print_r( $type_array );
        foreach( $this->objectArray as $key => $subarray )
        {

            /*
            [vpn-community-star] => vpn-community-star
            [vpn-community-meshed] => vpn-community-meshed
            [RulebaseAction] => RulebaseAction
                [CpmiAnyObject] => CpmiAnyObject
                    [host] => host
                    [service-tcp] => service-tcp
                    [group] => group
                    [network] => network
                    [service-udp] => service-udp
                    [service-group] => service-group
            [Track] => Track
            [Global] => Global
            [time] => time
                [service-icmp] => service-icmp
                [simple-gateway] => simple-gateway
                [CpmiHostCkp] => CpmiHostCkp
                [service-other] => service-other
                    [address-range] => address-range
            */

            print "KEY: '" . $key . "' - count: " . count($subarray) . "\n";


            if( $key == "host" )
            {
                $this->add_host_objects($subarray);

            }
            elseif( $key == "network" )
            {
                $this->add_network_objects($subarray);
            }
            elseif( $key == "address-range" )
            {
                foreach( $subarray as $host_key => $host )
                {
                    $domain = $host['domain']['name'];
                    $this->check_vsys( $domain );

                    #print_r($host);
                    $name = $host['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));
                    $first = $host['ipv4-address-first'];
                    $last = $host['ipv4-address-last'];
                    $type = "ip-range";
                    $description = $host['comments'];

                    #print "name: ".$host['name']. " - ip-address: ".$first." last: ".$last." comments: ".$host['comments']."\n";


                    $value = $first . "-" . $last;


                    $this->MainAddHost( $name, $value, $type, $description );
                    /*
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address == null )
                    {
                        print "- create address-range: " . $name . "\n";
                        $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
                    }
                    else
                    {
                        mwarning("address-range: " . $name . " already available\n");
                    }

                    $tmp_address->setDescription($description);
                    */


                    if( isset($host['ipv6-address-first']) )
                        $first = $host['ipv6-address-first'];
                    else
                        $first = "";

                    if( isset($host['ipv6-address-last']) )
                        $last = $host['ipv6-address-last'];
                    else
                        $last = "";


                    if( $first != "" || $last != "" )
                    {
                        $name = "IPv6-" . $name;
                        $name = $this->truncate_names($this->normalizeNames($name));
                        $value = $first . "-" . $last;
                        #$type = "ip-netmask";
                        #$description = $host['comments'];

                        mwarning("IPV6 - " . $first . "-" . $last . "\n");


                        $this->MainAddHost( $name, $value, $type, $description );

                        /*
                        $tmp_address = $this->sub->addressStore->find($name);
                        if( $tmp_address == null )
                        {
                            print "- create address-range: " . $name . "\n";
                            $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
                        }
                        else
                        {
                            mwarning("address-range: " . $name . " already available\n");
                        }

                        $tmp_address->setDescription($description);
                        */
                    }

                }
            }
            elseif( $key == "group" )
            {
                print "   - group is done later\n";
            }
            elseif( $key == "service-tcp" )
            {
                foreach( $subarray as $service_key => $service )
                {
                    #print_r($service);
                    $domain = $service['domain']['name'];
                    $this->check_vsys( $domain );

                    $name = $service['name'];
                    $dport = $service['port'];
                    $description = $service['comments'];

                    $this->MainAddService( $name, 'tcp', $dport, $description);

                    /*
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service == null )
                    {
                        print "- create tcp service: " . $name . "\n";
                        $tmp_service = $this->sub->serviceStore->newService($name, "tcp", $dport, $description);
                    }
                    else
                    {
                        mwarning("tcp service: " . $name . " already available\n");
                    }
                    */
                }
            }
            elseif( $key == "service-udp" )
            {

                foreach( $subarray as $service_key => $service )
                {
                    #print_r($service);
                    $domain = $service['domain']['name'];
                    $this->check_vsys( $domain );

                    $name = $service['name'];
                    $dport = $service['port'];
                    $description = $service['comments'];

                    $this->MainAddService( $name, 'udp', $dport, $description);
                    /*
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service == null )
                    {
                        print "- create udp service: " . $name . "\n";
                        $tmp_service = $this->sub->serviceStore->newService($name, "udp", $dport, $description);
                    }
                    else
                    {
                        mwarning("udp service: " . $name . " already available\n");
                    }
                    */
                }
            }

            elseif( $key == "service-icmp" )
            {
                foreach( $subarray as $service_key => $service )
                {
                    $domain = $service['domain']['name'];
                    $this->check_vsys( $domain );

                    #print_r($service);
                    //Todo: create tmp service, bring in information related to "icmp-type" which app-id will replace this service
                    $name = "tmp-" . $service['name'];
                    $dport = $service['icmp-type'];

                    $description = "icmp-type:{" . $dport."}";
                    #print "Todo: create tmp service: ".$name." | ".$dport. " | ".$description."\n";

                    $this->MainAddService( $name, 'tcp', '6500', $description);

                    /*
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service == null )
                    {
                        print "- create service-icmp: " . $name . "\n";
                        $tmp_service = $this->sub->serviceStore->newService($name, "tcp", '6500', $description);
                    }
                    else
                    {
                        mwarning("service-icmp: " . $name . " already available\n");
                    }
                    */
                }
            }
            elseif( $key == "service-other" )
            {
                foreach( $subarray as $service_key => $service )
                {
                    $domain = $service['domain']['name'];
                    $this->check_vsys( $domain );

                    #print_r($service);
                    //Todo: create tmp service, bring in information related to "ip-protocol" which app-id will replace this service
                    $name = "tmp-" . $service['name'];
                    $dport = $service['ip-protocol'];

                    $description = "ip-protocol=" . $dport;
                    #print "Todo: create tmp service: ".$name." | ".$dport. " | ".$description."\n";

                    $this->MainAddService( $name, 'tcp', '6500', $description);

                    /*
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service == null )
                    {
                        print "- create service-other: " . $name . "\n";
                        $tmp_service = $this->sub->serviceStore->newService($name, "tcp", '6500', $description);
                    }
                    else
                    {
                        mwarning("service-other: " . $name . " already available\n");
                    }
                    */
                }
            }
            elseif( $key == "service-group" )
            {
                print "   - service-group is done later\n";
            }
            elseif( $key == "CpmiAnyObject" )
            {
                #print_r( $subarray );
            }
            elseif( $key == "simple-gateway" )
            {
                foreach( $subarray as $host_key => $host )
                {
                    $domain = $host['domain']['name'];
                    $this->check_vsys( $domain );
                    #print_r( $host );
                    #print "name: ".$host['name']. " - ip-address: ".$host['ipv4-address']." comments: ".$host['comments']."\n";

                    //now create host object
                    $name = $host['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));
                    $value = $host['ipv4-address'];
                    $type = "ip-netmask";

                    $this->MainAddHost( $name, $value, $type );

                    /*
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address == null )
                    {
                        print "- create address simple-gateway: " . $name . "\n";
                        $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
                    }
                    else
                    {
                        mwarning("address simple-gateway: " . $name . " already available\n");
                    }
                    */
                }
            }
            elseif( $key == "CpmiHostCkp" )
            {
                foreach( $subarray as $host_key => $host )
                {
                    $domain = $host['domain']['name'];
                    $this->check_vsys( $domain );

                    #print_r( $host );
                    #print "name: ".$host['name']. " - ip-address: ".$host['ipv4-address']." comments: ".$host['comments']."\n";

                    //now create host object

                    $name = $host['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));
                    $value = $host['ipv4-address'];
                    $type = "ip-netmask";

                    $this->MainAddHost( $name, $value, $type );

                    /*
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address == null )
                    {
                        print "- create address CpmiHostCkp: " . $name . "\n";
                        $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
                    }
                    else
                    {
                        mwarning("address CpmiHostCkp: " . $name . " already available\n");
                    }
                    */
                }
            }
            elseif( $key == "time" )
            {
                //todo add schedule objects
                foreach( $subarray as $host_key => $host )
                {
                    $domain = $host['domain']['name'];
                    $this->check_vsys( $domain );

                    #print_r( $host );
                    /*
                     [end-never] =>
                    [comments] =>
                    [color] => black
                    [start-now] => 1
                    [start] => Array
                        (
                            [date] => 21-Aug-2019
                            [iso-8601] => 2019-08-21T14:06:06
                            [time] => 14:06
                            [posix] => 1566396366000
                        )
                    [type] => time
                    [tags] => Array
                        ()
                    [recurrence] => Array
                        (
                            [month] => Any
                            [pattern] => Daily
                        )
                    [uid] => 3ed639af-a7c1-4aa2-b7e2-743aa066070b
                    [domain] => Array
                        (
                            [uid] => 1597c33e-af2f-824d-b6e0-5feb8ba1eda8
                            [domain-type] => domain
                            [name] => Europe_VPN
                        )
                    [name] => NTP_Rule
                    [end] => Array
                        (
                            [date] => 31-Aug-2019
                            [iso-8601] => 2019-08-31T14:05:00
                            [time] => 14:05
                            [posix] => 1567260300000
                        )
                     */

                    $name = $host['name'];
                    $TimeRangeName = rtrim($name);
                    $TimeRangeNamePan = $this->truncate_names($this->normalizeNames($TimeRangeName));

                    //Todo: create object
                    $tmp_schedule = $this->sub->scheduleStore->find($TimeRangeNamePan);
                    if( $tmp_schedule === null )
                    {
                        //if( $print )
                            print "\n * create schedule object: " . $TimeRangeNamePan . "\n";
                        $tmp_schedule = $this->sub->scheduleStore->createSchedule( $TimeRangeNamePan );
                        
                        $startISO = $host['start']['iso-8601'];

                        $endISO = $host['end']['iso-8601'];

                        $start = str_replace( "-", "/", $startISO );
                        $start = str_replace( "T", "@", $start );
                        $start = substr($start, 0, -3);

                        $end = str_replace( "-", "/", $endISO );
                        $end = str_replace( "T", "@", $end );
                        $end = substr($end, 0, -3);

                        $tmp_schedule->setNonRecurring( $start."-".$end );
                    }
                    else
                    {
                        $addlog = "time-range object already available - this can not be added: " . $name;
                        $tmp_schedule->set_node_attribute('warning', $addlog);
                    }

                }
            }
            elseif( $key == "RulebaseAction" )
            {
                //nothing must be done here: validation is done in accesslayer
                //foreach( $subarray as $host_key => $host ){
                #print_r( $host );
                /*
                [comments] => Drop
                [color] => none
                [display-name] => Drop
                [customFields] =>
                [domain]
                    [uid] => a0bbbc99-adef-4ef8-bb6d-defdefdefdef
                    [domain-type] => data domain
                    [name] => Check Point Data
                [name] => Drop
                [icon] => Actions/actionsDrop
                [type] => RulebaseAction
                [tags]
                 */
                //}
            }
            elseif( $key == "dns-domain" )
            {
                $this->add_fqdn_objects($subarray);
            }
            elseif( $key == "group-with-exclusion" )
            {
                print "   - group-with-exclusion is done later\n";
            }
            elseif( $key == "checkpoint-host" || $key == "simple-cluster" || $key == "CpmiClusterMember" )
            {
                $this->add_host_objects($subarray);
            }
            elseif(
                $key == "vpn-community-meshed"
                || $key == "vpn-community-star"
                #|| $key == "CpmiClusterMember"
                || $key == "CpmiGatewayCluster"
                || $key == "Track"
                || $key == "Global"
                || $key == "application-site"
                || $key == "DropUserCheckInteractionScheme"
                || $key == "Internet"
                || $key == "application-site-category"
                || $key == "access-role"
                || $key == "application-site-group"
                || $key == "AskUserCheckInteractionScheme"
                || $key == "threat-profile"
                || $key == "ThreatExceptionRulebase"
                || $key == "ThreatBladeException"

                || $key == "updatable-object"

                || $key == "CpmiAntimalwareAction"
                || $key == "CpmiSdTopicPerProfileDynamic"
                || $key == "DynamicGlobalNetworkObject"


                #|| $key == ""

            )
            {
                mwarning( "KEY: ".$key." not supported yet", null, false );
            }
            else
            {
                mwarning( "KEY: ".$key." not supported yet", null, false );
            }


        }

        #print_r( $type_array['group'] );
        $group_missing_members = array();


        if( isset($this->objectArray['group']) )
        {
            foreach( $this->objectArray['group'] as $host )
            {
                $missing_host_members = array();
                $missing_network_members = array();

                #print_r( $host );

                $domain = $host['domain']['name'];
                $this->check_vsys( $domain );

                $name = $host['name'];
                $name = $this->truncate_names($this->normalizeNames($name));
                $description = $host['comments'];

                print "\n - addressgroup name: " . $host['name'] . "\n";


                $tmp_addressgroup = $this->sub->addressStore->find($name);
                if( $tmp_addressgroup === null )
                {
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($name);
                    $tmp_addressgroup->setDescription($description);


                    foreach( $host['members'] as $member_uid )
                    {
                        if( !is_array($member_uid) )
                        {
                            $member_name = $this->find_address_uid($member_uid);
                            $member_name = $this->truncate_names($this->normalizeNames($member_name));
                            if( $member_name != null )
                            {
                                $tmp_address = $this->sub->addressStore->find($member_name);
                                if( $tmp_address != null )
                                {
                                    print "    - add member: " . $member_name . "\n";
                                    $tmp_addressgroup->addMember($tmp_address);
                                }
                                else
                                {
                                    $group_missing_members[$name][$member_name] = $member_name;
                                    $group_missing_members[$name]['domain'] = $domain;
                                    print "     - missing addressgroup: " . $member_name . " try to fix it later\n";
                                    #mwarning( "addressgroup: '".$name ."' | member: '".$member_name."' not found" );
                                }
                            }
                        }
                        else
                        {
                            //check if type=host
                            if( $member_uid['type'] == "host" && (isset($member_uid['ipv4-address']) || isset($member_uid['ipv4-address'])) )
                            {
                                $missing_host_members[] = $member_uid;

                                $member_name = $member_uid['name'];
                                $member_name = $this->truncate_names($this->normalizeNames($member_name));
                                $group_missing_members[$name][$member_name] = $member_name;
                                $group_missing_members[$name]['domain'] = $domain;
                                print "     - missing object: " . $member_name . " try to fix it later\n";
                            }
                            elseif( $member_uid['type'] == "network" && (isset($member_uid['subnet4']) || isset($member_uid['subnet6'])) )
                            {
                                $missing_network_members[] = $member_uid;

                                $member_name = $member_uid['name'];
                                $member_name = $this->truncate_names($this->normalizeNames($member_name));
                                $group_missing_members[$name][$member_name] = $member_name;
                                $group_missing_members[$name]['domain'] = $domain;
                                print "     - missing object: " . $member_name . " try to fix it later\n";
                            }

                        }
                    }
                }
                else
                {
                    mwarning("check addressgroup as already available: " . $tmp_addressgroup->name(), null, FALSE);
                    print_r($host);
                }

                //add missing

                if( count($missing_host_members ) > 0 )
                    $this->add_host_objects($missing_host_members);

                if( count($missing_network_members ) > 0 )
                    $this->add_network_objects($missing_network_members);

            }
        }
        else
            mwarning("no group found", null, FALSE);

        //group-with-exclusion"
        if( isset($this->objectArray['group-with-exclusion']) )
        {
            foreach( $this->objectArray['group-with-exclusion'] as $host )
            {
                $missing_host_members = array();
                $missing_network_members = array();

                #print_r( $host );

                $domain = $host['domain']['name'];
                $this->check_vsys( $domain );

                $name = $host['name'];
                $name = $this->truncate_names($this->normalizeNames($name));
                $description = $host['comments'];

                print "\n - addressgroup name: " . $host['name'] . "\n";


                $tmp_addressgroup = $this->sub->addressStore->find($name);
                if( $tmp_addressgroup === null )
                {
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($name);
                    $tmp_addressgroup->setDescription($description);

                    /*
                    if( $name == "All_Markets_Net" )
                    {
                        print_r( $host['except'] );
                        print_r( $host['include'] );
                        exit();
                    }
                    */

                    //except
                    //include


                    foreach( $host['include']['members'] as $member_uid )
                    {
                        if( !is_array($member_uid) )
                        {
                            $member_name = $this->find_address_uid($member_uid);
                            $member_name = $this->truncate_names($this->normalizeNames($member_name));
                            if( $member_name != null )
                            {
                                $tmp_address = $this->sub->addressStore->find($member_name);
                                if( $tmp_address != null )
                                {
                                    print "    - add member: " . $member_name . "\n";
                                    $tmp_addressgroup->addMember($tmp_address);
                                }
                                else
                                {
                                    $group_missing_members[$name][$member_name] = $member_name;
                                    $group_missing_members[$name]['domain'] = $domain;
                                    print "     - missing addressgroup: " . $member_name . " try to fix it later\n";
                                    #mwarning( "addressgroup: '".$name ."' | member: '".$member_name."' not found" );
                                }
                            }
                        }
                        else
                        {
                            //check if type=host
                            if( $member_uid['type'] == "host" && (isset($member_uid['ipv4-address']) || isset($member_uid['ipv4-address'])) )
                            {
                                $missing_host_members[] = $member_uid;

                                $member_name = $member_uid['name'];
                                $member_name = $this->truncate_names($this->normalizeNames($member_name));
                                $group_missing_members[$name][$member_name] = $member_name;
                                $group_missing_members[$name]['domain'] = $domain;
                                print "     - missing object: " . $member_name . " try to fix it later\n";
                            }
                            elseif( $member_uid['type'] == "network" && (isset($member_uid['subnet4']) || isset($member_uid['subnet6'])) )
                            {
                                $missing_network_members[] = $member_uid;

                                $member_name = $member_uid['name'];
                                $member_name = $this->truncate_names($this->normalizeNames($member_name));
                                $group_missing_members[$name][$member_name] = $member_name;
                                $group_missing_members[$name]['domain'] = $domain;
                                print "     - missing object: " . $member_name . " try to fix it later\n";
                            }

                        }
                    }

                    if( isset( $host['except']['name'] ))
                    {
                        $description .= "| exclude missing: ".$host['except']['name'];
                        $tmp_addressgroup->setDescription($description);
                    }


                }
                else
                {
                    mwarning("check addressgroup as already available: " . $tmp_addressgroup->name(), null, FALSE);
                    print_r($host);
                }

                //add missing

                if( count($missing_host_members ) > 0 )
                    $this->add_host_objects($missing_host_members);

                if( count($missing_network_members ) > 0 )
                    $this->add_network_objects($missing_network_members);

            }
        }
        else
            mwarning("no group found", null, FALSE);

        //fix address group - especially needed if addressgroup is used in addressgroup but the group is not yet created
        foreach( $group_missing_members as $groupname => $group )
        {

            $domain = $group['domain'];
            unset($group['domain']);
            $this->check_vsys($domain);

            $tmp_addressgroup = $this->sub->addressStore->find($groupname);

            print "\n - fix for addressgroup: " . $groupname . "\n";

            foreach( $group as $membername => $member )
            {
                $tmp_address = $this->sub->addressStore->find($member);
                if( $tmp_address != null )
                {
                    print "    - add member: " . $member . "\n";
                    $tmp_addressgroup->addMember($tmp_address);
                }
                else
                    mwarning("addressgroup: '" . $groupname . "' | member: '" . $member . "' not found");
            }
        }


        //service group implementation
        $group_missing_members = array();
        if( isset($this->objectArray['service-group']) )
        {
            foreach( $this->objectArray['service-group'] as $host )
            {
                #print_r( $host );
                $domain = $host['domain']['name'];
                $this->check_vsys( $domain );

                $name = $host['name'];
                $description = $host['comments'];

                //Todo: problem that this can not be migrated to MainAddServiceGroup; reason => uid
                print "\n - servicegroup name: " . $host['name'] . "\n";


                $tmp_servicegroup = $this->sub->serviceStore->find($name);
                if( $tmp_servicegroup === null )
                {

                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($name);
                    #$tmp_servicegroup->setDescription( $description );


                    foreach( $host['members'] as $member_uid )
                    {
                        $member_name = $this->find_service_uid($member_uid);

                        if( $member_name != "" )
                        {
                            $tmp_service = $this->sub->serviceStore->find($member_name);
                            if( $tmp_service != null )
                            {
                                print "    - add member: " . $member_name . "\n";
                                $tmp_servicegroup->addMember($tmp_service);
                            }
                            else
                            {
                                $group_missing_members[$name][$member_name] = $member_name;
                                $group_missing_members[$name]['domain'] = $domain;
                                print "     - missing servicegroup: " . $member_name . " try to fix it later\n";
                                #mwarning( "servicegroup: '".$name ."' | member: '".$member_name."' not found" );
                            }
                        }
                    }
                }
                else
                {
                    mwarning("check servicegroup as already available: " . $tmp_servicegroup->name(), null, FALSE);
                    print_r($host);
                }
            }
        }
        else
            mwarning("no service-group found", null, FALSE);

        //fix service group - especially needed if servicegroup is used in servicegroup but the group is not yet created
        foreach( $group_missing_members as $groupname => $group )
        {
            #print_r( $group );
            $domain = $group['domain'];
            unset($group['domain']);
            $this->check_vsys($domain);

            $tmp_servicegroup = $this->sub->serviceStore->find($groupname);

            print "\n - fix for servicegroup: " . $groupname . "\n";

            foreach( $group as $membername => $member )
            {
                $tmp_service = $this->sub->serviceStore->find($member);
                if( $tmp_service != null )
                {
                    print "    - add member: " . $member . "\n";
                    $tmp_servicegroup->addMember($tmp_service);
                }
                else
                    mwarning("servicegroup: '" . $groupname . "' | member: '" . $member . "' not found");
            }
        }
    }

    public function find_address_uid($member_uid)
    {
        $member_name = null;

        if( is_array($member_uid) )
        {
            #mwarning( "uid is array" );
            #print_r( $member_uid );
            $member_uid = $member_uid['uid'];
        }


        if( isset($this->objectArray['host'][$member_uid]) )
        {
            $member_name = $this->objectArray['host'][$member_uid]['name'];
            #print "  1-".$member_name."\n";
        }
        elseif( isset($this->objectArray['network'][$member_uid]) )
        {
            $member_name = $this->objectArray['network'][$member_uid]['name'];
            #print "  2-".$member_name."\n";
        }
        elseif( isset($this->objectArray['address-range'][$member_uid]) )
        {
            $member_name = $this->objectArray['address-range'][$member_uid]['name'];
            #print "  3-".$member_name."\n";
        }
        elseif( isset($this->objectArray['dns-domain'][$member_uid]) )
        {
            $member_name = $this->objectArray['dns-domain'][$member_uid]['name'];
            $name = $this->truncate_names($this->normalizeNames($member_name));
            if( preg_match("/^./", $name) )
                $name = ltrim($name, '.');
            $member_name = $name;
            #print "  1-".$member_name."\n";
        }
        elseif( isset($this->objectArray['checkpoint-host'][$member_uid]) )
        {
            $member_name = $this->objectArray['checkpoint-host'][$member_uid]['name'];
            #print "  1-".$member_name."\n";
        }

        elseif( isset($this->objectArray['CpmiClusterMember'][$member_uid]) )
        {
            $member_name = $this->objectArray['CpmiClusterMember'][$member_uid]['name'];
            #print "  1-".$member_name."\n";
        }
        elseif( isset($this->objectArray['simple-cluster'][$member_uid]) )
        {
            $member_name = $this->objectArray['simple-cluster'][$member_uid]['name'];
            #print "  1-".$member_name."\n";
        }
        elseif( isset($this->objectArray['group-with-exclusion'][$member_uid]) )
        {
            $member_name = $this->objectArray['group-with-exclusion'][$member_uid]['name'];
            #print "  1-".$member_name."\n";
        }
        elseif( isset($this->objectArray['group'][$member_uid]) )
        {
            $member_name = $this->objectArray['group'][$member_uid]['name'];
            #print "  4-".$member_name."\n";
        }
        elseif( isset($this->objectArray['simple-gateway'][$member_uid]) )
        {
            $member_name = $this->objectArray['simple-gateway'][$member_uid]['name'];
            #print "  4-".$member_name."\n";
        }
        elseif( isset($this->objectArray['CpmiHostCkp'][$member_uid]) )
        {
            $member_name = $this->objectArray['CpmiHostCkp'][$member_uid]['name'];
            #print "  4-".$member_name."\n";
        }
        //
        else
        {
            //missing objectArray['CpmiClusterMember']

//CpmiAnyObject
            if( isset($this->objectArray['CpmiAnyObject'][$member_uid]) )
            {
                #print "    - ANY\n";
            }
            else
            {
                print "     X not found: " . $member_uid . " check where it is defined\n";
                mwarning("not found: " . $member_uid . "\n", null, FALSE);
            }


        }

        return $member_name;
    }

    public function find_service_uid($member_uid)
    {
        $member_name = null;

        if( is_array($member_uid) )
            $member_uid = $member_uid['uid'];


        if( isset($this->objectArray['service-tcp'][$member_uid]) )
            $member_name = $this->objectArray['service-tcp'][$member_uid]['name'];

        elseif( isset($this->objectArray['service-udp'][$member_uid]) )
            $member_name = $this->objectArray['service-udp'][$member_uid]['name'];

        elseif( isset($this->objectArray['service-icmp'][$member_uid]) )
            $member_name = "tmp-" . $this->objectArray['service-icmp'][$member_uid]['name'];

        elseif( isset($this->objectArray['service-other'][$member_uid]) )
            $member_name = "tmp-" . $this->objectArray['service-other'][$member_uid]['name'];

        elseif( isset($this->objectArray['service-group'][$member_uid]) )
            $member_name = $this->objectArray['service-group'][$member_uid]['name'];


        else
        {
            #print "     X not found: ".$member_uid." check if ANY\n";
            #mwarning( "not found: ".$member_uid."\n" );
        }


        return $member_name;
    }

    public function add_host_objects($subarray)
    {
        foreach( $subarray as $host_key => $host )
        {
            if( $host['type'] != 'host' && $host['type'] != 'checkpoint-host' && $host['type'] !=  "simple-cluster" && $host['type'] != "CpmiClusterMember" )
            {
                print_r($host);
                mwarning("no type host");
                continue;
            }

            $domain = $host['domain']['name'];
            $this->check_vsys( $domain );

            #print_r( $host );
            #print "name: ".$host['name']. " - ip-address: ".$host['ipv4-address']." comments: ".$host['comments']."\n";

            //now create host object

            $name = $host['name'];
            $name = $this->truncate_names($this->normalizeNames($name));

            if( isset($host['ipv4-address']) )
                $value = $host['ipv4-address'];
            elseif( isset($host['ipv6-address']) )
                $value = $host['ipv6-address'];

            $type = "ip-netmask";

            $description = $host['comments'];

            #$host['domain']['domain-type']
            #$host['domain']['name']
            #print_r( $host['tags'] );

            $tmp_address = $this->MainAddHost( $name, $value, $type, $description );


            if( isset($host['nat-settings']) && is_array($host['nat-settings']) && isset($host['nat-settings']['ipv4-address']) )
            {
                $type = "ip-netmask";
                $valuenat = $host['nat-settings']['ipv4-address'];

                $name = $name . "-hidenat";

                $this->MainAddHost( $name, $valuenat, $type );

                /*
                $tmp_address = $this->sub->addressStore->find($name . "-hidenat");
                if( $tmp_address == null )
                {
                    print "- create address network: " . $name . "-hidenat" . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name . "-hidenat", $type, $valuenat);
                }
                else
                {
                    mwarning("address network: " . $name . " already available\n");
                }
                */
            }

            /*
            $tmp_address = $this->sub->addressStore->find($name);
            if( $tmp_address == null )
            {
                print "- create address host: " . $name . "\n";
                $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
            }
            else
            {
                mwarning("address host: " . $name . " already available\n");
            }

            $tmp_address->setDescription($description);
            */

            if( isset($host['groups']) )
            {
                foreach( $host['groups'] as $group )
                {
                    $this->objectArray['group'][] = $group;
                }

                //Todo: SVEN create group
                #print_r( $host['groups'] );
                #mwarning( "missing info" );
            }


            //Todo: validate if this is the correct implementation
            if( $host['type'] == 'host' && isset($host['interfaces']) )
            {
                if( count( $host['interfaces'] ) > 0 )
                {
                    $tmp_addrgroup_name = $tmp_address->name();

                    print "change address name:" . $tmp_address->name() . "\n";
                    $tmp_address->setName($tmp_address->name() . "-typ_host");
                    print "new address name:" . $tmp_address->name() . "\n";



                    print " * create addressgroup: " . $tmp_addrgroup_name . "\n";

                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($tmp_addrgroup_name);

                    $tmp_addressgroup->addMember($tmp_address);

                    foreach( $host['interfaces'] as $host )
                    {
                        $name = $host['name']."-int";
                        $IPvalue = $host['subnet4']."/".$host['mask-length4'];
                        $tmp_address = $this->MainAddHost($name, $IPvalue, 'ip-netmask');

                        $tmp_addressgroup->addMember($tmp_address);
                    }
                }
            }
        }
    }

    public function add_fqdn_objects($subarray)
    {
        foreach( $subarray as $host_key => $fqdn )
        {
            if( $fqdn['type'] != 'dns-domain' )
            {
                print_r($fqdn);
                mwarning("no type $fqdn");
                continue;
            }

            $domain = $fqdn['domain']['name'];
            $this->check_vsys( $domain );

            print_r( $fqdn );
            #print "name: ".$host['name']. " - ip-address: ".$host['ipv4-address']." comments: ".$host['comments']."\n";

            //now create host object

            $name = $fqdn['name'];
            $name = $this->truncate_names($this->normalizeNames($name));
            if( preg_match("/^./", $name) )
                $name = ltrim($name, '.');

            $description = $fqdn['comments'];

            $this->MainAddHost( $name, $name, "fqdn", $description );

            /*
            $tmp_address = $this->sub->addressStore->find($name);
            if( $tmp_address == null )
            {
                print "- create address fqdn: " . $name . "\n";
                $tmp_address = $this->sub->addressStore->newAddress($name, $type, $name);
            }
            else
            {
                mwarning("address fqdn: " . $name . " already available\n");
            }

            $tmp_address->setDescription($description);
            */

        }
    }
    public function add_network_objects($subarray)
    {
        foreach( $subarray as $host_key => $host )
        {
            #print_r( $host );

            if( $host['type'] != 'network' )
            {
                print_r($host);
                mwarning("no type network");
                continue;
            }

            $domain = $host['domain']['name'];
            $this->check_vsys( $domain );
            #print_r($host);
            #print "name: ".$host['name']. " - ip-address: ".$host['subnet4']." mask: ".$host['mask-length4']." comments: ".$host['comments']."\n";

            $name = $host['name'];
            $name = $this->truncate_names($this->normalizeNames($name));
            if( isset($host['subnet4']) )
                $value = $host['subnet4'];
            elseif( isset($host['subnet6']) )
                $value = $host['subnet6'];

            if( isset($host['mask-length4']) )
                $mask = $host['mask-length4'];
            elseif( isset($host['mask-length6']) )
                $mask = $host['mask-length6'];


            if( isset($host['nat-settings']) && is_array($host['nat-settings']) && isset($host['nat-settings']['ipv4-address']) )
            {
                $type = "ip-netmask";
                $valuenat = $host['nat-settings']['ipv4-address'];

                $name = $name . "-hidenat";

                $this->MainAddHost( $name, $valuenat, $type );

                /*
                $tmp_address = $this->sub->addressStore->find($name . "-hidenat");
                if( $tmp_address == null )
                {
                    print "- create address network: " . $name . "-hidenat" . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name . "-hidenat", $type, $valuenat);
                }
                else
                {
                    mwarning("address network: " . $name . " already available\n");
                }
                */
            }

            $type = "ip-netmask";
            $description = $host['comments'];

            $value = $value . "/" . $mask;

            $this->MainAddHost( $name, $value, $type, $description );

            /*
            $tmp_address = $this->sub->addressStore->find($name);
            if( $tmp_address == null )
            {
                print "- create address network: " . $name . "\n";
                $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
            }
            else
            {
                mwarning("address network: " . $name . " already available\n");
            }

            $tmp_address->setDescription($description);
            */

            if( isset($host['groups']) )
            {
                foreach( $host['groups'] as $group )
                {
                    $this->objectArray['group'][] = $group;
                }

                //Todo: SVEN create group
                #print_r( $host['groups'] );
                #mwarning( "missing info" );
            }
        }
    }
}