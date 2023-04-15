<?php


trait CPnew_object
{
    public function addHost($tmp_array)
    {
        $addconfig = TRUE;

        #print_r( array_keys( $end_array[0] ) );
        //todo: print out
        #print_r( $end_array[0] );

        $net_obj_array = array(
            #'dynamic_net_obj',
            #'machines_range',
            #'security_zone_obj',
            'network',
            'host',
            #'gateway', //todo: implement
            'group',
            #'hostname',
            #'cluster_member', //todo: implement
            #'gateway_cluster ' // Todo: implementation needed
        );

        //supported type on old CP migration:
        /*
        host
        network
        machines_range
        domain
        group
        security_zone_obj
        cluster_member
        dynamic_net_obj
        hostname
        group_with_exclusion
        gateway_cluster
        gateway_fw
        gateway
        gatways
        router
        community
        sofwar_gateway
        voip_gk
        voip_gw
         */

        $missingMembers = array();

        /*
        if ( ( $line =~ /^\t\:netobj \(netobj/ ) ||			# V4.1 style
		( $line =~ /^\t\:network_objects \(network_objects/ )||	# NG style
		($line =~/^\t:network_objects \(/)                     # R65 style Added 2008-02-12 by Jacob
         */
        /*
        $tmp_array = array();
        if( isset($end_array[0]['network_objects']) )
        {
            print "using network_objects\n";
            $tmp_array = $end_array[0]['network_objects'];
        }
        elseif( isset($end_array[0]['netobj']) )
        {
            print "using netobj\n";
            $tmp_array = $end_array[0]['netobj'];
        }
        else
        {
            derr("OBJECTS not found");
            //Todo: how to handle these things???
            /*
             * (netobj/ ) ||			# V4.1 style
             *
             * \(network_objects/ )||	# NG style
             */
        //}



        foreach( $tmp_array as $objKey => $netobj )
        {
            if( isset($netobj['type']) )
            {
                if( isset($type[$netobj['type']]) )
                    $type[$netobj['type']]++;
                else
                    $type[$netobj['type']] = 1;

                if( in_array($netobj['type'], $net_obj_array) )
                {
                    #print_r( $netobj );
                }


#########################################################
#########################################################
                /*
                [dynamic_net_obj] => 19
                [machines_range] => 5
                [security_zone_obj] => 3
                [network] => 571
                [host] => 504
                [gateway] => 67
                [group] => 59
                [hostname] => 1
                [cluster_member] => 51
                [gateway_cluster] => 25
                 */
                /*
                [network] => 27
                [dynamic_net_obj] => 6
                [machines_range] => 3
                [security_zone_obj] => 4
                [host] => 11
                [hostname] => 2
                [group] => 8
                [group_with_exclusion] => 1
                [gateway] => 1
                [cluster_member] => 2
                [gateway_cluster] => 1
                 */
#########################################################
#########################################################

                $description = "";
                $name = "";
                $IPvalue = "";
                if( isset($netobj['AdminInfo']['name']) )
                {
                    #print "NAME: " . $netobj['AdminInfo']['name'] . "\n";
                    $name = $netobj['AdminInfo']['name'];
                }
                elseif( isset($netobj[0][0]) )
                {
                    $name = $netobj[0][0];
                }
                else
                {
                    derr("NONAME:|" . $objKey . "|\n");
                }

                if( isset($netobj['comments']) )
                {
                    if( is_array($netobj['comments']) )
                    {
                        print_r($netobj['comments']);
                        derr("comments as array");
                    }
                    else
                    {
                        #print "COMMENT: " . $netobj['comments'] . "\n";
                        $description = $netobj['comments'];
                    }
                }
                else
                {
                    #print "NOCOMMENT\n";
                }

                if( $netobj['type'] == 'host'  )
                {
                    #print_r( $netobj );

                    if( isset($netobj['ipaddr']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr'];

                        if( $IPvalue != "" )
                        {
                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                        }
                    }
                    else
                    {
                        #print "NOIPADDR\n";
                    }

                    if( isset($netobj['ipaddr6']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr6'];
                        if( is_array($IPvalue) )
                        {
                            print_r($netobj);
                            derr("IPv6 value array");
                        }

                        if( $IPvalue != "" )
                        {
                            $tmp_address = $this->sub->addressStore->find($name);
                            if( $tmp_address != null )
                                $name = "IPv6".$name;
                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                        }
                    }
                    else
                    {
                        #print "NOIPADDR\n";
                    }
                }
                elseif( $netobj['type'] == 'network' )
                {
                    if( isset($netobj['ipaddr']) && isset($netobj['netmask']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr'];
                        $IPnetmask = cidr::netmask2cidr($netobj['netmask']);

                        if( $IPvalue != "" && $IPnetmask != "" )
                        {
                            $IPvalue = $IPvalue . "/" . $IPnetmask;

                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                        }
                    }
                    else
                    {
                        #print "NOIPADDR\n";
                    }

                    if( isset($netobj['ipaddr6']) && isset($netobj['netmask6']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr6'];
                        $IPnetmask = cidr::ipv6_netmask2cidr( $netobj['netmask6'] );
                        #$IPnetmask = $netobj['netmask6'];

                        if( $IPvalue != "" && $IPnetmask != "" )
                        {
                            $IPvalue = $IPvalue . "/" . $IPnetmask;

                            $tmp_address = $this->sub->addressStore->find($name);
                            if( $tmp_address != null )
                                $name = "IPv6".$name;

                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                        }
                    }
                    else
                    {
                        #print "NOIPADDR\n";
                    }
                }
                elseif( $netobj['type'] == 'group' )
                {
                    $members = array();

                    foreach( $netobj as $key => $member )
                    {
                        if( is_numeric($key) && $key != 0 )
                        {
                            $members[] = $member['Name'];
                        }
                    }

                    #print "NAME: ".$name."\n";
                    #print_r( $members );

                    $this->MainAddAddressGroup($name, $members, $description, $missingMembers);
                }
                elseif( $netobj['type'] == 'machines_range' )
                {
                    //Todo: implementatiion
                    /*
                     * [0] => Array
                        (
                        )

                    [AdminInfo] => Array
                        (
                            [chkpf_uid] => "{0247AA27-E632-4CA0-A21B-C93324E94ACA}"
                            [ClassName] => address_range
                            [table] => network_objects
                            [Wiznum] => -1
                            [LastModified] => Array
                                (
                                    [Time] => "Thu Mar  3 06:38:08 2016"
                                    [last_modified_utc] => 1456987088
                                    [By] => "Check Point Security Management Server Update Process"
                                    [From] => localhost
                                )

                            [icon] => "NetworkObjects/AddressRanges/AddressRange"
                            [name] => ltn-tsi-r-ihist-proficy-srv
                        )

                    [edges] =>
                    [NAT] =>
                    [add_adtr_rule] => false
                    [addr_type_indication] => IPv4
                    [color] => cyan
                    [comments] =>
                    [ipaddr_first] => 10.199.6.30
                    [ipaddr_first6] =>
                    [ipaddr_last] => 10.199.6.39
                    [ipaddr_last6] =>
                    [type] => machines_range
                     */

                    //Todo: more validation needed if both entries are valid IPv4
                    if( isset($netobj['ipaddr_first']) && isset($netobj['ipaddr_last']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr_first'] . "-" . $netobj['ipaddr_last'];

                        if( $IPvalue != "-" )
                        {
                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-range', $description);
                        }
                    }
                    else
                    {
                        #print "NOIPADDR\n";
                    }

                    //Todo: more validation for IPv6 needed
                    if( isset($netobj['ipaddr6_first']) && isset($netobj['ipaddr6_last']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr6_first'] . "-" . $netobj['ipaddr6_last'];

                        if( $IPvalue != "-" )
                        {
                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                        }
                    }
                    else
                    {
                        #print "NOIPADDR\n";
                    }
                }
                elseif( $netobj['type'] == 'dynamic_net_obj' )
                {
                    //Todo: is implementation needed?????
                    //not implemented in R77
                }
                elseif( $netobj['type'] == 'security_zone_obj' )
                {
                    //Todo: is implementation needed?????
                    //not implemented in R77
                }
                elseif( $netobj['type'] == 'gateway' )
                {
                    if( isset($netobj['ipaddr']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr'];

                        if( $IPvalue != "" )
                        {
                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                        }
                    }

                    if( isset($netobj['ipaddr6']) )
                    {
                        #print "IPv4: " . $netobj['ipaddr'] . "\n";
                        $IPvalue = $netobj['ipaddr6'];
                        if( is_array($IPvalue) )
                        {
                            print_r($netobj);
                            derr("IPv6 value array");
                        }

                        if( $IPvalue != "" )
                        {
                            $tmp_address = $this->sub->addressStore->find($name);
                            if( $tmp_address != null )
                                $name = "IPv6".$name;
                            if( $addconfig )
                                $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                        }
                    }
                }
                elseif(  $netobj['type'] == 'cluster_member' )
                {
                    print_r( $netobj );
                    #derr( "STOP" );
                }
                elseif( $netobj['type'] == 'gateway_cluster' )
                {
                    if( isset($netobj['interfaces']) )
                    {
                        //what to do here?
                        print_r( $netobj['interfaces'] );
                        print "WHAT happend here?\n";
                        foreach( $netobj['interfaces'] as $interface )
                        {

                            if( isset( $interface['ipaddr'] ) && $interface['ipaddr'] != "" )
                            {
                                $tmp_name = $interface['ipaddr'];

                                $ipversion2 = $this->ip_version($tmp_name);
                                if( $ipversion2 == "v4" )
                                    $hostCidr2 = "32";
                                elseif( $ipversion2 == "v6" )
                                    $hostCidr2 = "128";
                                else
                                    $hostCidr2 = "32";

                                $IPvalue = $tmp_name . "/" . $hostCidr2;

                                $tmp_name = $this->truncate_names($this->normalizeNames($tmp_name));

                                $this->MainAddHost($tmp_name, $IPvalue, 'ip-netmask');

                                $addToGroup[] = $tmp_name;
                            }

                            if( isset( $interface['ipaddr6'] ) && $interface['ipaddr6'] != "" )
                            {
                                $tmp_name = $interface['ipaddr6'];

                                $ipversion2 = $this->ip_version($tmp_name);
                                if( $ipversion2 == "v4" )
                                    $hostCidr2 = "32";
                                elseif( $ipversion2 == "v6" )
                                    $hostCidr2 = "128";
                                else
                                    $hostCidr2 = "32";

                                $IPvalue = $tmp_name . "/" . $hostCidr2;

                                $tmp_name = $this->truncate_names($this->normalizeNames($tmp_name));

                                $this->MainAddHost($tmp_name, $IPvalue, 'ip-netmask');

                                $addToGroup[] = $tmp_name;
                            }

                        }
                        $this->MainAddAddressGroup($name, $addToGroup, $description);
                    }
                    else
                    {
                        if( isset($netobj['ipaddr']) )
                        {
                            #print "IPv4: " . $netobj['ipaddr'] . "\n";
                            $IPvalue = $netobj['ipaddr'];

                            if( $IPvalue != "" )
                            {
                                if( $addconfig )
                                    $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                            }
                        }
                        else
                        {
                            #print "NOIPADDR\n";
                        }

                        if( isset($netobj['ipaddr6']) )
                        {
                            #print "IPv4: " . $netobj['ipaddr'] . "\n";
                            $IPvalue = $netobj['ipaddr6'];
                            if( is_array($IPvalue) )
                            {
                                print_r($netobj);
                                derr("IPv6 value array");
                            }

                            if( $IPvalue != "" )
                            {
                                if( $addconfig )
                                    $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                            }
                        }
                        else
                        {
                            #print "NOIPADDR\n";
                        }
                    }

                    if( isset($netobj['single_VPN_IP']) && $netobj['single_VPN_IP'] != "" )
                    {
                        $name .= '_single_VPN_IP';
                        $IPvalue = $netobj['single_VPN_IP'];
                        $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                    }

                }
                elseif( $netobj['type'] == 'hostname' )
                {
                }
                else
                {
                    print_r($netobj);
                    print "TYPE:" . $netobj['type'] . "\n";
                }
            }
        }

        $tmp_array = array();


        print "MISSING ADRESSGROUP members:\n";

        foreach( $missingMembers as $keyfix => $fixgroup )
        {
            $name = $keyfix;
            $members = $fixgroup;


            print "\nFIX addressgroup: " . $name . "\n";
            $this->MainAddAddressGroup($name, $members, "");
        }
        #print_r( $missingMembers );


        print_r($type);

    }
}