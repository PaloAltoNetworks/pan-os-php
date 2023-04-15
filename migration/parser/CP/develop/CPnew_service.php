<?php


trait CPnew_service
{
    public function addService($tmp_array)
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
            #'gateway',
            'group',
            #'hostname',
            #'cluster_member',
            #'gateway_cluster '
        );

        $missingMembers = array();

        /*
        $tmp_array = array();
        if( isset($end_array[0]['services']) )
        {
            $tmp_array = $end_array[0]['services'];
        }
        elseif( isset($end_array[0]['xyzi']) )
        {
            #$tmp_array = $end_array[0]['netobj'];
        }
        else
        {
            print_r(array_keys($end_array[0]));

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

                if( $netobj['type'] == 'Tcp'
                    || $netobj['type'] == 'tcp'
                    || $netobj['type'] == 'TCP'
                    || $netobj['type'] == 'tcp_citrix'
                    || $netobj['type'] == 'Tcp_subservice'

                    || $netobj['type'] == 'Udp'
                    || $netobj['type'] == 'udp'
                )
                {
                    #print_r( $netobj );

                    if( isset($netobj['port']) )
                    {
                        if( $netobj['type'] == 'Udp'
                            || $netobj['type'] == 'udp'
                        )
                            $protocol = "udp";
                        else
                            $protocol = "tcp";

                        $dport = $netobj['port'];

                        if( strpos( $dport, ">" ) != false )
                        {
                            $tmp_dport = str_replace( ">", "", $dport );
                            $dport = intval($tmp_dport) + 1;
                            $dport .="-65535";
                        }
                        elseif( strpos( $dport, "<" ) != false )
                        {
                            $tmp_dport = str_replace( "<", "", $dport );
                            $dport = intval($tmp_dport) - 1;
                            $dport = "0-".$dport;
                        }

                        $this->MainAddService($name, $protocol, $dport, $description);
                    }


                }
                elseif( $netobj['type'] == 'Other'
                    || $netobj['type'] == 'other' )
                {
                    #print_r( $netobj );

                    /*
                    [0] => Array
                        (
                            [0] => high_udp_for_secure_SCCP
                        )

                    [AdminInfo] => Array
                        (
                            [chkpf_uid] => "{7DD1933B-94E8-4770-9D45-F52B77FAAFB4}"
                            [ClassName] => other_service
                            [table] => services
                            [icon] => "Services/Other"
                            [LastModified] => Array
                                (
                                    [Time] => "Thu Mar  3 06:38:31 2016"
                                    [last_modified_utc] => 1456987111
                                    [By] => "Check Point Security Management Server Update Process"
                                    [From] => localhost
                                )

                        )

                    [unsupported_compatibility_packages] =>
                    [aggressive_aging_timeout] => 0
                    [color] => black
                    [comments] =>
                    [default_aggressive_aging_timeout] => 0
                    [enable_aggressive_aging] => true
                    [etm_enabled] => false
                    [exp] => high_udp_for_secure_phones
                    [include_in_any] => false
                    [is_default_aggressive_timeout] => true
                    [needruleinfo] => false
                    [prohibit_aggressive_aging] => false
                    [proto_type] =>
                    [protocol] => 17
                    [reload_proof] => false
                    [replies] => true
                    [sync_on_cluster] => true
                    [timeout] => 0
                    [type] => other
                    [updated_by_sd] => false
                    [weight] => 0
                     */

                    if( isset($netobj['protocol']) )
                    {
                        $protocol = $netobj['protocol'];

                        switch ($protocol)
                        {
                            case 17:
                                $protocol = "udp";
                                break;
                            case 0:
                                echo "i ist gleich 0";
                                break;
                        }
                        #$description .= "-prot:" . $protocol;

                        $protocol = "tcp";
                    }

                    else
                        $protocol = "tcp";

                    $dport = "65000";
                    #$description .= "-type:" . $netobj['type'];


                    $this->MainAddService("tmp-" . $name, $protocol, $dport, $description);
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
                    $findTMP = TRUE;
                    $this->MainAddServiceGroup($name, $members, $description, $missingMembers, $findTMP);
                }
                elseif( $netobj['type'] == 'Icmp'
                    || $netobj['type'] == 'icmp'
                    || $netobj['type'] == 'icmpv6'

                    || $netobj['type'] == 'Rpc'
                    || $netobj['type'] == 'dcerpc'
                    || $netobj['type'] == 'DceRpc'

                    || $netobj['type'] == 'gtp'
                    || $netobj['type'] == 'gtp_v1'
                    || $netobj['type'] == 'gtp_mm_v0'
                    || $netobj['type'] == 'gtp_mm_v1'
                    || $netobj['type'] == 'gtp_mm_v2'
                    || $netobj['type'] == 'gtp_v2'
                    || $netobj['type'] == 'gtp_additional_v2'
                )
                {
                    print_r($netobj);

                    $protocol = "tcp";
                    $dport = "65000";
                    #$description .= "-type:" . $netobj['type'];

                    $this->MainAddService("tmp-" . $name, $protocol, $dport, $description);
                }
                else
                {
                    print_r($netobj);
                    print "TYPE:" . $netobj['type'] . "\n";
                }
            }
        }

        $tmp_array = array();

        #print_r( $missingMembers );

        print "MISSING SERVICEGROUP members:\n";

        foreach( $missingMembers as $keyfix => $fixgroup )
        {
            $name = $keyfix;
            $members = $fixgroup;

            print "\n\nFIX servicegroup: " . $name . "\n";
            $findTMP = FALSE;

            $missingMembers2 = array();
            $tmp_addressgroup = $this->MainAddServiceGroup($name, $members, null, $missingMembers2, $findTMP);

            #print_r( $missingMembers2 );
        }


        print_r($type);

    }
}