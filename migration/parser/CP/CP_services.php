<?php



trait CP_services
{
    public function add_services($KEYS, $array)
    {

        //Todo: missing parts: 20200605 swaschkut
        /*
          - type:
        - icmp
        - icmpv6
        - other
        - gtp
         */

        #print "|" . $KEYS . "|" . count($array) . "\n";

        #print_r(array_keys($array));
        #print_r( $array );

        foreach( $array as $object )
        {


            if( isset($object['type']) )
            {
                if( $object['type'] == 'tcp' ||
                    $object['type'] == 'udp' ||
                    preg_match("/^tcp_/", $object['type'])
                )
                {
                    $name = $object['name'];
                    $protocol = $object['type'];

                    if( preg_match("/^tcp_/", $object['type']) )
                        $protocol = 'tcp';

                    if( !isset($object['destinationport']) )
                    {
                        print_r($object);
                        mwarning("no destinationport defined; skip object");
                        continue;
                    }

                    $dport = $object['destinationport'];

                    if( !is_numeric($dport) )
                    {
                        if( preg_match("/:/", $dport) )
                            $dport = str_replace(":", "-", $dport);
                        elseif( preg_match("/>/", $dport) )
                        {
                            $dport = str_replace(">", "", $dport);
                            $dport = (intval($dport) + 1) . "-65535";
                        }
                        elseif( preg_match("/</", $dport) )
                        {
                            $dport = str_replace("<", "", $dport);
                            $dport = "1-" . (intval($dport) - 1);
                        }
                        elseif( preg_match("/-/", $dport) )
                        {

                        }
                        else
                            mwarning("check dport: " . $dport);
                    }


                    $description = '';
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    $sport = null;
                    //[sourceport] => 989
                    if( isset($object['sourceport']) )
                    {
                        $sport = $object['sourceport'];

                        if( !is_numeric($sport) )
                        {
                            if( preg_match("/:/", $sport) )
                                $sport = str_replace(":", "-", $sport);
                            elseif( preg_match("/>/", $sport) )
                            {
                                $sport = str_replace(">", "", $sport);
                                $sport = (intval($sport) + 1) . "-65535";
                            }
                            elseif( preg_match("/</", $sport) )
                            {
                                $sport = str_replace("<", "", $sport);
                                $sport = "1-" . (intval($sport) - 1);
                            }
                            elseif( preg_match("/-/", $sport) )
                            {

                            }
                            else
                                mwarning("check dport: " . $sport);
                        }
                    }


                    if( isset($object['layer7filter']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? app-id migration?
                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    $this->MainAddService($name, $protocol, $dport, $description, $sport);


                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "comment" &&
                            $key1 != "destinationport" &&
                            $key1 != "layer7filter" &&
                            $key1 != "shared" &&
                            $key1 != "sourceport"
                        )
                        {
                            print "KEY: " . $key1 . " not yet checked\n";
                            print_r($object);
                        }

                    }

                    /*
                     * [name] => DCERPC
                        [type] => tcp
                        [destinationport] => 135
                        [comment] => Microsoft-RPC (DCERPC/MS-RPC), used e.g. for MS-Exchange


                    [name] => ypupdated
                    [type] => tcp
                    [destinationport] => 111
                    [layer7filter] => SunRPC_ypupdated
                    [comment] => Sun Yellow Pages protocol (NIS), update service
                     */

                }
                elseif( $object['type'] == 'other' )
                {
                    $name = $object['name'];
                    $type = $object['type'];
                    print "NAME: " . $name . " TYPE: " . $type . "\n";
                    print_r($object);


                    $name = "tmp-" . $name;
                    $protocol = "tcp";
                    $dport = "65000";

                    $description = '';
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    $this->MainAddService($name, $protocol, $dport, $description, null);

                    /*
                     * [name] => ZSP
                        [type] => other
                        [comment] => Zone Security Protocol
                     */
                }
                elseif( $object['type'] == 'icmp' )
                {
                    $name = $object['name'];
                    $type = $object['type'];
                    print "NAME: " . $name . " TYPE: " . $type . "\n";
                    print_r($object);


                    $name = "tmp-" . $name;
                    $protocol = "tcp";
                    $dport = "65000";

                    $description = '';
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    $this->MainAddService($name, $protocol, $dport, $description, null);

                    //Todo: 20200605 swaschkut - create tmp service - which need to be migrated to APP-Id
                    /*
                    [name] => timestamp-reply
                    [type] => icmp
                    [comment] => ICMP, timestamp reply
                    */
                }
                elseif( $object['type'] == 'icmpv6' )
                {
                    $name = $object['name'];
                    $type = $object['type'];
                    print "NAME: " . $name . " TYPE: " . $type . "\n";
                    print_r($object);


                    $name = "tmp-" . $name;
                    $protocol = "tcp";
                    $dport = "65000";

                    $description = '';
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    $this->MainAddService($name, $protocol, $dport, $description, null);

                    //Todo: 20200605 swaschkut - create tmp service - which need to be migrated to APP-Id
                    /*
                     * [name] => time-exceeded6
                        [type] => icmpv6
                     */
                }
                elseif( preg_match("/^gtp/", $object['type']) )
                {
                    $name = $object['name'];
                    $type = $object['type'];
                    print "NAME: " . $name . " TYPE: " . $type . "\n";
                    print_r($object);


                    $name = "tmp-" . $name;
                    $protocol = "tcp";
                    $dport = "65000";

                    $description = '';
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    $this->MainAddService($name, $protocol, $dport, $description, null);

                    //Todo: 20200605 swaschkut - create tmp service - which need to be migrated to APP-Id
                    /*
                     * [name] => gtp_v0_default
                    [type] => gtp
                    [destinationport] => 3386
                    [comment] => GPRS Tunneling Protocol version 0
                     */


                    /*
                     * [name] => gtp_v1_default
                    [type] => gtp_v1
                    [comment] => GPRS Tunneling Protocol version 1
                     */
                }
                elseif( $object['type'] == 'group' )
                {
                    //do nothing, check next foreach loop
                }
                else
                {
                    print_r($object);
                    mwarning("TYPE: |" . $object['type'] . "| not supported yet\n");

                }
            }
            else
            {
                print "skipped: no TYPE\n";
                print_r($object);
            }
        }

        $missingServiceGroupMembers = array();
        //add groups in a different steps, so that all other address objects are defined already
        foreach( $array as $object )
        {
            if( isset($object['type']) )
            {
                if( $object['type'] == 'group' )
                {
                    /*
                     * [name] => Yahoo_Messenger
                        [type] => group
                        [groupmembers] => Array
                            (
                                [0] => Yahoo_Messenger_messages
                                [1] => Yahoo_Messenger_Voice_Chat_TCP
                                [2] => Yahoo_Messenger_Voice_Chat_UDP
                                [3] => Yahoo_Messenger_Webcams
                            )

                        [comment] => Yahoo Messenger
                     */
                    $name = $object['name'];

                    if( isset($object['groupmembers']) )
                        $members = $object['groupmembers'];
                    else
                        $members = array();

                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {

                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    $findTMP = TRUE;
                    $this->MainAddServiceGroup($name, $members, $description, $missingServiceGroupMembers, $findTMP);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "groupmembers" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "shared"
                        )
                        {
                            print_r($object);
                            mwarning("KEY: " . $key1 . " not yet checked\n");
                        }
                    }
                }
            }
        }

        print PH::boldText("\nadd missing servicegroup members\n");

        foreach( $missingServiceGroupMembers as $servicegroup_name => $members )
        {

            $findTMP = FALSE;
            print "\n\n";
            $tmp_addressgroup = $this->MainAddServiceGroup($servicegroup_name, $members, null, $findTMP);
        }
    }
}

