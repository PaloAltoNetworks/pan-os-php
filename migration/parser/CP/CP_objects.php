<?php



trait CP_objects
{
    public function add_host_objects($KEYS, $array)
    {
        foreach( $array as $object )
        {
            $IPvalue = null;
            $members = array();

            if( isset($object['type']) )
            {
                if( $object['type'] == 'host' )
                {
                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));
                    if( isset( $object['ipaddr'] ) )
                        $IPvalue = $object['ipaddr'];
                    elseif( isset( $object['ipaddr6'] ) )
                        $IPvalue = $object['ipaddr6'];

                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['interfaces']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "ipaddr" &&
                            $key1 != "ipaddr6" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "interfaces" &&
                            $key1 != "shared"
                        )
                        {
                            mwarning("KEY: " . $key1 . " not yet checked\n");
                            print_r($object);
                        }

                    }
                }
                elseif( $object['type'] == 'network' )
                {
                    print_r( $object );

                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));
                    if( isset( $object['ipaddr'] ) )
                    {
                        $IPvalue = $object['ipaddr'];
                        if( isset( $object['netmask'] ) && !$object['netmask'] == "" )
                        {
                            #$IPvalue .= "\\".$object['netmask'];

                            $tmp_cidr = CIDR::netmask2cidr( $object['netmask'] );
                            $IPvalue .= "/".$tmp_cidr;
                        }

                    }

                    elseif( isset( $object['ipaddr6'] ) )
                    {
                        $IPvalue = $object['ipaddr6'];
                        if( isset( $object['netmask6'] ) && $object['netmask6'] != ""  )
                        {
                            $tmp_cidr = CIDR::netmask2cidr( $object['netmask6'] );
                            $IPvalue .= "/".$tmp_cidr;

                        }

                    }


                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "ipaddr" &&
                            $key1 != "ipaddr6" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "shared" )
                        {
                            print_r($object);
                            mwarning("KEY: " . $key1 . " not yet checked\n");

                        }
                    }
                }
                elseif( $object['type'] == 'machines_range' )
                {
                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));
                    if( isset( $object['ipaddr'] ) )
                        $IPvalue = $object['ipaddr'];
                    elseif( isset( $object['ipaddr6'] ) )
                        $IPvalue = $object['ipaddr6'];
                    $IPvalue = str_replace(" ", "", $IPvalue);

                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    $this->MainAddHost($name, $IPvalue, 'ip-range', $description);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "ipaddr" &&
                            $key1 != "ipaddr6" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "shared" )
                        {
                            print_r($object);
                            mwarning("KEY: " . $key1 . " not yet checked\n");
                        }
                    }
                }
                elseif( $object['type'] == 'domain' )
                {
                    $name = $object['name'];
                    $tmp_name = $name;
                    if( preg_match("/^./", $tmp_name) )
                    {
                        //Todo swaschkut 20201110 - not correctly translated, PAN-OS do not cover wildcard in FQDN objects
                        #$IPvalue = "*" . $name;
                        $tmp_name = ltrim($name, '.');
                        $IPvalue = $tmp_name;
                    }
                    else
                    {
                        $IPvalue = $name;
                        $tmp_name = $name;
                    }





                    $name = $this->truncate_names($this->normalizeNames($tmp_name));



                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    $this->MainAddHost($name, $IPvalue, 'fqdn', $description);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "shared" )
                        {
                            print_r($object);
                            mwarning("KEY: " . $key1 . " not yet checked\n");
                        }

                    }
                }
                elseif( $object['type'] == 'group' )
                {
                    //this is done later please check next foreach loop
                    #print_r( $object );
                }
                elseif( $object['type'] == 'security_zone_obj' )
                {
                    print "TYPE: " . $object['type'] . "\n";
                    //must this zones be added?
                    print_r($object);
                    /*
                    [name] => WirelessZone
                    [type] => security_zone_obj
                    [on-interface] => Array
                        (
                            [0] => internal
                        )
                     */
                    //Expedition is doing nothing
                }
                elseif( $object['type'] == 'cluster_member' )
                {
                    print "TYPE: " . $object['type'] . "\n";
                    print_r($object);
                    /*
                     [name] => MFR_FW_2
                    [type] => cluster_member
                    [on-interface] => Array
                        (
                            [0] => internal
                        )

                    [ipaddr] => 10.149.10.245
                    [interfaces] => Array
                        (
                            [0] => 10.222.205.245/27
                            [1] => 10.222.221.245/27
                            [2] => 10.222.220.245/27
                            [3] => 10.222.242.245/27
                            [4] => 10.248.1.9/28
                            [5] => 10.248.14.245/24
                            [6] => 10.222.232.245/27
                            [7] => 10.128.141.245/27
                            [8] => 10.222.234.245/27
                            [9] => 10.247.128.137/28
                            [10] => 192.168.51.245/24
                            [11] => 10.248.20.245/24
                            [12] => 10.149.10.245/24
                            [13] => 172.29.66.245/25
                            [14] => 10.222.236.245/27
                            [15] => 10.222.241.245/27
                            [16] => 10.203.147.99/24
                            [17] => 172.30.70.245/24
                            [18] => 91.209.74.2/24
                            [19] => 10.222.237.245/27
                        )
                     */
                    //Expedition
                    //{$address[$ipversion][]="('ip-netmask','$type','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";}

                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));

                    if( isset( $object['ipaddr'] ) )
                        $IPvalue = $object['ipaddr'];
                    elseif( isset( $object['ipaddr6'] ) )
                        $IPvalue = $object['ipaddr6'];

                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    if( isset($object['interfaces']) )
                    {
                        //what to do here?
                        #$members = $object['interfaces'];
                    }

                    $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);
                    #$this->MainAddAddressGroup($name, $members, $description, $missingAddressGroupMembers);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "ipaddr" &&
                            $key1 != "ipaddr6" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "interfaces" &&
                            $key1 != "shared"
                        )
                        {
                            mwarning("KEY: " . $key1 . " not yet checked\n");
                            print_r($object);
                        }

                    }
                }
                elseif( $object['type'] == 'dynamic_net_obj' )
                {
                    print "TYPE: " . $object['type'] . "\n";
                    print_r($object);
                    /*
                     * [name] => LocalMachine_All_Interfaces
                    [type] => dynamic_net_obj
                    [on-interface] => Array
                        (
                            [0] => internal
                        )

                    [comment] => Check Point Local Machine (All Interfaces)
                     */
                    //Expedition
                    //$address[$ipversion][]="('ip-netmask','$type','$ip','$mask','$name','$name','1','1','$description','$source','$vsys')";}
                }
                elseif( $object['type'] == 'hostname' )
                {
                    print "TYPE: " . $object['type'] . "\n";
                    print_r($object);
                    /*
                    [name] => Trusted_Zone
                    [type] => hostname
                    [on-interface] => Array
                        (
                            [0] => internal
                        )

                    [comment] => Trusted Zone is resolved dynamically by client using Access Zones  Policy
                     */
                }
                elseif( $object['type'] == 'group_with_exclusion' )
                {
                    //will be checked later
                }
                elseif( $object['type'] == "gateway_cluster" )
                {
                    print "TYPE: " . $object['type'] . "\n";
                    print_r($object);

                    //check Expedition - longer code
                    /*
                     * if ($obj_interfaces==""){
                            $address[$ipversion][]="('ip-netmask','ip-netmask','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";
                        }
                        else{
                            #Convert to Group
                            $newMembers=array();
                            $myInt=explode(",",$obj_interfaces);
                            $execute_group=FALSE;
                            if (count($myInt)==1) {
                                $get_parts=explode("/",$obj_interfaces);
                                if ($ip==$get_parts[0]){
                                    #as Host
                                    $address[$ipversion][]="('ip-netmask','ip-netmask','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";
                                    $execute_group=FALSE;
                                }
                                else {
                                    #group
                                    $execute_group=TRUE;
                                }
                            }
                            elseif (count($myInt)>1){
                                $execute_group=TRUE;
                            }

                            if ($execute_group===TRUE){
                                if (($ip!="") AND ($ip!="0.0.0.0")){
                                    $address[$ipversion][]="('ip-netmask','ip-netmask','$ip','$hostCidr','INT-$ip-$hostCidr','INT-$ip-$hostCidr','0','1','$description','$source','$vsys')";
                                    $newMembers[]="INT-$ip-$hostCidr";
                                    foreach($myInt as $key=>$value){
                                        $network_and_cidr=explode("/",$value);
                                        $ipversion2=ip_version($network_and_cidr[0]);
                                        if ($ipversion2=="v4"){$hostCidr2="32";}
                                        if ($ipversion2=="v6"){$hostCidr2="128";}
                                        else {$ipversion2="v4";}
                                        $nameInt="INT-".$network_and_cidr[0]."-".$hostCidr2;
                                        if (($nameInt!="INT--") AND ($nameInt!="INT-0.0.0.0-0")){
                                            $newMembers[]=$nameInt;
                                            $address[$ipversion][]="('ip-netmask','ip-netmask','$network_and_cidr[0]','$hostCidr2','$nameInt','$nameInt','0','1','$description','$source','$vsys')";
                                        }
                                    }
                                    //$projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,type,checkit) VALUES ('$name','$name','$source','static','0')");
                                    //$lid=$projectdb->insert_id;
                                    $addressgroups[]="('$lid','$name','$name','$source','static','0','$vsys','$description')";
                                    foreach ($newMembers as $key2=>$member_var){
                                        $addmembers[]="('$lid','$member_var','$source','$vsys')";
                                        #$projectdb->query("INSERT INTO address_groups (lid,member,source) values('$lid','$member_var','$source');");
                                    }
                                    $lid++;
                                    add_log2('warning','Transformation','Host called ['.$name.'] has many Interfaces ['.$obj_interfaces.'] Converting to Address Group',$source,'No action required','objects',$lid,'address_groups_id');
                                }
                                $execute_group=FALSE;
                            }
                     */

                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));
                    if( isset( $object['ipaddr'] ) )
                        $IPvalue = $object['ipaddr'];
                    elseif( isset( $object['ipaddr6'] ) )
                        $IPvalue = $object['ipaddr6'];

                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    if( isset($object['interfaces']) )
                    {
                        //what to do here?
                        foreach( $object['interfaces'] as $interface )
                        {
                            $tmp_name = $interface;
                            $tmp_name = explode("/", $tmp_name);


                            $tmp_IP = $tmp_name[0];
                            $tmp_cidr = $tmp_name[1];

                            if( $tmp_name[0] != "" )
                            {
                                $tmp_name = $tmp_name[0];

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


                                //Interface IP read from routing table is network but real interface IP can only get from objects.C
                                $tmp_interfaces = $this->template->network->findInterfacesNetworkMatchingIP($tmp_IP);
                                if( count($tmp_interfaces) > 0 )
                                {
                                    //ONLY first interface get checked
                                    $tmp_addresses = $tmp_interfaces[0]->getLayer3IPAddresses();

                                    //todo: check that $tmp_IP is part of network $tmp_addresses[0]
                                    $tmp_interfaces[0]->removeIPv4Address($tmp_addresses[0]);
                                    $tmp_interfaces[0]->addIPv4Address($tmp_IP . "/" . $tmp_cidr);
                                }
                            }
                        }
                        $this->MainAddAddressGroup($name, $addToGroup, $description);
                    }
                    else
                        $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "ipaddr" &&
                            $key1 != "ipaddr6" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "interfaces" &&
                            $key1 != "shared" &&
                            $key1 != "groupmembers" &&
                            $key1 != "gateway_brand"
                        )
                        {
                            mwarning("KEY: " . $key1 . " not yet checked\n");
                            print_r($object);
                        }

                    }

                }
                elseif( $object['type'] == "gateway_fw" ||
                    $object['type'] == "gateway" ||
                    $object['type'] == "gateways" ||
                    $object['type'] == "router"
                )
                {
                    /*
                     * [name] => AWS_VPC_Tun4
    [type] => gateway
    [on-interface] => Array
        (
            [0] => internal
        )

    [ipaddr] => 176.32.107.244
                     */


                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));

                    if( isset( $object['ipaddr'] ) )
                        $IPvalue = $object['ipaddr'];
                    elseif( isset( $object['ipaddr6'] ) )
                        $IPvalue = $object['ipaddr6'];
                    else
                    {
                        print "TYPE: " . $object['type'] . "\n";
                        print_r($object);

                        continue;
                    }


                    $description = "";
                    if( isset($object['comment']) )
                        $description = $object['comment'];

                    if( isset($object['on-interface']) )
                    {
                        //what to do here?
                    }

                    if( isset($object['interfaces']) )
                    {
                        //what to do here?
                        foreach( $object['interfaces'] as $interface )
                        {
                            $tmp_name = $interface;
                            $tmp_name = explode("/", $tmp_name);


                            $tmp_IP = $tmp_name[0];
                            $tmp_cidr = $tmp_name[1];

                            if( $tmp_name[0] != "" )
                            {
                                $tmp_name = $tmp_name[0];

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

                                //Interface IP read from routing table is network but real interface IP can only get from objects.C
                                $tmp_interfaces = $this->template->network->findInterfacesNetworkMatchingIP($tmp_IP);
                                if( count($tmp_interfaces) > 0 )
                                {
                                    //ONLY first interface get checked
                                    $tmp_addresses = $tmp_interfaces[0]->getLayer3IPAddresses();

                                    //todo: check that $tmp_IP is part of network $tmp_addresses[0]
                                    $tmp_interfaces[0]->removeIPv4Address($tmp_addresses[0]);
                                    $tmp_interfaces[0]->addIPv4Address($tmp_IP . "/" . $tmp_cidr);
                                }
                            }
                        }
                        $this->MainAddAddressGroup($name, $addToGroup, $description);
                    }
                    else
                        $this->MainAddHost($name, $IPvalue, 'ip-netmask', $description);

                    if( isset($object['shared']) )
                    {
                        //Todo: 20200605 swaschkut what to do here? create object at highest PAN-OS level?
                    }

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "ipaddr" &&
                            $key1 != "ipaddr6" &&
                            $key1 != "comment" &&
                            $key1 != "on-interface" &&
                            $key1 != "interfaces" &&
                            $key1 != "shared"
                        )
                        {
                            mwarning("KEY: " . $key1 . " not yet checked\n");
                            print_r($object);
                        }

                    }
                    //$address[$ipversion][]="('ip-netmask','$type','$ip','$mask','$name','$name','1','1','$description','$source','$vsys')";}
                    //$address[$ipversion][]="('ip-netmask','$type','$ip','$hostCidr','$name','$name','1','1','$description','$source','$vsys')";}
                }
                elseif( $object['type'] == "community" )
                {
                    //do nothing
                }
                elseif(
                    $object['type'] == "sofaware_gateway" ||
                    $object['type'] == "voip_gk" ||
                    $object['type'] == "voip_gw"
                )
                {
                    /*
                     $ipaddress_host_edge=$ipaddress_host_edge+1;
                    $ipaddress_host_edge_ip="10.10.10.".$ipaddress_host_edge;
                    $address[$ipversion][]="('ip-netmask','$type','$ipaddress_host_edge_ip','32','$name','$name','1','1','$description','$source','$vsys')";
                    add_log('warning','Phase 2: Reading Address Objects and Groups','Sofaware/voIP gateway found, creating group with 2 members',$source,'Added '.$name.' with ip '.$ipaddress_host_edge_ip);
                     */
                }
                else
                {
                    print_r($object);
                    mwarning("TYPE: " . $object['type'] . " not supported yet\n");

                }
            }
            else
            {
                print_r($object);
                mwarning("skipped: no TYPE\n");

            }
        }

        $missingAddressGroupMembers = array();
        //add groups in a different steps, so that all other address objects are defined already
        foreach( $array as $object )
        {
            if( isset($object['type']) )
            {
                if( $object['type'] == 'group' )
                {
                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));

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

                    $this->MainAddAddressGroup($name, $members, $description, $missingAddressGroupMembers);

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
                elseif( $object['type'] == 'group_with_exclusion' )
                {
                    print_r($object);

                    /*
                     * [name] => USER_VLANS_EXCLUDE_VPN
                    [type] => group_with_exclusion
                    [on-interface] => Array
                        (
                            [0] => internal
                        )

                    [groupmembers_base] => Array
                        (
                            [0] => USER_VLANS
                        )

                    [groupmembers_exception] => Array
                        (
                            [0] => VPN_Nets
                        )
                     */
                    //Expedition added these groups

                    $name = $object['name'];
                    $name = $this->truncate_names($this->normalizeNames($name));

                    if( isset($object['groupmembers_base']) )
                        $members = $object['groupmembers_base'];
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

                    $tmp_addressgroup = $this->MainAddAddressGroup($name, $members, $description, $missingAddressGroupMembers);

                    $addlog = "Addressgroup exception not removed";
                    $tmp_addressgroup->set_node_attribute('warning', $addlog);

                    foreach( $object as $key1 => $value )
                    {
                        if( $key1 != 'type' &&
                            $key1 != "name" &&
                            $key1 != "groupmembers_base" &&
                            $key1 != "groupmembers_exception" &&
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

        print PH::boldText("\nadd missing addressgroup members\n");
        foreach( $missingAddressGroupMembers as $addressgroup_name => $members )
        {
            print "\n\n";
            $tmp_addressgroup = $this->MainAddAddressGroup($addressgroup_name, $members, null);
        }
    }
}

