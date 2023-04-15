<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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

trait SONICWALLinterface
{

    function add_interface( $interface)
    {
        global $debug;
        global $print;


        $padding = "    ";
        $padding_name = substr($padding, 0, -1);

        /*
         0|X18|
            1|no ip-assignment|
            2|link-speed full 10000|
            3|mac default|
            4|shutdown-port|
            5|flow-reporting|
            6|no cos-8021p|
            7|no exclude-route|
            8|no asymmetric-route|
            9|no port redundancy-aggregation|
            10|mtu 1500|
            11||

            0|MGMT|
            1|ip-assignment MGMT static|
            2|ip 10.0.39.161|
            3|backup-ip 10.0.39.162|
            4|netmask 255.255.254.0|
            5|gateway 10.0.38.1|
            6|exit|
            7||
            8|comment "Default MGMT"|
            9|management https|
            10|management ping|
            11|management snmp|
            12|management ssh|
            13|user-login https|
            14|https-redirect|
            15|link-speed auto-negotiate|
            16|mac default|
            17|flow-reporting|
            18|no asymmetric-route|
            19|mtu 1500|
            20||

            0|ipv6 X0|
            1|ip-assignment static|
            2|ip ::|
            3|prefix-length 64|
            4|no advertise subnet-prefix|
            5||
            6|router-advertisement|
            7|no enable|
            8|interval min 200|
            9|interval max 600|
            10|no link-mtu|
            11|no reachable-time|
            12|no retransmit-timer|
            13|current-hop-limit 64|
            14|router lifetime 1800|
            15|router preference medium|
            16|no managed|
            17|no other-config|
            18|exit|
            19|exit|
            20||
            21|ipv6-traffic|
            22|listen-router-advertisement|
            23|no stateless-address-autoconfig|
            24|duplicate-address-detection-transmits 1|
            25|reachable-time 30|
            26|max ndp-size 128|
            27|management https|
            28|management ping|
            29|no management snmp|
            30|no user-login https|
            31|https-redirect|
            32||

         */

        foreach( $interface as $key => $interface_entry )
        {
            $tmp_int_main = null;
            $tmp_sub = null;

            $orig_service_entry = $interface_entry;

            if( $debug )
            {
                print_r($interface_entry);
            }


            $interface_entry = explode("\n", $interface_entry);
            if( (isset($interface_entry[4]) && $interface_entry[4] != "    shutdown-port") )
            {
                foreach( $interface_entry as $key2 => $interface )
                {
                    $is_ipv6 = FALSE;
                    $interface = trim($interface);

                    #print "key: ".$key2." - |".$interface."|\n";

                    if( $key2 == 0 )
                    {
                        $name = $interface;
                        $name = $this->truncate_names($this->normalizeNames($name));

                        if( strpos($name, "ipv6") !== FALSE )
                        {
                            $is_ipv6 = TRUE;
                            $name = str_replace("ipv6 ", "", $name);
                        }


                        if( strpos($name, "vlan") !== FALSE )
                        {
                            $tmp_name = explode(' ', $name);

                            $name = $tmp_name[0];
                            $vlan = $tmp_name[2];


                            $tmp_int_main = $this->template->network->findInterface($name);
                            if( !is_object($tmp_int_main) )
                            {
                                if( $print )
                                    print $padding_name . "- name: " . $name . "\n";
                                $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($name, 'layer3');
                                $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);
                            }

                            $tmp_sub = $this->template->network->findInterface($name . "." . $vlan);
                            if( $tmp_sub === null )
                            {
                                $tmp_sub = $tmp_int_main->addSubInterface($vlan, $name . "." . $vlan);
                                $this->template_vsys->importedInterfaces->addInterface($tmp_sub);
                            }

                            //to continue adding ip aso.
                            $tmp_int_main = $tmp_sub;
                        }
                        else
                        {
                            $tmp_int_main = $this->template->network->findInterface($name);
                            if( !is_object($tmp_int_main) )
                            {
                                if( $print )
                                    print $padding_name . "- name: " . $name . "\n";
                                $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($name, 'layer3');
                                $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);
                            }
                        }
                    }
                    elseif( $interface == "" )
                    {

                    }
                    elseif( ($key2 == 1 || $key2 == 2) && $interface == "no ip-assignment" )
                    {
                        print "continue\n";
                        continue;
                    }
                    elseif( $key2 == 1 && preg_match('#^ip-assignment (.*) static$#m', $interface, $output_array) )
                    {
                        $zone = $output_array[1];

                        $ip_address = $interface_entry[2];
                        $ip_address = trim($ip_address);

                        if( $ip_address != "no ip" )
                        {
                            $ip_array = explode(" ", $ip_address);

                            if( isset($ip_array[2]) && $ip_array[2] == 'netmask' )
                            {
                                $ip_address = $ip_array[1] . "/" . cidr::netmask2cidr($ip_array[3]);
                            }
                            else
                                $ip_address = $ip_array[1] . "/32";

                            if( $print )
                                print $padding . "- add ip address: " . $ip_address . "\n";
                            $tmp_int_main->addIPv4Address($ip_address);
                        }

                        $tmp_zone = $this->template_vsys->zoneStore->find($zone);
                        if( $tmp_zone != null )
                        {
                            if( $print )
                                print $padding . "- add zone: " . $zone . "\n";
                            $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                        }
                        else
                        {
                            if( $debug )
                                print $padding . " zone: " . $zone . " for interface:  " . $tmp_int_main->name() . " not found\n";

                        }
                    }
                    #elseif( $key2 == 1 && preg_match('#^ip-assignment static$#m', $interface, $output_array) )
                    elseif( $key2 == 1 && $interface == "ip-assignment static" )
                    {
                        //normally only for IPV6

                        #$zone = $output_array[1];

                        $ip_address = $interface_entry[2];
                        $ip_address = trim($ip_address);

                        if( $ip_address != "no ip" )
                        {
                            $ip_array = explode(" ", $ip_address);
                            if( isset($interface_entry[3]) && strpos($interface_entry[3], "prefix-length") !== FALSE )
                            {
                                $tmp_netmask = trim($interface_entry[3]);
                                $tmp_netmask = explode(" ", $tmp_netmask);
                                $netmask = $tmp_netmask[1];
                            }
                            else
                                $netmask = 0;

                            $ip_address = $ip_array[1] . "/" . $netmask;

                            if( $print )
                                print $padding . "- add ip address: " . $ip_address . "\n";
                            $tmp_int_main->addIPv6Address($ip_address);
                        }
                    }
                    else
                    {
                        #print "    O|".$key2 . "|" . $interface . "|\n";
                    }
                }
            }
        }
    }

}

