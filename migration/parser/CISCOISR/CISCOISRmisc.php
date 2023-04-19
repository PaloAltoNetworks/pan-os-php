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

trait CISCOISRmisc
{



    function create_address_host_objects( $ip_host_array)
    {
        global $debug;
        global $print;

        //example:
        /*
         |ip host em-abz-vcs-02.enermech.local 192.0.2.1|
            Array
            (
                [0] => ip
                [1] => host
                [2] => em-abz-vcs-02.enermech.local
                [3] => 192.0.2.1
            )

         */
        foreach( $ip_host_array as $words )
        {
            $name = $this->truncate_names($this->normalizeNames($words[2]));
            $type = "ip-netmask";
            $value = $words[3] . "/32";

            $tmp_address = $this->sub->addressStore->find($name);
            if( $tmp_address === null )
            {
                if( $print )
                    print " * create object: " . $name . " type: " . $type . " value: " . $value . "\n";
                $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
            }
        }


    }


    function create_objectgroup( $objectgroup_array)
    {
        global $debug;
        global $print;

        foreach( $objectgroup_array as $objectgroup )
        {
            /*
             * EXAMPLE
            Array
            (
                [name] => globalprotect-gateways-object
                [0] => Array
                    (
                        [type] => host
                        [value] => 34.98.251.101
                    )

                [1] => Array
                    (
                        [type] => host
                        [value] => 34.99.227.23
                    )

                [2] => Array
                    (
                        [type] => host
                        [value] => 34.103.211.29
                    )

                [3] => Array
                    (
                        [type] => host
                        [value] => 34.99.239.23
                    )

             */
            if( isset($objectgroup['name']) )
            {
                $name = $this->truncate_names($this->normalizeNames($objectgroup['name']));

                $tmp_addressgroup = $this->sub->addressStore->find($name);
                if( $tmp_addressgroup === null )
                {
                    if( $print )
                        print "\n * create addressgroup object: " . $name . "\n";
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($name);
                }
                unset($objectgroup['name']);
            }
            //addressgroup name -> $objectgroup['name']

            #print_r( $objectgroup );
            foreach( $objectgroup as $host )
            {
                #print_r( $host );
                if( $host['type'] != "host" )
                    mwarning("addressgroup found with NO host; addressgroup name: " . $tmp_addressgroup->name() . " hostname: " . $host[1], null, FALSE);

                $name = "h-" . $host['value'];
                $value = $host['value'] . "/32";
                $type = $type = "ip-netmask";

                $tmp_address = $this->sub->addressStore->find($name);
                if( $tmp_address === null )
                {
                    if( $print )
                        print "      * create address object: " . $name . " type: " . $type . " value: " . $value . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value);
                }
                if( $tmp_address !== null )
                {
                    if( $print )
                    {
                        #print "  * add addressobject: ".$tmp_address->name(). " to addressgroup: ".$tmp_addressgroup->name()."\n";
                        print "   * add addressobject: " . $tmp_address->name() . "\n";
                    }
                    $tmp_addressgroup->addMember($tmp_address);
                }
            }
        }
    }


    function accesslist_search_srcdst($object, &$keyToCheck, &$rule_array)
    {
        #print "accesslist_search_srcdst-start\n";
        #print_r( $rule_array );
        #print "key to check-start: ".$keyToCheck."\n";
        #print_r( $object );

        global $found_eq_src;


        if( !isset($object[$keyToCheck]) )
        {
            print "return null accesslist_serachsrcdst - " . $keyToCheck . "\n";
            if( !isset($rule_array['dst']) )
                $rule_array['dst'] = 'any';
            return null;
        }


        $ip_check = explode(".", $object[$keyToCheck]);

        if( $object[$keyToCheck] != "any" && $object[$keyToCheck] != "tcp" && $object[$keyToCheck] != "udp" && $object[$keyToCheck] != "icmp"
            && $object[$keyToCheck] != "host" && $object[$keyToCheck] != "object-group"
            && count($ip_check) != 4
            //&& !$found_eq_src
        )
        {
            $rule_array['app'] = $object[$keyToCheck];
            $rule_array['app1'] = $object[$keyToCheck];
            $keyToCheck++;
        }


        if( !isset($object[$keyToCheck]) )
        {
            if( !isset($rule_array['dst']) )
                $rule_array['dst'] = 'any';
            if( $rule_array['app'] == "log" )
                unset($rule_array['app']);
            return null;
        }


        //if app was set before calcuate check the new value
        $ip_check = explode(".", $object[$keyToCheck]);

        if( $object[$keyToCheck] == "any" || $object[$keyToCheck] == "tcp" || $object[$keyToCheck] == "udp"
            || $object[$keyToCheck] == "icmp"
            || $object[$keyToCheck] == "host" || $object[$keyToCheck] == "object-group"
            || count($ip_check) == 4
        )
        {

            #print_r( $object);
            if( $object[$keyToCheck] == "tcp" || $object[$keyToCheck] == "udp" || $object[$keyToCheck] == "icmp" )
            {
                #print_r($object);
                $rule_array['protocol'] = $object[$keyToCheck];
                $keyToCheck++;
            }

            if( $object[$keyToCheck] == "any" )
            {

                $keyToCheck++;

                if( !isset($rule_array['src']) )
                    $rule_array['src'] = 'any';
                elseif( !isset($rule_array['dst']) )
                {
                    $found_eq_src = FALSE;
                    $rule_array['dst'] = 'any';
                }

                else
                {
                    print_r($object);
                    print_r($rule_array);
                    mwarning("both src and dst set but ANY found");
                }
            }

            elseif( $object[$keyToCheck] == "host" || $object[$keyToCheck] == "object-group" )
            {
                $keyToCheck++;
                if( !isset($rule_array['src']) )
                    $rule_array['src'] = $object[$keyToCheck];
                elseif( !isset($rule_array['dst']) )
                {
                    $found_eq_src = FALSE;
                    $rule_array['dst'] = $object[$keyToCheck];
                }

                else
                {
                    print_r($object);
                    print_r($rule_array);
                    mwarning("both src and dst set but host found");
                }

                $keyToCheck++;
            }
            elseif( count($ip_check) == 4 )
            {
                if( !isset($rule_array['src']) )
                {
                    print "check SRC wildcard\n";

                    if( isset($object[$keyToCheck + 1]) )
                    {
                        self::accesslist_search_srcdst_wildcardmask($object, $keyToCheck, $rule_array);
                        #$rule_array['src'] = $object[$keyToCheck];
                    }
                    else
                        $rule_array['src'] = $object[$keyToCheck];
                }

                elseif( !isset($rule_array['dst']) )
                {
                    #print "check DST wildcard\n";
                    $found_eq_src = FALSE;

                    #$keyToCheck--;

                    #print "deeper validation of: ".$keyToCheck ." - ".($keyToCheck + 1)."\n";
                    #print_r( $object );

                    if( isset($object[$keyToCheck + 1]) )
                    {
                        self::accesslist_search_srcdst_wildcardmask($object, $keyToCheck, $rule_array);
                    }
                    else
                    {
                        $rule_array['dst'] = $object[$keyToCheck];
                    }


                }

                else
                {
                    print_r($object);
                    print_r($rule_array);
                    mwarning("both src and dst set but host found");
                }

                $keyToCheck++;
            }
        }
        else
        {
            $rule_array['app'] = $object[$keyToCheck];
            $keyToCheck++;

        }

        #print "accesslist_search_srcdst-end\n";
        #print_r( $rule_array );
        #print "key to check-end: ".$keyToCheck."\n";
    }


    function accesslist_search_srcdst_wildcardmask($object, &$keyToCheck, &$rule_array)
    {
        global $found_eq_src;

        #print "check why DST is no set\n";
        #print_r( $rule_array );
        #print "key to check-wildcard-start: ".$keyToCheck."\n";
        #print_r( $object );

        if( !isset($object[$keyToCheck]) )
        {
            print "key not set: " . $keyToCheck . "\n";
            return null;
        }


        if( $object[$keyToCheck] == "eq" )
        {
            if( !isset($rule_array['dst']) )
            {
                $rule_array['dst'] = "any";
                $found_eq_src = FALSE;
            }

            //no key++ needed
        }
        else
        {
            $ip_check = explode(".", $object[$keyToCheck]);

            print "IPCHECk: \n";
            print_r($ip_check);

            if( count($ip_check) == 4 )
            {
                #print "search SRC must be IP / reverse netmask\n";
                $value = $object[$keyToCheck];

                $keyToCheck++;
                if( isset($object[$keyToCheck]) )
                {
                    $wildcardnetmask = $object[$keyToCheck];

                    $netmask = self::wildcardnetmask2netmask($wildcardnetmask);
                    $cidr = CIDR::netmask2cidr($netmask);

                    print "NETMASK: " . $netmask . "\n";
                    print "CIDR: " . $cidr . "\n";

                    if( !isset($rule_array['src']) )
                    {
                        $rule_array['src'] = $value . "/" . $cidr;

                        //IS this the problem??
                        #$keyToCheck++;


                        #if( !isset( $object[$keyToCheck] ) )
                        #return null;
                    }

                    elseif( !isset($rule_array['dst']) )
                    {
                        $found_eq_src = FALSE;
                        $rule_array['dst'] = $value . "/" . $cidr;
                    }
                }
            }
            else
            {
                print_r($object);
                mwarning("not an IP - not implemented");
            }
        }

        #print "accesslist_search_srcdst-wildcard-end\n";
        #print_r( $rule_array );
        #print "key to check-wildcard-end: ".$keyToCheck."\n";
    }

    function find_service_port($object = null, $keyToCheck = null, $service = null)
    {
        global $debug;
        global $print;
        #global $svcReplaceByOther;

        if( $object != null && $keyToCheck != null )
            $service = $object[$keyToCheck];


        if( !is_numeric($service) )
        {
            if( isset($this->svcReplaceByOther[$service]) )
            {
                $service = $this->svcReplaceByOther[$service][0];
            }
            else
            {
                if( $debug )
                    print_r($object);
                mwarning("no service port found for: " . $service);
            }

        }

        return $service;
    }

    function create_access_list( $accesslist_array)
    {
        global $debug;
        global $print;
        global $svcReplaceByOther;
        global $found_eq;
        global $found_eq_src;
        global $found_timerange;

        $rule_array_final = array();
        $rule_key = 0;

        foreach( $accesslist_array as $accesslist )
        {

            //type outside
            /*
             * EXAMPLES
            Array
            (
                [0] => access-list
                [1] => 109
                [2] => permit
                [3] => ip
                [4] => 192.168.4.0
                [5] => 0.0.0.255
                [6] => 172.16.3.0
                [7] => 0.0.0.255
            )
            Array
            (
                [0] => access-list
                [1] => 20
                [2] => permit
                [3] => 89.104.224.241
            )
            Array
            (
                [0] => access-list
                [1] => 20
                [2] => permit
                [3] => 89.104.224.240
            )
            Array
            (
                [0] => access-list
                [1] => 20
                [2] => permit
                [3] => 89.104.234.241
            )
            Array
            (
                [0] => access-list
                [1] => 20
                [2] => permit
                [3] => 172.16.0.38
            )
            Array
            (
                [0] => access-list
                [1] => 20
                [2] => remark
                [3] => SNMP
            )
             */

            if( $accesslist['type'] == "outside" )
            {
                //Todo: check example above

                unset($accesslist['type']);
                if( isset($accesslist['value'][0]) && isset($accesslist['value'][1]) )
                {
                    $name = $accesslist['value'][0] . "-" . $accesslist['value'][1];
                    unset($accesslist['value'][0]);
                    unset($accesslist['value'][1]);
                    #$accesslist = $accesslist['value'];
                    array_splice($accesslist['value'], 0, 0);
                }

                else
                {
                    if( $debug )
                        print_r($accesslist);
                    mwarning("no accesslist name found");
                    continue;
                }
                /*
                                            foreach( $accesslist as $object )
                                            {
                                                print "1SVEN\n";
                                                print_r( $object );
                                            }
                                            */

            }
            elseif( $accesslist['type'] == "standard" )
            {

                unset($accesslist['type']);
                if( isset($accesslist['value']) && isset($accesslist['value'][3]) )
                {
                    $name = $accesslist['value'][3];
                    unset($accesslist['value']);
                }

                else
                {
                    if( $debug )
                        print_r($accesslist);
                    mwarning("no accesslist name found");
                    continue;
                }

                /*
                                foreach( $accesslist as $object )
                                {
                                    print "2SVEN\n";
                                    print_r( $object );
                                }
                                */
            }

            elseif( $accesslist['type'] == "extended" )
            {
                /*
                    Array
                    (
                        [0] => permit
                        [1] => tcp
                        [2] => host
                        [3] => 10.60.112.164
                        [4] => any
                        [5] => eq
                        [6] => www
                    )
                    Array
                    (
                        [0] => permit
                        [1] => igmp
                        [2] => any
                        [3] => any
                    )
                    Array
                    (
                        [0] => deny
                        [1] => pim
                        [2] => any
                        [3] => host
                        [4] => 224.0.0.13
                    )
                    Array
                    (
                        [0] => permit
                        [1] => pim
                        [2] => any
                        [3] => any
                    )

                 */

                unset($accesslist['type']);
                if( isset($accesslist['value']) && isset($accesslist['value'][3]) )
                {
                    $name = $accesslist['value'][3];
                    unset($accesslist['value']);
                }

                else
                {
                    if( $debug )
                        print_r($accesslist);
                    mwarning("no accesslist name found");
                    continue;
                }

                foreach( $accesslist as $object )
                {
                    print "3SVEN\n";
                    print_r($object);
                }


            }

            #$accesslist=array_values($accesslist);
            #array_splice($accesslist, 0, 0);
            #print "array_splice:\n";
            #print_r( $accesslist );

            foreach( $accesslist as $object )
            {
                $keyToCheck = 0;
                $found_eq = FALSE;
                $found_eq_src = FALSE;
                $found_timerange = FALSE;
                $rule_array = array();

                print_r($object);
                if( isset($object[$keyToCheck]) && ($object[$keyToCheck] == "permit" || $object[$keyToCheck] == "deny" || $object[$keyToCheck] == "remark") )
                {
                    if( $object[$keyToCheck] == "remark" )
                    {
                        $description = "";
                        foreach( $object as $comment )
                            $description .= $comment;
                        $rule_array['description'] = $description;

                        continue;
                    }

                    $rule_array['action'] = $object[$keyToCheck];
                    $rule_array['tag'] = $name;
                    $keyToCheck++;
                    if( $object[$keyToCheck] == "ip" )
                        $keyToCheck++;


                    #print "now check SRC\n";
                    //search for SRC - easy wah
                    self::accesslist_search_srcdst($object, $keyToCheck, $rule_array);

                    if( !isset($rule_array['src']) )
                    {
                        self::accesslist_search_srcdst_wildcardmask($object, $keyToCheck, $rule_array);
                        $keyToCheck++;
                    }


                    if( isset($rule_array['src']) )
                    {
                        if( isset($object[$keyToCheck]) && ($object[$keyToCheck] == "eq" || $object[$keyToCheck] == "gt" || $object[$keyToCheck] == "lt" || $object[$keyToCheck] == "range") )
                        {
                            if( $object[$keyToCheck] == "range" )
                            {
                                $keyToCheck++;
                                $first = self::find_service_port($object, $keyToCheck);
                                $keyToCheck++;
                                $second = self::find_service_port($object, $keyToCheck);

                                $protocol = "tcp";
                                if( isset($rule_array['protocol']) )
                                    $protocol = $rule_array['protocol'];
                                else
                                {
                                    if( $debug )
                                        print_r($object);
                                    mwarning("not protocol found");
                                }

                                $rule_array['srv-src'] = $protocol . "|" . $first . "-" . $second;

                                $keyToCheck++;
                            }
                            if( $object[$keyToCheck] == "eq" )
                            {
                                $found_eq_src = TRUE;

                                $keyToCheck++;

                                $service = self::find_service_port($object, $keyToCheck);
                                $protocol = "tcp";
                                if( isset($rule_array['protocol']) )
                                    $protocol = $rule_array['protocol'];
                                else
                                {
                                    if( $debug )
                                        print_r($object);
                                    mwarning("not protocol found");
                                }
                                $rule_array['srv-src'] = $protocol . "|" . $service;

                                $keyToCheck++;

                                //more srv src port
                                while(
                                    $object[$keyToCheck] != "any"
                                    && $object[$keyToCheck] != "tcp" && $object[$keyToCheck] != "udp"
                                    && $object[$keyToCheck] != "icmp"
                                    && $object[$keyToCheck] != "host" && $object[$keyToCheck] != "object-group"
                                    && count(explode(".", $object[$keyToCheck])) != 4
                                    //&& !$found_eq_src
                                )
                                {
                                    $service = self::find_service_port($object, $keyToCheck);
                                    $rule_array['srv-src'] .= "," . $service;
                                    $keyToCheck++;
                                }


                            }
                            elseif( $object[$keyToCheck] == "gt" )
                            {
                                $keyToCheck++;

                                $service = self::find_service_port($object, $keyToCheck);

                                $first = intval($service) + 1;
                                $second = "65535";

                                $protocol = "tcp";
                                if( isset($rule_array['protocol']) )
                                    $protocol = $rule_array['protocol'];
                                else
                                {
                                    if( $debug )
                                        print_r($object);
                                    mwarning("not protocol found");
                                }

                                $rule_array['srv-src'] = $protocol . "|" . $first . "-" . $second;

                                $keyToCheck++;
                            }
                            elseif( $object[$keyToCheck] == "lt" )
                            {
                                $keyToCheck++;

                                $service = self::find_service_port($object, $keyToCheck);


                                $first = "65535";
                                $second = intval($service) - 1;

                                $protocol = "tcp";
                                if( isset($rule_array['protocol']) )
                                    $protocol = $rule_array['protocol'];
                                else
                                {
                                    if( $debug )
                                        print_r($object);
                                    mwarning("not protocol found");
                                }

                                $rule_array['srv-src'] = $protocol . "|" . $first . "-" . $second;

                                $keyToCheck++;
                            }
                        }

                        #print "now check DST\n";
                        //search for DST - easy way
                        self::accesslist_search_srcdst($object, $keyToCheck, $rule_array);


                        if( !isset($rule_array['dst']) )
                        {
                            #print "DST not set - additonal check needed\n";
                            self::accesslist_search_srcdst_wildcardmask($object, $keyToCheck, $rule_array);
                            $keyToCheck++;
                            #print "is DST now set?\n";
                            #print_r( $rule_array );
                        }

                    }


                    if( isset($object[$keyToCheck]) )
                    {
                        if( $object[$keyToCheck] == "eq" )
                        {
                            $found_eq = TRUE;

                            $keyToCheck++;

                            $service = self::find_service_port($object, $keyToCheck);
                            $protocol = "tcp";
                            if( isset($rule_array['protocol']) )
                                $protocol = $rule_array['protocol'];
                            else
                            {
                                if( $debug )
                                    print_r($object);
                                mwarning("not protocol found");
                            }
                            $rule_array['srv'] = $protocol . "|" . $service;

                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "gt" )
                        {
                            $keyToCheck++;

                            $service = self::find_service_port($object, $keyToCheck);

                            $first = intval($service) + 1;
                            $second = "65535";

                            $protocol = "tcp";
                            if( isset($rule_array['protocol']) )
                                $protocol = $rule_array['protocol'];
                            else
                            {
                                if( $debug )
                                    print_r($object);
                                mwarning("not protocol found");
                            }

                            $rule_array['srv'] = $protocol . "|" . $first . "-" . $second;

                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "lt" )
                        {
                            $keyToCheck++;

                            $service = self::find_service_port($object, $keyToCheck);


                            $first = "65535";
                            $second = intval($service) - 1;

                            $protocol = "tcp";
                            if( isset($rule_array['protocol']) )
                                $protocol = $rule_array['protocol'];
                            else
                            {
                                if( $debug )
                                    print_r($object);
                                mwarning("not protocol found");
                            }

                            $rule_array['srv'] = $protocol . "|" . $first . "-" . $second;

                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "range" )
                        {
                            $keyToCheck++;
                            $first = self::find_service_port($object, $keyToCheck);
                            $keyToCheck++;
                            $second = self::find_service_port($object, $keyToCheck);

                            $protocol = "tcp";
                            if( isset($rule_array['protocol']) )
                                $protocol = $rule_array['protocol'];
                            else
                            {
                                if( $debug )
                                    print_r($object);
                                mwarning("not protocol found");
                            }

                            $rule_array['srv'] = $protocol . "|" . $first . "-" . $second;

                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "log" || $object[$keyToCheck] == "log-input" || $object[$keyToCheck] == "established" )
                        {
                            //not interested in getting log information
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "echo" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = "echo";
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "echo-reply" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = "icmp_echo-reply";
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "mask-request" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = 'icmp_address_mask';
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "timestamp-request" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = 'icmp_timestamp';
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "information-request" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = 'icmp_info_req';
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "timestamp-reply" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = "icmp_timestamp";
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "redirect" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = 'icmp_redirect';
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "time-exceeded" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = 'icmp_time_exceeded';
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "packet-too-big" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            //Todo: find /create custom appid type 3 code 4 - is icmp unreachable with only type 3 correct???
                            $rule_array['app'] = 'icmp_unreachable';
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "source-quench" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = 'icmp_source_quench';
                            $keyToCheck++;
                        }
                        elseif( $object[$keyToCheck] == "traceroute" && isset($rule_array['protocol']) && $rule_array['protocol'] == "icmp" )
                        {
                            $rule_array['app'] = "traceroute";
                            $keyToCheck++;
                        }

                        elseif( $object[$keyToCheck] == "time-range" )
                        {
                            $found_timerange = TRUE;

                            if( $debug )
                                print_r($object);
                            mwarning($object[$keyToCheck] . " found - not implemented");

                            $keyToCheck++;
                        }
                        else
                        {
                            if( $debug )
                                print_r($object);

                            $check_if_ip = explode(".", $object[$keyToCheck]);
                            if( count($check_if_ip) != 4 )
                                mwarning($object[$keyToCheck] . " found - not implemented");
                        }

                    }


                    do
                    {
                        //another information available ????  normaly if eq found
                        if( isset($object[$keyToCheck]) )
                        {
                            if( $object[$keyToCheck] == "log" || $object[$keyToCheck] == "log-input" || $object[$keyToCheck] == "established" )
                            {
                                //not interested in getting log information
                            }
                            elseif( $found_eq )
                            {
                                $service = self::find_service_port($object, $keyToCheck);
                                $rule_array['srv'] .= "," . $service;
                            }
                            elseif( $found_timerange )
                            {
                                //Todo: implementation needed
                            }
                            else
                            {

                                print "'" . $object[$keyToCheck] . "' - found - additional check needed\n\n";
                                print_r($object);
                                print "FINAL\n";
                                print_r($rule_array);
                            }


                            $keyToCheck++;
                        }
                    } while( count($object) > $keyToCheck );
                    #$demo_array[ $object[$keyToCheck] ] = $object[$keyToCheck];
                    //SRC:
                    //check if $object[$keyToCheck] == IPv4
                    //check if $object[$keyToCheck+1] has three ... => calculate netmask

                    //DST:


                }
                elseif( $keyToCheck == 0 )
                {
                    if( $debug )
                        print_r($object);
                    mwarning("no permit or deny found at [0]", null, FALSE);
                }


                $rule_array_final[$rule_key] = $rule_array;
                $rule_key++;
                $rule_array = array();
            }


        }


        #print_r( $rule_array_final );


        if( count($rule_array_final) > 0 )
        {
            foreach( $rule_array_final as $rule_count => $rule_array )
            {
                if( empty($rule_array) )
                    continue;

                $tmp_rule = $this->sub->securityRules->newSecurityRule("Rule-" . $rule_count);

                if( $print )
                    print " * create security Rule: 'Rule-" . $rule_count . "'\n";

                print_r($rule_array);

                if( $print )
                    print "     * action: " . $rule_array['action'] . "\n";
                //ACTION
                if( $rule_array['action'] == "permit" )
                {
                    $tmp_rule->setAction('allow');
                }
                elseif( $rule_array['action'] == "deny" )
                {
                    $tmp_rule->setAction('deny');
                }


                if( $print )
                    print "     * source: " . $rule_array['src'] . "\n";
                //SRC
                if( $rule_array['src'] == "any" )
                {
                    $tmp_rule->source->setAny();
                }
                else
                {
                    if( strpos($rule_array['src'], "/") !== FALSE )
                    {
                        if( strpos($rule_array['src'], "/32") !== FALSE )
                            $pad = "h-";
                        else
                            $pad = "n-";

                        $name = str_replace("/", "m", $rule_array['src']);
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }
                    else
                    {
                        $pad = "h-";
                        $name = $rule_array['src'];
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }


                    $tmp_src = $this->sub->addressStore->find($pad . $name);
                    if( $tmp_src == null )
                    {
                        if( $print )
                            print "       * create address object: " . $pad . $name . " - " . $rule_array['src'] . "\n";
                        $tmp_src = $this->sub->addressStore->newAddress($pad . $name, 'ip-netmask', $rule_array['src']);
                    }

                    $tmp_rule->source->addObject($tmp_src);
                }


                if( $print )
                    print "     * destination: " . $rule_array['dst'] . "\n";
                //DST
                if( $rule_array['dst'] == "any" )
                {
                    $tmp_rule->destination->setAny();
                }
                else
                {
                    if( strpos($rule_array['dst'], "/") !== FALSE )
                    {
                        if( strpos($rule_array['dst'], "/32") !== FALSE )
                            $pad = "h-";
                        else
                            $pad = "n-";

                        $name = str_replace("/", "m", $rule_array['dst']);
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }
                    else
                    {
                        $pad = "h-";
                        $name = $rule_array['dst'];
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }

                    $tmp_dst = $this->sub->addressStore->find($pad . $name);
                    if( $tmp_dst == null )
                    {
                        if( $print )
                            print "       * create address object: " . $pad . $name . " - " . $rule_array['dst'] . "\n";
                        $tmp_dst = $this->sub->addressStore->newAddress($pad . $name, 'ip-netmask', $rule_array['dst']);
                    }


                    $tmp_rule->destination->addObject($tmp_dst);
                }


                if( isset($rule_array['srv-src']) && !isset($rule_array['srv']) )
                {
                    $prot = explode("|", $rule_array['srv-src']);

                    $protocol = $prot[0];
                    $services = $prot[1];

                    if( !is_numeric($services) )
                    {
                        $tmp_service = $this->sub->serviceStore->find($services);
                        if( $tmp_service !== null )
                        {
                            $services = $tmp_service->getDestPort();
                        }
                    }

                    $tmp_srv = $this->sub->serviceStore->find($protocol . "-src" . $services . "_1-65535");
                    if( $tmp_srv == null )
                    {
                        if( $print )
                            print "      * create service: " . $protocol . "-src" . $services . "_1-65535 - 1-65535 - source: " . $services . "\n";
                        $tmp_srv = $this->sub->serviceStore->newService($protocol . "-src" . $services . "_1-65535", $protocol, '1-65535', '', $services);
                    }


                    if( $tmp_srv !== null )
                    {
                        if( $print )
                            print "     * service source and destination added: " . $tmp_srv->name() . "\n";
                        $tmp_rule->services->add($tmp_srv);
                    }

                    else
                        mwarning("service not found nor created: " . $protocol . "-src" . $services . "_1-65535");
                }

                if( isset($rule_array['srv']) )
                {
                    if( isset($rule_array['srv-src']) )
                    {
                        $src_prot = explode("|", $rule_array['srv-src']);
                        $src_protocol = $src_prot[0];
                        $src_services = $src_prot[1];

                        $prot = explode("|", $rule_array['srv']);
                        $protocol = $prot[0];
                        $services = $prot[1];

                        if( !is_numeric($services) )
                        {
                            $tmp_service = $this->sub->serviceStore->find($services);
                            if( $tmp_service !== null )
                            {
                                $services = $tmp_service->getDestPort();
                            }
                        }

                        $tmp_srv = $this->sub->serviceStore->find($protocol . "-src" . $src_services . "_" . $services);
                        if( $tmp_srv == null )
                        {
                            if( $print )
                                print "      * create service: " . $protocol . "-src" . $src_services . "_" . $services . " - " . $services . " - source: " . $src_services . "\n";
                            $tmp_srv = $this->sub->serviceStore->newService($protocol . "-src" . $src_services . "_" . $services, $protocol, $services, '', $src_services);
                        }


                        if( $tmp_srv !== null )
                        {
                            if( $print )
                                print "     * service source and destination added: " . $tmp_srv->name() . "\n";
                            $tmp_rule->services->add($tmp_srv);
                        }

                        else
                            mwarning("service not found nor created: " . $protocol . "-src" . $src_services . "_" . $services);
                    }
                    else
                    {
                        $prot = explode("|", $rule_array['srv']);

                        $protocol = $prot[0];
                        $services = $prot[1];

                        if( !is_numeric($services) )
                        {
                            $tmp_service = $this->sub->serviceStore->find($services);
                            if( $tmp_service !== null )
                            {
                                $services = $tmp_service->getDestPort();
                            }
                        }

                        $tmp_srv = $this->sub->serviceStore->find($protocol . "-" . $services);
                        if( $tmp_srv == null )
                        {
                            if( $print )
                                print "      * create service: " . $protocol . "-" . $services . " - " . $services . "\n";
                            $tmp_srv = $this->sub->serviceStore->newService($protocol . "-" . $services, $protocol, $services);
                        }

                        if( $tmp_srv !== null )
                        {
                            if( $print )
                                print "     * service destination added: " . $tmp_srv->name() . "\n";
                            $tmp_rule->services->add($tmp_srv);
                        }
                        else
                            mwarning("service not found nor created: " . $protocol . "-" . $services);
                    }
                }
                elseif( !isset($rule_array['srv-src']) )
                {
                    if( $print )
                        print "     * service set to ANY\n";
                    $tmp_rule->services->setAny();
                }


                if( isset($rule_array['app']) )
                {
                    $tmp_app = $this->sub->appStore->find($rule_array['app']);

                    if( $tmp_app !== null )
                    {
                        $tmp_rule->apps->addApp($tmp_app);
                        $tmp_rule->services->setApplicationDefault();
                    }
                    else
                    {
                        if( $rule_array['app'] == "esp" )
                        {
                            $tmp_app = $this->sub->appStore->find("ipsec-esp");
                        }
                        elseif( $rule_array['app'] == "ahp" )
                        {
                            $tmp_app = $this->sub->appStore->find("ipsec-ah");
                        }

                        if( $tmp_app !== null )
                        {
                            $tmp_rule->apps->addApp($tmp_app);
                            $tmp_rule->services->setApplicationDefault();
                        }
                        else
                        {
                            print_r($rule_array);
                            mwarning("app-id: " . $rule_array['app'] . " not found!!!", null, FALSE);
                        }
                    }
                    if( $print )
                        print "     * app: " . $rule_array['app'] . "\n";
                }


                if( isset($rule_array['tag']) )
                {
                    if( $print )
                        print "     * tag: " . $rule_array['tag'] . "\n";

                    $tagname = $rule_array['tag'];
                    $tmp_tag = $this->sub->tagStore->find($tagname);

                    if( $tmp_tag == null )
                    {
                        #$color = "color" . $thecolor;
                        $tmp_tag = $this->sub->tagStore->createTag($tagname);
                        if( $print )
                            print "      * Tag create: " . $tmp_tag->name() . "\n";
                        /*
                        $tmp_tag->setColor($color);

                        if( $thecolor == 16 )
                            $thecolor = 1;
                        else
                            $thecolor++;
                        */
                    }
                    $tmp_rule->tags->addTag($tmp_tag);
                }


                if( isset($rule_array['description']) )
                {
                    if( $print )
                        print "     * description: " . $rule_array['description'];
                    $tmp_rule->setDescription($rule_array['description']);
                }
            }
        }


    }

    function add_cisco_services()
    {
        global $projectdb;
        global $debug;
        global $print;

        $vsys = $this->template_vsys->name();

        $source = "";

        #$exists = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND name_ext IN ('echo','gopher','pcanywhere-data');");
        #if ($exists->num_rows == 0) {
        $add_srv = array();
        $add_srv[] = array($source, $vsys, 'echo', 'echo', '', '7');
        $add_srv[] = array($source, $vsys, 'discard', 'discard', '', '9');
        $add_srv[] = array($source, $vsys, 'tacacs', 'tacacs', 'tcp', '49');  //changed tacacs-plus
        $add_srv[] = array($source, $vsys, 'tacacs', 'tacacs', 'udp', '49');  //changed tacacs-plus
        $add_srv[] = array($source, $vsys, 'domain', 'domain', 'udp', '53');
        $add_srv[] = array($source, $vsys, 'sunrpc', 'sunrpc', 'tcp', '111'); // changed portmapper
        $add_srv[] = array($source, $vsys, 'sunrpc', 'sunrpc', 'udp', '111'); // changed portmapper
        $add_srv[] = array($source, $vsys, 'pim-auto-rp', 'pim-auto-rp', 'tcp', '496');
        $add_srv[] = array($source, $vsys, 'pim-auto-rp', 'pim-auto-rp', 'udp', '496');
        $add_srv[] = array($source, $vsys, 'talk', 'talk', 'tcp', '517');
        $add_srv[] = array($source, $vsys, 'talk', 'talk', 'udp', '517');
        $add_srv[] = array($source, $vsys, 'kerberos', 'kerberos', 'tcp', '750');
        $add_srv[] = array($source, $vsys, 'kerberos', 'kerberos', 'udp', '750');
        $add_srv[] = array($source, $vsys, 'nfs', 'nfs', 'tcp', '2049');
        $add_srv[] = array($source, $vsys, 'nfs', 'nfs', 'udp', '2049');
        $add_srv[] = array($source, $vsys, 'sip', 'sip', 'tcp', '5060');
        $add_srv[] = array($source, $vsys, 'sip', 'sip', 'udp', '5060');
        //        $add_srv[] = array($source,$vsys,'112','vrrp','112','0');
        //        $add_srv[] = array($source,$vsys,'46','rsvp','46','0');
        //        $add_srv[] = array($source,$vsys,'57','skip','57','0');
        //        $add_srv[] = array($source,$vsys,'97','etherip','97','0');
        //        $add_srv[] = array($source,$vsys,'ah','ipsec-ah','ah','0');
        //        $add_srv[] = array($source,$vsys,'eigrp','eigrp','eigrp','0');
        //        $add_srv[] = array($source,$vsys,'esp','ipsec-esp','esp','0');
        //        $add_srv[] = array($source,$vsys,'gre','gre','gre','0');
        //        $add_srv[] = array($source,$vsys,'icmp','icmp','icmp','0');
        //        $add_srv[] = array($source,$vsys,'icmp6','ipv6-icmp','icmp6','0');
        //        $add_srv[] = array($source,$vsys,'igmp','igmp','igmp','0');
        //        $add_srv[] = array($source,$vsys,'ipinip','ip-in-ip','ipinip','0');
        //        $add_srv[] = array($source,$vsys,'ipsec','ipsec','ipsec','0');
        //        $add_srv[] = array($source,$vsys,'ospf','ospf','ospf','0');
        //        $add_srv[] = array($source,$vsys,'pim','pim','pim','0');
        $add_srv[] = array($source, $vsys, 'daytime', 'daytime', 'tcp', '13');
        $add_srv[] = array($source, $vsys, 'chargen', 'chargen', 'tcp', '19');
        $add_srv[] = array($source, $vsys, 'ftp-data', 'ftp-data', 'tcp', '20');
        $add_srv[] = array($source, $vsys, 'ftp', 'ftp', 'tcp', '21');
        $add_srv[] = array($source, $vsys, 'ssh', 'ssh', 'tcp', '22');
        $add_srv[] = array($source, $vsys, 'telnet', 'telnet', 'tcp', '23');
        $add_srv[] = array($source, $vsys, 'smtp', 'smtp', 'tcp', '25');
        $add_srv[] = array($source, $vsys, 'whois', 'whois', 'tcp', '43');
        $add_srv[] = array($source, $vsys, 'gopher', 'gopher', 'tcp', '70');
        $add_srv[] = array($source, $vsys, 'finger', 'finger', 'tcp', '79');
        $add_srv[] = array($source, $vsys, 'www', 'www', 'tcp', '80');
        $add_srv[] = array($source, $vsys, 'hostname', 'hostname', 'tcp', '101');
        $add_srv[] = array($source, $vsys, 'pop2', 'pop2', 'tcp', '109');
        $add_srv[] = array($source, $vsys, 'pop3', 'pop3', 'tcp', '110');
        $add_srv[] = array($source, $vsys, 'ident', 'ident', 'tcp', '113');
        $add_srv[] = array($source, $vsys, 'nntp', 'nntp', 'tcp', '119');
        $add_srv[] = array($source, $vsys, 'netbios-ssn', 'netbios-ssn', 'tcp', '139');  //changed netbios-ss_tcp
        $add_srv[] = array($source, $vsys, 'imap4', 'imap4', 'tcp', '143');  //changed imap
        $add_srv[] = array($source, $vsys, 'bgp', 'bgp', 'tcp', '179');
        $add_srv[] = array($source, $vsys, 'irc', 'irc', 'tcp', '194');
        $add_srv[] = array($source, $vsys, 'ldap', 'ldap', 'tcp', '389');
        $add_srv[] = array($source, $vsys, 'https', 'https', 'tcp', '443');
        $add_srv[] = array($source, $vsys, 'exec', 'exec', 'tcp', '512');  //changed r-exec
        $add_srv[] = array($source, $vsys, 'login', 'login', 'tcp', '513');
        $add_srv[] = array($source, $vsys, 'cmd', 'cmd', 'tcp', '514');
        $add_srv[] = array($source, $vsys, 'rsh', 'rsh', 'tcp', '514');
        $add_srv[] = array($source, $vsys, 'lpd', 'lpd', 'tcp', '515');
        $add_srv[] = array($source, $vsys, 'uucp', 'uucp', 'tcp', '540');
        $add_srv[] = array($source, $vsys, 'klogin', 'klogin', 'tcp', '543'); //changed eklogin
        $add_srv[] = array($source, $vsys, 'kshell', 'kshell', 'tcp', '544');
        $add_srv[] = array($source, $vsys, 'rtsp', 'rtsp', 'tcp', '554');
        $add_srv[] = array($source, $vsys, 'ldaps', 'ldaps', 'tcp', '636');
        $add_srv[] = array($source, $vsys, 'lotusnotes', 'lotusnotes', 'tcp', '1352');  //changed lotus-notes
        $add_srv[] = array($source, $vsys, 'citrix-ica', 'citrix-ica', 'tcp', '1494');  //changed citrix
        $add_srv[] = array($source, $vsys, 'sqlnet', 'sqlnet', 'tcp', '1521'); //changed oracle
        $add_srv[] = array($source, $vsys, 'h323', 'h323', 'tcp', '1720'); //changed h.323
        $add_srv[] = array($source, $vsys, 'pptp', 'pptp', 'tcp', '1723');
        $add_srv[] = array($source, $vsys, 'ctiqbe', 'ctiqbe', 'tcp', '2748');
        $add_srv[] = array($source, $vsys, 'cifs', 'cifs', 'tcp', '3020');
        $add_srv[] = array($source, $vsys, 'aol', 'aol', 'tcp', '5190');  //changed aim
        $add_srv[] = array($source, $vsys, 'pcanywhere-data', 'pcanywhere-data', 'tcp', '5631');
        $add_srv[] = array($source, $vsys, 'time', 'time', 'udp', '37');
        $add_srv[] = array($source, $vsys, 'nameserver', 'nameserver', 'udp', '42');
        $add_srv[] = array($source, $vsys, 'bootps', 'bootps', 'udp', '67');
        $add_srv[] = array($source, $vsys, 'bootpc', 'bootpc', 'udp', '68');
        $add_srv[] = array($source, $vsys, 'tftp', 'tftp', 'udp', '69');
        $add_srv[] = array($source, $vsys, 'ntp', 'ntp', 'udp', '123');
        $add_srv[] = array($source, $vsys, 'netbios-ns', 'netbios-ns', 'udp', '137');
        $add_srv[] = array($source, $vsys, 'netbios-dgm', 'netbios-dgm', 'udp', '138');  //changed netbios-dg
        $add_srv[] = array($source, $vsys, 'netbios-ss', 'netbios-ss', 'udp', '139');  //changed netbios-ss_udp
        $add_srv[] = array($source, $vsys, 'snmp', 'snmp', 'udp', '161');
        $add_srv[] = array($source, $vsys, 'snmptrap', 'snmptrap', 'udp', '162');  //changed snmp-trap
        $add_srv[] = array($source, $vsys, 'xdmcp', 'xdmcp', 'udp', '177');
        $add_srv[] = array($source, $vsys, 'dnsix', 'dnsix', 'udp', '195');
        $add_srv[] = array($source, $vsys, 'mobile-ip', 'mobile-ip', 'udp', '434');  //changed mobile
        $add_srv[] = array($source, $vsys, 'isakmp', 'isakmp', 'udp', '500');
        $add_srv[] = array($source, $vsys, 'biff', 'biff', 'udp', '512');
        $add_srv[] = array($source, $vsys, 'who', 'who', 'udp', '513');
        $add_srv[] = array($source, $vsys, 'syslog', 'syslog', 'udp', '514');
        $add_srv[] = array($source, $vsys, 'rip', 'rip', 'udp', '520');
        $add_srv[] = array($source, $vsys, 'radius', 'radius', 'udp', '1645');
        $add_srv[] = array($source, $vsys, 'radius-acct', 'radius-acct', 'udp', '1646');
        $add_srv[] = array($source, $vsys, 'secureid-udp', 'secureid-udp', 'udp', '5510');
        $add_srv[] = array($source, $vsys, 'pcanywhere-status', 'pcanywhere-status', 'udp', '5632');

        $add_srv[] = array($source, $vsys, 'snmptrap', 'snmptrap', 'udp', '162');
        //        $add_srv[] = array($source,$vsys,'netbios-ssn','netbios-ssn','tcp','139');


        #$out = implode(",", $add_srv);
        #$projectdb->query("INSERT INTO services (source,vsys,name_ext,name,protocol,dport) VALUES " . $out . ";");

        foreach( $add_srv as $service )
        {
            $tmp_tag = $this->sub->tagStore->findOrCreate("default");

            $tmp_service = $this->sub->serviceStore->find($service[2]);
            if( $tmp_service === null )
            {
                if( $service[4] == "" )
                {
                    $tmp_service = $this->sub->serviceStore->find("tmp-" . $service[2]);
                    if( $tmp_service === null )
                    {
                        if( $print )
                            print " * create service Object: tmp-" . $service[2] . ", tcp, " . $service[5] . "\n";
                        $tmp_service = $this->sub->serviceStore->newService("tmp-" . $service[2], "tcp", $service[5]);
                    }
                    $tmp_service->set_node_attribute('error', "no service protocoll - tcp is used");
                }
                else
                {
                    if( $print )
                        print " * create service Object: " . $service[2] . ", " . $service[4] . ", " . $service[5] . "\n";
                    $tmp_service = $this->sub->serviceStore->newService($service[2], $service[4], $service[5]);
                }
                $tmp_service->tags->addTag($tmp_tag);
            }
            elseif( $tmp_service->protocol() != $service[4] && $tmp_service->getDestPort() != $service[2] )
            {
                print "change service name:" . $tmp_service->name() . "\n";
                $tmp_service->setName($tmp_service->protocol() . "-" . $tmp_service->name());
                print "new service name:" . $tmp_service->name() . "\n";

                $tmp_service2 = $this->sub->serviceStore->find($service[4] . "-" . $service[2]);
                if( $tmp_service2 === null )
                {
                    if( $print )
                        print " * create service Object: " . $service[4] . "-" . $service[2] . ", " . $service[4] . ", " . $service[5] . "\n";
                    $tmp_service2 = $this->sub->serviceStore->newService($service[4] . "-" . $service[2], $service[4], $service[5]);

                }

                if( $print )
                {
                    print " * create addressgroup: " . $service[2] . "\n";
                    print "  * add service: " . $tmp_service->name() . "\n";
                    print "  * add service: " . $tmp_service2->name() . "\n";
                }
                $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($service[2]);

                $tmp_servicegroup->tags->addTag($tmp_tag);
                $tmp_service->tags->addTag($tmp_tag);
                $tmp_service2->tags->addTag($tmp_tag);

                $tmp_servicegroup->addMember($tmp_service);
                $tmp_servicegroup->addMember($tmp_service2);
            }
        }

        unset($add_srv);
        #}
    }

}


