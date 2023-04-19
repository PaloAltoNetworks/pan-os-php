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


trait SONICWALLaddress
{
    #print_r( $address );
    #print_r( $services );

    function add_address( $address)
    {
        global $debug;
        global $print;

        $padding = "   ";
        $padding_name = substr($padding, 0, -1);

        #print_r( $address );
        //working

        foreach( $address as $key => $address_entry )
        {
            $ii = 0;
            #print_r( $address_entry );
            /*
                        [0] => ipv4
                    [1] => X0 IP
                    [2] => uuid
                    [3] => cfeeb502-52cf-c94a-0100-c0eae48f6104
                    [4] => zone
                    [5] => LAN
                    [6] => host
                    [7] => 10.83.4.10*/

            if( strpos($address_entry, "name") !== FALSE )
            {

                $address_entry = explode('"', $address_entry);

                if( count($address_entry) == 1 )
                {
                    $tmp_address_entry = explode(" ", $address_entry[$ii]);
                    foreach( $tmp_address_entry as $tmp2 )
                    {
                        $address_entry[] = trim($tmp2);
                    }

                    unset($address_entry[$ii]);
                    unset($address_entry[$ii + 3]);
                    unset($address_entry[$ii + 4]);
                }
                else
                {
                    unset($address_entry[$ii + 2]);
                    unset($address_entry[$ii + 3]);
                    foreach( $address_entry as $key => $tmp )
                    {
                        $address_entry[$key] = trim($tmp);
                        if( $key == ($ii + 4) )
                        {
                            unset($address_entry[$key]);
                            $tmp = trim($tmp);
                            foreach( explode(" ", $tmp) as $tmp2 )
                            {
                                $address_entry[] = $tmp2;
                            }
                        }
                    }
                }

            }
            else
            {
                $address_entry = explode('"', $address_entry);

                if( count($address_entry) == 1 )
                {
                    $address_entry = explode(' ', $address_entry[$ii]);
                }
                else
                {
                    //cleanup blank at beginning or end
                    foreach( $address_entry as $key => $tmp_address_entry )
                    {
                        $tmp_fix_entry = trim($tmp_address_entry);
                        $address_entry[$key] = $tmp_fix_entry;

                        if( $key == ($ii + 2) )
                        {
                            unset($address_entry[$ii + 2]);
                            $tmp_entry = explode(' ', $tmp_fix_entry);
                            $address_entry = array_merge($address_entry, $tmp_entry);
                        }
                    }
                }

            }
            $address_entry = array_values($address_entry);


            //Todo: bring in name validation
            if( isset($address_entry[$ii + 1]) )
                $name = $address_entry[$ii + 1];
            else
                if( $debug )
                {
                    print $padding . " no name found\n";
                    print_r($address_entry);
                }

            if( isset($address_entry[$ii + 2]) )
                $type = $address_entry[$ii + 2];
            else
                if( $debug )
                {
                    print $padding . " no name found\n";
                    print_r($address_entry);
                }


            $ipversion = $address_entry[0];

            if( $ipversion != "ipv4" && $ipversion != "ipv6" )
            {
                if( $debug )
                {
                    print $padding_name . "* name: " . $name . "\n";
                    print $padding . "X ipversion: " . $ipversion . " not supported\n";
                    if( $debug )
                        print_r($address_entry);

                    $tmp_address = $this->sub->addressStore->find("TMP_" . $name);
                    if( $tmp_address == null )
                        $tmp_address = $this->sub->addressStore->newAddress("TMP_" . $name, 'ip-netmask', "1.1.1.1");
                    $tmp_address->set_node_attribute('error', "address object name: 'TMP_" . $name . "' has not supported ipversion: " . $ipversion);
                    #print_r( $address_entry );
                }
                continue;
            }


            if( $type == "host" )
            {
                //address-object ipv4 ops-vpn.tamu.edu host 165.91.138.4 zone LAN
                if( isset($address_entry[3]) )
                    $ip = $address_entry[3];
                else
                    if( $debug )
                    {
                        print $padding . "X no IP available\n";
                        print_r($address_entry);
                    }

                if( $ipversion == "ipv4" )
                    $netmask = "32";
                elseif( $ipversion == "ipv6" )
                {
                    if( isset($address_entry[4]) )
                    {
                        if( $address_entry[4] != "zone" )
                            $netmask = str_replace("/", "", $address_entry[4]);
                        else
                            $netmask = "0";
                    }
                    else
                    {
                        $netmask = "0";
                    }
                }

                if( isset($address_entry[5]) )
                    $zone = $address_entry[5];
                else
                    if( $debug )
                        print $padding . "X no zone available\n";
            }
            elseif( $type == "network" )
            {
                if( isset($address_entry[3]) )
                {
                    $ip = $address_entry[3];
                }
                else
                    if( $debug )
                    {
                        print $padding . "X no IP available\n";
                        print_r($address_entry);
                    }

                if( $ipversion == "ipv4" )
                {
                    #$netmask = cidr::cidr2netmask( $address_entry[4] );
                    $netmask = cidr::netmask2cidr($address_entry[4]);

                    if( isset($address_entry[6]) )
                        $zone = $address_entry[6];
                    else
                        if( $debug )
                            print $padding . "X no zone available\n";
                }
                elseif( $ipversion == "ipv6" )
                {
                    if( $address_entry[4] != "zone" )
                        $netmask = str_replace("/", "", $address_entry[4]);
                    else
                        $netmask = "0";
                }


            }
            elseif( $type == "range" )
            {
                $ip = $address_entry[3];
                $endip = $address_entry[4];
                $zone = $address_entry[6];
            }
            elseif( $type == "fqdn" )
            {
                /*
                 address-object fqdn ftp-edi.pubnet.org domain ftp-edi.pubnet.org zone WAN
                 */
                print_r($address_entry);
            }
            else
            {
                if( $debug )
                {
                    mwarning("address object type: '" . $address_entry[2] . "' is not supported.\n", null, FALSE);
                    print_r($address_entry);
                }

            }
            $name = $this->truncate_names($this->normalizeNames($name));
            $tmp_address = $this->sub->addressStore->find($name);
            if( $tmp_address == null )
            {
                if( $print )
                    print $padding_name . "* name: '" . $name . "' type: '" . $type . "' value: ";

                if( $type == 'host' || $type == 'network' )
                {
                    if( $print )
                        print "'" . $ip . "/" . $netmask . "'\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-netmask', $ip . "/" . $netmask);
                }
                elseif( $type == 'range' )
                {
                    if( $print )
                        print "'" . $ip . "-" . $endip . "'\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-range', $ip . "-" . $endip);
                }

            }
        }
    }

    function add_address_fqdn( $fqdn)
    {
        global $debug;
        global $print;

        $padding = "   ";
        $padding_name = substr($padding, 0, -1);

        #print_r( $fqdn );
        //working

        #print "output fqdn\n";

        foreach( $fqdn as $key => $fqdn_entry )
        {


            $fqdn_entry = explode('"', $fqdn_entry);

            if( count($fqdn_entry) == 1 )
            {
                $fqdn_entry = explode(' ', $fqdn_entry[0]);
            }
            else
            {

                $fqdn_entry[0] = trim($fqdn_entry[0]);
                $tmp_fqdn1 = trim($fqdn_entry[2]);
                unset($fqdn_entry[2]);
                $fqdn_entry2 = explode(' ', $tmp_fqdn1);

                $fqdn_entry = array_merge($fqdn_entry, $fqdn_entry2);
            }

            #print_r( $fqdn_entry );


            if( isset($fqdn_entry[0]) && isset($fqdn_entry[2]) && $fqdn_entry[0] == "fqdn" && $fqdn_entry[2] == "domain" )
            {
                if( isset($fqdn_entry[1]) && isset($fqdn_entry[3]) )
                {
                    $name = $fqdn_entry[1];
                    $fqdn = $fqdn_entry[3];

                    if( $print )
                        print $padding . " * create address: '" . $name . "' with fqdn: " . $fqdn . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name, 'fqdn', $fqdn);
                }

            }


            /*
                 [0] => fqdn
        [1] => edi.lightningsource.com
        [2] => domain
        [3] => edi.lightningsource.com
        [4] => zone
        [5] => WAN
        [6] => no
        [7] => dns-ttl
             */
        }
    }

}

