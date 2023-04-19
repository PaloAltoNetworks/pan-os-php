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


trait HUAWEIaddress
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


            $addr = explode ( "\n", $address_entry );
            #print_r( $addr );
            /*
             *     [0] => ip address-set nrheai06_09 type object
    [1] =>  address 0 10.15.123.135 0
    [2] =>  address 1 10.15.123.136 0
    [3] =>  address 2 10.15.123.137 0
    [4] =>  address 3 10.15.123.138 0
    [5] => #
             */
            $name = "";
            $ip_addresses = array();
            $is_group = false;

            foreach( $addr as $key => $line )
            {
                if( $line == "#" )
                    continue;

                if( $key == 0 )
                {
                    //find object name
                    $needle1 = "ip address-set ";
                    $needle2 = " type ";
                    $name = $this->find_string_between($line, $needle1, $needle2);

                    $needle1 = " type ";
                    $type = $this->find_string_between($line, $needle1);
                    $type = $this->strip_hidden_chars($type);
                    if( $type == "group" )
                        $is_group = true;

                }
                elseif( (strpos( $line, " description" ) !== false) && (strpos( $line, " description" ) == 0) )
                {
                    print "DESCRIPTION: ".$line."\n";
                }
                else{
                    //create array to add address
                    $ip = explode( " ", $line );
                    if( $ip[3] == "address-set" )
                    {
                        $ip_addresses[] = $ip[4];
                    }
                    elseif( $ip[3] == "range" )
                    {
                        $ip_addresses[] = $ip[4]."-".$ip[5];

                    }
                    else
                    {
                        $address = $ip[3];
                        #print "LINE: ".$line."\n";
                        #print_r( $ip );

                        if( strpos( $line, "mask" ) !== false )
                        {
                            $address = $this->calculate_address_mask( $ip[3], $ip[5] );

                            /*
                            $ip[5] = $this->strip_hidden_chars( $ip[5] );

                            #print "MASK: ".$ip[5]."\n";

                            if( strpos( $ip[5], "." ) !== false )
                            {
                                #$address .= "/".CIDR::cidr2netmask( $ip[5] );
                                if( (strpos( $ip[5], "0." ) !== false) && (strpos( $ip[5], "0." ) == 0) )
                                {
                                    $netmask = $this->wildcardnetmask2netmask( $ip[5] );
                                    $netmask = CIDR::netmask2cidr( $netmask );
                                }

                                else
                                    $netmask = CIDR::netmask2cidr( $ip[5] );
                            }
                            else
                                $netmask = $ip[5];

                            if( $netmask != '32' )
                                $address .= "/".$netmask ;
                            */
                        }
                        elseif( strpos( $ip[4], "." ) !== false )
                        {
                            $address = $this->calculate_address_mask( $ip[3], $ip[4] );
                            /*
                            $ip[4] = $this->strip_hidden_chars( $ip[4] );
                            
                            if( (strpos( $ip[4], "0." ) !== false) && (strpos( $ip[4], "0." ) == 0) )
                            {
                                $netmask = $this->wildcardnetmask2netmask( $ip[4] );
                                $netmask = CIDR::netmask2cidr( $netmask );
                            }

                            else
                                $netmask = CIDR::netmask2cidr( $ip[4] );

                            if( $netmask != '32' )
                                $address .= "/".$netmask ;
                            */
                        }

                        #print "ADD: ".$this->strip_hidden_chars( $address )."\n";
                        $ip_addresses[] = $this->strip_hidden_chars( $address );
                    }

                }
            }

            /*
            print "NAME: ".$name."\n";
            if( $is_group )
                print "GROUP\n";
            print_r( $ip_addresses );
*/
            #exit;



            $name = $this->truncate_names($this->normalizeNames($name));
            $tmp_address = $this->sub->addressStore->find($name);
            if( $tmp_address == null )
            {
                if( count( $ip_addresses ) > 1 || count( $ip_addresses ) == 0 )
                {
                    //create address_group first
                    if( $print )
                        print "\n" . $padding_name . "* name: " . $name . "\n";
                    $tmp_addressgroup = $this->sub->addressStore->newAddressgroup($name);

                    foreach( $ip_addresses as $ip_obj )
                    {
                        if( strpos( $ip_obj, "." ) != false )
                        {
                            #print "FIND: ".$ip_obj."\n";
                            $name = $this->truncate_names($this->normalizeNames($ip_obj));
                            $tmp_address = $this->sub->addressStore->find($name);

                            if( $tmp_address == null )
                            {
                                if( strpos( $ip_obj, "-" ) !== false )
                                {
                                    $type = 'range';
                                }
                                else
                                    $type = "ip-netmask";

                                if( $print )
                                    print $padding_name . "* name: '" . $name . "' type: '" . $type . "' value: ";

                                if( $type == 'ip-netmask')
                                {
                                    if( $print )
                                        print $ip_obj . "'\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-netmask', $ip_obj);
                                }
                                elseif( $type == 'range' )
                                {
                                    if( $print )
                                        print $ip_obj . "'\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-range', $ip_obj);
                                }
                            }

                        }
                        else
                        {
                            //searach addr_group
                            $name = $this->truncate_names($this->normalizeNames($ip_obj));
                            $tmp_address = $this->sub->addressStore->find($name);
                            if( $tmp_address == null )
                                mwarning( "addressgroup: '".$name. "' not found\n" );
                        }

                        if( $tmp_address != null )
                        {
                            if( $print )
                                print $padding . "- member name: '" . $tmp_address->name() . "'\n";

                            $tmp_addressgroup->addMember($tmp_address);
                        }
                    }
                }
                else
                {
                    if( isset( $ip_addresses[0] ) )
                    {
                        $name = $this->truncate_names($this->normalizeNames($ip_addresses[0]));
                        $tmp_address = $this->sub->addressStore->find($name);

                        if( $tmp_address == null )
                        {

                            if( strpos($ip_addresses[0], "-") !== FALSE )
                            {
                                $type = 'range';
                            }
                            else
                                $type = "ip-netmask";

                            if( $print )
                                print $padding_name . "* name: '" . $name . "' type: '" . $type . "' value: ";

                            if( $type == 'ip-netmask' )
                            {
                                if( $print )
                                    print  $ip_addresses[0] . "'\n";
                                $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-netmask', $ip_addresses[0]);
                            }
                            elseif( $type == 'range' )
                            {
                                if( $print )
                                    print  $ip_addresses[0] . "'\n";
                                $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-range', $ip_addresses[0]);
                            }
                        }
                    }
                    else
                    {
                        if( $print )
                            print "\n" . $padding_name . "* name: " . $name . "\n";
                        $tmp_addressgroup = $this->sub->addressStore->newAddressgroup($name);

                        print_r( $ip_addresses );
                        mwarning( "why empyty array???" );
                    }


                }

                /*
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
                */

            }
        }
    }



}

