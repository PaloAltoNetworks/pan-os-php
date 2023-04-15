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

trait SCREENOSaddresses
{

    function get_address_SCREENOS($screenos_config_file)
    {

        global $debug;
        global $print;
        $source = "";
        $add_address = array();
        $vsys = "root";


        foreach( $screenos_config_file as $line => $names_line )
        {
            $names_line = trim($names_line);

            if( preg_match("/^set vsys /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $vsys = $data[2];
            }
            if( preg_match("/^set address /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                if( isset($data[4]) )
                {
                    $name_ext = $data[3];
                    $zone = $data[2];

                    $name_int = str_replace("/", "_", $name_ext);
                    $name_int = $this->truncate_names($this->normalizeNames($name_int));

                    $ipaddressCheck = $data[4];
                    $ipversionCheck = $this->ip_version($ipaddressCheck);
                    if( $ipversionCheck == "noip" )
                    {
                        if( isset($data[5]) )
                        {
                            $description = addslashes(trim($data[5]));
                        }
                        else
                        {
                            $description = "";
                        }
                        if( preg_match("/\//", $ipaddressCheck) )
                        {
                            #Mode ip/mask
                            $ipnetmask = explode("/", $ipaddressCheck);
                            $ipaddress = $ipnetmask[0];
                            $ipversion = $this->ip_version($ipaddress);
                            $cidr = $ipnetmask[1];
                            $add_address[] = array('ip-netmask', $name_ext, '0', $source, '0', $ipaddress, $cidr, $description, $name_int, $vsys, $zone);
                        }
                        else
                        {
                            #Is FQDN
                            $valid = FALSE;
                            if( isset($data[5]) )
                            {
                                $valid = filter_var($data[5], FILTER_VALIDATE_IP);
                            }
                            if( $valid )
                            {
                                $ipaddress = $ipaddressCheck;
                                $netmask = $data[5];
                                $cidr = $this->mask2cidrv4($netmask);
                                $add_address[] = array('ip-netmask', $name_ext, '1', $source, '0', '1.1.1.1', $cidr, $description, $name_int, $vsys, $zone);
                                #add_log('error', 'Adding Address', 'Invalid IP address [' . $ipaddress . '] found in Object [' . $name_ext . ']', $source, 'Add right IP address to this Object');
                            }
                            else
                            {
                                $ipaddress = $ipaddressCheck;
                                $add_address[] = array('fqdn', $name_ext, '0', $source, '0', $ipaddress, '32', $description, $name_int, $vsys, $zone);
                            }
                        }
                    }
                    else
                    {
                        $ipaddress = $ipaddressCheck;
                        $netmask = $data[5];
                        if( isset($data[6]) )
                        {
                            $description = addslashes(trim($data[6]));
                        }
                        else
                        {
                            $description = "";
                        }
                        $cidr = $this->mask2cidrv4($netmask);

                        $table = "address";
                        $add_address[] = array('ip-netmask', $name_ext, '0', $source, '0', $ipaddress, $cidr, $description, $name_int, $vsys, $zone);
                    }
                }
                else
                {
                    mwarning("check set address line: " . $names_line, null, FALSE);
                }
            }
        }

        if( count($add_address) > 0 )
        {
            foreach( $add_address as $address_object )
            {
                if( $address_object[9] == "root" )
                {
                    $this->template_vsys = $this->template->findVirtualSystem('vsys1');
                    if( $this->template_vsys === null )
                    {
                        derr("vsys: " . $address_object[9] . " could not be found ! Exit\n");
                    }
                }
                else
                {
                    // Did we find VSYS1 ?
                    $this->template_vsys = $this->template->findVSYS_by_displayName($address_object[9]);
                    if( $this->template_vsys === null )
                    {
                        derr("vsys: " . $address_object[9] . " could not be found ! Exit\n");
                    }
                }

                if( $address_object[9] == 'Global' )
                    $addressStore = $this->pan->addressStore;
                else
                    $addressStore = $this->sub->addressStore;

                $tmp_object = $this->sub->addressStore->find($address_object[8]);
                if( $tmp_object == null )
                {
                    if( $address_object[0] == 'ip-netmask' )
                    {
                        if( $print )
                            print "create address object: " . $address_object[8] . " - value: " . $address_object[5] . "\n";
                        if( $address_object[6] == "" )
                        {
                            $tmp_object = $this->sub->addressStore->newAddress($address_object[8], $address_object[0], $address_object[5]);
                        }
                        else
                        {
                            $tmp_object = $this->sub->addressStore->newAddress($address_object[8], $address_object[0], $address_object[5] . "/" . $address_object[6]);
                        }


                        #print "create address object ip netmask: ".$address_object[1]." for vsys: ".$this->sub->name()."\n";
                    }
                    elseif( $address_object[0] == 'fqdn' )
                    {
                        if( $print )
                            print "create address object: " . $address_object[1] . " - value: " . $address_object[0] . "\n";
                        $tmp_object = $this->sub->addressStore->newAddress($address_object[1], $address_object[0], $address_object[5]);
                        #print "create address object fqdn : ".$address_object[1]."\n";
                    }
                }
                else
                {
                    //20190429 Sven
                    //if object is available check if different zone
                }
            }

            unset($add_address);
        }
    }

    function get_address_groups($screenos_config_file )
    {
        global $debug;
        global $print;

        $this->template_vsys = $this->template->findVirtualSystem('vsys1');
        if( $this->template_vsys === null )
        {
            derr("vsys: vsys1 could not be found ! Exit\n");
        }


        foreach( $screenos_config_file as $line => $names_line )
        {
            $names_line = trim($names_line);


            if( preg_match("/^set vsys /i", $names_line) )
            {
                $this->vsys_parser($names_line);
            }

            if( preg_match("/^set group address /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $zone = $data[3];
                $name_ext = $data[4];
                $name_ext = $this->truncate_names($this->normalizeNames($name_ext));

                if( $zone == 'Global' )
                    $addressStore = $this->pan->addressStore;
                else
                    $addressStore = $this->sub->addressStore;

                $tmp_addressgroup = $this->sub->addressStore->find($name_ext);
                if( $tmp_addressgroup == null )
                {
                    if( $print )
                        print "create addressgroup object: " . $name_ext . "\n";
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($name_ext);
                    #print "create addressgroup object: ".$name_ext."\n";
                }
                else
                {
                    //Todo: check if addressgroup of different Zone is already available,
                    //if available address object is not allowed to be a member of this group
                    #if( $debug )
                    #mwarning( "addresgroup ".$name_ext." already available\n", null, false );
                }

                if( isset($data[5]) )
                {
                    switch ($data[5])
                    {
                        case "comment":
                            $comment = $data[6];
                            $tmp_addressgroup->setDescription($comment);
                            break;

                        case "add":
                            $member = $data[6];
                            #$member = $this->truncate_names($this->normalizeNames($member));
                            $tmp_object = $this->sub->addressStore->find($member);
                            if( $tmp_object !== null )
                            {
                                $tmp_addressgroup->addMember($tmp_object);
                            }
                            else
                            {
                                $member = str_replace("/", "_", $member);
                                $member = str_replace(":", "", $member);
                                $member = $this->truncate_names($this->normalizeNames($member));

                                $tmp_object = $this->sub->addressStore->find($member);
                                if( $tmp_object !== null )
                                {
                                    $tmp_addressgroup->addMember($tmp_object);
                                }
                                else
                                {
                                    #add_log2("error",'Importing Address groups','The address group called [' . $member . '] provides an unknwon '. $data[5].' action',$source, "Review address group $member",'objects',$addrGroupObj[$member][$zone]->getLid(),'address_groups_id');
                                    //                             echo "ERROR ".$member.PHP_EOL;
                                    print "can not find address object/ addressgroup: " . $member . " in vsys: " . $this->sub->name() . " - " . $this->sub->alternativeName() . "\n";
                                }
                            }
                            break;

                        default:
                    }
                }
            }
        }
    }


}

