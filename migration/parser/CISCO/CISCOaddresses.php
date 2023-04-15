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

trait CISCOaddresses
{

    public function get_object_network()
    {
        global $projectdb;

        global $debug;
        global $print;

        $addHost = array();
        $AddDescription = array();
        $isObjectNetwork = 0;
        $nat_lid = "";
        $ObjectNetworkName = "";
        $ObjectNetworkNamePan = "";
        $vsys = $this->template_vsys->name();

        $source = "";

        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);

            if( $names_line == "!" || preg_match("/^object-group network/i", $names_line) )
            {
                $isObjectNetwork = 0;
            }

            if( $isObjectNetwork == 1 )
            {
                $found = FALSE;
                $tmp_address = $this->sub->addressStore->find($ObjectNetworkNamePan);

                if( preg_match("/^host/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $ipaddress = $netObj[1];

                    if( $tmp_address !== null )
                    {
                        if( $tmp_address->isAddress() && $tmp_address->isType_ipNetmask() && $ipaddress == $tmp_address->value() )
                            $found = TRUE;
                    }

                    if( !$found && $tmp_address === null )
                    {
                        $ipversion = $this->ip_version($ipaddress);
                        if( $ipversion == "v4" )
                        {
                            $hostCidr = "32";
                            $addHost["ipv4"][] = array($ObjectNetworkNamePan, 'ip-netmask', $ObjectNetworkName, '0', $source, '0', $ipaddress, $hostCidr, '1', $vsys, 'object');
                        }
                        elseif( $ipversion == "v6" )
                        {
                            $hostCidr = "128";
                            $addHost["ipv6"][] = array($ObjectNetworkNamePan, 'ip-netmask', $ObjectNetworkName, '0', $source, '0', $ipaddress, $hostCidr, '1', $vsys, 'object', '0');
                        }
                    }
                    else
                        mwarning("object: " . $ObjectNetworkNamePan . " already available", null, FALSE);
                }
                elseif( preg_match("/^\bfqdn\b/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $fqdn = $netObj[1];
                    if( ($fqdn == "v4") or ($fqdn == "v6") )
                    {
                        $fqdn = $netObj[2];
                    }

                    if( $tmp_address !== null )
                    {
                        if( $tmp_address->isAddress() && $tmp_address->isType_FQDN() && $fqdn == $tmp_address->value() )
                            $found = TRUE;
                    }

                    if( !$found )
                    {
                        $addHost["ipv4"][] = array($ObjectNetworkNamePan, 'fqdn', $ObjectNetworkName, '0', $source, '0', $fqdn, '', '1', $vsys, 'object');
                    }
                }
                elseif( preg_match("/^\bsubnet\b/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $ipaddress = $netObj[1];

                    if( $tmp_address !== null )
                    {
                        if( $tmp_address->isAddress() && $tmp_address->isType_ipNetmask() && $ipaddress == $tmp_address->value() )
                            $found = TRUE;
                    }

                    if( !$found )
                    {
                        $ipversion = $this->ip_version($ipaddress);
                        if( $ipversion == "v4" )
                        {
                            $hostCidr = $netObj[2];
                            $tmp_hostCidr = $this->mask2cidrv4(rtrim($hostCidr));

                            if( !is_int( $tmp_hostCidr ) )
                            {
                                //print "WILDCARD\n";
                                //print "VALUE: ".$ipaddress."\n";
                                //print "NETMASK: ".$hostCidr."\n";

                                $cidr_array = explode(".", $hostCidr);
                                $tmp_hostCidr = "";
                                foreach( $cidr_array as $key => &$entry )
                                {
                                    $final_entry = 255 - (int)$entry;
                                    if( $key == 0 )
                                        $tmp_hostCidr .= $final_entry;
                                    else
                                        $tmp_hostCidr .= ".".$final_entry;
                                }

                                //print $tmp_hostCidr."\n";

                                //$tmp_address = $this->MainAddHost($name, $value);

                                $tmp_name = $ipaddress."m".$tmp_hostCidr;
                                $type = 'ip-wildcard';
                                $value = $ipaddress;
                                $netmask = $tmp_hostCidr;
                            }
                            else
                            {
                                $hostCidr = $tmp_hostCidr;
                                $tmp_name = $ObjectNetworkName;
                                $type = 'ip-netmask';
                                $value = $ipaddress;
                                $netmask = $hostCidr;
                            }

                            $addHost["ipv4"][] = array($ObjectNetworkNamePan, $type, $tmp_name, '0', $source, '0', $value, $netmask, '1', $vsys, 'object');
                        }
                        elseif( $ipversion == "v6" )
                        {
                            $split = explode("/", $ipaddress);
                            $ipaddress = $split[0];
                            $hostCidr = $split[1];

                            $addHost["ipv6"][] = array($ObjectNetworkNamePan, 'ip-netmask', $ObjectNetworkName, '0', $source, '0', $ipaddress, $hostCidr, '1', $vsys, 'object', '0');
                        }
                    }
                }
                elseif( preg_match("/^\brange\b/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $first_ipaddress = $netObj[1];
                    $last_ipaddress = $netObj[2];

                    if( $tmp_address !== null )
                    {
                        if( $tmp_address->isAddress() && $tmp_address->isType_ipRange() && ($first_ipaddress . "-" . $last_ipaddress) == $tmp_address->value() )
                            $found = TRUE;
                    }

                    if( !$found )
                    {
                        $ipversion = $this->ip_version($first_ipaddress);
                        if( $ipversion == "v4" )
                        {
                            $addHost["ipv4"][] = array($ObjectNetworkNamePan, 'ip-range', $ObjectNetworkName, '0', $source, '0', $first_ipaddress . "-" . $last_ipaddress, '', '1', $vsys, 'object');
                        }
                        elseif( $ipversion == "v6" )
                        {
                            $addHost["ipv6"][] = array($ObjectNetworkNamePan, 'ip-range', $ObjectNetworkName, '0', $source, '0', $first_ipaddress . "-" . $last_ipaddress, '', '1', $vsys, 'object', '0');
                        }
                    }
                }
                elseif( preg_match("/^\bdescription\b/i", $names_line) )
                {
                    $netObj = preg_split('/description /', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $description = addslashes($netObj[0]);
                    $description = str_replace("\n", '', $description); // remove new lines
                    $description = str_replace("\r", '', $description);
                    #$AddDescription[] = "UPDATE address SET description='$description' WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$ObjectNetworkName' AND vtype='object'";
                    if( isset($AddDescription[$ObjectNetworkNamePan]) )
                        $AddDescription[$ObjectNetworkNamePan] .= $description;
                    else
                        $AddDescription[$ObjectNetworkNamePan] = $description;
                }
            }

            if( preg_match("/^object network/i", $names_line) )
            {
                $isObjectNetwork = 1;
                $names = explode(" ", $names_line);
                $ObjectNetworkName = rtrim($names[2]);
                $ObjectNetworkNamePan = $this->truncate_names($this->normalizeNames($ObjectNetworkName));
            }
        }

        #return null;

        if( isset($addHost["ipv4"]) && count($addHost["ipv4"]) > 0 )
        {
            foreach( $addHost["ipv4"] as $address_object )
            {
                if( $address_object[1] == "ip-range" || $address_object[1] == "fqdn" )
                {
                    $IPvalue = $address_object[6];
                }
                elseif( $address_object[1] == "ip-netmask" || $address_object[1] == "ip-wildcard" )
                {
                    $IPvalue = $address_object[6] . "/" . $address_object[7];
                }

                $this->MainAddHost( $address_object[0], $IPvalue, $address_object[1] );
            }
            unset($addHost["ipv4"]);
        }
        if( isset($addHost["ipv6"]) && count($addHost["ipv6"]) > 0 )
        {
            #print_r( $addHost["ipv6"]);

            foreach( $addHost["ipv6"] as $address_object )
            {
                if( $address_object[1] == "ip-range" || $address_object[1] == "fqdn" )
                {
                    $IPvalue = $address_object[6];
                }
                elseif( $address_object[1] == "ip-netmask" || $address_object[1] == "ip-wildcard" )
                {
                    $IPvalue = $address_object[6]. "/" . $address_object[7];
                }

                $this->MainAddHost( $address_object[0], $IPvalue, $address_object[1]  );
            }
            unset($addHost["ipv6"]);
        }
        if( count($AddDescription) > 0 )
        {
            foreach( $AddDescription as $address_object => $description )
            {
                $tmp_address = $this->sub->addressStore->find($address_object);
                if( $tmp_address !== null )
                    $tmp_address->setDescription($description);
            }
            unset($AddDescription);
        }
    }



    public function get_objectgroup_network2()
    {
        global $projectdb;
        global $debug;
        global $print;

        $isObjectGroup = 0;
        $addHost = array();
        $addMember = array();
        $addMember2 = array();
        $addGroups = array();

        $source = '';
        $vsys = $this->template_vsys->name();

        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);

            if( preg_match("/^object-group network/i", $names_line) )
            {
                #$groupLid++;
                $isObjectGroup = 1;
                $names = explode(" ", $names_line);
                $HostGroupName = rtrim($names[2]);
                $HostGroupNamePan = $this->truncate_names($this->normalizeNames($HostGroupName));
                #$addGroups[] = "($groupLid,'$HostGroupNamePan','$HostGroupName','$source','$vsys')";

                $addressGroupData = [
                    'name' => $HostGroupName,
                    'type' => 'static',
                    #'id'    => $groupLid,
                    'source' => $source,
                    'vsys' => $vsys
                ];

                $tmp_addressgroup = $this->sub->addressStore->find($HostGroupNamePan);
                if( $tmp_addressgroup === null )
                {
                    if( $print )
                        print "\n * create addressgroup: " . $HostGroupNamePan . "\n";
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($HostGroupNamePan);
                }
                else
                {
                    mwarning("addressgroup: " . $HostGroupNamePan . " already available\n", null, FALSE);
                    if( $tmp_addressgroup->isAddress() )
                    {
                        $addlog = "an addressgroup same name; member:" . $names_line;
                        $tmp_addressgroup->set_node_attribute('error', $addlog);


                        if( $print )
                            print "\n * create addressgroup: tmp_" . $HostGroupNamePan . "\n";
                        $tmp_addressgroup = $this->sub->addressStore->newAddressGroup("tmp_" . $HostGroupNamePan);
                    }

                }
            }
            else
            {
                if( ($isObjectGroup == 1) and
                    (!preg_match("/\bnetwork-object\b/", $names_line)) and
                    (!preg_match("/\bdescription\b/", $names_line)) and
                    (!preg_match("/\bgroup-object\b/", $names_line)) and
                    (!preg_match("/\brange\b/", $names_line)) )
                {
                    $isObjectGroup = 0;
                }

                if( $isObjectGroup == 1 )
                {
                    if( preg_match("/network-object/i", $names_line) && !preg_match("/description/i", $names_line) )
                    {
                        $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);


                        if( isset($netObj[2]) )
                        {
                            $type = $netObj[1];
                            $obj2 = rtrim($netObj[2]);
                            $value = $obj2;
                            $obj2 = str_replace(":", "_", $obj2);
                            $obj2 = str_replace("/", "m", $obj2);
                            $obj2 = $this->truncate_names($this->normalizeNames($obj2));
                        }

                        else
                        {
                            $obj2 = rtrim($netObj[1]);
                            $value = $obj2;
                            $type = $value;
                            $obj2 = str_replace(":", "_", $obj2);
                            $obj2 = str_replace("/", "m", $obj2);
                            $obj2 = $this->truncate_names($this->normalizeNames($obj2));

                            $tmp_hostCidr = explode("/", $value);
                            $hostCidr = $tmp_hostCidr[1];

                            #print_r( $netObj );
                            #mwarning( "netObj[2] not set [could be IPv6????]: ".$names_line , null, false);
                            #continue;
                        }


                        if( $type == "host" )
                        {
                            $ipversion = $this->ip_version($value);
                            if( $ipversion == "v4" )
                            {
                                $hostCidr = 32;
                                $tmp_prefix = "H-";
                            }
                            elseif( $ipversion == "v6" )
                            {
                                $hostCidr = 128;
                                $tmp_prefix = "H-";
                            }
                            else
                            {
                                $hostCidr = null;
                                #$tmp_prefix = "XYZ";
                                $tmp_prefix = "";
                            }

                            $tmp_address = $this->sub->addressStore->find($tmp_prefix . $obj2);
                            if( $tmp_address === null )
                            {
                                if( $hostCidr !== null )
                                    $value = $value . "/" . $hostCidr;
                                else
                                {
                                    $value = $value;
                                    #print "LINE: ".$names_line."\n";
                                }


                                if( $print )
                                    print "  * create address object: " . $tmp_prefix . $obj2 . " , value: " . $value . "\n";
                                $tmp_address = $this->sub->addressStore->newAddress($tmp_prefix . $obj2, 'ip-netmask', $value);
                            }
                            if( $tmp_address !== null )
                            {
                                //if( !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address ){
                                if( $print )
                                {
                                    print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                }

                                $tmp_addressgroup->addMember($tmp_address);
                            }
                            elseif( $type == "object" )
                            {
                                $tmp_address = $this->sub->addressStore->find($obj2);
                                if( $tmp_address === null )
                                {
                                    mwarning("addressobject: " . $obj2 . " not found \n", null, FALSE);
                                }
                                if( $tmp_address !== null )
                                {
                                    //if( !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address ){
                                    if( $print )
                                    {
                                        print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                    }

                                    $tmp_addressgroup->addMember($tmp_address);
                                    /*}
                                    else
                                    {
                                        if( $print )
                                        {
                                            print "    * addressobject: " . $tmp_address->name() . " already a member or submember of addressgroup: " . $tmp_addressgroup->name() . "\n";
                                        }
                                    }*/
                                }

                            }
                            else
                            {
                                $ipversion = $this->ip_version($type);


                                $obj2 = $type;
                                if( $ipversion == "v4" )
                                {
                                    #$hostCidr = $this->mask2cidrv4(rtrim($netObj[2]));
                                    $hostCidr = $this->mask2cidrv4(rtrim($value));
                                    $float_hostCidr = (float)$hostCidr;

                                    if( (int)$float_hostCidr != $float_hostCidr )
                                    {
                                        $hostCidr = "32";
                                    }


                                    if( $hostCidr == "32" )
                                    {
                                        $NameComplete = "H-$obj2";
                                    }
                                    else
                                    {
                                        $NameComplete = "N-$obj2-$hostCidr";
                                    }

                                    $tmp_address = $this->sub->addressStore->find($NameComplete);
                                    if( $tmp_address === null )
                                    {
                                        if( $print )
                                            print "  * create address object: " . $NameComplete . " | value: " . $obj2 . ", CIDR: " . $hostCidr . "\n";
                                        $tmp_address = $this->sub->addressStore->newAddress($NameComplete, 'ip-netmask', $obj2 . "/" . $hostCidr);
                                    }
                                    if( $tmp_address !== null )
                                    {
                                        //if( !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address ){
                                        if( $print )
                                        {
                                            print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                        }

                                        $tmp_addressgroup->addMember($tmp_address);
                                        /*}
                                        else
                                        {
                                            if( $print )
                                            {
                                                print "    * addressobject: " . $tmp_address->name() . " already a member or submember of addressgroup: " . $tmp_addressgroup->name() . "\n";
                                            }
                                        }*/
                                    }

                                }
                                elseif( $ipversion == "v6" )
                                {
                                    //TODO SVEN waschkut 20190625
                                    #mwarning( "IPv6 found, not implemented in this case" );
                                    # TO BE IMPLEMENTED

                                    $obj2 = rtrim($netObj[1]);
                                    $value = $obj2;
                                    $type = $value;
                                    $obj2 = str_replace(":", "_", $obj2);
                                    $obj2 = str_replace("/", "m", $obj2);
                                    $obj2 = $this->truncate_names($this->normalizeNames($obj2));

                                    $tmp_hostCidr = explode("/", $value);
                                    $hostCidr = $tmp_hostCidr[1];

                                    $tmp_address = $this->sub->addressStore->find($obj2);
                                    if( $tmp_address === null )
                                    {
                                        if( $print )
                                            print "  * create address object: " . $obj2 . " with value: " . $value . "\n";
                                        $tmp_address = $this->sub->addressStore->newAddress($obj2, 'ip-netmask', $value);
                                    }

                                    if( $tmp_address !== null )
                                    {
                                        //if( !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address ){
                                        if( $print )
                                        {
                                            print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                        }

                                        $tmp_addressgroup->addMember($tmp_address);
                                        /*}
                                        else
                                        {
                                            if( $print )
                                            {
                                                print "    * addressobject: " . $tmp_address->name() . " already a member or submember of addressgroup: " . $tmp_addressgroup->name() . "\n";
                                            }
                                        }
                                        */
                                    }
                                }
                                else
                                {
                                    #NAME CHECKAR si name y cidr o name solo o si es name solo o name-cidr
                                    $hostCidr = $this->mask2cidrv4(rtrim($netObj[2]));

                                    #$addressObj = $objectsInMemory->getAddressReference($fileName, $source, $vsys,$obj2, $hostCidr);
                                    #$addMember2[] = "('$groupLid','H-$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";
                                    $tmp_address = $this->sub->addressStore->find($obj2);
                                    if( $tmp_address === null )
                                    {
                                        if( $hostCidr !== null )
                                        {
                                            $value = $obj2 . "/" . $hostCidr;
                                            $tmp_prefix = "H-";
                                        }

                                        else
                                        {
                                            $value = $obj2;
                                            $tmp_prefix = "";
                                            #print "LINE: ".$names_line."\n";
                                        }

                                        $tmp_address = $this->sub->addressStore->find($tmp_prefix . $obj2);
                                        if( $tmp_address === null )
                                        {
                                            if( $print )
                                                print "  * create address object: " . $tmp_prefix . $obj2 . " with value: " . $value . "\n";
                                            $tmp_address = $this->sub->addressStore->newAddress($tmp_prefix . $obj2, 'ip-netmask', $value);
                                        }
                                    }
                                    else
                                    {
                                        //check if netmask is 0
                                        if( $tmp_address->isAddress() && $tmp_address->getNetworkMask() == 32 )
                                        {
                                            if( $hostCidr !== null )
                                            {
                                                $value = $obj2 . "/" . $hostCidr;
                                                $tmp_prefix = "H-";
                                            }

                                            $tmp_value = $tmp_address->value();
                                            $tmp_value1 = explode("/", $tmp_value);
                                            $tmp_value = $tmp_value1[0];

                                            $tmp_name = $tmp_address->name() . "_" . $hostCidr;
                                            $tmp_address = $this->sub->addressStore->find($tmp_name);
                                            if( $tmp_address === null )
                                            {
                                                if( $print )
                                                    print "  * create address object: " . $tmp_name . " change value to: " . $tmp_value . "/" . $hostCidr . "\n";
                                                $tmp_address = $this->sub->addressStore->newAddress($tmp_name, 'ip-netmask', $tmp_value . "/" . $hostCidr);
                                            }
                                        }
                                    }


                                    if( $tmp_address !== null )
                                    {
                                        #if( !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address ){
                                        if( $print )
                                        {
                                            print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                        }

                                        $tmp_addressgroup->addMember($tmp_address);

                                        /*}
                                        else
                                        {
                                            if( $print )
                                            {
                                                print "    * addressobject: " . $tmp_address->name() . " already a member or submember of addressgroup: " . $tmp_addressgroup->name() . "\n";
                                            }
                                        }*/
                                    }
                                }
                            }
                        }
                        elseif( $type == "object" )
                        {
                            $tmp_address = $this->sub->addressStore->find($obj2);
                            if( $tmp_address === null )
                            {
                                mwarning("addressobject: " . $obj2 . " not found \n", null, FALSE);
                            }
                            if( $tmp_address !== null )
                            {
                                if( $print )
                                {
                                    print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                }

                                $tmp_addressgroup->addMember($tmp_address);
                            }

                        }
                        elseif( preg_match("/group-object/i", $names_line) )
                        {

                            $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $obj2 = rtrim($netObj[1]);
                            $obj2 = $this->truncate_names($this->normalizeNames($obj2));

                            #$addressObj = $objectsInMemory->getAddressGroupReference($fileName, $source, $vsys,$obj2);
                            #$addMember2[] = "('$groupLid','$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";

                            $tmp_address = $this->sub->addressStore->find($obj2);
                            if( $tmp_address === null )
                            {
                                mwarning("addressgroup object: " . $obj2 . " not found \n", null, FALSE);
                            }
                            if( $tmp_address !== null )
                            {
                                /*

                                if( count( $tmp_addressgroup->members() ) > 0 &&  !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address )
                                {
                                    if( $print )
                                    {
                                        print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                    }

                                    $tmp_addressgroup->addMember($tmp_address);

                                }
                                else
                                {

                                */
                                if( $print )
                                {
                                    print "    * addressobject: " . $tmp_address->name() . " already a member or submember of addressgroup: " . $tmp_addressgroup->name() . "\n";
                                }
                                $tmp_addressgroup->addMember($tmp_address);
                                //}

                            }
                        }
                        elseif( preg_match("/description/i", $names_line) )
                        {
                            $netObj = preg_split('/description /', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $description = addslashes($netObj[0]);
                            $description = str_replace("\n", '', $description); // remove new lines
                            $description = str_replace("\r", '', $description);
                            #$AddDescription[] = "UPDATE address SET description='$description' WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$ObjectNetworkName' AND vtype='object'";

                            $tmp_description = $tmp_addressgroup->description();

                            if( $print )
                                print "      * set Description to: " . $tmp_description . " " . $description . "\n";
                            $tmp_addressgroup->setDescription($tmp_description . " " . $description);

                        }
                        else
                        {
                            $value = $netObj[1];
                            $hostCidr = rtrim($netObj[2]);

                            $obj2 = str_replace(":", "_", $value);
                            $obj2 = str_replace("/", "m", $obj2);
                            $obj2 = $this->truncate_names($this->normalizeNames($obj2));

                            $tmp_hostCidr = $this->mask2cidrv4(rtrim($hostCidr));

                            if( is_int($tmp_hostCidr) )
                            {
                                $hostCidr = $tmp_hostCidr;
                                $tmp_name = $obj2."m".$hostCidr;


                                $tmp_address = $this->sub->addressStore->find($tmp_name);
                                if( $tmp_address === null )
                                {
                                    if( $hostCidr !== null )
                                    {
                                        $value = $obj2 . "/" . $hostCidr;
                                        $tmp_prefix = "H-";
                                    }

                                    else
                                    {
                                        $value = $obj2;
                                        $tmp_prefix = "";
                                        #print "LINE: ".$names_line."\n";
                                    }

                                    $tmp_address = $this->sub->addressStore->find($tmp_prefix . $obj2);
                                    if( $tmp_address === null )
                                    {
                                        if( $print )
                                            print "  * create address object: " . $tmp_prefix . $obj2 . " with value: " . $value . "\n";
                                        $tmp_address = $this->sub->addressStore->newAddress($tmp_prefix . $obj2, 'ip-netmask', $value);
                                    }
                                }
                                else
                                {
                                    //check if netmask is 0
                                    if( $tmp_address->isAddress() && $tmp_address->getNetworkMask() == 32 )
                                    {
                                        if( $hostCidr !== null )
                                        {
                                            $value = $obj2 . "/" . $hostCidr;
                                            $tmp_prefix = "H-";
                                        }

                                        $tmp_value = $tmp_address->value();
                                        $tmp_value1 = explode("/", $tmp_value);
                                        $tmp_value = $tmp_value1[0];

                                        $tmp_name = $tmp_address->name() . "_" . $hostCidr;
                                        $tmp_address = $this->sub->addressStore->find($tmp_name);
                                        if( $tmp_address === null )
                                        {
                                            if( $print )
                                                print "  * create address object: " . $tmp_name . " change value to: " . $tmp_value . "/" . $hostCidr . "\n";
                                            $tmp_address = $this->sub->addressStore->newAddress($tmp_name, 'ip-netmask', $tmp_value . "/" . $hostCidr);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                //print "WILDCARD\n";
                                //print "VALUE: ".$obj2."\n";
                                //print "NETMASK: ".$hostCidr."\n";

                                $cidr_array = explode(".", $hostCidr);
                                $tmp_hostCidr = "";
                                foreach( $cidr_array as $key => &$entry )
                                {
                                    $final_entry = 255 - (int)$entry;
                                    if( $key == 0 )
                                        $tmp_hostCidr .= $final_entry;
                                    else
                                        $tmp_hostCidr .= ".".$final_entry;
                                }

                                //print $tmp_hostCidr."\n";

                                $name = $obj2."m".$tmp_hostCidr;
                                $value = $obj2."/".$tmp_hostCidr;
                                $tmp_address = $this->MainAddHost($name, $value);
                            }



                            if( $tmp_address !== null )
                            {
                                if( $print )
                                {
                                    print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                }
                                $tmp_addressgroup->addMember($tmp_address);
                            }
                        }
                    }
                    elseif( preg_match("/group-object/i", $names_line) )
                    {

                        $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $obj2 = rtrim($netObj[1]);
                        $obj2 = $this->truncate_names($this->normalizeNames($obj2));

                        #$addressObj = $objectsInMemory->getAddressGroupReference($fileName, $source, $vsys,$obj2);
                        #$addMember2[] = "('$groupLid','$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";

                        $tmp_address = $this->sub->addressStore->find($obj2);
                        if( $tmp_address === null )
                        {
                            mwarning("addressgroup object: " . $obj2 . " not found \n", null, FALSE);
                        }
                        if( $tmp_address !== null )
                        {
                            /*

                            if( count( $tmp_addressgroup->members() ) > 0 &&  !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address )
                            {
                                if( $print )
                                {
                                    print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                }

                                $tmp_addressgroup->addMember($tmp_address);

                            }
                            else
                            {

                            */
                            if( $print )
                            {
                                print "    * addressobject: " . $tmp_address->name() . " already a member or submember of addressgroup: " . $tmp_addressgroup->name() . "\n";
                            }
                            $tmp_addressgroup->addMember($tmp_address);
                            //}

                        }
                    }
                    elseif( preg_match("/^\brange\b/i", $names_line) )
                    {
                        $found = FALSE;
                        $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $first_ipaddress = $netObj[1];
                        $last_ipaddress = $netObj[2];

                        $ObjectNetworkNamePan = "R-".$first_ipaddress."-".$last_ipaddress;
                        $ObjectNetworkName = $ObjectNetworkNamePan;
                        $tmp_address = $this->sub->addressStore->find($ObjectNetworkNamePan);

                        if( $tmp_address !== null )
                        {
                            if( $tmp_address->isAddress() && $tmp_address->isType_ipRange() && ($first_ipaddress . "-" . $last_ipaddress) == $tmp_address->value() )
                                $found = TRUE;
                        }

                        if( !$found )
                        {
                            $ipversion = $this->ip_version($first_ipaddress);
                            if( $ipversion == "v4" )
                            {
                                $addHost["ipv4"][] = array($ObjectNetworkNamePan, 'ip-range', $ObjectNetworkName, '0', $source, '0', $first_ipaddress . "-" . $last_ipaddress, '', '1', $vsys, 'object');
                            }
                            elseif( $ipversion == "v6" )
                            {
                                $addHost["ipv6"][] = array($ObjectNetworkNamePan, 'ip-range', $ObjectNetworkName, '0', $source, '0', $first_ipaddress . "-" . $last_ipaddress, '', '1', $vsys, 'object', '0');
                            }
                        }
                    }
                    elseif( preg_match("/description/i", $names_line) )
                    {
                        $netObj = preg_split('/description /', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $description = addslashes($netObj[0]);
                        $description = str_replace("\n", '', $description); // remove new lines
                        $description = str_replace("\r", '', $description);
                        #$AddDescription[] = "UPDATE address SET description='$description' WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$ObjectNetworkName' AND vtype='object'";

                        $tmp_description = $tmp_addressgroup->description();

                        if( $print )
                            print "      * set Description to: " . $tmp_description . " " . $description . "\n";
                        $tmp_addressgroup->setDescription($tmp_description . " " . $description);

                    }
                }
            }
        }
    }
}
