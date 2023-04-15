<?php


#namespace expedition;


trait SOPHOSaddress
{
    public function address($master_array)
    {
        foreach( $master_array['network'] as $policy )
        {
            $addr_name = str_replace(',', "", $policy['name']);
            //$addr_name = str_replace('(',"",$addr_name);
            //$addr_name = str_replace(')',"",$addr_name);

            $addr_type = explode("/", $policy['_type']);

            if( $policy['_type'] == 'network/host,' )
            {
                $addr_value = str_replace(',', "", $policy['address']);
                $addr_comment = str_replace(',', "", $policy['comment']);
                //[_type] => network/host,
                print "name: " . $addr_name . " - value: " . $addr_value . "\n";

                if( $addr_value !== "" )
                {
                    $tmp_address = $this->sub->addressStore->find($addr_name);
                    if( $tmp_address == null )
                    {
                        print "create address - name: " . $addr_name . " - value: " . $addr_value . "\n";
                        $tmp_address = $this->sub->addressStore->newAddress($addr_name, 'ip-netmask', $addr_value);
                        $tmp_address->setDescription($addr_comment);
                    }
                }
            }
            elseif( $policy['_type'] == 'network/dns_host,' || $policy['_type'] == 'network/dns_group,' )
            {
                //network/dns_group

                $addr_value = str_replace(',', "", $policy['hostname']);
                $addr_comment = str_replace(',', "", $policy['comment']);
                //[_type] => network/host,
                print "name: " . $addr_name . " - value: " . $addr_value . "\n";

                $tmp_address = $this->sub->addressStore->find($addr_name);
                if( $tmp_address == null )
                {
                    #print $tmp_address->name()."\n";
                    print "create address fqdn - name: " . $addr_name . " - value: " . $addr_value . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($addr_name, 'fqdn', $addr_value);
                    $tmp_address->setDescription($addr_comment);
                }
                else
                {
                    #print "NULL\n";
                }
            }
            elseif( $policy['_type'] == 'network/group,' )
            {
                //check seperate import later on
            }
            elseif( $policy['_type'] == 'network/range,' )
            {
                $addr_from = str_replace(',', "", $policy['from']);
                $addr_to = str_replace(',', "", $policy['to']);
                $addr_comment = str_replace(',', "", $policy['comment']);
                //[_type] => network/host,

                if( $addr_from !== "" && $addr_to !== "" )
                {
                    print "name: " . $addr_name . " - value: " . $addr_from . "-" . $addr_to . "\n";
                    $tmp_address = $this->sub->addressStore->find($addr_name);
                    if( $tmp_address == null )
                    {
                        print "create address ip-range - name: " . $addr_name . " - value: " . $addr_from . "-" . $addr_to . "\n";
                        $tmp_address = $this->sub->addressStore->newAddress($addr_name, 'ip-range', $addr_from . "-" . $addr_to);
                        $tmp_address->setDescription($addr_comment);
                    }
                    else
                    {

                    }
                }
            }
            elseif( $policy['_type'] == 'network/network,' || $policy['_type'] == 'network/interface_network,' )
            {
                $addr_value = str_replace(',', "", $policy['address']);
                $addr_netmask = str_replace(',', "", $policy['netmask']);
                $addr_comment = str_replace(',', "", $policy['comment']);
                //[_type] => network/host,
                if( $policy['address6'] !== "," )
                {
                    print "name: " . $addr_name . " - value: " . $addr_value . "\n";
                    $tmp_address = $this->sub->addressStore->find($addr_name . "IPv4");
                }
                else
                    $tmp_address = $this->sub->addressStore->find("n_" . $addr_name);


                if( $tmp_address == null )
                {
                    $dummy = "n_";
                    $dummy = "";
                    print "create network - name: " . $dummy . $addr_name . " - value: " . $addr_value . "\n";
                    if( $policy['address6'] !== "," )
                    {
                        $tmp_address = $this->sub->addressStore->newAddress($dummy . $addr_name . "_IPv4", 'ip-netmask', $addr_value . "/" . $addr_netmask);
                    }
                    else
                        $tmp_address = $this->sub->addressStore->newAddress($dummy . $addr_name, 'ip-netmask', $addr_value . "/" . $addr_netmask);

                    $tmp_address->setDescription($addr_comment);
                }

                if( $policy['address6'] !== "," )
                {
                    #print "CHECK - IPv6|".$policy['address6']."|\n";

                    $addr_value = str_replace(',', "", $policy['address6']);
                    $addr_netmask = str_replace(',', "", $policy['netmask6']);


                    if( $addr_value == "::" && $addr_netmask !== "64" )
                    {
                        $dummy = "n_";
                        $dummy = "";

                        if( $addr_netmask !== "" )
                        {
                            #print "NETMASK IPV6:|".$addr_netmask."|\n";
                            $tmp_address6 = $this->sub->addressStore->find($dummy . $addr_name . "IPv6");
                            if( $tmp_address6 == null )
                            {
                                $tmp_address6 = $this->sub->addressStore->newAddress($dummy . $addr_name . "_IPv6", 'ip-netmask', $addr_value . "/" . $addr_netmask);
                                $tmp_address6->setDescription($addr_comment);
                            }
                        }
                    }

                    if( $addr_netmask !== "" )
                    {
                        //create addressgroup
                        $tmp_address_group = $this->sub->addressStore->find($addr_name);

                        $tmp_address_group = $this->sub->addressStore->newAddressGroup($addr_name);

                        $tmp_address_group->addMember($tmp_address);
                        if( $addr_value == "::" && $addr_netmask !== "64" )
                        {
                            $tmp_address_group->addMember($tmp_address6);
                        }

                        #print_r( $policy );
                        #derr( "IPV6" );
                    }
                }
            }
            else
            {
                print "|" . $policy['_type'] . "|\n";
                print_r($policy);
            }

        }
    }


    public function addressgroup($master_array)
    {
        foreach( $master_array['network'] as $policy )
        {
            $srv_name = str_replace(',', "", $policy['name']);

            if( $policy['_type'] == 'network/group,' )
            {
                $tmp_address_group = $this->sub->addressStore->find($srv_name);
                if( $tmp_address_group !== FALSE )
                {
                    $tmp_address_group = $this->sub->addressStore->newAddressGroup($srv_name);
                }

                $tmp_found = FALSE;

                if( isset($policy['members']) )
                {
                    $src_array = explode(",", $policy['members']);
                }
                else
                {
                    #print_r( $policy );
                    #derr( "something wrong [members] - missing" );
                    continue;
                }


                print "- set address group members: ";
                foreach( $src_array as $members )
                {
                    #print "src_ref:".$source."\n";
                    foreach( $master_array['network'] as $master_service )
                    {
                        #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                        if( str_replace(',', "", $master_service['_ref']) == $members )
                        {
                            //search object in addressstore
                            $tmp_name = str_replace(',', "", $master_service['name']);
                            print "\nFOUND address: " . $tmp_name . " - " . $members . "\n";

                            $tmp_service = $this->sub->addressStore->find($tmp_name);
                            // add to rule source
                            if( $tmp_service !== null )
                                $tmp_address_group->addMember($tmp_service);
                            else
                            {
                                $tmp_service = $this->sub->addressStore->find("n_" . $tmp_name);

                                if( $tmp_service !== null )
                                    $tmp_address_group->addMember($tmp_service);
                                else
                                    mwarning("addressobject: " . $tmp_name . " not found.");
                            }

                            print "$tmp_name";
                            $tmp_found = TRUE;
                            break;
                        }
                        elseif( $master_service['_ref'] == "REF_NetworkAny" )
                        {
                            $tmp_found = TRUE;
                            break;
                        }
                        else
                        {
                            #print "NOT FOUND\n";
                        }
                    }
                    if( !$tmp_found )
                    {
                        mwarning("   - network object not found:" . $members . "\n");
                    }
                }
            }
        }
    }
}

