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

trait HUAWEI_securityrules
{
    function add_accessrule( $tmp_accessrule)
    {
        global $debug;
        global $print;

        $padding = "    ";
        $padding_name = substr($padding, 0, -1);


        $accessrule = $tmp_accessrule[1];
        $accessaction = $tmp_accessrule[2];

        $missing_default_service = array();

        $test_array = array();

        foreach( $accessrule as $key => $accessrule_entry )
        {
            $rulestring = "";

            $rulestring .=  " rule name ".$accessrule_entry."";
            $rulestring .= "  action ".$accessaction[$key];

            $rulearray = explode( "\n", $rulestring );
            $tmp_rule = null;

            foreach( $rulearray as $ruleentry )
            {
                $linearray = explode( " ", trim( $ruleentry ) );
                #$test_array[$linearray[0]] = $linearray[0];

                #print_r( $linearray );

                if( $linearray[0] == "rule" )
                {
                    $name = $linearray[2];
                    $name_string = implode( " ", $linearray );
                    $name_string = str_replace( "rule name ", "", $name_string );

                    #print "NAME: ".$linearray[2]."\n";

                    $name = "Rule " . $this->truncate_names($this->normalizeNames($name));
                    $tmp_rule = $this->sub->securityRules->find($name);
                    if( $tmp_rule == null )
                    {
                        if( $print )
                            print "\n" . $padding_name . "* name: " . $name . "\n";
                        $tmp_rule = $this->sub->securityRules->newSecurityRule($name);
                    }
                    else
                    {
                        print_r( $rulearray );
                        mwarning( "rule name already found" );
                    }
                }
                elseif( $linearray[0] == "disable" )
                {
                    //set rule to disable
                    if( $print )
                        print $padding . "- disable\n";
                    $tmp_rule->setDisabled(TRUE);
                }
                elseif( $linearray[0] == "source-address" )
                {
                    $this->rule_add_address(  $tmp_rule, $linearray, "source" );
                }
                elseif( $linearray[0] == "destination-address" )
                {
                    $this->rule_add_address(  $tmp_rule, $linearray, "destination" );
                }
                elseif( $linearray[0] == "action" )
                {
                    #print "ACTION: ".$linearray[1]."\n";
                    $action = $linearray[1];

                    if( $action == "permit" )
                    {
                        if( $print )
                            print $padding . "- action: allow \n";
                        $tmp_rule->setAction( "allow");
                    }
                    elseif( $action == "deny" )
                    {
                        if( $print )
                            print $padding . "- action: " . $action . " \n";
                        $tmp_rule->setAction($action);
                    }
                }
                elseif( $linearray[0] == "policy" )
                {

                }
                elseif( $linearray[0] == "session" )
                {

                }
                elseif( $linearray[0] == "source-zone" )
                {
                    #print "SRC-Zone: ".$linearray[1]."\n";
                    $from_zone = $linearray[1];
                    $from_zone = $this->truncate_names($this->normalizeNames($from_zone));
                    $tmp_zone = $this->template_vsys->zoneStore->find($from_zone);
                    if( $tmp_zone != null )
                    {
                        if( $print )
                            print $padding . "- from zone: " . $from_zone . "\n";
                        $tmp_rule->from->addZone($tmp_zone);
                    }
                    else
                    {
                        if( $debug )
                            print $padding . "X from zone: " . $from_zone . " not found\n";

                        $tmp_zone = $this->template_vsys->zoneStore->find($from_zone);
                        if( $tmp_zone == null )
                        {
                            if( $print )
                                print "  - name: " . $from_zone . "\n";
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($from_zone, 'layer3');
                        }
                        $tmp_rule->from->addZone($tmp_zone);
                    }
                }
                elseif( $linearray[0] == "destination-zone" )
                {
                    #print "DST-Zone: ".$linearray[1]."\n";
                    $from_zone = $linearray[1];
                    $from_zone = $this->truncate_names($this->normalizeNames($from_zone));
                    $tmp_zone = $this->template_vsys->zoneStore->find($from_zone);
                    if( $tmp_zone != null )
                    {
                        if( $print )
                            print $padding . "- to zone: " . $from_zone . "\n";
                        $tmp_rule->to->addZone($tmp_zone);
                    }
                    else
                    {
                        if( $debug )
                            print $padding . "X to zone: " . $from_zone . " not found\n";

                        $tmp_zone = $this->template_vsys->zoneStore->find($from_zone);
                        if( $tmp_zone == null )
                        {
                            if( $print )
                                print "  - name: " . $from_zone . "\n";
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($from_zone, 'layer3');
                        }
                        $tmp_rule->to->addZone($tmp_zone);
                    }
                }
                elseif( $linearray[0] == "service" )
                {
                    $dport = "";
                    $protocol = "";

                    if( $linearray[1] == "protocol" )
                    {
                        $protocol = $linearray[2];

                        if( $protocol == "tcp" || $protocol == "udp" )
                        {
                            $dport = "";
                            if( isset($linearray[3]) && $linearray[3] == "destination-port" )
                                $dport = $this->findDport( $linearray, $dport, 4 );
                            elseif( isset($linearray[3]) && $linearray[3] == "source-port" )
                            {
                                if( isset($linearray[7]) && $linearray[7] == "destination-port" )
                                    $dport = $this->findDport( $linearray, $dport, 8 );

                                if( isset($linearray[6]) && $linearray[6] == "destination-port" )
                                    $dport = $this->findDport( $linearray, $dport, 7 );
                            }

                            else
                                $dport = "0-65535";

                            if( $protocol == "tcp" || $protocol == "udp" )
                                $name = $protocol . "_";
                            else
                                $name = $protocol;

                            $name .= str_replace( ",", "_", $dport);
                        }
                        else
                        {
                            $name = "TMP_".$protocol;

                            print "NAME: ".$name."\n";
                            print_r( $linearray );

                            if( isset($linearray[4]) && $linearray[3] == "icmp-type" )
                            {
                                $name = "TMP_".$linearray[4];
                            }
                        }
                    }
                    else
                    {
                        $name = $linearray[1];
                    }




                    $name = $this->truncate_names($this->normalizeNames($name));
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service != null )
                    {
                        if( $print )
                            print $padding_name . "- service add: " . $tmp_service->name() . "\n";

                        $tmp_rule->services->add($tmp_service);
                    }
                    else
                    {



                        if( $dport == "" && $protocol == "" )
                            $missing_default_service[ $name ] = $name;
                        else
                        {
                            #print "DPORT: ".$dport."\n";
                            #print "PROTO: ".$protocol."\n";

                            if( $print )
                                print $padding_name . "* name: '" . $name . "' protocol: '" . $protocol . "' port: '" . $dport . "'\n";
                            $tmp_service = $this->sub->serviceStore->newService($name, $protocol, $dport);

                            $tmp_rule->services->add($tmp_service);
                        }
                        if( $tmp_service == null )
                        {
                            #print_r( $linearray );
                            print $padding_name . "X check service: " . $name . " | service created: TMP_" . $name . "\n";

                            $name = $this->truncate_names($this->normalizeNames( "TMP_".$name ) );
                            $tmp_service = $this->sub->serviceStore->find($name);
                            if( $tmp_service == null )
                            {
                                $tmp_service = $this->sub->serviceStore->newService( $name, "tcp", "65000");
                                $tmp_rule->services->add($tmp_service);
                            }
                            else
                                $tmp_rule->services->add($tmp_service);

                            #$tmp_service->set_node_attribute('error', $name);

                            #mwarning( "service: ".$name." not found", null, false );
                        }

                    }

                }
                elseif( $linearray[0] == "profile" )
                {

                }
                elseif( $linearray[0] == "description" )
                {
                    #print_r( $linearray );

                    $description = "";

                    $i = 1;
                    do
                    {
                        if( isset($linearray[$i]) )
                        {
                            $description .= $linearray[$i]." ";
                        }
                        $i++;
                    } while( $i < count($linearray) + 1 );

                    if( $print )
                        print $padding . "- description: " . $description . "\n";
                    $tmp_rule->setDescription($description);
                }
                elseif( $linearray[0] == "long-link" )
                {

                }
                elseif( $linearray[0] == "application" )
                {

                }
                elseif( $linearray[0] == "time-range" )
                {

                }
            }
            print "----------------------\n";


        }

        print_r( $missing_default_service );
    }

    function rule_add_address(  $tmp_rule, $linearray, $add_type )
    {
        global $print;
        global $padding_name;

        $address = "";

        //write function to use for source and destination
        if( $linearray[1] == "address-set" )
        {
            //Todo: possible to miss parts regarding "
            $address = $linearray[2];
        }
        elseif( $linearray[1] == "range" )
        {
            #print_r( $linearray );
            $address = $linearray[2]."-".$linearray[3];
        }
        elseif( $linearray[1] == "domain-set" )
        {
            if( $add_type == "source" )
                mwarning( "domain-set for source must be implemented via User-id", null, false );
            elseif( $add_type == "destination" )
            {
                $name = $linearray[2];
                if( strpos( $name, '"' ) !== false )
                {
                    $i = 3;
                    do
                    {
                        if( isset($linearray[$i]) )
                        {
                            $name .= " ".$linearray[$i]." ";
                        }
                        $i++;
                    } while( $i < count($linearray) + 1 );
                    $name = str_replace( '"', '', $name );
                }
                $name = trim( $name );

                $chars = array("[", "]", '"');
                $custom_url = str_replace( $chars, "", $name );

                $tmp_custom_url = $this->sub->customURLProfileStore->find( $custom_url );
                if( $tmp_custom_url !== null )
                {
                    if( $print )
                        print $padding_name." * add custom URL: ".$custom_url."\n";

                    if( $tmp_rule->destination->isAny() )
                        $tmp_rule->urlCategories->add( $tmp_custom_url );
                    else
                    {
                        mwarning( "clone rule first" );
                        $tmp_clone_rule = $tmp_rule->owner->cloneRule( $tmp_rule );
                        $tmp_clone_rule->destination->setAny();
                        $tmp_clone_rule->urlCategories->add( $tmp_custom_url );
                    }
                }
                else
                    mwarning( "customer URL: ".$custom_url." not found" );

            }
        }
        elseif( isset($linearray[2]) && $linearray[2] == "mask" )
        {
            $address = $this->calculate_address_mask( $linearray[1], $linearray[3] );
        }
        else
        {
            $address = $this->calculate_address_mask( $linearray[1], $linearray[2] );
        }

        $name = $this->truncate_names($this->normalizeNames($address));
        $tmp_address = $this->sub->addressStore->find($name);
        if( $tmp_address != null )
        {
            if( $print )
                print $padding_name . "- ".$add_type." address object: " . $name . " \n";
            $tmp_rule->$add_type->addObject($tmp_address);
        }
        else
        {
            /*[0] => destination-address
    [1] => 192.168.89.22
    [2] => mask
    [3] => 255.255.255.255
            */
            if( $linearray[2] == "mask" )
            {
                $address = $this->calculate_address_mask( $linearray[1], $linearray[3] );
                $name = $this->truncate_names($this->normalizeNames($address));
                $type = 'ip-netmask';
                if( $print )
                    print $padding_name . "* name: '" . $name . "' type: '" . $type . "' value: ";

                if( $type == 'ip-netmask')
                {
                    if( $print )
                        print $address . "'\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-netmask', $address);
                    if( $tmp_address != null )
                    {
                        if( $print )
                            print $padding_name . "- ".$add_type." address object: " . $name . " \n";
                        $tmp_rule->$add_type->addObject($tmp_address);
                    }
                }

            }
            else
            {
                print_r( $linearray );
                mwarning( $add_type." address object: ".$name." not found", null, false );
            }
        }
    }

    function calculate_address_mask( $address, $mask )
    {
        $mask = $this->strip_hidden_chars( $mask );

        #print "MASK: ".$mask."\n";

        if( strpos( $mask, "." ) !== false )
        {
            #$address .= "/".CIDR::cidr2netmask( $ip[5] );
            if( (strpos( $mask, "0." ) !== false) && (strpos( $mask, "0." ) == 0) )
            {
                $netmask = $this->wildcardnetmask2netmask( $mask );
                $netmask = CIDR::netmask2cidr( $netmask );
            }
            else
                $netmask = CIDR::netmask2cidr( $mask );
        }
        else
            $netmask = $mask;

        if( $netmask != '32' )
            $address .= "/".$netmask ;

        return $address;
    }
}

