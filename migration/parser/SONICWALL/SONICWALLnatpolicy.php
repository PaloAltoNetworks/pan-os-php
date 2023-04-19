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

trait SONICWALLnatpolicy
{

    function add_natpolicy( $natpolicy)
    {
        global $debug;
        global $print;

        $padding = "    ";
        $padding_name = substr($padding, 0, -1);


        foreach( $natpolicy as $key => $natpolicy_entry )
        {
            $natpolicy_entry = trim($natpolicy_entry);
            $natpolicy_entry = explode("\n", $natpolicy_entry);

            $counter = 0;
            $natpolicy_array = array();
            foreach( $natpolicy_entry as $key2 => $natpolicy )
            {
                $natpolicy = trim($natpolicy);
                $array = preg_split('#\s+#', $natpolicy, 2);

                if( isset($array[0]) )
                {
                    if( isset($array[1]) )
                    {
                        if( !isset($natpolicy_array[$array[0]]) )
                            $natpolicy_array[$array[0]] = $array[1];
                        else
                        {
                            $natpolicy_array[$counter . "-" . $array[0]] = $natpolicy_array[$array[0]];
                            $natpolicy_array[$array[0]] = $array[1];
                            $counter++;
                        }
                    }
                    else
                        $natpolicy_array[$array[0]] = "";
                }
            }

            if( $debug )
                #print_r(  $natpolicy_array);

                if( isset($natpolicy_array[0]) )
                {
                    //check if ipv6
                    if( strpos($natpolicy_array[0], "ipv6") != FALSE )
                    {
                        if( $debug )
                            print $padding . "X ipv6 rule\n";
                    }
                }

            if( isset($natpolicy_array["id"]) )
            {
                $name = $natpolicy_array["id"];
                $name = "Rule id " . $this->truncate_names($this->normalizeNames($name));
                $tmp_rule = $this->sub->natRules->find($name);
                if( $tmp_rule == null )
                {
                    if( $print )
                        print "\n" . $padding_name . "* name: '" . $name . "'\n";
                    $tmp_rule = $this->sub->natRules->newNatRule($name);
                }
            }
            else
                $tmp_rule = null;

            if( is_object($tmp_rule) )
            {
                if( isset($natpolicy_array["inbound"]) )
                {
                    $accessrule = $natpolicy_array["inbound"];
                    $accessrule = str_replace('"', "", $accessrule);
                    $accessrule = str_replace(':', "", $accessrule);
                    $accessrule = str_replace("V", ".", $accessrule);

                    $zone_array = $this->template_vsys->zoneStore->getAll();
                    foreach( $zone_array as $tmp_zone )
                    {
                        $zone_interfaces = $tmp_zone->attachedInterfaces->getAll();

                        foreach( $zone_interfaces as $interface )
                        {
                            if( $interface->name() == $accessrule )
                            {
                                if( $print )
                                    print $padding . "- from Zone: '" . $tmp_zone->name() . "'\n";
                                $tmp_rule->from->addZone($tmp_zone);
                            }
                        }
                    }

                }


                if( isset($natpolicy_array["outbound"]) )
                {
                    $accessrule = $natpolicy_array["outbound"];
                    $accessrule = str_replace('"', "", $accessrule);
                    $accessrule = str_replace(':', "", $accessrule);
                    $accessrule = str_replace("V", ".", $accessrule);

                    if( $accessrule == 'any' )
                    {
                        $tmp_zone = $this->template_vsys->zoneStore->findOrCreate('TMP_FIX');
                        if( $print )
                            print $padding . "- to Zone: '" . $tmp_zone->name() . "'\n";
                        $tmp_rule->to->addZone($tmp_zone);
                    }
                    else
                    {
                        $zone_array = $this->template_vsys->zoneStore->getAll();
                        foreach( $zone_array as $tmp_zone )
                        {
                            $zone_interfaces = $tmp_zone->attachedInterfaces->getAll();

                            foreach( $zone_interfaces as $interface )
                            {
                                if( $interface->name() == $accessrule )
                                {
                                    if( $print )
                                    {
                                        print $padding . "- to Zone: '" . $tmp_zone->name() . "'\n";
                                        print $padding . "- destination-interface: '" . $interface->name() . "'\n";
                                    }

                                    $tmp_rule->to->addZone($tmp_zone);
                                    $tmp_rule->setDestinationInterface($interface->name());
                                    //Todo: not working this way
                                    #$interface->addReference($tmp_rule->);
                                }
                            }
                        }
                    }
                }

                if( isset($natpolicy_array["source"]) )
                {
                    $accessrule = $natpolicy_array["source"];
                    $accessrule = str_replace("group ", "", $accessrule);
                    $accessrule = str_replace("name ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);

                    $name = $accessrule;
                    $name = $this->truncate_names($this->normalizeNames($name));
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address != null )
                    {
                        if( $print )
                            print $padding . "- source address object: '" . $name . "' \n";
                        $tmp_rule->source->addObject($tmp_address);
                    }
                    elseif( $name == 'any' )
                    {
                        if( $print )
                            print $padding . "- source address object: '" . $name . "' \n";
                    }
                    else
                        if( $print || $debug )
                        {
                            print $padding . "X sourceaddress object: '" . $name . "' not found \n";
                            print $padding . $accessrule . "\n";
                        }
                }

                if( isset($natpolicy_array["translated-source"]) )
                {
                    $accessrule = $natpolicy_array["translated-source"];
                    $accessrule = str_replace("group ", "", $accessrule);
                    $accessrule = str_replace("name ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);

                    if( $accessrule != "original" )
                    {

                        $name = $this->truncate_names($this->normalizeNames($accessrule));
                        $tmp_address = $this->sub->addressStore->find($name);
                        if( $tmp_address != null )
                        {
                            if( $print )
                                print $padding . "- translated source object: '" . $name . "' \n";

                            $tmp_rule->snathosts->addObject($tmp_address);
                            #$tmp_rule->changeSourceNAT('static-ip');
                            $tmp_rule->changeSourceNAT('dynamic-ip-and-port');
                        }
                        else
                            if( $print || $debug )
                            {
                                print $padding . "X translated-source object: '" . $name . "' not found \n";
                            }
                    }
                }


                if( isset($natpolicy_array["destination"]) )
                {
                    $accessrule = $natpolicy_array["destination"];
                    $accessrule = str_replace("group ", "", $accessrule);
                    $accessrule = str_replace("name ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);

                    $name = $accessrule;
                    $name = $this->truncate_names($this->normalizeNames($name));
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address != null )
                    {
                        if( $print )
                            print $padding . "- destination address object: '" . $name . "' \n";
                        $tmp_rule->destination->addObject($tmp_address);
                    }
                    elseif( $name == 'any' )
                    {
                        if( $print )
                            print $padding . "- destination address object: '" . $name . "' \n";
                    }
                    else
                        if( $print || $debug )
                        {
                            print $padding . "X destination address object: '" . $name . "' not found \n";
                            print $padding . $accessrule . "\n";
                        }
                }


                if( isset($natpolicy_array["service"]) )
                {
                    $accessrule = $natpolicy_array["service"];
                    $accessrule = str_replace("group ", "", $accessrule);
                    $accessrule = str_replace("name ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);
                    $service = $accessrule;
                    $service = $this->truncate_names($this->normalizeNames($service));
                    $tmp_service = $this->sub->serviceStore->find($service);
                    if( $tmp_service != null )
                    {
                        if( $print )
                            print $padding . "- service object: " . $service . " \n";
                        $tmp_rule->setService($tmp_service);
                    }
                    elseif( $service == 'any' )
                    {
                        if( $print )
                            print $padding . "- service: '" . $name . "' \n";
                    }
                    else
                    {
                        /*
                        $tmp_service = $this->sub->serviceStore->find( "TMP_".$service );
                        if( $tmp_service != null )
                        {
                            if( $print )
                                print $padding."- service object: TMP_".$service." \n";
                            $tmp_rule->services->add( $tmp_service );
                        }
                        else */
                        if( $print || $debug )
                        {
                            print $padding . "X service object: " . $service . " and TMP_" . $service . " not found \n";
                            print $padding . $accessrule . "\n";
                        }
                    }
                }

                if( !isset($natpolicy_array["enable"]) )
                {
                    if( $print )
                        print $padding . "- disable\n";
                    $tmp_rule->setDisabled(TRUE);
                }

                if( isset($natpolicy_array["comment"]) )
                {
                    $accessrule = $natpolicy_array["comment"];
                    $accessrule = str_replace('"', "", $accessrule);

                    if( $print )
                        print $padding . "- description: " . $accessrule . "\n";
                    $tmp_rule->setDescription($accessrule);
                }

                if( isset($natpolicy_array["translated-destination"]) )
                {
                    if( $natpolicy_array["translated-destination"] != "original" )
                    {
                        $accessrule = $natpolicy_array["translated-destination"];
                        $accessrule = str_replace("group ", "", $accessrule);
                        $accessrule = str_replace("name ", "", $accessrule);
                        $accessrule = str_replace('"', "", $accessrule);
                        $name = $accessrule;

                        $name = $this->truncate_names($this->normalizeNames($name));
                        $tmp_address = $this->sub->addressStore->find($name);
                        if( $tmp_address == null )
                        {
                            if( $print )
                                print $padding . "X translated-destination object: '" . $name . "' not found\n";
                        }
                        $port = null;

                        if( isset($natpolicy_array["translated-service"]) && $natpolicy_array["translated-service"] != "original" )
                        {
                            $accessrule = $natpolicy_array["translated-service"];
                            $accessrule = str_replace("group ", "", $accessrule);
                            $accessrule = str_replace("name ", "", $accessrule);
                            $accessrule = str_replace('"', "", $accessrule);
                            $port = $accessrule;
                        }

                        if( $tmp_address != null )
                        {
                            //Todo: if address group check if only one member -> add this addressobject
                            if( $print )
                                print $padding . "- translated-destination object: '" . $name . "'\n";
                            $tmp_rule->setDNAT($tmp_address, $port);
                        }
                    }
                }

            }
        }
    }

}

