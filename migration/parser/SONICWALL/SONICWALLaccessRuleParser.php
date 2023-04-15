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

trait SONICWALLaccessRuleParser
{
    function add_accessrule( $accessrule)
    {
        global $debug;
        global $print;

        $padding = "    ";
        $padding_name = substr($padding, 0, -1);

        foreach( $accessrule as $key => $accessrule_entry )
        {
            $accessrule_entry = trim($accessrule_entry);
            $accessrule_entry = explode("\n", $accessrule_entry);

            $accessrule_array = array();
            foreach( $accessrule_entry as $key2 => $accessrule )
            {
                $accessrule = trim($accessrule);
                $array = preg_split('#\s+#', $accessrule, 2);

                if( isset($array[0]) )
                {
                    if( isset($array[1]) )
                    {
                        if( !isset($accessrule_array[$array[0]]) )
                            $accessrule_array[$array[0]] = $array[1];
                        else
                        {
                            if( is_array($accessrule_array[$array[0]]) )
                                $accessrule_array[$array[0]][] = $array[1];
                            else
                            {
                                $tmp_string = $accessrule_array[$array[0]];
                                $accessrule_array[$array[0]] = array();
                                $accessrule_array[$array[0]][] = $tmp_string;
                                $accessrule_array[$array[0]][] = $array[1];
                            }
                        }
                    }
                    else
                        $accessrule_array[$array[0]] = "";
                }
            }

            #print_r(  $accessrule_array);
            //Todo: 20190528 continue optimizing access rule reading;

            /*
                 [0] => ipv6 from WLAN to DMZ action allow
        [1] =>     id 153
        [2] =>     enable
        [3] =>     from WLAN
        [4] =>     to DMZ
        [5] =>     action allow
        [6] =>     source address any
        [7] =>     source port any
        [8] =>     service any
        [9] =>     destination address any
        [10] =>     schedule always-on
                [11] =>     users included all
                [12] =>     users excluded none
        [13] =>     comment "IPv6:From Any to Any for Any service"
                [14] =>     fragments
        [15] =>     logging
                [16] =>     no flow-reporting
                [17] =>     no packet-monitoring
                [18] =>     no management
                [19] =>     max-connections 100
                [20] =>     priority manual 2
                [21] =>     tcp timeout 15
                [22] =>     udp timeout 30
                [23] =>     no connection-limit source
                [24] =>     no connection-limit destination
                [25] =>     quality-of-service dscp preserve
                [26] =>     no quality-of-service class-of-service
             */
            foreach( $accessrule_entry as $key2 => $accessrule )
            {
                $accessrule = trim($accessrule);

                if( $key2 == 0 )
                {
                    //check if ipv6
                    if( strpos($accessrule, "ipv6") != FALSE )
                    {
                        if( $debug )
                            print $padding . "X ipv6 rule\n";
                    }
                }
                elseif( $key2 == 1 )
                {
                    $name = $accessrule;
                    $name = "Rule " . $this->truncate_names($this->normalizeNames($name));
                    $tmp_rule = $this->sub->securityRules->find($name);
                    if( $tmp_rule == null )
                    {
                        if( $print )
                            print "\n" . $padding_name . "* name: " . $name . "\n";
                        $tmp_rule = $this->sub->securityRules->newSecurityRule($name);
                    }
                }
                elseif( $key2 == 2 )
                {
                    if( $accessrule == "no enable" )
                    {
                        if( $print )
                            print $padding . "- disable\n";
                        $tmp_rule->setDisabled(TRUE);
                    }
                }
                elseif( $key2 == 3 )
                {
                    $from_zone = str_replace("from ", "", $accessrule);
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
                    }

                }
                elseif( $key2 == 4 )
                {
                    $to_zone = str_replace("to ", "", $accessrule);
                    $to_zone = $this->truncate_names($this->normalizeNames($to_zone));
                    $tmp_zone = $this->template_vsys->zoneStore->find($to_zone);
                    if( $tmp_zone != null )
                    {
                        if( $print )
                            print $padding . "- to zone: " . $to_zone . "\n";
                        $tmp_rule->to->addZone($tmp_zone);
                    }
                    else
                    {
                        if( $debug )
                            print $padding . "X to zone: " . $to_zone . " not found\n";
                    }
                }
                elseif( $key2 == 5 )
                {
                    $action = str_replace("action ", "", $accessrule);
                    if( $action == "allow" )
                    {
                        if( $print )
                            print $padding . "- action: " . $action . " \n";
                        $tmp_rule->setAction($action);
                    }
                    elseif( $action == "deny" )
                    {
                        if( $print )
                            print $padding . "- action: " . $action . " \n";
                        $tmp_rule->setAction($action);
                    }
                    else
                    {
                        if( $debug )
                            print $padding . "X action: " . $action . " not supported\n";

                        $action = "deny";
                        if( $print )
                            print $padding . "- action: " . $action . " \n";
                        $tmp_rule->setAction($action);
                    }
                }
                elseif( $key2 == 6 )
                {
                    $accessrule = str_replace("address group ", "", $accessrule);
                    $accessrule = str_replace("address name ", "", $accessrule);
                    $accessrule = str_replace("address ", "", $accessrule);
                    $accessrule = str_replace("source ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);

                    $name = $accessrule;
                    $name = $this->truncate_names($this->normalizeNames($name));
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address != null )
                    {
                        if( $print )
                            print $padding . "- source address object: " . $name . " \n";
                        $tmp_rule->source->addObject($tmp_address);
                    }
                    elseif( $name == 'any' )
                    {
                        if( $print )
                            print $padding . "- source address object: " . $name . " \n";
                    }
                    else
                        if( $print || $debug )
                        {
                            print $padding . "X source address object: " . $name . " not found \n";
                        }

                }
                elseif( $key2 == 7 )
                {
                    if( $accessrule != "source port any" )
                    {
                        if( $print )
                            print $padding . "X source port usage: " . $accessrule . "\n";
                    }
                }
                elseif( $key2 == 8 )
                {
                    $accessrule = str_replace("service group ", "", $accessrule);
                    $accessrule = str_replace("service name ", "", $accessrule);
                    $accessrule = str_replace("service ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);
                    $service = $accessrule;
                    $service = $this->truncate_names($this->normalizeNames($service));
                    $tmp_service = $this->sub->serviceStore->find($service);
                    if( $tmp_service != null )
                    {
                        if( $print )
                            print $padding . "- service object: " . $service . " \n";
                        $tmp_rule->services->add($tmp_service);
                    }
                    elseif( $service == 'any' )
                    {
                        if( $print )
                            print $padding . "- service: " . $name . " \n";
                    }
                    else
                    {
                        $tmp_service = $this->sub->serviceStore->find("TMP_" . $service);
                        if( $tmp_service != null )
                        {
                            if( $print )
                                print $padding . "- service object: TMP_" . $service . " \n";
                            $tmp_rule->services->add($tmp_service);
                            $tmp_rule->services->set_node_attribute('error', "TMP Service object set");
                        }
                        else
                            if( $print || $debug )
                            {
                                print $padding . "X service object: " . $service . " and TMP_" . $service . " not found \n";
                            }
                    }
                }
                elseif( $key2 == 9 )
                {
                    $accessrule = str_replace("address group ", "", $accessrule);
                    $accessrule = str_replace("address name ", "", $accessrule);
                    $accessrule = str_replace("address ", "", $accessrule);
                    $accessrule = str_replace("destination ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);

                    $name = $accessrule;
                    $name = $this->truncate_names($this->normalizeNames($name));
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address != null )
                    {
                        if( $print )
                            print $padding . "- destination address object: " . $name . " \n";
                        $tmp_rule->destination->addObject($tmp_address);
                    }
                    elseif( $name == 'any' )
                    {
                        if( $print )
                            print $padding . "- destination address object: " . $name . " \n";
                    }
                    else
                        if( $print || $debug )
                        {
                            print $padding . "X destination address object: " . $name . " not found \n";
                        }
                }
                elseif( $key2 == 13 )
                {
                    $accessrule = str_replace("comment ", "", $accessrule);
                    $accessrule = str_replace('"', "", $accessrule);

                    if( $print )
                        print $padding . "- description: " . $accessrule . "\n";
                    $tmp_rule->setDescription($accessrule);
                }
            }
        }
    }

}

