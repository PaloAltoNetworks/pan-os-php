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

trait SONICWALLroute
{

    function add_route_to_vr($xmlString, $vr)
    {
        $newRoute = new StaticRoute('***tmp**', $vr);

        $xmlElement = DH::importXmlStringOrDie($vr->owner->owner->xmlroot->ownerDocument, $xmlString);
        $xmlElement = DH::importXmlStringOrDie($vr->owner->xmlroot->ownerDocument, $xmlString);
        $newRoute->load_from_xml($xmlElement);

        return $newRoute;
    }

    function add_routing( $route)
    {
        global $debug;
        global $print;

        $route_array = array();
        $tmp_route = array();


        $padding = "    ";
        $padding_name = substr($padding, 0, -1);


        if( isset($route[0]) )
            $tmp_route = explode("\n", $route[0]);

        /*
            print "1 -------------------\n";

            print_r($tmp_route);

            print "2 -------------------\n";

            exit;
            */

        $i = 0;
        $jj = 0;
        foreach( $tmp_route as $key => $route_entry )
        {
            /*
            |    policy ipv6 interface MGMT metric 1 destination name "MGMT IPv6 Primary Static Address"
    |        id 45
    |        interface MGMT
    |        metric 1
    |        source any
    |        destination name "MGMT IPv6 Primary Static Address"
    |        service any
    |        gateway default
    |        no comment
    |        no disable-on-interface-down
    |        no vpn-precedence
    |        no probe
    |        exit
             */

            $route_entry = $this->strip_hidden_chars($route_entry);
            $route_entry = str_replace("    ", "", $route_entry);

            if( strpos($route_entry, "policy interface") !== FALSE )
            {
                $route_array[$i]["policy interface"] = $route_entry;
                $route_array[$i]["ipv6"] = 0;
            }
            if( strpos($route_entry, "policy ipv6 interface") !== FALSE )
            {
                $route_array[$i]["policy interface"] = $route_entry;
                $route_array[$i]["ipv6"] = 1;
            }
            elseif( strpos($route_entry, "policy interface") !== FALSE )
            {
                $route_array[$i]["policy interface"] = $route_entry;
            }
            elseif( strpos($route_entry, "exit") !== FALSE )
            {
                $i++;
                $jj = 0;
            }
            else
            {
                if( $route_entry != "" && strpos($route_entry, "no ") === FALSE && strpos($route_entry, "mode simple") === FALSE )
                {
                    $route_entry1 = explode(' ', $route_entry, 2);
                    if( count($route_entry1) == 2 )
                        $route_array[$i][$route_entry1[0]] = $route_entry1[1];
                    else
                        $route_array[$i][$route_entry1[0]] = $route_entry1[0];

                    $jj++;
                }
            }
        }


        foreach( $route_array as $key => $route )
        {
            if( isset($route['source']) && $route['source'] == 'any' && isset($route['service']) && $route['service'] == 'any' )
            {
                if( $debug )
                {
                    #print "|/";

                    #print $route_entry;

                    print $route['policy interface'] . "\n";

                    #print_r( $route );

                    #print "/|\n";
                }
                /*
                   [policy interface] => policy interface X2 metric 20 destination name "X2 Subnet"
                    [ipv6] => 0
                    [id] => 7
                    [enable] => enable
                    [interface] => X2
                    [metric] => 20
                    [source] => any
                    [destination] => name "X2 Subnet"
                    [service] => any
                    [gateway] => default
                    [admin-distance] => value 20
                 */
                #if( isset($route['enable']) ){
                if( isset($route['interface']) )
                    $interfaceto = $route['interface'];
                else
                    $interfaceto = "";

                #$interfaceto = $this->truncate_names($this->normalizeNames($interfaceto));
                $interfaceto = str_replace(":V", ".", $interfaceto);

                if( isset( $route['metric']) )
                    $preference = $route['metric'];
                else
                    $preference = 10;

                $vr = 'default';
                $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
                if( $tmp_vr == null )
                    $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);

                $xml_interface = "";
                if( $interfaceto !== "" )
                {
                    $xml_interface = "<interface>" . $interfaceto . "</interface>";
                    $tmp_interface = $this->template->network->find($interfaceto);
                    if( $tmp_interface != null )
                    {
                        $tmp_vr->attachedInterfaces->addInterface($tmp_interface);
                    }

                }

                if( isset($route['gateway']) )
                {
                    if( strpos($route['gateway'], 'name') !== FALSE )
                    {
                        $gateway = str_replace('"', "", $route['gateway']);
                        $gateway = str_replace('name ', "", $gateway);

                        $tmp_address = $this->sub->addressStore->find($gateway);
                        if( $tmp_address != null )
                        {
                            $gateway = $tmp_address->value();
                            $gateway = "<nexthop><ip-address>" . $gateway . "</ip-address></nexthop>";
                        }
                        else
                            $gateway = "";

                    }
                    else
                    {
                        $gateway = $route['gateway'];
                        $gateway = "<nexthop><next-vr>" . $gateway . "</next-vr></nexthop>";
                    }
                }


                else
                    $gateway = "";

                if( isset($route['destination']) )
                    $tmp_object_name = str_replace("name ", "", $route['destination']);
                $tmp_object_name = str_replace('"', '', $tmp_object_name);
                $tmp_object_name = $this->truncate_names($this->normalizeNames($tmp_object_name));

                $tmp_address = $this->sub->addressStore->find($tmp_object_name);
                if( $tmp_address == null )
                    mwarning("object: '" . $tmp_object_name . "' for static Route not found");
                else
                {
                    $network_and_mask = "1.1.1.1/32";
                    $network_and_mask = $tmp_address->value();

                    $route_name = "route-" . $key;
                    $xmlString = "<entry name=\"" . $route_name . "\">" . $gateway . "<metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                    $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);

                    print "    - add route : " . $route_name . " | " . $network_and_mask . " | \n";
                    $tmp_vr->addstaticRoute($tmpRoute);
                }

                #}
                #else
                #    mwarning( "route not installed, because it is not enabled: ".$route['policy interface'] , null, false);
            }
            else
            {
                //Todo:
                if( $print )
                    print "\nX create Policy Based Forwarding Rule\n";

                if( $debug || $print )
                {
                    #print "|/";

                    #print $route_entry;
                    #print_r( $route );
                    if( isset($route['policy interface']) )
                        print " X " . $route['policy interface'] . "\n\n";
                    else
                    {
                        print "missing information\n";
                        print_r($route);
                    }


                    #print "/|\n";
                }
            }
        }
    }

}
