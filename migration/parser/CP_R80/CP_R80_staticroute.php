<?php


trait CP_R80_staticroute
{

    function importRoutes($routetable)
    {
        $vr = "vr_" . "chkpt";

        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr === null )
        {
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
        }


        /*

        Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface

        */


        $lines = explode("\n", $routetable);

        $start = FALSE;
        $routeentry = "";
        $routearray = array();

        foreach( $lines as $index => &$line )
        {


            $line = $this->strip_hidden_chars($line);

            if( empty($line) )
                continue;

            if( $start )
            {
                print "LINE: " . $line . "\n";

                $line = preg_replace("/\s+/", " ", $line);
                #$line = str_replace( ",", "", $line);
                $routeentry = explode(" ", $line);

                if( count( $routeentry ) > 8 )
                {
                    print "There is a problem with your shared route table file at LINE: ".$index."\n";
                    derr( "FIX shared route table file" );
                }

                $routearray[] = $routeentry;
            }

            if( strpos($line, "Iface") !== FALSE )
            {
                $lastResort = $line;
                $start = TRUE;
            }

        }

        print_r( $routearray );

        foreach( $routearray as $key => $entry )
        {
            /*
            [0] => 165.225.80.40
            [1] => 0.0.0.0
            [2] => 255.255.255.255
            [3] => UHD
            [4] => 0
            [5] => 0
            [6] => 0
            [7] => vpnt5
             */
            print_r( $entry );

            if( isset( $entry[1] ) && ( $entry[1] == "0.0.0.0" || $entry[1] == "*") )
            {
                $int_name = $entry[7];
                $ipv4 = $entry[0];
                $ipv4_mask = CIDR::netmask2cidr($entry[2]);

                $vlan = "";
                if( strpos($int_name, ".") !== FALSE )
                {
                    $int_array = explode(".", $int_name);
                    $int_name = $int_array[0];
                    $vlan = $int_array[1];
                }

                $tmp_int_main = $this->template->network->findInterface($int_name);
                if( !is_object($tmp_int_main) )
                {
                    print "    - create interface: " . $int_name . "\n";
                    $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($int_name, 'layer3');
                    $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                    if( $vlan == "" )
                    {
                        $tmp_int_main->addIPv4Address($ipv4 . "/" . $ipv4_mask);

                        $zone_counter = 1;
                        do
                        {
                            $new_zone_name = "Zone" . $zone_counter;

                            $zone_counter++;

                            $tmp_zone = $this->template_vsys->zoneStore->find($new_zone_name);
                        } while( $tmp_zone !== null );
                        if( $tmp_zone == null )
                        {
                            $tmp_name = $this->truncate_names($this->normalizeNames($new_zone_name));
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                        }

                        $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);

                        $tmp_vr->attachedInterfaces->addInterface($tmp_int_main);
                    }


                }

                if( $vlan != "" )
                {
                    $tmp_sub = $this->template->network->findInterface($int_name . "." . $vlan);
                    if( $tmp_sub === null )
                    {
                        $tmp_sub = $tmp_int_main->addSubInterface($vlan, $int_name . "." . $vlan);
                        $this->template_vsys->importedInterfaces->addInterface($tmp_sub);

                        $tmp_sub->addIPv4Address($ipv4 . "/" . $ipv4_mask);

                        $zone_counter = 1;
                        do
                        {
                            $new_zone_name = "Zone" . $zone_counter;

                            $zone_counter++;

                            $tmp_zone = $this->template_vsys->zoneStore->find($new_zone_name);
                        } while( $tmp_zone !== null );
                        if( $tmp_zone == null )
                        {
                            $tmp_name = $this->truncate_names($this->normalizeNames($new_zone_name));
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                        }

                        $tmp_zone->attachedInterfaces->addInterface($tmp_sub);

                        $tmp_vr->attachedInterfaces->addInterface($tmp_sub);
                    }
                }


            }
            else
            {
                //add static route

                $routes[] = $entry;
            }
        }

        foreach( $routes as $key => $entry )
        {

            print_r($entry);

            /*
            [0] => 0.0.0.0
            [1] => 212.12.183.129
            [2] => 0.0.0.0
            [3] => UGD
            [4] => 0
            [5] => 0
            [6] => 0
            [7] => eth4
             */

            if( count( $entry ) < 8 )
                continue;

            $route_type = "ip-address";
            $ip_gateway = $entry[1];
            $metric = 10;

            $routename = "route" . $key;

            if( !filter_var($entry[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && !filter_var($entry[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) )
            {
                print_r( $entry );
                mwarning( "skip migration static route due to valid IP-Address" );
                continue;
            }


            $route_network = $entry[0] . "/" . CIDR::netmask2cidr($entry[2]);


            $interfaceto = $entry[7];
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


            $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";


            $newRoute = new StaticRoute('***tmp**', $tmp_vr);
            $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

            print " * add static route: " . $tmpRoute->name() . " with Destination: " . $route_network . " - IP-Gateway: " . $ip_gateway . " - Interface: " . $interfaceto . "\n";


            $tmp_vr->addstaticRoute($tmpRoute);
        }


    }

}