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


trait CISCOnetwork
{
    #function get_static_routes($this->data, $source, $vsys, $template) {
    function get_static_routes()
    {
        global $projectdb;
        global $vrid;

        global $debug;
        global $print;

        $source = "";
        $template = "";

        $vsys = $this->template_vsys->name();
        #Check if THE VR is already created for this VSYS
        $vr = "vr_" . $vsys;

        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr === null )
        {
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
        }
        /*
        $addRoutes = array();
        $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr';");
        if ($isDup->num_rows == 0) {
            $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
            $vrid = $projectdb->insert_id;
        } else {
            $get = $isDup->fetch_assoc();
            $vrid = $get['id'];
        }
    */

        $interfaceMapping = array();
        $all_interfaces = $this->template->network->getAllInterfaces();
        foreach( $all_interfaces as $int )
        {
            $int_name = $int->name();
            $zone = $this->template_vsys->zoneStore->findZoneMatchingInterfaceName($int_name);
            if( $zone !== null )
            {
                $zone_name = $this->template_vsys->zoneStore->findZoneMatchingInterfaceName($int_name)->name();
                $interfaceMapping[$zone_name] = $int_name;
            }

        }
        /*
        $getInterface=$projectdb->query("SELECT unitname,zone FROM interfaces WHERE template='$template' AND zone!='';");
        if ($getInterface->num_rows>0){
            while($getInterfaceData=$getInterface->fetch_assoc()){
                $interfaceMapping[$getInterfaceData['zone']]=$getInterfaceData['unitname'];
            }
        }
        */

        #print_r($interfaceMapping);


        $x = 1;
        $count = 0;
        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);
            if( preg_match("/^route /i", $names_line) || preg_match("/^ipv6 route /i", $names_line) )
            {

                #print $names_line."\n";

                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                if( preg_match("/^ipv6 route /i", $names_line) )
                {
                    $zoneName = $netObj[2];

                    $tmp_ip_networks = explode("/", rtrim($netObj[3]));
                    $ip_network = $tmp_ip_networks[0];
                    $ip_netmask = $tmp_ip_networks[1];

                    $ip_gateway = rtrim($netObj[4]);

                    $metric = "";
                }
                else
                {
                    $zoneName = $netObj[1];
                    $ip_network = $netObj[2];
                    $ip_netmask = rtrim($netObj[3]);
                    $ip_gateway = rtrim($netObj[4]);

                    $metric = $netObj[5];
                }

                $route_network = "";
                $cidr = "";

                if( ($metric == "") or ($metric == "0") or ($metric == "1") )
                {
                    $metric = "10";
                }


                $ip_version = $this->ip_version($ip_network);
                if( $ip_version == "noip" )
                {
                    # name

                    $tmp_address = $this->sub->addressStore->find($ip_network);
                    if( $tmp_address !== null && $tmp_address->isAddress() )
                    {
                        $ip_network = $tmp_address->value();

                        $tmp_array = explode("/", $ip_network);
                        $ip_version = $this->ip_version($tmp_array[0]);
                    }
                    /*
                    $getHostname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name_ext='$ip_network'");
                    if ($getHostname->num_rows == 1) {
                        $getName = $getHostname->fetch_assoc();
                        $ip_network = $getName['ipaddress'];
                        $ip_version=$this->ip_version($ip_network);
                    }
                    */
                }

                $gateway_ip_version = $this->ip_version($ip_gateway);
                if( $gateway_ip_version == "noip" )
                {
                    # name
                    $tmp_address = $this->sub->addressStore->find($ip_gateway);
                    if( $tmp_address !== null && $tmp_address->isAddress() )
                    {
                        $ip_gateway = $tmp_address->getNetworkValue();
                    }
                    /*
                    $getHostname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name_ext='$ip_gateway'");
                    if ($getHostname->num_rows == 1) {
                        $getName = $getHostname->fetch_assoc();
                        $ip_gateway = $getName['ipaddress'];
                    }
                    */
                }

                $routename = "";

                if( ($ip_network == "0.0.0.0") and ($ip_netmask == "0.0.0.0") )
                {
                    if( $count == 0 )
                    {
                        $routename = "default";
                        $count++;
                    }
                    else
                    {
                        $routename = "default " . $count;
                        $count++;
                    }

                    $route_network = "0.0.0.0/0";
                }
                else
                {
                    $routename = "Route " . $x;
                    $x++;

                    $tmp_array = explode("/", $ip_network);
                    if( count($tmp_array) == 2 )
                    {
                        $cidr = $tmp_array[1];
                        if( !is_int( $cidr ) )
                        {
                            $cidr_array = explode(".", $cidr);
                            $tmp_hostCidr = "";
                            foreach( $cidr_array as $key => &$entry )
                            {
                                $final_entry = 255 - (int)$entry;
                                if( $key == 0 )
                                    $tmp_hostCidr .= $final_entry;
                                else
                                    $tmp_hostCidr .= "." . $final_entry;
                            }

                            $cidr = cidr::netmask2cidr($tmp_hostCidr);
                            $route_network = $tmp_array[1]."/".$cidr;
                        }
                        else
                            $route_network = $ip_network;
                    }
                    else
                    {
                        $cidr = $this->mask2cidrv4($ip_netmask);
                        $route_network = "$ip_network/$cidr";
                    }
                }

                if( $zoneName != "" )
                {
                    if( isset($interfaceMapping[$zoneName]) )
                        $interfaceto = $interfaceMapping[$zoneName];
                    else
                    {
                        mwarning("no interface mapping available for zone: " . $zoneName, null, FALSE);
                        $interfaceto = "";
                    }

                }
                else
                {
                    $interfaceto = "";
                }

                $addRoutes[] = "('$zoneName','$source','$vrid','$template','$ip_version','$routename','$route_network','$interfaceto','ip-address','$ip_gateway','$metric','$vsys','10')";


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

                $route_type = "ip-address";
                $nexthop_value = $ip_gateway;

                if( $ip_version == "v4" )
                    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";
                elseif( $ip_version == "v6" )
                    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ipv6-address>" . $ip_gateway . "</ipv6-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";

                $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

                if( $print )
                    print " * add static route: " . $tmpRoute->name() . " with Destination: " . $route_network . " - IP-Gateway: " . $ip_gateway . " - Interface: " . $interfaceto . "\n";

                if( $ip_version == "v4" )
                    $tmp_vr->addstaticRoute($tmpRoute);
                elseif( $ip_version == "v6" )
                    $tmp_vr->addstaticRoute($tmpRoute, 'ipv6');
            }
        }
    }


    #function get_interfaces($this->data, $source, $vsys, $template) {
    function get_interfaces()
    {
        $vsys = $this->template_vsys->name();
        #Check if THE VR is already created for this VSYS
        $vr = "vr_" . $vsys;

        $source = "";
        $template = "";


        global $projectdb;
        global $vrid;
        $zoneName = "";
        $unitipaddress = "";
        $unitipv6address = "";
        $addZones = array();
        $addInterface = array();
        $isFirst = TRUE;
        $isInterface = FALSE;
        $media = "ethernet";
        $comment = '';
        $tmp_shutdown = FALSE;
        $tmp_disable = FALSE;


        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr === null )
        {
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
        }


        foreach( $this->data as $line => $names_line )
        {

            if( preg_match("/^interface /i", $names_line) )
            {
                $isInterface = TRUE;
                $dataI = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $interfaceName = $dataI[1];

                /*
                if( preg_match("/^Management/i", $interfaceName) )
                {
                    //do not import interface like Management
                    $isInterface = FALSE;
                    $interfaceName = "";
                    continue;
                }
                */


                if( preg_match("/ethernet/i", $names_line) )
                {
                    $media = "ethernet";
                }

            }


            if( $isInterface === TRUE )
            {
                if( preg_match("/shutdown/i", $names_line) )
                {
                    $tmp_shutdown = TRUE;
                    $tmp_disable = TRUE;

                }
                elseif( preg_match("/description /i", $names_line) )
                {
                    $tmpExplode = explode(' ', trim($names_line), 2);
                    if( count($tmpExplode) > 1 )
                        $comment = $this->normalizeComments($tmpExplode[1]);
                }
                elseif( preg_match("/nameif /i", $names_line) )
                {
                    $tmp_shutdown = false;
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $zoneName = $netObj[1];
                }
                elseif( preg_match("/ip address /i", $names_line) || preg_match("/ipv6 address /i", $names_line) )
                {

                    print "LINE <ip address >: " . $names_line . "\n";

                    if( preg_match("/ link-local/", $names_line) )
                        continue;

                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);


                    if( preg_match("/ipv6 address /i", $names_line) )
                    {
                        $tmp_ip = explode("/", $netObj[2]);
                        $ip_network = $tmp_ip[0];
                        $ip_netmask = $tmp_ip[1];
                        if( isset( $tmp_ip[1] ) )
                            $ip_netmask = $tmp_ip[1];
                        else
                            $ip_netmask = "";
                    }
                    else
                    {
                        $ip_network = $netObj[2];
                        $ip_netmask = rtrim($netObj[3]);

                    }
                    $ip_version = $this->ip_version($ip_network);

                    if( $ip_version == "v4" )
                    {
                        $cidr = $this->mask2cidrv4($ip_netmask);
                        $unitipaddress = $ip_network . "/" . $cidr;
                    }
                    elseif( $ip_version == "v6" )
                    {
                        # TO BE IMPLEMENTED
                        if( $ip_netmask !== "" )
                            $unitipv6address = $ip_network . "/" . $ip_netmask;
                        else
                            $unitipv6address = $ip_network;
                    }
                    else
                    {
                        $tmp_address = $this->sub->addressStore->find($ip_network);
                        if( $tmp_address !== null )
                        {
                            $ip_network = $tmp_address->getNetworkValue();
                            $ip_version = $this->ip_version($ip_network);
                            if( $ip_version == "v4" )
                            {
                                $cidr = $this->mask2cidrv4($ip_netmask);
                                $unitipaddress = $ip_network . "/" . $cidr;
                            }
                            elseif( $ip_version == "v6" )
                            {
                                # TO BE IMPLEMENTED
                                $unitipv6address = $ip_network . "/" . $ip_netmask;
                            }
                        }
                        else
                        {
                            mwarning("interface IP object not found: " . $ip_network);
                        }
                        /*
                        $getHostname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name_ext='$ip_network'");
                        if ($getHostname->num_rows == 1) {
                            $getName = $getHostname->fetch_assoc();
                            $ip_network = $getName['ipaddress'];
                            $ip_version = $this->ip_version($ip_network);
                            if ($ip_version == "v4") {
                                $cidr = $this->mask2cidrv4($ip_netmask);
                                $unitipaddress = $ip_network . "/" . $cidr;
                            } elseif ($ip_version == "v6") {
                                # TO BE IMPLEMENTED
                            }
                        }
                        */
                    }
                }
                elseif( preg_match("/ vlan /", $names_line) )
                {
                    $tmp = explode(" ", $names_line);
                    $unittag = $tmp[2];
                }
                elseif( preg_match("/^!/i", $names_line) )
                {
                    $isInterface = FALSE;
                    #ADD INFO INTO DB
                    if( !isset($unittag) || $unittag == "" )
                    {
                        $unittag = 0;
                        $unitname = (isset($zoneName)) ? $zoneName : '';
                    }
                    else
                    {
                        $unitname = $zoneName . "." . $unittag;
                    }

                    if( $unitname != "" )
                    {

                        if( $interfaceName != "" )
                        {
                            $intsplit = explode(".", $interfaceName);
                            $name = $intsplit[0];
                            if( isset($intsplit[1]) )
                            {
                                if( ($unittag == "0") or ($unittag == "") )
                                {
                                    $unittag = $intsplit[1];
                                    $unitname = $interfaceName;
                                }
                                else
                                {
                                    $unitname = $interfaceName;
                                }
                            }
                            else
                            {
                                $unittag = 0;
                                $unitname = $interfaceName;
                            }

                            if( preg_match("/Vlan/", $name) )
                            {
                                $vlansplit = explode("Vlan", $name);
                                $unittag = intval($vlansplit[1]);
                                $name = "Vlan";
                                $unitname = "Vlan." . $unittag;
                                if( $isFirst === TRUE )
                                {
                                    $isFirst = FALSE;

                                    if( !$tmp_shutdown )
                                    {
                                        #print "add1: VLAN\n";
                                        $addInterface[] = array($vrid, $source, $vsys, $template, '0', 'Vlan', 'Vlan', '', '', $media, $comment, '', $tmp_disable);
                                    }
                                }
                            }

                            if( !$tmp_shutdown )
                            {
                                #print "add2: " . $name . " - " . $unitname . " - " . $unittag . "\n";
                                $addInterface[] = array($vrid, $source, $vsys, $template, $unittag, $unitname, $name, $unitipaddress, $zoneName, $media, $comment, $unitipv6address, $tmp_disable);
                            }

                        }
                        else
                        {
                            if( !$tmp_shutdown )
                            {
                                #print "add3: " . $zoneName . " - " . $unitname . " - " . $unittag . "\n";
                                $addInterface[] = array($vrid, $source, $vsys, $template, $unittag, $unitname, $interfaceName, $unitipaddress, $zoneName, $media, $comment, $unitipv6address, $tmp_disable);
                            }
                        }

                        #Insert Zone
                        $addZones[] = array($source, $template, $vsys, $zoneName, 'layer3');
                    }
                    else
                    {
                        #print "problemes: interfaceName|".$interfaceName."| - unitname|".$unitname."| - unittag|".$unittag."|\n";


                        #print "unitipv4: ".$unitipaddress."\n";
                        #print "unitipv6: ".$unitipv6address."\n";

                        $unitname = $interfaceName;
                        $zoneName = "";

                        if( !$tmp_shutdown )
                        {
                            #print "add4: interfaceName|".$interfaceName."| - unitname|".$unitname."| - unittag|".$unittag."|\n";
                            $addInterface[] = array($vrid, $source, $vsys, $template, $unittag, $unitname, $interfaceName, $unitipaddress, $zoneName, $media, $comment, $unitipv6address, $tmp_disable);
                        }


                    }


                    $unittag = "";
                    $unitipaddress = "";
                    $unitipv6address = "";
                    $zoneName = "";
                    $vr = "";
                    $unitname = "";
                    $comment = "";
                    $tmp_shutdown = FALSE;
                    $tmp_disable = FALSE;
                }
            }
        }

        if( count($addZones) > 0 )
        {
            foreach( $addZones as $zone )
            {
                if( $zone[3] != "" )
                {
                    $tmp_zone = $this->template_vsys->zoneStore->find($zone[3]);
                    if( $tmp_zone == null )
                    {
                        $tmp_name = $this->truncate_names($this->normalizeNames($zone[3]));
                        $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                    }
                }
                else
                {
                    print "LINE: " . $names_line . "\n";
                    mwarning("empty zone: why??", null, FALSE);
                }


            }
            unset($addZones);
        }
        if( count($addInterface) > 0 )
        {

            #print_r( $addInterface );

            foreach( $addInterface as $int )
            {
                $tmp_int_main = $this->template->network->findInterface($int[6]);
                if( !is_object($tmp_int_main) )
                {
                    $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($int[6], 'layer3');
                    $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                    if( $int[7] != "" and ($int[6] == $int[5]) )
                    {
                        $int_array = explode(",", $int[7]);
                        foreach( $int_array as $tmp_int_name )
                            $tmp_int_main->addIPv4Address($tmp_int_name);
                    }
                    if( $int[11] != "" and ($int[6] == $int[5]) )
                    {
                        $int_array = explode(",", $int[11]);
                        foreach( $int_array as $tmp_int_name )
                            $tmp_int_main->addIPv6Address($tmp_int_name);
                    }
                    if( $int[8] != "" && ($int[6] === $int[5]) )
                    {
                        $tmp_zone = $this->template_vsys->zoneStore->find($int[8]);
                        if( $tmp_zone == null )
                        {
                            $tmp_name = $this->truncate_names($this->normalizeNames($int[8]));
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                        }

                        $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                        $tmp_vr->attachedInterfaces->addInterface($tmp_int_main);
                    }

                    if( $int[10] != "" )
                    {
                        $tmp_int_main->setDescription($int[10], "comment");
                    }

                    if( $int[12]  )
                    {
                        $tmp_int_main->setLinkState( "down" );
                        $description = $tmp_int_main->description();
                        $tmp_int_main->setDescription($description." | link-state down", "comment");
                    }
                }

                if( $int[6] !== $int[5] )
                {
                    $tmp_sub = $this->template->network->findInterface($int[5]);
                    if( $tmp_sub === null )
                    {
                        $tmp_sub = $tmp_int_main->addSubInterface($int[4], $int[5]);
                        $this->template_vsys->importedInterfaces->addInterface($tmp_sub);
                    }

                    if( $int[7] != "" )
                    {
                        $int_array = explode(",", $int[7]);
                        foreach( $int_array as $tmp_int_name )
                            $tmp_sub->addIPv4Address($tmp_int_name);
                    }
                    if( $int[11] != "" )
                    {
                        $int_array = explode(",", $int[11]);
                        foreach( $int_array as $tmp_int_name )
                            $tmp_sub->addIPv6Address($tmp_int_name);
                    }
                    if( $int[8] != "" )
                    {
                        $tmp_name = $this->truncate_names($this->normalizeNames($int[8]));
                        $tmp_zone = $this->template_vsys->zoneStore->find($tmp_name);
                        if( $tmp_zone == null )
                        {
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                        }

                        $tmp_zone->attachedInterfaces->addInterface($tmp_sub);
                        $tmp_vr->attachedInterfaces->addInterface($tmp_sub);
                    }

                    if( $int[10] != "" )
                    {
                        $tmp_sub->setDescription($int[10], "comment");
                    }

                    if( $int[12]  )
                    {
                        $tmp_sub->setLinkState( "down" );
                        $description = $tmp_sub->description();
                        $tmp_sub->setDescription($description." | link-state down", "comment");
                    }

                }
            }
            unset($addInterface);
        }
    }


    function importDynamicRoutes($cisco )
    {

        $vsys = $this->template_vsys->name();
        #Check if THE VR is already created for this VSYS
        $vr = "vr_" . $vsys;

        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr === null )
        {
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
        }


        /*


        Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
               D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
               N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
               E1 - OSPF external type 1, E2 - OSPF external type 2, V - VPN
               i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
               ia - IS-IS inter area, * - candidate default, U - per-user static route
               o - ODR, P - periodic downloaded static route, + - replicated route
        Gateway of last resort is 10.140.9.9 to network 0.0.0.0

        */


        $lines = explode("\n", $cisco);

        $start = FALSE;

        $codes = $this->find_string_between($cisco, "Codes: ", "Gateway of last resort is");
#$codes = strip_hidden_chars($codes);
        $codes = str_replace("       ", "", $codes);

        $codelines = explode("\n", $codes);


        $codeArray = implode(", ", $codelines);
        $codeArray = explode(", ", $codeArray);

        foreach( $codeArray as $key => $entry )
        {
            if( empty($entry) )
                continue;

            $tmparray2 = explode(" - ", $entry);
            unset($codeArray[$key]);
            $codeArray[$tmparray2[0]] = $tmparray2[1];
        }

        #print_r( $codeArray );

        $routeentry = "";

        foreach( $lines as $index => &$line )
        {
            if( count( $lines ) == $index+1 && !empty($routeentry) )
            {
                $routeentry = preg_replace("/\s+/", " ", $routeentry);
                $routeentry = str_replace(",", "", $routeentry);
                $routeentry = explode(" ", $routeentry);
                $routearray[] = $routeentry;
                $routeentry = "";
            }

            $line = $this->strip_hidden_chars($line);

            if( empty($line) )
                continue;

            if( $start )
            {
                if( isset($line[0]) && ($line[0] == "C" || $line[0] == "L" || $line[0] == "S") )
                    continue;


                if( isset($line[0]) && array_key_exists($line[0], $codeArray) )
                {
                    $routeentry = $line;

                    if( ( isset($lines[$index+1][0]) && array_key_exists($lines[$index+1][0], $codeArray) ) && !empty($routeentry) )
                    {
                        $routeentry = preg_replace("/\s+/", " ", $routeentry);
                        $routeentry = str_replace(",", "", $routeentry);
                        $routeentry = explode(" ", $routeentry);
                        $routearray[] = $routeentry;
                        $routeentry = "";
                    }

                }
                else
                {
                    $routeentry .= $line;
                    if( ( isset($lines[$index+1][0]) && array_key_exists($lines[$index+1][0], $codeArray) ) && !empty($routeentry) )
                    {
                        $routeentry = preg_replace("/\s+/", " ", $routeentry);
                        $routeentry = str_replace(",", "", $routeentry);
                        $routeentry = explode(" ", $routeentry);
                        $routearray[] = $routeentry;
                        $routeentry = "";
                    }
                }


            }

            if( strpos($line, "Gateway of last resort is") !== FALSE )
            {
                $lastResort = $line;
                $start = TRUE;
            }
        }

#print "LastResorrt: ".$lastResort."\n";
#print_r( $routearray );
        
        foreach( $routearray as $key => $entry )
        {
            if( (array_key_exists($entry[0], $codeArray)) && (array_key_exists($entry[1], $codeArray)) )
            {
                $ip = $entry[2];
                $mask = $entry[3];
                $destination = $entry[6];
                $interface = $entry[8];

                $length = 9;
            }
            else
            {
                $ip = $entry[1];
                $mask = $entry[2];
                $destination = $entry[5];

                if( empty($entry[7]) )
                    $interface = $entry[6];
                else
                    $interface = $entry[7];

                $length = 8;
            }

            $description = array_slice($entry, 0, $length);
            $description = implode("-", $description);


            print "".$ip."/".$mask."=>".$destination."|int:".$interface."|";
            print $description;
            print "|\n";


            $array[] = array($ip, $mask, $destination, $interface, $description);
        }

        #print_r( $array );

        foreach( $array as $key => $route )
        {
            $route_type = "ip-address";
            $ip_gateway = $route[2];
            $metric = 10;

            $routename = "route" . $key;
            $route_network = $route[0] . "/" . CIDR::netmask2cidr($route[1]);


            $interfaceto = "";
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


