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

trait FORTINETnetwork
{
    #function get_interfaces($fortinet_config_file, $vsys, $source, $template, $ismultiornot) {
    function get_interfaces( $ismultiornot)
    {
        global $projectdb;

        global $debug;
        global $print;

        global $tmp_template_vsys;

        $isConfig = FALSE;
        $isInterface = FALSE;
        $becareful = FALSE;
        $interfaceName = "";
        $status = "";
        $isZone = FALSE;
        $addZones = "";
        $addInterface = "";
        $unittag = "";
        $addVR = "";
        $media = "";
        $unitipaddress1 = "";
        $allRoutes = array();
        $myroutes = array();

        $secondary = FALSE;
        $config_ipv6 = FALSE;
        $config_ipv6_prefix = FALSE;
        $myVR = array();
        $aggregate = array();
        $unitipaddress = array();

        foreach( $this->data as $line => $names_line )
        {
            if( preg_match("/config system interface/i", $names_line) )
            {
                $isConfig = TRUE;
            }
            if( $isConfig === TRUE )
            {

                if( (preg_match("/config secondaryip/i", $names_line) or (preg_match("/config secondary-IP/i", $names_line))) and ($isZone == TRUE) )
                {
                    $secondary = TRUE;
                    continue;
                }

                if( ($secondary == TRUE) and (preg_match("/\bend\b/", $names_line)) )
                {
                    $secondary = FALSE;
                    continue;
                }

                if( (preg_match("/config ip6-prefix-list/", $names_line)) and ($isZone == TRUE) and ($config_ipv6 == TRUE) )
                {
                    $config_ipv6_prefix = TRUE;
                    continue;
                }

                if( (preg_match("/config ipv6/", $names_line)) and ($isZone == TRUE) )
                {
                    $config_ipv6 = TRUE;
                    continue;
                }


                if( (preg_match("/\bend\b/", $names_line)) and ($config_ipv6_prefix == TRUE) and ($config_ipv6 == TRUE) )
                {
                    $config_ipv6_prefix = FALSE;
                    continue;
                }

                if( (preg_match("/\bend\b/", $names_line)) and ($config_ipv6_prefix == FALSE) and ($config_ipv6 == TRUE) )
                {
                    $config_ipv6 = FALSE;
                    continue;
                }


                if( (preg_match("/\bedit\b/i", $names_line)) and ($isZone == FALSE) and ($secondary == FALSE) )
                {
                    # MEDIA DEFAULT ETHERNET
                    $media = "ethernet";
                    $isZone = TRUE;
                    $zoneName = "";
                    $vr = "";
                    $Network = "";
                    $InterfaceMASK = "";
                    $InterfaceIP = "";
                    $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $zoneName = trim($data1[1]);
                }
                if( preg_match("/set vdom /i", $names_line) )
                {
                    $dataDom = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    #print_r( $dataDom );
                    $vdom = trim($dataDom[2]);
                    $vr = "vr_" . $vdom;


                    $tmp_virtual_router = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
                    if( $tmp_virtual_router == null )
                    {
                        if( $print )
                        {

                            if( $this->configType == "panos" )
                                print " * create virtual Router: " . $vr . " tempate: ".$this->template->name()."\n";
                            elseif( $this->configType == "panorama" )
                                print " * create virtual Router: " . $vr . " tempate: ".$this->template->owner->name()."\n";
                        }

                        $tmp_virtual_router = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
                    }

                    #if( $ismultiornot == 'singlevsys' ){
                    $vsysID = 1;
                    $this->template_vsys = $this->template->findVSYS_by_displayName($vdom);
                    if( $this->template_vsys === null )
                    {
                        #print "VSYS: ".$vsysID." already available - check displayName ".$vsysName."\n";
                        if( $print )
                            print " * create vsys" . $vsysID . " with VDOM name: '" . $vdom . "'\n";
                        $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
                        $this->template_vsys->setAlternativeName($vdom);

                        $tmp_template_vsys[ $vdom ] = intval($vsysID);
                    }
                    else
                    {

                    }
                    #}


                    /*
                    $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr';");
                    if ($isDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vdom');");
                        $vrid = $projectdb->insert_id;
                    } else {
                        $get = $isDup->fetch_assoc();
                        $vrid = $get['id'];
                    }
                    if (!isset($myVR[$vrid])){
                        $myVR[$vrid]=array("config"=>$fortinet_config_file,"source"=>$source,"vsys"=>$vdom, "ismultiornot"=>$ismultiornot,"vr"=>$vrid,"template"=>$template);

                    }
                    */
                }
                if( preg_match("/set ip /i", $names_line) )
                {
                    $dataIp = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $InterfaceIP = $dataIp[2];
                    $InterfaceMASK = trim($dataIp[3]);
                    //$ip1=ip2long($InterfaceIP);$mask1=ip2long($InterfaceMASK);$Network1=$ip1 & $mask1;$Network=long2ip($Network1);
                    $cidr = $this->mask2cidrv4($InterfaceMASK);
                    $unitipaddress[] = $InterfaceIP . "/" . $cidr;
                }
                if( preg_match("/set vlanid /i", $names_line) )
                {
                    $dataVlan = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $unittag = $dataVlan[2];
                }
                if( preg_match("/set interface /i", $names_line) )
                {
                    $dataVlan = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $interfaceName = $dataVlan[2];
                }
                if( preg_match("/set status down/i", $names_line) )
                {
                    $status = "down";
                }
                if( preg_match("/set type tunnel/i", $names_line) )
                {
                    $media = "tunnel";
                    continue;
                }
                if( preg_match("/set type aggregate/i", $names_line) )
                {
                    $media = "aggregate-ethernet";
                    $aggregate[$zoneName] = $zoneName;
                    continue;
                }
                if( (preg_match("/\bnext\b/i", $names_line)) and ($isZone == TRUE) and (($secondary == FALSE) and ($config_ipv6 == FALSE)) )
                {

                    if( ($zoneName != "") and ($vr != "") )
                    {
                        #Insert Interface
                        if( $interfaceName == "" )
                        {
                            $interfaceName = $zoneName;
                            $zoneName = $this->truncate_names($this->normalizeNames($zoneName));
                        }
                        if( $unittag == "" )
                        {
                            $unittag = 0;
                            $unitname = $interfaceName;
                        }
                        else
                        {
                            $unitname = $interfaceName . "." . $unittag;
                        }
                        if( count($unitipaddress) > 0 )
                        {
                            $unitipaddress1 = implode(",", $unitipaddress);
                        }

                        if( isset($aggregate[$interfaceName]) )
                        {
                            $media = "aggregate-ethernet";
                        }

                        if( $media == "ethernet" )
                        {
                            $tmp_int_main = $this->template->network->findInterface($interfaceName);
                            if( !is_object($tmp_int_main) )
                            {
                                if( $print )
                                    print " * create interface: " . $interfaceName . "\n";
                                $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($interfaceName, 'layer3');


                                if( $print )
                                    print " * import interface to vsys: " . $this->template_vsys->name() . "\n";
                                $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                                if( $print )
                                    print " * add interface to virtualrouter: " . $tmp_virtual_router->name() . "\n";
                                $tmp_virtual_router->attachedInterfaces->addInterface($tmp_int_main);

                                if( $unitipaddress > 0 )
                                {
                                    foreach( $unitipaddress as $tmp_ip )
                                        $tmp_int_main->addIPv4Address($tmp_ip);
                                }

                                $tmp_zone = $this->template_vsys->zoneStore->find($zoneName);
                                if( $tmp_zone == null )
                                {
                                    if( $print )
                                        print " * create zone: " . $zoneName . "\n";
                                    $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneName, 'layer3');
                                }

                                if( $print )
                                    print " * add interface to zone: " . $tmp_zone->name() . "\n";
                                $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                            }


                            if( $unitname != $interfaceName )
                            {
                                $tmp_int_sub = $this->template->network->findInterface($unitname);
                                if( !is_object($tmp_int_sub) )
                                {
                                    if( $print )
                                        print " * create interface: " . $unitname . "\n";

                                    #$tmp_int_sub = $tmp_int_main->addSubInterface($unitname, $unittag);
                                    $tmp_int_sub = $tmp_int_main->addSubInterface($unittag, $unitname);

                                    if( $print )
                                        print " * import interface to vsys: " . $this->template_vsys->name() . "\n";
                                    $this->template_vsys->importedInterfaces->addInterface($tmp_int_sub);

                                    if( $print )
                                        print " * add interface to virtualrouter: " . $tmp_virtual_router->name() . "\n";
                                    $tmp_virtual_router->attachedInterfaces->addInterface($tmp_int_sub);

                                    if( $unitipaddress > 0 )
                                    {
                                        foreach( $unitipaddress as $tmp_ip )
                                            $tmp_int_sub->addIPv4Address($tmp_ip);
                                    }

                                    $tmp_zone = $this->template_vsys->zoneStore->find($zoneName);
                                    if( $tmp_zone == null )
                                    {
                                        if( $print )
                                            print " * create zone: " . $zoneName . "\n";
                                        $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneName, 'layer3');
                                    }

                                    if( $print )
                                        print " * add interface to zone: " . $tmp_zone->name() . "\n";
                                    $tmp_zone->attachedInterfaces->addInterface($tmp_int_sub);
                                }
                            }

                        }
                        elseif( $media == 'tunnel' )
                        {
                            $tmp_int_main = $this->template->network->findInterface($zoneName);
                            if( !is_object($tmp_int_main) )
                            {
                                if( $print )
                                    print " * create interface: " . $interfaceName . "\n";
                                $tmp_int_main = $this->template->network->tunnelIfStore->newTunnelIf($zoneName);
                                $tmp_int_main->set_node_attribute('error', "Zone must be wrong");

                                if( $print )
                                    print " * import interface to vsys: " . $this->template_vsys->name() . "\n";
                                $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                                if( $print )
                                    print " * add interface to virtualrouter: " . $tmp_virtual_router->name() . "\n";
                                $tmp_virtual_router->attachedInterfaces->addInterface($tmp_int_main);

                                if( $unitipaddress > 0 )
                                {
                                    foreach( $unitipaddress as $tmp_ip )
                                        $tmp_int_main->addIPv4Address($tmp_ip);
                                }
                            }
                            $this->tunnelinterface[$zoneName] = $tmp_int_main;

                            $tmp_zone = $this->template_vsys->zoneStore->find($zoneName);
                            if( $tmp_zone == null )
                            {
                                if( $print )
                                    print " * create zone: " . $zoneName . "\n";
                                $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneName, 'layer3');
                            }

                            if( $print )
                                print " * add interface to zone: " . $tmp_zone->name() . "\n";
                            $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                            $tmp_zone->set_node_attribute('error', "wrong attached tunnel interface");

                        }
                        elseif( $media == "aggregate-ethernet" )
                        {
                            /*
                             *aggregate-ethernet:
                            Array
                            (
                                [0] => root
                                [1] => 298
                                [2] => LAG_TO_SW.298
                                [3] => LAG_TO_SW
                                [4] => 172.17.198.1/24
                                [5] => Vlan298
                                [6] => aggregate-ethernet
                            )

                             */
                            #print "aggregate-ethernet:\n";
                            #print_r( array($vdom,$unittag,$unitname,$interfaceName,$unitipaddress1,$zoneName,$media) );

                            if( $unitipaddress1 != "" )
                                $unitipaddress = explode(",", $unitipaddress1);
                            else
                                $unitipaddress = array();

                            $tmp_int_main = $this->template->network->findInterface($interfaceName);
                            if( !is_object($tmp_int_main) )
                            {
                                if( $print )
                                    print " * create interface: " . $interfaceName . "\n";
                                $tmp_int_main = $this->template->network->aggregateEthernetIfStore->newEthernetIf($interfaceName, 'layer3');

                                if( $print )
                                    print " * import interface to vsys: " . $this->template_vsys->name() . "\n";
                                $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                                if( $print )
                                    print " * add interface to virtualrouter: " . $tmp_virtual_router->name() . "\n";
                                $tmp_virtual_router->attachedInterfaces->addInterface($tmp_int_main);

                                if( count($unitipaddress) > 0 )
                                {
                                    #print_r( $unitipaddress );
                                    foreach( $unitipaddress as $tmp_ip )
                                        $tmp_int_main->addIPv4Address($tmp_ip);
                                }

                                $tmp_zone = $this->template_vsys->zoneStore->find($zoneName);
                                if( $tmp_zone == null )
                                {
                                    if( $print )
                                        print " * create zone: " . $zoneName . "\n";
                                    $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneName, 'layer3');
                                }

                                if( $print )
                                    print " * add interface to zone: " . $tmp_zone->name() . "\n";
                                $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                            }


///*
                            if( $unitname != $interfaceName )
                            {
                                $tmp_int_sub = $this->template->network->findInterface($unitname);
                                if( !is_object($tmp_int_sub) )
                                {
                                    if( $print )
                                        print " * create ae interface: " . $unitname . "\n";

                                    #$tmp_int_sub = $tmp_int_main->addSubInterface($unitname, $unittag);
                                    $tmp_int_sub = $tmp_int_main->addSubInterface($unittag, $unitname);

                                    if( $print )
                                        print " * import interface to vsys: " . $this->template_vsys->name() . "\n";
                                    $this->template_vsys->importedInterfaces->addInterface($tmp_int_sub);

                                    if( $print )
                                        print " * add interface to virtualrouter: " . $tmp_virtual_router->name() . "\n";
                                    $tmp_virtual_router->attachedInterfaces->addInterface($tmp_int_sub);

                                    if( $unitipaddress > 0 )
                                    {
                                        foreach( $unitipaddress as $tmp_ip )
                                            $tmp_int_sub->addIPv4Address($tmp_ip);
                                    }

                                    $tmp_zone = $this->template_vsys->zoneStore->find($zoneName);
                                    if( $tmp_zone == null )
                                    {
                                        if( $print )
                                            print " * create zone: " . $zoneName . "\n";
                                        $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneName, 'layer3');
                                    }

                                    if( $print )
                                        print " * add interface to zone: " . $tmp_zone->name() . "\n";
                                    $tmp_zone->attachedInterfaces->addInterface($tmp_int_sub);
                                }

                            }


//*/
                        }
                        else
                        {
                            print "what kind of interface information is this?";
                            print_r(array($vdom, $unittag, $unitname, $interfaceName, $unitipaddress1, $zoneName, $media));
                        }

                        if( $status == "down" )
                        {
                            if( $print )
                                mwarning("Interface: " . $interfaceName . " was configured as down - fix it\n", null, FALSE);
                        }

                        #$addInterface[] = "('$vrid','$source','$vdom','$template','$unittag','$unitname','$interfaceName','$unitipaddress1','$zoneName','$media')";
                        #Insert Zone
                        #$addZones[] = "('$source','$template','$vdom','$zoneName','layer3')";

                    }
                    $unittag = "";
                    $unitipaddress = array();
                    $zoneName = "";
                    $status = "";
                    $vr = "";
                    $media = "";
                    $unitname = "";
                    $unitipaddress1 = "";
                    $interfaceName = "";
                    $isZone = FALSE;
                }
                if( ($isZone == FALSE) and (preg_match("/\bend\b/i", $names_line)) )
                {
                    $isConfig = FALSE;
                }
            }
        }
        /*
        if (count($addZones) > 0) {
            $unique = array_unique($addZones);
            $projectdb->query("INSERT INTO zones (source,template,vsys,name,type) VALUES " . implode(",", $unique) . ";");
        }
        if (count($addInterface) > 0) {
            $unique = array_unique($addInterface);
            $projectdb->query("INSERT INTO interfaces (vr_id,source,vsys,template,unittag,unitname,name,unitipaddress,zone,media) VALUES " . implode(",", $unique) . ";");
        }

        #Add Interfaces to the VR
        $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
        while ($data = $getVR->fetch_assoc()) {
            $vr_id = $data['id'];
            $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id'");
            while ($data2 = $getInt->fetch_assoc()) {
                $int[] = $data2['unitname'];
            }
            $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
            $int = "";
        }

        #Add Interfaces to the Zones
        $getVR = $projectdb->query("SELECT name FROM zones WHERE template='$template';");
        while ($data = $getVR->fetch_assoc()) {
            $zone = $data['name'];
            $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND zone='$zone'");
            while ($data2 = $getInt->fetch_assoc()) {
                $int[] = $data2['unitname'];
            }
            $projectdb->query("UPDATE zones SET interfaces='" . implode(",", $int) . "' WHERE name='$zone';");
            $int = "";
        }
    */


        # Calculate Static Rutes
        #if (count($myVR)>0){
        ####$myVR = $this->template->network->virtualRouterStore->virtualRouters();

        print "\nget static routing:\n";

        $all_vsys = $this->template->getVirtualSystems();


        ##if( count( $myVR ) > 0 ){
        if( count($all_vsys) > 0 )
        {
            foreach( $all_vsys as $v )

                ##foreach ($myVR as $virtualRouter => $tmp_vr)
            {

                print "vsysname: ".$v->name()."\n";
                $this->template_vsys = $v;
                #$allRoutes[] = get_routes($params['config'], $params['source'], $params['vsys'], $params['ismultiornot'], $params['vr'], $params['template']);

                ##print "VRcount: ".count( $myVR )."\n";
                ##print "VRname: ".$tmp_vr->name()."\n";
                #$tmp_vsyss = $tmp_vr->findConcernedVsys();
                /*
                $tmp_vsyss = array();

                if(  count( $tmp_vsyss ) != 0 )
                {
                    $v = reset( $tmp_vsyss );
                }
                */

                #print "TEST: ".array_values($tmp_vsyss)[0]."\n";
                #$allRoutes[] = get_routes($data, $v, $ismultiornot, $tmp_vr);
                $allRoutes[] = $this->get_routes( $ismultiornot);
                #$allRoutes = array();
            }


            if( count($allRoutes) > 0 )
            {

                foreach( $allRoutes as $key => $value )
                {
                    if( $value != "" )
                    {
                        foreach( $value as $kkey => $vvalue )
                        {
                            $myroutes[] = $vvalue;
                        }
                    }
                }
                #$unique = array_unique($myroutes);


                #print_r( $myroutes );
                #$projectdb->query("INSERT INTO routes_static (source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys,admin_dist,vrouter) VALUES " . implode(",", $unique) . ";");


                foreach( $myroutes as $staticRoute )
                {
                    $tmp_vr = null;
                    $newRoute = null;
                    $tmpRoute = null;


                    $source = $staticRoute[0];
                    $vr_id = $staticRoute[1];
                    $template = $staticRoute[2];
                    $ip_version = $staticRoute[3];
                    $routename = $staticRoute[4];
                    $destination = $staticRoute[5];
                    $interfaceto = $staticRoute[6];
                    $nexthop = $staticRoute[7];
                    $nexthop_value = $staticRoute[8];
                    $metric = $staticRoute[9];
                    $vsys = $staticRoute[10];
                    $admin_dist = $staticRoute[11];
                    #$tmp_vr = $staticRoute[12];

                    $vr = "vr_" . $vsys;

                    $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
                    if( $tmp_vr === null )
                    {
                        $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
                    }

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


                    if( $ip_version == "v4" )
                        $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $nexthop_value . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $destination . "</destination></entry>";
                    elseif( $ip_version == "v6" )
                        $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ipv6-address>" . $nexthop_value . "</ipv6-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $destination . "</destination></entry>";


                    $newRoute = new StaticRoute($routename, $tmp_vr);
                    $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

                    if( $print )
                        print " * VR: " . $tmp_vr->name() . "| add static route " . $routename . ": " . $tmpRoute->name() . " with Destination: " . $destination . " - IP-Gateway: " . $nexthop_value . " - Interface: " . $interfaceto . "\n";

                    if( $ip_version == "v4" )
                        $tmp_vr->addstaticRoute($tmpRoute);
                    elseif( $ip_version == "v6" )
                        $tmp_vr->addstaticRoute($tmpRoute, 'ipv6');
                }


                $allRoutes = array();
            }
        }


    }


#function get_routes($fortinet_config_file, $source, $vsys, $ismultiornot, $vr_id, $template) {
#function get_routes($data, $v, $ismultiornot, $tmp_vr) {
    function get_routes( $ismultiornot)
    {
        global $projectdb;
        global $debug;
        global $print;

        $source = "";
        $template = "";

        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            print_r( $tmp_template_vsys );

            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        print "problem here VSYS: '".$vsys."'\n";

        $isRouting = FALSE;
        $isRoute = FALSE;
        $network = "";
        $netmask = "";
        $metric = "1";
        $isDisabled = FALSE;
        $gateway = "";
        $zoneName = "";
        $lastline = "x";
        $routes = array();
        $count = 0;

        $ip_version = "";
        $destination = "";
        $interface = "";
        $nexthop = "";
        $nexthop_value = "";
        $distance = "";
        $name = "";
        $vr_id = "";

        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }


        foreach( $this->data as $line => $names_line )
        {
            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {

                if( preg_match("/config router static/i", $names_line) )
                {
                    $isRouting = TRUE;
                }
                if( (preg_match("/\bend\b/i", $names_line)) and ($isRouting == TRUE) )
                {
                    $isRouting = FALSE;
                    break;
                };
                if( $isRouting == TRUE )
                {

                    if( preg_match("/\bedit\b/i", $names_line) )
                    {
                        $isRoute = TRUE;
                        $network = "";
                        $netmask = "";
                        $metric = "1";
                        $gateway = "";
                        $zoneName = "";
                        $ip_version = "";
                        $distance = "";
                        $nexthop_value = "";
                        $isDisabled = FALSE;
                        $nexthop = "None";
                        $destination = "";
                        $interface = "";
                        $vars = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $name = "Route " . trim($vars[1]);
                    }
                    elseif( (preg_match("/\bnext\b/i", $names_line)) and ($isDisabled == FALSE) )
                    {
                        $isRoute = FALSE;
                        $vars = "";
                        $vars = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                        if( $metric == "0" )
                        {
                            $metric = "1";
                        }
                        else
                        {
                            $metric = "10";
                        }

                        if( ($network == "0.0.0.0") and ($netmask == "0.0.0.0") )
                        {
                            if( $count == 0 )
                            {
                                $routes[] = array($source, $vr_id, $template, $ip_version, 'default', $destination, $interface, $nexthop, $nexthop_value, $metric, $vsys, $distance);
                                $count++;
                            }
                            else
                            {
                                $newRouteName = "default " . $count;
                                $routes[] = array($source, $vr_id, $template, $ip_version, $newRouteName, $destination, $interface, $nexthop, $nexthop_value, $metric, $vsys, $distance);
                                $count++;
                            }
                        }
                        elseif( ($network == "") and ($netmask == "") and ($nexthop_value != "") )
                        {
                            $destination = "0.0.0.0/0";
                            $ip_version = "v4";
                            $routes[] = array($source, $vr_id, $template, $ip_version, $name, $destination, $interface, $nexthop, $nexthop_value, $metric, $vsys, $distance);
                        }
                        elseif( ($network != "") and ($netmask != "") and (($nexthop_value != "") or ($nexthop == "discard")) )
                        {
                            $routes[] = array($source, $vr_id, $template, $ip_version, $name, $destination, $interface, $nexthop, $nexthop_value, $metric, $vsys, $distance);
                        }
                        elseif( ($network != "") and ($netmask != "") and ($interface != "") )
                        {
                            $routes[] = array($source, $vr_id, $template, $ip_version, $name, $destination, $interface, $nexthop, $nexthop_value, $metric, $vsys, $distance);
                            $interface = "";
                        }
                    }

                    if( $isRoute == TRUE )
                    {
                        if( preg_match("/set distance /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $distance = $data[2];
                        }

                        elseif( preg_match("/set status disable/i", $names_line) )
                        {
                            $isDisabled = TRUE;
                            $isRoute = FALSE;
                        }

                        elseif( preg_match("/set metric /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $metric = $data[2];
                        }
                        elseif( preg_match("/set device /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $interfaceRaw = $data[2];
                            if( $interfaceRaw != "" )
                            {

                                $tmp_zone = $this->template_vsys->zoneStore->find($interfaceRaw);

                                if( $tmp_zone !== null )
                                {
                                    #print "name: ".$tmp_zone->name()."\n";
                                    $tmp_interface2 = $tmp_zone->attachedInterfaces->interfaces();
                                    foreach( $tmp_interface2 as $demo )
                                    {
                                        if( $demo->type() == 'layer3' && count($demo->getLayer3IPv4Addresses()) > 0 )
                                        {
                                            #print "INTERFACE: ".$demo->name()."\n";

                                            $interface = $demo->name();
                                        }
                                    }
                                }

                                /*
                                //search for interface name attached to a zone
                                $getInt=$projectdb->query("SELECT unitname FROM interfaces WHERE zone='$interfaceRaw' AND source='$source';");
                                if ($getInt->num_rows==1){
                                    $getIntData=$getInt->fetch_assoc();
                                    $interface=$getIntData['unitname'];
                                }
                                */

                            }
                        }
                        elseif( preg_match("/set dst /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $network = $data[2];
                            $netmask = $data[3];
                            $cidr = $this->mask2cidrv4($netmask);
                            $destination = $network . "/" . $cidr;
                            $ip_version = $this->ip_version($network);
                        }
                        elseif( preg_match("/set gateway /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $nexthop_value = $data[2];
                            $nexthop = "ip-address";
                        }
                        elseif( preg_match("/set blackhole enable/i", $names_line) )
                        {
                            $nexthop = "discard";
                        }
                        else
                        {

                        }
                    }
                }
            }
            $lastline = $names_line;
        }
        return $routes;
    }


    function get_zones( $ismultiornot)
    {

        global $debug;
        global $print;

        $isConfigZone = FALSE;
        $zoneName = "";

        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }
        $lastline = "";
        foreach( $this->data as $line => $names_line )
        {
            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {
                if( preg_match("/config system zone/i", $names_line) )
                {
                    $isConfigZone = TRUE;
                }
                if( ($isConfigZone == TRUE) and (preg_match("/\bedit\b/i", $names_line)) )
                {
                    $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $zoneName = trim($data1[1]);
                    $zoneName = $this->truncate_names($this->normalizeNames($zoneName));
                }
                if( ($isConfigZone == TRUE) and (preg_match("/set interface/i", $names_line)) )
                {
                    $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    unset($data1[0]);
                    unset($data1[1]);
                    $tmp_int = [];

                    foreach( $data1 as $key => $int )
                    {
                        $tmp_zone = $this->template_vsys->zoneStore->find($int);

                        if( $tmp_zone !== null )
                        {
                            #print "name: ".$tmp_zone->name()."\n";
                            $tmp_interface2 = $tmp_zone->attachedInterfaces->interfaces();
                            foreach( $tmp_interface2 as $demo )
                            {
                                if( $demo->type() == 'layer3' )
                                {
                                    $tmp_int[] = $demo;

                                    if( $print )
                                        print " * remove interface " . $demo->name() . " from zone: " . $tmp_zone->name() . "\n";
                                    $tmp_zone->attachedInterfaces->removeInterface($demo);
                                }
                            }

                            if( $print )
                                print " * remove zone " . $tmp_zone->name() . " from vsys: " . $this->template_vsys->name() . "\n";
                            $this->template_vsys->zoneStore->removeZone($tmp_zone);
                        }
                    }

                    foreach( $tmp_int as $key => $value )
                    {

                        $tmp_zone = $this->template_vsys->zoneStore->find($zoneName);

                        if( $tmp_zone === null )
                        {
                            if( $print )
                                print " * create zone: " . $zoneName . "\n";
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneName, 'layer3');
                        }

                        if( $tmp_zone !== null )
                        {
                            if( $print )
                                print " * add interface " . $value->name() . " to zone: " . $tmp_zone->name() . "\n";
                            $tmp_zone->attachedInterfaces->addInterface($value);
                        }
                    }
                    $zoneName = "";
                }
                if( ($isConfigZone == TRUE) and (preg_match("/\bend\b/i", $names_line)) )
                {
                    $isConfigZone = FALSE;
                    $START = FALSE;
                }
            }
            $lastline = $names_line;
        }
    }


}


