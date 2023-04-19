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


trait SCREENOSnetwork
{
    function map_vr($screenos_config_file)
    {
        global $projectdb;

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

            if( (preg_match("/^set zone/", $names_line)) and (preg_match("/\bvrouter\b/", $names_line)) )
                #if( (preg_match("/^set zone/", $names_line)) )
            {

                $datavr = $this->name_preg_split($names_line);


                print "Zone: " . $datavr[2] . " - vrouter: " . $datavr[4] . "\n";

                $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($datavr[4]);

                $tmp_zone = $this->template_vsys->zoneStore->find($datavr[2]);
                if( $tmp_zone != null )
                {
                    $tmp_attachedIntefaces = $tmp_zone->attachedInterfaces->getAll();
                    foreach( $tmp_attachedIntefaces as $interface )
                    {


                        if( is_object($tmp_vr) )
                        {
                            print "add Interface: |" . $interface->name() . " to virtualRouter: " . $tmp_vr->name() . "|\n";
                            $tmp_vr->attachedInterfaces->addInterface($interface);
                        }
                        else
                            mwarning("virtualrouter: " . $datavr[4] . " not found\n", null, FALSE);

                    }
                }

                continue;

                $getVRID = $projectdb->query("SELECT id FROM virtual_routers WHERE name='$datavr[4]'  AND source='$source' AND template='$template';");
                if( $getVRID->num_rows > 0 )
                {
                    $getDataVR = $getVRID->fetch_assoc();
                    $vrid = $getDataVR['id'];
                    $projectdb->query("UPDATE interfaces SET vr_id='$vrid' WHERE zone='$datavr[2]' AND template='$template';");


                    /*
                    $getInt = $projectdb->query("SELECT interfaces FROM zones WHERE source='$source' AND template='$template'  AND name='$datavr[2]';");
                    if ($getInt->num_rows > 0) {
                        while ($newdata = $getInt->fetch_assoc()) {
                            $inter = $newdata['interfaces'];
                            $dd = explode(",", $inter);
                            $inter = array();
                            foreach ($dd as $key => $value) {
                                $inter[] = "'$value'";
                            }
                            $projectdb->query("UPDATE interfaces SET vr_id='$vrid' WHERE name IN (" . implode(",", $inter) . ") AND template='$template' AND source='$source';");
                            #print "UPDATE interfaces SET vr_id='$vrid' WHERE name IN (".implode(",",$inter).") AND template='$template' AND source='$source';\n";
                        }
                    }

                     */

                }
            }
        }

        #exit;
        /*
            $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE source='$source' AND template='$template';");
            if ($getVR->num_rows>0){
                while($data=$getVR->fetch_assoc()){
                    $vrid=$data['id'];
                    $getInt=$projectdb->query("SELECT tointerface, count(id) as t FROM routes_static WHERE template='$template' AND vr_id='$vrid' GROUP BY tointerface HAVING t > 1;");
                    if ($getInt->num_rows>0){
                        while($data2=$getInt->fetch_assoc()){
                            $interface=$data2['tointerface'];
                            if ($interface!=""){
                                $projectdb->query("UPDATE interfaces SET vr_id='$vrid' WHERE template='$template' AND unitname='$interface';");
                            }

                        }
                    }
                }
            }

            /*
            #Add Interfaces to the VR
            $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
            if ($getVR->num_rows > 0) {
                while ($data = $getVR->fetch_assoc()) {
                    $vr_id = $data['id'];
                    $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id';");
                    $int = array();
                    while ($data2 = $getInt->fetch_assoc()) {
                        $int[] = $data2['unitname'];
                    }
                    if (count($int) > 0) {
                        $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
                        #print "UPDATE virtual_routers SET interfaces='".implode(",",$int)."' WHERE id='$vr_id';\n";
                        $int = "";
                    }
                }
            }
             */
        /*
            $interfaces_updated = array();
            #Add Interfaces based on the Static Routes
            $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
            if ($getVR->num_rows > 0) {
                while ($data = $getVR->fetch_assoc()) {
                    $vr_id = $data['id'];
                    $getInt = $projectdb->query("SELECT tointerface FROM routes_static WHERE template='$template' AND vr_id='$vr_id';");
                    $int = array();
                    while ($data2 = $getInt->fetch_assoc()) {
                        if(strcmp($data2['tointerface'],"")!=0){
                            $int[] = $data2['tointerface'];
                        }
                    }
                    $int = array_unique($int);

                    if (count($int) > 0) {
                        $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
                        foreach($int as $interface_name){
                            if (!in_array($interface_name, $interfaces_updated)){
                                $query = 'UPDATE interfaces SET vr_id='.$vr_id.' WHERE unitname="'.$interface_name.'";';
                                $projectdb->query($query);
                                $interfaces_updated[] = $interface_name;
                            }
                        }
                        unset($int);
                    }
                }
            }

        */
    }


    function add_route_to_vr($xmlString, $vr)
    {
        $newRoute = new StaticRoute('***tmp**', $vr);

        $xmlElement = DH::importXmlStringOrDie($vr->owner->owner->xmlroot->ownerDocument, $xmlString);
        $xmlElement = DH::importXmlStringOrDie($vr->owner->xmlroot->ownerDocument, $xmlString);
        $newRoute->load_from_xml($xmlElement);

        return $newRoute;
    }


    /**
     *
     * @param type $screenos_config_file
     * @param type $source
     * @param type $vsys
     * @param type $ismultiornot
     * @param type $template
     * @global type $projectdb
     */
    function get_routes($screenos_config_file)
    {
        #global $projectdb;
        $isvrouter = FALSE;
        $param = FALSE;
        $add_route = array();
        $x = 1;
        $count = 0;
        $vsys = "root";

        $source = "";
        $vr_id = "";
        $template = "";
        $vr = "not set";

        foreach( $screenos_config_file as $line => $names_line )
        {
            if( preg_match("/^set vsys /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $vsys = $data[2];

                $this->template_vsys = $this->template->findVSYS_by_displayName($vsys);
                if( $this->template_vsys === null )
                {
                    derr($vsys . ": was not found ? Exit\n");
                }
            }

            if( ($isvrouter == TRUE) and ($param == FALSE) and (preg_match("/^exit/", $names_line)) )
            {
                $isvrouter = FALSE;
                $x = 1;
            }

            if( ($isvrouter == TRUE) and ($param == FALSE) )
            {
                if( preg_match("/^set route-map /i", $names_line) )
                {
                    $param = TRUE;
                }
                if( preg_match("/^set protocol /i", $names_line) )
                {
                    $param = TRUE;
                }
            }
            if( ($isvrouter == TRUE) and ($param == TRUE) )
            {
                if( preg_match("/^exit/i", $names_line) )
                {
                    $param = FALSE;
                }
            }

            if( preg_match("/^set vrouter /i", $names_line) )
            {
                $isvrouter = TRUE;
                $data = $this->name_preg_split($names_line);
                if( !isset($data[3]) or $data[3] == "sharable" )
                {
                    $vr = $data[2];

                    #print "vsys: ".$vsys." add vrouter: ".$vr."\n";

                    $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
                    if( $tmp_vr == null )
                        $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
                }
            }

            if( ($isvrouter == TRUE) and preg_match("/^set route source /i", $names_line) )
            {
                #set route source 10.10.10.0/24 interface ethernet0/2 gateway 1.1.1.1 preference 20 metric 2
                $data = $this->name_preg_split($names_line);
                $message = "The following route should be created as a Policy Based Forwarding Rule. "
                    . "<a href=\"https://FIREWALL_URL/#policies::VSYS::policies/pbf-rulebase\" target=blank>https://FIREWALL_URL/#policies::VSYS::policies/pbf-rulebase</a> "
                    . "<br><b>Source</b>: $data[3]";
                $get_interface = array_search('interface', $data);
                $interface_name = $data[$get_interface + 1];

                $get_destination = array_search('destination', $data);
                if( $get_destination > 0 )
                {
                    $destination_name = $data[$get_destination + 1];
                    $message = "$message<br><b>Destination</b>: $destination_name";
                }
                $message = "$message<br><b>Forwarding-Egress Interface</b>: $interface_name ";

                $get_gateway = array_search('gateway', $data);
                if( isset($get_gateway) )
                {
                    $gateway_name = $data[$get_gateway + 1];
                    $message = "$message<br><b>Forwarding-Next Hop</b>: $gateway_name";
                }
                #add_log2('error', 'Reading Route', 'Source Routes are not supported.', $source, $message, '', '', '');
            }

            elseif( ($isvrouter == TRUE) and preg_match("/^set route (.*) vrouter (.*)/i", $names_line) )
            {
                #set route 10.10.10.10/24 vrouter "vrt1" preference 20 metric 1
                $data = $this->name_preg_split($names_line);

                $network_and_mask = $data[2];

                $get_vroute = array_search('vroute', $data);
                $route_name = $data[$get_vroute + 1];

                $get_preference = array_search('preference', $data);
                $preference = $data[$get_preference + 1];

                $interfaceto = '';
                $get_vrouter = array_search('vrouter', $data);
                $gateway = $data[$get_vrouter + 1];
                $gateway = str_replace('"', "", $gateway);

                $route_name = "Route " . $x;
                $x++;

                #$add_route[] = array($network_and_mask,'next-vr',$gateway,$interfaceto,$preference,$route_name,$source,$tmp_vr,$vsys,$template);

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

                $xmlString = "<entry name=\"" . $route_name . "\"><nexthop><next-vr>" . $gateway . "</next-vr></nexthop><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);
                $tmp_vr->addstaticRoute($tmpRoute);
            }

            elseif(
                ($isvrouter == TRUE)
                and ((preg_match("/^set route /i", $names_line)) or (preg_match("/^set vrouter $vr route /i", $names_line)))
                and (preg_match("/ gateway /i", $names_line))
                and (!preg_match("/^set route source/i", $names_line))
            )
            {
                $data = $this->name_preg_split($names_line);
                #set route 0.0.0.0/0 interface ethernet1/1.1:1 gateway 166.14.132.57
                #set route 199.12.0.162/32 interface ethernet1/2.21:1 gateway 199.12.6.205 preference 20


                $get_gateway = array_search('gateway', $data);
                $gateway = $data[$get_gateway + 1];
                $get_network = array_search('route', $data);
                if( $get_network )
                {
                    $network_and_mask = $data[$get_network + 1];
                }
                else
                {
                    $network_and_mask = $data[2];
                }

                $get_preference = array_search('preference', $data);
                $preference = $data[$get_preference + 1];
                $get_interface = array_search('interface', $data);
                if( $get_interface !== FALSE )
                {
                    $interfaceto1 = $data[$get_interface + 1];
                    $int = explode(":", $interfaceto1);
                    $interfaceto = $int[0];
                }
                else
                {
                    $interfaceto = "";
                }

                if( !is_numeric($preference) )
                {
                    $preference = "1";
                }

                if( $network_and_mask == "0.0.0.0/0" )
                {
                    if( $count == 0 )
                    {
                        $add_route[] = array($network_and_mask, 'ip-address', $gateway, $interfaceto, $preference, 'default', $source, $vr_id, $vsys, $template);

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

                        $xmlString = "<entry name=\"default\"><nexthop><ip-address>" . $gateway . "</ip-address></nexthop><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                        $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);
                        $tmp_vr->addstaticRoute($tmpRoute);

                        $count++;
                    }
                    else
                    {
                        $routeNewName = 'default ' . $count;
                        $add_route[] = array($network_and_mask, 'ip-address', $gateway, $interfaceto, $preference, $routeNewName, $source, $vr_id, $vsys, $template);

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
                        $xmlString = "<entry name=\"" . $routeNewName . "\"><nexthop><ip-address>" . $gateway . "</ip-address></nexthop><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                        $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);
                        $tmp_vr->addstaticRoute($tmpRoute);

                        $count++;
                    }
                }
                else
                {
                    $route_name = "Route " . $x;

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

                    if( preg_match("/\bgateway\b/", $names_line) )
                    {
                        $route_type = "ip-address";
                        $nexthop_value = $gateway;
                        $xmlString = "<entry name=\"" . $route_name . "\"><nexthop><ip-address>" . $gateway . "</ip-address></nexthop><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                    }
                    else
                    {
                        $route_type = "None";
                        $nexthop_value = "";
                        $xmlString = "<entry name=\"" . $route_name . "\"><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";

                        if( $interfaceto == "" )
                            mwarning("route type NONE: but no Interface\n");
                    }
                    $add_route[] = array($network_and_mask, $route_type, $nexthop_value, $interfaceto, $preference, $route_name, $source, $vr_id, $vsys, $template);


                    $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);
                    $tmp_vr->addstaticRoute($tmpRoute);

                    $x++;
                }
            }
            elseif( ($isvrouter == TRUE) and ((preg_match("/^set route /i", $names_line)) or (preg_match("/^set vrouter $vr route /i", $names_line))) and (preg_match("/ interface /i", $names_line)) )
            {
                #set route 55.128.17.56/32 interface ethernet0/0 preference 20 description "txt"
                $data = $this->name_preg_split($names_line);
                $get_network = array_search('route', $data);
                if( $get_network )
                {
                    $network_and_mask = $data[$get_network + 1];
                }
                else
                {
                    $network_and_mask = $data[2];
                }
                $get_interface = array_search('interface', $data);
                if( $get_interface !== FALSE )
                {
                    $interfaceto1 = $data[$get_interface + 1];
                    $int = explode(":", $interfaceto1);
                    $interfaceto = $int[0];
                }
                else
                {
                    $interfaceto = "";
                }
                $get_preference = array_search('preference', $data);
                $preference = $data[$get_preference + 1];
                if( !is_numeric($preference) )
                {
                    $preference = "1";
                }
                if( $network_and_mask == "0.0.0.0/0" )
                {
                    if( $count == 0 )
                    {
                        #$add_route[] = "('$network_and_mask','ip-address','$gateway','$interfaceto','$preference','default','$source','$vr_id','$vsys','$template')";

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
                        $xmlString = "<entry name=\"default\"><nexthop><ip-address>" . $gateway . "</ip-address></nexthop><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                        $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);
                        $tmp_vr->addstaticRoute($tmpRoute);

                        $count++;
                    }
                    else
                    {
                        $routeNewName = 'default ' . $count;
                        #$add_route[] = "('$network_and_mask','ip-address','$gateway','$interfaceto','$preference','$routeNewName','$source','$vr_id','$vsys','$template')";

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
                        $xmlString = "<entry name=\"" . $routeNewName . "\"><nexthop><ip-address>" . $gateway . "</ip-address></nexthop><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                        $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);
                        $tmp_vr->addstaticRoute($tmpRoute);

                        $count++;
                    }
                }
                else
                {
                    $route_name = "Route " . $x;

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

                    if( preg_match("/\bgateway\b/", $names_line) )
                    {
                        $route_type = "ip-address";
                        $nexthop_value = $gateway;
                        $xmlString = "<entry name=\"" . $route_name . "\"><nexthop><ip-address>" . $gateway . "</ip-address></nexthop><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";
                    }
                    else
                    {
                        $route_type = "None";
                        $nexthop_value = "";
                        $xmlString = "<entry name=\"" . $route_name . "\"><metric>" . $preference . "</metric>" . $xml_interface . "<destination>" . $network_and_mask . "</destination></entry>";

                        if( $interfaceto == "" )
                            mwarning("route type NONE: but no Interface\n");
                    }
                    #$add_route[] = array($network_and_mask,$route_type,$nexthop_value,$interfaceto,$preference,$route_name,$source,$vr_id,$vsys,$template);


                    $tmpRoute = $this->add_route_to_vr($xmlString, $tmp_vr);
                    $tmp_vr->addstaticRoute($tmpRoute);

                    $x++;
                }
            }

        }


        /*
            #Map zones to routes by interface
            $getGW = $projectdb->query("SELECT id,tointerface FROM routes_static WHERE source='$source' AND template='$template';");
            if ($getGW->num_rows > 0) {
                while ($data = $getGW->fetch_assoc()) {
                    $tointerface = $data['tointerface'];
                    $routeid = $data['id'];
                    #Compare agains what interface is
                    $getZone = $projectdb->query("SELECT zone FROM interfaces WHERE unitname='$tointerface' AND source='$source';");
                    if ($getZone->num_rows > 0) {
                        $getZoneData = $getZone->fetch_assoc();
                        $theZone = $getZoneData['zone'];
                        $projectdb->query("UPDATE routes_static SET zone='$theZone' WHERE id='$routeid';");
                    }
                }
            }
        */
    }


    function get_interfaces($screenos_config_file)
    {
        global $projectdb;
        $interfaces = array();
        $zones = array();
        global $dip;
        global $debug;
        global $print;
        $vsys = "root";


        $source = "";
        $template = "";

        foreach( $screenos_config_file as $line => $names_line )
        {

            $names_line = trim($names_line);


            if( preg_match("/^set vsys /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $vsys = $data[2];

                $this->template_vsys = $this->template->findVSYS_by_displayName($vsys);
                if( $this->template_vsys === null )
                {
                    derr("vsys: |" . $vsys . "| could not be found ! Exit\n");
                }
            }

            if( preg_match("/^set vrouter /i", $names_line) )
            {
                //TODO:
            }
            if( preg_match("/^set interface /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                #echo "DATA: \n";
                #print_r($data);

                $dip_tp_sat_type = "";
                $int = explode(":", $data[2]);
                $interName = $int[0];


                if( $vsys != "root" && $vsys != 'mgmt' )
                    $interfaces[$interName]["vsys"] = $vsys;


                if( $data[3] == "zone" )
                {
                    $interfaces[$interName]["zone"] = $data[4];
                    //echo "Data 4: " .$data[4]. "\n";
                }
                elseif( ($data[3] == "ip") and (preg_match("/\//", $data[4])) )
                {
                    if( isset($interfaces[$interName]["ip"]) )
                    {
                        if( strpos($interfaces[$interName]["ip"], $data[4]) == FALSE )
                        {
                            $interfaces[$interName]["ip"] .= "," . $data[4];
                        }
                    }
                    else
                    {
                        $interfaces[$interName]["ip"] = $data[4];
                    }
                }
                elseif( ($data[3] == "ip") and filter_var($data[4], FILTER_VALIDATE_IP) and filter_var($data[5], FILTER_VALIDATE_IP) )
                {
                    $cidr = $this->mask2cidrv4($data[5]);
                    $new_interface = $data[4] . "/" . $cidr;
                    if( isset($interfaces[$interName]["ip"]) )
                    {
                        if( strpos($interfaces[$interName]["ip"], $new_interface) == FALSE )
                            $interfaces[$interName]["ip"] .= "," . $new_interface;
                    }
                    else
                    {
                        $interfaces[$interName]["ip"] = $data[4];
                    }
                }
                elseif( $data[3] == "tag" )
                {
                    $interfaces[$interName]["tag"] = $data[4];
                    $interfaces[$interName]["zone"] = $data[6];
                    //echo "Data 6: " .$data[6]. "\n";
                }
                elseif( ($data[3] == "ext") and ($data[7] == "dip") )
                {
                    $dip_id = $data[8];
                    if( $data[9] == "shift-from" )
                    {
                        # Alert ? Not supported by now
                        if( $debug )
                            mwarning("dip shift-from | not supported yet", null, FALSE);
                    }
                    else
                    {
                        $dip_startip = $data[9];
                        $dip_endip = $data[10];
                        if( isset($data[11]) )
                        {
                            if( $data[11] == "fix-port" )
                            {
                                $dip_tp_sat_type = "dynamic-ip";
                            }
                        }
                        else
                        {
                            $dip_tp_sat_type = "dynamic-ip-and-port";
                        }

                        $dip[] = array($vsys, $dip_id, $interName, $dip_startip, $dip_endip, $dip_tp_sat_type);
                    }

                }
                #MIP
                elseif( $data[3] == "dip" )
                {
                    $dip_id = $data[4];
                    if( $data[5] == "shift-from" )
                    {
                        # Alert ? Not supported by now
                    }
                    else
                    {
                        $dip_startip = $data[5];
                        if( isset($data[6]) )
                        {
                            $dip_endip = $data[6];
                        }
                        else
                        {
                            print_r($data);
                            mwarning("dip not endip", null, FALSE);
                        }

                        if( isset($data[7]) )
                        {
                            if( $data[7] == "fix-port" )
                            {
                                $dip_tp_sat_type = "dynamic-ip";
                            }
                        }
                        else
                        {
                            $dip_tp_sat_type = "dynamic-ip-and-port";
                        }
                    }
                    $dip[] = array($vsys, $dip_id, $interName, $dip_startip, $dip_endip, $dip_tp_sat_type);
                }
                elseif( $data[3] == "mip" )
                {
                    //function get_nat_MIP handle this part
                    /*
                    $mip_ip = $data[4];
                    $mip_name = "MIP".$mip_ip;
                    $tmp_object = $this->sub->addressStore->find( $mip_name );
                    if( $tmp_object == null )
                    {
                        $tmp_object = $this->sub->addressStore->newAddress($mip_name, 'ip-netmask', $mip_ip);
                    }
                    */
                    #print "set interface  : data[3] mip not supported yet: ".$names_line."\n";
                    #mwarning( "interface MIP IP not supported yet", null, false);
                }
                elseif( $data[2] == "id" )
                {
                    $int = explode(":", $data[4]);
                    $interName = $int[0];
                    if( $data[5] == "zone" )
                    {
                        $interfaces[$interName]["zone"] = $data[6];
                    }
                }
                else
                {
                    //Todo: 20190515 continue interface implementation
                    #mwarning( "set interface // not supported yet data[3]: ".$data[3]." line: ".$names_line, null, false);
                }
            }

        }


        if( count($interfaces) > 0 )
        {
            $outInterface = array();
            foreach( $interfaces as $key => $interface )
            {
                if( isset($interface["vsys"]) )
                    $vsys = $interface['vsys'];
                if( isset($interface["tag"]) )
                {
                    /*
                    if (preg_match("/\./", $key)) {
                        $unitName = $key;
                    } else {
                        $unitName = $key . "." . $interface["tag"];
                    }
                    */
                    $unitName = $key;
                    $unitTag = $interface["tag"];
                }
                else
                {
                    $unitName = $key;
                    $unitTag = "0";
                }
                if( isset($interface["ip"]) )
                {
                    $all_ipaddress = $interface["ip"];
                }
                else
                {
                    $all_ipaddress = "";
                }
                if( isset($interface["zone"]) )
                {
                    $zone = $interface["zone"];
                    //echo "ZONA---->" .$zone. "\n";
                    $zones[] = "('$source','$template','$vsys','$zone','layer3')";
                }
                else
                {
                    $zone = "";
                }
                if( preg_match("/^tunnel/", $key) )
                {
                    $outInterface[] = array('tunnel', $source, 'tunnel', 'layer3', '', $unitName, $unitTag, $all_ipaddress, $template, $vsys, $zone);
                }
                elseif( preg_match("/^loopback/", $key) )
                {
                    $outInterface[] = array('loopback', $source, 'loopback', 'layer3', '', $unitName, $unitTag, $all_ipaddress, $template, $vsys, $zone);
                }
                else
                {
                    if( preg_match("/\./", $key) )
                    {
                        $removetags = explode(".", $key);
                        $key = $removetags[0];
                    }
                    $outInterface[] = array('ethernet', $source, $key, 'layer3', '', $unitName, $unitTag, $all_ipaddress, $template, $vsys, $zone);
                }
            }


            foreach( $outInterface as $int )
            {
                if( $int[9] == "root" )
                {
                    $this->template_vsys = $this->template->findVirtualSystem('vsys1');
                    if( $this->template_vsys === null )
                    {
                        derr("vsys: vsys1 could not be found ! Exit\n");
                    }
                }
                else
                {
                    $this->template_vsys = $this->template->findVSYS_by_displayName($int[9]);
                    if( $this->template_vsys === null )
                    {
                        derr($int[9] . ": was not found ? Exit\n");
                    }
                }


                if( $int[0] == 'ethernet' )
                {
                    $tmp_int_main = $this->template->network->findInterface($int[2]);
                    if( !is_object($tmp_int_main) )
                    {
                        $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($int[2], 'layer3');
                        $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                        if( $int[7] != "" and ($int[5] == $int[2]) )
                        {
                            $int_array = explode(",", $int[7]);
                            foreach( $int_array as $tmp_int_name )
                                $tmp_int_main->addIPv4Address($tmp_int_name);
                        }
                        if( $int[10] != "" )
                        {
                            $tmp_zone = $this->template_vsys->zoneStore->find($int[10]);
                            if( $tmp_zone == null )
                                $tmp_zone = $this->template_vsys->zoneStore->newZone($int[10], 'layer3');

                            $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                        }

                    }
                    if( !$this->template_vsys->importedInterfaces->hasInterface($tmp_int_main) )
                        $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                    if( $int[5] !== $int[2] )
                    {
                        $tmp_sub = $this->template->network->findInterface($int[5]);
                        if( !is_object($tmp_sub) )
                        {
                            print "   - add subinterface: " . $int[5] . "\n";
                            $tmp_sub = $tmp_int_main->addSubInterface($int[6], $int[5]);
                            $this->template_vsys->importedInterfaces->addInterface($tmp_sub);
                        }


                        if( !$this->template_vsys->importedInterfaces->hasInterface($tmp_sub) )
                            $this->template_vsys->importedInterfaces->addInterface($tmp_sub);

                        print "name: " . $tmp_sub->name() . " type: " . $tmp_sub->type . "\n";

                        if( $int[7] != "" )
                        {
                            $int_array = explode(",", $int[7]);
                            foreach( $int_array as $tmp_int_name )
                                $tmp_sub->addIPv4Address($tmp_int_name);
                        }
                        if( $int[10] != "" )
                        {
                            $tmp_zone = $this->template_vsys->zoneStore->find($int[10]);
                            if( $tmp_zone == null )
                                $tmp_zone = $this->template_vsys->zoneStore->newZone($int[10], 'layer3');

                            $tmp_zone->attachedInterfaces->addInterface($tmp_sub);
                        }
                    }
                }
                elseif( $int[0] == 'tunnel' )
                {
                    $tmp_int_main = $this->template->network->findInterface($int[2]);
                    if( !is_object($tmp_int_main) )
                    {
                        $tmp_int_main = $this->template->network->tunnelIfStore->newTunnelIf($int[5]);
                        $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                        if( $int[7] != "" )
                        {
                            $tmp_int_main->addIPv4Address($int[7]);
                        }
                    }
                    if( $int[10] != "" )
                    {
                        $tmp_zone = $this->template_vsys->zoneStore->find($int[10]);
                        if( $tmp_zone == null )
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($int[10], 'layer3');

                        $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                    }

                }
                elseif( $int[0] == 'loopback' )
                {
                    $tmp_int_main = $this->template->network->findInterface($int[5]);
                    if( !is_object($tmp_int_main) )
                    {
                        $tmp_int_main = $this->template->network->loopbackIfStore->newLoopbackIf($int[5]);
                        $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                        if( $int[7] != "" )
                        {
                            $tmp_int_main->addIPv4Address($int[7]);
                        }
                    }
                    if( $int[10] != "" )
                    {
                        $tmp_zone = $this->template_vsys->zoneStore->find($int[10]);
                        if( $tmp_zone == null )
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($int[10], 'layer3');

                        $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                    }

                }
                else
                {

                    if( $debug )
                    {
                        print "interface type: " . $int[0] . " must be implemented\n";
                        print_r($int);
                    }
                }
            }

            unset($outInterface);
            unset($interfaces);
        }
    }


}


