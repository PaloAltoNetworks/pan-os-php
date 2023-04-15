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

trait FORTINETnatrules
{
    function remove_regions_from_nat($source, $vsys)
    {
        global $projectdb;
        $RegionsFound = array();

        $getDFRegions = $projectdb->query("SELECT id,name FROM default_regions;");
        if( $getDFRegions->num_rows > 0 )
        {
            while( $getDFRegionsData = $getDFRegions->fetch_assoc() )
            {
                $defaultRegions[$getDFRegionsData['id']] = $getDFRegionsData['name'];
            }
        }

        $ids_rules = getNatIdsBySourceVsys($source, $vsys);

        $getRegions = $projectdb->query("SELECT rule_lid,member_lid FROM nat_rules_src WHERE table_name='default_regions' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
        if( $getRegions->num_rows > 0 )
        {
            while( $getRegionsData = $getRegions->fetch_assoc() )
            {
                $rule_lid = $getRegionsData['rule_lid'];
                $member_lid = $getRegionsData['member_lid'];
                if( isset($defaultRegions[$member_lid]) )
                {
                    $regionName = $defaultRegions[$member_lid];
                    $RegionsFound[$rule_lid][] = $regionName;
                }
            }
            if( count($RegionsFound) > 0 )
            {
                foreach( $RegionsFound as $Rule => $Region )
                {
                    add_log2("warning", "Removing Regions from NAT Rules", 'Nat RuleID [' . $Rule . '] contains Regions [' . implode(",", $Region) . ']', $source, 'Expedition will Remove Regions from Nat Rules', 'rules', $Rule, 'nat_rules');
                }
                $projectdb->query("DELETE FROM nat_rules_src WHERE rule_lid IN (" . implode(",", array_keys($RegionsFound)) . " AND table_name='default_regions')");
            }
        }

        $getRegions = $projectdb->query("SELECT rule_lid,member_lid FROM nat_rules_dst WHERE table_name='default_regions' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
        if( $getRegions->num_rows > 0 )
        {
            while( $getRegionsData = $getRegions->fetch_assoc() )
            {
                $rule_lid = $getRegionsData['rule_lid'];
                $member_lid = $getRegionsData['member_lid'];
                if( isset($defaultRegions[$member_lid]) )
                {
                    $regionName = $defaultRegions[$member_lid];
                    $RegionsFound[$rule_lid][] = $regionName;
                }
            }
            if( count($RegionsFound) > 0 )
            {
                foreach( $RegionsFound as $Rule => $Region )
                {
                    add_log2("warning", "Removing Regions from NAT Rules", 'Nat RuleID [' . $Rule . '] contains Regions [' . implode(",", $Region) . ']', $source, 'Expedition will Remove Regions from Nat Rules', 'rules', $Rule, 'nat_rules');
                }
                $projectdb->query("DELETE FROM nat_rules_dst WHERE rule_lid IN (" . implode(",", array_keys($RegionsFound)) . " AND table_name='default_regions')");
            }
        }
    }

    #add_nat_from_vip($data, $v, $source, $ismultiornot, $addVIP);
    function add_nat_from_vip($data,  $source, $ismultiornot, $addVIP)
    {
        global $debug;
        global $print;

        global $projectdb;
        $nat_lid = "";
        $addDestination = "";
        $addTag = array();
        $dnat = $snat = $uturn = FALSE;

        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }


        #$getVIP = $projectdb->query("SELECT protocol,name,extip,extintf,portforward,mappedip,extport,mappedport,vsys,source FROM fortinet_vip WHERE vsys='$vsys' AND source='$source';");
        #if ( $getVIP->num_rows > 0) {
        if( count($addVIP) > 0 )
        {
            $create_tag_array = array('dnat' => 'DNAT', 'snat' => 'SNAT', 'uturn' => 'U-TURN');

            foreach( $create_tag_array as $key => $create_tag )
            {
                $tmp_tag = $this->sub->tagStore->find($create_tag);
                if( $tmp_tag == null )
                {
                    $tmp_tag = $this->sub->tagStore->createTag($create_tag);
                }

                if( $tmp_tag != null )
                {
                    if( $key == "dnat" )
                    {
                        $dnat = TRUE;
                        $DNAT_tag = $tmp_tag;
                    }

                    elseif( $key == 'snat' )
                    {
                        $snat = TRUE;
                        $SNAT_tag = $tmp_tag;
                    }

                    elseif( $key == 'uturn' )
                    {
                        $uturn = TRUE;
                        $UTURN_tag = $tmp_tag;
                    }
                }
            }

            # Create new TAGS for Nat RULEs DNAT and SNAT and U-TURN
            /*
            $getTags=$projectdb->query("SELECT id,name FROM tag WHERE name IN ('DNAT','SNAT','U-TURN') AND source='$source' AND vsys='$vsys';");
            if ($getTags->num_rows>0){
                $dnat=$snat=$uturn=false;
                while($getTagsData=$getTags->fetch_assoc()){
                    if ($getTagsData['name']=="DNAT"){
                        $dnat=true;
                        $DNAT_tag=$getTagsData['id'];
                    }
                    if ($getTagsData['name']=="SNAT"){
                        $snat=true;
                        $SNAT_tag=$getTagsData['id'];
                    }
                    if ($getTagsData['name']=="U-TURN"){
                        $uturn=true;
                        $UTURN_tag=$getTagsData['id'];
                    }
                }
            }

            if ($dnat==false){
                $projectdb->query("INSERT INTO tag (name,name_ext,source,vsys,devicegroup,color,comments) VALUES ('DNAT','DNAT','$source','$vsys','default','color1','Created by Expedition');");
                $DNAT_tag=$projectdb->insert_id;
            }
            if ($snat==false){
                $projectdb->query("INSERT INTO tag (name,name_ext,source,vsys,devicegroup,color,comments) VALUES ('SNAT','SNAT','$source','$vsys','default','color2','Created by Expedition');");
                $SNAT_tag=$projectdb->insert_id;
            }
            if ($uturn==false){
                $projectdb->query("INSERT INTO tag (name,name_ext,source,vsys,devicegroup,color,comments) VALUES ('U-TURN','U-TURN','$source','$vsys','default','color3','Created by Expedition');");
                $UTURN_tag=$projectdb->insert_id;
            }
            */

            //not needed anymore
            /*
            $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
            if ($getPosition->num_rows == 0) {
                $position = 0;
            } else {
                $ddata = $getPosition->fetch_assoc();
                $position = $ddata['t'] ;
            }
            if ($nat_lid == "") {
                $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
                $getLID1 = $getlastlid->fetch_assoc();
                $nat_lid = intval($getLID1['max']);
            }
            */


            //Todo SWASCHKUT 20191001 is this needed
            /*
                    # Load Interfaces
                    $loadInterface=$projectdb->query("SELECT unitipaddress,unitname,zone FROM interfaces WHERE template='$template' AND source='$source' AND unitipaddress !='';");
                    if ($loadInterface->num_rows>0){
                        $interfaces=array();
                        while($loadInterfaceData=$loadInterface->fetch_assoc()){
                            $interfacesRaw=explode(",",$loadInterfaceData['unitipaddress']);
                            foreach($interfacesRaw as $interfacesRawItem){
                                $interfaces[$interfacesRawItem]["zone"]=$loadInterfaceData['zone'];
                                $interfaces[$interfacesRawItem]["name"]=$loadInterfaceData['unitname'];
                            }
                        }
                    }

                    # Pre load Objects with the interface information
                    $objectsInMemory=array();
                    foreach ($interfaces as $checkNet=>$properties){
                        $interfacesRaw=explode("/",$checkNet);
                        $interfacesRawIP=$interfacesRaw[0];
                        $interfacesRawMask=$interfacesRaw[1];
                        $interfacesNet = long2ip((ip2long($interfacesRawIP)) & ((-1 << (32 - (int)$interfacesRawMask))));
                        $theNetwork=$interfacesNet."/".$interfacesRawMask;
                        $getAddress=$projectdb->query("SELECT id FROM address WHERE source='$source' AND (vsys='$vsys' OR vsys='shared')  AND ipaddress='$interfacesNet' AND cidr='$interfacesRawMask' LIMIT 1;");
                        if ($getAddress->num_rows>0){
                            $getAddressData=$getAddress->fetch_assoc();
                            $objectsInMemory[$theNetwork]=$getAddressData['id'];
                        }
                    }

                    # GET Virtual Router based on VSYS
                    $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE vsys='$vsys' AND template='$template' AND source='$source';");
                    if ($getVR->num_rows>0){
                        $getVRDAta=$getVR->fetch_assoc();
                        $vr=$getVRDAta['id'];
                    }
            */


            foreach( $addVIP as $data )
            {

                if( $debug )
                {
                    print "addVIP\n";
                    print_r($data);
                }

                /*
        #while ($data = $getVIP->fetch_assoc()) {
            $ruleName = $data['name'];
            $ruleNameClean=truncate_rulenames($this->normalizeNames($ruleName));
            $to = '';
            $from = $data['extintf'];
            $extport = $data['extport'];
            $protocol = $data['protocol'];
            $tp_dat_port = $data['mappedport'];
            $extip = $data['extip'];
            $mappedip = $data['mappedip'];
            $portforward=$data['portforward'];

            if ($from=="any"){
                $addUturn=true;
            }
            else{
                $addUturn=false;
            }

            if ($extport != "") {
                $getSRV = $projectdb->query("SELECT id FROM services WHERE dport='$extport' AND protocol='$protocol' AND vsys='$vsys' AND source='$source' GROUP BY dport,protocol;");
                if ($getSRV->num_rows == 0) {
                    $name = $protocol . "-" . $extport;
                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol,description) VALUES ('$source','$vsys','$name','$name','$extport','$protocol','Created by Expedition')");
                    $op_service_lid = $projectdb->insert_id;
                    $op_service_table = "services";
                }
                else {
                    $dddata = $getSRV->fetch_assoc();
                    $op_service_lid = $dddata['id'];
                    $op_service_table = "services";
                }
            }

            $getExtip = $projectdb->query("SELECT id,type FROM address WHERE name='$ruleName' AND ipaddress='$extip' AND vsys='$vsys' AND source='$source';");
            if ($getExtip->num_rows == 1) {
                $AddDST=true;
                $dddata = $getExtip->fetch_assoc();
                $dst_lid = $dddata['id'];
                $dst_type = $dddata['type'];
                $dst_table = "address";


            }
            else {
                $AddDST=false;
                if (preg_match("/\-/", $mappedip)) {
                    #Range
                    $newName = "range-" . $mappedip;
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$mappedip','','Created by Expedition','ip-range','')");
                    $dst_lid = $projectdb->insert_id;
                    $dst_table = "address";
                    $dst_type = "ip-range";
                }
                else {
                    #IP-netmask
                    $newName = "H-" . $mappedip;
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$mappedip','32','Created by Expedition','ip-netmask','')");
                    $dst_lid = $projectdb->insert_id;
                    $dst_table = "address";
                    $dst_type = "ip-netmask";
                }
            }


            $getMappedip = $projectdb->query("SELECT id,type FROM address WHERE ipaddress='$mappedip' AND vsys='$vsys' AND source='$source' GROUP BY ipaddress;");
            if ($getMappedip->num_rows == 1) {
                $dddata = $getMappedip->fetch_assoc();
                $tp_dat_address_lid = $dddata['id'];
                $tp_dat_address_table = "address";
                $dat_type = $dddata['type'];
            }
            else {
                if (preg_match("/\-/", $mappedip)) {
                    #Range
                    $newName = "range-" . $mappedip;
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$mappedip','','Created by Expedition','ip-range','ip-range')");
                    $tp_dat_address_lid = $projectdb->insert_id;
                    $tp_dat_address_table = "address";
                    $dat_type = "ip-range";
                } else {
                    #IP-netmask
                    $newName = "H-" . $mappedip;
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$mappedip','32','Created by Expedition','ip-netmask','ip-netmask')");
                    $tp_dat_address_lid = $projectdb->insert_id;
                    $tp_dat_address_table = "address";
                    $dat_type = "ip-netmask";
                }
            }

            if ($addUturn==true){
                $position++;
                $nat_lid++;

                # get The network from the Translated Address
                $foundInterface=false;
                $foundStatic=false;
                foreach($interfaces as $checkNet=>$properties){

                    if (preg_match("/\-/", $mappedip)) {
                        $mappedRaw=explode("-",$mappedip);
                        $mappedip=$mappedRaw[0];
                    }

                    if (netMatchV4($checkNet, $mappedip)==TRUE){
                        $matchedNetworkRaw=explode("/",$checkNet);
                        $matchedNetwork=$matchedNetworkRaw[0];
                        $matchedNetmask=$matchedNetworkRaw[1];
                        $matchedZone=$properties['zone'];
                        $matchedNetworkIP=$checkNet;
                        $matchedInterface=$properties['name'];
                        $interfacesNet = long2ip((ip2long($matchedNetwork)) & ((-1 << (32 - (int)$matchedNetmask))));
                        $matchedTheNetwork=$interfacesNet."/".$matchedNetmask;
                        $foundInterface=true;
                    }
                }

                if ($foundInterface==false){
                    $matchedZone="";
                    #Check if Network Object Exists
                    if (preg_match("/\-/", $mappedip)) {
                        $mappedRaw=explode("-",$mappedip);
                        $mappedip=$mappedRaw[0];
                    }

                    add_log2('warning','Creating U-Turn Nats FROM VIPs','Unable to calculate netmask for IP/Range ['.$mappedip.'] on Nat Rule ['.$nat_lid.']',$source,'Attaching 24 as CIDR. Please review','rules',$nat_lid,'nat_rules');
                    $matchedNetmask=24;
                    $matchedNetworkIP='';
                    $matchedInterface='';
                    $interfacesNet = long2ip((ip2long($mappedip)) & ((-1 << (32 - (int)$matchedNetmask))));
                    $matchedTheNetwork=$interfacesNet."/".$matchedNetmask;
                }

                if (!isset($objectsInMemory[$matchedTheNetwork])){
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','NET-$interfacesNet-$matchedNetmask','NET-$interfacesNet-$matchedNetmask','$interfacesNet','$matchedNetmask','Created by Expedition','ip-netmask','ip-netmask')");
                    $objectsInMemory[$matchedTheNetwork]=$projectdb->insert_id;
                }
                $member_lid=$objectsInMemory[$matchedTheNetwork];
                $addSource[]="('$source','$vsys','$nat_lid','$member_lid','address')";
                $ruleNameCleanC=truncate_rulenames($ruleNameClean."C");

                # Fix Destination Zone in case is ANY
                if ($to==""){
                    $getTO=getAutoZoneToVR($vr, $dst_lid, $dst_table, $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $to=key($getTO);
                    }
                }

                if ($matchedZone==""){
                    $getTO=getAutoZoneToVR($vr, $member_lid, 'address', $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $matchedZone=key($getTO);
                        if ($matchedNetworkIP==""){
                            $getInt=$projectdb->query("SELECT unitname,unitipaddress FROM interfaces WHERE zone='$matchedZone' AND source='$source' AND template='$template';");
                            if ($getInt->num_rows>0){
                                $getIntData=$getInt->fetch_assoc();
                                $matchedNetworkIP=$getIntData['unitipaddress'];
                                $matchedInterface=$getIntData['unitname'];
                            }
                        }
                    }
                }

                $addRule[] = "('0','$nat_lid','$source','$vsys','$ruleNameCleanC',1,'$position','Added from VIP','$to','','','','$tp_dat_address_lid','$tp_dat_address_table','dynamic-ip-and-port','interface-address','$matchedNetworkIP','$matchedInterface')";
                $addTag[] = "('$nat_lid','$UTURN_tag','tag')";
                $addFROM[] = "('$source','$vsys','$nat_lid','$matchedZone')";
                $addDestination[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";

            }

            # Add the Destination Nat Rule
            $position++;
            $nat_lid++;

            if ($dst_type != $dat_type) {
                $checkit = 1;
                add_log('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from FORTINET');
            }

            # In case the mapped port its a range just keep any



            if (preg_match("/-/",$tp_dat_port)){$tp_dat_port='';}

            if ($from!="any"){
                $addFROM[] = "('$source','$vsys','$nat_lid','$from')";
            }
            else{
                $from="";
            }

            if ($to=="any"){$to='';}
            if ($AddDST==true){
                $addDestination[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                # Fix Destination Zone in case is ANY
                if ($to==""){
                    $getTO=getAutoZoneToVR($vr, $dst_lid, $dst_table, $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $to=key($getTO);
                    }
                }
            }

            $addRule[] = "('$checkit','$nat_lid','$source','$vsys','$ruleNameClean',1,'$position','Added from VIP','$to','$op_service_lid','$op_service_table','$tp_dat_port','$tp_dat_address_lid','$tp_dat_address_table','','','','')";
            $addTag[] = "('$nat_lid','$DNAT_tag','tag')";



            if ($portforward==0){
                # If the port forward is not set we should have to create the Source Nat to force the nat like static-ip
                $position++;
                $nat_lid++;
                if (($tp_dat_address_lid!="") AND ($tp_dat_address_table!="")){
                    $addSource[]="('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                }

                # Fix Destination Zone in case is ANY
                if ($to==""){
                    $getTO=getAutoZoneToVR($vr, $dst_lid, $dst_table, $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $to=key($getTO);
                    }
                }

                if ($from==""){
                    $getFROM=getAutoZoneToVR($vr, $tp_dat_address_lid, $tp_dat_address_table, $vsys, $source);
                    if ((count($getFROM)>0) AND (key($getFROM)!='')){
                        $from=key($getFROM);
                        $addFROM[] = "('$source','$vsys','$nat_lid','$from')";
                    }
                }

                $addTranslated[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                $ruleNameCleanB=truncate_rulenames($ruleNameClean."B");
                $addRule[] = "('$checkit','$nat_lid','$source','$vsys','$ruleNameCleanB',0,'$position','Added from VIP','$to','','','','','','dynamic-ip-and-port','translated-address','','')";
                $addTag[] = "('$nat_lid','$SNAT_tag','tag')";

                $ruleName = "";
                $ruleNameClean=$ruleNameCleanB="";
                $to = "";
                $op_service_lid = "";
                $op_service_table = "";
                $tp_dat_port = "";
                $tp_dat_address_lid = "";
                $tp_dat_address_table = "";
                $checkit = 0;
            }



            $ruleName = "";
            $ruleNameClean=$ruleNameCleanB="";
            $to = "";
            $op_service_lid = "";
            $op_service_table = "";
            $tp_dat_port = "";
            $tp_dat_address_lid = "";
            $tp_dat_address_table = "";
            $checkit = 0;
                */

            }


            /*
            if (count($addRule) > 0) {
                $projectdb->query("INSERT INTO nat_rules (checkit,id,source,vsys,name,is_dat,position,description,op_zone_to,op_service_lid,op_service_table,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,tp_sat_type,tp_sat_address_type,tp_sat_ipaddress,tp_sat_interface) VALUES " . implode(",", $addRule) . ";");
                unset($addRule);
                if ((count($addDestination) > 0) AND ($addDestination!="")) {
                    $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addDestination) . ";");
                    unset($addDestination);
                }
                if ((count($addSource) > 0) AND ($addSource!="")) {
                    $projectdb->query("INSERT INTO nat_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addSource) . ";");
                    unset($addSource);
                }
                if ((count($addFROM)>0) AND ($addFROM!="")){
                    $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addFROM) . ";");
                    unset($addFROM);
                }
                if (count($addTranslated)>0){
                    $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$addTranslated).";");
                    unset($addTranslated);
                }
                if (count($addTag)>0){
                    $projectdb->query("INSERT INTO nat_rules_tag (rule_lid,member_lid,table_name) VALUES ".implode(",",$addTag).";");
                }

            }
            */

        }

    }


    function get_ippools( $ismultiornot)
    {
        global $debug;
        global $print;
        global $tmp_template_vsys;

        global $projectdb;
        $isObject = FALSE;
        $isAddress = FALSE;
        $addHost = array();
        $addressName = "";
        $endip = "";
        $startip = "";
        $addressNamePan = "";
        $source = "";



        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        $addVIP = array();


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
                if( preg_match("/config firewall ippool/i", $names_line) )
                {
                    $isObject = TRUE;
                }


                if( $isObject )
                {
                    if( preg_match("/^\bend\b/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/\bedit\b/i", $names_line) )
                    {
                        $isAddress = TRUE;
                        if( preg_match('/"([^"]+)"/', $names_line, $match) )
                        {
                            $newname = str_replace('/', '-', $match[1]);
                            $addressNamePan = $this->truncate_names($this->normalizeNames($newname));
                            $addressName = trim($match[1]);
                        }
                    }

                    if( $isAddress )
                    {

                        if( preg_match("/\bstartip\b/i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $startip = trim($meta[2]);
                        }

                        if( preg_match("/\bendip\b/i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $endip = trim($meta[2]);
                        }
                        if( preg_match("/\bnext\b/i", $names_line) )
                        {

                            $addVIP[] = array($addressName, $source, $vsys, $endip, $startip);
                            if( $startip == $endip )
                            {
                                $addHost[] = array($source, $vsys, $addressName, $addressNamePan, 'ip-netmask', $startip, '32', 'Created from a IPPOOL', '');
                            }
                            else
                            {
                                $addHost[] = array($source, $vsys, $addressName, $addressNamePan, 'ip-range', $startip . "-" . $endip, '', 'Created from a IPPOOL', '');
                            }

                            $isAddress = FALSE;
                            $endip = "";
                            $startip = "";
                            $addressNamePan = "";
                            $addressName = "";
                        }
                    }
                }
            }
            else
                #print "NO START\n";


            $lastline = $names_line;
        }


        if( count($addVIP) > 0 )
        {
            //Todo: swaschkut 20190930 create array???? or tmp address objects?
            #$projectdb->query("INSERT INTO fortinet_ippools (name,source,vsys,end_ip,start_ip) VALUES " . implode(",", $addVIP) . ";");
        }

        print "COUNTER: ".count($addHost)."\n";
        if( count($addHost) > 0 )
        {
            foreach( $addHost as $tmp_addr )
            {
                $name = $tmp_addr[3];
                $type = $tmp_addr[4];
                $ipaddress = $tmp_addr[5];
                $cidr = $tmp_addr[6];
                $description = $tmp_addr[7];

                $tmp_address = $this->sub->addressStore->find($name);
                if( $tmp_address === null )
                {
                    $value = $ipaddress;
                    if( $cidr !== "" )
                        $value = $value . "/" . $cidr;

                    if( $print )
                        print " * create object: " . $name . " type: " . $type . " value: " . $value . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value, $description);
                    #$addlog = "no value or type available in original config file";
                    #$tmp_address->set_node_attribute( 'error', $addlog );
                }
                else
                {
                    mwarning("address object: '" . $name . "' already available.", null, FALSE);
                }
            }
            /*
            if ($addHost != "") {
                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,type,ipaddress,cidr,description,vtype) VALUES " . implode(",", $addHost) . ";");
            }
            */
        }
    }

    function get_vip( $ismultiornot, &$addVIP)
    {

        global $debug;
        global $print;
        global $tmp_template_vsys;

        global $projectdb;
        $isObject = FALSE;
        $isAddress = FALSE;
        $addHost = array();
        #$addVIP = array();

        $isFake = FALSE;

        $isAddress = FALSE;
        $extip = "";
        $extintf = "";
        $mappedip = "";
        $extport = "";
        $mappedport = "";
        $portforward = 0;
        $addressNamePan = "";
        $addressName = "";
        $protocol = "tcp";
        $type = "";

        $source = "";


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
                if( preg_match("/config firewall vip/i", $names_line) )
                {
                    $isObject = TRUE;
                }

                if( $isObject )
                {
                    if( preg_match("/^\bend\b/i", $names_line) and ($isFake == FALSE) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/\bedit\b/i", $names_line) and ($isFake == FALSE) )
                    {
                        $isAddress = TRUE;
                        if( preg_match('/"([^"]+)"/', $names_line, $match) )
                        {
                            $newname = str_replace('/', '-', $match[1]);
                            $addressNamePan = $this->truncate_names($this->normalizeNames($newname));
                            $addressName = trim($match[1]);
                            $type = "";
                            $isFake = FALSE;
                        }
                    }

                    if( $isAddress )
                    {

                        if( preg_match("/set type server-load-balance/", $names_line) )
                        {
                            $type = "LB";
                        }

                        if( preg_match("/set extip /", $names_line) )
                        {
                            $meta = explode("set extip ", $names_line);
                            $extip = trim($meta[1]);

                            if( $type == "LB" )
                            {
                                $addHost[] = array($source, $vsys, $addressName, $addressNamePan, 'ip-netmask', $extip, '32', 'Created from a VIP was Load Balancer Not supported by Expedition', '');
                                $addressName = "";
                                $type = "";
                            }

                        }
                        if( preg_match("/set extintf /i", $names_line) )
                        {
                            if( preg_match('/"([^"]+)"/', $names_line, $match) )
                            {
                                $extintf = trim($match[1]);
                            }
                        }
                        if( preg_match("/set portforward /i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( $meta[2] == "enable" )
                            {
                                $portforward = 1;
                            }
                            else
                            {
                                $portforward = 0;
                            }
                        }
                        if( preg_match("/set mappedip /i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $mappedip = trim($meta[2]);
                        }
                        if( preg_match("/set extport /i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $extport = trim($meta[2]);
                        }
                        if( preg_match("/set mappedport /i", $names_line) )
                        {
                            $meta = explode("set mappedport ", $names_line);
                            $mappedport = trim($meta[1]);
                        }
                        if( preg_match("/set protocol /i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $protocol = trim($meta[2]);
                        }

                        if( preg_match("/edit /", $names_line) )
                        {
                            $isFake = TRUE;
                        }
                        if( preg_match("/next/", $names_line) and ($isFake == TRUE) )
                        {
                            $isFake = FALSE;
                        }

                        if( preg_match("/\bnext\b/i", $names_line) and ($isFake == FALSE) )
                        {

                            if( $addressName != "" )
                            {
                                $addVIP[] = array($addressName, $source, $vsys, $extip, $extintf, $mappedip, $mappedport, $extport, $portforward, $protocol);

                                if( preg_match("/\-/", $extip) )
                                {
                                    $addHost[] = array($source, $vsys, $addressName, $addressNamePan, 'ip-range', $extip, '', 'Created from a VIP', '');
                                }
                                else
                                {
                                    $addHost[] = array($source, $vsys, $addressName, $addressNamePan, 'ip-netmask', $extip, '32', 'Created from a VIP', '');
                                }

                                $isAddress = FALSE;
                                $extip = "";
                                $extintf = "";
                                $mappedip = "";
                                $extport = "";
                                $mappedport = "";
                                $portforward = 0;
                                $addressNamePan = "";
                                $addressName = "";
                                $protocol = "tcp";
                                $type = "";
                            }
                        }
                    }
                }
            }

            $lastline = $names_line;
        }
        if( count($addVIP) > 0 )
        {
            //Todo: how to handle VIP - see also ippools

            mwarning( "VIP not yet implemented" );
            print_r( $addVIP );

            #$projectdb->query("INSERT INTO fortinet_vip (name,source,vsys,extip,extintf,mappedip,mappedport,extport,portforward,protocol) VALUES " . implode(",", $addVIP) . ";");
        }
        if( count($addHost) > 0 )
        {

            foreach( $addHost as $tmp_addr )
            {
                $name = $tmp_addr[3];
                $type = $tmp_addr[4];
                $ipaddress = $tmp_addr[5];
                $cidr = $tmp_addr[6];
                $description = $tmp_addr[7];

                $tmp_address = $this->sub->addressStore->find($name);
                if( $tmp_address === null )
                {
                    $value = $ipaddress;
                    if( $cidr !== "" )
                        $value = $value . "/" . $cidr;

                    if( $print )
                        print " * create object: " . $name . " type: " . $type . " value: " . $value . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name, $type, $value, $description);
                    #$addlog = "no value or type available in original config file";
                    #$tmp_address->set_node_attribute( 'error', $addlog );
                }
                else
                {
                    mwarning("address object: '" . $name . "' already available.", null, FALSE);
                }
            }

            /*if ($addHost != "") {
                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,type,ipaddress,cidr,description,vtype) VALUES " . implode(",", $addHost) . ";");
            }*/
        }
    }

    function get_vipgrp( $ismultiornot, &$addVIP)
    {

        global $debug;
        global $print;

        global $projectdb;
        $isObject = FALSE;
        $isAddress = FALSE;
        #$addVIP = array();
        $addressGroupsMembers = array();
        $addressGroup = array();
        $addressName_ext = "";
        $interface = "";
        $addressName_int = "";
        $members = array();

        $source = "";

        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        /*
        $lid=0;
        $getMaxID = $projectdb->query("SELECT max(id) as max FROM address_groups_id;");
        if ($getMaxID->num_rows == 1) {
            $max1 = $getMaxID->fetch_assoc();
            $lid = $max1['max'];
            if (($lid == null) OR ($lid == '')){
                $lid=0;
            }
            $lid++;
        }
        */

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
                if( preg_match("/config firewall vipgrp/i", $names_line) )
                {
                    $isObject = TRUE;
                }

                if( $isObject )
                {
                    if( preg_match("/^\bend\b/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/\bedit\b/i", $names_line) )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $newname = str_replace('/', '-', $meta[1]);
                        $addressName_int = $this->truncate_names($this->normalizeNames($newname));
                        $addressName_ext = trim($meta[1]);
                    }

                    if( $isAddress )
                    {
                        if( preg_match("/\binterface\b/i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $interface = trim($meta[2]);
                        }
                        if( preg_match("/set member /i", $names_line) )
                        {
                            $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            unset($meta[0]);
                            unset($meta[1]);
                            $members = $meta;
                        }

                        if( preg_match("/\bnext\b/i", $names_line) )
                        {
                            $membersExtended = implode(",", $members);
                            $addVIP[] = array($addressName_ext, $source, $vsys, $interface, $membersExtended);
                            #Add AddressGroups and members
                            //$addressGroup[]="('$lid','$source','$vsys','$addressName_ext','$addressName_int','static')";
                            $HostGroupNamePan = $addressName_int;
                            $tmp_addressgroup = $this->sub->addressStore->find($HostGroupNamePan);
                            if( $tmp_addressgroup === null )
                            {
                                if( $print )
                                    print "\n * create addressgroup: " . $HostGroupNamePan . "\n";
                                $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($HostGroupNamePan);
                            }
                            else
                            {
                                print PH::boldText("   * addressgroup: " . $HostGroupNamePan . " already available; VSYS: " . $this->sub->name() . " - using existing one\n");
                            }

                            foreach( $members as $key => $value )
                            {
                                //$addressGroupsMembers[]="('$source','$vsys','$lid','$value')";
                                $tmp_address = $this->sub->addressStore->find($value);
                                if( $tmp_address !== null )
                                {
                                    if( $print )
                                    {
                                        print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                                    }
                                    $tmp_addressgroup->addMember($tmp_address);
                                }
                                else
                                    mwarning("address object with name: " . $value . " not found\n", null, FALSE);
                            }

                            $isAddress = FALSE;
                            $members = array();
                            $interface = "";
                            $addressName_int = "";
                            $addressName_ext = "";
                            #$lid++;
                        }
                    }
                }
            }


            $lastline = $names_line;
        }
        if( count($addVIP) > 0 )
        {
            if( $addVIP != "" )
            {
                #$projectdb->query("INSERT INTO fortinet_vipgrp (name,source,vsys,interface,member) VALUES " . implode(",", $addVIP) . ";");
            }
        }
        /*
        if (count($addressGroup)>0){
            #$projectdb->query("INSERT INTO address_groups_id (id,source,vsys,name_ext,name,type) VALUES ".implode(",",$addressGroup).";");
            unset($addressGroup);
            if (count($addressGroupsMembers)>0){
                #$projectdb->query("INSERT INTO address_groups (source,vsys,lid,member) VALUES ".implode(",",$addressGroupsMembers).";");
                unset($addressGroupsMembers);
            }
        }
        */
    }

}


