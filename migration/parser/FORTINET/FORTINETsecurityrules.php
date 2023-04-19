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

trait FORTINETsecurityrules
{
    #$addSNAT[] = array($RuleNamePan, $Status, $ZonaDST, '', 0, $srv_member_lid, $srv_table_name, 'dynamic-ip-and-port', 'translated-address', '', $Comments, '', $ZonaSRC);
    function create_source_nat_policy( $tmp_rule, $rule_name, $dip_type, $tmp_address, $snat_int_array = array())
    {
        global $debug;
        global $print;


        $tmp_nat_rule = $this->sub->natRules->find($rule_name);
        if( $tmp_nat_rule == null )
        {
            if( $print )
                print " * create NATrule: '" . $rule_name . "'\n";
            $tmp_nat_rule = $this->sub->natRules->newNatRule($rule_name);


            #$tmp_rule->display();
            $disabled = "";
            if( $tmp_rule->isDisabled() )
                $tmp_nat_rule->setDisabled(TRUE);

            //From
            $tmp_froms = $tmp_rule->from->getAll();
            foreach( $tmp_froms as $tmp_from )
                $tmp_nat_rule->from->addZone($tmp_from);

            //To
            $tmp_tos = $tmp_rule->to->getAll();
            if( count($tmp_tos) == 1 )
            {

                if( $tmp_tos[0] == 'any' )
                {
                    mwarning("DSTZONE fix needed", null, FALSE);
                }
                else
                    $tmp_nat_rule->to->addZone($tmp_tos[0]);
            }
            else
            {
                if( $debug )
                    mwarning("security rule " . $tmp_rule->name() . " has more than 1 to Zone\n", null, FALSE);
            }


            //SRC
            $tmp_srcs = $tmp_rule->source->getAll();
            foreach( $tmp_srcs as $tmp_src )
                $tmp_nat_rule->source->addObject($tmp_src);

            //DST
            $tmp_dsts = $tmp_rule->destination->getAll();
            foreach( $tmp_dsts as $tmp_dst )
                $tmp_nat_rule->destination->addObject($tmp_dst);

            //SRV:
            $tmp_services = $tmp_rule->services->getAll();
            if( count($tmp_services) == 1 )
                $tmp_nat_rule->setService($tmp_services[0]);
            else
            {
                $g_name = str_replace(" ID ", "", $rule_name);
                $tmp_servicegroup = $this->sub->serviceStore->find("SRV_Group_" . $g_name);
                if( $tmp_servicegroup == null )
                {
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup("SRV_Group_" . $g_name);
                    foreach( $tmp_services as $tmp_service )
                        $tmp_servicegroup->addMember($tmp_service);
                }
                $tmp_nat_rule->setService($tmp_servicegroup);
            }

            //add DIP NAT rule # Interface DIP later on
            if( $dip_type == "dip-id" )
            {
                //dynamic-IP translated address
                //src nat:
                $tmp_nat_rule->snathosts->addObject($tmp_address);
                $tmp_nat_rule->changeSourceNAT('dynamic-ip-and-port');
            }
            else
            {
                if( count($snat_int_array) > 1 )
                    if( $debug )
                    {
                        print "NAT rule: " . $tmp_nat_rule->name() . "\n";
                        #print_r( $snat_int_array);
                        print "fix interface: snat intr more then one";
                        #mwarning( "fix interface: snat intr more then one", null, false );
                    }

                if( isset($snat_int_array[0][0]) )
                {
                    #$tmp_nat_rule->snatinterface = $snat_int_array[0][0];
                    $tmp_nat_rule->setSNATInterface($snat_int_array[0][0]);
                }
                if( isset($snat_int_array[0][1]) )
                {
                    /*
                    $tmp_value = explode( '/', $snat_int_array[0][1]  );
                    $tmp_address_snat_int = $this->sub->addressStore->all( 'value string.regex /'.$tmp_value[0].'/' );


                    if( !empty( $tmp_address_snat_int ) && count( $tmp_address_snat_int  == 1) && $tmp_address_snat_int[0]->getNetworkValue() == $tmp_value[0] )
                    {
                        #print "mip existing ip name ".$tmp_address1[0]->name()." value: ".$tmp_address1[0]->value()." add to rule\n";
                        $tmp_address_snat_int = $tmp_address_snat_int[0];
                    }
                    else
                    {
                        */
                    $new_name = $name_int = $this->truncate_names($this->normalizeNames($snat_int_array[0][1]));
                    $tmp_address_snat_int = $this->sub->addressStore->find($new_name);
                    if( $tmp_address_snat_int === null )
                        $tmp_address_snat_int = $this->sub->addressStore->newAddress($new_name, 'ip-netmask', $snat_int_array[0][1]);
                    //}

                    $tmp_nat_rule->snathosts->addObject($tmp_address_snat_int);

                }


                $tmp_nat_rule->changeSourceNAT('dynamic-ip-and-port');
            }

        }
        else
        {
            mwarning("NAT Rule name already available: " . $rule_name, null, FALSE);
        }
    }

    function get_security_policy($data1, $source, $ismultiornot, &$regions)
    {

        global $debug;
        global $print;

        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        global $projectdb;
        $isAddress = FALSE;
        $isObject = FALSE;
        $sql = array();
        $sql1 = array();
        $lid = "";
        $addressNamePan = "";
        $addressName = "";
        $nat_lid = "";
        $sql_rule = array();
        $sql_src_zone = array();
        $sql_dst_zone = array();
        $Comments = "";
        $Status = "";
        $sql_src = array();
        $sql_dst = array();
        $sql_srv = array();
        $Action = "deny";
        $nat_activated = 0;
        $ippool = "";
        $srv_table_name = "";
        $srv_member_lid = "";
        $src_table_name = "";
        $src_member_lid = "";
        $dst_member_lid = "";
        $dst_table_name = "";
        $addNatDst_tmp = array();
        $addNatSrc_tmp = array();
        $addNatSrc = array();
        $addNatDst = array();

        $addSNAT = array();
        $addNATFrom = array();
        $addNATTranslatedAddress = array();


        $multi_service = FALSE;


        $thecolor = 1;
        $x = 1;
        //Todo: swaschkut 20190930
        /*
            #Load Default Regions
            $defaultRegions=array();
            $getDFRegions=$projectdb->query("SELECT id,name FROM default_regions;");
            if ($getDFRegions->num_rows>0){
                while($getDFRegionsData=$getDFRegions->fetch_assoc()){
                    $defaultRegions[$getDFRegionsData['name']]=$getDFRegionsData['id'];
                }
            }

            #Load TAGS in case we found set global-label
            $getTag=$projectdb->query("SELECT id,name FROM tag WHERE source='$source';");
            if ($getTag->num_rows>0){
                $allTags=array();
                while($getTagData=$getTag->fetch_assoc()){
                    $allTags[$getTagData['name']]=$getTagData['id'];
                }
            }
        */


        /*
            $getPosition = $projectdb->query("SELECT max(position) as t FROM security_rules WHERE vsys='$vsys' AND source='$source';");
            if ($getPosition->num_rows == 0) {
                $position = 1;
            } else {
                $ddata = $getPosition->fetch_assoc();
                $position = $ddata['t'] + 1;
            }
            if ($lid == "") {
                $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
                $getLID1 = $getlastlid->fetch_assoc();
                $lid = intval($getLID1['max']) + 1;
            }
            $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
            if ($getPosition->num_rows == 0) {
                $nat_position = 1;
            } else {
                $ddata = $getPosition->fetch_assoc();
                $nat_position = $ddata['t'] + 1;
            }
            if ($nat_lid == "") {
                $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
                if ($getlastlid->num_rows==0){
                    $nat_lid = 1;
                }
                else{
                    $getLID1 = $getlastlid->fetch_assoc();
                    $nat_lid = intval($getLID1['max']) + 1;
                }

            }
        */
//TMP
        $position = "";
        $nat_position = "";
        $ZonaDST = "";
        $ZonaSRC = "";
        $checkit = 0;
        $negate_destination = 0;
        $negate_source = 0;

        $tmp_rule = null;


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
        foreach( $data1 as $line => $names_line )
        {
            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( (preg_match("/\bconfig firewall policy\b/i", $lastline)) and (preg_match("/^end/i", $names_line)) )
            {
                $START = FALSE;
                $VDOM = FALSE;
            }

            if( $START )
            {
                if( preg_match("/\bconfig firewall policy\b/i", $names_line) )
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
                    if(
                        preg_match("/\bedit\b/i", $names_line) &&
                        (preg_match("/\bnext\b/i", $lastline) || preg_match("/\bconfig firewall policy\b/i", $lastline))
                    )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $RuleName = "Rule " . trim($meta[1]);
                        $RuleNamePan = $this->truncate_names($this->normalizeNames($RuleName));

                        $tmp_rule = $this->sub->securityRules->find($RuleNamePan);


                        if( $tmp_rule == null )
                        {
                            if( $print )
                                print " * create rule: '" . $RuleNamePan . "'\n";
                            $tmp_rule = $this->sub->securityRules->newSecurityRule($RuleNamePan);
                        }
                        else
                            if( $debug )
                            {
                                mwarning("rule " . $RuleNamePan . " already available\n", null, FALSE);
                            }

                    }

                    if( $isAddress )
                    {
                        if( preg_match("/\bnext\b/i", $names_line) )
                        {
                            $isAddress = FALSE;

                            if( $print )
                            {
                                print "     - Description: " . $Comments . "\n";
                                print "     - set action: " . $Action . "\n";
                            }
                            $tmp_rule->setDescription($Comments);
                            $tmp_rule->setAction($Action);

                            if( $Status )
                            {
                                if( $print )
                                    print "     - disable Rule\n";
                                $tmp_rule->setDisabled(TRUE);
                            }

                            if( $negate_source )
                            {
                                if( $print )
                                    print "     - set Source negated\n";
                                $tmp_rule->setSourceIsNegated(TRUE);
                            }

                            if( $negate_destination )
                            {
                                if( $print )
                                    print "     - set Destination negated\n";
                                $tmp_rule->setDestinationIsNegated(TRUE);
                            }

                            //Todo:
                            /*
                             * $checkit -
                             * 1) IPsec is enabled | maybe if TAG is set
                             * 2) or  application-list
                             */


                            #$sql_rule[] = "('$lid','$position','$RuleNamePan','$source','$vsys','$Comments','$Action','$Status','$checkit','$negate_source','$negate_destination')";
//NAT is activated
                            if( $nat_activated == 1 )
                            {
                                if( $ippool != "" )
                                {
                                    #Do Source Nat
                                    $name = $this->truncate_names($this->normalizeNames($ippool));

                                    $tmp_address = $this->sub->addressStore->find($name);
                                    if( $tmp_address === null )
                                        $tmp_address = $this->sub->addressStore->find("tmp-" . $name);

                                    if( $tmp_address !== null )
                                    {
                                        $pool_table_name = "address";
                                        $pool_member = $tmp_address;
                                    }
                                    else
                                    {
                                        //Todo: swaschkut 20190930
                                        //check if object is available from default_regions
                                        $addlog = "IPPOOL not found in DB Source:[' . $ippool . '] in Rule " . $tmp_rule->name() . " fix to be added";
                                        $tmp_rule->set_node_attribute('warning', $addlog);

                                        mwarning($addlog, null, FALSE);
                                    }
                                    /*
                                    $getPool = $projectdb->query("SELECT id FROM address WHERE name_ext='$ippool' AND source='$source' AND vsys='$vsys';");
                                    if ($getPool->num_rows == 1) {
                                        $getPoolData = $getPool->fetch_assoc();
                                        $pool_member_lid = $getPoolData['id'];
                                        $pool_table_name = "address";
                                    } else {
                                        //Todo: swaschkut 20190930
                                        #add_log('error', 'Phase 5: Reading NAT Policies', 'IPPOOL not found in DB Source:[' . $ippool . '] in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'fix to be added');
                                    }
                                    */

                                    if( $multi_service === TRUE )
                                    {
                                        $srv_member_lid = "";
                                        $srv_table_name = "";
                                        //Todo: swaschkut 20190930
                                        #add_log2('error', 'Phase 5: Reading NAT Policies', 'More than one Service found in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'Create a group and add the group to the rule if you need','rules',$nat_lid,'nat_rules');
                                    }
                                    if( $ZonaDST == "any" )
                                        $ZonaDST = "";

                                    #$addSNAT[] = array($source, $vsys, $nat_lid, $nat_position, $RuleNamePan, $Status, $ZonaDST, '', 0, $srv_member_lid, $srv_table_name, 'dynamic-ip-and-port', 'translated-address', '', $Comments, '', $ZonaSRC);
                                    $this->create_source_nat_policy( $tmp_rule, $RuleNamePan, 'dip-id', $pool_member, null);


                                    if( $ZonaSRC != "any" )
                                    {
                                        #$addNATFrom[] = array($source, $vsys, $nat_lid, $ZonaSRC);
                                    }


                                    //Todo: swaschkut 20191001 fix neeted
                                    #$addNATTranslatedAddress[] = array($source, $vsys, $nat_lid, $pool_member, $pool_table_name);
//                                $nat_lid++;
//                                $nat_position++;
                                }
                                else
                                {
                                    #Source Nat with the External interface
                                    if( $ZonaDST == "any" )
                                    {
                                        //Todo: swaschkut 20190930
                                        #add_log2('warning','Creating Oubound Nat from Security Rule ['.$lid.']','Unable to identify the interface to use for Outbound Nat on Nat Rule ['.$nat_lid.']',$source,'Assign The right interface.','rules',$nat_lid,'nat_rules');
                                        #$addSNAT[] = array($source, $vsys, $nat_lid, $nat_position, $RuleNamePan, $Status, '', '', 0, $srv_member_lid, $srv_table_name, 'dynamic-ip-and-port', 'interface-address', '', $Comments, '', $ZonaSRC);
                                        $this->create_source_nat_policy( $tmp_rule, $RuleNamePan, 'interface', null, array());

                                        if( $ZonaSRC != "any" )
                                        {
                                            #$addNATFrom[] = array($source, $vsys, $nat_lid, $ZonaSRC);
                                        }

                                        if( $multi_service === TRUE )
                                        {
                                            $srv_member_lid = "";
                                            $srv_table_name = "";
                                            //Todo: swaschkut 20190930
                                            #add_log2('error', 'Phase 5: Reading NAT Policies', 'More than one Service found in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'Create a group and add the group to the rule if you need','rules',$nat_lid,'nat_rules');
                                        }
                                    }
                                    else
                                    {
                                        //Todo: check if $this->template_vsys->zoneStore->hasZoneNamed( 'name, true [casesensitive] ) is not better

                                        $snat_int_array = array();

                                        #$tmp_zone = $this->template_vsys->zoneStore->hasZoneNamed( $ZonaDST, true );

                                        $tmp_zones = $this->template_vsys->zoneStore->getall();
                                        foreach( $tmp_zones as $tmp_zone )
                                        {
                                            if( $tmp_zone->name() == $ZonaDST )
                                            {
                                                #print "name: " . $tmp_zone->name() . "\n";
                                                $tmp_interface = $tmp_zone->attachedInterfaces->interfaces();
                                                foreach( $tmp_interface as $demo )
                                                {
                                                    if( $demo->type() == 'layer3' && count($demo->getLayer3IPv4Addresses()) > 0 )
                                                    {
                                                        #print "INTERFACE: ".$demo->name()."\n";

                                                        $snat_int_array[] = array($demo->name(), $demo->getLayer3IPv4Addresses()[0]);
                                                    }
                                                }
                                            }
                                        }

                                        #$gettmp=$projectdb->query("SELECT interfaces FROM zones WHERE BINARY name='$ZonaDST' AND vsys='$vsys' AND source='$source' LIMIT 1;");
                                        if( count($snat_int_array) > 0 )
                                            #if ($gettmp->num_rows==1)
                                        {
                                            /*
                                            $gettmpData=$gettmp->fetch_assoc();
                                            $gettmpInt=$gettmpData['interfaces'];
                                            $interfaceName=explode(",",$gettmpInt);

                                            $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE BINARY unitname='$interfaceName[0]' AND vsys='$vsys' AND source='$source';");
                                            if ($getInterface->num_rows == 1) {
                                                $getInterfaceData = $getInterface->fetch_assoc();
                                                $interfacedata = $getInterfaceData['unitipaddress'];
                                            }
                                            */
                                            //Todo: swaschkut 20191001
                                            $interfacedata = $snat_int_array[0][1];
                                            $interfaceName = $snat_int_array[0][0];


                                            if( $multi_service === TRUE )
                                            {
                                                $srv_member_lid = "";
                                                $srv_table_name = "";
                                                //Todo: swaschkut 20190930
                                                #add_log2('error', 'Phase 5: Reading NAT Policies', 'More than one Service found in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'Create a group and add the group to the rule if you need','rules',$nat_lid,'nat_rules');
                                            }
                                            if( preg_match("/,/", $interfacedata) )
                                            {
                                                //Todo: swaschkut 20190930
                                                #add_log2('error','Reading Security Policy with Nat Enabled','The interface used for source nat ['.$nat_lid.'] has more than one IP address '.$interfacedata.'. Assigning only the interface, you can force the IP address to use if you know it',$source,'Review the Rule','rules',$nat_lid,'nat_rules');
                                                $explodeInterface = explode(",", $interfacedata);
                                                $interfacedata = '';
                                            }
                                            if( $ZonaDST == "any" )
                                                $ZonaDST = "";

                                            if( $interfacedata == "" )
                                            {
                                                //Todo: swaschkut 20190930
                                                #add_log2('warning','Creating Oubound Nat from Security Rule ['.$lid.']','Unable to identify the interface to use for Outbound Nat on Nat Rule ['.$nat_lid.']',$source,'Assign The right interface.','rules',$nat_lid,'nat_rules');
                                            }
                                            #$addSNAT[] = array($source, $vsys, $nat_lid, $nat_position, $RuleNamePan, $Status, $ZonaDST, '', 0, $srv_member_lid, $srv_table_name, 'dynamic-ip-and-port', 'interface-address', $interfacedata, $Comments, $interfaceName, $ZonaSRC);


                                            $this->create_source_nat_policy( $tmp_rule, $RuleNamePan, 'interface', $interfaceName, $snat_int_array);

                                            if( $ZonaSRC != "any" )
                                            {
                                                #$addNATFrom[] = array($source, $vsys, $nat_lid, $ZonaSRC);
                                            }
                                        }
                                    }
                                }
                                if( is_array($addNatSrc_tmp) )
                                {
                                    foreach( $addNatSrc_tmp as $key => $value )
                                    {
                                        $addNatSrc[] = $value;
                                    }
                                }
                                if( is_array($addNatDst_tmp) )
                                {
                                    foreach( $addNatDst_tmp as $key => $value )
                                    {
                                        $addNatDst[] = $value;
                                    }
                                }

                                $nat_lid++;
                                $nat_position++;
                            }


                            $lid++;
                            $position++;
                            $RuleName = "";
                            $addressNamePan = "";
                            $addressName = "";
                            $ZonaSRC = "";
                            $ZonaDST = "";
                            $Action = "deny";
                            $checkit = 0;
                            $Comments = "";
                            $Status = 0;
                            $isAddress = FALSE;
                            $negate_destination = 0;
                            $negate_source = 0;
                            $nat_activated = 0;
                            $ippool = "";
                            $srv_table_name = "";
                            $srv_member_lid = "";
                            $src_table_name = "";
                            $src_member_lid = "";
                            $dst_member_lid = "";
                            $dst_table_name = "";
                            $pool_member_lid = "";
                            $pool_table_name = "";
                            $addNatDst_tmp = array();
                            $addNatSrc_tmp = array();
                            $interfaceName = "";
                        }

                        //done
                        if( preg_match("/\bset name\b/i", $names_line) )
                        {
                            $meta2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $RuleNamePan = $this->truncate_names($this->normalizeNames(trim($meta2[2])));

                            if( $print )
                                print "     - rename Rule: " . $tmp_rule->name() . " to " . $RuleNamePan . "\n";
                            $tmp_rule->setName($RuleNamePan);
                        }


                        if( preg_match("/\bset srcintf\b/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            unset($data[0]);
                            unset($data[1]);
                            foreach( $data as $zone )
                            {
                                $ZonaSRC = trim($zone);
                                $ZonaSRC = $this->truncate_names($this->normalizeNames($ZonaSRC));
                                if( $ZonaSRC != "any" )
                                {
                                    #$sql_src_zone[] = array($source,$vsys,$ZonaSRC,$lid);
                                    $tmp_zone = $this->template_vsys->zoneStore->find($ZonaSRC);

                                    if( $tmp_zone !== null )
                                    {
                                        if( $print )
                                            print "     - add from zone: " . $ZonaSRC . "\n";
                                        $tmp_rule->from->addZone($tmp_zone);
                                    }
                                    else
                                        mwarning("Rule: " . $tmp_rule->name() . " source zone: " . $ZonaSRC . " not found in vsys: " . $this->template_vsys->name() . " - " . $this->template_vsys->alternativeName(), null, FALSE);
                                }
                            }
                        }

                        if( preg_match("/\bset dstintf\b/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            unset($data[0]);
                            unset($data[1]);
                            foreach( $data as $zone )
                            {
                                $ZonaDST = trim($zone);
                                $ZonaDST = $this->truncate_names($this->normalizeNames($ZonaDST));
                                if( $ZonaDST != "any" )
                                {
                                    #$sql_dst_zone[] = array($source,$vsys,$ZonaDST,$lid);
                                    $tmp_zone = $this->template_vsys->zoneStore->find($ZonaDST);

                                    if( $tmp_zone !== null )
                                    {
                                        if( $print )
                                            print "     - add to zone: " . $ZonaDST . "\n";
                                        $tmp_rule->to->addZone($tmp_zone);
                                    }
                                    else
                                        mwarning("Rule: " . $tmp_rule->name() . " destination zone: " . $ZonaDST . " not found vsys: " . $this->template_vsys->name() . " - " . $this->template_vsys->alternativeName(), null, FALSE);
                                }
                            }
                        }


                        if( preg_match("/set srcaddr /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            foreach( $data as $value => $datas )
                            {
                                if( ($datas == "set") or ($datas == "srcaddr") or ($datas == "all") or ($datas == "Any") or ($datas == "any") )
                                {

                                }
                                else
                                {
                                    $name = $datas;
                                    $name = $this->truncate_names($this->normalizeNames($name));

                                    $tmp_address = $this->sub->addressStore->find($name);
                                    if( $tmp_address === null )
                                        $tmp_address = $this->sub->addressStore->find("tmp-" . $name);

                                    if( $tmp_address !== null )
                                    {
                                        if( $print )
                                            print "     - add source address object: " . $name . "\n";
                                        $tmp_rule->source->addObject($tmp_address);
                                    }
                                    else
                                    {
                                        //Todo: swaschkut 20190930
                                        //check if object is available from default_regions
                                        mwarning("source address object: " . $name . " not found - TODO\n", null, FALSE);
                                        /*
                                         if (isset($regions[$name])){
                                                $src_table_name="default_regions";
                                                $src_member_lid=$defaultRegions[$regions[$name]];
                                                $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                                $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                            }
                                            else{
                                                //Todo: swaschkut 20190930
                                                #add_log2('error', 'Phase 5: Reading Security Policies', 'Address not found in DB Source:[' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add IP Address','rules',$lid,'security_rules');
                                                $myname = $this->truncate_names($this->normalizeNames($name));
                                                $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,vtype,vsys) values('ip-netmask','$name','$myname','1','$source','1','ip-netmask','$vsys');");
                                                $src_table_name = "address";
                                                $src_member_lid = $projectdb->insert_id;
                                                $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                                $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                            }
                                         */
                                    }
                                    /*
                                    $getName = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$name' LIMIT 1");
                                    if ($getName->num_rows == 1) {
                                        $getit = $getName->fetch_assoc();
                                        $src_table_name = "address";
                                        $src_member_lid = $getit['id'];
                                        $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                        $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                    }
                                    else {
                                        $getName = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$name' LIMIT 1");
                                        if ($getName->num_rows == 1) {
                                            $getit = $getName->fetch_assoc();
                                            $src_table_name = "address_groups_id";
                                            $src_member_lid = $getit['id'];
                                            $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                            $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                        }
                                        else {
                                            if (isset($regions[$name])){
                                                $src_table_name="default_regions";
                                                $src_member_lid=$defaultRegions[$regions[$name]];
                                                $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                                $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                            }
                                            else{
                                                //Todo: swaschkut 20190930
                                                #add_log2('error', 'Phase 5: Reading Security Policies', 'Address not found in DB Source:[' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add IP Address','rules',$lid,'security_rules');
                                                $myname = $this->truncate_names($this->normalizeNames($name));
                                                $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,vtype,vsys) values('ip-netmask','$name','$myname','1','$source','1','ip-netmask','$vsys');");
                                                $src_table_name = "address";
                                                $src_member_lid = $projectdb->insert_id;
                                                $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                                $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                            }

                                        }
                                    }*/
                                }
                            }
                        }

                        if( preg_match("/set dstaddr /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            foreach( $data as $value => $datas )
                            {

                                if( ($datas == "set") or ($datas == "dstaddr") or ($datas == "all") or ($datas == "Any") or ($datas == "any") )
                                {

                                }
                                else
                                {
                                    $name = $datas;

                                    $name = $this->truncate_names($this->normalizeNames($name));

                                    $tmp_address = $this->sub->addressStore->find($name);
                                    if( $tmp_address === null )
                                        $tmp_address = $this->sub->addressStore->find("tmp-" . $name);

                                    if( $tmp_address !== null )
                                    {
                                        if( $print )
                                            print "     - add destination address object: " . $name . "\n";
                                        $tmp_rule->destination->addObject($tmp_address);
                                    }
                                    else
                                    {
                                        //Todo: swaschkut 20190930
                                        //check if object is available from default_regions
                                        mwarning("destination address object: " . $name . " not found - TODO\n", null, FALSE);
                                    }
                                    /*
                                    $getName = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$name' LIMIT 1");
                                    if ($getName->num_rows == 1) {
                                        $getit = $getName->fetch_assoc();
                                        $dst_table_name = "address";
                                        $dst_member_lid = $getit['id'];
                                        $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                        $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                    } else {
                                        $getName = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$name' LIMIT 1");
                                        if ($getName->num_rows == 1) {
                                            $getit = $getName->fetch_assoc();
                                            $dst_table_name = "address_groups_id";
                                            $dst_member_lid = $getit['id'];
                                            $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                            $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                        } else {
                                            if (isset($regions[$name])){
                                                $dst_table_name="default_regions";
                                                $dst_member_lid=$defaultRegions[$regions[$name]];
                                                $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                                $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                            }
                                            else{
                                                add_log2('error', 'Phase 5: Reading Security Policies', 'Address not found in DB Destination:[' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add IP Address','rules',$lid,'security_rules');
                                                $myname = $this->truncate_names($this->normalizeNames($name));
                                                $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,vtype,vsys) values('ip-netmask','$name','$myname','1','$source','1','ip-netmask','$vsys');");
                                                $dst_table_name = "address";
                                                $dst_member_lid = $projectdb->insert_id;
                                                $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                                $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                            }

                                        }
                                    }
                                    */
                                }
                            }
                        }


                        if( preg_match("/set service /i", $names_line) )
                        {
                            # FOR NATS I have to check the number of services and if they are groups or not
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( count($data) > 3 )
                                $multi_service = TRUE;
                            else
                                $multi_service = FALSE;
                            foreach( $data as $value => $datas )
                            {

                                if( ($datas == "set") or ($datas == "service") or ($datas == "ANY") or ($datas == "ALL") )
                                {

                                }
                                else
                                {
                                    $name = $datas;
                                    //normlize
                                    $name = $this->truncate_names($this->normalizeNames($name));

                                    $tmp_service = $this->sub->serviceStore->find($name);
                                    if( $tmp_service !== null )
                                    {
                                        if( $print )
                                            print "     - add service: " . $name . "\n";
                                        $tmp_rule->services->add($tmp_service);
                                    }
                                    else
                                    {
                                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $name);
                                        if( $tmp_service === null )
                                            $tmp_service = $this->sub->serviceStore->find("app-" . $name);
                                        if( $tmp_service !== null )
                                        {
                                            if( $print )
                                                print "     - add service: " . $tmp_service->name() . "\n";
                                            $tmp_rule->services->add($tmp_service);
                                        }
                                        else
                                        {
                                            $tmp_service = $this->sub->serviceStore->find("tmp-" . $name);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print " * create service 'tmp-" . $name . "' with dummy -dport '6500' and -proto 'TCP' because no information is available\n";

                                                $tmp_service = $this->sub->serviceStore->newService("tmp-" . $name, "tcp", "6500", '', '');

                                                $add_log = 'Service not found in DB [' . $name . ']  Generating the Object [tmp-' . $name . '], add the Protocol/Port';
                                                $tmp_rule->set_node_attribute('error', $add_log);
                                            }

                                            if( $tmp_service !== null )
                                            {
                                                if( $print )
                                                    print "     - add service: " . $tmp_service->name() . "\n";
                                                $tmp_rule->services->add($tmp_service);
                                            }
                                            else
                                            {
                                                mwarning("service object: '" . $name . "' not found \n", null, FALSE);
                                            }
                                        }
                                    }


                                    /*
                                    $getName = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND name_ext='$name' LIMIT 1");
                                    if ($getName->num_rows == 1) {
                                        $getit = $getName->fetch_assoc();
                                        $srv_table_name = "services";
                                        $srv_member_lid = $getit['id'];
                                        $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                    } else {
                                        $getName = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$name' LIMIT 1");
                                        if ($getName->num_rows == 1) {
                                            $getit = $getName->fetch_assoc();
                                            $srv_table_name = "services_groups_id";
                                            $srv_member_lid = $getit['id'];
                                            $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                        } else {
                                            //$getName = $projectdb->query("SELECT id FROM shared_services WHERE source='$source' AND name='$name' LIMIT 1");
                                            $getName = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='$name' AND vsys = 'shared' LIMIT 1");
                                            if ($getName->num_rows == 1) {
                                                $getit = $getName->fetch_assoc();
                                                //$srv_table_name = "shared_services";
                                                $srv_table_name = "services";
                                                $srv_member_lid = $getit['id'];
                                                $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                            } else {
                                                add_log('error', 'Phase 5: Reading Security Policies', 'Service not found in DB [' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add the Protocol/Port');
                                                $myname = $this->truncate_names($this->normalizeNames($name));
                                                $projectdb->query("INSERT INTO services (name,name_ext,checkit,source,used,vsys) values ('$myname','$name','1','$source','0','$vsys');");
                                                $srv_member_lid = $projectdb->insert_id;
                                                $srv_table_name = "services";
                                                $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                            }
                                        }
                                    }
                                    */
                                }
                            }
                        }

                        if( preg_match("/set action/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $Action = trim($data[2]);
                            if( $Action == "accept" )
                            {
                                $Action = "allow";
                                $checkit = 0;
                            }
                            elseif( $Action == "deny" )
                            {
                                $Action = "deny";
                                $checkit = 0;
                            }
                            elseif( $Action == "ipsec" )
                            {
                                $Action = "allow";
                                $checkit = 1;
                                $add_log = 'Security Rule ID has action set to ipsec. Rule was used for tunnels. Review it.';
                                $tmp_rule->set_node_attribute('warning', $add_log);
                            }
                            else
                            {
                                $Action = "deny";
                                $checkit = 0;
                            }
                        }

                        if( preg_match("/set comments/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $Commentsa = trim($data[2]);
                            $Comments = $this->normalizeComments($Commentsa);
                        }

                        if( preg_match("/set status/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $Status = trim($data[2]);
                            if( $Status == "enable" )
                            {
                                $Status = 0;
                            }
                            elseif( $Status == "disable" )
                            {
                                $Status = 1;
                            }
                            else
                            {
                                $Status = 0;
                            }
                        }

                        if( preg_match("/set dstaddr-negate/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $negate = trim($data[2]);
                            if( $negate == "enable" )
                            {
                                $negate_destination = 1;
                            }
                            elseif( $negate == "disable" )
                            {
                                $negate_destination = 0;
                            }
                            else
                            {
                                $negate_destination = 0;
                            }
                        }

                        if( preg_match("/set srcaddr-negate/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $negate = trim($data[2]);
                            if( $negate == "enable" )
                            {
                                $negate_source = 1;
                            }
                            elseif( $negate == "disable" )
                            {
                                $negate_source = 0;
                            }
                            else
                            {
                                $negate_source = 0;
                            }
                        }

                        if( preg_match("/set application-list/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( $data[2] == "default" )
                            {
                                $checkit = 0;
                            }
                            else
                            {
                                $checkit = 1;
                                $add_log = 'Security Rule ID has application-list.  Review it.';
                                $tmp_rule->set_node_attribute('warning', $add_log);
                            }
                        }

                        if( preg_match("/set nat enable/i", $names_line) )
                        {
                            $nat_activated = 1;
                        }

                        if( preg_match("/set poolname/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $ippool = trim($data[2]);
                        }

                        if( preg_match("/set global-label /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $tag = $this->truncate_tags(trim($data[2]));

                            $tmp_tag = $this->sub->tagStore->find($tag);
                            if( $tmp_tag == null )
                            {
                                $color = "color" . $thecolor;
                                #$tag_id = $projectdb->insert_id;
                                $tmp_tag = $this->sub->tagStore->createTag($tag);
                                $tmp_tag->setColor($color);

                                if( $thecolor == 16 )
                                    $thecolor = 1;
                                else
                                    $thecolor++;
                            }

                            if( $tmp_tag != null )
                            {
                                if( $print )
                                    print"     - Tag add: " . $tmp_tag->name() . "\n";
                                $tmp_rule->tags->addTag($tmp_tag);
                            }


                            /*
                            if (isset($allTags[$tag])){
                                $tagid=$allTags[$tag];
                                $addTag[]="('$source','$lid','tag','$tagid','$vsys')";
                            }
                            else{
                                # Insert new Tag
                                $color = "color" . $thecolor;
                                #$projectdb->query("INSERT INTO tag (name,source,vsys,color,used) VALUES ('$tag','$source','$vsys','$color',1);");
                                #$allTags[$tag]=$projectdb->insert_id;
                                if ($thecolor == 16) {
                                    $thecolor = 1;
                                } else {
                                    $thecolor++;
                                }
                                #$tagid=$projectdb->insert_id;
                                $tagid = "";
                                $addTag[]="('$source','$lid','tag','$tagid','$vsys')";
                            }
                            */
                        }

                    }
                }
            }
            $lastline = $names_line;
        }

        /*
        if (count($sql_rule) > 0) {
            $projectdb->query("INSERT INTO security_rules (lid,position,name,source,vsys,description,action,disabled,checkit,negate_source,negate_destination) VALUES " . implode(",", $sql_rule) . ";");


            if (count($sql_src_zone) > 0) {
                $projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid) VALUES " . implode(",", $sql_src_zone) . ";");
            }
            if (count($sql_dst_zone) > 0) {
                $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES " . implode(",", $sql_dst_zone) . ";");
            }
            if (count($sql_src) > 0) {
                $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $sql_src) . ";");
            }
            if (count($sql_dst) > 0) {
                $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $sql_dst) . ";");
            }
            if (count($sql_srv) > 0) {
                $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $sql_srv) . ";");
            }
            if (count($addTag)>0){
                $projectdb->query("INSERT INTO security_rules_tag (source,rule_lid,table_name,member_lid,vsys) VALUES ".implode(",",$addTag).";");
            }

        }
    */
        if( count($addSNAT) > 0 )
        {
            print "addSNAT array:\n";
            print_r($addSNAT);
        }

        /*
            if( count($addNATFrom) > 0 )
            {
                print "addNATFrom array:\n";
                print_r($addNATFrom);
            }
            */


        if( count($addNATTranslatedAddress) > 0 )
        {
            print "addNATTranslatedAddress array:\n";
            print_r($addNATTranslatedAddress);
        }


        if( count($addNatSrc) > 0 )
        {
            print "addNatSrc array:\n";
            print_r($addNatSrc);
        }

        if( count($addNatDst) > 0 )
        {
            print "addNatDst array:\n";
            print_r($addNatDst);
        }

        if( count($addSNAT) > 0 )
        {
            /*
            if ($addSNAT != "") {
                $projectdb->query("INSERT INTO nat_rules (source,vsys,id,position,name,disabled,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_ipaddress,description,tp_sat_interface) VALUES " . implode(",", $addSNAT) . ";");
            }

            if (count($addNATFrom) > 0) {
                $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addNATFrom) . ";");
            }
            if (count($addNATTranslatedAddress) > 0) {
                $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNATTranslatedAddress) . ";");
            }
            if (count($addNatSrc) > 0) {
                $projectdb->query("INSERT INTO nat_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNatSrc) . ";");
            }
            if (count($addNatDst) > 0) {
                $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNatDst) . ";");
            }

            # Check for Regions in NAT Rules
            $getRegionSrcLid=$projectdb->query("SELECT id,rule_lid,member_lid FROM nat_rules_src WHERE source='$source' AND table_name='default_regions';");
            if ($getRegionSrcLid->num_rows>0){
                while($getRegionSrcLidData=$getRegionSrcLid->fetch_assoc()){

                }
            }
            */

        }


        /*
            # Check if there is any Address group with Regions as Member, if yes remove from the group, search Rules where the groups was used and add the Regions where used
            # Raise and Alert to the Groups with Regions
            $getRegion=$projectdb->query("SELECT lid,member_lid FROM address_groups WHERE source='$source' AND table_name='default_regions';");
            if ($getRegion->num_rows>0){
                $grouplid=array();
                $grouplidMembers=array();
                while($getRegionData=$getRegion->fetch_assoc()){
                    $grouplid[]=$getRegionData['lid'];
                    $grouplidMembers[$getRegionData['lid']]['members'][]=$getRegionData['member_lid'];
                }
                $grouplid=array_unique($grouplid);
                if (count($grouplid)>0){
                    $getGroup=$projectdb->query("SELECT id,name FROM address_groups_id WHERE id IN (".implode(",",$grouplid).");");
                    if ($getGroup->num_rows>0){
                        while($getGroupData=$getGroup->fetch_assoc()){
                            $groupName=$getGroupData['name'];
                            $lid=$getGroupData['id'];
                            $grouplidMembers[$lid]['name']=$groupName;
                            add_log2("error",'Reading Address Groups','Found GEO references as Member of an Address Group named ['.$groupName.']',$source,'Expedition will replace by Regions where the group is used.','objects',$lid,'address_groups');
                        }
                    }

                    foreach($grouplidMembers as $groupID=>$groupMembers){
                        $getSecuritySRC=$projectdb->query("SELECT rule_lid FROM security_rules_src WHERE source='$source' AND table_name='address_groups_id' AND member_lid='$groupID';");
                        if ($getSecuritySRC->num_rows>0){
                            while($getSecuritySRCData=$getSecuritySRC->fetch_assoc()){
                                $ruleAffected=$getSecuritySRCData['rule_lid'];
                                foreach($groupMembers['members'] as $memberRegions){
                                    $addSRC[]= "('$source','default_regions','$memberRegions','$ruleAffected')";
                                }

                            }
                        }
                        $getSecurityDST=$projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE source='$source' AND table_name='address_groups_id' AND member_lid='$groupID';");
                        if ($getSecurityDST->num_rows>0){
                            while($getSecurityDSTData=$getSecurityDST->fetch_assoc()){
                                $ruleAffected=$getSecurityDSTData['rule_lid'];
                                foreach($groupMembers['members'] as $memberRegions){
                                    $addDST[]= "('$source','default_regions','$memberRegions','$ruleAffected')";
                                }

                            }
                        }
                    }
                    if (count($addSRC)>0){
                        $projectdb->query("INSERT INTO security_rules_src (source,table_name,member_lid,rule_lid) VALUES ".implode(",",$addSRC).";");
                    }
                    if (count($addDST)>0){
                        $projectdb->query("INSERT INTO security_rules_dst (source,table_name,member_lid,rule_lid) VALUES ".implode(",",$addDST).";");
                    }
                }
                # Clean the Regions as Members from Groups
                $projectdb->query("DELETE FROM address_groups WHERE source='$source' AND table_name='default_regions';");
                # Check if Group now is Empty
                foreach ($grouplid as $groupID){
                    $getEmpty=$projectdb->query("SELECT id FROM address_groups WHERE lid='$groupID';");
                    if ($getEmpty->num_rows==0){
                        $groupName=$grouplidMembers[$groupID]['name'];
                        add_log2('info','Replacing Regions from Groups to Rules','While we replaced Regions where part from an Address Group into the Rules the Group became empty.',$source,'Group ['.$groupName.'] has been Removed','objects',$groupID,'address_groups_id');
                        $projectdb->query("DELETE FROM security_rules_src WHERE member_lid='$groupID' AND table_name='address_groups_id';");
                        $projectdb->query("DELETE FROM security_rules_dst WHERE member_lid='$groupID' AND table_name='address_groups_id';");
                        $projectdb->query("DELETE FROM address_groups_id WHERE id='$groupID';");
                    }
                }

            }
            */
    }

}


