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


trait CISCOnat
{

    public $nat_lid = 1;


    //copied from todo/lib/lib_rules.php
    #function recalculate_Dst_basedOn_NAT(mysqli $connection, STRING $source, STRING $vsys, STRING $vr, STRING $project, STRING $vendor=null)
    #function recalculate_Dst_basedOn_NAT( VirtualSystem $vsys, VirtualRouter $vr, STRING $vendor=null)
    function recalculate_Dst_basedOn_NAT( STRING $vendor = null)
    {
        $vendor = "cisco";

        $vsyss = $this->template->virtualSystems;

        foreach( $vsyss as $v )
        {
            print "vsys name: " . $v->name() . " - " . $v->alternativeName() . "\n";
            $vsys = $v;
        }


        $vsys = $this->template->findVirtualSystem("vsys1");

        $tmp_vrs = $this->template->network->virtualRouterStore->getAll();
        $vr = $tmp_vrs[1];


        $add_logs = array();
        #$projectdb = $connection;

        if( !isset($vendor) )
        {
            $vendor = 'Paloalto';
        }

        switch (strtolower($vendor))
        {
            case "paloalto":
                $vendor_type = 0;
                break;
            case "stonesoft":
                $vendor_type = 1;
                break;
            case "cisco":
                $vendor_type = 2;
                break;
            case "checkpoint":
                $vendor_type = 3;
                break;
            case "checkpointr80":
                $vendor_type = 4;
                break;
            default:
                $vendor_type = 5;
                break;
        }

        #$ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
        /* Todo: Sven example output from getIPtoZoneRouteMapping
         $record = Array('network' => $interfaceIP, 'start' => $start, 'end' => $end, 'zone' => $findZone, 'origin' => 'connected', 'priority' => 1);
         $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
         */


        $natted_rules = array();   //IDs of the modified rules
        $security_rules = array();

//    $objectsInMemory = loadObjectsInMemory($connection, $source, $vsys);
        /***
         * COLLECT ALL THE POLICY RULES AS OBJECTS
         */
        //Initialize a 2Dim associative array for the security rules with the size of the rules we have.


        $security_rules = $vsys->securityRules->rules();
        #$security_rules = loadInMemorySecRules($connection, $source, $vsys);
        /*
                ##$memberAnyAddress = new MemberObject('', '','0.0.0.0', '0');
                $memberAnyAddress = new Address("ANY-dummy", null );
                $memberAnyAddress->setType( "ip-netmask" );
                $memberAnyAddress->setValue( "0.0.0.0/0" );

                ##$memberAnyService = new MemberObject('', '','0-65535', 'any');

                $memberAnyTCPService = new Service( "ANY-tcp-dummy", null);
                $memberAnyTCPService->setProtocol( "tcp" );
                $memberAnyTCPService->setDestPort( "0-65535" );

                $memberAnyUDPService = new Service( "ANY-udp-dummy", null);
                $memberAnyUDPService->setProtocol( "udp" );
                $memberAnyUDPService->setDestPort( "0-65535" );

                $memberAnyService = new ServiceGroup( "ANY-dummy" );
                $memberAnyService->addMember( $memberAnyTCPService );
                $memberAnyService->addMember( $memberAnyUDPService );
        */

        $newRulesDNAT = $newRulesSNAT = $newRulesNONAT = $rulesNONAT = array(); //This array will contain information to generate new Rules that come from splitting security rules based on NATs

        //Select the NAT rules that are Not disabled
        ##$getDAT = $connection->query("SELECT id, tp_dat_address_lid, tp_dat_address_table, devicegroup, is_dat, op_zone_to, op_service_lid, op_service_table, tp_sat_type, tp_sat_bidirectional
        ##FROM nat_rules WHERE disabled='0' AND source='$source' AND vsys='$vsys' ORDER BY position;");


        $getDAT = $vsys->natRules->rules("!(rule is.disabled)");
        $getDAT = $vsys->natRules->rules();

        #while ($getNatData = $getDAT->fetch_assoc())
        /** @var $getDAT NatRule[] */

        foreach( $getDAT as $getNatData )
        {
            /*            #$nat_rule_lid   = $getNatData['id'];
                        #$devicegroup    = $getNatData['devicegroup'];
                        #$is_dat         = $getNatData['is_dat'];

                        $tp_sat_type = $getNatData['tp_sat_type'];
                        $tp_sat_type = $getNatData->SourceNat_Type();

                        $tp_sat_bidirectional = $getNatData['tp_sat_bidirectional'];
                        $tp_sat_bidirectional = $getNatData->isBiDirectional();

                        $nat_to_zones = array($getNatData['op_zone_to']);
                        $nat_to_zones = $getNatData->to->getAll();

                        //Get the destionation afterNAT
                        $member_lid_dat    = $getNatData['tp_dat_address_lid'];
                        $member_lid_dat = $getNatData->dnathost;


                        /*
                        $table_name_dat    = $getNatData['tp_dat_address_table'];
                        if($table_name_dat!='' && $member_lid_dat!='') {
                            $member = new MemberObject($member_lid_dat, $table_name_dat);
                            $exploded_nat_Tdst_Members = explodeGroups2Members(array($member),$connection, $source, $vsys);
                        }
                        else{
                            $exploded_nat_Tdst_Members = array(new MemberObject('', '','0.0.0.0', '0'));
                        }*/


            /*
                        //Get the zones TO
                        $nat_Tto_zones = array();
                        foreach( $exploded_nat_Tdst_Members as $sec_source) {
                            $member_lid = $sec_source->name;
                            $table_name = $sec_source->location;
                            if ($member_lid == 'any') {
                                $nat_Tto_zones = array('any');
                                break;
                            }
                            else {
                                $nat_Tto_zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                            }
                        }


                        //Get the service in NAT
                        $member_lid_opSrv    = $getNatData['op_service_lid'];
                        $table_name_opSrv    = $getNatData['op_service_table'];
                        if($member_lid_opSrv!='' && $table_name_opSrv !='') {
                            $exploded_nat_srv_Members = explodeGroups2Services(array(new MemberObject($member_lid_opSrv, $table_name_opSrv)), $connection, $source, $vsys);

                        }
                        else{
                            $exploded_nat_srv_Members = array($memberAnyService);
                        }
                        if(count($exploded_nat_srv_Members)==0){
                            $exploded_nat_srv_Members = array($memberAnyService);
                        }

                        $negate_source=0;  //Note: In Stonesoft, we do not negate rules due to the JUMP approach they use. Insead, in case a Negate is applied in Stonesoft, we calculate all the opposite addresses



                        //Initialize Sources and Destinations for mapping
                        $nat_src_members=array();
                        $exploded_nat_src_Members=array();

                        $nat_dst_members=array();
                        $exploded_nat_dst_Members=array();

                        $nat_Tsrc_members=array();
                        $exploded_nat_Tsrc_Members = array();


                        //Get the From beforeNAT
                        $getFrom = $connection->query("SELECT name FROM nat_rules_from WHERE rule_lid='$nat_rule_lid';");
                        if ($getFrom->num_rows > 0) {
                            $nat_from_zones = array();
                            while ($getFromData = $getFrom->fetch_assoc()){
                                $nat_from_zones[]=$getFromData['name'];;
                            }
                        }
                        else{
                            $nat_from_zones = array("any");
                        }

                        //Get the source beforeNAT
                        $getSrc = $connection->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid='$nat_rule_lid';");
                        if ($getSrc->num_rows > 0) {
                            while ($getINData = $getSrc->fetch_assoc()){
                                $member_lid = $getINData['member_lid'];
                                $table_name = $getINData['table_name'];

                                $member = new MemberObject($member_lid,$table_name);
                                $nat_src_members[]=$member;
                            }
                            $exploded_nat_src_Members = explodeGroups2Members($nat_src_members,$connection, $source, $vsys);
                        }
                        else{
                            $exploded_nat_src_Members[] = new MemberObject('', '','0.0.0.0', '0');
                        }

                        //Get the destination beforeNAT
                        $getDst = $connection->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid='$nat_rule_lid';");
                        if ($getDst->num_rows > 0) {
                            while ($getINData = $getDst->fetch_assoc()){
                                $member_lid = $getINData['member_lid'];
                                $table_name = $getINData['table_name'];

                                $member = new MemberObject($member_lid,$table_name);
                                $nat_dst_members[]=$member;
                            }
                            $exploded_nat_dst_Members = explodeGroups2Members($nat_dst_members,$connection, $source, $vsys);
                        }
                        else{
                            $exploded_nat_dst_Members[] = new MemberObject('', '','0.0.0.0', '0');
                        }

                        //Get the sources afterNAT
                        $getTSrc = $connection->query("SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid='$nat_rule_lid';");
                        if ($getTSrc->num_rows > 0){
                            while($getDSrcData = $getTSrc->fetch_assoc()){
                                $member_lid = $getDSrcData['member_lid'];
                                $table_name = $getDSrcData['table_name'];

                                $member = new MemberObject($member_lid,$table_name);
                                $nat_Tsrc_members[]=$member;
                            }
                            $exploded_nat_Tsrc_Members = explodeGroups2Members($nat_Tsrc_members,$connection, $source, $vsys);
                        }
                        else{
                            $exploded_nat_Tsrc_Members[] = new MemberObject('', '','0.0.0.0', '0');
                        }
            */

            /* Now we have For this NAT rule:
             *  1.1- the NAT origins (in $exploded_nat_src_Members)
             *  1.2- the NAT destinations (in $exploded_nat_dst_Members)
             *  1.3- the NAT Srv (in $exploded_nat_srv_Members)
             *  1.4- the NAT Tdest (in $exploded_nat_Tdst_Members)
             *  1.5- the NAT Tsour (in $exploded_nat_Tsrc_Members)
             *  1.6- the NAT From Zone (in $nat_from_zones)
             *  1.7- the NAT To after NAT (in $nat_to_zones)
             *
             *  2.1- all the sources for all the security rules (in $security_rule[ruleID]['src'])
             *  2.2- all the destina for all the security rules (in $security_rule[ruleID]['dst'])
             *  2.3- all the service for all the security rules (in $security_rule[ruleID]['srv'])
             *  2.4- all the zoneFro for all the security rules (in $security_rule[ruleID]['form'])
             *  2.5- all the ZoneTo  for all the security rules (in $security_rule[ruleID]['to'])
             *
             * Ready for doing the matching
             */

            $exploded_nat_src_Members = $getNatData->source->getAll();
            $exploded_nat_dst_Members = $getNatData->destination->getAll();

            $exploded_nat_srv_Members = $getNatData->service;
            //Todo: additional manipulation needed: create array, why, only one object is allowed, so service group is created before;
            //but for check it is needed to get all services in an array


            $exploded_nat_Tdst_Members = $getNatData->dnathost;
            $exploded_nat_Tsrc_Members = $getNatData->snathosts->getAll();
            //Todo: missing Tservice

            $nat_from_zones = $getNatData->from->getAll();
            $nat_to_zones = $getNatData->to->getAll();

            //Todo:SVEN all securityRules are available in array() -> $security_rule

            /*
                        print "\n\n###########################\n";
                        print "Rule: ".$getNatData->name()."\n";

                        foreach( $exploded_nat_src_Members as $members )
                        {
                            print "exploded_nat_src_Members|".$members->name()."|";
                        }
                        print "1\n";


                        //------------------------------------------------------------------------------------------------------
                        foreach( $exploded_nat_dst_Members as $members )
                        {
                            print "exploded_nat_dst_Members|".$members->name()."|";
                        }
                        print "2\n";

                        if( $exploded_nat_srv_Members !== null )
                            print "exploded_nat_srv_Members|".$exploded_nat_srv_Members->name()."|";
                        print "3\n";


                        if( $exploded_nat_Tdst_Members !== null )
                            print "exploded_nat_Tdst_Members|".$exploded_nat_Tdst_Members->name()."|";
                        print "4\n";
                        #print_r( $exploded_nat_Tdst_Members );
                        //------------------------------------------------------------------------------------------------------


                        foreach( $exploded_nat_Tsrc_Members as $members )
                        {
                            print "exploded_nat_Tsrc_Members|".$members->name()."|";
                        }
                        print "5\n";
                        #print_r( $exploded_nat_Tsrc_Members );

                        foreach( $nat_from_zones as $members )
                        {
                            print "nat_from_zones|".$members->name()."|";
                        }
                        print "6\n";
                        #print_r( $nat_from_zones );

                        foreach( $nat_to_zones as $members )
                        {
                            print "nat_to_zones|".$members->name()."|";
                        }
                        print "7\n";
                        #print_r( $nat_to_zones );

            */


            //Find the Security rules that are affected by this NAT
            /*
                        //NO NAT Rule
                        if( count($exploded_nat_Tdst_Members)==1 && $exploded_nat_Tdst_Members[0]==$memberAnyAddress &&
                            count($exploded_nat_Tsrc_Members)==1 && $exploded_nat_Tsrc_Members[0]==$memberAnyAddress &&
                            ($tp_sat_type=='' || $tp_sat_type=='none'))
                        {
            */

            //NO NAT Rule
            if(
                //4)
                #count($exploded_nat_Tdst_Members)==1 && $exploded_nat_Tdst_Members[0]==$memberAnyAddress
                !$getNatData->destinationNatIsEnabled()

                //5)
                #&& count($exploded_nat_Tsrc_Members)==1 && $exploded_nat_Tsrc_Members[0]==$memberAnyAddress
                && $getNatData->sourceNatTypeIs_None()


                #&& $getNatData->sourceNatTypeIs_None()
                #&& ( $tp_sat_type=='' || $tp_sat_type=='none' )
            )
            {
                print "Rule: " . $getNatData->name() . " - NO NAT\n";
                //Todo: continue here

                /*
                case "paloalto":$vendor_type=0;
                case "stonesoft":$vendor_type=1;
                case "cisco":$vendor_type=2;
                case "checkpoint":$vendor_type=3;
                case "checkpointr80":$vendor_type=4;
                default:    $vendor_type=5;
                */

                if( $vendor == 0 || $vendor == 1 || $vendor == 2 || $vendor == 3 )
                {

                    $natted_rules = array();

                    /**
                     * @param SecurityRule $security_rules []
                     */
                    foreach( $security_rules as $security_rule_lid => $security_rule )
                    {
                        $zonesFrom = array();
                        #$isFromCovered = $this->isAinB_Zones($security_rule->from->getAll(), $getNatData->from->getAll(), $zonesFrom);
                        $isFromCovered = $getNatData->from->includesContainer($security_rule->from, TRUE, $zonesFrom);
                        if( !$isFromCovered )
                        {
                            continue 1;
                        }
                        $zonesTo = array();
                        #$isToCovered = $this->isAinB_Zones($security_rule->to->getAll(), $getNatData->to->getAll(), $zonesTo);
                        $isToCovered = $getNatData->to->includesContainer($security_rule->to, TRUE, $zonesTo);
                        if( !$isToCovered )
                        {
                            continue 1;
                        }

                        $sourcesMatched = array();
//                $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $sourcesMatched, true);
                        #$isSrcCovered = $this->isAinB($security_rule->source->getAll(), $getNatData->source->getAll(), $sourcesMatched);
                        $isSrcCovered = $getNatData->source->includesContainer($security_rule->source, TRUE, $sourcesMatched);
                        if( !$isSrcCovered )
                        {
                            continue 1;
                        }


                        $destinationsMatched = array();
                        #$isDstCovered = $this->isAinB($security_rule->destination->getAll(), $getNatData->destination->getAll(), $destinationsMatched);
                        $isDstCovered = $getNatData->destination->includesContainer($security_rule->destination, TRUE, $destinationsMatched);
                        if( !$isDstCovered )
                        {
                            continue 1;
                        }


                        $servicesMatched = array();
                        //$exploded_nat_srv_Members = $getNatData->service
                        //securityrule has services container array
                        //natrule has one service
                        #$isSrvCovered = $this->isAinB_service($security_rule->services->getAll(), $getNatData->service, $servicesMatched);

                        $secrule_mapping = new ServiceDstPortMapping();
                        $secrule_mapping->mergeWithArrayOfServiceObjects($security_rule->services->getAll());
                        $natrule_mapping = $getNatData->service->dstPortMapping();

                        print "secmapping: " . $secrule_mapping->mappingToText() . "\n";
                        print "natmapping: " . $natrule_mapping->mappingToText() . "\n";

                        //check now if secrule mapping is part of natrule_mapping
                        //Todo: until now only equal mapping is true, improve it
                        //Todo: no serviceMatched possible right now
                        $isSrvCovered = $natrule_mapping->equals($secrule_mapping);
                        if( !$isSrvCovered )
                        {
                            continue 1;
                        }


                        //Todo: continue here swaschkut 20200204
                        /*
                                                //Recover the DST ip before the Static NAT
                                                if     ( $isFromCovered * $isToCovered * $isSrcCovered * $isDstCovered * $isSrvCovered == true )
                                                { //Fully covered
                                                    $natted_rules[] = $security_rule;
                                                }
                                                elseif ( $isSrcCovered && $isDstCovered && $isSrvCovered )
                                                {  //Partially Covered
                                                    if ( count($security_rule['dst']) != 1
                                                        || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress))
                                                    {
                                                        // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                                                        //Clone the rule and add a subset with the new Destinations before Nat
                                                        $count = isset($newRulesNONAT[$security_rule_lid]['cloned']) ? $newRulesNONAT[$security_rule_lid]['cloned'] + 1 : 0;
                                                        if (!isset($newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid'])) {
                                                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                                        }
                                                        $newRulesNONAT[$security_rule_lid]['cloned'] = $count;

                                                        $newRulesNONAT[$security_rule_lid]['clones'][$count]['from'] = $zonesFrom;
                                                        $newRulesNONAT[$security_rule_lid]['clones'][$count]['to'] = $zonesTo;
                                                        $newRulesNONAT[$security_rule_lid]['clones'][$count]['sources'] = $sourcesMatched;
                                                        $newRulesNONAT[$security_rule_lid]['clones'][$count]['destinations'] = $destinationsMatched;
                                                        $newRulesNONAT[$security_rule_lid]['clones'][$count]['services'] = $servicesMatched;
                                                    }
                                                }
                                                */
                    }


                    /*
                    if (count($natted_rules) > 0) {
                        $unique = array_unique($natted_rules);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $unique);
                    }
                    */
                }
                elseif( $vendor == 4 ) //todo: info vendor CheckPointR80
                {
                    /*
                    $natted_rules = array();
                    foreach ($security_rules as $security_rule_lid => $security_rule) {
//                    $zonesFrom = array();
//                    $isFromCovered = isAinB_Zones($security_rule['from'], $nat_from_zones, $zonesFrom);
//                    if (!$isFromCovered) {
//                        continue 1;
//                    }
//                    $zonesTo = array();
//                    $isToCovered = isAinB_Zones($security_rule['to'], $nat_to_zones, $zonesTo);
//                    if (!$isToCovered) {
//                        continue 1;
//                    }
                        $sourcesMatched = array();
//                $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $sourcesMatched, true);
                        $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $sourcesMatched);
                        if (!$isSrcCovered) {
                            continue 1;
                        }
                        $destinationsMatched = array();
                        $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members, $destinationsMatched);
                        if (!$isDstCovered) {
                            continue 1;
                        }
                        $servicesMatched = array();
                        $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                        if (!$isSrvCovered) {
                            continue 1;
                        }
                        //Recover the DST ip before the Static NAT
                        if ($isSrcCovered * $isDstCovered * $isSrvCovered == 1) { //Fully covered
                            $natted_rules[] = $security_rule_lid;
                            $rulesNONAT[$security_rule_lid]['from'] = $nat_from_zones;
                            $rulesNONAT[$security_rule_lid]['to'] = $nat_to_zones;
                        }
                        elseif ($isSrvCovered && $isDstCovered && $isSrvCovered) {//Partially Covered
                            if (count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress)) {
                                // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                                //Clone the rule and add a subset with the new Destinations before Nat
                                $count = isset($newRulesNONAT[$security_rule_lid]['cloned']) ? $newRulesNONAT[$security_rule_lid]['cloned'] + 1 : 0;
                                if (!isset($newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid'])) {
                                    $newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                }
                                $newRulesNONAT[$security_rule_lid]['cloned'] = $count;
                                $newRulesNONAT[$security_rule_lid]['clones'][$count]['from'] = $nat_from_zones;
                                $newRulesNONAT[$security_rule_lid]['clones'][$count]['to'] = $nat_to_zones;
                            }
                        }
                    }
                    if (count($natted_rules) > 0) {
                        $unique = array_unique($natted_rules);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $unique);
                    }
                    */
                }
            }

            //DNAT Logic applies here
            #elseif( $is_dat == 1 )
            elseif( $getNatData->destinationNatIsEnabled() )
            {
                if( $vendor_type == 0 ) //todo: info vendor PaloAltoNetworks
                {
                }
                elseif( $vendor_type == 1 ) //TODO: Review the code for Stonesoft based on the function fix_Zones_Policies
                {
                    /*
                    $natted_rules = array();
                    foreach ($security_rules as $sec_rule_lid => $security_rule) {
                        $isDSTCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members);
                        if (!$isDSTCovered) {
                            //No need to check if the Source matches
                            continue;
                        }
                        $isSRCCovered = isAinB($security_rule['src'], $exploded_nat_src_Members);

                        if ($isSRCCovered) {
                            //Calculate destination Zone after NAT
                            $correct_zones_to = getAutoZone($ipMapping['ipv4'], $member_lid_dat, $table_name_dat, $negate_source);  //This will provide all the zones that this NAT has as destination AFTER NAT

                            $natted_rules[] = $sec_rule_lid;  //Add this rule in the list of modified rules, so we do not need to process it again.
                            $connection->query("DELETE FROM security_rules_to WHERE rule_lid='$sec_rule_lid';");
                            $connection->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                                . "VALUES ('$sec_rule_lid', '" . implode(',', $correct_zones_to) . "', '$source', '$vsys', '$devicegroup');");
                            $add_logs[] = "('NOW()','2', 'Auto Zone Assign', 'Rule [$sec_rule_lid]. Forcing TO Zone as [". implode(',', $correct_zones_to)."] based on DAT defined in NAT rule [$nat_rule_lid]', '$source', 'No Action Required', 'rules', '$sec_rule_lid', 'security_rules')";
                        }
                    }
                    if (count($natted_rules) > 0) {
                        $unique = array_unique($natted_rules);
                        $out = implode(",", $unique);
                        $query = "UPDATE security_rules SET blocked=1 WHERE id in (" . $out . ");";
                        $connection->query($query);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $natted_rules);
                    }
                    */
                }
                elseif( $vendor_type == 2 ) //todo: info vendor CISCO
                {

                    /*
                    $natted_rules = array();
                    foreach ($security_rules as $security_rule_lid => $security_rule){
                        $zonesFrom = array();
                        $isFromCovered = isAinB_Zones($security_rule['from'], $nat_from_zones, $zonesFrom);
                        if(!$isFromCovered){
                            continue 1;
                        }

                        $zonesTo = array();
                        $isToCovered = isAinB_Zones($security_rule['to'], $nat_Tto_zones, $zonesTo);
                        if(!$isToCovered){
                            continue 1;
                        }

                        $TDstMembers = array();
                        $isTDstCovered = isAinB($security_rule['dst'], $exploded_nat_Tdst_Members, $TDstMembers);
                        if(!$isTDstCovered){
                            continue 1;
                        }

                        $SrcMembers = array();
                        $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $SrcMembers);
                        if(!$isSrcCovered){
                            continue 1;
                        }

                        $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members);
                        if(!$isSrvCovered){
                            continue 1;
                        }

                        //Recover the IP before NAT
                        if($isFromCovered * $isToCovered * $isSrcCovered * $isTDstCovered * $isSrvCovered == 1) { //Fully covered
                            $natted_rules[] = $security_rule_lid;
                            // "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                            //Modify the rule and replace the destination with before NAT
                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$security_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($exploded_nat_dst_Members as $dst_Member){
                                $destinations[] = "('$security_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                            }
                            if(count($destinations)>0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                                $add_logs[] = "('NOW()','1', 'Correcting Destination based on DNAT', 'Destination address corrected to value before DNAT, based on NAT Rule[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$security_rule_lid', 'security_rules')";
                            }
                        }
                        elseif($isTDstCovered && $isSrcCovered && $isSrvCovered) {
                            if(count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0]!=$memberAnyAddress)) {
                                // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                                //Clone the rule and add a subset with the new Destinations before Nat
                                $count = isset($newRulesDNAT[$security_rule_lid]['cloned']) ? $newRulesDNAT[$security_rule_lid]['cloned'] + 1 : 0;
                                if (!isset($newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid'])) {
                                    $newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                }
                                $newRulesDNAT[$security_rule_lid]['cloned'] = $count;

                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['from'] = $zonesFrom;
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['to'] = $zonesTo;
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['destinations'] = $exploded_nat_dst_Members;
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['services'] = $exploded_nat_srv_Members;
                            }
                        }
                    }

                    if(count($natted_rules)>0){
                        $unique = array_unique($natted_rules);
                        $out = implode(",", $unique);
                        $query = "UPDATE security_rules SET blocked=1 WHERE id in (" . $out . ");";
                        $connection->query($query);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $natted_rules);
                    }
                    */
                }
                elseif( $vendor_type == 3 ) //todo: info vendor CheckPoint
                {

                }
                elseif( $vendor_type == 4 ) //todo: info vendor CheckPointR80
                {
                    /*
                    $natted_rules = array();
                    foreach ($security_rules as $security_rule_lid => $security_rule){
//                    $zonesFrom = array();
//                    $isFromCovered = isAinB_Zones($security_rule['from'], $nat_from_zones, $zonesFrom);
//                    if(!$isFromCovered){
//                        continue 1;
//                    }
//
//                    $zonesTo = array();
//                    $isToCovered = isAinB_Zones($security_rule['to'], $nat_Tto_zones, $zonesTo);
//                    if(!$isToCovered){
//                        continue 1;
//                    }

                        $DstMembers = array();
                        $isTDstCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members, $DstMembers);
                        if(!$isTDstCovered){
                            continue 1;
                        }

//                    echo "Sec Rule[$security_rule_lid] and Nat[$nat_rule_lid] matches: DST, ";

                        $SrcMembers = array();
                        $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $SrcMembers);
                        if(!$isSrcCovered){
//                        echo "\n";
                            continue 1;

                        }
//                    echo "SRC-";

                        $SrvMembers = array();
                        $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $SrvMembers);
                        if(!$isSrvCovered){
//                        echo "\n";
//                        echo "Sec:";
//                        print_r($security_rule['srv']);
//                        echo "Nat:";
//                        print_r($exploded_nat_srv_Members);
//                        echo "Result: $isSrvCovered Cross:";
//                        print_r($SrvMembers);
//                        die;
                            continue 1;
                        }
//                    echo "SRV\n";
//                    die;

                        //Recover the IP before NAT
                        if($isSrcCovered * $isTDstCovered * $isSrvCovered == 1) { //Fully covered
                            $natted_rules[] = $security_rule_lid;
                            // "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                            //Modify the rule and replace the destination with before NAT
                            //TODO: convert into one single INSERT
                            foreach ($nat_from_zones as $zone) {
                                if($zone != "any") {
                                    $tempZonesFrom[]="($security_rule_lid, '$zone', '$vsys', '$source')";

                                }
                            }
                            if (count($tempZonesFrom)>0){
                                $unique = array_unique($tempZonesFrom);
                                $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES ".implode(",",$unique).";";
                                $connection->query($query);
                            }

                            foreach ($nat_Tto_zones as $zone) {
                                if($zone != "any") {
                                    $tempZonesTo[]= "($security_rule_lid, '$zone', '$vsys', '$source')";
                                }
                            }
                            if (count($tempZonesTo)>0){
                                $unique = array_unique($tempZonesTo);
                                $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES ".implode(",",$unique).";";
                                $connection->query($query);
                            }
                        }
                        elseif($isTDstCovered && $isSrcCovered && $isSrvCovered) {
                            if(count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0]!=$memberAnyAddress)) {
                                // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                                //Clone the rule and add a subset with the new Destinations before Nat
                                $count = isset($newRulesDNAT[$security_rule_lid]['cloned']) ? $newRulesDNAT[$security_rule_lid]['cloned'] + 1 : 0;
                                if (!isset($newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid'])) {
                                    $newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                }
                                $newRulesDNAT[$security_rule_lid]['cloned'] = $count;
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['from'] = $nat_from_zones;
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['to'] = $nat_Tto_zones;
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['destinations'] = $DstMembers;
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['services'] = $SrvMembers;
                            }
                        }
                    }

                    if(count($natted_rules)>0){
                        $unique = array_unique($natted_rules);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $unique);
                    }
            */
                }

            }
            //NAT Logic applies here
            else
            {
                if( $vendor_type == 0 ) //todo: info vendor PaloAltoNetworks
                {
                }
                elseif( $vendor_type == 1 ) //todo: info vendor Stonesoft
                {
                    /*
                    $natted_rules = array();
                    //Find the Security rules that are affected by this NAT
                    foreach ($security_rules as $sec_rule_lid => $security_rule) {
//                    $counter++;

                        $isDSTCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members);
                        if (!$isDSTCovered) {
                            break;
                        }
                        $isSRCCovered = isAinB($security_rule['src'], $exploded_nat_src_Members);

                        if ($isSRCCovered) {
                            //TODO: Use this part to update source Zones, for example
                            $natted_rules[] = $sec_rule_lid;
                        }
                    }
//                printMemory($my, "        Matches done");
                    if (count($natted_rules) > 0) {
                        $unique = array_unique($natted_rules);
//                    $out = implode(",", $unique);
//                    fwrite($my, "$nat_rule_lid matches $out\n");
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $unique);
                    }
                    */
                }
                elseif( $vendor_type == 2 ) //todo: info vendor CISCO
                {
                    /*
                    if($tp_sat_type =='static-ip' && $tp_sat_bidirectional=='1'){
                        $natted_rules = array();
                        foreach ($security_rules as $security_rule_lid => $security_rule) {
                            $zonesFrom = array();
                            $isFromCovered = isAinB_Zones($security_rule['from'], $nat_to_zones, $zonesFrom);
                            if(!$isFromCovered){
                                continue 1;
                            }
                            $zonesTo = array();
                            $isToCovered = isAinB_Zones($security_rule['to'], $nat_from_zones, $zonesTo);
                            if(!$isToCovered){
                                continue 1;
                            }

                            $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_dst_Members);
                            if (!$isSrcCovered) {
                                continue 1;
                            }
                            $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_src_Members);
                            if (!$isDstCovered) {
                                continue 1;
                            }
                            $servicesMatched = array();
                            $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                            if (!$isSrvCovered) {
                                continue 1;
                            }

                            if($isFromCovered * $isToCovered * $isSrvCovered * $isDstCovered * $isSrvCovered == 1){ //Fully covered
                                $natted_rules[] = $security_rule_lid;
                                //   "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                                //Modify the rule and replace the destination with before NAT
                                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$security_rule_lid'";
                                $connection->query($query);
                                $destinations = array();
                                foreach ($exploded_nat_Tsrc_Members as $dst_Member){
                                    $destinations[] = "('$security_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                                if(count($destinations)>0) {
                                    $unique = array_unique($destinations);
                                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                    $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$security_rule_lid] and NAT Rule[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$security_rule_lid', 'security_rules')";
                                }
                            }
                            //Recover the DST ip before the Static NAT
                            elseif($isSrvCovered && $isDstCovered && $isSrvCovered){ //Partially Covered
                                if(count($security_rule['dst'])!=1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0]!=$memberAnyAddress)) {
                                    // "Rule $security_rule_lid is partially covered by Static NAT $nat_rule_lid\n";
                                    //Clone the rule and add a subset with the new Destinations before Nat
                                    $count = isset($newRulesSNAT[$security_rule_lid]['cloned'])? $newRulesSNAT[$security_rule_lid]['cloned']+1 : 0;
                                    if(!isset($newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'])){
                                        $newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                    }
                                    $newRulesSNAT[$security_rule_lid]['cloned'] = $count;

                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['from'] = $zonesFrom;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['to'] = $zonesTo;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['destinations']=$exploded_nat_Tsrc_Members;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['services']=$servicesMatched;
                                }
                            }
                        }


                        if (count($natted_rules) > 0) {
                            $unique = array_unique($natted_rules);
                            //Remove those Security Rules from the Associative array, as they have already found a NAT match
                            removeKeysFromArray($security_rules, $unique);
                        }
                    }
                    */
                }
                elseif( $vendor_type == 3 ) //todo: info vendor CheckPoint
                {
                    /*
                    if($tp_sat_type =='static-ip' && $tp_sat_bidirectional=='1'){
                        $natted_rules = array();
                        foreach ($security_rules as $security_rule_lid => $security_rule) {
                            $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_dst_Members);
                            if (!$isSrcCovered) {
                                continue 1;
                            }
                            $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_src_Members);
                            if (!$isDstCovered) {
                                continue 1;
                            }
                            $servicesMatched = array();
                            $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                            if (!$isSrvCovered) {
                                continue 1;
                            }

                            if($isSrvCovered * $isDstCovered * $isSrvCovered == 1){ //Fully covered
                                $natted_rules[] = $security_rule_lid;
                                //   "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                                //Modify the rule and replace the destination with before NAT
                                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$security_rule_lid'";
                                $connection->query($query);
                                $destinations = array();
                                foreach ($exploded_nat_Tsrc_Members as $dst_Member){
                                    $destinations[] = "('$security_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                                if(count($destinations)>0) {
                                    $unique = array_unique($destinations);
                                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                    $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$security_rule_lid] and NAT Rule[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$security_rule_lid', 'security_rules')";
                                }
                            }
                            //Recover the DST ip before the Static NAT
                            elseif($isSrvCovered && $isDstCovered && $isSrvCovered){ //Partially Covered
                                if(count($security_rule['dst'])!=1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0]!=$memberAnyAddress)) {
                                    // "Rule $security_rule_lid is partially covered by Static NAT $nat_rule_lid\n";
                                    //Clone the rule and add a subset with the new Destinations before Nat
                                    $count = isset($newRulesSNAT[$security_rule_lid]['cloned'])? $newRulesSNAT[$security_rule_lid]['cloned']+1 : 0;
                                    if(!isset($newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'])){
                                        $newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                    }
                                    $newRulesSNAT[$security_rule_lid]['cloned'] = $count;

                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['destinations']=$exploded_nat_Tsrc_Members;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['services']=$servicesMatched;
                                }
                            }
                        }


                        if (count($natted_rules) > 0) {
                            $unique = array_unique($natted_rules);
                            //Remove those Security Rules from the Associative array, as they have already found a NAT match
                            removeKeysFromArray($security_rules, $unique);
                        }
                    }
                    */
                }
                elseif( $vendor_type == 4 ) //todo: info vendor CheckPointR80
                {
                    /*
                    if($tp_sat_type =='static-ip' && $tp_sat_bidirectional=='1'){
                        $natted_rules = array();
                        foreach ($security_rules as $security_rule_lid => $security_rule) {
//                        $zonesFrom = array();
//                        $isFromCovered = isAinB_Zones($security_rule['from'], $nat_to_zones, $zonesFrom);
//                        if(!$isFromCovered){
//                            continue 1;
//                        }
//                        $zonesTo = array();
//                        $isToCovered = isAinB_Zones($security_rule['to'], $nat_from_zones, $zonesTo);
//                        if(!$isToCovered){
//                            continue 1;
//                        }

                            $SrcMembers = array();
                            $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_dst_Members, $SrcMembers);
                            if (!$isSrcCovered) {
                                continue 1;
                            }
                            $DstMembers = array();
                            $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_src_Members, $DstMembers);
                            if (!$isDstCovered) {
                                continue 1;
                            }
                            $servicesMatched = array();
                            $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                            if (!$isSrvCovered) {
                                continue 1;
                            }

                            if($isSrvCovered * $isDstCovered * $isSrvCovered == 1){ //Fully covered
                                $natted_rules[] = $security_rule_lid;
                                //   "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                                //Modify the rule and replace the destination with before NAT
                                $tempZonesFrom=array();
                                $tempZonesTo=array();
                                foreach ($nat_Tto_zones as $zone) {
                                    if($zone != "any") {
                                        $tempZonesFrom[] = "($security_rule_lid, '$zone', '$vsys', '$source')";

                                    }
                                }

                                if (count($tempZonesFrom)>0){
                                    $unique = array_unique($tempZonesFrom);
                                    $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES ".implode(",",$unique).";";
                                    $connection->query($query);
                                }

                                foreach ($nat_Tto_zones as $zone) {
                                    if ($zone != "any") {
                                        $tempZonesTo[] = "($security_rule_lid, '$zone', '$vsys', '$source')";

                                    }
                                }
                                if (count($tempZonesTo)>0){
                                    $unique = array_unique($tempZonesTo);
                                    $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES ".implode(",",$unique).";";
                                    $connection->query($query);
                                }
                            }
                            //Recover the DST ip before the Static NAT
                            elseif($isSrvCovered && $isDstCovered && $isSrvCovered){ //Partially Covered
                                if(count($security_rule['dst'])!=1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0]!=$memberAnyAddress)) {
                                    // "Rule $security_rule_lid is partially covered by Static NAT $nat_rule_lid\n";
                                    //Clone the rule and add a subset with the new Destinations before Nat
                                    $count = isset($newRulesSNAT[$security_rule_lid]['cloned'])? $newRulesSNAT[$security_rule_lid]['cloned']+1 : 0;
                                    if(!isset($newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'])){
                                        $newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                    }
                                    $newRulesSNAT[$security_rule_lid]['cloned'] = $count;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['from'] = $nat_from_zones;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['to']   = $nat_to_zones;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['destinations']=$DstMembers;
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['services']=$servicesMatched;
                                }
                            }
                        }


                        if (count($natted_rules) > 0) {
                            $unique = array_unique($natted_rules);
                            //Remove those Security Rules from the Associative array, as they have already found a NAT match
                            removeKeysFromArray($security_rules, $unique);
                        }
                    }
                    */
                }
            }
        }
        //Done analysing all the NAT rules and checking the Security Rules that Match


        return null;


        //Todo: SVEN - add found NAT to Security Rules
        /*
                //Time to Insert the new Partial NATed Security Rules
                if($vendor_type==2)
                { //todo: info vendor CISCO

                    //Reload the new Security Rules, in case they have been modified by a NAT doing full Match
                    // So we can check which ones of the Partial Matches are already covered by the original Sec Rule
                    $security_rules = loadInMemorySecRules($connection, $source, $vsys);

                    //***** DNATS
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='DNAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','DNAT','color1')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanDNAT = array();
                    foreach ($newRulesDNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isFromCovered   = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                            $isToCovered     = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
        //                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                            if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Destination based on DNAT', 'Security Rule[$sec_rule_lid] covers the DNAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesDNAT = $newRulesCleanDNAT;

                    //Compact Rules by: From-Tp-Source-Destination
                    $newRulesCleanDNAT = array();
                    $removedRules = array();
                    foreach ($newRulesDNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                                    md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesDNAT = $newRulesCleanDNAT;

                    foreach ($newRulesDNAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];

                            //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                            $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'DNAT', $project);

                            //Tag the cloned Rule with the DNAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_from WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $zonesFrom = array();
                            if(isset($clone['from'])){
                                foreach ($clone['from'] as $zone) {
                                    if($zone != "any") {
                                        $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesFrom) > 0) {
                                    $unique = array_unique($zonesFrom);
                                    $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $query = "DELETE FROM security_rules_to WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $zonesTo = array();
                            if(isset($clone['to'])){
                                foreach ($clone['to'] as $zone) {
                                    if($zone != "any") {
                                        $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesTo) > 0) {
                                    $unique = array_unique($zonesTo);
                                    $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            foreach ($clone['services'] as $srv_Member) {
                                if($srv_Member != $memberAnyService) {
                                    $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($services) > 0) {
                                $unique = array_unique($services);
                                $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }
                            $add_logs[] = "('NOW()','1', 'Correcting Destination based on DNAT', 'Destination address corrected to value before DNAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    //***** Static NATS
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='Static-NAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','Static-NAT','color6')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanSNAT = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isFromCovered   = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                            $isToCovered     = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
        //                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                            if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Destination based on Static NAT', 'Security Rule[$sec_rule_lid] covers the Static NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    //Compact Rules by: From-Tp-Source-Destination
                    $newRulesCleanSNAT = array();
                    $removedRules = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                                    md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    //Compact Rules by: From-Tp-Service
                    $newRulesCleanSNAT = array();
                    $removedRules = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                                    md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                                    md5(serialize($clone['services'])) == md5(serialize($clone2['services']))){
                                    $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    foreach ($newRulesSNAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];

                            //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                            $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'SNAT', $project);

                            //Tag the cloned Rule with the SNAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_from WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $zonesFrom = array();
                            if(isset($clone['from'])){
                                foreach ($clone['from'] as $zone) {
                                    if($zone != "any") {
                                        $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesFrom) > 0) {
                                    $unique = array_unique($zonesFrom);
                                    $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $query = "DELETE FROM security_rules_to WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $zonesTo = array();
                            if(isset($clone['to'])){
                                foreach ($clone['to'] as $zone) {
                                    if($zone != "any") {
                                        $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesTo) > 0) {
                                    $unique = array_unique($zonesTo);
                                    $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            if(isset($clone['services'])) {
                                foreach ($clone['services'] as $srv_Member) {
                                    if($srv_Member != $memberAnyService) {
                                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                    }
                                }
                                if (count($services) > 0) {
                                    $unique = array_unique($services);
                                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }
                            $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    //***** NO-NATS
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='NO-NAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','NO-NAT','color3')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Filter out those NONAT clones that won't match
                    $newRulesCleanNONAT = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];

                            //Check if the TO zone contains the DST addresses
                            $zones = array();
                            foreach ($clone['sources'] as $sec_source) {
                                $member_lid = $sec_source->name;
                                $table_name = $sec_source->location;
                                if ($member_lid == 'any') {
                                    $zones = array('any');
                                    break;
                                } else {
                                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                                }
                            }
                            $foundZones = array();
                            if (isAinB_Zones($clone['from'], $zones, $foundZones) != 1) {
                                //The sources are not in the FROM zones
                                continue;
                            }

                            //Check if the FROM zone contains the SRC addresses
                            $zones = array();
                            foreach ($clone['destinations'] as $sec_source) {
                                $member_lid = $sec_source->name;
                                $table_name = $sec_source->location;
                                if ($member_lid == 'any') {
                                    break;
                                } else {
                                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                                }
                            }
                            $foundZones = array();
                            if (isAinB_Zones($clone['to'], $zones, $foundZones) != 1) {
                                //The destinations are not in the TO zones
                                continue;
                            }

                            $newRulesCleanNONAT[$sec_rule_lid] = $clones;
                        }
                    }

                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanNONAT = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isFromCovered   = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                            $isToCovered     = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                            $isSrcCovered    = isAinB($clone['sources'], $security_rules[$sec_rule_lid]['src']);
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
        //                if($isFromCovered*$isToCovered*$isSrcCovered*$isDstCovered*$isSrvCovered == 1){
                            if($isFromCovered*$isToCovered*$isSrcCovered*$isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NO-NAT', 'Security Rule[$sec_rule_lid] covers the NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-Tp-Service-Destination
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                                    md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                                    md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['sources'] = array_merge($clone['sources'], $clone2['sources']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-Tp-Source-Destination
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                                    md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                                    md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-To-Source-Service
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                                    md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                                    md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                                    md5(serialize($clone['services'])) == md5(serialize($clone2['services']))){
                                    $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    foreach ($newRulesNONAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];
                            $new_rule_lid = clone_security_rule("", "-1", $vsys, $source, $sec_rule_lid, 'NO-NAT', $project);

                            //Tag the cloned Rule with the NO-NAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_src WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $sources = array();
                            foreach ($clone['sources'] as $src_Member) {
                                if($src_Member != $memberAnyAddress) {
                                    $sources[] = "('$new_rule_lid','$src_Member->name','$src_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($sources) > 0) {
                                $unique = array_unique($sources);
                                $query = "INSERT INTO security_rules_src (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_from WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $zonesFrom = array();
                            if(isset($clone['from'])){
                                foreach ($clone['from'] as $zone) {
                                    if($zone != "any") {
                                        $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesFrom) > 0) {
                                    $unique = array_unique($zonesFrom);
                                    $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $query = "DELETE FROM security_rules_to WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $zonesTo = array();
                            if(isset($clone['to'])){
                                foreach ($clone['to'] as $zone) {
                                    if($zone != "any") {
                                        $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesTo) > 0) {
                                    $unique = array_unique($zonesTo);
                                    $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            if(isset($clone['services'])) {
                                foreach ($clone['services'] as $srv_Member) {
                                    if($srv_Member != $memberAnyService) {
                                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                    }
                                }
                                if (count($services) > 0) {
                                    $unique = array_unique($services);
                                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }
                            $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NAT', 'Security Rule[$sec_rule_lid] cloned to consider NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    if(count($add_logs)>0){
                        add_log_bulk($connection, $add_logs);
                    }

                    updateRuleNames($projectdb, $source, $vsys, "fix_duplicates", "", "security_rules");
                }
                if($vendor_type==3)
                { //todo: info vendor CheckPoint

                    //Reload the new Security Rules, in case they have been modified by a NAT doing full Match
                    // So we can check which ones of the Partial Matches are already covered by the original Sec Rule
                    $security_rules = loadInMemorySecRules($connection, $source, $vsys);

                    //***** DNATS
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='DNAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','DNAT','color1')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanDNAT = array();
                    foreach ($newRulesDNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
        //                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                            if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Destination based on DNAT', 'Security Rule[$sec_rule_lid] covers the DNAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesDNAT = $newRulesCleanDNAT;

                    //Compact Rules by: From-To-Source-Destination
                    $newRulesCleanDNAT = array();
                    $removedRules = array();
                    foreach ($newRulesDNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesDNAT = $newRulesCleanDNAT;

                    foreach ($newRulesDNAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];

                            //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                            $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'DNAT', $project);

                            //Tag the cloned Rule with the DNAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            foreach ($clone['services'] as $srv_Member) {
                                if($srv_Member != $memberAnyService) {
                                    $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($services) > 0) {
                                $unique = array_unique($services);
                                $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }
                            $add_logs[] = "('NOW()','1', 'Correcting Destination based on DNAT', 'Destination address corrected to value before DNAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    //***** Static NATS
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='Static-NAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','Static-NAT','color6')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanSNAT = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
        //                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                            if($isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Destination based on Static NAT', 'Security Rule[$sec_rule_lid] covers the Static NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    //Compact Rules by: From-Tp-Source-Destination
                    $newRulesCleanSNAT = array();
                    $removedRules = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    //Compact Rules by: From-Tp-Service
                    $newRulesCleanSNAT = array();
                    $removedRules = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['services'])) == md5(serialize($clone2['services']))){
                                    $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    foreach ($newRulesSNAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];

                            //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                            $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'SNAT', $project);

                            //Tag the cloned Rule with the SNAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            if(isset($clone['services'])) {
                                foreach ($clone['services'] as $srv_Member) {
                                    if($srv_Member != $memberAnyService) {
                                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                    }
                                }
                                if (count($services) > 0) {
                                    $unique = array_unique($services);
                                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }
                            $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    //***** NO-NATS
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='NO-NAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','NO-NAT','color3')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanNONAT = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isSrcCovered    = isAinB($clone['sources'], $security_rules[$sec_rule_lid]['src']);
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
        //                if($isFromCovered*$isToCovered*$isSrcCovered*$isDstCovered*$isSrvCovered == 1){
                            if($isSrcCovered*$isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NO-NAT', 'Security Rule[$sec_rule_lid] covers the NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-Tp-Service-Destination
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['sources'] = array_merge($clone['sources'], $clone2['sources']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-Tp-Source-Destination
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-To-Source-Service
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                                    md5(serialize($clone['services'])) == md5(serialize($clone2['services']))){
                                    $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    foreach ($newRulesNONAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];
                            $new_rule_lid = clone_security_rule("", "-1", $vsys, $source, $sec_rule_lid, 'NO-NAT', $project);

                            //Tag the cloned Rule with the NO-NAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_src WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $sources = array();
                            foreach ($clone['sources'] as $src_Member) {
                                if($src_Member != $memberAnyAddress) {
                                    $sources[] = "('$new_rule_lid','$src_Member->name','$src_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($sources) > 0) {
                                $unique = array_unique($sources);
                                $query = "INSERT INTO security_rules_src (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            if(isset($clone['services'])) {
                                foreach ($clone['services'] as $srv_Member) {
                                    if($srv_Member != $memberAnyService) {
                                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                    }
                                }
                                if (count($services) > 0) {
                                    $unique = array_unique($services);
                                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }
                            $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NAT', 'Security Rule[$sec_rule_lid] cloned to consider NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    if(count($add_logs)>0){
                        add_log_bulk($connection, $add_logs);
                    }

                    updateRuleNames($projectdb, $source, $vsys, "fix_duplicates", "", "security_rules");
                }
                if($vendor_type==4)
                {
                    //todo: info vendor CheckPointR80

                    //Fixing zones of Security Rules that did not match any Nat Rule
                    echo "Calculating the zone for those rules that did not make any match\n";
                    $rules = array();
                    foreach ($security_rules as $key=>$value){
                        $rules[] = $key;
                    }
                    set_Zones_Security_Rules_noNat($rules, $source, $vsys, $vr, $ipMapping);
                    //Done Calculating zones of Security Rules that did not match any Nat Rule

                    echo "Going to insert the new partial matches\n";
                    //Reload the new Security Rules, in case they have been modified by a NAT doing full Match
                    // So we can check which ones of the Partial Matches are already covered by the original Sec Rule
                    $security_rules = loadInMemorySecRules($connection, $source, $vsys);

                    //***** DNATS
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='DNAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','DNAT','color1')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    echo "Inserting DNAT affected Rules\n";
                    $newRulesCleanDNAT = array();
                    foreach ($newRulesDNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isFromCovered   = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                            $isToCovered     = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
                            if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
        //                if($isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Destination based on DNAT', 'Security Rule[$sec_rule_lid] covers the DNAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesDNAT = $newRulesCleanDNAT;

                    //Compact Rules by: Source-Service
                    $newRulesCleanDNAT = array();
                    $removedRules = array();
                    foreach ($newRulesDNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['services'])) == md5(serialize($clone2['services']))){
                                    $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesDNAT = $newRulesCleanDNAT;

                    foreach ($newRulesDNAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];

                            //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                            $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'DNAT', $project);

                            //TODO: Make those Delete and Insert as unique queries
                            //Tag the cloned Rule with the DNAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            foreach ($clone['services'] as $srv_Member) {
                                if($srv_Member != $memberAnyService) {
                                    $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($services) > 0) {
                                $unique = array_unique($services);
                                $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }


                            //Adding the From Zone
                            $zonesFrom = array();
                            if(isset($clone['from'])){
                                foreach ($clone['from'] as $zone) {
                                    if($zone != "any") {
                                        $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesFrom) > 0) {
                                    $unique = array_unique($zonesFrom);
                                    $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            //Adding the To Zone
                            $zonesTo = array();
                            if(isset($clone['to'])){
                                foreach ($clone['to'] as $zone) {
                                    if($zone != "any") {
                                        $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesTo) > 0) {
                                    $unique = array_unique($zonesTo);
                                    $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $add_logs[] = "('NOW()','1', 'Correcting Destination, Zone From and Zone To based on DNAT', 'Destination address corrected to value before DNAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    //***** Static NATS
                    echo "Inserting Static-NAT affected Rules\n";
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='Static-NAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','Static-NAT','color6')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanSNAT = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isFromCovered   = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                            $isToCovered     = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
                            if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
        //                if($isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Destination based on Static NAT', 'Security Rule[$sec_rule_lid] covers the Static NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue;
                            }
                            else {
                                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    //Compact Rules by: From-Tp-Source-Destination
                    $newRulesCleanSNAT = array();
                    $removedRules = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    //Compact Rules by: From-Tp-Service
                    $newRulesCleanSNAT = array();
                    $removedRules = array();
                    foreach ($newRulesSNAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['services'])) == md5(serialize($clone2['services']))){
                                    $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesSNAT = $newRulesCleanSNAT;

                    foreach ($newRulesSNAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];

                            //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                            $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'SNAT', $project);

                            //Tag the cloned Rule with the SNAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            if(isset($clone['services'])) {
                                foreach ($clone['services'] as $srv_Member) {
                                    if($srv_Member != $memberAnyService) {
                                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                    }
                                }
                                if (count($services) > 0) {
                                    $unique = array_unique($services);
                                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            //Adding the From Zone
                            $zonesFrom = array();
                            if(isset($clone['from'])){
                                foreach ($clone['from'] as $zone) {
                                    if($zone != "any") {
                                        $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesFrom) > 0) {
                                    $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $zonesFrom) . ";";
                                    $connection->query($query);
                                }
                            }

                            //Adding the To Zone
                            $zonesTo = array();
                            if(isset($clone['to'])){
                                foreach ($clone['to'] as $zone) {
                                    if($zone != "any") {
                                        $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesTo) > 0) {
                                    $unique = array_unique($zonesTo);
                                    $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $add_logs[] = "('NOW()','1', 'Correcting Destination, Zone From and Zone To based on Static Bidirectional NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    //***** NO-NATS
                    echo "Inserting No-NAT affected Rules\n";
                    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='NO-NAT'";
                    $result = $connection->query($query);
                    if($result->num_rows==0){
                        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','NO-NAT','color3')";
                        $connection->query($query);
                        $tag_id = $connection->insert_id;
                    }
                    else{
                        $this->data = $result->fetch_assoc();
                        $tag_id = $this->data['id'];
                    }

                    //Check which rules are already covered by the original Security Rule
                    $newRulesCleanNONAT = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            $isFromCovered   = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                            $isToCovered     = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                            $isSrcCovered    = isAinB($clone['sources'], $security_rules[$sec_rule_lid]['src']);
                            $isDstCovered    = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                            $isSrvCovered    = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                            $nat_rule_lid = $clone['nat_lid'];
                            if($isFromCovered*$isToCovered*$isSrcCovered*$isDstCovered*$isSrvCovered == 1){
        //                if($isSrcCovered*$isDstCovered*$isSrvCovered > 0){
                                $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NO-NAT', 'Security Rule[$sec_rule_lid] covers the NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                                continue 1;
                            }
                            else {
                                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                            }
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-Tp-Service-Destination
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['sources'] = array_merge($clone['sources'], $clone2['sources']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-Tp-Source-Destination
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                                    md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations']))){
                                    $clone['services'] = array_merge($clone['services'], $clone2['services']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    //Compact Rules by: From-To-Source-Service
                    $newRulesCleanNONAT = array();
                    $removedRules = array();
                    foreach ($newRulesNONAT as $sec_rule_lid => &$clones){
                        foreach ($clones['clones'] as $id => &$clone){
                            if(isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid])){
                                continue;
                            }
                            foreach ($clones['clones'] as $id2 => &$clone2) {
                                if($id == $id2 || ( isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid]))){
                                    continue;
                                }
                                if (md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                                    md5(serialize($clone['services'])) == md5(serialize($clone2['services']))){
                                    $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                                    $clone['nat_lid'] .= ",".$clone2['nat_lid'];
                                    $removedRules[$sec_rule_lid][] = $id2;
                                }
                            }
                            $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                        }
                    }
                    $newRulesNONAT = $newRulesCleanNONAT;

                    foreach ($newRulesNONAT as $sec_rule_lid => $clones) {
                        foreach ($clones['clones'] as $clone) {
                            $nat_rule_lid = $clone['nat_lid'];
                            $new_rule_lid = clone_security_rule("", "-1", $vsys, $source, $sec_rule_lid, 'NO-NAT', $project);

                            //TODO:
                            //Tag the cloned Rule with the NO-NAT tag
                            $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                            $connection->query($query);

                            $query = "DELETE FROM security_rules_src WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $sources = array();
                            foreach ($clone['sources'] as $src_Member) {
                                if($src_Member != $memberAnyAddress) {
                                    $sources[] = "('$new_rule_lid','$src_Member->name','$src_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($sources) > 0) {
                                $unique = array_unique($sources);
                                $query = "INSERT INTO security_rules_src (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach ($clone['destinations'] as $dst_Member) {
                                if($dst_Member != $memberAnyAddress) {
                                    $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                                }
                            }
                            if (count($destinations) > 0) {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                            }

                            $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                            $connection->query($query);
                            $services = array();
                            if(isset($clone['services'])) {
                                foreach ($clone['services'] as $srv_Member) {
                                    if($srv_Member != $memberAnyService) {
                                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                                    }
                                }
                                if (count($services) > 0) {
                                    $unique = array_unique($services);
                                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            //Adding the From Zone
                            $zonesFrom = array();
                            if(isset($clone['from'])){
                                foreach ($clone['from'] as $zone) {
                                    if($zone != "any") {
                                        $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesFrom) > 0) {
                                    $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $zonesFrom) . ";";
                                    $connection->query($query);
                                }
                            }

                            //Adding the To Zone
                            $zonesTo = array();
                            if(isset($clone['to'])){
                                foreach ($clone['to'] as $zone) {
                                    if($zone != "any") {
                                        $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                                    }
                                }
                                if (count($zonesTo) > 0) {
                                    $unique = array_unique($zonesTo);
                                    $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                    $connection->query($query);
                                }
                            }

                            $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses and Zones based on NO-NAT', 'Security Rule[$sec_rule_lid] cloned to consider NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
                        }
                    }

                    if(count($add_logs)>0){
                        add_log_bulk($connection, $add_logs);
                    }

                    updateRuleNames($projectdb, $source, $vsys, "fix_duplicates", "", "security_rules");
                }

                */
    }


    #function fix_destination_nat($config_path, $source, $vsys) {

    /**
     * @param array() $this->data
     * @param VirtualSystem $v
     * @return null
     */
    function fix_destination_nat()
    {
        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }
        //global $projectdb;
        //$this->data = file($config_path);

        /*
        foreach( $this->sub->securityRules->rules() as $rule )
        {
            print "check SecRule: ".$rule->name()."\n";
            $rule->zoneCalculation( 'from', "replace", "vr_vsys1" );
            $rule->zoneCalculation( 'to', "replace", "vr_vsys1" );
        }*/

        /*
        $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
        if ($getVR->num_rows == 1) {
            $VRData = $getVR->fetch_assoc();
            $vr = $VRData['id'];


            #############################################################

            $from_or_to = "from";
            $rule_or_nat = "rule";


            //$record = Array('network' => $destination, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone, 'origin' => 'static', 'priority' => 2);
            //$ipv4sort[  $record['end'] - $record['start']  ][  $record['start']  ][] = &$record;
            //$ipv4 = $ipv4sort;
            //$ipMapping = Array('ipv4' => &$ipv4, 'ipv6' => &$ipv6);
            $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);



            $ids_rules = getSecurityIdsBySourceVsys($source, $vsys);


            //delete FROM zone entries for all security rules
            $projectdb->query("DELETE FROM security_rules_from WHERE rule_lid IN (".implode(',', $ids_rules).");");

            //get all SRC entries from all security rules
            $query = "SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE rule_lid IN (".implode(',', $ids_rules).");";
            $getSRC = $projectdb->query($query);
            if ($getSRC->num_rows > 0) {
                while ($getSRCData = $getSRC->fetch_assoc()) {
                    $member_lid = $getSRCData['member_lid'];
                    $table_name = $getSRCData['table_name'];
                    $rule_lid = $getSRCData['rule_lid'];


                    // Mirar si para esta regla es negated o no
                    $getIsNegated = $projectdb->query("SELECT negate_source, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                    if ($getIsNegated->num_rows > 0) {
                        $getINData = $getIsNegated->fetch_assoc();
                        $negate_source = $getINData['negate_source'];
                        $devicegroup = $getINData['devicegroup'];
                    }


                    $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_source';");
                    if ($getZones->num_rows == 1){
                        $getZonesData = $getZones->fetch_assoc();
                        $zones_sql = $getZonesData['zone'];
                        $zones = explode(",", $zones_sql);
                    }
                    else
                    {

                        $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_source','$vsys', '$source');");
                    }
                    foreach ($zones as $zone) {
                        $getZone = $projectdb->query("SELECT id FROM security_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                        if ($getZone->num_rows == 0) {
                            $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) "
                                . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                        }
                    }
                }
            }
            ############################################################

            #############################################################

            $from_or_to = "to";
            $rule_or_nat = "rule";
            $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid IN (".implode(',', $ids_rules).");");
            $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE rule_lid IN (".implode(',', $ids_rules).");");
            if ($getSRC->num_rows > 0) {
                while ($getSRCData = $getSRC->fetch_assoc()) {
                    $member_lid = $getSRCData['member_lid'];
                    $table_name = $getSRCData['table_name'];
                    $rule_lid = $getSRCData['rule_lid'];

                    // Mirar si para esta regla es negated o no
                    $getIsNegated = $projectdb->query("SELECT negate_destination, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                    if ($getIsNegated->num_rows > 0) {
                        $getINData = $getIsNegated->fetch_assoc();
                        $negate_destination = $getINData['negate_destination'];
                        $devicegroup = $getINData['devicegroup'];
                    }

                    // Transfer this information of the tmp_calc_zone into memory space
                    $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_destination';");
                    if ($getZones->num_rows == 1){
                        $getZonesData = $getZones->fetch_assoc();
                        $zones_sql = $getZonesData['zone'];
                        $zones = explode(",", $zones_sql);
                    }
                    else{
                        $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination);
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_destination','$vsys', '$source');");
                    }
                    foreach ($zones as $zone) {
                        $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                        if ($getZone->num_rows == 0) {
                            $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                                . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                        }
                    }
                }
            }
            ############################################################
        }

        */
        # Fix based in access-group direction
        foreach( $this->data as $line => $names_line )
        {
            if( preg_match("/^access-group /i", $names_line) )
            {
                $addfrom = array();
                $rules = array();
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $tagname = $this->truncate_tags($netObj[1]);

                $direction = $netObj[2];
                if( $direction == 'global' )
                {
                    continue;
                }

                $zoneFrom = $netObj[4];
                $tmp_zone = $this->template_vsys->zoneStore->find($zoneFrom);

                if( $direction == "in" )
                {
                    $table_direction = "security_rules_from";
                    $whatzone = "FROM";
                    $ZoneToCalculate = "To";
                }
                else //if ($direction == "out")
                {
                    $table_direction = "security_rules_to";
                    $whatzone = "TO";
                    $ZoneToCalculate = "From";
                }


                print "\nsearch for TAG: " . $tagname . "\n";
                $tmp_tag = $this->sub->tagStore->find($tagname);


                $tmp_rules = $this->sub->securityRules->rules("tag has " . $tmp_tag->name());

                foreach( $tmp_rules as $tmp_rule )
                {
                    $message = 'Auto Zone Assign - Forcing Zone [' . $whatzone . '] to [' . $zoneFrom . '] on access-list [' . $tagname . '] based on access-group direction [' . $direction . ']';
                    print "RULE: " . $tmp_rule->name() . " - " . $message . "\n";

                    $message .= " - No Action Required";

                    if( $whatzone == "FROM" )
                    {
                        $tmp_rule->from->addZone($tmp_zone);
                        $tmp_rule->set_node_attribute("warning", $message);
                    }
                    elseif( $whatzone == "TO" )
                    {
                        $tmp_rule->to->addZone($tmp_zone);
                        $tmp_rule->set_node_attribute("warning", $message);
                    }

                }

                /*
                //Get the Implicit zone that is defined in the Access_list
                $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='$tagname';");
                if ($getTag->num_rows == 1) {
                    $getTagData = $getTag->fetch_assoc();
                    $member_lid = $getTagData['id'];
                    $table_name = "tag";
                    $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_tag WHERE member_lid='$member_lid' AND table_name='$table_name';");
                    if ($getRules->num_rows > 0) {
                        while ($getRulesData = $getRules->fetch_assoc()) {
                            $rule_lid = $getRulesData['rule_lid'];
                            $addfrom[] = "('$source','$vsys','$zoneFrom','$rule_lid','default')";
                            $rules[] = $getRulesData['rule_lid'];
                        }
                    }
                    if (count($rules) > 0) {
                        $projectdb->query("DELETE FROM $table_direction WHERE rule_lid IN (" . implode(",", $rules) . ") ;");
                        unset($rules);
                    }
                    if (count($addfrom) > 0) {
                        $projectdb->query("INSERT INTO $table_direction (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $addfrom) . ";");
                        unset($addfrom);
                        add_log2('warning', 'Auto Zone Assign', 'Forcing Zone [' . $whatzone . '] to [' . $zoneFrom . '] on access-list [' . $tagname . '] based on access-group direction [' . $direction . ']', $source, 'No Action Required', '', '', '');
                    }
                }
                */

                //Calculate the Zone that is remaining

            }
        }
    }


    function get_interfaceIP_for_zone_SNAT( $tmp_nat_rule, $op_zone_to, $err_number, $nat_type = "dynamic-ip-and-port")
    {
        global $print;

        $tmp_zone = $this->template_vsys->zoneStore->find($op_zone_to);
        if( $tmp_zone != null )
        {
            $tmp_attachedInterfaces = $tmp_zone->attachedInterfaces->getAll();
            if( count($tmp_attachedInterfaces) != 0 )
            {
                $tmp_interface = $tmp_attachedInterfaces[0];
                if( $tmp_interface->type() == 'layer3' && count($tmp_interface->getLayer3IPv4Addresses()) > 0 )
                {
                    $tp_sat_address_type = "interface-address";
                    $tmp_nat_rule->snatinterface = $tmp_interface->name();

                    //add SNAT Interface IP-address
                    $tp_sat_ipaddress = $tmp_interface->getLayer3IPv4Addresses()[0];

                    $tmp_value = explode('/', $tp_sat_ipaddress);
                    $tmp_address_snat_int = $this->sub->addressStore->all('value string.regex /' . $tmp_value[0] . '/');

                    if( !empty($tmp_address_snat_int) && count($tmp_address_snat_int) == 1 && $tmp_address_snat_int[0]->getNetworkValue() == $tmp_value[0] )
                        $tmp_address_snat_int = $tmp_address_snat_int[0];
                    else
                    {
                        $new_name = $name_int = $this->truncate_names($this->normalizeNames($tp_sat_ipaddress));
                        $tmp_address_snat_int = $this->sub->addressStore->find($new_name);
                        if( $tmp_address_snat_int === null )
                            $tmp_address_snat_int = $this->sub->addressStore->newAddress($new_name, 'ip-netmask', $tp_sat_ipaddress);
                    }

                    $tmp_nat_rule->snathosts->addObject($tmp_address_snat_int);
                    $tmp_nat_rule->changeSourceNAT($nat_type);

                    if( $print )
                    {
                        print "    * add snat interface: " . $tmp_interface->name() . "\n";
                        print "    * snat type: 'dynamic-ip-and-port'\n";
                        print "    * add snathost: " . $tmp_address_snat_int->name() . "\n";
                    }
                }
            }
        }
        else
        {
            mwarning("X can not find Zone with name: " . $op_zone_to . " | Problem " . $err_number . "\n");
        }
    }


    function set_from_to_zone($zone_define, $tmp_nat_rule, $zone)
    {
        global $print;

        if( ($zone != "any") and ($zone != "") )
        {
            $tmp_zone = $this->template_vsys->zoneStore->find($zone);
            if( $tmp_zone !== null )
            {

                if( $zone_define == "from" )
                {
                    if( $print )
                        print "    * add from: " . $tmp_zone->name() . "\n";
                    $tmp_nat_rule->from->addZone($tmp_zone);
                }

                elseif( $zone_define == "to" )
                {
                    if( $print )
                        print "    * add to: " . $tmp_zone->name() . "\n";
                    $tmp_nat_rule->to->addZone($tmp_zone);
                }

            }
        }
        else
        {
            //check if this additional validation and change make sense
            //todo bring in correct virtual router
            #$tmp_nat_rule->zoneCalculation( $zone_define, "replace", "vr_vsys1" );
        }

    }

    function set_source_nat($tmp_nat_rule, $tp_dat_address_lid, $dst_lid, $nat_type)
    {
        global $print;

        if( is_object($tp_dat_address_lid) )
        {
            if( $print )
                print "    * add source: " . $tp_dat_address_lid->name() . "\n";
            $tmp_nat_rule->source->addObject($tp_dat_address_lid);
        }
        else
            mwarning("problem with tp_dat_address_lid: '" . $tp_dat_address_lid . "'");

        if( is_object($dst_lid) )
        {
            if( $print )
                print "    * add sourceNAT: " . $dst_lid->name() . "\n";
            $tmp_nat_rule->snathosts->addObject($dst_lid);
        }
        else
            mwaring("problem with dst_lid: '" . $dst_lid . "'");

        if( $print )
            print "    * snat type: '" . $nat_type . "'\n";
        $tmp_nat_rule->changeSourceNAT($nat_type);
    }


    function get_twice_nats( $isafter)
    {

        global $debug;
        global $print;

        global $projectdb;
        global $nat_lid;

        $nat_lid = 1;

        $AddFrom = array();
        $AddSource = array();
        $AddTranslated = array();
        $AddDestination = array();

        $addNatRule = array();

        $ruleName = "";
        $op_zone_to = "";
        $op_service_lid = "";
        $op_service_table = "";
        $tp_dat_port = "";
        $tp_dat_address_lid = "";
        $tp_dat_address_table = "";
        $checkit = 0;
        $tp_sat_interface = "";
        $tp_dat_address_lid = "";
        $tp_dat_address_table = "";
        $op_service_table = "";
        $op_service_lid = "";
        $tp_sat_address_type = "";
        $tp_sat_ipaddress = "";
        $tp_sat_type = "";
        $tp_dat_port = "";
        $isdat = "";
        $from = "";


        $vsys = $this->template_vsys->name();
        $source = "";
        $position = "";

        /*
         * //SWASCHKUT no longer needed;
        #Nat Stuff Related
        $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
        if ($getPosition->num_rows == 0) {
            $position = 1;
        }
        else {
            $ddata = $getPosition->fetch_assoc();
            $position = $ddata['t'] + 1;
        }
        if ($nat_lid == "") {
            $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = intval($getLID1['max']) + 1;
        }
        */


        foreach( $this->data as $line => $names_line )
        {
            $names_line = rtrim($names_line);

            if( (preg_match("/^nat \(/", $names_line)) and (
                    (preg_match("/source static/", $names_line)) or
                    (preg_match("/source dynamic/", $names_line)) or
                    (preg_match("/destination static/", $names_line))) )
            {


                #nat (outside,inside) 1 source dynamic any PAT-ADDRESS-100 destination static SERVER-33.33.33.33 SERVER-192.168.100.200 service SMTP-SERVICE SMTP-SERVICE
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $zones = str_replace("(", '', $netObj[1]);
                $zones = str_replace(")", '', $zones);
                $zonesAll = explode(",", $zones);
                $from = $zonesAll[0];
                $op_zone_to = $zonesAll[1];
                $checkit = 0;

                if( $isafter == "after" )
                {
                    if( (preg_match("/ after-object \(/", $names_line)) or (preg_match("/ after-auto \(/", $names_line)) )
                    {
                    }
                    else
                    {
                        continue;
                    }
                }
                else
                {
                    if( (preg_match("/ after-object \(/", $names_line)) or (preg_match("/ after-auto \(/", $names_line)) )
                    {
                        continue;
                    }
                }


                #nat (outside,inside) after-object 1 source dynamic any PAT-ADDRESS-100 destination static SERVER-33.33.33.33 SERVER-192.168.100.200 service SMTP-SERVICE SMTP-SERVICE
                if(
                    isset($netObj[2]) && ((is_numeric($netObj[2])) or ($netObj[2] == "after-object") or ($netObj[2] == "after-auto"))
                )
                {
                    unset($netObj[2]);
                    $netObj = array_values($netObj);
                }
                //SWASCHKUT - already done, why again
                if( isset($netObj[2]) && is_numeric($netObj[2]) )
                {
                    unset($netObj[2]);
                    $netObj = array_values($netObj);
                }

                $ruleName = "Nat Twice " . $nat_lid;

                $tmp_nat_rule = $this->sub->natRules->find($ruleName);
                if( $tmp_nat_rule === null )
                {
                    if( $print )
                        print "  * create NAT rule: '" . $ruleName . "'\n";
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName);
                }
                else
                {
                    mwarning("NAT rule: " . $ruleName . " - already available");
                }


                if( preg_match("/\binactive\b/", $names_line) )
                {
                    $disabled = 1;
                    $tmp_nat_rule->setDisabled(TRUE);
                }
                else
                {
                    $disabled = 0;
                }
                #Description
                $isDescriptionin = array_search('description', $netObj);
                $descPos = $isDescriptionin + 1;
                if( $isDescriptionin != FALSE )
                {
                    $description1 = array_slice($netObj, $descPos);
                    $description = addslashes(implode(" ", $description1));

                    $tmp_nat_rule->setDescription($description);

                    $descPos = "";
                    $description1 = "";
                    $isDescriptionin = "";
                }
                else
                {
                    $description = "";
                }


                $bidirectional = 0;
                if( isset($netObj[2]) && ($netObj[2] == "source") and ($netObj[3] == "dynamic") )
                {
                    #get Real IP Address by name
                    $ObjectNetworkName = $netObj[4];
                    if( $ObjectNetworkName == "any" )
                    {
                    }
                    else
                    {
                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));

                        $tmp_address = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tmp_address !== null )
                        {
                            if( $print )
                                print "    * add source: " . $tmp_address->name() . "\n";
                            $tmp_nat_rule->source->addObject($tmp_address);
                        }
                        else
                        {
                            if( $print )
                                print "  X address object for source : " . $ObjectNetworkName . " not found\n";
                        }
                        /*
                                            $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                                            if ($getRealIP->num_rows == 1)
                                            {
                                                $getRealIPData = $getRealIP->fetch_assoc();
                                                $RealIP = $getRealIPData['ipaddress'];
                                                $RealIPCIDR = $getRealIPData['cidr'];
                                                $member_lid = $getRealIPData['id'];
                                                $table_name = "address";
                                                $RealIPType = $getRealIPData['type'];
                                                $AddSource[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                                            }
                                            else
                                            {
                                                $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                                                if ($getRealIP->num_rows == 1) {
                                                    $getRealIPData = $getRealIP->fetch_assoc();
                                                    $member_lid = $getRealIPData['id'];
                                                    $table_name = "address_groups_id";
                                                    $AddSource[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                                                }
                                            }
                                        */

                        if( ($from == "any") or ($from == "") )
                        {
                            //todo bring in correct virtual router
                            print "NAT rule: " . $tmp_nat_rule->name() . " zone calculation for from\n";
                            if( $this->template->owner == null )
                            {
                                //$template class is PANConf
                                $tmp_nat_rule->zoneCalculation('from', "replace", "vr_vsys1");
                            }
                            else
                            {
                                //panorama template
                                $tmp_nat_rule->zoneCalculation('from', "replace", "vr_vsys1", $this->template->owner->name(), $this->sub->name());
                            }


                            /*
                            #Calculate the Zones based on Real IP
                            if ($table_name=="address_groups_id"){
                                $getMem=$projectdb->query("SELECT member_lid,table_name FROM address_groups WHERE lid='$member_lid' AND table_name !='address_groups_id' LIMIT 1;");
                                if ($getMem->num_rows==1){
                                    $getMemData=$getMem->fetch_assoc();
                                    $mem_member_lid=$getMemData['member_lid'];
                                    $mem_table_name=$getMemData['table_name'];
                                    $from = search_zone_address_one($mem_member_lid, $vsys, $source, $mem_table_name);
                                }
                            }
                            else{
                                $from = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                            }
                            */
                        }
                    }


                    $mappedIP = $netObj[5];
                    if( $mappedIP == $ObjectNetworkName )
                    {
                        # No Source NAT
                        $tp_sat_type = "";
                    }
                    else
                    {
                        # Source NAT
                        if( $mappedIP == "any" )
                        {
                        }
                        elseif( $mappedIP == "interface" )
                        {
                            $this->get_interfaceIP_for_zone_SNAT( $tmp_nat_rule, $op_zone_to, "4186");
                        }
                        else
                        {
                            if( $mappedIP == "pat-pool" )
                            {
                                $mappedIP = $netObj[6];
                                unset($netObj[6]);
                                $tp_sat_type = "dynamic-ip-and-port";
                            }
                            else
                            {
                                $tp_sat_type = "dynamic-ip";
                            }


                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));

                            $tmp_address = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $tmp_address !== null )
                            {
                                if( $print )
                                    print "    * add SNAT: " . $tp_sat_type . " - with object: " . $ObjectNetworkName . "\n";

                                $tmp_nat_rule->snathosts->addObject($tmp_address);
                                $tmp_nat_rule->changeSourceNAT($tp_sat_type);
                            }
                            else
                            {
                                if( $print )
                                    print "  X address object for source : " . $ObjectNetworkName . " not found. problem 4220\n";
                            }
                        }
                    }

                    unset($netObj[2]);
                    unset($netObj[3]);
                    unset($netObj[4]);
                    unset($netObj[5]);
                    $netObj = array_values($netObj);
                }

                if( isset($netObj[2]) && $netObj[2] == "flat" )
                {
                    $add_log2 = 'Nat Rule ID [' . $nat_lid . '] containg unsuported "flat" option. Review NAT rule';
                    unset($netObj[2]);
                    $netObj = array_values($netObj);
                }

                if( isset($netObj[2]) && ($netObj[2] == "source") and ($netObj[3] == "static") )
                {
                    #get Real IP Address by name
                    $ObjectNetworkName = $netObj[4];
                    if( $ObjectNetworkName == "any" )
                    {
                    }
                    else
                    {
                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));

                        $tmp_address = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tmp_address !== null )
                        {
                            if( $print )
                                print "    * add source: " . $tmp_address->name() . "\n";
                            #$tmp_nat_rule->source->
                            $tmp_nat_rule->source->addObject($tmp_address);
                        }
                        else
                        {
                            if( $print )
                                print "  X address object for source : " . $ObjectNetworkName . " not found\n";
                        }


                        if( ($from == "any") or ($from == "") )
                        {
                            //todo bring in correct virtual router
                            print "NAT rule: " . $tmp_nat_rule->name() . " zone calculation for from\n";
                            if( $this->template->owner == null )
                            {
                                //$template class is PANConf
                                $tmp_nat_rule->zoneCalculation('from', "replace", "vr_vsys1");
                            }
                            else
                            {
                                //panorama template
                                $tmp_nat_rule->zoneCalculation('from', "replace", "vr_vsys1", $this->template->owner->name(), $this->sub->name());
                            }
                        }
                    }


                    $mappedIP = $netObj[5];
                    if( $mappedIP == $ObjectNetworkName )
                    {
                        # No Source NAT
                        $tp_sat_type = "";
                    }
                    else
                    {

                        # Source NAT
                        $tp_sat_type = "static-ip";
                        /*
                        if (preg_match("/ unidirectional /",$names_line)){
                            $bidirectional=0;
                        }
                        else{
                            $bidirectional=1;
                            $tmp_nat_rule->setBiDirectional( true );
                        }
                        */
                        if( $mappedIP == "any" )
                        {
                        }
                        elseif( $mappedIP == "interface" )
                        {
                            $this->get_interfaceIP_for_zone_SNAT( $tmp_nat_rule, $op_zone_to, "4309", $tp_sat_type);
                        }
                        else
                        {

                            # Pat pool should not be found here but. . .
                            mwarning("found PAT pool, where it is not expected.");
                            if( $mappedIP == "pat-pool" )
                            {
                                $mappedIP = $netObj[6];
                                unset($netObj[6]);
                            }

                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));

                            $tmp_address = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $tmp_address !== null )
                            {
                                if( $print )
                                    print "    * add SNAT: " . $tp_sat_type . " - with object: " . $ObjectNetworkName . "\n";

                                $tmp_nat_rule->snathosts->addObject($tmp_address);
                                $tmp_nat_rule->changeSourceNAT($tp_sat_type);
                            }
                            else
                            {
                                if( $print )
                                    print "  X address object for source : " . $ObjectNetworkName . " not found. problem 4340\n";
                            }
                        }

                        if( preg_match("/ unidirectional /", $names_line) )
                        {
                            $bidirectional = 0;
                        }
                        else
                        {
                            $bidirectional = 1;
                            $tmp_nat_rule->setBiDirectional(TRUE);
                        }
                    }


                    unset($netObj[2]);
                    unset($netObj[3]);
                    unset($netObj[4]);
                    unset($netObj[5]);
                    $netObj = array_values($netObj);
                }

                if( isset($netObj[2]) && $netObj[2] == "round-robin" )
                {
                    unset($netObj[2]);
                    $netObj = array_values($netObj);
                }

                if( isset($netObj[2]) && ($netObj[2] == "destination") and ($netObj[3] == "static") )
                {
                    #get Real IP Address by name
                    $ObjectNetworkName = $netObj[4];
                    if( $ObjectNetworkName == "any" )
                    {
                    }
                    else
                    {

                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));

                        $tmp_address = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tmp_address !== null )
                        {
                            if( $print )
                                print "    * add destination: " . $tmp_address->name() . "\n";
                            $tmp_nat_rule->destination->addObject($tmp_address);
                        }
                        else
                        {
                            if( $print )
                                print "  X address object for source : " . $ObjectNetworkName . " not found\n";
                        }


                        if( $tmp_nat_rule->to->isAny() )
                        {
                            //todo bring in correct virtual router
                            print "NAT rule: " . $tmp_nat_rule->name() . " zone calculation for to\n";

                            if( $this->template->owner == null )
                            {
                                //$template class is PANConf
                                $tmp_nat_rule->zoneCalculation('to', "replace", "vr_vsys1");
                            }
                            else
                            {
                                //panorama template
                                $tmp_nat_rule->zoneCalculation('to', "replace", "vr_vsys1", $this->template->owner->name(), $this->sub->name());
                            }
                        }
                    }


                    $mappedIP = $netObj[5];
                    if( $mappedIP == $ObjectNetworkName )
                    {
                        # No Source NAT
                        $isdat = 0;
                    }
                    else
                    {
                        mwarning("4 source NAT - continue");

                        # Source NAT
                        $isdat = 1;
                        if( $mappedIP == "any" )
                        {
                        }
                        elseif( $mappedIP == "interface" )
                        {
                            $this->get_interfaceIP_for_zone_SNAT( $tmp_nat_rule, $op_zone_to, "0815");
                        }
                        else
                        {

                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));

                            $tmp_address = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $tmp_address !== null )
                            {
                                if( $print )
                                    print "    * add DNAT: " . $ObjectNetworkName . "\n";

                                $tmp_nat_rule->setDNAT($tmp_address);
                            }
                            else
                            {
                                if( $print )
                                    print "  X address object for source : " . $ObjectNetworkName . " not found. problem 4340\n";
                            }
                        }
                    }
                    unset($netObj[2]);
                    unset($netObj[3]);
                    unset($netObj[4]);
                    unset($netObj[5]);
                    $netObj = array_values($netObj);
                }

                if( isset($netObj[2]) && $netObj[2] == "service" )
                {
                    #Destination Port Real
                    $real_port = $netObj[3];


                    $tmp_service = $this->sub->serviceStore->find($real_port);
                    if( $tmp_service != null )
                    {
                        if( $print )
                            print " * add service " . $tmp_service->name() . "\n";
                        $tmp_nat_rule->setService($tmp_service);
                    }
                    else
                    {
                        if( $real_port == "any" )
                        {
                        }
                        else
                        {
                            $add_log2 = 'Unknown Service [' . $real_port . '] on Nat Rule ID [' . $nat_lid . ']; Using first service port. Change it from the GUI';
                            $op_service_lid = 1;
                            $op_service_table = 'services';
                            $checkit = 1;
                        }
                    }

                    #Destination Port Mapped
                    $dst_port = $netObj[4];
                    if( $dst_port == $real_port )
                    {
                        # No translate Port
                        $tp_dat_port = "";
                    }
                    else
                    {
                        $tmp_service = $this->sub->serviceStore->find($dst_port);
                        if( $tmp_service != null )
                        {
                            $tmp_dnat_object = $tmp_nat_rule->dnathost;
                            $tp_dat_port = $tmp_service->getDestPort();

                            if( $tmp_dnat_object !== null )
                            {
                                if( $print )
                                    print " * add DNAT service " . $tmp_service->name() . "\n";
                                $tmp_nat_rule->setDNAT($tmp_dnat_object, $tp_dat_port);
                            }
                            else
                            {
                                mwarning(" dnathost is null - no DNAT service port set");
                                #derr();
                            }

                        }
                        else
                        {
                            if( $dst_port == "any" )
                            {
                            }
                            else
                            {
                                $add_log2 = "Unknown Service [" . $dst_port . "] on Nat Rule ID [" . $nat_lid . "] Add the right Port from the GUI";
                                $tp_dat_port = "";
                            }
                        }
                    }
                }

                if( $op_zone_to == "any" )
                {
                    $op_zone_to = "";
                    $checkit = 1;
                    $add_log2 = 'Nat RuleID [' . $nat_lid . '] has destination Zone as ANY. Fix it before to finish. Check it manually';
                }
                if( ($from == "any") and ($op_zone_to != "") )
                {
                    $from = $op_zone_to;
                    $AddFrom[] = "('$vsys','$source','$from','$nat_lid')";
                }
                else
                {
                    $AddFrom[] = "('$vsys','$source','$from','$nat_lid')";
                }

                if( ($from != "any") and ($from != "") )
                {
                    $tmp_zone = $this->template_vsys->zoneStore->find($from);
                    if( $tmp_zone !== null )
                    {
                        if( $print )
                            print "    * add from: " . $tmp_zone->name() . "\n";
                        $tmp_nat_rule->from->addZone($tmp_zone);
                    }
                }

                if( ($op_zone_to != "any") and ($op_zone_to != "") )
                {
                    $tmp_zone = $this->template_vsys->zoneStore->find($op_zone_to);
                    if( $tmp_zone !== null )
                    {
                        if( $print )
                            print "    * add to: " . $tmp_zone->name() . "\n";
                        $tmp_nat_rule->to->addZone($tmp_zone);
                    }
                }

                $addNatRule[] = "('$bidirectional','$description','$source','$vsys','$nat_lid','$position','$disabled','$op_zone_to','$ruleName','$checkit','$tp_sat_address_type','$tp_sat_interface','$tp_sat_ipaddress','$tp_sat_type','$isdat','$tp_dat_address_lid','$tp_dat_address_table','$tp_dat_port','$op_service_lid','$op_service_table')";


                $nat_lid++;
                $position++;
                $ruleName = "";
                $op_zone_to = "";
                $op_service_lid = "";
                $op_service_table = "";
                $tp_dat_port = "";
                $tp_dat_address_lid = "";
                $tp_dat_address_table = "";
                $checkit = 0;
                $tp_sat_interface = "";
                $tp_dat_address_lid = "";
                $tp_dat_address_table = "";
                $op_service_table = "";
                $op_service_lid = "";
                $tp_sat_address_type = "";
                $tp_sat_ipaddress = "";
                $tp_sat_type = "";
                $tp_dat_port = "";
                $isdat = "";
                $from = "";

            }

        }
    }

    function get_objects_nat()
    {
        global $debug;
        global $print;
        global $nat_lid;

        $isObjectNetwork = 0;


        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        $source = "";

        //tmp defined because of old part
        $position = 1;
        $dst_cidr = "0";


        $tp_dat_address_lid = null;
        $dst_lid = null;

        //define later on
        $op_service_lid = null;

        //    $my = fopen("/tmp/nat_cisco.txt","a");
        $ObjectNetworkName = "";
        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);
            if( $isObjectNetwork == 1 )
            {
                if( preg_match("/^nat /i", $names_line) )
                {
                    #nat (services,outside) static x.x.x.x service tcp smtp smtp (DNAT)
                    #nat (services,outside) static y.y.y.y (SNAT static)
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $zones = str_replace("(", '', $netObj[1]);
                    $zones = str_replace(")", '', $zones);
                    $zonesAll = explode(",", $zones);
                    $from = $zonesAll[0];
                    $to = $zonesAll[1];
                    $checkit = 0;
                    if( $to == "any" )
                    {
                        $to = "";
                        $checkit = 1;
                        $add_log2 = 'Nat RuleID [' . $nat_lid . '] has destination Zone as ANY. Fix it before to finish; Check it manually';
                    }

                    //Todo: validate if this exclusion is correct
                    if( (preg_match("/ after-object /", $names_line)) or (preg_match("/ after-auto /", $names_line)) )
                    {
                        $isObjectNetwork = 0;
                        continue;
                    }

                    $ruleName = "AutoNat $ObjectNetworkName";

                    $tmp_nat_rule = $this->sub->natRules->find($ruleName);
                    if( $tmp_nat_rule === null )
                    {
                        if( $print )
                            print "\n* create NAT rule: '" . $ruleName . "'\n";
                        $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName);
                    }
                    else
                    {
                        mwarning("NAT rule: " . $ruleName . " - already available");
                    }

                    //Todo this should set it for each NAT rule, validate that it not any
                    $this->set_from_to_zone("from", $tmp_nat_rule, $from);
                    $this->set_from_to_zone("to", $tmp_nat_rule, $to);

                    $Status = 0; #Rule Enabled by default
                    if( (isset($netObj[4])) and (isset($netObj[4]) and $netObj[4] == "net-to-net") )
                    {
                    }
                    //                if (isset($netObj[4]) AND ( $netObj[4] != "dns") AND ($netObj[4] != "route-lookup") AND $netObj[4] != "no-proxy-arp") {


                    $RealIPCIDR = "";

                    if( ($netObj[2] == "static") and (isset($netObj[4]) and $netObj[4] == "service") )
                    {
                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));

                        $tmp_address_tp_dat_address_lid = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tmp_address_tp_dat_address_lid !== null )
                        {
                            $RealIP = $tmp_address_tp_dat_address_lid->getNetworkValue();
                            $RealIPCIDR = $tmp_address_tp_dat_address_lid->getNetworkMask();

                            if( $tmp_address_tp_dat_address_lid->isAddress() )
                                $tp_dat_address_table = "address";
                            else
                                $tp_dat_address_table = "address_groups_id";

                            if( $print )
                            {
                                print "   * destination nat set: " . $tmp_address_tp_dat_address_lid->name() . "\n";
                            }
                            $tmp_nat_rule->setDNAT($tmp_address_tp_dat_address_lid);
                        }
                        else
                        {
                            if( $print )
                                print "  X address object for source : " . $ObjectNetworkName . " not found. problem #not defined XYZ\n";
                        }


                        $protocol = $netObj[5];
                        $src_port = trim($netObj[7]);
                        #$addFROM[] = "('$source','$vsys','$nat_lid','$to')";

                        //specific for static NAT from outside
                        #$this->set_from_to_zone("from", $tmp_nat_rule, $to);
                        #$this->set_from_to_zone("to", $tmp_nat_rule, $to);

                        if( is_numeric($src_port) )
                        {
                            $tmp_name = $protocol . "-" . $src_port;
                            $tmp_service_op_service_lid = $this->sub->serviceStore->find($tmp_name);
                            if( $tmp_service_op_service_lid === null )
                            {
                                if( $print )
                                    print " * create service " . $tmp_name . "\n";
                                $tmp_service_op_service_lid = $this->sub->serviceStore->newService($tmp_name, $protocol, $src_port);
                            }

                            if( $tmp_service_op_service_lid !== null )
                            {
                                if( $print )
                                {
                                    print "   * add service: " . $tmp_service_op_service_lid->name() . "\n";
                                }
                                $tmp_nat_rule->setService($tmp_service_op_service_lid);
                            }
                        }
                        else
                        {
                            $tmp_name = $src_port;
                            $tmp_service_op_service_lid = $this->sub->serviceStore->find($tmp_name);
                            if( $tmp_service_op_service_lid === null )
                            {
                                if( $print )
                                    print " * create service " . $tmp_name . "\n";
                                $tmp_service_op_service_lid = $this->sub->serviceStore->newService($tmp_name, $protocol, "6500");
                                $tmp_service_op_service_lid->set_node_attribute('error', 'Unknown Service [' . $src_port . '] with Protocol [' . $protocol . '] on Nat Rule ID [' . $nat_lid . '] - Using 6500 port. Change it from the GUI');
                            }

                            if( $tmp_service_op_service_lid !== null )
                            {
                                if( $print )
                                {
                                    print "   * add service: " . $tmp_service_op_service_lid->name() . "\n";
                                }
                                $tmp_nat_rule->setService($tmp_service_op_service_lid);
                            }
                        }


                        #Destination Port
                        $dst_port = $netObj[6];
                        if( !is_numeric($dst_port) )
                        {
                            $tmp_name = $dst_port;
                            $tmp_service_tp_dat_port = $this->sub->serviceStore->find($tmp_name);
                            if( $tmp_service_tp_dat_port === null )
                            {
                                $tmp_name = $protocol . "-" . $dst_port;
                                $tmp_service_tp_dat_port = $this->sub->serviceStore->find($tmp_name);
                                if( $tmp_service_tp_dat_port === null )
                                {
                                    if( $print )
                                        print " * create service " . $tmp_name . "\n";
                                    $tmp_service_tp_dat_port = $this->sub->serviceStore->newService($tmp_name, $protocol, "6500");
                                    $tmp_service_tp_dat_port->set_node_attribute('error', 'Unknown Service [' . $src_port . '] with Protocol [' . $protocol . '] on Nat Rule ID [' . $nat_lid . '] - Using 6500 port. Change it from the GUI');
                                }
                            }

                            $tp_dat_port = $tmp_service_tp_dat_port->getDestPort();

                            if( $tmp_address_tp_dat_address_lid !== null )
                            {
                                if( $print )
                                    print "   * add nat service: " . $tmp_service_tp_dat_port->name() . "\n";
                                $tmp_nat_rule->setDNAT($tmp_address_tp_dat_address_lid, $tp_dat_port);
                            }
                        }
                        else
                        {
                            $tmp_name = $protocol . "-" . $dst_port;
                            $tmp_service_tp_dat_port = $this->sub->serviceStore->find($tmp_name);
                            if( $tmp_service_tp_dat_port === null )
                            {
                                if( $print )
                                    print " * create service " . $tmp_name . "\n";
                                $tmp_service_tp_dat_port = $this->sub->serviceStore->newService($tmp_name, $protocol, $dst_port);
                            }
                            $tp_dat_port = $tmp_service_tp_dat_port->getDestPort();

                            if( $tmp_address_tp_dat_address_lid !== null )
                            {
                                if( $print )
                                    print "   * add nat service: " . $tmp_service_tp_dat_port->name() . "\n";
                                $tmp_nat_rule->setDNAT($tmp_address_tp_dat_address_lid, $tp_dat_port);
                            }

                        }


                        mwarning("continue here regard IP check");

                        # Mapped IP check if its IP or Object
                        $mappedIP = $netObj[3];
                        if( $mappedIP == "interface" )
                        {
                            print_r( $netObj );
                            mwarning("static nat interface found");
                            $this->get_interfaceIP_for_zone_SNAT( $tmp_nat_rule, $to, "static-service 0815", $nat_type = "dynamic-ip-and-port");
                        }
                        elseif( $this->ip_version($mappedIP) == "noip" )
                        {
                            //This is a label

                            // Let's check if this label has been provided with a CIDR
                            $mappedCIDR = $RealIPCIDR;  //By default, we consider the CIDR should be the one from the source


                            //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid is static <object> service\n"); fclose($my);

                            $tmp_name = $mappedIP;
                            $tmp_address_dst_lid = $this->sub->addressStore->find($tmp_name);
                            if( $tmp_address_dst_lid !== null )
                            {
                                $dst_cidr = $tmp_address_dst_lid->getNetworkMask();
                                if( $dst_cidr == 0 && $RealIPCIDR == 32 )
                                {
                                    $tmp_address_dst_lid->setValue($tmp_address_dst_lid->getNetworkValue() . "/32");
                                }
                                elseif( $dst_cidr == 32 && $mappedCIDR == 32 )
                                {
                                    //We can use this label, that will become a valid object
                                    //                                    echo "NAT for $ObjectNetworkName. Label $mappedIP found with cidr 32. Nothing to do\n";
                                }
                                else
                                {
                                    //We need to look for an object with the name-cidr and if it doesnt exist, clone the label and make it an object
                                    //                                    echo "NAT for $ObjectNetworkName. Label $mappedIP not found with cidr 32 or 0.";
                                    $newname = $mappedIP . "-" . $mappedCIDR;

                                    $ObjectNetworkName = $this->truncate_names($this->normalizeNames($newname));
                                    $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                                    if( $tmp_address_dst_lid !== null )
                                    {
                                        $dst_table = "address";
                                    }
                                    else
                                    {

                                        $tmp_address_dst_lid = $this->sub->addressStore->newAddress($ObjectNetworkName, 'ip-netmask', $mappedIP);
                                        //                                        echo "We create $newname\n";
                                        //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr,vtype) VALUES ('$source','$vsys','$newname','$newname','$mappedIP','ip-netmask','$mappedCIDR','object')");
                                        //$dst_lid = $projectdb->insert_id;
                                        $dst_table = "address";
                                        $dst_cidr = "32";
                                        $dst_type = 'ip-netmask';
                                    }
                                }
                            }
                        }

                        else
                        {
                            //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid is static <IP> service\n"); fclose($my);

                            if( $RealIPCIDR == "32" )
                            {
                                $type = "ip-netmask";
                                $prefix = "H";
                                $newname = $prefix . "-" . $mappedIP;
                            }
                            else
                            {
                                $type = "ip-netmask";
                                $prefix = "N";
                                $newname = $prefix . "-" . $mappedIP . "-" . $RealIPCIDR;

                                $mappedIP = $mappedIP."/".$RealIPCIDR;
                            }

                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($newname));

                            $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);

                            if( $tmp_address_dst_lid === null )
                            {
                                if( $print )
                                    print "   * create address object: " . $ObjectNetworkName . " with value: " . $mappedIP . "\n";

                                $tmp_address_dst_lid = $this->sub->addressStore->newAddress($ObjectNetworkName, "ip-netmask", $mappedIP);
                            }

                            if( $tmp_address_dst_lid !== null )
                            {
                                if( $print )
                                    print "    * add destination: " . $ObjectNetworkName . "\n";
                                $tmp_nat_rule->destination->addObject($tmp_address_dst_lid);
                            }
                        }
                    }


                    elseif( $netObj[2] == "static" )
                    {
                        //                    fwrite($my, $names_line."\n");
                        #get Real IP Address by name
                        $dst_ip = "";

                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));

                        $tmp_address_tp_dat_address_lid = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tmp_address_tp_dat_address_lid !== null )
                        {
                            $RealIP = $tmp_address_tp_dat_address_lid->getNetworkValue();
                            $RealIPCIDR = $tmp_address_tp_dat_address_lid->getNetworkMask();

                            if( $tmp_address_tp_dat_address_lid->isAddress() )
                                $tp_dat_address_table = "address";
                            else
                                $tp_dat_address_table = "address_groups_id";
                        }
                        else
                        {
                            if( $print )
                                print "  X address object for source : " . $ObjectNetworkName . " not found. problem #not defined XYZ\n";
                        }


                        $mappedIP = $netObj[3];
                        //                    fwrite($my, "  ".$mappedIP.": ".$this->ip_version($mappedIP)."\n");
                        if( $this->ip_version($mappedIP) == "noip" )
                        {
                            //This is a label or an object
                            //                        fwrite($my, "  $mappedIP is an label or an object\n");
                            // Let's check if this label has been provided with a CIDR
                            $mappedCIDR = $RealIPCIDR;  //By default, we consider the CIDR should be the one from the source

                            /*
                            //Todo: SWASCHKUT 20191118 something OLd???? not working, two arguments required
                            if(isset($netObj[4]))
                            {
                                if( cidr_match( $netObj[4] ) )
                                    $mappedCIDR =  $this->mask2cidrv4($netObj[4]);
                            }
                            */

                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));

                            $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $tmp_address_dst_lid !== null )
                            {
                                $dst_ip = $tmp_address_dst_lid->getNetworkValue();
                                $dst_cidr = $tmp_address_dst_lid->getNetworkMask();

                                if( $tmp_address_dst_lid->isAddress() )
                                    $dst_table = "address";
                                else
                                    $dst_table = "address_groups_id";
                            }
                            else
                            {
                                $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));

                                $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                                if( $tmp_address_dst_lid !== null )
                                {
                                    $dst_ip = $tmp_address_dst_lid->getNetworkValue();
                                    $dst_cidr = $tmp_address_dst_lid->getNetworkMask();

                                    if( $tmp_address_dst_lid->isAddress() )
                                        $dst_table = "address";
                                    else
                                        $dst_table = "address_groups_id";


                                    if( $dst_cidr == 0 && $RealIPCIDR == 32 )
                                    {
                                        $tmp_address_dst_lid->setValue($dst_ip . "/32");
                                    }
                                    elseif( $dst_cidr == 32 && $mappedCIDR == 32 )
                                    {
                                        //We can use this label, that will become a valid object
                                        //                                echo "NAT for $ObjectNetworkName. Label $mappedIP found with cidr 32. Nothing to do\n";
                                    }
                                    else
                                    {
                                        //We need to look for an object with the name-cidr and if it doesnt exist, clone the label and make it an object
                                        //                                echo "NAT for $ObjectNetworkName. Label $mappedIP not found with cidr 32 or 0.";
                                        $newname = $mappedIP . "-" . $mappedCIDR;
                                        $mappedIP = $mappedIP."/".$mappedCIDR;

                                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($newname));

                                        $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                                        if( $tmp_address_dst_lid !== null )
                                        {
                                            $dst_ip = $tmp_address_dst_lid->getNetworkValue();
                                            $dst_cidr = $tmp_address_dst_lid->getNetworkMask();
                                        }
                                        else
                                        {
                                            if( $print )
                                                print "   * create address object: " . $newname . " with value: " . $mappedIP . "\n";

                                            $tmp_address_dst_lid = $this->sub->addressStore->find($newname);
                                            if( $tmp_address_dst_lid === null )
                                                $tmp_address_dst_lid = $this->sub->addressStore->newAddress($newname, "ip-netmask", $mappedIP);

                                            $dst_table = "address";
                                            $dst_cidr = "32";
                                        }

                                    }
                                }
                            }
                        }
                        else
                        {
                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));

                            $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $tmp_address_dst_lid !== null )
                            {
                                $dst_ip = $tmp_address_dst_lid->getNetworkValue();
                                $dst_cidr = $tmp_address_dst_lid->getNetworkMask();
                            }
                            else
                            {
                                if( ($RealIPCIDR == "32") or ($RealIPCIDR == "") )
                                {
                                    $type = "ip-netmask";
                                    $prefix = "H";
                                    $newname = "$prefix-$mappedIP";
                                    $RealIPCIDR2 = "32";
                                }
                                else
                                {
                                    $type = "ip-netmask";
                                    $prefix = "N";
                                    $newname = "$prefix-$mappedIP-$RealIPCIDR";
                                    $RealIPCIDR2 = $RealIPCIDR;

                                    $mappedIP = $mappedIP."/".$RealIPCIDR;
                                }

                                if( $print )
                                    print "   * create address object: " . $newname . " with value: " . $mappedIP . "\n";

                                $tmp_address_dst_lid = $this->sub->addressStore->find($newname);
                                if( $tmp_address_dst_lid === null )
                                    $tmp_address_dst_lid = $this->sub->addressStore->newAddress($newname, "ip-netmask", $mappedIP);


                                $dst_ip = $tmp_address_dst_lid->getNetworkValue();
                                $dst_cidr = $tmp_address_dst_lid->getNetworkMask();
                                $dst_type = 'ip-netmask';


                                if( $tmp_address_dst_lid->isAddress() )
                                    $dst_table = "address";
                                else
                                    $dst_table = "address_groups_id";
                            }
                        }


                        #Warning regarding DNS translation
                        if( isset($netObj[4]) == "dns" )
                        {
                            $msg = 'has an unsupported feature. Object was [' . $ObjectNetworkName . ']. DNS translation. Check it manually';
                            $tmp_nat_rule->set_node_attribute("error", 'Nat RuleID [' . $nat_lid . '] ' . $msg);
                            mwarning($msg, null, FALSE);
                        }

                        # Fix cidr=0 change by 32
                        if( $dst_cidr == 0 )
                        {
                            $dst_cidr = 32;
                        }

                        if( ($tp_dat_address_table == "address") and ($dst_table == "address") )
                        {
                            if( ($tmp_address_tp_dat_address_lid === $tmp_address_dst_lid) or ($RealIP === $dst_ip) )
                            {
                                #Identity Nat
                                $ruleName = "IdentityNat $ObjectNetworkName";

                                if( $print )
                                    print "   * change Rule Name to: " . $ruleName . "\n";
                                $tmp_nat_rule->setName($ruleName);

                                #$this->set_from_to_zone("from", $tmp_nat_rule, $from);
                                #$this->set_from_to_zone("to", $tmp_nat_rule, $to);

                                $nat_type = 'none';
                                $this->set_source_nat($tmp_nat_rule, $tmp_address_tp_dat_address_lid, $tmp_address_dst_lid, $nat_type);
                            }
                            else
                            {
                                if( $RealIPCIDR == $dst_cidr )
                                {
                                    $nat_type = "static-ip";
                                    //problem with static-ip rewrite delete everything
                                    //Todo: SWASCHKUT 20191118 - validate if not already fixed 20200120
                                    //$nat_type = "dynamic-ip-and-port";

                                    #$this->set_from_to_zone("from", $tmp_nat_rule, $from);
                                    #$this->set_from_to_zone("to", $tmp_nat_rule, $to);

                                    $this->set_source_nat($tmp_nat_rule, $tmp_address_tp_dat_address_lid, $tmp_address_dst_lid, $nat_type);


                                    if( $print )
                                        print "    * set BiDir yes\n";
                                    $tmp_nat_rule->setBiDirectional(TRUE);
                                }
                                elseif( $dst_cidr == "32" )
                                {
                                    $nat_type = "dynamic-ip-and-port";

                                    #$this->set_from_to_zone("from", $tmp_nat_rule, $from);
                                    #$this->set_from_to_zone("to", $tmp_nat_rule, $to);

                                    $this->set_source_nat($tmp_nat_rule, $tmp_address_tp_dat_address_lid, $tmp_address_dst_lid, $nat_type);
                                }
                                else
                                {
                                    mwarning('Nat RuleID [' . $nat_lid . '] was not migrated. [' . $names_line . ']. The original rule seems malformed and could not be migrated. Please review the use of original rule with the firewall administrator. Send an email with this line to fwmigrate@paloaltonetworks.com if this NAT should have been migrated.');
                                }
                            }
                        }
                        else
                        {
                            #Cant assing a group as a source OP with static-ip
                            mwarning('Nat RuleID [' . $nat_lid . '] is trying to apply a group to the translated packet. [' . $names_line . '] - Rule not imported.');
                        }


                    }
                    elseif( ($netObj[2] == "dynamic") and ($netObj[3] == "interface") )
                    {
                        #nat (inside,outside) dynamic interface

                        $this->get_interfaceIP_for_zone_SNAT( $tmp_nat_rule, $to, "not defined", "dynamic-ip-and-port");

                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));

                        $tmp_address_tp_dat_address_lid = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tmp_address_tp_dat_address_lid !== null )
                        {
                            if( $print )
                                print "    * add source: " . $ObjectNetworkName . "\n";
                            $tmp_nat_rule->source->addObject($tmp_address_tp_dat_address_lid);
                        }
                        else
                        {
                            if( $print )
                                print "  X address object for source : " . $ObjectNetworkName . " not found. problem #not defined XYZ\n";
                        }
                    }
                    elseif( ($netObj[2] == "dynamic") and ($netObj[3] == "pat-pool") )
                    {

                        #nat (inside,outside) dynamic pat-pool IPv4_POOL
                        #get Real IP Address by name

                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));
                        $tmp_address_tp_dat_address_lid = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tmp_address_tp_dat_address_lid !== null )
                        {
                            $RealIP = $tmp_address_tp_dat_address_lid->getNetworkValue();
                            $RealIPCIDR = $tmp_address_tp_dat_address_lid->getNetworkMask();

                            $tp_dat_address_table = "address";
                        }



                        $mappedIP = $netObj[3];
                        if( $this->ip_version($mappedIP) == "noip" )
                        {
                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));
                            $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $tmp_address_dst_lid !== null )
                            {
                                $dst_ip = $tmp_address_dst_lid->getNetworkValue();
                                $dst_cidr = $tmp_address_dst_lid->getNetworkMask();

                                if( $tmp_address_dst_lid->isAddress() )
                                    $dst_table = "address";
                                else
                                    $dst_table = "address_groups_id";
                            }

                        }
                        else
                        {
                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));
                            $tmp_address_dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $tmp_address_dst_lid !== null )
                            {
                                if( $tmp_address_dst_lid->isAddress() )
                                {
                                    $dst_ip = $tmp_address_dst_lid->getNetworkValue();
                                    $dst_cidr = $tmp_address_dst_lid->getNetworkMask();
                                    $dst_table = "address";
                                }
                                else
                                    $dst_table = "address_groups_id";

                            }
                            else
                            {
                                if( ($RealIPCIDR == "32") or ($RealIPCIDR == "") )
                                {
                                    $type = "ip-netmask";
                                    $prefix = "H";
                                    $newname = "$prefix." - ".$mappedIP";
                                    $RealIPCIDR2 = "32";
                                }
                                else
                                {
                                    $type = "ip-netmask";
                                    $prefix = "N";
                                    $newname = "$prefix-$mappedIP-$RealIPCIDR";
                                    $RealIPCIDR2 = $RealIPCIDR;
                                }

                                $new_name = $name_int = $this->truncate_names($this->normalizeNames($newname));
                                $tmp_address_snat_int = $this->sub->addressStore->find($new_name);
                                if( $tmp_address_snat_int === null )
                                    $tmp_address_snat_int = $this->sub->addressStore->newAddress($new_name, 'ip-netmask', $mappedIP . "/" . $RealIPCIDR2);
                            }
                        }


                        #$this->set_from_to_zone("from", $tmp_nat_rule, $from);
                        #$this->set_from_to_zone("to", $tmp_nat_rule, $to);

                        if( $tmp_address_tp_dat_address_lid !== null )
                        {
                            if( $print )
                                print "    * add source: " . $tmp_address_tp_dat_address_lid->name() . "\n";
                            $tmp_nat_rule->source->addObject($tmp_address_tp_dat_address_lid);
                        }

                        if( $tmp_address_dst_lid !== null )
                        {
                            if( $print )
                                print "    * add sourceNAT: " . $tmp_address_dst_lid->name() . "\n";
                            $tmp_nat_rule->snathosts->addObject($tmp_address_dst_lid);
                        }

                        if( $print )
                            print "    * snat type: 'dynamic-ip-and-port'\n";
                        $tmp_nat_rule->changeSourceNAT('dynamic-ip-and-port');
                    }
                    elseif( $netObj[2] == "dynamic" )
                    {
                        #nat (inside,outside) dynamic 10.2.2.2
                        #get Real IP Address by name

                        $ObjectNetworkName = $this->truncate_names($this->normalizeNames($ObjectNetworkName));
                        $tp_dat_address_lid = $this->sub->addressStore->find($ObjectNetworkName);
                        if( $tp_dat_address_lid !== null )
                        {
                            if( $tp_dat_address_lid->isAddress() )
                            {
                                $RealIP = $tp_dat_address_lid->getNetworkValue();
                                $RealIPCIDR = $tp_dat_address_lid->getNetworkMask();
                                $tp_dat_address_table = "address";
                            }
                            else
                                $tp_dat_address_table = "address_groups_id";
                        }


                        $mappedIP = $netObj[3];
                        if( $this->ip_version($mappedIP) == "noip" )
                        {
                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($mappedIP));
                            $nat_type = "dynamic-ip";
                            $dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $dst_lid !== null )
                            {
                                if( $dst_lid->isAddress() )
                                {
                                    $dst_ip = $dst_lid->getNetworkValue();
                                    $dst_cidr = $dst_lid->getNetworkMask();
                                    $dst_table = "address";
                                }
                                else
                                    $dst_table = "address_groups_id";
                            }
                        }
                        else
                        {
                            $nat_type = "dynamic-ip-and-port";

                            $type = "ip-netmask";
                            $prefix = "H";
                            $newname = "$prefix-$mappedIP";
                            $RealIPCIDR2 = "32";

                            $ObjectNetworkName = $this->truncate_names($this->normalizeNames($newname));
                            $dst_lid = $this->sub->addressStore->find($ObjectNetworkName);
                            if( $dst_lid !== null )
                            {
                                if( $dst_lid->isAddress() )
                                {
                                    $dst_ip = $dst_lid->getNetworkValue();
                                    $dst_cidr = $dst_lid->getNetworkMask();
                                    $dst_table = "address";
                                }
                                else
                                    $dst_table = "address_groups_id";
                            }
                            else
                            {
                                $dst_lid = $this->sub->addressStore->newAddress($ObjectNetworkName, 'ip-netmask', $mappedIP . "/" . $RealIPCIDR2);
                            }
                        }


                        if( isset($netObj[4]) == "interface" )
                        {
                            #Fallback Activation
                            $tp_fallback_type = "interface-address";
                            $tp_sat_interface_fallback = $to;
                            $tp_sat_ipaddress_fallback = "";
                            mwarning('Nat RuleID [' . $nat_lid . '] is using Interface Address for Fallback. [' . $names_line . ']. No action Required.');
                        }
                        else
                        {
                            $tp_fallback_type = "None";
                            $tp_sat_interface_fallback = "";
                            $tp_sat_ipaddress_fallback = "";
                        }


                        #$this->set_from_to_zone("from", $tmp_nat_rule, $from);
                        #$this->set_from_to_zone("to", $tmp_nat_rule, $to);


                        if( $print )
                            print "    * add source: " . $tp_dat_address_lid->name() . "\n";
                        $tmp_nat_rule->source->addObject($tp_dat_address_lid);

                        if( $print )
                            print "    * add sourceNAT: " . $dst_lid->name() . "\n";
                        $tmp_nat_rule->snathosts->addObject($dst_lid);


                        if( $print )
                            print "    * snat type: '" . $nat_type . "'\n";
                        $tmp_nat_rule->changeSourceNAT($nat_type);
                    }


                    $nat_lid++;
                    $position++;
                    $ruleName = "";
                    $to = "";
                    $op_service_lid = "";
                    $op_service_table = "";
                    $tp_dat_port = "";
                    $tp_dat_address_lid = "";
                    $tp_dat_address_table = "";
                    $checkit = 0;
                }
            }

            if( preg_match("/^object network/i", $names_line) )
            {
                $isObjectNetwork = 1;
                $names = explode(" ", $names_line);
                $ObjectNetworkName = rtrim($names[2]);
                $ObjectNetworkNamePan = $this->truncate_names($this->normalizeNames($ObjectNetworkName));
            }

            if( preg_match("/^access-list/", $names_line) )
            {
                $isObjectNetwork = 0;
            }
        }
    }



    /*function fix_destination_nat_old($config_path, $source, $vsys) {
        global $projectdb;
        $this->data = file($config_path);

        #First Calculate the Zones
        $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
        if ($getVR->num_rows == 1) {
            $VRData = $getVR->fetch_assoc();
            $vr = $VRData['id'];
            $from_or_to = "from";
            $rule_or_nat = "rule";

            $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

            $projectdb->query("DELETE FROM security_rules_from WHERE source='$source' AND vsys='$vsys';");
            $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE source='$source' AND vsys='$vsys';");
            if ($getSRC->num_rows > 0) {
                while ($getSRCData = $getSRC->fetch_assoc()) {
                    $member_lid = $getSRCData['member_lid'];
                    $table_name = $getSRCData['table_name'];
                    $rule_lid = $getSRCData['rule_lid'];

                    // Mirar si para esta regla es negated o no
                    $getIsNegated = $projectdb->query("SELECT negate_source, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                    if ($getIsNegated->num_rows > 0) {
                        $getINData = $getIsNegated->fetch_assoc();
                        $negate_source = $getINData['negate_source'];
                        $devicegroup = $getINData['devicegroup'];
                    }

                    $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_source';");
                    if ($getZones->num_rows == 1){
                        $getZonesData = $getZones->fetch_assoc();
                        $zones_sql = $getZonesData['zone'];
                        $zones = explode(",", $zones_sql);
                    }
                    else{
                        $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_source','$vsys', '$source');");
                    }
                    foreach ($zones as $zone) {
                        $getZone = $projectdb->query("SELECT id FROM security_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid' AND vsys = '$vsys' AND source = '$source';");
                        if ($getZone->num_rows == 0) {
                            $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) "
                                . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                        }
                    }
                }
            }

            $from_or_to = "to";
            $rule_or_nat = "rule";
            $projectdb->query("DELETE FROM security_rules_to WHERE source='$source' AND vsys='$vsys';");
            $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE source='$source' AND vsys='$vsys';");
            if ($getSRC->num_rows > 0) {
                while ($getSRCData = $getSRC->fetch_assoc()) {
                    $member_lid = $getSRCData['member_lid'];
                    $table_name = $getSRCData['table_name'];
                    $rule_lid = $getSRCData['rule_lid'];

                    // Mirar si para esta regla es negated o no
                    $getIsNegated = $projectdb->query("SELECT negate_destination, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                    if ($getIsNegated->num_rows > 0) {
                        $getINData = $getIsNegated->fetch_assoc();
                        $negate_destination = $getINData['negate_destination'];
                        $devicegroup = $getINData['devicegroup'];
                    }

                    $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_destination';");
                    if ($getZones->num_rows == 1){
                        $getZonesData = $getZones->fetch_assoc();
                        $zones_sql = $getZonesData['zone'];
                        $zones = explode(",", $zones_sql);
                    }else{
                        $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination);
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_destination','$vsys', '$source');");
                    }
                    foreach ($zones as $zone) {
                        $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid' AND vsys = '$vsys' AND source = '$source';");
                        if ($getZone->num_rows == 0) {
                            $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                                . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                        }
                    }
                }
            }
        }

        # Fix based in access-group direction

        foreach ($this->data as $line => $names_line) {
            if (preg_match("/^access-group /i", $names_line)) {
                $addfrom = array();
                $rules = array();
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $tagname = $this->truncate_tags($netObj[1]);
                $zoneFrom = $netObj[4];
                $direction = $netObj[2];
                if ($direction == "in") {
                    $table_direction = "security_rules_from";
                    $whatzone = "FROM";
                } elseif ($direction == "out") {
                    $table_direction = "security_rules_to";
                    $whatzone = "TO";
                }
                $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='$tagname';");
                if ($getTag->num_rows == 1) {
                    $getTagData = $getTag->fetch_assoc();
                    $member_lid = $getTagData['id'];
                    $table_name = "tag";
                    $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_tag WHERE source='$source' AND vsys='$vsys' AND member_lid='$member_lid' AND table_name='$table_name';");
                    if ($getRules->num_rows > 0) {
                        while ($getRulesData = $getRules->fetch_assoc()) {
                            $rule_lid = $getRulesData['rule_lid'];
                            $addfrom[] = "('$source','$vsys','$zoneFrom','$rule_lid','default')";
                            $rules[] = $getRulesData['rule_lid'];
                        }
                    }
                    if (count($rules) > 0) {
                        $projectdb->query("DELETE FROM $table_direction WHERE rule_lid IN (" . implode(",", $rules) . ") AND source='$source' AND vsys='$vsys';");
                        unset($rules);
                    }
                    if (count($addfrom) > 0) {
                        $projectdb->query("INSERT INTO $table_direction (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $addfrom) . ";");
                        unset($addfrom);
                        add_log2('warning', 'Auto Zone Assign', 'Forcing Zone [' . $whatzone . '] to [' . $zoneFrom . '] on access-list [' . $tagname . '] based on access-group direction [' . $direction . ']', $source, 'No Action Required', '', '', '');
                    }

                    //Calculate the Zone
                }
            }
        }


        $getDNAT = $projectdb->query("SELECT id,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE is_dat=1 AND source='$source' AND vsys='$vsys' AND tp_dat_address_table!='';");
        if ($getDNAT->num_rows > 0) {

            while ($this->data = $getDNAT->fetch_assoc()) {
                $zoneFROM = "";
                $rule_lid = $this->data['id'];
                $tp_dat_address_lid = $this->data['tp_dat_address_lid'];
                $tp_dat_address_table = $this->data['tp_dat_address_table'];
                #get Address name
                $getname = $projectdb->query("SELECT name FROM $tp_dat_address_table WHERE id='$tp_dat_address_lid'");
                $getnameData = $getname->fetch_assoc();
                $datName = $getnameData['name'];
                #Get Source Zone from Nat Rule
                $getFROM = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$rule_lid' AND source='$source' AND vsys='$vsys';");
                if ($getFROM->num_rows == 1) {
                    $this->dataFrom = $getFROM->fetch_assoc();
                    $zoneFROM = $this->dataFrom['name'];
                }
                #Get Destination from OP
                $getDST = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$rule_lid' AND source='$source' AND vsys='$vsys';");
                if ($getDST->num_rows == 1) {
                    $this->data2 = $getDST->fetch_assoc();
                    $dst_member_lid = $this->data2['member_lid'];
                    $dst_table_name = $this->data2['table_name'];
                    #get Address name
                    $getname = $projectdb->query("SELECT name FROM $dst_table_name WHERE id='$dst_member_lid'");
                    $getnameData = $getname->fetch_assoc();
                    $dstName = $getnameData['name'];
                }

                $getSecurityDST = $projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE source='$source' AND vsys='$vsys' AND "
                    . "member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                if ($getSecurityDST->num_rows > 0) {
                    while ($this->data4 = $getSecurityDST->fetch_assoc()) {
                        $security_rule = $this->data4['rule_lid'];
                        #Check the ZONE, has to be the same from ZoneFROM
                        $getSecurityZone = $projectdb->query("SELECT name FROM security_rules_from WHERE source='$source' AND vsys='$vsys' AND rule_lid='$security_rule';");
                        if ($getSecurityZone->num_rows == 1) {
                            $this->data5 = $getSecurityZone->fetch_assoc();
                            $security_from = $this->data5['name'];
                            if ($security_from == $zoneFROM) {
                                $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                            }
                        } else {
                            #No source ZONE maybe is ANY :-)
                            $exist = $projectdb->query("SELECT id FROM security_rules_dst "
                                . "WHERE source='$source' AND vsys='$vsys' AND "
                                . "table_name='$tp_dat_address_table' ANd member_lid='$tp_dat_address_lid' AND rule_lid='$security_rule';");
                            if ($exist->num_rows == 1) {
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                            } else {
                                //Crec que aixo sobra
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                $projectdb->query("INSERT INTO security_rules_dst (rule_lid,member_lid,table_name,source,vsys) VALUES ('$security_rule','$dst_member_lid','$dst_table_name','$source','$vsys');");
                            }
                            add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                        }
                    }
                }
            }
        }

        //Bidirectional
        // Cisco provides Security rules with post-NAT destination. Security policies need to be fixed to fit their pre-NAT destionations
        // for the comming back connection in the bidirectional NAT
        $query = "SELECT id, op_zone_to FROM nat_rules WHERE tp_sat_bidirectional=1 AND tp_sat_type='static-ip' AND source='$source' AND vsys='$vsys';";
        $getStaticBidirectNAT = $projectdb->query($query);
        if ($getStaticBidirectNAT->num_rows > 0) {
            while ($this->data = $getStaticBidirectNAT->fetch_assoc()) {
                $zoneB = $this->data['op_zone_to'];
                $rule_lid = $this->data['id'];
                //     Dir1 -  Original:  (ZoneA) A1 - (ZoneB) B1           Translate to:      (ZoneC) PostNatA1 - (ZoneB) B1
                //     Dir2 -  Original:  (ZoneB) B1 - (ZoneC) PostNatA1    Translate to:            (ZoneB)  B1 - (ZoneA) A1   (DNAT)

                //Get pre-NAT source. This will be the comming back post-NAT Destination
                $query = "SELECT member_lid, table_name FROM nat_rules_src WHERE source='$source' AND vsys='$vsys' AND rule_lid=$rule_lid;";
                $A1 = $projectdb->query($query);
                if ($A1->num_rows ==1){
                    $this->data2 = $A1->fetch_assoc();
                    $A1_member_lid = $this->data2['member_lid'];
                    $A1_table_name = $this->data2['table_name'];
                    #get Address name
                    $getname = $projectdb->query("SELECT name_ext FROM $A1_table_name WHERE id='$A1_member_lid'");
                    $getnameData = $getname->fetch_assoc();
                    $A1_name = $getnameData['name_ext'];
                }

                $A1_list = array();
                if($A1_table_name=='address'){
                    $query="SELECT a.id as id FROM address a "
                        . "INNER JOIN address b WHERE a.ipaddress=b.ipaddress and a.CIDR=b.cidr AND b.id='$A1_member_lid';";
                    $getA1_list = $projectdb->query($query);
                    if($getA1_list->num_rows > 0){
                        while($this->data_addr = $getA1_list->fetch_assoc()){
                            $A1_list[] = $this->data_addr['id'];
                        }
                    }
                }

                //Get pre-NAT destination. This will be the comming back Source
                $query = "SELECT member_lid, table_name FROM nat_rules_dst WHERE source='$source' AND vsys='$vsys' AND rule_lid=$rule_lid;";
                $B1 = $projectdb->query($query);
                if ($B1->num_rows ==1){
                    $this->data2 = $B1->fetch_assoc();
                    $B1_member_lid = $this->data2['member_lid'];
                    $B1_table_name = $this->data2['table_name'];
                }

                //Get post-NAT source. This will be the comming back pre-NAT Destination
                $query = "SELECT member_lid, table_name FROM nat_rules_translated_address WHERE source='$source' AND vsys='$vsys' AND rule_lid=$rule_lid;";
                $PostNatA1 = $projectdb->query($query);
                if ($PostNatA1->num_rows ==1){
                    $this->data2 = $PostNatA1->fetch_assoc();
                    $PostNatA1_member_lid = $this->data2['member_lid'];
                    $PostNatA1_table_name = $this->data2['table_name'];
                    #get Address name
                    $getname = $projectdb->query("SELECT name_ext FROM $PostNatA1_table_name WHERE id='$PostNatA1_member_lid'");
                    $getnameData = $getname->fetch_assoc();
                    $PostNatA1_name = $getnameData['name_ext'];
                }

                if(count($A1_list)>0){
                    $query = "SELECT rule_lid FROM security_rules_dst "
                        . "WHERE source='$source' AND vsys='$vsys' AND member_lid in ('".implode(",",$A1_list)."') AND table_name='address';";
                    $getSecurityDST = $projectdb->query($query);
                }
                else{
                    $getSecurityDST = $projectdb->query("SELECT rule_lid FROM security_rules_dst "
                        . "WHERE source='$source' AND vsys='$vsys' AND member_lid='$A1_member_lid' AND table_name='$A1_table_name';");
                }

                if ($getSecurityDST->num_rows > 0) {
                    while ($this->data4 = $getSecurityDST->fetch_assoc()) {
                        $security_rule = $this->data4['rule_lid'];
                        #Check the ZONE, has to be the same from ZoneFROM
                        $getSecurityZone = $projectdb->query("SELECT name FROM security_rules_from WHERE source='$source' AND vsys='$vsys' AND rule_lid='$security_rule';");
                        if ($getSecurityZone->num_rows == 1) {
                            $this->data5 = $getSecurityZone->fetch_assoc();
                            $security_from = $this->data5['name'];
                            if ($security_from == $zoneB) {
                                $query = "UPDATE security_rules_dst SET table_name='$PostNatA1_table_name', member_lid='$PostNatA1_member_lid' "
                                    . "WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND "
                                    . "member_lid in ('".implode(",",$A1_list)."') AND table_name='$A1_table_name';";
                                $projectdb->query($query);
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                add_log2('warning', 'Fixing Destination Nats', 'Security RuleID ['.$security_rule.'] has been modified by Nat RuleID ['.$rule_lid.'], Replaced Destination Address old[' . $A1_name . '] by new[' . $PostNatA1_name . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                            }else{

                            }
                        } else {

                            #No source ZONE maybe is ANY :-)
                            $exist = $projectdb->query("SELECT id FROM security_rules_dst "
                                . "WHERE source='$source' AND vsys='$vsys' AND "
                                . "table_name='$A1_table_name' ANd member_lid='$A1_member_lid' AND rule_lid='$security_rule';");
                            if ($exist->num_rows == 1) {
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                $projectdb->query("UPDATE security_rules_dst SET table_name='$PostNatA1_table_name', member_lid='$PostNatA1_member_lid' "
                                    . "WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND "
                                    . "member_lid in ('".implode(",",$A1_list)."') AND table_name='$A1_table_name';");
                            }
                            add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $A1_name . '] by new[' . $PostNatA1_name . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                        }
                    }
                }
            }
        }

        # Change rules TO where static-ip nat has the TP -source equal as a security rule destination
        $getStatic=$projectdb->query("SELECT id FROM nat_rules WHERE tp_sat_type='static-ip' AND source='$source' AND vsys='$vsys';");
        if ($getStatic->num_rows>0){
            while ($getStaticData=$getStatic->fetch_assoc()){
                $nat_lid=$getStaticData['id'];
                #get FROM Zone
                $getZone=$projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$nat_lid' LIMIT 1;");
                if ($getZone->num_rows==1){
                    $getZoneData=$getZone->fetch_assoc();
                    $zoneFrom=$getZoneData['name'];
                    $getTP=$projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$nat_lid' LIMIT 1;");
                    if ($getTP->num_rows==1){
                        while ($getTPData=$getTP->fetch_assoc()){
                            $ori_member_lid=$getTPData['member_lid'];
                            $ori_table_name=$getTPData['table_name'];
                            #Exact object Match, future check if its inside
                            $getRulesDst=$projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE source='$source' AND vsys='$vsys' AND member_lid='$ori_member_lid' AND table_name='$ori_table_name';");
                            if ($getRulesDst->num_rows>0){
                                while ($getRulesDstData=$getRulesDst->fetch_assoc()){
                                    $rule_lid=$getRulesDstData['rule_lid'];
                                    $getZoneDst=$projectdb->query("SELECT id,name FROM security_rules_to WHERE rule_lid='$rule_lid' LIMIT 1;");
                                    if ($getZoneDst->num_rows==1){
                                        $getZoneDstData=$getZoneDst->fetch_assoc();
                                        $zoneid=$getZoneDstData['id'];
                                        $zonename=$getZoneDstData['name'];
                                        if ($zoneFrom==$zonename){}
                                        else{
                                            $projectdb->query("UPDATE security_rules_to SET name='$zoneFrom' WHERE id='$zoneid';");
                                            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$rule_lid';");
                                            add_log2('warning', 'Fixing Destination Zones', 'Security RuleID [' . $rule_lid . '] has been modified by Nat RuleID [' . $nat_lid . '], Replaced Destination Zone old[' . $zonename . '] by new[' . $zoneFrom . ']', $source, 'Check it manually', 'rules', $rule_lid, 'security_rules');
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }
        }
    }*/


    //Todo: used in natpre83 - not yet supported
    function read_access_list( $source, $accesslist, $ARRAY, $NatID, $OPFrom, $op_zone_to, $nat_lid, $position, $type, $translated_address, $translated_port)
    {

        global $debug;
        global $print;

        $vsys = $this->template_vsys->name();

        $dst = "";
        $src = "";
        $srv = "";

        global $projectdb;
        foreach( $this->data as $line => $names_line )
        {
            $names_line = rtrim($names_line);
            if( (preg_match("/^access-list $accesslist /", $names_line)) and (preg_match("/ permit /", $names_line)) )
            {
                $isSourcePort = FALSE;
                $split = explode(" ", $names_line);
                # Cleaning
                $remove = array("access-list", $accesslist, "extended", "permit");
                foreach( $remove as $kremove => $del_val )
                {
                    if( ($key = array_search($del_val, $split)) !== FALSE )
                    {
                        unset($split[$key]);
                    }
                }
                # Init vars
                $protocol = "";
                $split = array_values($split);

                $start = 0;
                if( ($split[$start] == "ip") or ($split[$start] == "tcp") or ($split[$start] == "udp") )
                {
                    $protocol = $split[$start];
                    unset($split[$start]);
                }
                else
                {
                    $add_log2 = 'Access-list [' . $accesslist . '] with protocol other than TCP or UDP Or IP [' . $split[$start] . ']. fix it manually.';
                    mwarning($add_log2);
                    continue;
                }
                $split = array_values($split);

                # GET SOURCES
                if( $split[$start] == "host" )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "host\n");                fclose($my);
                    $src = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object-group" )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "object-group\n");                fclose($my);
                    $src = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object" )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "object\n");                fclose($my);
                    $src = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( ($split[$start] == "any") or ($split[$start] == "0.0.0.0") or ($split[$start] == "0") )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "any\n");                fclose($my);
                    $start++;
                }
                else
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "noip\n");                fclose($my);
                    # NAME or IP ADDRESS
                    if( $this->ip_version($split[$start]) == "noip" )
                    {
                        # NAME
                        $src = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                    else
                    {
                        # IP ADDRESS
                        $src = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                }

                # GET DESTINATIONS
                if( $split[$start] == "host" )
                {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object-group" )
                {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object" )
                {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( ($split[$start] == "any") or ($split[$start] == "0.0.0.0") or ($split[$start] == "0") )
                {
                    $start++;
                }
                elseif( ($split[$start] == "eq") or ($split[$start] == "lt") or ($split[$start] == "gt") or ($split[$start] == "neq") or ($split[$start] == "range") )
                {
                    print "IS SOURCE SERVICE:" . $split[$start + 1] . "\n";
                    $isSourcePort = TRUE;
                    if( $split[$start] == "range" )
                    {
                        $start = $start + 3;
                    }
                    else
                    {
                        $start = $start + 2;
                    }
                }
                else
                {
                    # NAME or IP ADDRESS
                    if( $this->ip_version($split[$start]) == "noip" )
                    {
                        # NAME
                        $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                    else
                    {
                        # IP ADDRESS
                        $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                }

                # If was source port then has to come the destination
                if( $isSourcePort == TRUE )
                {
                    # Get Destination
                    if( $split[$start] == "host" )
                    {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    }
                    elseif( $split[$start] == "object-group" )
                    {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    }
                    elseif( $split[$start] == "object" )
                    {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    }
                    elseif( ($split[$start] == "any") or ($split[$start] == "0.0.0.0") or ($split[$start] == "0") )
                    {
                        $start++;
                    }
                    else
                    {
                        # NAME or IP ADDRESS
                        if( $this->ip_version($split[$start]) == "noip" )
                        {
                            # NAME
                            $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        }
                        else
                        {
                            # IP ADDRESS
                            $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        }
                    }
                    $dst = "";
                }

                # Get SERVICES
                if( isset($split[$start]) )
                {
                    if( ($split[$start] == "eq") or ($split[$start] == "lt") or ($split[$start] == "gt") or ($split[$start] == "neq") or ($split[$start] == "range") )
                    {
                        $srv = $split[$start + 1];
                        if( is_numeric($srv) )
                        {
                            if( $split[$start] == "eq" )
                            {
                                //$srv = $srv;


                                /*
                                $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                if ($getSRV->num_rows == 1) {
                                    $getSRVData = $getSRV->fetch_assoc();
                                    $srv = $getSRVData['name_ext'];
                                } else {
                                    $name = $protocol . "_" . $srv;
                                    $name_int = $this->truncate_names($this->normalizeNames($name));
                                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                    $srv = $name;
                                }
                                */

                            }
                            elseif( $split[$start] == "lt" )
                            {
                                $srv = "0-" . $srv;


                                /*
                                $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                if ($getSRV->num_rows == 1) {
                                    $getSRVData = $getSRV->fetch_assoc();
                                    $srv = $getSRVData['name_ext'];
                                } else {
                                    $name = $protocol . "_" . $srv;
                                    $name_int = $this->truncate_names($this->normalizeNames($name));
                                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                    $srv = $name;
                                }
                                */
                            }
                            elseif( $split[$start] == "gt" )
                            {

                                $srv = $srv . "-65535";


                                /*
                                $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                if ($getSRV->num_rows == 1) {
                                    $getSRVData = $getSRV->fetch_assoc();
                                    $srv = $getSRVData['name_ext'];
                                } else {
                                    $name = $protocol . "_" . $srv;
                                    $name_int = $this->truncate_names($this->normalizeNames($name));
                                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                    $srv = $name;
                                }
    */
                            }
                            elseif( $split[$start] == "neq" )
                            {

                                $srv1 = intval($srv) - 1;
                                $srv2 = intval($srv) + 1;
                                $srv = "0-" . $srv1 . "," . $srv2 . "-65535";

                                /*
                                $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                if ($getSRV->num_rows == 1) {
                                    $getSRVData = $getSRV->fetch_assoc();
                                    $srv = $getSRVData['name_ext'];
                                } else {
                                    $name = $protocol . "_" . $srv;
                                    $name_int = $this->truncate_names($this->normalizeNames($name));
                                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                    $srv = $name;
                                }
                                */
                            }
                            elseif( $split[$start] == "range" )
                            {

                                $first = $split[$start + 1];
                                $second = $split[$start + 2];
                                if( !is_numeric($second) )
                                {
                                    $tmp_service_second = $this->sub->serviceStore->find($second);
                                    if( $tmp_service_second != null )
                                    {
                                        $second = $tmp_service_second->getDestPort();
                                    }
                                    else
                                    {
                                        mwarning("no dest Port for service object: " . $second . " - dport of first value used: " . $first);
                                        $second = $first;
                                    }

                                    /*
                                    $getSecond = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name='$second' LIMIT 1;");
                                    if ($getSecond->num_rows == 1) {
                                        $getSecondData = $getSecond->fetch_assoc();
                                        $second = $getSecondData['dport'];
                                    }
                                    */
                                }
                                $srv = $first . "-" . $second;


                                /*
                                $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                if ($getSRV->num_rows == 1) {
                                    $getSRVData = $getSRV->fetch_assoc();
                                    $srv = $getSRVData['name_ext'];
                                } else {
                                    $name = $protocol . "_" . $srv;
                                    $name_int = $this->truncate_names($this->normalizeNames($name));
                                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                    $srv = $name;
                                }
                                */
                            }


                            //DONE: SWASCHKUT general usage, moved out from all upper cases
                            $name = $protocol . "-" . $srv;
                            $name_int = $this->truncate_names($this->normalizeNames($name));

                            $tmp_service = $this->sub->serviceStore->find($name_int);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print "  * create service: " . $name_int . "\n";
                                $tmp_service = $this->sub->serviceStore->newService($name_int, $protocol, $srv);
                            }
                            if( $tmp_service !== null )
                            {
                                $srv = $tmp_service->name();
                            }


                        }
                        else
                        {
                        }
                    }
                    elseif( $split[$start] == "object-group" )
                    {
                        $srv = $split[$start + 1];
                    }
                }


                //diff to read_access_list2 start here
                $NONAT1["natid"] = $NatID;
                $NONAT1["nat_lid"] = $nat_lid;
                $NONAT1["access-list"] = $names_line;
                if( $NatID == "" )
                {
                    $NONAT1["name"] = "Rule " . $nat_lid;
                }
                elseif( $NatID > 0 )
                {
                    $NONAT1["name"] = "Rule " . $nat_lid . " Nat ID " . $NatID;
                }
                else
                {
                    $NONAT1["name"] = "Rule " . $nat_lid . " Identity Nat";
                }

                $NONAT1["from"] = $OPFrom;
                $NONAT1["op_zone_to"] = $op_zone_to;
                $NONAT1["position"] = $position;
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "IdentityNat $NatID: $src\n"); fclose($my);
                $NONAT1["source"] = isset($src) ? $src : '';
                $NONAT1["destination"] = $dst;
                $NONAT1["service"] = isset($srv) ? $srv : '';

                if( $type == "static" )
                {
                    $NONAT1["tp_sat_type"] = "static-ip";
                    $NONAT1["nat_rules_translated_address"] = trim($translated_address);
                    //$NONAT1["tp_sat_address_type"]="translated-addres";
                }
                elseif( $type == "pat" )
                {
                    if( $srv == "" )
                    {
                        $NONAT1["tp_sat_type"] = "static-ip";
                        $NONAT1["tp_sat_bidirectional"] = 1;
                    }
                    else
                    {
                        $NONAT1["is_dat"] = "1";

                        if( !is_numeric($translated_port) )
                        {
                            $tmp_service_second = $this->sub->serviceStore->find($translated_port);
                            if( $tmp_service_second != null )
                                $translated_port = $tmp_service_second->getDestPort();
                            else
                            {
                                mwarning("no dest Port for service object: " . $translated_port . " - tmp dport is used: " . $translated_port);
                                $translated_port = "65535";
                            }

                            /*
                            $getDport = $projectdb->query("SELECT dport FROM services WHERE BINARY name_ext='$translated_port' AND vsys='$vsys' AND source='$source' LIMIT 1;");
                            if ($getDport->num_rows == 1) {
                                $getDportData = $getDport->fetch_assoc();
                                $translated_port = $getDportData['dport'];
                            } else {
                                $add_log2 = 'Nat RuleID [' . $nat_lid . '] is using object [' . $translated_port . '] in service that is not defined in my Database. fix it manually.';
                                mwarning( $add_log2 );
                            }
                            */

                        }
                        $NONAT1["tp_dat_port"] = $translated_port;
                    }

                    $NONAT1["nat_rules_translated_address"] = trim($translated_address);
                }

                $ARRAY[] = $NONAT1;
                $NONAT1 = [];
                $nat_lid++;
                $position++;
                $src = "";
                $dst = "";
                $srv = "";
                $isSourcePort = FALSE;
            }
        }
        return array($ARRAY, $nat_lid, $position);
    }

    //Todo: used in natpred83 - not yet supported
    //SWASCHKUT - check diff between read_access_list2 and read_access_list, both are used - I assume duplicate code
    #function read_access_list2($vsys, $source, $accesslist, $this->data, $ARRAY, $NatID, $OPFrom, $op_zone_to, $nat_lid, $position, $type, $translated_address, $translated_port)
    function read_access_list2( $source, $accesslist, $ARRAY, $NatID, $OPFrom, $op_zone_to, $nat_lid, $position, $type, $translated_address, $translated_port)
    {

        global $debug;
        global $print;

        $vsys = $this->template_vsys->name();

        $dst = "";
        $src = "";
        $srv = "";

        global $projectdb;
        foreach( $this->data as $line => $names_line )
        {

            //this is exact code available on read_access_list function
            //how to reduce
            $names_line = rtrim($names_line);
            if( (preg_match("/^access-list $accesslist /", $names_line)) and (preg_match("/ permit /", $names_line)) )
            {
                $isSourcePort = FALSE;
                $split = explode(" ", $names_line);
                # Cleaning
                $remove = array("access-list", $accesslist, "extended", "permit");
                foreach( $remove as $kremove => $del_val )
                {
                    if( ($key = array_search($del_val, $split)) !== FALSE )
                    {
                        unset($split[$key]);
                    }
                }
                # Init vars
                $protocol = "";
                $split = array_values($split);

                $start = 0;
                if( ($split[$start] == "ip") or ($split[$start] == "tcp") or ($split[$start] == "udp") )
                {
                    $protocol = $split[$start];
                    unset($split[$start]);
                }
                else
                {
                    $add_log2 = 'Access-list [' . $accesslist . '] with protocol other than TCP or UDP Or IP [' . $split[$start] . ']. fix it manually.';
                    mwarning($add_log2);
                    continue;
                }
                $split = array_values($split);

                # GET SOURCES
                if( $split[$start] == "host" )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "host\n");                fclose($my);
                    $src = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object-group" )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "object-group\n");                fclose($my);
                    $src = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object" )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "object\n");                fclose($my);
                    $src = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( ($split[$start] == "any") or ($split[$start] == "0.0.0.0") or ($split[$start] == "0") )
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "any\n");                fclose($my);
                    $start++;
                }
                else
                {
                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "noip\n");                fclose($my);
                    # NAME or IP ADDRESS
                    if( $this->ip_version($split[$start]) == "noip" )
                    {
                        # NAME
                        $src = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                    else
                    {
                        # IP ADDRESS
                        $src = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                }

                # GET DESTINATIONS
                if( $split[$start] == "host" )
                {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object-group" )
                {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( $split[$start] == "object" )
                {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                }
                elseif( ($split[$start] == "any") or ($split[$start] == "0.0.0.0") or ($split[$start] == "0") )
                {
                    $start++;
                }
                elseif( ($split[$start] == "eq") or ($split[$start] == "lt") or ($split[$start] == "gt") or ($split[$start] == "neq") or ($split[$start] == "range") )
                {
                    print "IS SOURCE SERVICE:" . $split[$start + 1] . "\n";
                    $isSourcePort = TRUE;
                    if( $split[$start] == "range" )
                    {
                        $start = $start + 3;
                    }
                    else
                    {
                        $start = $start + 2;
                    }
                }
                else
                {
                    # NAME or IP ADDRESS
                    if( $this->ip_version($split[$start]) == "noip" )
                    {
                        # NAME
                        $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                    else
                    {
                        # IP ADDRESS
                        $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                }

                # If was source port then has to come the destination
                if( $isSourcePort == TRUE )
                {
                    # Get Destination
                    if( $split[$start] == "host" )
                    {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    }
                    elseif( $split[$start] == "object-group" )
                    {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    }
                    elseif( $split[$start] == "object" )
                    {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    }
                    elseif( ($split[$start] == "any") or ($split[$start] == "0.0.0.0") or ($split[$start] == "0") )
                    {
                        $start++;
                    }
                    else
                    {
                        # NAME or IP ADDRESS
                        if( $this->ip_version($split[$start]) == "noip" )
                        {
                            # NAME
                            $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        }
                        else
                        {
                            # IP ADDRESS
                            $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        }
                    }
                    $dst = "";
                }

                # Get SERVICES
                if( isset($split[$start]) )
                {
                    if( ($split[$start] == "eq") or ($split[$start] == "lt") or ($split[$start] == "gt") or ($split[$start] == "neq") or ($split[$start] == "range") )
                    {
                        $srv = $split[$start + 1];
                        if( is_numeric($srv) )
                        {
                            if( $split[$start] == "eq" )
                            {
                                //$srv = $srv;
                            }
                            elseif( $split[$start] == "lt" )
                            {
                                $srv = "0-" . $srv;
                            }
                            elseif( $split[$start] == "gt" )
                            {
                                $srv = $srv . "-65535";
                            }
                            elseif( $split[$start] == "neq" )
                            {
                                $srv1 = intval($srv) - 1;
                                $srv2 = intval($srv) + 1;
                                $srv = "0-" . $srv1 . "," . $srv2 . "-65535";
                            }
                            elseif( $split[$start] == "range" )
                            {
                                $first = $split[$start + 1];
                                $second = $split[$start + 2];
                                if( !is_numeric($second) )
                                {
                                    $tmp_service_second = $this->sub->serviceStore->find($second);
                                    if( $tmp_service_second != null )
                                        $second = $tmp_service_second->getDestPort();
                                    else
                                    {
                                        mwarning("no dest Port for service object: " . $second . " - dport of first value used: " . $first);
                                        $second = $first;
                                    }
                                }
                                $srv = $first . "-" . $second;
                            }

                            //DONE: SWASCHKUT general usage, moved out from all upper cases
                            $name = $protocol . "-" . $srv;
                            $name_int = $this->truncate_names($this->normalizeNames($name));

                            $tmp_service = $this->sub->serviceStore->find($name_int);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print "  * create service: " . $name_int . "\n";
                                $tmp_service = $this->sub->serviceStore->newService($name_int, $protocol, $srv);
                            }
                            if( $tmp_service !== null )
                                $srv = $tmp_service->name();
                        }
                        else
                        {
                        }
                    }
                    elseif( $split[$start] == "object-group" )
                    {
                        $srv = $split[$start + 1];
                    }
                }


                /*
                $names_line = rtrim($names_line);
                if ((preg_match("/^access-list $accesslist /", $names_line)) AND ( preg_match("/ permit /", $names_line))) {
                    $isSourcePort = false;
                    $split = explode(" ", $names_line);
                    # Cleaning
                    $remove = array("access-list", $accesslist, "extended", "permit");
                    foreach ($remove as $kremove => $del_val) {
                        if (($key = array_search($del_val, $split)) !== false) {
                            unset($split[$key]);
                        }
                    }
                    # Init vars
                    $protocol = "";
                    $split = array_values($split);

                    $start = 0;
                    if (($split[$start] == "ip") OR ( $split[$start] == "tcp") OR ( $split[$start] == "udp")) {
                        $protocol = $split[$start];
                        unset($split[$start]);
                    } else {
                        add_log2('error', 'Reading Nat Policies', 'Access-list [' . $accesslist . '] with protocol other than TCP or UDP Or IP [' . $split[$start] . '].', $source, 'fix it manually.', '', '', '');
                        continue;
                    }
                    $split = array_values($split);

                    # GET SOURCES
                    if ($split[$start] == "host") {
                        $src = $split[$start + 1];
                        $start = $start + 2;
                    } elseif ($split[$start] == "object-group") {
                        $src = $split[$start + 1];
                        $start = $start + 2;
                    } elseif ($split[$start] == "object") {
                        $src = $split[$start + 1];
                        $start = $start + 2;
                    } elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                        $start++;
                    } else {
                        # NAME or IP ADDRESS
                        if ($this->ip_version($split[$start]) == "noip") {
                            # NAME
                            $src = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        } else {
                            # IP ADDRESS
                            $src = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        }
                    }

                    # GET DESTINATIONS
                    if ($split[$start] == "host") {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    } elseif ($split[$start] == "object-group") {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    } elseif ($split[$start] == "object") {
                        $dst = $split[$start + 1];
                        $start = $start + 2;
                    } elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                        $start++;
                    } elseif (($split[$start] == "eq") OR ( $split[$start] == "lt") OR ( $split[$start] == "gt") OR ( $split[$start] == "neq") OR ( $split[$start] == "range")) {
                        print "IS SOURCE SERVICE:" . $split[$start + 1] . "\n";
                        $isSourcePort = true;
                        if ($split[$start] == "range") {
                            $start = $start + 3;
                        } else {
                            $start = $start + 2;
                        }
                    } else {
                        # NAME or IP ADDRESS
                        if ($this->ip_version($split[$start]) == "noip") {
                            # NAME
                            $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        } else {
                            # IP ADDRESS
                            $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                            $start = $start + 2;
                        }
                    }

                    # If was source port then has to come the destination
                    if ($isSourcePort == TRUE) {
                        # Get Destination
                        if ($split[$start] == "host") {
                            $dst = $split[$start + 1];
                            $start = $start + 2;
                        } elseif ($split[$start] == "object-group") {
                            $dst = $split[$start + 1];
                            $start = $start + 2;
                        } elseif ($split[$start] == "object") {
                            $dst = $split[$start + 1];
                            $start = $start + 2;
                        } elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                            $start++;
                        } else {
                            # NAME or IP ADDRESS
                            if ($this->ip_version($split[$start]) == "noip") {
                                # NAME
                                $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                                $start = $start + 2;
                            } else {
                                # IP ADDRESS
                                $dst = $split[$start] . "/" . $this->mask2cidrv4($split[$start + 1]);
                                $start = $start + 2;
                            }
                        }
                        $dst = "";
                    }

                    # Get SERVICES
                    if(isset($split[$start])) {
                        if (($split[$start] == "eq") OR ($split[$start] == "lt") OR ($split[$start] == "gt") OR ($split[$start] == "neq") OR ($split[$start] == "range")) {
                            $srv = $split[$start + 1];
                            if (is_numeric($srv)) {
                                if ($split[$start] == "eq") {
                                    $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                    if ($getSRV->num_rows == 1) {
                                        $getSRVData = $getSRV->fetch_assoc();
                                        $srv = $getSRVData['name_ext'];
                                    } else {
                                        $name = $protocol . "_" . $srv;
                                        $name_int = $this->truncate_names($this->normalizeNames($name));
                                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                        $srv = $name;
                                    }
                                } elseif ($split[$start] == "lt") {
                                    $srv = "0-" . $srv;
                                    $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                    if ($getSRV->num_rows == 1) {
                                        $getSRVData = $getSRV->fetch_assoc();
                                        $srv = $getSRVData['name_ext'];
                                    } else {
                                        $name = $protocol . "_" . $srv;
                                        $name_int = $this->truncate_names($this->normalizeNames($name));
                                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                        $srv = $name;
                                    }
                                } elseif ($split[$start] == "gt") {
                                    $srv = $srv . "-65535";
                                    $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                    if ($getSRV->num_rows == 1) {
                                        $getSRVData = $getSRV->fetch_assoc();
                                        $srv = $getSRVData['name_ext'];
                                    } else {
                                        $name = $protocol . "_" . $srv;
                                        $name_int = $this->truncate_names($this->normalizeNames($name));
                                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                        $srv = $name;
                                    }
                                } elseif ($split[$start] == "neq") {
                                    $srv1 = intval($srv) - 1;
                                    $srv2 = intval($srv) + 1;
                                    $srv = "0-" . $srv1 . "," . $srv2 . "-65535";
                                    $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                    if ($getSRV->num_rows == 1) {
                                        $getSRVData = $getSRV->fetch_assoc();
                                        $srv = $getSRVData['name_ext'];
                                    } else {
                                        $name = $protocol . "_" . $srv;
                                        $name_int = $this->truncate_names($this->normalizeNames($name));
                                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                        $srv = $name;
                                    }
                                } elseif ($split[$start] == "range") {
                                    $first = $split[$start + 1];
                                    $second = $split[$start + 2];
                                    if (!is_numeric($second)) {
                                        $getSecond = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$second' LIMIT 1;");
                                        if ($getSecond->num_rows == 1) {
                                            $getSecondData = $getSecond->fetch_assoc();
                                            $second = $getSecondData['dport'];
                                        }
                                    }
                                    $srv = $first . "-" . $second;
                                    $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                                    if ($getSRV->num_rows == 1) {
                                        $getSRVData = $getSRV->fetch_assoc();
                                        $srv = $getSRVData['name_ext'];
                                    } else {
                                        $name = $protocol . "_" . $srv;
                                        $name_int = $this->truncate_names($this->normalizeNames($name));
                                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                        $srv = $name;
                                    }
                                }
                            } else {

                            }
                        } elseif ($split[$start] == "object-group") {
                            $srv = $split[$start + 1];
                        }
                    }

                    */

                //Todo: SWASCHKUT starting from here it diffs from the read_access_list()
                # To be iterated by the elemets on globals
                if( $NatID !== 0 )
                {

                    /*
                     * Todo: SWASCHKUT
                    $getGlobals = $projectdb->query("SELECT * FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND natid='$NatID';");
                    $total_globals = $getGlobals->num_rows;
                    if ($total_globals > 0) {
                        while ($getGlobalsData = $getGlobals->fetch_assoc()) {
                            $zone = $getGlobalsData["zone"];
                            if ($getGlobalsData["type"] == "address") {
                                if ($getGlobalsData["cidr"] != "") {
                                    $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                                } else {
                                    $element_ipaddress[] = $getGlobalsData["address"];
                                }
                            } elseif ($getGlobalsData["type"] == "range") {
                                $element_ipaddress[] = $getGlobalsData["address"];
                            } elseif ($getGlobalsData["type"] == "hostname") {
                                $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                            } elseif ($getGlobalsData["type"] == "interface") {
                                $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                            }


                            if ($src != "") {
                                $NAT1["source"] = $src;
                            }
                            $NAT1["natid"] = $NatID;
                            $NAT1["nat_lid"] = $nat_lid;
                            $NAT1["access-list"] = $names_line;
                            $NAT1["tp_sat_type"] = "dynamic-ip-and-port";
                            $NAT1["name"] = "Rule " . $nat_lid . " Nat-ID " . $NatID;
                            $NAT1["from"] = $OPFrom;
                            $NAT1["op_zone_to"] = $zone;
                            $NAT1["position"] = $position;
                            $NAT1["destination"] = $dst;
                            $NAT1["service"] = isset($srv)?$srv:'';
                            $NAT1["tp_sat_address_type"] = "translated-addres";
                            $NAT1["nat_rules_translated_address"] = implode(",", $element_ipaddress);
                            $ARRAY[] = $NAT1;
                            $NAT1 = [];
                            $nat_lid++;
                            $position++;
                            $element_ipaddress = [];
                        }
                    }
                    */
                }

                $src = "";
                $dst = "";
                $srv = "";
                $isSourcePort = FALSE;

                /*
                  #  END
                  $NONAT1["natid"]=$NatID;
                  $NONAT1["nat_lid"]=$nat_lid;
                  $NONAT1["access-list"]=$names_line;
                  $NONAT1["name"]="Rule ".$nat_lid." Nat ID ".$NatID;
                  $NONAT1["from"]=$OPFrom;
                  $NONAT1["op_zone_to"]=$op_zone_to;
                  $NONAT1["position"]=$position;
                  $NONAT1["source"]=$src;
                  $NONAT1["destination"]=$dst;
                  $NONAT1["service"]=$srv;

                  if ($type=="dynamic"){
                  $NONAT1["tp_sat_type"]="dynamic-ip-and-port";
                  $NONAT1["nat_rules_translated_address"]=$translated_address;
                  $NONAT1["tp_sat_address_type"]="translated-addres";

                  }
                  $ARRAY[]=$NONAT1;
                  $NONAT1=[];
                  $nat_lid++;
                  $position++;
                 */
            }
        }
        return array($ARRAY, $nat_lid, $position);
    }


    # NATS
    //Todo: 20200120 - not yet supported
    #function natpre83($source, $vsys, $this->data, $template) {
    function natpre83()
    {
        global $debug;
        global $print;

        global $nat_lid;

        global $projectdb;

        mwarning("CISCO ASA config version pre8.3 are NOT supported related to NAT");

        return null;

        //Todo: SWASCHKUT - 20191018 truncate delete all entries in this TABLE
        #$projectdb->query("TRUNCATE TABLE cisco_nat_global;");
        $nat_lid = "";

        $position = "";
        $AddFrom = [];
        $AddSource = [];
        $AddTranslated = [];
        $AddDestination = [];
        $NAT = array();
        $NONAT = array();
        $NAT_static = array();
        $NAT_static_accesslist = array();
        $NAT_accesslist = array();


        $vsys = $this->template_vsys->name();
        $source = "";

        /*
        #Nat Stuff Related
        $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
        if ($getPosition->num_rows == 0) {
            $position = 1;
        }
        else {
            $ddata = $getPosition->fetch_assoc();
            $position = $ddata['t'] + 1;
        }
        if ($nat_lid == "") {
            $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
            if ($getlastlid->num_rows == 1) {
                $getLID1 = $getlastlid->fetch_assoc();
                $nat_lid = intval($getLID1['max']) + 1;
            } else {
                $nat_lid = 1;
            }
        }
    */

        foreach( $this->data as $line => $names_line )
        {
            $names_line = rtrim($names_line);

            #Regular Static NAT
            #static (inside,outside) 192.168.100.100 10.1.1.6 netmask 255.255.255.255
            if( preg_match_all("/^static \((.*),(.*)\)\s(tcp|udp)\s(.*)\s(.*)\saccess-list\s(.*)/", $names_line, $out) )
            {
                #static (dmz,outside) tcp NAT-SortidaSenseProxyPerSimetrica https access-list dmz_nat_static
                $from = $out[1][0];
                $to = $out[2][0];
                $NatID = "";


                $NAT_static_tmp = $this->read_access_list( $source, $out[6][0], $this->data, $NAT_static_accesslist, $NatID, $from, $to, $nat_lid, $position, "pat", $out[4][0], $out[5][0]);

                $NAT_static_accesslist = $NAT_static_tmp[0];
                $nat_lid = $NAT_static_tmp[1];
                $position = $NAT_static_tmp[2];
            }
            elseif( preg_match_all("/^static \((.*),(.*)\)\s(tcp|udp)\s(.*)\s(.*)\s(.*)\s(.*)\snetmask\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", $names_line, $out) )
            {
                $from = $out[1][0];
                $to = $out[2][0];
                $NatID = "";
                $netmask = $out[8][0];
                $static_cidr = $this->mask2cidrv4($netmask);
                $destination = $out[4][0];
                $destination_port = $out[5][0];
                $translated_address = $out[6][0];
                $translated_port = $out[7][0];
                $netmask = $out[8][0];
                $static_cidr = $this->mask2cidrv4($netmask);
                $protocol = $out[3][0];
                if( $static_cidr != "32" )
                {
                    $destination = $this->whatipaddress($out[4][0]) . "/" . $static_cidr;
                    $translated_address = $this->whatipaddress($out[6][0]) . "/" . $static_cidr;
                }

                if( is_numeric($destination_port) )
                {

                    $name = $protocol . "-" . $destination_port;
                    $name_int = $this->truncate_names($this->normalizeNames($name));

                    $tmp_service = $this->sub->serviceStore->find($name_int);
                    if( $tmp_service === null )
                    {
                        if( $print )
                            print "  * create service: " . $name_int . "\n";
                        $tmp_service = $this->sub->serviceStore->newService($name_int, $protocol, $destination_port);
                    }
                    if( $tmp_service !== null )
                    {
                        $destination_port = $tmp_service->name();
                    }
                    /*
                    $getDport = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$destination_port' AND protocol='$protocol' LIMIT 1;");
                    if ($getDport->num_rows == 1) {
                        $getDportData = $getDport->fetch_assoc();
                        $destination_port = $getDportData['name_ext'];
                    } else {
                        #
                        $name_int = $protocol . "_" . $destination_port;
                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name_int','$name_int','$destination_port','$protocol')");
                        $destination_port = $name_int;
                    }
                    */
                }

                if( !is_numeric($translated_port) )
                {
                    $name = $protocol . "-" . $destination_port;
                    $name_int = $this->truncate_names($this->normalizeNames($name));

                    $tmp_service = $this->sub->serviceStore->find($name_int);

                    if( $tmp_service !== null )
                    {
                        $translated_port = $tmp_service->getDestPort();
                    }
                    else
                    {
                        $add_log2 = 'Nat RuleID [' . $nat_lid . '] is using an Service [' . $translated_port . ' / ' . $protocol . '] that is not defined in my Database. fix it manually.';
                        mwarning($add_log2);
                    }

                    /*
                    $getDport = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$translated_port' LIMIT 1;");
                    if ($getDport->num_rows == 1) {
                        $getDportData = $getDport->fetch_assoc();
                        $translated_port = $getDportData['dport'];
                    } else {
                        #
                        $add_log2 = 'Nat RuleID [' . $nat_lid . '] is using an Service [' . $translated_port . ' / ' . $protocol . '] that is not defined in my Database. fix it manually.';
                    }
                    */
                }

                if( $translated_address == $destination )
                {
                    #NO NAT
                    $add_log2 = 'Nat rule will not be migrated because the source and translated address are the same. [' . $names_line . ']. fix it manually.';
                    mwarning($add_log2);
                }
                else
                {
                    $NAT1["destination"] = $destination;
                    $NAT1["nat_lid"] = $nat_lid;
                    $NAT1["access-list"] = $names_line;
                    $NAT1["tp_sat_type"] = "";
                    $NAT1["name"] = "Rule " . $nat_lid;
                    $NAT1["from"] = $to;
                    $NAT1["is_dat"] = 1;
                    $NAT1["op_zone_to"] = $to;
                    $NAT1["position"] = $position;
                    $NAT1["nat_rules_translated_address"] = $translated_address;
                    $NAT1["service"] = $destination_port;
                    $NAT1["tp_dat_port"] = $translated_port;
                    $NAT1["tp_sat_address_type"] = "";
                    $NAT_static[] = $NAT1;
                    $NAT1 = [];
                    $nat_lid++;
                    $position++;
                }

                //print $names_line."->";
                //print "FROM:$to SRC=ANY TO:$to DST=$destination port:$destination_port TP[ SRC=ANY DST=$translated_address Port:$translated_port ] MASK:$static_cidr\n";
            }
            elseif( preg_match_all("/^static \((.*),(.*)\)\s(.*)\s(.*)\snetmask\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", $names_line, $out) )
            {
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "NAT: ".$out[0][0]."\n"); fclose($my);
                $from = $out[1][0];
                $to = $out[2][0];
                $NatID = "";
                $netmask = $out[5][0];
                $static_cidr = $this->mask2cidrv4($netmask);
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   1-".$out[1][0].", 2-".$out[2][0].",3-".$out[3][0].", 4-".$out[4][0]." ,5-".$out[5][0]." and $static_cidr\n"); fclose($my);

                if( $static_cidr != "32" )
                {
                    $translated_src = $this->whatipaddress($out[3][0]) . "/" . $static_cidr;
                    $src = $this->whatipaddress($out[4][0]) . "/" . $static_cidr;
                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    NATting a network: $src -> $translated_src\n"); fclose($my);
                }
                else
                {
                    $translated_src = $this->whatipaddress($out[3][0]);
                    $src = $this->whatipaddress($out[4][0]);
                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    NATting a host:    $src -> $translated_src\n"); fclose($my);
                }

                if( $translated_src == $src )
                {
                    #NO NAT
                    $NAT1["source"] = $src;
                    $NAT1["nat_lid"] = $nat_lid;
                    $NAT1["access-list"] = $names_line;
                    $NAT1["tp_sat_type"] = "";
                    $NAT1["name"] = "Rule " . $nat_lid . " NoNat";
                    $NAT1["from"] = $from;
                    $NAT1["op_zone_to"] = $to;
                    $NAT1["position"] = $position;
                    $NAT_static[] = $NAT1;
                    $NAT1 = [];
                    $nat_lid++;
                    $position++;
                }
                else
                {

                    $NAT1["source"] = $src;
                    $NAT1["nat_lid"] = $nat_lid;
                    $NAT1["access-list"] = $names_line;
                    $NAT1["tp_sat_type"] = "static-ip";
                    $NAT1["name"] = "Rule " . $nat_lid;
                    $NAT1["from"] = $from;
                    $NAT1["op_zone_to"] = $to;
                    $NAT1["position"] = $position;
                    $NAT1["nat_rules_translated_address"] = $translated_src;
                    $NAT1["tp_sat_bidirectional"] = 1;
                    $NAT_static[] = $NAT1;
                    $NAT1 = [];
                    $nat_lid++;
                    $position++;
                }
            }
            elseif( preg_match_all("/^static \((.*),(.*)\)\s(.*)\saccess-list\s(.*)/", $names_line, $out) )
            {
                #static (outside,inside) 10.99.248.98  access-list a_policy_nat_xxx
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Access-list:  ".$out[0][0]."\n"); fclose($my);
                $from = $out[1][0];
                $to = $out[2][0];
                $NatID = "";
                $out[3][0] = trim($out[3][0]);
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$out[4][0].", ".$out[3][0]."-\n"); fclose($my);


                $NAT_static_tmp = $this->read_access_list( $source, $out[4][0], $this->data, $NAT_static_accesslist, $NatID, $from, $to, $nat_lid, $position, "static", $out[3][0], "");

                $NAT_static_accesslist = $NAT_static_tmp[0];
                $nat_lid = $NAT_static_tmp[1];
                $position = $NAT_static_tmp[2];
            }
            elseif( preg_match_all("/^global \((.*)\)\s(\d+)\s(.*)/", $names_line, $out) )
            {
                print "LINE: " . $names_line . "\n";
                # Dynamic
                # global (DMZ) 4 N_FAD_GENERICA netmask 255.255.0.0
                # global (WAN) 1 interface
                # nat (pweb_dmz) 0 access-list pweb_dmz_nat0_outbound
                $out2 = explode(" ", $out[3][0]);
                $global_zone = $out[1][0];
                $global_natid = $out[2][0];

                if( $out[3][0] == "interface" )
                {
                    $global[$out[2][0]][$out[1][0]][] = array("type" => "interface");
                    $type = "interface";

                    $tmp_zone = $this->template_vsys->zoneStore->find($global_zone);
                    if( $tmp_zone !== null )
                    {
                        $tmp_int = $tmp_zone->attachedInterfaces->interfaces();
                        if( count($tmp_int) > 0 )
                        {
                            $getIntIPaddress = $tmp_int[0]->getLayer3IPv4Addresses();
                            if( count($getIntIPaddress) == 0 )
                                $getIntIPaddress = $tmp_int[0]->getLayer3IPv6Addresses();

                            if( count($getIntIPaddress) > 0 )
                            {
                                $split_ipandcidr = explode("/", $getIntIPaddress[0]);
                                $interface_ipaddress = $split_ipandcidr[0];
                                $interface_cidr = $split_ipandcidr[1];
                            }
                        }
                    }
                    /*
                                    $getIntIP = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE template='$template' AND source='$source' AND zone='$global_zone' LIMIT 1;");
                                    if ($getIntIP->num_rows == 1)
                                    {
                                        $getIntIPData = $getIntIP->fetch_assoc();
                                        $getIntIPaddress = $getIntIPData['unitipaddress'];
                                        if ($getIntIPaddress != "") {
                                            $split_ipandcidr = explode("/", $getIntIPaddress);
                                            $interface_ipaddress = $split_ipandcidr[0];
                                            $interface_cidr = $split_ipandcidr[1];
                                        }
                                    }
                    */

                    //Todo: SWASCHKUT - what to do with this cisco_nat_global?????
                    print 'source=' . $source . ' AND vsys=' . $vsys . ' AND zone=' . $global_zone . ' AND natid=' . $global_natid . ' AND type=' . $type;
                    mwarning("interface found - implementation needed - global_zone: " . $global_zone);
                    /*
                    $already = $projectdb->query("SELECT id FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND zone='$global_zone' AND natid='$global_natid' AND type='$type';");
                    if ($already->num_rows == 0)
                    {
                        $projectdb->query("INSERT INTO cisco_nat_global (natid,zone,type,address,cidr,source,vsys) VALUES ('$global_natid','$global_zone','$type','$interface_ipaddress','$interface_cidr','$source','$vsys');");
                    }
    */

                }
                else
                {
                    $member_lid = "";
                    $table_name = "";
                    $hostname = "";
                    $hostname_ip = $out2[0];
                    if( ($this->ip_version($hostname_ip) == "v4") or ($this->ip_version($hostname_ip) == "v6") )
                    {
                        $type = "address";
                    }
                    elseif( preg_match("/-/", $hostname_ip) )
                    {
                        $type = "range";
                    }
                    else
                    {
                        $type = "hostname";
                        $hostname = $out2[0];

                        $tmp_address = $this->sub->addressStore->find($hostname_ip);
                        if( $tmp_address != null )
                        {
                            $hostname_ip = $tmp_address->value();
                        }

                        /*
                        $getMember = $projectdb->query("SELECT id,ipaddress FROM address WHERE BINARY name_ext='$hostname_ip' AND vsys='$vsys' AND source='$source' LIMIT 1;");
                        if ($getMember->num_rows == 1)
                        {
                            $getMemberData = $getMember->fetch_assoc();
                            $member_lid = $getMemberData['id'];
                            $table_name = "address";
                            $hostname_ip = $getMemberData['ipaddress'];
                        }
                        */
                    }

                    if( !isset($out2[2]) || $out2[2] == "" )
                    {
                        $out2[2] = "32";
                    }

                    $global[$out[2][0]] [$out[1][0]][] = array("type" => $type, "address" => $out2[0], "netmask" => $out2[2]);

                    print 'source=' . $source . ' AND vsys=' . $vsys . ' AND zone=' . $global_zone . ' AND natid=' . $global_natid . ' AND type=' . $type . ' AND address=' . $hostname_ip . ' AND netmask=' . $out2[2] . "\n";

                    print "ARRAY global:\n";
                    print_r($global);
                    mwarning("cisco_nat_global - general implementation needed");


                    /*
                    $already = $projectdb->query("SELECT id FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND zone='$global_zone' AND natid='$global_natid' AND type='$type' AND address='$hostname_ip' AND netmask='$out2[2]';");
                    if ($already->num_rows == 0) {
                        $getcidr = $this->mask2cidrv4($out2[2]);
                        if ($getcidr==0){$getcidr=32;}
                        $projectdb->query("INSERT INTO cisco_nat_global (natid,zone,type,address,netmask,cidr,source,vsys,member_lid,table_name,hostname) VALUES ('$global_natid','$global_zone','$type','$hostname_ip','$out2[2]','$getcidr','$source','$vsys','$member_lid','$table_name','$hostname');");
                    }
                    */
                }
            }
            elseif( (preg_match_all("/^nat \((.*)\)\s(\d+)\s(.*)\s(.*)\s(.*)/", $names_line, $out)) or (preg_match_all("/^nat \((.*)\)\s(\d+)\s(.*)\s(.*)/", $names_line, $out)) )
            {
                print "LINE: " . $names_line . "\n";

                # nat (LAN) 0 access-list LAN_nat0_outbound
                # nat (LAN) 1 172.50.0.0 255.255.255.0
                # nat (LAN) 1 REDILO 255.255.255.0
                # nat (DMZ) 4 192.168.1.0 255.255.255.0

                $nat_interface = FALSE;
                $OPFrom = $out[1][0];
                $NatID = $out[2][0];
                $src_addr = "";
                $allNatEntry = $out[0][0];
                if( $out[3][0] == "access-list" )
                {
                    if( $NatID == 0 )
                    {
                        # NONAT
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "is it here\n"); fclose($my);


                        $NONAT_tmp = $this->read_access_list( $source, $out[4][0], $this->data, $NONAT, $NatID, $OPFrom, "", $nat_lid, $position, "nonat", "", "");
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "was it here\n"); fclose($my);
                        $NONAT = $NONAT_tmp[0];
                        $nat_lid = $NONAT_tmp[1];
                        $position = $NONAT_tmp[2];
                    }
                    else
                    {
                        # Read Access-lists and pass the ip to nat the source or destination
                        //Todo SWASCHKUT
                        $static_tmp = $this->read_access_list2( $source, $out[4][0], $this->data, $NAT_accesslist, $NatID, $OPFrom, "", $nat_lid, $position, "dynamic", "", "");
                        $NAT_accesslist = $static_tmp[0];
                        $nat_lid = $static_tmp[1];
                        $position = $static_tmp[2];
                    }
                }
                else
                {
                    $src_mask = $out[4][0];
                    if( $src_mask == "255.255.255.255" )
                    {
                        $src_addr = $out[3][0];
                    }
                    else
                    {
                        $src_addr = $out[3][0];
                        if( $this->ip_version($src_addr) == "noip" )
                        {
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "HostRangeName\n"); fclose($my);
                            if( $out[4][0] != "" )
                            {
                                $addr_cidr = $this->mask2cidrv4($src_mask);
                                $src_addr = $src_addr . "/" . $addr_cidr;
                            }
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    $src_addr\n"); fclose($my);
                        }
                        elseif( $this->ip_version($src_addr) == "v4" )
                        {
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "HostRangeIP\n"); fclose($my);
                            $addr_cidr = $this->mask2cidrv4($src_mask);
                            $src_addr = $src_addr . "/" . $addr_cidr;
                            if( $src_addr == "0.0.0.0/0" )
                            {
                                $src_addr = "";
                            }
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    $src_addr\n"); fclose($my);
                        }
                        elseif( $this->ip_version($src_addr) == "v6" )
                        {
                            if( ($src_addr == "::/0") or ($src_addr == "0:0:0:0:0:0:0:0/0") )
                            {
                                $src_addr = "";
                            }
                        }
                    }
                    if( $NatID !== 0 )
                    {
                        $exists = FALSE;

                        print 'source=' . $source . ' AND vsys=' . $vsys . ' AND natid=' . $NatID;
                        mwarning("do someting if cisco_global_nat available");

                        /*Todo: SWASCHKUT
                        $getGlobals = $projectdb->query("SELECT * FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND natid='$NatID';");
                        $total_globals = $getGlobals->num_rows;
                        if ($total_globals > 0) {
                            while ($getGlobalsData = $getGlobals->fetch_assoc()) {
                                $zone = $getGlobalsData["zone"];
                                if ($getGlobalsData["type"] == "address") {
                                    if (($getGlobalsData["cidr"] != "") AND ($getGlobalsData["cidr"] != "0") AND ($getGlobalsData["cidr"] != "32")){
                                        $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                                    }
                                    else {
                                        $element_ipaddress[] = $getGlobalsData["address"];
                                    }
                                }
                                elseif ($getGlobalsData["type"] == "range") {
                                    $element_ipaddress[] = $getGlobalsData["address"];
                                }
                                elseif ($getGlobalsData["type"] == "hostname") {
                                    $hostname = $getGlobalsData["hostname"];
                                    $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                                }
                                elseif ($getGlobalsData["type"] == "interface") {
                                    $hostname = "";
                                    $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                                }

                                if (count($NAT) == 0) {
                                    if ($src_addr != "") {
                                        $NAT1["source"] = $src_addr;
                                    }
                                    $NAT1["natid"] = $NatID;
                                    $NAT1["nat_lid"] = $nat_lid;
                                    $NAT1["access-list"] = $names_line;
                                    $NAT1["tp_sat_type"] = "dynamic-ip-and-port";
                                    $NAT1["name"] = "Rule " . $nat_lid . " Nat-ID " . $NatID;
                                    $NAT1["from"] = $OPFrom;
                                    $NAT1["op_zone_to"] = $zone;
                                    $NAT1["position"] = $position;
                                    $NAT1["nat_rules_translated_address"] = implode(",", $element_ipaddress);
                                    $NAT[] = $NAT1;
                                    $NAT1 = [];
                                    $nat_lid++;
                                    $position++;
                                }
                                else {
                                    foreach ($NAT as $mykey => $myobjects) {
                                        if (($myobjects["natid"] == $NatID) AND ( $myobjects["op_zone_to"] == $zone) AND ( $myobjects["from"] == $OPFrom)) {
                                            $exists = true;
                                            break;
                                        }
                                    }
                                    if ($exists == TRUE) {
                                        $exists = false;
                                        $src_addr_last = $NAT[$mykey]["source"] . "," . $src_addr;
                                        $NAT[$mykey]["source"] = $src_addr_last;
                                    }
                                    else {
                                        if ($src_addr != "") {
                                            $NAT1["source"] = $src_addr;
                                        }
                                        $NAT1["natid"] = $NatID;
                                        $NAT1["nat_lid"] = $nat_lid;
                                        $NAT1["access-list"] = $names_line;
                                        $NAT1["tp_sat_type"] = "dynamic-ip-and-port";
                                        $NAT1["name"] = "Rule " . $nat_lid . " Nat-ID " . $NatID;
                                        $NAT1["from"] = $OPFrom;
                                        $NAT1["op_zone_to"] = $zone;
                                        $NAT1["position"] = $position;
                                        $NAT1["nat_rules_translated_address"] = implode(",", $element_ipaddress);
                                        $NAT[] = $NAT1;
                                        $NAT1 = [];
                                        $nat_lid++;
                                        $position++;
                                    }
                                }
                                $element_ipaddress = [];
                            }
                        }
                        */
                    }
                    else
                    {
                        # Identity NAT or NONAT
                        $exists = FALSE;
                        #Calc zone TO
                        //$getTO=$projectdb->query("SELECT ");

                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "$src_addr\n"); fclose($my);
                        if( count($NONAT) == 0 )
                        {
                            if( $src_addr != "" )
                            {
                                $NONAT1["source"] = $src_addr;
                            }
                            $NONAT1["natid"] = $NatID;
                            $NONAT1["nat_lid"] = $nat_lid;
                            $NONAT1["access-list"] = $names_line;

                            $NONAT1["name"] = "Rule " . $nat_lid . " Identity Nat";
                            $NONAT1["from"] = $OPFrom;
                            $NONAT1["op_zone_to"] = $zone;
                            $NONAT1["position"] = $position;
                            $NONAT[] = $NONAT1;
                            $NONAT1 = [];
                            $nat_lid++;
                            $position++;
                        }
                        else
                        {
                            foreach( $NONAT as $mykey => $myobjects )
                            {
                                if( ($myobjects["natid"] == $NatID) and ($myobjects["op_zone_to"] == $zone) and ($myobjects["from"] == $OPFrom) )
                                {
                                    $exists = TRUE;
                                    break;
                                }
                            }
                            if( $exists == TRUE )
                            {
                                $exists = FALSE;
                                $src_addr_last = $NONAT[$mykey]["source"] . "," . $src_addr;
                                $NONAT[$mykey]["source"] = $src_addr_last;
                            }
                            else
                            {
                                if( $src_addr != "" )
                                {
                                    $NONAT1["source"] = $src_addr;
                                }
                                $NONAT1["natid"] = $NatID;
                                $NONAT1["nat_lid"] = $nat_lid;
                                $NONAT1["access-list"] = $names_line;
                                $NONAT1["name"] = "Rule " . $nat_lid . " Identity Nat ";
                                $NONAT1["from"] = $OPFrom;
                                $NONAT1["op_zone_to"] = $zone;
                                $NONAT1["position"] = $position;
                                $NONAT[] = $NONAT1;
                                $NONAT1 = [];
                                $nat_lid++;
                                $position++;
                            }
                        }
                    }
                }
            }
        }

        if( count($NAT) > 0 )
        {
            $sorted = $this->array_orderby($NAT, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];
            foreach( $sorted as $key => $value )
            {
                $nat_lid = $value['nat_lid'];
                $nat_description = $value['access-list'];
                $tp_sat_type = $value['tp_sat_type'];
                $nat_position = $value['position'];
                $op_zone_to = $value['op_zone_to'];
                $nat_from = $value['from'];
                $nat_rulename = $value['name'];
                $translated_address = $value['nat_rules_translated_address'];

                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   $nat_lid, $nat_description, $nat_from, $translated_address \n"); fclose($my);


                if( preg_match("/\//", $translated_address) )
                {
                    $split = explode("/", $translated_address);
                }
                else
                {
                    $split[0] = $translated_address;
                    $split[1] = "32";
                }

                /*
                //Todo: SWASCHKUT 20191018
                //$translated_address_parts = explode("/",$translated_address);
                if ($this->ip_version($split[0])==="noip"){
                    //Look for objects with this name.
                    $getTrans = get_member_and_lid($split[0], $source, $vsys, "address");
                    $member_lid = $getTrans['member_lid'];
                    $table_name = $getTrans['table_name'];
                    $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   $split[0] in $table_name:$member_lid\n"); fclose($my);
                }
                else{
                    //Look for objects with this IP address
                    $getTrans = get_member_and_lid("$split[0]/$split[1]", $source, $vsys, "ipaddress");

                    if ($getTrans != ""){
                        //There is an object with such IP and CIDR
                        $member_lid = $getTrans['member_lid'];
                        $table_name = $getTrans['table_name'];
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   Found as $table_name:$member_lid\n"); fclose($my);
                    }
                    else{
                        //Look for an existing Label
                        $getTrans = get_member_and_lid("$split[0]/0", $source, $vsys, "ipaddress");
                        if($getTrans != ""){
                            //We found a label with such IP. Let's create an object with the name
                            $label_lid = $getTrans['member_lid'];
                            $query = "SELECT name_ext, name FROM address WHERE id='$label_lid';";
                            $getLabel = $projectdb->query($query);
                            $label=$getLabel->fetch_assoc();
                            $name = $label['name_ext'];
                            $name_int = $label['name'];

                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) "
                                . "VALUES ('$source','$vsys','$name-$split[1]','$name_int-$split[1]','$split[0]','$split[1]',0);");
                            $member_lid = $projectdb->insert_id;
                        }
                        else{
                            //There is not even a Label that we could use
                            $translated_address = str_replace("/", "-", $translated_address);
                            $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                            $member_lid = $projectdb->insert_id;
                        }
                    }
                    $table_name = "address";
                    $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                }
    */
                //END Todo: WASCHKUT


                /*
                if ($getTrans == "") {
                    $split = [];
                    if (preg_match("/\//", $translated_address)) {
                        $split = explode("/", $translated_address);
                    }
                    else {
                        $split[0] = $translated_address;
                        $split[1] = "32";
                    }
                    if ($this->ip_version($split[0]) == "noip") {
                        if (preg_match("/-/",$split[0])){
                            $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$split[0]' AND type='ip-range';");
                            if ($getDup->num_rows==1){
                                $getDupData=$getDup->fetch_assoc();
                                $member_lid=$getDupData['id'];
                            }
                            else {
                                $translated_address = str_replace("/", "-", $translated_address);
                                $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy,type) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'ip-range');");
                                $member_lid = $projectdb->insert_id;
                            }

                        }
                        else{
                            $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$split[0]' AND cidr='$split[1]';");
                            if ($getDup->num_rows==1){
                                $getDupData=$getDup->fetch_assoc();
                                $member_lid=$getDupData['id'];
                            }
                            else{
                                $translated_address = str_replace("/", "-", $translated_address);
                                $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                                $member_lid = $projectdb->insert_id;
                            }

                        }

                    }
                    else {
                        $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getObj->num_rows == 1) {
                            $getObjData = $getObj->fetch_assoc();
                            $member_lid = $getObjData['id'];
                        } else {
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                            $member_lid = $projectdb->insert_id;
                        }
                    }
                    $table_name = "address";
                    $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                }
                else {
                    $member_lid = $getTrans['member_lid'];
                    $table_name = $getTrans['table_name'];
                    $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    $my = fopen("ciscoNats.txt","a"); fwrite($my, "   $translated_address_parts[0] in $table_name:$member_lid\n"); fclose($my);
                }
                 */

                /*
                //Todo: SWASCHKUT
                $sources = isset($value['source'])?explode(",", $value['source']):array();
                foreach ($sources as $key => $val) {
                    $realip = explode("/", $val);
                    if ($realip[1] == "") {
                        $realip[1] = 32;
                    }
                    if ($value['source'] == "") {

                    } elseif ($this->ip_version($realip[0]) == "noip") {
                        $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $search_ip = $retrieveData['ipaddress'];
                            $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                            if ($searchIP->num_rows == 1) {
                                $searchIPData = $searchIP->fetch_assoc();
                                $member_lid1 = $searchIPData['id'];
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                $name_int == str_replace("/", "-", $name_int);
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        } else {
                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($getGRP->num_rows == 1) {
                                $getGRPData = $getGRP->fetch_assoc();
                                $member_lid1 = $getGRPData['id'];

                                if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                    add_log2('ok', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Replaced object [$realip[0]] by his members.', $source, 'No Action required.', 'rules', $nat_lid, 'nat_rules');
                                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                    if ($getMembers->num_rows > 0) {
                                        while ($getMembersData = $getMembers->fetch_assoc()) {
                                            $table_name1 = $getMembersData['table_name'];
                                            $member_lid1 = $getMembersData['member_lid'];
                                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    }
                                } else {
                                    $table_name1 = "address_groups_id";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                            }
                        }
                    } else {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            //$val = str_replace("-", "/", $val);
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                }

                $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address')";
                $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
                */
            }

            /*
            //Todo: SWASCHKUT
            $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type) VALUES " . implode(",", $add_nat_dyn) . ";");
            $unique_add_nat_from=array_unique($add_nat_from);
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $unique_add_nat_from) . ";");
            $unique_add_translated_address=array_unique($add_translated_address);
            $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $unique_add_translated_address) . ";");
            $add_nat_source_unique=array_unique($add_nat_source);
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source_unique) . ";");
            */
            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];

        }
        if( count($NONAT) > 0 )
        {
            $sorted = $this->array_orderby($NONAT, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_nat_source = [];
            $add_nat_destination = [];
            foreach( $sorted as $key => $value )
            {
                $nat_lid = $value['nat_lid'];
                $nat_description = $value['access-list'];
                $nat_position = $value['position'];
                $op_zone_to = $value['op_zone_to'];
                $nat_from = $value['from'];
                $nat_rulename = $value['name'];
                $src = $value['source'];
                $dst = $value['destination'];
                $srv = $value['service'];

                /*
                 TODO:SWASCHKUT

                if ($src != "") {
                    //TODO HERE: src podria ser un grupo, o un host, o . . .!!!

                    $realip = explode("/", $src);
                    if ($realip[1] == "")
                    {$realip[1] = 32;}


                    if ($this->ip_version($realip[0]) == "noip")
                    {
                        $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $search_ip = $retrieveData['ipaddress'];
                            $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                            if ($searchIP->num_rows == 1) {
                                $searchIPData = $searchIP->fetch_assoc();
                                $member_lid1 = $searchIPData['id'];
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        }
                        else
                        {
                            $query = "SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;";
                            $getGRP = $projectdb->query($query);
                            //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     $query\n");                fclose($my);
                            //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     ".$realip[0]." found here?\n");                fclose($my);
                            if ($getGRP->num_rows == 1) {
                                //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     yes\n");                fclose($my);
                                $getGRPData = $getGRP->fetch_assoc();
                                $member_lid1 = $getGRPData['id'];
                                if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                    $query = "SELECT member, member_lid, table_name FROM address_groups WHERE lid='$member_lid1';";
                                    $getMembers = $projectdb->query($query);
                                    //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     $query\n");                fclose($my);
                                    if ($getMembers->num_rows > 0) {

                                        // while ($getMembersData = $getMembers->fetch_assoc() ) {
                                        //    $subtable_name1 = $getMembersData['table_name'];
                                        //    $submember_lid1 = $getMembersData['member_lid'];
                                        //    $submember_name = $getMembersData['member'];
                                        //    $my = fopen("ciscoNats.txt", "a");                fwrite($my, "     $submember_name -> ('$source','$vsys','$submember_lid1','$subtable_name1','$nat_lid')\n");                fclose($my);
                                        //    if($submember_lid1!=0){
                                        //        $add_nat_source[] = "('$source','$vsys','$submember_lid1','$subtable_name1','$nat_lid')";
                                        //    }
                                        //}

                                        $table_name1 = "address_groups_id";
                                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }

                                }
                                else {
                                    $table_name1 = "address_groups_id";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                $add_log2 = 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database. fix it manually.';
                            }
                        }
                    }
                    else
                    {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                        if ($retrieve->num_rows == 1)
                        {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                        else
                        {
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$src','$src','$realip[0]','$realip[1]',1);");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                }

                # Destination
                if ($dst != "")
                {
                    $realip = explode("/", $dst);
                    if (!isset($realip[1]) || $realip[1] == "") {
                        $realip[1] = 32;
                    }

                    if ($this->ip_version($realip[0]) == "noip")
                    {
                        $retrieve = $projectdb->query("SELECT id,ipaddress,cidr FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $search_ip = $retrieveData['ipaddress'];
                            $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($searchIP->num_rows == 1)
                            {
                                $searchIPData = $searchIP->fetch_assoc();
                                $member_lid1 = $searchIPData['id'];
                                $table_name1 = "address";
                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                            else
                            {
                                $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        }
                        else
                        {
                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($getGRP->num_rows == 1) {
                                $getGRPData = $getGRP->fetch_assoc();
                                $member_lid1 = $getGRPData['id'];
                                if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                    $getMembers = $projectdb->query("SELECT id,member,member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                    if ($getMembers->num_rows > 0) {
                                        while ($getMembersData = $getMembers->fetch_assoc()) {
                                            $membername=$getMembersData['member'];

                                            $getTrans = get_member_and_lid($membername, $source, $vsys, "address");
                                            $member_lid1 = $getTrans['member_lid'];
                                            $table_name1 = $getTrans['table_name'];
                                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    }
                                } else {
                                    $table_name1 = "address_groups_id";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                $add_log2 = 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database. fix it manually.';
                            }
                        }
                    } else {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$dst' AND dummy=1 LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$dst','$dst','$realip[0]','$realip[1]',1);");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                    if ($op_zone_to == "") {
                        $op_zone_to = search_zone_address_one($member_lid1, $vsys, $source, $table_name1);
                    }
                }

                if ($srv != "") {
                    $srv_table_name = "";
                    $srv_member_lid = "";
                    $retrieve = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$srv';");
                    if ($retrieve->num_rows == 1) {
                        $retrieveData = $retrieve->fetch_assoc();
                        $srv_member_lid = $retrieveData['id'];
                        $srv_table_name = "services";
                    } else {
                        # Is GROUP
                        $retrieveGrp = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$srv';");
                        if ($retrieveGrp->num_rows == 1) {
                            $retrieveGrpdata = $retrieveGrp->fetch_assoc();
                            $srv_member_lid = $retrieveData['id'];
                            $srv_table_name = "services_groups_id";
                        } else {
                            add_log2('error', 'Reading [NO]Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $srv . '] in service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                        }
                    }
                }
                else{
                    $srv_table_name = "";
                    $srv_member_lid = "";
                }

                $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','','$nat_description','$op_zone_to','$nat_rulename','','$srv_member_lid','$srv_table_name')";
                $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
                */
            }
            /*
             * //Todo: SWASCHKUT
            $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,op_service_lid,op_service_table) VALUES " . implode(",", $add_nat_dyn) . ";");
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
            */
            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_nat_source = [];
            $add_nat_destination = [];
        }
        if( count($NAT_static) > 0 )
        {
            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Processing Static Nats\n"); fclose($my);
            $sorted = $this->array_orderby($NAT_static, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];
            $add_nat_destination = [];

            foreach( $sorted as $key => $value )
            {
                $tp_dat_port = "";
                $is_dat = 0;
                $tp_dat_address_table = "";
                $tp_dat_address_lid = "";
                $op_service_lid = "";
                $op_service_table = "";
                $tp_sat_bidirectional = 0;
                $nat_lid = $value['nat_lid'];
                $nat_description = $value['access-list'];
                $tp_sat_type = $value['tp_sat_type'];
                $nat_position = $value['position'];
                $op_zone_to = $value['op_zone_to'];
                $nat_from = $value['from'];
                $nat_rulename = $value['name'];
                $translated_address = isset($value['nat_rules_translated_address']) ? $value['nat_rules_translated_address'] : null;
                $tp_dat_port = isset($value['tp_dat_port']) ? $value['tp_dat_port'] : null;
                $is_dat = isset($value['is_dat']) ? $value['is_dat'] : null;
                $service = isset($value['service']) ? $value['service'] : null;
                $tp_sat_bidirectional = isset($value['tp_sat_bidirectional']) ? $value['tp_sat_bidirectional'] : null;

                /*
                 * //Todo: SWASCHKUT
                if ($is_dat == 1) {
                    $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                    if ($getTrans == "") {
                        $split = [];
                        if (preg_match("/\//", $translated_address)) {
                            $split = explode("/", $translated_address);
                        } else {
                            $split[0] = $translated_address;
                            $split[1] = "32";
                        }
                        if ($this->ip_version($split[0]) == "noip") {
                            $translated_address = str_replace("/", "-", $translated_address);
                            $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                            $tp_dat_address_lid = $projectdb->insert_id;
                        } else {
                            $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getObj->num_rows == 1) {
                                $getObjData = $getObj->fetch_assoc();
                                $tp_dat_address_lid = $getObjData['id'];
                            } else {
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                                $tp_dat_address_lid = $projectdb->insert_id;
                            }
                        }
                        $tp_dat_address_table = "address";
                    } else {
                        $tp_dat_address_lid = $getTrans['member_lid'];
                        $tp_dat_address_table = $getTrans['table_name'];
                    }
                }
                else {
                    if ($translated_address == "") {

                    }
                    else{
                        if (preg_match("/\//", $translated_address)) {
                            $split = explode("/", $translated_address);
                        }
                        else {
                            $split[0] = $translated_address;
                            $split[1] = "32";
                        }

                        if ($this->ip_version($split[0])==="noip"){
                            //Look for objects with this name.
                            $getTrans = get_member_and_lid($split[0], $source, $vsys, "address");
                            $member_lid = $getTrans['member_lid'];
                            $table_name = $getTrans['table_name'];
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   $split[0] in $table_name:$member_lid\n"); fclose($my);
                        }
                        else{
                            //Look for objects with this IP address
                            $getTrans = get_member_and_lid("$split[0]/$split[1]", $source, $vsys, "ipaddress");

                            if ($getTrans != ""){
                                //There is an object with such IP and CIDR
                                $member_lid = $getTrans['member_lid'];
                                $table_name = $getTrans['table_name'];
                                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   Found as $table_name:$member_lid\n"); fclose($my);
                            }
                            else{
                                //Look for an existing Label
                                $getTrans = get_member_and_lid("$split[0]/0", $source, $vsys, "ipaddress");
                                if($getTrans != ""){
                                    //We found a label with such IP. Let's create an object with the name
                                    $label_lid = $getTrans['member_lid'];
                                    $query = "SELECT name_ext, name FROM address WHERE id='$label_lid';";
                                    $getLabel = $projectdb->query($query);
                                    $label=$getLabel->fetch_assoc();
                                    $name = $label['name_ext'];
                                    $name_int = $label['name'];

                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) "
                                        . "VALUES ('$source','$vsys','$name-$split[1]','$name_int-$split[1]','$split[0]','$split[1]',0);");
                                    $member_lid = $projectdb->insert_id;
                                }
                                else{
                                    //There is not even a Label that we could use
                                    $translated_address = str_replace("/", "-", $translated_address);
                                    $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) "
                                        . "VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                                    $member_lid = $projectdb->insert_id;
                                }
                            }
                            $table_name = "address";
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                    }


                }

                if (isset($value['source'])) {
                    $sources = explode(",", $value['source']);
                    foreach ($sources as $key => $val) {
                        $realip = explode("/", $val);
                        if (!isset($realip[1]) || $realip[1] == "") {
                            $realip[1] = 32;
                        }
                        if ($value['source'] == "") {

                        }
                        elseif ($this->ip_version($realip[0]) == "noip") {
                            $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $search_ip = $retrieveData['ipaddress'];
                                $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                if ($searchIP->num_rows == 1) {
                                    $searchIPData = $searchIP->fetch_assoc();
                                    $member_lid1 = $searchIPData['id'];
                                    $table_name1 = "address";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                } else {
                                    $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                    $name_int == str_replace("/", "-", $name_int);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                if ($getGRP->num_rows == 1) {
                                    $getGRPData = $getGRP->fetch_assoc();
                                    $member_lid1 = $getGRPData['id'];

                                    if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                        if ($getMembers->num_rows > 0) {
                                            while ($getMembersData = $getMembers->fetch_assoc()) {
                                                $table_name1 = $getMembersData['table_name'];
                                                $member_lid1 = $getMembersData['member_lid'];
                                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                            }
                                        }
                                    } else {
                                        $table_name1 = "address_groups_id";
                                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                }
                                else {
                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                }
                            }
                        }
                        else {
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Source Address $realip[0] - $realip[1]"); fclose($my);
                            $query = "SELECT ipaddress, cidr FROM address WHERE id=185;";
                            $test = $projectdb->query($query);
                            $this->data = $test->fetch_assoc();
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$this->data['ipaddress']." - ".$this->data['cidr']."\n"); fclose($my);
                            //$query = "SELECT id, ipaddress, cidr FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;";
                            $query = "SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;";
                            $retrieve = $projectdb->query($query);

                            if ($retrieve->num_rows == 1){
                                //The Host or Range already exists
                                $retrieveData = $retrieve->fetch_assoc();
                                $member_lid1 = $retrieveData['id'];
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$realip[0]."-".$realip[1]." Found with ID $member_lid1\n"); fclose($my);
                            }
                            else{
                                //The Host or Range does not exist
                                $query = "SELECT * FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='0' LIMIT 1;;";
                                $retrieve = $projectdb->query($query);

                                if ($retrieve->num_rows > 0){
                                    //There exist a label with the same name
                                    $label = $retrieve->fetch_assoc();
                                    $name = $label['name']."-".$realip[1];
                                    $name_int = $label['name']."-".$realip[1];
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$name','$name_int','$realip[0]','$realip[1]',0);");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$realip[0]."-".$realip[1]." Not found, but yes to label $name_int\n"); fclose($my);
                                }
                                else{
                                    //There is nothing that brings us information about this new Host or Range. We need to create a new object.
                                    $val = str_replace("/", "-", $val);
                                    //This object has been corrected in its name. It has a - instead of a /, therefore it is not a dummy object anymore.
                                    //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',0);");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$realip[0]."-".$realip[1]." Not found. Not even a label\n"); fclose($my);
                                }

                            }
                        }
                    }
                }

                if (isset($value['destination'])) {
                    $sources = explode(",", $value['destination']);
                    foreach ($sources as $key => $val) {
                        $realip = explode("/", $val);
                        if ($realip[1] == "") {
                            $realip[1] = 32;
                        }

                        if ($value['destination'] == "") {

                        } elseif ($this->ip_version($realip[0]) == "noip") {
                            if ($realip[0] == "interface") {
                                $getInt = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE zone='$op_zone_to' AND source='$source' LIMIT 1");
                                if ($getInt->num_rows == 1) {
                                    $getIndData = $getInt->fetch_assoc();
                                    $interface = explode("/", $getIndData['unitipaddress']);
                                    $interface_ipaddress = $interface[0];
                                    $interface_cidr = $interface[1];
                                    $getIntObj = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$interface_ipaddress' AND cidr='$interface_cidr';");
                                    if ($getIntObj->num_rows == 1) {
                                        $getIntObjData = $getIntObj->fetch_assoc();
                                        $member_lid1 = $getIntObjData['id'];
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','services','$nat_lid')";
                                    } else {
                                        $interface = str_replace("/", "/", $getIndData['unitipaddress']);
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$interface','$interface','$interface_ipaddress','$interface_cidr',1);");
                                        $member_lid1 = $projectdb->insert_id;
                                        $table_name1 = "address";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Unable to retrieve IP address based on Zone [' . $op_zone_to . '].', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                }
                            } else {
                                $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                                if ($retrieve->num_rows == 1) {
                                    $retrieveData = $retrieve->fetch_assoc();
                                    $search_ip = $retrieveData['ipaddress'];
                                    $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                    if ($searchIP->num_rows == 1) {
                                        $searchIPData = $searchIP->fetch_assoc();
                                        $member_lid1 = $searchIPData['id'];
                                        $table_name1 = "address";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    } else {
                                        $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                        $name_int == str_replace("/", "-", $name_int);
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                        $member_lid1 = $projectdb->insert_id;
                                        $table_name1 = "address";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                    if ($getGRP->num_rows == 1) {
                                        $getGRPData = $getGRP->fetch_assoc();
                                        $member_lid1 = $getGRPData['id'];

                                        if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                            if ($getMembers->num_rows > 0) {
                                                while ($getMembersData = $getMembers->fetch_assoc()) {
                                                    $table_name1 = $getMembersData['table_name'];
                                                    $member_lid1 = $getMembersData['member_lid'];
                                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                }
                                            }
                                        } else {
                                            $table_name1 = "address_groups_id";
                                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    } else {
                                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                    }
                                }
                            }
                        } else {
                            $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $member_lid1 = $retrieveData['id'];
                                $table_name1 = "address";
                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                //$val = str_replace("-", "/", $val);
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                                //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$realip[0]/$realip[1]','$realip[0]/$realip[1]','$realip[0]','$realip[1]',1);");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        }
                    }
                }

                if (isset($value['service'])) {
                    if ($value['service'] == "") {

                    } else {
                        $getSRV = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$service' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getSRV->num_rows == 1) {
                            $getSRVData = $getSRV->fetch_assoc();
                            $op_service_lid = $getSRVData['id'];
                            $op_service_table = "services";
                        } else {
                            add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $service . '] in Service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                        }
                    }
                }

                $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address','$tp_dat_port','$is_dat','$tp_dat_address_lid','$tp_dat_address_table','$op_service_lid','$op_service_table','$tp_sat_bidirectional')";
                $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
                */
            }

            /*Todo: SWASCHKUT
            $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,tp_dat_port,is_dat,tp_dat_address_lid,tp_dat_address_table,op_service_lid,op_service_table,tp_sat_bidirectional) VALUES " . implode(",", $add_nat_dyn) . ";");
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
            $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_translated_address) . ";");
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
            */

            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];
            $add_nat_destination = [];
        }
        if( count($NAT_static_accesslist) > 0 )
        {
            $sorted = $this->array_orderby($NAT_static_accesslist, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];
            $add_nat_destination = [];

            foreach( $sorted as $key => $value )
            {
                $tp_dat_port = "";
                $is_dat = 0;
                $tp_dat_address_table = "";
                $tp_dat_address_lid = "";
                $op_service_lid = "";
                $op_service_table = "";
                $tp_sat_bidirectional = 0;
                $nat_lid = $value['nat_lid'];
                $nat_description = $value['access-list'];
                $tp_sat_type = $value['tp_sat_type'];
                $nat_position = $value['position'];
                $op_zone_to = $value['op_zone_to'];
                $nat_from = $value['from'];
                $nat_rulename = $value['name'];
                $translated_address = $value['nat_rules_translated_address'];
                if( isset($value['tp_dat_port']) )
                    $tp_dat_port = $value['tp_dat_port'];
                if( isset($value['is_dat']) )
                    $is_dat = $value['is_dat'];
                $service = $value['service'];
                if( isset($value['tp_sat_bidirectional']) )
                    $tp_sat_bidirectional = $value['tp_sat_bidirectional'];

                /*
                //Todo: SWASCHKUT
                if ($is_dat == 1) {
                    $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                    if ($getTrans == "") {
                        $split = [];
                        if (preg_match("/\//", $translated_address)) {
                            $split = explode("/", $translated_address);
                        } else {
                            $split[0] = $translated_address;
                            $split[1] = "32";
                        }
                        if ($this->ip_version($split[0]) == "noip") {
                            $translated_address = str_replace("/", "-", $translated_address);
                            $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                            $tp_dat_address_lid = $projectdb->insert_id;
                        } else {
                            $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getObj->num_rows == 1) {
                                $getObjData = $getObj->fetch_assoc();
                                $tp_dat_address_lid = $getObjData['id'];
                            } else {
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                                $tp_dat_address_lid = $projectdb->insert_id;
                            }
                        }
                        $tp_dat_address_table = "address";
                    } else {
                        $tp_dat_address_lid = $getTrans['member_lid'];
                        $tp_dat_address_table = $getTrans['table_name'];
                    }
                } else {
                    if ($translated_address == "")
                    {}
                    else
                    {
                        $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                        if ($getTrans == "") {
                            $split = [];
                            if (preg_match("/\//", $translated_address)) {
                                $split = explode("/", $translated_address);
                            } else {
                                $split[0] = $translated_address;
                                $split[1] = "32";
                            }
                            if ($this->ip_version($split[0]) == "noip") {
                                $translated_address = str_replace("/", "-", $translated_address);
                                $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                                $member_lid = $projectdb->insert_id;
                            } else {
                                $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if ($getObj->num_rows == 1) {
                                    $getObjData = $getObj->fetch_assoc();
                                    $member_lid = $getObjData['id'];
                                } else {
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                                    $member_lid = $projectdb->insert_id;
                                }
                            }
                            $table_name = "address";
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        } else {
                            $member_lid = $getTrans['member_lid'];
                            $table_name = $getTrans['table_name'];
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                    }
                }

                if (isset($value['source'])) {
                    $sources = explode(",", $value['source']);
                    foreach ($sources as $key => $val) {
                        $realip = explode("/", $val);
                        if ($realip[1] == "") {
                            $realip[1] = 32;
                        }
                        if ($value['source'] == "") {

                        } elseif ($this->ip_version($realip[0]) == "noip") {
                            $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $search_ip = $retrieveData['ipaddress'];
                                $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                if ($searchIP->num_rows == 1) {
                                    $searchIPData = $searchIP->fetch_assoc();
                                    $member_lid1 = $searchIPData['id'];
                                    $table_name1 = "address";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                } else {
                                    $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                    //$name_int = str_replace("-", "/", $name_int);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                if ($getGRP->num_rows == 1) {
                                    $getGRPData = $getGRP->fetch_assoc();
                                    $member_lid1 = $getGRPData['id'];

                                    if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                        if ($getMembers->num_rows > 0) {
                                            while ($getMembersData = $getMembers->fetch_assoc()) {
                                                $table_name1 = $getMembersData['table_name'];
                                                $member_lid1 = $getMembersData['member_lid'];
                                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                            }
                                        }
                                    } else {
                                        $table_name1 = "address_groups_id";
                                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                }
                            }
                        } else {
                            $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $member_lid1 = $retrieveData['id'];
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                $val = str_replace("-", "/", $val);
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        }
                    }
                }

                if (isset($value['destination'])) {
                    $sources = explode(",", $value['destination']);
                    foreach ($sources as $key => $val) {
                        $realip = explode("/", $val);
                        if ($realip[1] == "") {
                            $realip[1] = 32;
                        }
                        if ($value['destination'] == "") {

                        } elseif ($this->ip_version($realip[0]) == "noip") {
                            if ($realip[0] == "interface") {
                                $getInt = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE zone='$op_zone_to' AND source='$source' LIMIT 1");
                                if ($getInt->num_rows == 1) {
                                    $getIndData = $getInt->fetch_assoc();
                                    $interface = explode("/", $getIndData['unitipaddress']);
                                    $interface_ipaddress = $interface[0];
                                    $interface_cidr = $interface[1];
                                    $getIntObj = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$interface_ipaddress' AND cidr='$interface_cidr';");
                                    if ($getIntObj->num_rows == 1) {
                                        $getIntObjData = $getIntObj->fetch_assoc();
                                        $member_lid1 = $getIntObjData['id'];
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','services','$nat_lid')";
                                    } else {
                                        $interface = str_replace("/", "/", $getIndData['unitipaddress']);
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$interface','$interface','$interface_ipaddress','$interface_cidr',1);");
                                        $member_lid1 = $projectdb->insert_id;
                                        $table_name1 = "address";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Unable to retrieve IP address based on Zone [' . $op_zone_to . '].', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                }
                            } else {
                                $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                                if ($retrieve->num_rows == 1) {
                                    $retrieveData = $retrieve->fetch_assoc();
                                    $search_ip = $retrieveData['ipaddress'];
                                    $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                    if ($searchIP->num_rows == 1) {
                                        $searchIPData = $searchIP->fetch_assoc();
                                        $member_lid1 = $searchIPData['id'];
                                        $table_name1 = "address";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    } else {
                                        $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                        $name_int == str_replace("/", "-", $name_int);
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                        $member_lid1 = $projectdb->insert_id;
                                        $table_name1 = "address";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                    if ($getGRP->num_rows == 1) {
                                        $getGRPData = $getGRP->fetch_assoc();
                                        $member_lid1 = $getGRPData['id'];

                                        if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                            if ($getMembers->num_rows > 0) {
                                                while ($getMembersData = $getMembers->fetch_assoc()) {
                                                    $table_name1 = $getMembersData['table_name'];
                                                    $member_lid1 = $getMembersData['member_lid'];
                                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                }
                                            }
                                        } else {
                                            $table_name1 = "address_groups_id";
                                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    } else {
                                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                    }
                                }
                            }
                        } else {
                            $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $member_lid1 = $retrieveData['id'];
                                $table_name1 = "address";
                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                //$val = str_replace("-", "/", $val);
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        }
                    }
                }

                if (isset($value['service'])) {
                    if ($service == "") {

                    } else {
                        $getSRV = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$service' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getSRV->num_rows == 1) {
                            $getSRVData = $getSRV->fetch_assoc();
                            $op_service_lid = $getSRVData['id'];
                            $op_service_table = "services";
                        } else {
                            add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $service . '] in Service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                        }
                    }
                }

                $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address','$tp_dat_port','$is_dat','$tp_dat_address_lid','$tp_dat_address_table','$op_service_lid','$op_service_table','$tp_sat_bidirectional')";
                $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
                */
            }

            /*
             Todo: SWASCHKUT
            $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,tp_dat_port,is_dat,tp_dat_address_lid,tp_dat_address_table,op_service_lid,op_service_table,tp_sat_bidirectional) VALUES " . implode(",", $add_nat_dyn) . ";");
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
            $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_translated_address) . ";");
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
            */

            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];
            $add_nat_destination = [];
        }
        if( count($NAT_accesslist) > 0 )
        {
            $sorted = $this->array_orderby($NAT_accesslist, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];
            $add_nat_destination = [];

            foreach( $sorted as $key => $value )
            {
                $tp_dat_address_table = "";
                $tp_dat_address_lid = "";
                $op_service_lid = "";
                $op_service_table = "";
                $nat_lid = $value['nat_lid'];
                $nat_description = $value['access-list'];
                $tp_sat_type = $value['tp_sat_type'];
                $nat_position = $value['position'];
                $op_zone_to = $value['op_zone_to'];
                $nat_from = $value['from'];
                $nat_rulename = $value['name'];
                $translated_address = $value['nat_rules_translated_address'];
                $tp_dat_port = isset($value['tp_dat_port']) ? $value['tp_dat_port'] : '';
                $is_dat = isset($value['is_dat']) ? $value['is_dat'] : 0;
                $service = $value['service'];
                $tp_sat_bidirectional = isset($value['tp_sat_bidirectional']) ? $value['tp_sat_bidirectional'] : 0;


                /*
                             //Todo: SWASCHKUT

                            if ($is_dat == 1)
                            {
                                $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                                if ($getTrans == "") {
                                    $split = [];
                                    if (preg_match("/\//", $translated_address)) {
                                        $split = explode("/", $translated_address);
                                    } else {
                                        $split[0] = $translated_address;
                                        $split[1] = "32";
                                    }
                                    if ($this->ip_version($split[0]) == "noip") {
                                        $translated_address = str_replace("/", "-", $translated_address);
                                        $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                                        $tp_dat_address_lid = $projectdb->insert_id;
                                    } else {
                                        $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                        if ($getObj->num_rows == 1) {
                                            $getObjData = $getObj->fetch_assoc();
                                            $tp_dat_address_lid = $getObjData['id'];
                                        } else {
                                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                                            $tp_dat_address_lid = $projectdb->insert_id;
                                        }
                                    }
                                    $tp_dat_address_table = "address";
                                } else {
                                    $tp_dat_address_lid = $getTrans['member_lid'];
                                    $tp_dat_address_table = $getTrans['table_name'];
                                }
                            }
                            else
                            {
                                if ($translated_address == "")
                                {}
                                else
                                {
                                    $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                                    if ($getTrans == "") {
                                        $split = [];
                                        if (preg_match("/\//", $translated_address)) {
                                            $split = explode("/", $translated_address);
                                        } else {
                                            $split[0] = $translated_address;
                                            $split[1] = "32";
                                        }
                                        if (($split[1] == 0) OR ( $split[1] == "")) {
                                            $split[1] = "32";
                                            $translated_address = $split[0];
                                        }
                                        if ($this->ip_version($split[0]) == "noip") {
                                            $translated_address = str_replace("/", "-", $translated_address);
                                            $translated_address = $this->truncate_names($this->normalizeNames($translated_address));
                                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                                            $member_lid = $projectdb->insert_id;
                                        } else {
                                            $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                            if ($getObj->num_rows == 1) {
                                                $getObjData = $getObj->fetch_assoc();
                                                $member_lid = $getObjData['id'];
                                            } else {
                                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                                                $member_lid = $projectdb->insert_id;
                                            }
                                        }
                                        $table_name = "address";
                                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                                    } else {
                                        $member_lid = $getTrans['member_lid'];
                                        $table_name = $getTrans['table_name'];
                                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                                    }
                                }
                            }

                            if (isset($value['source'])) {
                                $sources = explode(",", $value['source']);
                                foreach ($sources as $key => $val) {
                                    $realip = explode("/", $val);
                                    if ($realip[1] == "") {
                                        $realip[1] = 32;
                                    }
                                    if ($value['source'] == "") {

                                    } elseif ($this->ip_version($realip[0]) == "noip") {
                                        $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                                        if ($retrieve->num_rows == 1) {
                                            $retrieveData = $retrieve->fetch_assoc();
                                            $search_ip = $retrieveData['ipaddress'];
                                            $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                            if ($searchIP->num_rows == 1) {
                                                $searchIPData = $searchIP->fetch_assoc();
                                                $member_lid1 = $searchIPData['id'];
                                                $table_name1 = "address";
                                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                            } else {
                                                $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                                $name_int == str_replace("/", "-", $name_int);
                                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                                $member_lid1 = $projectdb->insert_id;
                                                $table_name1 = "address";
                                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                            }
                                        } else {
                                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                            if ($getGRP->num_rows == 1) {
                                                $getGRPData = $getGRP->fetch_assoc();
                                                $member_lid1 = $getGRPData['id'];

                                                if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                                    if ($getMembers->num_rows > 0) {
                                                        while ($getMembersData = $getMembers->fetch_assoc()) {
                                                            $table_name1 = $getMembersData['table_name'];
                                                            $member_lid1 = $getMembersData['member_lid'];
                                                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                        }
                                                    }
                                                } else {
                                                    $table_name1 = "address_groups_id";
                                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                }
                                            } else {
                                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                            }
                                        }
                                    } else {
                                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                                        if ($retrieve->num_rows == 1) {
                                            $retrieveData = $retrieve->fetch_assoc();
                                            $member_lid1 = $retrieveData['id'];
                                            $table_name1 = "address";
                                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        } else {
                                            //$val = str_replace("-", "/", $val);
                                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                                            $member_lid1 = $projectdb->insert_id;
                                            $table_name1 = "address";
                                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    }
                                }
                            }

                            if (isset($value['destination'])) {
                                $sources = explode(",", $value['destination']);
                                foreach ($sources as $key => $val) {
                                    $realip = explode("/", $val);
                                    if ($realip[1] == "") {
                                        $realip[1] = 32;
                                    }
                                    if ($value['destination'] == "") {

                                    } elseif ($this->ip_version($realip[0]) == "noip") {
                                        if ($realip[0] == "interface") {
                                            $getInt = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE zone='$op_zone_to' AND source='$source' LIMIT 1");
                                            if ($getInt->num_rows == 1) {
                                                $getIndData = $getInt->fetch_assoc();
                                                $interface = explode("/", $getIndData['unitipaddress']);
                                                $interface_ipaddress = $interface[0];
                                                $interface_cidr = $interface[1];
                                                $getIntObj = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$interface_ipaddress' AND cidr='$interface_cidr';");
                                                if ($getIntObj->num_rows == 1) {
                                                    $getIntObjData = $getIntObj->fetch_assoc();
                                                    $member_lid1 = $getIntObjData['id'];
                                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','services','$nat_lid')";
                                                } else {
                                                    $interface = str_replace("/", "/", $getIndData['unitipaddress']);
                                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$interface','$interface','$interface_ipaddress','$interface_cidr',1);");
                                                    $member_lid1 = $projectdb->insert_id;
                                                    $table_name1 = "address";
                                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                }
                                            } else {
                                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Unable to retrieve IP address based on Zone [' . $op_zone_to . '].', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                            }
                                        } else {
                                            $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                                            if ($retrieve->num_rows == 1) {
                                                $retrieveData = $retrieve->fetch_assoc();
                                                $search_ip = $retrieveData['ipaddress'];
                                                $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                                if ($searchIP->num_rows == 1) {
                                                    $searchIPData = $searchIP->fetch_assoc();
                                                    $member_lid1 = $searchIPData['id'];
                                                    $table_name1 = "address";
                                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                } else {
                                                    $name_int = $this->truncate_names($this->normalizeNames($realip[0]));
                                                    $name_int == str_replace("/", "-", $name_int);
                                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]');");
                                                    $member_lid1 = $projectdb->insert_id;
                                                    $table_name1 = "address";
                                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                }
                                            } else {
                                                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                                if ($getGRP->num_rows == 1) {
                                                    $getGRPData = $getGRP->fetch_assoc();
                                                    $member_lid1 = $getGRPData['id'];

                                                    if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                                        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                                        if ($getMembers->num_rows > 0) {
                                                            while ($getMembersData = $getMembers->fetch_assoc()) {
                                                                $table_name1 = $getMembersData['table_name'];
                                                                $member_lid1 = $getMembersData['member_lid'];
                                                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                            }
                                                        }
                                                    } else {
                                                        $table_name1 = "address_groups_id";
                                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                                    }
                                                } else {
                                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                                }
                                            }
                                        }
                                    } else {
                                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                                        if ($retrieve->num_rows == 1) {
                                            $retrieveData = $retrieve->fetch_assoc();
                                            $member_lid1 = $retrieveData['id'];
                                            $table_name1 = "address";
                                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        } else {
                                            //$val = str_replace("-", "/", $val);
                                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                                            $member_lid1 = $projectdb->insert_id;
                                            $table_name1 = "address";
                                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    }
                                }
                            }

                            if (isset($value['service'])) {
                                if ($service == "") {

                                } else {
                                    $getSRV = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$service' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                    if ($getSRV->num_rows == 1) {
                                        $getSRVData = $getSRV->fetch_assoc();
                                        $op_service_lid = $getSRVData['id'];
                                        $op_service_table = "services";
                                    } else {
                                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $service . '] in Service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                    }
                                }
                            }

                            $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address','$tp_dat_port','$is_dat','$tp_dat_address_lid','$tp_dat_address_table','$op_service_lid','$op_service_table','$tp_sat_bidirectional')";
                            $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
                            */
            }

            /*
             * Todo: SWASCHKUT
            $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,tp_dat_port,is_dat,tp_dat_address_lid,tp_dat_address_table,op_service_lid,op_service_table,tp_sat_bidirectional) VALUES " . implode(",", $add_nat_dyn) . ";");
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
            $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_translated_address) . ";");
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
            */

            $add_nat_dyn = [];
            $add_nat_from = [];
            $add_translated_address = [];
            $add_nat_source = [];
            $add_nat_destination = [];
        }
    }

}
