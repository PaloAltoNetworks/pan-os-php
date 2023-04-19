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


trait SCREENOSnat
{

    /** This method checks that the existing DNAT rules are correct for being pushed to the Firewall. If not, they are marked for review.
     *
     * @param type $source
     * @param type $vsys
     * @param type $filename
     * @param type $PANOSversion
     * @global type $projectdb
     */
    function check_dnat_cidr($source, $vsys, $filename, $PANOSversion = 7)
    {
        global $projectdb;

        $query = "SELECT nat.* FROM nat_rules nat "
            . "WHERE nat.is_dat='1' AND nat.source ='$source' AND nat.vsys='$vsys' ";
        $getDnatCandidates = $projectdb->query($query);

        while( $natRule = $getDnatCandidates->fetch_assoc() )
        {
            $dNATrule_id = $natRule['id'];
            $dNATrule_tp_dat_address_lid = $natRule['tp_dat_address_lid'];
            $dNATrule_tp_dat_address_table = $natRule['tp_dat_address_table'];

            //Check Range of Translated Destinations
            if( $dNATrule_tp_dat_address_table === 'address' )
            {
                $query = "SELECT cidr FROM address WHERE id = $dNATrule_tp_dat_address_lid;";
                $getTranslatedDst_Mem = $projectdb->query($query);
                if( $getTranslatedDst_Mem->num_rows === 1 )
                {
                    $translatedDst = $getTranslatedDst_Mem->fetch_assoc();
                    $translatedDst_cidr = $translatedDst['cidr'];
                }
                else
                {
                    $translatedDst_cidr = -1;
                    //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id Error TD: $translatedDst_cidr\n"); fclose($my);
                    add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] does not have a Translated Destination.', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                }
            }
            else
            {
                $translatedDst_cidr = -1;
                //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id Error TD: $translatedDst_cidr\n"); fclose($my);
                add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] has a group as a Translated Destination. It may not fit with the Destinations', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
            }


            if( $translatedDst_cidr > 0 )
            {
                $query = "SELECT * FROM nat_rules_dst WHERE rule_lid='$dNATrule_id';";
                $getDstMem = $projectdb->query($query);
                if( $getDstMem->num_rows === 1 )
                {
                    $dstMem = $getDstMem->fetch_assoc();
                    $dstMember_lid = $dstMem['member_lid'];
                    $dstMember_table = $dstMem['table_name'];
                    if( $dstMember_table === 'address' )
                    {
                        $query = "SELECT cidr FROM address WHERE id = $dstMember_lid;";
                        $getDstMemCidr = $projectdb->query($query);
                        if( $getDstMemCidr->num_rows === 1 )
                        {
                            $DstMemCidr = $getDstMemCidr->fetch_assoc();
                            $dst_cidr = $DstMemCidr['cidr'];
                            if( $dst_cidr != $translatedDst_cidr )
                            {
                                //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, Error DST: $dst_cidr\n"); fclose($my);
                                add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] has a destination with different CIDR than the Translated Destination.', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                            }
                        }
                        else
                        {
                            //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, Error DST: More than 1\n"); fclose($my);
                            add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] does not have a valid Destination. It may not fit with the Translated Destination', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                        }
                    }
                    else
                    {
                        //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, Error DST: not an address. A group\n"); fclose($my);
                        add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] has a group as a Destination. It may not fit with the Translated Destination', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                    }
                }
                else
                {
                    //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, DST: not a defined dest\n"); fclose($my);
                    add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] does not have one single Destination. It may not fit with the Translated Destination', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                }
            }
        }
    }

    /** This methodsplits all the DNAT rules to have a single source in their rules. PANOS (until 7.1) does not support multiple sources in DNAT. They need to be atomic
     *
     * @param int $source
     * @param String $vsys
     * @param String $filename
     * @param int $PANOSversion Version of the PANOS device in which this configuration will be uploaded to
     * @global type $projectdb
     */
    function split_dnat_rules($source, $vsys, $filename, $PANOSversion = 7)
    {
        global $projectdb;

        if( $PANOSversion <= '7' )
        {
            $limit = "HAVING count(*) > 1";
        }
        else
        {
            $limit = "";
        }

        //Get all the DNAT rules that have more than on source
        $query = "SELECT nat.*, count(*) as amount FROM nat_rules nat, nat_rules_dst natdst "
            . "WHERE natdst.rule_lid = nat.id AND "
            . "nat.is_dat='1' AND nat.source ='$source' AND nat.vsys='$vsys' "
            . "GROUP BY nat.id "
            . "$limit";
        $getDnatCandidates = $projectdb->query($query);


        while( $natRule = $getDnatCandidates->fetch_assoc() )
        {
            $dNATrule_id = $natRule['id'];
            $dNATrule_amount = $natRule['amount'];

            //Check how many rules do we need to split to
            $message = "";
            $initialPosition = "";
            $finalPosition = "";
            $relations_to_delete = array();
            for( $i = 0; $i < $dNATrule_amount; $i++ )
            {
                $newLid = clone_nat_rule($initialPosition, $finalPosition, $vsys, $source, $dNATrule_id, $message, $filename);

                $query = "SELECT * FROM nat_rules_dst WHERE rule_lid = $newLid;";
                $getDstMem = $projectdb->query($query);
                $j = $dNATrule_amount - 1;
                while( $mem = $getDstMem->fetch_assoc() )
                {
                    $dst_rel_Id = $mem['id'];
                    if( $i != $j )
                    {
                        $relations_to_delete[] = $dst_rel_Id;
                    }
                    $j--;
                }
            }

            $to_delete = implode(",", $relations_to_delete);
            $query = "DELETE FROM nat_rules_dst WHERE id in ($to_delete);";
            $projectdb->query($query);

            $query = "UPDATE nat_rules SET disabled='1' WHERE id='$dNATrule_id'";
            $projectdb->query($query);
            add_log2('info', 'Reading Security Policies', 'DNAT RuleID [' . $dNATrule_id . '] has multiple Destinations. It has been split into multiple Individual DNAT rules, below this rule. This rule is now disabled, but left for Reviewing purposes. ', $source, 'Review the new split rules.', 'rules', $dNATrule_id, 'nat_rules');

        }
    }

    /** Updates the ZoneTo for the Security Rules based on the Destination Nats.
     *  It also corrects the ZoneTo of the Nat Rules. Screenos defined the ZoneTo after applying the NAT rule.
     *  However, in our destination NAT rules, we need to define the ZoneTo before applying NAT.
     *
     * @param type $source
     * @param type $vsys
     * @global type $projectdb
     */
    function fix_destination_nat($source, $vsys)
    {
        global $projectdb;

#FIX the MIPs Static-ip where in the security policy we find a MIP as a destination
        $getDNAT = $projectdb->query("SELECT id FROM nat_rules WHERE tp_sat_type='static-ip' AND tp_sat_bidirectional='1' AND source='$source' AND vsys='$vsys';");
        if( $getDNAT->num_rows > 0 )
        {

            while( $data = $getDNAT->fetch_assoc() )
            {
                $lid = $data['id'];
                # I need the Zone from the Source
                $getSource = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid';");
                if( $getSource->num_rows == 1 )
                {
                    $getSourceData = $getSource->fetch_assoc();
                    $member_lid = $getSourceData['member_lid'];
                    $table_name = $getSourceData['table_name'];
                    $zone = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                    $projectdb->query("UPDATE nat_rules_from SET name='$zone' WHERE rule_lid='$lid';");
                }

                $getTranslated = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                if( $getTranslated->num_rows > 0 )
                {
                    $getTranslatedData = $getTranslated->fetch_assoc();
                    $member_lid = $getTranslatedData['member_lid'];
                    $table_name = $getTranslatedData['table_name'];

                    #Change the ZoneTo in all the rules where is
                    $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE member_lid='$member_lid' AND table_name='$table_name';");
                    if( $getRules->num_rows > 0 )
                    {
                        while( $rulesData = $getRules->fetch_assoc() )
                        {
                            $rule_lid = $rulesData['rule_lid'];
                            $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$rule_lid' AND source='$source';");
                            $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES ('$source','$vsys','$zone','$rule_lid');");
                            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$rule_lid';");
                            add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $rule_lid . '] has been modified by Nat RuleID [' . $lid . '], Replaced Destination Zone by [' . $zone . ']', $source, 'Check it manually', 'rules', $rule_lid, 'security_rules');
                        }
                    }
                }
            }
        }

        // MT-364 Comment because nat dst zone to not necessary calculate
        /*$getDNAT = $projectdb->query("SELECT id FROM nat_rules WHERE is_dat='1' AND source='$source' AND vsys='$vsys';");
        if ($getDNAT->num_rows > 0) {
            while ($data = $getDNAT->fetch_assoc()) {
                $zones = array();
                $lid = $data['id'];
                # I need the Zone from the destination
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid';");
                while ($getDestinationData = $getDestination->fetch_assoc()) {
                    $member_lid = $getDestinationData['member_lid'];
                    $table_name = $getDestinationData['table_name'];
                    $zones[] = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                }
                $number_of_zones = count($zones);
                if($number_of_zones==1){
                    $zoneName=$zones[0];
                    $projectdb->query('UPDATE nat_rules SET op_zone_to = "'.$zoneName.'" WHERE id='.$lid.';');
                    //echo 'UPDATE nat_rules SET op_zone_to = "'.$zoneName.'" WHERE id='.$lid.';';
                }
                elseif($number_of_zones==0){
                    add_log2('warning', 'Fixing NAT To Zone', 'NAT RuleID [' . $rule_lid . '] does not have Zone To defined.', $source, 'Check it manually', 'rules', $rule_lid, 'nat_rules');
                }
                else{
                    $zoneName=$zones[0];
                    $projectdb->query('UPDATE nat_rules SET op_zone_to = "'.$zoneName.'" WHERE id='.$lid.';');
                    add_log2('warning', 'Fixing NAT To Zone', 'NAT RuleID [' . $rule_lid . '] has multiple Zone To defined. Split into multiple NAT Rules', $source, 'Check it manually', 'rules', $rule_lid, 'nat_rules');
                }

            }
        }*/
    }

// NAT Functions
// <editor-fold desc="  ****  NAT functions   ****" defaultstate="collapsed" >

    /**
     *
     * @param type $screenos_config_file
     * @param type $source
     * @param type $vsys
     * @param type $ismultiornot
     * @param type $template
     * @global type $projectdb
     */
    function get_nat_MIP($screenos_config_file)
    {

        global $debug;
        global $print;


        $addMIP = array();

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
            $addMIPFrom = array();
            if( preg_match("/^set vrouter /i", $names_line) )
            {

            }
            if( preg_match("/^set interface /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $int = explode(":", $data[2]);
                $interName = $int[0];

                if( $data[3] == "mip" )
                {
                    if( $data[5] == "host" )
                    {
                        $originalIP = $data[4];
                        $mappedIP = $data[6];
                        $mappedMask = $data[8];
                        $ip_version = $this->ip_version($mappedIP);
                        if( $ip_version == "v4" )
                        {
                            $mappedCidr = $this->mask2cidrv4($mappedMask);
                        }


                        $tmp_address1 = $this->sub->addressStore->all('value string.regex /' . $originalIP . '/');

                        if( !empty($tmp_address1) && count($tmp_address1) == 1 && $tmp_address1[0]->getNetworkValue() == $originalIP )
                        {
                            #print "mip existing ip name ".$tmp_address1[0]->name()." value: ".$tmp_address1[0]->value()." add to rule\n";
                            $tmp_address1 = $tmp_address1[0];
                        }
                        else
                        {
                            //search in global / shared
                            //if not available

                            if( $mappedCidr == "32" )
                            {
                                $name_int = "MIP" . $originalIP;
                                $tmp_address1 = $this->sub->addressStore->find($name_int);
                                if( $tmp_address1 == null )
                                    $tmp_address1 = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $originalIP . "/32");
                            }
                            else
                            {
                                $name_int = "MIPN-" . $originalIP . "_" . $mappedCidr;
                                $tmp_address1 = $this->sub->addressStore->find($name_int);
                                if( $tmp_address1 == null )
                                    $tmp_address1 = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $originalIP . "/" . $mappedCidr);
                            }
                            #print "mip ip name ".$tmp_address1->name()." value: ".$tmp_address1->value()." add to rule\n";
                        }

                        $ruleName = "MIP " . $originalIP;

                        if( $mappedCidr == "32" )
                        {
                            $name_int = "MIP" . $mappedIP;
                        }
                        else
                        {
                            $name_int = "MIPN-" . $mappedIP . "_" . $mappedCidr;
                        }

                        $tmp_object = $this->sub->addressStore->find($name_int);
                        if( $tmp_object == null )
                        {

                            if( $mappedCidr == "32" )
                            {
                                $tmp_object = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $mappedIP);
                            }
                            else
                                $tmp_object = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $mappedIP . "/" . $mappedCidr);
                        }


                        if( $print )
                            print "create NATrule: '" . $ruleName . "''\n";
                        $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName);

                        $tmp_nat_rule->source->addObject($tmp_object);

                        $tmp_nat_rule->snathosts->addObject($tmp_address1);
                        $tmp_nat_rule->from->setAny();
                        $tmp_nat_rule->to->setAny();
                        $tmp_nat_rule->setDescription('fix to Zone');
                        $tmp_nat_rule->changeSourceNAT('static-ip');

                    }
                }
            }
        }


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
    function get_nat_VIP($screenos_config_file)
    {
        global $projectdb;
        $interfaces = array();
        $zones = array();

        global $debug;
        global $print;

        $vsys = "root";

        $addVIP = array();

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

            if( preg_match("/^set vrouter /i", $names_line) )
            {

            }
            if( preg_match("/^set interface /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $int = explode(":", $data[2]);
                $interName = $int[0];
                if( $data[3] == "vip" )
                {

                    $tmp_int = $this->template->network->findInterface($interName);

                    if( $tmp_int !== null )
                        if( isset($tmp_int->getLayer3IPv4Addresses()[0]) )
                            $unitipaddress = $tmp_int->getLayer3IPv4Addresses()[0];
                        else
                            $unitipaddress = "";
                    #$zone = "SVEN";

                    if( $data[4] == "interface-ip" )
                    {
                        $interfacedata = explode("/", $unitipaddress);
                        $originalIP = $interfacedata[0];
                        $ip_version = $this->ip_version($originalIP);
                    }
                    else
                    {
                        $ip_version = $this->ip_version($data[4]);
                        $originalIP = $data[4];
                    }

                    if( $data[5] == "+" )
                    {
                        $originalPort = $data[6];
                        $mappedPort = $data[7];
                        $mappedIP = $data[8];
                    }
                    else
                    {
                        $originalPort = $data[5];
                        $mappedPort = $data[6];
                        $mappedIP = $data[7];
                    }

                    if( $ip_version == "v4" )
                    {
                        $mappedCidr = "32";
                    }
                    elseif( $ip_version == "v6" )
                    {
                        $mappedCidr = "128";
                    }

                    $tmp_address1 = $this->sub->addressStore->all('value string.regex /' . $originalIP . '/');

                    if( !empty($tmp_address1) && count($tmp_address1) == 1 && $tmp_address1[0]->getNetworkValue() == $originalIP )
                    {
                        $tmp_address1 = $tmp_address1[0];
                    }
                    else
                    {
                        //search in global / shared
                        //if not available

                        if( $mappedCidr == "32" )
                        {
                            $name_int = "VIP" . $originalIP;
                            $tmp_address1 = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $originalIP . "/32");
                        }
                        else
                        {
                            $name_int = "VIPN-" . $originalIP . "_" . $mappedCidr;
                            $tmp_address1 = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $originalIP . "/" . $mappedCidr);
                        }
                    }


                    $ruleName = "VIP " . $originalIP . " dPort " . $originalPort;

                    #Calculate DZONE from the VIP address into the Security Rules
                    #$dzone = search_zone_address_one($member_lid, $vsys, $source, $table_name);

                    # Translated Dport
                    $tmp_service_dport = $this->sub->serviceStore->find($mappedPort);
                    if( $tmp_service_dport !== null && !$tmp_service_dport->isTmpSrv() )
                    {
                        $dport = $tmp_service_dport->getDestPort();
                        $protocol = $tmp_service_dport->protocol();
                    }

                    else
                        print "service : " . $mappedPort . " not found\n";

                    # Original Dport
                    $name = $protocol . "-" . $originalPort;
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service == null )
                    {
                        if( $print )
                            print "create service Object: " . $name . ", " . $protocol . ", " . $originalPort . "\n";
                        $tmp_service = $this->sub->serviceStore->newService($name, $protocol, $originalPort);
                    }


                    if( $mappedCidr == "32" )
                    {
                        $name_int = "H-" . $mappedIP . "_" . "32";
                    }
                    else
                    {
                        $name_int = "N-" . $mappedIP . "-" . $mappedCidr;
                    }

                    $tmp_object = $this->sub->addressStore->find($name_int);
                    if( $tmp_object == null )
                    {

                        if( $mappedCidr == "32" )
                        {
                            $tmp_object = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $mappedIP);
                        }
                        else
                            $tmp_object = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $mappedIP . "/" . $mappedCidr);

                    }


                    if( $print )
                        print "create NATrule: '" . $ruleName . "''\n";
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName);

                    $tmp_nat_rule->destination->addObject($tmp_address1);

                    $tmp_nat_rule->setDNAT($tmp_object);

                    //Todo: 20190510 - dnatport add - fix setDNAT pan-c function


                    $tmp_nat_rule->from->setAny();
                    $tmp_nat_rule->to->setAny();

                    $tmp_nat_rule->setService($tmp_service);

                }
            }
        }
    }

    /**
     *
     * @param type $source
     * @param type $vsys
     * @param type $template
     * @global array $natdst_content
     * @global type $projectdb
     */
    function get_nat_DIP()
    {
        global $projectdb, $natdst_content;

        global $addDip;
        global $dip;
        global $debug;
        global $print;


        if( !empty($addDip) )
            $addDip = array_unique($addDip, SORT_REGULAR);
        else
            $addDip = array();


        $nat_lid = "";
        $addNatRule = array();
        $addZonesFrom = array();
        $addSources = array();
        $addDestination = array();
        $addTranslatedAddress = array();


        if( count($addDip) > 0 )
        {

            foreach( $addDip as $data )
            {
                if( $data[1] == "root" )
                {
                    $this->template_vsys = $this->template->findVirtualSystem('vsys1');
                    if( $this->template_vsys === null )
                    {
                        derr("vsys: vsys1 could not be found ! Exit\n");
                    }
                }
                else
                {
                    // Did we find VSYS1 ?
                    $this->template_vsys = $this->template->findVSYS_by_displayName($data[1]);
                    if( $this->template_vsys === null )
                    {
                        derr("vsys: " . $data[1] . " could not be found ! Exit\n");
                    }
                }

                //$addDip[] = "('$source','$vsys','$rulelid','dip-id','$dip_id')";
                #while ($data = $getMapping->fetch_assoc()) {
                //$rule_lid = ""; //Defined below
                //$dip_type = ""; //Defined below
                $dip_id = "";
                $zoneTo = "";
                $tp_sat_interface = "";
                $srv_table_name = "";
                $srv_member_lid = "";

                $rule_name = $data[2];
                $tmp_rule = $this->sub->securityRules->find($rule_name);
                if( $tmp_rule == null )
                {
                    mwarning('rule: ' . $rule_name . " not found | vsys: " . $this->sub->name() . " \n", null, FALSE);
                    continue;
                }


                $dip_type = $data[3];
                if( $dip_type == "dip-id" )
                {
                    $dip_id = $data[4];
                    #$RuleName = "Nat DIP " . $dip_id . " " . $originalRuleName;
                    $RuleName = "Nat DIP " . $dip_id . " " . $rule_name;

                    //Todo: 20190514 SVEN implement
                    if( $print )
                        print "Rule: " . $RuleName . "\n";


                    //search $vsys [0] and $dip_id [1] from array $dip
                    $id = "";
                    foreach( $dip as $key => $entry )
                    {
                        #if( $entry[0] == $vsys and $entry[1] == $dip_id )
                        if( $entry[1] == $dip_id )
                        {
                            $id = $key;
                            break;
                        }
                    }
                    #print "ID: ".$id."\n";


                    if( $id == "" )
                    {
                        mwarning("DIPID " . $dip_id . " not found!");
                        continue;

                    }


                    $dip_tp_sat_type = $dip[$id][5];
                    $tp_sat_address_type = "translated-address";
                    $tp_sat_interface = "";
                    $tp_sat_ip_address = "";
                    $startip = $dip[$id][3];
                    $endip = $dip[$id][4];

                    if( $endip == $startip )
                    {
                        $ip_address = $startip;
                        $new_name = "NATH-" . $ip_address . "_" . "32";
                        $ip_address_type = 'ip-netmask';
                        $ip_address_value = $ip_address . "/32";
                    }
                    else
                    {
                        $ip_address = $startip . "-" . $endip;
                        $new_name = "NATR-" . $ip_address;
                        $ip_address_type = 'ip-range';
                        $ip_address_value = $ip_address;
                    }

                    $tmp_address1 = $this->sub->addressStore->all('value string.regex /' . $ip_address . '/');

                    if( !empty($tmp_address1) && count($tmp_address1) == 1 && $tmp_address1[0]->getNetworkValue() == $ip_address )
                    {
                        #print "mip existing ip name ".$tmp_address1[0]->name()." value: ".$tmp_address1[0]->value()." add to rule\n";
                        $tmp_address1 = $tmp_address1[0];
                    }
                    else
                    {
                        $tmp_address1 = $this->sub->addressStore->find($new_name);
                        if( $tmp_address1 == null )
                            $tmp_address1 = $this->sub->addressStore->newAddress($new_name, $ip_address_type, $ip_address_value);
                    }
                }
                else
                {
                    #Calculate the Interface Ip address from the ZoneTO
                    #$RuleName = "Nat interface " . $originalRuleName;
                    $RuleName = "Nat interface " . $rule_name;

                    if( $print )
                        print "Rule: " . $RuleName . "\n";


                    $dip_tp_sat_type = "dynamic-ip-and-port";
                    $tp_sat_address_type = "interface-address";

                    $tmp_tos = $tmp_rule->to->getAll();
                    if( count($tmp_tos) == 1 )
                        $zoneTo = $tmp_tos[0];


                    //Todo: check if $this->template_vsys->zoneStore->hasZoneNamed( 'name, true [casesensitive] ) is not better
                    $tmp_zones = $this->template_vsys->zoneStore->getall();
                    $snat_int_array = array();
                    foreach( $tmp_zones as $tmp_zone )
                    {
                        if( $tmp_zone->name() == $zoneTo->name() )
                        {
                            #print "name: ".$tmp_zone->name()."\n";
                            $tmp_interface2 = $tmp_zone->attachedInterfaces->interfaces();
                            foreach( $tmp_interface2 as $demo )
                            {
                                if( $demo->type() == 'layer3' && count($demo->getLayer3IPv4Addresses()) > 0 )
                                {
                                    #print "INTERFACE: ".$demo->name()."\n";

                                    $snat_int_array[] = array($demo->name(), $demo->getLayer3IPv4Addresses()[0]);
                                }
                            }
                        }


                    }
                    //Todo: SVEN 20190513 how to find out ZONE information
                    /*
                    if ($zoneTo == "") {
                        $getDest = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$rule_lid' LIMIT 1;");
                        if ($getDest->num_rows == 1) {
                            $getDestData = $getDest->fetch_assoc();
                            $member_lid = $getDestData['member_lid'];
                            $table_name = $getDestData['table_name'];
                            $zoneTo = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                        }
                    }
                    */

                    //Todo: SVEN 201905 find interface related to specific zone
                    /*
                    $getInterface = $projectdb->query("SELECT name,unitname,unitipaddress FROM interfaces WHERE zone='$zoneTo' and unitipaddress!='' AND template='$template' LIMIT 1;");
                    if ($getInterface->num_rows == 1) {
                        $getInterfaceData = $getInterface->fetch_assoc();
                        $tp_sat_interface = $getInterfaceData['unitname'];
                        $tp_sat_ip_address = $getInterfaceData['unitipaddress'];
                    } else {
                        $tp_sat_interface = "";
                        $tp_sat_ip_address = "";
                    }
                    */
                }


                $tmp_nat_rule = $this->sub->natRules->find($RuleName);
                if( $tmp_nat_rule == null )
                {
                    if( $print )
                        print "create NATrule: '" . $RuleName . "''\n";
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($RuleName);


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
                        $tmp_nat_rule->to->addZone($tmp_tos[0]);
                    else
                        mwarning("security rule " . $tmp_rule->name() . " has more than 1 to Zone\n", null, FALSE);

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
                        $tmp_nat_rule->snathosts->addObject($tmp_address1);
                        $tmp_nat_rule->changeSourceNAT('dynamic-ip-and-port');
                    }
                    else
                    {
                        //Todo: SVEN 20190516 : set source nat interface and ip??
                        //set interface IP
                        //$tmp_nat_rule->snathosts->addObject($tmp_address1);
                        //$tmp_nat_rule->snatinterface = 'ethernet1/1';


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
                            $tmp_nat_rule->snatinterface = $snat_int_array[0][0];
                        }
                        if( isset($snat_int_array[0][1]) )
                        {

                            $tmp_value = explode('/', $snat_int_array[0][1]);
                            $tmp_address_snat_int = $this->sub->addressStore->all('value string.regex /' . $tmp_value[0] . '/');

                            if( !empty($tmp_address_snat_int) && count($tmp_address_snat_int ) == 1 && $tmp_address_snat_int[0]->getNetworkValue() == $tmp_value[0] )
                            {
                                #print "mip existing ip name ".$tmp_address1[0]->name()." value: ".$tmp_address1[0]->value()." add to rule\n";
                                $tmp_address_snat_int = $tmp_address_snat_int[0];
                            }
                            else
                            {
                                $new_name = $name_int = $this->truncate_names($this->normalizeNames($snat_int_array[0][1]));
                                $tmp_address_snat_int = $this->sub->addressStore->find($new_name);
                                if( $tmp_address_snat_int === null )
                                    $tmp_address_snat_int = $this->sub->addressStore->newAddress($new_name, 'ip-netmask', $snat_int_array[0][1]);
                            }

                            $tmp_nat_rule->snathosts->addObject($tmp_address_snat_int);

                        }

                        $tmp_nat_rule->changeSourceNAT('dynamic-ip-and-port');
                    }

                }
                else
                {
                    mwarning("NAT Rule name already available: " . $RuleName, null, FALSE);
                }
            }
        }
    }

    function generate_natdst( &$natdst_array)
    {
        global $projectdb;

        global $debug;
        global $print;

        $nat_lid = "";
        $addNatRule = array();
        $addZonesFrom = array();
        $addSources = array();
        $addDestination = array();


        foreach( $natdst_array as $natdst_entry )
        {

            $vsys_name = $natdst_entry[1];
            $rule_name = $natdst_entry[3];

            if( isset($natdst_entry[4]) )
                $ipaddress = $natdst_entry[4];
            else
                mwarning("natdst ip address not set", null, FALSE);

            if( isset($natdst_entry[5]) )
                $port = $natdst_entry[5];
            else
                mwarning("natdst ip address not set", null, FALSE);


            if( $vsys_name == "root" )
            {
                $this->template_vsys = $this->template->findVirtualSystem('vsys1');
                if( $this->template_vsys === null )
                {
                    derr("vsys: vsys1 could not be found ! Exit\n");
                }
            }
            else
            {
                // Did we find VSYS1 ?
                $this->template_vsys = $this->template->findVSYS_by_displayName($vsys_name);
                if( $this->template_vsys === null )
                {
                    derr("vsys: " . $vsys_name . " could not be found ! Exit\n");
                }
            }

            $tmp_rule = $this->sub->securityRules->find($rule_name);
            if( $tmp_rule == null )
            {
                mwarning('rule: ' . $rule_name . " not found | vsys: " . $this->sub->name() . " \n", null, FALSE);
                continue;
            }


            if( !isset($natdst_entry[6]) || (isset($natdst_entry[6]) && $natdst_entry[6] == "") )
            {

                $RuleName = "NAT dst " . $rule_name;

                $tmp_nat_rule = $this->sub->natRules->find($RuleName);
                if( $tmp_nat_rule == null )
                {
                    if( $print )
                        print "create NATrule: '" . $RuleName . "''\n";
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($RuleName);

                }
                else
                {
                    mwarning("NAT Rule name already available: " . $RuleName, null, FALSE);
                }
            }
            else
            {
                if( $natdst_entry[6] == "dip-id" )
                {
                    $nat_dip_id = " " . $natdst_entry[7];
                    $nat_dip_type = "DIP";
                }
                else
                {
                    $nat_dip_id = "";
                    $nat_dip_type = "interface";
                }

                $tmp_nat_rule = $this->sub->natRules->find("Nat " . $nat_dip_type . $nat_dip_id . " " . $rule_name);
                if( $tmp_nat_rule == null )
                {
                    mwarning("NATrule: Nat " . $nat_dip_type . $nat_dip_id . " " . $rule_name . " not found | vsys: " . $this->sub->name() . " \n", null, FALSE);
                    continue;
                }
            }


            if( $tmp_nat_rule != null )
            {
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
                    if( $debug )
                    {
                        if( $tmp_tos[0]->name() == 'any' )
                            print "validation needed if to zone is ANY\n";
                    }

                    $tmp_nat_rule->to->addZone($tmp_tos[0]);
                }
                else
                    mwarning("security rule " . $tmp_rule->name() . " has more than 1 to Zone\n", null, FALSE);

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


                //set NATDST
                //DST IP NAT
                //DST port NAT
                $tmp_address1 = $this->sub->addressStore->all('value string.regex /' . $ipaddress . '/');

                if( count($tmp_address1) > 1 )
                {
                    foreach( $tmp_address1 as $tmp_address )
                    {
                        if( $ipaddress == $tmp_address->getNetworkValue() )
                        {
                            $tmp_address1[0] = $tmp_address;
                            break;
                        }
                    }
                }
                elseif( $tmp_address1 == null )
                    #elseif( !empty( $tmp_address1 ) && count( $tmp_address1)  == 1 && $tmp_address1[0]->getNetworkValue() == $ipaddress )
                    #elseif( !empty( $tmp_address1 )  )
                {
                    $tmp_address1[0] = $this->sub->addressStore->find("H-" . $ipaddress);
                    if( $tmp_address1[0] == null )
                        $tmp_address1[0] = $this->sub->addressStore->newAddress("H-" . $ipaddress, 'ip-netmask', $ipaddress);
                }

                if( $port == "" )
                    $tmp_nat_rule->setDNAT($tmp_address1[0]);
                else
                    $tmp_nat_rule->setDNAT($tmp_address1[0], $port);
            }
        }
    }

// </editor-fold>

}

