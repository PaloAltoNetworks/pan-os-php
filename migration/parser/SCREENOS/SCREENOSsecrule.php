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


trait SCREENOSsecrule
{
    function rule_destination_parser($destination, $tmp_rule)
    {
        $myip = "";
        if( (strtolower($destination) == "any") or (strtolower($destination) == "any-ipv4") or (strtolower($destination) == "any-ipv6") )
        {
        }
        else
        {
            if( preg_match("/^MIP\(/", $destination) )
            {
                preg_match('#\((.*?)\)#', $destination, $match);
                $myip = $match[1];
                $destination = $this->truncate_names($this->normalizeNames($destination));
            }
            elseif( preg_match("/^VIP\(/", $destination) )
            {
                preg_match('#\((.*?)\)#', $destination, $match);
                $myip = $match[1];
                if( $this->ip_version($myip) == "noip" )
                {
                    #Then its interface name
                    mwarning("SVEN: need to find out interface part\n", null, FALSE);

                }
                $destination = $this->truncate_names($this->normalizeNames($destination));
            }
            else
            {
                $myip = "1.1.1.1";
                $destination = $this->truncate_names($this->normalizeNames($destination));
            }

            $tmp_dst = $this->sub->addressStore->find($destination);
            if( $tmp_dst !== null )
            {
                $tmp_rule->destination->addObject($tmp_dst);
            }
            else
            {
                print "search IP:".$myip." with name: ".$destination."\n";
                print "vsys: ".$this->sub->name()."\n";
                if( strpos( $myip, "/" ) === false )
                    $tmp_address1 = $this->sub->addressStore->all('value string.regex /' . $myip . '/');
                else
                    $tmp_address1 = array();

                if( !empty($tmp_address1) && count($tmp_address1) == 1 && $tmp_address1[0]->getNetworkValue() == $myip )
                {
                    #print "mip existing ip name ".$tmp_address1[0]->name()." value: ".$tmp_address1[0]->value()." add to rule\n";
                    $tmp_address1 = $tmp_address1[0];
                    $tmp_rule->destination->addObject($tmp_address1);
                }
                else
                {
                    print "can not find address object DST: " . $destination . " with ip " . $myip . "\n";
                    if( $myip == "1.1.1.1" )
                    {
                        #add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                        print "1.1.1.1 -> we defined it - can not find address object: " . $destination . " VSYS: " . $this->sub->name() . "\n";
                    }
                }
            }
        }
    }

    function rule_source_parser($src, $tmp_rule)
    {
        if( (strtolower($src) == "any") or (strtolower($src) == "any-ipv4") or (strtolower($src) == "any-ipv6") )
        {
        }
        else
        {
            if( preg_match("/^MIP\(/", $src) )
            {
                preg_match('#\((.*?)\)#', $src, $match);
                $myip = $match[1];
                $src = $this->truncate_names($this->normalizeNames($src));

            }
            else
            {
                $myip = "1.1.1.1";
                $src = $this->truncate_names($this->normalizeNames($src));
            }

            $tmp_src = $this->sub->addressStore->find($src);
            if( $tmp_src !== null )
            {
                $tmp_rule->source->addObject($tmp_src);
            }
            else
            {
                #print "search IP:".$myip." with name: ".$src."\n";
                #print "vsys: ".$this->sub->name()."\n";
                $tmp_address1 = $this->sub->addressStore->all('value string.regex /' . $myip . '/');

                if( !empty($tmp_address1) && count($tmp_address1) == 1 && $tmp_address1[0]->getNetworkValue() == $myip )
                {
                    #print "mip existing ip name ".$tmp_address1[0]->name()." value: ".$tmp_address1[0]->value()." add to rule\n";
                    $tmp_address1 = $tmp_address1[0];
                    $tmp_rule->source->addObject($tmp_address1);
                }
                else
                {
                    print "can not find address object SRC: " . $src . " with IP: " . $myip . "\n";
                    if( $myip == "1.1.1.1" )
                    {
                        #add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                        print "1.1.1.1 -> we defined it - can not find address object: " . $src . " VSYS: " . $this->sub->name() . " - " . $this->sub->alternativeName() . "\n";
                    }
                }
            }
        }
    }

    function rule_service_parser($service, $tmp_rule)
    {
        global $add_srv;
        global $debug;
        global $print;
        if( strtolower($service) == "any" )
        {
        }
        else
        {
            $service = $this->truncate_names($this->normalizeNames($service));

            $tmp_service = $this->sub->serviceStore->find($service);
            if( $tmp_service !== null )
            {
                $tmp_rule->services->add($tmp_service);
            }
            else
            {
                $tmp_service = $this->sub->serviceStore->find( "tmp-".$service);
                if( $tmp_service !== null )
                {
                    $tmp_rule->services->add($tmp_service);
                }
                else
                {
                    $found = FALSE;
                    foreach( $add_srv as $key => $tmp_srv )
                    {
                        if( $tmp_srv[0] == $service )
                        {
                            $tmp_service = $this->sub->serviceStore->find($tmp_srv[1]);
                            if( $tmp_service !== null )
                            {
                                $tmp_rule->services->add($tmp_service);
                                $found = TRUE;
                            }
                        }
                    }
                    #add_log2('error', 'Unknown Service Created', 'While reading RuleID [' . $lid . ']', $source, 'Please Fix the Protocol and Port or Replace it by an App-ID', 'objects', $member_lid, 'services');
                    if( !$found )
                    {
                        #$tmp_service = $this->sub->serviceStore->findOrCreate($service);
                        $tmp_service = $this->sub->serviceStore->newService($service, 'tcp', "65000");
                        $tmp_service->setDescription("FIX service - protocol / port / custom app");

                        if( $tmp_service !== null )
                        {
                            $tmp_rule->services->add($tmp_service);
                        }
                        if( $debug )
                            print "unknown Service: " . $service . " | service created with 'tcp/65000'\n";
                        return FALSE;
                    }
                }
            }
        }
        return TRUE;
    }


    function get_Security_Rules($screenos_config_file)
    {
        global $addDip;
        global $debug;
        global $print;
        global $natdst_array;

        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        $oldID = "";
        $extended_args = FALSE;
        $thecolor = 1;


        $vsys = "root";
        $v = null;
        $source = "";

        $badchar = array(
            // control characters
            chr(0), chr(1), chr(2), chr(3), chr(4), chr(5), chr(6), chr(7), chr(8), chr(9), chr(10),
            chr(11), chr(12), chr(13), chr(14), chr(15), chr(16), chr(17), chr(18), chr(19), chr(20),
            chr(21), chr(22), chr(23), chr(24), chr(25), chr(26), chr(27), chr(28), chr(29), chr(30),
            chr(31),
            // non-printing characters
            chr(127), chr(194), chr(160),
        );

        $tmp_rule = null;

        foreach( $screenos_config_file as $line => $names_line )
        {

            $names_line = trim($names_line);
            if( preg_match("/^set vsys /i", $names_line) )
            {
                $this->vsys_parser($names_line);
            }

            if( $extended_args == TRUE and $tmp_rule !== null )
            {

                if( preg_match("/^set dst-address negate/i", $names_line) )
                {
                    $tmp_rule->setDestinationIsNegated(TRUE);
                }
                elseif( preg_match("/^set dst-address /i", $names_line) )
                {
                    $dataExt = $this->name_preg_split($names_line);
                    $destination = $dataExt[2];

                    $this->rule_destination_parser($destination, $tmp_rule);

                }
                elseif( preg_match("/^set src-address negate/i", $names_line) )
                {
                    $tmp_rule->setSourceIsNegated(TRUE);
                }
                elseif( preg_match("/^set src-address /i", $names_line) )
                {
                    $dataExt = $this->name_preg_split($names_line);
                    $src = $dataExt[2];

                    $this->rule_source_parser($src, $tmp_rule);
                }

                elseif( preg_match("/^set service /i", $names_line) )
                {
                    $dataExt = $this->name_preg_split($names_line);
                    $service = $dataExt[2];

                    $this->rule_service_parser($service, $tmp_rule);
                }

                elseif( preg_match("/^set log session/i", $names_line) )
                {
                    $dataExt = $this->name_preg_split($names_line);
                    if( $dataExt[2] == "session-init" )
                    {

                        $tmp_rule->setLogStart(TRUE);
                    }
                    elseif( $dataExt[2] == "session-close" )
                    {
                        $tmp_rule->setLogEnd(TRUE);
                    }
                }
                elseif( preg_match("/^exit/i", $names_line) )
                {
                    $extended_args = FALSE;
                }
                else
                {
                    #print $names_line;
                }
            }

            if( preg_match("/^set policy id /i", $names_line) )
            {
                //replace the unwanted chars
                $names_line = str_replace($badchar, '', $names_line);
                $names_line = preg_replace('/[\x00-\x1F\x7F]/u', '', $names_line);

                //old
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s]*|[\s]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                //new
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $data = $this->name_preg_split($names_line);

                #$data2 = array_map('trim', $data);
                #$data2 = array_filter($data2, create_function('$value', 'return $value !== "";'));

                if( !isset($data[3]) )
                {
                    if( $names_line != "" )
                    {
                        print_r($data);
                        print "DATA: |" . $names_line . "| line:" . $line . "\n";
                    }
                    continue;
                }

                $policyID = $data[3];
                //print_r($data);

                if( $this->template_vsys === null )
                {

                    $this->template_vsys = $this->template->findVirtualSystem('vsys1');
                    if( $this->template_vsys === null )
                    {
                        derr("vsys: " . $vsys . " could not be found ! Exit\n");
                    }
                    #mwarning("no vsys found for rule: " . $policyID . "\n", null, false);
                    #continue;
                }

                if( $policyID != $oldID )
                {
                    $tmp_rule = $this->sub->securityRules->find('Rule ID ' . $policyID);
                    if( $tmp_rule == null )
                    {
                        if( $print )
                            print "create rule: 'Rule ID '" . $policyID . "\n";
                        $tmp_rule = $this->sub->securityRules->newSecurityRule('Rule ID ' . $policyID);
                    }
                    else
                        if( $debug )
                            print "rule already available\n";
                }
                else
                {
                    if( !isset($data[4]) )
                        $extended_args = TRUE;
                }
                $oldID = $policyID;
                if( is_object($tmp_rule) )
                {
                    if( isset($data[4]) and (($data[4] == "name") or ($data[4] == "from")) )
                    {
                        $next = 4;
                        if( $data[$next] == "name" )
                        {
                            #Add Tag
                            $color = "color" . $thecolor;
                            $tagname0 = $data[$next + 1];
                            if( $print )
                                print "     - Description: " . $tagname0 . "\n";
                            $tmp_rule->setDescription($tagname0);
                            $msplit = explode(",", $tagname0);

                            foreach( $msplit as $mkey => $mvalue )
                            {
                                $tagname = $this->truncate_tags($this->normalizeNames($mvalue));
                                if( $tagname != "" )
                                {
                                    $tmp_tag = $this->sub->tagStore->find($tagname);

                                    if( $tmp_tag == null )
                                    {
                                        $color = "color" . $thecolor;
                                        #$tag_id = $projectdb->insert_id;
                                        $tmp_tag = $this->sub->tagStore->createTag($tagname);
                                        $tmp_tag->setColor($color);

                                        if( $thecolor == 16 )
                                            $thecolor = 1;
                                        else
                                            $thecolor++;
                                    }

                                    if( $print )
                                        print"    Tag add: " . $tmp_tag->name() . "\n";
                                    $tmp_rule->tags->addTag($tmp_tag);
                                }
                            }

                            $next = 6;
                        }

                        if( $data[$next] == "from" )
                        {
                            $zoneFrom = $data[$next + 1];
                            if( strtolower($zoneFrom) != "global" )
                            {
                                $tmp_zone = $this->template_vsys->zoneStore->find($zoneFrom);
                                if( $tmp_zone == null )
                                    $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneFrom, 'layer3');
                                $tmp_rule->from->addZone($tmp_zone);
                            }
                        }


                        if( $data[$next + 2] == "to" )
                        {
                            $zoneTo = $data[$next + 3];
                            if( strtolower($zoneTo) != "global" )
                            {
                                $tmp_zone = $this->template_vsys->zoneStore->find($zoneTo);
                                if( $tmp_zone == null )
                                    $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneTo, 'layer3');
                                $tmp_rule->to->addZone($tmp_zone);
                            }
                        }


                        $src = $data[$next + 4];
                        $this->rule_source_parser($src, $tmp_rule);


                        $destination = $data[$next + 5];
                        $this->rule_destination_parser($destination, $tmp_rule);


                        $service = $data[$next + 6];
                        $srv_return = $this->rule_service_parser($service, $tmp_rule);

                        if( !$srv_return )
                        {
                            #print $names_line."\n";
                        }


                        # Read NAT SRC
                        if( (isset($data[$next + 7]) and isset($data[$next + 8])) and ($data[$next + 7] == "nat") and ($data[$next + 8] == "src") )
                        {
                            # there is snat
                            if( $data[$next + 9] == "dip-id" )
                            {
                                $dip_id = $data[$next + 10];
                                $addDip[] = array($source, $vsys, $tmp_rule->name(), 'dip-id', $dip_id);
                                $tmp_snat = "dip-id";
                                $next2 = $next + 10;
                                $posNat = $next + 11;
                            }
                            else
                            {
                                # Nat with the Interface from the TO Zone
                                $dip_id = "";
                                $addDip[] = array($source, $vsys, $tmp_rule->name(), 'interface', '');
                                $tmp_snat = "interface";
                                $next2 = $next + 9;
                                $posNat = $next + 9;
                            }

                            //Check coexisting NAT SRC and DST
                            if( isset($data[$posNat]) and ($data[$posNat] == "dst") and ($data[$posNat + 1] == "ip") )
                            {
                                $natdst_ip = $data[$posNat + 2];

                                if( $data[$posNat + 3] == "port" )
                                {
                                    $natdst_port = $data[$posNat + 4];
                                }
                                elseif( filter_var($data[$posNat + 3], FILTER_VALIDATE_IP) )
                                {
                                    $natdst_ip = $data[$posNat + 4] . "-" . $data[$posNat + 5];
                                    if( $data[$posNat + 4] == "port" )
                                    {
                                        $natdst_port = $data[$posNat + 5];
                                    }
                                }
                                else
                                {
                                    $natdst_port = '';
                                }


                                $splitaddress = explode("-", $natdst_ip);
                                $startip = $splitaddress[0];
                                if( isset($splitaddress[1]) )
                                {
                                    $endip = $splitaddress[1];
                                }
                                else
                                {
                                    $endip = $splitaddress[0];
                                }


                                if( $endip == $startip )
                                {
                                    $tmp_address = $this->sub->addressStore->all('value string.regex /' . $startip . "/");

                                    //Todo: 20190514 SVEN
                                    #print "ipnetmask".count( $tmp_address )."\n";

                                    #if( $tmp_address == null )
                                    if( !empty($tmp_address) && count($tmp_address ) == 1 && $tmp_address[0]->getNetworkValue() == $startip )
                                    {
                                        $tmp_address = $this->sub->addressStore->find("NATH-" . $startip);
                                        if( $tmp_address )
                                            $tmp_address = $this->sub->addressStore->newAddress("NATH-" . $startip, 'ip-netmask', $startip . "/32");
                                    }
                                }
                                else
                                {
                                    # Its a Range
                                    $tmp_address = $this->sub->addressStore->all('value string.regex /' . $startip . "-" . $endip . "/");


                                    #if( $tmp_address == null )
                                    if( !empty($tmp_address) && count($tmp_address ) == 1 && $tmp_address[0]->getNetworkValue() == $startip )
                                    {
                                        $tmp_address = $this->sub->addressStore->find("NATR-" . $startip . "-" . $endip);
                                        if( $tmp_address )
                                            $tmp_address = $this->sub->addressStore->newAddress("NATR-" . $startip . "-" . $endip, 'ip-range', $startip . "-" . $endip);
                                    }
                                }


                                $natdst_array[] = array($source, $vsys, 'template', $tmp_rule->name(), $natdst_ip, $natdst_port, $tmp_snat, $dip_id);
                            }
                        }


                        # Read NAT DST
                        if( (isset($data[$next + 7]) and isset($data[$next + 8])) and ($data[$next + 7] == "nat") and ($data[$next + 8] == "dst") and ($data[$next + 9] == "ip") )
                        {
                            $natdst_ip = $data[$next + 10];
                            $next2 = $next + 10;
                            if( $data[$next + 11] == "port" )
                            {
                                $natdst_port = $data[$next + 12];
                                $next2 = $next + 12;
                            }
                            elseif( filter_var($data[$next + 11], FILTER_VALIDATE_IP) )
                            {
                                $natdst_ip = $data[$next + 10] . "-" . $data[$next + 11];
                                $next2 = $next + 11;
                                if( $data[$next + 12] == "port" )
                                {
                                    $natdst_port = $data[$next + 13];
                                    $next2 = $next + 13;
                                }
                            }
                            else
                            {
                                //                        echo "NEXT+ $next+11: ".$names_line."\n";
                                $natdst_port = '';
                            }
                            $natdst_array[] = array($source, $vsys, 'template', $tmp_rule->name(), $natdst_ip, $natdst_port, '', '');
                        }

                        if( preg_match("/\bpermit\b/", $names_line) )
                        {
                            $action = "allow";
                            $tmp_rule->setAction($action);
                        }
                        elseif( preg_match("/\bdeny\b/", $names_line) )
                        {
                            $action = "deny";
                            $tmp_rule->setAction($action);
                        }
                        elseif( preg_match("/\breject\b/", $names_line) )
                        {
                            $action = "deny";
                            $tmp_rule->setAction($action);
                        }
                        else
                        {
                            //Todo: SVEn 20190514 investigate
                            //mwarning("No Action found:".$names_line."\n", null, false);
                            $action = "deny";
                            $tmp_rule->setAction($action);

                            if( preg_match("/tunnel vpn/", $names_line) )
                            {
                                //Todo: SVEn 20190514 investigate
                                //mwarning("SVEN: tunnel vpn - check ", null, false);
                            }
                        }
                    }
                    elseif( isset($data[4]) and ($data[4] == "disable") )
                    {
                        $tmp_rule->setDisabled(TRUE);
                    }
                    elseif( isset($data[4]) and ($data[4] == "application") )
                    {
                        $app = $data[5];
                        if( $app == "IGNORE" )
                        {

                        }
                        else
                        {
                            #add_log2('warning', 'Phase 5: Reading Security Rules', 'Seen Application (ALG:' . $data[5] . ') in Rule [' . $lid . ']', $source, 'Add the right APP-id to this Rule.','rules',$lid,'security_rules');

                            //Todo: 20190514 SVEN how to implement???
                            if( $debug )
                                mwarning("Seen Application (ALG:" . $data[5] . ") in Rule [" . $tmp_rule->name() . "]\n", null, FALSE);
                        }
                    }
                    elseif( isset($data[4]) and (($data[4] == "av") or ($data[4] == "attack")) )
                    {
                        #add_log2('1', 'Phase 5: Reading Security Rules', 'Attack or AV options are omited in Rule [' . $lid . ']', $source, 'No Action Required.','rules',$lid,'security_rules');
                        if( $debug )
                            mwarning("Attack or AV optins are omitted in Rule [" . $tmp_rule->name() . "]\n", null, FALSE);
                    }
                }
            }


            elseif( preg_match("/^set policy global id /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $policyID = $data[4];


                if( $this->template_vsys === null )
                {

                    $this->template_vsys = $this->template->findVirtualSystem('vsys1');
                    if( $this->template_vsys === null )
                    {
                        derr("vsys: " . $vsys . " could not be found ! Exit\n");
                    }
                    #mwarning("no vsys found for rule: " . $policyID . "\n", null, false);
                    #continue;
                }

                if( $policyID != $oldID )
                {
                    $tmp_rule = $this->sub->securityRules->find('Rule ID ' . $policyID);
                    if( $tmp_rule == null )
                    {
                        if( $print )
                            print "create rule: 'Rule ID " . $policyID . "'\n";
                        $tmp_rule = $this->sub->securityRules->newSecurityRule('Rule ID ' . $policyID);
                    }
                    else
                        if( $debug )
                            print "rule already available\n";
                }
                else
                {
                    if( !isset($data[5]) )
                    {
                        $extended_args = TRUE;
                    }
                }

                $oldID = $policyID;
                if( is_object($tmp_rule) )
                {
                    if( isset($data[5]) and (($data[5] == "name") or ($data[5] == "from")) )
                    {

                        $next = 5;
                        if( $data[$next] == "name" )
                        {
                            #Add Tag
                            $color = "color" . $thecolor;
                            $tagname0 = $data[$next + 1];
                            if( $print )
                                print "     - Description: " . $tagname0 . "\n";
                            $tmp_rule->setDescription($tagname0);
                            $msplit = explode(",", $tagname0);
                            foreach( $msplit as $mkey => $mvalue )
                            {


                                $tagname = $this->truncate_tags($this->normalizeNames($mvalue));

                                if( $tagname != "" )
                                {
                                    $tmp_tag = $this->sub->tagStore->find($tagname);

                                    if( $tmp_tag == null )
                                    {
                                        $color = "color" . $thecolor;
                                        #$tag_id = $projectdb->insert_id;
                                        $tmp_tag = $this->sub->tagStore->createTag($tagname);
                                        $tmp_tag->setColor($color);

                                        if( $thecolor == 16 )
                                            $thecolor = 1;
                                        else
                                            $thecolor++;
                                    }
                                    if( $print )
                                        print"    Tag add: " . $tmp_tag->name() . "\n";
                                    $tmp_rule->tags->addTag($tmp_tag);
                                }
                            }

                            $next = 7;
                        }

                        if( $data[$next] == "from" )
                        {
                            $zoneFrom = $data[$next + 1];
                            if( strtolower($zoneFrom) == "global" )
                            {
                                $tagname = "Global Rule";
                                $tmp_tag = $this->sub->tagStore->find($tagname);

                                if( $tmp_tag == null )
                                {
                                    $color = "color" . $thecolor;
                                    $tmp_tag = $this->sub->tagStore->createTag($tagname);
                                    $tmp_tag->setColor($color);

                                    if( $thecolor == 16 )
                                        $thecolor = 1;
                                    else
                                        $thecolor++;
                                }

                                $tmp_rule->tags->addTag($tmp_tag);
                            }
                            else
                            {
                                $tmp_zone = $this->template_vsys->zoneStore->find($zoneFrom);
                                if( $tmp_zone == null )
                                    $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneFrom, 'layer3');
                                $tmp_rule->from->addZone($tmp_zone);
                            }
                        }

                        if( $data[$next + 2] == "to" )
                        {
                            $zoneTo = $data[$next + 3];
                            if( strtolower($zoneTo) == "global" )
                            {

                            }
                            else
                            {
                                $tmp_zone = $this->template_vsys->zoneStore->find($zoneTo);
                                if( $tmp_zone == null )
                                    $tmp_zone = $this->template_vsys->zoneStore->newZone($zoneTo, 'layer3');
                                $tmp_rule->to->addZone($tmp_zone);
                            }
                        }

                        $src = $data[$next + 4];
                        $this->rule_source_parser($src, $tmp_rule);

                        $destination = $data[$next + 5];
                        $this->rule_destination_parser($destination, $tmp_rule);

                        $service = $data[$next + 6];
                        $this->rule_service_parser($service, $tmp_rule);


                        if( preg_match("/\bpermit\b/", $names_line) )
                        {
                            $action = "allow";
                            $tmp_rule->setAction($action);
                        }
                        elseif( preg_match("/\bdeny\b/", $names_line) )
                        {
                            $action = "deny";
                            $tmp_rule->setAction($action);
                        }
                        elseif( preg_match("/\breject\b/", $names_line) )
                        {
                            $action = "deny";
                            $tmp_rule->setAction($action);
                        }
                        else
                        {
                            //Todo: SVEn 20190514 investigate
                            //mwarning("No Action found:".$names_line."\n", null, false);
                            $action = "deny";
                            $tmp_rule->setAction($action);

                            if( preg_match("/tunnel vpn/", $names_line) )
                            {
                                //Todo: SVEn 20190514 investigate
                                //mwarning("SVEN: tunnel vpn - check ", null, false);
                            }
                        }
                    }
                    elseif( isset($data[5]) and ($data[5] == "disable") )
                    {
                        $tmp_rule->setDisabled(TRUE);
                    }
                    elseif( isset($data[5]) and ($data[5] == "application") )
                    {
                        $app = $data[6];
                        if( $app == "IGNORE" )
                        {
                        }
                        else
                        {
                            #add_log2('warning', 'Phase 5: Reading Security Rules', 'Seen Application (ALG:' . $data[6] . ') in Rule [' . $lid . ']', $source, 'Add the right APP-id to this Rule.', 'rules', $lid, 'security_rules');
                            if( $debug )
                                mwarning("Seen Application (ALG:" . $data[6] . ") in Rule [" . $tmp_rule->name() . "]\n", null, FALSE);
                        }
                    }
                    elseif( isset($data[5]) and (($data[5] == "av") or ($data[5] == "attack")) )
                    {
                        #add_log2('1', 'Phase 5: Reading Security Rules', 'Attack or AV options are omited in Rule [' . $lid . ']', $source, 'No Action Required.', 'rules', $lid, 'security_rules');
                        if( $debug )
                            mwarning("Attack or AV optins are omitted in Rule [" . $tmp_rule->name() . "]\n", null, FALSE);
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

}

