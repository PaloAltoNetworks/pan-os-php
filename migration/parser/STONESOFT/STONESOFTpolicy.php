<?php



trait STONESOFTpolicy
{



    public function add_policy( $configRoot)
    {
        //TCP services
        #$service_tcps = $configuration->xpath("//service_tcp");


        $policyCounter = 0;
        $policyCounterNAT = 0;
        $rule_missing_objects = array();

        $fw_sub_policies = $configRoot->getElementsByTagName('fw_sub_policy');
        print "count:(fw_sub_policy): " . count($fw_sub_policies) . "\n";


        foreach( $fw_sub_policies as $fw_sub_policy )
        {
            if( $fw_sub_policy->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = DH::findAttribute('name', $fw_sub_policy);
            $name = $this->subRule_name($name);

            $comment = DH::findAttribute('comment', $fw_sub_policy);


            print "\n\n################################################\n";
            print "\nFW-SUB-POLICY NAME: ".$name."\n";

            $tmp_tag = $this->sub->tagStore->find($name);
            if( $tmp_tag == null )
                $tmp_tag = $this->sub->tagStore->createTag($name);

            $tmp_tag2 = $this->sub->tagStore->find("fw_sub_policy");
            if( $tmp_tag2 == null )
                $tmp_tag2 = $this->sub->tagStore->createTag("fw_sub_policy");

            $this->create_policy( $fw_sub_policy, $tmp_tag, $tmp_tag2, $policyCounter, $policyCounterNAT,"SUBFWPOLICY", $rule_missing_objects );

        }

        print "################################################\n";

        $fw_policies = $configRoot->getElementsByTagName('fw_policy');
        print "count:(fw_policy): " . count($fw_policies) . "\n";

        foreach( $fw_policies as $fw_policy )
        {
            if( $fw_policy->nodeType != XML_ELEMENT_NODE )
                continue;


            $name = DH::findAttribute('name', $fw_policy);
            $comment = DH::findAttribute('comment', $fw_policy);
            $inspection_policy_ref = DH::findAttribute('inspection_policy_ref', $fw_policy);
            $template_policy_ref = DH::findAttribute('template_policy_ref', $fw_policy);



            ############################################################
            ############################################################
            //RESTRICTION

            if( !empty($this->filtered_policy) && !array_key_exists( $name, $this->filtered_policy ) )
                continue;
            ############################################################
            ############################################################


            print "\n\n################################################\n";
            print "FWPOLICY NAME: ".$name."\n";

            $tmp_tag = $this->sub->tagStore->find($name);
            if( $tmp_tag == null )
            {
                print "create Tag: ".$name."\n";
                $tmp_tag = $this->sub->tagStore->createTag($name);
            }


            $tmp_tag2 = $this->sub->tagStore->find("fw_policy");
            if( $tmp_tag2 == null )
            {
                print "create Tag:  fw_policy\n";
                $tmp_tag2 = $this->sub->tagStore->createTag("fw_policy");
            }


            $this->create_policy( $fw_policy, $tmp_tag, $tmp_tag2, $policyCounter,$policyCounterNAT, "FWPOLICY", $rule_missing_objects );

        }



        $subrules_array = $this->sub->securityRules->rules( '(tag has fw_sub_policy)' );
        foreach( $subrules_array as $subrule )
        {
            /**
             * example of documenting a variable's type
             * @var SecurityRule $subrule
             */

            print " remove subrule: ".$subrule->name()."\n";
            $subrule->owner->remove( $subrule );
        }




        print "\n\npolicy count: for '".$name."': ".$policyCounter."\n";
        print "\n\npolicyNAT count: for '".$name."': ".$policyCounterNAT."\n";

        print_r( $rule_missing_objects );

    }


    public function create_policy( $fw_policy, $tmp_tag, $tmp_tag2, &$policyCounter, &$policyCounterNAT, $nameType, &$rule_missing_objects )
    {
        /** @var DeviceGroup|VirtualSystem $v */



//access_entry
        $access_entry = DH::findFirstElementOrCreate('access_entry', $fw_policy);
        $access_rules = $access_entry->getElementsByTagName('rule_entry');





        print "count: ".count( $access_rules )."\n";
        $skip_counter = 0;

        foreach( $access_rules as $access_rule )
        {
            $node = DH::findFirstElement('comment_rule', $access_rule);
            if( $node )
            {
                #print "skip rule\n";
                $skip_counter++;
                continue;
            }

            $tag = DH::findAttribute('tag', $access_rule);
            $is_disabled = DH::findAttribute('is_disabled', $access_rule);
            $comment = DH::findAttribute('comment', $access_rule);

            $rulename = $this->sub->securityRules->findAvailableName($tag);


            print "\n- - - - - - - - - - - - - - - - - - - - - - - - \n";
            print " - create ".$nameType." sec policy: " . $rulename . "\n";
            $tmprule = $this->sub->securityRules->newSecurityRule($rulename);

            $tmprule->tags->addTag($tmp_tag);
            $tmprule->tags->addTag($tmp_tag2);

            if( $comment != "" )
            {
                print "     - set Description: ".$comment."\n";
                $tmprule->setDescription( $comment );
            }


            if( $is_disabled == "true" )
            {
                print "     - disable rule\n";
                $tmprule->setDisabled( true );
            }

            $access_rule = DH::findFirstElementOrCreate('access_rule', $access_rule);

            $tmprule = $this->match_condition( $access_rule, $tmprule );


            $access_rule_action = DH::findFirstElementOrCreate('action', $access_rule);

            $action_type = DH::findAttribute('type', $access_rule_action);
            #print "ACTION: ".$action_type."\n";
            if( $action_type != "allow"
                && $action_type != "discard"
                && $action_type != ""
                && $action_type != "blacklist"
                && $action_type != "jump"
                && $action_type != "refuse"
            )
            {
                print "ACTION: ".$action_type."\n";
                derr( "STOP" );
            }





            if( $action_type == "jump"  )
            {
                if( $nameType == "FWPOLICY" )
                {

                    //          <action subrule_class_id="97" subrule_ref="FSP.GNRL.McAfee.ePO" type="jump"/>
                    $subrule_class_id = DH::findAttribute('subrule_class_id', $access_rule_action);
                    $subrule_ref = DH::findAttribute('subrule_ref', $access_rule_action);

                    $subrule_ref = $this->subRule_name($subrule_ref);


                    print "\n\nSUBRULE TAG: " . $subrule_ref . "\n";

                    $tag_search = $this->sub->tagStore->find($subrule_ref);

                    if( $tag_search != null )
                    {
                        if( strpos( $subrule_ref, "(" ) !== False || strpos( $subrule_ref, "(" ) )
                        {
                            PH::print_stdout();
                            PH::print_stdout("----------------------------------------------");
                            PH::print_stdout("please change in name the following characters '(' and ')' with e.g.: '_': ".$subrule_ref);
                            derr("'(' or ')' are not allowed in the rule tag query, please replace in original configuration file", null, False);
                        }

                        $query = '(tag has fw_sub_policy) and (tag has ' . $subrule_ref . ')';
                        PH::print_stdout( "- query: ".$query);
                        $subrules_array = $this->sub->securityRules->rules( $query);
                        $old_tmp_subrule = $tmprule;
                        foreach( $subrules_array as $subrule )
                        {
                            //$rule,  $action = 'none', $isAPI = false, $print = false )
                            if( $subrule->includedInRule( $tmprule ) )
                            {
                                $tmp_subrule_name = $tmprule->name() . "_" . $subrule->name();

                                print " - clone: " . $subrule->name() . " - new name: " . $tmp_subrule_name . " - move after: " . $old_tmp_subrule->name() . "\n";;
                                $tmp_subrule = $subrule->owner->cloneRule($subrule, $tmp_subrule_name);
                                $tmp_subrule->owner->moveRuleAfter($tmp_subrule, $old_tmp_subrule);

                                if( $tmp_subrule->destination->isAny() )
                                {
                                    print "DST set from main rule: ".$tmp_subrule_name."\n";
                                    foreach( $tmprule->destination->getall() as $dst)
                                        $tmp_subrule->destination->addObject($dst);
                                }
                                if( $tmp_subrule->source->isAny() )
                                {
                                    print "SRC set from main rule: ".$tmp_subrule_name."\n";
                                    foreach( $tmprule->source->getall() as $srv)
                                        $tmp_subrule->source->addObject($srv);
                                }
                                if( $tmp_subrule->services->isAny() )
                                {
                                    print "service set from main rule: ".$tmp_subrule_name."\n";
                                    foreach( $tmprule->services->all() as $src)
                                        $tmp_subrule->services->add($src);
                                }

                                $tmp_tag2 = $this->sub->tagStore->find("fw_sub_policy");
                                $tmp_subrule->tags->removeTag($tmp_tag2);

                                $tmp_tag2 = $this->sub->tagStore->find("fixed-fw_sub_policy");
                                if( $tmp_tag2 == null )
                                    $tmp_tag2 = $this->sub->tagStore->createTag("fixed-fw_sub_policy");
                                $tmp_subrule->tags->addTag($tmp_tag2);


                                $old_tmp_subrule = $tmp_subrule;
                            }
                        }


                        $tmprule->setDisabled(TRUE);
                    }
                    else
                        mwarning("tag not found: " . $subrule_ref);

                }
                else
                {
                    mwarning( "action = jump but subpolicy\n" );
                }

            }
            elseif( $action_type == "allow")
            {
                
            }
            elseif( $action_type == "discard" || $action_type == "refuse" )
            {
                print "     - set rule action: DENY\n";
                $tmprule->setAction( "deny" );
            }
            elseif( $action_type == "blacklist" )
            {
                print "     - set rule action: DENY\n";
                $tmprule->setAction( "deny" );
            }
        }





//nat_entry
        $nat_entry = DH::findFirstElementOrCreate('nat_entry', $fw_policy);
        $nat_rules = $nat_entry->getElementsByTagName('rule_entry');

        print "- - - - - \n";

        print "countNAT: ".count( $nat_rules )."\n";
        $skip_counter_nat = 0;

        foreach( $nat_rules as $nat_rule )
        {
            $node = DH::findFirstElement('comment_rule', $nat_rule);
            if( $node )
            {
                #print "skip rule\n";
                $skip_counter_nat++;
                continue;
            }

            $tag = DH::findAttribute('tag', $nat_rule);

            $is_disabled = DH::findAttribute('is_disabled', $nat_rule);
            $comment = DH::findAttribute('comment', $nat_rule);

            $rulename = $this->sub->natRules->findAvailableName($tag);
            print " - create nat policy: " . $rulename . "\n";
            $tmprule = $this->sub->natRules->newNatRule($rulename);


            $tmprule->tags->addTag($tmp_tag);

            if( $comment != "" )
            {
                print "     - set Description: ".$comment."\n";
                $tmprule->setDescription( $comment );
            }


            if( $is_disabled == "true" )
            {
                print "     - disable rule\n";
                $tmprule->setDisabled( true );
            }

            $nat_rule = DH::findFirstElementOrCreate('nat_rule', $nat_rule);

            $tmprule = $this->match_condition( $nat_rule, $tmprule );

            //todo; swaschkut 20210218 add NAT condition SNAT DNAT and other settings;

            /*
            <nat_rule valid_fw_ref="ANY">
              <match_part>
                <match_sources>
                  <match_source_ref type="network_element" value="ANY"/>
                </match_sources>
                <match_destinations>
                  <match_destination_ref type="network_element" value="SLB.MIT.mitweb.renfe.sir"/>
                </match_destinations>
                <match_services>
                  <match_service_ref type="service" value="ANY"/>
                </match_services>
              </match_part>
              <action type="allow"/>
              <option>
                <log_policy closing_mode="true" log_level="undefined" mss_enforce="false"/>
                <nat_dst>
                  <static_nat generate_arp="false">
                    <packet_description ne_ref="SLB.MIT.mitweb.renfe.sir"/>
                    <packet_description_new ne_ref="SLB.FByMT.mitweb.sir.renfe.es"/>
                  </static_nat>
                </nat_dst>
              </option>
            </nat_rule>

            <option>
                <log_policy closing_mode="true" log_level="undefined" mss_enforce="false"/>
                <nat_src>
                  <dynamic_nat generate_arp="false">
                    <packet_description first_port="1024" last_port="65535" ne_ref="NAT.CFW.MNGT.RINT01"/>
                  </dynamic_nat>
                </nat_src>
              </option>
             */

            $option = DH::findFirstElementOrCreate('option', $nat_rule);
            $nat_dst = DH::findFirstElement('nat_dst', $option);
            $nat_src = DH::findFirstElement('nat_src', $option);

            if( $nat_dst )
            {
                $nat_dst_static = DH::findFirstElement('static_nat', $nat_dst);
                if( $nat_dst_static )
                {
                    $nat_dst_static_packet = DH::findFirstElement('packet_description_new', $nat_dst_static);

                    $tmp_addr_name = DH::findAttribute('ne_ref', $nat_dst_static_packet);
                    $tmp_addr_name = $this->truncate_names( $this->normalizeNames( $tmp_addr_name ) );

                    $tmp_dnat_object = $this->sub->addressStore->find($tmp_addr_name);

                    if( $tmp_dnat_object !==null )
                    {
                        print "     - set DNAT: object: ".$tmp_addr_name."\n";
                        $tmprule->setDNAT( $tmp_dnat_object );
                    }
                    else
                        print "      - object: ".$tmp_addr_name." not found - DNAT could not set\n";

                }

            }

            if( $nat_src )
            {
                $nat_src_dynamic = DH::findFirstElement('dynamic_nat', $nat_src);
                if( $nat_src_dynamic )
                {
                    $nat_src_dynamic_packet = DH::findFirstElement('packet_description', $nat_src_dynamic);

                    $tmp_addr_name = DH::findAttribute('ne_ref', $nat_src_dynamic_packet);
                    if( $tmp_addr_name == false )
                    {
                        $tmp_addr_name = DH::findAttribute('min_ip', $nat_src_dynamic_packet);
                        $tmp_addr_mask = DH::findAttribute('netmask', $nat_src_dynamic_packet);

                        $mask =CIDR::netmask2cidr($tmp_addr_mask);
                        $tmp_addr_name = $tmp_addr_name."m".$mask;

                        $value = $tmp_addr_name."/".$mask;

                        $tmp_addr_name = $this->truncate_names( $this->normalizeNames( $tmp_addr_name ) );
                        $tmp_snat_object = $this->sub->addressStore->find($tmp_addr_name);

                        if( $tmp_snat_object ==null )
                        {
                            print "\n - create address object: " . $tmp_addr_name . " Value: ".$value."\n";
                            $tmp_snat_object = $this->sub->addressStore->newAddress($tmp_addr_name, "ip-netmask", $value );
                        }
                    }
                    else
                    {
                        $tmp_addr_name = $this->truncate_names( $this->normalizeNames( $tmp_addr_name ) );
                        $tmp_snat_object = $this->sub->addressStore->find($tmp_addr_name);
                    }




                    if( $tmp_snat_object !==null )
                    {
                        print "     - set SNAT: object: ".$tmp_addr_name."\n";
                        $tmprule->snathosts->addObject($tmp_snat_object);
                        $tmprule->changeSourceNAT('dynamic-ip-and-port');
                    }

                }
            }
        }




        print "\n  - ACCESS: count: ".count( $access_rules )." | skipped HEADER: ".$skip_counter." | NAT: count: ".count( $nat_rules )." | skipped HEADER: ".$skip_counter_nat."\n";
        $policyCounter += ( count( $access_rules ) - $skip_counter);
        $policyCounterNAT += ( count( $nat_rules ) - $skip_counter_nat);


        $newdoc = new DOMDocument;
        $node = $newdoc->importNode($fw_policy, TRUE);
        $newdoc->appendChild($node);
        $html = $newdoc->saveHTML();

        #if( $name == "FGP.RINT01" )
        #{
        #print $html;
        #}


    }

    function subRule_name( $subRuleName)
    {
        $subRuleName = str_replace("(", "_", $subRuleName);
        $subRuleName = str_replace(")", "_", $subRuleName);
        return $subRuleName;
    }

    function match_condition( $access_rule, $tmprule)
    {
        $access_rule_match_part = DH::findFirstElementOrCreate('match_part', $access_rule);
        foreach( $access_rule_match_part->childNodes as $childNode )
        {
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;


            if( $childNode->nodeName == "match_sources" )
            {
                $type = "source";
            }
            elseif( $childNode->nodeName == "match_destinations" )
            {
                $type = "destination";
            }
            elseif( $childNode->nodeName == "match_services" )
            {
                $type = "service";
            }

            foreach( $childNode->childNodes as $childNode2 )
            {
                if( $childNode2->nodeType != XML_ELEMENT_NODE )
                    continue;

                $type_type = DH::findAttribute('type', $childNode2);
                $value = DH::findAttribute('value', $childNode2);

                #print "TYPE: '". $type."' with objecttype: '".$type_type ."' searchfor: '".$value."'\n";

                if( $type == "source" || $type == "destination" )
                {
                    $value = $this->truncate_names( $this->normalizeNames( $value ) );

                    if( $value == "ANY" || $value == "" )
                        continue;

                    $tmpaddress = $this->sub->addressStore->find($value);

                    if( $tmpaddress !== null )
                    {
                        print "     - add ".$type.": " . $tmpaddress->name() . "\n";
                        $tmprule->$type->addObject($tmpaddress);
                    }
                    else
                    {
                        $rule_missing_objects[ $type ][ $value ] = $value;
                        mwarning("can not find object: " . $value, null, FALSE);
                    }
                }
                elseif( $type == "service" )
                {
                    $value = $this->truncate_names( $this->normalizeNames( $value ) );

                    if( $value == "ANY" || $value == "" )
                        continue;

                    $tmpservice = $this->sub->serviceStore->find($value);
                    if( $tmpservice == null )
                        $tmpservice = $this->sub->serviceStore->find("tmp-" . $value);

                    if( $tmpservice != null )
                    {
                        print "     - add services: " . $tmpservice->name() . "\n";
                        if( $tmprule->isSecurityRule() )
                            $tmprule->services->add($tmpservice);
                        elseif( $tmprule->isNatRule() )
                        {
                            $tmprule->setService($tmpservice);
                        }
                    }
                    else
                    {
                        $rule_missing_objects[ $type ][ $value ] = $value;
                        mwarning("can not find service: " . $value, null, FALSE);
                    }
                }


            }
        }

        return $tmprule;
    }
}