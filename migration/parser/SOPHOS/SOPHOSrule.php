<?php

trait SOPHOSrule
{
    public function rule($master_array, $rulesort)
    {
        foreach( $rulesort as $rule )
        {

            foreach( $master_array['packetfilter'] as $policy )
            {

                #print "NAME:|".$rule."|\n";
                #print "REF:|".$policy['_ref']."|\n";
                $rule_ref = str_replace(',', "", $policy['_ref']);
                if( $rule == $rule_ref )
                {
                    #print_r( $policy );


                    $name_length = 63;
                    if( strlen($policy['name']) > $name_length )
                    {
                        print "\n\nrule name must cut to length " . $name_length . "| new rule name: '" . substr($policy['name'], 0, $name_length - 1) . "'\n";
                        $rule_name = substr($policy['name'], 0, $name_length - 1);
                    }
                    else
                    {
                        print "\nname: " . $policy['name'] . "\n";
                        $rule_name = str_replace(',', "", $policy['name']);
                    }
                    $rule_name = str_replace('(', "", $rule_name);
                    $rule_name = str_replace(')', "", $rule_name);
                    $rule_name = str_replace('+', "", $rule_name);
                    $rule_name = str_replace('Ù', "U", $rule_name);
                    $rule_name = str_replace('ä', "ae", $rule_name);
                    $rule_name = str_replace('@', "et", $rule_name);


                    $rule_name = rtrim($rule_name);


                    $tmp_rule = $this->sub->securityRules->newSecurityRule($rule_name);
                    print PH::boldText("generate new Rule:" . $rule_name . "\n");


                    if( strpos($policy['comment'], ",") !== 0 )
                    {
                        //set rule comment
                        print "- set comment: " . $policy['comment'] . "\n";
                        $rule_comment = str_replace(',', "", $policy['comment']);
                        $rule_comment = str_replace('(', "", $rule_comment);
                        $rule_comment = str_replace(')', "", $rule_comment);
                        $tmp_rule->setDescription($rule_comment);
                    }

                    if( strpos($policy['action'], "accept") !== FALSE )
                    {
                        //set rule action => allow
                        print "- set action: " . $policy['action'] . "\n";
                        $rule_action = str_replace(',', "", $policy['action']);
                        $tmp_rule->setAction('allow');
                    }
                    else
                    {
                        //set rule action => deny
                        print "- set action: " . $policy['action'] . "\n";
                        $tmp_rule->setAction('deny');
                    }

                    //for src/dst/service
                    //explode based on ","
                    //foreach entry search relevant

                    $tmp_found = FALSE;
                    $src_array = explode(",", $policy['sources']);
                    print "- set sources: ";
                    foreach( $src_array as $source )
                    {
                        #print "src_ref:".$source."\n";
                        foreach( $master_array['network'] as $master_address )
                        {
                            #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                            if( str_replace(',', "", $master_address['_ref']) == $source )
                            {
                                #print "FOUND address".$master_address['name']."\n";
                                //search object in addressstore
                                $tmp_name = str_replace(',', "", $master_address['name']);
                                $tmp_address = $this->sub->addressStore->findOrCreate($tmp_name);
                                // add to rule source
                                $tmp_rule->source->addObject($tmp_address);
                                print "$tmp_name";
                                $tmp_found = TRUE;
                                break;
                            }
                            elseif( $master_address['_ref'] == "REF_NetworkAny" )
                            {
                                $tmp_found = TRUE;
                                break;
                            }
                            else
                            {
                                #print "NOT FOUND\n";
                            }

                        }
                        if( !$tmp_found )
                        {
                            if( strpos($source, "Any") === FALSE )
                                mwarning("   - network object not found:" . $source . "\n");
                            else
                                print "ANY\n";
                        }
                    }
                    #print "\n";

                    $tmp_found = FALSE;
                    $dst_array = explode(",", $policy['destinations']);
                    print "- set destinations: ";
                    foreach( $dst_array as $destination )
                    {
                        #print "dst_ref:".$destination."\n";
                        foreach( $master_array['network'] as $master_address )
                        {
                            #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                            if( str_replace(',', "", $master_address['_ref']) == $destination )
                            {
                                #print "FOUND address".$master_address['name']."\n";
                                //search object in addressstore
                                $tmp_name = str_replace(',', "", $master_address['name']);
                                $tmp_address = $this->sub->addressStore->findOrCreate($tmp_name);
                                // add to rule destination
                                $tmp_rule->destination->addObject($tmp_address);
                                print "$tmp_name";
                                $tmp_found = TRUE;
                                break;
                            }
                            elseif( $master_address['_ref'] == "REF_NetworkAny" )
                            {
                                $tmp_found = TRUE;
                                break;
                            }
                            else
                            {
                                #print "NOT FOUND\n";
                            }
                        }
                        if( !$tmp_found )
                        {
                            if( strpos($destination, "Any") === FALSE )
                                mwarning("   - network object not found:" . $destination . "\n");
                            else
                                print "ANY\n";
                        }
                    }
                    print "\n";

                    $tmp_found = FALSE;
                    $srv_array = explode(",", $policy['services']);
                    print "- set services: ";
                    foreach( $srv_array as $service )
                    {
                        #print "srv_ref:".$service."\n";
                        foreach( $master_array['service'] as $master_service )
                        {
                            if( str_replace(',', "", $master_service['_ref']) == $service )
                            {
                                #print "FOUND service".$master_service['name']."\n";
                                //search object in servicestore
                                $tmp_name = str_replace(',', "", $master_service['name']);

                                $tmp_service = $this->sub->serviceStore->findOrCreate($tmp_name);
                                // add to rule service
                                $tmp_rule->services->add($tmp_service);
                                print "$tmp_name ";
                                $tmp_found = TRUE;
                                break;
                            }
                            elseif( $master_service['_ref'] == "REF_ServiceAny" )
                            {
                                $tmp_found = TRUE;
                                break;
                            }
                            else
                            {
                                #print "NOT FOUND\n";
                            }

                        }
                        if( !$tmp_found )
                        {
                            if( strpos($service, "Any") === FALSE )
                                mwarning("   - service object not found:" . $service . "\n");
                            else
                                print "ANY";
                        }
                    }
                    print "\n";

                    #print "- set tag: ";
                    $tag = $policy['group'];
                    $tag = str_replace(',', "", $tag);
                    #print "tag:|" . $tag . "|\n";
                    if( $tag != "" )
                    {
                        $tmp_tag = $this->sub->tagStore->findOrCreate($tag);
                        $tmp_rule->tags->addTag($tmp_tag);
                        print "- set tag: " . $tag;

                    }
                    print "\n";

                    if( $policy['status'] == 'false,' )
                    {
                        $tmp_rule->setDisabled(TRUE);
                        print "set rule to disable\n";
                    }
                }
            }
        }
    }

}