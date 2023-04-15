<?php

trait CP_R80_accesslayer
{
    function accesslayer_array($someArray)
    {

        /*
[source-negate] =>
    [destination-negate] =>
    [comments] =>
    [destination] => Array(       [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )

    [meta-info] => Array
        (
            [creator] => System
            [validation-state] => ok
            [last-modify-time] => Array
                (
                    [iso-8601] => 2018-10-25T16:41+0000
                    [posix] => 1540485690208
                )

            [creation-time] => Array
                (
                    [iso-8601] => 2017-06-16T22:32+0000
                    [posix] => 1497652328801
                )

            [lock] => unlocked
            [last-modifier] => fboulogne
        )

    [service-negate] =>
    [source] => Array   (   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )
    [type] => access-rule
    [content-direction] => any
    [content] => Array  (   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )

    [enabled] => 1
    [uid] => f83a3ef8-dd2f-c84a-a188-4ba0fcd5f219
    [rule-number] => 51
    [vpn] => Array(   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )
    [service] => Array(   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )
    [domain] => Array(   [uid] => 1597c33e-af2f-824d-b6e0-5feb8ba1eda8       [domain-type] => domain     [name] => Europe_VPN        )

    [content-negate] =>
    [action] => 6c488338-8eec-4103-ad21-cd461ac2c473
    [time] => Array(   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )
    [install-on] => Array(   [0] => 6c488338-8eec-4103-ad21-cd461ac2c476     )
    [track] => Array(   [per-session] =>        [per-connection] => 1       [alert] => none     [enable-firewall-session] =>        [accounting] =>         [type] => 598ead32-aa42-4615-90ed-f51a5928d41d  )
    [action-settings] => Array(   )
    [custom-fields] => Array(       [field-1] =>        [field-2] =>        [field-3] =>    )
         */
        #print_r( $this->objectArray );


        if( count($someArray) == 1 )
            $someArray = $someArray[0];


        $tmp_tag = null;

        foreach( $someArray as $key => $access )
        {
            if( isset($access['type']) )
                $type = $access['type'];
            else
                continue;

            //[type] => access-section
            if( $type == "access-section" )
            {
                #print_r( $access );

                if( isset( $access['name'] ) )
                {
                    $tagname = $this->strip_hidden_chars($access['name']);
                    $tmp_tag = $this->sub->tagStore->findOrCreate($tagname);
                }
                else
                    mwarning( "access-section - array['name] - not found" );

            }
            elseif( $type == "access-rule" )
            {
                #print_r( $access );


                //[rule-number] => 51
                //[enabled] => 1
                //[vpn] => Array(   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     ) ?????????????
                //[action] => 6c488338-8eec-4103-ad21-cd461ac2c473
                //[time] => Array(   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )
                //[install-on] => Array(   [0] => 6c488338-8eec-4103-ad21-cd461ac2c476     )

                //[destination] => Array(       [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )
                //[destination-negate] =>

                //[source] => Array   (   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )

                //[service] => Array(   [0] => 97aeb369-9aea-11d5-bd16-0090272ccb30     )
                //[service-negate] =>


                $domain = $access['domain']['name'];
                $this->check_vsys( $domain, 'rule' );

                //todo:
                //check if pan-os / panorama
                //check if vsys or DG is available

                $domainType = $access['domain']['domain-type'];


                #print_r( $access );



                if( isset( $access['name'] ) )
                {
                    //Todo: remove unsupported characters
                    $name = $access['name'];
                }

                else
                {
                    $name = $domain . "_Rule " . $access['rule-number'];
                }

                $name = $this->truncate_names($this->normalizeNames($name));

                $name = $this->sub->securityRules->findAvailableName($name);

                if( empty( $name ) )
                    $name = "EMPTY";

                print "\ncreate Rule: " . $name . "\n";
                $tmp_secrule = $this->sub->securityRules->newSecurityRule($name);
                if( $tmp_tag != null )
                    $tmp_secrule->tags->addTag($tmp_tag);

                //enabled/disabled
                if( $access['enabled'] == "0" )
                    $tmp_secrule->setDisabled(TRUE);

                if( $access['comments'] != "")
                {
                        print "    * description: " . $access['comments'] . "\n";
                    $tmp_secrule->setDescription( $access['comments'] );
                }


                //set rule action
                if( isset($this->objectArray['RulebaseAction'][$access['action']]) )
                {
                    $rule_action = $this->objectArray['RulebaseAction'][$access['action']]['name'];

                    if( $rule_action == "Accept" )
                    {
                        $action = "allow";
                    }
                    elseif( $rule_action == "Drop" )
                    {
                        //$action = "deny";
                        $action = "drop";
                    }
                    else
                        $action = "drop";

                    print "    - set action: " . $action . "\n";
                    $tmp_secrule->setAction($action);
                }

                //Zone from / to
                if( $domainType != "global domain" )
                {
                    //set from / to based on?????
                }


                //add SOURCE
                foreach( $access['source'] as $source )
                {
                    $source_name = $this->find_address_uid($source);
                    $source_name = $this->truncate_names($this->normalizeNames($source_name));
                    if( $source_name == null )
                    {
                        //CpmiAnyObject
                        if( isset($this->objectArray['CpmiAnyObject'][$source]) )
                        {
                            print "    - source: ANY\n";
                        }
                        else
                            print "check again: " . $source . "\n";
                    }
                    else
                    {
                        $tmp_address = $this->sub->addressStore->find($source_name);
                        if( $tmp_address != null )
                        {
                            print "    - source add: " . $source_name . "\n";
                            $tmp_secrule->source->addObject($tmp_address);
                        }
                        else
                        {
                            if( $domainType === "global domain" )
                            {
                                $tagname_overwrite = "planned to be overwritten";
                                print "create dummy object: ".$source_name." tag it with '".$tagname_overwrite."'\n";
                                /** @var AddressGroup $tmp_addressgroup */
                                $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($source_name);

                                $tmp_tag_grp = $this->sub->tagStore->findOrCreate( $tagname_overwrite );
                                $tmp_addressgroup->tags->addTag( $tmp_tag_grp );
                                //if global create empty address-group - tag it with planned to be overwritten

                                $tmp_secrule->source->addObject($tmp_addressgroup);
                            }
                            else
                            {
                                mwarning("address object ".$source_name." not found");
                            }
                        }
                    }
                }


                //add DESTINATION
                foreach( $access['destination'] as $destination )
                {
                    $destination_name = $this->find_address_uid($destination);
                    $destination_name = $this->truncate_names($this->normalizeNames($destination_name));
                    if( $destination_name == null )
                    {
                        //CpmiAnyObject
                        if( isset($this->objectArray['CpmiAnyObject'][$destination]) )
                        {
                            print "    - destination: ANY\n";
                        }
                        else
                            print "check again: " . $destination . "\n";
                    }
                    else
                    {
                        $tmp_address = $this->sub->addressStore->find($destination_name);
                        if( $tmp_address != null )
                        {
                            print "    - destination add: " . $destination_name . "\n";
                            $tmp_secrule->destination->addObject($tmp_address);
                        }
                        else
                        {
                            if( $domainType === "global domain" )
                            {
                                $tagname_overwrite = "planned to be overwritten";
                                print "create dummy object: ".$destination_name." tag it with '".$tagname_overwrite."'\n";
                                /** @var AddressGroup $tmp_addressgroup */
                                $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($destination_name);

                                $tmp_tag = $this->sub->tagStore->findOrCreate( $tagname_overwrite );
                                $tmp_addressgroup->tags->addTag( $tmp_tag );
                                //if global create empty address-group - tag it with planned to be overwritten

                                $tmp_secrule->destination->addObject($tmp_addressgroup);
                            }
                            else
                            {
                                mwarning("address object ".$destination_name." not found");
                            }

                        }
                    }
                }

                //add SERVICES
                foreach( $access['service'] as $service )
                {
                    #print "service: ".$service."\n";
                    $service_name = $this->find_service_uid($service);

                    if( $service_name == null )
                    {
                        //CpmiAnyObject
                        if( isset($this->objectArray['CpmiAnyObject'][$service]) )
                        {
                            print "    - service: ANY\n";
                        }
                        else
                            print "check again: " . $service . "\n";
                    }
                    else
                    {
                        $tmp_service = $this->sub->serviceStore->find($service_name);
                        if( $tmp_service != null )
                        {
                            print "    - service add: " . $service_name . "\n";
                            $tmp_secrule->services->add($tmp_service);
                        }
                        else
                        {
                            mwarning("service object not found");
                        }
                    }
                }
            }
        }
    }
}