<?php


trait CP_R80_natlayer
{
    function natlayer_array($someArray)
    {

        $tmp_tag = null;

        if( count($someArray) == 1 )
            $someArray = $someArray[0];

        #print_r( $someArray );

        foreach( $someArray as $key => $access )
        {
            #print_r( $access );
            /*
            [comments] => [07-10-2014] NAT internet JBO
            [method] => hide
            [auto-generated] =>
            [translated-destination] => 85c0f50f-6d8a-4528-88ab-5fb11d8fe16c
            [meta-info] => Array
                (
                    [creator] => System
                    [validation-state] => ok
                    [last-modify-time] => Array
                        (
                            [iso-8601] => 2018-10-25T16:50+0000
                            [posix] => 1540486201397
                        )

                    [creation-time] => Array
                        (
                            [iso-8601] => 2017-06-16T22:32+0000
                            [posix] => 1497652329167
                        )

                    [lock] => unlocked
                    [last-modifier] => fboulogne
                )

            [original-service] => 97aeb369-9aea-11d5-bd16-0090272ccb30
            [translated-source] => f6e096b1-f6bf-46f8-f7ae-656b179d259f
            [type] => nat-rule
            [translated-service] => 85c0f50f-6d8a-4528-88ab-5fb11d8fe16c
            [enabled] => 1
            [uid] => 0ae24bbc-fb9c-4d31-a801-45b6ad451ea9
            [rule-number] => 23
            [domain] => Array
                (
                    [uid] => 1597c33e-af2f-824d-b6e0-5feb8ba1eda8
                    [domain-type] => domain
                    [name] => Europe_VPN
                )

            [original-destination] => 5f8c3892-ceaa-11e2-e4bb-051e98a52ba0
            [original-source] => 108e9d50-7d20-4525-8144-3e21b88998a1
            [install-on] => Array
                (
                    [0] => 6c488338-8eec-4103-ad21-cd461ac2c476
                )
             */


            if( isset($access['type']) )
                $type = $access['type'];
            else
                continue;


            //[type] => access-section
            if( $type == "nat-section" )
            {
                #print_r( $access );

                if( isset( $access['name'] ) )
                {
                    $tagname = $this->strip_hidden_chars($access['name']);

                    if( $tagname !== "" )
                        $tmp_tag = $this->sub->tagStore->findOrCreate($tagname);
                }

            }
            elseif( $type == "nat-rule" )
            {
                /*
                    [comments] => [07-10-2014] NAT internet JBO
                [method] => hide
                [auto-generated] =>

                [translated-destination] => 85c0f50f-6d8a-4528-88ab-5fb11d8fe16c

                    [original-service] => 97aeb369-9aea-11d5-bd16-0090272ccb30
                [translated-source] => f6e096b1-f6bf-46f8-f7ae-656b179d259f

                [translated-service] => 85c0f50f-6d8a-4528-88ab-5fb11d8fe16c
                    [enabled] => 1
                    [rule-number] => 23

                    [original-destination] => 5f8c3892-ceaa-11e2-e4bb-051e98a52ba0
                    [original-source] => 108e9d50-7d20-4525-8144-3e21b88998a1
                 */

                $domain = $access['domain']['name'];
                $domainType = $access['domain']['domain-type'];
                $domain = $access['domain']['name'];
                $this->check_vsys( $domain, 'rule' );


                #print_r( $access );

                $name = $domain . "_NATRule " . $access['rule-number'];

                print "\ncreate Rule: " . $name . " [method] =>" . $access['method'] . "\n";
                $tmp_natrule = $this->sub->natRules->newNatRule($name);

                if( $tmp_tag != null )
                    $tmp_natrule->tags->addTag($tmp_tag);

                if( $access['comments'] != "")
                {
                    print "    * description: " . $access['comments'] . "\n";
                    $tmp_natrule->setDescription( $access['comments'] );
                }

                //enabled/disabled
                if( $access['enabled'] == "0" )
                    $tmp_natrule->setDisabled(TRUE);

                //comments
                if( isset($access['comments']) && $access['comments'] != "" )
                {
                    $description = $this->strip_hidden_chars($access['comments']);
                    print "    - description: " . $description . "\n";
                    $tmp_natrule->setDescription($description);
                }


                //Zone from / to
                if( $domainType != "global domain" )
                {
                    //set from / to based on?????
                }


                //add SOURCE

                $source = $access['original-source'];

                $source_name = $this->find_address_uid($source);

                if( $source_name == null )
                {
                    //CpmiAnyObject
                    if( isset($this->objectArray['CpmiAnyObject'][$source]) )
                    {
                        print "    - original-source: ANY\n";
                    }
                    else
                        print "check again: " . $source . "\n";
                }
                else
                {
                    $tmp_address = $this->sub->addressStore->find($source_name);
                    if( $tmp_address != null )
                    {
                        print "    - original-source add: " . $source_name . "\n";
                        $tmp_natrule->source->addObject($tmp_address);
                    }
                    else
                    {
                        mwarning("address object ".$source_name." not found");
                    }
                }


                //add DESTINATION
                $destination = $access['original-destination'];
                $destination_name = $this->find_address_uid($destination);

                if( $destination_name == null )
                {
                    //CpmiAnyObject
                    if( isset($this->objectArray['CpmiAnyObject'][$destination]) )
                    {
                        print "    - original-destination: ANY\n";
                    }
                    else
                        print "check again: " . $destination . "\n";
                }
                else
                {
                    $tmp_address = $this->sub->addressStore->find($destination_name);
                    if( $tmp_address != null )
                    {
                        print "    - original-destination add: " . $destination_name . "\n";
                        $tmp_natrule->destination->addObject($tmp_address);
                    }
                    else
                    {
                        mwarning("address object ".$destination_name." not found");
                    }
                }


                //add SERVICES
                $service = $access['original-service'];

                #print "service: ".$service."\n";
                $service_name = $this->find_service_uid($service);

                if( $service_name == null )
                {
                    //CpmiAnyObject
                    if( isset($this->objectArray['CpmiAnyObject'][$service]) )
                    {
                        print "    - original-service: ANY\n";
                    }
                    else
                        print "check again: " . $service . "\n";
                }
                else
                {
                    $tmp_service = $this->sub->serviceStore->find($service_name);
                    if( $tmp_service != null )
                    {
                        print "    - original-service add: " . $service_name . "\n";
                        $tmp_natrule->setService($tmp_service);
                    }
                    else
                    {
                        mwarning("service object not found");
                    }
                }

                //check NAT


                $check = $access['translated-source'];
                if( isset($check) && $check != "" )
                {
                    #print "SNAT: ".$check."\n";

                    $translated_source = $check;
                    $translated_source_name = $this->find_address_uid($translated_source);

                    if( $translated_source_name == null )
                    {
                        //CpmiAnyObject
                        if( isset($this->objectArray['Global'][$translated_source]) )
                        {
                            print "    - translated-source: ANY\n";

                            $tmp_address = $this->sub->addressStore->find($source_name . "-hidenat");
                            if( $tmp_address != null )
                            {
                                print "    - translated-source add: " . $source_name . "-hidenat\n";
                                $tmp_natrule->snathosts->addObject($tmp_address);

                                print "    * snat type: 'dynamic-ip-and-port'\n";
                                $tmp_natrule->changeSourceNAT('dynamic-ip-and-port');
                            }

                        }
                        else
                            print "check again: " . $translated_source . "\n";
                    }
                    else
                    {
                        $tmp_address = $this->sub->addressStore->find($translated_source_name);
                        if( $tmp_address != null )
                        {
                            print "    - translated-source add: " . $translated_source_name . "\n";
                            ###$tmp_natrule->destination->addObject( $tmp_address );

                            $tmp_natrule->snathosts->addObject($tmp_address);

                            print "    * snat type: 'dynamic-ip-and-port'\n";
                            $tmp_natrule->changeSourceNAT('dynamic-ip-and-port');
                        }
                        else
                        {
                            mwarning("address object ".$translated_source_name." not found");
                        }
                    }
                }

                $tmp_service = null;

                $check = $access['translated-service'];
                if( isset($check) && $check != "" )
                {
                    #print "DNAT service: ".$check."\n";
                    $service = $check;
                    $service_name = $this->find_service_uid($service);

                    if( $service_name == null )
                    {
                        //CpmiAnyObject
                        if( isset($this->objectArray['Global'][$service]) )
                        {
                            print "    - translated-service: ANY\n";
                        }
                        else
                            print "check again: " . $service . "\n";
                    }
                    else
                    {
                        $tmp_service = $this->sub->serviceStore->find($service_name);
                        if( $tmp_service != null )
                        {

                        }
                        else
                        {
                            mwarning("service object not found");
                        }
                    }
                }



                $check = $access['translated-destination'];
                if( isset($check) && $check != "" )
                {
                    #print "DNAT: ".$check."\n";

                    $translated_destination = $check;
                    $translated_destination_name = $this->find_address_uid($translated_destination);

                    if( $translated_destination_name == null )
                    {
                        //CpmiAnyObject
                        if( isset($this->objectArray['Global'][$translated_destination]) )
                        {
                            print "    - translated-destination: ANY\n";
                        }
                        else
                            print "check again: " . $translated_destination . "\n";
                    }
                    else
                    {
                        $tmp_address = $this->sub->addressStore->find($translated_destination_name);
                        if( $tmp_address != null )
                        {
                            print "    - translated-destination add: " . $translated_destination_name . "\n";
                            ###$tmp_natrule->destination->addObject( $tmp_address );
                            if( $tmp_service != null )
                            {
                                print "    - translated-service add: " . $tmp_service->name() . "\n";
                                $tmp_natrule->setDNAT($tmp_address, $tmp_service->getDestPort() );
                            }
                            else
                                $tmp_natrule->setDNAT($tmp_address);


                        }
                        else
                        {
                            mwarning("address object ".$translated_destination_name." not found");
                        }
                    }
                }
            }
        }
    }
}