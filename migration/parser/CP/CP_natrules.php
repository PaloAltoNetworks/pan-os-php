<?php



trait CP_natrules
{
    public function add_nat_rules($KEYS, $array)
    {
        #print_r(array_keys($array));
        #print_r( $array );

        //why is this not set?
        $rule_location = $this->sub;

        $i = 1;
        foreach( $array as $object )
        {
            $tmp_natrule = null;
            $name = null;

            print "------------------------------------------\n";
            #print_r( $object );


            if( !isset($object['number']) )
            {
                $object['number'] = "blank" . $i;
                $i++;
            }

            if( isset($object['number']) )
            {
                $name = "Rule" . $object['number'];
                print "NAME: " . $name . "\n";


                $tmp_natrule = $rule_location->natRules->newNatRule($name);
            }
            else
                continue;

            if( isset($object['header']) )
            {
                $header = $object['header'];
                print "HEADER: " . $header . "\n";

                //Todo: create main function
                // search tag if not available create it and add it to rule

                if( $header != "" )
                {
                    $tagname = $this->strip_hidden_chars($header);
                    $tmp_tag = $rule_location->tagStore->findOrCreate($tagname);
                    $tmp_natrule->tags->addTag($tmp_tag);
                }
            }

            if( isset($object['enabled']) )
            {
                $enabled = $object['enabled'];
                print "ENABLED: " . $enabled . "\n";

                if( $enabled == "no" )
                    $tmp_natrule->setDisabled(TRUE);
            }


            /*
            [number] => 239
            [header] =>
            [enabled] => yes
            */

            if( isset($object['orig_from']) )
            {
                $from = $object['orig_from'];
                print "FROM: ";
                $this->rule_from_to($from, "from", $tmp_natrule, $name);
            }

            if( isset($object['orig_to']) )
            {
                $to = $object['orig_to'];
                print "TO: ";
                $this->rule_from_to($to, "to", $tmp_natrule, $name);
            }


            if( isset($object['orig_service']) )
            {
                $services = $object['orig_service'];
                print "SERVICES: ";
                if( !empty($services) )
                {
                    print "\n";
                    #print_r( $services );
                    foreach( $services as $service_name )
                    {
                        #$service_name = $service['layer3'];
                        print " - " . $service_name . "\n";

                        if( strtolower($service_name) == "any" )
                        {
                            print "    - " . $service_name . "\n";
                            continue;
                        }


                        $tmp_service = $this->rule_location->serviceStore->find($service_name);
                        if( $tmp_service != null )
                        {
                            print "    - " . $service_name . "\n";
                            $tmp_natrule->setService($tmp_service);
                        }
                        else
                        {
                            mwarning(" X service object " . $service_name . " not found", null, FALSE);
                        }
                    }
                }
            }

            /*
            [orig_service] => Array
                (
                    [0] => Any
                )

            [nat_type] => static
            [nat_from] => ORIGINAL
            [nat_to] => Flagstar_Rich_Channe_Local_10.227.240.6
            [nat_service] => ORIGINAL
             */

            if( isset($object['nat_type']) )
            {
                $nat_type = $object['nat_type'];
                print "NAT TYPE: " . $nat_type . "\n";
            }

            $tmp_service = null;
            if( isset($object['nat_service']) )
            {
                $nat_services = $object['nat_service'];
                print "NAT SERVICES: " . $nat_services . "\n";

                if( $nat_services == "ORIGINAL" )
                {
                    //Todo: set $rule->service()
                }
                else
                {
                    $tmp_service = $this->rule_location->serviceStore->find($nat_services);
                    if( $tmp_service != null )
                    {
                        print "    - " . $nat_services . "\n";
                        //Todo: check if SNAT or DNAT
                    }
                    else
                    {
                        mwarning(" X service object " . $nat_services . " not found", null, FALSE);
                    }
                }
            }

            if( isset($object['nat_from']) )
            {
                $nat_from = $object['nat_from'];
                print "NAT FROM: " . $nat_from . "\n";

                if( $nat_from != "ORIGINAL" )
                {
                    $tmp_address = $this->rule_location->addressStore->find($nat_from);

                    if( $tmp_address !== null )
                    {
                        print "    * add sourceNAT: " . $tmp_address->name() . "\n";
                        $tmp_natrule->snathosts->addObject($tmp_address);
                        print "    * snat type: 'dynamic-ip-and-port'\n";
                        $tmp_natrule->changeSourceNAT('dynamic-ip-and-port');
                    }
                    else
                        mwarning( "SNAT object ".$nat_from." not found" );
                }



            }
            if( isset($object['nat_to']) )
            {
                $nat_to = $object['nat_to'];
                print "NAT TO: " . $nat_to . "\n";

                if( $nat_to != "ORIGINAL" )
                {
                    $tmp_address = $this->rule_location->addressStore->find($nat_to);

                    if( $tmp_address !== null )
                    {
                        print " * add DNAT " . $tmp_address->name() . "\n";
                        $tmp_natrule->setDNAT($tmp_address);
                    }
                    else
                        mwarning( "DNAT object ".$nat_from." not found" );
                }

            }


            if( isset($object['install_on']) )
            {
                $install_on = $object['install_on'];
                print "INSTALL ON: ";
                if( !empty($install_on) )
                    print_r($install_on);
                else
                    print "--\n";
            }

            if( isset($object['comment']) )
            {
                $comment = $object['comment'];
                print "COMMENT: " . $comment . "\n";

                /*
                if( $comment !== "" )
                {
                   , Comment:


                    $tmp_comment = explode( ", Comment:", $comment );

                    $tmp_natrule->setDescription( $tmp_comment[1] );
                    $rule_name = str_replace("Name:", "", $tmp_comment[0] );
                    $rule_name = trim( $rule_name );
                    if( $rule_name != "" )
                    {
                        //Todo: set new rulename
                        $tmp_natrule->setname($rule_name);
                    }
                }
                */
            }

            $check_array = array(
                '0' => "number",
                '1' => "header",
                '2' => "enabled",
                '3' => "orig_from",
                '4' => "orig_to",
                '5' => "orig_service",
                '6' => "nat_type",
                '7' => "nat_from",
                '8' => "nat_to",
                '9' => "nat_service",
                '10' => "install_on",
                '11' => "comment"
            );


            if( is_array($object) && array_keys($object) === $check_array )
            {
                #print "SAME\n";
            }
            else
            {
                if( !is_array($object) )
                {
                    mwarning("STRING: " . $object . "\n");
                    continue;
                }


                foreach( $object as $key1 => $value )
                {
                    if( !in_array($key1, $check_array) )
                    {
                        mwarning("KEY: " . $key1 . " not yet checked\n");
                        print_r($object);
                    }
                }
            }

        }
    }
}