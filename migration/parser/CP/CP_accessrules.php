<?php


trait CP_accessrules
{
    public $rule_location;

    public function add_access_rules($KEYS, $array)
    {
        #print_r(array_keys($array));
        #print_r( $array );

        //why is this not set?
        $this->rule_location = $this->sub;

        $i = 1;
        foreach( $array as $object )
        {
            $tmp_secrule = null;
            $name = null;

            print "------------------------------------------\n";
            if( !isset($object['number']) )
            {
                $object['number'] = "blank" . $i;
                $i++;
            }

            if( isset($object['number']) )
            {
                $name = "Rule" . $object['number'];
                $name = $this->truncate_names($this->normalizeNames($name));
                print "NAME: " . $name . "\n";


                $tmp_secrule = $this->rule_location->securityRules->newSecurityRule($name);
            }

            if( isset($object['header']) )
            {
                $header = $object['header'];
                print "HEADER: " . $header . "\n";

                //Todo: create main function
                // search tag if not available create it and add it to rule

                if( $header != "" )
                {
                    $tagname = $this->strip_hidden_chars($header);
                    $tmp_tag = $this->rule_location->tagStore->findOrCreate($tagname);
                    $tmp_secrule->tags->addTag($tmp_tag);
                }
            }

            if( isset($object['enabled']) )
            {
                $enabled = $object['enabled'];
                print "ENABLED: " . $enabled . "\n";

                if( $enabled == "no" )
                    $tmp_secrule->setDisabled(TRUE);
            }

            if( isset($object['from']) )
            {
                $from = $object['from'];
                print "FROM: ";
                $this->rule_from_to($from, "from", $tmp_secrule, $name);
            }
            if( isset($object['from_inverted']) )
            {
                $from_inverted = $object['from_inverted'];
                print "FROM INVERTED: " . $from_inverted . "\n";

                if( $from_inverted == "yes" )
                    $tmp_secrule->setSourceIsNegated(TRUE);
            }


            if( isset($object['users']) )
            {
                $users = $object['users'];
                print "USERS: ";
                if( !empty($users) )
                    print_r($users);
                else
                    print "--\n";
            }


            if( isset($object['to']) )
            {
                $to = $object['to'];
                print "TO: ";

                $this->rule_from_to($to, "to", $tmp_secrule, $name);
            }
            if( isset($object['to_inverted']) )
            {
                $to_inverted = $object['to_inverted'];
                print "TO INVERTED: " . $to_inverted . "\n";

                if( $to_inverted == "yes" )
                    $tmp_secrule->setDestinationIsNegated(TRUE);
            }


            if( isset($object['services']) )
            {
                $services = $object['services'];
                print "SERVICES: ";
                if( !empty($services) )
                {
                    print "\n";
                    #print_r( $services );
                    foreach( $services as $service )
                    {
                        $service_name = $service['layer3'];
                        #print " - ".$service_name."\n";

                        if( strtolower($service_name) == "any" )
                        {
                            print "    - " . $service_name . "\n";
                            continue;
                        }


                        $tmp_service = $this->rule_location->serviceStore->find($service_name);
                        if( $tmp_service != null )
                        {
                            print "    - " . $service_name . "\n";
                            $tmp_secrule->services->add($tmp_service);
                        }
                        else
                        {
                            $tmp_service = $this->rule_location->serviceStore->find("tmp-".$service_name);
                            if( $tmp_service != null )
                            {
                                print "    - " . "tmp-".$service_name . "\n";
                                $tmp_secrule->services->add($tmp_service);
                            }
                            else
                                mwarning(" X service object " . $service_name . " not found", null, FALSE);
                        }

                        //search for service
                        // add service

                        foreach( $service as $key => $srvobject )
                        {
                            if( $key !== "layer3" )
                            {
                                print_r($srvobject);
                                mwarning($key . " not configured");
                            }

                        }
                    }
                }

                else
                    print "--\n";
            }
            if( isset($object['services_inverted']) )
            {
                $services_inverted = $object['services_inverted'];
                print "SERVICES INVERTED: " . $services_inverted . "\n";

                if( $services_inverted == "yes" )
                    //Todo: bring in own calculation
                    mwarning("implement - service inverted");
            }


            if( isset($object['action']) )
            {
                $rule_action = $object['action'];
                print "ACTION: " . $rule_action . "\n";

                #print "    - set action: ".$action."\n";
                #$tmp_secrule->setAction( $action );

                if( strtolower($rule_action) == "accept" )
                {
                    $action = "allow";
                }
                elseif( strtolower($rule_action) == "drop" )
                {
                    //$action = "deny";
                    $action = "drop";
                }
                else
                    $action = "drop";

                print "    - set action: " . $action . "\n";
                $tmp_secrule->setAction($action);
            }
            if( isset($object['action_qualifier']) )
            {
                $action_qualifier = $object['action_qualifier'];
                print "ACTION_QUALIFIER: " . $action_qualifier . "\n";
                //Todo: swaschkut 20200612 for what is this needed???
            }
            if( isset($object['log']) )
            {
                $log = $object['log'];
                print "LOG: " . $log . "\n";
            }
            if( isset($object['time']) and ($object['time'] !== "Any") )
            {
                $time = $object['time'];
                print "TIME: " . $time . "\n";

                $addlog = "time field with value ['.$time.'] is used. This field has not been migrated. Check whether this security rule needs to be activated: ";
                $tmp_secrule->set_node_attribute('warning', $addlog);

                mwarning( "TIME found, but not supported yet" );
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

                if( $comment !== "" )
                {
                    /*
                     * , Comment:
                     */


                    $tmp_comment = explode(", Comment:", $comment);

                    if( count( $tmp_comment ) > 0 )
                    {
                        if( !isset( $tmp_comment[1] ) )
                            print_r( $tmp_comment );
                        else
                            $tmp_secrule->setDescription($tmp_comment[1]);


                        $rule_name = str_replace("Name:", "", $tmp_comment[0]);
                        $rule_name = trim($rule_name);
                        if( $rule_name != "" )
                        {
                            //Todo: set new rulename
                            $rule_name = $this->truncate_names($this->normalizeNames($rule_name));
                            $tmp_secrule->setname($rule_name);
                        }
                    }
                    else
                    {
                        print_r( $tmp_comment );
                        derr( "check" );
                    }



                }

            }
            if( isset($object['location']) )
            {
                $location = $object['location'];
                print "LOCATION: " . $location . "\n";
            }
            /*
[action] =>
[action_qualifier] =>
[log] =>
[time] =>
[install_on] => Array
    (
    )

[comment] =>
[location] =>
             */
            #print_r(array_keys($object));

            /*
                 *
                [number] => 1438
                [header] => PR038072 Datasafe - Datacenter strategy Honolulu
                [enabled] => no
                [from] => Array
                    (
                    )

                [from_inverted] => no
                [users] => Array
                    (
                    )

                [to] => Array
                    (
                    )

                [to_inverted] => no
                [services] => Array
                    (
                    )

                [services_inverted] => no
                [action] =>
                [action_qualifier] =>
                [log] =>
                [time] =>
                [install_on] => Array
                    (
                    )

                [comment] =>
                [location] =>
                 */

            $check_array = array(
                '0' => "number",
                '1' => "header",
                '2' => "enabled",
                '3' => "from",
                '4' => "from_inverted",
                '5' => "users",
                '6' => "to",
                '7' => "to_inverted",
                '8' => "services",
                '9' => "services_inverted",
                '10' => "action",
                '11' => "action_qualifier",
                '12' => "log",
                '13' => "time",
                '14' => "install_on",
                '15' => "comment",
                '16' => "location"
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

    public function rule_from_to($array, $fromORto, $tmp_rule, $rule_name)
    {
        if( !empty($array) )
        {
            print "\n";
            #print_r( $array );

            if( $fromORto == 'from' )
                $direction = 'source';
            else
                $direction = 'destination';

            foreach( $array as $item )
            {
                if( is_array($item) )
                    $item_object = $item['object'];
                else
                    $item_object = $item;

                if( strtolower($item_object) == "any" )
                {
                    print "   - " . $item_object . "\n";
                    continue;
                }

                #print "itemobject1: |".$item_object."|\n";
                if( preg_match("/^\./", $item_object) )
                {
                    $item_object = ltrim($item_object, '.');
                    #$item_object = "*" . $item_object;
                    #print "itemobject:2 |".$item_object."|\n";

                }


                if( strtolower($item_object) != "any" )
                {
                    if( $this->print )
                        print " - find object: " . $item_object . "\n";

                    $item_object = $this->truncate_names($this->normalizeNames($item_object));

                    $tmp_address = $this->rule_location->addressStore->find($item_object);

                    if( $tmp_address === null )
                    {
                        $tmp_address = $this->MainAddHost($item_object, "1.1.1.1/32", 'ip-netmask', "tmp as object not found");
                        $addlog = "fix object - not found in original config file";
                        $tmp_address->set_node_attribute('warning', $addlog);
                    }


                    if( $tmp_address !== null )
                    {
                        if( $fromORto == 'from' )
                            $tmp_rule->source->addObject($tmp_address);
                        else
                            $tmp_rule->destination->addObject($tmp_address);
                    }

                    else
                        mwarning("address objectname: " . $item_object . " not found for rule: " . $rule_name . "\n");
                }


            }

        }
        else
            print "--\n";
    }


}
