<?php



#namespace expedition;


trait SOPHOSservice
{
    private function create_service($srv_name, $srv_value, $srv_protocol, $srv_comment, $name_extension = "")
    {
        if( $name_extension != "" )
        {
            if( $name_extension == "_tcp" )
                $srv_protocol[1] = "tcp";
            elseif( $name_extension == "_udp" )
                $srv_protocol[1] = "udp";
        }

        print "name: " . $srv_name . " - value: " . $srv_value . " - prot: " . $srv_protocol[1] . "\n";

        $tmp_service = $this->sub->serviceStore->find($srv_name . $name_extension);
        if( $tmp_service !== FALSE )
        {
            print "create service - name: " . $srv_name . " - value: " . $srv_value . " - prot: " . $srv_protocol[1] . "\n";
            $tmp_service = $this->sub->serviceStore->newService($srv_name . $name_extension, $srv_protocol[1], $srv_value);
            $tmp_service->setDescription($srv_comment);
        }

        return $tmp_service;
    }

    private function cleanup_text($policy)
    {
        $srv_value = str_replace(',', "", $policy['dst_high']);
        $srv_value_low = str_replace(',', "", $policy['dst_low']);
        if( $srv_value_low !== $srv_value )
            $srv_value = $srv_value_low . "-" . $srv_value;

        $srv_protocol = explode("/", $policy['_type']);
        $srv_protocol = str_replace(',', "", $srv_protocol);
        $srv_comment = str_replace(',', "", $policy['comment']);
        $srv_comment = str_replace('(', "", $srv_comment);
        $srv_comment = str_replace(')', "", $srv_comment);

        return array("value" => $srv_value, "protocol" => $srv_protocol, "comment" => $srv_comment);
    }

    public function service($master_array)
    {
        foreach( $master_array['service'] as $policy )
        {
            $srv_name = str_replace(',', "", $policy['name']);

            if( $policy['_type'] == 'service/group,' )
            {
                //check seperate import later on
            }
            elseif( $policy['_type'] == 'service/tcp,' )
            {
                $srv_policy = $this->cleanup_text($policy);
                $this->create_service($srv_name, $srv_policy['value'], $srv_policy['protocol'], $srv_policy['comment']);
            }
            elseif( $policy['_type'] == 'service/udp,' )
            {
                $srv_policy = $this->cleanup_text($policy);
                $this->create_service($srv_name, $srv_policy['value'], $srv_policy['protocol'], $srv_policy['comment']);
            }

            elseif( $policy['_type'] == 'service/tcpudp,' )
            {
                $srv_policy = $this->cleanup_text($policy);
                $tmp_service_tcp = $this->create_service($srv_name, $srv_policy['value'], array('1' => "tcp"), $srv_policy['comment'], "_tcp");
                $tmp_service_udp = $this->create_service($srv_name, $srv_policy['value'], array('1' => "udp"), $srv_policy['comment'], "_udp");

                $tmp_service_group = $this->sub->serviceStore->find($srv_name);
                if( $tmp_service_group !== FALSE )
                {
                    $tmp_service_group = $this->sub->serviceStore->newServiceGroup($srv_name);
                    $tmp_service_group->addMember($tmp_service_tcp);
                    $tmp_service_group->addMember($tmp_service_udp);
                }
            }
            else
            {
                print "|" . $policy['_type'] . "|\n";
                print_r($policy);
            }
        }

    }


    public function servicegroup($master_array)
    {
        foreach( $master_array['service'] as $policy )
        {
            $srv_name = str_replace(',', "", $policy['name']);

            if( $policy['_type'] == 'service/group,' )
            {
                $tmp_service_group = $this->sub->serviceStore->find($srv_name);
                if( $tmp_service_group !== FALSE )
                {
                    $tmp_service_group = $this->sub->serviceStore->newServiceGroup($srv_name);
                }

                $tmp_found = FALSE;
                $src_array = explode(",", $policy['members']);
                print "- set group members: ";
                foreach( $src_array as $members )
                {
                    #print "src_ref:".$source."\n";
                    foreach( $master_array['service'] as $master_service )
                    {
                        #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                        if( str_replace(',', "", $master_service['_ref']) == $members )
                        {
                            //search object in addressstore
                            $tmp_name = str_replace(',', "", $master_service['name']);
                            print "FOUND service: " . $tmp_name . " - " . $members . "\n";

                            $tmp_service = $this->sub->serviceStore->find($tmp_name);
                            // add to rule source
                            if( $tmp_service !== FALSE )
                                $tmp_service_group->addMember($tmp_service);
                            else
                                derr("serviceobject: " . $tmp_name . " not found.");

                            print "$tmp_name";
                            $tmp_found = TRUE;
                            break;
                        }
                        elseif( $master_service['_ref'] == "REF_NetworkAny" )
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
                        mwarning("   - network object not found:" . $source . "\n");
                    }
                }
            }
        }
    }
}


