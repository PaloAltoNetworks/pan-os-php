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


trait CISCOservices
{
    function get_icmp_groups()
    {
        global $projectdb;

        global $debug;
        global $print;

        $addName = array();
        $isIcmpGroup = 0;
        $IcmpGroupName = "";
        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);
            if( !preg_match("/^icmp-object/", $names_line) )
            {
                $isIcmpGroup = 0;
            }

            if( preg_match("/^object-group icmp-type/i", $names_line) )
            {
                $isIcmpGroup = 1;
                $names = explode(" ", $names_line);
                $IcmpGroupName = rtrim($names[2]);

                $tmp_servicegroup = $this->sub->serviceStore->find($IcmpGroupName);
                if( $tmp_servicegroup === null )
                {
                    if( $print )
                        print " * create protocol group: " . $IcmpGroupName . "\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($IcmpGroupName);
                }
            }

            if( $isIcmpGroup == 1 )
            {
                if( preg_match("/\bicmp-object\b/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    #$addName[] = "('$netObj[1]','$source','$vsys','$IcmpGroupName')";

                    $tmp_service = $this->sub->serviceStore->find($netObj[1]);
                    if( $tmp_service === null )
                    {
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $netObj[1]);
                        if( $tmp_service !== null )
                        {
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to icmp group " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                        else
                        {
                            #derr( "object-group protcol - protocol-object: ".$netObj[1]. " not yet available: ".$names_line );
                            if( $print )
                                print "   * create service tmp-" . $netObj[1] . "\n";
                            if( $netObj[1] == "tcp" || $netObj[1] == "udp" )
                                $Protocol = $netObj[1];
                            else
                                $Protocol = 'tcp';

                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $netObj[1], $Protocol, "1-65535");
                            $tmp_service->set_node_attribute('error', "no service protocol - " . $Protocol . " is used");
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to icmp group " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }

                    }
                    else
                    {
                        if( $print )
                            print "   * add service: " . $tmp_service->name() . " to icmp group " . $tmp_servicegroup->name() . "\n";
                        $tmp_servicegroup->addMember($tmp_service);
                    }
                }
            }


        }
    }

    function get_protocol_groups()
    {
        global $projectdb;

        global $debug;
        global $print;

        $addName = array();
        $isProtocolGroup = 0;
        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);

            if( preg_match("/^object-group protocol/i", $names_line) )
            {
                $isProtocolGroup = 1;
                $names = explode(" ", $names_line);
                $ProtocolGroupName = rtrim($names[2]);

                $tmp_servicegroup = $this->sub->serviceStore->find($ProtocolGroupName);
                if( $tmp_servicegroup === null )
                {
                    if( $print )
                        print " * create protocol group: " . $ProtocolGroupName . "\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($ProtocolGroupName);
                }
            }

            if( $isProtocolGroup == 1 )
            {
                if( preg_match("/protocol-object/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                    $tmp_service = $this->sub->serviceStore->find($netObj[1]);
                    if( $tmp_service === null )
                    {
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $netObj[1]);
                        if( $tmp_service !== null )
                        {
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to protocol group " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                        else
                        {
                            if( $print )
                                print "   * create service tmp-" . $netObj[1] . "\n";
                            if( $netObj[1] == "tcp" || $netObj[1] == "udp" )
                                $Protocol = $netObj[1];
                            else
                                $Protocol = 'tcp';

                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $netObj[1], $Protocol, "1-65535");
                            $tmp_service->set_node_attribute('error', "no service protocol - tcp is used");
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to protocol group " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                    }
                    else
                    {
                        if( $print )
                            print "   * add service: " . $tmp_service->name() . " to protocol group " . $tmp_servicegroup->name() . "\n";
                        $tmp_servicegroup->addMember($tmp_service);
                    }
                }
            }
        }
    }


    function get_object_service()
    {
        global $projectdb;
        global $debug;
        global $print;

        $vsys = $this->template_vsys->name();
        $ObjectServiceName = "";
        $ObjectServiceNamePan = "";

        $isObjectService = 0;
        $addService = array();

        $source = "";

        foreach( $this->data as $line => $names_line )
        {
            $addlog = "";
            $names_line = trim($names_line);
            if( $isObjectService == 1 )
            {

                $found = FALSE;
                $tmp_service = $this->sub->serviceStore->find($ObjectServiceNamePan);


                if( preg_match("/^service protocol/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $srv_protocol = $netObj[2];


                    if( $tmp_service !== null )
                    {
                        if( $tmp_service->isService() && $srv_protocol == $tmp_service->protocol() )
                            $found = TRUE;
                    }

                    if( !$found && $tmp_service === null )
                    {
                        #$addService[] = array($ObjectServiceNamePan,$ObjectServiceName,$srv_protocol,'','','','','1',$source,$vsys);
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $ObjectServiceNamePan);
                        if( $tmp_service === null )
                        {
                            if( $print )
                                print " * create service tmp-" . $ObjectServiceNamePan . "\n";
                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $ObjectServiceNamePan, "tcp", "6500");
                            $tmp_service->set_node_attribute('error', 'Service Protocol found [' . $ObjectServiceName . '] and Protocol [' . $srv_protocol . '] - Replace it by the right app-id - tcp 6500 is used');
                        }

                    }
                    else
                        mwarning("object: " . $ObjectServiceNamePan . " already available");


                    /*
                    $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND protocol='$srv_protocol' AND vsys='$vsys';");

                    if ($search->num_rows == 0) {
                        $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','$srv_protocol','','','','','1','$source','$vsys')";
                        add_log('warning', 'Reading Services Objects and Groups', 'Service Protocol found [' . $ObjectServiceName . '] and Protocol [' . $srv_protocol . ']', $source, 'Replace it by the right app-id');
                    }
                    */
                }
                elseif( preg_match("/^service icmp/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                    if( $tmp_service !== null )
                    {
                        if( $tmp_service->isService() )
                            $found = TRUE;
                    }

                    if( !$found && $tmp_service === null )
                    {
                        if( isset($netObj[2]) )
                            $icmptype = $netObj[2];
                        else
                            $icmptype = "";

                        #$addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','icmp','','',1,'$icmptype','1','$source','$vsys')";
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $ObjectServiceNamePan);
                        if( $tmp_service === null )
                        {
                            if( $print )
                                print " * create service tmp-" . $ObjectServiceNamePan . "\n";
                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $ObjectServiceNamePan, "tcp", "6500");
                            $tmp_service->set_node_attribute('error', 'ICMP Service found [' . $ObjectServiceName . '] with icmptype: "' . $icmptype . '" - Replace it by the ICMP app-id - tcp 6500 is used');
                        }

                    }
                    else
                        mwarning("object: " . $ObjectServiceNamePan . " already available");
                    /*
                    $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';");
                    if ($search->num_rows == 0) {
                        $icmptype = $netObj[2];
                        $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','icmp','','',1,'$icmptype','1','$source','$vsys')";
                        add_log('warning', 'Phase 3: Reading Services Objects and Groups', 'ICMP Service found [' . $ObjectServiceName . ']', $source, 'Replace it by the ICMP app-id');
                    }
                    */
                }
                elseif( preg_match("/^service icmp6/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                    if( $tmp_service !== null )
                    {
                        if( $tmp_service->isService() )
                            $found = TRUE;
                    }

                    if( !$found && $tmp_service === null )
                    {
                        if( isset($netObj[2]) )
                            $icmptype = $netObj[2];
                        else
                            $icmptype = "";
                        #$addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','icmp','','',1,'$icmptype','1','$source','$vsys')";
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $ObjectServiceNamePan);
                        if( $tmp_service === null )
                        {
                            if( $print )
                                print " * create service tmp-" . $ObjectServiceNamePan . "\n";
                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $ObjectServiceNamePan, "tcp", "6500");
                            $tmp_service->set_node_attribute('error', 'ICMP6 Service found [' . $ObjectServiceName . '] with icmptype: "' . $icmptype . '" - Replace it by the ICMP app-id - tcp 6500 is used');
                        }

                    }
                    else
                        mwarning("object: " . $ObjectServiceNamePan . " already available");
                    /*
                    $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';");
                    if ($search->num_rows == 0) {
                        $icmptype = $netObj[2];
                        $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','icmp','','',1,'$icmptype','1','$source','$vsys')";
                        add_log('warning', 'Phase 3: Reading Services Objects and Groups', 'ICMP6 Service found [' . $ObjectServiceName . ']', $source, 'Replace it by the ICMP app-id');
                    }
                    */
                }

                elseif( preg_match("/^service tcp-udp/i", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                    $tmp_servicegroup = $this->sub->serviceStore->find($ObjectServiceNamePan);
                    if( $tmp_servicegroup === null )
                    {
                        if( $print )
                            print " * create servicegroup " . $ObjectServiceNamePan . "\n";
                        $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($ObjectServiceNamePan);


                        $tmp_service = $this->sub->serviceStore->find($netObj[4]);
                        if( $tmp_service !== null )
                        {
                            if( $print )
                                print "   * add service " . $tmp_service->name() . " to servicgroup " . $ObjectServiceNamePan . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                    }
                }
                elseif( (preg_match("/^service tcp/i", $names_line)) or (preg_match("/^service udp/i", $names_line)) )
                {


                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    //print_r($netObj);
                    $next = 2;
                    $sport = "";
                    $dport = "";
                    $srv_protocol = $netObj[1];
                    #Supported to find first destination  than source and vice versa

                    if( isset($netObj[2]) )
                    {
                        $tmp_return = $this->service_get_source_destination($netObj, $next, $ObjectServiceNamePan, $ObjectServiceName, $names_line);

                        $port_final = $tmp_return[0];
                        $addlog = $tmp_return[1];
                        $next = $tmp_return[2];

                        if( $netObj[2] == "source" )
                        {
                            $sport = $port_final;
                        }
                        else
                        {
                            $dport = $port_final;
                        }
                    }
                    else
                    {
                        // In case:
                        // object service MPI-MS-SQL-Monitor_Reply
                        // service udp
                        $dport = '1-65535';
                    }

                    if( isset($netObj[$next]) )
                    {
                        $tmp_return = $this->service_get_source_destination($netObj, $next, $ObjectServiceNamePan, $ObjectServiceName, $names_line);

                        $port_final = $tmp_return[0];
                        $addlog = $tmp_return[1];
                        $next = $next;

                        if( $netObj[$next] == "source" )
                        {
                            $sport = $port_final;
                        }
                        else
                        {
                            $dport = $port_final;
                        }
                    }

                    if( $dport == "" )
                    {
                        $addlog = "service with no destination port found: " . $names_line;
                        #mwarning( $addlog, null, false );
                        //if dst port not found bring in a tmp value and report it
                        $dport = '65535';
                    }

                    /** @var Service $tmp_service */
                    if( $sport == "" )
                        $newName = $srv_protocol . "-" . $dport;
                    else
                        $newName = $srv_protocol . "-" . $sport . "-" . $dport;

                    $newName = $ObjectServiceNamePan;

                    $tmp_service = $this->sub->serviceStore->find($newName);
                    if( $tmp_service === null )
                    {
                        if( $print )
                            print " * create service " . $newName . "|-proto:" . $srv_protocol . "|-dport:" . $dport . "|-sport:" . $sport . "|\n";

                        $tmp_service = $this->sub->serviceStore->newService($newName, $srv_protocol, $dport, '', $sport);
                        if( $addlog != "" )
                            $tmp_service->set_node_attribute('error', $addlog);
                    }
                    /*
                    $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';");
                    //echo "FINAL: SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';\n";
                    if ($search->num_rows == 0) {
                        $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','$srv_protocol','$sport','$dport','0','',0,'$source','$vsys')";
                    }
                    */
                }
                elseif( preg_match("/^service [0-9]{1,3}$/", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $srv_protocol = $netObj[1];

                    if( $tmp_service !== null )
                    {
                        if( $tmp_service->isService() && $srv_protocol == $tmp_service->protocol() )
                            $found = TRUE;
                    }

                    if( !$found && $tmp_service === null )
                    {
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $ObjectServiceNamePan);
                        if( $tmp_service === null )
                        {
                            if( $print )
                                print " * create service tmp-" . $ObjectServiceNamePan . "\n";
                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $ObjectServiceNamePan, "tcp", "6500");
                            $tmp_service->set_node_attribute('error', 'Service Protocol found [' . $ObjectServiceName . '] and Protocol [' . $srv_protocol . '] - Replace it by the right app-id - tcp 6500 is used');
                            $tmp_service->setDescription( "protocol-id:{".$srv_protocol."}" );
                        }
                    }
                    else
                        mwarning("object: " . $ObjectServiceNamePan . " already available");
                }
                elseif( preg_match("/^service [a-z]*$/", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $srv_protocol = $netObj[1];

                    if( $tmp_service !== null )
                    {
                        if( $tmp_service->isService() && $srv_protocol == $tmp_service->protocol() )
                            $found = TRUE;
                    }

                    if( !$found && $tmp_service === null )
                    {
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $ObjectServiceNamePan);
                        if( $tmp_service === null )
                        {
                            if( $print )
                                print " * create service tmp-" . $ObjectServiceNamePan . "\n";
                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $ObjectServiceNamePan, "tcp", "6500");
                            $tmp_service->set_node_attribute('error', 'Service Protocol found [' . $ObjectServiceName . '] and Protocol [' . $srv_protocol . '] - Replace it by the right app-id - tcp 6500 is used');
                            $tmp_service->setDescription( "protocol-id:{".$srv_protocol."}" );
                        }
                    }
                    else
                        mwarning("object: " . $ObjectServiceNamePan . " already available");
                }
                elseif( preg_match("/^description/i", $names_line) )
                {

                }
            }


            if( preg_match("/^object service/i", $names_line) )
            {
                $isObjectService = 1;
                $names = explode(" ", $names_line);
                $ObjectServiceName = rtrim($names[2]);
                $ObjectServiceNamePan = $this->truncate_names($this->normalizeNames($ObjectServiceName));
            }

        }
    }

    function service_get_source_destination($netObj, $next, $ObjectServiceNamePan, $ObjectServiceName, $names_line)
    {
        if( ($netObj[$next] == "source") or ($netObj[$next] == "destination") )
        {
            $addlog = "";
            if( $netObj[$next + 1] == "eq" )
            {
                $port = $netObj[$next + 2];
                $next = $next + 3;//5
                if( is_numeric($port) )
                {
                    $port_final = $port;
                }
                else
                {
                    $port_final = $this->search_for_service_port( $ObjectServiceNamePan, $names_line, $port);
                }
                if( $port_final == "" )
                {
                    $addlog = 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                    $port_final = "6500";
                }
            }
            elseif( $netObj[$next + 1] == "neq" )
            {
                $port = $netObj[$next + 2];
                $next = $next + 3;//5
                if( is_numeric($port) )
                {
                    $port_final = $port;
                    $srv_port_before = intval($port_final) - 1;
                    $srv_port_after = intval($port_final) + 1;
                    $port_final = "1-$srv_port_before,$srv_port_after-65535";
                }
                else
                {
                    $port_final = $this->search_for_service_port( $ObjectServiceNamePan, $names_line, $port);

                    $srv_port_before = intval($port_final) - 1;
                    $srv_port_after = intval($port_final) + 1;
                    $port_final = "1-$srv_port_before,$srv_port_after-65535";
                }
                if( $port_final == "" )
                {
                    $addlog = 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                    $port_final = "6500";
                }
            }
            elseif( $netObj[$next + 1] == "lt" )
            {
                $port = $netObj[$next + 2];
                $next = $next + 3;//5
                if( is_numeric($port) )
                {
                    $port_final = $port;
                    $srv_port_before = intval($port_final);
                    $port_final = "1-$srv_port_before";
                }
                else
                {
                    $port_final = $this->search_for_service_port( $ObjectServiceNamePan, $names_line, $port);

                    $srv_port_before = intval($port_final);
                    $port_final = "1-$srv_port_before";
                }
                if( $port_final == "" )
                {
                    $addlog = 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                    $port_final = "6500";
                }
            }
            elseif( $netObj[$next + 1] == "gt" )
            {
                $port = $netObj[$next + 2];
                $next = $next + 3;//5
                if( is_numeric($port) )
                {
                    $port_final = $port;
                    $srv_port_before = intval($port_final);
                    $port_final = "$srv_port_before-65535";
                }
                else
                {
                    $port_final = $this->search_for_service_port( $ObjectServiceNamePan, $names_line, $port);

                    $srv_port_before = intval($port_final);
                    $port_final = "$srv_port_before-65535";
                }
                if( $port_final == "" )
                {
                    $addlog = 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                    $port_final = "6500";
                }
            }
            elseif( $netObj[$next + 1] == "range" )
            {
                $port_first = $netObj[$next + 2];
                $port_last = rtrim($netObj[$next + 3]);
                $next = $next + 4;//6

                $tmp_range_port = $this->range_get_ports($port_first, $port_last, $ObjectServiceName, $ObjectServiceNamePan, $names_line);
                $port_first_port = $tmp_range_port[0];
                $port_last_port = $tmp_range_port[1];

                # Check first if they are EQUAL
                if( $port_first_port == $port_last_port )
                {
                    $LastPort = "";
                }
                else
                {
                    $LastPort = "-$port_last_port";
                }

                $port_final = $port_first_port . $LastPort;
            }

        }

        return array($port_final, $addlog, $next);
    }

    function get_objectgroup_service()
    {
        global $projectdb;
        global $debug;
        global $print;

        $isServiceGroup = 0;
        $addMember = array();
        $addMemberID = array();


        foreach( $this->data as $line => $names_line )
        {
            $addlog = "";
            $names_line = trim($names_line);
            if( preg_match("/^object-group service/i", $names_line) )
            {
                $isServiceGroup = 1;
                $names = explode(" ", $names_line);
                $HostGroupName = rtrim($names[2]);
                $HostGroupNamePan = $this->truncate_names($this->normalizeNames($HostGroupName));
                if( isset($names[3]) )
                {
                    $Protocol = rtrim($names[3]);
                }
                else
                {
                    $Protocol = "";
                }

                /** @var ServiceGroup $tmp_servicegroup */
                $tmp_servicegroup = $this->sub->serviceStore->find($HostGroupNamePan);
                if( $tmp_servicegroup === null )
                {
                    if( $print )
                        print "     * create servicegroup: " . $HostGroupNamePan . "\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($HostGroupNamePan);
                }
                else
                {
                    mwarning("servicegroup: " . $HostGroupNamePan . " already available\n");
                    if( $tmp_servicegroup->isService() )
                    {
                        $addlog = "an servicegroup same name; member:" . $names_line;
                        $tmp_servicegroup->set_node_attribute('error', $addlog);


                        if( $print )
                            print "\n * create servicegroup: tmp_" . $HostGroupNamePan . "\n";
                        $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup("tmp_" . $HostGroupNamePan);
                        $tmp_servicegroup->set_node_attribute('error', "service object with same name available");
                    }
                }

                continue;
            }

            if( (!preg_match("/port-object /", $names_line)) and
                (!preg_match("/description /", $names_line)) and
                (!preg_match("/group-object /", $names_line)) and
                (!preg_match("/service-object /", $names_line)) )
            {
                $isServiceGroup = 0;
            }

            if( $isServiceGroup == 1 )
            {
                if( preg_match("/port-object /", $names_line) )
                {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $operator = $netObj[1];
                    if( $operator == "eq" )
                    {
                        $port = rtrim($netObj[2]);
                        if( is_numeric($port) )
                        {
                            $port_final = $port;
                        }
                        else
                        {
                            # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                            /*
                            $searchname = $projectdb->query("SELECT dport FROM services WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$port' LIMIT 1;");
                            $cisconame = $searchname->fetch_assoc();
                            $port_final = $cisconame['dport'];
                            */
                            $port_final = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port);

                            if( $port_final == "" )
                            {
                                $addlog = 'Unknown Service port mapping for: ' . $port . ' in ServiceGroup [' . $HostGroupNamePan . '] with Protocol [' . $Protocol . '] - NOT Adding to the DB!!';
                                #$portpan=$this->truncate_names($this->normalizeNames($port));
                                # Im not sure if is useful
                                #$projectdb->query("INSERT INTO services (name,type,name_ext,checkit,project,used) values('$portpan','$newlid','','$port','1','$projectname','0');");
                                #$projectdb->query("INSERT INTO services_groups (lid,member,project) values ('$lidgroup','$port','$projectname');");
                                $port_final = "mt-error";
                            }
                        }

                        if( $port_final == "mt-error" )
                        {

                        }
                        else
                        {
                            if( $Protocol == "tcp-udp" )
                            {
                                # TCP AND UDP
                                /** @var Service $tmp_service */
                                $tmp_service = $this->sub->serviceStore->find('tcp-' . $port_final);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "   * create service tcp-" . $port_final . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService('tcp-' . $port_final, 'tcp', $port_final);
                                }
                                if( $print )
                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                $tmp_servicegroup->addMember($tmp_service);

                                $tmp_service = $this->sub->serviceStore->find('udp-' . $port_final);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "   * create service udp-" . $port_final . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService('udp-' . $port_final, 'udp', $port_final);

                                }
                                if( $print )
                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                $tmp_servicegroup->addMember($tmp_service);
                            }
                            else
                            {
                                # TCP OR UDP
                                /** @var Service $tmp_service */
                                $tmp_service = $this->sub->serviceStore->find($Protocol . "-" . $port_final);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "   * create service " . $Protocol . "-" . $port_final . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService($Protocol . "-" . $port_final, $Protocol, $port_final);

                                }
                                if( $print )
                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                $tmp_servicegroup->addMember($tmp_service);
                            }
                        }
                    }
                    elseif( $operator == "range" )
                    {

                        $port_first = $netObj[2];
                        $port_last = rtrim($netObj[3]);


                        $tmp_range_port = $this->range_get_ports($port_first, $port_last, $HostGroupName, $HostGroupNamePan, $names_line);
                        $port_first_port = $tmp_range_port[0];
                        $port_last_port = $tmp_range_port[1];

                        # Check first if they are EQUAL
                        if( $port_first_port == $port_last_port )
                        {
                            $isRange = "";
                            $LastPort = "";
                            $vtype = "";
                            $addlog_warning = 'Moving Service-Range to Service [' . $names_line . '] ports are the same - No Action Required';
                        }
                        else
                        {
                            $isRange = "-range";
                            $isRange = "";
                            $LastPort = "-$port_last_port";
                            $vtype = "range";
                        }

                        $port_final = $port_first_port . $LastPort;
                        $name = $port_final;
                        if( $Protocol == "tcp-udp" )
                        {

                            $tmp_service = $this->sub->serviceStore->find('tcp-' . $name);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print "   * create service tcp-" . $port_final . "\n";
                                $tmp_service = $this->sub->serviceStore->newService('tcp-' . $name, 'tcp', $port_final);
                            }
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);

                            $tmp_service = $this->sub->serviceStore->find('udp-' . $name);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print "   * create service udp-" . $name . "\n";
                                $tmp_service = $this->sub->serviceStore->newService('udp-' . $name, 'udp', $port_final);

                            }
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                        else
                        {
                            $tmp_service = $this->sub->serviceStore->find($Protocol . "-" . $name);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print "   * create service " . $Protocol . "-" . $name . "\n";
                                $tmp_service = $this->sub->serviceStore->newService($Protocol . "-" . $name, $Protocol, $port_final);
                            }
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                    }
                }
                elseif( preg_match("/group-object /i", $names_line) )
                {

                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $obj2 = rtrim($netObj[1]);
                    #$addMember[] = "('$lidgroup','$obj2','$source','$vsys')";

                    $tmp_servicegroup2 = $this->sub->serviceStore->find($obj2);
                    if( $tmp_servicegroup2 !== null )
                    {
                        if( $print )
                            print "   * add servicegroup: " . $obj2 . " to servicegroup: " . $tmp_servicegroup->name() . "\n";
                        $tmp_servicegroup->addMember($tmp_servicegroup2);
                    }
                }
                elseif( preg_match("/service-object /i", $names_line) )
                {

                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $Protocol = $netObj[1];
                    if( ($Protocol == "tcp") or ($Protocol == "udp") )
                    {
                        if( !isset($netObj[2]) )
                        {
                            $tmp_service = $this->sub->serviceStore->find($Protocol . "-All");
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print "  * create service: " . $Protocol . "-All\n";
                                $tmp_service = $this->sub->serviceStore->newService($Protocol . "-All", $Protocol, "1-65535");
                            }
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                        else
                        {
                            $port = $netObj[2];
                            $next = 3;

                            # New addition to cover
                            #

                            if( $port == "eq" )
                            {
                                $port = $netObj[$next]; // 3
                                if( is_numeric($port) )
                                {
                                    $port_final = $port;

                                    $tmp_service = $this->sub->serviceStore->find($Protocol . "-" . $port_final);
                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print "  * create service: " . $Protocol . "-" . $port_final . "\n";
                                        $tmp_service = $this->sub->serviceStore->newService($Protocol . "-" . $port_final, $Protocol, $port_final);
                                    }
                                    if( $print )
                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                    $tmp_servicegroup->addMember($tmp_service);
                                }
                                else
                                {
                                    $tmp_service = $this->sub->serviceStore->find($port);
                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print "  * create service: " . $port . "\n";
                                        $tmp_service = $this->sub->serviceStore->newService($port, $Protocol, "6500");
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $tmp_service->set_node_attribute('error', $addlog);
                                    }
                                    /** @var Service $tmp_service */
                                    if( $tmp_service->isGroup() )
                                        $tmp_service = $this->sub->serviceStore->find($port."_".$Protocol);

                                    if( $tmp_service->isService() && $tmp_service->protocol() !==  $Protocol)
                                    {
                                        $dport = $tmp_service->getDestPort();
                                        $tmp_name = $Protocol."-".$dport;
                                        $tmp_service = $this->sub->serviceStore->find($tmp_name);
                                        if( $tmp_service === null )
                                        {
                                            if( $print )
                                                print "  * create service: " . $tmp_name . "|".$dport."\n";
                                            $tmp_service = $this->sub->serviceStore->newService($tmp_name, $Protocol, $dport);
                                        }
                                    }

                                    if( $print )
                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                    $tmp_servicegroup->addMember($tmp_service);
                                }
                            }
                            elseif( $port == "gt" )
                            {
                                $port = $netObj[$next];
                                if( is_numeric($port) )
                                {
                                    $port = $port + 1;
                                    $port_final = $port . "-65535";

                                    $tmp_service = $this->sub->serviceStore->find($Protocol . "-" . $port_final);
                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print "  * create service: " . $Protocol . "-" . $port_final . "\n";
                                        $tmp_service = $this->sub->serviceStore->newService($Protocol . "-" . $port_final, $Protocol, $port_final);
                                    }
                                    if( $print )
                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                    $tmp_servicegroup->addMember($tmp_service);
                                }
                                else
                                {
                                    $tmp_service = $this->sub->serviceStore->find($port);
                                    if( $tmp_service === null )
                                    {
                                        $port_final = "6500";
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for GT : ' . $port . ' Using 6500 port. Change it from the GUI';

                                        if( $print )
                                            print "  * create service: " . $port . "\n";
                                        $tmp_service = $this->sub->serviceStore->newService($port, $Protocol, $port_final);
                                        $tmp_service->set_node_attribute('error', $addlog);
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                    {
                                        $temp_dport = $tmp_service->getDestPort() + 1;
                                        $temp_protocol = $tmp_service->protocol();
                                        $port_final = $temp_dport . "-65535";

                                        $tmp_name = $temp_protocol . "-" . $port_final;

                                        $tmp_service = $this->sub->serviceStore->find($tmp_name);
                                        if( $tmp_service === null )
                                        {
                                            if( $print )
                                                print "  * create service: " . $tmp_name . "\n";
                                            $tmp_service = $this->sub->serviceStore->newService($tmp_name, $Protocol, $port_final);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                    }
                                }
                            }
                            elseif( $port == "lt" )
                            {
                                $port = $netObj[$next];
                                if( is_numeric($port) )
                                {
                                    $port = $port - 1;
                                    $port_final = "0-" . $port;

                                    $tmp_service = $this->sub->serviceStore->find($Protocol . "-" . $port_final);
                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print "  * create service: " . $Protocol . "-" . $port_final . "\n";
                                        $tmp_service = $this->sub->serviceStore->newService($Protocol . "-" . $port_final, $Protocol, $port_final);
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                }
                                else
                                {
                                    $tmp_service = $this->sub->serviceStore->find($port);
                                    if( $tmp_service === null )
                                    {
                                        $port_final = "6500";
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port . 'Using 6500 port. Change it from the GUI';

                                        if( $print )
                                            print "  * create service: " . $port . "\n";
                                        $tmp_service = $this->sub->serviceStore->newService($port, $Protocol, $port_final);
                                        $tmp_service->set_node_attribute('error', $addlog);
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                    {
                                        $searchnameData = $tmp_service->name();
                                        $temp_dport = $tmp_service->getDestPort() - 1;
                                        $temp_protocol = $tmp_service->protocol();
                                        $port_final = "0-" . $temp_dport;

                                        $tmp_name = $temp_protocol . "-" . $port_final;

                                        $tmp_service = $this->sub->serviceStore->find($tmp_name);
                                        if( $tmp_service === null )
                                        {
                                            if( $print )
                                                print "  * create service: " . $tmp_name . "\n";
                                            $tmp_service = $this->sub->serviceStore->newService($tmp_name, $temp_protocol, $port_final);

                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                    }
                                }

                            }
                            elseif( $port == "range" )
                            {
                                //Todo: SVEN remove
                                #return null;

                                $port_first = $netObj[$next]; //3
                                $port_last = rtrim($netObj[$next + 1]); //4

                                if( is_numeric($port_first) )
                                {
                                    $port_first_port = $port_first;
                                }
                                else
                                {
                                    $port_first_port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port_first);

                                    if( $port_first_port == "" )
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_first . 'Using 6500 port. Change it from the GUI';
                                        $port_first_port = "6500";
                                    }
                                }
                                if( is_numeric($port_last) )
                                {
                                    $port_last_port = $port_last;
                                }
                                else
                                {

                                    $port_last_port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port_last);

                                    if( $port_last_port == "" )
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_last . 'Using 6500 port. Change it from the GUI';
                                        $port_last_port = "6500";
                                    }
                                }

                                # Check first if they are EQUAL
                                if( $port_first_port == $port_last_port )
                                {
                                    $isRange = "";
                                    $LastPort = "";
                                    $vtype = "";
                                    $addlog = 'Moving Service-Range to Service [' . $names_line . '] ports are the same - No Action Required';
                                }
                                else
                                {
                                    $isRange = "-range";
                                    $isRange = "";
                                    $LastPort = "-" . $port_last_port;
                                    $vtype = "range";
                                }

                                $name_ext = $Protocol . "-" . $port_first_port . $LastPort . "-source";
                                $final_protocol = $Protocol;
                                $final_source_port = $port_first_port . $LastPort;
                                $final_destination_port = '1-65535';
                                $tmp_service = $this->sub->serviceStore->find($name_ext);


                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "  * create service: " . $name_ext . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                    if( $addlog != "" )
                                        $tmp_service->set_node_attribute('error', $addlog);
                                    if( $print )
                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                    $tmp_servicegroup->addMember($tmp_service);
                                }
                                else
                                {
                                    if( $print )
                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                    $tmp_servicegroup->addMember($tmp_service);
                                }
                            }


                            #

                            if( $port == "source" )
                            {
                                $next = 4;
                                $port = $netObj[3];

                                if( !isset($port) )
                                {
                                    $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($Protocol, '1-65535', '1-65535');

                                    if( $tmp_service === null )
                                    {
                                        $tmp_service = $this->sub->serviceStore->newService($Protocol . "-All", $Protocol, '1-65535', "", '1-65535');
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                        $tmp_servicegroup->addMember($tmp_service);
                                }

                                if( $port == "eq" )
                                {
                                    $port = $netObj[$next]; // 3

                                    $this->serviceEQ("source", $port, $HostGroupNamePan, $HostGroupName,$names_line, $Protocol, $tmp_servicegroup);
                                    /*
                                    if( !is_numeric($port) )
                                        $port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port);

                                    if( is_numeric($port) )
                                    {
                                        $port_final = $port;
                                        $final_source_port = $port_final;
                                        $final_destination_port = '1-65535';
                                        $final_protocol = $Protocol;
                                        //name,name_ext,protocol,sport,dport,
                                        $name = $Protocol . "-" . $port_final . "-source";
                                        $name_ext = $name;
                                        #$getService = $projectdb->query("SELECT name FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='1-65535' AND vsys='$vsys';");

                                        $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);
                                    }
                                    else
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $port_final = "6500";
                                        $final_source_port = $port_final;
                                        $final_destination_port = '1-65535';
                                        $final_protocol = $Protocol;
                                        $name = $port . "-source";
                                        $name_ext = $name;
                                        #$getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");

                                        $tmp_service = $this->sub->serviceStore->find($port);
                                    }

                                    if( $tmp_service === null )
                                    {
                                        $tmp_service = $this->sub->serviceStore->find($name_ext);
                                        if( $tmp_service === null )
                                        {
                                            if( $print )
                                                print "  * create service: " . $name_ext . "\n";
                                            $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                        }
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                    {
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    */
                                }
                                elseif( $port == "gt" )
                                {
                                    $port = $netObj[$next];
                                    if( is_numeric($port) )
                                    {
                                        $port = $port + 1;
                                        $port_final = $port . "-65535";
                                        $final_source_port = $port_final;
                                        $final_destination_port = '1-65535';
                                        $final_protocol = $Protocol;
                                        $name = $Protocol . "-" . $port_final . "-source";
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);
                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }

                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                    }
                                    else
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for GT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $port_final = "6500";
                                        $final_source_port = $port_final;
                                        $final_destination_port = '1-65535';
                                        $final_protocol = $Protocol;
                                        $name = $port . "-source";
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->find($port);
                                        #$getService = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");

                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            $temp_dport = $tmp_service->getDestPort() + 1;
                                            $temp_protocol = $tmp_service->protocol();
                                            $port_final = $temp_dport . "-65535";
                                            $final_source_port = $port_final;
                                            $final_destination_port = '1-65535';
                                            $final_protocol = $temp_protocol;
                                            $name = $temp_protocol . "-" . $port_final;
                                            $name_ext = $name;

                                            $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);
                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                }
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                    }
                                }
                                elseif( $port == "lt" )
                                {
                                    $port = $netObj[$next];
                                    if( is_numeric($port) )
                                    {
                                        $port = $port - 1;
                                        $port_final = "0-" . $port;
                                        $final_source_port = $port_final;
                                        $final_destination_port = '1-65535';
                                        $final_protocol = $Protocol;
                                        $name = $Protocol . "-" . $port_final . "-source";
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);
                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                    }
                                    else
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $port_final = "6500";

                                        $final_source_port = $port_final;
                                        $final_destination_port = '1-65535';
                                        $final_protocol = $Protocol;
                                        $name = $port . "-source";
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->find($port);

                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            #$searchnameData = $getService->fetch_assoc();
                                            $temp_dport = $tmp_service->getDestPort() - 1;
                                            $temp_protocol = $tmp_service->protocol();
                                            $port_final = "0-" . $temp_dport;
                                            $final_source_port = $port_final;
                                            $final_destination_port = '1-65535';
                                            $final_protocol = $temp_protocol;
                                            $name = $temp_protocol . "-" . $port_final;
                                            $name_ext = $name;

                                            $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);


                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                }
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                    }
                                }
                                elseif( $port == "range" )
                                {
                                    $port_first = $netObj[$next]; //3
                                    $port_last = rtrim($netObj[$next + 1]); //4


                                    $tmp_range_port = $this->range_get_ports($port_first, $port_last, $HostGroupName, $HostGroupNamePan, $names_line);
                                    $port_first_port = $tmp_range_port[0];
                                    $port_last_port = $tmp_range_port[1];

                                    # Check first if they are EQUAL
                                    if( $port_first_port == $port_last_port )
                                    {
                                        $isRange = "";
                                        $LastPort = "";
                                        $vtype = "";
                                        $addlog = 'Moving Service-Range to Service [' . $names_line . '] ports are the same - No Action Required';
                                    }
                                    else
                                    {
                                        $isRange = "-range";
                                        $isRange = "";
                                        $LastPort = "-" . $port_last_port;
                                        $vtype = "range";
                                    }

                                    $name_ext = $Protocol . "-" . $port_first_port . $LastPort . "-source";
                                    $final_protocol = $Protocol;
                                    $final_source_port = $port_first_port . $LastPort;
                                    $final_destination_port = '1-65535';
                                    $tmp_service = $this->sub->serviceStore->find($name_ext);


                                    if( $tmp_service === null )
                                    {
                                        $tmp_service = $this->sub->serviceStore->find($name_ext);
                                        if( $tmp_service === null )
                                        {
                                            if( $print )
                                                print "  * create service: " . $name_ext . "\n";
                                            $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                        }
                                        if( $addlog != "" )
                                            $tmp_service->set_node_attribute('error', $addlog);
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                    {
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                }
                            }

                            if( $port == "destination" )
                            {
                                //Todo: SVEN remove
                                #return null;

                                $next = 4;
                                $port = $netObj[3];

                                if( !isset($port) )
                                {
                                    $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($Protocol, '1-65535', '');

                                    if( $tmp_service === null )
                                    {
                                        $tmp_service = $this->sub->serviceStore->find($Protocol . "-All");
                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->newService($Protocol . "-All", $Protocol, '1-65535');
                                        }
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                        $tmp_servicegroup->addMember($tmp_service);
                                }

                                if( $port == "eq" )
                                {
                                    $port = $netObj[$next]; // 3

                                    $this->serviceEQ("destination", $port, $HostGroupNamePan, $HostGroupName, $names_line, $Protocol, $tmp_servicegroup);
                                    /*
                                    if( !is_numeric($port) )
                                        $port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port);

                                    if( is_numeric($port) )
                                    {
                                        $port_final = $port;
                                        $final_source_port = "";
                                        $final_destination_port = $port_final;
                                        $final_protocol = $Protocol;
                                        //name,name_ext,protocol,sport,dport,
                                        $name = $Protocol . "-" . $port_final;
                                        $name_ext = $name;
                                        #$getService = $projectdb->query("SELECT name FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='1-65535' AND vsys='$vsys';");

                                        $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port);
                                    }
                                    else
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $port_final = "6500";
                                        $final_source_port = "";
                                        $final_destination_port = $port_final;

                                        $final_protocol = $Protocol;
                                        $name = $port;
                                        $name_ext = $name;
                                        #$getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");

                                        $tmp_service = $this->sub->serviceStore->find($port);
                                    }

                                    if( $tmp_service === null )
                                    {
                                        $tmp_service = $this->sub->serviceStore->find($name_ext);
                                        if( $tmp_service === null )
                                        {
                                            if( $print )
                                                print "  * create service: " . $name_ext . "\n";
                                            $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                        }
                                        if( $addlog != "" )
                                            $tmp_service->set_node_attribute('error', $addlog);
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                    {
                                        if( $tmp_service->isService() && $tmp_service->protocol() !==  $Protocol)
                                        {
                                            $dport = $tmp_service->getDestPort();
                                            $tmp_name = $Protocol."-".$dport;
                                            $tmp_service = $this->sub->serviceStore->find($tmp_name);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $tmp_name . "|".$dport."\n";
                                                $tmp_service = $this->sub->serviceStore->newService($tmp_name, $Protocol, $dport);
                                            }
                                        }

                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    */
                                }
                                elseif( $port == "gt" )
                                {
                                    $port = $netObj[$next];

                                    if( is_numeric($port) )
                                    {
                                        $port = $port + 1;
                                        $port_final = $port . "-65535";
                                        $final_source_port = "";
                                        $final_destination_port = $port_final;
                                        $final_protocol = $Protocol;
                                        $name = $Protocol . "-" . $port_final;
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                    }
                                    else
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for GT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $port_final = "6500";
                                        $final_source_port = "";
                                        $final_destination_port = $port_final;
                                        $final_protocol = $Protocol;
                                        $name = $port . "-source";
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->find($port);

                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            $temp_dport = $tmp_service->getDestPort() + 1;
                                            $temp_protocol = $tmp_service->protocol();
                                            $port_final = $temp_dport . "-65535";
                                            $final_source_port = "";
                                            $final_destination_port = $port_final;
                                            $final_protocol = $temp_protocol;
                                            $name = $temp_protocol . "-" . $port_final;
                                            $name_ext = $name;

                                            $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                }
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                    }
                                }
                                elseif( $port == "lt" )
                                {
                                    $port = $netObj[$next];

                                    if( is_numeric($port) )
                                    {
                                        $port = $port - 1;
                                        $port_final = "0-" . $port;
                                        $final_source_port = "";
                                        $final_destination_port = $port_final;
                                        $final_protocol = $Protocol;
                                        $name = $Protocol . "-" . $port_final;
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                    }
                                    else
                                    {
                                        $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $port_final = "6500";

                                        $final_source_port = "";
                                        $final_destination_port = $port_final;
                                        $final_protocol = $Protocol;
                                        $name = $port;
                                        $name_ext = $name;

                                        $tmp_service = $this->sub->serviceStore->find($port);

                                        if( $tmp_service === null )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                            }
                                            if( $addlog != "" )
                                                $tmp_service->set_node_attribute('error', $addlog);
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                        {
                                            $temp_dport = $tmp_service->getDestPort() - 1;
                                            $temp_protocol = $tmp_service->protocol();
                                            $port_final = "0-" . $temp_dport;
                                            $final_source_port = "";
                                            $final_destination_port = $port_final;
                                            $final_protocol = $temp_protocol;
                                            $name = $temp_protocol . "-" . $port_final;
                                            $name_ext = $name;

                                            $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                }
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                    }
                                }
                                elseif( $port == "range" )
                                {
                                    $port_first = $netObj[$next]; //3
                                    $port_last = rtrim($netObj[$next + 1]); //4

                                    $tmp_range_port = $this->range_get_ports($port_first, $port_last, $HostGroupName, $HostGroupNamePan, $names_line);
                                    $port_first_port = $tmp_range_port[0];
                                    $port_last_port = $tmp_range_port[1];

                                    # Check first if they are EQUAL
                                    if( $port_first_port == $port_last_port )
                                    {
                                        $isRange = "";
                                        $LastPort = "";
                                        $vtype = "";
                                        $addlog = 'Moving Service-Range to Service [' . $names_line . '] ports are the same - No Action Required';
                                    }
                                    else
                                    {
                                        $isRange = "-range";
                                        $isRange = "";
                                        $LastPort = "-" . $port_last_port;
                                        $vtype = "range";
                                    }

                                    $name_ext = $Protocol . "-" . $port_first_port . $LastPort;
                                    $final_protocol = $Protocol;
                                    $final_source_port = "";
                                    $final_destination_port = $port_first_port . $LastPort;
                                    $tmp_service = $this->sub->serviceStore->find($name_ext);

                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print "  * create service: " . $name_ext . "\n";
                                        $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                        if( $addlog != "" )
                                            $tmp_service->set_node_attribute('error', $addlog);
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                    else
                                    {
                                        if( $print )
                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                        $tmp_servicegroup->addMember($tmp_service);
                                    }
                                }
                            }
                        }
                    }
                    elseif( $Protocol == "tcp-udp" )
                    {
                        if( isset($netObj[2]) )
                        {
                            $port = $netObj[2];

                            $next = 3;
                            if( $port == "destination" )
                            {
                                $next = 4;
                                $port = $netObj[3];
                            }

                            if( $port == "eq" )
                            {
                                $port = $netObj[$next];
                                $port_final = "";
                                if( is_numeric($port) )
                                {
                                    $port_final = $port;
                                }
                                else
                                {
                                    $tmp_service = $this->sub->serviceStore->find($port);
                                    if( $tmp_service !== null )
                                    {
                                        if( $tmp_service->isService() )
                                            $port_final = $tmp_service->getDestPort();
                                        else
                                        {
                                            foreach( $tmp_service->members() as $member )
                                            {
                                                if( $port_final != "" )
                                                {
                                                    print "portfinal is: " . $port_final . "\n";
                                                    $tmp_member_port = $member->getDestPort();
                                                    if( $port_final != $tmp_member_port )
                                                        mwarning("servicegroup has different ports available: " . $tmp_member_port, null, FALSE);
                                                }
                                                $port_final = $member->getDestPort();
                                            }
                                        }
                                    }
                                    else
                                    {
                                        $addlog = 'Unknown Service-Range  [' . $HostGroupName . '] source-port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                                        $port_final = "6500";
                                    }
                                }


                                $tmp_service = $this->sub->serviceStore->find('tcp-' . $port_final);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "   * create service tcp-" . $port_final . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService('tcp-' . $port_final, 'tcp', $port_final);
                                    if( $addlog !== "" )
                                        $tmp_service->set_node_attribute('error', $addlog);
                                }
                                if( $print )
                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                $tmp_servicegroup->addMember($tmp_service);

                                $tmp_service = $this->sub->serviceStore->find('udp-' . $port_final);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "   * create service udp-" . $port_final . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService('udp-' . $port_final, 'udp', $port_final);
                                    if( $addlog !== "" )
                                        $tmp_service->set_node_attribute('error', $addlog);

                                }
                                if( $print )
                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                $tmp_servicegroup->addMember($tmp_service);
                            }
                            elseif( $port == "range" )
                            {
                                $port_first = $netObj[$next];
                                $port_last = rtrim($netObj[$next + 1]);

                                $tmp_range_port = $this->range_get_ports($port_first, $port_last, $HostGroupName, $HostGroupNamePan, $names_line);
                                $port_first_port = $tmp_range_port[0];
                                $port_last_port = $tmp_range_port[1];

                                # Check first if they are EQUAL
                                if( $port_first_port == $port_last_port )
                                {
                                    $isRange = "";
                                    $LastPort = "";
                                    $vtype = "";
                                    $addlog = 'Moving Service-Range to Service [' . $names_line . '] ports are the same' . ' No Action Required';
                                }
                                else
                                {
                                    $isRange = "-range";
                                    $isRange = "";
                                    $LastPort = "-$port_last_port";
                                    $vtype = "range";
                                }

                                $port_final = $port_first_port . $LastPort;
                                $name = $port_final;

                                $tmp_service = $this->sub->serviceStore->find('tcp-' . $name);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "   * create service tcp-" . $port_final . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService('tcp-' . $name, 'tcp', $port_final);
                                }
                                if( $print )
                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                $tmp_servicegroup->addMember($tmp_service);

                                $tmp_service = $this->sub->serviceStore->find('udp-' . $name);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "   * create service udp-" . $name . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService('udp-' . $name, 'udp', $port_final);

                                }
                                if( $print )
                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                $tmp_servicegroup->addMember($tmp_service);
                            }
                        }
                        else
                        {
                            mwarning("netObj[2] not set: " . $names_line);
                        }
                    }
                    elseif( $Protocol == "object" )
                    {

                        $obj2 = $netObj[2];
                        $obj2pan = $this->truncate_names($this->normalizeNames($obj2));

                        $tmp_service = $this->sub->serviceStore->find($obj2pan);
                        if( $tmp_service === null )
                        {
                            $obj2pan = "tmp-" . $obj2pan;
                            $tmp_service = $this->sub->serviceStore->find($obj2pan);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print "  * create service: " . $obj2pan . "\n";
                                $tmp_service = $this->sub->serviceStore->newService($obj2pan, "tcp", "6500");
                            }
                        }

                        if( $tmp_service !== null )
                        {
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                    }
                    else
                    {
                        if( ($Protocol == "icmp") or ($Protocol == "icmp6") )
                        {
                            if( isset($netObj[2]) )
                            {
                                $code = $netObj[2];
                                $servicename = "$Protocol-$code";
                            }
                            else
                            {
                                $code = "";
                                $servicename = $Protocol;
                            }


                            $tmp_service = $this->sub->serviceStore->find("tmp-" . $servicename);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print " * create service tmp-" . $servicename . "\n";
                                $tmp_service = $this->sub->serviceStore->newService("tmp-" . $servicename, "tcp", "6500");
                                $tmp_service->set_node_attribute('error', 'ICMP Service found [' . $servicename . '] with icmptype: "' . $code . '" - Replace it by the ICMP app-id - tcp 6500 is used');
                            }
                            if( $print )
                                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                        elseif( $Protocol == 'ip' )
                        {
                            if( isset($netObj[2]) )
                            {
                                if( $netObj[2] == "source" )
                                {
                                    $next = 4;
                                    $port = $netObj[3];
                                    $protocols = ['tcp', 'udp'];

                                    foreach( $protocols as $Protocol )
                                    {
                                        if( !isset($port) )
                                        {
                                            $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($Protocol, '1-65535', '1-65535');

                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->newService($Protocol . "-All", $Protocol, '1-65535', "", '1-65535');
                                                }
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                                $tmp_servicegroup->addMember($tmp_service);
                                        }

                                        if( $port == "eq" )
                                        {
                                            $port = $netObj[$next]; // 3
                                            if( is_numeric($port) )
                                            {
                                                $port_final = $port;
                                                $final_source_port = $port_final;
                                                $final_destination_port = '1-65535';
                                                $final_protocol = $Protocol;
                                                //name,name_ext,protocol,sport,dport,
                                                $name = $Protocol . "-" . $port_final . "-source";
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);
                                            }
                                            else
                                            {
                                                $addlog = 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                                                $port_final = "6500";
                                                $final_source_port = $port_final;
                                                $final_destination_port = '1-65535';
                                                $final_protocol = $Protocol;
                                                $name = $port . "-source";
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->find($port);
                                            }

                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                }
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                        elseif( $port == "gt" )
                                        {
                                            $port = $netObj[$next];
                                            if( is_numeric($port) )
                                            {
                                                $port = $port + 1;
                                                $port_final = $port . "-65535";
                                                $final_source_port = $port_final;
                                                $final_destination_port = '1-65535';
                                                $final_protocol = $Protocol;
                                                $name = $Protocol . "-" . $port_final . "-source";
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                    if( $tmp_service === null )
                                                    {
                                                        if( $print )
                                                            print "  * create service: " . $name_ext . "\n";
                                                        $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    }
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                            }
                                            else
                                            {
                                                $addlog = 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for GT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                                $port_final = "6500";
                                                $final_source_port = $port_final;
                                                $final_destination_port = '1-65535';
                                                $final_protocol = $Protocol;
                                                $name = $port . "-source";
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->find($port);

                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                    if( $tmp_service === null )
                                                    {
                                                        if( $print )
                                                            print "  * create service: " . $name_ext . "\n";
                                                        $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    }
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    $temp_dport = $tmp_service->getDestPort() + 1;
                                                    $temp_protocol = $tmp_service->protocol();
                                                    $port_final = $temp_dport . "-65535";
                                                    $final_source_port = $port_final;
                                                    $final_destination_port = '1-65535';
                                                    $final_protocol = $temp_protocol;
                                                    $name = $temp_protocol . "-" . $port_final;
                                                    $name_ext = $name;

                                                    $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                                    if( $tmp_service === null )
                                                    {
                                                        $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                        if( $tmp_service === null )
                                                        {
                                                            if( $print )
                                                                print "  * create service: " . $name_ext . "\n";
                                                            $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                        }
                                                        if( $addlog != "" )
                                                            $tmp_service->set_node_attribute('error', $addlog);
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                    else
                                                    {
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                }
                                            }
                                        }
                                        elseif( $port == "lt" )
                                        {
                                            $port = $netObj[$next];
                                            if( is_numeric($port) )
                                            {
                                                $port = $port - 1;
                                                $port_final = "0-" . $port;
                                                $final_source_port = $port_final;
                                                $final_destination_port = '1-65535';
                                                $final_protocol = $Protocol;
                                                $name = $Protocol . "-" . $port_final . "-source";
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                    if( $tmp_service === null )
                                                    {
                                                        if( $print )
                                                            print "  * create service: " . $name_ext . "\n";
                                                        $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    }
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                            }
                                            else
                                            {
                                                $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                                $port_final = "6500";

                                                $final_source_port = $port_final;
                                                $final_destination_port = '1-65535';
                                                $final_protocol = $Protocol;
                                                $name = $port . "-source";
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->find($port);

                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    $temp_dport = $tmp_service->getDestPort() - 1;
                                                    $temp_protocol = $tmp_service->protocol();
                                                    $port_final = "0-" . $temp_dport;
                                                    $final_source_port = $port_final;
                                                    $final_destination_port = '1-65535';
                                                    $final_protocol = $temp_protocol;
                                                    $name = $temp_protocol . "-" . $port_final;
                                                    $name_ext = $name;

                                                    $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);


                                                    if( $tmp_service === null )
                                                    {
                                                        $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                        if( $tmp_service === null )
                                                        {
                                                            if( $print )
                                                                print "  * create service: " . $name_ext . "\n";
                                                            $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                        }
                                                        if( $addlog != "" )
                                                            $tmp_service->set_node_attribute('error', $addlog);
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                    else
                                                    {
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                }
                                            }

                                        }
                                        elseif( $port == "range" )
                                        {
                                            $port_first = $netObj[$next]; //3
                                            $port_last = rtrim($netObj[$next + 1]); //4


                                            $tmp_range_port = $this->range_get_ports($port_first, $port_last, $HostGroupName, $HostGroupNamePan, $names_line);
                                            $port_first_port = $tmp_range_port[0];
                                            $port_last_port = $tmp_range_port[1];

                                            # Check first if they are EQUAL
                                            if( $port_first_port == $port_last_port )
                                            {
                                                $isRange = "";
                                                $LastPort = "";
                                                $vtype = "";
                                                $addlog = 'Moving Service-Range to Service [' . $names_line . '] ports are the same - No Action Required';
                                            }
                                            else
                                            {
                                                $isRange = "-range";
                                                $isRange = "";
                                                $LastPort = "-" . $port_last_port;
                                                $vtype = "range";
                                            }

                                            $name_ext = $Protocol . "-" . $port_first_port . $LastPort . "-source";
                                            $final_protocol = $Protocol;
                                            $final_source_port = $port_first_port . $LastPort;
                                            $final_destination_port = '1-65535';
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);


                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                    }
                                }
                                elseif( $netObj[2] == "destination" )
                                {
                                    $next = 4;
                                    $port = $netObj[3];
                                    $protocols = ['tcp', 'udp'];
                                    foreach( $protocols as $Protocol )
                                    {

                                        if( !isset($port) )
                                        {
                                            $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($Protocol, '1-65535', '');

                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->newService($Protocol . "-All", $Protocol, '1-65535');
                                                }
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                                $tmp_servicegroup->addMember($tmp_service);
                                        }

                                        if( $port == "eq" )
                                        {
                                            $port = $netObj[$next]; // 3

                                            if( !is_numeric($port) )
                                                $port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port);

                                            if( is_numeric($port) )
                                            {
                                                $port_final = $port;
                                                $final_source_port = "";
                                                $final_destination_port = $port_final;
                                                $final_protocol = $Protocol;
                                                //name,name_ext,protocol,sport,dport,
                                                $name = $Protocol . "-" . $port_final;
                                                $name_ext = $name;
                                                #$getService = $projectdb->query("SELECT name FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='1-65535' AND vsys='$vsys';");

                                                $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port);
                                            }
                                            else
                                            {
                                                $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                                                $port_final = "6500";
                                                $final_source_port = "";
                                                $final_destination_port = $port_final;

                                                $final_protocol = $Protocol;
                                                $name = $port;
                                                $name_ext = $name;
                                                #$getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");

                                                $tmp_service = $this->sub->serviceStore->find($port);
                                            }

                                            if( $tmp_service === null )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                }
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                        elseif( $port == "gt" )
                                        {
                                            $port = $netObj[$next];

                                            if( is_numeric($port) )
                                            {
                                                $port = $port + 1;
                                                $port_final = $port . "-65535";
                                                $final_source_port = "";
                                                $final_destination_port = $port_final;
                                                $final_protocol = $Protocol;
                                                $name = $Protocol . "-" . $port_final;
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                    if( $tmp_service === null )
                                                    {
                                                        if( $print )
                                                            print "  * create service: " . $name_ext . "\n";
                                                        $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    }
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                            }
                                            else
                                            {
                                                $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for GT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                                $port_final = "6500";
                                                $final_source_port = "";
                                                $final_destination_port = $port_final;
                                                $final_protocol = $Protocol;
                                                $name = $port . "-source";
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->find($port);

                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                    if( $tmp_service === null )
                                                    {
                                                        if( $print )
                                                            print "  * create service: " . $name_ext . "\n";
                                                        $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    }
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    $temp_dport = $tmp_service->getDestPort() + 1;
                                                    $temp_protocol = $tmp_service->protocol();
                                                    $port_final = $temp_dport . "-65535";
                                                    $final_source_port = "";
                                                    $final_destination_port = $port_final;
                                                    $final_protocol = $temp_protocol;
                                                    $name = $temp_protocol . "-" . $port_final;
                                                    $name_ext = $name;

                                                    $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                                    if( $tmp_service === null )
                                                    {
                                                        $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                        if( $tmp_service === null )
                                                        {
                                                            if( $print )
                                                                print "  * create service: " . $name_ext . "\n";
                                                            $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                        }
                                                        if( $addlog != "" )
                                                            $tmp_service->set_node_attribute('error', $addlog);
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                    else
                                                    {
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                }
                                            }
                                        }
                                        elseif( $port == "lt" )
                                        {
                                            $port = $netObj[$next];

                                            if( is_numeric($port) )
                                            {
                                                $port = $port - 1;
                                                $port_final = "0-" . $port;
                                                $final_source_port = "";
                                                $final_destination_port = $port_final;
                                                $final_protocol = $Protocol;
                                                $name = $Protocol . "-" . $port_final;
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                                if( $tmp_service === null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                    if( $tmp_service === null )
                                                    {
                                                        if( $print )
                                                            print "  * create service: " . $name_ext . "\n";
                                                        $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    }
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                            }
                                            else
                                            {
                                                $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port . 'Using 6500 port. Change it from the GUI';
                                                $port_final = "6500";

                                                $final_source_port = "";
                                                $final_destination_port = $port_final;
                                                $final_protocol = $Protocol;
                                                $name = $port;
                                                $name_ext = $name;

                                                $tmp_service = $this->sub->serviceStore->find($name_ext);

                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "  * create service: " . $name_ext . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                    if( $addlog != "" )
                                                        $tmp_service->set_node_attribute('error', $addlog);
                                                    if( $print )
                                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                }
                                                else
                                                {
                                                    $temp_dport = $tmp_service->getDestPort() - 1;
                                                    $temp_protocol = $tmp_service->protocol();
                                                    $port_final = "0-" . $temp_dport;
                                                    $final_source_port = "";
                                                    $final_destination_port = $port_final;
                                                    $final_protocol = $temp_protocol;
                                                    $name = $temp_protocol . "-" . $port_final;
                                                    $name_ext = $name;

                                                    $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);

                                                    if( $tmp_service === null )
                                                    {
                                                        $tmp_service = $this->sub->serviceStore->find($name_ext);
                                                        if( $tmp_service === null )
                                                        {
                                                            if( $print )
                                                                print "  * create service: " . $name_ext . "\n";
                                                            $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                        }
                                                        if( $addlog != "" )
                                                            $tmp_service->set_node_attribute('error', $addlog);
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                    else
                                                    {
                                                        if( $print )
                                                            print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                        $tmp_servicegroup->addMember($tmp_service);
                                                    }
                                                }
                                            }
                                        }
                                        elseif( $port == "range" )
                                        {
                                            $port_first = $netObj[$next]; //3
                                            $port_last = rtrim($netObj[$next + 1]); //4

                                            $tmp_range_port = $this->range_get_ports($port_first, $port_last, $HostGroupName, $HostGroupNamePan, $names_line);
                                            $port_first_port = $tmp_range_port[0];
                                            $port_last_port = $tmp_range_port[1];


                                            # Check first if they are EQUAL
                                            if( $port_first_port == $port_last_port )
                                            {
                                                $isRange = "";
                                                $LastPort = "";
                                                $vtype = "";
                                                $addlog = 'Moving Service-Range to Service [' . $names_line . '] ports are the same - No Action Required';
                                            }
                                            else
                                            {
                                                $isRange = "-range";
                                                $isRange = "";
                                                $LastPort = "-" . $port_last_port;
                                                $vtype = "range";
                                            }

                                            #$name_ext = $Protocol . $port_first_port . $LastPort;
                                            $name_ext = $Protocol . $port_first_port . $LastPort;
                                            $final_protocol = $Protocol;
                                            $final_source_port = "";
                                            $final_destination_port = $port_first_port . $LastPort;
                                            $tmp_service = $this->sub->serviceStore->find($name_ext);

                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "  * create service: " . $name_ext . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                                                if( $addlog != "" )
                                                    $tmp_service->set_node_attribute('error', $addlog);
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            else
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                $Protocol_array = array("tcp", "udp");
                                foreach( $Protocol_array as $Protocol )
                                {
                                    $tmp_service = $this->sub->serviceStore->find($Protocol . "-All");
                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print "  * create service: " . $Protocol . "-All\n";
                                        $tmp_service = $this->sub->serviceStore->newService($Protocol . "-All", $Protocol, "1-65535");
                                    }
                                    if( $print )
                                        print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                    $tmp_servicegroup->addMember($tmp_service);
                                }
                            }

                        }
                        else
                        {
                            $tmp_service = $this->sub->serviceStore->find("tmp-" . $Protocol);
                            if( $tmp_service === null )
                            {
                                if( $print )
                                    print " * create service Object: tmp-" . $Protocol . ", tcp, 6500\n";
                                $tmp_service = $this->sub->serviceStore->newService("tmp-" . $Protocol, "tcp", "6500");
                                $tmp_service->set_node_attribute('error', "no service protocol - tcp is used - 6500");
                                $tmp_servicegroup->addMember($tmp_service);
                            }
                            else
                                $tmp_servicegroup->addMember($tmp_service);
                        }
                    }
                }
            }
        }
    }

    function search_for_service_port( $ObjectServiceNamePan, $names_line, $port)
    {
        $port_final = "";
        $tmp_service = $this->sub->serviceStore->find($port);
        if( $tmp_service !== null )
        {
            if( $tmp_service->isService() )
                $port_final = $tmp_service->getDestPort();
            else
            {
                $tmp_service = $this->sub->serviceStore->find("tcp-" . $port);
                if( $tmp_service !== null )
                {
                    if( $tmp_service->isService() )
                        $port_final = $tmp_service->getDestPort();
                }
                else
                {
                    $tmp_service = $this->sub->serviceStore->find("udp-" . $port);
                    if( $tmp_service !== null )
                    {
                        if( $tmp_service->isService() )
                            $port_final = $tmp_service->getDestPort();
                    }
                    else
                    {
                        $tmp_service = $this->sub->serviceStore->find($port . "_tcp");
                        if( $tmp_service !== null )
                        {
                            if( $tmp_service->isService() )
                                $port_final = $tmp_service->getDestPort();
                        }
                        else
                        {
                            $tmp_service = $this->sub->serviceStore->find($port . "_udp");
                            if( $tmp_service !== null )
                            {
                                if( $tmp_service->isService() )
                                    $port_final = $tmp_service->getDestPort();
                            }
                            else
                                mwarning("servicegroup found: " . $port . " with line: " . $names_line);
                        }
                    }
                }
            }
        }
        else
        {
            $tmp_service = $this->sub->serviceStore->find("tmp-" . $port);
            if( $tmp_service !== null )
                $port_final = $tmp_service->getDestPort();
            else
                mwarning("service not found: tmp-" . $port . " name: " . $ObjectServiceNamePan . " line: " . $names_line);
        }

        return $port_final;
    }


    function range_get_ports($port_first, $port_last, $HostGroupName, $HostGroupNamePan, $names_line)
    {
        if( is_numeric($port_first) )
        {
            $port_first_port = $port_first;
        }
        else
        {
            $port_first_port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port_first);

            if( $port_first_port == "" )
            {
                $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_first . 'Using 6500 port. Change it from the GUI';
                $port_first_port = "6500";
            }
        }
        if( is_numeric($port_last) )
        {
            $port_last_port = $port_last;
        }
        else
        {

            $port_last_port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port_last);

            if( $port_last_port == "" )
            {
                $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_last . 'Using 6500 port. Change it from the GUI';
                $port_last_port = "6500";
            }
        }

        return array($port_first_port, $port_last_port);
    }


    function getTimeOutClass()
    {
        $aclsWithTimeout = array();

        $aclClassName = '';

        foreach ( $this->data as $line => $input_line) {
            $input_line = rtrim($input_line);
            preg_match('/.*class-map (?<aclClassName>.*)/', $input_line, $output_array);
            if(isset($output_array['aclClassName'])){
                $aclClassName = $output_array['aclClassName'];
                $aclsWithTimeout[$aclClassName]['name'] = $aclClassName;
            }
            else{
                preg_match('/.*class (?<aclClassName>.*)/', $input_line, $output_array);
                if(isset($output_array['aclClassName'])){
                    $aclClassName = $output_array['aclClassName'];
                }
                else {
                    preg_match('/.*match access-list (?<aclName>.*)/', $input_line, $output_array);
                    if (isset($output_array['aclName'])) {
                        $aclsWithTimeout[$aclClassName]['aclName'] = $output_array['aclName'];
                    } else {
                        //set connection timeout idle 4:00:00
                        preg_match('/.*set connection timeout (?<timeout>.*)/', $input_line, $output_array);
                        if (isset($output_array['timeout'])) {
                            switch ($output_array['timeout']) {
                                case 'dcd':
                                    $timeout = 86400;
                                    break;
                                default:
                                    preg_match('/.*set connection timeout .* (?<hours>\d*):(?<minutes>\d*):(?<seconds>\d*).*/', $input_line, $output_array);
                                    if(count($output_array)>0){
                                        $timeout = $output_array['hours']*60*60 + $output_array['minutes']*60 + $output_array['seconds'];
                                    }
                                    else{
                                        $timeout = 86400;
                                    }
                                    break;
                            }
                            $aclsWithTimeout[$aclClassName]['timeout'] = $timeout;
                        }
                    }
                }
            }
        }

        $acls = array();
        $generalServices = array();
        foreach ($aclsWithTimeout as $acl_entry){
            if(isset($acl_entry['timeout']) && isset($acl_entry['aclName'])) {
                $acls[$acl_entry['aclName']]['timeout'] =$acl_entry['timeout'];
            }
            elseif(isset($acl_entry['timeout']) && isset($acl_entry['service'])){
                $generalServices[$acl_entry['service']]['timeout'] =$acl_entry['timeout'];
            }
        }

        return [
            'acls'=>$acls,
            'services'=>$generalServices
        ];
    }


    function fixServiceTimeouts( $aclsWithTimeouts=array(), $servicesWithTimouts=array())
    {
        foreach ($aclsWithTimeouts as $aclGroup=> $acl)
        {
            $timeout = $acl['timeout'];
            $services = [];

            $tmp_rules = $this->sub->securityRules->rules("name regex /" . $aclGroup ."/");
            foreach( $tmp_rules as $tmp_rule )
            {
                /** @var SecurityRule $tmp_rule */
                foreach( $tmp_rule->services->members() as $member )
                {
                    $services[ $member->name() ] = $member;

                    /** @var Service|ServiceGroup $member */
                    if( $member->isService() )
                    {
                        $newService = $member->owner->newService( $member->name()."_t".$timeout, $member->protocol(), $member->getDestPort(), $member->description(), $member->getSourcePort()  );
                        $newService->setTimeout( $timeout );

                        $tmp_rule->services->add( $newService );
                        $tmp_rule->services->remove( $member );
                    }
                }
            }
        }
    }

    function serviceEQ($type, $port, $HostGroupNamePan, $HostGroupName,$names_line, $final_protocol, $tmp_servicegroup)
    {
        global $print;
        $addlog = "";

        if( !is_numeric($port) )
            $port = $this->search_for_service_port( $HostGroupNamePan, $names_line, $port);

        if( is_numeric($port) )
        {
            if( $type === "source" )
            {
                $port_final = $port;
                $final_source_port = $port;
                $final_destination_port = '1-65535';
                $name_ext = $final_protocol . "-" . $port_final . "-source";
            }
            elseif( $type === "destination" )
            {
                $port_final = $port;
                $final_source_port = "";
                $final_destination_port = $port_final;
                $name_ext = $final_protocol . "-" . $port_final;
            }

            $tmp_service = $this->sub->serviceStore->findByProtocolDstSrcPort($final_protocol, $final_destination_port, $final_source_port);
        }
        else
        {
            $port_final = "6500";
            if( $type === "source" )
            {
                $addlog = 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                $final_source_port = $port_final;
                $final_destination_port = '1-65535';
                $name_ext = $port . "-source";
            }
            elseif( $type === "destination" )
            {
                $addlog = 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port . 'Using 6500 port. Change it from the GUI';
                $final_source_port = "";
                $final_destination_port = $port_final;
                $name_ext = $port;
            }
            $tmp_service = $this->sub->serviceStore->find($port);
        }

        if( $tmp_service === null )
        {
            $tmp_service = $this->sub->serviceStore->find($name_ext);
            if( $tmp_service === null )
            {
                if( $print )
                    print "  * create service: " . $name_ext . "\n";
                $tmp_service = $this->sub->serviceStore->newService($name_ext, $final_protocol, $final_destination_port, "", $final_source_port);
                if( $addlog != "" )
                    $tmp_service->set_node_attribute('error', $addlog);
            }
        }

        /*
        if( $type === "destination" && $tmp_service !== null)
        {
            if( $tmp_service->isService() && $tmp_service->protocol() !==  $final_protocol)
            {
                $dport = $tmp_service->getDestPort();
                $tmp_name = $final_protocol."-".$dport;
                $tmp_service = $this->sub->serviceStore->find($tmp_name);
                if( $tmp_service === null )
                {
                    if( $print )
                        print "  * create service: " . $tmp_name . "|".$dport."\n";
                    $tmp_service = $this->sub->serviceStore->newService($tmp_name, $final_protocol, $dport);
                }
            }
        }*/

        if( $tmp_service !== null )
        {
            if( $print )
                print "   * add service: " . $tmp_service->name() . " to servicegroup " . $tmp_servicegroup->name() . "\n";
            $tmp_servicegroup->addMember($tmp_service);
        }
    }
}
