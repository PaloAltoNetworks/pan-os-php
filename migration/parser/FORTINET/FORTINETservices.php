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

trait FORTINETservices
{
    function add_fortinet_services($ismultiornot, $source)
    {

        global $projectdb;

        global $debug;
        global $print;

        $table = "services";
        $table_group = "services_groups";
        $table_group_id = "services_groups_id";

        if( $ismultiornot == "multivsys" )
        {
            $vsys = "shared";
            //$table = "shared_services";
            //$table_group = "shared_services_groups";
            //$table_group_id = "shared_services_groups_id";

            $tmp_sub = $this->sub;
            $this->sub = $this->pan;
        }
        else
        {
            $vsys = "root";
            /*
                    $all_vsys = $pan->getVirtualSystems();
                    $counter = 0;
                    foreach( $all_vsys as $vsys)
                    {
                        print "vsys: ".$vsys->name()." - ".$vsys->alternativeName()."\n";
                        $counter++;
                    }

                    $v = $pan->findVSYS_by_displayName( $vsys );
            */

        }


        if( $vsys !== "shared" && $this->sub === null )
        {
            derr("VSYS " . $vsys . " not found");
        }
        

        $this->addServicePredefined( "fortinet" );


        if( $ismultiornot == "multivsys" )
            $this->sub = $tmp_sub;
    }


    function get_services2($data, $source, $ismultiornot)
    {

        global $debug;
        global $print;
        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        global $projectdb;
        $isAddress = FALSE;
        $isObject = FALSE;
        $sql = array();
        $type = "";
        $ipaddress = "";
        $netmask = "";
        $cidr = "";
        $addressName = "";
        $protocol_number = "";
        $addressNamePan = "";
        $description = "";
        $getRangeEnd = "";
        $getRangeStart = "";
        $fqdn = "";
        $sql = array();
        $protocol_udp = [];
        $protocol_tcp = [];
        $tcp_src_elements_array = array();
        $tcp_src_elements = "";
        $protocol = "";
        $tcp_dst_elements = "";

        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }
        $lastline = "";
        foreach( $data as $line => $names_line )
        {


            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {
                if( preg_match("/^config firewall service custom/i", $names_line) )
                {
                    $isObject = TRUE;
                }

                if( $isObject )
                {
                    if( preg_match("/^end/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/edit /i", $names_line) )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $addressNamePan = $this->truncate_names($this->normalizeNames($meta[1]));
                        $addressName = trim($meta[1]);
                    }

                    if( $isAddress )
                    {
                        if( preg_match("/next/i", $names_line) )
                        {
                            $isAddress = FALSE;
                            if( (preg_match("/TCP\/UDP/i", $protocol)) or preg_match("/TCP/i", $protocol) or preg_match("/UDP/i", $protocol) )
                            {
                                if( ((count($protocol_udp) == 0) and (is_array($protocol_udp))) and ((count($protocol_tcp) > 0) and (is_array($protocol_tcp))) )
                                {
                                    # IS TCP ONLY
                                    foreach( $protocol_tcp as $k => $v1 )
                                    {
                                        $tcp = explode(":", $v1);
                                        $tcp_dst = $tcp[0];
                                        if( isset($tcp[1]) )
                                        {
                                            $tcp_src = $tcp[1];
                                        }
                                        else
                                        {
                                            $tcp_src = "";
                                        }

                                        # Dst port
                                        if( preg_match("/-/", $tcp_dst) )
                                        {
                                            $tcp_dst_elements = explode("-", $tcp_dst);
                                            if( trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1]) )
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst_elements[0];
                                            }
                                            else
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst;
                                            }
                                        }
                                        else
                                        {
                                            $tcp_dst_elements_array[] = $tcp_dst;
                                        }

                                        # Src Port
                                        if( $tcp_src != "" )
                                        {
                                            if( preg_match("/-/", $tcp_src) )
                                            {
                                                $tcp_src_elements = explode("-", $tcp_src);
                                                if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src_elements[0];
                                                }
                                                else
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src;
                                                }
                                            }
                                            else
                                            {
                                                $tcp_src_elements_array[] = $tcp_src;
                                            }
                                        }
                                    }


                                    if( count($tcp_src_elements_array) > 0 )
                                    {
                                        $tcp_src_elements = implode(",", $tcp_src_elements_array);
                                    }
                                    else
                                    {
                                        $tcp_src_elements = '';
                                    }

                                    $tcp_dst_elements = implode(",", $tcp_dst_elements_array);
                                    $sql[] = array($source, $addressName, $addressNamePan, $vsys, $description, $tcp_src_elements, $tcp_dst_elements, 'tcp');
                                    $tcp_src_elements = "";
                                    $tcp_src_elements_array = [];
                                    $tcp_dst_elements = "";
                                    $tcp_dst_elements_array = [];
                                }
                                elseif( (count($protocol_udp) > 0) and (count($protocol_tcp) == 0) )
                                {
                                    # IS UDP ONLY
                                    foreach( $protocol_udp as $k => $v1 )
                                    {
                                        $tcp = explode(":", $v1);
                                        $tcp_dst = $tcp[0];
                                        if( isset($tcp[1]) )
                                        {
                                            $tcp_src = $tcp[1];
                                        }
                                        else
                                        {
                                            $tcp_src = "";
                                        }

                                        # Dst port
                                        if( preg_match("/-/", $tcp_dst) )
                                        {
                                            $tcp_dst_elements = explode("-", $tcp_dst);
                                            if( trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1]) )
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst_elements[0];
                                            }
                                            else
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst;
                                            }
                                        }
                                        else
                                        {
                                            $tcp_dst_elements_array[] = $tcp_dst;
                                        }

                                        # Src Port
                                        if( $tcp_src != "" )
                                        {
                                            if( preg_match("/-/", $tcp_src) )
                                            {
                                                $tcp_src_elements = explode("-", $tcp_src);
                                                if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src_elements[0];
                                                }
                                                else
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src;
                                                }
                                            }
                                            else
                                            {
                                                $tcp_src_elements_array[] = $tcp_src;
                                            }
                                        }


                                    }

                                    $tcp_src_elements = implode(",", $tcp_src_elements_array);
                                    $tcp_dst_elements = implode(",", $tcp_dst_elements_array);
                                    $sql[] = array($source, $addressName, $addressNamePan, $vsys, $description, $tcp_src_elements, $tcp_dst_elements, 'udp');
                                    $tcp_src_elements = "";
                                    $tcp_src_elements_array = [];
                                    $tcp_dst_elements = "";
                                    $tcp_dst_elements_array = [];
                                }
                                elseif( ((count($protocol_udp) > 0) and (is_array($protocol_udp))) and ((is_array($protocol_tcp)) and (count($protocol_tcp) > 0)) )
                                {

                                    //Todo: SWASCHKUT 20190920 - general method for such as other vendors has this situation too
                                    # IS TCP AND UDP CREATING GROUP
                                    #Create Group and get ID

                                    #$projectdb->query("INSERT INTO services_groups_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$addressName','$addressNamePan')");
                                    #$grpID = $projectdb->insert_id;

                                    $addressNamePan = $this->truncate_names($this->normalizeNames($addressNamePan));
                                    $tmp_servicegroup = $this->sub->serviceStore->find($addressNamePan);
                                    if( $tmp_servicegroup == null )
                                    {
                                        if( $print )
                                            print "\n * create servicegroup Object: " . $addressNamePan . "\n";
                                        $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($addressNamePan);
                                    }
                                    else
                                    {
                                        if( !$tmp_servicegroup->isGroup() )
                                        {
                                            mwarning("service found not a Group for: '" . $addressNamePan . "'");
                                            if( $tmp_servicegroup->tags->hasTag('predefined') )
                                            {
                                                $this->sub->serviceStore->remove($tmp_servicegroup);
                                                $newname = "";
                                            }
                                            else
                                            {
                                                $newname = "g_tmp_";
                                            }

                                            $name = $this->truncate_names($this->normalizeNames($newname . $addressNamePan));
                                            if( $print )
                                                print "\n * create servicegroup Object: " . $name . "\n";
                                            $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($name);

                                            if( $newname != "" )
                                            {
                                                $add_log = 'Service with same name already available, added prefix: g_tmp_';
                                                $tmp_servicegroup->set_node_attribute('error', $add_log);
                                            }

                                        }
                                        else
                                            if( $print )
                                                print " X servicegroup: " . $addressNamePan . " already available.\n";
                                    }


                                    foreach( $protocol_tcp as $k => $v1 )
                                    {
                                        $tcp = explode(":", $v1);
                                        $tcp_dst = $tcp[0];
                                        if( isset($tcp[1]) )
                                        {
                                            $tcp_src = $tcp[1];
                                        }
                                        else
                                        {
                                            $tcp_src = "";
                                        }

                                        # Dst port
                                        if( preg_match("/-/", $tcp_dst) )
                                        {
                                            $tcp_dst_elements = explode("-", $tcp_dst);
                                            if( trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1]) )
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst_elements[0];
                                            }
                                            else
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst;
                                            }
                                        }
                                        else
                                        {
                                            $tcp_dst_elements_array[] = $tcp_dst;
                                        }

                                        # Src Port
                                        if( $tcp_src != "" )
                                        {
                                            if( preg_match("/-/", $tcp_src) )
                                            {
                                                $tcp_src_elements = explode("-", $tcp_src);
                                                if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src_elements[0];
                                                }
                                                else
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src;
                                                }
                                            }
                                            else
                                            {
                                                $tcp_src_elements_array[] = $tcp_src;
                                            }
                                        }


                                    }

                                    if( count($tcp_src_elements_array) > 0 )
                                    {
                                        $tcp_src_elements = implode(",", $tcp_src_elements_array);
                                    }
                                    else
                                    {
                                        $tcp_src_elements = "";
                                    }

                                    $tcp_dst_elements = implode(",", $tcp_dst_elements_array);
                                    if( $tcp_src_elements != "" )
                                    {
                                        #$tcp_src_elements_name=str_replace(",","_",$tcp_src_elements);
                                        #$tcp_dst_elements_name=str_replace(",","_",$tcp_dst_elements);
                                        $tcp_src_elements_name = $tcp_src_elements;
                                        $tcp_dst_elements_name = $tcp_dst_elements;
                                        $srvname = $this->truncate_names("tcp-" . $tcp_src_elements_name . "-" . $tcp_dst_elements_name);
                                    }
                                    else
                                    {
                                        $tcp_src_elements_name = "";
                                        #$tcp_dst_elements_name=str_replace(",","_",$tcp_dst_elements);
                                        $tcp_dst_elements_name = $tcp_dst_elements;
                                        $srvname = $this->truncate_names("tcp-" . $tcp_dst_elements_name);
                                    }

                                    #$sql[] = array($source,$srvname,$srvname,$vsys,$description,$tcp_src_elements,$tcp_dst_elements,'tcp');

                                    $srvname = $this->truncate_names($this->normalizeNames($srvname));
                                    $tmp_service = $this->sub->serviceStore->find($srvname);
                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print " * create service " . $srvname . " -proto: tcp -dport:|" . $tcp_dst_elements_name . "| -description '' -sport:" . $tcp_src_elements_name . "\n";

                                        /** @var Service $tmp_service */
                                        $tmp_service = $this->sub->serviceStore->newService($srvname, 'tcp', $tcp_dst_elements_name, '', $tcp_src_elements_name);

                                        print "service: ".$tmp_service->name()."\n";
                                        print "dstport: ".$tmp_service->getDestPort()."\n";
                                        print "srcprot: ".$tmp_service->getSourcePort()."\n";

                                        if( !$tmp_servicegroup->hasNamedObjectRecursive($srvname) )
                                        {
                                            if( $print )
                                                print "  * add service Objects: " . $srvname . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                            if( $print )
                                                print "  - service Objects: " . $srvname . " already a member of this service group\n";
                                    }

                                    #$projectdb->query("INSERT INTO services_groups (source,vsys,member,lid) VALUES ('$source','$vsys','$srvname','$grpID')");

                                    $tcp_src_elements = "";
                                    $tcp_src_elements_array = [];
                                    $tcp_dst_elements = "";
                                    $tcp_dst_elements_array = [];
                                    #UDP
                                    $tcp_src_elements = "";
                                    $tcp_dst_elements = "";
                                    $tcp_src_elements_name = "";
                                    $tcp_dst_elements_name = "";

                                    foreach( $protocol_udp as $k => $v1 )
                                    {
                                        $tcp = explode(":", $v1);
                                        $tcp_dst = $tcp[0];
                                        if( isset($tcp[1]) )
                                        {
                                            $tcp_src = $tcp[1];
                                        }
                                        else
                                        {
                                            $tcp_src = "";
                                        }

                                        # Dst port
                                        if( preg_match("/-/", $tcp_dst) )
                                        {
                                            $tcp_dst_elements = explode("-", $tcp_dst);
                                            if( trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1]) )
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst_elements[0];
                                            }
                                            else
                                            {
                                                $tcp_dst_elements_array[] = $tcp_dst;
                                            }
                                        }
                                        else
                                        {
                                            $tcp_dst_elements_array[] = $tcp_dst;
                                        }

                                        # Src Port
                                        if( $tcp_src != "" )
                                        {
                                            if( preg_match("/-/", $tcp_src) )
                                            {
                                                $tcp_src_elements = explode("-", $tcp_src);
                                                if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src_elements[0];
                                                }
                                                else
                                                {
                                                    $tcp_src_elements_array[] = $tcp_src;
                                                }
                                            }
                                            else
                                            {
                                                $tcp_src_elements_array[] = $tcp_src;
                                            }
                                        }


                                    }

                                    if( count($tcp_src_elements_array) > 0 )
                                    {
                                        $tcp_src_elements = implode(",", $tcp_src_elements_array);
                                    }
                                    else
                                    {
                                        $tcp_src_elements = "";
                                    }
                                    $tcp_dst_elements = implode(",", $tcp_dst_elements_array);
                                    if( $tcp_src_elements != "" )
                                    {
                                        #$tcp_src_elements_name=str_replace(",","_",$tcp_src_elements);
                                        #$tcp_dst_elements_name=str_replace(",","_",$tcp_dst_elements);
                                        $tcp_src_elements_name = $tcp_src_elements;
                                        $tcp_dst_elements_name = $tcp_dst_elements;
                                        $srvname = $this->truncate_names("udp-" . $tcp_src_elements_name . "-" . $tcp_dst_elements_name);
                                    }
                                    else
                                    {
                                        $tcp_src_elements_name = "";
                                        #$tcp_dst_elements_name=str_replace(",","_",$tcp_dst_elements);
                                        $tcp_dst_elements_name = $tcp_dst_elements;
                                        $srvname = $this->truncate_names("udp-" . $tcp_dst_elements_name);
                                    }
                                    #$sql[] = array($source,$srvname,$srvname,$vsys,$description,$tcp_src_elements,$tcp_dst_elements,'udp');

                                    #$projectdb->query("INSERT INTO services_groups (source,vsys,member,lid) VALUES ('$source','$vsys','$srvname','$grpID')");

                                    $srvname = $this->truncate_names($this->normalizeNames($srvname));
                                    $tmp_service = $this->sub->serviceStore->find($srvname);
                                    if( $tmp_service === null )
                                    {
                                        if( $print )
                                            print " * create service " . $srvname . " -proto: udp -dport:|" . $tcp_dst_elements_name . "| -description '' -sport:" . $tcp_src_elements_name . "\n";

                                        $tmp_service = $this->sub->serviceStore->newService($srvname, 'udp', $tcp_dst_elements_name, '', $tcp_src_elements_name);

                                        if( !$tmp_servicegroup->hasNamedObjectRecursive($srvname) )
                                        {
                                            if( $print )
                                                print "  * add service Objects: " . $srvname . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_service);
                                        }
                                        else
                                            if( $print )
                                                print "  - service Objects: " . $srvname . " already a member of this service group\n";
                                    }

                                    $tcp_src_elements = "";
                                    $tcp_src_elements_array = [];
                                    $tcp_dst_elements = "";
                                    $tcp_dst_elements_array = [];
                                    $tcp_src_elements_name = "";
                                    $tcp_dst_elements_name = "";
                                }
                            }
                            else
                            {
                                if( $protocol == "IP" )
                                {
                                    $protocol = $protocol_number;
                                }
                                $sql[] = array($source, $addressName, $addressNamePan, $vsys, $description, '', '', $protocol);
                            }
                            $protocol = "";
                            $protocol_tcp = [];
                            $protocol_udp = [];
                            $description = "";
                            $tcp_src_elements = "";
                            $tcp_dst_elements = "";
                        }

                        if( preg_match("/set protocol /i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $protocol = $data1[2]; #TCP/UDP o IP o ICMP o TCP/UDP/SCTP
                        }

                        if( preg_match("/set udp-portrange/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( (isset($data1[2])) and ($data1[2] == "0:0") )
                            {

                            }
                            else
                            {
                                unset($data1[0]);
                                unset($data1[1]);
                                $protocol_udp = array_values($data1);
                                $protocol = "UDP";
                            }
                        }

                        if( preg_match("/set tcp-portrange/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( (isset($data1[2])) and ($data1[2] == "0:0") )
                            {

                            }
                            else
                            {
                                unset($data1[0]);
                                unset($data1[1]);
                                $protocol_tcp = array_values($data1);
                                $protocol = "TCP";
                            }
                        }

                        if( preg_match("/set protocol-number/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( isset($data1[2]) )
                            {
                                $protocol_number = $data1[2];
                            }
                            else
                            {
                                echo "Error: " . $names_line . PHP_EOL;
                            }

                        }

                        if( preg_match("/^set icmptype/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( isset($data1[2]) )
                            {
                                $protocol_icmp_type = $data1[2];
                            }
                            else
                            {
                                echo "Error: " . $names_line . PHP_EOL;
                            }

                        }

                        if( preg_match("/^set icmpcode/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( isset($data1[2]) )
                            {
                                $protocol_icmp_code = $data1[2];
                            }
                            else
                            {
                                echo "Error: " . $names_line . PHP_EOL;
                            }

                        }

                        if( preg_match("/set comment/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $description = $data1[2];
                        }
                    }
                }
            }


            $lastline = $names_line;
        }


        if( count($sql) > 0 )
        {
            #$sql_unique = array_unique($sql);

            #print_r( $sql );

            foreach( $sql as $srv_object )
            {

                $ObjectServiceNamePan = $srv_object[2];
                $srv_protocol = $srv_object[7];
                $dport = $srv_object[6];
                $sport = $srv_object[5];

                if( $srv_protocol == "tcp" || $srv_protocol == "udp" )
                {
                    $ObjectServiceNamePan = $this->truncate_names($this->normalizeNames($ObjectServiceNamePan));
                    $tmp_service = $this->sub->serviceStore->find($ObjectServiceNamePan);
                    if( $tmp_service === null )
                    {
                        if( $print )
                            print " * create service " . $ObjectServiceNamePan . " -proto:" . $srv_protocol . " -dport:|" . $dport . "| -description '' -sport:" . $sport . "\n";

                        $tmp_service = $this->sub->serviceStore->newService($ObjectServiceNamePan, $srv_protocol, $dport, '', $sport);
                    }
                }
                else
                {
                    if( $srv_protocol == "" )
                    {
                        $ObjectServiceNamePan = $this->truncate_names($this->normalizeNames($ObjectServiceNamePan));
                        $tmp_service = $this->sub->serviceStore->find("tmp-" . $ObjectServiceNamePan);
                        if( $tmp_service === null )
                        {
                            if( $print )
                                print " * create service 'tmp-" . $ObjectServiceNamePan . "' with dummy -dport '6500' and -proto 'TCP' because no information is available\n";

                            $tmp_service = $this->sub->serviceStore->newService("tmp-" . $ObjectServiceNamePan, "tcp", "6500", '', '');
                        }
                    }
                    else
                    {
                        $ObjectServiceNamePan = $this->truncate_names($this->normalizeNames($ObjectServiceNamePan));
                        $tmp_service = $this->sub->serviceStore->find("app-" . $ObjectServiceNamePan);
                        if( $tmp_service === null )
                        {
                            if( $print )
                                print " * create service 'app-" . $ObjectServiceNamePan . "' with description: " . $srv_protocol . "\n";

                            $tmp_service = $this->sub->serviceStore->newService("app-" . $ObjectServiceNamePan, "tcp", "6500", $srv_protocol, '');
                        }
                        #print_r( $srv_object );
                        #mwarning( "no service protocol found is not TCP or UDP\n" , null, false);
                    }

                }

            }

            #$projectdb->query("INSERT INTO services (source,name_ext,name,vsys,description,sport,dport,protocol) VALUES " . implode(",", $sql_unique) . ";");
        }
    }

// old "
// <editor-fold desc="  ****  old get_services   ****" defaultstate="collapsed" >
    function get_services($fortinet_config_file, $source, $vsys, $ismultiornot)
    {

        global $projectdb;
        $isAddress = FALSE;
        $isObject = FALSE;
        $sql = array();
        $type = "";
        $ipaddress = "";
        $netmask = "";
        $cidr = "";
        $addressName = "";
        $addressNamePan = "";
        $description = "";
        $getRangeEnd = "";
        $getRangeStart = "";
        $protocol_number = "";
        $tcp_src_elements_array = array();
        $fqdn = "";
        $sql = array();
        $protocol_udp = "";
        $protocol_tcp = "";
        $protocol = "";
        $tcp_src_elements = "";
        $tcp_dst_elements = "";

        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }
        $lastline = "";
        foreach( $fortinet_config_file as $line => $names_line )
        {

            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {
                if( preg_match("/^config firewall service custom/i", $names_line) )
                {
                    $isObject = TRUE;
                }

                if( $isObject )
                {
                    if( preg_match("/^end/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/edit /i", $names_line) )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $addressNamePan = $this->truncate_names($this->normalizeNames($meta[1]));
                        $addressName = $meta[1];
                    }

                    if( $isAddress )
                    {
                        if( preg_match("/next/i", $names_line) )
                        {
                            $isAddress = FALSE;
                            if( (preg_match("/TCP\/UDP/i", $protocol)) or preg_match("/TCP/i", $protocol) or preg_match("/UDP/i", $protocol) )
                            {
                                if( ($protocol_udp == "") and ($protocol_tcp != "") )
                                {
                                    # IS TCP ONLY
                                    $tcp = explode(":", $protocol_tcp);
                                    $tcp_dst = $tcp[0];
                                    if( isset($tcp[1]) )
                                    {
                                        $tcp_src = $tcp[1];
                                    }
                                    else
                                    {
                                        $tcp_src = "";
                                    }
                                    # Dst port
                                    if( preg_match("/-/", $tcp_dst) )
                                    {
                                        $tcp_dst_elements = explode("-", $tcp_dst);
                                        if( trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1]) )
                                        {
                                            $tcp_dst_elements = $tcp_dst_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_dst_elements = $tcp_dst;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_dst_elements = $tcp_dst;
                                    }
                                    # Src Port
                                    if( preg_match("/-/", $tcp_src) )
                                    {
                                        $tcp_src_elements = explode("-", $tcp_src);
                                        if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                        {
                                            $tcp_src_elements = $tcp_src_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_src_elements = $tcp_src;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                    $sql[] = "('$source','$addressName','$addressNamePan','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','tcp')";
                                }
                                elseif( ($protocol_udp != "") and ($protocol_tcp == "") )
                                {
                                    # IS UDP ONLY
                                    $tcp = explode(":", $protocol_udp);
                                    $tcp_dst = $tcp[0];
                                    if( isset($tcp[1]) )
                                    {
                                        $tcp_src = $tcp[1];
                                    }
                                    else
                                    {
                                        $tcp_src = "";
                                    }

                                    if( preg_match("/-/", $tcp_dst) )
                                    {
                                        $tcp_dst_elements = explode("-", $tcp_dst);
                                        if( $tcp_dst_elements[0] == $tcp_dst_elements[1] )
                                        {
                                            $tcp_dst_elements = $tcp_dst_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_dst_elements = $tcp_dst;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_dst_elements = $tcp_dst;
                                    }

                                    if( preg_match("/-/", $tcp_src) )
                                    {
                                        $tcp_src_elements = explode("-", $tcp_src);
                                        if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                        {
                                            $tcp_src_elements = $tcp_src_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_src_elements = $tcp_src;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                    $sql[] = "('$source','$addressName','$addressNamePan','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','udp')";
                                }
                                elseif( ($protocol_udp != "") and ($protocol_tcp != "") )
                                {
                                    # IS TCP AND UDP CREATING GROUP
                                    #Create Group and get ID
                                    $projectdb->query("INSERT INTO services_groups_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$addressName','$addressNamePan')");
                                    $grpID = $projectdb->insert_id;

                                    $tcp = explode(":", $protocol_tcp);
                                    $tcp_dst = $tcp[0];
                                    if( isset($tcp[1]) )
                                    {
                                        $tcp_src = $tcp[1];
                                    }
                                    else
                                    {
                                        $tcp_src = "";
                                    }

                                    if( preg_match("/-/", $tcp_dst) )
                                    {
                                        $tcp_dst_elements = explode("-", $tcp_dst);
                                        if( trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1]) )
                                        {
                                            $tcp_dst_elements = $tcp_dst_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_dst_elements = $tcp_dst;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_dst_elements = $tcp_dst;
                                    }

                                    if( preg_match("/-/", $tcp_src) )
                                    {
                                        $tcp_src_elements = explode("-", $tcp_src);
                                        if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                        {
                                            $tcp_src_elements = $tcp_src_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_src_elements = $tcp_src;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                    if( $tcp_src_elements != "" )
                                    {
                                        $srvname = "tcp-" . $tcp_src_elements . "-" . $tcp_dst_elements;
                                    }
                                    else
                                    {
                                        $srvname = "tcp-" . $tcp_dst_elements;
                                    }

                                    $sql[] = "('$source','$srvname','$srvname','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','tcp')";
                                    $projectdb->query("INSERT INTO services_groups (source,vsys,member,lid) VALUES ('$source','$vsys','$srvname','$grpID')");

                                    #UDP
                                    $tcp_src_elements = "";
                                    $tcp_dst_elements = "";

                                    $tcp = explode(":", $protocol_udp);
                                    $tcp_dst = $tcp[0];
                                    if( isset($tcp[1]) )
                                    {
                                        $tcp_src = $tcp[1];
                                    }
                                    else
                                    {
                                        $tcp_src = "";
                                    }

                                    if( preg_match("/-/", $tcp_dst) )
                                    {
                                        $tcp_dst_elements = explode("-", $tcp_dst);
                                        if( $tcp_dst_elements[0] == $tcp_dst_elements[1] )
                                        {
                                            $tcp_dst_elements = $tcp_dst_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_dst_elements = $tcp_dst;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_dst_elements = $tcp_dst;
                                    }

                                    if( preg_match("/-/", $tcp_src) )
                                    {
                                        $tcp_src_elements = explode("-", $tcp_src);
                                        if( $tcp_src_elements[0] == $tcp_src_elements[1] )
                                        {
                                            $tcp_src_elements = $tcp_src_elements[0];
                                        }
                                        else
                                        {
                                            $tcp_src_elements = $tcp_src;
                                        }
                                    }
                                    else
                                    {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                    if( $tcp_src_elements != "" )
                                    {
                                        $srvname = "udp-" . $tcp_src_elements . "-" . $tcp_dst_elements;
                                    }
                                    else
                                    {
                                        $srvname = "udp-" . $tcp_dst_elements;
                                    }
                                    $sql[] = "('$source','$srvname','$srvname','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','udp')";
                                    $projectdb->query("INSERT INTO services_groups (source,vsys,member,lid) VALUES ('$source','$vsys','$srvname','$grpID')");
                                }
                            }
                            elseif( $protocol == "IP" )
                            {

                            }
                            elseif( $protocol == "ICMP" )
                            {

                            }
                            $protocol = "";
                            $protocol_tcp = "";
                            $protocol_udp = "";
                            $description = "";
                            $tcp_src_elements = "";
                            $tcp_dst_elements = "";
                        }

                        if( preg_match("/set protocol /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $protocol = $data[2]; #TCP/UDP o IP o ICMP o TCP/UDP/SCTP
                        }

                        if( preg_match("/set udp-portrange/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( $data[2] == "0:0" )
                            {

                            }
                            else
                            {
                                $protocol_udp = $data[2];
                                $protocol = "UDP";
                            }
                        }

                        if( preg_match("/set tcp-portrange/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            if( $data[2] == "0:0" )
                            {

                            }
                            else
                            {
                                $protocol_tcp = $data[2];
                                $protocol = "TCP";
                            }
                        }

                        if( preg_match("/set protocol-number/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $protocol_number = $data[2];
                        }

                        if( preg_match("/set icmptype/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $protocol_icmp_type = $data[2];
                        }

                        if( preg_match("/set icmpcode/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $protocol_icmp_code = $data[2];
                        }

                        if( preg_match("/set comment/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $description = $data[2];
                        }
                    }
                }
            }


            $lastline = $names_line;
        }
        if( count($sql) > 0 )
        {
            $sql_unique = array_unique($sql);
            $projectdb->query("INSERT INTO services (source,name_ext,name,vsys,description,sport,dport,protocol) VALUES " . implode(",", $sql_unique) . ";");
        }
    }
// </editor-fold>

#function get_services_groups($fortinet_config_file, $source, $vsys, $ismultiornot) {
    function get_services_groups($data, $source, $ismultiornot)
    {

        global $debug;
        global $print;

        global $projectdb;
        $isAddress = FALSE;
        $isObject = FALSE;
        $sql = array();
        $sql1 = array();
        $lid = "";
        $addressNamePan = "";
        $addressName = "";

        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }
        $lastline = "";
        foreach( $data as $line => $names_line )
        {


            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {
                if( preg_match("/config firewall service group/i", $names_line) )
                {
                    $isObject = TRUE;
                }


                if( $isObject )
                {
                    if( preg_match("/^\bend\b/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/\bedit\b/i", $names_line) )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $newname = str_replace('/', '-', $meta[1]);
                        $addressNamePan = $this->truncate_names($this->normalizeNames($newname));
                        $addressName = trim($meta[1]);

                        #$projectdb->query("INSERT INTO services_groups_id (name_ext,name,source,vsys) VALUES ('$addressName','$addressNamePan','$source','$vsys')");

                        $addressNamePan = $this->truncate_names($this->normalizeNames($addressNamePan));
                        $tmp_servicegroup = $this->sub->serviceStore->find($addressNamePan);
                        if( $tmp_servicegroup == null )
                        {
                            if( $print )
                                print "\n * create servicegroup Object: " . $addressNamePan . "\n";
                            $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($addressNamePan);
                        }
                        else
                        {
                            if( $print )
                                mwarning(" X servicegroup: " . $addressNamePan . " already available", null, FALSE);
                        }


                        #$lid = $projectdb->insert_id;
                    }

                    if( $isAddress )
                    {
                        if( preg_match("/\bnext\b/i", $names_line) )
                        {
                            $isAddress = FALSE;
                            $lid = "";
                            $addressNamePan = "";
                            $addressName = "";
                        }

                        if( preg_match("/set member /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            foreach( $data as $value => $datos )
                            {
                                if( ($datos == "set") or ($datos == "member") )
                                {

                                }
                                else
                                {
                                    $memberPan = $this->truncate_names($this->normalizeNames(trim($datos)));
                                    #$sql[] = "('$datos','$source','$vsys','$lid')";
                                    $tmp_object = $this->sub->serviceStore->find($memberPan);
                                    if( $tmp_object !== null && $tmp_servicegroup->isGroup() )
                                    {
                                        $tmp_servicegroup->addMember($tmp_object);
                                        if( !$tmp_servicegroup->hasNamedObjectRecursive($memberPan) )
                                        {
                                            if( $print )
                                                print "  * add service Objects: " . $memberPan . " to servicegroup " . $tmp_servicegroup->name() . "\n";
                                            $tmp_servicegroup->addMember($tmp_object);
                                        }
                                        else
                                            if( $print )
                                                print "  - service Objects: " . $memberPan . " already a member of this service group\n";
                                    }
                                    else
                                    {
                                        //Todo swaschkut 20190930 - what about tmp servcies
                                        if( $print )
                                            print " X service object: " . $memberPan . " not found. can not be added to service group\n";
                                    }

                                }
                            }
                        }
                    }
                }
            }


            $lastline = $names_line;
        }
        if( count($sql) > 0 )
        {
            #$projectdb->query("INSERT INTO services_groups (member,source,vsys,lid) VALUES " . implode(",", $sql));
        }
    }

}

