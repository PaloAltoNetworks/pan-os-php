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


trait SCREENOSservice
{
    function get_services($screenos_config_file)
    {
        global $debug;
        global $print;


        $this->template_vsys = $this->template->findVirtualSystem('vsys1');
        if( $this->template_vsys === null )
        {
            derr("vsys: vsys1 could not be found ! Exit\n");
        }


        $vsys = "root";
        $serviceObj = array();


        foreach( $screenos_config_file as $line => $names_line )
        {

            $names_line = trim($names_line);
            if( preg_match("/^set vsys /i", $names_line) )
            {
                $this->vsys_parser($names_line);
            }

            if( preg_match("/^set service /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $protocol = "";

                if( isset($data[3]) )
                {
                    $name_ext = $data[2];
                    $name_ext = $this->truncate_names($this->normalizeNames($name_ext));
                    switch ($data[3])
                    {
                        case "protocol":
                            $protocol = $data[4];

                            if( ($protocol == "tcp") or ($protocol == "udp") )
                            {
                                $dport = $data[8];
                                $sport = $data[6];

                                $dportsplit = explode("-", $dport);
                                if( $dportsplit[0] == $dportsplit[1] )
                                {
                                    $dport = $dportsplit[0];
                                }
                                $sportsplit = explode("-", $sport);
                                if( $sportsplit[0] == $sportsplit[1] )
                                {
                                    $sport = $sportsplit[0];
                                }
                                if( ($sport == "1-65535") or ($sport == "0-65535") )
                                {
                                    $sport = "";
                                }
                            }
                            else
                            {
                                $sport = "";
                                $dport = "";
                            }


                            if( ($protocol == "tcp") or ($protocol == "udp") )
                            {
                                $tmp_service = $this->sub->serviceStore->find($name_ext);
                                if( $tmp_service == null )
                                {
                                    if( $print )
                                        print "create service Object: " . $name_ext . ", " . $protocol . ", " . $dport . ", " . $sport . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService($name_ext, $protocol, $dport, "", $sport);
                                }

                            }
                            else
                            {
                                if( $debug )
                                    print "service: " . $name_ext . " protocol: " . $protocol . " and port: " . $dport . " not supported\n";
                            }

                            if( isset($data[9]) )
                            {
                                if( $data[9] == "timeout" )
                                {
                                    $timeout = $data[10];
                                    if( $timeout != "never" )
                                    {
                                        //20190429 Sven - how to implement, new PAN-OS version 8.1 only support service timeout
                                        #$serviceObj[$vsys][$name_ext]->setTimeout($timeout);
                                    }
                                    else
                                    {
                                        //max PAN-OS service timeout
                                        $timeout = 604800;
                                    }

                                    //Netscreen timeout is in minutes
                                    $timeout = intval($timeout) * 60;
                                    if( $print )
                                        print " * set timeout to: " . $timeout . "\n";

                                    $tmp_service->setTimeout($timeout);
                                    #add_log2('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', $source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.', 'objects', $lid, 'services');
                                }
                            }
                            break;
                        case "+":

                            $tmp_service = $this->sub->serviceStore->find($name_ext);
                            $newProtocol = $data[4];
                            if( $tmp_service !== null && !$tmp_service->isTmpSrv() && !$tmp_service->isGroup() )
                            {
                                $protocol = $tmp_service->protocol();

                                if( $newProtocol == $protocol )
                                {

                                    if( ($newProtocol == "tcp") or ($newProtocol == "udp") )
                                    {
                                        $dport = $data[8];
                                        $sport = $data[6];

                                        $dportsplit = explode("-", $dport);
                                        if( $dportsplit[0] == $dportsplit[1] )
                                        {
                                            $dport = $dportsplit[0];
                                        }
                                        $sportsplit = explode("-", $sport);
                                        if( $sportsplit[0] == $sportsplit[1] )
                                        {
                                            $sport = $sportsplit[0];
                                        }
                                        if( ($sport == "1-65535") or ($sport == "0-65535") )
                                        {
                                            $sport = "";
                                        }
                                    }
                                    else
                                    {
                                        $sport = "";
                                        $dport = "";
                                    }

                                    $tmp_dport = $tmp_service->getDestPort();
                                    $tmp_sport = $tmp_service->getSourcePort();
                                    if( $dport != "" )
                                        $tmp_service->setDestPort($tmp_dport . "," . $dport);

                                    if( $sport != "" )
                                        $tmp_service->setSourcePort($tmp_sport . "," . $sport);

                                    if( isset($data[9]) )
                                    {
                                        if( $data[9] == "timeout" )
                                        {
                                            $timeout = $data[10];
                                            if( $timeout != "never" )
                                            {
                                                #$serviceObj[$vsys][$name_ext]->setTimeout($timeout);
                                            }
                                            else
                                            {
                                                # Its never ToDo: Check what is the max tmout
                                            }
                                            #add_log2('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', $source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.', 'objects', $thisLid, 'services');
                                        }
                                    }

                                }
                                else
                                {
                                    $tmp_name = $tmp_service->name();
                                    $tmp_service->setName($protocol . "-" . $tmp_name);

                                    //add SNMP, maybe better to add at shared level
                                    if( $print )
                                        print "create servicegroup Object: " . $tmp_name . "\n";
                                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($tmp_name);
                                    $tmp_servicegroup->addMember($tmp_service);


                                    # Create a ServiceGroup
                                    //echo "CREATE A GROUP for $name_ext".PHP_EOL;
                                    #add_log2("error",'Importing Services','The service called [' . $name_ext . '] is using different protocols',$source,'Replace the Service by the App-id or Create a ServiceGroup with the different services','objects',$thisLid,'services');
                                    //echo $names_line.PHP_EOL;

                                    if( ($newProtocol == "tcp") or ($newProtocol == "udp") )
                                    {
                                        $dport = $data[8];
                                        $sport = $data[6];

                                        $dportsplit = explode("-", $dport);
                                        if( $dportsplit[0] == $dportsplit[1] )
                                        {
                                            $dport = $dportsplit[0];
                                        }
                                        $sportsplit = explode("-", $sport);
                                        if( $sportsplit[0] == $sportsplit[1] )
                                        {
                                            $sport = $sportsplit[0];
                                        }
                                        if( ($sport == "1-65535") or ($sport == "0-65535") )
                                        {
                                            $sport = "";
                                        }

                                        $tmp_name = $newProtocol . "-" . $name_ext;
                                    }
                                    else
                                    {
                                        $sport = "";
                                        $dport = "65535";
                                        $tmp_name = "tmp" . $newProtocol . "-" . $name_ext;
                                        $newProtocol = "tcp";
                                    }

                                    if( $print )
                                        print "create service Object: " . $newProtocol . "-" . $name_ext . ", " . $newProtocol . ", " . $dport . ", " . $sport . "\n";
                                    $tmp_newservice = $this->sub->serviceStore->newService($newProtocol . "-" . $name_ext, $newProtocol, $dport, "", $sport);
                                    $tmp_servicegroup->addMember($tmp_newservice);

                                    #print "service | ".$name_ext ." | problem TCP/UDP \n";
                                }
                            }
                            elseif( is_object($tmp_service) && $tmp_service->isGroup() )
                            {
                                if( ($newProtocol == "tcp") or ($newProtocol == "udp") )
                                {
                                    $dport = $data[8];
                                    $sport = $data[6];

                                    $dportsplit = explode("-", $dport);
                                    if( $dportsplit[0] == $dportsplit[1] )
                                    {
                                        $dport = $dportsplit[0];
                                    }
                                    $sportsplit = explode("-", $sport);
                                    if( $sportsplit[0] == $sportsplit[1] )
                                    {
                                        $sport = $sportsplit[0];
                                    }
                                    if( ($sport == "1-65535") or ($sport == "0-65535") )
                                    {
                                        $sport = "";
                                    }
                                    $tmp_name = $newProtocol . "-" . $name_ext;
                                }
                                else
                                {
                                    $sport = "";
                                    $dport = "65535";
                                    $tmp_name = "tmp" . $newProtocol . "-" . $name_ext;
                                    $newProtocol = "tcp";
                                }

                                if( $print )
                                    print "create service Object: " . $tmp_name . "-" . $dport . ", " . $newProtocol . ", " . $dport . ", " . $sport . "\n";
                                $tmp_newservice = $this->sub->serviceStore->newService($tmp_name . "-" . $dport, $newProtocol, $dport, "", $sport);
                                $tmp_service->addMember($tmp_newservice);
                            }
                            else
                            {
                                print "Error: Adding info to a ghost service " . $names_line . PHP_EOL;
                            }
                            break;
                        case "timeout":
                            $timeout = $data[4];
                            if( $timeout != "never" )
                            {
                                if( isset($serviceObj[$vsys][$name_ext]) )
                                {

                                }
                                else
                                {

                                }
                            }
                            else
                            {
                                # Its never ToDo: Check what is the max tmout
                                if( $debug )
                                    mwarning("service timeout not implemented\n", null, FALSE);
                            }
                            #add_log2('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', $source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.', 'objects', $lid, 'services');
                            break;
                        default:
                            break;

                    }
                }
            }
        }

    }

    function get_services_groups($screenos_config_file, $servicegroup)
    {

        global $debug;
        global $print;
        global $add_srv;

        //20190430 SVen add addressgroup SNMP with member TCP-SNMP and UDP-SNMP
        //better do add do shared, but now added to each VSYS


        $this->template_vsys = $this->template->findVirtualSystem('vsys1');
        if( $this->template_vsys === null )
        {
            derr("vsys: vsys1 could not be found ! Exit\n");
        }


        foreach( $screenos_config_file as $line => $names_line )
        {
            $names_line = trim($names_line);

            if( preg_match("/^set vsys /i", $names_line) )
            {
                $this->vsys_parser($names_line);

                //add SNMP, maybe better to add at shared level
                $tmp_servicegroup = $this->sub->serviceStore->find('SNMP');
                if( $tmp_servicegroup == null )
                {
                    if( $print )
                        print "create servicegroup Object: SNMP\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup('SNMP');
                    $tmp_object = $this->sub->serviceStore->find('TCP-SNMP');
                    if( $tmp_object !== null )
                    {
                        $tmp_servicegroup->addMember($tmp_object);
                    }
                    $tmp_object = $this->sub->serviceStore->find('UDP-SNMP');
                    if( $tmp_object !== null )
                    {
                        $tmp_servicegroup->addMember($tmp_object);
                    }
                }


            }


            if( preg_match("/^set group service /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);

                $name_ext = $data[3];
                $name_ext = $this->truncate_names($this->normalizeNames($name_ext));

                $tmp_servicegroup = $this->sub->serviceStore->find($name_ext);
                if( $tmp_servicegroup == null )
                {
                    if( $print )
                        print "create servicegroup Object: " . $name_ext . "\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($name_ext);

                    #print "create servicegroup object: ".$name_ext."\n";
                }

                if( isset($data[4]) )
                {
                    switch ($data[4])
                    {
                        case "comment":
                            $comment = $data[5];

                            //PAN-OS does not has servicegroup description possiblities
                            #$tmp_servicegroup->setDescription( $comment );
                            break;

                        case "add":
                            $member = $data[5];
                            #$member = $this->truncate_names($this->normalizeNames($member));
                            $tmp_object = $this->sub->serviceStore->find($member);
                            if( $tmp_object !== null )
                            {
                                $tmp_servicegroup->addMember($tmp_object);
                            }
                            else
                            {
                                $member = $this->truncate_names($this->normalizeNames($member));
                                $tmp_object = $this->sub->serviceStore->find($member);
                                if( $tmp_object !== null )
                                {
                                    $tmp_servicegroup->addMember($tmp_object);
                                }

                                else
                                {
                                    $tmp_object = $this->sub->serviceStore->find( "tmp-".$member);
                                    if( $tmp_object !== null )
                                    {
                                        $tmp_servicegroup->addMember($tmp_object);
                                    }
                                    else
                                    {
                                        $found = FALSE;
                                        foreach( $add_srv as $key => $tmp_srv )
                                        {
                                            if( $tmp_srv[0] == $member )
                                            {
                                                $tmp_service = $this->sub->serviceStore->find($tmp_srv[1]);
                                                if( $tmp_service !== null )
                                                {
                                                    $tmp_servicegroup->addMember($tmp_service);
                                                    $found = TRUE;
                                                }
                                            }
                                        }

                                        if( !$found )
                                        {
                                            print "not found: ".$member."/n";

                                            $tmp_service = $this->sub->serviceStore->newService($member, 'tcp', "65000");
                                            $tmp_service->setDescription("FIX service - protocol / port / custom app");

                                            if( $tmp_service !== null )
                                            {
                                                $tmp_servicegroup->addMember($tmp_service);
                                            }
                                            if( $debug )
                                                print "servicegroup: " . $tmp_servicegroup->name() . " service object not available : " . $member . " \n";
                                            $servicegroup[$tmp_servicegroup->name()][$this->sub->name()][] = $member;
                                        }
                                    }


                                }
                            }
                            break;

                        default:

                    }
                }
            }
        }

        return $servicegroup;
    }


    function fix_servicegroup_tmp_service( $servicegroup)
    {
        global $debug;
        global $print;


        foreach( $servicegroup as $key => $vsyss )
        {
            foreach( $vsyss as $key2 => $groups )
            {
                /*
                //search vsys $key2
                $this->template_vsys = $this->template->findVirtualSystem($key2);
                if( $this->template_vsys === null )
                {
                    derr("vsys: vsys1 could not be found ! Exit\n");
                }
                */

                $tmp_servicegroup = $this->sub->serviceStore->find($key);
                $tmp_rule_references = $tmp_servicegroup->refrules;


                foreach( $tmp_rule_references as $ref )
                {

                    $refClass = get_class($ref);
                    if( $refClass == 'ServiceGroup' )
                    {

                    }
                    elseif( $refClass == 'ServiceRuleContainer' )
                    {
                        /** @var ServiceRuleContainer $ref */

                        $ruleClass = get_class($ref->owner);
                        if( $ruleClass == 'SecurityRule' )
                        {
                            foreach( $groups as $key3 => $group )
                            {

                                $tmp_service2 = $this->sub->serviceStore->findOrCreate($group);
                                $ref->add($tmp_service2);
                            }


                        }
                        elseif( $ruleClass == 'NatRule' )
                        {
                            if( $debug )
                                mwarning('unsupported use case in ' . $ref->_PANC_shortName(), null, FALSE);
                        }
                        else
                            if( $debug )
                                mwarning('unsupported owner_class: ' . $ruleClass, null, FALSE);
                    }
                    else
                        if( $debug )
                            mwarning('unsupport class : ' . $refClass, null, FALSE);
                }


            }
        }
    }


    function fix_services_multiple_protocol($vsys, $source)
    {
        global $projectdb;
        $getDup = $projectdb->query("SELECT name_ext,name,count(id) as duplicates FROM services WHERE source='$source' AND dport!='' AND vsys='$vsys' GROUP BY name HAVING duplicates > 1;");
        while( $names = $getDup->fetch_assoc() )
        {
            $name_int = $names['name'];
            $originalname = $names['name'];
            add_log('1', 'Phase 3: Reading Services Objects and Groups', 'Creating ServiceGroup [' . $name_int . ']. Original SRV contains more than one Protocol', $source, 'No Action Requierd.');
            $getSGDup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name='$name_int';");
            if( $getSGDup->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO services_groups_id (name,name_ext,source,vsys) values ('$name_int','$originalname','$source','$vsys');");
                $grplid = $projectdb->insert_id;
            }
            else
            {
                #EXISTS Raise error?
            }

            $getElement = $projectdb->query("SELECT id,name_ext,name,protocol FROM services WHERE source='$source' AND BINARY name='$name_int';");
            while( $data2 = $getElement->fetch_assoc() )
            {
                $id = $data2['id'];
                $protocol = $data2['protocol'];
                $mynewname = $name_int . "-" . $protocol;
                $mynewname_int = $this->truncate_names($this->normalizeNames($mynewname));
                $projectdb->query("UPDATE services SET name_ext='$mynewname', name='$mynewname_int' WHERE id='$id';");
                $projectdb->query("INSERT INTO services_groups (lid,member_lid,table_name,vsys,source) VALUES ('$grplid','$id','services','$vsys','$source')");
            }
        }
    }


}



