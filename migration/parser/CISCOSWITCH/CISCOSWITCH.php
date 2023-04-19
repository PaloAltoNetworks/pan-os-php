<?php

require_once("parser/CISCOSWITCH/CISCOSWITCHmisc.php");

class CISCOSWITCH extends PARSER
{
    use CISCOSWITCHmisc;
    use SHAREDNEW;


    public $rule_count = 0;
    public $print_rule_array = TRUE;
    public $print = TRUE;
    public $debug = TRUE;

    public $wildcard = FALSE;


    public $svcReplaceByOther = array();

    function cisco_service_replace()
    {
        $this->svcReplaceByOther["ip"] = array('any');
        $this->svcReplaceByOther['smtp'] = array('25');
        $this->svcReplaceByOther['snmp'] = array('161');
        $this->svcReplaceByOther['www'] = array('80');
        $this->svcReplaceByOther['netbios-ss'] = array('139');
        $this->svcReplaceByOther['netbios-ns'] = array('137');
        $this->svcReplaceByOther['netbios-dgm'] = array('138');
        $this->svcReplaceByOther['24962Replace'] = array('24962');
        $this->svcReplaceByOther['bootps'] = array('67');
        $this->svcReplaceByOther['tacacs'] = array('49');
        $this->svcReplaceByOther['msrpc'] = array('135');

        $this->svcReplaceByOther['bootpc'] = array('68');
        $this->svcReplaceByOther['domain'] = array('53');
        $this->svcReplaceByOther['isakmp'] = array('500');
        $this->svcReplaceByOther['ftp'] = array('21');
        $this->svcReplaceByOther['pop3'] = array('110');
        $this->svcReplaceByOther['ident'] = array('113');
        $this->svcReplaceByOther['ntp'] = array('123');
        $this->svcReplaceByOther['lpd'] = array('53');
        $this->svcReplaceByOther['sunrpc'] = array('111');
        $this->svcReplaceByOther['snmptrap'] = array('162');
        $this->svcReplaceByOther['sunrpc1'] = array('111');
        $this->svcReplaceByOther['sunrpc2'] = array('111');
        $this->svcReplaceByOther['sunrpc3'] = array('111');
        $this->svcReplaceByOther['sunrpc4'] = array('111');
        $this->svcReplaceByOther['sunrpc5'] = array('111');
        $this->svcReplaceByOther['bgp'] = array('179');

        $this->svcReplaceByOther['ftp-data'] = array('20');
        $this->svcReplaceByOther['telnet'] = array('23');
        $this->svcReplaceByOther['tftp'] = array('69');//but UDP how to fix????
        $this->svcReplaceByOther['nameserver'] = array('53');
        $this->svcReplaceByOther['daytime'] = array('13');
        $this->svcReplaceByOther['chargen'] = array('19');
        $this->svcReplaceByOther['echo'] = array('7');
        $this->svcReplaceByOther['rip'] = array('520');//but UDP how to fix???
    }

    function vendor_main()
    {




        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done

        $this->print = TRUE;
        $this->debug = TRUE;


        $this->cisco_service_replace();

        //CISCOSWITCH specific
        //------------------------------------------------------------------------
        $this->clean_config();


        $this->import_config(); //This should update the $source
        //------------------------------------------------------------------------
        CONVERTER::deleteDirectory( );
    }

    function clean_config()
    {

        $config_file = file($this->configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->data = array();
        foreach( $config_file as $line => $names_line )
        {
            /*
            if( (preg_match("/description/", $names_line)) OR (preg_match("/remark/", $names_line)) )
            {
                #$data[] = $names_line;

                //Todo: SVEN 20191203 - problem with config "
                $tmp_array = explode("\r", $names_line);
                foreach( $tmp_array as $tmp_line )
                    $data[] = $tmp_line;
            }
            else
            {
                #"<--- More --->"
                if( preg_match("/^<--- More --->/", $names_line) || preg_match("/^              /", $names_line) )
                {

                }
                elseif( preg_match("/\'/", $names_line) )
                {
                    $data[] = str_replace("'", "_", $names_line);
                }
                elseif( preg_match("/\\r/", $names_line) )
                {
                    $tmp_array = explode("\r", $names_line);
                    foreach( $tmp_array as $tmp_line )
                        $data[] = $tmp_line;
                }
                else
                {
                    $data[] = $names_line;
                }
            }
            */
            $this->data[] = $names_line;

        }
    }

    function import_config()
    {

        //CISCOSWITCH specific functions




        $this->load_custom_application();


        $IpMaskTable = array();
        $NetworkGroupTable = array();


        $foundObject = array();
        $keyToCheck = 0;
        $accessList = "";
        $found_objectgroup = FALSE;
        $objectgroup = array();

        foreach( $this->data as $index => &$line )
        {
            $line = $this->strip_hidden_chars($line);

            $line = trim($line, "\r");
            $line = trim($line, " ");

            $line = str_replace("   ", " ", $line);
            $line = str_replace("  ", " ", $line);

            #print "|".$line."|\n";
            $words = explode(' ', $line);

            $words['sequence'] = "sequence_not_numeric";
            $words['name'] = "NULL";

            if( is_numeric($words[0]) )
            {
                $words['sequence'] = $words[0];
                unset($words[0]);
                //accesslist-sequence
                $keyToCheck = 1;
            }


            if( count($words) == 0 )
                continue;

            if( empty($words[$keyToCheck]) )
                continue;

            if( strpos($words[$keyToCheck], '#') === FALSE && strpos($words[$keyToCheck], '!') === FALSE )
            {
                if( isset($words[0]) )
                {
                    if( ($words[0] == "ip" || $words[0] == "ipv6") && $words[1] == "access-list" )
                    {
                        #print_r($words);
                        if( $words[2] !== "extended" )
                        {
                            //accesslist-name
                            $accessList = $words[2];
                        }

                    }
                    elseif( ($words[0] == "object-group") )
                    {
                        if( $found_objectgroup && !empty($objectgroup_child) )
                            $objectgroup[] = $objectgroup_child;

                        $objectgroup_child = array();
                        print "CREATE object group" . $words[2] . "\n";
                        $objectgroup_child['name'] = $words[2];
                        $found_objectgroup = TRUE;
                        continue;
                    }
                    elseif( strpos($words[0], ".") !== FALSE && $found_objectgroup )
                    {
                        $objectgroup_child[] = $words[0] . "/" . $words[1];
                        continue;
                    }
                    elseif( $found_objectgroup )
                    {
                        if( !empty($objectgroup_child) )
                            $objectgroup[] = $objectgroup_child;
                        $found_objectgroup = FALSE;
                    }
                }


                $words['name'] = $accessList;

                if( $words[$keyToCheck] == "permit" || $words[$keyToCheck] == "deny" )
                {
                    if( $accessList !== "" )
                    {
                        if( strpos($accessList, "-in4") !== FALSE || strpos($accessList, "-in6") !== FALSE )
                        {
                            $accessList1 = str_replace("-in4", "", $accessList);
                            $accessList1 = str_replace("-in6", "", $accessList1);
                            $words['access-list']['from'] = $accessList1;

                            if( strpos($accessList, "-in4") !== FALSE )
                                $words['access-list']['ipv4'] = TRUE;
                            if( strpos($accessList, "-in6") !== FALSE )
                                $words['access-list']['ipv6'] = TRUE;
                        }
                        elseif( strpos($accessList, "-out4") !== FALSE || strpos($accessList, "-out6") !== FALSE )
                        {
                            $accessList1 = str_replace("-out4", "", $accessList);
                            $accessList1 = str_replace("-out6", "", $accessList1);
                            $words['access-list']['to'] = $accessList1;

                            if( strpos($accessList, "-out4") !== FALSE )
                                $words['access-list']['ipv4'] = TRUE;
                            if( strpos($accessList, "-out6") !== FALSE )
                                $words['access-list']['ipv6'] = TRUE;
                        }
                        else
                        {

                            $words['access-list']['to'] = $accessList;

                            //Todo: why should this rule be deleted?
                            #$words['access-list']['delete'] = "delete";


                            #print "ACL:|".$accessList."|\n";
                        }


                    }
                    $foundObject[] = $words;

                }
                else
                {
                    #print_r( $words );
                }

            }

        }

        #exit;

        print "found " . count($foundObject) . " ACL rules\n";

        if( !empty($objectgroup) )
        {
            print_r($objectgroup);
            foreach( $objectgroup as $key => $group )
            {
                $HostGroupNamePan = $group['name'];
                $tmp_addressgroup = $this->sub->addressStore->find($HostGroupNamePan);
                if( $tmp_addressgroup === null )
                {
                    if( $this->print )
                        print "\n * create addressgroup: " . $HostGroupNamePan . "\n";
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($HostGroupNamePan);
                }
                unset($group['name']);

                foreach( $group as $object )
                {
                    $address_value = explode("/", $object);
                    //create address object; format is IP/subnetmask
                    print "add: " . $address_value[0] . " with netmask: " . $address_value[1] . "\n";
                    $pad = "n-";
                    //calculate based on $address_value[1]
                    $tmp_netmask = CIDR::netmask2cidr($address_value[1]);

                    $name = $pad . $address_value[0] . "/" . $tmp_netmask;

                    $tmp_address = $this->MainAddHost( $name, $address_value[0] . "/" . $tmp_netmask );
                    /*
                    $tmp_address = $this->sub->addressStore->find($name);
                    if( $tmp_address == null )
                    {
                        if( $this->print )
                            print "      * create address object: " . $name . " - " . $address_value[0] . "/" . $tmp_netmask . "\n";
                        $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-netmask', $address_value[0] . "/" . $tmp_netmask);
                    }
                    */

                    $tmp_addressgroup->addMember($tmp_address);
                }
            }
        }


        foreach( $foundObject as $object )
        {

            #print_r( $object );

            //$object[0] => permit / deny
            //$object[1] => tcp / udp / ip     || migrate to app-id icmp / gre / ospf

            $rule_array = array();
            $wildcard = FALSE;
            $protocol = "";
            if( $object[$keyToCheck] == "permit" || $object[$keyToCheck] == "deny" )
            {

                $rule_array['action'] = $object[$keyToCheck];
                $ii = $keyToCheck + 1;

                if( $object['name'] != "" )
                    $rule_array['name'] = $object['name'];
                else
                    $rule_array['name'] = "NONAME";
                $rule_array['sequence'] = $object['sequence'];


                if( is_numeric($object[$ii]) )
                {
                    $tmp_app = $this->sub->appStore->get_app_by_ipprotocol($object[$ii]);
                    if( $tmp_app !== null )
                        $rule_array['appid'] = $tmp_app->name();
                }


                if( isset($rule_array['appid']) || $object[$ii] == "ip" || $object[$ii] == "ipv6" || $object[$ii] == "tcp" || $object[$ii] == 'udp' || $object[$ii] == 'icmp' || $object[$ii] == 'gre' || $object[$ii] == 'ospf' || $object[$ii] == 'esp' || $object[$ii] == 'ahp' || $object[$ii] == 'igmp' )
                {
                    if( isset($object['access-list']['delete']) )
                    {
                        print "delete | but why: " . $object['name'] . "\n";
                        continue;
                    }

                    if( isset($object['access-list']['ipv6']) )
                        $rule_array['ipv6'] = TRUE;

                    if( isset($object['access-list']['to']) )
                    {
                        $rule_array['to'] = $object['access-list']['to'];
                    }


                    if( isset($object['access-list']['from']) )
                        $rule_array['from'] = $object['access-list']['from'];

                    if( $object[$ii] == 'icmp' || $object[$ii] == 'gre' || $object[$ii] == 'ospf' || $object[$ii] == 'esp' || $object[$ii] == 'ahp' || $object[$ii] == 'igmp' )
                    {
                        if( isset($rule_array['appid']) )
                            mwarning("appid already set: " . $rule_array['appid'], null, FALSE);
                        else
                            $rule_array['appid'] = $object[$ii];
                    }

                    $ii++;//2
                    if( $object[$ii] == "any" || $object[$ii] == "host" || $object[$ii] == "object-group" || strpos($object[$ii], "/") !== FALSE )
                    {
                        //find SOURCE information
                        if( isset($object[$ii]) && $object[$ii] == "any" )
                        {
                            //any => SRC: any
                            //[2]
                            $rule_array['src'] = $object[$ii];
                            $ii++;//3
                        }
                        elseif( isset($object[$ii]) && ($object[$ii] == "host" || $object[$ii] == "object-group") )
                        {
                            #print_r($object);
                            //host ip => [3]
                            $ii++;
                            $rule_array['src'] = $object[$ii];
                            $ii++;//4
                        }
                        elseif( isset($object[$ii]) && strpos($object[$ii], "/") !== FALSE )
                        {
                            $rule_array['src'] = $object[$ii];
                            $ii++;
                        }
                        else
                            derr('not supported: ' . $object[$ii]);

                        //find DESTINATION information
                        if( isset($object[$ii]) && $object[$ii] == "any" )
                        {
                            //any => DST: any
                            //[3]
                            $rule_array['dst'] = $object[$ii];
                            $ii++;//4
                        }
                        elseif( isset($object[$ii]) && ($object[$ii] == "host" || $object[$ii] == "object-group") )
                        {
                            //host ip => [5]
                            $ii++;
                            $rule_array['dst'] = $object[$ii];
                            $ii++;//7
                        }
                        elseif( isset($object[$ii]) && strpos($object[$ii], "/") !== FALSE )
                        {
                            $rule_array['dst'] = $object[$ii];
                            $ii++;
                        }
                        else
                        {
                            //no DESTINATION found => search for source service information
                            if( isset($object[$ii]) && ($object[$ii] == "eq" || $object[$ii] == "range" || $object[$ii] == "lt" || $object[$ii] == "gt" || $object[$ii] == "neq") )
                            {
                                $tmp_array = $this->service_reading($object, $rule_array, $ii, 'src-srv');
                                $rule_array = $tmp_array[0];
                                $ii = $tmp_array[1];
                            }

                            //find DESTINATION information
                            if( $ii !== "" && isset($object[$ii]) && !isset($rule_array['dst']) )
                            {

                                $tmp_array = $this->dst_reading($object, $rule_array, $ii);
                                $rule_array = $tmp_array[0];
                                $ii = $tmp_array[1];
                            }
                        }

                        //search for destination service information
                        if( isset($object[$ii]) && ($object[$ii] == "eq" || $object[$ii] == "range" || $object[$ii] == "lt" || $object[$ii] == "gt" || $object[$ii] == "neq") )
                        {
                            $tmp_array = $this->service_reading($object, $rule_array, $ii);
                            $rule_array = $tmp_array[0];
                            $ii = $tmp_array[1];
                        }
                        elseif( isset($object[$ii]) )
                        {
                            if( $object[$ii] == "established" )
                            {
                                #print_r( $object );
                                #derr( 'not supported: '.$object[$ii] );
                                //TODO: 20190109: feedback no migration needed
                                continue;
                            }
                            elseif( $object[$ii] == "log" )
                            {

                            }
                            else
                            {
                                if( $object[2] == "icmp" )
                                {
                                    //if( $object[$ii] == 'echo' || $object[$ii] == 'echo-request' || $object[$ii] == 'echo-reply' || $object[$ii] == 'unreachable')

                                    if( $object[$ii] == 'echo' )
                                    {
                                        $rule_array['appid'] = 'icmp_' . $object[$ii];
                                    }
                                    elseif( $object[$ii] == 'echo-request' )
                                    {
                                        $rule_array['appid'] = 'icmp_' . $object[$ii];
                                    }
                                    elseif( $object[$ii] == 'echo-reply' )
                                    {
                                        $rule_array['appid'] = 'icmp_' . $object[$ii];
                                    }
                                    elseif( $object[$ii] == 'unreachable' )
                                    {
                                        $rule_array['appid'] = 'icmp_' . $object[$ii];
                                    }
                                    elseif( $object[$ii] == 'port-unreachable' )
                                    {
                                        $rule_array['appid'] = 'icmp_' . $object[$ii];
                                    }
                                    elseif( $object[$ii] == 'time-exceeded' )
                                    {
                                        $rule_array['appid'] = 'icmp_' . $object[$ii];
                                    }
                                    elseif( $object[$ii] == 'nd-na' )
                                    {
                                        $rule_array['appid'] = 'ipv6-icmp_' . $object[$ii];
                                        #$this->print_rule_array = true;
                                    }
                                    elseif( $object[$ii] == 'nd-ns' )
                                    {
                                        $rule_array['appid'] = 'ipv6-icmp_' . $object[$ii];
                                        #$this->print_rule_array = true;
                                    }
                                    else
                                    {
                                        mwarning('ICMP type not supported: ' . $object[$ii]);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        //SOURCE INFORMATION is WILDCARD | not ANY / HOST or something with a NETMASK
                        //$ii //2
                        $tmp_array = $this->wildcard_reading($object, $rule_array, $ii, 'src');
                        $rule_array = $tmp_array[0];
                        $ii = $tmp_array[1];

                        //find DESTINATION information
                        if( isset($object[$ii]) && $object[$ii] == "any" )
                        {
                            //any => DST: any
                            //[3]
                            $rule_array['dst'] = $object[$ii];
                            $ii++;//4
                        }
                        elseif( isset($object[$ii]) && ($object[$ii] == "host" || $object[$ii] == "object-group") )
                        {
                            //host ip => [5]
                            $ii++;
                            $rule_array['dst'] = $object[$ii];
                            $ii++;//7
                        }
                        elseif( isset($object[$ii]) && strpos($object[$ii], "/") !== FALSE )
                        {
                            $rule_array['dst'] = $object[$ii];
                            $ii++;
                        }
                        else
                        {
                            //no DESTINATION found => search for source service information
                            if( isset($object[$ii]) && ($object[$ii] == "eq" || $object[$ii] == "range" || $object[$ii] == "lt" || $object[$ii] == "gt" || $object[$ii] == "neq") )
                            {
                                $tmp_array = $this->service_reading($object, $rule_array, $ii, 'src-srv');
                                $rule_array = $tmp_array[0];
                                $ii = $tmp_array[1];
                            }

                            //find DESTINATION information
                            if( $ii !== "" && isset($object[$ii]) && !isset($rule_array['dst']) )
                            {

                                $tmp_array = $this->dst_reading($object, $rule_array, $ii);
                                $rule_array = $tmp_array[0];
                                $ii = $tmp_array[1];
                            }
                        }


                        //search for destination service information
                        if( isset($object[$ii]) && ($object[$ii] == "eq" || $object[$ii] == "range" || $object[$ii] == "lt" || $object[$ii] == "gt" || $object[$ii] == "neq") )
                        {
                            $tmp_array = $this->service_reading($object, $rule_array, $ii);
                            $rule_array = $tmp_array[0];
                            $ii = $tmp_array[1];
                        }
                        elseif( isset($object[$ii]) )
                        {
                            if( $object[$ii] == "established" )
                            {
                                #print_r( $object );
                                #derr( 'not supported: '.$object[$ii] );
                                //TODO: 20190109: feedback no migration needed
                                continue;
                            }
                            elseif( $object[$ii] == "log" )
                            {

                            }
                        }
                    }
                }
                else
                {
                    print_r($object);
                    mwarning(' Protocol not supported yet - plan for APP-ID migration: ' . $object[$ii], null, FALSE);
                    continue;
                }
            }


            //CREATE PAN-OS rules
            if( !empty($rule_array) )//&& $wildcard )
            {
                #print_r( $rule_array );

                //cleanup of IPv4 deny rules if IPv6 is available in addition
                if( isset($rule_array['ipv6']) && $rule_array['src'] == "any" && $rule_array['dst'] == "any" && !isset($rule_array['srv']) && !isset($rule_array['src-srv']) && $rule_array['action'] == "deny" )
                {
                    $available_rules = $this->sub->securityRules->rules();

                    foreach( $available_rules as $rule )
                    {
                        if( $rule->source->isAny() && $rule->destination->isAny() && $rule->services->isAny() && $rule->actionIsDeny() )
                        {
                            if( $rule->to->isAny() && isset($rule_array['from']) )
                            {
                                $tmp_from = $this->template_vsys->zoneStore->find($rule_array['from']);

                                if( $tmp_from === null )
                                    continue;
                                else
                                {
                                    if( $rule->from->hasZone($tmp_from) )
                                    {
                                        if( $this->print )
                                        {
                                            $msg = "remove Rule because of IPv6 ANY ANY ANY DENY: " . $rule->name();
                                            print PH::boldText("\n" . $msg . "\n");
                                            mwarning($msg, null, FALSE);
                                        }

                                        $rule->display();
                                        $this->sub->securityRules->remove($rule);
                                    }
                                }
                            }

                            if( $rule->from->isAny() && isset($rule_array['to']) )
                            {
                                $tmp_to = $this->template_vsys->zoneStore->find($rule_array['to']);

                                if( $tmp_to === null )
                                    continue;
                                else
                                {
                                    if( $rule->to->hasZone($tmp_to) )
                                    {
                                        if( $this->print )
                                        {
                                            $msg = "remove Rule because of IPv6 FROM:ANY TO: " . $tmp_to->name() . " ANY ANY ANY DENY: " . $rule->name();
                                            print PH::boldText("\n" . $msg . "\n");
                                            mwarning($msg, null, FALSE);
                                        }

                                        $rule->display();
                                        $this->sub->securityRules->remove($rule);
                                    }
                                }
                            }
                        }
                    }
                }


                $rulename = "Rule-" . $this->rule_count . "_" . $rule_array['name'] . "-" . $rule_array['sequence'];
                $rule = $this->sub->securityRules->newSecurityRule($rulename);

                if( $this->print )
                    print " * create security Rule: '" . $rulename . "'\n";


                $tmp_tag = $this->sub->tagStore->find($rule_array['name']);

                if( $tmp_tag === null )
                {
                    if( $this->print )
                        print "      * create new TAG called: '" . $rule_array['name'] . "'\n";
                    $tmp_tag = $this->sub->tagStore->createTag($rule_array['name']);
                }
                if( !$rule->tags->hasTag($tmp_tag) )
                {
                    if( $this->print )
                        print "    * add TAG called: '" . $tmp_tag->name() . "'\n";
                    $rule->tags->addTag($tmp_tag);
                }


                if( isset($rule_array['ipv6']) )
                {
                    $tmp_tag = $this->sub->tagStore->find("ipv6");

                    if( $tmp_tag === null )
                    {
                        if( $this->print )
                            print "      * create new TAG called: 'ipv6'\n";
                        $tmp_tag = $this->sub->tagStore->createTag("ipv6");
                    }
                    if( $this->print )
                        print "    * add TAG called: '" . $tmp_tag->name() . "'\n";
                    $rule->tags->addTag($tmp_tag);
                }

                //TO-ZONE
                if( isset($rule_array['to']) )
                {
                    $tmp_to = $this->template_vsys->zoneStore->find($rule_array['to']);

                    if( $tmp_to === null )
                    {
                        if( $this->print )
                            print "      * create new Zone called: " . $rule_array['to'] . "\n";
                        $tmp_to = $this->template_vsys->zoneStore->newZone($rule_array['to'], 'layer3');
                    }


                    $rule->to->addZone($tmp_to);
                    if( $this->print )
                        print "    * add to Zone: " . $tmp_to->name() . "\n";
                }

                //FROM-ZONE
                if( isset($rule_array['from']) )
                {
                    $tmp_from = $this->template_vsys->zoneStore->find($rule_array['from']);

                    if( $tmp_from === null )
                    {
                        if( $this->print )
                            print "      * create new Zone called: " . $rule_array['from'] . "\n";
                        $tmp_from = $this->template_vsys->zoneStore->newZone($rule_array['from'], 'layer3');
                    }


                    $rule->from->addZone($tmp_from);
                    if( $this->print )
                        print "    * add from Zone: " . $tmp_from->name() . "\n";
                }


                //SRC
                if( $rule_array['src'] == "any" )
                {
                    $rule->source->setAny();
                }
                else
                {
                    if( strpos($rule_array['src'], "/") !== FALSE )
                    {
                        if( strpos($rule_array['src'], "/32") !== FALSE )
                            $pad = "h-";
                        else
                            $pad = "n-";

                        $name = str_replace("/", "m", $rule_array['src']);
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }
                    else
                    {
                        $pad = "h-";
                        $name = $rule_array['src'];
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }


                    $tmp_src = $this->sub->addressStore->find($pad . $name);
                    if( $tmp_src == null )
                    {
                        if( $this->print )
                            print "      * create address object: " . $pad . $name . " - " . $rule_array['src'] . "\n";
                        $tmp_src = $this->sub->addressStore->newAddress($pad . $name, 'ip-netmask', $rule_array['src']);
                    }

                    $rule->source->addObject($tmp_src);
                    if( $this->print )
                        print "    * add source addressobject: " . $tmp_src->name() . "\n";
                }


                if( !isset($rule_array['dst']) )
                {
                    #print_r( $object );
                    #print_r( $rule_array );
                }

                //DST
                if( $rule_array['dst'] == "any" )
                {
                    $rule->destination->setAny();
                }
                else
                {
                    if( strpos($rule_array['dst'], "/") !== FALSE )
                    {
                        if( strpos($rule_array['dst'], "/32") !== FALSE )
                            $pad = "h-";
                        else
                            $pad = "n-";

                        $name = str_replace("/", "m", $rule_array['dst']);
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }
                    else
                    {
                        if( strpos($rule_array['dst'], ".") !== FALSE )
                            $pad = "h-";
                        else
                            $pad = "";
                        $name = $rule_array['dst'];
                        $name = str_replace("::", "__", $name);
                        $name = str_replace(":", "_", $name);
                    }

                    $tmp_dst = $this->sub->addressStore->find($pad . $name);
                    if( $tmp_dst == null )
                    {
                        if( $this->print )
                            print "      * create address object: " . $pad . $name . " - " . $rule_array['dst'] . "\n";
                        $tmp_dst = $this->sub->addressStore->newAddress($pad . $name, 'ip-netmask', $rule_array['dst']);
                    }


                    $rule->destination->addObject($tmp_dst);
                    if( $this->print )
                        print "    * add destination addressobject: " . $tmp_dst->name() . "\n";
                }

                if( isset($rule_array['src-srv']) && !isset($rule_array['srv']) )
                {
                    $prot = explode("|", $rule_array['src-srv']);

                    $protocol = $prot[0];
                    $services = $prot[1];

                    $tmp_srv = $this->sub->serviceStore->find($protocol . "-src" . $services . "_1-65535");
                    if( $tmp_srv == null )
                    {
                        if( $this->print )
                            print "     * create service source: " . $protocol . "-src" . $services . "_1-65535\n";
                        $tmp_srv = $this->sub->serviceStore->newService($protocol . "-src" . $services . "_1-65535", $protocol, '1-65535', '', $services);
                    }


                    if( $tmp_srv !== null )
                    {
                        if( $this->print )
                            print "    * service source and destination added: " . $tmp_srv->name() . "\n";
                        $rule->services->add($tmp_srv);
                    }
                    else
                        mwarning("service not found nor created: " . $protocol . "-src" . $services . "_1-65535");
                }

                if( isset($rule_array['srv']) )
                {
                    if( isset($rule_array['src-srv']) )
                    {
                        $src_prot = explode("|", $rule_array['src-srv']);
                        $src_protocol = $src_prot[0];
                        $src_services = $src_prot[1];

                        $prot = explode("|", $rule_array['srv']);
                        $protocol = $prot[0];
                        $services = $prot[1];

                        $tmp_srv = $this->sub->serviceStore->find($protocol . "-src" . $src_services . "_" . $services);
                        if( $tmp_srv == null )
                        {
                            if( $this->print )
                                print "     * create service source: " . $protocol . "-src" . $src_services . "_" . $services . "\n";
                            $tmp_srv = $this->sub->serviceStore->newService($protocol . "-src" . $src_services . "_" . $services, $protocol, $services, '', $src_services);
                        }


                        if( $tmp_srv !== null )
                        {
                            if( $this->print )
                                print "    * service source and destination added: " . $tmp_srv->name() . "\n";
                            $rule->services->add($tmp_srv);
                        }

                        else
                            mwarning("service not found nor created: " . $protocol . "-src" . $src_services . "_" . $services);
                    }
                    else
                    {
                        $prot = explode("|", $rule_array['srv']);

                        $protocol = $prot[0];
                        $services = $prot[1];

                        $tmp_srv = $this->sub->serviceStore->find($protocol . "-" . $services);
                        if( $tmp_srv == null )
                        {
                            if( $this->print )
                                print "     * create service object: " . $protocol . "-" . $services . "\n";
                            $tmp_srv = $this->sub->serviceStore->newService($protocol . "-" . $services, $protocol, $services);
                        }

                        if( $tmp_srv !== null )
                        {
                            if( $this->print )
                                print "    * service destination added: " . $tmp_srv->name() . "\n";
                            $rule->services->add($tmp_srv);
                        }
                        else
                            mwarning("service not found nor created: " . $protocol . "-" . $services);
                    }
                }
                elseif( !isset($rule_array['src-srv']) )
                {
                    if( $this->print )
                        print "    * service set to ANY\n";
                    $rule->services->setAny();
                }


                if( isset($rule_array['appid']) )
                {
                    if( strpos($rule_array['appid'], "icmp") !== FALSE )
                    {
                        if( isset($rule_array['ipv6']) )
                        {
                            if( $rule_array['appid'] == "icmp" )
                            {
                                $tmp_app = $this->sub->appStore->find('ipv6-icmp');

                                $tmp_app1 = $this->sub->appStore->find('traceroute');
                                if( $tmp_app1 !== null )
                                {
                                    if( $this->print )
                                        print "    * APP add: " . $tmp_app1->name() . "\n";
                                    $rule->apps->addApp($tmp_app1);
                                }
                                $tmp_app1 = $this->sub->appStore->find('ping');
                                if( $tmp_app1 !== null )
                                {
                                    if( $this->print )
                                        print "    * APP add: " . $tmp_app1->name() . "\n";
                                    $rule->apps->addApp($tmp_app1);
                                }
                            }
                            else
                                $tmp_app = $this->sub->appStore->findorCreate('ipv6-' . $rule_array['appid']);
                        }
                        else
                        {
                            if( $rule_array['appid'] == "icmp" )
                            {
                                $tmp_app = $this->sub->appStore->find('icmp');
                                $tmp_app1 = $this->sub->appStore->find('traceroute');
                                if( $tmp_app1 !== null )
                                {
                                    if( $this->print )
                                        print "    * APP add: " . $tmp_app1->name() . "\n";
                                    $rule->apps->addApp($tmp_app1);
                                }
                                $tmp_app1 = $this->sub->appStore->find('ping');
                                if( $tmp_app1 !== null )
                                {
                                    if( $this->print )
                                        print "    * APP add: " . $tmp_app1->name() . "\n";
                                    $rule->apps->addApp($tmp_app1);
                                }
                            }
                            else
                                $tmp_app = $this->sub->appStore->findorCreate('' . $rule_array['appid']);
                        }

                        if( $tmp_app !== null )
                        {
                            if( isset($tmp_app->tmp_details) )
                            {

                            }
                            if( $this->print )
                                print "    * APP add: " . $tmp_app->name() . "\n";
                            $rule->apps->addApp($tmp_app);
                            $rule->services->setApplicationDefault();
                        }
                        else
                        {

                        }


                    }
                    else
                    {
                        if( $rule_array['appid'] == "esp" || $rule_array['appid'] == "ahp" )
                            $rule_array['appid'] = "ipsec";

                        $tmp_app = $this->sub->appStore->find($rule_array['appid']);

                        if( $tmp_app !== null )
                        {
                            if( $this->print )
                                print "    * APP add: " . $tmp_app->name();
                            $rule->apps->addApp($tmp_app);
                            $rule->services->setApplicationDefault();
                        }
                        else
                        {
                            $this->print_rule_array = TRUE;

                            mwarning("app-id: " . $rule_array['appid'] . " not found!!!", null, FALSE);
                        }
                    }
                }

                //ACTION
                if( $rule_array['action'] == "permit" )
                {
                    if( $this->print )
                        print "    * action set: ALLOW\n";
                    $rule->setAction('allow');
                }
                elseif( $rule_array['action'] == "deny" )
                {
                    if( $this->print )
                        print "    * action set: DENY\n";
                    $rule->setAction('deny');
                }


                $this->rule_count++;
            }
        }

    }

}