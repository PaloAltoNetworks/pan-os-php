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


trait CISCOsecurityrules
{

    /**
     * @param array $this->data
     * @param VirtualSystem $v
     */
    function get_security_policies2()
    {
        global $projectdb;

        global $debug;
        global $print;

        $print = true;

        #$AccessGroups = array();
        #$AccessGroups['global'] = new SecurityGroup('global');
        $AccessGroups['global'] = array();
        $thecolor = 1;
        $addTag = array();
        $allTags = array();


        //Create the AccessGroups and the Tags for the AccessGroup
        foreach( $this->data as $line => $names_line )
        {
            if( preg_match("/^access-group /i", $names_line) )
            {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                #$group = new SecurityGroup($netObj[1]);
                $group = array();
                $group['position'] = 1;


                $direction = $netObj[2];

                switch ($direction)
                {
                    case "in":
                        #$group->addZoneFrom($netObj[4]);
                        $group['addZoneFrom'] = $netObj[4];
                        #$tmp_rule->from->addZone($tmp_zone);
                        break;
                    case "out":
                        #$group->addZoneTo($netObj[4]);
                        $group['addZoneTo'] = $netObj[4];
                        #$tmp_rule->to->addZone($tmp_zone);
                        break;
                    default:
                        break;
                }

                $AccessGroups[$netObj[1]] = $group;
                #$AccessGroups[$netObj[1]] = $tmp_rule;

                #Add Tag
                $color = "color" . $thecolor;
                $tagname = $this->truncate_tags($netObj[1]);

                $tagname = $this->truncate_tags($this->normalizeNames($tagname));
                if( $tagname != "" )
                {
                    $tmp_tag = $this->sub->tagStore->find($tagname);

                    if( $tmp_tag == null )
                    {
                        $color = "color" . $thecolor;
                        #$tag_id = $projectdb->insert_id;
                        $tmp_tag = $this->sub->tagStore->createTag($tagname);
                        if( $print )
                            print"    Tag create: " . $tmp_tag->name() . "\n";
                        $tmp_tag->setColor($color);

                        if( $thecolor == 16 )
                            $thecolor = 1;
                        else
                            $thecolor++;
                    }


                    #$tmp_rule->tags->addTag($tmp_tag);
                }

            }
            if( preg_match("/crypto map /", $names_line) )
            {
                $split = explode(" ", $names_line);
                if( ($split[4] == "match") and ($split[5] == "address") )
                {
                    #$group = new SecurityGroup(trim($split[6]));
                    $group = array();
                    $group['position'] = 1;
                    $AccessGroups[trim($split[6])] = $group;


                    #Add Tag
                    $color = "color" . $thecolor;
                    $tagname = $this->truncate_tags(trim($split[6]));

                    $tagname = $this->truncate_tags($this->normalizeNames($tagname));
                    if( $tagname != "" )
                    {
                        $tmp_tag = $this->sub->tagStore->find($tagname);

                        if( $tmp_tag == null )
                        {
                            $color = "color" . $thecolor;
                            #$tag_id = $projectdb->insert_id;
                            $tmp_tag = $this->sub->tagStore->createTag($tagname);
                            $tmp_tag->setColor($color);

                            if( $thecolor == 16 )
                                $thecolor = 1;
                            else
                                $thecolor++;
                        }

                        if( $print )
                            print"    Tag add: " . $tmp_tag->name() . "\n";
                        #$tmp_rule->tags->addTag($tmp_tag);
                    }

                }
            }
        }

        /* @var $group SecurityGroup
         * @var $groupName string
         */

        foreach( $AccessGroups as $groupName => &$group )
        {
            #$tagObj = $this->sub->tagStore->find( $groupName );
            $tagObj = $this->sub->tagStore->findOrCreate($groupName);
            if( $tagObj != null )
                $group['setTag'] = $tagObj;
            else
            {
                mwarning("TAG: " . $groupName . " not found");
            }

        }


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

            if( $Protocol == "tcp" )
                $allTcp = $tmp_service;
            else
                $allUdp = $tmp_service;
        }


        $newRuleComment = '';
        #$checkFirepower = 0;
        #$isFirePower = 0;


        $service_source = "";
        $tmp_counter = 1;
        foreach( $this->data as $line => $names_line )
        {
            $skip_acl = FALSE;
            $IPv6 = FALSE;
            $names_line = trim($names_line);
            if( preg_match("/^access-list /i", $names_line) || preg_match("/^ipv6 access-list /i", $names_line) )
            {
//                echo "$names_line".PHP_EOL;

                if( preg_match("/^ipv6 access-list /i", $names_line) )
                {
                    $IPv6 = TRUE;
                    $names_line = str_replace("ipv6 access-list", "access-list", $names_line);
                }

                preg_match_all('/"(?:\\\\.|[^\\\\"])*"|\S+/', $names_line, $netObj);
                $netObj = $netObj[0];


                $tmp_rule = $this->sub->securityRules->find($netObj[1]);
                if( $tmp_rule != null )
                {
                    mwarning("rule: " . $netObj[1] . " available\n", null, FALSE);
                }


                if( isset($AccessGroups[$netObj[1]]) )
                {


                    #print "rulename: ".$AccessGroups[$netObj[1]]->name()."\n";

                    array_shift($netObj); //Remove the "access-list" string
                    $groupName = array_shift($netObj); //

                    $name = substr($groupName, 0, 30) . "_" . $AccessGroups[$groupName]['position'];

                    $tmp_rule = $this->sub->securityRules->find($name);
                    if( $tmp_rule == null )
                    {
                        if( $print )
                            print "\n* create securityRule: " . $name . "\n";

                        $tmp_rule = $this->sub->securityRules->newSecurityRule($name);
                        $tmp_protocol = "";
                        $service_source = "";
                        #$AccessGroups[$groupName]['position']++;

                        if( isset($AccessGroups[$groupName]['addZoneFrom']) )
                        {
                            $zone_name = $AccessGroups[$groupName]['addZoneFrom'];
                            $tmp_zone = $this->template_vsys->zoneStore->find($zone_name);
                            if( $tmp_zone == null )
                                $tmp_zone = $this->template_vsys->zoneStore->newZone($zone_name, 'layer3');

                            $tmp_rule->from->addZone($tmp_zone);
                        }

                        if( isset($AccessGroups[$groupName]['addZoneto']) )
                        {
                            $zone_name = $AccessGroups[$groupName]['addZoneto'];
                            $tmp_zone = $this->template_vsys->zoneStore->find($zone_name);
                            if( $tmp_zone == null )
                                $tmp_zone = $this->template_vsys->zoneStore->newZone($zone_name, 'layer3');

                            $tmp_rule->to->addZone($tmp_zone);
                        }

                    }

                    //COMMENTS
                    $remark = $netObj[0];
                    if( $remark == "remark" )
                    {
                        array_shift($netObj);
                        $newRuleComment .= addslashes(" " . implode(" ", $netObj));
                        $newRuleComment = $this->truncate_names($this->normalizeNames($newRuleComment));
                        continue;
                    }
                    else
                    {
                        //Todo: if remark then no rule
                        $AccessGroups[$groupName]['position']++;
                    }

                    //RULE NUMBER
                    $lineNumber = $netObj[0];
                    switch ($lineNumber)
                    {
                        case "line":
                            array_shift($netObj);
                            array_shift($netObj);
                            break;
                    }

                    $extended = $netObj[0];
                    switch ($extended)
                    {
                        case "advanced":
                            if( $this->checkFirePower == 0 )
                            {
                                $this->checkFirePower = 1;
                                $this->isFirePower = 1;
                                #$newRule->setIsFirepower(1);
                                /*
                                $tmp_tag = $this->sub->tagStore->findOrCreate("isFirepower");
                                if( $print )
                                    print "  * add Tag: isFirepower to rule: " . $tmp_rule->name();
                                $tmp_rule->tags->addTag($tmp_tag);
                                */
                            }
                            #array_shift($netObj);
                        case "standard":
                        case "extended":
                            array_shift($netObj);
                            $tmp_tag = $this->sub->tagStore->findOrCreate($groupName);
                            if( $print )
                                print "    * add Tag: " . $groupName . "\n";
                            $tmp_rule->tags->addTag($tmp_tag);
                            break;
                        case "ethertype":
                            $addlog = 'INFO - Reading Security Policies - The following ACL was not imported: "' . $names_line . '" - Level 2 rules are not supported - rules - security rules';
                            $skip_acl = TRUE;
                            break;
                    }

                    if( $skip_acl )
                    {
                        continue;
                    }


                    //ACTION
                    $action = $netObj[0];

                    //Todo: swaschkut 20210211 removed switch, as it did not work for deny
                    if( $action == 'permit' || $action == "trust" )
                    {
                        if( $print )
                            print "    * set action allow\n";
                        $tmp_rule->setAction("allow");
                        array_shift($netObj);
                    }
                    elseif( $action == 'deny' )
                    {
                        if( $print )
                            print "    * set action deny\n";
                        $tmp_rule->setAction("deny");
                        array_shift($netObj);
                    }

                    //continue;

                    //PROTOCOL
                    $protocolObject = array_shift($netObj); //
                    switch ($protocolObject)
                    {
                        case 'object-group':
                            $value = array_shift($netObj);
                            $value = $this->truncate_names($this->normalizeNames($value));
                            #mwarning(  "object-group value: ".$value."\n", null, false);
                            #continue;


                            $tmp_service = $this->sub->serviceStore->find($value);
                            if( !is_null($tmp_service) )
                            {
                                if( $print )
                                    print "    * add service: " . $tmp_service->name() . "\n";
                                $tmp_rule->services->add($tmp_service);
                                if( $value == "domain" )
                                    print "448\n";
                            }
                            break;

                        case 'object':
                            $value = array_shift($netObj);
                            $value = $this->truncate_names($this->normalizeNames($value));

                            $tmp_service = $this->sub->serviceStore->find($value);
                            if( $tmp_service === null )
                            {
                                $value = "tmp-" . $value;
                                $tmp_service = $this->sub->serviceStore->find($value);
                                if( $tmp_service === null )
                                {
                                    if( $print )
                                        print "    * create service: " . $value . "\n";
                                    $tmp_service = $this->sub->serviceStore->newService($value, "tcp", "6500");
                                }
                            }

                            if( $tmp_service !== null )
                            {
                                if( $print )
                                    print "    * add service: " . $tmp_service->name() . "\n";
                                $tmp_rule->services->add($tmp_service);
                            }
                            break;

                        case 'ip':
                            //Todo: swaschkut 20191011 how to fix protocol IP in general
                            $tmp_protocol = "ip";
                            #$tmp_protocol = "tcp";
                            #$newRule->setProtocol(["ip"]);
                            #$newRule->setService([$any]);
                            break;

                        case 'tcp':
                        case 'udp':
                            $tmp_protocol = $protocolObject;
                            break;

                        case 'icmp':

                            $app = 'icmp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'ah':
                            $app = 'ipsec-ah';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'icmp6':
                            $app = 'ipv6-icmp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case "gre":
                            $app = 'gre';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'esp';
                            $app = 'ipsec-esp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'igrp':
                            $app = 'igp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'ipinip':
                            $app = 'ip-in-ip';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'nos':
                            $app = 'ipip';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'pcp':
                            $app = 'ipcomp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'eigrp':
                            $app = 'eigrp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'igmp':
                            $app = 'igmp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'ipsec':
                            $app = 'ipsec';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'ospf':
                            $app = 'ospf';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'pim':
                            $app = 'pim';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'pptp':
                            $app = 'pptp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'sctp':
                            $app = 'sctp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case 'snp':
                            $app = 'snp';
                            $findAppObject = $this->sub->appStore->findOrCreate($app);
                            $tmp_rule->apps->addApp($findAppObject);
                            echo "   - added app '{$app}'\n";
                            break;

                        case (preg_match('/^[0-9]{1,3}$/', $protocolObject) ? true : false):
                            $findAppObject = $this->sub->appStore->get_app_by_ipprotocol( $protocolObject );
                            if( $findAppObject !== null )
                            {
                                $tmp_rule->apps->addApp($findAppObject);
                                echo "   - added app '{$findAppObject->name()}'\n";
                            }

                            break;

                        default:
                            //not implemented

                            break;
                    }


                    //OTHER FIELDS INCLUDING: Source, Destination, SourcePort, DestinationPort, User, Log
                    # Adding experimental support for FirePower
                    $rule_object_set = array();
                    while( count($netObj) > 0 )
                    {
                        $currentField = array_shift($netObj);

                        #print "currentfield: ".$currentField."\n";

                        if( $currentField != "webtype" && $currentField != "ethertype" )
                        {
                            #$newRule->setComment($newRuleComment);

                            if( $newRuleComment != "" )
                            {
                                if( $print )
                                    print "    * description: " . $newRuleComment . "\n";
                                $tmp_rule->setDescription($newRuleComment);
                                $newRuleComment = '';
                            }

                            switch ($currentField)
                            {

                                case "ifc":
                                    $value = array_shift($netObj);

                                    $tmp_zone = $this->template_vsys->zoneStore->find($value);

                                    if( !isset($rule_object_set['from']) )
                                    {
                                        print "    * FROM set to ".$value."\n";
                                        if( $tmp_zone !== null )
                                            $tmp_rule->from->addZone($tmp_zone);
                                        $rule_object_set['from'] = "set";
                                    }
                                    elseif( !isset($rule_object_set['to']) )
                                    {
                                        print "    * TO set to ".$value."\n";
                                        if( $tmp_zone !== null )
                                            $tmp_rule->to->addZone($tmp_zone);
                                        $rule_object_set['to'] = "set";
                                    }
                                    break;
                                case "rule-id":
                                    $value = array_shift($netObj);

                                    //todo add tag rule-id value:
                                    $tmp_tag = null;
                                    $tagname = "rule-id ".$value;
                                    $tmp_tag = $this->sub->tagStore->find($tagname);
                                    if( $tmp_tag == null )
                                    {
                                        $tmp_tag = $this->sub->tagStore->createTag($tagname);
                                        if( $print )
                                            print"    Tag create: " . $tmp_tag->name() . "\n";
                                    }
                                    if( $tmp_tag !== null )
                                        $tmp_rule->tags->addTag($tmp_tag);

                                    #mwarning('rule-id not implemented yet; value:' . $value, null, FALSE);

                                    #$newRule->setFirepowerId($value);
                                    break;
                                case "any":
                                case "any4":
                                case "any6":

                                    if( !isset($rule_object_set['source']) )
                                    {
                                        print "    * source set to ANY\n";
                                        $tmp_rule->source->setAny();
                                        $rule_object_set['source'] = "set";
                                    }
                                    elseif( !isset($rule_object_set['destination']) )
                                    {
                                        print "    * destination set to ANY\n";
                                        $tmp_rule->destination->setAny();
                                        $rule_object_set['destination'] = "set";
                                    }
                                    elseif( !isset($rule_object_set['service']) )
                                    {
                                        print "    * service set to ANY\n";
                                        $tmp_rule->services->setAny();
                                        $rule_object_set['service'] = "set";
                                    }
                                    break;

                                case "object":
                                    $value = array_shift($netObj);
                                    $value = CISCOASA::removeEnclosingQuotes($value);
                                    $value = $this->truncate_names($this->normalizeNames($value));
                                    #mwarning( "object found; value: ".$value , null, false);

                                    $ipversion = $this->ip_version($value);
                                    if( $ipversion == 'v4' )
                                    {
                                        $tmp_prefix = "H-";
                                        $netmask = "/32";
                                    }
                                    elseif( $ipversion == 'v6' )
                                    {
                                        $tmp_prefix = "H-";
                                        $netmask = "/128";
                                    }
                                    else
                                    {
                                        $tmp_prefix = "";
                                        $netmask = "";
                                        #mwarning( "no v4 or v6 ipversion found value:". $value );
                                    }

                                    $tmp_address = $this->sub->addressStore->find($tmp_prefix . $value);
                                    if( $tmp_address === null )
                                    {
                                        if( $print )
                                            print "     * create address object: " . $tmp_prefix . $value . " , value: " . $value . $netmask . "\n";
                                        $tmp_address = $this->sub->addressStore->newAddress($tmp_prefix . $value, 'ip-netmask', $value . $netmask);
                                    }


                                    if( !isset($rule_object_set['source']) )
                                    {
                                        if( $tmp_address !== null )
                                        {
                                            if( $print )
                                                print "    * add source - address object: " . $tmp_prefix . $value . " , value: " . $value . $netmask . "\n";
                                            $tmp_rule->source->addObject($tmp_address);
                                            $rule_object_set['source'] = "set";
                                        }
                                    }
                                    elseif( !isset($rule_object_set['destination']) )
                                    {
                                        if( $tmp_address !== null )
                                        {
                                            if( $print )
                                                print "    * add destination - address object: " . $tmp_prefix . $value . " , value: " . $value . $netmask . "\n";
                                            $tmp_rule->destination->addObject($tmp_address);
                                            $rule_object_set['destination'] = "set";
                                        }
                                    }
                                    else
                                    {
                                        mwarning("Problem 1959: object value in a wrong position? $names_line\n");
                                    }


                                    break;

                                case "object-group":
                                    $value = array_shift($netObj);
                                    $value = CISCOASA::removeEnclosingQuotes($value);
                                    $value = $this->truncate_names($this->normalizeNames($value));
                                    #mwarning( "object-group found; value: ".$value , null, false);


                                    #if( !in_array('source', $rule_object_set))
                                    if( !isset($rule_object_set['source']) )
                                    {

                                        $tmp_address = $this->sub->addressStore->find($value);
                                        if( $tmp_address === null )
                                        {
                                            mwarning("addressgroup: " . $value . " not found", null, FALSE);
                                        }
                                        if( $tmp_address !== null )
                                        {
                                            if( $print )
                                                print "    * add source - addressgroup object: " . $value . "\n";
                                            $tmp_rule->source->addObject($tmp_address);
                                            $rule_object_set['source'] = "set";
                                        }
                                    }
                                    #elseif( !in_array('destination', $rule_object_set))
                                    elseif( !isset($rule_object_set['destination']) )
                                    {
                                        $tmp_address = $this->sub->addressStore->find($value);
                                        if( $tmp_address === null )
                                        {

                                            $tmp_service = $this->sub->serviceStore->find($value);
                                            if( $tmp_service !== null )
                                            {
                                                print "addressgroup not found - now it is service source, but how to implement\n" . $names_line . "\n";
                                                print "which port information is needed?\n";
                                                foreach( $tmp_service->members() as $member )
                                                {
                                                    if( $member->isService() )
                                                        print "member: " . $member->name() . " - sourceport: |" . $member->getSourcePort() . "| dstport: |" . $member->getDestPort() . "|\n";
                                                    else
                                                    {
                                                        foreach( $tmp_service->members() as $member )
                                                        {
                                                            if( $member->isService() )
                                                                print "member: " . $member->name() . " - sourceport: |" . $member->getSourcePort() . "| dstport: |" . $member->getDestPort() . "|\n";
                                                            else
                                                            {
                                                                mwarning("this is not a solution fix it finaly");
                                                            }
                                                        }
                                                    }
                                                }

                                            }
                                            else
                                            {
                                                mwarning("servicegroup: " . $value . " not found", null, FALSE);
                                            }

                                        }
                                        if( $tmp_address !== null )
                                        {
                                            if( $print )
                                                print "    * add destination - addressgroup object: " . $value . "\n";
                                            $tmp_rule->destination->addObject($tmp_address);
                                            $rule_object_set['destination'] = "set";
                                        }
                                    }
                                    elseif( !isset($rule_object_set['service']) )
                                    {
                                        if( $value == "domain" )
                                            print "896\n";
                                        $tmp_service = $this->sub->serviceStore->find($value);
                                        if( $tmp_service === null )
                                        {
                                            mwarning("servicegroup: " . $value . " not found", null, FALSE);
                                        }
                                        if( $tmp_service !== null )
                                        {
                                            if( $print )
                                                print "    * add service - servicegroup object: " . $value . "\n";
                                            $tmp_rule->services->add($tmp_service);
                                            if( $value == "domain" )
                                                print "911\n";

                                            $rule_object_set['service'] = "set";
                                        }
                                    }
                                    else
                                    {
                                        mwarning("Problem 1960: object-group value in a wrong position? $names_line\n");
                                    }

                                    break;

                                case "host":
                                    $value = array_shift($netObj);
                                    $value = $this->truncate_names($this->normalizeNames($value));


                                    $ipversion = $this->ip_version($value);
                                    if( $ipversion == 'v4' )
                                    {
                                        $netmask = "32";
                                        $tmp_prefix = "H-";
                                    }
                                    elseif( $ipversion == 'v6' )
                                    {
                                        $netmask = "128";
                                        $tmp_prefix = "H-";
                                    }
                                    else
                                    {
                                        $tmp_prefix = "";
                                        $netmask = "";
                                        #mwarning( "no v4 or v6 ipversion found for host" );
                                    }

                                    $tmp_address = $this->sub->addressStore->find($tmp_prefix . $value);
                                    if( $tmp_address === null )
                                    {
                                        if( $tmp_prefix == "" && $netmask == "" )
                                            mwarning("something wrong with host object", null, FALSE);
                                        else
                                        {
                                            if( $print )
                                                print "    * create address object: H-" . $value . " , value: " . $value . "/" . $netmask . "\n";
                                            $tmp_address = $this->sub->addressStore->newAddress("H-" . $value, 'ip-netmask', $value . "/" . $netmask);
                                        }

                                    }

                                    if( !isset($rule_object_set['source']) )
                                    {

                                        if( $tmp_address !== null )
                                        {
                                            if( $print )
                                                print "    * add source - address object: H-" . $value . " , value: " . $value . "/" . $netmask . "\n";
                                            $tmp_rule->source->addObject($tmp_address);
                                            $rule_object_set['source'] = "set";
                                        }



                                    }
                                    elseif( !isset($rule_object_set['destination']) )
                                    {
                                        if( $tmp_address !== null )
                                        {
                                            if( $print )
                                                print "    * add destination - address object: H-" . $value . " , value: " . $value . "/" . $netmask . "\n";
                                            $tmp_rule->destination->addObject($tmp_address);
                                            $rule_object_set['destination'] = "set";
                                        }
                                    }
                                    else
                                    {
                                        echo "Problem 1959: Host value in a wrong position? $names_line\n";
                                    }

                                    break;

                                case "interface":
                                    $value = array_shift($netObj);
                                    $value = $this->truncate_names($this->normalizeNames($value));

                                    $tmp_zone = $this->template_vsys->zoneStore->find($value);

                                    if( !isset($rule_object_set['source']) )
                                    {
                                        if( $print )
                                            print "    * add source ANY and set from: " . $value . "\n";
                                        $tmp_rule->source->setAny();
                                        if( $tmp_zone !== null )
                                            $tmp_rule->from->addZone($tmp_zone);
                                        $rule_object_set['source'] = "set";
                                    }
                                    elseif( !isset($rule_object_set['destination']) )
                                    {
                                        if( $print )
                                            print "    * add destination ANY and set to: " . $value . "\n";
                                        $tmp_rule->destination->setAny();

                                        if( $tmp_zone !== null )
                                            $tmp_rule->to->addZone($tmp_zone);
                                        $rule_object_set['destination'] = "set";
                                    }
                                    break;
                                case "inactive":
                                    #$newRule->setDisabled();
                                    $tmp_rule->setDisabled(TRUE);
                                    break;

                                case "user-group":
                                case "user":
                                    $value = array_shift($netObj);
                                    $value = CISCOASA::removeEnclosingQuotes($value);
                                    $value = CISCOASA::removeDoubleBackSlash($value);
                                    $value = $this->truncate_names($this->normalizeNames($value));
                                    mwarning("user found: " . $value . "\n", null, FALSE);
                                    break;

                                case "object-group-user":
                                    $value = array_shift($netObj);
                                    $value = $this->truncate_names($this->normalizeNames($value));
                                    mwarning("user found: " . $value . "\n", null, FALSE);
                                    break;

                                // Cases for SERVICES
                                case "neq":
                                    #$missingFields = $newRule->getMissingFields();
                                    $value = array_shift($netObj);
                                    $value = $this->truncate_names($this->normalizeNames($value));
                                    #$object = $inMemoryObjects->getServiceNEQ($devicegroup, $source, $vsys, $value, $newRule->protocol);
                                    mwarning("neq found; value: " . $value, null, FALSE);
                                    break;

                                case "eq":
                                    #$missingFields = $newRule->getMissingFields();
                                    $value = array_shift($netObj);
                                    $value = $this->truncate_names($this->normalizeNames($value));



                                    if( !isset($rule_object_set['destination']) )
                                    {
                                        $value_name = $value;
                                        if( !is_numeric(  $value ) )
                                        {
                                            //search for correct port
                                            $tmp_service2 = $this->sub->serviceStore->find($value);

                                            if( $tmp_service2 == null || !$tmp_service2->isService() )
                                            {
                                                mwarning("eq found but service source must be set, value: " . $value." | only TCP set", null, FALSE);
                                                $tmp_service2 = $this->sub->serviceStore->find("tcp-".$value);
                                            }

                                            if( $tmp_service2 == null )
                                            {
                                                $tmp_service2 = $this->sub->serviceStore->find($value."_tcp");
                                            }

                                            #if( $tmp_service2 != null || $tmp_service2->isService() )
                                            if( $tmp_service2->isService() )
                                                $value = $tmp_service2->getDestPort();
                                        }


                                        $service_source = $tmp_protocol . "/" . $value;
                                        if( $tmp_protocol == "ip" )
                                        {
                                            //Todo: further tasks needed to migrate
                                            mwarning("protocol IP found but TCP is used: " . $service_source);
                                            $tmp_protocol = "tcp";
                                        }


                                            $value2 = "1-65535";

                                        $tmp_service = $this->sub->serviceStore->find($value2."src".$value_name);
                                        if( $tmp_service === null )
                                        {
                                            if( $tmp_protocol == "" || $tmp_protocol == "ip" )
                                            {
                                                //Todo: SVEN 20200203
                                                //if IP then create tcp and udp, plus a service group where both are in
                                                $tmp_protocol = "tcp";
                                            }


                                            $tmp_service = $this->sub->serviceStore->find($tmp_protocol . "-" . $value2."src".$value_name);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "     * create service: " . $tmp_protocol . "-" . $value2 ."src".$value . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($tmp_protocol . "-" . $value2."src".$value_name, $tmp_protocol, $value2, "", $value);
                                            }
                                        }




                                        if( $print )
                                            print "    * add service - service object: " . $tmp_service->name() . "\n";
                                        $tmp_rule->services->add($tmp_service);


                                        $rule_object_set['service'] = "set";


                                    }
                                    else
                                    {

                                        if( $service_source != "" )
                                            mwarning("service source need to be set: " . $service_source);


                                        $tmp_service = $this->sub->serviceStore->find($value);
                                        if( $tmp_service === null )
                                            $tmp_service = $this->sub->serviceStore->find("tmp-".$value);

                                        if( $tmp_service === null )
                                        {
                                            if( $tmp_protocol == "" || $tmp_protocol == "ip" )
                                            {
                                                //Todo: SVEN 20200203
                                                //if IP then create tcp and udp, plus a service group where both are in
                                                $tmp_protocol = "tcp";
                                            }


                                            $tmp_service = $this->sub->serviceStore->find($tmp_protocol . "-" . $value);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "     * create service: " . $tmp_protocol . "-" . $value . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($tmp_protocol . "-" . $value, $tmp_protocol, $value);
                                            }
                                        }
                                        if( $tmp_service !== null )
                                        {
                                            if( $tmp_service->isGroup() )
                                                $tmp_service = $this->sub->serviceStore->find($value."_".$tmp_protocol);

                                            if( !$tmp_service->isGroup() && $tmp_protocol != "" && $tmp_service->protocol() != $tmp_protocol )
                                            {
                                                if( !is_numeric($value) )
                                                {
                                                    $tmp_service2 = $this->sub->serviceStore->find($value);
                                                    if( $tmp_service2 !== null )
                                                    {
                                                        $value = $tmp_service2->getDestPort();
                                                    }
                                                }
                                                $tmp_service = $this->sub->serviceStore->find($tmp_protocol . "-" . $value);
                                                #mwarning( "servicgroup found and protocol is: ".$tmp_protocol );
                                                if( $tmp_service === null )
                                                {
                                                    if( $print )
                                                        print "     * create service: " . $tmp_protocol . "-" . $value . "\n";
                                                    $tmp_service = $this->sub->serviceStore->newService($tmp_protocol . "-" . $value, $tmp_protocol, $value);
                                                }
                                            }
                                            if( $print )
                                                print "    * add service - service object: " . $tmp_service->name() . "\n";
                                            $tmp_rule->services->add($tmp_service);
                                            if( $value == "domain" )
                                                print "1254\n";

                                            $rule_object_set['service'] = "set";
                                        }
                                    }

                                    break;

                                case "lt":
                                    #$missingFields = $newRule->getMissingFields();
                                    $value = array_shift($netObj);
                                    $value = $this->truncate_names($this->normalizeNames($value));

                                    mwarning("lt found; value: " . $value, null, FALSE);

                                    if( !isset($rule_object_set['destination']) )
                                    {
                                        print "2WARNING sven\n";
                                        print "LINE: " . $names_line . "\n";

                                        mwarning("service source must be set");

                                    }
                                    elseif( !isset($rule_object_set['service']) )
                                    {
                                        //$tmp_protocol
                                        if( $tmp_protocol == "ip" )
                                        {
                                            //Todo: further tasks needed to migrate
                                            $tmp_protocol = "tcp";
                                        }

                                        $port = "1-" . (intval($value) - 1);
                                        if( $tmp_protocol != "" )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($tmp_protocol . "-" . $port);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "   * create service " . $tmp_protocol . "-" . $port . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($tmp_protocol . "-" . $port, $tmp_protocol, $port);
                                            }
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . "\n";
                                            $tmp_rule->services->add($tmp_service);
                                            if( $value == "domain" )
                                                print "1309\n";
                                        }
                                    }
                                    break;

                                case "gt":
                                    #$missingFields = $newRule->getMissingFields();
                                    $value = array_shift($netObj);
                                    $value = $this->truncate_names($this->normalizeNames($value));


                                    if( !isset($rule_object_set['destination']) )
                                    {
                                        print "3WARNING sven\n";
                                        print "LINE: " . $names_line . "\n";

                                        mwarning("service source must be set");

                                    }
                                    elseif( !isset($rule_object_set['service']) )
                                    {
                                        //$tmp_protocol
                                        if( $tmp_protocol == "ip" )
                                        {
                                            //Todo: further tasks needed to migrate
                                            $tmp_protocol = "tcp";
                                        }


                                        $port = (intval($value) + 1) . "-65535";
                                        if( $tmp_protocol != "" )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($tmp_protocol . "-" . $port);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "   * create service " . $tmp_protocol . "-" . $port . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($tmp_protocol . "-" . $port, $tmp_protocol, $port);
                                            }
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . "\n";
                                            $tmp_rule->services->add($tmp_service);
                                            if( $value == "domain" )
                                                print "1360\n";
                                        }
                                    }


                                    break;

                                case "range":
                                    #$missingFields = $newRule->getMissingFields();
                                    $valueStart = array_shift($netObj);
                                    $valueEnd = array_shift($netObj);


                                    if( !is_numeric($valueStart) )
                                    {
                                        $tmp_service = $this->sub->serviceStore->find($valueStart);
                                        if( $tmp_service !== null and !$tmp_service->isGroup())
                                        {
                                            if( $tmp_service->isGroup() )
                                            {
                                                $tmp_service_members = $tmp_service->members();
                                                $tmp_service = $tmp_service_members[0];
                                            }

                                            $valueStart = $tmp_service->getDestPort();
                                        }
                                        else
                                        {
                                            mwarning( $valueEnd . " service not available" );
                                        }
                                    }
                                    if( !is_numeric($valueEnd) )
                                    {
                                        $tmp_service = $this->sub->serviceStore->find($valueEnd);
                                        if( $tmp_service !== null  )
                                        {
                                            if( $tmp_service->isGroup() )
                                            {
                                                $tmp_service_members = $tmp_service->members();
                                                $tmp_service = $tmp_service_members[0];
                                            }
                                            $valueEnd = $tmp_service->getDestPort();
                                        }
                                        else
                                        {
                                            mwarning( $valueEnd . " service not available" );
                                        }

                                    }

                                    //Todo if $valuestart or $valueEnd nnot numeric =>


                                    $value = $valueStart . "-" . $valueEnd;
                                    $value = $this->truncate_names($this->normalizeNames($value));
                                    #$object = $inMemoryObjects->getServiceRangeReference($devicegroup, $source, $vsys, $valueStart, $valueEnd, $newRule->protocol);


                                    if( !isset($rule_object_set['destination']) )
                                    {
                                        mwarning("service source: range found; value: " . $value, null, FALSE);
                                        print "service source must be set now\n";
                                        if( $tmp_protocol == "ip" )
                                        {
                                            //Todo: further tasks needed to migrate
                                            $tmp_protocol = "tcp";
                                        }
                                        $service_source = $tmp_protocol . "/" . $value;
                                    }
                                    elseif( !isset($rule_object_set['service']) )
                                    {
                                        if( $service_source != "" )
                                            mwarning("service source need to be set: " . $service_source);

                                        if( $tmp_protocol == "ip" )
                                        {
                                            //Todo: further tasks needed to migrate
                                            $tmp_protocol = "tcp";
                                        }


                                        if( $tmp_protocol != "" )
                                        {
                                            $tmp_service = $this->sub->serviceStore->find($tmp_protocol . "-" . $value);
                                            if( $tmp_service === null )
                                            {
                                                if( $print )
                                                    print "   * create service " . $tmp_protocol . "-" . $value . "\n";
                                                $tmp_service = $this->sub->serviceStore->newService($tmp_protocol . "-" . $value, $tmp_protocol, $value);
                                            }
                                            if( $print )
                                                print "   * add service: " . $tmp_service->name() . "\n";
                                            $tmp_rule->services->add($tmp_service);
                                            if( $value == "domain" )
                                                print "1414\n";
                                        }
                                        else
                                        {
                                            #print "LINE: ".$names_line."\n";
                                            #mwarning( "could be object-group TCPUDP - but where to find?" );

                                            $tmp_service_group = $this->sub->serviceStore->find("TCPUDP-" . $value);
                                            if( $tmp_service_group === null )
                                            {
                                                //create service group
                                                if( $print )
                                                    print "   * create servicegroup: 'TCPUDP-" . $value . "'\n";
                                                $tmp_service_group = $this->sub->serviceStore->newServiceGroup("TCPUDP-" . $value);

                                                $tmp_service = $this->sub->serviceStore->find("tcp-" . $value);
                                                if( $tmp_service == null )
                                                {
                                                    $tmp_service = $this->sub->serviceStore->find("tmp-" . $value);
                                                    if( $tmp_service == null )
                                                    {
                                                        if( $print )
                                                            print "   * create service: 'tcp-" . $value . "'\n";
                                                        $tmp_service = $this->sub->serviceStore->newService('tcp-' . $value, 'tcp', $value);
                                                    }
                                                }
                                                if( $tmp_service !== null )
                                                {
                                                    if( $print )
                                                        print "   * add tcp service: " . $tmp_service->name() . "'\n";
                                                    $tmp_service_group->addMember($tmp_service);
                                                }

                                                $tmp_service = $this->sub->serviceStore->find("udp-" . $value);
                                                if( $tmp_service == null )
                                                {
                                                    if( $print )
                                                        print "   * create service: 'udp-" . $value . "'\n";
                                                    $tmp_service = $this->sub->serviceStore->newService('udp-' . $value, 'udp', $value);
                                                }
                                                if( $tmp_service !== null )
                                                {
                                                    if( $print )
                                                        print "   * add udp service: " . $tmp_service->name() . "'\n";
                                                    $tmp_service_group->addMember($tmp_service);
                                                }
                                            }
                                            if( $tmp_service_group !== null )
                                            {
                                                if( $print )
                                                    print "   * add service: " . $tmp_service_group->name() . "\n";
                                                $tmp_rule->services->add($tmp_service_group);
                                                if( $value == "domain" )
                                                    print "1462\n";
                                            }
                                        }


                                    }

                                    break;


                                case "echo":
                                case "echo-reply":

                                    $app = 'ping';
                                    $findAppObject = $this->sub->appStore->findOrCreate($app);
                                    $tmp_rule->apps->addApp($findAppObject);
                                    echo "   - app add: '{$app}'\n";
                                    #mwarning( "echo / echo-reply found; value: " , null, false);
                                    break;
                                case "source-quench":
                                    //This is a type of icmp
                                    break;

                                case "traceroute":
                                    /*
                                    if(in_array('icmp',$newRule->protocol)){
                                        $object = $inMemoryObjects->getDefaultApplication('traceroute');
                                        if(!is_null($object)) {
                                            $newRule->addApplication($object);
                                        }
                                    }
                                    */
                                    $app = 'icmp';
                                    $findAppObject = $this->sub->appStore->findOrCreate($app);
                                    $tmp_rule->apps->addApp($findAppObject);
                                    echo "   - app add: '{$app}'\n";
                                    $app = 'ping';
                                    $findAppObject = $this->sub->appStore->findOrCreate($app);
                                    $tmp_rule->apps->addApp($findAppObject);
                                    echo "   - app add: '{$app}'\n";
                                    $app = 'traceroute';
                                    $findAppObject = $this->sub->appStore->findOrCreate($app);
                                    $tmp_rule->apps->addApp($findAppObject);
                                    echo "   - app add: '{$app}'\n";
                                    #mwarning( "traceroute found; value: " , null, false);
                                    break;

                                case "unreachable":

                                    mwarning("unreachable found; value: ", null, FALSE);
                                    break;

                                case "log":
                                case "disable":
                                case "warnings":
                                case "default":
                                case "debugging":
                                case "time-exceeded":
                                case "notifications":
                                case "critical":
                                case "event-log":
                                case "flow-start":
//                            case "unreachable":
                                    $not_needed = array_shift($netObj);
                                    break;

                                case "interval":
                                    $interval = array_shift($netObj);
                                    break;

                                case "time-range":
                                    $starting_date = array_shift($netObj);

                                    print "time-range: ".$starting_date."\n";

                                    $TimeRangeName = rtrim($starting_date);
                                    $TimeRangeNamePan = $this->truncate_names($this->normalizeNames($TimeRangeName));

                                    $tmp_schedule = $this->sub->scheduleStore->find( $TimeRangeNamePan );
                                    if( $tmp_schedule !== null )
                                    {
                                        print "  - set schedule: ".$tmp_schedule->name()."\n";
                                        $tmp_rule->setSchedule($tmp_schedule->name());
                                    }
                                    else
                                    {
                                        $addlog = "time-range field with value ['.$starting_date.'] is used. This field has not been migrated. Check whether this security rule needs to be activated: " . $names_line;
                                        $tmp_rule->set_node_attribute('warning', $addlog);
                                    }


                                    //Todo: swaschkut 20191011
                                    //set rule to disable because of time-range found?
                                    //$tmp_rule->setDisabled( true );

                                    /*
                                    $newRule->addLog('warning',
                                        'Reading Security Policies',
                                        'Security RuleID [_RuleLid_] is using a time-range field with value ['.$starting_date.']. This field has not been migrated',
                                        'Check whether this security rule needs to be activated');
                                    */
                                    break;

                                /*
                                 *                          //Todo: SWASCHKUT implementation needed for:
                                 * example:                 access-list DMZ_NAME_access_in extended permit tcp 1.2.11.0 255.255.255.0 object-group DM_INLINE_NETWORK_588 eq 2345
                                 */

                                default:
                                    //Check if it is an IP netmask
                                    print "CURRENT-FIELD: '".$currentField."'\n";
                                    $currentIP = explode("/", $currentField);
                                    if( isset($currentIP[1]) )
                                        $ipv6Mask = $currentIP[1];

                                    $versionCheck = $this->ip_version($currentIP[0]);

                                    print "IPversion: " . $versionCheck . " for: " . $currentIP[0] . "\n";

                                    if( $versionCheck == "v4" )
                                    {
                                        $nextField = isset($netObj[0]) ? $netObj[0] : '';


                                        $cidr = CIDR::netmask2cidr($nextField);
                                        //$cidr = $this->mask2cidrv4($nextField);


                                        if( $cidr == "32" )
                                        {
                                            $NameComplete = "H-$currentField";
                                        }
                                        else
                                        {
                                            $NameComplete = "N-$currentField-$cidr";
                                        }

                                        $tmp_address = $this->sub->addressStore->find($NameComplete);
                                        if( $tmp_address === null )
                                        {
                                            if( $print )
                                                print "  * create address object: " . $NameComplete . " | value: " . $currentField . ", CIDR: " . $cidr . "\n";
                                            $tmp_address = $this->sub->addressStore->newAddress($NameComplete, 'ip-netmask', $currentField . "/" . $cidr);
                                        }

                                        array_shift($netObj);
                                    }
                                    elseif( $versionCheck == "v6" )
                                    {

                                        $value = $currentField;
                                        $name = str_replace(":", "_", $value);
                                        $name = str_replace("/", "m", $name);
                                        $tmp_address = $this->sub->addressStore->find($name);
                                        if( $tmp_address === null )
                                        {
                                            if( $print )
                                                print "     * create address object: " . $name . " , value: " . $value . "\n";
                                            $tmp_address = $this->sub->addressStore->newAddress($name, 'ip-netmask', $value);
                                        }

                                        #array_shift($netObj);
                                    }
                                    else
                                    {
                                        //Check if it is a known label
                                        $nextField = isset($netObj[0]) ? $netObj[0] : '';
                                        $cidr = $this->convertWildcards($nextField, 'cidr');
                                        if( $cidr == FALSE )
                                        {
                                            if( $this->checkNetmask($nextField) )
                                            {
                                                $cidr = $this->mask2cidrv4($nextField);
                                                array_shift($netObj);
                                            }
                                        }
                                        #mwarning( "1nov4 / nov6 which IPversion not implemented for default case: ".$currentField."|".$cidr, null, false );

                                        $tmp_prefix = "";
                                        $value = $currentField;
                                        $netmask = $cidr;


                                        $tmp_name = $tmp_prefix . $value . "_" . $netmask;
                                        $tmp_address = $this->sub->addressStore->find($value);
                                        if( $tmp_address === null )
                                        {
                                            if( $print )
                                                print "     * create address object: " . $tmp_name . " , value: " . $value . "/" . $netmask . "\n";
                                            $tmp_address = $this->sub->addressStore->newAddress($tmp_prefix . $value, 'ip-netmask', $value . "/" . $netmask);
                                        }
                                        else
                                        {
                                            //check if netmask is 0
                                            if( $tmp_address->isAddress() && $tmp_address->getNetworkMask() == 32 )
                                            {
                                                if( $netmask !== null )
                                                {
                                                    $value = $value . "/" . $netmask;
                                                    $tmp_prefix = "";
                                                }

                                                $tmp_value = $tmp_address->value();
                                                $tmp_value1 = explode("/", $tmp_value);
                                                $tmp_value = $tmp_value1[0];

                                                $tmp_name = $tmp_address->name() . "_" . $netmask;
                                                $tmp_address = $this->sub->addressStore->find($tmp_name);
                                                if( $tmp_address === null )
                                                {
                                                    if( $print )
                                                        print "  * create address object: " . $tmp_name . " change value to: " . $tmp_value . "/" . $netmask . "\n";
                                                    $value = $tmp_value;
                                                    $tmp_address = $this->sub->addressStore->newAddress($tmp_name, 'ip-netmask', $tmp_value . "/" . $netmask);
                                                }
                                            }
                                        }
                                    }

                                    if( $tmp_address !== null )
                                    {
                                        if( !isset($rule_object_set['source']) )
                                        {
                                            if( $tmp_address !== null )
                                            {
                                                if( $print )
                                                    print "    * add source - address object: " . $tmp_address->name() . " , value: " . $tmp_address->value() . "\n";
                                                $tmp_rule->source->addObject($tmp_address);
                                                $rule_object_set['source'] = "set";


                                            }
                                        }
                                        elseif( !isset($rule_object_set['destination']) )
                                        {
                                            if( $tmp_address !== null )
                                            {
                                                if( $print )
                                                {
                                                    if( $tmp_address->isAddress() )
                                                        print "    * add destination - address object: " . $tmp_address->name() . " , value: " . $tmp_address->value() . "\n";
                                                    else
                                                        print "    * add destination - address object: " . $tmp_address->name() . "\n";

                                                }

                                                $tmp_rule->destination->addObject($tmp_address);
                                                $rule_object_set['destination'] = "set";
                                            }
                                        }
                                        else
                                        {
                                            if( $currentField != 'event-log' && $currentField != 'flow-start' )
                                                mwarning("Problem 2115: Field '" . $currentField . "' not recognized in [" . $names_line . "]", null, FALSE);
                                        }
                                    }
                                    else
                                    {
                                        mwarning("no address object found!");
                                    }

                                    break;
                            }
                        }
                    }


                    if( $tmp_rule->services->isAny() )
                    {
                        if( $tmp_protocol == "ip" )
                        {
                            print "    * service set to ALL-TCP ports\n";
                            $tmp_rule->services->add($allTcp);
                            print "    * service set to ALL-UDP ports\n";
                            $tmp_rule->services->add($allUdp);
                        }
                        else
                        {
                            if( $tmp_protocol == "tcp" )
                            {
                                print "    * service set to ALL-TCP ports\n";
                                $tmp_rule->services->add($allTcp);
                            }
                            elseif( $tmp_protocol == "udp" )
                            {
                                print "    * service set to ALL-UDP ports\n";
                                $tmp_rule->services->add($allUdp);
                            }
                            else
                            {
                                print "protocol is: |" . $tmp_protocol . "|\n";
                            }
                        }

                    }

                    //Todo: Sven Waschkut 20200203
                    continue;

                    //In case a Security Rule belongs to an Access Group that was not found (not declared), create the group here
                    if( !isset($AccessGroups[$groupName]) )
                    {
                        $AccessGroups[$groupName] = new SecurityGroup($groupName, FALSE);
                    }

                    //Final check before adding this Rule into the Group (memory space still)
                    if( $newRule->isValid() )
                    {
                        //Complementing the rule with information coming from the Access Group it belongs to
                        $from = $AccessGroups[$groupName]->getZoneFrom();
                        $to = $AccessGroups[$groupName]->getZoneTo();
                        if( count($from) > 0 )
                        {
                            $newRule->setZoneFrom($from);
                        }
                        if( count($to) > 0 )
                        {
                            $newRule->setZoneTo($to);
                        }

                        $newRule->addTag($AccessGroups[$groupName]->getTag());

                        if( in_array('icmp', $newRule->protocol) && $newRule->application == null )
                        {
                            $object = $inMemoryObjects->getDefaultApplication('icmp');
                            if( !is_null($object) )
                            {
                                $newRule->addApplication($object);
                            }
                        }

                        if( in_array('sctp', $newRule->protocol) && $newRule->application == null )
                        {
                            $object = $inMemoryObjects->getDefaultApplication('sctp');
                            if( !is_null($object) )
                            {
                                $newRule->addApplication($object);
                            }
                        }

                        //Adding AllPorts for security rules with TCP and UDP protocols that do not specify a port
                        if( !isset($newRule->service) )
                        {
                            if( isset($newRule->protocol['ip']) )
                            {
                                $newRule->setService(array_merge($allTcp, $allUdp));
                            }
                            else
                            {
                                if( isset($newRule->protocol['tcp']) )
                                {
                                    $newRule->addService($allTcp[0]);
                                }
                                if( isset($newRule->protocol['udp']) )
                                {
                                    $newRule->addService($allUdp[0]);
                                }
                            }
                        }

                        //Check if the rule needs to be split into Two due to Services that should be transformed into Apps
                        $tcpudpProtocols = array();     //TCP and UDP protocols
                        $networkProtocols = $newRule->protocol;  //Other protocols
                        //echo "-----------------\n";
                        //echo "Newrules->service: \n";
                        //print_r($newRule->service);
                        //echo "Newrules->protocol: \n";
                        //print_r($newRule->protocol);

                        if( isset($networkProtocols['tcp']) )
                        {
                            $tcpudpProtocols[] = 'tcp';
                            unset($networkProtocols['tcp']);
                        }
                        if( isset($networkProtocols['udp']) )
                        {
                            $tcpudpProtocols[] = 'udp';
                            unset($networkProtocols['udp']);
                        }
                        if( isset($networkProtocols['ip']) )
                        {
                            $tcpudpProtocols[] = 'tcp';
                            $tcpudpProtocols[] = 'udp';
                            unset($networkProtocols['ip']);
                        }

                        //If we have network protocols and TCP/UDP protocols, we need to split the rule
                        //print_r($networkProtocols);
                        //print_r($tcpudpProtocols);

                        if( count($networkProtocols) > 0 && count($tcpudpProtocols) > 0 )
                        {
                            $networkProtocolRule = clone $newRule;

                            //Preparing and adding the TCP/UDP rule
                            $newRule->setApplications(array());
                            $newRule->setProtocol($tcpudpProtocols);


                            //Check that the services are from the Protocol that has been specified
                            //Initially the Service may have both UDP and TCP ports
                            //It only one of the two protocols is in this service, then we need to find out which ports we should keep
                            if( count($tcpudpProtocols) == 1 )
                            {
                                $protocol = array_pop($tcpudpProtocols);
                                $services = $newRule->service;

                                $explodedServices = explodeGroups2Services($services, $projectdb, $source, $vsys);
                                $validServices = array();
                                /* @var $service MemberObject */
                                foreach( $explodedServices as $service )
                                {

                                    //echo "Service cidr: " .$service->cidr. "\n";
                                    //echo "Protocol: " .$protocol. "\n";
                                    //print_r($service);
                                    if( $service->cidr == $protocol )
                                    {
                                        $validServices[] = $service;
                                    }
                                }
                                if( count($validServices) == count($explodedServices) )
                                {
                                    $newRule->setService($services);
                                }
                                else
                                {
                                    $newRule->setService($validServices);
                                }
                            }

                            //Verify if the source port has been defined
                            if( count($newRule->sourcePort) > 0 && $newRule->sourcePort[0]->name != 'any' )
                            {
                                $sourcePorts = array();
                                /* @var $sourcePort MemberObject */
                                foreach( $newRule->sourcePort as $sourcePort )
                                {
                                    $sourcePorts[] = $sourcePort->cidr . "/" . $sourcePort->value;
                                }
                                $newRule->addLog(
                                    'warning',
                                    'Reading Security Policies',
                                    'This rule had the following source ports:' . implode(', ', $sourcePorts),
                                    'Recommended to identify involved Applications and verify they are included in the rule');
                            }

                            $AccessGroups[$groupName]->addRule($newRule);

                            //Preparing and adding the NetworkProtocol rule
                            $networkProtocolRule->setProtocol($networkProtocols);
                            $networkProtocolRule->setService(array($any));
                            $AccessGroups[$groupName]->addRule($networkProtocolRule);
                        }
                        elseif( count($networkProtocols) > 0 )
                        { //Preparing and adding the NetworkProtocol rule
                            $newRule->setProtocol($networkProtocols);
                            $newRule->setService(array($any));
                            $AccessGroups[$groupName]->addRule($newRule);
                        }
                        else
                        { //Preparing and Adding the TPC/UDP Rule to the Group
                            $newRule->setApplications(array());
                            if( count($tcpudpProtocols) == 1 )
                            {
                                $protocol = array_pop($tcpudpProtocols);
                                $services = $newRule->service;
                                $explodedServices = $inMemoryObjects->explodeGroup2Services($services, $source, $vsys);
                                $validServices = array();
                                /* @var $service MemberObject */
                                foreach( $explodedServices as $service )
                                {
                                    if( $service->cidr == $protocol )
                                    {
                                        $validServices[] = $service;
                                    }
                                }
                                if( count($validServices) == count($explodedServices) )
                                {
                                    $newRule->setService($services);
                                }
                                else
                                {
                                    $newRule->setService($validServices);
                                }
                            }

                            //Verify if the source port has been defined
                            if( count($newRule->sourcePort) > 0 && $newRule->sourcePort[0]->name != 'any' )
                            {
                                $sourcePorts = array();
                                /* @var $sourcePort MemberObject */
                                foreach( $newRule->sourcePort as $sourcePort )
                                {
                                    $sourcePorts[] = $sourcePort->cidr . "/" . $sourcePort->value;
                                }
                                $newRule->addLog(
                                    'warning',
                                    'Reading Security Policies',
                                    'This rule had the following source ports: ' . implode(', ', $sourcePorts),
                                    'Recommended to identify involved Applications and verify they are included in the rule');
                            }

                            $AccessGroups[$groupName]->addRule($newRule);
                        }
                    }
                }
            }
        }


        //Todo: swaschkut 20191010 reorganisation of the sec rules:
        // get last entry of access-groups and move all sec rules with tag from access-group to top,
        //continue with the next "last" access-group

        //Todo: Sven Waschkut remove it
        $empty_array = array();
        return $empty_array;

//    print_r($AccessGroups);

        //Move the global access-group to the last entry
        // We have defined 'global' as the first element at the beginning of the function

        $globalGroup = array_shift($AccessGroups);
        $AccessGroups['global'] = $globalGroup;

        // Calculate the rule IDs
        $query = "SELECT max(id) as max FROM security_rules";
        $result = $projectdb->query($query);
        if( $result->num_rows > 0 )
        {
            $this->data = $result->fetch_assoc();
            $initiGlobalPosition = is_null($this->data['max']) ? 0 : $this->data['max'];
        }
        else
        {
            $initiGlobalPosition = 0;
        }

        /* @var $accessGroup SecurityGroup */
        foreach( $AccessGroups as $key => $accessGroup )
        {
            if( $accessGroup->getUsed() == TRUE )
            {
                $AccessGroups[$key]->setInitialID($initiGlobalPosition);
                $initiGlobalPosition += $accessGroup->getLastRulePosition();
            }
        }

        //Insert new Addresses and Services
        $inMemoryObjects->insertNewAddresses($projectdb);
        $inMemoryObjects->insertNewServices($projectdb);

        //        $inMemoryObjects->removeUnusedLabels($projectdb, $source, $vsys);

        removeUnusedLabels($projectdb, $source, $vsys);

        //Generate Security Rules
        $sec_rules = array();
        $sec_rules_srv = array();
        $sec_rules_src = array();
        $sec_rules_dst = array();
        $sec_rules_from = array();
        $sec_rules_to = array();
        $sec_rules_usr = array();
        $sec_rules_tags = array();
        $sec_rules_app = array();


        //print_r($AccessGroups);

        /* @var $accessGroup SecurityGroup
         * @var $rule SecurityRuleCisco
         * @var $srv MemberObject
         * @var $src MemberObject
         * @var $dst MemberObject
         * @var $from String
         * @var $to String
         * @var $user String
         * @var $app MemberObject
         */
        $firePowerTrack = array();

        foreach( $AccessGroups as $key => $accessGroup )
        {
            if( $accessGroup->getUsed() )
            {
                foreach( $accessGroup->getRules() as $rule )
                {
                    //( source, vsys, rule_lid, table_name, member_lid)
//                    print_r($rule);

                    if( $this->isFirePower == 1 )
                    {
                        $firePowerId = $rule->getFirepowerId();
                        if( !isset($firePowerTrack[$firePowerId]) )
                        {
                            $firePowerTrack[$firePowerId] = $firePowerId;
                            $rule_lid = $rule->globalPosition;
                            // (id, position, name, name_ext, description, action, disabled, vsys, source)
                            $sec_rules[] = "('$rule->globalPosition', '$rule->globalPosition', '$rule->name','$rule->name', '$rule->comment','$rule->action', $rule->disabled, '$vsys', '$source')";
                        }
                        if( isset($rule->service) )
                        {
                            foreach( $rule->service as $srv )
                            {
                                if( $srv->location != 'any' )
                                {
                                    $sec_rules_srv[] = "('$source', '$vsys','$rule_lid','$srv->location','$srv->name')";
                                }
                            }
                        }

                        //( source, vsys, rule_lid, table_name, member_lid)
                        $src = $rule->source;
                        if( $src->location != 'any' )
                        {
                            $sec_rules_src[] = "('$source', '$vsys','$rule_lid','$src->location','$src->name')";
                        }

                        //( source, vsys, rule_lid, table_name, member_lid)
                        $dst = $rule->destination;
                        if( $dst->location != 'any' )
                        {
                            $sec_rules_dst[] = "('$source', '$vsys','$rule_lid','$dst->location','$dst->name')";
                        }

                        //(source, vsys, rule_lid, name)
                        if( isset($rule->zoneFrom) )
                        {
                            foreach( $rule->zoneFrom as $from )
                            {
                                $sec_rules_from[] = "('$source', '$vsys','$rule_lid','$from')";
                            }
                        }

                        //(source, vsys, rule_lid, name)
                        if( isset($rule->zoneTo) )
                        {
                            foreach( $rule->zoneTo as $to )
                            {
                                $sec_rules_to[] = "('$source', '$vsys','$rule_lid','$to')";
                            }
                        }

                        //(source, vsys, rule_lid, name)
                        if( isset($rule->user) )
                        {
                            foreach( $rule->user as $user )
                            {
                                $sec_rules_usr[] = "('$source', '$vsys','$rule_lid','$user')";
                            }
                        }

                        //(source, vsys, rule_lid, table_name, member_lid)
                        if( isset($rule->application) )
                        {
                            foreach( $rule->application as $app )
                            {
                                $sec_rules_app[] = "('$source', '$vsys','$rule_lid','$app->location','$app->name')";
                            }
                        }

                        //(source, vsys, member_lid, rule_lid, table_name, member_lid)
                        if( isset($rule->tag) )
                        {
                            foreach( $rule->tag as $tag )
                            {
                                $sec_rules_tags[] = "('$source', '$vsys','$rule_lid','$tag->location','$tag->name')";
                            }
                        }

                        //Adding all the warning messages
                        if( isset($rule->logs) )
                        {
                            foreach( $rule->logs as $log )
                            {
                                //Replace _RuleLid_ by its Rulelid
                                $log['message'] = str_replace('_RuleLid_', $rule_lid, $log['message']);
                                add_log2($log['logType'], $log['task'], $log['message'], $source, $log['action'], 'rules', $rule_lid, 'security_rules');
                            }
                        }


                    }
                    else
                    {
                        $rule_lid = $rule->globalPosition;
                        // (id, position, name, name_ext, description, action, disabled, vsys, source)
                        $sec_rules[] = "('$rule->globalPosition', '$rule->globalPosition', '$rule->name','$rule->name', '$rule->comment','$rule->action', $rule->disabled, '$vsys', '$source')";

                        if( isset($rule->service) )
                        {
                            foreach( $rule->service as $srv )
                            {
                                if( $srv->location != 'any' )
                                {
                                    $sec_rules_srv[] = "('$source', '$vsys','$rule_lid','$srv->location','$srv->name')";
                                }
                            }
                        }

                        //( source, vsys, rule_lid, table_name, member_lid)
                        $src = $rule->source;
                        if( $src->location != 'any' )
                        {
                            $sec_rules_src[] = "('$source', '$vsys','$rule_lid','$src->location','$src->name')";
                        }

                        //( source, vsys, rule_lid, table_name, member_lid)
                        $dst = $rule->destination;
                        if( $dst->location != 'any' )
                        {
                            $sec_rules_dst[] = "('$source', '$vsys','$rule_lid','$dst->location','$dst->name')";
                        }

                        //(source, vsys, rule_lid, name)
                        if( isset($rule->zoneFrom) )
                        {
                            foreach( $rule->zoneFrom as $from )
                            {
                                $sec_rules_from[] = "('$source', '$vsys','$rule_lid','$from')";
                            }
                        }

                        //(source, vsys, rule_lid, name)
                        if( isset($rule->zoneTo) )
                        {
                            foreach( $rule->zoneTo as $to )
                            {
                                $sec_rules_to[] = "('$source', '$vsys','$rule_lid','$to')";
                            }
                        }

                        //(source, vsys, rule_lid, name)
                        if( isset($rule->user) )
                        {
                            foreach( $rule->user as $user )
                            {
                                $sec_rules_usr[] = "('$source', '$vsys','$rule_lid','$user')";
                            }
                        }

                        //(source, vsys, rule_lid, table_name, member_lid)
                        if( isset($rule->application) )
                        {
                            foreach( $rule->application as $app )
                            {
                                $sec_rules_app[] = "('$source', '$vsys','$rule_lid','$app->location','$app->name')";
                            }
                        }

                        //(source, vsys, member_lid, rule_lid, table_name, member_lid)
                        if( isset($rule->tag) )
                        {
                            foreach( $rule->tag as $tag )
                            {
                                $sec_rules_tags[] = "('$source', '$vsys','$rule_lid','$tag->location','$tag->name')";
                            }
                        }

                        //Adding all the warning messages
                        if( isset($rule->logs) )
                        {
                            foreach( $rule->logs as $log )
                            {
                                //Replace _RuleLid_ by its Rulelid
                                $log['message'] = str_replace('_RuleLid_', $rule_lid, $log['message']);
                                add_log2($log['logType'], $log['task'], $log['message'], $source, $log['action'], 'rules', $rule_lid, 'security_rules');
                            }
                        }
                    }

                }
            }
        }


        if( count($sec_rules) > 0 )
        {
            $query = "INSERT INTO security_rules (id, position, name, name_ext, description, action, disabled, vsys, source) VALUES " . implode(",", $sec_rules) . ";";
            $projectdb->query($query);
            unset($sec_rules);
        }

        if( count($sec_rules_srv) > 0 )
        {
            $unique = array_unique($sec_rules_srv);
            $query = "INSERT INTO security_rules_srv (source, vsys, rule_lid, table_name, member_lid) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_srv);
            unset($unique);
        }

        if( count($sec_rules_src) > 0 )
        {
            $unique = array_unique($sec_rules_src);
            $query = "INSERT INTO security_rules_src (source, vsys, rule_lid, table_name, member_lid) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_src);
            unset($unique);
        }

        if( count($sec_rules_dst) > 0 )
        {
            $unique = array_unique($sec_rules_dst);
            $query = "INSERT INTO security_rules_dst (source, vsys, rule_lid, table_name, member_lid) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_dst);
            unset($unique);
        }

        if( count($sec_rules_from) > 0 )
        {
            $unique = array_unique($sec_rules_from);
            $query = "INSERT INTO security_rules_from (source, vsys, rule_lid, name) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_from);
            unset($unique);
        }

        if( count($sec_rules_to) > 0 )
        {
            $unique = array_unique($sec_rules_to);
            $query = "INSERT INTO security_rules_to (source, vsys, rule_lid, name) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_to);
            unset($unique);
        }

        if( count($sec_rules_usr) > 0 )
        {
            $unique = array_unique($sec_rules_usr);
            $query = "INSERT INTO security_rules_usr (source, vsys, rule_lid, name) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_usr);
            unset($unique);
        }

        if( count($sec_rules_app) > 0 )
        {
            $unique = array_unique($sec_rules_app);
            $query = "INSERT INTO security_rules_app (source, vsys, rule_lid, table_name, member_lid) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_app);
            unset($unique);
        }

        if( count($sec_rules_tags) > 0 )
        {
            $unique = array_unique($sec_rules_tags);
            $query = "INSERT INTO security_rules_tag (source, vsys, rule_lid, table_name, member_lid) VALUES " . implode(",", $unique) . ";";
            $projectdb->query($query);
            unset($sec_rules_tags);
            unset($unique);
        }

        if( $this->isFirePower == 1 )
        {
            # Fix Rule 9998 Remove the services and add app teredo
            $get9998 = $projectdb->query("SELECT id FROM security_rules WHERE description LIKE '%rule-id 9998%' AND source='$source' LIMIT 1;");
            if( $get9998->num_rows == 1 )
            {
                $get9998data = $get9998->fetch_assoc();
                $get9998Id = $get9998data['id'];
                $projectdb->query("DELETE from security_rules_srv WHERE rule_lid='$get9998Id';");
                $getTeredo = $projectdb->query("SELECT id FROM default_applications WHERE name = 'teredo';");
                if( $getTeredo->num_rows == 1 )
                {
                    $getTeredoData = $getTeredo->fetch_assoc();
                    $getTeredoId = $getTeredoData['id'];
                    $projectdb->query("INSERT INTO security_rules_app (rule_lid,member_lid,table_name) VALUES ('$get9998Id','$getTeredoId','default_applications');");
                }
            }
        }

        return $AccessGroups;
    }
}
