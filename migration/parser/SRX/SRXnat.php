<?php

trait SRXnat
{
//Todo:
    /*
     * policy order
     * static
     * destination
     * source
     * https://forums.juniper.net/t5/SRX-Services-Gateway/Order-of-Operation-Source-NAT-and-Security-Policy/td-p/311607
     */


    /**
     * @param DomElement $configRoot
     * @param VirtualSystem $v
     * @return null
     */
    function get_XML_nat2($configRoot)
    {
        global $debug;
        global $print;


        //source
        //destination
        //static


        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            if( $nodeName == "source" )
            {
                $this->get_source_destionation_nat($childNode, 'name', "source");

            }
            elseif( $nodeName == "destination" )
            {
                $this->get_source_destionation_nat($childNode, 'ipaddr', "destination");
            }
            elseif( $nodeName == "static" )
            {
                foreach( $childNode->childNodes as $key1 => $child1 )
                {
                    /** @var DOMElement $childNode */
                    if( $child1->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName1 = $child1->nodeName;

                    if( $nodeName1 == "rule-set" )
                        $this->get_rule_nat($child1, "static");
                    else
                        mwarning("not implemented", $child1);
                }

            }
            elseif( $nodeName == "proxy-arp" )
            {
                #mwarning("not implemented yet:", $childNode, false);
            }
            else
                mwarning("not implemented", $childNode);
        }

    }

    function get_source_destionation_nat($childNode, $tag,  $type)
    {
        foreach( $childNode->childNodes as $key1 => $child )
        {
            /** @var DOMElement $childNode */
            if( $child->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName1 = $child->nodeName;

            if( $nodeName1 == "pool" )
            {
                foreach( $child->childNodes as $key2 => $child2 )
                {
                    /** @var DOMElement $childNode */
                    if( $child2->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName2 = $child2->nodeName;

                    if( $nodeName2 == "name" )
                        $name = $child2->textContent;
                    elseif( $nodeName2 == "address" )
                    {
                        $ipaddr = DH::findFirstElement($tag, $child2);

                        if( $ipaddr !== FALSE )
                            $ipaddr = $ipaddr->textContent;
                        else
                            mwarning("problem", $child2);

                        $name = $this->truncate_names( $this->normalizeNames( $name ) );

                        print "      - create address: " . $name . " | value: " . $ipaddr . "\n";
                        $tmpaddress = $this->sub->addressStore->find($name);
                        if( $tmpaddress == null )
                            $tmpaddress = $this->sub->addressStore->newAddress($name, 'ip-netmask', $ipaddr);
                        else
                        {
                            if( !$tmpaddress->isGroup() && $tmpaddress->value() !== $ipaddr )
                                mwarning("duplicate object: " . $name . " oldvalue: " . $tmpaddress->value() . " newvalue: " . $ipaddr, null, FALSE);
                        }
                    }
                    elseif( $nodeName2 == "port" )
                    {
                        /*
                         <port>
                                <range>
                                    <low>1024</low>
                                    <to>
                                        <high>63487</high>
                                    </to>
                                </range>
                            </port>
                         */
                        //Todo: how to handle pool port for NAT???
                        $range = DH::findFirstElement('range', $child2);
                        if( $range === FALSE )
                            mwarning("<range> not implemented", $child2, FALSE);
                        else
                        {
                            $low = DH::findFirstElement('low', $range);
                            if( $low === FALSE )
                                mwarning("<low> not implemented", $range, FALSE);
                            else
                                print "      - rule pool port range low: " . $low->textContent . "\n";

                            $to = DH::findFirstElement('to', $range);
                            if( $to === FALSE )
                                mwarning("<to> not implemented", $range, FALSE);
                            else
                            {
                                $high = DH::findFirstElement('high', $to);
                                if( $high === FALSE )
                                    mwarning("<to> not implemented", $range, FALSE);
                                else
                                    print "      - rule pool port range to high: " . $high->textContent . "\n";
                            }

                        }
                    }
                    else
                        mwarning("not implemented", $child2);

                }
            }
            elseif( $nodeName1 == "rule-set" )
            {
                $this->get_rule_nat($child, $type);
            }
            else
            {
                //rules missing
                mwarning("not implemented", $child);
            }

        }
    }

    /**
     * @param DOMNode $child1
     * @param VirtualSystem $v
     * @param string $type
     */
    function get_rule_nat($child1, $type)
    {
        $tmp_rule_from = "";
        $tmp_rule_to = "";
        $tmp_tag = null;

        foreach( $child1->childNodes as $key2 => $child2 )
        {
            /** @var DOMElement $childNode */
            if( $child2->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName2 = $child2->nodeName;

            if( $nodeName2 == "name" )
            {
                $tmp_ruleset_name = $child2->textContent;
                print "\n - ruleset name: " . $tmp_ruleset_name . "\n";

                $tmp_tag = $this->sub->tagStore->find($tmp_ruleset_name);
                if( $tmp_tag == null )
                    $tmp_tag = $this->sub->tagStore->createTag($tmp_ruleset_name);

            }
            elseif( $nodeName2 == "from" )
            {
                foreach( $child2->childNodes as $key3 => $child3 )
                {
                    /** @var DOMElement $childNode */
                    if( $child3->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName3 = $child3->nodeName;

                    if( $nodeName3 == "zone" )
                    {
                        $tmp_rule_from = $child3->textContent;
                        print "    - ruleset from zone: " . $tmp_rule_from . "\n";
                    }
                    else
                        mwarning("not implemented", $child3);
                }
            }
            elseif( $nodeName2 == "to" )
            {
                foreach( $child2->childNodes as $key3 => $child3 )
                {
                    /** @var DOMElement $childNode */
                    if( $child3->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName3 = $child3->nodeName;

                    if( $nodeName3 == "zone" )
                    {
                        $tmp_rule_to = $child3->textContent;
                        print "    - ruleset to zone: " . $tmp_rule_to . "\n";
                    }
                    else
                        mwarning("not implemented", $child3);
                }
            }
            elseif( $nodeName2 == "rule" )
            {
                $tmp_rule = null;

                //search attribute <rule inactive="inactive">
                $inactive = $child2->getAttribute('inactive');

                foreach( $child2->childNodes as $key3 => $child3 )
                {
                    /** @var DOMElement $childNode */

                    if( $child3->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName3 = $child3->nodeName;

                    //name
                    if( $nodeName3 == "name" )
                    {
                        print "\n     - rule name: " . $child3->textContent . "\n";
                        $tmp_rule_name = $this->sub->natRules->findAvailableName($child3->textContent);
                        $tmp_rule = $this->sub->natRules->newNatRule($tmp_rule_name);

                        if( $inactive !== "" )
                        {
                            print "     - set disabled\n";
                            $tmp_rule->setDisabled(TRUE);
                        }

                        $tmp_from_zone = null;
                        if( $tmp_rule_from != "" )
                        {
                            $tmp_from_zone = $this->template_vsys->zoneStore->find($tmp_rule_from);
                            if( $tmp_from_zone != null )
                            {
                                if( $type == "static" )
                                {
                                    print "    - set to zone: " . $tmp_from_zone->name() . "\n";
                                    $tmp_rule->to->addZone($tmp_from_zone);
                                }
                                else
                                {
                                    print "    - set from zone: " . $tmp_from_zone->name() . "\n";
                                    $tmp_rule->from->addZone($tmp_from_zone);
                                }
                            }
                            else
                                mwarning( "zone: ". $tmp_rule_to. " not found!" );

                        }

                        $tmp_to_zone = null;
                        if( $tmp_rule_to != "" )
                        {
                            $tmp_to_zone = $this->template_vsys->zoneStore->find($tmp_rule_to);
                            if( $tmp_to_zone !== null )
                            {
                                if( $type == "static" )
                                {
                                    print "    - set from zone: " . $tmp_to_zone->name() . "\n";
                                    $tmp_rule->from->addZone($tmp_to_zone);
                                }
                                else
                                {
                                    print "    - set to zone: " . $tmp_to_zone->name() . "\n";
                                    $tmp_rule->to->addZone($tmp_to_zone);
                                }
                            }
                            else
                                mwarning( "zone: ". $tmp_rule_to. " not found!" );

                        }

                        if( $tmp_tag != null )
                        {
                            $tmp_rule->tags->addTag($tmp_tag);
                        }
                    }
                    elseif( $nodeName3 == "static-nat-rule-match" )
                    {
                        //Todo: 20200304 - zone calculation wrong, need to see what is possible

                        /*
                        <static-nat-rule-match>
                            <destination-address>
                                <dst-addr>212.65.63.222/32</dst-addr>
                            </destination-address>
                        </static-nat-rule-match>
                         */
                        $destination = DH::findFirstElement('destination-address', $child3);
                        if( $destination === FALSE )
                            $destination = DH::findFirstElement('destination-address-name', $child3);

                        if( $destination === FALSE )
                            mwarning("<destination-address> /<destination-address-name> not found", $child3, FALSE);
                        else
                        {
                            $dst = DH::findFirstElement('dst-addr', $destination);
                            if( $dst === FALSE )
                                $dst = DH::findFirstElement('dst-addr-name', $destination);



                            if( $dst === FALSE )
                            {
                                mwarning("<dst-addr> not found", $destination, FALSE);
                            }
                            else
                            {
                                print "      - rule static-nat-rule-match: " . $dst->textContent . "\n";

                                $tmp_address = $this->sub->addressStore->all("value string.eq " . $dst->textContent);
                                if( isset($tmp_address[0]) )
                                    #$tmp_rule->source->addObject( $tmp_address[0] );
                                    $tmp_address = $tmp_address[0];
                                else
                                {
                                    $tmp_addr = explode("/", $dst->textContent);
                                    $addr_name = $tmp_addr[0];
                                    if( count( $tmp_addr ) == 2 )
                                        $addr_name .= "m" . $tmp_addr[1];
                                    $addr_value = $dst->textContent;

                                    $tmp_address = $this->sub->addressStore->find( $addr_name );
                                    if( $tmp_address === null )
                                        $tmp_address = $this->sub->addressStore->newAddress($addr_name, "ip-netmask", $addr_value);
                                    #$tmp_rule->source->addObject( $tmp_address );
                                }


                                print "     - set snathost: " . $tmp_address->name() . "\n";
                                $tmp_rule->snathosts->addObject($tmp_address);
                                $tmp_rule->changeSourceNAT('static-ip');
                            }
                        }
                    }
                    elseif( $nodeName3 == "src-nat-rule-match" )
                    {
                        $this->src_dst_rule_match($child3, $tmp_rule);
                        #$tmp_rule->changeSourceNAT("dynamic-ip-and-port");
                    }
                    elseif( $nodeName3 == "dest-nat-rule-match" )
                    {
                        $this->src_dst_rule_match($child3, $tmp_rule);
                    }
                    elseif( $nodeName3 == "then" )
                    {
                        /*
                         <then>
                        <static-nat>
                            <prefix>
                                <addr-prefix>192.168.156.196/32</addr-prefix>
                            </prefix>
                        </static-nat>
                    </then>
                         */
                        $tmp_tag = $this->sub->tagStore->find($type . "NAT");
                        if( $tmp_tag == null )
                            $tmp_tag = $this->sub->tagStore->createTag($type . "NAT");
                        $tmp_rule->tags->addTag($tmp_tag);

                        if( $type == "static" )
                        {
                            $static = DH::findFirstElement('static-nat', $child3);
                            if( $static === FALSE )
                                mwarning("<static-nat> not implemented", $child3, FALSE);
                            $prefix = DH::findFirstElement('prefix', $static);
                            if( $prefix === FALSE )
                            {
                                $prefix = DH::findFirstElement('prefix-name', $static);
                                if( $prefix === FALSE )
                                    mwarning("<prefix> not implemented", $static, FALSE);
                            }

                            $addrprefix = DH::findFirstElement('addr-prefix', $prefix);
                            if( $addrprefix === FALSE )
                            {
                                $addrprefix = DH::findFirstElement('addr-prefix-name', $prefix);
                                if( $addrprefix === FALSE )
                                    mwarning("<addr-prefix> not implemented", $prefix, FALSE);
                            }

                            print "      - rule then: " . $addrprefix->textContent . "\n";


                            $tmp_address = $this->sub->addressStore->all("value string.eq " . $addrprefix->textContent);
                            if( isset($tmp_address[0]) )
                                #$tmp_rule->source->addObject( $tmp_address[0] );
                                $tmp_address = $tmp_address[0];
                            else
                            {
                                $tmp_addr = explode("/", $addrprefix->textContent);
                                $addr_name = $tmp_addr[0];
                                if( count( $tmp_addr ) == 2 )
                                    $addr_name .= "m" . $tmp_addr[1];
                                $addr_value = $addrprefix->textContent;

                                $tmp_address = $this->sub->addressStore->find( $addr_name );
                                if( $tmp_address === null )
                                    $tmp_address = $this->sub->addressStore->newAddress($addr_name, "ip-netmask", $addr_value);
                                #$tmp_rule->source->addObject( $tmp_address );
                            }

                            $tmp_rule->source->addObject($tmp_address);

                            print "     - enable birdir NAT\n";
                            $tmp_rule->setBiDirectional(TRUE);
                        }
                        elseif( $type == "source" )
                        {
                            $source = DH::findFirstElement('source-nat', $child3);
                            if( $source === FALSE )
                                mwarning("<source-nat> not implemented", $child3, FALSE);
                            $pool = DH::findFirstElement('pool', $source);
                            if( $pool === FALSE )
                            {
                                #mwarning("<pool> not implemented", $source, false);

                                $interface = DH::findFirstElement('interface', $source);
                                if( $interface === FALSE )
                                    mwarning("<interface> not implemented", $source, FALSE);
                                else
                                {
                                    print "      - rule then: '" . $interface->textContent . "'\n";

                                    if( $tmp_to_zone !== null )
                                        $tmpintarray = $tmp_to_zone->attachedInterfaces->interfaces();
                                    else
                                        $tmpintarray = array();

                                    if( count($tmpintarray) == 1 )
                                    {
                                        $tmpint = $tmpintarray[0];

                                        print "     - set snatinterface to: " . $tmpint->name() . "\n";
                                        $tmp_rule->snatinterface = $tmpint->name();

                                        //not possible yet
                                        #if( isset( $tmpint->getLayer3IPv4Addresses()[0] ) )
                                        #    $tmp_rule->snathosts = $tmpint->getLayer3IPv4Addresses()[0];


                                        $tmp_rule->changeSourceNAT("dynamic-ip-and-port");
                                    }
                                    else
                                    {
                                        if( $tmp_to_zone != null )
                                        {
                                            $tmpint = $tmpintarray[0];

                                            //Todo:
                                            // - get all DST address ip
                                            // - check which interface must be set
                                            // - if multiple interface => split NAT rule

                                            /** @var NatRule[] $tmp_rule */
                                            $tmpDSTaddress = $tmp_rule->destination->all();
                                            //it could be also an addressgroup

                                            #print_r( $tmpintarray );
                                            //Todo: continue working here, check CASE 01594364
                                            //Todo: swaschkut 20200928
                                            // <destination-address-name>MS-Health-Monitoring-1</destination-address-name>
                                            mwarning("too many interfaces found for zone: " . $tmp_to_zone->name() . "\n");
                                            
                                            print "     - set snatinterface to: " . $tmpint->name() . "\n";
                                            $tmp_rule->snatinterface = $tmpint->name();

                                            //not possible yet
                                            #if( isset( $tmpint->getLayer3IPv4Addresses()[0] ) )
                                            #    $tmp_rule->snathosts = $tmpint->getLayer3IPv4Addresses()[0];


                                            $tmp_rule->changeSourceNAT("dynamic-ip-and-port");


                                        }

                                    }


                                }
                            }
                            else
                            {
                                $poolname = DH::findFirstElement('pool-name', $pool);
                                if( $poolname === FALSE )
                                    mwarning("<pool-name> not implemented", $poolname, FALSE);
                                else
                                {
                                    print "      - rule then: " . $poolname->textContent . "\n";

                                    $tmp_address = $this->sub->addressStore->find($poolname->textContent);
                                    if( $tmp_address !== null )
                                    {
                                        print "     - set snathost to: " . $tmp_address->name() . "\n";
                                        $tmp_rule->snathosts->addObject($tmp_address);
                                        $tmp_rule->changeSourceNAT("dynamic-ip-and-port");
                                    }

                                }

                            }
                        }
                        elseif( $type == "destination" )
                        {
                            $destination = DH::findFirstElement('destination-nat', $child3);
                            if( $destination === FALSE )
                                mwarning("<source-nat> not implemented", $child3, FALSE);
                            $pool = DH::findFirstElement('pool', $destination);
                            if( $pool === FALSE )
                            {
                                $off = DH::findFirstElement('off', $destination);
                                if( $off === FALSE )
                                    mwarning("<pool> and <off> not found", $destination, FALSE);
                            }
                            else
                            {
                                $poolname = DH::findFirstElement('pool-name', $pool);
                                if( $poolname === FALSE )
                                    mwarning("<pool-name> not implemented", $poolname, FALSE);
                                else
                                {
                                    print "      - rule then: " . $poolname->textContent . "\n";

                                    $tmp_address = $this->sub->addressStore->find($poolname->textContent);
                                    if( $tmp_address !== null )
                                    {
                                        print "     - set DNAT to: " . $tmp_address->name() . "\n";

                                        $tmp_rule->setDNAT($tmp_address);
                                    }
                                }
                            }

                        }
                    }
                    else
                        mwarning("not implemented", $child3);
                }
            }
            else
                mwarning("not implemented", $child2);
        }
    }


    function src_dst_rule_match($child3,  $tmp_rule)
    {
        //foreach needed
        foreach( $child3->childNodes as $key4 => $child4 )
        {
            /** @var DOMElement $childNode */
            if( $child4->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName4 = $child4->nodeName;

            //name
            if( $nodeName4 == "destination-address" )
            {
                $dst = DH::findFirstElement('dst-addr', $child4);
                if( $dst === FALSE )
                {
                    print "      - rule dest-nat-rule-match: " . $child4->textContent . "\n";
                    #mwarning("<dst-addr> not implemented", $child4, false);

                    $tmp_address = $this->sub->addressStore->all("value string.eq " . $child4->textContent);
                    if( count($tmp_address) == 0 )
                    {
                        #print "count: " . count($tmp_address) . "\n";
                        $value = $child4->textContent;
                        $tmp_name = explode("/", $value);
                        $name = $tmp_name[0] . "m" . $tmp_name[1];

                        $tmp_address[0] = $this->sub->addressStore->newAddress($name, "ip-netmask", $value);
                    }
                    if( isset($tmp_address[0]) )
                    {
                        $tmp_address = $tmp_address[0];
                        print "     - set destination: " . $tmp_address->name() . "\n";
                        $tmp_rule->destination->addObject($tmp_address);
                    }
                }
                else
                {
                    print "      - rule dest-nat-rule-match: " . $dst->textContent . "\n";
                    $tmp_address = $this->sub->addressStore->all("value string.eq " . $dst->textContent);
                    if( count($tmp_address) == 0 )
                    {
                        #print "count: " . count($tmp_address) . "\n";
                        $value = $dst->textContent;
                        $tmp_name = explode("/", $value);
                        $name = $tmp_name[0] . "m" . $tmp_name[1];

                        $tmp_address[0] = $this->sub->addressStore->newAddress($name, "ip-netmask", $value);
                    }
                    if( isset($tmp_address[0]) )
                    {
                        $tmp_address = $tmp_address[0];
                        print "     - set destination: " . $tmp_address->name() . "\n";
                        $tmp_rule->destination->addObject($tmp_address);
                    }
                }
            }
            elseif( $nodeName4 == "destination-address-name" )
            {
                $dstname = DH::findFirstElement('dst-addr-name', $child4);
                if( $dstname === FALSE )
                {
                    print "      - rule dest-nat-rule-match: " . $child4->textContent . "\n";
                    $tmp_address = $this->sub->addressStore->find($child4->textContent);
                }
                else
                {
                    print "      - rule dest-nat-rule-match: " . $dstname->textContent . "\n";
                    $tmp_address = $this->sub->addressStore->find($dstname->textContent);
                }

                if( $tmp_address !== null )
                {
                    print "     - set destination: " . $tmp_address->name() . "\n";
                    $tmp_rule->destination->addObject($tmp_address);
                }

            }
            elseif( $nodeName4 == "source-address" )
            {
                print "      - rule dest-nat-rule-match: " . $child4->textContent . "\n";
                $tmp_address = $this->sub->addressStore->all("value string.eq " . $child4->textContent);
                if( count($tmp_address) == 0 )
                {
                    #print "count: " . count($tmp_address) . "\n";
                    $value = $child4->textContent;
                    $tmp_name = explode("/", $value);
                    $name = $tmp_name[0] . "m" . $tmp_name[1];

                    $tmp_address[0] = $this->sub->addressStore->newAddress($name, "ip-netmask", $value);
                }
                if( isset($tmp_address[0]) )
                {
                    $tmp_address = $tmp_address[0];
                    print "     - set source: " . $tmp_address->name() . "\n";
                    $tmp_rule->source->addObject($tmp_address);
                }
            }
            elseif( $nodeName4 == "source-address-name" )
            {
                print "      - rule dest-nat-rule-match: " . $child4->textContent . "\n";
                $tmp_address = $this->sub->addressStore->find($child4->textContent);
                if( $tmp_address !== null )
                {
                    print "     - set source: " . $tmp_address->name() . "\n";
                    $tmp_rule->source->addObject($tmp_address);
                }

            }
            elseif( $nodeName4 == "destination-port" )
            {
                $dstport = DH::findFirstElement('dst-port', $child4);
                if( $dstport === FALSE )
                    mwarning("<dst-port> not implemented", $child4, FALSE);
                else
                {
                    print "      - rule dest-nat-rule-match: " . $dstport->textContent . "\n";
                    $tmp_service = $this->sub->serviceStore->all("value string.eq " . $dstport->textContent);

                    #print "count: " . count($tmp_service) . "\n";
                    if( isset($tmp_service[0]) )
                    {
                        print "     - add service: " . $tmp_service[0]->name() . "\n";
                        $tmp_rule->setService($tmp_service[0]);
                    }
                }
            }
            else
                mwarning("not implemented", $child4);


        }

    }

}