<?php


trait SRXfilter
{
    /**
     * @param DomElement $filterRoot
     */
    function get_XML_filter($filterRootList, $ruleNamePrefix = "")
    {
        $counter = 0;

        $migrateAll = false;

        $missingNode = array();
        $filtername = "";
        foreach( $filterRootList as $filterRoot )
        {
            foreach( $filterRoot->childNodes as $key => $childNode )
            {
                /** @var DOMElement $childNode */
                if( $childNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $nodeName = $childNode->nodeName;

                if( $nodeName == 'name' )
                {
                    $filtername = $childNode->textContent;

                    if( !$migrateAll && !isset($this->filterInputInterface[$filtername]) && !isset($this->filterOutputInterface[$filtername]) )
                        break;

                }
                elseif( $nodeName == 'term' )
                {
                    $tmp_rule = null;
                    foreach( $childNode->childNodes as $key2 => $childNode2 )
                    {
                        /** @var DOMElement $childNode2 */
                        if( $childNode2->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $nodeName2 = $childNode2->nodeName;

                        if( $nodeName2 == 'name' )
                        {
                            $secRuleName = $childNode2->textContent;
                            print "create SecRule: " . $secRuleName . "\n";
                            /** @var SecurityRule $tmp_rule */

                            $name = $this->sub->securityRules->findAvailableName( $ruleNamePrefix.$secRuleName );

                            $tmp_rule = $this->sub->securityRules->newSecurityRule($name);

                            $tmp_tag = $this->sub->tagStore->find($filtername);
                            if( $tmp_tag == null )
                            {
                                $tmp_tag = $this->sub->tagStore->createTag($filtername);
                            }
                            $tmp_rule->tags->addTag( $tmp_tag );

                            $counter++;
                        }
                        elseif( $nodeName2 == 'from' )
                        {
                            if( isset($this->filterInputInterface[$filtername]) )
                                foreach( $this->filterInputInterface[$filtername] as $tmp_zone )
                                {
                                    $tmp_rule->to->addZone($tmp_zone);
                                }

                            if( isset($this->filterOutputInterface[$filtername]) )
                                foreach( $this->filterOutputInterface[$filtername] as $tmp_zone )
                                {
                                    $tmp_rule->from->addZone($tmp_zone);
                                }

                            $protocol = null;
                            foreach( $childNode2->childNodes as $key3 => $childNode3 )
                            {

                                /** @var DOMElement $childNode3 */
                                if( $childNode3->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $nodeName3 = $childNode3->nodeName;

                                if( $nodeName3 == 'source-address' || $nodeName3 == 'destination-address' )
                                {
                                    $addressValueNode = DH::findFirstElement('name', $childNode3);
                                    $value = $addressValueNode->textContent;
                                    $name = $this->normalizeNames($value);

                                    $value_array = explode( "/", $value );
                                    if( isset( $value_array[1] ) )
                                    {
                                        if( strpos( $value_array[1], "." ) !== false )
                                        {
                                            print_r( $value_array );

                                            $netmask = $this->netmask2wildcardnetmask( $value_array[1] );
                                            #$netmask = cidr::cidr2netmask( $value_array[1] );
                                            #$netmask = cidr::netmask2cidr( $value_array[1] );
                                            print "|orig: ".$value_array[1]." new: ".$netmask."\n";
                                            $value = $value_array[0]."/".$netmask;

                                        }
                                    }

                                    $tmp_address = $this->MainAddHost($name, $value);

                                    if( $nodeName3 == 'source-address' )
                                        $direction = "source";
                                    elseif( $nodeName3 == 'destination-address' )
                                        $direction = "destination";

                                    $tmp_rule->$direction->addObject($tmp_address);
                                    print "  - " . $direction . ": name: " . $name . " - value: " . $value . "\n";

                                }
                                elseif( $nodeName3 == 'protocol' )
                                {
                                    if( $protocol !== null )
                                    {
                                        if( !is_array( $protocol) )
                                        {
                                            $tmp_proto = $protocol;
                                            $protocol = array();
                                            $protocol[] = $tmp_proto;
                                        }
                                        print "add protocol array\n";
                                        $protocol[]= $childNode3->textContent;
                                    }
                                    else
                                    {
                                        $protocol = $childNode3->textContent;
                                        print "set protocol: ".$protocol."\n";
                                    }


                                    if( is_array( $protocol ) )
                                    {
                                        foreach( $protocol as $proto )
                                        {
                                            if( $proto != 'tcp' && $proto != 'udp' )
                                            {
                                                $name = "tmp-" . $proto;
                                                $description = "protocol-id:{" . $proto . "}";


                                                $tmp_service = $this->MainAddService($name, 'tcp', '65535', $description);
                                                $tmp_rule->services->add($tmp_service);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        if( $protocol != 'tcp' && $protocol != 'udp' )
                                        {
                                            $name = "tmp-" . $protocol;
                                            $description = "protocol-id:{" . $protocol . "}";


                                            $tmp_service = $this->MainAddService($name, 'tcp', '65535', $description);
                                            $tmp_rule->services->add($tmp_service);
                                        }
                                    }


                                }
                                elseif( $nodeName3 == 'destination-port' )
                                {
                                    $port = $childNode3->textContent;

                                    if( !is_array( $protocol) )
                                    {
                                        if( empty( $protocol) )
                                            $protocol = "tcp";
                                        $tmp_service = $this->MainAddService($protocol . "_" . $port, $protocol, $port);
                                        $tmp_rule->services->add($tmp_service);
                                    }
                                    else
                                        foreach( $protocol as $proto )
                                        {
                                            $tmp_service = $this->MainAddService($proto . "_" . $port, $proto, $port);
                                            $tmp_rule->services->add($tmp_service);
                                        }

                                }
                                elseif( $nodeName3 == 'source-port' )
                                {
                                    $port = $childNode3->textContent;

                                    if( !is_array( $protocol) )
                                    {
                                        if( empty( $protocol) )
                                            $protocol = "tcp";

                                        $tmp_service = $this->MainAddService($protocol . "_1-65535_" . $port, $protocol, "1-65535", '', $port);
                                        $tmp_rule->services->add($tmp_service);
                                    }
                                    else
                                        foreach( $protocol as $proto )
                                        {
                                            $tmp_service = $this->MainAddService($proto . "_1-65535_" . $port, $proto, "1-65535", '', $port);
                                            $tmp_rule->services->add($tmp_service);
                                        }

                                }
                                elseif( $nodeName3 == 'port' )
                                {
                                    $port = $childNode3->textContent;

                                    if( !is_array( $protocol) )
                                    {
                                        $tmp_service = $this->MainAddService($protocol . "_" . $port, $protocol, $port);
                                        $tmp_rule->services->add($tmp_service);
                                    }
                                    else
                                        foreach( $protocol as $proto )
                                        {
                                            $tmp_service = $this->MainAddService($proto . "_" . $port, $proto, $port);
                                            $tmp_rule->services->add($tmp_service);
                                        }


                                }
                                elseif( $nodeName3 == 'tcp-established' )
                                {
                                    print "tcp-established found - not migrated\n";
                                    $description = $tmp_rule->description();
                                    $tmp_rule->setDescription( $description." - tcp-established not migrated"  );
                                }
                                elseif( $nodeName3 == 'icmp-type' )
                                {
                                    //but protocol must be already found as 'icmp'
                                    if( $protocol == "icmp" )
                                    {
                                        $port = $childNode3->textContent;
                                        $name = "tmp-icmp-type" . $port;
                                        $description = "icmp-type:{" . $port . "}";


                                        $tmp_service = $this->MainAddService($name, 'tcp', '65535', $description);
                                        $tmp_rule->services->add($tmp_service);
                                    }
                                }
                                elseif( $nodeName3 == 'dscp' )
                                {
                                    print "dscp found - not migrated\n";
                                    $description = $tmp_rule->description();
                                    $tmp_rule->setDescription( $description." - dscp not migrated"  );
                                }
                                else
                                {
                                    //Todo: something missing
                                }
                            }
                        }
                        elseif( $nodeName2 == 'then' )
                        {
                            $accept = DH::findFirstElement('accept', $childNode2);
                            if( $accept != FALSE )
                            {
                                $tmp_rule->setAction("allow");
                            }

                            $discard = DH::findFirstElement('discard', $childNode2);
                            if( $discard != FALSE )
                            {
                                $tmp_rule->setAction("deny");
                            }

                            $count = DH::findFirstElement('count', $childNode2);
                            if( $count != FALSE )
                            {
                                //Todo: what todo with this information
                            }
                        }
                    }
                }
            }
        }
    }

}