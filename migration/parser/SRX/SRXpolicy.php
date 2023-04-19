<?php


trait SRXpolicy
{
    /**
     * @param DomElement $configRoot
     * @param VirtualSystem $v
     * @return null
     */
    function get_XML_policies2($configRoot)
    {
        global $debug;
        global $print;



        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            $from = "";
            $to = "";

            if( $nodeName == "policy" )
            {
                /*
                <policy>
                    <from-zone-name>Universe</from-zone-name>
                    <to-zone-name>zonePublicExtVPN</to-zone-name>
                    <policy>
                        <name>allow_bgp</name>
                        <match>
                            <source-address>BOR-R_L3_UNIVERSE_INT</source-address>
                            <destination-address>BOR-R_L3_PublicExtVPN_INT</destination-address>
                            <application>junos-bgp</application>
                            <application>BFD</application>
                        </match>
                        <then>
                            <permit>
                            </permit>
                        </then>
                    </policy>
                </policy>
                 */

                $comment = "";
                foreach( $childNode->childNodes as $key1 => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName1 = $child->nodeName;


                    if( $nodeName1 == 'from-zone-name' )
                    {
                        $from = $child->textContent;
                    }
                    elseif( $nodeName1 == 'to-zone-name' )
                    {
                        $to = $child->textContent;
                    }
                    elseif( $nodeName1 == 'policy' )
                    {
                        $this->create_policy($from, $to, $child, "", $comment);
                        $comment = "";
                    }
                    elseif( $nodeName1 == 'junos:comment' )
                    {
                        $comment = $child->nodeValue;
                    }
                    else
                        mwarning("not implemented", $child);
                }
            }
            elseif( $nodeName == "global" )
            {
                $comment = "";
                foreach( $childNode->childNodes as $key1 => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName1 = $child->nodeName;


                    if( $nodeName1 == 'policy' )
                    {
                        $this->create_policy( $from = "", $to = "", $child, "global", $comment );
                        $comment = "";
                    }
                    elseif( $nodeName1 == 'junos:comment' )
                    {
                        $comment = $child->nodeValue;
                    }
                    else
                        mwarning("not implemented", $child);
                }
            }
            else
                mwarning("not implemented", $childNode);
        }
    }


    function create_policy( $from, $to, $child, $type, $comment = "")
    {
        $inactive = $child->getAttribute('inactive');


        foreach( $child->childNodes as $key2 => $child2 )
        {
            /** @var DOMElement $childNode */
            if( $child2->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName2 = $child2->nodeName;

            if( $nodeName2 == 'name' )
            {
                if( $type === "global" )
                    $type = $type."__";

                $name = $child2->textContent;
                #$name = $this->sub->securityRules->findAvailableName($type . $name);
                $name = $this->sub->securityRules->findAvailableName($type . $from."__".$to."__".$name);
                print "\n - create policy: " . $name . "\n";
                $tmprule = $this->sub->securityRules->newSecurityRule($name);

                if( $comment != "" )
                {
                    print "     - add description: " . $comment . "\n";
                    $tmprule->setDescription( $comment );
                }


                if( $inactive !== "" )
                {
                    print "     - set disabled\n";
                    $tmprule->setDisabled(TRUE);
                }

                if( $type == "global" )
                {
                    $tmp_tag = $this->sub->tagStore->find($type);
                    if( $tmp_tag == null )
                        $tmp_tag = $this->sub->tagStore->createTag($type);
                    $tmprule->tags->addTag($tmp_tag);
                }

                if( $from != "" )
                {
                    print "    - find from: '".$from."'\n";
                    $from_zone = $this->template_vsys->zoneStore->find($from);
                    if( $from_zone != null )
                    {
                        print "     - add from: " . $from_zone->name() . "\n";
                        $tmprule->from->addZone($from_zone);
                    }
                    else
                        mwarning( "ZONE from: ".$from." not found", null, false );

                }


                if( $to != "" )
                {
                    print "    - find to: '".$to."'\n";
                    $to_zone = $this->template_vsys->zoneStore->find($to);
                    if( $to_zone !== null )
                    {
                        print "     - add to: " . $to_zone->name() . "\n";
                        $tmprule->to->addZone($to_zone);
                    }
                    else
                        mwarning( "ZONE to: ".$to." not found", null, false );

                }
            }
            elseif( $nodeName2 == 'match' )
            {
                #$to = $child->textContent;
                /*
                <match>
                    <source-address>passwordVaultRoutersGrp</source-address>
                    <destination-address>Net_175_174_68_0</destination-address>
                    <application>junos-ssh</application>
                    <application>junos-telnet</application>
                </match>
                 */
                foreach( $child2->childNodes as $key3 => $child3 )
                {
                    /** @var DOMElement $childNode */
                    if( $child3->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName3 = $child3->nodeName;

                    if( $nodeName3 == 'source-address' )
                    {
                        $source = $child3->textContent;
                        if( strtolower($source) != "any" )
                        {
                            $source = $this->truncate_names( $this->normalizeNames( $source ) );
                            $tmpaddress = $this->sub->addressStore->find($source);

                            if( $tmpaddress !== null )
                            {
                                print "     - add source: " . $tmpaddress->name() . "\n";
                                $tmprule->source->addObject($tmpaddress);
                            }
                            else
                            {
                                mwarning( "address object: ". $source." not found." );
                            }

                        }
                    }
                    elseif( $nodeName3 == 'destination-address' )
                    {
                        $destination = $child3->textContent;
                        if( strtolower($destination) != "any" )
                        {
                            $destination = $this->truncate_names( $this->normalizeNames( $destination ) );
                            $tmpaddress = $this->sub->addressStore->find($destination);

                            if( $tmpaddress !== null)
                            {
                                print "     - add destination: " . $tmpaddress->name() . "\n";
                                $tmprule->destination->addObject($tmpaddress);
                            }
                            else
                            {
                                mwarning( "address object: ". $destination." not found." );
                            }
                        }
                    }
                    elseif( $nodeName3 == 'application' )
                    {
                        $service = $child3->textContent;
                        if( strtolower($service) != "any" )
                        {
                            $tmpservice = $this->sub->serviceStore->find($service);
                            if( $tmpservice == null )
                                $tmpservice = $this->sub->serviceStore->find("tmp-" . $service);

                            if( $tmpservice != null )
                            {
                                print "     - add services: " . $tmpservice->name() . "\n";
                                $tmprule->services->add($tmpservice);
                            }
                            else
                            {
                                mwarning("can not find service: " . $service, null, FALSE);

                                $tmpservice = $this->sub->serviceStore->newService("tmp-" . $service, "tcp", "65000");
                                print "     - add services: " . $tmpservice->name() . "\n";
                                $tmprule->services->add($tmpservice);

                            }

                        }
                    }
                    elseif( $nodeName3 == 'from-zone' )
                    {
                        $from = $child3->textContent;

                        if( $from != "" and $from != "any" )
                        {
                            #print "    - find from: '".$from."'\n";
                            $from = $this->template_vsys->zoneStore->find($from);
                            if( $from != null )
                            {
                                print "     - add from: " . $from->name() . "\n";
                                $tmprule->from->addZone($from);
                            }
                            else
                                mwarning( "ZONE from: '".$from."' not found" );

                        }



                    }
                    elseif( $nodeName3 == 'to-zone' )
                    {
                        $to = $child3->textContent;

                        if( $to != "" and $to != "any" )
                        {
                            #print "    - find to: '".$to."'\n";
                            $to = $this->template_vsys->zoneStore->find($to);
                            if( $to !== null )
                            {
                                print "     - add to: " . $to->name() . "\n";
                                $tmprule->to->addZone($to);
                            }
                            else
                                mwarning( "ZONE to: '".$to."' not found" );

                        }
                    }
                    else
                        mwarning("not implemented", $child3);
                }
            }
            elseif( $nodeName2 == 'description' )
            {
                $description = $child2->textContent;
                $tmprule->setDescription($description);
            }
            elseif( $nodeName2 == 'then' )
            {
                $then = $child2->textContent;
                #print "then: |".$then."|\n";

                //Todo: 20200226 - continue here
                //permit
                //deny
                //log -> session-init

                if( $child2->nodeType == XML_ELEMENT_NODE )
                {
                    $permit = DH::findFirstElement('permit', $child2);
                    if( $permit !== FALSE )
                    {
                        print "     - set rule action to allow\n";
                        $tmprule->setAction("allow");
                    }

                    $deny = DH::findFirstElement('deny', $child2);
                    if( $deny !== FALSE )
                    {
                        print "     - set rule action to deny\n";
                        $tmprule->setAction("deny");
                    }

                    $reject = DH::findFirstElement('reject', $child2);
                    if( $reject !== FALSE )
                    {
                        print "     - set rule action to deny\n";
                        $tmprule->setAction("deny");
                    }


                    $log = DH::findFirstElement('log', $child2);
                    if( $log !== FALSE )
                    {
                        $log = DH::findFirstElement('session-init', $log);
                        if( $log !== FALSE )
                        {
                            print "     - enable log at start\n";
                            $tmprule->setLogStart(TRUE);
                        }

                        #mwarning("<log> not implemented", $log, false);
                    }


                }


            }
            else
                mwarning("not implemented", $child2);
        }
    }

}