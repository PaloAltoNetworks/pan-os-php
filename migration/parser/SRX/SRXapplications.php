<?php



trait SRXapplications
{
#function get_XML_Zones_Address_All_new($configuration, $vsys, $source, $template, &$objectsInMemory) {
    /**
     * @param DomElement $configRoot
     * @param VirtualSystem $v
     * @return null
     */
    function get_XML_Applications2($configRoot)
    {
        global $debug;
        global $print;
        //$configRoot /configuration/security/address-book


        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            if( $nodeName == "application" )
            {

                // - service
//$address = $configuration->xpath("/configuration/applications/application");
                /*
                <application>
                    <name>rco</name>
                    <term>
                        <name>rco</name>
                        <protocol>tcp</protocol>
                        <source-port>0-65535</source-port>
                        <destination-port>798-798</destination-port>
                    </term>
                    <term>
                        <name>798-798</name>
                        <protocol>tcp</protocol>
                        <source-port>0-65535</source-port>
                        <destination-port>798-798</destination-port>
                    </term>
                    <term>
                        <name>799-799</name>
                        <protocol>tcp</protocol>
                        <source-port>0-65535</source-port>
                        <destination-port>799-799</destination-port>
                    </term>
                </application>
                 */


                $name = "";
                $protocol = 'tcp';
                $dstports = "65535";
                $tmpservice = null;
                $tmpservice2 = null;

                $tcpudp = false;
                $removed = false;
                foreach( $childNode->childNodes as $key => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName = $child->nodeName;

                    if( $nodeName == 'name' )
                    {
                        $tmpproto = "";

                        $name = $child->textContent;
                        $tcpudpname = $name;
                        #print "addressname: ".$name."\n";

                        $tmpservice = $this->sub->serviceStore->find($name);

                        if( $tmpservice == null )
                        {
                            print "\n - create service object1: " . $name . "\n";
                            $tmpservice = $this->sub->serviceStore->newService($name, $protocol, $dstports);
                        }
                        else
                        {
                            mwarning("address object with name: " . $name . " already available\n");
                            continue;
                        }
                    }
                    elseif( $nodeName == 'protocol' )
                    {
                        $protocol = $child->textContent;
                        #print "addressname: ".$name."\n";

                        if( $tmpproto == "" )
                        {
                            if( $protocol == "tcp" || $protocol == "udp" )
                                $tmpservice->setProtocol($protocol);
                            else
                            {
                                $tmpservice2 = $this->sub->serviceStore->find("tmp-" . $tmpservice->name());
                                if( $tmpservice2 == null )
                                {
                                    print "    - change name to: 'tmp-" . $tmpservice->name() . "'\n";
                                    $tmpservice->setName("tmp-" . $tmpservice->name());
                                }
                            }
                        }
                        elseif( $tmpservice->protocol() != $protocol )
                        {
                            $tcpudp = true;

                            //1) rename existing service - add protocol at beginning
                            $tmpservice->setName( strtoupper($tmpservice->protocol())."-" . $tmpservice->name());

                            $tmp_obj = false;
                            if( $protocol != "tcp" || $protocol != "udp" )
                            {
                                $tmp_obj = true;
                                $srv_protocol = $protocol;

                                $tmpname = "tmp-" . $tcpudpname;
                                $protocol = "tcp";
                                $dstports = "65535";
                            }
                            else
                                $tmpname = strtoupper($protocol)."-" . $tcpudpname;

                            $tmpservice2 = $this->sub->serviceStore->find($tmpname );
                            if( $tmpservice2 === null )
                            {
                                print "\n - create service object2: " . $tmpname . "\n";
                                $tmpservice2 = $this->sub->serviceStore->newService($tmpname, $protocol, $dstports);

                                if( $tmp_obj )
                                {
                                    print "  * set description: 'protocol-id:{".$srv_protocol."}'";
                                    $tmpservice2->setDescription( "protocol-id:{".$srv_protocol."}" );
                                }


                            }
                            //2) create new object with - protocol_NAME -> set protocol and port

                            // create address group with name
                            //add both members
                            $tmp_servicegroup = $this->sub->serviceStore->find( $tcpudpname );
                            if( $tmp_servicegroup == null )
                            {
                                if( $print )
                                    print "create servicegroup Object: ".$tcpudpname."\n";
                                $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup( $tcpudpname );
                                $tmp_object = $this->sub->serviceStore->find('TCP-'.$tcpudpname);
                                if( $tmp_object !== null )
                                {
                                    $tmp_servicegroup->addMember($tmp_object);
                                }
                                $tmp_object = $this->sub->serviceStore->find('UDP-'.$tcpudpname);
                                if( $tmp_object !== null )
                                {
                                    $tmp_servicegroup->addMember($tmp_object);
                                }

                                if( $tmp_obj )
                                {
                                    $tmp_object = $this->sub->serviceStore->find('tmp-'.$tcpudpname);
                                    if( $tmp_object !== null )
                                    {
                                        $tmp_servicegroup->addMember($tmp_object);
                                    }
                                }
                            }
                        }

                    }
                    elseif( $nodeName == 'source-port' )
                    {
                        $sourceport = $child->textContent;
                        #print "addressname: ".$name."\n";

                        if( $sourceport != "0-65535" && $sourceport != "1-65535" )
                            mwarning("source port must be set");
                    }
                    elseif( $nodeName == 'destination-port' )
                    {
                        $destinationport = $child->textContent;
                        #print "addressname: ".$name."\n";

                        $tmpdstport = $tmpservice->getDestPort();

                        if( $tmpdstport != $destinationport )
                            $tmpdstport = $destinationport;

                        if( !$tcpudp )
                            $tmpservice->setDestPort($tmpdstport);
                        else
                            $tmpservice2->setDestPort($tmpdstport);

                    }
                    elseif( $nodeName == 'description' )
                    {
                        $description = $child->textContent;
                        #print "addressname: ".$name."\n";

                        print "   - set description: " . $description . "\n";
                        if( !$tcpudp )
                            $tmpservice->setDescription($description);
                        else
                            $tmpservice2->setDescription($description);
                    }
                    elseif( $nodeName == 'inactivity-timeout' )
                    {
                        $timeout = $child->textContent;

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

                        if( $print )
                            print " * set timeout to: " . $timeout . "\n";

                        if( !$tcpudp )
                            $tmpservice->setTimeout($timeout);
                        else
                            $tmpservice2->setTimeout($timeout);
                    }

                    elseif( $nodeName == 'term' )
                    {
                        /*
                        <term>
                            <name>798-798</name>
                            <protocol>tcp</protocol>
                            <source-port>0-65535</source-port>
                            <destination-port>798-798</destination-port>
                        </term>
                         */

                        //Todo: remove service object
                        // create servicegroup object
                        /** @var PANConf $sub */
                        $sub = $this->sub;

                        //swaschkut 20210523
                        //Todo: problem here is that service naming is not correct



                        $tmpservicegroup = $this->sub->serviceStore->find( $name );
                        #$tmpservicegroup = $this->sub->serviceStore->find( $name );

                        if( $tmpservicegroup != null && !$removed )
                        {
                            print " * object already there: ".$tmpservicegroup->name()." type: ?\n";
                            /** @var Service $tmpservice */
                            print " - remove object: ".$tmpservice->name()."\n";
                            $this->sub->serviceStore->remove( $tmpservice, true );
                            $removed = true;
                        }

                        $tmpservicegroup = $this->sub->serviceStore->find( $name );
                        if( $tmpservicegroup == null )
                        {
                            print " * create Servicegroup: ".$name."\n";
                            $tmpservicegroup = $this->sub->serviceStore->newServiceGroup( $name );
                            #$tmpservicegroup = $this->sub->serviceStore->newServiceGroup( $name );
                        }



                        $tmpservice = null;
                        $tmpservice2 = null;
                        foreach( $child->childNodes as $key2 => $child2 )
                        {
                            /** @var DOMElement $childNode */
                            if( $child2->nodeType != XML_ELEMENT_NODE )
                                continue;

                            $nodeName2 = $child2->nodeName;

                            if( $nodeName2 == 'name' )
                            {
                                $tmpproto = "";

                                $name2 = $child2->textContent;

                                $newName = $name2;
                                $tmpservice = $this->sub->serviceStore->find($newName);
                                if( $tmpservice !== null )
                                    $newName = $name."-".$name2;

                                $tmpservice = $this->sub->serviceStore->find($newName);
                                if( $tmpservice == null )
                                {
                                    $protocol = "tcp";
                                    $dstports = "65535";

                                    print "\n - create service object: " . $newName . "\n";
                                    $tmpservice = $this->sub->serviceStore->newService($newName, $protocol, $dstports);

                                    if( $tmpservicegroup !== $tmpservice )
                                    {
                                        print " - add service: ".$tmpservice->name()." to group: ".$tmpservicegroup->name()."\n";
                                        $tmpservicegroup->addMember( $tmpservice );
                                    }
                                }
                                else
                                {
                                    mwarning("address object with name: " . $newName . " already available\n");

                                    if( $tmpservicegroup !== $tmpservice )
                                    {
                                        print " - add service: ".$tmpservice->name()." to group: ".$tmpservicegroup->name()."\n";
                                        $tmpservicegroup->addMember( $tmpservice );
                                    }


                                    break;
                                }
                            }
                            elseif( $nodeName2 == 'protocol' )
                            {
                                $protocol = $child2->textContent;
                                #print "addressname: ".$name."\n";

                                if( $tmpproto == "" )
                                {
                                    if( $protocol == "tcp" || $protocol == "udp" )
                                    {
                                        $tcpudp = true;
                                        $tmpproto = $protocol;
                                        if( $tmpservice->isGroup() )
                                            print "prob: ".$tmpservice->name()."\n";
                                        print " - set protocol: ".$protocol."\n";
                                        $tmpservice->setProtocol($protocol);
                                    }

                                    else
                                    {
                                        $tmpservice2 = $this->sub->serviceStore->find("tmp-" . $tmpservice->name());
                                        if( $tmpservice2 == null )
                                        {
                                            $srv_protocol = $protocol;

                                            print "    - change name to: 'tmp-" . $tmpservice->name() . "'\n";
                                            $tmpservice->setName("tmp-" . $tmpservice->name());

                                            print "  * set description: 'protocol-id:{".$srv_protocol."}'";
                                            $tmpservice->setDescription( "protocol-id:{".$srv_protocol."}" );
                                        }
                                    }
                                }

                                elseif( $tmpservice->protocol() != $protocol )
                                {
                                    $tcpudp = true;
                                    //1) rename existing service - add protocol at beginning
                                    $tmpservice->setName( strtoupper($tmpservice->protocol())."-" . $tmpservice->name());

                                    $tmp_obj = false;
                                    if( $protocol != "tcp" || $protocol != "udp" )
                                    {
                                        $tmp_obj = true;
                                        $srv_protocol = $protocol;

                                        $tmpname = "tmp-" . $tcpudpname;
                                        $protocol = "tcp";
                                        $dstports = "65535";
                                    }
                                    else
                                        $tmpname = strtoupper($protocol)."-" . $tcpudpname;

                                    $tmpservice2 = $this->sub->serviceStore->find($tmpname );
                                    if( $tmpservice2 === null )
                                    {
                                        print "\n - create service object: " . $tmpname . "\n";
                                        $tmpservice2 = $this->sub->serviceStore->newService($tmpname, $protocol, $dstports);

                                        if( $tmp_obj )
                                        {
                                            print "  * set description: 'protocol-id:{".$srv_protocol."}'";
                                            $tmpservice2->setDescription( "protocol-id:{".$srv_protocol."}" );
                                        }

                                    }
                                    //2) create new object with - protocol_NAME -> set protocol and port

                                    // create address group with name
                                    //add both members
                                    $tmp_servicegroup = $this->sub->serviceStore->find( $tcpudpname );
                                    if( $tmp_servicegroup == null )
                                    {
                                        if( $print )
                                            print "create servicegroup Object: ".$tcpudpname."\n";
                                        $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup( $tcpudpname );
                                        $tmp_object = $this->sub->serviceStore->find('TCP-'.$tcpudpname);
                                        if( $tmp_object !== null )
                                        {
                                            $tmp_servicegroup->addMember($tmp_object);
                                        }
                                        $tmp_object = $this->sub->serviceStore->find('UDP-'.$tcpudpname);
                                        if( $tmp_object !== null )
                                        {
                                            $tmp_servicegroup->addMember($tmp_object);
                                        }
                                        if( $tmp_obj )
                                        {
                                            $tmp_object = $this->sub->serviceStore->find('tmp-'.$tcpudpname);
                                            if( $tmp_object !== null )
                                            {
                                                $tmp_servicegroup->addMember($tmp_object);
                                            }
                                        }
                                    }
                                }

                            }
                            elseif( $nodeName2 == 'source-port' )
                            {
                                $sourceport = $child2->textContent;
                                #print "addressname: ".$name."\n";

                                $tmpsrcport = $tmpservice->getSourcePort();


                                if( $sourceport != "0-65535" && $sourceport != "1-65535" )
                                {

                                    if( strpos($tmpsrcport, $sourceport) === FALSE )
                                    {
                                        if( $tmpsrcport == "" )
                                            $port = $sourceport;
                                        else
                                            $port = $tmpsrcport . "," . $sourceport;

                                        print "     - set SrcPort to: " . $port . "\n";
                                        if( $tcpudp )
                                            $tmpservice->setSourcePort($port);
                                        else
                                            $tmpservice2->setSourcePort($port);
                                    }
                                }


                            }
                            elseif( $nodeName2 == 'destination-port' )
                            {
                                $destinationport = $child2->textContent;
                                #print "addressname: ".$name."\n";
                                if( $tcpudp )
                                    $tmpdstport = $tmpservice->getDestPort();
                                elseif( $tmpservice2 !== null )
                                    $tmpdstport = $tmpservice2->getDestPort();
                                else
                                    $tmpdstport = "";

                                if( $tmpdstport == "65535" )
                                    $tmpdstport = "";

                                if( strpos($tmpdstport, $destinationport) === FALSE )
                                {
                                    if( $tmpdstport == "" )
                                        $port = $destinationport;
                                    else
                                        $port = $tmpdstport . "," . $destinationport;

                                    print "     - set DestPort to: " . $port . "\n";
                                    if( $tcpudp )
                                        $tmpservice->setDestPort($port);
                                    elseif( $tmpservice2 !== null )
                                        $tmpservice2->setDestPort($port);
                                }

                            }
                            elseif( $nodeName == 'inactivity-timeout' )
                            {
                                $timeout = $child->textContent;

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

                                if( $print )
                                    print " * set timeout to: " . $timeout . "\n";

                                if( !$tcpudp )
                                    $tmpservice->setTimeout($timeout);
                                else
                                    $tmpservice2->setTimeout($timeout);
                            }

                            #if( $tmpservice->getDestPort() == "65535" )
                            #    $tmpservice->setDestPort("0-65535");
                        }

                    }
                    else
                        mwarning("was not found", $child);
                }
            }
            elseif( $nodeName == "application-set" )
            {
                // - ServicesGroups
                //$address = $configuration->xpath("/configuration/applications/application-set");
                /*
                <application-set>
                    <name>appSrvRobotToDevicesGrp</name>
                    <application>
                        <name>junos-icmp-all</name>
                    </application>
                    <application>
                        <name>snmp-161</name>
                    </application>
                    <application>
                        <name>ssh-22</name>
                    </application>
                </application-set>
                 */
                foreach( $childNode->childNodes as $key => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    #$tmpservicegroup = null;

                    $nodeName = $child->nodeName;

                    if( $nodeName == 'name' )
                    {
                        $name = $child->textContent;
                        #print "addressname: ".$name."\n";

                        $tmpservicegroup = $this->sub->serviceStore->find($name);

                        if( $tmpservicegroup == null )
                        {
                            print "\n - create servicegroup object: " . $name . "\n";
                            $tmpservicegroup = $this->sub->serviceStore->newServiceGroup($name);
                        }
                        else
                        {
                            mwarning("service object with name: " . $name . " already available\n");
                            continue;
                        }


                    }
                    elseif( $nodeName == 'application' )
                    {
                        $servicename = DH::findFirstElement('name', $child);
                        if( $servicename === FALSE )
                            derr("<name> was not found", $child);

                        $servicename = $servicename->textContent;
                        #print "addressname: ".$name."\n";

                        $servicename = $this->truncate_names( $this->normalizeNames( $servicename ) );

                        #print "   - find service : ".$servicename."\n";
                        $tmpservice = $this->sub->serviceStore->find($servicename);
                        if( $tmpservice == null )
                        {
                            #print "   - find service : tmp-".$servicename."\n";
                            $tmpservice = $this->sub->serviceStore->find("tmp-" . $servicename);
                        }

                        if( $tmpservice != null )
                        {
                            print "   - add object: " . $tmpservice->name() . "\n";
                            $tmpservicegroup->addMember($tmpservice);
                        }
                        else
                            mwarning("object not found: " . $servicename);
                    }
                }
            }
            else
                mwarning("was not found", $childNode);
        }
    }
}