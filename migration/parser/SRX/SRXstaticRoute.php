<?php


trait SRXstaticRoute
{
    /*
    <routing-instances>
        <instance>
            <name>GinEfa-VR</name>
            <instance-type>virtual-router</instance-type>
            <interface>
                <name>reth2.2541</name>
            </interface>
            <routing-options>
                <static>
                    <route>
                        <name>10.11.150.63/32</name>
                        <next-hop>10.11.163.249</next-hop>
                    </route>
                    <route>
                        <name>10.11.150.64/32</name>
                        <next-hop>10.11.163.249</next-hop>
                    </route>
                    <route>
                        <name>10.11.151.63/32</name>
                        <next-hop>10.11.163.249</next-hop>
                    </route>
     */

    /**
     * @param DomElement $configRoot
     * @param VirtualSystem $v
     * @return null
     */
    function get_XML_staticRoutes($configRoot, $shared = false, $tmp_vr)
    {
        global $debug;
        global $print;
        //$configRoot /configuration/routing-instances




        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            if( $nodeName == 'instance' )
            {
                foreach( $childNode->childNodes as $key2 => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName = $child->nodeName;

                    if( $nodeName == 'name' )
                    {
                        $vrname = $child->textContent;
                        print "instancename: " . $vrname . "\n";

                    }
                    elseif( $nodeName == "instance-type" )
                    {
                        $instancetype = $child->textContent;
                        print "instancetype: " . $instancetype . "\n";

                        if( $instancetype == "virtual-router" || $instancetype == "forwarding" )
                        {
                            //todo: create virtual-router
                            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vrname);
                            $this->template_vsys->importedVirtualRouter->addVirtualRouter($tmp_vr);
                        }
                        else
                            mwarning("instance-type: " . $instancetype . " not supported yet");

                    }
                    elseif( $nodeName == "interface" )
                    {
                        $interface = DH::findFirstElement('name', $child);
                        $interface = $interface->textContent;

                        $interface = $this->interfaceRename( $interface );

                        print "     - find interface: " . $interface . "\n";
                        $tmpinterface = $this->template->network->findInterfaceOrCreateTmp($interface);

                        $this->template_vsys->importedInterfaces->addInterface($tmpinterface);
                        //search now for interface and add it to virtual router
                        print "     - add interface: " . $tmpinterface->name() . " to virtual-router\n";
                        $tmp_vr->attachedInterfaces->addInterface($tmpinterface);

                    }
                    elseif( $nodeName == "routing-options" )
                    {
                        $this->addRoutingOptions( $child, $tmp_vr );
                    }
                }
            }
        }
    }

    public function addRoutingOptions( $child, $tmp_vr )
    {
        global $print;

        $static = DH::findFirstElement('static', $child);
        if( $static != null )
        {
            $isNextVr = FALSE;
            foreach( $static->childNodes as $key3 => $child2 )
            {
                /** @var DOMElement $childNode */
                if( $child2->nodeType != XML_ELEMENT_NODE )
                    continue;


                $nodeName = $child2->nodeName;
                if( $nodeName == 'route' )
                {
                    $isNextVr = FALSE;
                    $routename = DH::findFirstElement('name', $child2);
                    $routename = $routename->textContent;

                    $routenexthop = DH::findFirstElement('next-hop', $child2);
                    if( $routenexthop != null )
                        $routenexthop = $routenexthop->textContent;
                    else
                        $routenexthop = "";


                    $routenext_table = DH::findFirstElement('next-table', $child2);
                    if( $routenext_table != null )
                    {
                        $isNextVr = TRUE;

                        $routenext_table = $routenext_table->textContent;
                        $nextVRname = explode(".", $routenext_table);
                        $routenexthop = $nextVRname[0];
                    }

                    else
                        $routenext_table = "";

                    /*
                    if ($zoneName!="")
                    {
                        if( isset( $interfaceMapping[$zoneName] ) )
                            $interfaceto=$interfaceMapping[$zoneName];
                        else
                        {
                            mwarning( "no interface mapping available for zone: ".$zoneName , null, false);
                            $interfaceto="";
                        }

                    }
                    else{
                        $interfaceto="";
                    }


                    $xml_interface = "";
                    if( $interfaceto !== "" )
                    {
                        $xml_interface = "<interface>".$interfaceto."</interface>";
                        $tmp_interface = $this->template->network->find( $interfaceto );
                        if( $tmp_interface != null )
                        {
                            $tmp_vr->attachedInterfaces->addInterface( $tmp_interface);
                        }
                    }
                    */

                    $xml_interface = "";
                    $interfaceto = "";

                    $route_type = "ip-address";
                    $ip_gateway = $routenexthop;
                    $metric = 10;
                    $route_network = $routename;
                    $routename = str_replace("/", "_", $routename);

                    if( $isNextVr )
                        $nexthop = "<next-vr>" . $ip_gateway . "</next-vr>";
                    else
                        $nexthop = "<ip-address>" . $ip_gateway . "</ip-address>";

                    #if( $ip_version == "v4" )
                    $xmlString = "<entry name=\"" . $routename . "\"><nexthop>" . $nexthop . "</nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";
                    #elseif( $ip_version == "v6" )
                    #    $xmlString = "<entry name=\"".$routename."\"><nexthop><ipv6-address>".$ip_gateway."</ipv6-address></nexthop><metric>".$metric."</metric>".$xml_interface."<destination>".$route_network."</destination></entry>";

                    $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                    $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

                    if( $print )
                        print " * add static route: " . $tmpRoute->name() . " with Destination: " . $route_network . " - IP-Gateway: " . $ip_gateway . " - Interface: " . $interfaceto . "\n";

                    #if( $ip_version == "v4" )
                    $tmp_vr->addstaticRoute($tmpRoute);
                    #elseif( $ip_version == "v6" )
                    #    $tmp_vr->addstaticRoute( $tmpRoute, 'ipv6' );

                }

            }
        }
    }
}