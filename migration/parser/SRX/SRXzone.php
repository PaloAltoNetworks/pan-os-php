<?php


trait SRXzone
{
    /**
     * @param DomElement $configRoot
     * @param VirtualSystem $v
     * @return null
     */
    function get_XML_Zones($configRoot, $shared)
    {
        global $debug;
        global $print;
        //$configRoot /configuration/security/zones



        /*
        <functional-zone>
            <management>
                <interfaces>
                    <name>reth3.0</name>
                    <host-inbound-traffic>
                        <system-services>
                            <name>ping</name>
                        </system-services>
                    </host-inbound-traffic>
                </interfaces>
            </management>
        </functional-zone>
        <security-zone>
            <name>zonePublicEbiz</name>
            <screen>zonePublicEbiz</screen>
            <interfaces>
                <name>reth1.2700</name>
            </interfaces>
            <interfaces>
                <name>reth2.2709</name>
            </interfaces>
        </security-zone>
         */

        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            if( $nodeName == 'security-zone' )
            {
                $tmp_zone = null;
                foreach( $childNode->childNodes as $key => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName = $child->nodeName;

                    if( $nodeName == 'name' )
                    {
                        $zonename = $child->textContent;
                        //create Zone
                        $tmp_zone = $this->template_vsys->zoneStore->find($zonename);
                        if( $tmp_zone == null )
                        {
                            print " - create Zone: " . $zonename . "\n";
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($zonename, 'layer3');
                        }
                    }
                    elseif( $nodeName == 'screen' )
                    {
                        //what todo????
                    }
                    elseif( $nodeName == 'interfaces' )
                    {
                        $interfacename = DH::findFirstElement('name', $child);
                        $interfacename = $interfacename->textContent;

                        $interfacename = $this->interfaceRename( $interfacename );
                        
                        $tmp_interface = $this->template->network->findInterfaceOrCreateTmp($interfacename);

                        print "    - add interface: " . $tmp_interface->name() . "\n";
                        $tmp_zone->attachedInterfaces->addInterface($tmp_interface);
                    }
                    elseif( $nodeName == "address-book" )
                    {
                        $this->get_XML_Zones_Address_All_new2($child);
                    }
                }


            }
            elseif( $nodeName == 'functional-zone' )
            {

            }

        }
    }
}