<?php


trait SRXinterfaces
{
#function get_Interfaces_new($configuration, $vsys, $source, $template) {
    function get_Interfaces_new($configRoot, $shared = false)
    {
        global $debug;
        global $print;

        global $LSYS_bool;
        //$configRoot /configuration/interfaces

        $ae_array = array();

        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $interfaceName = "";
            $comment = "";
            $create_subinterface = FALSE;
            $tmp_int_main = null;
            $isTunnel = false;

            foreach( $childNode->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $nodeName = $node->nodeName;

                if( $LSYS_bool && (
                        #preg_match("/^ge-/", $interfaceName) ||
                        #preg_match("/^ae/", $interfaceName) ||
                        preg_match("/^fxp/", $interfaceName) ||
                        preg_match("/^fab/", $interfaceName)
                    )
                )
                {
                    continue;
                }


                if( $nodeName == 'name' )
                {
                    $interfaceName = $node->textContent;
                    $interfaceName = $this->interfaceRename( $interfaceName );

                    if( $LSYS_bool && (
                            #preg_match("/^ge-/", $interfaceName) ||
                            #preg_match("/^ae/", $interfaceName) ||
                            preg_match("/^fxp/", $interfaceName) ||
                            preg_match("/^fab/", $interfaceName)
                        )
                    )
                    {
                        continue;
                    }

                    /** @var EthernetInterface $tmp_int_main */
                    $tmp_int_main = $this->template->network->findInterface($interfaceName);
                    if( $tmp_int_main === null )
                    {
                        /*

                            */
                        if( $LSYS_bool && (
                                #preg_match("/^ge-/", $interfaceName) ||
                                #preg_match("/^ae/", $interfaceName) ||
                                preg_match("/^fxp/", $interfaceName) ||
                                preg_match("/^fab/", $interfaceName)
                            )
                        )
                        {
                            continue;
                        }
                        elseif( preg_match("/^lo/", $interfaceName) )
                        {
                            $tmp_name = explode( "lo", $interfaceName );
                            $tmp_counter = $tmp_name[1]+1;
                            $interfaceName = "loopback.".$tmp_counter;

                            $tmp_int_main = $this->template->network->loopbackIfStore->newLoopbackIf($interfaceName);
                        }
                        elseif( preg_match("/^st0/", $interfaceName) )
                        {
                            $isTunnel = true;
                            #$interfaceName = "tunnel";
                        }
                        elseif( preg_match("/^ae/", $interfaceName) )
                        {
                            /** @var PANConf $sub */
                            $sub = $this->template;


                            $tmp_int_main = $this->template->network->aggregateEthernetIfStore->newEthernetIf($interfaceName, 'layer3');

                            $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                            if( $print )
                                print "* create ethernet interface with name: " . $interfaceName . "\n";
                            

                            if( isset( $ae_array[ $interfaceName] ) )
                            {
                                print "change interface to aggegrate-ethernet: ".$ae_array[ $interfaceName]->name()."\n";

                                //type  must be set to aggregate-group

                                /** @var EthernetInterface $tmp_int */
                                $tmp_int = $ae_array[ $interfaceName];

                                print " * set AE: ".$interfaceName." on interface: ".$tmp_int->name()."\n";
                                $tmp_int->setAE( $interfaceName );
                            }
                        }
                        else
                        {
                            $int_type = 'layer3';

                            //Todo: check if gigether-options/ieee-802.3ad/bundle is avaialble
                            $tmp_node = DH::findFirstElement( "gigether-options", $childNode );
                            if( $tmp_node !==  false )
                            {
                                #print "found gigether-options\n";
                                $tmp_node = DH::findFirstElement( "ieee-802.3ad", $tmp_node );
                                if( $tmp_node !==  false )
                                {
                                    #print "found ieee-802.3ad\n";
                                    $tmp_node = DH::findFirstElement( "bundle", $tmp_node );
                                    if( $tmp_node !==  false )
                                    {
                                        #print "found bundle\n";
                                        $int_type = 'aggregate-group';
                                    }

                                }

                            }
                            else
                                print "not found gigether-options\n";





                            $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($interfaceName, $int_type);

                            if( $int_type == "layer3" )
                                $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                            if( $print )
                                print "* create ethernet ".$int_type." interface with name: " . $interfaceName . "\n";


                        }

                    }

                    $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter( $this->template_vsys->name()."_router" );
                    if( $tmp_vr != null )
                        $tmp_vr->attachedInterfaces->addInterface($tmp_int_main);

                }
                elseif( $nodeName == "description" )
                {
                    $comment = $node->textContent;
                    if( $print )
                        print "  * description: " . $comment . "\n";
                    $tmp_int_main->description = $comment;
                }
                elseif( $nodeName == "vlan-tagging" )
                {
                    $create_subinterface = TRUE;
                    #print "create subinterfaces\n";
                }
                elseif( $nodeName == "unit" )
                {
                    #print_xmlNode( $node );

                    $tmp_sub = null;
                    foreach( $node->childNodes as $unit )
                    {
                        if( $unit->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $nodeName = $unit->nodeName;

                        if( $nodeName == 'name' )
                        {
                            $tmpunit = $unit->textContent;
                            $tmp_name = $interfaceName . "." . $tmpunit;

                            #print "subname: ".$tmp_name."\n";
                            //PAN-OS subinterface .0 is not possible => main interface
                            if( $tmpunit != 0 ){
                                $tmp_sub = $this->template->network->findInterface($tmp_name);
                                if( $tmp_sub === null )
                                {

                                    if( $isTunnel )
                                    {
                                        if( $print )
                                            print "\n  * create tunnel interface: " . $tmp_name . "\n";

                                        $tmp_sub = $this->template->network->tunnelIfStore->newTunnelIf($tmp_name);
                                        $tmp_int_main = $tmp_sub;

                                    }
                                    else
                                    {
                                        if( $print )
                                            print "\n  * add subinterface: with name/vlan: " . $tmp_name . "\n";
                                        $tmp_sub = $tmp_int_main->addSubInterface($tmpunit);
                                        $create_subinterface = TRUE;
                                    }

                                    $this->template_vsys->importedInterfaces->addInterface($tmp_sub);
                                }

                                $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter( $this->template_vsys->name()."_router" );
                                if( $tmp_vr != null )
                                    $tmp_vr->attachedInterfaces->addInterface($tmp_sub);
                            }
                            else
                            {
                                #print "add IP to main interface\n";}
                            }

                        }
                        elseif( $nodeName == "description" )
                        {
                            $comment = $unit->textContent;

                            if( is_object( $tmp_sub ) )
                            {
                                if( $print )
                                    print "    * description: " . $comment . "\n";
                                $tmp_sub->description = $comment;
                            }


                        }
                        elseif( $nodeName == "vlan-id" )
                        {
                            $unitTag = $unit->textContent;
                        }
                        elseif( $nodeName == "family" )
                        {
                            $tmp_inet = DH::findFirstElement('inet', $unit);

                            if( is_object( $tmp_inet ) )
                                foreach( $tmp_inet->childNodes as $child_address )
                            {
                                if( $unit->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $nodeName = $child_address->nodeName;
                                if( $nodeName == "address" )
                                {
                                    $tmp_ip_address = DH::findFirstElement('name', $child_address);
                                    $tmp_ip_address = $tmp_ip_address->textContent;

                                    if( $create_subinterface )
                                    {
                                        $tmp_sub->addIPv4Address($tmp_ip_address);
                                    }
                                    else
                                    {
                                        $tmp_int_main->addIPv4Address($tmp_ip_address);
                                    }
                                    if( $print )
                                        print "    * add IP-adddress: " . $tmp_ip_address . "\n";
                                }
                                elseif( $nodeName == "filter" )
                                {
                                    $inOutArray = array('input', 'output');
                                    foreach( $inOutArray as $inOut )
                                    {
                                        $tmp_filter_input = DH::findFirstElement($inOut, $child_address);
                                        if( $tmp_filter_input != false )
                                        {
                                            $tmp_filter_name = DH::findFirstElement('filter-name', $tmp_filter_input);
                                            $tmp_filter_name = $tmp_filter_name->textContent;

                                            if( $create_subinterface )
                                                if( $inOut == 'input' )
                                                    $this->filterInputInterface[$tmp_filter_name][] = $tmp_sub->name();
                                                else
                                                    $this->filterOutputInterface[$tmp_filter_name][] = $tmp_sub->name();
                                            else
                                                if( $inOut == 'input' )
                                                    $this->filterInputInterface[$tmp_filter_name][] = $tmp_int_main->name();
                                                else
                                                    $this->filterOutputInterface[$tmp_filter_name][] = $tmp_int_main->name();
                                        }
                                        else
                                        {
                                            $inputLists = $child_address->getElementsByTagName( $inOut.'-list' );

                                            foreach( $inputLists as $inputList )
                                            {
                                                $tmp_filter_name = $inputList->textContent;

                                                if( $create_subinterface )
                                                    if( $inOut == 'input' )
                                                        $this->filterInputInterface[$tmp_filter_name][] = $tmp_sub->name();
                                                    else
                                                        $this->filterOutputInterface[$tmp_filter_name][] = $tmp_sub->name();
                                                else
                                                    if( $inOut == 'input' )
                                                        $this->filterInputInterface[$tmp_filter_name][] = $tmp_int_main->name();
                                                    else
                                                        $this->filterOutputInterface[$tmp_filter_name][] = $tmp_int_main->name();
                                            }
                                        }
                                    }


                                }
                            }
                        }
                    }
                }
                elseif( $nodeName == "gigether-options" )
                {
                    /*
                     *  <interface>
                    <name>ge-0/0/0</name>
                    <gigether-options>
                        <ieee-802.3ad>
                            <bundle>ae0</bundle>
                        </ieee-802.3ad>
                    </gigether-options>
                </interface>
                     */
                    foreach( $node->childNodes as $childNode )
                    {
                        if( $childNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $nodeName2 = $childNode->nodeName;

                        if( $nodeName2 == 'ieee-802.3ad' )
                        {
                            #
                            $bundle_element = DH::findFirstElement( "bundle", $childNode );
                            #$bundle_element = $childNode->firstChild;
                            $ae_name = $bundle_element->textContent;

                            #print "AE: ".$ae_name."\n";
                            #print "intname: ".$tmp_int_main->name()."\n";

                            $tmp_counter = explode( "ae", $ae_name );
                            $tmp_counter = intval( $tmp_counter[1] )+1;
                            $ae_array[ "ae".$tmp_counter ] = $tmp_int_main;
                        }
                        else
                        {
                            mwarning("node: '" . $nodeName . "' not covered\n", null, FALSE);
                        }
                    }
                }
                elseif( $nodeName == "redundant-ether-options" || $nodeName == "gratuitous-arp-reply" || $nodeName == "fabric-options" )
                {
                    mwarning("node: '" . $nodeName . "' not covered\n", null, FALSE);
                }
                else
                {
                    mwarning("node: '" . $nodeName . "' not covered\n");
                }
            }
        }
    }

}
