<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

class NatRule extends Rule
{

    /** @var null|Service|ServiceGroup $service Destination port associated to this NatRule. Null means 'any' */
    public $service = null;

    protected $snattype = 'none';

    /** @var AddressRuleContainer|null */
    public $snathosts = null;

    /** @var null|string */
    public $snatinterface = null;

    private $_snatbidir = 'no';

    private $_snatUsesFloatingIP = FALSE;

    /** @var null|Address|AddressGroup */
    public $dnathost = null;

    public $dnattype = "none";

    /** @var null|string */
    public $dnatports = null;

    /** @var null|DOMElement */
    public $snatroot = null;

    /**  @var null|DOMElement
     * @ignore
     */
    public $dnatroot = array();
    /** @ignore */
    public $serviceroot = null;

    /** @var null|EthernetInterface|AggregateEthernetInterface|IPsecTunnel|LoopbackInterface|TmpInterface */
    protected $_destinationInterface = null;

    static public $templatexml = '<entry name="**temporarynamechangeme**"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination><service>any</service><disabled>no</disabled></entry>';
    static protected $templatexmlroot = null;

    /**
     * @param RuleStore $owner
     * @param bool $fromTemplateXML
     */
    public function __construct($owner, $fromTemplateXML = FALSE)
    {
        $this->owner = $owner;

        $this->parentAddressStore = $this->owner->owner->addressStore;
        $this->parentServiceStore = $this->owner->owner->serviceStore;

        $this->tags = new TagRuleContainer($this);

        $this->from = new ZoneRuleContainer($this);
        $this->from->name = 'from';
        $this->from->parentCentralStore = $owner->owner->zoneStore;

        $this->to = new ZoneRuleContainer($this);
        $this->to->name = 'to';
        $this->to->parentCentralStore = $owner->owner->zoneStore;

        $this->source = new AddressRuleContainer($this);
        $this->source->name = 'source';
        $this->source->parentCentralStore = $this->parentAddressStore;

        $this->destination = new AddressRuleContainer($this);
        $this->destination->name = 'destination';
        $this->destination->parentCentralStore = $this->parentAddressStore;

        $this->snathosts = new AddressRuleContainer($this);
        $this->snathosts->name = 'snathosts';
        $this->snathosts->parentCentralStore = $this->parentAddressStore;

        if( $fromTemplateXML )
        {
            $xmlElement = DH::importXmlStringOrDie($owner->xmlroot->ownerDocument, self::$templatexml);
            $this->load_from_domxml($xmlElement);
        }
    }


    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("name not found\n");

        $this->load_common_from_domxml();
        //print "found rule name '".$this->name."'\n";

        $this->load_from();
        $this->load_to();
        $this->load_source();
        $this->load_destination();


        //						//
        // to-interface properties Extraction	//
        //						//
        $toInterface = DH::findFirstElement('to-interface', $xml);
        if( $toInterface !== FALSE )
        {
            if( strtolower($toInterface->textContent) != 'any' )
            {
                $this->_destinationInterface = $toInterface->textContent;

                #$tmp_interface = $this->owner->owner->owner->network->findInterface( $this->_destinationInterface );
                #$tmp_interface->addReference( $this );
            }

        }
        // end of to-interface extraction


        //						                    //
        // Destination NAT properties Extraction	//
        //						                    //
        $this->dnatroot = DH::findFirstElement('destination-translation', $xml);
        if( $this->dnatroot === FALSE )
        {
            $this->dnatroot = DH::findFirstElement('dynamic-destination-translation', $xml);
            $this->dnattype = 'dynamic';
        }
        else
            $this->dnattype = 'static';


        if( $this->dnatroot !== FALSE )
        {
            //print "rule '".$this->name."' has destination-translation\n";
            if( $this->dnatroot->hasChildNodes() )
            {
                $this->subdnatTAroot = DH::findFirstElement('translated-address', $this->dnatroot);
                if( $this->subdnatTAroot !== FALSE )
                {
                    $f = $this->parentAddressStore->findOrCreate($this->subdnatTAroot->textContent, $this);

                    $this->dnathost = $f;

                    $this->subdnatTProot = DH::findFirstElement('translated-port', $this->dnatroot);
                    if( $this->subdnatTProot !== FALSE )
                    {
                        $this->dnatports = $this->subdnatTProot->textContent;
                        if( strlen($this->dnatports) < 0 )
                            $this->dnatports = null;
                    }
                }
            }
        }
        // end of destination translation extraction


        //										//
        // Source NAT properties Extraction		//
        //										//
        $this->snatroot = DH::findFirstElement('source-translation', $xml);
        if( $this->snatroot !== FALSE )
        {
            //print "we have found a source NAT\n";
            // next <tag> will determine NAT type
            $firstE = DH::firstChildElement($this->snatroot);
            $this->snattype = $firstE->nodeName;

            // Do we support this type of NAT ?
            if( $this->snattype != "static-ip" && $this->snattype != "dynamic-ip-and-port" && $this->snattype != "dynamic-ip" )
                derr("SNAT type '" . $this->snattype . "' for rule '" . $this->name . "' is not supported, EXIT\n");

            //print "Determined NAT type ".$tcur['name']."\n";


            if( $this->snattype == "static-ip" )
            {
                $isbidrx = DH::findFirstElement('bi-directional', $firstE);
                if( $isbidrx !== FALSE )
                {
                    $this->_snatbidir = $isbidrx->textContent;
                    if( $this->_snatbidir != 'yes' && $this->_snatbidir != 'no' )
                    {
                        mwarning("unsupported bi-directional value: {$this->_snatbidir}, assumed 'no' as a fix", $this->xmlroot);
                        $this->_snatbidir = 'no';
                    }
                }
                $transladx = DH::findFirstElement('translated-address', $firstE);

                if( $transladx === FALSE )
                    mwarning('invalid nat rule with missing "translated-address". Rule: ' . $this->name);

                $transladx = DH::findFirstElementOrCreate('translated-address', $firstE);

                $fad = $this->parentAddressStore->findOrCreate($transladx->textContent);

                $this->snathosts->addObject($fad);
                $this->snathosts->xmlroot = $transladx;
            }
            else if( $this->snattype == "dynamic-ip" )
            {
                $subtype = DH::findFirstElement('translated-address', $firstE);
                if( $subtype === FALSE )
                    mwarning('invalid nat rule with missing "translated-address". Rule: ' . $this->name);

                $subtype = DH::findFirstElementOrCreate('translated-address', $firstE);

                if( DH::firstChildElement($subtype) === FALSE )
                {
                    // this rule has no address specified
                    mwarning('invalid nat rule with missing "<member>"', $subtype);
                }
                else
                {
                    foreach( $subtype->childNodes as $node )
                    {
                        if( $node->nodeType != 1 ) continue;
                        $translad = $this->parentAddressStore->findOrCreate($node->textContent);
                        $this->snathosts->addObject($translad);
                    }

                    $this->snathosts->xmlroot = $subtype;

                }
            }
            else if( $this->snattype == "dynamic-ip-and-port" )
            {
                // Is it <translated-address> type ?
                $subtype = DH::findFirstElement('translated-address', $firstE);

                if( $subtype !== FALSE )
                {
                    if( DH::firstChildElement($subtype) === FALSE )
                    {
                        // this rule has no address specified
                    }
                    else
                    {
                        foreach( $subtype->childNodes as $node )
                        {
                            if( $node->nodeType != 1 ) continue;
                            $translad = $this->parentAddressStore->findOrCreate($node->textContent);
                            $this->snathosts->addObject($translad);
                        }

                        $this->snathosts->xmlroot = $subtype;

                    }

                }
                else
                {
                    $subtype = DH::findFirstElement('interface-address', $firstE);
                    if( $subtype !== FALSE )
                    {
                        if( DH::firstChildElement($subtype) === FALSE )
                            derr("Cannot understand dynmaic NAT for rule '" . $this->name . "'\n");

                        foreach( $subtype->childNodes as $node )
                        {
                            if( $node->nodeType != 1 ) continue;

                            if( $node->nodeName == 'interface' )
                            {
                                $this->snatinterface = $node->textContent;

                                #$tmp_interface = $this->owner->owner->owner->network->findInterface($this->snatinterface);
                                #$tmp_interface->addReference( $this );

                            }
                            else if( $node->nodeName == 'ip' )
                            {
                                $translad = $this->parentAddressStore->findOrCreate($node->textContent);
                                $this->snathosts->addObject($translad);
                            }
                            else if( $node->nodeName == 'floating-ip' )
                            {
                                $translad = $this->parentAddressStore->findOrCreate($node->textContent);
                                $this->snathosts->addObject($translad);
                                $this->_snatUsesFloatingIP = TRUE;
                            }
                            else
                                derr("Cannot understand dynamic NAT for rule '" . $this->name . "'\n");
                        }
                    }
                    else
                    {
                        mwarning("Unknown dynamic SNAT type on rule '" . $this->name . " don't mess too much with this rule or face unpredictable results");
                    }
                }


            }

        }
        //
        // End of Source NAT properties extraction	//


        //  								//
        //	Begin of <service> extraction	//
        //								    //
        $this->serviceroot = DH::findFirstElementOrCreate('service', $xml, 'any');
        if( $this->serviceroot !== FALSE )
        {
            $lname = $this->serviceroot->textContent;
            if( strtolower($lname) != 'any' )
            {
                //print "found service named $lname in  NAT rule '".$this->name."'\n";
                $f = $this->parentServiceStore->findOrCreate($lname, $this, TRUE);
                if( !$f )
                {
                    derr("Error: service object named '$lname' not found in NAT rule '" . $this->name . "'\n");
                }

                $this->service = $f;
            }
        }
        else
        {
            derr('unexpected error');
        }
        // End of <service> extraction 	//


    }


    public function referencedObjectRenamed($h, $oldname = "")
    {
        if( $this->service === $h )
        {
            $this->rewriteService_XML();
            return;
        }
        if( $this->dnathost === $h )
        {
            $this->rewriteDNAT();
            return;
        }
        if( $this->snatinterface === $oldname )
        {
            $this->snatinterface = $h->name();
            $this->rewriteSNAT_XML();
            return;
        }

        mwarning("object is not part of this nat rule : {$h->toString()}");
    }

    /**
     * @param ReferenceableObject $old
     * @param ReferenceableObject $new
     * @return bool
     * @throws Exception
     */
    public function replaceReferencedObject($old, $new)
    {
        if( $this->service === $old )
        {
            /** @var Service|ServiceGroup $old */
            /** @var Service|ServiceGroup $new */

            $this->service = $new;
            $this->rewriteService_XML();
            $old->removeReference($this);
            $new->addReference($this);
            return TRUE;
        }
        if( $this->dnathost === $old )
        {
            /** @var Address|AddressGroup $old */
            /** @var Address|AddressGroup $new */

            $this->setDNAT($new, $this->dnatports);

            return TRUE;
        }

        mwarning("object is not part of this nat rule : {$old->toString()}");

        return FALSE;
    }

    /**
     * @param $old AddressGroup|Address|Service|ServiceGroup
     * @param $new Address|AddressGroup|Service|ServiceGroup
     * @return bool
     * @throws Exception
     */
    public function API_replaceReferencedObject($old, $new)
    {
        if( $this->service === $old )
        {
            $this->service = $new;
            $this->rewriteService_XML();
            $old->removeReference($this);
            $new->addReference($this);
            $xpath = DH::elementToPanXPath($this->serviceroot);
            $connector = findConnectorOrDie($this);
            $connector->sendEditRequest($xpath, DH::dom_to_xml($this->serviceroot, -1, FALSE), TRUE);
            return TRUE;
        }
        if( $this->dnathost === $old )
        {
            $this->setDNAT($new, $this->dnatports);

            $xpath = DH::elementToPanXPath($this->dnatroot);
            $connector = findConnectorOrDie($this);
            $connector->sendEditRequest($xpath, DH::dom_to_xml($this->dnatroot, -1, FALSE), TRUE);

            return TRUE;
        }

        mwarning("object is not part of this nat rule : {$old->toString()}");

        return FALSE;
    }


    public function rewriteSNAT_XML()
    {
        if( $this->snattype == 'none' )
        {
            if( $this->snatroot !== null )
                $this->xmlroot->removeChild($this->snatroot);
            $this->snatroot = null;
            return;
        }

        $this->snatroot = DH::createOrResetElement($this->xmlroot, 'source-translation');


        if( $this->snattype == 'dynamic-ip-and-port' )
        {
            $subroot = DH::createOrResetElement($this->snatroot, 'dynamic-ip-and-port');

            if( $this->snatinterface === null )
            {
                $subsubroot = DH::createOrResetElement($subroot, 'translated-address');
                $translatedObjects = $this->snathosts->all();

                DH::Hosts_to_xmlDom($subsubroot, $translatedObjects, 'member', FALSE);
            }
            else
            {
                $subsubroot = DH::createOrResetElement($subroot, 'interface-address');

                DH::createOrResetElement($subsubroot, 'interface', $this->snatinterface);
                #$tmp_interface = $this->owner->owner->owner->network->findInterface($this->snatinterface);
                #$tmp_interface->addReference( $this );

                $snatIP = $this->snathosts->all();
                if( count($snatIP) > 0 )
                {
                    if( $this->_snatUsesFloatingIP )
                        DH::createOrResetElement($subsubroot, 'floating-ip', reset($snatIP)->name());
                    else
                        DH::createOrResetElement($subsubroot, 'ip', reset($snatIP)->value());
                }

            }
        }
        elseif( $this->snattype == 'dynamic-ip' )
        {
            $subroot = DH::createOrResetElement($this->snatroot, 'dynamic-ip');

            $subsubroot = DH::createOrResetElement($subroot, 'translated-address');
            $translatedObjects = $this->snathosts->all();

            DH::Hosts_to_xmlDom($subsubroot, $translatedObjects, 'member', FALSE);
        }
        else if( $this->snattype == 'static-ip' )
        {
            $subroot = DH::createOrResetElement($this->snatroot, 'static-ip');


            foreach( $this->snathosts->all() as $obj )
            {
                $subsubroot = DH::createOrResetElement($subroot, 'translated-address', $obj->name());
            }

            DH::createOrResetElement($subroot, 'bi-directional', $this->_snatbidir);
        }
        else
            derr("NAT type not supported for rule '" . $this->snattype . "'\n");

        //print_r($this->snatroot);

        $this->snathosts->xmlroot = $subsubroot;

    }


    /**
     * @param bool $yes
     */
    public function setBiDirectional($yes)
    {
        if( $this->snattype != 'static-ip' )
        {
            mwarning( "setBiDirectional cannot be set on snattype: ".$this->snattype." - it must be 'static-ip'\n" );
            return;
            #derr('You cannot do this on non static NATs');
        }


        if( is_string($yes) )
        {
            if( $yes == 'yes' || $yes == 'no' )
            {
                $this->_snatbidir = $yes;
            }
            else
            {
                derr("This value is not supported: '$yes'");
            }
        }
        else
        {
            if( $yes === TRUE || $yes === FALSE )
            {
                $this->_snatbidir = boolYesNo($yes);
            }
            else
            {
                derr("This value is not supported: '$yes'");
            }
        }



        $this->rewriteSNAT_XML();
    }

    /**
     * @return bool
     */
    public function isBiDirectional()
    {
        return yesNoBool($this->_snatbidir);
    }

    public function changeSourceNAT($newtype, $interface = null, $bidirectional = FALSE)
    {
        if( $newtype == 'static-ip' )
            $this->snattype = $newtype;
        elseif( $newtype == 'dynamic-ip-and-port' )
            $this->snattype = $newtype;
        elseif( $newtype == 'dynamic-ip' )
            $this->snattype = $newtype;
        elseif( $newtype == 'none' )
        {
            $this->snatroot = null;
        }
        else
            derr('not supported yet');

        $this->rewriteSNAT_XML();
    }

    /**
     * Reset DNAT to none
     *
     */
    public function setNoDNAT()
    {
        if( $this->dnathost === null )
            return;

        $this->dnathost->removeReference($this);
        $this->dnathost = null;
        $this->dnatports = null;

        $this->dnatroot->parentNode->removeChild($this->dnatroot);

        return TRUE;
    }

    public function API_setNoDNAT()
    {
        $ret = $this->setNoDNAT();
        if( $ret )
        {
            $connector = findConnectorOrDie($this);
            $xpath = $this->getXPath() . '/destination-translation';

            $connector->sendDeleteRequest($xpath);

        }

        return $ret;
    }

    /**
     * @param Address|AddressGroup $host
     * @param null $ports
     * @return bool
     * @throws Exception
     */
    public function setDNAT($host, $ports = null, $type = 'static')
    {
        if( $host === null )
            derr(" Host cannot be NULL");

        if( !is_object($host) )
            derr("Host must be an address object");

        if( is_object($ports) )
            derr("ports must be NOT a service object");

        if( $host === $this->dnathost && $ports === $this->dnatports && $type == $this->dnattype )
            return FALSE;

        if( $this->dnathost !== null )
        {
            if( !$this->snathosts->has($host) )
                $this->dnathost->removeReference($this);
        }

        if( $type != 'static' && $type != 'dynamic' && $type != 'none' )
            derr( "DNAT type support only static, dynamic or none. send: '".$type."'" );

        $this->dnattype = $type;

        $this->dnathost = $host;
        $host->addReference($this);

        if( is_numeric($ports) && $ports > 0 && $ports < 65535 )
            $this->dnatports = $ports;
        elseif( $ports != "" )
        {
            mwarning("port: " . $ports . " can not be set");
        }



        $this->rewriteDNAT();



        return TRUE;
    }

    public function API_setDNAT($host, $ports = null, $type = 'static')
    {
        $ret = $this->setDNAT($host, $ports, $type);
        if( $ret )
        {
            $connector = findConnectorOrDie($this);
            if( $type == "dynamic" )
                $xpath = $this->getXPath() . '/dynamic-destination-translation';
            else
                $xpath = $this->getXPath() . '/destination-translation';

            if( $host === null && ($ports === null | $ports == '') || $type == 'none' )
                $connector->sendDeleteRequest($xpath);
            else
                $connector->sendEditRequest($xpath, $this->dnatroot);

        }

        return $ret;
    }

    public function rewriteDNAT()
    {
        $host = $this->dnathost;
        $ports = $this->dnatports;
        $type = $this->dnattype;

        if( $this->dnattype == "dynamic" )
        {
            $this->dnatroot = DH::createOrResetElement($this->xmlroot, 'dynamic-destination-translation');
            $delete = DH::findFirstElement( 'destination-translation', $this->xmlroot );
            if( $delete != null )
                DH::removeChild($this->xmlroot, $delete);
        }
        else
        {
            $this->dnatroot = DH::createOrResetElement($this->xmlroot, 'destination-translation');
            $delete = DH::findFirstElement( 'dynamic-destination-translation', $this->xmlroot );
            if( $delete != null )
                DH::removeChild($this->xmlroot, $delete);
        }

        $this->subdnatTAroot = DH::createOrResetElement($this->dnatroot, 'translated-address', $host->name());

        $this->subdnatTProot = DH::createOrResetElement($this->dnatroot, 'translated-port');


        $this->dnathost = $host;
        $this->dnathost->addReference($this);
        $this->dnatports = $ports;
        $this->dnattype = $type;


        if( $ports === null )
        {
            DH::removeChild($this->dnatroot, $this->subdnatTProot);
        }
        else
        {
            DH::setDomNodeText($this->subdnatTProot, $ports);
        }
    }

    public function setNoSNAT()
    {
        $this->snattype = 'none';
        $this->snathosts->setAny();
        $this->rewriteSNAT_XML();

        return TRUE;
    }

    public function API_setNoSNAT()
    {
        $ret = $this->setNoSNAT();
        if( $ret )
        {
            $connector = findConnectorOrDie($this);
            $xpath = $this->getXPath() . '/source-translation';

            $connector->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function setDestinationInterface($newDestinationInterface)
    {
        if( $this->_destinationInterface === $newDestinationInterface )
            return FALSE;

        $this->_destinationInterface = $newDestinationInterface;


        //Todo: swaschkut 20201030 - not working if trying to add this on DG rule for template vsys interface
        if( get_class($this->owner->owner->owner) == "PanoramaConf" )
        {

        }
        else
        {
            $tmp_interface = $this->owner->owner->owner->network->findInterface($this->_destinationInterface);
            $tmp_interface->addReference($this);
        }


        $find = DH::findFirstElementOrCreate('to-interface', $this->xmlroot);
        DH::setDomNodeText($find, $newDestinationInterface);

        return TRUE;
    }

    public function setSNATInterface($newSNATInterface)
    {
        if( $this->snatinterface === $newSNATInterface )
            return FALSE;

        $this->snatinterface = $newSNATInterface;

        if( get_class( $this->owner->owner->owner ) != "PanoramaConf" )
        {
            $tmp_interface = $this->owner->owner->owner->network->findInterface($this->snatinterface);
            $tmp_interface->addReference($this);
        }
        else
        {
            //Todo: swaschkut 20201105 add interface reference for Panroama template vsys interface
            //how do find template / vsys????
        }


        //rewrite SNAT needed

        return TRUE;
    }

    /**
     * @param $newServiceObject Service|ServiceGroup|null use null to set ANY
     * @return bool return true if any change was made
     */
    public function setService($newServiceObject)
    {
        if( $this->service === $newServiceObject )
            return FALSE;

        if( $this->service !== null )
        {
            $this->service->removeReference($this);
        }

        $this->service = $newServiceObject;

        if( $newServiceObject !== null )
            $this->service->addReference($this);

        $this->rewriteService_XML();

        return TRUE;
    }

    /**
     * @param $newServiceObject Service|ServiceGroup|null use null to set ANY
     * @return bool return true if any change was made
     */
    public function API_setService($newServiceObject)
    {
        $ret = $this->setService($newServiceObject);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $xpath = $this->getXPath() . '/service';
            $con->sendEditRequest($xpath, $this->serviceroot);
        }

        return $ret;
    }


    public function reLinkObjects()
    {
        // to be written
        reLinkObjs($this->src, $this);
        reLinkObjs($this->dst, $this);
        reLinkObjs($this->snathosts, $this);
        if( $this->dnathost )
            $this->dnathost->addReference($this);
        if( $this->service )
            $this->service->addReference($this);
    }


    /**
     *
     *
     */
    public function rewriteService_XML()
    {
        DH::clearDomNodeChilds($this->serviceroot);

        if( $this->service === null )
        {
            DH::setDomNodeText($this->serviceroot, 'any');

            return;
        }

        DH::setDomNodeText($this->serviceroot, $this->service->name());
    }


    public function display($padding = 0)
    {
        $padding = str_pad('', $padding);

        $dis = '';
        if( $this->disabled )
            $dis = '<disabled>';

        $s = '*ANY*';
        if( $this->service )
            $s = $this->service->name();

        PH::print_stdout( $padding . "*Rule named {$this->name}  $dis" );
        PH::print_stdout( $padding . "  From: " . $this->from->toString_inline() . "  |  To:  " . $this->to->toString_inline() );
        PH::print_stdout( $padding . "  Source: " . $this->source->toString_inline() );

        if( $this->_destinationInterface !== null )
            PH::print_stdout( $padding . "  Destination Interface: " . $this->destinationInterface() );

        PH::print_stdout( $padding . "  Destination: " . $this->destination->toString_inline() );
        PH::print_stdout( $padding . "  Service:  " . $s );

        if( $this->snattype == 'static-ip' )
            PH::print_stdout( $padding . "  SNAT Type: " . $this->snattype . "   BiDir: " . $this->_snatbidir );
        else
            PH::print_stdout( $padding . "  SNAT Type: " . $this->snattype );


        if( $this->snattype != 'none' )
        {
            if( $this->snatinterface !== null )
                PH::print_stdout( $padding . "   SNAT HOSTS: {$this->snatinterface}/{$this->snathosts->toString_inline()}" );
            else
                PH::print_stdout( $padding . "   SNAT HOSTS: {$this->snathosts->toString_inline()}" );
        }

        if( $this->dnathost === null )
            PH::print_stdout( $padding . "  DNAT: none" );
        else
        {
            $text = $padding . "  DNAT: " . $this->dnathost->name();
            if( $this->dnatports != "" )
                $text .= " dport: " . $this->dnatports;
            PH::print_stdout( $text );
        }


        PH::print_stdout( $padding . "    Tags:  " . $this->tags->toString_inline()  );

        if( $this->_targets !== null )
            PH::print_stdout( $padding . "  Targets:  " . $this->targets_toString() );

        if( strlen($this->_description) > 0 )
            PH::print_stdout( $padding . "  Desc:  " . $this->_description );
        else
            PH::print_stdout( $padding . "  Desc:  " );

        PH::print_stdout( "" );
    }

    /**
     * @return string
     * @deprecated use SourceNat_Type() instead
     */
    public function natType()
    {
        return $this->snattype;
    }

    public function destinationInterface()
    {
        return $this->_destinationInterface;
    }

    public function destinationNatIsEnabled()
    {
        return $this->dnathost !== null;
    }

    /**
     * @return string options are : 'none' , 'dynamic-ip', 'dynamic-ip-and-port', 'static-ip'
     */
    public function sourceNatIsEnabled()
    {
        return $this->snattype !== 'none';
    }

    public function SourceNat_Type()
    {
        return $this->snattype;
    }

    public function sourceNatTypeIs_None()
    {
        return $this->snattype == 'none';
    }

    public function sourceNatTypeIs_Dynamic()
    {
        return $this->snattype == 'dynamic-ip';
    }

    public function sourceNatTypeIs_DIPP()
    {
        return $this->snattype == 'dynamic-ip-and-port';
    }

    public function sourceNatTypeIs_Static()
    {
        return $this->snattype == 'static-ip';
    }

    public function hasDestinationInterface()
    {
        if( $this->_destinationInterface === null )
            return FALSE;

        return TRUE;
    }

    public function isNatRule()
    {
        return TRUE;
    }

    public function cleanForDestruction()
    {
        $this->from->__destruct();
        $this->to->__destruct();
        $this->source->__destruct();
        $this->destination->__destruct();
        $this->tags->__destruct();

        $this->from = null;
        $this->to = null;
        $this->source = null;
        $this->destination = null;
        $this->tags = null;

        if( $this->service !== null )
        {
            $this->service->removeReference($this);
            unset($this->service);
        }

        if( $this->dnathost !== null )
        {
            $this->dnathost->removeReference($this);
            unset($this->dnathost);
        }

    }

    public function storeVariableName()
    {
        return "natRules";
    }

    public function ruleNature()
    {
        return 'nat';
    }
}



