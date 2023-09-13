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

/**
 * Class DHCPStore
 * @property $o DHCP[]
 */
class SharedGatewayStore extends ObjStore
{

    /** @var null|PANConf */
    public $owner;

    public $version;

    /** @var VirtualSystem[] */
    public $virtualSystems = array();

    public static $childn = 'SharedGateway';

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        foreach( $this->xmlroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            /** @var DOMElement $node */

            if( $this->skipEmptyXmlObjects && !$node->hasChildNodes() )
            {
                mwarning('XML element had no child, it was skipped', $node);
                continue;
            }

            $localVsys = new VirtualSystem($this);
            $localVsys->load_from_domxml($node);

            $this->virtualSystems[] = $localVsys;
        }
    }

    /**
     * @return SharedGateway[]
     */
    public function SharedGateways()
    {
        return $this->o;
    }

    /**
     * @param $vrName string
     * @return null|SharedGateway
     */
    public function findSharedGateway($vrName)
    {
        return $this->findByName($vrName);
    }

    /**
     * Creates a new DHCP in this store. It will be placed at the end of the list.
     * @param string $name name of the new VirtualRouter
     * @return SharedGateway
     */
    public function newSharedGateway($name)
    {
        foreach( $this->SharedGateways() as $vr )
        {
            if( $vr->name() == $name )
                derr("SharedGateway: " . $name . " already available\n");
        }

        $SharedGateway = new SharedGateway($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, dhcp::$templatexml);

        $SharedGateway->load_from_domxml($xmlElement);

        $SharedGateway->owner = null;
        $SharedGateway->setName($name);

        //20190507 - which add method is best, is addvirtualRouter needed??
        $this->addSharedGateway($SharedGateway);
        $this->add($SharedGateway);

        return $SharedGateway;
    }

    /**
     * @param SharedGateway $SharedGateway
     * @return bool
     */
    public function addSharedGateway($SharedGateway)
    {
        if( !is_object($SharedGateway) )
            derr('this function only accepts dhcp class objects');

        if( $SharedGateway->owner !== null )
            derr('Trying to add a dhcp that has a owner already !');


        $ser = spl_object_hash($SharedGateway);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $SharedGateway->owner = $this;

            $this->fastMemToIndex[$ser] = $SharedGateway;
            $this->fastNameToIndex[$SharedGateway->name()] = $SharedGateway;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($SharedGateway->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a dhcp that is already here :)');

        return FALSE;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('shared-gateway', $xml);
        }
    }

    private function &getBaseXPath()
    {

        $str = "";
        /*
                if( $this->owner->owner->isTemplate() )
                    $str .= $this->owner->owner->getXPath();
                elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
                    $str = '/config/shared';
                else
                    derr('unsupported');
        */

        //TODO: intermediate solution
        $str .= '/config/devices/entry/network';

        return $str;
    }

    public function &getSharedGatewayStoreXPath()
    {
        $path = $this->getBaseXPath();
        return $path;
    }

}