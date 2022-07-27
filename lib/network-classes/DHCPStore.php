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
class DHCPStore extends ObjStore
{

    /** @var null|PANConf */
    public $owner;

    public static $childn = 'DHCP';

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return DHCP[]
     */
    public function DHCPs()
    {
        return $this->o;
    }

    /**
     * @param $vrName string
     * @return null|DCHP
     */
    public function findDHCP($vrName)
    {
        return $this->findByName($vrName);
    }

    /**
     * Creates a new DHCP in this store. It will be placed at the end of the list.
     * @param string $name name of the new VirtualRouter
     * @return DHCP
     */
    public function newDHCP($name)
    {
        foreach( $this->DHCPs() as $vr )
        {
            if( $vr->name() == $name )
                derr("DHCP: " . $name . " already available\n");
        }

        $dhcp = new DHCP($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, dhcp::$templatexml);

        $dhcp->load_from_domxml($xmlElement);

        $dhcp->owner = null;
        $dhcp->setName($name);

        //20190507 - which add method is best, is addvirtualRouter needed??
        $this->addDHCP($dhcp);
        $this->add($dhcp);

        return $dhcp;
    }

    /**
     * @param DHCP $dhcp
     * @return bool
     */
    public function addDHCP($dhcp)
    {
        if( !is_object($dhcp) )
            derr('this function only accepts dhcp class objects');

        if( $dhcp->owner !== null )
            derr('Trying to add a dhcp that has a owner already !');


        $ser = spl_object_hash($dhcp);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $dhcp->owner = $this;

            $this->fastMemToIndex[$ser] = $dhcp;
            $this->fastNameToIndex[$dhcp->name()] = $dhcp;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($dhcp->xmlroot);

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

            $xml = DH::findFirstElementOrCreate('dhcp', $xml);
            $this->xmlroot = DH::findFirstElementOrCreate('interface', $xml);
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

    public function &getDHCPStoreXPath()
    {
        $path = $this->getBaseXPath() . '/dhcp/interface';
        return $path;
    }

}