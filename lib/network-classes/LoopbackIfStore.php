<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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
 * @property $o LoopbackInterface[]
 * @property PANConf $owner
 */
class LoopbackIfStore extends ObjStore
{
    public static $childn = 'LoopbackInterface';

    protected $fastMemToIndex = null;
    protected $fastNameToIndex = null;

    /**
     * @param $name string
     * @param $owner PANConf
     */
    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return LoopbackInterface[]
     */
    public function getInterfaces()
    {
        return $this->o;
    }


    /**
     * Creates a new LoopbackInterface in this store. It will be placed at the end of the list.
     * @param string $name name of the new LoopbackInterface
     * @return LoopbackInterface
     */
    public function newLoopbackIf($name)
    {
        foreach( $this->getInterfaces() as $interface )
        {
            if( $interface->name() == $name )
                derr("Interface: " . $name . " already available\n");
        }

        $loopbackIf = new LoopbackInterface($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, LoopbackInterface::$templatexml);

        $loopbackIf->load_from_domxml($xmlElement);

        $loopbackIf->owner = null;
        $loopbackIf->setName($name);

        $this->addLoopbackIf($loopbackIf);
        $this->add($loopbackIf);

        return $loopbackIf;
    }


    /**
     * @param LoopbackInterface $loopbackIf
     * @return bool
     */
    public function addLoopbackIf($loopbackIf)
    {
        if( !is_object($loopbackIf) )
            derr('this function only accepts LoopbackInterface class objects');

        if( $loopbackIf->owner !== null )
            derr('Trying to add a LoopbackInterface that has a owner already !');


        $ser = spl_object_hash($loopbackIf);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $loopbackIf->owner = $this;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($loopbackIf->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a LoopbackInterface that is already here :)');

        return FALSE;
    }

    /**
     * @param LoopbackInterface $s
     * @return bool
     */
    public function API_addLoopbackIf($s)
    {
        $ret = $this->addLoopbackIf($s);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $xpath = $s->getXPath();
            $con->sendSetRequest($xpath, DH::domlist_to_xml($s->xmlroot->childNodes, -1, FALSE));
        }

        return $ret;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            //TODO: 20180331 why I need to create full path? why it is not set before???
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);
            $xml = DH::findFirstElementOrCreate('interface', $xml);
            $xml = DH::findFirstElementOrCreate('loopback', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('units', $xml);
        }
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
            $str = '/config/shared';
        else
            derr('unsupported');

        //TODO: intermediate solution
        $str = '/config/devices/entry/network/interface';

        $str = $str . '/loopback/units';

        return $str;
    }


    private function &getBaseXPath()
    {
        if( $this->owner->isPanorama() || $this->owner->isFirewall() )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();

        //TODO: intermediate solution
        $str = '/config/devices/entry/network/interface';

        return $str;
    }

    public function &getLoopbackIfStoreXPath()
    {
        $path = $this->getBaseXPath() . '/loopback/units';
        return $path;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
            {
                $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
                $xml = DH::findFirstElementOrCreate('entry', $xml);
                $xml = DH::findFirstElementOrCreate('network', $xml);
                $xml = DH::findFirstElementOrCreate('interface', $xml);
                $xml = DH::findFirstElementOrCreate('loopback', $xml);

                DH::findFirstElementOrCreate('units', $xml);
                #DH::findFirstElementOrCreate('tag', $this->owner->xmlroot);
            }

        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            if( !$o->isTmp() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
    }
}