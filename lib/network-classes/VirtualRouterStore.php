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
 * Class IPsecTunnelStore
 * @property $o IPsecTunnel[]
 */
class VirtualRouterStore extends ObjStore
{

    /** @var null|PANConf */
    public $owner;

    public static $childn = 'VirtualRouter';

    protected $fastMemToIndex;
    protected $fastNameToIndex;


    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return VirtualRouter[]
     */
    public function virtualRouters()
    {
        return $this->o;
    }

    /**
     * @param $vrName string
     * @return null|VirtualRouter
     */
    public function findVirtualRouter($vrName)
    {
        return $this->findByName($vrName);
    }

    /**
     * Creates a new VirtualRouter in this store. It will be placed at the end of the list.
     * @param string $name name of the new VirtualRouter
     * @return VirtualRouter
     */
    public function newVirtualRouter($name)
    {
        foreach( $this->virtualRouters() as $vr )
        {
            if( $vr->name() == $name )
                derr("VirtualRouter: " . $name . " already available\n");
        }

        $virtualRouter = new virtualRouter($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, virtualRouter::$templatexml);

        $virtualRouter->load_from_domxml($xmlElement);

        $virtualRouter->owner = null;
        $virtualRouter->setName($name);

        //20190507 - which add method is best, is addvirtualRouter needed??
        $this->addvirtualRouter($virtualRouter);
        $this->add($virtualRouter);

        return $virtualRouter;
    }

    /**
     * @param VirtualRouter $virtualRouter
     * @return bool
     */
    public function addVirtualRouter($virtualRouter)
    {
        if( !is_object($virtualRouter) )
            derr('this function only accepts virtualRouter class objects');

        if( $virtualRouter->owner !== null )
            derr('Trying to add a virtualRouter that has a owner already !');


        $ser = spl_object_hash($virtualRouter);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $virtualRouter->owner = $this;

            $this->fastMemToIndex[$ser] = $virtualRouter;
            $this->fastNameToIndex[$virtualRouter->name()] = $virtualRouter;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($virtualRouter->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a virtualRouter that is already here :)');

        return FALSE;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('virtual-router', $xml);
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

    public function &getvirtualRouterStoreXPath()
    {
        $path = $this->getBaseXPath() . '/virtual-router';
        return $path;
    }

}