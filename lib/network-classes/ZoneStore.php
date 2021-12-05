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
 * Class ZoneStore
 *
 * @property ZoneStore $parentCentralStore
 * @property Zone[] $o
 *
 */
class ZoneStore extends ObjStore
{
    /** @var DeviceGroup|PanoramaConf|VirtualSystem */
    public $owner;

    public $parentCentralStore = null;

    public static $childn = 'Zone';

    /**
     * @param VirtualSystem|DeviceCloud|DeviceGroup|PanoramaConf|Container|FawkesConf $owner
     */
    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;

        $this->findParentCentralStore();
    }


    /**
     * looks for a zone named $name ,return that Zone object, null if not found
     * @param string $name
     * @return Zone
     */
    public function find($name, $ref = null, $nested = false)
    {
        return $this->findByName($name, $ref, $nested);
    }


    /**
     * add a Zone to this store. Use at your own risk.
     * @param Zone
     * @param bool
     * @return bool
     */
    public function addZone(Zone $zone, $rewriteXML = TRUE)
    {
        $fasthashcomp = null;

        $ret = $this->add($zone);

        if( $ret && $rewriteXML && !$zone->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->appendChild($zone->xmlroot);
        }
        return $ret;
    }


    /**
     * remove a Zone a Zone to this store.
     * @param Zone
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeZone(Zone $zone)
    {
        $ret = $this->remove($zone);

        if( $ret && !$zone->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($zone->xmlroot);
        }

        return $ret;
    }

    /**
     * @param Zone|string $zoneName can be Zone object or zone name (string). this is case sensitive
     * @return bool
     */
    public function hasZoneNamed($zoneName, $caseSensitive = TRUE)
    {
        return $this->has($zoneName, $caseSensitive);
    }


    /**
     * @param string $ifName
     * @return null|Zone
     */
    public function findZoneMatchingInterfaceName($ifName)
    {
        foreach( $this->o as $zone )
        {
            if( $zone->isTmp() )
                continue;

            if( $zone->attachedInterfaces->hasInterfaceNamed($ifName) )
                return $zone;
        }

        return null;
    }

    /**
     * @param $vsys string|VirtualSystem
     * @return null|Zone
     */
    public function findZoneWithExternalVsys($vsys)
    {
        if( is_string($vsys) )
        {
            foreach( $this->o as $zone )
            {
                if( $zone->type() == 'external' )
                    if( isset($zone->externalVsys[$vsys]) )
                        return $zone;
            }
            return null;
        }

        foreach( $this->o as $zone )
        {
            if( $zone->type() == 'external' )
            {
                if( isset($zone->externalVsys[$vsys->name()]) )
                    return $zone;
            }
        }
        return null;
    }


    /**
     * return an array with all Zones in this store
     * @return Zone[]
     */
    public function zones()
    {
        return $this->o;
    }


    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $zone )
            {
                if( !$zone->isTmp() )
                    $this->xmlroot->appendChild($zone->xmlroot);
            }
        }

    }

    /**
     *
     * @ignore
     */
    protected function findParentCentralStore()
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $curo = $this;
            while( isset($curo->owner) && $curo->owner !== null )
            {

                if( isset($curo->owner->zoneStore) &&
                    $curo->owner->zoneStore !== null )
                {
                    $this->parentCentralStore = $curo->owner->zoneStore;
                    //PH::print_stdout(  $this->toString()." : found a parent central store: ".$parentCentralStore->toString() );
                    return;
                }
                $curo = $curo->owner;
            }
        }

        //PH::print_stdout( $this->toString().": no parent store found" );

    }


    public function &getXPath()
    {
        if( $this->xmlroot === null )
            derr('unsupported on virtual Stores');

        $xpath = $this->owner->getXPath() . "/zone/";

        return $xpath;

    }


    public function newZone($name, $type)
    {
        foreach( $this->zones() as $zone )
        {
            if( $zone->name() == $name )
                derr("Zone: " . $name . " already available\n");
        }

        $found = $this->find($name, null);
        if( $found !== null )
            derr("cannot create Zone named '" . $name . "' as this name is already in use ");

        $ns = new Zone($name, $this, TRUE, $type);

        $this->addZone($ns);

        return $ns;

    }


}



