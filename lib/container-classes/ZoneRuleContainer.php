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
 * Class ZoneRuleContainer
 * @property SecurityRule|NatRule|PbfRule|CaptivePortalRule|DecryptionRule $owner
 *
 */
class ZoneRuleContainer extends ObjRuleContainer
{
    /** @var null|ZoneStore */
    public $parentCentralStore = null;

    public function __construct($owner)
    {
        $this->owner = $owner;
        #$this->name = 'zone';

        #$this->findParentCentralStore();
    }


    /**
     * add a Zone to this store
     * @param bool $rewritexml
     * @return bool
     */
    public function addZone(Zone $Obj, $rewritexml = TRUE)
    {
        /*
        if( is_string($Obj) )
        {
            $f = $this->parentCentralStore->findOrCreate($Obj);
            if( $f === null )
            {
                derr(": Error : cannot find tag named '".$Obj."'\n");
            }
            return $this->add($f);
        }*/

        $ret = $this->add($Obj);
        if( $ret && $rewritexml )
        {
            $this->rewriteXML();
        }


        return $ret;
    }

    /**
     * add a Zone to this store
     * @param bool $rewritexml
     * @return bool
     */
    public function API_addZone(Zone $Obj, $rewritexml = TRUE)
    {
        if( $this->addZone($Obj, $rewritexml) )
        {
            if( count($this->o) == 1 )
            {
                $this->API_sync();
                return TRUE;
            }
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($xpath, "<member>{$Obj->name()}</member>");

            return TRUE;
        }

        return FALSE;
    }


    /**
     * remove a Zone a Zone to this store. Be careful if you remove last zone as
     * it would become 'any' and won't let you do so.
     * @param bool $rewritexml
     * @param bool $forceAny
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeZone(Zone $Obj, $rewritexml = TRUE, $forceAny = FALSE)
    {
        $count = count($this->o);

        $ret = $this->remove($Obj);

        if( $ret && $count == 1 && !$forceAny )
        {
            derr("you are trying to remove last Zone from a rule which will set it to ANY, please use forceAny=true for object: "
                . $this->toString());
        }

        if( $ret && $rewritexml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param Zone $Obj
     * @param bool $rewritexml
     * @param bool $forceAny
     * @return bool
     */
    public function API_removeZone(Zone $Obj, $rewritexml = TRUE, $forceAny = FALSE)
    {
        if( $this->removeZone($Obj, $rewritexml, $forceAny) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 0 )
            {
                $this->API_sync();
                return TRUE;
            }

            $xpath .= "/member[text()='{$Obj->name()}']";
            $con->sendDeleteRequest($xpath);

            return TRUE;
        }

        return FALSE;
    }

    public function setAny()
    {
        $this->removeAll();

        $this->rewriteXML();
    }

    /**
     * @param Zone|string $zone can be Zone object or zone name (string). this is case sensitive
     * @return bool
     */
    public function hasZone($zone, $caseSensitive = TRUE)
    {
        return $this->has($zone, $caseSensitive);
    }


    /**
     * return an array with all Zones in this store
     * @return Zone[]
     */
    public function zones()
    {
        return $this->o;
    }


    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        //PH::print_stdout(  "started to extract '".$this->toString()."' from xml" );
        $this->xmlroot = $xml;
        $i = 0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( $i == 0 && strtolower($node->textContent) == 'any' )
            {
                return;
            }

            if( strlen($node->textContent) < 1 )
            {
                derr('this container has members with empty name!', $node);
            }

            $f = $this->parentCentralStore->findOrCreate($node->textContent, $this);
            $this->o[] = $f;
            $i++;
        }
    }


    public function rewriteXML()
    {
        DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', TRUE);
    }

    public function toString_inline()
    {
        if( count($this->o) == 0 )
        {
            $out = '**ANY**';
            return $out;
        }

        $out = parent::toString_inline();
        return $out;
    }


    /**
     *
     * @ignore
     */
    public function findParentCentralStore()
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

    }


    /**
     * Merge this set of Zones with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     *
     */
    public function merge($other)
    {
        if( count($this->o) == 0 )
            return;

        if( count($other->o) == 0 )
        {
            $this->setAny();
            return;
        }

        foreach( $other->o as $s )
        {
            $this->addZone($s);
        }

    }

    /**
     * To determine if a container has all the zones from another container. Very useful when looking to compare similar rules.
     * @param $other
     * @param $anyIsAcceptable
     * * @param $missingZones
     * @return boolean true if Zones from $other are all in this store
     */
    public function includesContainer(ZoneRuleContainer $other, $anyIsAcceptable = TRUE, &$foundZones = array())
    {
        $tmp_return = TRUE;

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return FALSE;
        }

        if( $this->count() == 0 )
            return TRUE;

        if( $other->count() == 0 )
            return FALSE;

        $zones = $other->zones();

        foreach( $zones as $zone )
        {
            if( !$this->hasZone($zone) )
                $tmp_return = FALSE;
            else
                $foundZones[] = $zone;

        }
        if( !$tmp_return )
            return FALSE;

        return TRUE;

    }

    public function API_setAny()
    {
        $this->setAny();
        $xpath = &$this->getXPath();
        $con = findConnectorOrDie($this);
        $con->sendDeleteRequest($xpath);
        $con->sendSetRequest($xpath, '<member>any</member>');
    }


    public function &getXPath()
    {
        $str = $this->owner->getXPath() . '/' . $this->name;

        if( $this->owner !== null && $this->owner->isPbfRule() && $this->name == 'from' )
            $str .= '/zone';

        return $str;
    }

    public function copy(ZoneRuleContainer $other)
    {
        if( $other->count() == 0 && $this->count() != 0 )
            $this->removeAll();

        foreach( $other->o as $member )
        {
            $this->addZone($member);
        }
    }

    /**
     * @return bool
     */
    public function isAny()
    {
        return (count($this->o) == 0);
    }
}





