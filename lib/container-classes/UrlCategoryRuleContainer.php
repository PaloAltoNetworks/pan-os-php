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
 * Class UrlCategoryRuleContainer
 * @property customURLProfile[]|URLProfile[] $o
 * @property Rule|SecurityRule $owner
 *
 */
class UrlCategoryRuleContainer extends ObjRuleContainer
{
    /** @var null|SecurityProfileStore */
    public $parentCentralStore = null;



    public function __construct($owner)
    {
        $this->owner = $owner;
        $this->o = array();

        $this->findParentCentralStore( 'customURLProfileStore' );
    }


    /**
     * @param customURLProfile|URLProfile $Obj
     * @param bool $rewriteXml
     * @return bool
     */
    public function add($Obj, $rewriteXml = TRUE)
    {
        $this->fasthashcomp = null;

        $ret = parent::add($Obj);
        if( $ret && $rewriteXml )
        {
            $this->appDef = FALSE;
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param customURLProfile|URLProfile $Obj
     * @param bool $rewritexml
     * @return bool
     */
    public function API_add($Obj, $rewritexml = TRUE)
    {
        if( $this->add($Obj, $rewritexml) )
        {
            $this->API_sync();

            return TRUE;
        }

        return FALSE;
    }


    /**
     * @param customURLProfile|URLProfile $Obj
     * @param bool $rewriteXml
     * @param bool $forceAny
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function remove($Obj, $rewriteXml = TRUE, $forceAny = FALSE)
    {
        $count = count($this->o);

        $ret = parent::remove($Obj);

        if( $ret && $count == 1 && !$forceAny )
        {
            derr("you are trying to remove last Object from a rule which will set it to ANY, please use forceAny=true for object: "
                . $this->toString());
        }

        if( $ret && $rewriteXml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param customURLProfile|URLProfile $Obj
     * @param bool $rewriteXml
     * @param bool $forceAny
     * @return bool
     */
    public function API_remove($Obj, $rewriteXml = TRUE, $forceAny = FALSE)
    {
        if( $this->remove($Obj, $rewriteXml, $forceAny) )
        {
            $this->API_sync();
            return TRUE;
        }

        return FALSE;
    }

    public function setAny()
    {
        $this->fasthashcomp = null;

        foreach( $this->o as $o )
        {
            $this->remove($o, FALSE, TRUE);
        }

        $this->appDef = FALSE;
        $this->rewriteXML();
    }



    /**
     * @param customURLProfile|URLProfile|string $object can be customURLProfileStore|URLProfileStore object or object name (string)
     * @return bool
     */
    public function has($object, $caseSensitive = TRUE)
    {
        return parent::has($object, $caseSensitive);
    }


    /**
     * return an array with all objects
     * @return customURLProfile[]|URLProfile[]
     */
    public function members()
    {
        return $this->o;
    }

    /**
     * return an array with all objects
     * @return customURLProfile[]|URLProfile[]
     */
    public function all()
    {
        return $this->o;
    }

    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        #PH::print_stdout( "started to extract '".$this->toString()."' from xml");
        $this->xmlroot = $xml;
        $i = 0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            $lower = $node->textContent;

            if( $lower == 'any' )
            {
                if( count($this->o) != 0 )
                    mwarning('rule has a bad combination of url categories', $xml, false);

                $this->o = array();
                continue;
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
        //todo: fix it
        DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', TRUE);
    }



    /**
     * Merge this set of objects with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     * @param UrlCategoryRuleContainer $other
     *
     */
    public function merge(UrlCategoryRuleContainer $other)
    {
        $this->fasthashcomp = null;

        if( $this->isAny() )
            return;

        if( $other->isAny() )
        {
            $this->setAny();
            return;
        }

        foreach( $other->o as $s )
        {
            $this->add($s, FALSE);
        }

        $this->rewriteXML();
    }

    /**
     * To determine if a container has all the zones from another container. Very useful when looking to compare similar rules.
     * @param $other
     * @param $anyIsAcceptable
     * @return boolean true if Zones from $other are all in this store
     */
    public function includesContainer(UrlCategoryRuleContainer $other, $anyIsAcceptable = TRUE)
    {

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return FALSE;
        }

        if( $this->count() == 0 )
            return TRUE;

        if( $other->count() == 0 )
            return FALSE;

        $objects = $other->members();

        foreach( $objects as $o )
        {
            if( !$this->has($o) )
                return FALSE;
        }

        return TRUE;

    }

    public function API_setAny()
    {
        $this->setAny();
        $this->API_sync();
    }

    /**
     * @param UrlCategoryRuleContainer $other
     * @return bool
     */
    public function equals($other)
    {

        if( count($this->o) != count($other->o) )
            return FALSE;

        if( $this->appDef != $other->appDef )
            return FALSE;

        foreach( $this->o as $o )
        {
            if( !in_array($o, $other->o, TRUE) )
                return FALSE;
        }


        return TRUE;
    }


    /**
     * @return string
     */
    public function &getXPath()
    {

        $str = $this->owner->getXPath() . '/' . $this->name;

        return $str;

    }

    /**
     * @return bool
     */
    public function isAny()
    {
        if( $this->appDef )
            return FALSE;

        return (count($this->o) == 0);
    }


    /**
     * @param customURLProfile|URLProfile
     * @param bool $anyIsAcceptable
     * @return bool
     */
    public function hasObjectRecursive($object, $anyIsAcceptable = FALSE)
    {
        if( $object === null )
            derr('cannot work with null objects');

        if( $anyIsAcceptable && $this->count() == 0 )
            return FALSE;

        foreach( $this->o as $o )
        {
            if( $o === $object )
                return TRUE;
        }

        return FALSE;
    }

    /**
     * @param string $objectName
     * @return bool
     */
    public function hasNamedObjectRecursive($objectName)
    {
        foreach( $this->o as $o )
        {
            if( $o->name() === $objectName )
                return TRUE;
        }

        return FALSE;
    }


    /**
     * To determine if a store has all the Service from another store, it will expand ServiceGroups instead of looking for them directly. Very useful when looking to compare similar rules.
     * @param UrlCategoryRuleContainer $other
     * @param bool $anyIsAcceptable if any of these objects is Any the it will return false
     * @return bool true if Service objects from $other are all in this store
     */
    public function includesStoreExpanded(UrlCategoryRuleContainer $other, $anyIsAcceptable = TRUE)
    {
        //Todo check how to improve this as the Class is clones from Servicerulecontainer
        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return FALSE;
        }

        if( $this->count() == 0 )
            return TRUE;

        if( $other->count() == 0 )
            return FALSE;

        $localA = array();
        $A = array();

        foreach( $this->o as $object )
            $localA[] = $object;

        $localA = array_unique_no_cast($localA);

        $otherAll = $other->all();

        foreach( $otherAll as $object )
            $A[] = $object;

        $A = array_unique_no_cast($A);

        $diff = array_diff_no_cast($A, $localA);

        if( count($diff) > 0 )
        {
            return FALSE;
        }


        return TRUE;

    }

    /**
     * @return customURLProfile[]|URLProfile[]
     */
    public function &membersExpanded($keepGroupsInList = FALSE)
    {
        //Todo: work on this as one URL can be part of two profiles
        $localA = array();

        if( count($this->o) == 0 )
            return $localA;

        foreach( $this->o as $member )
        {
            $localA[] = $member;
        }

        $localA = array_unique_no_cast($localA);

        return $localA;
    }


    public function toString_inline()
    {
        $arr = &$this->o;
        $c = count($arr);

        if( $c == 0 )
        {
            $ret = '**ANY**';
            return $ret;
        }

        $first = TRUE;

        $ret = '';

        foreach( $arr as $s )
        {
            if( $first )
            {
                $ret .= $s->name();
            }
            else
                $ret .= ',' . $s->name();


            $first = FALSE;
        }

        return $ret;

    }

    public function generateFastHashComp($force = FALSE)
    {
        if( isset($this->fasthashcomp) && $this->fasthashcomp !== null && !$force )
            return;

        $class = get_class($this);
        $fasthashcomp = $class;

        $tmpa = $this->o;

        usort($tmpa, "__CmpObjName");

        foreach( $tmpa as $o )
        {
            $fasthashcomp .= '.*/' . $o->name();
        }

        if( $this->appDef )
            $fasthashcomp .= '.app-default';

        $this->fasthashcomp = md5($fasthashcomp, TRUE);

    }

}





