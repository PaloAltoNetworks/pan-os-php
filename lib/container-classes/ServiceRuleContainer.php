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

/**
 * Class ServiceRuleContainer
 * @property Service[]|ServiceGroup[] $o
 * @property Rule|SecurityRule|NatRule $owner
 *
 * @method Service[]|ServiceGroup[] getMembersDiff(ServiceRuleContainer $otherObject)
 * @method displayMembersDiff(ServiceRuleContainer $otherObject, $indent = 0, $toString = FALSE)
 *
 */
class ServiceRuleContainer extends ObjRuleContainer
{
    /** @var null|ServiceStore */
    public $parentCentralStore = null;

    private $appDef = FALSE;
    private $wrongService = FALSE;


    public function __construct($owner)
    {
        $this->owner = $owner;
        $this->o = array();

        $this->findParentCentralStore();
    }


    /**
     * @param Service|ServiceGroup $Obj
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
     * @param Service|ServiceGroup $Obj
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

    public function isApplicationDefault()
    {
        return $this->appDef;
    }


    /**
     * @param Service|ServiceGroup $Obj
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
     * @param Service|ServiceGroup $Obj
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

    function setApplicationDefault()
    {
        if( $this->appDef )
            return FALSE;

        $this->fasthashcomp = null;

        $this->appDef = TRUE;

        foreach( $this->o as $o )
        {
            $this->remove($o, FALSE, TRUE);
        }

        $this->rewriteXML();

        return TRUE;
    }

    /**
     * @param Service|ServiceGroup|string $object can be Service|ServiceGroup object or object name (string)
     * @return bool
     */
    public function has($object, $caseSensitive = TRUE)
    {
        return parent::has($object, $caseSensitive);
    }


    /**
     * return an array with all objects
     * @return Service[]|ServiceGroup[]
     */
    public function members()
    {
        return $this->o;
    }

    /**
     * return an array with all objects
     * @return Service[]|ServiceGroup[]
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
        //print "started to extract '".$this->toString()."' from xml\n";
        $this->xmlroot = $xml;
        $i = 0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            $lower = $node->textContent;

            if( $lower == 'any' )
            {
                if( count($this->o) != 0 && !$this->wrongService)
                {
                    mwarning('rule has a bad combination of services', $xml);
                    $this->wrongService = true;
                }


                $this->o = array();
                continue;
            }
            else if( $lower == 'application-default' )
            {
                if( count($this->o) != 0 && !$this->wrongService )
                {
                    mwarning('rule has a bad combination of services', $xml);
                    $this->wrongService = true;
                }


                $this->o = array();
                $this->appDef = TRUE;
                continue;
            }
            else
            {
                if( $this->appDef == TRUE && !$this->wrongService )
                    #if( count($this->o) != 0 )
                {
                    mwarning('rule has a bad combination of services', $xml);
                    $this->wrongService = TRUE;
                }
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
        if( $this->appDef )
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', TRUE, 'application-default');
        else
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', TRUE);
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
            $currentObject = $this;
            while( isset($currentObject->owner) && $currentObject->owner !== null )
            {

                if( isset($currentObject->owner->serviceStore) &&
                    $currentObject->owner->serviceStore !== null )
                {
                    $this->parentCentralStore = $currentObject->owner->serviceStore;
                    //print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
                    return;
                }
                $currentObject = $currentObject->owner;
            }
        }

        #mwarning('no parent store found!', null, false);

    }


    /**
     * Merge this set of objects with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     * @param ServiceRuleContainer $other
     *
     */
    public function merge(ServiceRuleContainer $other)
    {
        $this->fasthashcomp = null;

        if( $this->appDef && !$other->appDef || !$this->appDef && $other->appDef )
            derr("You cannot merge 'application-default' type service stores with app-default ones");

        if( $this->appDef && $other->appDef )
            return;

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
    public function includesContainer(ServiceRuleContainer $other, $anyIsAcceptable = TRUE, &$foundServices = array())
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

        $objects = $other->members();

        foreach( $objects as $o )
        {
            if( !$this->has($o) )
                $tmp_return = FALSE;
            else
                $foundServices[] = $o;
        }
        if( !$tmp_return )
            return FALSE;

        return TRUE;
    }

    public function API_setAny()
    {
        $this->setAny();
        $this->API_sync();
    }

    /**
     * @return bool true if not already App Default
     */
    public function API_setApplicationDefault()
    {
        $ret = $this->setApplicationDefault();

        if( !$ret )
            return FALSE;

        $this->API_sync();

        return TRUE;
    }

    /**
     * @param ServiceRuleContainer $other
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
     * @param Service|ServiceGroup
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
            if( $o->isGroup() )
                if( $o->hasObjectRecursive($object) ) return TRUE;
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
            if( $o->isGroup() )
                if( $o->hasNamedObjectRecursive($objectName) ) return TRUE;
        }

        return FALSE;
    }


    /**
     * To determine if a store has all the Service from another store, it will expand ServiceGroups instead of looking for them directly. Very useful when looking to compare similar rules.
     * @param ServiceRuleContainer $other
     * @param bool $anyIsAcceptable if any of these objects is Any the it will return false
     * @return bool true if Service objects from $other are all in this store
     */
    public function includesStoreExpanded(ServiceRuleContainer $other, $anyIsAcceptable = TRUE)
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

        $localA = array();
        $A = array();

        foreach( $this->o as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $localA = array_merge($localA, $flat);
            }
            else
                $localA[] = $object;
        }
        $localA = array_unique_no_cast($localA);

        $otherAll = $other->all();

        foreach( $otherAll as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $A = array_merge($A, $flat);
            }
            else
                $A[] = $object;
        }
        $A = array_unique_no_cast($A);

        $diff = array_diff_no_cast($A, $localA);

        if( count($diff) > 0 )
        {
            return FALSE;
        }


        return TRUE;

    }

    /**
     * @return Service[]|ServiceGroup[]
     */
    public function &membersExpanded($keepGroupsInList = FALSE)
    {
        $localA = array();

        if( count($this->o) == 0 )
            return $localA;

        foreach( $this->o as $member )
        {
            if( $member->isGroup() )
            {
                $flat = $member->expand($keepGroupsInList);
                $localA = array_merge($localA, $flat);
                if( $keepGroupsInList )
                    $localA[] = $member;
            }
            else
                $localA[] = $member;
        }

        $localA = array_unique_no_cast($localA);

        return $localA;
    }


    public function toString_inline()
    {
        $arr = &$this->o;
        $c = count($arr);

        if( $this->appDef )
        {
            $ret = 'application-default';
            return $ret;
        }

        if( $c == 0 )
        {
            $ret = '*ANY*';
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

    /**
     * @param string $value
     * @param array $objects
     * @param bool $check_recursive
     * @return bool
     */
    function hasValue($value, $check_recursive = FALSE)
    {
        $objects = $this->o;
        foreach( $objects as $object )
        {
            if( !$check_recursive )
                if( $object->isGroup() )
                    continue;

            if( !$object->isGroup() )
                if( $value == $object->getDestPort() )
                    return TRUE;

            $port_mapping = $object->dstPortMapping();
            $port_mapping_text = $port_mapping->mappingToText();

            if( strpos($port_mapping_text, " ") !== FALSE )
                $port_mapping_array = explode(" ", $port_mapping_text);
            else
                $port_mapping_array[0] = $port_mapping_text;

            foreach( $port_mapping_array as $port_mapping_text )
            {
                $text_replace = array('tcp/', 'udp/');
                $port_mapping_text = str_replace($text_replace, "", $port_mapping_text);

                if( strpos($port_mapping_text, "-") !== FALSE )
                {
                    $port_mapping_range = explode("-", $port_mapping_text);
                    if( intval($port_mapping_range[0]) <= intval($value) && intval($port_mapping_range[1]) >= intval($value) )
                        return TRUE;
                }
                elseif( strpos($port_mapping_text, ",") !== FALSE )
                {
                    $port_mapping_list = explode(",", $port_mapping_text);
                    foreach( $port_mapping_list as $list_object )
                    {
                        if( $value == $list_object )
                            return TRUE;
                    }
                }
                elseif( $value == $port_mapping_text )
                    return TRUE;
            }
        }

        return FALSE;
    }
}





