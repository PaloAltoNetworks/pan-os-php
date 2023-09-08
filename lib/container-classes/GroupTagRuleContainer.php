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
 * Class GroupTagRuleContainer
 * @property Tag[] $o
 * @property Rule $owner
 */
class GroupTagRuleContainer extends ObjRuleContainer
{
    /** @var null|TagStore */
    public $parentCentralStore = null;

    public function __construct($owner)
    {
        $this->owner = $owner;
        $this->name = 'group-tag';

        $this->findParentCentralStore( 'tagStore' );
    }


    public function removeAllTags()
    {
        $this->removeAll();
        $this->rewriteXML();
    }

    public function removeTag(Tag $tag, $rewriteXML = TRUE)
    {

        $ret = $this->remove($tag);

        if( $ret && $rewriteXML )
        {
            $this->rewriteXML();
        }

        return $ret;
    }

    public function API_removeTag(Tag $tag, $rewriteXML = TRUE)
    {
        if( $this->removeTag($tag, $rewriteXML) )
        {
            $con = findConnectorOrDie($this);
            $xpath = $this->getXPath();
            $con->sendDeleteRequest($xpath);

            return TRUE;
        }

        return FALSE;
    }


    public function merge(GroupTagRuleContainer $container, $exclusionFilter = null)
    {
        $change = FALSE;
        foreach( $container->o as $obj )
        {
            if( !$this->has($obj) )
            {
                $exclude = FALSE;
                if( $exclusionFilter !== null )
                {
                    foreach( $exclusionFilter as &$filter )
                    {
                        if( strpos($obj->name(), $filter) === 0 )
                        {
                            $exclude = TRUE;
                            break;
                        }
                    }
                }

                if( !$exclude )
                {
                    $change = TRUE;
                    $this->addTag($obj);
                }
            }
        }

        return $change;
    }

    /**
     * @param Tag|string can be Tag object or tag name (string). this is case sensitive
     * @param bool
     * @return bool
     */
    public function hasTag($tag, $caseSensitive = TRUE)
    {
        return $this->has($tag, $caseSensitive);
    }

    /**
     * @param Tag|string can be Tag object or tag name (string). this is case sensitive
     * @return bool
     */
    public function hasTagRegex($regex)
    {
        return $this->hasObjectRegex($regex);
    }


    /**
     * add a Tag to this container
     * @param string|Tag
     * @param bool
     * @return bool
     */
    public function addTag($Obj, $rewriteXML = TRUE)
    {
        if( is_string($Obj) )
        {
            $f = $this->parentCentralStore->findOrCreate($Obj);
            if( $f === null )
            {
                derr(": Error : cannot find tag named '" . $Obj . "'\n");
            }
            return $this->addTag($f);
        }

        $ret = $this->add($Obj);

        if( $ret && $rewriteXML )
        {
            $this->rewriteXML();
        }

        return $ret;
    }

    /**
     * @param Tag|String $Obj
     * @param bool|true $rewriteXML
     * @return bool
     */
    public function API_addTag($Obj, $rewriteXML = TRUE)
    {
        if( $this->addTag($Obj, $rewriteXML) )
        {
            $con = findConnectorOrDie($this);

            $con->sendSetRequest($this->getXPath(), $Obj->name());

            return TRUE;
        }

        return FALSE;
    }

    public function &getXPath()
    {
        $xpath = $this->owner->getXPath() . '/group-tag';
        return $xpath;
    }


    /**
     * returns a copy of current Tag array
     * @return Tag[]
     */
    public function tags()
    {
        return $this->o;
    }


    /**
     * @param DOMElement $xml
     *      * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;
        $toBeCleaned = array();

        $f = $this->parentCentralStore->findOrCreate($xml->textContent, $this);
        $this->o[] = $f;
        /*
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( strlen($node->textContent) < 1 )
            {
                mwarning('invalid (empty) tag name found in rule "' . $this->owner->toString() . '", IT WILL BE CLEANED', $node);
                $toBeCleaned[] = $node;
            }
            else
            {
                $f = $this->parentCentralStore->findOrCreate($node->textContent, $this);
                $this->o[] = $f;
            }
        }

        foreach( $toBeCleaned as $cleanMe )
        {
            $xml->removeChild($cleanMe);
        }
        */
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                $this->xmlroot = DH::createElement($this->owner->xmlroot, 'group-tag');
            $tmpKey = key($this->o);
            #print "|".$this->o[$tmpKey]->name()."|\n";
            $tmpName = $this->o[$tmpKey]->name();
            TAG::revertreplaceNamewith( $tmpName );
            $this->xmlroot->textContent = $tmpName;
            #DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', FALSE);
        }
        else
        {
            if( $this->xmlroot !== null )
            {
                $this->owner->xmlroot->removeChild($this->xmlroot);
                $this->xmlroot = null;
            }
        }
    }



    public function copy(GroupTagRuleContainer $other)
    {
        $this->removeAll();

        foreach( $other->o as $member )
        {
            $this->add($member);
        }

        $this->rewriteXML();
    }

}



