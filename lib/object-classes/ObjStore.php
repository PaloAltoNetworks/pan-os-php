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

class ObjStore
{
    use PathableName;
    use XmlConvertible;


    public $owner = null;
    public $name = '';

    /** @var null|ReferenceableObject[] */
    public $o = array();

    /** @var null|ReferenceableObject[] */
    protected $nameIndex = array();

    protected $classn = null;

    protected $skipEmptyXmlObjects = FALSE;


    public function count()
    {
        return count($this->o);
    }

    public function countUnused()
    {
        $count = 0;
        foreach( $this->o as $o )
        {
            if( $o->countReferences() == 0 )
                $count++;
        }

        return $count;
    }

    public function setName($newname)
    {
        $this->name = $newname;
    }

    public function name()
    {
        return $this->name;
    }

    //Todo: check if $nested = false; must be set
    #NEW - protected function findByName($name, $ref = null, $nested = FALSE)
    protected function findByName($name, $ref = null, $nested = TRUE)
    {
        if( isset($this->nameIndex[$name]) )
        {
            $o = $this->nameIndex[$name];
            if( $ref !== null )
                $o->addReference($ref);
            return $o;
        }

        if( get_class( $this ) == "EthernetIfStore" || get_class( $this ) == "AggregateEthernetIfStore" || get_class( $this ) == "VirtuelWireStore" )
            return null;

        if( $nested && isset($this->parentCentralStore) && $this->parentCentralStore !== null )
        {
            $f = $this->parentCentralStore->findbyName($name, $ref, $nested);
            if( $f !== null )
                return $f;
        }

        return null;
    }

    public function find($name )
    {
        $f = $this->findByName( $name );

        if( $f !== null )
            return $f;

        return null;
    }

    /**
     * Returns 'true' if this object is in the store
     *
     */
    public function inStore($Obj)
    {
        if( in_array($Obj, $this->o, TRUE) )
        {
            return TRUE;
        }

        return FALSE;
    }


    /**
     * search for object with its name and returns it. If it doesn't exist, create it and return it.
     *
     */
    public function findOrCreate($name, $ref = null)
    {
        $f = $this->findByName($name, $ref);

        if( $f !== null )
            return $f;

        $f = $this->createTmp($name, $ref);

        return $f;
    }

    function createTmp($name, $ref = null)
    {

        $f = new $this->classn($name, $this);
        /** @var ReferenceableObject $f */

        $this->o[] = $f;
        $this->nameIndex[$name] = $f;
        $f->type = 'tmp';
        $f->addReference($ref);

        return $f;
    }


    /**
     *
     *
     */
    public function display($indentSpace = 0)
    {
        $indent = '';

        for( $i = 0; $i < $indentSpace; $i++ )
        {
            $indent .= ' ';
        }

        $c = count($this->o);
        $k = array_keys($this->o);

        PH::print_stdout( "$indent" );
        PH::print_stdout( "Displaying the $c " . $this->classn . "(s) in " . $this->toString() );

        for( $i = 0; $i < $c; $i++ )
        {
            PH::print_stdout( $indent . $this->o[$k[$i]]->name );
        }
    }

    /**
     * @param ReferenceableObject $h
     * @param string $oldName
     * @throws Exception
     */
    public function referencedObjectRenamed($h, $oldName)
    {
        if( isset($this->nameIndex[$h->name()]) )
        {
            derr("an object with this name already exists in this store");
        }

        if( isset($this->nameIndex[$oldName]) )
        {
            $o = $this->nameIndex[$oldName];
            if( $o === $h )
            {
                unset($this->nameIndex[$oldName]);
                $this->nameIndex[$h->name()] = $h;
            }
            else
                mwarning("tried to broadcast name change to a Store that doesnt own this object");
        }
        else
        {
            #mwarning("object with name '{$oldName}' was not part of this store/index");
        }

    }


    /**
     * @param ReferenceableObject $Obj
     * @return bool
     * @ignore
     */
    protected function add($Obj)
    {
        if( !in_array($Obj, $this->o, TRUE) )
        {
            $this->o[] = $Obj;
            $this->nameIndex[$Obj->name()] = $Obj;
            $Obj->owner = $this;

            return TRUE;
        }

        return FALSE;
    }

    protected function removeAll()
    {
        foreach( $this->o as $o )
        {
            $o->owner = null;
        }

        $this->o = array();
        $this->nameIndex = array();
    }

    /**
     * @param ReferenceableObject $Obj
     * @return bool
     */
    protected function remove($Obj)
    {
        $pos = array_search($Obj, $this->o, TRUE);
        if( $pos !== FALSE )
        {
            unset($this->o[$pos]);
            unset($this->nameIndex[$Obj->name()]);
            $Obj->owner = null;

            return TRUE;
        }

        return FALSE;
    }

    /**
     * Returns an array with all objects in store
     * @return array
     */
    public function getAll()
    {
        return $this->o;
    }


    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $o )
            {
                $this->xmlroot->appendChild($o->xmlroot);
            }
        }
    }


    /**
     * should only be called from a store constructor
     * @ignore
     */
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


            $newObj = new $this->classn('**tmp**', $this);
            $newObj->load_from_domxml($node);


            $this->o[] = $newObj;
            $this->nameIndex[$newObj->name()] = $newObj;
        }
    }

    /**
     * Returns an Array with all Address|AddressGroup inside this store
     * @return Tag[]|Schedule[]
     */
    public function &resultingObjectSet()
    {

        $res = array();

        if( isset($this->owner->parentDeviceGroup) )
        {
            $varName = $this->storeName();
            /** @var ServiceStore $var */
            $var = $this->owner->parentDeviceGroup->$varName;
            #$var = $this->owner->parentDeviceGroup->serviceStore;
            $res = $var->resultingObjectSet();
        }
        elseif( $this->owner->isPanorama() )
        {
            $varName = $this->storeName();
            /** @var ServiceStore $var */
            $var = $this->owner->$varName;
            #$var = $this->owner->serviceStore;
            $res = $var->all();
        }

        if( !$this->owner->isPanorama() )
        {
            $varName = $this->storeName();
            if( $varName == "tagStore" )
                $res = array_merge($res, $this->getAll());
            elseif( $varName == "scheduleStore" )
                $res = array_merge($res, $this->getAll());
        }


        return $res;
    }

}

