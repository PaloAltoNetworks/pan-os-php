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
 * Class ObjRuleContainer
 * @property $fasthashcomp string
 */
class ObjRuleContainer
{
    use PathableName;
    use XmlConvertible;


    public $owner = null;
    public $name = '';

    public $o = array();

    public function count()
    {
        return count($this->o);
    }

    public function setName($newname)
    {
        $this->name = $newname;
    }


    /**
     * Return true if all objects from this store are the same then in the other store.
     *
     */
    public function equals($ostore)
    {
        if( count($ostore->o) != count($this->o) )
        {
            //PH::print_stdout( "Not same count '".count($ostore->o)."':'".count($this->o)."'" );
            return FALSE;
        }
        //PH::print_stdout( "passed" );
        foreach( $this->o as $o )
        {
            if( !in_array($o, $ostore->o, TRUE) )
                return FALSE;
        }
        return TRUE;
    }


    public function equals_fasterHash($other)
    {
        $thisHash = $this->getFastHashComp();
        $otherHash = $other->getFastHashComp();

        if( $thisHash == $otherHash )
        {
            if( $this->equals($other) )
                return TRUE;
        }

        return FALSE;
    }


    public function generateFastHashComp($force = FALSE)
    {
        if( isset($this->fasthashcomp) && $this->fasthashcomp !== null && !$force )
            return;

        $class = get_class($this);
        $this->fasthashcomp = $class;

        $tmpa = $this->o;

        usort($tmpa, "__CmpObjName");

        foreach( $tmpa as $o )
        {
            $this->fasthashcomp .= '.*/' . $o->name();
        }

        $this->fasthashcomp = md5($this->fasthashcomp, TRUE);

    }

    public function getFastHashComp()
    {
        if( !isset($this->fasthashcomp) || $this->fasthashcomp === null )
            $this->generateFastHashComp();

        return $this->fasthashcomp;
    }


    protected function has($obj, $caseSensitive = TRUE)
    {
        if( is_string($obj) )
        {
            if( !$caseSensitive )
                $obj = strtolower($obj);

            foreach( $this->o as $o )
            {
                if( !$caseSensitive )
                {
                    if( $obj == strtolower($o->name()) )
                    {
                        return TRUE;
                    }
                }
                else
                {
                    if( $obj == $o->name() )
                        return TRUE;
                }
            }
            return FALSE;
        }

        foreach( $this->o as $o )
        {
            if( $o === $obj )
                return TRUE;
        }

        return FALSE;
    }

    /**
     * @param string $regex
     * @return bool
     */
    protected function hasObjectRegex($regex)
    {
        foreach( $this->o as $o )
        {
            $matching = preg_match($regex, $o->name());
            if( $matching === FALSE )
                derr("regular expression error on '$regex'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
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

        $text = "$indent";
        $text .= "Displaying the $c object(s) in " . $this->toString();
        PH::print_stdout( $text );

        foreach( $this->o as $o )
        {
            PH::print_stdout($indent . $o->name() );
        }
    }

    public function toString_inline()
    {
        return PH::list_to_string($this->o);
    }


    public function referencedObjectRenamed($h)
    {
        if( in_array($h, $this->o, TRUE) )
        {
            $this->fasthashcomp = null;
            $this->rewriteXML();
        }
    }

    public function replaceReferencedObject($old, $new)
    {
        if( $old === $new )
            return FALSE;

        $pos = array_search($old, $this->o, TRUE);

        if( $pos !== FALSE )
        {
            while( $pos !== FALSE )
            {
                unset($this->o[$pos]);
                $pos = array_search($old, $this->o, TRUE);
            }

            if( $new !== null && !$this->has($new->name()) )
            {
                $this->o[] = $new;
                $new->addReference($this);
            }
            $old->removeReference($this);

            if( $new === null || $new->name() != $old->name() )
                $this->rewriteXML();

            return TRUE;
        }
        #elseif( !$this->isDynamic() )
        #    mwarning("object is not part of this group: " . $old->toString());



        return FALSE;
    }

    public function API_replaceReferencedObject($old, $new)
    {
        $ret = $this->replaceReferencedObject($old, $new);

        if( $ret )
        {
            $this->API_sync();
        }

        return $ret;
    }

    /**
     *
     * @ignore
     **/
    protected function add($Obj)
    {
        if( !in_array($Obj, $this->o, TRUE) )
        {
            if( isset($this->fasthashcomp) )
                unset($this->fasthashcomp);

            $this->o[] = $Obj;

            $Obj->addReference($this);

            return TRUE;
        }

        return FALSE;
    }

    protected function removeAll()
    {
        if( isset($this->fasthashcomp) )
            unset($this->fasthashcomp);

        foreach( $this->o as $o )
        {
            $o->removeReference($this);
        }

        $this->o = array();

    }

    protected function remove($Obj)
    {
        if( isset($this->fasthashcomp) )
            unset($this->fasthashcomp);

        $pos = array_search($Obj, $this->o, TRUE);
        if( $pos !== FALSE )
        {
            unset($this->o[$pos]);

            $Obj->removeReference($this);

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

    public function __destruct()
    {
        if( PH::$ignoreDestructors )
            return;

        if( $this->o === null )
            return;

        // remove this object from the referencers list
        foreach( $this->o as $o )
        {
            $o->removeReference($this);
        }

        $this->o = null;
        $this->owner = null;
    }

    /**
     * @param int $position
     * @throws Exception
     */
    public function getItemAtPosition($position)
    {
        if( $position < 0 )
            derr("cannot request an item with negative position ($position)");

        if( $position > count($this->o) )
            derr("requesting item position #$position but this container has only " . count($this->o) . "objects");

        return $this->o[array_keys($this->o)[$position]];

    }


    /*public function rewriteXML()
    {
        if( $this->centralStore )
        {
            clearA($this->xmlroot['children']);
        }

    }*/


    public function &getMembersDiff($otherObject)
    {
        $result = array('minus' => array(), 'plus' => array());

        $localObjects = $this->o;
        $otherObjects = $otherObject->o;

        usort($localObjects, '__CmpObjName');
        usort($otherObjects, '__CmpObjName');

        $diff = array_udiff($otherObjects, $localObjects, '__CmpObjName');
        if( count($diff) != 0 )
            foreach( $diff as $d )
            {
                $result['minus'][] = $d;
            }

        $diff = array_udiff($localObjects, $otherObjects, '__CmpObjName');
        if( count($diff) != 0 )
            foreach( $diff as $d )
            {
                $result['plus'][] = $d;
            }

        return $result;
    }

    public function displayMembersDiff($otherObject, $indent = 0, $toString = FALSE)
    {
        $retString = '';

        $indent = str_pad(' ', $indent);


        $retString .= $indent . "Diff for between " . $this->toString() . " vs " . $otherObject->toString() . "\n";

        $diff = $this->getMembersDiff($otherObject);

        if( count($diff['minus']) != 0 )
            foreach( $diff['minus'] as $d )
            {
                /** @var Address|AddressGroup $d */
                $retString .= $indent . " - {$d->name()}\n";
            }

        if( count($diff['plus']) != 0 )
            foreach( $diff['plus'] as $d )
            {
                $retString .= $indent . " + {$d->name()}\n";
            }

        if( $toString )
            return $retString;

        PH::print_stdout( $retString );
    }

    public function name()
    {
        return $this->name;
    }

    /**
     *
     * @ignore
     */

    public function findParentCentralStore( $storeType )
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $currentObject = $this;
            while( isset($currentObject->owner) && $currentObject->owner !== null )
            {
                if( isset($currentObject->owner->$storeType) && $currentObject->owner->$storeType !== null )
                {
                    $this->parentCentralStore = $currentObject->owner->$storeType;
                    return;
                }
                $currentObject = $currentObject->owner;
            }
        }
        mwarning('no parent store found!');
    }


}

