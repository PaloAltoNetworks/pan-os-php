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


trait RuleWithGroupTag
{
    /** @var Tag */
    public $grouptag = null;

    function grouptag_loadFromXml()
    {
        $xml = DH::findFirstElement('group-tag', $this->xmlroot);

        if( $xml !== FALSE )
        {
            $f = $this->owner->owner->tagStore->find($xml->textContent, $this);
            if( $f == null && is_object($this->owner->owner->tagStore->parentCentralStore))
                $f = $this->owner->owner->tagStore->parentCentralStore->find($xml->textContent, $this);
            if( $f != null )
            {
                $f->addReference( $this );
                $this->grouptag = $f;
            }
        }
    }

    /*
    public function referencedObjectRenamed($h, $oldname = "")
    {
        if( $this->grouptag === $h )
        {
            $this->rewriteGroupTag_XML();
            return;
        }
    }
    */

    public function rewriteGroupTag_XML()
    {
        if( $this->grouptag === null )
        {
            $tmpRoot = DH::findFirstElement('group-tag', $this->xmlroot);

            if( $tmpRoot === FALSE )
                return TRUE;

            $this->xmlroot->removeChild($tmpRoot);
        }
        else
        {
            $tmpRoot = DH::findFirstElementOrCreate('group-tag', $this->xmlroot);
            DH::setDomNodeText($tmpRoot, $this->grouptag->name());
        }
    }

    /**
     * return grouptag txt if rule has grouptag set
     * @return null
     */
    public function groupTag()
    {
        return $this->grouptag;
    }

    public function grouptagIs( $value )
    {
        if( $this->grouptag === null )
            return false;
        if( $this->grouptag->name() === $value->name() )
            return true;
        return false;
    }

    /**
     * @param null|string $newGroupTag empty or null description will erase existing one
     * @return bool false if no update was made to description (already had same value)
     */
    function setGroupTag($newGroupTag = null)
    {
        if( is_object( $newGroupTag ) )
            $newGroupTag = $newGroupTag->name();

        if( $newGroupTag === null || strlen($newGroupTag) < 1 )
        {
            if( $this->grouptag === null )
                return FALSE;

            if( is_object($this->grouptag) )
                $this->grouptag->removeReference($this);

            $this->grouptag = null;
        }
        else
        {
            $newGroupTag = utf8_encode($newGroupTag);
            if( is_object( $this->grouptag ) && $this->grouptag->name() == $newGroupTag )
                return FALSE;

            if( is_object($this->grouptag) )
                $this->grouptag->removeReference($this);

            $f = $this->owner->owner->tagStore->findOrCreate($newGroupTag, $this);
            if( $f != null )
                $f->addReference( $this );

            $this->grouptag = $f;
        }

        $this->rewriteGroupTag_XML();



        return TRUE;
    }

    /**
     * @return bool true if value was changed
     */
    public function API_setGroupTag($newGroupTag)
    {
        $ret = $this->setGroupTag($newGroupTag);
        if( $ret )
        {
            $xpath = $this->getXPath() . '/group-tag';
            $con = findConnectorOrDie($this);

            if( !is_object( $this->grouptag )  )
                $con->sendDeleteRequest($xpath);
            else
                $con->sendSetRequest($this->getXPath(), '<group-tag>' . htmlspecialchars($this->grouptag->name()) . '</group-tag>');

        }

        return $ret;
    }

    /**
     * @return bool false if no update was made to description (already had same value)
     */
    function removeGroupTag()
    {
        if( $this->grouptag === null )
            return TRUE;

        $this->grouptag = null;
        $tmpRoot = DH::findFirstElement('group-tag', $this->xmlroot);

        if( $tmpRoot === FALSE )
            return TRUE;

        $this->xmlroot->removeChild($tmpRoot);


        return TRUE;
    }

    /**
     * @param string $newGroupTag
     * @return bool true if value was changed
     */
    public function API_removeGroupTag()
    {
        $ret = $this->removeGroupTag();
        if( $ret )
        {
            $xpath = $this->getXPath() . '/group-tag';
            $con = findConnectorOrDie($this);

            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }
}
