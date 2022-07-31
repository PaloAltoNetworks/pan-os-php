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
 * @property DOMElement|null $xmlroot
 */
trait ObjectWithDescription
{
    /** @var string */
    protected $_description = null;

    /**
     * @return string if no description then string will be empty: ''
     */
    function description()
    {
        if( $this->_description === null )
            return '';

        return $this->_description;
    }

    /**
     * @param null|string $newDescription empty or null description will erase existing one
     * @return bool false if no update was made to description (already had same value)
     */
    function setDescription($newDescription = null, $tagName = "description")
    {
        if( $newDescription === null || strlen($newDescription) < 1 )
        {
            if( $this->_description === null )
                return FALSE;

            $this->_description = null;
            $tmpRoot = DH::findFirstElement($tagName, $this->xmlroot);

            if( $tmpRoot === FALSE )
                return TRUE;

            $this->xmlroot->removeChild($tmpRoot);
        }
        else
        {
            $newDescription = utf8_encode($newDescription);
            if( $this->_description == $newDescription )
                return FALSE;
            $this->_description = $newDescription;
            $tmpRoot = DH::findFirstElementOrCreate($tagName, $this->xmlroot);
            DH::setDomNodeText($tmpRoot, $this->_description);
        }

        return TRUE;
    }


    /**
     * @param string $newDescription
     * @return bool true if value was changed
     */
    public function API_setDescription($newDescription, $tagName = "description")
    {
        $ret = $this->setDescription($newDescription, $tagName);
        if( $ret )
        {
            $xpath = $this->getXPath() . '/' . $tagName;
            $con = findConnectorOrDie($this);

            if( strlen($this->_description) < 1 )
                $con->sendDeleteRequest($xpath);
            else
                $con->sendSetRequest($this->getXPath(), '<' . $tagName . '>' . htmlspecialchars($this->_description) . '</' . $tagName . '>');

        }

        return $ret;
    }

    public function description_merge( $other )
    {
        $description = $this->description();
        $other_description = $other->description();

        if ( (empty($description) && empty($other_description)) || ( !empty($description) && !empty($other_description) && strpos($description, $other_description) !== false  )) {
            return;
        }
        if( empty($other_description) )
            return;

        $new_description = $description;

        //Todo: validation needed
        //1) to long
        //2) take half max of first and half max of second

        $description_len = strlen($description);
        $other_description_len = strlen($other_description);

        if( $this->owner->owner->version < 71 )
            $max_length = 253;
        else
            $max_length = 1020;

        if( $description_len + $other_description_len > $max_length )
        {
            if( $description_len > $max_length / 2 && $other_description_len > $max_length / 2 )
            {
                $new_description = substr($description, 0, $max_length / 2 - 1) . "|" . substr($other_description, 0, $max_length / 2 - 1);
            }
            else
                $new_description = substr($description . "|" . $other_description, 0, $max_length);
        }
        else
            $new_description = $description . "|" . $other_description;

        $this->setDescription($new_description);
    }

    protected function _load_description_from_domxml()
    {
        $descroot = DH::findFirstElement('description', $this->xmlroot);
        if( $descroot !== FALSE )
            $this->_description = $descroot->textContent;
    }

}

