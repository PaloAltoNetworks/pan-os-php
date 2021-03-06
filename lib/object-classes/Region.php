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


class Region
{
    use AddressCommon;
    use PathableName;
    use XmlConvertible;


    /**
     * you should not need this one for normal use
     * @param string $name
     * @param AddressStore $owner
     * @param bool $fromXmlTemplate
     */
    function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $this->owner->addressRoot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);


            $this->owner = null;

            $this->setName( $name );
        }
        else
            $this->name = $name;

    }


    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("region name not found\n");


        return TRUE;
    }

    public function isRegion()
    {
        return TRUE;
    }

    public function name()
    {
        return $this->name;
    }

    /**
     * change the name of this object
     * @param string $newName
     *
     */
    public function setName($newName)
    {
        $this->setRefName($newName);
        $this->xmlroot->setAttribute('name', $newName);

        if( $this->isTmpAddr() )
            unset($this->_ip4Map);
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        if( $this->isTmpAddr() )
        {
            mwarning('renaming of TMP object in API is not possible, it was ignored');
            return;
        }
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();
        $c->sendRenameRequest($xpath, $newName);
        $this->setName($newName);
    }

    /**
     * Return an array['start']= startip and ['end']= endip
     * @return IP4Map
     */
    public function getIP4Mapping()
    {
        if( isset($this->_ip4Map) )
        {
            return $this->_ip4Map;
        }

        $this->_ip4Map = new IP4Map();


        return $this->_ip4Map;
    }


    static protected $templatexml = '<entry name="**temporarynamechangeme**"><address><member>tempvaluechangeme</member></entry>';
}