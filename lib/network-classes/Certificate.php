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

class Certificate
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var null|CertificateStore */
    public $owner = null;

    private $isTmp = TRUE;

    public $_type = 'tmp';


    public $algorithm = null;

    public $commonName = null;
    public $privateKey = null;
    public $privateKeyLen = null;

    public $publicKey = null;
    public $publicKeyLen = null;

    /**
     * @param string $name
     * @param CertificateStore $owner
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        if( !is_string($name) )
            derr('name must be a string');

        $this->owner = $owner;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();

            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $this->owner->xmlroot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);

            #$this->owner = null;
            $this->setName($name);
            $this->owner = $owner;

            $this->load_from_domxml($this->xmlroot);

        }

        $this->name = $name;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }


    public function isTmp()
    {
        return $this->isTmp;
    }

    public function type()
    {
        return $this->_type;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->isTmp = FALSE;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("certificate name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("Certificate name '" . $this->name . "' is not valid", $xml);

        $algorithm = DH::findFirstElement('algorithm', $xml);
        if( $algorithm !== FALSE )
        {
            if( $algorithm->textContent !== "" )
                $this->algorithm = $algorithm->textContent;
        }

        $commonName = DH::findFirstElement('common-name', $xml);
        if( $commonName !== FALSE )
        {
            if( $commonName->textContent !== "" )
                $this->commonName = $commonName->textContent;
        }

        $privatekey = DH::findFirstElement('private-key', $xml);
        if( $privatekey !== FALSE )
        {
            if( $privatekey->textContent !== "" )
            {
                $this->privateKey = $privatekey->textContent;
                $this->privateKeyLen = strlen($this->privateKey);
            }
        }

        $publickey = DH::findFirstElement('public-key', $xml);
        if( $publickey !== FALSE )
        {
            if( $publickey->textContent !== "" )
            {
                $this->publicKey = $publickey->textContent;
                $this->publicKeyLen = strlen($this->publicKey);
            }
        }
    }


    public function API_setName($newname)
    {
        if( !$this->isTmp() )
        {
            $c = findConnectorOrDie($this);
            $path = $this->getXPath();

            $c->sendRenameRequest($path, $newname);
        }
        else
        {
            mwarning('this is a temporary object, cannot be renamed from API');
        }

        $this->setName($newname);
    }


    public function &getXPath()
    {
        if( $this->isTmp() )
            derr('no xpath on temporary objects');

        $str = $this->owner->getXPath() . "entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner->owner  !== null && get_class( $this->owner->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }

        return $str;
    }


    static protected $templatexml = '<entry name="**temporarynamechangeme**"></entry>';
}



