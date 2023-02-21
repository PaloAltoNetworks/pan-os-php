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
    public $privateKeyAlgorithm = null;
    public $privateKeyHash = null;

    public $publicKey = null;
    public $publicKeyLen = null;
    public $publicKeyAlgorithm = null;
    public $publicKeyHash = null;

    public $notValidbefore = null;
    public $notValidafter = null;

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
        $notValidbefore = DH::findFirstElement('not-valid-before', $xml);
        if( $notValidbefore !== FALSE )
        {
            if( $notValidbefore->textContent !== "" )
                $this->notValidbefore = $notValidbefore->textContent;
        }
        $notValidafter = DH::findFirstElement('not-valid-after', $xml);
        if( $notValidafter !== FALSE )
        {
            if( $notValidafter->textContent !== "" )
                $this->notValidafter = $notValidafter->textContent;
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
                #$this->privateKeyLen = strlen($this->privateKey);

                /*
                //openssl x509 -in "cert.pem" -text -noout
                file_put_contents("/tmp/cert.pem", $this->privateKey);
                exec('openssl x509 -in "/tmp/cert.pem" -text -noout', $output);

                $string = implode( "\n", $output );

                $pattern = "/Public Key Algorithm: (.*)\n/im";
                if( preg_match($pattern, $string, $matches) )
                {
                    $str = str_replace( "Encryption", "", $matches[1] );
                    $this->privateKeyAlgorithm = $str;
                }

                $pattern = "/Public-Key: (.*)\n/im";
                if( preg_match($pattern, $string, $matches) )
                {
                    $str = str_replace( "(", "", $matches[1] );
                    $str = str_replace( " bit)", "", $str );
                    $this->privateKeyLen = $str;
                }


                $pattern = "/Signature Algorithm: (.*)\n/im";
                if( preg_match($pattern, $string, $matches) )
                {
                    $str_Array = explode( "With", $matches[1] );
                    $this->privateKeyHash = $str_Array[0];
                }
                */
            }
        }

        $publickey = DH::findFirstElement('public-key', $xml);
        if( $publickey !== FALSE )
        {
            if( $publickey->textContent !== "" )
            {
                $this->publicKey = $publickey->textContent;

                ###########################################################################

                $pkey_obj = openssl_pkey_get_public( $this->publicKey );
                $cert_details = openssl_pkey_get_details( $pkey_obj );
                #print_r( $cert_details );

                //publicKey Algorithm
                if( isset( $cert_details['rsa'] ) )
                    $this->publicKeyAlgorithm = 'rsa';
                elseif( isset( $cert_details['dsa'] ) )
                    $this->publicKeyAlgorithm = 'dsa';
                elseif( isset( $cert_details['dh'] ) )
                    $this->publicKeyAlgorithm = 'dh';
                elseif( isset( $cert_details['ec'] ) )
                    $this->publicKeyAlgorithm = 'ec';

                //publicKey Bits
                if( isset( $cert_details['bits'] ) )
                    $this->publicKeyLen = $cert_details['bits'];


                //this does not container the bits
                $cert = openssl_x509_read( $this->publicKey );
                $cert_obj = openssl_x509_parse( $cert );
                #print_r( $cert_obj );

                //publicKey Signature Algorithm
                if( isset( $cert_obj['signatureTypeLN'] ) )
                {
                    //[signatureTypeSN] => RSA-SHA256
                    //    [signatureTypeLN] => sha256WithRSAEncryption

                    if( strpos( $cert_obj['signatureTypeLN'], 'ecdsa' ) !== False   )
                    {
                        $str_Array = explode( "ecdsa-with-", $cert_obj['signatureTypeLN'] );
                        $string = strtolower($str_Array[1]);
                        $this->publicKeyHash = $string;
                    }
                    else
                    {
                        $str_Array = explode( "With", $cert_obj['signatureTypeLN'] );
                        $this->publicKeyHash = $str_Array[0];
                    }
                }
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

    public function hasPublicKey()
    {
        if( $this->publicKey !== null )
            return true;

        return false;
    }

    public function getPkeyAlgorithm()
    {
        return $this->publicKeyAlgorithm;
    }

    public function getPkeyBits()
    {
        return $this->publicKeyLen;
    }

    public function getPkeyHash()
    {
        return $this->publicKeyHash;
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



