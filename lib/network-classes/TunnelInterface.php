<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class TunnelInterface
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    protected $_ipv4Addresses = array();

    /** @var string */
    public $type = 'tunnel';

    function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
    }


    public function isTunnelType()
    {
        return TRUE;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tunnel name name not found\n");

        $ipNode = DH::findFirstElement('ip', $xml);
        if( $ipNode !== FALSE )
        {
            foreach( $ipNode->childNodes as $l3ipNode )
            {
                if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                //Todo: check if this is for IPv4 and IPv6
                $this->_ipv4Addresses[] = $l3ipNode->getAttribute('name');
            }
        }
    }

    /**
     * @return string
     */
    public function type()
    {
        return $this->type;
    }

    public function getIPv4Addresses()
    {
        return $this->_ipv4Addresses;
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( $this->name != "**temporarynamechangeme**" )
            $this->setRefName($name);

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return TRUE;

    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getTunnelIfStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"><ip/></entry>';
}