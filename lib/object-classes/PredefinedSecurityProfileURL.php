<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class PredefinedSecurityProfileURL
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /** @var SecurityProfileStore|null */
    public $owner = null;

    /** @var array $members */
    private $members = array();

    /** @var DOMElement */
    private $membersRoot = null;

    /**
     * @param SecurityProfileStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($owner, $fromXmlTemplate = FALSE)
    {
        #$this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElement('entry', $doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            #$this->setName($name);
        }

        $this->owner = $owner;

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
        if( $this->xmlroot === null )
            return TRUE;
        return FALSE;
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
            derr("PredefinedProfileURL name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("PredefinedProfileURL name '" . $this->name . "' is not valid.", $xml);


        return TRUE;
    }


    public function display()
    {
        print "     * " . get_class($this) . " '" . $this->name() . "'    \n";

        print "\n\n";
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isPredefinedURL()
    {
        return TRUE;
    }
}

