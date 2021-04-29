<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class DecryptionProfile
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /** @var SecurityProfileStore|null */
    public $owner = null;


    /**
     * @param SecurityProfileStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
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

            $this->setName($name);
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

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();
        $c->sendRenameRequest($xpath, $newName);
        $this->setName($newName);
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getSecurityProfileStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
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
            derr("DecryptionProfile name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("DecryptionProfile name '" . $this->name . "' is not valid.", $xml);

        return TRUE;
    }

    public function display()
    {
        print "     * " . get_class($this) . " '" . $this->name() . "'    \n";

        /*
        //Todo: continue for print out
        foreach( $this->tmp_url_prof_array as $url_type )
        {
            print "       ".PH::boldText( strtoupper( $url_type ) )."\n";
            foreach( $this->$url_type as $member )
            {
                print "         - ".$member."\n";
            }
        }*/


        print "\n\n";
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isDecryptionProfile()
    {
        return TRUE;
    }

    /**
     * @param $otherObject Tag
     * @return bool
     */
    /*
    public function equals( $otherObject )
    {
        if( ! $otherObject->isTag() )
            return false;

        if( $otherObject->name != $this->name )
            return false;

        return $this->sameValue( $otherObject);
    }

    public function sameValue( Tag $otherObject)
    {
        if( $this->isTmp() && !$otherObject->isTmp() )
            return false;

        if( $otherObject->isTmp() && !$this->isTmp() )
            return false;

        if( $otherObject->color !== $this->color )
            return false;

        return true;
    }
    */
}

