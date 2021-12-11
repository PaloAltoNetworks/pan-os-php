<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class SaasSecurityProfile
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /** @var string|null */
    protected $value;

    public $_all;

    /** @var SecurityProfileStore|null */
    public $owner;

    public $secprof_type;

    /**
     * you should not need this one for normal use
     * @param string $name
     * @param SecurityProfileStore $owner
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

            if( is_object( $owner->xmlroot ) )
                $rootDoc = $owner->xmlroot->ownerDocument;
            else
            {
                $owner->createXmlRoot();
                $rootDoc = $owner->xmlroot->ownerDocument;
            }
            #$rootDoc = $this->owner->securityProfileRoot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
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
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml, $withoutname = false)
    {
        $this->secprof_type = "saas-security";
        $this->xmlroot = $xml;

        if( !$withoutname )
        {
            $this->name = DH::findAttribute('name', $xml);
            if( $this->name === FALSE )
                derr("Saas-Security SecurityProfile name not found\n");
        }


        return TRUE;
    }

    public function display()
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    ");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);
        //Todo: continue for PH::print_stdout( ); out
    }


    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

