<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class SecurityProfile
{
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;
    use ReferenceableObject;

    /** @var string|null */
    protected $value;

    public $secprof_type;

    /** @var SecurityProfileStore|null */
    public $owner;

    const TypeTmp = 0;
    const TypeVirus = 1;
    const TypeSpyware = 2;
    const TypeVulnerability = 3;
    const TypeFile_blocking = 4;
    const TypeWildfire_analysis = 5;
    const TypeUrl_filtering = 6;
    const TypeData_filtering = 7;
    const TypeDNS_security = 8;
    const TypeSaas_security = 9;

    static private $SecurityProfileTypes = array(
        self::TypeTmp => 'tmp',
        self::TypeVirus => 'virus',
        self::TypeSpyware => 'spyware',
        self::TypeVulnerability => 'vulnerability',
        self::TypeFile_blocking => 'file-blocking',
        self::TypeWildfire_analysis => 'wildfire-analysis',
        self::TypeUrl_filtering => 'url-filtering',
        self::TypeData_filtering => 'data-filtering',
        self::TypeDNS_security => 'dns-security',
        self::TypeSaas_security => 'saas-security'
    );

    public $type = self::TypeTmp;


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

            $rootDoc = $this->owner->securityProfileRoot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
        }

        $this->name = $name;
    }


    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->secprof_type = "secprof";

        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("secprof name not found\n");

        $this->_load_description_from_domxml();

        #PH::print_stdout(  "object named '".$this->name."' found" );


        $typeFound = FALSE;

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */

            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $lsearch = array_search($node->nodeName, self::$SecurityProfileTypes);
            if( $lsearch !== FALSE )
            {
                $typeFound = TRUE;
                $this->type = $lsearch;
                $this->value = $node->textContent;
            }
        }

        if( !$typeFound )
        {
            if( !PH::$ignoreInvalidAddressObjects )
                derr('Object type not found or not supported for address object ' . $this->name . '. Please check your configuration file and fix it or invoke with argument "shadow-ignoreInvalidAddressObjects"', $xml);

            mwarning('Object type not found or not supported for address object ' . $this->name . ' but you manually did bypass this error', $xml);
            return FALSE;
        }

        if( $this->owner->owner->version >= 60 )
        {
            $tagRoot = DH::findFirstElement('tag', $xml);
            if( $tagRoot !== FALSE )
                $this->tags->load_from_domxml($tagRoot);
        }


        return TRUE;
    }



    public function display()
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'"  );
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);
    }



    public function rewriteXML()
    {
        if( $this->isTmpAddr() )
            return;

        DH::clearDomNodeChilds($this->xmlroot);

        $tmp = DH::createElement($this->xmlroot, self::$SecurityProfileTypes[$this->type], $this->value);

        if( $this->_description !== null && strlen($this->_description) > 0 )
        {
            DH::createElement($this->xmlroot, 'description', $this->_description);
        }
    }



    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getAddressStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    /**
     * @return string ie: 'ip-netmask' 'ip-range'
     */
    public function type()
    {
        //return self::$SecurityProfileTypes[$this->type];
        return $this->type;
    }

    public function isSecurityProfile()
    {
        return TRUE;
    }

    public function isTmpSecProf()
    {
        if( $this->type === self::$SecurityProfileTypes[self::TypeTmp] )
            return TRUE;

        return FALSE;
    }

    public function isTmp()
    {
        return self::isTmpSecProf();
    }

    public function isType_Virus()
    {
        return $this->type == self::TypeVirus;
    }

    public function isType_Spyware()
    {
        return $this->type == self::TypeSpyware;
    }

    public function isType_Vulnerability()
    {
        return $this->type == self::TypeVulnerability;
    }

    public function isType_TMP()
    {
        return $this->type == self::TypeTmp;
    }

    public function isType_File_blocking()
    {
        return $this->type == self::TypeFile_blocking;
    }

    public function isType_Wildfire_analysis()
    {
        return $this->type == self::TypeWildfire_analysis;
    }

    public function isType_Url_filtering()
    {
        return $this->type == self::TypeUrl_filtering;
    }

    /**
     * @param $otherObject SecurityProfile
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isSecurityProfile() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(SecurityProfile $otherObject)
    {
        if( $this->isTmpSecProf() && !$otherObject->isTmpSecProf() )
            return FALSE;

        if( $otherObject->isTmpSecProf() && !$this->isTmpSecProf() )
            return FALSE;

        if( $otherObject->type !== $this->type )
            return FALSE;

        if( $otherObject->value !== $this->value )
            return FALSE;

        return TRUE;
    }


    public function removeReference($object)
    {
        $this->super_removeReference($object);

        // adding extra cleaning
        if( $this->isTmpSecProf() && $this->countReferences() == 0 && $this->owner !== null )
        {
            //todo fix as remove has protected
            #$this->owner->remove($this);
        }

    }

    static $templatexml = '<entry name="**temporarynamechangeme**"><ip-netmask>tempvaluechangeme</ip-netmask></entry>';

}

