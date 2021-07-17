<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class URLProfile
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

    public $allow = array();
    public $alert = array();
    public $block = array();
    public $continue = array();
    public $override = array();


    /*
        const TypeTmp = 0;
        const TypeVirus = 1;
        const TypeSpyware = 2;
        const TypeVulnerability = 3;
        const TypeFile_blocking = 4;
        const TypeWildfire_analysis = 5;
        const TypeUrl_filtering = 6;



        static private $SecurityProfileTypes = Array(self::TypeTmp => 'tmp',
            self::TypeVirus => 'virus',
            self::TypeSpyware => 'spyware',
            self::TypeVulnerability => 'vulnerability',
            self::TypeFile_blocking => 'file-blocking',
            self::TypeWildfire_analysis => 'wildfire-analysis',
            self::TypeUrl_filtering =>  'url-filtering'
        );



        protected $type = self::TypeTmp;
    */
    public $tmp_url_prof_array = array('allow', 'alert', 'block', 'continue', 'override');

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
    public function load_from_domxml(DOMElement $xml, $withOwner = true )
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("URL SecurityProfile name not found\n");

        #print "\nsecprofURL TMP: object named '".$this->name."' found\n";

        if( $withOwner )
        {
            if(  get_class($this->owner->owner) == "PanoramaConf" || get_class($this->owner->owner) == "PANConf" || get_class($this->owner->owner) == "FawkesConf" )
                $predefined_urls = $this->owner->owner->urlStore->securityProfiles();
            else
                $predefined_urls = $this->owner->owner->owner->urlStore->securityProfiles();
            foreach( $predefined_urls as $predefined_url )
                $this->allow[$predefined_url->name()] = $predefined_url->name();
        }
        else
        {
            $this->allow = array();
        }



        foreach( $this->tmp_url_prof_array as $url_type )
        {
            $tmp_url_action = DH::findFirstElement($url_type, $xml);
            if( $tmp_url_action !== FALSE )
            {
                foreach( $tmp_url_action->childNodes as $tmp_entry )
                {
                    if( $tmp_entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $url_category = $tmp_entry->textContent;
                    $this->_all[ $url_category ] = $url_type;

                    if( $url_type == 'allow' )
                        $this->allow[ $url_category ] = $url_category;
                    elseif( $url_type !== 'allow' )
                    {
                        if( $url_type == 'alert' )
                            $this->alert[ $url_category ] = $url_category;
                        elseif( $url_type == 'block' )
                            $this->block[ $url_category ] = $url_category;
                        elseif( $url_type == 'continue' )
                            $this->continue[ $url_category ] = $url_category;
                        elseif( $url_type == 'override' )
                            $this->override[ $url_category ] = $url_category;

                        unset($this->allow[ $url_category ]);
                    }
                }
            }
        }

        return TRUE;
    }


    public function display()
    {
        print "     * " . get_class($this) . " '" . $this->name() . "'    \n";

        //Todo: continue for print out
        foreach( $this->tmp_url_prof_array as $url_type )
        {
            print "       " . PH::boldText(strtoupper($url_type)) . "\n";
            sort($this->$url_type);
            foreach( $this->$url_type as $member )
            {
                print "         - " . $member . "\n";
            }
        }

        #print "\n\n";
    }

    public function getAllow()
    {
        return $this->allow;
    }

    public function getAlert()
    {
        return $this->alert;
    }

    public function getBlock()
    {
        return $this->block;
    }

    public function getContinue()
    {
        return $this->continue;
    }

    public function getOverride()
    {
        return $this->override;
    }

    public function setAction($action, $filter)
    {
        if( $filter == "all" )
        {
            //Todo:
            //1) update memory
            //2) update XML
            //3) update API
        }
        elseif( strpos($filter, "all-") !== FALSE )
        {
            $tmp_action = explode("all-", $filter);


        }
        else
        {
            //check if input is possible category;
            $curr_action = getAction($filter);
            //category
        }

    }


//ALL above are wrong and from addressstroe
//TOdo:

    /**
     * @return string ie: 'ip-netmask' 'ip-range'
     */
    public function type()
    {
        return self::$SecurityProfileTypes[$this->type];
    }

    public function isSecurityProfile()
    {
        return TRUE;
    }

    public function isTmpSecProf()
    {
        if( $this->type == self::TypeTmp )
            return TRUE;

        return FALSE;
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


    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

