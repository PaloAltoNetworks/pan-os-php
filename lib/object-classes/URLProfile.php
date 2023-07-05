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

    public $secprof_type;

    public $allow = array();
    public $alert = array();
    public $block = array();
    public $continue = array();
    public $override = array();

    public $predefined = array();


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
        $this->setName($newName);

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml, $withOwner = true )
    {
        $this->secprof_type = "url-filtering";

        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("URL SecurityProfile name not found\n");

        #PH::print_stdout( "\nsecprofURL TMP: object named '".$this->name."' found");

        if( $withOwner )
        {
            if(  get_class($this->owner->owner) == "PanoramaConf" || get_class($this->owner->owner) == "PANConf" || get_class($this->owner->owner) == "FawkesConf" )
                $predefined_url_store = $this->owner->owner->urlStore;
            else
                $predefined_url_store = $this->owner->owner->owner->urlStore;
            $predefined_urls = $predefined_url_store->securityProfiles();

            foreach( $predefined_urls as $predefined_url )
                $this->allow[$predefined_url->name()] = $predefined_url->name();
            $this->predefined = $this->allow;
        }
        else
        {
            $this->allow = array();
            $this->predefined = $this->allow;
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

                    // add references
                    if( isset( $this->predefined[$url_category] ) )
                    {
                        $tmp_obj = $predefined_url_store->find($url_category);
                        if( $tmp_obj !== null )
                            $tmp_obj->addReference($this);
                    }
                    else
                    {
                        # add references to custom url category
                        $tmp_obj = $this->owner->owner->customURLProfileStore->find( $url_category );
                        if( $tmp_obj !== null )
                            $tmp_obj->addReference($this);
                    }
                }
            }
        }

        return TRUE;
    }


    public function display()
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    " );
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);

        //Todo: continue for PH::print_stdout( ); out
        foreach( $this->tmp_url_prof_array as $url_type )
        {
            PH::print_stdout(  "       " . PH::boldText(strtoupper($url_type)) );
            sort($this->$url_type);
            foreach( $this->$url_type as $member )
            {
                PH::print_stdout(  "         - " . $member );
                PH::$JSON_TMP['sub']['object'][$this->name()][strtoupper($url_type)][] = $member;
            }
        }
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

    public function setAction($action, $category)
    {
        if( $category == "all" )
        {
            //Todo:
            //1) update memory
            //2) update XML
            //3) update API
        }
        elseif( strpos($category, "all-") !== FALSE )
        {
            $tmp_action = explode("all-", $category);

        }
        else
        {
            print "do something\n";
            //check if input is possible category;
            $curr_action = $this->getAction($category);

            print "curAction: ".$curr_action."\n";

            $this->deleteMember( $category, $curr_action );

            $this->addMember( $category, $action);

        }

    }

    public function getAction( $category )
    {
        if( isset( $this->alert[$category] ) )
            return "alert";

        if( isset( $this->block[$category] ) )
            return "block";

        if( isset( $this->continue[$category] ) )
            return "continue";

        if( isset( $this->override[$category] ) )
            return "override";

        return "allow";
    }



//ALL above are wrong and from addressstroe
//TOdo:

    /**
     * Add a member to this group, it must be passed as an object
     * @param string $newMember Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function addMember($newMember, $type, $rewriteXml = TRUE)
    {
        if( !in_array( $type, $this->tmp_url_prof_array ) )
            return false;

        if( !in_array($newMember, $this->$type, TRUE) )
        {
            $this->$type[] = $newMember;
            $this->_all[$newMember] = $type;
            if( $rewriteXml && $this->owner !== null )
            {
                $tmp = DH::findFirstElementOrCreate("credential-enforcement", $this->xmlroot);
                $array = array( $this->xmlroot, $tmp );
                #$array = array( $this->xmlroot );
                foreach( $array as $xmlNode )
                {
                    $tmp = DH::findFirstElementOrCreate($type, $xmlNode);
                    DH::createElement($tmp, 'member', $newMember);
                }
            }

            return TRUE;
        }

        return FALSE;
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param string $newMember Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function deleteMember($newMember, $type, $rewriteXml = TRUE)
    {
        if( !in_array( $type, $this->tmp_url_prof_array ) )
            return false;

        if( in_array($newMember, $this->$type, TRUE) )
        {
            $key = array_search($newMember, $this->$type);
            unset($this->$type[$key]);
            unset($this->_all[$key]);

            if( $rewriteXml && $this->owner !== null )
            {
                $tmp = DH::findFirstElementOrCreate("credential-enforcement", $this->xmlroot);
                $array = array( $this->xmlroot, $tmp );
                #$array = array( $this->xmlroot );
                foreach( $array as $xmlNode )
                {
                    $actionXMLnode = DH::findFirstElementOrCreate($type, $xmlNode);
                    foreach( $actionXMLnode->childNodes as $membernode )
                    {
                        /** @var DOMElement $membernode */
                        if( $membernode->nodeType != 1 ) continue;

                        if( $membernode->textContent == $newMember )
                            $actionXMLnode->removeChild( $membernode );
                    }

                    if( count( $this->$type ) === 0 || $type === "allow")
                        $xmlNode->removeChild( $actionXMLnode );
                }
            }

            return TRUE;
        }

        return FALSE;
    }

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

    /**
     * @param customURLProfile $old
     * @param customURLProfile|null $new
     * @return bool
     */
    public function replaceReferencedObject($old, $new)
    {
        if( $old === null )
            derr("\$old cannot be null");

        if( isset( $this->_all[$old->name()] ) )
        {
            $old_type = $this->_all[$old->name()];

            if( $new === null || $new->name() == $old->name() )
                return False;

            #if( $new !== null && !$this->has( $new->name() ) )
            if( $new !== null && !isset( $this->_all[$new->name()] ) )
            {
                $this->deleteMember($old->name(), $old_type);
                $this->addMember( $new->name(), $old_type );
                $new->addReference($this);
            }
            else
            {
                $this->deleteMember($old->name(), $old_type);
                if( isset($this->_all[$new->name()]) )
                    $this->deleteMember($new->name(), $this->_all[$new->name()]);
                $this->addMember( $new->name(), $old_type );
            }
            $old->removeReference($this);

            #if( $new === null || $new->name() != $old->name() )
            #    $this->rewriteXML();

            return TRUE;
        }

        return FALSE;
    }

    public function API_replaceReferencedObject($old, $new)
    {
        $ret = $this->replaceReferencedObject($old, $new);

        if( $ret )
        {
            $this->API_sync();
        }

        return $ret;
    }

    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

