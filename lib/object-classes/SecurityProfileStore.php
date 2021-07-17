<?php


class SecurityProfileStore extends ObjStore
{

    /** @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf|null */
    public $owner;
    public $name = 'temporaryname';

    protected $type = '**needsomethinghere**';

    protected $fastMemToIndex = null;
    protected $fastNameToIndex = null;

    public $nameIndex = array();

    /** @var URLProfileStore[] */
    public $_all = array();

    /** @var URLProfileStore[] */
    public $_SecurityProfiles = array();


    /** @var null|SecurityProfileStore */
    protected $parentCentralStore = null;

    public static $childn = 'SecurityProfile';

    private $secprof_array = array('virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering', 'custom-url-category', 'predefined-url', 'data-filtering');
    private $secprof_fawkes_array = array('virus-and-wildfire-analysis', 'spyware', 'vulnerability', 'file-blocking', 'dns-security', 'url-filtering', 'custom-url-category', 'predefined-url');
    /** @var DOMElement */
    public $securityProfileRoot;


    /*
     * FAWKES
     *    <dns-security>    <spyware>   <vulnerability> <url-filtering> <file-blocking> <saas-security> <virus-and-wildfire-analysis>
     */


    /*
     * FAWKES
     * define new ProfileStore:
     * ->VirusWildfireProfileStore; DnsSecurityProfileStore; SaasSecurityProfileStore
     */

    /*
$this->customURLProfileStore = new SecurityProfileStore($this, "customURLProfileStore");
        $this->customURLProfileStore->name = 'CustomURL';

        $this->URLProfileStore = new SecurityProfileStore($this, "URLProfileStore");
        $this->URLProfileStore->name = 'URL';

        $this->AntiVirusProfileStore = new SecurityProfileStore($this, "AntiVirusProfileStore");
        $this->AntiVirusProfileStore->name = 'AntiVirus';


        $this->VulnerabilityProfileStore = new SecurityProfileStore($this, "VulnerabilityProfileStore");
        $this->VulnerabilityProfileStore->name = 'Vulnerability';

        $this->AntiSpywareProfileStore = new SecurityProfileStore($this, "AntiSpywareProfileStore");
        $this->AntiSpywareProfileStore->name = 'AntiSpyware';

        $this->FileBlockingProfileStore = new SecurityProfileStore($this, "FileBlockingProfileStore");
        $this->FileBlockingProfileStore->name = 'FileBlocking';

        $this->WildfireProfileStore = new SecurityProfileStore($this, "WildfireProfileStore");
        $this->WildfireProfileStore->name = 'WildFire';


        $this->securityProfileGroupStore = new SecurityProfileGroupStore($this);
        $this->securityProfileGroupStore->name = 'SecurityProfileGroups';


        $this->DecryptionProfileStore = new SecurityProfileStore($this, "DecryptionProfileStore");
        $this->DecryptionProfileStore->name = 'Decryption';

        $this->HipObjectsProfileStore = new SecurityProfileStore($this, "HipObjectsProfileStore");
        $this->HipObjectsProfileStore->name = 'HipObjects';

        $this->HipProfilesProfileStore = new SecurityProfileStore($this, "HipProfilesProfileStore");
        $this->HipProfilesProfileStore->name = 'HipProfiles';
     */
    static private $storeNameByType = array(
        'URLProfileStore' => array('name' => 'URL', 'varName' => 'urlSecProf', 'xpathRoot' => 'url-filtering'),
        'AntiVirusProfileStore' => array('name' => 'Virus', 'varName' => 'avSecProf', 'xpathRoot' => 'virus'),

        'VirusAndWildfireProfileStore' => array('name' => 'VirusAndWildfire', 'varName' => 'avawfSecProf', 'xpathRoot' => 'virus-and-wildfire-analysis'),
        'DNSSecurityProfileStore' => array('name' => 'DNSSecurity', 'varName' => 'dnsSecProf', 'xpathRoot' => 'dns-security'),

        'AntiSpywareProfileStore' => array('name' => 'AntiSpyware', 'varName' => 'asSecProf', 'xpathRoot' => 'spyware'),
        'VulnerabilityProfileStore' => array('name' => 'Vulnerability', 'varName' => 'fbSecProf', 'xpathRoot' => 'vulnerability'),
        'FileBlockingProfileStore' => array('name' => 'FileBlocking', 'varName' => 'fbSecProf', 'xpathRoot' => 'file-blocking'),
        'WildfireProfileStore' => array('name' => 'Wildfire', 'varName' => 'wfSecProf', 'xpathRoot' => 'wildfire-analysis'),
        'DataFilteringProfileStore' => array('name' => 'DataFiltering', 'varName' => 'dfSecProf', 'xpathRoot' => 'data-filtering'),
        'DoSProtectionProfileStore' => array('name' => 'DoSProtection', 'varName' => 'dosSecProf', 'xpathRoot' => 'XYZ'),

        'customURLProfileStore' => array('name' => 'customURL', 'varName' => 'customUrlSecProf', 'xpathRoot' => 'custom-url-category'),
        'PredefinedSecurityProfileURL' => array('name' => 'predefinedURL', 'varName' => 'predefinedUrlSecProf', 'xpathRoot' => 'predefined-url-category'),

        'DecryptionProfileStore' => array('name' => 'Decryption', 'varName' => 'decryptProf', 'xpathRoot' => 'decryption'),
        'HipObjectsProfileStore' => array('name' => 'HIP-Objects', 'varName' => 'hipObjProf', 'xpathRoot' => 'hip-objects'),
        'HipProfilesProfileStore' => array('name' => 'HIP-Profiles', 'varName' => 'hipProfProf', 'xpathRoot' => 'hip-profiles'),
    );


    public function name()
    {
        return $this->name;
    }

    public function __construct($owner, $profileType)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

        $allowedTypes = array_keys(self::$storeNameByType);
        if( !in_array($profileType, $allowedTypes) )
            derr("Error : type '$profileType' is not a valid one");

        $this->type = $profileType;

        $this->name = self::$storeNameByType[$this->type]['name'];


        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
        {
            $this->parentCentralStore = $owner->parentDeviceGroup->$profileType;
        }
        elseif( isset($owner->parentContainer) && $owner->parentContainer !== null )
        {
            $this->parentCentralStore = $owner->parentContainer->$profileType;
        }
        else
            $this->findParentCentralStore();

        $this->_SecurityProfiles = array();



    }

    public $predefinedStore_appid_version = null;

    /** @var null|SecurityProfileStore */
    public static $predefinedStore = null;

    /**
     * @return SecurityProfileStore|null
     */
    public static function getPredefinedStore()
    {
        if( self::$predefinedStore !== null )
            return self::$predefinedStore;


        self::$predefinedStore = new SecurityProfileStore(null, "PredefinedSecurityProfileURL");
        self::$predefinedStore->setName('predefined URL');
        self::$predefinedStore->load_from_predefinedfile();

        return self::$predefinedStore;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->securityProfileRoot = $xml;

        $duplicatesRemoval = array();


        if( $xml !== null )
        {
            $this->xmlroot = $xml;

            foreach( $xml->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;
                if( $node->tagName != 'entry' )
                {
                    mwarning("A SecyrityProfile entry with tag '{$node->tagName}' was found and ignored");
                    continue;
                }
                $tmp_name = DH::findAttribute('name', $node);
                /** @var URLProfileStore|customURLProfileStore $nr */
                $nr = new $this->type($tmp_name, $this);
                $nr->load_from_domxml($node);
                if( PH::$enableXmlDuplicatesDeletion )
                {
                    if( isset($this->nameIndex[$nr->name()]) )
                    {
                        mwarning("SecProf named '{$nr->name()}' is present twice on the config and was cleaned by PAN-PHP-FRAMEWORK");
                        $duplicatesRemoval[] = $node;
                        continue;
                    }
                }

                $this->nameIndex[$nr->name()] = $nr;
                $this->fastNameToIndex[$nr->name()] = $nr;

                //
                $this->_SecurityProfiles[ $nr->name() ] = $nr;
                #$this->_SecurityProfiles[$this->name] = $nr;
                $this->_all[] = $nr;
                #$this->_all[$this->name] = $nr;
                $this->o[] = $nr;
            }
        }
    }

    public function load_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/pan-url-categories', $xmlDoc);

        $this->load_predefined_url_categories_from_domxml($cursor);

    }

    /**
     * Look for a rule named $name. Return NULL if not found
     * @param string $name
     * @return null|URLProfileStore|AntiVirusProfileStore|customURLProfileStore
     */
    /*public function find($name)
    {
        if( !is_string($name) )
            derr("String was expected for rule name");

        if( isset($this->fastNameToIndex[$name]) )
            return $this->_SecurityProfiles[ $name ];

        return null;
    }*/

    /**
     * Should only be called from a CentralStore or give unpredictable results
     * @param string $objectName
     * @param ReferenceableObject $ref
     * @param bool $nested
     * @return null|URLProfileStore|AntiVirusProfileStore|customURLProfileStore
     */
    public function find($objectName, $ref = null, $nested = TRUE)
    {
        $f = null;

        if( isset($this->fastNameToIndex[$objectName]) )
        {
            $foundObject = $this->_SecurityProfiles[ $objectName ];
            $foundObject->addReference($ref);
            return $foundObject;
        }

        /*
        if( isset($this->_all[$objectName]) )
        {
            $foundObject = $this->_all[$objectName];
            $foundObject->addReference($ref);
            return $foundObject;
        }*/

        // when load a PANOS firewall attached to a Panorama
        if( $nested && isset($this->panoramaShared) )
        {
            $f = $this->panoramaShared->find($objectName, $ref, FALSE);

            if( $f !== null )
                return $f;
        }
        // when load a PANOS firewall attached to a Panorama
        if( $nested && isset($this->panoramaDG) )
        {
            $f = $this->panoramaDG->find($objectName, $ref, FALSE);
            if( $f !== null )
                return $f;
        }

        if( $nested && $this->parentCentralStore )
        {
            $f = $this->parentCentralStore->find($objectName, $ref, $nested);
        }

        return $f;
    }

    public function findOrCreate($fn, $ref = null, $nested = TRUE)
    {
        $f = $this->find($fn, $ref, $nested);

        if( $f !== null )
            return $f;

        $f = $this->createTmp($fn, $ref);

        return $f;
    }

    /**
     * @param URLProfileStore|AntiVirusProfileStore|customURLProfileStore
     * @return bool
     */
    function inStore($SecurityProfile)
    {
        $serial = spl_object_hash($SecurityProfile);

        if( isset($this->fastMemToIndex[$serial]) )
            return TRUE;

        return FALSE;
    }

    /**
     * Returns an Array with all SecurityProfiles inside this store
     * @param null|string|string[] $withFilter
     * @return CustomProfileURL[]|URLProfileStore
     */
    public function &securityProfiles($withFilter = null)
    {
        $query = null;

        if( $withFilter !== null && $withFilter !== '' )
        {
            $queryContext = array();

            if( is_array($withFilter) )
            {
                $filter = &$withFilter['query'];
                $queryContext['nestedQueries'] = &$withFilter;
            }
            else
                $filter = &$withFilter;

            $errMesg = '';
            $query = new RQuery('rule');
            if( $query->parseFromString($filter, $errMsg) === FALSE )
                derr("error while parsing query: {$errMesg}");

            $res = array();

            foreach( $this->o as $securityProfile )
            {
                $queryContext['object'] = $securityProfile;
                if( $query->matchSingleObject($queryContext) )
                    $res[] = $securityProfile;
            }

            return $res;
        }

        $res = $this->o;

        return $res;
    }

    /**
     * Counts the number of SecurityProfiles in this store
     *
     */
    public function count()
    {
        return count($this->_SecurityProfiles);
    }

    public function removeAllSecurityProfiles()
    {
        $this->removeAll();
        $this->rewriteXML();
    }


    /**
     * @param string $base
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
     */
    public function findAvailableSecurityProfileName($base, $suffix, $startCount = '')
    {
        $maxl = 31;
        $basel = strlen($base);
        $suffixl = strlen($suffix);
        $inc = $startCount;
        $basePlusSuffixL = $basel + $suffixl;

        while( TRUE )
        {
            $incl = strlen(strval($inc));

            if( $basePlusSuffixL + $incl > $maxl )
            {
                $newname = substr($base, 0, $basel - $suffixl - $incl) . $suffix . $inc;
            }
            else
                $newname = $base . $suffix . $inc;

            if( $this->find($newname) === null )
                return $newname;

            if( $startCount == '' )
                $startCount = 0;
            $inc++;
        }
    }


    /**
     * return tags in this store
     * @return SecurityProfile[]
     */
    public function tags()
    {
        return $this->o;
    }


    /**
     * @param URLProfileStore|customURLProfileStore|AntiVirusProfileStore|AntiSpywareProfileStore|FileBlockingProfileStore|VulnerabilityProfileStore|WildfireProfileStore|VirusAndWildfireProfileStore|DNSSecurityProfileStore|DecryptionProfileStore|HipObjectsProfileStore|HipProfilesProfileStore $rule
     * @return bool
     */
    public function addSecurityProfile($rule)
    {

        if( !is_object($rule) )
            derr('this function only accepts Rule class objects');

        if( $rule->owner !== null )
            derr('Trying to add a rule that has a owner already !');

        /*if( $rule->owner !== $this )
        {
            $rule->from->findParentCentralStore();
            if( !$rule->isPbfRule() )
                $rule->to->findParentCentralStore();
        }*/

        $ser = spl_object_hash($rule);


        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $rule->owner = $this;

            $this->_SecurityProfiles[ $rule->name() ] = $rule;
            $this->_all[] = $rule;
            $this->o[] = $rule;

            $index = lastIndex($this->_SecurityProfiles);
            $this->fastMemToIndex[$ser] = $index;
            $this->fastNameToIndex[$rule->name()] = $index;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($rule->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a SecurityProfiles that is already here :)');


        return FALSE;

    }


    /**
     * Creates a new URLProfileStore in this store. It will be placed at the end of the list.
     * @param string $name name of the new Rule
     * @param bool $inPost create it in post or pre (if applicable)
     * @return URLProfileStore
     */
    public function newSecurityProfileURL($name)
    {
        $rule = new URLProfileStore($name, $this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, URLProfileStore::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addSecurityProfile($rule);

        return $rule;
    }

    /**
     * Creates a new customURLProfileStore in this store. It will be placed at the end of the list.
     * @param string $name name of the new Rule
     * @param bool $inPost create it in post or pre (if applicable)
     * @return customURLProfileStore
     */
    public function newCustomSecurityProfileURL($name)
    {
        $rule = new customURLProfileStore($name, $this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, customURLProfileStore::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addSecurityProfile($rule);

        return $rule;
    }

    /**
     * Creates a new PredefinedSecurityProfileURL in this store. It will be placed at the end of the list.
     * @param string $name name of the new Rule
     * @param bool $inPost create it in post or pre (if applicable)
     * @return customURLProfileStore
     */
    public function newPredefinedSecurityProfileURL($name)
    {
        $rule = new PredefinedSecurityProfileURL($this);

        #$xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, PredefinedSecurityProfileURL::$templatexml);
        #$rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        #$this->addSecurityProfile($rule);

        return $rule;
    }

    public function load_predefined_url_categories_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined URL category name not found\n");

            $app = $this->newPredefinedSecurityProfileURL($appName);
            #$app->type = 'predefined';

            $this->add($app);
        }

        sort($this->o);
    }



    /**
     * @param SecurityProfile $tag
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeSecurityProfile(SecurityProfile $tag)
    {
        $ret = $this->remove($tag);

        if( $ret && !$tag->isTmpSecProf() && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($tag->xmlroot);
        }

        return $ret;
    }

    /**
     * @param SecurityProfile $securityProfile
     * @return bool
     */
    public function API_removeSecurityProfile(SecurityProfile $securityProfile)
    {
        $xpath = null;

        if( !$securityProfile->isTmp() )
            $xpath = $securityProfile->getXPath();

        $ret = $this->removeSecurityProfile($securityProfile);

        if( $ret && !$securityProfile->isTmp() )
        {
            $con = findConnectorOrDie($this);
            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
            $str = '/config/shared';
        else
            derr('unsupported');

        $str = $str . '/profiles';

        return $str;
    }


    private function &getBaseXPath()
    {
        if( $this->owner->isPanorama() || $this->owner->isFirewall() )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();


        return $str;
    }

    public function &getSecurityProfileStoreXPath()
    {
        $path = $this->getBaseXPath() . '/profiles';
        return $path;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
                DH::findFirstElementOrCreate('profiles', $this->owner->xmlroot);
        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            if( !$o->isTmpSecProf() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
    }


    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $SecurityProfileTypeForXml = self::$storeNameByType[$this->type]['xpathRoot'];
            $xml = DH::findFirstElementOrCreate('profiles', $this->owner->xmlroot);

            $this->xmlroot = DH::findFirstElementOrCreate($SecurityProfileTypeForXml, $xml);
        }
    }


    /**
     *
     * @ignore
     */
    protected function findParentCentralStore()
    {
        $this->parentCentralStore = null;

        $profileType = $this->type;

        $cur = $this;
        while( isset($cur->owner) && $cur->owner !== null )
        {
            $ref = $cur->owner;
            if( isset($ref->$profileType) &&
                $ref->$profileType !== null )
            {
                $this->parentCentralStore = $ref->$profileType;
                #print $this->toString()." : found a parent central store: ".$this->parentCentralStore->toString()."\n";
                return;
            }
            $cur = $ref;
        }
    }
}