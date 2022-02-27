<?php

/**
 * Class SecurityProfileGroup
 * @property SecurityProfileGroup[] $o
 * @property VirtualSystem|DeviceGroup|PanoramaConf|PANConf|Container|DeviceCloud $owner
 * @method SecurityProfileGroup[] getAll()
 */
class SecurityProfileGroupStore extends ObjStore
{

    /** @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf|null */
    public $owner;
    public $name = 'temporaryname';

    /** @var null|SecurityProfileGroupStore */
    public $parentCentralStore = null;

    public static $childn = 'SecurityProfileGroup';

    public $secprof_array = array('virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering', 'data-filtering');
    public $secprof_store = array( 'AntiVirusProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'WildfireProfileStore', 'URLProfileStore', 'DataFilteringProfileStore' );

    private $secprof_fawkes_array = array('virusandwildfire-analysis', 'spyware', 'vulnerability', 'file-blocking', 'dns-security', 'url-filtering');
    private $secprof_fawkes_store = array( 'VirusAndWildfireProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'DNSSecurityProfileStore', 'URLProfileStore' );
    

    /** @var DOMElement */
    public $securityProfileRoot;

    /** @var DOMElement */
    public $securityProfileGroupRoot;

    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

        $this->setParentCentralStore( 'securityProfileGroupStore' );
    }

    public function all()
    {
        return $this->o;
    }

    public function count()
    {
        return count($this->o);
    }

    public function load_securityprofile_groups_from_domxml($xml)
    {
        $this->securityProfileGroupRoot = $xml;
        $this->xmlroot = $this->securityProfileGroupRoot;


        $duplicatesRemoval = array();
        $nameIndex = array();

        foreach( $this->securityProfileGroupRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = DH::findAttribute('name', $node);
            $tmp_secgroup = new SecurityProfileGroup( $name, $this, true );

            $this->o[] = $tmp_secgroup;
            $this->nameIndex[$name] = TRUE;

            $tmp_secgroup->load_from_domxml( $node, $this);

            $this->addSecurityProfileGroup( $tmp_secgroup );
            #$this->xmlroot->appendChild($tmp_secgroup->xmlroot);
        }
    }

    /**
     * Returns name of this rule
     * @return string
     */
    public function name()
    {
        return $this->name;
    }

    /**
     * @param $name
     * @param null $ref
     * @param bool $nested
     * @return null|SecurityProfileGroup
     */
    public function find($name, $ref = null, $nested = TRUE)
    {
        $f = $this->findByName($name, $ref, $nested);

        if( $f !== null )
            return $f;

        if( $nested && $this->parentCentralStore !== null )
            return $this->parentCentralStore->find($name, $ref, $nested);

        return null;
    }

    public function findByHash( $hash)
    {
        foreach( $this->all() as $securityProfileGroup )
        {
            if( $hash == $securityProfileGroup->hash )
                return $securityProfileGroup;
        }

        return null;
    }

    public function calculateHash( $secprofArray )
    {
        $str = '';
        $counter = count( $this->secprof_array );
        $i = 1;
        foreach( $this->secprof_array as $secprof )
        {
            if( isset( $secprofArray[$secprof] ) )
                $str .= $secprof.':'.$secprofArray[$secprof];

            if( $i < $counter )
            {
                if( isset( $secprofArray[$secprof] ) )
                    $str .= ',';

                $i++;
            }
        }

        return md5( $str );
    }

    public function createSecurityProfileGroup_based_Profile( $secProf_array, $secProfOBJ_array = array() )
    {
        $name = $this->findAvailableSecurityProfileGroupName( "secProfGroup"  );

        $tmp_secProfGroup = new SecurityProfileGroup( $name, $this, true );

        $this->o[] = $tmp_secProfGroup;
        $this->nameIndex[$name] = TRUE;

        $string = "<entry name=\"".$name."\">\n";

        foreach( $secProf_array as $key => $secProf )
        {
            $string .= "<".$key.">\n";
            $string .= "<member>".$secProf."</member>\n";
            $string .= "</".$key.">\n";

            if( isset( $secProfOBJ_array[$secProf] ) )
                $secProfOBJ_array[$secProf]->addReference( $tmp_secProfGroup );
        }

        $string .= "</entry>\n";


        $newSecProfGroupRoot = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $string);

        $tmp_secProfGroup->load_from_domxml( $newSecProfGroupRoot, $this );


        $this->xmlroot->appendChild($tmp_secProfGroup->xmlroot);
        #$this->addSecurityProfileGroup( $tmp_secProfGroup );


        return $tmp_secProfGroup;

    }

    public function removeAllSecurityProfileGroups()
    {
        $this->removeAll();
        $this->rewriteXML();
    }

    /**
     * add a SecurityProfileGroup to this store. Use at your own risk.
     * @param SecurityProfileGroupStore $Obj
     * @param bool
     * @return bool
     */
    public function addSecurityProfileGroup(SecurityProfileGroup $Obj, $rewriteXML = TRUE)
    {
        $ret = $this->add($Obj);
        if( $ret && $rewriteXML )
        {
            if( $this->xmlroot === null )
                $this->xmlroot = DH::findFirstElementOrCreate('profile-group', $this->owner->xmlroot);

            $this->xmlroot->appendChild($Obj->xmlroot);
        }
        return $ret;
    }

    /**
     * @param string $base
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
     */
    public function findAvailableSecurityProfileGroupName($base, $suffix = '', $startCount = '')
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
     * return securityprofilegroups in this store
     * @return SecurityProfileGroup[]
     */
    public function securityProfileGroups()
    {
        return $this->o;
    }

    function createSecurityProfileGroup($name, $ref = null)
    {
        if( $this->find($name, null, FALSE) !== null )
            derr('SecurityProfileGroup named "' . $name . '" already exists, cannot create');

        if( $this->xmlroot === null )
        {
            if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
                $this->xmlroot = DH::findFirstElementOrCreate('profile-group', $this->owner->xmlroot);
            else
                $this->xmlroot = DH::findFirstElementOrCreate('profile-group', $this->owner->sharedroot);
        }

        $newSecurityProfileGroup = new SecurityProfileGroup($name, $this);
        $newSecurityProfileGroup->owner = null;

        $this->o[] = $newSecurityProfileGroup;

        $newSecurityProfileRoot = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, SecurityProfileGroup::$templatexml);
        $newSecurityProfileRoot->setAttribute('name', $name);
        $newSecurityProfileGroup->load_from_domxml($newSecurityProfileRoot, $this);

        if( $ref !== null )
            $newSecurityProfileGroup->addReference($ref);

        $this->addSecurityProfileGroup($newSecurityProfileGroup);

        return $newSecurityProfileGroup;
    }

    function findOrCreate($name, $ref = null, $nested = TRUE)
    {
        $f = $this->find($name, $ref, $nested);

        if( $f !== null )
            return $f;

        return $this->createSecurityProfileGroup($name, $ref);
    }

    function API_createSecurityProfileGroup($name, $ref = null)
    {
        $newSecurityProfileGroup = $this->createSecurityProfileGroup($name, $ref);

        $xpath = $this->getXPath();
        $con = findConnectorOrDie($this);
        $element = $newSecurityProfileGroup->getXmlText_inline();
        $con->sendSetRequest($xpath, $element);

        return $newSecurityProfileGroup;
    }


    /**
     * @param SecurityProfileGroupStore $tag
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeSecurityProfileGroup(SecurityProfileGroup $tag)
    {
        $ret = $this->remove($tag);

        if( $ret && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($tag->xmlroot);
        }

        return $ret;
    }

    /**
     * @param SecurityProfileGroupStore $securityProfileGroup
     * @return bool
     */
    public function API_removeSecurityProfileGroup(SecurityProfileGroup $securityProfileGroup)
    {
        $xpath = null;

        $xpath = $securityProfileGroup->getXPath();

        $ret = $this->removeSecurityProfileGroup($securityProfileGroup);

        if( $ret )
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

        $str = $str . '/profile-group';

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

    public function &getSecurityProfileGroupStoreXPath()
    {
        $path = $this->getBaseXPath() . '/profile-group';
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
                $this->xmlroot = DH::findFirstElementOrCreate('profile-group', $this->owner->xmlroot);
        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            #PH::print_stdout(  "OBJ: ".$o->name() );
            $this->xmlroot->appendChild($o->xmlroot);
        }
    }



    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            if( $this->owner->isPanorama() || $this->owner->isFirewall() )
                $xml = $this->owner->sharedroot;
            else
                $xml = $this->owner->xmlroot;

            $xml = DH::findFirstElementOrCreate('profile-group', $xml);
            $this->xmlroot = $xml;
        }
    }
}

