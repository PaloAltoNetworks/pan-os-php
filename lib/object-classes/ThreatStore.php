<?php


class ThreatStore extends ObjStore
{
    /** @var array|Threat[] */
    public $vulnerability = array();

    /** @var array|Threat[] */
    public $phoneHome = array();

    public $predefinedStore_threat_version = null;

    /** @var null|ThreatStore */
    public static $predefinedStore = null;

    /**
     * @return ThreatStore|null
     */
    public static function getPredefinedStore( $owner )
    {
        if( self::$predefinedStore !== null )
            return self::$predefinedStore;

        self::$predefinedStore = new AppStore( $owner );
        self::$predefinedStore->setName('predefined Threats');
        self::$predefinedStore->load_from_predefinedfile();

        return self::$predefinedStore;
    }


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        #$this->o = &$this->apps;
        $this->o = array();

        /*
        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->appStore;
        elseif( isset($owner->parentContainer) && $owner->parentContainer !== null )
        {
            $this->parentCentralStore = $owner->parentContainer->appStore;
        }
        else
            $this->findParentCentralStore();
        */
    }

    public function load_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/threats/vulnerability', $xmlDoc);
        $this->load_vulnerability_from_domxml($cursor);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/threats/phone-home', $xmlDoc);
        $this->load_phone_home_containers_from_domxml($cursor);


        #$appid_version = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);
        #self::$predefinedStore->predefinedStore_appid_version = $appid_version->nodeValue;

    }

    public function load_vulnerability_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $threatx )
        {
            if( $threatx->nodeType != XML_ELEMENT_NODE )
                continue;

            $threatName = DH::findAttribute('name', $threatx);
            if( $threatName === FALSE )
                derr("threat name not found\n");

            $threat = new Threat($threatName, $this);
            $threat->type = 'predefined';
            $threat->xmlroot = $threatx;
            $this->add($threat);
        }
    }
}
