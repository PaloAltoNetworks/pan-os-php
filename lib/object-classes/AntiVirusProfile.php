<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class AntiVirusProfile
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

    public $ftp = array();
    public $http = array();
    public $imap = array();
    public $pop3 = array();
    public $smb = array();
    public $smtp = array();


    public $tmp_virus_prof_array = array('http', 'smtp', 'imap', 'pop3', 'ftp', 'smb');


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
    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("Virus SecurityProfile name not found\n");

        #print "\nsecprofURL TMP: object named '".$this->name."' found\n";

        #$this->owner->_SecurityProfiles[$this->name] = $this;
        #$this->owner->_all[$this->name] = $this;
        #$this->owner->o[] = $this;


        //predefined URL category
        //$tmp_array[$secprof_type][$typeName]['allow']['URL category'] = all predefined URL category


        $tmp_decoder = DH::findFirstElement('decoder', $xml);
        if( $tmp_decoder !== FALSE )
        {
            $tmp_array = array();

            foreach( $tmp_decoder->childNodes as $tmp_entry )
            {
                if( $tmp_entry->nodeType != XML_ELEMENT_NODE )
                    continue;


                $appName = DH::findAttribute('name', $tmp_entry);
                if( $appName === FALSE )
                    derr("secprof name not found\n");


                #$tmp_array['virus'][$this->name][$appName] = array();

                $action = DH::findFirstElement('action', $tmp_entry);
                if( $action !== FALSE )
                {
                    #$tmp_array['virus'][$this->name][$appName]['action'] = $action->textContent;
                    #$this->$appName['action'] = $action->textContent;
                }
                else
                {
                    #$this->$appName['action'] = " -- NOT SET -- ";
                    //Todo: if not, set default???
                }


                $action_wildfire = DH::findFirstElement('wildfire-action', $tmp_entry);
                if( $action_wildfire !== FALSE )
                {
                    #$tmp_array['virus'][$this->name][$appName]['wildfire-action'] = $action_wildfire->textContent;
                    #$this->$appName['wildfire-action'] = $action_wildfire->textContent;
                }
                else
                {
                    #$this->$appName['wildfire-action'] = " -- NOT SET -- ";
                    //Todo: if not, set default???
                }


            }

            #print_r( $tmp_array );
        }


        return TRUE;
    }

    public function display()
    {
        print "     * " . get_class($this) . " '" . $this->name() . "'    \n\n";

        //Todo: continue for print out

        foreach( $this->tmp_virus_prof_array as $key => $type )
        {
            print "       o " . PH::boldText($type) . "\n";
            //was not set in specific config files
            if( isset( $this->$type['action'] ) )
                print "          - action:          '" . $this->$type['action'] . "'\n";
            if( isset( $this->$type['wildfire-action'] ) )
                print "          - wildfire-action: '" . $this->$type['wildfire-action'] . "'\n";
        }


        #print "\n\n";
    }


    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

