<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class VirusAndWildfireProfile
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
    function __construct( $name, $owner, $fromXmlTemplate = FALSE)
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

        $this->setName($newName);

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->secprof_type = "virus-and-wildfire-analysis";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("VirusAndWildFire SecurityProfile name not found\n");

        #PH::print_stdout(  "\nsecprofURL TMP: object named '".$this->name."' found" );

        #$this->owner->_SecurityProfiles[$this->secprof_type][$this->name] = $this;
        #$this->owner->_all[$this->secprof_type][$this->name] = $this;
        #$this->owner->o[] = $this;


        //predefined URL category
        //$tmp_array[$this->secprof_type][$typeName]['allow']['URL category'] = all predefined URL category

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


        $tmp_rule = DH::findFirstElement('rules', $xml);
        if( $tmp_rule !== FALSE )
        {
            #$tmp_array[$this->secprof_type][$this->secprof_type][$this->name]['rules'] = array();
            $tmp_array[$this->secprof_type][$this->name]['rules'] = array();
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $vb_severity = DH::findAttribute('name', $tmp_entry1);
                if( $vb_severity === FALSE )
                    derr("VB severity name not found\n");

                $severity = DH::findFirstElement('severity', $tmp_entry1);
                if( $severity !== FALSE )
                {
                    if( $severity->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['severity'] = array();
                    foreach( $severity->childNodes as $member )
                    {
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['severity'][$member->textContent] = $member->textContent;
                    }
                }

                $severity = DH::findFirstElement('file-type', $tmp_entry1);
                if( $severity !== FALSE )
                {
                    if( $severity->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['file-type'] = array();
                    foreach( $severity->childNodes as $member )
                    {
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['file-type'][$member->textContent] = $member->textContent;
                    }
                }

                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    if( $tmp_action !== FALSE )
                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['action'] = $tmp_action->nodeName;

                    if( $this->secprof_type == 'file-blocking' )
                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['action'] = $action->textContent;
                }

                $packet_capture = DH::findFirstElement('packet-capture', $tmp_entry1);
                if( $packet_capture !== FALSE )
                {
                    if( $packet_capture->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['packet-capture'] = $packet_capture->textContent;
                }

                $direction = DH::findFirstElement('direction', $tmp_entry1);
                if( $direction !== FALSE )
                {
                    if( $direction->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['direction'] = $direction->textContent;
                }

                $analysis = DH::findFirstElement('analysis', $tmp_entry1);
                if( $analysis !== FALSE )
                {
                    if( $analysis->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['analysis'] = $analysis->textContent;
                }
            }
        }


        $tmp_threat_exception = DH::findFirstElement('threat-exception', $xml);
        if( $tmp_threat_exception !== FALSE )
        {
            $tmp_array[$this->secprof_type][$this->name]['threat-exception'] = array();
            foreach( $tmp_threat_exception->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $tmp_name = DH::findAttribute('name', $tmp_entry1);
                if( $tmp_name === FALSE )
                    derr("VB severity name not found\n");

                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    $tmp_array[$this->secprof_type][$this->name]['threat-exception'][$tmp_name]['action'] = $tmp_action->nodeName;
                }
            }
        }

        #print_r( $tmp_array );

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

