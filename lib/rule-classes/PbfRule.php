<?php


class PbfRule extends RuleWithUserID
{
    use NegatableRule;
    use RuleWithSchedule;

    protected $schedule = null;

    static public $templatexml = '<entry name="**temporarynamechangeme**"><from><zone></zone></from>
<source><member>any</member></source><destination><member>any</member></destination></entry>';
    static protected $templatexmlroot = null;

    /** @var ZoneRuleContainer|InterfaceContainer */
    public $from;


    protected $_zoneBased = TRUE;

    /**
     * For developer use only
     */
    protected function load_from()
    {
        $tmp1 = DH::findFirstElementOrCreate('from', $this->xmlroot);

        $tmp = DH::firstChildElement($tmp1);
        if( $tmp === null || $tmp === false )
        {
            $skip_validate =  DH::findAttribute("skip-validate", $this->xmlroot);
            if( $skip_validate == False || ($skip_validate !== False && $skip_validate !== "yes" ) )
                mwarning("PBF rule has nothing inside <from> tag, please fix before going forward", $tmp1, FALSE, TRUE);
            return;
        }


        if( $tmp->tagName == 'zone' )
        {
            $this->_zoneBased = TRUE;
            $this->from = new ZoneRuleContainer($this);
            $this->from->name = 'from';
            $this->from->findParentCentralStore('zoneStore');
            $this->from->load_from_domxml($tmp);
        }
        elseif( $tmp->tagName == 'interface' )
        {
            $this->_zoneBased = FALSE;
            $this->from = new InterfaceContainer($this, $this->owner->_networkStore);
            $this->from->name = 'from';
            $this->from->load_from_domxml($tmp);
        }
        else
            derr("PBF rule has unsupported <from> type '{$tmp->tagName}'");
    }

    /**
     * @param RuleStore $owner
     * @param bool $fromTemplateXML
     */
    public function __construct($owner, $fromTemplateXML = FALSE)
    {
        $this->owner = $owner;

        $this->parentAddressStore = $this->owner->owner->addressStore;
        $this->parentServiceStore = $this->owner->owner->serviceStore;

        $this->tags = new TagRuleContainer($this);
        $this->grouptag = new TagRuleContainer($this);

        $this->source = new AddressRuleContainer($this);
        $this->source->name = 'source';
        $this->source->parentCentralStore = $this->parentAddressStore;

        $this->destination = new AddressRuleContainer($this);
        $this->destination->name = 'destination';
        $this->destination->parentCentralStore = $this->parentAddressStore;

        $this->services = new ServiceRuleContainer($this);
        $this->services->name = 'service';


        if( $fromTemplateXML )
        {
            $xmlElement = DH::importXmlStringOrDie($owner->xmlroot->ownerDocument, self::$templatexml);
            $this->load_from_domxml($xmlElement);
        }
    }


    /**
     * @param DOMElement $xml
     * @throws Exception
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("name not found\n");

        $this->load_common_from_domxml();

        $this->load_source();
        $this->load_destination();
        $this->load_from();

        $this->userID_loadUsersFromXml();
        $this->_readNegationFromXml();

        //										//
        // Begin <service> extraction			//
        //										//
        $tmp = DH::findFirstElement('service', $xml);
        if( $tmp !== FALSE )
            $this->services->load_from_domxml($tmp);
        // end of <service> zone extraction

        $this->schedule_loadFromXml();
    }

    /**
     * Helper function to quickly print a function properties to CLI
     */
    public function display($padding = 0)
    {
        $padding = str_pad('', $padding);

        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);

        $dis = '';
        if( $this->disabled )
        {
            $dis = '<disabled>';
            PH::$JSON_TMP['sub']['object'][$this->name()]['disabled'] = "true";
        }
        else
            PH::$JSON_TMP['sub']['object'][$this->name()]['disabled'] = "false";


        $sourceNegated = '';
        if( $this->sourceIsNegated() )
        {
            $sourceNegated = '*negated*';
            PH::$JSON_TMP['sub']['object'][$this->name()]['sourcenegated'] = "true";
        }
        else
            PH::$JSON_TMP['sub']['object'][$this->name()]['sourcenegated'] = "false";


        $destinationNegated = '';
        if( $this->destinationIsNegated() )
        {
            $destinationNegated = '*negated*';
            PH::$JSON_TMP['sub']['object'][$this->name()]['destinationnegated'] = "true";
        }
        else
            PH::$JSON_TMP['sub']['object'][$this->name()]['destinationnegated'] = "false";


        $text = $padding . "*Rule named '{$this->name}' $dis";
        if( $this->owner->version >= 70 )
        {
            $text .= " UUID: '" . $this->uuid() . "'";
            PH::$JSON_TMP['sub']['object'][$this->name()]['uuid'] = $this->uuid();
        }
        PH::print_stdout( $text );

        if( $this->from !== null )
        {
            PH::print_stdout( $padding . "  From: " . $this->from->toString_inline() );
            PH::$JSON_TMP['sub']['object'][$this->name()]['from'] = $this->from->toString_inline();
        }

        PH::print_stdout( $padding . "  Source: $sourceNegated " . $this->source->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['source'] = $this->source->toString_inline();

        PH::print_stdout( $padding . "  Destination: $destinationNegated " . $this->destination->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['destination'] = $this->destination->toString_inline();

        PH::print_stdout( $padding . "  Service:  " . $this->services->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['service'] = $this->services->toString_inline();

        if( !$this->userID_IsCustom() )
        {
            PH::print_stdout( $padding . "  User: *" . $this->userID_type() . "*");
            PH::$JSON_TMP['sub']['object'][$this->name()]['user'] = $this->userID_type();
        }
        else
        {
            $users = $this->userID_getUsers();
            PH::print_stdout( $padding . " User:  " . PH::list_to_string($users) );
            PH::$JSON_TMP['sub']['object'][$this->name()]['user'] = PH::list_to_string($users);
        }
        PH::print_stdout( $padding . "  Tags:  " . $this->tags->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['tag'] = $this->tags->toString_inline();

        if( $this->_targets !== null )
        {
            PH::print_stdout( $padding . "  Targets:  " . $this->targets_toString() );
            PH::$JSON_TMP['sub']['object'][$this->name()]['target'] = $this->targets_toString();
        }


        if( $this->_description !== null && strlen($this->_description) > 0 )
        {
            PH::print_stdout( $padding . "  Desc:  " . $this->_description );
            PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = $this->_description;
        }

        if( $this->schedule !== null )
        {
            PH::print_stdout( $padding . "  Schedule:  " . $this->schedule->name() );
            PH::$JSON_TMP['sub']['object'][$this->name()]['schedule'][] = $this->schedule->name();
        }

        PH::print_stdout();
    }

    public function cleanForDestruction()
    {
        $this->from->__destruct();
        $this->source->__destruct();
        $this->destination->__destruct();
        $this->tags->__destruct();
        $this->services->__destruct();

        $this->from = null;
        $this->source = null;
        $this->destination = null;
        $this->tags = null;
        $this->grouptag = null;

        $this->services = null;

        $this->owner = null;
    }

    public function ruleNature()
    {
        return 'pbf';
    }

    public function isPbfRule()
    {
        return TRUE;
    }

    public function isZoneBased()
    {
        return $this->_zoneBased;
    }

    public function isInterfaceBased()
    {
        return !$this->_zoneBased;
    }


    public function storeVariableName()
    {
        return "pbfRules";
    }


}