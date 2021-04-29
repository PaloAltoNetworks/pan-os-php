<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


class CaptivePortalRule extends Rule
{
    use NegatableRule;

    static public $templatexml = '<entry name="**temporarynamechangeme**"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination><service><member>any</member></service></entry></entry>';
    static protected $templatexmlroot = null;

    const ActionNoCaptivePortal = 0;
    const ActionWebForm = 1;
    const ActionBrowserChallenge = 2;

    static private $RuleActions = array(
        self::ActionNoCaptivePortal => 'no-captive-portal',
        self::ActionWebForm => 'web-form',
        self::ActionBrowserChallenge => 'browser-challenge'

    );

    protected $action = self::ActionNoCaptivePortal;

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

        $this->from = new ZoneRuleContainer($this);
        $this->from->name = 'from';
        $this->from->parentCentralStore = $owner->owner->zoneStore;

        $this->to = new ZoneRuleContainer($this);
        $this->to->name = 'to';
        $this->to->parentCentralStore = $owner->owner->zoneStore;

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
        $this->load_to();


        //										//
        // Begin <service> extraction			//
        //										//
        $tmp = DH::findFirstElementOrCreate('service', $xml);
        $this->services->load_from_domxml($tmp);
        // end of <service> zone extraction

        $this->_readNegationFromXml();

        //
        // Begin <action> extraction
        //
        $tmp = DH::findFirstElement('action', $xml);
        if( $tmp !== FALSE )
        {
            $actionFound = array_search($tmp->textContent, self::$RuleActions);
            if( $actionFound === FALSE )
            {
                mwarning("unsupported action '{$tmp->textContent}' found, allow assumed", $tmp);
            }
            else
            {
                $this->action = $actionFound;
            }
        }
        else
        {
            mwarning("'<action> not found, assuming 'no-captive-portal'", $xml);
        }
        // End of <rule-type>

    }

    public function action()
    {
        return self::$RuleActions[$this->action];
    }

    public function actionIsNoCP()
    {
        return $this->action == self::ActionNoCaptivePortal;
    }

    public function actionIsNoWebForm()
    {
        return $this->action == self::ActionWebForm;
    }

    public function actionIsBrowserChallenge()
    {
        return $this->action == self::ActionBrowserChallenge;
    }


    public function display($padding = 0)
    {
        if( !is_string($padding) )
            $padding = str_pad('', $padding);

        $dis = '';
        if( $this->disabled )
            $dis = '<disabled>';

        $sourceNegated = '';
        if( $this->sourceIsNegated() )
            $sourceNegated = '*negated*';

        $destinationNegated = '';
        if( $this->destinationIsNegated() )
            $destinationNegated = '*negated*';


        print $padding . "*Rule named '{$this->name}' $dis\n";
        print $padding . "  From: " . $this->from->toString_inline() . "  |  To:  " . $this->to->toString_inline() . "\n";
        print $padding . "  Source: $sourceNegated " . $this->source->toString_inline() . "\n";
        print $padding . "  Destination: $destinationNegated " . $this->destination->toString_inline() . "\n";
        print $padding . "  Service:  " . $this->services->toString_inline() . "\n";
        print $padding . "  Action: {$this->action()}\n";
        print $padding . "    Tags:  " . $this->tags->toString_inline() . "\n";

        if( strlen($this->_description) > 0 )
            print $padding . "  Desc:  " . $this->_description . "\n";

        print "\n";
    }

    public function cleanForDestruction()
    {
        $this->from->__destruct();
        $this->to->__destruct();
        $this->source->__destruct();
        $this->destination->__destruct();
        $this->tags->__destruct();


        $this->from = null;
        $this->to = null;
        $this->source = null;
        $this->destination = null;
        $this->tags = null;

        $this->owner = null;
    }

    public function isCaptivePortalRule()
    {
        return TRUE;
    }

    public function ruleNature()
    {
        return 'captive-portal';
    }

    public function storeVariableName()
    {
        return "captivePortalRules";
    }

}