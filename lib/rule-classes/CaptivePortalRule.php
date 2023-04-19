<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
        $tmp = DH::findFirstElement('service', $xml);
        if( $tmp !== FALSE )
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
            $skip_validate =  DH::findAttribute("skip-validate", $xml);
            if( $skip_validate == False || ($skip_validate !== False && $skip_validate !== "yes" ) )
                mwarning("CaptivePortal Rule '<action>' not found, assuming 'no-captive-portal'", $xml, FALSE, TRUE);
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
        //until here same for appoverride


        $text = $padding . "*Rule named '{$this->name}' $dis";
        if( $this->owner->version >= 70 )
        {
            $text .= " UUID: '" . $this->uuid() . "'";
            PH::$JSON_TMP['sub']['object'][$this->name()]['uuid'] = $this->uuid();
        }
        PH::print_stdout( $text );


        PH::print_stdout( $padding . "  From: " . $this->from->toString_inline() . "  |  To:  " . $this->to->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['from'] = $this->from->toString_inline();
        PH::$JSON_TMP['sub']['object'][$this->name()]['to'] = $this->to->toString_inline();

        PH::print_stdout( $padding . "  Source: $sourceNegated " . $this->source->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['source'] = $this->source->toString_inline();

        PH::print_stdout( $padding . "  Destination: $destinationNegated " . $this->destination->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['destination'] = $this->destination->toString_inline();

        PH::print_stdout( $padding . "  Service:  " . $this->services->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['service'] = $this->services->toString_inline();


        PH::print_stdout( $padding . "  Action: {$this->action()}" );
        PH::$JSON_TMP['sub']['object'][$this->name()]['action'] = $this->action();

        PH::print_stdout( $padding . "    Tags:  " . $this->tags->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['tag'] = $this->tags->toString_inline();

        if( $this->_description !== null && strlen($this->_description) > 0 )
        {
            PH::print_stdout( $padding . "  Desc:  " . $this->_description );
            PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = $this->_description;
        }

        PH::print_stdout();
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
        $this->grouptag = null;

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