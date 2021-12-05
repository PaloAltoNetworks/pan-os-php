<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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


class QoSRule extends RuleWithUserID
{
    use NegatableRule;

    static public $templatexml = '<entry name="**temporarynamechangeme**"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination>
<source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application>
><service><member>any</member></service>><action><class>1</class></action></entry>';
    static protected $templatexmlroot = null;


    const ActionClass1 = 0;
    const ActionClass2 = 1;
    const ActionClass3 = 2;
    const ActionClass4 = 3;
    const ActionClass5 = 4;
    const ActionClass6 = 5;
    const ActionClass7 = 6;
    const ActionClass8 = 7;


    static private $RuleActions = array(
        self::ActionClass1 => 1,
        self::ActionClass2 => 2,
        self::ActionClass3 => 3,
        self::ActionClass4 => 4,
        self::ActionClass5 => 5,
        self::ActionClass6 => 6,
        self::ActionClass7 => 7,
        self::ActionClass8 => 8
    );

    protected $action = self::ActionClass1;

    /** @var AppRuleContainer $apps */
    public $apps;

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

        $this->apps = new AppRuleContainer($this);
        $this->apps->name = 'apps';

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


        //														//
        // Begin <application> application extraction			//
        //														//
        $tmp = DH::findFirstElementOrCreate('application', $xml);
        $this->apps->load_from_domxml($tmp);
        // end of <application> application extraction

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
                mwarning("unsupported action '{$tmp->textContent}' found, class 1 assumed", $tmp);
            }
            else
            {
                $this->action = $actionFound;
            }
        }
        else
        {
            mwarning("'<action> not found, assuming class '1'", $xml);
        }
        // End of <rule-type>

        $this->userID_loadUsersFromXml();
    }

    public function action()
    {
        return self::$RuleActions[$this->action];
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

        PH::print_stdout( $padding . "  Service:  " . $this->services->toString_inline() . "    Apps:  " . $this->apps->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['service'] = $this->services->toString_inline();
        PH::$JSON_TMP['sub']['object'][$this->name()]['application'] = $this->apps->toString_inline();

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

        PH::print_stdout( $padding . "  Class: {$this->action()}");
        PH::$JSON_TMP['sub']['object'][$this->name()]['class'] = $this->action();

        PH::$JSON_TMP['sub']['object'][$this->name()]['tag'] = $this->tags->toString_inline();


        if( strlen($this->_description) > 0 )
        {
            PH::print_stdout( $padding . "  Desc:  " . $this->_description );
            PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = $this->_description;
        }

        PH::print_stdout("");
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

    public function isQoSRule()
    {
        return TRUE;
    }

    public function ruleNature()
    {
        return 'qos';
    }

    public function storeVariableName()
    {
        return "qosRules";
    }

}