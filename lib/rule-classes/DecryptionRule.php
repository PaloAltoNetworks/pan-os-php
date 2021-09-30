<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

class DecryptionRule extends RuleWithUserID
{
    use NegatableRule;
    use RulewithLogging;

    protected $_profile = null;

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

        $this->load_from();
        $this->load_to();
        $this->load_source();
        $this->load_destination();

        $this->userID_loadUsersFromXml();
        $this->_readNegationFromXml();

        if( $this->owner->owner->version >= 100 )
            $this->_readLogSettingFromXml();

        //										//
        // Begin <service> extraction			//
        //										//
        if( $this->owner->owner->version >= 61 )
        {
            $tmp = DH::findFirstElementOrCreate('service', $xml);
            $this->services->load_from_domxml($tmp);
        }
        // end of <service> zone extraction

        $profileXML = DH::findFirstElement('profile', $xml);
        if( $profileXML !== FALSE )
        {
            $this->_profile = $profileXML->nodeValue;
        }
    }

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


        PH::print_stdout( $padding . "  From: " . $this->from->toString_inline() . "  |  To:  " . $this->to->toString_inline() );
        PH::$JSON_TMP['sub']['object'][$this->name()]['from'] = $this->from->toString_inline();
        PH::$JSON_TMP['sub']['object'][$this->name()]['to'] = $this->to->toString_inline();

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

        if( strlen($this->_description) > 0 )
        {
            PH::print_stdout( $padding . "  Desc:  " . $this->_description );
            PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = $this->_description;
        }

        if( $this->_profile !== null )
        {
            PH::print_stdout( $padding . "  Profil:  " . $this->getDecryptionProfile() );
            PH::$JSON_TMP['sub']['object'][$this->name()]['profile'] = $this->getDecryptionProfile();
        }


        PH::print_stdout("");
    }

    public function getDecryptionProfile()
    {
        return $this->_profile;
    }

    public function setDecryptionProfile( $newDecryptName )
    {
        //Todo: swaschkut 20210323 - check if decryptionprofile is available
        //Panorama/PAN-OS => default / FAWKES => best-practice

        //Todo: profile can only be set if <action>decrypt</action> is available
        //if <action>no-decrypt</action> the field <profile> is not available

        $this->_profile = $newDecryptName;

        $domNode = DH::findFirstElementOrCreate('profile', $this->xmlroot);
        DH::setDomNodeText($domNode, $newDecryptName);
    }

    public function cleanForDestruction()
    {
        $this->from->__destruct();
        $this->to->__destruct();
        $this->source->__destruct();
        $this->destination->__destruct();
        $this->tags->__destruct();
        $this->services->__destruct();

        $this->from = null;
        $this->to = null;
        $this->source = null;
        $this->destination = null;
        $this->tags = null;
        $this->services = null;

        $this->owner = null;
    }

    public function isDecryptionRule()
    {
        return TRUE;
    }

    public function storeVariableName()
    {
        return "decryptionRules";
    }

    public function ruleNature()
    {
        return 'decryption';
    }

} 