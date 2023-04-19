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

class DecryptionRule extends RuleWithUserID
{
    use NegatableRule;
    use RulewithLogging;

    protected $_profile = null;

    /** @var null|DOMElement */
    protected $categoryroot = null;

    /** @var string[] */
    protected $_urlCategories = array();

    /**
     * @var UrlCategoryRuleContainer
     */
    public $urlCategories;

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

        $this->urlCategories = new UrlCategoryRuleContainer($this);
        $this->urlCategories->name = 'urlcategories';

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
            $tmp = DH::findFirstElement('service', $xml);
            if( $tmp !== FALSE )
                $this->services->load_from_domxml($tmp);
        }
        // end of <service> zone extraction


        //										//
        // Begin <category> extraction			//
        //										//
        $tmp = DH::findFirstElement('category', $xml);
        if( $tmp )
        {
            if( $tmp->hasChildNodes() )
                $this->urlCategories->load_from_domxml($tmp);
            else
            {
                //fixing own created code, introduced on 2020 Sep 18th, with creating <category/>
                $tmp_member = DH::findFirstElementOrCreate('member', $tmp);
                $tmp_member->textContent = 'any';
            }
        }

        //
        // Begin <category> extraction
        //

        /*     <category> <member>adult</member></category>      */

        $this->categoryroot = DH::findFirstElement('category', $xml);
        if( $this->categoryroot === FALSE )
            $this->categoryroot = null;
        else
            $this->extract_category_from_domxml();

        // End of <category>


        $profileXML = DH::findFirstElement('profile', $xml);
        if( $profileXML !== FALSE )
            $this->_profile = $profileXML->nodeValue;
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

        if( $this->_description !== null && strlen($this->_description) > 0 )
        {
            PH::print_stdout( $padding . "  Desc:  " . $this->_description );
            PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = $this->_description;
        }

        if( $this->_profile !== null )
        {
            PH::print_stdout( $padding . "  Profil:  " . $this->getDecryptionProfile() );
            PH::$JSON_TMP['sub']['object'][$this->name()]['profile'] = $this->getDecryptionProfile();
        }

        $text = $padding . "  URL Category: ";
        if( !empty($this->_urlCategories) )
        {
            $text .= PH::list_to_string($this->_urlCategories) . "\n";
            foreach( $this->_urlCategories as $tmp )
                PH::$JSON_TMP['sub']['object'][$this->name()]['urlcategory'][] = $tmp;
        }
        else
        {
            $text .= "**ANY**";
            PH::$JSON_TMP['sub']['object'][$this->name()]['urlcategory'][] = "**ANY**";
        }
        PH::print_stdout( $text );

        PH::print_stdout();
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

    protected function extract_category_from_domxml()
    {
        $xml = $this->categoryroot;

        foreach( $xml->childNodes as $url_category )
        {
            if( $url_category->nodeType != XML_ELEMENT_NODE ) continue;

            $value = $url_category->textContent;
            if( strlen($value) < 1 )
            {
                mwarning('This rule has empty URL Category, please check your configuration file (corrupted?):', $url_category);
                continue;
            }
            $this->_urlCategories[$value] = $value;
            //Todo:
            //search for URL and add to UrlCagegoriesContainer
        }

        if( isset($this->_urlCategories['any']) )
        {
            if( count($this->_urlCategories) != 1 )
                mwarning('This security rule has URL category = ANY but it also have categories defined. ' .
                    'Please check your configuration file (corrupted?). *ANY* will be assumed by this framework', $xml, False);
            $this->_urlCategories = array();
        }

    }

    public function urlCategories()
    {
        return $this->_urlCategories;
    }

    public function urlCategoriescount()
    {
        return count($this->_urlCategories);
    }

    public function urlCategoryIsAny()
    {
        return count($this->_urlCategories) == 0;
    }

    /**
     * @param string $category
     * @return bool return TRUE if this rule is using the category defined in $category
     */
    public function urlCategoriesHas($category)
    {
        return isset($this->_urlCategories[$category]);
    }

    /**
     * enable or disabled logging at end
     * @param bool $yes
     * @return bool
     */
    public function setUrlCategories($category)
    {
        if( !isset( $this->_urlCategories[ $category ] ) )
        {
            $tmp = DH::findFirstElementOrCreate('category', $this->xmlroot);

            $tmp_member = DH::findFirstElementOrCreate('member', $tmp);
            $tmp_member->textContent = $category;

            $this->_urlCategories[ $category ] = $category;

            return TRUE;
        }
        return FALSE;
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
        $this->grouptag = null;
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