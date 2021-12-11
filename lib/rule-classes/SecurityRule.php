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


class SecurityRule extends RuleWithUserID
{
    use NegatableRule;
    use RulewithLogging;

    protected $action = self::ActionAllow;

    protected $logstart = FALSE;
    protected $logend = TRUE;

    protected $schedule = null;
    protected $qosMarking = array();

    /** @var null|DOMElement */
    protected $categoryroot = null;

    /** @var string[] */
    protected $_urlCategories = array();

    /**
     * @var UrlCategoryRuleContainer
     */
    public $urlCategories;

    protected $dsri = FALSE;

    protected $secproftype = 'none';

    /** @var null|string[]|DOMElement */
    public $secprofroot = null;
    protected $secprofgroup = null;
    protected $secprofgroup_obj = null;

    protected $secprofProfiles = array();
    protected $secprofProfiles_obj = array();

    public $hipprofroot = null;
    protected $hipprofProfiles = null;

    /** @var AppRuleContainer */
    public $apps;

    const TypeUniversal = 0;
    const TypeIntrazone = 1;
    const TypeInterzone = 2;

    static private $RuleTypes = array(
        self::TypeUniversal => 'universal',
        self::TypeIntrazone => 'intrazone',
        self::TypeInterzone => 'interzone'
    );


    const ActionAllow = 0;
    const ActionDeny = 1;
    const ActionDrop = 2;
    const ActionResetClient = 3;
    const ActionResetServer = 4;
    const ActionResetBoth = 5;

    static private $RuleActions = array(
        self::ActionAllow => 'allow',
        self::ActionDeny => 'deny',
        self::ActionDrop => 'drop',
        self::ActionResetClient => 'reset-client',
        self::ActionResetServer => 'reset-server',
        self::ActionResetBoth => 'reset-both'
    );

    protected $ruleType = self::TypeUniversal;


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

        $this->apps = new AppRuleContainer($this);
        $this->apps->name = 'apps';

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

        //print "found rule name '".$this->name."'\n";

        $this->load_common_from_domxml();


        $this->load_source();
        $this->load_destination();
        $this->load_from();
        $this->load_to();


        //														//
        // Begin <application> application extraction			//
        //														//
        $tmp = DH::findFirstElement('application', $xml);
        if( $tmp === false )
        {
            $tmp = DH::findFirstElementOrCreate('application', $xml);
            $tmp_member = DH::findFirstElementOrCreate('member', $tmp);
            $tmp_member->textContent= 'any';
        }
        $this->apps->load_from_domxml($tmp);
        // end of <application> application extraction


        //										//
        // Begin <service> extraction			//
        //										//
        $tmp = DH::findFirstElement('service', $xml);
        if( $tmp === false )
        {
            $tmp = DH::findFirstElementOrCreate('service', $xml);
            $tmp_member = DH::findFirstElementOrCreate('member', $tmp);
            $tmp_member->textContent= 'any';
        }
        $this->services->load_from_domxml($tmp);
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

        $this->_readLogSettingFromXml();

        // end of <category> zone extraction

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeName == 'log-start' )
            {
                $this->logstart = yesNoBool($node->textContent);
            }
            else if( $node->nodeName == 'log-end' )
            {
                $this->logend = yesNoBool($node->textContent);
            }
            else if( $node->nodeName == 'action' )
            {
                $actionFound = array_search($node->textContent, self::$RuleActions);
                if( $actionFound === FALSE )
                {
                    mwarning("unsupported action '{$tmp->textContent}' found, allow assumed", $tmp);
                }
                else
                {
                    $this->action = $actionFound;
                }
            }
            else if( $node->nodeName == 'option' )
            {
                foreach( $node->childNodes as $subnode )
                {
                    if( $subnode->nodeName == 'disable-server-response-inspection' )
                    {
                        $lstate = strtolower($subnode->textContent);
                        if( $lstate == 'yes' )
                        {
                            $this->dsri = TRUE;
                        }
                    }
                }
            }
            elseif( $node->nodeName == 'schedule' )
            {
                #$this->schedule = $node->textContent;

                $f = $this->owner->owner->scheduleStore->find($node->textContent, $this);
                if( $f == null && is_object($this->owner->owner->scheduleStore->parentCentralStore))
                    $f = $this->owner->owner->scheduleStore->parentCentralStore->find($node->textContent, $this);
                if( $f != null )
                {
                    $f->addReference( $this );
                    $this->schedule = $f;
                }
            }
            elseif( $node->nodeName == 'qos' )
            {
                $tmp = DH::findFirstElement('marking', $node);
                $node1 = $tmp->firstChild;
                $this->qosMarking = array($node1->nodeName => $node1->textContent);
            }
        }


        //
        // Begin <profile-setting> extraction
        //
        $this->secprofroot = DH::findFirstElement('profile-setting', $xml);
        if( $this->secprofroot === FALSE )
            $this->secprofroot = null;
        else
            $this->extract_security_profile_from_domxml();
        // End of <profile-setting>


        //
        // Begin <hip-profiles> extraction // valid for PAN-OS version < 10.0
        // Todo: PAN-OS version >= 10.0 -> source-hip and destination-hip
        //
        if( $this->owner->version < 100 )
            $hipprofilevariable = 'hip-profiles';
        else
            $hipprofilevariable = 'source-hip';

        $this->hipprofroot = DH::findFirstElement($hipprofilevariable, $xml);
        if( $this->hipprofroot === FALSE )
            $this->hipprofroot = null;
        else
            $this->extract_hip_profile_from_domxml( );


        // End of <hip-profiles>

        $this->_readNegationFromXml();

        //
        // Begin <rule-type> extraction
        //
        if( $this->owner->version >= 61 )
        {
            $tmp = DH::findFirstElement('rule-type', $xml);
            if( $tmp !== FALSE )
            {
                $typefound = array_search($tmp->textContent, self::$RuleTypes);
                if( $typefound === FALSE )
                {
                    mwarning("unsupported rule-type '{$tmp->textContent}', universal assumed", $tmp);
                }
                else
                {
                    $this->ruleType = $typefound;
                }
            }
        }
        // End of <rule-type>

        $this->userID_loadUsersFromXml();


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
    }


    /**
     * @return string type of this rule : 'universal', 'intrazone', 'interzone'
     */
    public function type()
    {
        return self::$RuleTypes[$this->ruleType];
    }


    public function setType($type)
    {
        if( $this->owner->owner->version < 61 )
            derr('ruletype is introduce in PAN-OS 6.1');

        $type = strtolower($type);

        $typefound = array_search($type, self::$RuleTypes);
        if( $typefound === FALSE )
            derr("unsupported rule-type '{$type}', universal assumed");

        if( $this->ruleType == $typefound )
            return FALSE;

        $this->ruleType = $typefound;

        $find = DH::findFirstElementOrCreate('rule-type', $this->xmlroot);
        DH::setDomNodeText($find, $type);

        return TRUE;
    }

    public function API_setType($type)
    {
        $ret = $this->setType($type);

        if( $ret )
        {
            $xpath = $this->getXPath() . '/rule-type';
            $con = findConnectorOrDie($this);

            $con->sendEditRequest($xpath, "<rule-type>{$this->type()}</rule-type>");
        }

        return $ret;
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
                    'Please check your configuration file (corrupted?). *ANY* will be assumed by this framework', $xml);
            $this->_urlCategories = array();
        }

    }


    /**
     *
     * @ignore
     */
    protected function extract_security_profile_from_domxml()
    {

        if( $this->secprofroot === null || $this->secprofroot === FALSE )
        {
            $this->secprofroot = null;
            return;
        }

        $xml = $this->secprofroot;

        //print "Now trying to extract associated security profile associated to '".$this->name."'\n";

        $groupRoot = DH::findFirstElement('group', $xml);
        $profilesRoot = DH::findFirstElement('profiles', $xml);

        if( $groupRoot !== FALSE )
        {
            //print "Found SecProf <group> tag\n";
            $firstE = DH::firstChildElement($groupRoot);

            if( $firstE !== FALSE )
            {
                $this->secproftype = 'group';

                //Todo findOrCreate can NOT be used because of default object not created
                #$tmp_group =  $this->owner->owner->securityProfileGroupStore->findorCreate( $firstE->textContent );
                $tmp_group =  $this->owner->owner->securityProfileGroupStore->find( $firstE->textContent );
                if( is_object( $tmp_group ) )
                {
                    $this->secprofgroup = $firstE->textContent;
                    //Todo: swaschkut 20210422
                    //- not working due to parentcentralStore implementation wrong
                    $tmp_group->addReference( $this );
                }
                else
                {
                    //todo: not an object - default object not yet created
                    $this->secprofgroup = $firstE->textContent;
                }
            }
        }
        elseif( $profilesRoot !== FALSE )
        {
            //print "Found SecProf <profiles> tag\n";
            $this->secproftype = 'profile';

            foreach( $profilesRoot->childNodes as $prof )
            {
                if( $prof->nodeType != XML_ELEMENT_NODE ) continue;
                $firstE = DH::firstChildElement($prof);
                if( $firstE !== FALSE )
                {
                    $this->secprofProfiles[$prof->nodeName] = $firstE->textContent;

                    $checkArray = $this->owner->owner->securityProfileGroupStore->secprof_array;
                    $tmp_key = array_search( $prof->nodeName, $checkArray );
                    $tmp_store_name =  $this->owner->owner->securityProfileGroupStore->secprof_store[ $tmp_key ];

                    $profile = $this->owner->owner->$tmp_store_name->find( $firstE->textContent );

                    if( $profile != null )
                    {
                        $this->secprofProfiles_obj[$prof->nodeName] = $profile;

                        $profile->addReference( $this );
                    }
                    else
                    {
                        //todo: not an object - default object not yet created
                        $this->secprofProfiles_obj[$prof->nodeName] = $firstE->textContent;
                    }
                }
            }
        }
    }

    public function securityProfileIsBlank()
    {
        if( $this->secproftype == 'none' )
            return TRUE;

        if( $this->secproftype == 'group' && $this->secprofgroup !== null )
            return FALSE;

        if( $this->secproftype == 'profile' )
        {
            if( is_array($this->secprofProfiles) && count($this->secprofProfiles) > 0 )
                return FALSE;

        }

        return TRUE;

    }

    /**
     * return profile type: 'group' or 'profile' or 'none'
     * @return string
     */
    public function securityProfileType()
    {
        return $this->secproftype;
    }

    public function securityProfileGroup()
    {
        if( $this->secproftype != 'group' )
            derr('Cannot be called on a rule that is of security type =' . $this->secproftype);

        return $this->secprofgroup;
    }

    public function securityProfiles()
    {
        if( $this->secproftype != 'profile' )
            return array();

        return $this->secprofProfiles;
    }

    public function securityProfilHash()
    {
        $string = "";
        if( $this->secproftype === 'group' )
            $string = $this->secprofgroup;
        elseif( $this->secproftype === 'profile' )
        {
            $stringArray = array_keys($this->secprofProfiles_obj);
            $string = implode( ", ", $stringArray );
        }

        return md5( $string );
    }

    public function securityProfiles_obj()
    {
        if( $this->secproftype != 'profile' )
            return array();

        return $this->secprofProfiles_obj;
    }

    public function removeSecurityProfile()
    {
        if( $this->secproftype == 'none' )
            return FALSE;

        $this->secproftype = 'none';
        $this->secprofgroup = null;
        $this->secprofProfiles = array();

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function API_removeSecurityProfile()
    {
        $ret = $this->removeSecurityProfile();

        if( $ret )
        {
            $xpath = $this->getXPath() . '/profile-setting';
            $con = findConnectorOrDie($this);

            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function setSecurityProfileGroup($newgroup)
    {
        //TODO : implement better 'change' detection to remove this return true
        $this->secproftype = 'group';
        $this->secprofgroup = $newgroup;
        $this->secprofProfiles = array();

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function API_setSecurityProfileGroup($newgroup)
    {
        $ret = $this->setSecurityProfileGroup($newgroup);

        if( $ret )
        {
            $xpath = $this->getXPath() . '/profile-setting';
            $con = findConnectorOrDie($this);

            $con->sendEditRequest($xpath, '<profile-setting><group><member>' . $newgroup . '</member></group></profile-setting>');
        }

        return $ret;
    }


    public function setSecProf_AV($newAVprof)
    {
        $this->secproftype = 'profiles';
        $this->secprofgroup = null;
        if( $newAVprof == "null" )
            unset($this->secprofProfiles['virus']);
        else
            $this->secprofProfiles['virus'] = $newAVprof;

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function setSecProf_Vuln($newAVprof)
    {
        $this->secproftype = 'profiles';
        $this->secprofgroup = null;
        if( $newAVprof == "null" )
            unset($this->secprofProfiles['vulnerability']);
        else
            $this->secprofProfiles['vulnerability'] = $newAVprof;

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function setSecProf_URL($newAVprof)
    {
        $this->secproftype = 'profiles';
        $this->secprofgroup = null;
        if( $newAVprof == "null" )
            unset($this->secprofProfiles['url-filtering']);
        else
            $this->secprofProfiles['url-filtering'] = $newAVprof;

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function setSecProf_DataFilt($newAVprof)
    {
        $this->secproftype = 'profiles';
        $this->secprofgroup = null;
        if( $newAVprof == "null" )
            unset($this->secprofProfiles['data-filtering']);
        else
            $this->secprofProfiles['data-filtering'] = $newAVprof;

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function setSecProf_FileBlock($newAVprof)
    {
        $this->secproftype = 'profiles';
        $this->secprofgroup = null;

        if( $newAVprof == "null" )
            unset($this->secprofProfiles['file-blocking']);
        else
            $this->secprofProfiles['file-blocking'] = $newAVprof;

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function setSecProf_Spyware($newAVprof)
    {
        $this->secproftype = 'profiles';
        $this->secprofgroup = null;
        if( $newAVprof == "null" )
            unset($this->secprofProfiles['spyware']);
        else
            $this->secprofProfiles['spyware'] = $newAVprof;

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function setSecProf_Wildfire($newAVprof)
    {
        $this->secproftype = 'profiles';
        $this->secprofgroup = null;
        if( $newAVprof == "null" )
            unset($this->secprofProfiles['wildfire-analysis']);
        else
            $this->secprofProfiles['wildfire-analysis'] = $newAVprof;

        $this->rewriteSecProfXML();

        return TRUE;
    }

    public function rewriteSecProfXML()
    {

        if( $this->secprofroot !== null )
            DH::clearDomNodeChilds($this->secprofroot);
        if( $this->secproftype == 'group' )
        {
            if( $this->secprofroot === null || $this->secprofroot === FALSE )
                $this->secprofroot = DH::createElement($this->xmlroot, 'profile-setting');
            else
                $this->xmlroot->appendChild($this->secprofroot);

            $tmp = $this->secprofroot->ownerDocument->createElement('group');
            $tmp = $this->secprofroot->appendChild($tmp);
            $tmp = $tmp->appendChild($this->secprofroot->ownerDocument->createElement('member'));
            $tmp->appendChild($this->secprofroot->ownerDocument->createTextNode($this->secprofgroup));
        }
        else if( $this->secproftype == 'profiles' )
        {
            if( $this->secprofroot === null || $this->secprofroot === FALSE )
                $this->secprofroot = DH::createElement($this->xmlroot, 'profile-setting');
            else
                $this->xmlroot->appendChild($this->secprofroot);

            $tmp = $this->secprofroot->ownerDocument->createElement('profiles');
            $tmp = $this->secprofroot->appendChild($tmp);

            foreach( $this->secprofProfiles as $index => $value )
            {
                $type = $tmp->appendChild($this->secprofroot->ownerDocument->createElement($index));
                $ntmp = $type->appendChild($this->secprofroot->ownerDocument->createElement('member'));
                $ntmp->appendChild($this->secprofroot->ownerDocument->createTextNode($value));
            }
        }
    }

    /**
     *
     * @ignore
     */
    protected function extract_hip_profile_from_domxml()
    {

        if( $this->hipprofroot === null || $this->secprofroot === FALSE )
        {
            $this->hipprofroot = null;
            return;
        }

        $xml = $this->hipprofroot;

        #print "\nNow trying to extract associated hip profile associated to '".$this->name."'\n";


        foreach( $xml->childNodes as $prof )
        {
            if( $prof->nodeType != XML_ELEMENT_NODE ) continue;

            $this->hipprofProfiles[$prof->textContent] = $prof->textContent;
            #print PH::boldText("name: |".$prof->nodeName."| - |".$prof->textContent."|\n" );
        }
    }

    public function hipProfileIsBlank()
    {
        if( $this->hipprofroot == null )
            return TRUE;

        if( $this->hipprofProfiles !== null )
            return FALSE;

        return TRUE;

    }

    public function urlCategories()
    {
        return $this->_urlCategories;
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

    public function action()
    {
        return self::$RuleActions[$this->action];
    }

    public function actionIsAllow()
    {
        return $this->action == self::ActionAllow;
    }

    public function actionIsDeny()
    {
        return $this->action == self::ActionDeny;
    }

    public function actionIsDrop()
    {
        return $this->action == self::ActionDrop;
    }

    public function actionIsResetClient()
    {
        return $this->action == self::ActionResetClient;
    }

    public function actionIsResetServer()
    {
        return $this->action == self::ActionResetServer;
    }

    public function actionIsResetBoth()
    {
        return $this->action == self::ActionResetBoth;
    }

    public function actionIsNegative()
    {
        return $this->action != self::ActionAllow;
    }

    public function setAction($newAction)
    {
        $newAction = strtolower($newAction);
        $actionFound = array_search($newAction, self::$RuleActions);

        if( $actionFound !== FALSE )
        {
            $this->action = $actionFound;
            if( $this->owner->version < 70 && $actionFound > self::ActionDeny )
            {
                derr("action '$newAction' is not supported before PANOS 7.0");
            }
            $domNode = DH::findFirstElementOrCreate('action', $this->xmlroot);
            DH::setDomNodeText($domNode, $newAction);
        }
        else
            derr("'$newAction' is not supported action type\n");
    }

    public function API_setAction($newAction)
    {
        $this->setAction($newAction);

        $domNode = DH::findFirstElementOrDie('action', $this->xmlroot);
        $connector = findConnectorOrDie($this);
        $connector->sendSetRequest($this->getXPath(), $domNode);
    }


    /**
     * return true if rule is set to Log at Start
     * @return bool
     */
    public function logStart()
    {
        return $this->logstart;
    }

    /**
     * enabled or disabled logging at start
     * @param bool $yes
     * @return bool
     */
    public function setLogStart($yes)
    {
        if( $this->logstart != $yes )
        {
            $tmp = DH::findFirstElementOrCreate('log-start', $this->xmlroot);
            DH::setDomNodeText($tmp, boolYesNo($yes));

            $this->logstart = $yes;

            return TRUE;
        }
        return FALSE;
    }

    /**
     * return true if rule is set to Log at End
     * @return bool
     */
    public function logEnd()
    {
        return $this->logend;
    }

    /**
     * enable or disabled logging at end
     * @param bool $yes
     * @return bool
     */
    public function setLogEnd($yes)
    {
        if( $this->logend != $yes )
        {
            $tmp = DH::findFirstElementOrCreate('log-end', $this->xmlroot);
            DH::setDomNodeText($tmp, boolYesNo($yes));

            $this->logend = $yes;

            return TRUE;
        }
        return FALSE;
    }

    /**
     * enable or disabled logging at end
     * @param bool $yes
     * @return bool
     */
    public function API_setLogEnd($yes)
    {
        if( !$this->setLogEnd($yes) )
            return FALSE;

        $con = findConnectorOrDie($this);
        $con->sendSetRequest($this->getXPath(), "<log-end>" . boolYesNo($yes) . "</log-end>");

        return TRUE;
    }

    /**
     * enable or disabled logging at end
     * @param bool $yes
     * @return bool
     */
    public function API_setLogStart($yes)
    {
        if( !$this->setLogStart($yes) )
            return FALSE;

        $con = findConnectorOrDie($this);
        $con->sendSetRequest($this->getXPath(), "<log-start>" . boolYesNo($yes) . "</log-start>");

        return TRUE;
    }

    /**
     *
     * @return bool
     */
    public function isDSRIEnabled()
    {
        if( $this->dsri )
            return TRUE;

        return FALSE;
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
        //until here same for appoverride


        $text = $padding . "*Rule named '{$this->name}' $dis";
        if( $this->owner->version >= 70 )
        {
            $text .= " UUID: '" . $this->uuid() . "'";
            PH::$JSON_TMP['sub']['object'][$this->name()]['uuid'] = $this->uuid();
        }
        PH::print_stdout( $text );

        PH::print_stdout( $padding . "  Action: {$this->action()}    Type:{$this->type()}");
        PH::$JSON_TMP['sub']['object'][$this->name()]['action'] = $this->action();
        PH::$JSON_TMP['sub']['object'][$this->name()]['ruletype'] = $this->type();


        PH::print_stdout( $padding . "  From: " . $this->from->toString_inline() . "  |  To:  " . $this->to->toString_inline() );
        foreach( $this->from->zones() as $from )
            PH::$JSON_TMP['sub']['object'][$this->name()]['from'][] = $from->name();
        if( count( $this->from->zones() ) == 0 )
            PH::$JSON_TMP['sub']['object'][$this->name()]['from'][] = "any";

        foreach( $this->to->zones() as $to )
            PH::$JSON_TMP['sub']['object'][$this->name()]['to'][] = $to->name();
        if( count( $this->to->zones() ) == 0 )
            PH::$JSON_TMP['sub']['object'][$this->name()]['to'][] = "any";

        PH::print_stdout( $padding . "  Source: $sourceNegated " . $this->source->toString_inline() );
        foreach( $this->source->getAll() as $src )
            PH::$JSON_TMP['sub']['object'][$this->name()]['source'][] = $src->name();

        PH::print_stdout( $padding . "  Destination: $destinationNegated " . $this->destination->toString_inline() );
        foreach( $this->destination->getAll() as $dst )
            PH::$JSON_TMP['sub']['object'][$this->name()]['destination'][] = $dst->name();

        PH::print_stdout( $padding . "  Service:  " . $this->services->toString_inline() . "    Apps:  " . $this->apps->toString_inline() );
        foreach( $this->services->getAll() as $srv )
            PH::$JSON_TMP['sub']['object'][$this->name()]['service'][] = $srv->name();
        if( $this->services->isApplicationDefault() )
            PH::$JSON_TMP['sub']['object'][$this->name()]['service'][] = "application-default";
        if( $this->services->isAny() )
            PH::$JSON_TMP['sub']['object'][$this->name()]['service'][] = "any";

        foreach( $this->apps->getAll() as $app )
            PH::$JSON_TMP['sub']['object'][$this->name()]['application'][] = $app->name();
        if( $this->apps->isAny() )
            PH::$JSON_TMP['sub']['object'][$this->name()]['application'][] = "any";

        $text = "";
        if( !$this->userID_IsCustom() )
        {
            $text .= $padding . "  User: *" . $this->userID_type() . "*";
            PH::$JSON_TMP['sub']['object'][$this->name()]['user'] = $this->userID_type();
        }
        else
        {
            $users = $this->userID_getUsers();
            $text .= $padding . "  User:  '" . PH::list_to_string($users, " | ") . "'";
            foreach( $users as $user )
                PH::$JSON_TMP['sub']['object'][$this->name()]['user'][] = $user;
        }
        if( !$this->hipProfileIsBlank() )
        {
            $text .= $padding . "  HIP:   " . PH::list_to_string($this->hipprofProfiles);
            foreach( $this->hipprofProfiles as $hipProf )
                PH::$JSON_TMP['sub']['object'][$this->name()]['hip'][] = $hipProf;
        }
        PH::print_stdout( $text );
        PH::print_stdout( $padding . "  Tags:  " . $this->tags->toString_inline() );
        foreach( $this->tags->getAll() as $tag )
            PH::$JSON_TMP['sub']['object'][$this->name()]['tag'][] = $tag->name();

        if( $this->_targets !== null )
        {
            PH::print_stdout( $padding . "  Targets:  " . $this->targets_toString() );
            foreach( $this->targets() as $target )
                PH::$JSON_TMP['sub']['object'][$this->name()]['target'][] = $target;
        }


        if( strlen($this->_description) > 0 )
        {
            PH::print_stdout( $padding . "  Desc:  " . $this->_description );
            PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = $this->_description;
        }
        else
        {
            PH::print_stdout( $padding . "  Desc:  ");
            PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = "";
        }


        if( !$this->securityProfileIsBlank() )
        {
            if( $this->securityProfileType() == "group" )
            {
                PH::print_stdout( $padding . "  SecurityProfil: [SECGROUP] => '" . $this->securityProfileGroup() . "'");
                PH::$JSON_TMP['sub']['object'][$this->name()]['securityprofilegroup'] = $this->securityProfileGroup();
            }

            else
            {
                $text = $padding . "  SecurityProfil: ";
                foreach( $this->securityProfiles() as $id => $profile )
                {
                    $text .= "[" . $id . "] => '" . $profile . "'  ";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['securityprofile'][$id] = $profile;
                }

                PH::print_stdout( $text );
            }
        }
        else
        {
            PH::print_stdout( $padding . "  SecurityProfil:");
            PH::$JSON_TMP['sub']['object'][$this->name()]['securityprofilegroup'] = "null";
            PH::$JSON_TMP['sub']['object'][$this->name()]['securityprofile'] = "null";
        }



        $text = $padding . "  LogSetting: ";
        if( !empty($this->logSetting()) )
        {
            $text .= "[LogProfile] => '" . $this->logSetting() . "'";
            PH::$JSON_TMP['sub']['object'][$this->name()]['logsetting']['logprofile'] = $this->logSetting();
        }

        $text .= " ( ";
        if( $this->logStart() )
        {
            $text .= "log at start";
            PH::$JSON_TMP['sub']['object'][$this->name()]['logsetting']['start'] = "true";
        }

        if( $this->logStart() && $this->logEnd() )
            $text .= " - ";
        if( $this->logEnd() )
        {
            $text .= "log at end";
            PH::$JSON_TMP['sub']['object'][$this->name()]['logsetting']['end'] = "true";
        }

        $text .= " )";
        PH::print_stdout( $text );

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

        if( $this->dsri )
        {
            PH::print_stdout( $padding . "  DSRI: disabled");
            PH::$JSON_TMP['sub']['object'][$this->name()]['dsri'][] = "disabled";
        }


        if( $this->schedule !== null )
        {
            PH::print_stdout( $padding . "  Schedule:  " . $this->schedule->name() );
            PH::$JSON_TMP['sub']['object'][$this->name()]['schedule'][] = $this->schedule->name();
        }


        PH::print_stdout( "" );
    }


    // 'last-30-days','incomplete,insufficient-data'
    public function &API_getAppStats($timePeriod, $excludedApps)
    {
        $con = findConnectorOrDie($this);

        $parentClass = get_class($this->owner->owner);

        $type = 'panorama-trsum';
        if( $parentClass == 'VirtualSystem' )
        {
            $type = 'trsum';
        }

        $excludedApps = explode(',', $excludedApps);
        $excludedAppsString = '';

        $first = TRUE;

        foreach( $excludedApps as &$e )
        {
            if( !$first )
                $excludedAppsString .= ' and ';

            $excludedAppsString .= "(app neq $e)";

            $first = FALSE;
        }
        if( !$first )
            $excludedAppsString .= ' and ';


        if( $parentClass == 'VirtualSystem' )
        {
            $dvq = '(vsys eq ' . $this->owner->owner->name() . ')';

        }
        else
        {
            $devices = $this->owner->owner->getDevicesInGroup();
            //print_r($devices);

            $first = TRUE;

            if( count($devices) == 0 )
                derr('cannot request rule stats for a device group that has no member');

            $dvq = '(' . array_to_devicequery($devices) . ')';
        }

        $query = 'type=report&reporttype=dynamic&reportname=custom-dynamic-report&async=yes&cmd=<type>'
            . '<' . $type . '><aggregate-by><member>app</member></aggregate-by>'
            . '<values><member>sessions</member></values></' . $type . '></type><period>' . $timePeriod . '</period>'
            . '<topn>500</topn><topm>10</topm><caption>untitled</caption>'
            . '<query>' . "$dvq and $excludedAppsString (rule eq '" . $this->name . "')</query>";

        //print "Query: $query\n";

        $ret = $con->getReport($query);

        return $ret;
    }

    public function &API_getAppContainerStats($timePeriod = 'last-30-days', $fastMode = TRUE, $limit = 50, $excludedApps = array())
    {
        $con = findConnectorOrDie($this);

        $parentClass = get_class($this->owner->owner);

        if( $fastMode )
            $type = 'panorama-trsum';
        else
            $type = 'panorama-traffic';

        if( $parentClass == 'VirtualSystem' )
        {
            if( $fastMode )
                $type = 'trsum';
            else
                $type = 'traffic';
        }

        $excludedAppsString = '';

        $first = TRUE;
        foreach( $excludedApps as &$e )
        {
            if( !$first )
                $excludedAppsString .= ' and ';

            $excludedAppsString .= "(app neq $e)";
            $first = FALSE;
        }

        $dvq = '';

        if( $parentClass == 'VirtualSystem' )
        {
            $dvq = ' and (vsys eq ' . $this->owner->owner->name() . ')';

        }
        else
        {
            $devices = $this->owner->owner->getDevicesInGroup();

            if( count($devices) == 0 )
                derr('cannot request rule stats for a device group that has no member');

            $dvq = ' and (' . array_to_devicequery($devices) . ')';

        }

        $repeatOrCount = 'sessions';

        if( !$fastMode )
            $repeatOrCount = 'repeatcnt';

        $query = 'type=report&reporttype=dynamic&reportname=custom-dynamic-report&async=yes&cmd=<type>'
            . "<{$type}>\n<aggregate-by><member>container-of-app</member><member>app</member></aggregate-by>\n"
            . "<values><member>{$repeatOrCount}</member></values></{$type}></type><period>{$timePeriod}</period>"
            . "<topn>{$limit}</topn>\n<topm>50</topm>\n<caption>untitled</caption>\n"
            . "<query>(rule eq '{$this->name}') {$dvq} {$excludedAppsString}</query>\n"
            . "<runnow>yes</runnow>\n";

        //print "Query: $query\n";

        $ret = $con->getReport($query);

        return $ret;
    }

    /**
     * @param integer $startTimestamp
     * @param null|integer $endTimestamp
     * @param bool|true $fastMode
     * @param int $limit
     * @param array $excludedApps
     * @return array|DomDocument
     * @throws Exception
     */
    public function &API_getAppContainerStats2($startTimestamp, $endTimestamp = null, $fastMode = TRUE, $limit = 50, $excludedApps = array())
    {
        $con = findConnectorOrDie($this);

        $parentClass = get_class($this->owner->owner);

        if( $fastMode )
            $type = 'panorama-trsum';
        else
            $type = 'panorama-traffic';

        if( $parentClass == 'VirtualSystem' )
        {
            if( $fastMode )
                $type = 'trsum';
            else
                $type = 'traffic';
        }

        if( $parentClass == 'DeviceGroup' && $con->info_PANOS_version_int < 80 )
        {
            $deviceClass = get_class($this->owner->owner->owner);
            if( $deviceClass == 'PanoramaConf' )
            {
                $connected_devices = $this->owner->owner->owner->managedFirewallsSerialsModel;
                foreach( $this->owner->owner->getDevicesInGroup(TRUE) as $serial => $device )
                {
                    if( strpos($connected_devices[$serial]['model'], 'PA-70') !== FALSE )
                    {
                        if( $fastMode )
                            $type = 'trsum';
                        else
                            $type = 'traffic';
                    }
                }
            }
        }


        $excludedAppsString = '';

        $first = TRUE;
        foreach( $excludedApps as &$e )
        {
            if( !$first )
                $excludedAppsString .= ' and ';

            $excludedAppsString .= "(app neq $e)";
            $first = FALSE;
        }

        if( $parentClass == 'VirtualSystem' )
        {
            $dvq = ' and (vsys eq ' . $this->owner->owner->name() . ')';

        }
        else if( $con->info_PANOS_version_int < 71 )
        {
            // if PANOS < 7.1 then you need to list each device serial number
            $devices = $this->owner->owner->getDevicesInGroup(TRUE);

            if( count($devices) == 0 )
                derr('cannot request rule stats for a device group that has no member');

            $dvq = ' and (' . array_to_devicequery($devices) . ')';
        }
        else
        {
            $dvq = " and ( device-group eq '{$this->owner->owner->name()}')";
        }

        $repeatOrCount = 'sessions';

        if( !$fastMode )
            $repeatOrCount = 'repeatcnt';

        $startString = date('Y/m/d H:i:00', $startTimestamp);

        if( $endTimestamp === null )
        {
            $endString = date('Y/m/d H:00:00');
        }
        else
            $endString = date('Y/m/d H:00:00', $endTimestamp);

        $query = '<type>'
            . "<{$type}><aggregate-by><member>container-of-app</member><member>app</member></aggregate-by>"
            . "<values><member>{$repeatOrCount}</member></values></{$type}></type>"
            . "<topn>{$limit}</topn><topm>50</topm><caption>rule app container usage</caption>"
            . "<start-time>{$startString}</start-time>"
            . "<end-time>{$endString}</end-time>"
            . "<query>(rule eq '{$this->name}') {$dvq} {$excludedAppsString}</query>";


        $apiArgs = array();
        $apiArgs['type'] = 'report';
        $apiArgs['reporttype'] = 'dynamic';
        $apiArgs['reportname'] = 'custom-dynamic-report';
        $apiArgs['async'] = 'yes';
        $apiArgs['cmd'] = $query;


        $ret = $con->getReport($apiArgs);

        return $ret;
    }


    public function &API_getServiceStats($timePeriod = 'last-30-days', $fastMode = TRUE, $limit = 50, $specificApps = null)
    {
        $con = findConnectorOrDie($this);

        $query_appfilter = '';

        if( $specificApps !== null )
        {
            if( !is_array($specificApps) )
            {
                if( is_string($specificApps) )
                {
                    $specificApps = explode(',', $specificApps);
                }
                else
                    derr('$specificApps is not an array or a string');
            }

            $query_appfilter = ' and (';

            $first = TRUE;
            foreach( $specificApps as &$app )
            {
                if( !$first )
                    $query_appfilter .= ' or ';
                else
                    $first = FALSE;

                $query_appfilter .= "(app eq $app)";
            }

            $query_appfilter .= ') ';
        }

        $parentClass = get_class($this->owner->owner);

        if( $fastMode )
            $type = 'panorama-trsum';
        else
            $type = 'panorama-traffic';

        if( $parentClass == 'VirtualSystem' )
        {
            if( $fastMode )
                $type = 'trsum';
            else
                $type = 'traffic';
        }

        if( $parentClass == 'VirtualSystem' )
        {
            $dvq = '(vsys eq ' . $this->owner->owner->name() . ')';
        }
        else
        {
            $devices = $this->owner->owner->getDevicesInGroup();
            //print_r($devices);

            $first = TRUE;

            if( count($devices) == 0 )
                derr('cannot request rule stats for a device group that has no member');

            $dvq = '(' . array_to_devicequery($devices) . ')';
        }

        $query = "<type>"
            . "<" . $type . "><aggregate-by><member>proto</member><member>dport</member></aggregate-by>"
            . "</" . $type . "></type><period>" . $timePeriod . "</period>"
            . "<topn>{$limit}</topn><topm>50</topm><caption>untitled</caption>"
            . "<query>" . "$dvq $query_appfilter and (rule eq '" . $this->name . "')</query>";

        $apiArgs = array();
        $apiArgs['type'] = 'report';
        $apiArgs['reporttype'] = 'dynamic';
        $apiArgs['reportname'] = 'custom-dynamic-report';
        $apiArgs['async'] = 'yes';
        $apiArgs['cmd'] = $query;

        $ret = $con->getReport($apiArgs);

        return $ret;
    }

    public function &API_getAddressStats($timePeriod = 'last-30-days', $srcORdst = 'src', $fastMode = TRUE, $limit = 50, $excludedAddresses = array())
    {
        $con = findConnectorOrDie($this);

        $parentClass = get_class($this->owner->owner);

        if( $fastMode )
            $type = 'panorama-trsum';
        else
            $type = 'panorama-traffic';

        if( $parentClass == 'VirtualSystem' )
        {
            if( $fastMode )
                $type = 'trsum';
            else
                $type = 'traffic';
        }

        if( $parentClass == 'VirtualSystem' )
        {
            $dvq = '(vsys eq ' . $this->owner->owner->name() . ')';
        }
        else
        {
            $devices = $this->owner->owner->getDevicesInGroup();
            //print_r($devices);

            $first = TRUE;

            if( count($devices) == 0 )
                derr('cannot request rule stats for a device group that has no member');

            $dvq = '(' . array_to_devicequery($devices) . ')';
        }

        $excludedAppsString = '';

        $first = TRUE;
        foreach( $excludedAddresses as &$e )
        {
            if( !$first )
                $excludedAppsString .= ' and ';

            $excludedAppsString .= "(app neq $e)";
            $first = FALSE;
        }

        $query = "<type>"
            . "<" . $type . "><aggregate-by><member>" . $srcORdst . "</member></aggregate-by>"
            . "</" . $type . "></type><period>" . $timePeriod . "</period>"
            . "<topn>{$limit}</topn><topm>50</topm><caption>untitled</caption>"
            . "<query>" . "$dvq {$excludedAppsString} and (rule eq '" . $this->name . "')</query>";


        $apiArgs = array();
        $apiArgs['type'] = 'report';
        $apiArgs['reporttype'] = 'dynamic';
        $apiArgs['reportname'] = 'custom-dynamic-report';
        $apiArgs['async'] = 'yes';
        $apiArgs['cmd'] = $query;

        $ret = $con->getReport($apiArgs);

        return $ret;
    }

    public function cleanForDestruction()
    {
        $this->from->__destruct();
        $this->to->__destruct();
        $this->source->__destruct();
        $this->destination->__destruct();
        $this->tags->__destruct();
        $this->apps->__destruct();
        $this->services->__destruct();

        $this->from = null;
        $this->to = null;
        $this->source = null;
        $this->destination = null;
        $this->tags = null;
        $this->services = null;
        $this->apps = null;

        $this->owner = null;
    }

    public function isSecurityRule()
    {
        return TRUE;
    }

    public function storeVariableName()
    {
        return "securityRules";
    }

    public function ruleNature()
    {
        return 'security';
    }

    /**
     * For developer use only
     *
     */
    protected function rewriteSDsri_XML()
    {
        if( $this->dsri )
        {
            $find_option = DH::findFirstElementOrCreate('option', $this->xmlroot);
            $this->xmlroot = $find_option;
            $find = DH::findFirstElementOrCreate('disable-server-response-inspection', $this->xmlroot);
            DH::setDomNodeText($find, 'yes');
        }
        else
        {
            $find_option = DH::findFirstElementOrCreate('option', $this->xmlroot);
            $this->xmlroot = $find_option;
            $find = DH::findFirstElementOrCreate('disable-server-response-inspection', $this->xmlroot);
            DH::setDomNodeText($find, 'no');
        }
    }

    /**
     * disable rule if $disabled = true, enable it if not
     * @param bool $disabled
     * @return bool true if value has changed
     */
    public function setDsri($dsri)
    {
        $old = $this->dsri;
        $this->dsri = $dsri;

        if( $dsri != $old )
        {
            $this->rewriteSDsri_XML();
            return TRUE;
        }

        return FALSE;
    }

    /**
     * disable rule if $dsri = true, enable it if not
     * @param bool $dsri
     * @return bool true if value has changed
     */
    public function API_setDsri($dsri)
    {
        $ret = $this->setDsri($dsri);

        if( $ret )
        {
            $xpath = $this->getXPath() . '/option/disable-server-response-inspection';
            $con = findConnectorOrDie($this);
            if( $this->dsri )
                $con->sendEditRequest($xpath, '<disable-server-response-inspection>yes</disable-server-response-inspection>');
            else
                $con->sendEditRequest($xpath, '<disable-server-response-inspection>no</disable-server-response-inspection>');
        }

        return $ret;
    }

    public function rewriteHipProfXML( )
    {
        if( $this->owner->version < 100 )
            $hipprofilevariable = 'hip-profiles';
        else
            $hipprofilevariable = 'source-hip';

        if( $this->hipprofroot !== null )
            DH::clearDomNodeChilds($this->hipprofroot);

        if( $this->hipprofroot === null || $this->hipprofroot === FALSE )
            $this->hipprofroot = DH::createElement($this->xmlroot, $hipprofilevariable);
        else
            $this->xmlroot->appendChild($this->hipprofroot);


        $tmp = $this->hipprofroot->ownerDocument->createElement('member');
        $tmp = $this->hipprofroot->appendChild($tmp);
        $tmp->appendChild($this->hipprofroot->ownerDocument->createTextNode($this->hipprofProfiles));
    }

    public function setHipProfile($hipProfile)
    {
        //TODO : implement better 'change' detection to remove this return true
        $this->hipprofProfiles = $hipProfile;

        $this->rewriteHipProfXML();

        return TRUE;
    }

    public function API_setHipProfil($hipProfile)
    {
        $ret = $this->setHipProfile($hipProfile);

        if( $this->owner->version < 100 )
            $hipprofilevariable = 'hip-profiles';
        else
            $hipprofilevariable = 'source-hip';

        if( $ret )
        {
            $xpath = $this->getXPath() . '/'.$hipprofilevariable;
            $con = findConnectorOrDie($this);

            $con->sendEditRequest($xpath, '<'.$hipprofilevariable.'><member>' . $hipProfile . '</member></'.$hipprofilevariable.'>');
        }

        return $ret;
    }

    /**
     * return schedule txt if rule has scheduler set
     * @return null
     */
    public function schedule()
    {
        return $this->schedule;
    }

    /**
     * @param null|string $newSchedule empty or null description will erase existing one
     * @return bool false if no update was made to description (already had same value)
     */
    function setSchedule($newSchedule = null)
    {
        if( is_object( $newSchedule ) )
            $newSchedule = $newSchedule->name();

        if( $newSchedule === null || strlen($newSchedule) < 1 )
        {
            if( $this->schedule === null )
                return FALSE;

            if( is_object($this->schedule) )
                $this->schedule->removeReference($this);

            $this->schedule = null;
            $tmpRoot = DH::findFirstElement('schedule', $this->xmlroot);

            if( $tmpRoot === FALSE )
                return TRUE;

            $this->xmlroot->removeChild($tmpRoot);


        }
        else
        {
            $newSchedule = utf8_encode($newSchedule);
            if( is_object( $this->schedule ) && $this->schedule->name() == $newSchedule )
                return FALSE;

            if( is_object($this->schedule) )
                $this->schedule->removeReference($this);

            $f = $this->owner->owner->scheduleStore->findOrCreate($newSchedule, $this);
            if( $f != null )
                $f->addReference( $this );

            $this->schedule = $f;

            #$this->schedule = $newSchedule;
            $tmpRoot = DH::findFirstElementOrCreate('schedule', $this->xmlroot);
            DH::setDomNodeText($tmpRoot, $this->schedule->name());
        }

        return TRUE;
    }

    /**
     * @return bool true if value was changed
     */
    public function API_setSchedule($newSchedule)
    {
        $ret = $this->setSchedule($newSchedule);
        if( $ret )
        {
            $xpath = $this->getXPath() . '/schedule';
            $con = findConnectorOrDie($this);

            if( !is_object( $this->schedule )  )
                $con->sendDeleteRequest($xpath);
            else
                $con->sendSetRequest($this->getXPath(), '<schedule>' . htmlspecialchars($this->schedule->name()) . '</schedule>');

        }

        return $ret;
    }

    /**
     * @return bool false if no update was made to description (already had same value)
     */
    function removeSchedule()
    {
        if( $this->schedule === null )
            return TRUE;

        $this->schedule = null;
        $tmpRoot = DH::findFirstElement('schedule', $this->xmlroot);

        if( $tmpRoot === FALSE )
            return TRUE;

        $this->xmlroot->removeChild($tmpRoot);


        return TRUE;
    }

    /**
     * @param string $newSchedule
     * @return bool true if value was changed
     */
    public function API_removeSchedule()
    {
        $ret = $this->removeSchedule();
        if( $ret )
        {
            $xpath = $this->getXPath() . '/schedule';
            $con = findConnectorOrDie($this);

            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }


    /**
     * @param null|string $newSchedule empty or null description will erase existing one
     * @return bool false if no update was made to description (already had same value)
     */
    function setQoSMarking($arg1 = null, $arg2 = null)
    {
        //ip-dscp;ip-precedence;follow-c2s-flow
        //1- af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,cs0-cs7,ef
        //2- cs0 - cs7
        //3 - ""

        //validation:
        $tmp_qos_marking = array();
        $tmp_qos_marking['ip-dscp'] = array('af11' => 'af11', 'af12' => 'af12', 'af13' => 'af13', 'af21' => 'af21', 'af22' => 'af22', 'af23' => 'af23',
            'af31' => 'af31', 'af32' => 'af32', 'af33' => 'af33', 'af41' => 'af41', 'af42' => 'af42', 'af43' => 'af43',
            'cs0' => 'cs0', 'cs1' => 'cs1', 'cs2' => 'cs2', 'cs3' => 'cs3', 'cs4' => 'cs4', 'cs5' => 'cs5', 'cs6' => 'cs6', 'cs7' => 'cs7', 'ef' => 'ef');
        $tmp_qos_marking['ip-precedence'] = array('cs0' => 'cs0', 'cs1' => 'cs1', 'cs2' => 'cs2', 'cs3' => 'cs3', 'cs4' => 'cs4', 'cs5' => 'cs5', 'cs6' => 'cs6', 'cs7' => 'cs7');
        $tmp_qos_marking['follow-c2s-flow'] = array();

        if( !isset($tmp_qos_marking[$arg1]) )
            derr("qosmarking: " . $arg1 . " not allowed in PAN-OS. possible values for arg1: 'ip-dscp', 'ip-precedence', 'follow-c2s-flow'");
        else
        {
            if( $arg1 == "follow-c2s-flow" )
            {
                if( $arg2 != "" )
                    derr("qosmarking: " . $arg1 . " with " . $arg2 . " not allowed in PAN-OS; 'arg2' must be not set!");
            }

            if( !isset($tmp_qos_marking[$arg1][$arg2]) )
            {
                print_r($tmp_qos_marking[$arg1]);
                derr("qosmarking: " . $arg1 . " with " . $arg2 . " not allowed in PAN-OS");
            }

        }


        if( $arg1 === null || $arg2 === null || strlen($arg1) < 1 || strlen($arg2) < 1 )
        {
            if( empty($this->qosMarking) )
                return FALSE;

            $this->qosMarking = array();
            $tmpRoot = DH::findFirstElement('qos', $this->xmlroot);

            if( $tmpRoot === FALSE )
                return TRUE;

            $this->xmlroot->removeChild($tmpRoot);
        }
        else
        {

            if( $this->qosMarking == array($arg1 => $arg2) )
                return FALSE;
            $this->qosMarking = array($arg1 => $arg2);

            $tmpRoot = DH::findFirstElementOrCreate('qos', $this->xmlroot);
            $tmpRoot = DH::findFirstElementOrCreate('marking', $tmpRoot);
            $tmpRoot = DH::findFirstElementOrCreate($arg1, $tmpRoot);
            DH::setDomNodeText($tmpRoot, $arg2);
        }

        return TRUE;
    }

    /**
     * @return bool true if value was changed
     */
    public function API_setQoSMarking($arg1, $arg2)
    {
        $ret = $this->setQoSMarking($arg1, $arg2);
        if( $ret )
        {
            $xpath = $this->getXPath() . '/qos';
            $con = findConnectorOrDie($this);

            if( empty($this->qosMarking) )
                $con->sendDeleteRequest($xpath);
            else
                $con->sendSetRequest($this->getXPath(), '<qos><marking><' . $arg1 . '>' . $arg2 . '</' . $arg1 . '></marking></qos>');

        }

        return $ret;
    }

    /**
     * @return bool false if no update was made to description (already had same value)
     */
    function removeQoSmarking()
    {
        #if($this->schedule === null )
        #    return true;

        $this->qosMarking = array();
        $tmpRoot = DH::findFirstElement('qos', $this->xmlroot);

        if( $tmpRoot === FALSE )
            return TRUE;

        $this->xmlroot->removeChild($tmpRoot);


        return TRUE;
    }

    /**
     * @return bool true if value was changed
     */
    public function API_removeQoSmarking()
    {
        $ret = $this->removeQoSmarking();
        if( $ret )
        {
            $xpath = $this->getXPath() . '/qos';
            $con = findConnectorOrDie($this);

            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    /**
     * @param SecurityRule $rule
     * @return bool false also if service partial match!!!
     */
    function includedInRule( $rule,  $action = 'none', $isAPI = false, $print = false )
    {
        if( !$rule->isSecurityRule() )
            return false;


        $SRC_B = $this->source;
        $DST_B = $this->destination;
        $SVC_B = $this->services;

        $SRC_A = $rule->source;
        $DST_A = $rule->destination;
        $SVC_A = $rule->services;



        if( $SRC_A->getIP4Mapping()->includesOtherMap( $SRC_B->getIP4Mapping()) == 0 )
        {
            if( $print )
                PH::print_stdout( "Source not matching");
            return false;
        }
        elseif( $SRC_A->getIP4Mapping()->includesOtherMap( $SRC_B->getIP4Mapping()) == 2 )
        {
            if( $print )
                PH::print_stdout( "Source partial matching");
            if( $action == "remove" )
            {
                $result = $SRC_A->getMembersDiff( $SRC_B);
                foreach( $result['minus'] as $plus )
                {
                    if( $print )
                        PH::print_stdout( "remove SRC: ".$plus->name() );
                    if( $isAPI )
                        $this->source->API_remove( $plus );
                    else
                        $this->source->remove( $plus );

                    if( $this->source->isAny() )
                        return false;
                }
            }
        }


        if( $DST_A->getIP4Mapping()->includesOtherMap( $DST_B->getIP4Mapping()) == 0 )
        {
            if( $print )
                PH::print_stdout( "Destination not matching");
            return false;
        }
        elseif( $DST_A->getIP4Mapping()->includesOtherMap( $DST_B->getIP4Mapping()) == 2 )
        {
            if( $print )
                PH::print_stdout( "Destination partial matching");
            if( $action == "remove" )
            {
                $result = $DST_A->getMembersDiff( $DST_B);
                foreach( $result['minus'] as $plus )
                {
                    if( $print )
                        PH::print_stdout( "remove DST: " . $plus->name() );
                    if( $isAPI )
                        $this->destination->API_remove($plus);
                    else
                        $this->destination->remove($plus, true, true );

                    if( $this->destination->isAny() )
                        return false;
                }
            }
        }


        //Todo - not explicit what I tried to implement but usable; work like addrresscontainer

        if( !$rule->services->isAny() ){

            $result = $SVC_A->getMembersDiff( $SVC_B);


            foreach( $result['minus'] as $plus )
            {
                if( $print )
                    PH::print_stdout( "remove service: " . $plus->name() );
                $this->services->remove($plus, TRUE, TRUE);

                if( $this->services->isAny() )
                {
                    if( $print )
                        PH::print_stdout( "Service not");
                    return FALSE;
                }
            }
        }





        if( !$SVC_A->includesContainer( $SVC_B) )
        {
            if( $print )
                PH::print_stdout( "Service not");
            return false;
        }

        return true;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"><option><disable-server-response-inspection>no</disable-server-response-inspection></option><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>any</member>
</service><hip-profiles><member>any</member></hip-profiles><action>allow</action><log-start>no</log-start><log-end>yes</log-end><negate-source>no</negate-source><negate-destination>no</negate-destination><tag/><description/><disabled>no</disabled></entry>';

    static public $templatexml100 = '<entry name="**temporarynamechangeme**"><option><disable-server-response-inspection>no</disable-server-response-inspection></option><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>any</member>
</service><source-hip><member>any</member></source-hip><destination-hip><member>any</member></destination-hip><action>allow</action><log-start>no</log-start><log-end>yes</log-end><negate-source>no</negate-source><negate-destination>no</negate-destination><tag/><description/><disabled>no</disabled></entry>';
}


