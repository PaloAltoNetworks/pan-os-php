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


class DefaultSecurityRule extends Rule
{
    use RulewithLogging;

    protected $action = self::ActionAllow;

    protected $logstart = FALSE;
    protected $logend = TRUE;

    protected $secproftype = 'none';

    /** @var null|string[]|DOMElement */
    public $secprofroot = null;
    protected $secprofgroup = null;
    protected $secprofgroup_obj = null;

    protected $secprofProfiles = array();
    protected $secprofProfiles_obj = array();

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

    public $urlCategories;
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


        #$this->load_source();
        #$this->load_destination();
        #$this->load_from();
        #$this->load_to();


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
                    mwarning("unsupported action '{$node->textContent}' found, allow assumed", $node);
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
            else
            {
                if( strpos( $this->name(), "intrazone"  ) !== FALSE )
                    $this->ruleType = self::TypeIntrazone;
                elseif( strpos( $this->name(), "interzone"  ) !== FALSE )
                    $this->ruleType = self::TypeInterzone;
            }
        }
        // End of <rule-type>
    }


    /**
     * @return string type of this rule : 'universal', 'intrazone', 'interzone'
     */
    public function type()
    {
        return self::$RuleTypes[$this->ruleType];
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
            derr('Cannot be called on a rule that is of security profile type = "' . $this->secproftype.'"');

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

            if( $con->isAPI() )
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

            if( $con->isAPI() )
                $con->sendEditRequest($xpath, '<profile-setting><group><member>' . $newgroup . '</member></group></profile-setting>');
        }

        return $ret;
    }


    public function setSecProf_AV($newAVprof)
    {
        $this->secproftype = 'profile';
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
        $this->secproftype = 'profile';
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
        $this->secproftype = 'profile';
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
        $this->secproftype = 'profile';
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
        $this->secproftype = 'profile';
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
        $this->secproftype = 'profile';
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
        $this->secproftype = 'profile';
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

        if( $this->secprofroot !== null && $this->secprofroot !== false )
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
        else if( $this->secproftype == 'profile' )
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
        elseif( $this->secproftype == 'none' )
        {
            $this->secprofroot = DH::findFirstElement( 'profile-setting', $this->xmlroot);
            if( $this->secprofroot !== FALSE )
                $this->xmlroot->removeChild( $this->secprofroot );
        }

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
        if( $con->isAPI() )
            $connector->sendSetRequest($this->getXPath(), '<action>'.$domNode->textContent.'</action>');
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
        if( $con->isAPI() )
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
        if( $con->isAPI() )
            $con->sendSetRequest($this->getXPath(), "<log-start>" . boolYesNo($yes) . "</log-start>");

        return TRUE;
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
        /*
        if( $this->sourceIsNegated() )
        {
            $sourceNegated = '*negated*';
            PH::$JSON_TMP['sub']['object'][$this->name()]['sourcenegated'] = "true";
        }
        else
            */
            PH::$JSON_TMP['sub']['object'][$this->name()]['sourcenegated'] = "false";


        $destinationNegated = '';
        /*
        if( $this->destinationIsNegated() )
        {
            $destinationNegated = '*negated*';
            PH::$JSON_TMP['sub']['object'][$this->name()]['destinationnegated'] = "true";
        }
        else
        */
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

        /*
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
        */

        PH::print_stdout( $padding . "  Tags:  " . $this->tags->toString_inline() );
        foreach( $this->tags->getAll() as $tag )
            PH::$JSON_TMP['sub']['object'][$this->name()]['tag'][] = $tag->name();

        /*
        if( $this->_targets !== null )
        {
            PH::print_stdout( $padding . "  Targets:  " . $this->targets_toString() );
            foreach( $this->targets() as $target )
                PH::$JSON_TMP['sub']['object'][$this->name()]['target'][] = $target;
        }
        */


        if( $this->_description !==null && strlen($this->_description) > 0 )
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

        /*
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
        */

        PH::print_stdout();
    }


    public function isDefaultSecurityRule()
    {
        return TRUE;
    }

    public function storeVariableName()
    {
        return "defaultRules";
    }

    public function ruleNature()
    {
        return 'defaultSecurity';
    }


    static public $templatexml = '<entry name="**temporarynamechangeme**"><action>allow</action><log-start>no</log-start><log-end>yes</log-end><tag/><description/></entry>';

    static public $templatexml100 = '<entry name="**temporarynamechangeme**"><action>allow</action><log-start>no</log-start><log-end>yes</log-end><tag/><description/></entry>';
}


