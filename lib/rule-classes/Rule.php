<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class Rule
{

    use PathableName;
    use centralServiceStoreUser;
    use centralAddressStoreUser;
    use ObjectWithDescription;
    use XmlConvertible;

    protected $name = 'temporaryname';
    protected $disabled = FALSE;

    /**
     * @var ZoneRuleContainer
     */
    public $from = null;
    /**
     * @var ZoneRuleContainer
     */
    public $to = null;
    /**
     * @var AddressRuleContainer
     */
    public $source;
    /**
     * @var AddressRuleContainer
     */
    public $destination;

    /**
     * @var TagRuleContainer
     */
    public $tags;

    /**
     * @var ServiceRuleContainer
     */
    public $services;

    /**
     * @var RuleStore
     */
    public $owner = null;

    /** @var null|string[][] */
    protected $_targets = null;

    protected $_targetIsNegated = FALSE;


    private $uuid;

    /**
     * Returns name of this rule
     * @return string
     */
    public function name()
    {
        return $this->name;
    }

    /**
     * Returns uuid of this rule
     * @return string
     */
    public function uuid()
    {
        return $this->uuid;
    }

    /**
     *
     * @return bool
     */
    public function isDisabled()
    {
        return $this->disabled;
    }

    /**
     *
     * @return bool
     */
    public function isEnabled()
    {
        if( $this->disabled )
            return FALSE;

        return TRUE;
    }

    /**
     * For developer use only
     */
    protected function load_from()
    {
        $tmp = DH::findFirstElementOrCreate('from', $this->xmlroot);
        $this->from->load_from_domxml($tmp);
    }


    /**
     * For developer use only
     */
    protected function load_to()
    {
        $tmp = DH::findFirstElementOrCreate('to', $this->xmlroot);
        $this->to->load_from_domxml($tmp);
    }


    /**
     * For developer use only
     */
    protected function load_source()
    {
        $tmp = DH::findFirstElementOrCreate('source', $this->xmlroot);
        $this->source->load_from_domxml($tmp);
    }

    /**
     * For developer use only
     */
    protected function load_destination()
    {
        $tmp = DH::findFirstElementOrCreate('destination', $this->xmlroot);
        $this->destination->load_from_domxml($tmp);
    }

    /**
     * For developer use only
     *
     */
    protected function load_common_from_domxml()
    {
        if( $this->owner->owner->version >= 90 )
        {
            $this->uuid = DH::findAttribute('uuid', $this->xmlroot);
        }

        foreach( $this->xmlroot->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;


            if( $node->nodeName == 'disabled' )
            {
                $lstate = strtolower($node->textContent);
                if( $lstate == 'yes' )
                {
                    $this->disabled = TRUE;
                }
            }
            else if( $node->nodeName == 'tag' )
            {
                $this->tags->load_from_domxml($node);
            }
            else if( $node->nodeName == 'description' )
            {
                $this->_description = $node->textContent;
            }
            else if( $node->nodeName == 'target' )
            {
                $targetNegateNode = DH::findFirstElement('negate', $node);
                if( $targetNegateNode !== FALSE )
                {
                    $this->_targetIsNegated = yesNoBool($targetNegateNode->textContent);
                }

                $targetDevicesNodes = DH::findFirstElement('devices', $node);

                if( $targetDevicesNodes !== FALSE )
                {
                    foreach( $targetDevicesNodes->childNodes as $targetDevicesNode )
                    {
                        if( $targetDevicesNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        /**  @var DOMElement $targetDevicesNode */

                        $targetSerial = $targetDevicesNode->getAttribute('name');
                        if( strlen($targetSerial) < 1 )
                        {
                            mwarning('a target with empty serial number was found', $targetDevicesNodes);
                            continue;
                        }

                        if( $this->_targets === null )
                            $this->_targets = array();

                        $vsysNodes = DH::firstChildElement($targetDevicesNode);

                        if( $vsysNodes === FALSE )
                        {
                            $this->_targets[$targetSerial] = array();
                            //mwarning($targetSerial, $targetDevicesNode);
                        }
                        else
                        {
                            foreach( $vsysNodes->childNodes as $vsysNode )
                            {
                                if( $vsysNode->nodeType != XML_ELEMENT_NODE )
                                    continue;
                                /**  @var DOMElement $vsysNode */
                                $vsysName = $vsysNode->getAttribute('name');
                                if( strlen($vsysName) < 1 )
                                    continue;

                                $this->_targets[$targetSerial][$vsysName] = $vsysName;
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @return bool TRUE if an update was made
     */
    public function target_setAny()
    {
        if( $this->_targets === null )
            return FALSE;

        $this->_targets = null;

        $node = DH::findFirstElement('target', $this->xmlroot);
        if( $node !== FALSE )
        {
            $deviceNode = DH::findFirstElement('devices', $node);
            if( $deviceNode !== FALSE )
                $node->removeChild($deviceNode);
        }

        return TRUE;
    }

    /**
     * @return bool TRUE if an update was made
     */
    public function API_target_setAny()
    {
        $ret = $this->target_setAny();

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $con->sendDeleteRequest($this->getXPath() . '/target/devices');
        }

        return $ret;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function target_addDevice($serialNumber, $vsys = null)
    {
        if( strlen($serialNumber) < 4 )
            derr("unsupported serial number to be added in target: '{$serialNumber}'");

        if( $vsys !== null && strlen($vsys) < 1 )
            derr("unsupported vsys value to be added in target : '{$vsys}'");

        if( $this->_targets === null )
            $this->_targets = array();

        if( !isset($this->_targets[$serialNumber]) )
        {
            $this->_targets[$serialNumber] = array();
            if( $vsys !== null )
                $this->_targets[$serialNumber][$vsys] = $vsys;

            $this->target_rewriteXML();
            return TRUE;
        }

        if( count($this->_targets[$serialNumber]) == 0 )
        {
            if( $vsys === null )
                return FALSE;

            derr("attempt to add a VSYS ({$vsys}) in target of a rule that is mentioning a firewall ({$serialNumber}) that is not multi-vsys");
        }

        if( $vsys === null )
            derr("attempt to add a non multi-vsys firewall ({$serialNumber}) in a target that is multi-vsys");

        $this->_targets[$serialNumber][$vsys] = $vsys;
        $this->target_rewriteXML();

        return TRUE;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function API_target_addDevice($serialNumber, $vsys)
    {
        $ret = $this->target_addDevice($serialNumber, $vsys);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $targetNode = DH::findFirstElementOrDie('target', $this->xmlroot);
            $targetString = DH::dom_to_xml($targetNode);
            $con->sendEditRequest($this->getXPath() . '/target', $targetString);
        }

        return $ret;
    }


    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function target_removeDevice($serialNumber, $vsys = null)
    {
        if( strlen($serialNumber) < 4 )
            derr("unsupported serial number to be added in target: '{$serialNumber}'");

        if( $vsys !== null && strlen($vsys) < 1 )
            derr("unsupported vsys value to be added in target : '{$vsys}'");

        if( $this->_targets === null )
            return FALSE;

        if( !isset($this->_targets[$serialNumber]) )
            return FALSE;

        if( count($this->_targets[$serialNumber]) == 0 )
        {
            if( $vsys === null )
            {
                unset($this->_targets[$serialNumber]);
                if( count($this->_targets) == 0 )
                    $this->_targets = null;
                $this->target_rewriteXML();
                return TRUE;
            }

            derr("attempt to remove a VSYS ({$vsys}) in target of a rule that is mentioning a firewall ({$serialNumber}) which is not multi-vsys");
        }

        if( $vsys === null )
            derr("attempt to remove a non multi-vsys firewall ({$serialNumber}) in a target that is multi-vsys");

        if( !isset($this->_targets[$serialNumber][$vsys]) )
            return FALSE;

        unset($this->_targets[$serialNumber][$vsys]);

        if( count($this->_targets[$serialNumber]) == 0 )
            unset($this->_targets[$serialNumber]);

        $this->target_rewriteXML();

        return TRUE;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function API_target_removeDevice($serialNumber, $vsys)
    {
        $ret = $this->target_removeDevice($serialNumber, $vsys);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $targetNode = DH::findFirstElementOrDie('target', $this->xmlroot);
            $targetString = DH::dom_to_xml($targetNode);
            $con->sendEditRequest($this->getXPath() . '/target', $targetString);
        }

        return $ret;
    }


    public function target_rewriteXML()
    {
        $targetNode = DH::findFirstElementOrCreate('target', $this->xmlroot);

        DH::clearDomNodeChilds($targetNode);
        DH::createElement($targetNode, 'negate', boolYesNo($this->_targetIsNegated));

        if( $this->_targets === null )
            return;

        $devicesNode = DH::createElement($targetNode, 'devices');

        foreach( $this->_targets as $serial => &$vsysList )
        {
            $entryNode = DH::createElement($devicesNode, 'entry');
            $entryNode->setAttribute('name', $serial);
            if( count($vsysList) > 0 )
            {
                $vsysNode = DH::createElement($entryNode, 'vsys');
                foreach( $vsysList as $vsys )
                {
                    $vsysEntryNode = DH::createElement($vsysNode, 'entry');
                    $vsysEntryNode->setAttribute('name', $vsys);
                }
            }
        }
    }

    /**
     * @return bool TRUE if an update was made
     * @var bool $TRUEorFALSE
     */
    public function target_negateSet($TRUEorFALSE)
    {
        if( $this->_targetIsNegated === $TRUEorFALSE )
            return FALSE;

        $this->_targetIsNegated = $TRUEorFALSE;

        $node = DH::findFirstElementOrCreate('target', $this->xmlroot);
        DH::findFirstElementOrCreate('negate', $node, boolYesNo($TRUEorFALSE));

        return TRUE;
    }

    public function target_isNegated()
    {
        return $this->_targetIsNegated;
    }

    /**
     * @return bool TRUE if an update was made
     * @var bool $TRUEorFALSE
     */
    public function API_target_negateSet($TRUEorFALSE)
    {
        $ret = $this->target_negateSet($TRUEorFALSE);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($this->getXPath() . '/target', '<negate>' . boolYesNo($TRUEorFALSE) . '</negate>');
        }

        return $ret;
    }


    public function targets()
    {
        return $this->_targets;
    }

    public function targets_toString()
    {
        if( !isset($this->_targets) )
            return 'any';

        $str = '';

        foreach( $this->_targets as $device => $vsyslist )
        {
            if( strlen($str) > 0 )
                $str .= ',';

            if( count($vsyslist) == 0 )
                $str .= $device;
            else
            {
                $first = TRUE;
                foreach( $vsyslist as $vsys )
                {
                    if( !$first )
                        $str .= ',';
                    $first = FALSE;
                    $str .= $device . '/' . $vsys;
                }
            }

        }

        return $str;
    }

    public function target_isAny()
    {
        return $this->_targets === null;
    }

    /**
     * @param string $deviceSerial
     * @param string|null $vsys
     * @return bool
     */
    public function target_hasDeviceAndVsys($deviceSerial, $vsys = null)
    {
        if( $this->_targets === null )
            return FALSE;

        if( !isset($this->_targets[$deviceSerial]) )
            return FALSE;

        if( count($this->_targets[$deviceSerial]) == 0 && $vsys === null )
            return TRUE;

        if( $vsys === null )
            return FALSE;

        return isset($this->_targets[$deviceSerial][$vsys]);
    }


    /**
     * For developer use only
     *
     */
    protected function rewriteSDisabled_XML()
    {
        if( $this->disabled )
        {
            $find = DH::findFirstElementOrCreate('disabled', $this->xmlroot);
            DH::setDomNodeText($find, 'yes');
        }
        else
        {
            $find = DH::findFirstElementOrCreate('disabled', $this->xmlroot);
            DH::setDomNodeText($find, 'no');
        }
    }

    /**
     * disable rule if $disabled = true, enable it if not
     * @param bool $disabled
     * @return bool true if value has changed
     */
    public function setDisabled($disabled)
    {
        $old = $this->disabled;
        $this->disabled = $disabled;

        if( $disabled != $old )
        {
            $this->rewriteSDisabled_XML();
            return TRUE;
        }

        return FALSE;
    }

    /**
     * disable rule if $disabled = true, enable it if not
     * @param bool $disabled
     * @return bool true if value has changed
     */
    public function API_setDisabled($disabled)
    {
        $ret = $this->setDisabled($disabled);

        if( $ret )
        {
            $xpath = $this->getXPath() . '/disabled';
            $con = findConnectorOrDie($this);
            if( $this->disabled )
                $con->sendEditRequest($xpath, '<disabled>yes</disabled>');
            else
                $con->sendEditRequest($xpath, '<disabled>no</disabled>');
        }

        return $ret;
    }

    public function setEnabled($enabled)
    {
        if( $enabled )
            return $this->setDisabled(FALSE);
        else
            return $this->setDisabled(TRUE);
    }

    public function API_setEnabled($enabled)
    {
        if( $enabled )
            return $this->API_setDisabled(FALSE);
        else
            return $this->API_setDisabled(TRUE);
    }


    public function &getXPath()
    {
        $str = $this->owner->getXPath($this) . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setName($name)
    {

        if( $this->name == $name )
            return TRUE;

        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this, $oldname);
            }
            else
                return FALSE;
        }

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return TRUE;

    }

    /**
     * @param string $newname
     */
    public function API_setName($newname)
    {
        $con = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $con->sendRenameRequest($xpath, $newname);

        $this->setName($newname);
    }

    public function API_clearPolicyAppUsageDATA()
    {
        $con = findConnectorOrDie($this);

        if( $con->info_PANOS_version_int >= 90 )
        {
            $cmd = '<clear><policy-app-usage-data><ruleuuid>' . $this->uuid() . '</ruleuuid></policy-app-usage-data></clear>';
            $res = $con->sendOpRequest($cmd, TRUE);
            ///api/?type=op&cmd=<clear><policy-app-usage-data><ruleuuid></ruleuuid></policy-app-usage-data></clear>
        }
        else
        {
            print "  PAN-OS version must be 9.0 or higher";
        }

        return null;
    }


    function zoneCalculation($fromOrTo, $mode = "append", $virtualRouter = "*autodetermine*", $template_name = "*notPanorama*", $vsys_name = "*notPanorama*")
    {
        //DEFAULT settings:
        $mode_default = "append";
        $virtualRouter_default = "*autodetermine*";
        $template_default = "*notPanorama*";
        $vsys_default = "*notPanorama*";


        $padding = '     ';
        $cachedIPmapping = array();

        //check how the get information if e.g. connector is available
        $isAPI = FALSE;


        ////////////////////////
        /// plain starting calculation

        $addrContainerIsNegated = FALSE;

        $zoneContainer = null;
        $addressContainer = null;

        if( $fromOrTo == 'from' )
        {
            $zoneContainer = $this->from;
            $addressContainer = $this->source;
            if( $this->isSecurityRule() && $this->sourceIsNegated() )
                $addrContainerIsNegated = TRUE;
        }
        elseif( $fromOrTo == 'to' )
        {
            $zoneContainer = $this->to;
            $addressContainer = $this->destination;
            if( $this->isSecurityRule() && $this->destinationIsNegated() )
                $addrContainerIsNegated = TRUE;
        }
        else
            derr('unsupported');

        //Workaround
        $zoneContainer->findParentCentralStore();
        $zoneStore = $zoneContainer->parentCentralStore;


        $system = $this->owner->owner;

        /** @var VirtualRouter $virtualRouterToProcess */
        $virtualRouterToProcess = null;

        if( !isset($cachedIPmapping) )
            $cachedIPmapping = array();

        $serial = spl_object_hash($this->owner);
        $configIsOnLocalFirewall = FALSE;

        if( !isset($cachedIPmapping[$serial]) )
        {
            if( $system->isDeviceGroup() || $system->isPanorama() )
            {
                $firewall = null;
                $panorama = $system;
                if( $system->isDeviceGroup() )
                    $panorama = $system->owner;

                if( $template_name == $template_default )
                    derr('with Panorama configs, you need to specify a template name');

                if( $virtualRouter == $virtualRouter_default )
                    derr('with Panorama configs, you need to specify virtualRouter argument. Available virtual routes are: ');

                $_tmp_explTemplateName = explode('@', $template_name);
                if( count($_tmp_explTemplateName) > 1 )
                {
                    $firewall = new PANConf();
                    $configIsOnLocalFirewall = TRUE;
                    $doc = null;

                    if( strtolower($_tmp_explTemplateName[0]) == 'api' )
                    {
                        $panoramaConnector = findConnector($system);
                        $connector = new PanAPIConnector($panoramaConnector->apihost, $panoramaConnector->apikey, 'panos-via-panorama', $_tmp_explTemplateName[1]);
                        $firewall->connector = $connector;
                        $doc = $connector->getMergedConfig();
                        $firewall->load_from_domxml($doc);
                        unset($connector);
                    }
                    elseif( strtolower($_tmp_explTemplateName[0]) == 'file' )
                    {
                        $filename = $_tmp_explTemplateName[1];
                        if( !file_exists($filename) )
                            derr("cannot read firewall configuration file '{$filename}''");
                        $doc = new DOMDocument();
                        if( !$doc->load($filename, XML_PARSE_BIG_LINES) )
                            derr("invalive xml file" . libxml_get_last_error()->message);
                        unset($filename);
                    }
                    else
                        derr("unsupported method: {$_tmp_explTemplateName[0]}@");


                    // delete rules to avoid loading all the config
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/devices/entry/vsys/entry/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/shared/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");

                    //print "\n\n deleted $deletedNodesCount nodes \n\n";

                    $firewall->load_from_domxml($doc);

                    unset($deletedNodesCount);
                    unset($doc);
                }


                /** @var Template $template */
                if( !$configIsOnLocalFirewall )
                {
                    $template = $panorama->findTemplate($template_name);
                    if( $template === null )
                        derr("cannot find Template named '{$template_name}'. Available template list:" . PH::list_to_string($panorama->templates));
                }

                if( $configIsOnLocalFirewall )
                    $virtualRouterToProcess = $firewall->network->virtualRouterStore->findVirtualRouter($virtualRouter);
                else
                    $virtualRouterToProcess = $template->deviceConfiguration->network->virtualRouterStore->findVirtualRouter($virtualRouter);

                if( $virtualRouterToProcess === null )
                {
                    if( $configIsOnLocalFirewall )
                        $tmpVar = $firewall->network->virtualRouterStore->virtualRouters();
                    else
                        $tmpVar = $template->deviceConfiguration->network->virtualRouterStore->virtualRouters();

                    derr("cannot find VirtualRouter named '{$virtualRouter}' in Template '{$template_name}'. Available VR list: " . PH::list_to_string($tmpVar));
                }

                if( (!$configIsOnLocalFirewall && count($template->deviceConfiguration->virtualSystems) == 1) || ($configIsOnLocalFirewall && count($firewall->virtualSystems) == 1) )
                {
                    if( $configIsOnLocalFirewall )
                        $system = $firewall->virtualSystems[0];
                    else
                        $system = $template->deviceConfiguration->virtualSystems[0];
                }
                else
                {
                    $vsysConcernedByVR = $virtualRouterToProcess->findConcernedVsys();
                    if( count($vsysConcernedByVR) == 1 )
                    {
                        $system = array_pop($vsysConcernedByVR);
                    }
                    elseif( $vsys_name == '*autodetermine*' )
                    {
                        derr("cannot autodetermine resolution context from Template '{$template}' VR '{$virtualRouter}'' , multiple VSYS are available: " . PH::list_to_string($vsysConcernedByVR) . ". Please provide choose a VSYS.");
                    }
                    else
                    {
                        if( $configIsOnLocalFirewall )
                            $vsys = $firewall->findVirtualSystem($vsys_name);
                        else
                            $vsys = $template->deviceConfiguration->findVirtualSystem($vsys_name);
                        if( $vsys === null )
                            derr("cannot find VSYS '{$vsys_name}' in Template '{$template_name}'");
                        $system = $vsys;
                    }
                }

                //derr(DH::dom_to_xml($template->deviceConfiguration->xmlroot));
                //$tmpVar = $system->importedInterfaces->interfaces();
                //derr(count($tmpVar)." ".PH::list_to_string($tmpVar));
            }
            else if( $virtualRouter != '*autodetermine*' )
            {
                $virtualRouterToProcess = $system->owner->network->virtualRouterStore->findVirtualRouter($virtualRouter);
                if( $virtualRouterToProcess === null )
                    derr("VirtualRouter named '{$virtualRouter}' not found");
            }
            else
            {
                $vRouters = $system->owner->network->virtualRouterStore->virtualRouters();
                $foundRouters = array();

                foreach( $vRouters as $router )
                {
                    foreach( $router->attachedInterfaces->interfaces() as $if )
                    {
                        if( $system->importedInterfaces->hasInterfaceNamed($if->name()) )
                        {
                            $foundRouters[] = $router;
                            break;
                        }
                    }
                }

                print $padding . " - VSYS/DG '{$system->name()}' has interfaces attached to " . count($foundRouters) . " virtual routers\n";
                if( count($foundRouters) > 1 )
                    derr("more than 1 suitable virtual routers found, please specify one fo the following: " . PH::list_to_string($foundRouters));
                if( count($foundRouters) == 0 )
                    derr("no suitable VirtualRouter found, please force one or check your configuration");

                $virtualRouterToProcess = $foundRouters[0];
            }
            $cachedIPmapping[$serial] = $virtualRouterToProcess->getIPtoZoneRouteMapping($system);
        }


        $ipMapping = &$cachedIPmapping[$serial];

        if( $addressContainer->isAny() && $this->isSecurityRule() )
        {
            print $padding . " - SKIPPED : address container is ANY()\n";
            return;
        }

        if( $this->isSecurityRule() )
            $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4'], $addrContainerIsNegated);
        else
            $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4']);

        if( count($resolvedZones) == 0 )
        {
            print $padding . " - WARNING : no zone resolved (FQDN? IPv6?)\n";
            return;
        }


        $plus = array();
        foreach( $zoneContainer->zones() as $zone )
            $plus[$zone->name()] = $zone->name();

        $minus = array();
        $common = array();

        foreach( $resolvedZones as $zoneName => $zone )
        {
            if( isset($plus[$zoneName]) )
            {
                unset($plus[$zoneName]);
                $common[] = $zoneName;
                continue;
            }
            $minus[] = $zoneName;
        }

        if( count($common) > 0 )
            print $padding . " - untouched zones: " . PH::list_to_string($common) . "\n";
        if( count($minus) > 0 )
            print $padding . " - missing zones: " . PH::list_to_string($minus) . "\n";
        if( count($plus) > 0 )
            print $padding . " - unneeded zones: " . PH::list_to_string($plus) . "\n";

        if( $mode == 'replace' )
        {
            print $padding . " - REPLACE MODE, syncing with (" . count($resolvedZones) . ") resolved zones.";
            if( $addressContainer->isAny() )
                echo $padding . " *** IGNORED because value is 'ANY' ***\n";
            elseif( count($resolvedZones) == 0 )
                echo $padding . " *** IGNORED because no zone was resolved ***\n";
            elseif( count($minus) == 0 && count($plus) == 0 )
            {
                echo $padding . " *** IGNORED because there is no diff ***\n";
            }
            else
            {
                print "\n";

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    if( count($common) > 0 )
                    {
                        foreach( $minus as $zoneToAdd )
                        {
                            $newRuleName = $this->owner->findAvailableName($this->name());
                            $newRule = $this->owner->cloneRule($this, $newRuleName);
                            $newRule->to->setAny();
                            $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                            echo $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'\n";
                            if( $isAPI )
                            {
                                $newRule->API_sync();
                                $newRule->owner->API_moveRuleAfter($newRule, $this);
                            }
                            else
                                $newRule->owner->moveRuleAfter($newRule, $this);
                        }
                        return;
                    }

                    $first = TRUE;
                    foreach( $minus as $zoneToAdd )
                    {
                        if( $first )
                        {
                            $this->to->setAny();
                            $this->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                            echo $padding . " - changed original NAT 'TO' zone='{$zoneToAdd}'\n";
                            if( $isAPI )
                                $this->to->API_sync();
                            $first = FALSE;
                            continue;
                        }
                        $newRuleName = $this->owner->findAvailableName($this->name());
                        $newRule = $this->owner->cloneRule($this, $newRuleName);
                        $newRule->to->setAny();
                        $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                        echo $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'\n";
                        if( $isAPI )
                        {
                            $newRule->API_sync();
                            $newRule->owner->API_moveRuleAfter($newRule, $this);
                        }
                        else
                            $newRule->owner->moveRuleAfter($newRule, $this);
                    }

                    return;
                }

                $zoneContainer->setAny();
                foreach( $resolvedZones as $zone )
                    $zoneContainer->addZone($zoneStore->findOrCreate($zone));
                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
        elseif( $mode == 'append' )
        {
            print $padding . " - APPEND MODE: adding missing (" . count($minus) . ") zones only.";

            if( $addressContainer->isAny() )
            {
                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    foreach( $zoneStore->getAll() as $zone )
                        $allZones[] = $zone->name();

                    self::zoneCalculationNatClone( $allZones, $zoneStore, $padding, $isAPI );
                }
                else
                    print " *** IGNORED because value is 'ANY' ***\n";
            }
            elseif( count($minus) == 0 )
                print " *** IGNORED because no missing zones were found ***\n";
            else
            {
                print "\n";

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    self::zoneCalculationNatClone( $minus, $zoneStore, $padding, $isAPI );

                    return;
                }

                foreach( $minus as $zone )
                {
                    $zoneContainer->addZone($zoneStore->findOrCreate($zone));
                }

                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
        elseif( $mode == 'unneeded-tag-add' )
        {
            print $padding . " - UNNEEDED-TAG-ADD MODE: adding rule tag for unneeded zones.";

            if( $addressContainer->isAny() )
                print " *** IGNORED because value is 'ANY' ***\n";
            elseif( count($plus) == 0 )
                print " *** IGNORED because no unneeded zones were found ***\n";
            else
            {
                print "\n";

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    derr($padding . ' NAT rules are not supported yet');
                }

                if( $fromOrTo == 'from' )
                    $tag_add = 'unneeded-from-zone';
                elseif( $fromOrTo == 'to' )
                    $tag_add = 'unneeded-to-zone';

                $objectFind = $this->tags->parentCentralStore->findOrCreate($tag_add);
                $this->tags->addTag($objectFind);

                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
    }

    public function zoneCalculationNatClone( $zoneArray, $zoneStore, $padding, $isAPI )
    {
        foreach( $zoneArray as $zoneToAdd )
        {
            $newRuleName = $this->owner->findAvailableName($this->name());
            $newRule = $this->owner->cloneRule($this, $newRuleName);
            $newRule->to->setAny();

            $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
            echo $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'\n";
            if( $isAPI )
            {
                $newRule->API_sync();
                $newRule->owner->API_moveRuleAfter($newRule, $this);
            }
            else
                $newRule->owner->moveRuleAfter($newRule, $this);
        }

        if( $this->to->isAny() )
        {
            print " remove origin NAT rule as TO zone ANY is not allowed\n";
            $this->owner->remove( $this );
        }
    }

    public function isPreRule()
    {
        return $this->owner->ruleIsPreRule($this);
    }

    public function isPostRule()
    {
        return $this->owner->ruleIsPostRule($this);
    }


    public function isSecurityRule()
    {
        return FALSE;
    }

    public function isNatRule()
    {
        return FALSE;
    }

    public function isDecryptionRule()
    {
        return FALSE;
    }

    public function isAppOverrideRule()
    {
        return FALSE;
    }

    public function isCaptivePortalRule()
    {
        return FALSE;
    }

    public function isAuthenticationRule()
    {
        return FALSE;
    }

    public function isPbfRule()
    {
        return FALSE;
    }

    public function isQoSRule()
    {
        return FALSE;
    }

    public function isDoSRule()
    {
        return FALSE;
    }

    public function ruleNature()
    {
        return 'unknown';
    }

}




