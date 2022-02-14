<?php
/**
 * ISC License
 *
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

class XMLISSUE extends UTIL
{
    public $region_array = array();



    //Todo: optimisation needed to use class UTIL available parent methods

    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=api://[MGMT-IP-Address] ";


        #$this->prepareSupportedArgumentsArray();


        PH::processCliArgs();
        $this->help(PH::$args);
        $this->init_arguments();
        $this->load_config();


        $this->main();


        $this->save_our_work( true );


        $this->endOfScript();
    }

    public function main()
    {


///////////////////////////////////////////////////////////
//clean stage config / delete all <deleted> entries
        $xpath = new DOMXpath($this->xmlDoc);

// example 1: for everything with an id
        $elements = $xpath->query("//deleted");


        foreach( $elements as $element )
        {
            $element->parentNode->removeChild($element);
        }
///////////////////////////////////////////////////////////

//REGION objects

        $filename = dirname(__FILE__) . '/../../lib/object-classes/predefined.xml';

        $xmlDoc_region = new DOMDocument();
        $xmlDoc_region->load($filename, XML_PARSE_BIG_LINES);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/region', $xmlDoc_region);
        foreach( $cursor->childNodes as $region_entry )
        {
            if( $region_entry->nodeType != XML_ELEMENT_NODE )
                continue;

            $region_name = DH::findAttribute('name', $region_entry);
            #PH::print_stdout( $region_name );
            $this->region_array[$region_name] = $region_entry;
        }


///////////////////////////////////////////////////////////




//
// REAL JOB STARTS HERE
//
//


        $totalAddressGroupsFixed = 0;
        $totalServiceGroupsFixed = 0;


        $totalAddressGroupsSubGroupFixed = 0;
        $totalServiceGroupsSubGroupFixed = 0;

        $countDuplicateAddressObjects = 0;
        $countDuplicateServiceObjects = 0;

        $countDuplicateSecRuleObjects = 0;
        $countDuplicateNATRuleObjects = 0;

        $countSecRuleObjectsWithDoubleSpaces = 0;
        $countNATRuleObjectsWithDoubleSpaces = 0;

        $countMissconfiguredSecRuleServiceObjects=0;
        $countMissconfiguredSecRuleApplicationObjects=0;

        $countMissconfiguredSecRuleSourceObjects=0;
        $countMissconfiguredSecRuleDestinationObjects=0;

        $countMissconfiguredSecRuleCategoryObjects=0;

        $countMissconfiguredAddressObjects = 0;
        $countMissconfiguredAddressRegionObjects = 0;
        $countAddressObjectsWithDoubleSpaces = 0;

        $countMissconfiguredServiceObjects = 0;
        $countServiceObjectsWithDoubleSpaces = 0;


        $countEmptyAddressGroup = 0;
        $countEmptyServiceGroup = 0;

        $service_app_default_available = false;
        $countMissconfiguredSecRuleServiceAppDefaultObjects = 0;

        $countRulesWithAppDefault = 0;

        $address_region = array();
        $address_name = array();



        /** @var DOMElement[] $locationNodes */
        $locationNodes = array();
        $tmp_shared_node = DH::findXPathSingleEntry('/config/shared', $this->xmlDoc);
        if( $tmp_shared_node !== false )
            $locationNodes['shared'] = $tmp_shared_node;

        if( $this->configType == 'panos' )
            $tmpNodes = DH::findXPath('/config/devices/entry/vsys/entry', $this->xmlDoc);
        elseif( $this->configType == 'panorama' )
            $tmpNodes = DH::findXPath('/config/devices/entry/device-group/entry', $this->xmlDoc);
        elseif( $this->configType == 'fawkes' )
        {
            $search_array = array( '/config/devices/entry/container/entry','/config/devices/entry/device/cloud/entry' );
            $tmpNodes = DH::findXPath($search_array, $this->xmlDoc);

        }

        foreach( $tmpNodes as $node )
            $locationNodes[$node->getAttribute('name')] = $node;

        PH::print_stdout( " - Found " . count($locationNodes) . " locations (VSYS/DG/Container/DeviceCloud)");
        foreach( $locationNodes as $key => $tmpNode )
            PH::print_stdout( "   - ".$key);

        PH::print_stdout( "*******   ********   ********");

        foreach( $locationNodes as $locationName => $locationNode )
        {
            PH::print_stdout( "** PARSING VSYS/DG/Container/DeviceCloud '{$locationName}' **");

            $addressObjects = array();
            $addressGroups = array();
            $addressIndex = array();
            $addressRegion = array();

            $serviceObjects = array();
            $serviceGroups = array();
            $serviceIndex = array();



            $secRules = array();
            $secRuleIndex = array();
            $natRules = array();
            $natRuleIndex = array();
            $secRuleServiceIndex = array();
            $secRuleApplicationIndex = array();

            $zoneObjects = array();
            $zoneIndex = array();

            $address_region = array();
            $address_name = array();
            $service_name = array();
            $secrule_name = array();
            $natrule_name = array();

            $objectTypeNode = DH::findFirstElement('address', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_region( $objectName, $objectNode, $address_region );
                    $this->check_name( $objectName, $objectNode, $address_name );

                    $addressObjects[$objectName][] = $objectNode;

                    if( !isset($addressIndex[$objectName]) )
                        $addressIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $addressIndex[$objectName]['regular'][] = $objectNode;
                }

            }

            $objectTypeNode = DH::findFirstElement('address-group', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_region( $objectName, $objectNode, $address_region );
                    $this->check_name( $objectName, $objectNode, $address_name );

                    $addressGroups[$objectName][] = $objectNode;

                    if( !isset($addressIndex[$objectName]) )
                        $addressIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $addressIndex[$objectName]['group'][] = $objectNode;
                }
            }


            PH::print_stdout( "");
            PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
            PH::print_stdout( " - parsed " . count($addressObjects) . " address objects and " . count($addressGroups) . " groups");
            PH::print_stdout( "");

            //
            //
            //
            PH::print_stdout( " - Scanning for address / addressgroup with same name as REGION objects...");
            foreach( $address_region as $objectName => $node )
            {
                PH::print_stdout( "    - address object '{$objectName}' from DG/VSYS {$locationName} has lower precedence as REGION object ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $countMissconfiguredAddressRegionObjects++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address / addressgroup with double spaces in name...");
            foreach( $address_name as $objectName => $node )
            {
                PH::print_stdout( "    - address object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $countAddressObjectsWithDoubleSpaces++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address with missing IP-netmask/IP-range/FQDN information...");
            foreach( $addressObjects as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $ip_netmaskNode = DH::findFirstElement('ip-netmask', $node);
                    $ip_rangeNode = DH::findFirstElement('ip-range', $node);
                    $fqdnNode = DH::findFirstElement('fqdn', $node);
                    $ip_wildcardNode = DH::findFirstElement('ip-wildcard', $node);
                    if( $ip_netmaskNode === FALSE && $ip_rangeNode === FALSE && $fqdnNode === FALSE && $ip_wildcardNode === FALSE )
                    {
                        PH::print_stdout( "    - address object '{$objectName}' from DG/VSYS {$locationName} has missing IP configuration ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'Address' at XML line #{$node->getLineNo()}");
                        $countMissconfiguredAddressObjects++;
                    }
                }
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address groups with empty members...");
            foreach( $addressGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('static', $node);
                    $dynamicNode = DH::findFirstElement('dynamic', $node);
                    if( $staticNode === FALSE && $dynamicNode === FALSE )
                    {
                        PH::print_stdout( "    - addressgroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'AddressGroup' at XML line #{$node->getLineNo()}");
                        $countEmptyAddressGroup++;
                    }
                }
            }


            //
            //
            //
            PH::print_stdout( " - Scanning for address groups with duplicate members...");
            foreach( $addressGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('static', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( isset($membersIndex[$memberName]) )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*");
                            $nodesToRemove[] = $staticNodeMember;
                            $totalAddressGroupsFixed++;
                            continue;
                        }

                        $membersIndex[$memberName] = TRUE;
                    }

                    foreach( $nodesToRemove as $nodeToRemove )
                        $nodeToRemove->parentNode->removeChild($nodeToRemove);
                }
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address groups with own membership as subgroup...");
            foreach( $addressGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('static', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( $objectName == $memberName )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*");
                            $staticNodeMember->parentNode->removeChild($staticNodeMember);
                            $totalAddressGroupsSubGroupFixed++;
                            continue;
                        }
                    }
                }
            }


            //
            //
            //
            PH::print_stdout( " - Scanning for duplicate address objects...");
            foreach( $addressIndex as $objectName => $objectNodes )
            {
                $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                if( $dupCount < 2 )
                    continue;

                PH::print_stdout( "   - found address object named '{$objectName}' that exists " . $dupCount . " time (*FIX_MANUALLY*):");

                $tmp_addr_array = array();
                foreach( $objectNodes['regular'] as $objectNode )
                {
                    $ip_netmaskNode = DH::findFirstElement('ip-netmask', $objectNode);
                    $ip_fqdnNode = DH::findFirstElement('fqdn', $objectNode);
                    if( $ip_netmaskNode !== FALSE )
                    {
                        /** @var DOMElement $objectNode */
                        $text = "       - type 'Address' value: '" . $ip_netmaskNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                        //Todo: check if address object value is same, then delete it
                        //TODO: VALIDATION needed if working as expected

                        if( !isset($tmp_addr_array[$ip_netmaskNode->nodeValue]) )
                            $tmp_addr_array[$ip_netmaskNode->nodeValue] = $ip_netmaskNode->nodeValue;
                        else
                        {
                            $objectNode->parentNode->removeChild($objectNode);
                            $text .= PH::boldText(" (removed)");
                            $countDuplicateAddressObjects--;
                        }

                        PH::print_stdout( $text );

                        $countDuplicateAddressObjects++;
                    }
                    elseif( $ip_fqdnNode !== FALSE )
                    {
                        /** @var DOMElement $objectNode */
                        PH::print_stdout( "       - type 'Address' value: '" . $ip_fqdnNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}");

                        $countDuplicateAddressObjects++;
                    }
                    else
                        continue;

                }

                $tmp_srv_array = array();
                foreach( $objectNodes['group'] as $objectNode )
                {
                    #print_r($objectNodes['group']);
                    $protocolNode = DH::findFirstElement('static', $objectNode);
                    if( $protocolNode === FALSE )
                        continue;

                    $txt = "";
                    foreach( $protocolNode->childNodes as $member )
                    {
                        /** @var DOMElement $objectNode */
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $txt .= $member->nodeValue;
                    }

                    /** @var DOMElement $objectNode */
                    $text = "       - type 'AddressGroup' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if servicegroup object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    if( !isset($tmp_srv_array[$txt]) )
                        $tmp_srv_array[$txt] = $txt;
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);
                        $text .= PH::boldText(" (removed)");
                        $countDuplicateAddressObjects--;
                    }
                    PH::print_stdout( $text);


                    $countDuplicateAddressObjects++;
                }
                #$countDuplicateAddressObjects--;
            }


            //
            //
            //
            //
            //
            //

            $objectTypeNode = DH::findFirstElement('service', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_name( $objectName, $objectNode, $service_name );

                    if( $objectName == "application-default" )
                        $service_app_default_available = true;

                    $serviceObjects[$objectName][] = $objectNode;

                    if( !isset($serviceIndex[$objectName]) )
                        $serviceIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $serviceIndex[$objectName]['regular'][] = $objectNode;
                }

            }

            $objectTypeNode = DH::findFirstElement('service-group', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_name( $objectName, $objectNode, $service_name );

                    $serviceGroups[$objectName][] = $objectNode;

                    if( !isset($serviceIndex[$objectName]) )
                        $serviceIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $serviceIndex[$objectName]['group'][] = $objectNode;
                }
            }

            PH::print_stdout( "");
            PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
            PH::print_stdout( " - parsed " . count($serviceObjects) . " service objects and " . count($serviceGroups) . " groups");
            PH::print_stdout( "");

            //
            //
            //
            PH::print_stdout( " - Scanning for service / servicegroup with double spaces in name...");
            foreach( $service_name as $objectName => $node )
            {
                PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $countServiceObjectsWithDoubleSpaces++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service with missing protocol information...");
            foreach( $serviceObjects as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $protocolNode = DH::findFirstElement('protocol', $node);
                    if( $protocolNode === FALSE )
                    {
                        PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has missing protocol configuration ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'Service' at XML line #{$node->getLineNo()}");
                        $countMissconfiguredServiceObjects++;
                    }
                }
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service groups with empty members...");
            foreach( $serviceGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                    {
                        PH::print_stdout( "    - servicegroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'ServiceGroup' at XML line #{$node->getLineNo()}");
                        $countEmptyServiceGroup++;
                    }
                }
            }

            PH::print_stdout( " - Scanning for service groups with duplicate members...");
            foreach( $serviceGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( isset($membersIndex[$memberName]) )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*");
                            $nodesToRemove[] = $staticNodeMember;
                            $totalServiceGroupsFixed++;
                            continue;
                        }

                        $membersIndex[$memberName] = TRUE;
                    }

                    foreach( $nodesToRemove as $nodeToRemove )
                        $nodeToRemove->parentNode->removeChild($nodeToRemove);
                }
            }


            //
            //
            //
            PH::print_stdout( " - Scanning for service groups with own membership as subgroup...");
            foreach( $serviceGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( $objectName == $memberName )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*");
                            $staticNodeMember->parentNode->removeChild($staticNodeMember);
                            $totalServiceGroupsSubGroupFixed++;
                            continue;
                        }
                    }
                }
            }


            PH::print_stdout( " - Scanning for duplicate service objects...");
            foreach( $serviceIndex as $objectName => $objectNodes )
            {
                $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                if( $dupCount < 2 )
                    continue;

                PH::print_stdout( "   - found service object named '{$objectName}' that exists " . $dupCount . " time (*FIX_MANUALLY*):");
                $tmp_srv_array = array();
                foreach( $objectNodes['regular'] as $objectNode )
                {
                    $protocolNode = DH::findFirstElement('protocol', $objectNode);
                    if( $protocolNode === FALSE )
                        continue;

                    /** @var DOMElement $objectNode */
                    $text = "       - type 'Service' value: '" . $protocolNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if service object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                        $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);
                        $text .= PH::boldText(" (removed)");
                        $countDuplicateServiceObjects--;
                    }
                    PH::print_stdout( $text);

                    $countDuplicateServiceObjects++;
                }

                $tmp_srv_array = array();
                foreach( $objectNodes['group'] as $objectNode )
                {
                    $protocolNode = DH::findFirstElement('members', $objectNode);
                    if( $protocolNode === FALSE )
                        continue;


                    /** @var DOMElement $objectNode */
                    $text = "       - type 'ServiceGroup' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if servicegroup object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                        $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);
                        $text .= PH::boldText(" (removed)");
                        $countDuplicateServiceObjects--;
                    }
                    PH::print_stdout( $text);

                    $countDuplicateServiceObjects++;
                }
                #$countDuplicateServiceObjects--;
            }

            //
            //
            //
            //
            //
            //
            $applicationGroups = array();
            $applicationIndex = array();
            $totalApplicationGroupsFixed = 0;
            $this->checkRemoveDuplicateMembers( $locationNode, $locationName, 'application-group', $applicationGroups, $applicationIndex, $totalApplicationGroupsFixed );

            //
            //
            $customURLcategory = array();
            $customURLcategoryIndex = array();
            $totalCustomUrlCategoryFixed = 0;
            $locationNode_profiles = DH::findFirstElement('profiles', $locationNode);
            if( $locationNode_profiles !== FALSE )
                $this->checkRemoveDuplicateMembers( $locationNode_profiles, $locationName, 'custom-url-category', $customURLcategory, $customURLcategoryIndex, $totalCustomUrlCategoryFixed );

            //
            //
            //
            //
            //
            //


            $objectTypeNode_array_rulebase['rulebase'] = DH::findFirstElement('rulebase', $locationNode);
            $objectTypeNode_array_rulebase['pre-rulebase'] = DH::findFirstElement('pre-rulebase', $locationNode);
            $objectTypeNode_array_rulebase['post-rulebase'] = DH::findFirstElement('post-rulebase', $locationNode);

            //Todo: missing part: pre-rulebase / post-rulebase
            foreach( $objectTypeNode_array_rulebase as $key => $objectTypeNode_rulebase )
            {
                $secRules = array();
                $secRuleIndex = array();
                $natRules = array();
                $natRuleIndex = array();
                $secRuleSourceIndex = array();
                $secRuleDestinationIndex = array();
                $secRuleServiceIndex = array();
                $secRuleApplicationIndex = array();
                $secRuleCategoryIndex = array();
                $secRuleServiceAppDefaultIndex = array();

                if( $objectTypeNode_rulebase !== FALSE )
                {
                    PH::print_stdout( "");
                    PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");

                    PH::print_stdout( "[".$key."]");

                    foreach( $objectTypeNode_rulebase->childNodes as $objectNode_ruletype )
                    {
                        if( $objectNode_ruletype->nodeName == "security" )
                        {
                            $objectTypeNode = DH::findFirstElement('rules', $objectNode_ruletype);
                            if( $objectTypeNode !== FALSE )
                            {
                                foreach( $objectTypeNode->childNodes as $objectNode )
                                {
                                    $secRuleServices = array();
                                    $secRuleApplication = array();
                                    $secRuleSource = array();
                                    $secRuleDestination = array();

                                    /** @var DOMElement $objectNode */
                                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $objectName = $objectNode->getAttribute('name');

                                    $this->check_name( $objectName, $objectNode, $secrule_name );

                                    $secRules[$objectName][] = $objectNode;

                                    if( !isset($secRuleIndex[$objectName]) )
                                        $secRuleIndex[$objectName] = array('regular' => array(), 'group' => array());

                                    $secRuleIndex[$objectName]['regular'][] = $objectNode;

                                    //Todo:
                                    //check if service has 'application-default' and additional
                                    $objectNode_services = DH::findFirstElement('service', $objectNode);
                                    $demo = iterator_to_array($objectNode_services->childNodes);
                                    foreach( $demo as $objectService )
                                    {
                                        /** @var DOMElement $objectService */
                                        if( $objectService->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectServiceName = $objectService->textContent;
                                        if( isset($secRuleServices[$objectServiceName]) )
                                        {
                                            //Secrule service has twice same service added
                                            $text = "     - Secrule: ".$objectName." has same service defined twice: ".$objectServiceName;
                                            $objectNode_services->removeChild($objectService);
                                            $text .= PH::boldText(" (removed)");
                                            PH::print_stdout( $text );
                                        }
                                        else
                                            $secRuleServices[$objectServiceName] = $objectService;
                                    }
                                    if( isset($secRuleServices['application-default'])  )
                                    {
                                        if( count($secRuleServices) > 1 )
                                        {
                                            $secRuleServiceIndex[$objectName] = $secRuleServices['application-default'];
                                            #PH::print_stdout( "     - Rule: '" . $objectName . "' has service application-default + something else defined.");
                                            #print_r($secRuleServices);
                                        }
                                        else
                                        {
                                            $secRuleServiceAppDefaultIndex[$objectName] = $secRuleServices['application-default'];
                                        }

                                    }


                                    //check if application has 'any' adn additional
                                    $objectNode_applications = DH::findFirstElement('application', $objectNode);
                                    $demo = iterator_to_array($objectNode_applications->childNodes);
                                    foreach( $demo as $objectApplication )
                                    {
                                        /** @var DOMElement $objectApplication */
                                        if( $objectApplication->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectApplicationName = $objectApplication->textContent;
                                        if( isset($secRuleApplication[$objectApplicationName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same application defined twice: ".$objectApplicationName;
                                            $objectNode_applications->removeChild($objectNode_applications);
                                            $text .=PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                        }
                                        else
                                            $secRuleApplication[$objectApplicationName] = $objectApplication;
                                    }
                                    if( isset($secRuleApplication['any']) and count($secRuleApplication) > 1 )
                                    {
                                        $secRuleApplicationIndex[$objectName] = $secRuleApplication['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.\n" ;
                                    }

                                    $objectNode_category = DH::findFirstElement('category', $objectNode);
                                    if( $objectNode_category && !$objectNode_category->hasChildNodes() )
                                        $secRuleCategoryIndex[$objectName] = $objectNode_category;

                                    //check if source has 'any' and additional
                                    $objectNode_sources = DH::findFirstElement('source', $objectNode);
                                    $demo = iterator_to_array($objectNode_sources->childNodes);
                                    foreach( $demo as $objectSource )
                                    {
                                        /** @var DOMElement $objectSource */
                                        if( $objectSource->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectSourceName = $objectSource->textContent;
                                        if( isset($secRuleSource[$objectSourceName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same source defined twice: ".$objectSourceName;
                                            $objectNode_sources->removeChild($objectSource);
                                            $text .=PH::boldText(" (removed)");
                                            PH::print_stdout( $text );
                                            $countMissconfiguredSecRuleSourceObjects++;
                                        }
                                        else
                                        {
                                            $secRuleSource[$objectSourceName] = $objectSource;
                                            #PH::print_stdout( $objectName.'add to array: '.$objectSourceName );
                                        }

                                    }
                                    if( isset($secRuleSource['any']) and count($secRuleSource) > 1 )
                                    {
                                        $secRuleSourceIndex[$objectName] = $secRuleSource['any'];
                                        PH::print_stdout( "     - Rule: '".$objectName."' has source 'any' + something else defined." );
                                    }

                                    //check if destination has 'any' and additional
                                    $objectNode_destinations = DH::findFirstElement('destination', $objectNode);
                                    $demo = iterator_to_array($objectNode_destinations->childNodes);
                                    foreach( $demo as $objectDestination )
                                    {
                                        /** @var DOMElement $objectDestination */
                                        if( $objectDestination->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectDestinationName = $objectDestination->textContent;
                                        #PH::print_stdout( "rule: ".$objectName." name: ".$objectDestinationName);
                                        if( isset($secRuleDestination[$objectDestinationName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same destination defined twice: ".$objectDestinationName;
                                            $objectNode_destinations->removeChild($objectDestination);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $countMissconfiguredSecRuleDestinationObjects++;
                                        }
                                        else
                                            $secRuleDestination[$objectDestinationName] = $objectDestination;
                                    }
                                    #if( $objectName === "FW RULE-00.06" )
                                    #derr('end');
                                    if( isset($secRuleDestination['any']) and count($secRuleDestination) > 1 )
                                    {
                                        $secRuleDestinationIndex[$objectName] = $secRuleDestination['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.") ;
                                    }
                                }

                            }

                            PH::print_stdout( " - parsed " . count($secRules) . " Security Rules");
                            PH::print_stdout( "");
                        }

                        elseif( $objectNode_ruletype->nodeName == "nat" )
                        {

                            $objectTypeNode = DH::findFirstElement('rules', $objectNode_ruletype);
                            if( $objectTypeNode !== FALSE )
                            {
                                foreach( $objectTypeNode->childNodes as $objectNode )
                                {
                                    /** @var DOMElement $objectNode */
                                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $objectName = $objectNode->getAttribute('name');


                                    $natRules[$objectName][] = $objectNode;

                                    if( !isset($natRuleIndex[$objectName]) )
                                        $natRuleIndex[$objectName] = array('regular' => array(), 'group' => array());

                                    $natRuleIndex[$objectName]['regular'][] = $objectNode;
                                }

                            }


                            PH::print_stdout( " - parsed " . count($natRules) . " NAT Rules");
                            PH::print_stdout( "");
                        }

                    }

                    //
                    //
                    //
                    PH::print_stdout( " - Scanning for Security Rules with double spaces in name...");
                    foreach( $secrule_name as $objectName => $node )
                    {
                        PH::print_stdout( "    - Security Rules object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                        $countSecRuleObjectsWithDoubleSpaces++;
                    }

                    PH::print_stdout( " - Scanning for duplicate Security Rules...");
                    foreach( $secRuleIndex as $objectName => $objectNodes )
                    {
                        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                        if( $dupCount < 2 )
                            continue;

                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that exists " . $dupCount . " time:");

                        $tmp_secrule_array = array();
                        foreach( $objectNodes['regular'] as $objectNode )
                        {

                            /** @var DOMElement $objectNode */
                            $text = "       - type 'Security Rules' at XML line #{$objectNode->getLineNo()}";

                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($secRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text .= PH::boldText(" - new name: " . $newName . " (fixed)");
                                PH::print_stdout( $text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                PH::print_stdout( $text );
                            }


                            $countDuplicateSecRuleObjects++;
                        }
                    }

                    //
                    //
                    //
                    PH::print_stdout( " - Scanning for NAT Rules with double spaces in name...");
                    foreach( $natrule_name as $objectName => $node )
                    {
                        PH::print_stdout( "    - NAT Rules object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                        $countNATRuleObjectsWithDoubleSpaces++;
                    }

                    PH::print_stdout( "\n - Scanning for duplicate NAT Rules...");
                    foreach( $natRuleIndex as $objectName => $objectNodes )
                    {
                        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                        if( $dupCount < 2 )
                            continue;

                        PH::print_stdout( "   - found NAT Rule named '{$objectName}' that exists " . $dupCount . " time:");
                        $tmp_natrule_array = array();
                        foreach( $objectNodes['regular'] as $key => $objectNode )
                        {

                            /** @var DOMElement $objectNode */
                            $text = "       - type 'NAT Rules' at XML line #{$objectNode->getLineNo()}";


                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($natRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text .= PH::boldText(" - new name: " . $newName . " (fixed)\n");
                                PH::print_stdout( $text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                PH::print_stdout( $text );
                            }


                            $countDuplicateNATRuleObjects++;
                        }
                    }

                    PH::print_stdout( "\n - Scanning for missconfigured Source Field in Security Rules...");
                    foreach( $secRuleSourceIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleSourceObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Destination Field in Security Rules...");
                    foreach( $secRuleDestinationIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleDestinationObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Service Field in Security Rules...");
                    foreach( $secRuleServiceIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has service 'application-default' and an additional service configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleServiceObjects++;
                    }


                    PH::print_stdout( " - Scanning for missconfigured Application Field in Security Rules...");
                    foreach( $secRuleApplicationIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has application 'any' and additional application configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleApplicationObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Category Field in Security Rules...");
                    foreach( $secRuleCategoryIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has XML element 'category' but not child element 'member' configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleCategoryObjects++;
                    }

                    if( $service_app_default_available )
                    {
                        PH::print_stdout( " - Scanning for Security Rules with 'application-default' set | service object 'application-default' is available ...");
                        foreach( $secRuleServiceAppDefaultIndex as $objectName => $objectNode )
                        {
                            PH::print_stdout( "   - found Security Rule named '{$objectName}' that is using SERVICE OBJECT at XML line #{$objectNode->getLineNo()}");
                            $countMissconfiguredSecRuleServiceAppDefaultObjects++;
                        }
                    }
                }
            }


            ///config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='mn053-mnr-int']/address-group
            ///
            ///
            PH::print_stdout( " - Scanning for /config/readonly/devices/entry[@name='localhost.localdomain']/device-group/ for duplicate address-group ...");
            $tmpReadOnly = DH::findXPath("/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$locationName."']", $this->xmlDoc);
            $readOnly = array();

            foreach( $tmpReadOnly as $node )
                $readOnly[] = $node;

            $readonlyDGAddressgroups = array();

            if( isset( $readOnly[0] ) )
            {
                $readonlyAddressgroups = DH::findFirstElement('address-group', $readOnly[0]);
                if( $readonlyAddressgroups !== false )
                    $demo = iterator_to_array($readonlyAddressgroups->childNodes);
                else
                    $demo = array();
            }
            else
                $demo = array();

            foreach( $demo as $objectAddressGroup )
            {
                /** @var DOMElement $objectApplication */
                if( $objectAddressGroup->nodeType != XML_ELEMENT_NODE )
                    continue;

                $objectAddressGroupName = $objectAddressGroup->getAttribute('name');
                if( isset($readonlyDGAddressgroups[$objectAddressGroupName]) )
                {
                    $text = "     - readOnly DG: ".$locationName." has same addressgroup defined twice: ".$objectAddressGroupName;
                    $readonlyAddressgroups->removeChild($objectAddressGroup);
                    $text .= PH::boldText(" (removed)");
                    PH::print_stdout($text);
                }
                else
                    $readonlyDGAddressgroups[$objectAddressGroupName] = $objectAddressGroup;
            }


            //
            //
            //
            //
            //
            //


            $objectTypeNode = DH::findFirstElement('zone', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $zoneObjects[$objectName][] = $objectNode;

                    if( !isset($zoneIndex[$objectName]) )
                        $zoneIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $zoneIndex[$objectName]['regular'][] = $objectNode;
                }

            }

            PH::print_stdout( "");
            PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
            PH::print_stdout( " - parsed " . count($zoneObjects) . " zone objects");
            PH::print_stdout( "");

            //
            //
            //
            PH::print_stdout( " - Scanning for zones with wrong zone type (e.g. Layer3 instead of layer3 - case sensitive - Expedition issue?)...");
            foreach( $zoneObjects as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $zone_network = DH::findFirstElement('network', $node);

                    foreach( $zone_network->childNodes as $key => $zone_type )
                    {
                        /** @var DOMElement $objectNode */
                        if( $zone_type->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $str = $zone_type->nodeName;

                        if( preg_match_all('/[A-Z][^A-Z]*/', $str, $results) )
                        {
                            if( isset($results[0][0]) )
                            {
                                PH::print_stdout( "       - type 'Zone' name: '" . $node->getAttribute('name') . "' - '" . $results[0][0] . "' at XML line #{$zone_type->getLineNo()} (*FIX_MANUALLY*)");
                            }
                        }
                    }
                }
            }

            PH::print_stdout( "** ** ** ** ** ** **");
        }

///
///
///
        PH::print_stdout( " - Scanning for /config/readonly/shared for duplicate address-group ...");
        $tmpReadOnly = DH::findXPath("/config/readonly/shared", $this->xmlDoc);
        $readOnly = array();

        foreach( $tmpReadOnly as $node )
            $readOnly[] = $node;

        $readonlyDGAddressgroups = array();

        if( isset( $readOnly[0] ) )
        {
            $readonlyAddressgroups = DH::findFirstElement('address-group', $readOnly[0]);
            if( $readonlyAddressgroups !== false )
                $demo = iterator_to_array($readonlyAddressgroups->childNodes);
            else
                $demo = array();
        }
        else
            $demo = array();

        foreach( $demo as $objectAddressGroup )
        {
            /** @var DOMElement $objectApplication */
            if( $objectAddressGroup->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectAddressGroupName = $objectAddressGroup->getAttribute('name');
            if( isset($readonlyDGAddressgroups[$objectAddressGroupName]) )
            {
                $text = "     - readOnly shared has same addressgroup defined twice: ".$objectAddressGroupName;
                $readonlyAddressgroups->removeChild($objectAddressGroup);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout($text);
            }
            else
                $readonlyDGAddressgroups[$objectAddressGroupName] = $objectAddressGroup;
        }

        ////////////////////////////////////////////////////////////
        ///config/readonly/devices/entry[@name='localhost.localdomain']/template

        PH::print_stdout( " - Scanning for config/readonly/devices/entry[@name='localhost.localdomain'] for duplicate template ...");
        $tmpReadOnly = DH::findXPath("/config/readonly/devices/entry[@name='localhost.localdomain']", $this->xmlDoc);
        $readOnly = array();

        foreach( $tmpReadOnly as $node )
            $readOnly[] = $node;

        $readonlyTemplatesArray = array();

        if( isset( $readOnly[0] ) )
        {
            $readonlyTemplates = DH::findFirstElement('template', $readOnly[0]);
            if( $readonlyTemplates !== false )
                $demo = iterator_to_array($readonlyTemplates->childNodes);
            else
                $demo = array();
        }
        else
            $demo = array();

        foreach( $demo as $objectTemplate )
        {
            /** @var DOMElement $objectTemplate */
            if( $objectTemplate->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectTemplateName = $objectTemplate->getAttribute('name');
            if( isset($readonlyTemplatesArray[$objectTemplateName]) )
            {
                $text = "     - readOnly /config/readonly/devices/entry[@name='localhost.localdomain']/template has same Template defined twice: ".$objectTemplateName;
                $readonlyTemplates->removeChild($objectTemplate);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout($text);
            }
            else
                $readonlyTemplatesArray[$objectTemplateName] = $objectTemplate;
        }



        ////////////////////////////////////////////////////////////

        PH::print_stdout( "");
        PH::print_stdout( "Summary:");
        PH::print_stdout( " - FIXED: duplicate address-group members: {$totalAddressGroupsFixed}");
        PH::print_stdout( " - FIXED: duplicate service-group members: {$totalServiceGroupsFixed}");
        PH::print_stdout( " - FIXED: own address-group as subgroup member: {$totalAddressGroupsSubGroupFixed}");
        PH::print_stdout( " - FIXED: own service-group as subgroup members: {$totalServiceGroupsSubGroupFixed}");

        PH::print_stdout( " - FIXED: duplicate application-group members: {$totalApplicationGroupsFixed}");

        PH::print_stdout( "\n\nIssues that could not be fixed (look in logs for FIX_MANUALLY keyword):");


        PH::print_stdout( " - FIX_MANUALLY: duplicate address objects: {$countDuplicateAddressObjects} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: duplicate service objects: {$countDuplicateServiceObjects} (look in the logs)");
        PH::print_stdout( "");

        PH::print_stdout( " - FIX_MANUALLY: missconfigured address objects: {$countMissconfiguredAddressObjects} (look in the logs)");
        PH::print_stdout( " - FIX_MANUALLY: address objects with double spaces in name: {$countAddressObjectsWithDoubleSpaces} (look in the logs)");
        PH::print_stdout( " - FIX_MANUALLY: address objects with same name as REGION: {$countMissconfiguredAddressRegionObjects} (look in the logs)");
        PH::print_stdout( " - FIX_MANUALLY: empty address-group: {$countEmptyAddressGroup} (look in the logs)");
        PH::print_stdout( "");

        PH::print_stdout( " - FIX_MANUALLY: missconfigured service objects: {$countMissconfiguredServiceObjects} (look in the logs)");
        PH::print_stdout( " - FIX_MANUALLY: service objects with double spaces in name: {$countServiceObjectsWithDoubleSpaces} (look in the logs)");
        PH::print_stdout( " - FIX_MANUALLY: empty service-group: {$countEmptyServiceGroup} (look in the logs)");
        PH::print_stdout( "");

        PH::print_stdout( " - FIX_MANUALLY: Security Rules with double spaces in name: {$countSecRuleObjectsWithDoubleSpaces} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: duplicate Security Rules: {$countDuplicateSecRuleObjects} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: NAT Rules with double spaces in name: {$countNATRuleObjectsWithDoubleSpaces} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: duplicate NAT Rules: {$countDuplicateNATRuleObjects} (look in the logs )");
        PH::print_stdout( "");

        PH::print_stdout( " - FIX_MANUALLY: missconfigured Source Field in Security Rules: {$countMissconfiguredSecRuleSourceObjects} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: missconfigured Destination Field in Security Rules: {$countMissconfiguredSecRuleDestinationObjects} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: missconfigured Service Field in Security Rules: {$countMissconfiguredSecRuleServiceObjects} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: missconfigured Application Field in Security Rules: {$countMissconfiguredSecRuleApplicationObjects} (look in the logs )");
        PH::print_stdout( " - FIX_MANUALLY: missconfigured Category Field in Security Rules: {$countMissconfiguredSecRuleCategoryObjects} (look in the logs )");
        PH::print_stdout( "");

        if( $service_app_default_available )
        {
            PH::print_stdout( " - FIX_MANUALLY: SERVICE OBJECT 'application-default' available and used in Security Rules: {$countMissconfiguredSecRuleServiceAppDefaultObjects} (look in the logs )");
            PH::print_stdout( "");
        }

        if( $this->configInput['type'] == 'api' )
            PH::print_stdout( "\n\nINPUT mode API detected: FIX is ONLY saved in offline file.");
    }

    public function supportedArguments()
    {

        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to answer, increase this value (default=60)');

    }

    function check_region( $name, $object, &$address_region )
    {
        if( strlen( $name ) == 2 && ctype_upper( $name ) )
        {
            if( array_key_exists( $name, $this->region_array ) )
            {
                $address_region[ $name ] = $object;
            }
        }
    }

    /**
     * @param $name string
     * @param $object DOMNode
     * @param $address_name array
     **/
    function check_name( $name, $object, &$address_name )
    {
        $needle = "  ";
        if( strpos( $name, $needle ) !== FALSE )
        {
            $address_name[ $name ] = $object;
        }
    }

    function checkRemoveDuplicateMembers( $locationNode, $locationName, $tagName, &$tagNameArray, &$tagNameIndex, &$totalTagNameFixed )
    {
        $objectTypeNode = DH::findFirstElement($tagName, $locationNode);
        if( $objectTypeNode !== FALSE )
        {
            foreach( $objectTypeNode->childNodes as $objectNode )
            {
                /** @var DOMElement $objectNode */
                if( $objectNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $objectName = $objectNode->getAttribute('name');

                $this->check_region( $objectName, $objectNode, $address_region );

                $tagNameArray[$objectName][] = $objectNode;

                if( !isset($tagNameIndex[$objectName]) )
                    $tagNameIndex[$objectName] = array('regular' => array(), 'group' => array());

                $tagNameIndex[$objectName]['group'][] = $objectNode;
            }
        }

        //
        //
        //

        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
        PH::print_stdout( " - parsed ". count($tagNameArray) . " ".$tagName );
        PH::print_stdout( "");
        PH::print_stdout( " - Scanning for ".$tagName." with duplicate members..." );

        foreach( $tagNameArray as $objectName => $nodes )
        {
            foreach( $nodes as $node )
            {

                //custom-url-catgegory
                $staticNode = DH::findFirstElement('list', $node);
                if( $staticNode === FALSE )
                {
                    //application-group and all other address-group/service-group
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                        continue;
                }

                $membersIndex = array();
                /** @var DOMElement[] $nodesToRemove */
                $nodesToRemove = array();

                $demo = iterator_to_array($staticNode->childNodes);
                foreach( $demo as $NodeMember )
                {
                    /** @var DOMElement $NodeMember */
                    if( $NodeMember->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $memberName = $NodeMember->textContent;

                    if( isset($membersIndex[$memberName]) )
                    {
                        PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*" );
                        $staticNode->removeChild($NodeMember);
                        $totalTagNameFixed++;
                        continue;
                    }

                    $membersIndex[$memberName] = TRUE;
                }
            }
        }
    }

}