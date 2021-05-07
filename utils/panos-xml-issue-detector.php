<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

print "\n*********** START OF SCRIPT " . basename(__FILE__) . " ************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
// load PAN-PHP-FRAMEWORK library
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

PH::processCliArgs();

$configInput = null;
$configOutput = null;


if( !isset(PH::$args['in']) )
    derr("missing 'in' argument");


if( isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if( !is_string($configOutput) || strlen($configOutput) < 1 )
        derr('"out" argument is not a valid string');
}
else
    derr('"out" is missing from arguments');

if( isset(PH::$args['debugapi']) )
    $debugAPI = TRUE;
else
    $debugAPI = FALSE;

$configInput = PH::processIOMethod(PH::$args['in'], TRUE);
if( $configInput['status'] == 'fail' )
    derr($configInput['msg']);


$apiMode = FALSE;

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc = new DOMDocument();
    if( !$xmlDoc->load($configInput['filename'], 4194304) )
        derr("error while reading xml config file");

}
elseif( $configInput['type'] == 'api' )
{
    $apiMode = TRUE;
    /** @var PanAPIConnector $connector */
    $connector = $configInput['connector'];
    if( $debugAPI )
        $connector->setShowApiCalls(TRUE);
    print " - Downloading config from API... ";
    $xmlDoc = $connector->getRunningConfig();
    print "OK!\n";
}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult = DH::findXPath('/config/devices/entry/vsys', $xmlDoc);
if( $xpathResult === FALSE )
    derr('XPath error happened');
if( $xpathResult->length < 1 )
    $configType = 'panorama';
else
    $configType = 'panos';
unset($xpathResult);

print " - Detected platform type is '{$configType}'\n";


///////////////////////////////////////////////////////////
//clean stage config / delete all <deleted> entries
$xpath = new DOMXpath($xmlDoc);

// example 1: for everything with an id
$elements = $xpath->query("//deleted");


foreach( $elements as $element )
{
    $element->parentNode->removeChild($element);
}
///////////////////////////////////////////////////////////

//REGION objects
$region_array = array();


$filename = dirname(__FILE__) . '/../lib/object-classes/predefined.xml';

$xmlDoc_region = new DOMDocument();
$xmlDoc_region->load($filename, XML_PARSE_BIG_LINES);

$cursor = DH::findXPathSingleEntryOrDie('/predefined/region', $xmlDoc_region);
foreach( $cursor->childNodes as $region_entry )
{
    if( $region_entry->nodeType != XML_ELEMENT_NODE )
        continue;

    $region_name = DH::findAttribute('name', $region_entry);
    #print $region_name."\n";
    $region_array[$region_name] = $region_entry;
}

function check_region( $name, $object, &$address_region )
{
    global $region_array;

    if( strlen( $name ) == 2 && ctype_upper( $name ) )
    {
        if( array_key_exists( $name, $region_array ) )
        {
            $address_region[ $name ] = $object;
        }
    }
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

$countMissconfiguredSecRuleServiceObjects=0;
$countMissconfiguredSecRuleApplicationObjects=0;

$countMissconfiguredSecRuleSourceObjects=0;
$countMissconfiguredSecRuleDestinationObjects=0;

$countMissconfiguredSecRuleCategoryObjects=0;

$countMissconfiguredAddressObjects = 0;
$countMissconfiguredAddressRegionObjects = 0;

$countMissconfiguredServiceObjects = 0;


$countEmptyAddressGroup = 0;
$countEmptyServiceGroup = 0;

$service_app_default_available = false;
$countMissconfiguredSecRuleServiceAppDefaultObjects = 0;

$countRulesWithAppDefault = 0;

$address_region = array();


/** @var DOMElement[] $locationNodes */
$locationNodes['shared'] = DH::findXPathSingleEntryOrDie('/config/shared', $xmlDoc);

if( $configType == 'panos' )
    $tmpNodes = DH::findXPath('/config/devices/entry/vsys/entry', $xmlDoc);
else
    $tmpNodes = DH::findXPath('/config/devices/entry/device-group/entry', $xmlDoc);


foreach( $tmpNodes as $node )
    $locationNodes[$node->getAttribute('name')] = $node;

print " - Found " . count($locationNodes) . " locations (VSYS/DG)\n";

print "\n *******   ********   ********\n\n";

foreach( $locationNodes as $locationName => $locationNode )
{
    print "\n** PARSING VSYS/DG '{$locationName}' **\n";

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


    $objectTypeNode = DH::findFirstElement('address', $locationNode);
    if( $objectTypeNode !== FALSE )
    {
        foreach( $objectTypeNode->childNodes as $objectNode )
        {
            /** @var DOMElement $objectNode */
            if( $objectNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectName = $objectNode->getAttribute('name');

            check_region( $objectName, $objectNode, $address_region );

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

            check_region( $objectName, $objectNode, $address_region );

            $addressGroups[$objectName][] = $objectNode;

            if( !isset($addressIndex[$objectName]) )
                $addressIndex[$objectName] = array('regular' => array(), 'group' => array());

            $addressIndex[$objectName]['group'][] = $objectNode;
        }
    }


    print "\n\n";
    print "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####\n";
    print " - parsed " . count($addressObjects) . " address objects and " . count($addressGroups) . " groups\n";
    print "\n";

    //
    //
    //
    print "\n - Scanning for address / addressgroup with same name as REGION objects...\n";
    foreach( $address_region as $objectName => $nodes )
    {
        echo "    - address object '{$objectName}' from DG/VSYS {$locationName} has lower precedence as REGION object ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}\n";
        $countMissconfiguredAddressRegionObjects++;
    }

    //
    //
    //
    print "\n - Scanning for address with missing IP-netmask/IP-range/FQDN information...\n";
    foreach( $addressObjects as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $ip_netmaskNode = DH::findFirstElement('ip-netmask', $node);
            $ip_rangeNode = DH::findFirstElement('ip-range', $node);
            $fqdnNode = DH::findFirstElement('fqdn', $node);
            if( $ip_netmaskNode === FALSE && $ip_rangeNode === FALSE && $fqdnNode === FALSE )
            {
                echo "    - address object '{$objectName}' from DG/VSYS {$locationName} has missing IP configuration ... (*FIX_MANUALLY*)\n";
                print "       - type 'Address' at XML line #{$node->getLineNo()}\n";
                $countMissconfiguredAddressObjects++;
            }
        }
    }

    //
    //
    //
    print "\n - Scanning for address groups with empty members...\n";
    foreach( $addressGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('static', $node);
            $dynamicNode = DH::findFirstElement('dynamic', $node);
            if( $staticNode === FALSE && $dynamicNode === FALSE )
            {
                echo "    - addressgroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)\n";
                print "       - type 'AddressGroup' at XML line #{$node->getLineNo()}\n";
                $countEmptyAddressGroup++;
            }
        }
    }


    //
    //
    //
    print "\n - Scanning for address groups with duplicate members...\n";
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
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*\n";
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
    print "\n - Scanning for address groups with own membership as subgroup...\n";
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
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*\n";
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
    print "\n - Scanning for duplicate address objects...\n";
    foreach( $addressIndex as $objectName => $objectNodes )
    {
        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

        if( $dupCount < 2 )
            continue;

        print "   - found address object named '{$objectName}' that exists " . $dupCount . " time (*FIX_MANUALLY*):\n";

        $tmp_addr_array = array();
        foreach( $objectNodes['regular'] as $objectNode )
        {
            $ip_netmaskNode = DH::findFirstElement('ip-netmask', $objectNode);
            $ip_fqdnNode = DH::findFirstElement('fqdn', $objectNode);
            if( $ip_netmaskNode !== FALSE )
            {
                /** @var DOMElement $objectNode */
                print "       - type 'Address' value: '" . $ip_netmaskNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                //Todo: check if address object value is same, then delete it
                //TODO: VALIDATION needed if working as expected

                if( !isset($tmp_addr_array[$ip_netmaskNode->nodeValue]) )
                    $tmp_addr_array[$ip_netmaskNode->nodeValue] = $ip_netmaskNode->nodeValue;
                else
                {
                    $objectNode->parentNode->removeChild($objectNode);
                    print PH::boldText(" (removed)");
                    $countDuplicateAddressObjects--;
                }

                print "\n";

                $countDuplicateAddressObjects++;
            }
            elseif( $ip_fqdnNode !== FALSE )
            {
                /** @var DOMElement $objectNode */
                print "       - type 'Address' value: '" . $ip_fqdnNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";
                print "\n";

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
            //print "|".$txt."|\n";

            /** @var DOMElement $objectNode */
            print "       - type 'AddressGroup' at XML line #{$objectNode->getLineNo()}";

            //Todo: check if servicegroup object value is same, then delete it
            //TODO: VALIDATION needed if working as expected

            if( !isset($tmp_srv_array[$txt]) )
                $tmp_srv_array[$txt] = $txt;
            else
            {
                $objectNode->parentNode->removeChild($objectNode);
                print PH::boldText(" (removed)");
                $countDuplicateAddressObjects--;
            }
            print "\n";


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


            $serviceGroups[$objectName][] = $objectNode;

            if( !isset($serviceIndex[$objectName]) )
                $serviceIndex[$objectName] = array('regular' => array(), 'group' => array());

            $serviceIndex[$objectName]['group'][] = $objectNode;
        }
    }

    print "\n\n";
    print "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####\n";
    print " - parsed " . count($serviceObjects) . " service objects and " . count($serviceGroups) . " groups\n";
    print "\n";

    //
    //
    //
    print "\n - Scanning for service with missing protocol information...\n";
    foreach( $serviceObjects as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $protocolNode = DH::findFirstElement('protocol', $node);
            if( $protocolNode === FALSE )
            {
                echo "    - service object '{$objectName}' from DG/VSYS {$locationName} has missing protocol configuration ... (*FIX_MANUALLY*)\n";
                print "       - type 'Service' at XML line #{$node->getLineNo()}\n";
                $countMissconfiguredServiceObjects++;
            }
        }
    }

    //
    //
    //
    print "\n - Scanning for service groups with empty members...\n";
    foreach( $serviceGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('members', $node);
            if( $staticNode === FALSE )
            {
                echo "    - servicegroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)\n";
                print "       - type 'ServiceGroup' at XML line #{$node->getLineNo()}\n";
                $countEmptyServiceGroup++;
            }
        }
    }

    print "\n - Scanning for service groups with duplicate members...\n";
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
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*\n";
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
    print "\n - Scanning for service groups with own membership as subgroup...\n";
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
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*\n";
                    $staticNodeMember->parentNode->removeChild($staticNodeMember);
                    $totalServiceGroupsSubGroupFixed++;
                    continue;
                }
            }
        }
    }


    print "\n - Scanning for duplicate service objects...\n";
    foreach( $serviceIndex as $objectName => $objectNodes )
    {
        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

        if( $dupCount < 2 )
            continue;

        print "   - found service object named '{$objectName}' that exists " . $dupCount . " time (*FIX_MANUALLY*):\n";
        $tmp_srv_array = array();
        foreach( $objectNodes['regular'] as $objectNode )
        {
            $protocolNode = DH::findFirstElement('protocol', $objectNode);
            if( $protocolNode === FALSE )
                continue;

            /** @var DOMElement $objectNode */
            print "       - type 'Service' value: '" . $protocolNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

            //Todo: check if service object value is same, then delete it
            //TODO: VALIDATION needed if working as expected

            if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
            else
            {
                $objectNode->parentNode->removeChild($objectNode);
                print PH::boldText(" (removed)");
                $countDuplicateServiceObjects--;
            }
            print "\n";

            $countDuplicateServiceObjects++;
        }

        $tmp_srv_array = array();
        foreach( $objectNodes['group'] as $objectNode )
        {
            $protocolNode = DH::findFirstElement('members', $objectNode);
            if( $protocolNode === FALSE )
                continue;


            /** @var DOMElement $objectNode */
            print "       - type 'ServiceGroup' at XML line #{$objectNode->getLineNo()}";

            //Todo: check if servicegroup object value is same, then delete it
            //TODO: VALIDATION needed if working as expected

            if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
            else
            {
                $objectNode->parentNode->removeChild($objectNode);
                print PH::boldText(" (removed)");
                $countDuplicateServiceObjects--;
            }
            print "\n";

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
            print "\n\n";
            print "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####\n";

            print "[".$key."]\n";

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


                            $secRules[$objectName][] = $objectNode;

                            if( !isset($secRuleIndex[$objectName]) )
                                $secRuleIndex[$objectName] = array('regular' => array(), 'group' => array());

                            $secRuleIndex[$objectName]['regular'][] = $objectNode;

                            //Todo:
                            //check if service has 'application-default' and additional
                            $objectNode_services = DH::findFirstElement('service', $objectNode);
                            foreach( $objectNode_services->childNodes as $objectService )
                            {
                                /** @var DOMElement $objectService */
                                if( $objectService->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $objectServiceName = $objectService->textContent;
                                if( isset($secRuleServices[$objectServiceName]) )
                                {
                                    //Secrule service has twice same service added
                                }
                                else
                                    $secRuleServices[$objectServiceName] = $objectService;
                            }
                            if( isset($secRuleServices['application-default'])  )
                            {
                                if( count($secRuleServices) > 1 )
                                {
                                    $secRuleServiceIndex[$objectName] = $secRuleServices['application-default'];
                                    #print "     - Rule: '" . $objectName . "' has service application-default + something else defined.\n";
                                    #print_r($secRuleServices);
                                }
                                else
                                {
                                    $secRuleServiceAppDefaultIndex[$objectName] = $secRuleServices['application-default'];
                                }

                            }


                            //check if application has 'any' adn additional
                            $objectNode_applications = DH::findFirstElement('application', $objectNode);
                            foreach( $objectNode_applications->childNodes as $objectApplication )
                            {
                                /** @var DOMElement $objectApplication */
                                if( $objectApplication->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $objectApplicationName = $objectApplication->textContent;
                                if( isset($secRuleApplication[$objectApplicationName]) )
                                {
                                    //Secrule has same application defined twice
                                }
                                else
                                    $secRuleApplication[$objectApplicationName] = $objectApplication;
                            }
                            if( isset($secRuleApplication['any']) and count($secRuleApplication) > 1 )
                            {
                                $secRuleApplicationIndex[$objectName] = $secRuleApplication['any'];
                                #print "     - Rule: '".$objectName."' has application 'any' + something else defined.\n" ;
                            }

                            $objectNode_category = DH::findFirstElement('category', $objectNode);
                            if( $objectNode_category && !$objectNode_category->hasChildNodes() )
                                $secRuleCategoryIndex[$objectName] = $objectNode_category;

                            //check if source has 'any' and additional
                            $objectNode_sources = DH::findFirstElement('source', $objectNode);
                            foreach( $objectNode_sources->childNodes as $objectSource )
                            {
                                /** @var DOMElement $objectSource */
                                if( $objectSource->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $objectSourceName = $objectSource->textContent;
                                if( isset($secRuleSource[$objectSourceName]) )
                                {
                                    //Secrule has same application defined twice
                                }
                                else
                                {
                                    $secRuleSource[$objectSourceName] = $objectSource;
                                    #print $objectName.'add to array: '.$objectSourceName."\n";
                                }

                            }
                            if( isset($secRuleSource['any']) and count($secRuleSource) > 1 )
                            {
                                $secRuleSourceIndex[$objectName] = $secRuleSource['any'];
                                print "     - Rule: '".$objectName."' has source 'any' + something else defined.\n" ;
                            }

                            //check if destination has 'any' and additional
                            $objectNode_destinations = DH::findFirstElement('destination', $objectNode);
                            foreach( $objectNode_destinations->childNodes as $objectDestination )
                            {
                                /** @var DOMElement $objectDestination */
                                if( $objectDestination->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $objectDestinationName = $objectDestination->textContent;
                                if( isset($secRuleDestination[$objectDestinationName]) )
                                {
                                    //Secrule has same application defined twice
                                }
                                else
                                    $secRuleDestination[$objectSourceName] = $objectDestination;
                            }
                            if( isset($secRuleDestination['any']) and count($secRuleDestination) > 1 )
                            {
                                $secRuleDestinationIndex[$objectName] = $secRuleDestination['any'];
                                #print "     - Rule: '".$objectName."' has application 'any' + something else defined.\n" ;
                            }
                        }

                    }

                    print " - parsed " . count($secRules) . " Security Rules\n";
                    print "\n";
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


                    print " - parsed " . count($natRules) . " NAT Rules\n";
                    print "\n";
                }

            }



            print "\n - Scanning for duplicate Security Rules...\n";
            foreach( $secRuleIndex as $objectName => $objectNodes )
            {
                $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                if( $dupCount < 2 )
                    continue;

                print "   - found Security Rule named '{$objectName}' that exists " . $dupCount . " time:\n";

                $tmp_secrule_array = array();
                foreach( $objectNodes['regular'] as $objectNode )
                {

                    /** @var DOMElement $objectNode */
                    print "       - type 'Security Rules' at XML line #{$objectNode->getLineNo()}";

                    $newName = $key . $objectNode->getAttribute('name');
                    if( !isset($secRuleIndex[$newName]) )
                    {
                        $objectNode->setAttribute('name', $newName);
                        print PH::boldText(" - new name: " . $newName . " (fixed)\n");
                    }
                    else
                        print " - Rulename can not be fixed: '" . $newName . "' is also available\n";

                    $countDuplicateSecRuleObjects++;
                }
            }

            print "\n - Scanning for duplicate NAT Rules...\n";
            foreach( $natRuleIndex as $objectName => $objectNodes )
            {
                $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                if( $dupCount < 2 )
                    continue;

                print "   - found NAT Rule named '{$objectName}' that exists " . $dupCount . " time:\n";
                $tmp_natrule_array = array();
                foreach( $objectNodes['regular'] as $key => $objectNode )
                {

                    /** @var DOMElement $objectNode */
                    print "       - type 'NAT Rules' at XML line #{$objectNode->getLineNo()}";


                    $newName = $key . $objectNode->getAttribute('name');
                    if( !isset($natRuleIndex[$newName]) )
                    {
                        $objectNode->setAttribute('name', $newName);
                        print PH::boldText(" - new name: " . $newName . " (fixed)\n");
                    }
                    else
                        print " - Rulename can not be fixed: '" . $newName . "' is also available\n";

                    $countDuplicateNATRuleObjects++;
                }
            }

            print "\n - Scanning for missconfigured Source Field in Security Rules...\n";
            foreach( $secRuleSourceIndex as $objectName => $objectNode )
            {
                print "   - found Security Rule named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}\n";
                $countMissconfiguredSecRuleSourceObjects++;
            }

            print "\n - Scanning for missconfigured Destination Field in Security Rules...\n";
            foreach( $secRuleDestinationIndex as $objectName => $objectNode )
            {
                print "   - found Security Rule named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}\n";
                $countMissconfiguredSecRuleDestinationObjects++;
            }

            print "\n - Scanning for missconfigured Service Field in Security Rules...\n";
            foreach( $secRuleServiceIndex as $objectName => $objectNode )
            {
                print "   - found Security Rule named '{$objectName}' that has service 'application-default' and an additional service configured at XML line #{$objectNode->getLineNo()}\n";
                $countMissconfiguredSecRuleServiceObjects++;
            }


            print "\n - Scanning for missconfigured Application Field in Security Rules...\n";
            foreach( $secRuleApplicationIndex as $objectName => $objectNode )
            {
                print "   - found Security Rule named '{$objectName}' that has application 'any' and additional application configured at XML line #{$objectNode->getLineNo()}\n";
                $countMissconfiguredSecRuleApplicationObjects++;
            }

            print "\n - Scanning for missconfigured Category Field in Security Rules...\n";
            foreach( $secRuleCategoryIndex as $objectName => $objectNode )
            {
                print "   - found Security Rule named '{$objectName}' that has XML element 'category' but not child element 'member' configured at XML line #{$objectNode->getLineNo()}\n";
                $countMissconfiguredSecRuleCategoryObjects++;
            }

            if( $service_app_default_available )
            {
                print "\n - Scanning for Security Rules with 'application-default' set | service object 'application-default' is available ...\n";
                foreach( $secRuleServiceAppDefaultIndex as $objectName => $objectNode )
                {
                    print "   - found Security Rule named '{$objectName}' that is using SERVICE OBJECT at XML line #{$objectNode->getLineNo()}\n";
                    $countMissconfiguredSecRuleServiceAppDefaultObjects++;
                }
            }

        }
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

    print "\n\n";
    print "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####\n";
    print " - parsed " . count($zoneObjects) . " zone objects \n";
    print "\n";

    //
    //
    //
    print "\n - Scanning for zones with wrong zone type (e.g. Layer3 instead of layer3 - case sensitive - Expedition issue?)...\n";
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
                        print "       - type 'Zone' name: '" . $node->getAttribute('name') . "' - '" . $results[0][0] . "' at XML line #{$zone_type->getLineNo()} (*FIX_MANUALLY*)\n";

                    }

                }


            }
        }
    }

    print "\n** ** ** ** ** ** **\n";
}


echo "\nSummary:\n";
echo " - FIXED: duplicate address-group members: {$totalAddressGroupsFixed}\n";
echo " - FIXED: duplicate service-group members: {$totalServiceGroupsFixed}\n";
echo " - FIXED: own address-group as subgroup member: {$totalAddressGroupsSubGroupFixed}\n";
echo " - FIXED: own service-group as subgroup members: {$totalServiceGroupsSubGroupFixed}\n";

echo "\n\nIssues that could not be fixed (look in logs for FIX_MANUALLY keyword):\n";
echo " - FIX_MANUALLY: address objects with same name as REGION: {$countMissconfiguredAddressRegionObjects} (look in the logs)\n\n";

echo " - FIX_MANUALLY: duplicate address objects: {$countDuplicateAddressObjects} (look in the logs )\n";
echo " - FIX_MANUALLY: duplicate service objects: {$countDuplicateServiceObjects} (look in the logs)\n\n";

echo " - FIX_MANUALLY: missconfigured address objects: {$countMissconfiguredAddressObjects} (look in the logs)\n";
echo " - FIX_MANUALLY: empty address-group: {$countEmptyAddressGroup} (look in the logs)\n\n";
echo " - FIX_MANUALLY: missconfigured service objects: {$countMissconfiguredServiceObjects} (look in the logs)\n";
echo " - FIX_MANUALLY: empty service-group: {$countEmptyServiceGroup} (look in the logs)\n\n";

echo " - FIX_MANUALLY: duplicate Security Rules: {$countDuplicateSecRuleObjects} (look in the logs )\n";
echo " - FIX_MANUALLY: duplicate NAT Rules: {$countDuplicateNATRuleObjects} (look in the logs )\n\n";

echo " - FIX_MANUALLY: missconfigured Source Field in Security Rules: {$countMissconfiguredSecRuleSourceObjects} (look in the logs )\n";
echo " - FIX_MANUALLY: missconfigured Destination Field in Security Rules: {$countMissconfiguredSecRuleDestinationObjects} (look in the logs )\n";
echo " - FIX_MANUALLY: missconfigured Service Field in Security Rules: {$countMissconfiguredSecRuleServiceObjects} (look in the logs )\n";
echo " - FIX_MANUALLY: missconfigured Application Field in Security Rules: {$countMissconfiguredSecRuleApplicationObjects} (look in the logs )\n";
echo " - FIX_MANUALLY: missconfigured Category Field in Security Rules: {$countMissconfiguredSecRuleCategoryObjects} (look in the logs )\n\n";

if( $service_app_default_available )
    echo " - FIX_MANUALLY: SERVICE OBJECT 'application-default' available and used in Security Rules: {$countMissconfiguredSecRuleServiceAppDefaultObjects} (look in the logs )\n\n";


if( $configInput['type'] == 'api' )
    echo "\n\nINPUT mode API detected: FIX is ONLY saved in offline file.\n";


// save our work !!!
if( $configOutput !== null )
{
    echo "\n\nSaving to file: " . PH::$args['out'] . "\n";
    if( $configOutput != '/dev/null' )
    {
        $xmlDoc->save(PH::$args['out']);
    }
}


print "\n************* END OF SCRIPT " . basename(__FILE__) . " ************\n\n";

