<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


AddressCallContext::$supportedActions[] = array(
    'name' => 'delete',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding . "  * SKIPPED: this object is used by other objects and cannot be deleted (use delete-Force to try anyway)\n";
            return;
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'delete-Force',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding . "  * WARNING : this object seems to be used so deletion may fail.\n";
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'decommission',
    'GlobalInitFunction' => function (AddressCallContext $context) {
        $context->objecttodelete = array();
    },
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $context->arguments['file'] !== "false" )
        {
            if( !isset($context->cachedList) )
            {
                $text = file_get_contents($context->arguments['file']);

                if( $text === FALSE )
                    derr("cannot open file '{$context->arguments['file']}");

                $lines = explode("\n", $text);
                foreach( $lines as $line )
                {
                    $line = trim($line);
                    if( strlen($line) == 0 )
                        continue;
                    $list[$line] = TRUE;
                }

                $context->cachedList = &$list;
            }
            else
                $list = &$context->cachedList;
        }
        else
            $list[] = $object->name();

        foreach( $list as $key => $item )
        {
            if( $object->name() == $key )
            {
                if( $object->countReferences() != 0 )
                {
                    print "delete all references: \n";
                    print $object->display_references();

                    if( $context->isAPI )
                        $object->API_removeWhereIamUsed(TRUE);
                    else
                        $object->removeWhereIamUsed(TRUE);
                }
                $context->objecttodelete[] = $object;
            }
        }
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {
        print "\n\n" . PH::boldText("DELETE ADDRESS OBJECTS:") . "\n";
        foreach( $context->objecttodelete as $object )
        {
            //error handling enabled because of address object reference settings in :
            //- interfaces: ethernet/vlan/loopback/tunnel
            //- IKE gateway
            // is not implemented yet
            PH::enableExceptionSupport();
            try
            {

                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
                print "finally delete address object: " . $object->name() . "\n";

            } catch(Exception $e)
            {
                PH::disableExceptionSupport();
                print "\n\n " . PH::boldText("  ***** an error occured : ") . $e->getMessage() . "\n\n";

                print PH::boldText("address object: " . $object->name() . " can not be removed. Check error message above.\n");

                return;
            }
        }
    },
    'args' => array(
        'file' => array('type' => 'string', 'default' => 'false'),
    ),
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'replace-IP-by-MT-like-Object',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( !$object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is not temporary or not an IP address/netmask\n";
            return;
        }

        $rangeDetected = FALSE;

        if( !$object->nameIsValidRuleIPEntry() )
        {
            echo $context->padding . "     *  SKIPPED because object is not an IP address/netmask or range\n";
            return;
        }

        $objectRefs = $object->getReferences();
        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            {
                $clearForAction = FALSE;
                echo $context->padding . "     *  SKIPPED because its used in unsupported class $class\n";
                return;
            }
        }

        $pan = PH::findRootObjectOrDie($object->owner);

        if( strpos($object->name(), '-') === FALSE )
        {
            $explode = explode('/', $object->name());

            if( count($explode) > 1 )
            {
                $name = $explode[0];
                $mask = $explode[1];
            }
            else
            {
                $name = $object->name();
                $mask = 32;
            }

            if( $mask > 32 || $mask < 0 )
            {
                echo $context->padding . "    * SKIPPED because of invalid mask detected : '$mask'\n";
                return;
            }

            if( filter_var($name, FILTER_VALIDATE_IP) === FALSE )
            {
                echo $context->padding . "    * SKIPPED because of invalid IP detected : '$name'\n";
                return;
            }

            if( $mask == 32 )
            {
                $newName = 'H-' . $name;
            }
            else
            {
                $newName = 'N-' . $name . '-' . $mask;
            }
        }
        else
        {
            $rangeDetected = TRUE;
            $explode = explode('-', $object->name());
            $newName = "R-" . $explode[0] . '-' . $explode[1];
        }

        echo $context->padding . "    * new object name will be $newName\n";

        $objToReplace = $object->owner->find($newName);
        if( $objToReplace === null )
        {
            if( $context->isAPI )
            {
                if( $rangeDetected )
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-range', $explode[0] . '-' . $explode[1]);
                else
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-netmask', $name . '/' . $mask);
            }
            else
            {
                if( $rangeDetected )
                    $objToReplace = $object->owner->newAddress($newName, 'ip-range', $explode[0] . '-' . $explode[1]);
                else
                    $objToReplace = $object->owner->newAddress($newName, 'ip-netmask', $name . '/' . $mask);
            }
        }
        else
        {
            $objMap = IP4Map::mapFromText($name . '/' . $mask);
            if( !$objMap->equals($objToReplace->getIP4Mapping()) )
            {
                echo "    * SKIPPED because an object with same name exists but has different value\n";
                return;
            }
        }


        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);

                if( $class == 'AddressRuleContainer' )
                {
                    /** @var AddressRuleContainer $objectRef */
                    echo $context->padding . "     - replacing in {$objectRef->toString()}\n";

                    if( $objectRef->owner->isNatRule()
                        && $objectRef->name == 'snathosts'
                        && $objectRef->owner->sourceNatTypeIs_DIPP()
                        && $objectRef->owner->snatinterface !== null )
                    {
                        echo $context->padding . "        -  SKIPPED because it's a SNAT with Interface IP address\n";
                        continue;
                    }


                    if( $context->isAPI )
                        $objectRef->API_add($objToReplace);
                    else
                        $objectRef->addObject($objToReplace);

                    if( $context->isAPI )
                        $objectRef->API_remove($object);
                    else
                        $objectRef->remove($object);
                }
                elseif( $class == 'NatRule' )
                {
                    /** @var NatRule $objectRef */
                    echo $context->padding . "     - replacing in {$objectRef->toString()}\n";

                    if( $context->isAPI )
                        $objectRef->API_setDNAT($objToReplace, $objectRef->dnatports);
                    else
                        $objectRef->replaceReferencedObject($object, $objToReplace);
                }
                else
                {
                    derr("unsupported class '$class'");
                }

            }
        }
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'removeWhereUsed',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $context->isAPI )
            $object->API_removeWhereIamUsed(TRUE, $context->padding, $context->arguments['actionIfLastMemberInRule']);
        else
            $object->removeWhereIamUsed(TRUE, $context->padding, $context->arguments['actionIfLastMemberInRule']);
    },
    'args' => array('actionIfLastMemberInRule' => array('type' => 'string',
        'default' => 'delete',
        'choices' => array('delete', 'disable', 'setAny')
    ),
    ),
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'addObjectWhereUsed',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        if( $context->isAPI )
            $object->API_addObjectWhereIamUsed($foundObject, TRUE, $context->padding . '  ', FALSE, $context->arguments['skipNatRules']);
        else
            $object->addObjectWhereIamUsed($foundObject, TRUE, $context->padding . '  ', FALSE, $context->arguments['skipNatRules']);
    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*'),
        'skipNatRules' => array('type' => 'bool', 'default' => FALSE))
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'add-member',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $addressObjectName = $context->arguments['addressobjectname'];

        if( !$object->isGroup() )
        {
            echo $context->padding . "     *  SKIPPED because object is not an address group\n";
            return;
        }

        $address0bjectToAdd = $object->owner->find($addressObjectName);
        if( $address0bjectToAdd === null )
        {
            echo $context->padding . "     *  SKIPPED because address object name: " . $addressObjectName . " not found\n";
            return;
        }

        if( $object->has($address0bjectToAdd) )
        {
            echo $context->padding . "     *  SKIPPED because address object is already a member of this address group\n";
            return;
        }

        if( $address0bjectToAdd->isType_ipWildcard() )
        {
            echo $context->padding . "     *  SKIPPED because wildcard address object can not be added as a member to a address group\n";
            return;
        }

        if( $context->isAPI )
            $object->API_addMember($address0bjectToAdd);
        else
            $object->addMember($address0bjectToAdd);

        return;

    },
    'args' => array(
        'addressobjectname' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'AddToGroup',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $objectlocation = $object->getLocationString();

        $addressGroupName = $context->arguments['addressgroupname'];
        $deviceGroupName = $context->arguments['devicegroupname'];

        if( $object->name() == $addressGroupName )
        {
            echo $context->padding . "     *  SKIPPED because address group can not added to itself\n";
            return;
        }

        if( $deviceGroupName == '*nodefault*' || $objectlocation == $deviceGroupName )
            $addressGroupToAdd = $object->owner->find($addressGroupName);
        else
        {
            if( get_class($object->owner->owner) == "DeviceGroup" )
            {
                if( isset($object->owner->owner->childDeviceGroups(TRUE)[$objectlocation]) )
                {
                    echo $context->padding . "     *  SKIPPED because address object is configured in Child DeviceGroup\n";
                    return;
                }
                if( !isset($object->owner->owner->parentDeviceGroups()[$deviceGroupName]) )
                {
                    echo $context->padding . "     *  SKIPPED because address object is configured at another child DeviceGroup at same level\n";
                    return;
                }

                $deviceGroupToAdd = $object->owner->owner->childDeviceGroups(TRUE)[$deviceGroupName];
            }
            elseif( get_class($object->owner->owner) == "PanoramaConf" )
                $deviceGroupToAdd = $object->owner->owner->findDeviceGroup($deviceGroupName);
            elseif( get_class($object->owner->owner) == "PANConf" )
                $deviceGroupToAdd = $object->owner->owner->findVirtualSystem($deviceGroupName);
            else
                derr("action is not defined yet for class: " . get_class($object->owner->owner));

            $addressGroupToAdd = $deviceGroupToAdd->addressStore->find($addressGroupName);
        }

        if( $addressGroupToAdd === null )
        {
            echo $context->padding . "     *  SKIPPED because address group name: " . $addressGroupName . " not found\n";
            return;
        }

        if( $addressGroupToAdd->isDynamic() )
        {
            echo $context->padding . "     *  SKIPPED because address group name: " . $addressGroupName . " is not static.\n";
            return;
        }

        if( $addressGroupToAdd->has($object) )
        {
            echo $context->padding . "     *  SKIPPED because address object is already a member of this address group\n";
            return;
        }

        if( $context->isAPI )
            $addressGroupToAdd->API_addMember($object);
        else
            $addressGroupToAdd->addMember($object);

        return;

    },
    'args' => array(
        'addressgroupname' => array('type' => 'string', 'default' => '*nodefault*'),
        'devicegroupname' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                "please define a DeviceGroup name for Panorama config or vsys name for Firewall config.\n"
        )
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'replaceWithObject',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        /** @var AddressGroup|AddressRuleContainer $objectRef */

        foreach( $objectRefs as $objectRef )
        {
            echo $context->padding . " * replacing in {$objectRef->toString()}\n";
            if( $context->isAPI )
                $objectRef->API_replaceReferencedObject($object, $foundObject);
            else
                $objectRef->replaceReferencedObject($object, $foundObject);
        }

    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Add',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is temporary\n";
            return;
        }
        $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $object->tags->API_addTag($objectFind);
        else
            $object->tags->addTag($objectFind);
    },
    'args' => array('tagName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Add-Force',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is temporary\n";
            return;
        }

        if( $context->isAPI )
        {
            $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
            if( $objectFind === null )
                $objectFind = $object->tags->parentCentralStore->API_createTag($context->arguments['tagName']);
        }
        else
            $objectFind = $object->tags->parentCentralStore->findOrCreate($context->arguments['tagName']);

        if( $context->isAPI )
            $object->tags->API_addTag($objectFind);
        else
            $object->tags->addTag($objectFind);
    },
    'args' => array('tagName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is temporary\n";
            return;
        }

        $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $object->tags->API_removeTag($objectFind);
        else
            $object->tags->removeTag($objectFind);
    },
    'args' => array('tagName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove-All',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is temporary\n";
            return;
        }

        foreach( $object->tags->tags() as $tag )
        {
            echo $context->padding . "  - removing tag {$tag->name()}... ";
            if( $context->isAPI )
                $object->tags->API_removeTag($tag);
            else
                $object->tags->removeTag($tag);
            echo "OK!\n";
        }
    },
    //'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove-Regex',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is temporary\n";
            return;
        }
        $pattern = '/' . $context->arguments['regex'] . '/';
        foreach( $object->tags->tags() as $tag )
        {
            $result = preg_match($pattern, $tag->name());
            if( $result === FALSE )
                derr("'$pattern' is not a valid regex");
            if( $result == 1 )
            {
                echo $context->padding . "  - removing tag {$tag->name()}... ";
                if( $context->isAPI )
                    $object->tags->API_removeTag($tag);
                else
                    $object->tags->removeTag($tag);
                echo "OK!\n";
            }
        }
    },
    'args' => array('regex' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'z_BETA_summarize',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            echo $context->padding . "    - SKIPPED because object is not a group\n";
            return;
        }
        if( $object->isDynamic() )
        {
            echo $context->padding . "    - SKIPPED because group is dynamic\n";
            return;
        }

        /** @var AddressGroup $object */
        $members = $object->expand();
        $mapping = new IP4Map();

        $listOfNotConvertibleObjects = array();

        foreach( $members as $member )
        {
            if( $member->isGroup() )
                derr('this is not supported');
            if( $member->type() == 'fqdn' )
            {
                $listOfNotConvertibleObjects[] = $member;
            }

            $mapping->addMap($member->getIP4Mapping(), TRUE);
        }
        $mapping->sortAndRecalculate();

        $object->removeAll();
        foreach( $listOfNotConvertibleObjects as $obj )
            $object->addMember($obj);

        foreach( $mapping->getMapArray() as $entry )
        {
            //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
            $objectName = 'R-' . long2ip($entry['start']) . '-' . long2ip($entry['start']);
            $newObject = $object->owner->find($objectName);
            if( $newObject === null )
                $newObject = $object->owner->newAddress($objectName, 'ip-range', long2ip($entry['start']) . '-' . long2ip($entry['start']));
            $object->addMember($newObject);
        }

        echo $context->padding . "  - group had " . count($members) . " expanded members vs {$mapping->count()} IP4 entries and " . count($listOfNotConvertibleObjects) . " unsupported objects\n";

    },
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (AddressCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addResolveGroupIPCoverage = FALSE;
        $addNestedMembers = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;

        if( isset($optionalFields['ResolveIP']) )
            $addResolveGroupIPCoverage = TRUE;

        if( isset($optionalFields['NestedMembers']) )
            $addNestedMembers = TRUE;

        $headers = '<th>location</th><th>name</th><th>type</th><th>value</th><th>description</th><th>tags</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addResolveGroupIPCoverage )
            $headers .= '<th>ip resolution</th>';
        if( $addNestedMembers )
            $headers .= '<th>nested members</th>';

        $lines = '';
        $encloseFunction = function ($value, $nowrap = TRUE) {
            if( is_string($value) )
                $output = htmlspecialchars($value);
            elseif( is_array($value) )
            {
                $output = '';
                $first = TRUE;
                foreach( $value as $subValue )
                {
                    if( !$first )
                    {
                        $output .= '<br />';
                    }
                    else
                        $first = FALSE;

                    if( is_string($subValue) )
                        $output .= htmlspecialchars($subValue);
                    else
                        $output .= htmlspecialchars($subValue->name());
                }
            }
            else
                derr('unsupported');

            if( $nowrap )
                return '<td style="white-space: nowrap">' . $output . '</td>';

            return '<td>' . $output . '</td>';
        };

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Address|AddressGroup $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                if( $object->owner->owner->isPanorama() || $object->owner->owner->isFirewall() )
                    $lines .= $encloseFunction('shared');
                else
                    $lines .= $encloseFunction($object->owner->owner->name());

                $lines .= $encloseFunction($object->name());

                if( $object->isGroup() )
                {
                    if( $object->isDynamic() )
                    {
                        $lines .= $encloseFunction('group-dynamic');
                        $lines .= $encloseFunction('');
                    }
                    else
                    {
                        $lines .= $encloseFunction('group-static');
                        $lines .= $encloseFunction($object->members());
                    }
                    $lines .= $encloseFunction($object->description(), FALSE);
                    $lines .= $encloseFunction($object->tags->tags());
                }
                elseif( $object->isAddress() )
                {
                    if( $object->isTmpAddr() )
                    {
                        $lines .= $encloseFunction('unknown');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                    }
                    else
                    {
                        $lines .= $encloseFunction($object->type());
                        $lines .= $encloseFunction($object->value());
                        $lines .= $encloseFunction($object->description(), FALSE);
                        $lines .= $encloseFunction($object->tags->tags());
                    }
                }

                if( $addWhereUsed )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $encloseFunction($refTextArray);
                }
                if( $addResolveGroupIPCoverage )
                {
                    $mapping = $object->getIP4Mapping();
                    $strMapping = explode(',', $mapping->dumpToString());

                    foreach( array_keys($mapping->unresolved) as $unresolved )
                        $strMapping[] = $unresolved;

                    $lines .= $encloseFunction($strMapping);
                }
                if( $addNestedMembers )
                {
                    if( $object->isGroup() )
                    {
                        $members = $object->expand(TRUE);
                        $lines .= $encloseFunction($members);
                    }
                    else
                        $lines .= $encloseFunction('');
                }

                $lines .= "</tr>\n";

            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html-export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/jquery-1.11.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);


        file_put_contents($filename, $content);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation', 'ResolveIP', 'NestedMembers'),
                'help' =>
                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n" .
                    "  - NestedMembers: lists all members, even the ones that may be included in nested groups\n" .
                    "  - ResolveIP\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n"
            )
    )

);


AddressCallContext::$supportedActions[] = array(
    'name' => 'replaceByMembersAndDelete',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        $object->replaceByMembersAndDelete($context->padding, $context->isAPI);
        /*
        if( !$object->isGroup() )
        {
            echo $context->padding." - SKIPPED : it's not a group\n";
            return;
        }

        if( $object->owner === null )
        {
            echo $context->padding." -  SKIPPED : object was previously removed\n";
            return;
        }

        $objectRefs = $object->getReferences();
        $clearForAction = true;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'AddressGroup' )
            {
                $clearForAction = false;
                echo "- SKIPPED : it's used in unsupported class $class\n";
                return;
            }
        }
        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);
                /** @var AddressRuleContainer|AddressGroup $objectRef */
        /*
                        if( $objectRef->owner === null )
                        {
                            echo $context->padding."  - SKIPPED because object already removed ({$objectRef->toString()})\n";
                            continue;
                        }

                        echo $context->padding."  - adding members in {$objectRef->toString()}\n";

                        if( $class == 'AddressRuleContainer' )
                        {
                            /** @var AddressRuleContainer $objectRef */
        /*
                            foreach( $object->members() as $objectMember )
                            {
                                if( $context->isAPI )
                                    $objectRef->API_add($objectMember);
                                else
                                    $objectRef->addObject($objectMember);

                                echo $context->padding."     -> {$objectMember->toString()}\n";
                            }
                            if( $context->isAPI )
                                $objectRef->API_remove($object);
                            else
                                $objectRef->remove($object);
                        }
                        elseif( $class == 'AddressGroup')
                        {
                            /** @var AddressGroup $objectRef */
        /*
                            foreach( $object->members() as $objectMember )
                            {
                                if( $context->isAPI )
                                    $objectRef->API_addMember($objectMember);
                                else
                                    $objectRef->addMember($objectMember);
                                echo $context->padding."     -> {$objectMember->toString()}\n";
                            }
                            if( $context->isAPI )
                                $objectRef->API_removeMember($object);
                            else
                                $objectRef->removeMember($object);
                        }
                        else
                        {
                            derr('unsupported class');
                        }

                    }

                    if( $context->isAPI )
                        $object->owner->API_remove($object, true);
                    else
                        $object->owner->remove($object, true);
                }
                */
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-Rename',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }
        if( $object->isGroup() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to Group objects\n";
            return;
        }

        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $newName = str_replace('$$current.name$$', $object->name(), $newName);
        }
        if( strpos($newName, '$$value$$') !== FALSE )
        {
            $newName = str_replace('$$value$$', $object->value(), $newName);
        }
        if( strpos($newName, '$$value.no-netmask$$') !== FALSE )
        {
            if( $object->isType_ipNetmask() )
                $replace = $object->getNetworkValue();
            else
                $replace = $object->value();

            $newName = str_replace('$$value.no-netmask$$', $replace, $newName);
        }
        if( strpos($newName, '$$netmask$$') !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                echo $context->padding . " *** SKIPPED : 'netmask' alias is not compatible with this type of objects\n";
                return;
            }
            $replace = $object->getNetworkMask();

            $newName = str_replace('$$netmask$$', $replace, $newName);
        }
        if( strpos($newName, '$$netmask.blank32$$') !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                echo $context->padding . " *** SKIPPED : 'netmask' alias is not compatible with this type of objects\n";
                return;
            }

            $replace = '';
            $netmask = $object->getNetworkMask();
            if( $netmask != 32 )
                $replace = $object->getNetworkMask();

            $newName = str_replace('$$netmask.blank32$$', $replace, $newName);
        }
        if( strpos($newName, '$$reverse-dns$$') !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                echo $context->padding . " *** SKIPPED : 'reverse-dns' alias is compatible with ip-netmask type objects\n";
                return;
            }
            if( $object->getNetworkMask() != 32 )
            {
                echo $context->padding . " *** SKIPPED : 'reverse-dns' actions only works on /32 addresses\n";
                return;
            }

            $ip = $object->getNetworkValue();
            $reverseDns = gethostbyaddr($ip);

            if( $ip == $reverseDns )
            {
                echo $context->padding . " *** SKIPPED : 'reverse-dns' could not be resolved\n";
                return;
            }

            $newName = str_replace('$$reverse-dns$$', $reverseDns, $newName);
        }


        if( $object->name() == $newName )
        {
            echo $context->padding . " *** SKIPPED : new name and old name are the same\n";
            return;
        }

        echo $context->padding . " - new name will be '{$newName}'\n";

        $findObject = $object->owner->find($newName);
        if( $findObject !== null )
        {
            echo $context->padding . " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        else
        {
            echo $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);
            echo "OK!\n";
        }

    },
    'args' => array('stringFormula' => array(
        'type' => 'string',
        'default' => '*nodefault*',
        'help' =>
            "This string is used to compose a name. You can use the following aliases :\n" .
            "  - \$\$current.name\$\$ : current name of the object\n" .
            "  - \$\$netmask\$\$ : netmask\n" .
            "  - \$\$netmask.blank32\$\$ : netmask or nothing if 32\n" .
            "  - \$\$reverse-dns\$\$ : value truncated of netmask if any\n" .
            "  - \$\$value\$\$ : value of the object\n" .
            "  - \$\$value.no-netmask\$\$ : value truncated of netmask if any\n")
    ),
    'help' => ''
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-Replace-Character',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $characterToreplace = $context->arguments['search'];
        $characterForreplace = $context->arguments['replace'];


        $newName = str_replace($characterToreplace, $characterForreplace, $object->name());


        if( $object->name() == $newName )
        {
            echo $context->padding . " *** SKIPPED : new name and old name are the same\n";
            return;
        }

        echo $context->padding . " - new name will be '{$newName}'\n";

        $findObject = $object->owner->find($newName);
        if( $findObject !== null )
        {
            echo $context->padding . " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        else
        {
            echo $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);
            echo "OK!\n";
        }

    },
    'args' => array(
        'search' => array('type' => 'string', 'default' => '*nodefault*'),
        'replace' => array('type' => 'string', 'default' => '*nodefault*')
    ),
    'help' => ''
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $newName = $context->arguments['prefix'] . $object->name();
        echo $context->padding . " - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            echo $context->padding . " *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName) !== null )
        {
            echo $context->padding . " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('prefix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $newName = $object->name() . $context->arguments['suffix'];
        echo $context->padding . " - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            echo $context->padding . " *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName) !== null )
        {
            echo $context->padding . " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('suffix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $prefix = $context->arguments['prefix'];

        if( strpos($object->name(), $prefix) !== 0 )
        {
            echo $context->padding . " *** SKIPPED : prefix not found\n";
            return;
        }
        $newName = substr($object->name(), strlen($prefix));

        if( !preg_match("/^[a-zA-Z0-9]/", $newName[0]) )
        {
            echo $context->padding . " *** SKIPPED : object name contains not allowed character at the beginning\n";
            return;
        }

        echo $context->padding . " - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName) !== null )
        {
            echo $context->padding . " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('prefix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( substr($object->name(), $suffixStartIndex, strlen($object->name())) != $suffix )
        {
            echo $context->padding . " *** SKIPPED : suffix not found\n";
            return;
        }
        $newName = substr($object->name(), 0, $suffixStartIndex);

        echo $context->padding . " - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName) !== null )
        {
            echo $context->padding . " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('suffix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . " * SKIPPED this is a temporary object\n";
            return;
        }

        $localLocation = 'shared';

        if( !$object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            echo $context->padding . " * SKIPPED because original and target destinations are the same: $targetLocation\n";
            return;
        }

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $targetLocation == 'shared' )
        {
            $targetStore = $rootObject->addressStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->addressStore;
        }

        if( $localLocation == 'shared' )
        {
            $reflocations = $object->getReferencesLocation();

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    $locations = $findSubSystem->childDeviceGroups(TRUE);
                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        echo $context->padding . "   * SKIPPED : moving from SHARED to sub-level is NOT possible because of references on higher DG level\n";
                        return;
                    }
                }
            }
        }

        if( $localLocation != 'shared' && $targetLocation != 'shared' )
        {
            if( $context->baseObject->isFirewall() )
            {
                echo $context->padding . "   * SKIPPED : moving between VSYS is not supported\n";
                return;
            }

            #echo $context->padding."   * SKIPPED : moving between 2 VSYS/DG is not supported yet\n";
            #return;

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    $locations = $findSubSystem->childDeviceGroups(TRUE);
                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        echo $context->padding . "   * SKIPPED : moving between 2 VSYS/DG is not possible because of references on higher DG level\n";
                        return;
                    }
                }
            }
        }

        $conflictObject = $targetStore->find($object->name(), null, FALSE);
        if( $conflictObject === null )
        {
            if( $object->isGroup() && !$object->isDynamic() )
            {
                foreach( $object->members() as $memberObject )
                    if( $targetStore->find($memberObject->name()) === null )
                    {
                        echo $context->padding . "   * SKIPPED : this group has an object named '{$memberObject->name()} that does not exist in target location '{$targetLocation}'\n";
                        return;
                    }
            }

            echo $context->padding . "   * moved, no conflict\n";
            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->remove($object);
                $targetStore->add($object);
                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->remove($object);
                $targetStore->add($object);
            }
            return;
        }

        if( $context->arguments['mode'] == 'skipifconflict' )
        {
            echo $context->padding . "   * SKIPPED : there is an object with same name. Choose another mode to resolve this conflict\n";
            return;
        }

        echo $context->padding . "   - there is a conflict with an object of same name and type. Please use address-merger.php script with argument 'allowmergingwithupperlevel'";
        if( $conflictObject->isGroup() )
            echo " - Group\n";
        else
            echo " - ".$conflictObject->type() . "\n";

        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            echo $context->padding . "   * SKIPPED because conflict has mismatching types\n";
            return;
        }

        if( $conflictObject->isTmpAddr() )
        {
            echo $context->padding . "   * SKIPPED because the conflicting object is TMP| value: ".$conflictObject->value()."\n";
            //normally the $object must be moved and the conflicting TMP object must be replaced by this $object
            return;
        }

        if( $object->isGroup() )
        {
            if( $object->equals($conflictObject) )
            {
                echo "    * Removed because target has same content\n";

                $object->replaceMeGlobally($conflictObject);
                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);

                return;
            }
            else
            {
                $object->displayValueDiff($conflictObject, 9);
                if( $context->arguments['mode'] == 'removeifmatch' )
                {
                    echo $context->padding . "    * SKIPPED because of mismatching group content\n";
                    return;
                }

                $localMap = $object->getIP4Mapping();
                $targetMap = $conflictObject->getIP4Mapping();

                if( !$localMap->equals($targetMap) )
                {
                    echo $context->padding . "    * SKIPPED because of mismatching group content and numerical values\n";
                    return;
                }

                echo $context->padding . "    * Removed because it has same numerical value\n";

                $object->replaceMeGlobally($conflictObject);
                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);

                return;

            }
        }

        if( $object->equals($conflictObject) )
        {
            echo "    * Removed because target has same content\n";
            $object->replaceMeGlobally($conflictObject);

            if( $context->isAPI )
                $object->owner->API_remove($object);
            else
                $object->owner->remove($object);
            return;
        }
        elseif( $object->isType_ipNetmask() )
        {
            if( str_replace('/32', '', $conflictObject->value()) == str_replace('/32', '', $object->value()) )
            {
                echo "    * Removed because target has same content\n";
                $object->replaceMeGlobally($conflictObject);

                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
                return;
            }
        }

        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $localMap = $object->getIP4Mapping();
        $targetMap = $conflictObject->getIP4Mapping();

        if( !$localMap->equals($targetMap) )
        {
            echo $context->padding . "    * SKIPPED because of mismatching content and numerical values\n";
            return;
        }

        echo "    * Removed because target has same numerical value\n";

        $object->replaceMeGlobally($conflictObject);
        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);


    },
    'args' => array('location' => array('type' => 'string', 'default' => '*nodefault*'),
        'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict', 'removeIfMatch', 'removeIfNumericalMatch'))
    ),
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'showIP4Mapping',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            $resolvMap = $object->getIP4Mapping();
            echo $context->padding . "* {$resolvMap->count()} entries\n";
            foreach( $resolvMap->getMapArray() as &$resolvRecord )
            {
                //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
                echo $context->padding . " - " . str_pad(long2ip($resolvRecord['start']), 14) . " - " . long2ip($resolvRecord['end']) . "\n";
            }
            /*foreach($resolvMap['unresolved'] as &$resolvRecord)
            {
                echo "     * UNRESOLVED: {$resolvRecord->name()}\n";
            }*/

        }
        else
        {
            $type = $object->type();

            if( $type == 'ip-netmask' || $type == 'ip-range' )
            {
                $resolvMap = $object->getIP4Mapping()->getMapArray();
                $resolvMap = reset($resolvMap);
                //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
                echo $context->padding . " - " . str_pad(long2ip($resolvMap['start']), 14) . " - " . long2ip($resolvMap['end']) . "\n";
            }
            else echo $context->padding . " - UNSUPPORTED \n";
        }
    }
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $object->display_references(7);
    },
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'display',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            if( $object->isDynamic() )
            {
                $tag_string = "";
                if( count($object->tags->tags()) > 0 )
                    $tag_string = "tag: '".$object->tags->toString_inline()."'";
                PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' (DYNAMIC)    desc: '{$object->description()}' $tag_string" );
            }
            else
            {
                PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' ({$object->count()} members)   desc: '{$object->description()}'" );

                foreach( $object->members() as $member )
                {
                    if( $member->isAddress() )
                        PH::print_stdout( "          - {$member->name()}  value: '{$member->value()}'" );
                    else
                        PH::print_stdout( "          - {$member->name()}" );
                }

            }
        }
        else
        {
            $tag_string = "";
            if( count($object->tags->tags()) > 0 )
                $tag_string = "tag: '".$object->tags->toString_inline()."'";
            PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}'  value: '{$object->value()}'  desc: '{$object->description()}' $tag_string" );
        }


        PH::print_stdout(  "" );
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'description-Append',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;
        $description = $address->description();

        if( $address->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : object is tmp\n";
            return;
        }

        $textToAppend = "";
        if( $description != "" )
            $textToAppend = " ";


        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $textToAppend .= str_replace('$$current.name$$', $address->name(), $newName);
        }
        else
        {
            $textToAppend .= $newName;
        }


        if( $context->object->owner->owner->version < 71 )
            $max_length = 253;
        else
            $max_length = 1020;

        if( strlen($description) + strlen($textToAppend) > $max_length )
        {
            echo $context->padding . " *** SKIPPED : resulting description is too long\n";
            return;
        }

        echo $context->padding . " - new description will be: '{$description}{$textToAppend}' ... ";

        if( $context->isAPI )
            $address->API_setDescription($description . $textToAppend);
        else
            $address->setDescription($description . $textToAppend);

        echo "OK";
    },
    'args' => array(
        'stringFormula' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                "This string is used to compose a name. You can use the following aliases :\n" .
                "  - \$\$current.name\$\$ : current name of the object\n")
    ),
    'help' => ''
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'description-Delete',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;
        $description = $address->description();

        if( $address->isTmpAddr() )
        {
            echo $context->padding . " *** SKIPPED : object is tmp\n";
            return;
        }
        if( $description == "" )
        {
            echo $context->padding . " *** SKIPPED : no description available\n";
            return;
        }

        echo $context->padding . " - new description will be: '' ... ";

        if( $context->isAPI )
            $address->API_setDescription("");
        else
            $address->setDescription("");

        echo "OK";
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'value-host-object-add-netmask-m32',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;

        if( $address->isGroup() )
        {
            echo $context->padding . " *** SKIPPED : object is of type GROUP\n";
            return;
        }

        if( !$address->isType_ipNetmask() )
        {
            echo $context->padding . " *** SKIPPED : object is not IP netmask\n";
            return;
        }

        $value = $address->value();

        if( strpos($value, "/") !== FALSE )
        {
            echo $context->padding . " *** SKIPPED : object: " . $address->name() . " with value: " . $value . " is not a host object.\n";
            return;
        }


        //
        $new_value = $value . "/32";

        echo $context->padding . " - new value will be: '" . $new_value . "'\n";

        if( $context->isAPI )
            $address->API_editValue($new_value);
        else
            $address->setValue($new_value);

        echo "OK";
    }
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'value-set-reverse-dns',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            echo $context->padding . " *** SKIPPED : object is of type GROUP\n";
            return;
        }
        if( !$object->isType_ipNetmask() )
        {
            echo $context->padding . " *** SKIPPED : 'value-set-reverse-dns' alias is compatible with ip-netmask type objects\n";
            return;
        }
        if( $object->getNetworkMask() != 32 )
        {
            echo $context->padding . " *** SKIPPED : 'value-set-reverse-dns' actions only works on /32 addresses\n";
            return;
        }

        $ip = $object->getNetworkValue();
        $reverseDns = gethostbyaddr($ip);

        if( $ip == $reverseDns )
        {
            echo $context->padding . " *** SKIPPED : 'value-set-reverse-dns' could not be resolved\n";
            return;
        }
        echo $context->padding . " - new value will be: '" . $reverseDns . " with type: fqdn'\n";

        $object->setType( 'fqdn' );
        $object->setValue($reverseDns);

        if( $context->isAPI )
            $object->API_sync();

        echo "OK";
    }
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'value-set-ip-for-fqdn',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            echo $context->padding . " *** SKIPPED : object is of type GROUP\n";
            return;
        }
        if( !$object->isType_FQDN() )
        {
            echo $context->padding . " *** SKIPPED : object is NOT of type FQDN\n";
            return;
        }


        $fqdn = $object->value();

        $reverseDns = gethostbynamel($fqdn);
        if( count( $reverseDns ) == 0 )
        {
            echo $context->padding . " *** SKIPPED : 'value-set-ip-for-fqdn' could not be resolved\n";
            return;
        }
        elseif( count( $reverseDns ) > 1 )
        {
            echo $context->padding . " *** SKIPPED : 'value-set-ip-for-fqdn' resolved more than one IP-Address [".implode(",",$reverseDns)."]\n";
            return;
        }

        echo $context->padding . " - new value will be: '" . $reverseDns[0] . " with type: ip-netmask'\n";

        $object->setType( 'ip-netmask' );
        $object->setValue($reverseDns[0]);

        if( $context->isAPI )
            $object->API_sync();

        echo "OK";
    }
);

//starting with 7.0 PAN-OS support max. 2500 members per group, former 500
AddressCallContext::$supportedActions[] = array(
    'name' => 'split-large-address-groups',
    'MainFunction' => function (AddressCallContext $context) {
        $largeGroupsCount = $context->arguments['largeGroupsCount'];
        $splitCount = $largeGroupsCount - 1;

        $group = $context->object;


        if( $group->isGroup() )
        {
            $membersCount = $group->count();

            // if this group has more members than $largeGroupsCount then we must split it
            if( $membersCount > $largeGroupsCount )
            {
                print "     AddressGroup named '" . $group->name() . "' with $membersCount members \n";

                // get member list in $members
                $members = $group->members();

                $i = 0;

                if( isset($newGroup) ) unset($newGroup);

                // loop move every member to a new subgroup
                foreach( $members as $member )
                {
                    // Condition to detect if previous sub-group is full
                    // so we have to create a new one
                    if( $i % $splitCount == 0 )
                    {
                        if( isset($newGroup) )
                        { // now we can rewrite XML
                            $newGroup->rewriteXML();
                        }

                        // create a new sub-group with name 'original--1'
                        if( $context->isAPI )
                            $newGroup = $group->owner->API_newAddressGroup($group->name() . '--' . ($i / $splitCount));
                        else
                            $newGroup = $group->owner->newAddressGroup($group->name() . '--' . ($i / $splitCount));
                        print "      New AddressGroup object created with name: " . $newGroup->name() . "\n";

                        // add this new sub-group to the original one. Don't rewrite XML for performance reasons.
                        if( $context->isAPI )
                            $group->API_addMember($newGroup, FALSE);
                        else
                            $group->addMember($newGroup, FALSE);
                    }

                    // remove current group member from old group, don't rewrite XML yet for performance savings
                    if( $context->isAPI )
                        $group->API_removeMember($member, FALSE);
                    else
                        $group->removeMember($member, FALSE);

                    // we add current group member to new subgroup
                    if( $context->isAPI )
                        $newGroup->API_addMember($member, FALSE);
                    else
                        $newGroup->addMember($member, FALSE);

                    $i++;
                }
                if( isset($newGroup) )
                { // now we can rewrite XML
                    $newGroup->rewriteXML();
                }

                // Now we can rewrite XML
                $group->rewriteXML();

                print "     AddressGroup count after split: " . $group->count() . " \n";

                print "\n";
            }
            else
                print "     * SKIP: ADDRESS GROUP members count is smaller as largeGroupsCount argument is set: " . $largeGroupsCount . " \n";
        }
        else
            print "     * SKIP: address object is not a ADDRESS GROUP. \n";

    },
    'args' => array('largeGroupsCount' => array('type' => 'string', 'default' => '2490')
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'replace-Object-by-IP',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is already tmp address\n";
            return;
        }

        if( $object->isGroup() )
        {
            echo $context->padding . "     *  SKIPPED because object is address group\n";
            return;
        }

        if( !$object->isType_ipRange() && !$object->isType_ipNetmask() && !$object->isAddress() )
        {
            echo $context->padding . "     *  SKIPPED because object is not an IP address/netmask\n";
            return;
        }

        $rangeDetected = FALSE;

        /*
        if( !$object->nameIsValidRuleIPEntry() )
        {
            echo $context->padding . "     *  SKIPPED because object is not an IP address/netmask or range\n";
            return;
        }
        */

        $objectRefs = $object->getReferences();
        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            {
                $clearForAction = FALSE;
                echo $context->padding . "     *  SKIPPED because its used in unsupported class $class\n";
                return;
            }
        }

        $pan = PH::findRootObjectOrDie($object->owner);

        if( !$object->isType_ipRange() )
        {
            //$explode = explode('/',$object->getNetworkValue());
            $explode = explode('/', $object->value());

            if( count($explode) > 1 )
            {
                $name = $explode[0];
                $mask = $explode[1];
            }
            else
            {
                $name = $object->value();
                $mask = 32;
            }

            if( $mask > 32 || $mask < 0 )
            {
                echo $context->padding . "    * SKIPPED because of invalid mask detected : '$mask'\n";
                return;
            }

            if( filter_var($name, FILTER_VALIDATE_IP) === FALSE )
            {
                echo $context->padding . "    * SKIPPED because of invalid IP detected : '$name'\n";
                return;
            }

            if( $mask == 32 )
            {
                $newName = $name;
            }
            else
            {
                $newName = $name . '/' . $mask;
            }
        }
        else
        {
            $rangeDetected = TRUE;
            $explode = explode('-', $object->value());
            $newName = $explode[0] . '-' . $explode[1];
        }

        echo $context->padding . "    * new object name will be $newName\n";


        $objToReplace = $object->owner->find($newName);
        if( $objToReplace === null )
        {
            if( $context->isAPI )
            {
                $objToReplace = $object->owner->createTmp($newName);

                /*
                if( $rangeDetected)
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-range', $explode[0].'-'.$explode[1] );
                else
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-netmask', $name.'/'.$mask);
                */
            }
            else
            {
                $objToReplace = $object->owner->createTmp($newName);
            }
        }
        else
        {
            if( !$object->isType_ipRange() )
            {
                $objMap = IP4Map::mapFromText($name . '/' . $mask);
                if( !$objMap->equals($objToReplace->getIP4Mapping()) )
                {
                    echo "    * SKIPPED because an object with same name exists but has different value\n";
                    return;
                }
            }
            //TODO: same valdiation for IP Range

        }

        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);

                if( $class == 'AddressRuleContainer' )
                {
                    /** @var AddressRuleContainer $objectRef */
                    echo $context->padding . "     - replacing in {$objectRef->toString()}\n";

                    if( $objectRef->owner->isNatRule()
                        && $objectRef->name == 'snathosts'
                        && $objectRef->owner->sourceNatTypeIs_DIPP()
                        && $objectRef->owner->snatinterface !== null )
                    {
                        echo $context->padding . "        -  SKIPPED because it's a SNAT with Interface IP address\n";
                        continue;
                    }


                    if( $context->isAPI )
                        $objectRef->API_add($objToReplace);
                    else
                        $objectRef->addObject($objToReplace);

                    if( $context->isAPI )
                        $objectRef->API_remove($object);
                    else
                        $objectRef->remove($object);
                }
                elseif( $class == 'NatRule' )
                {
                    /** @var NatRule $objectRef */
                    echo $context->padding . "     - replacing in {$objectRef->toString()}\n";

                    if( $context->isAPI )
                        $objectRef->API_setDNAT($objToReplace, $objectRef->dnatports);
                    else
                        $objectRef->replaceReferencedObject($object, $objToReplace);
                }
                else
                {
                    derr("unsupported class '$class'");
                }

            }
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);

    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'display-NAT-usage',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding . "     *  SKIPPED because object is temporary \n";
            return;
        }

        $objectRefs = $object->getReferences();



        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            #if( $class != 'NatRule' )
            {
                $clearForAction = FALSE;
                echo $context->padding . "     *  SKIPPED it is not used in NAT rule\n";
                return;
            }

            #print "name: ".$objectRef->name()."\n";


            if( isset($objectRef->owner) && $objectRef->owner !== null )
            {
                $objRef_owner = $objectRef->owner;
                $class = get_class($objRef_owner);
                $class = strtolower($class);
                #print "CLASS: ".$class."\n";
                if( $class != "natrule" )
                {
                    echo $context->padding . "     *  SKIPPED it is not used in NAT rule\n";
                    return;
                }

                print "\n";

                if( $objRef_owner->sourceNatIsEnabled() )
                {
                    //SNAT

                    print $context->padding . $objRef_owner->source->toString_inline()."";
                    print " => ".$objRef_owner->snathosts->toString_inline()."";
                    print "\n";

                    foreach( $objRef_owner->source->members() as $key =>$member )
                    {
                        if( $object === $member )
                            print $context->padding . PH::boldText( $member->value() );
                        else
                            print $context->padding . $member->value();
                    }
                    foreach( $objRef_owner->snathosts->members() as $key => $member )
                    {
                        print " => ";
                        if( $object === $member )
                            print PH::boldText( $member->value() );
                        else
                            print $member->value();
                    }


                    if( $objRef_owner->isBiDirectional() )
                    {
                        //Bidir
                        print $context->padding . "rule is bidir-NAT\n";
                        print $context->padding . "name: ".$objRef_owner->name()."\n";
                    }
                }
                elseif( $objRef_owner->destinationNatIsEnabled() )
                {
                    //DNAT

                    print $context->padding . $objRef_owner->destination->toString_inline()."";
                    print " => ".$objRef_owner->dnathost->name()."";
                    print "\n";

                    foreach( $objRef_owner->destination->members() as $key => $member )
                    {
                        if( $object === $member )
                            print $context->padding . PH::boldText( $member->value() );
                        else
                            print $context->padding .  $member->value();
                    }
                    print " => ";
                    print $objRef_owner->dnathost->value()."\n";
                }

            }




        }


    },
);