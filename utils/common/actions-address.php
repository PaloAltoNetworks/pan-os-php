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


AddressCallContext::$supportedActions[] = array(
    'name' => 'delete',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use delete-Force to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus( $context, "WARNING", $string );
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'decommission',
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
            if( $object->countReferences() != 0 )
            {
                $string = "delete all references: " ;
                PH::ACTIONlog( $context, $string );
                $object->display_references();

                if( $context->isAPI )
                    $object->API_removeWhereIamUsed(TRUE);
                else
                    $object->removeWhereIamUsed(TRUE);
            }

            //error handling enabled because of address object reference settings in :
            //- interfaces: ethernet/vlan/loopback/tunnel
            //- IKE gateway
            // is not implemented yet
            PH::enableExceptionSupport();
            try
            {
                if( $object->owner != null )
                {
                    if( $context->isAPI )
                        $object->owner->API_remove($object);
                    else
                        $object->owner->remove($object);
                    $string = "finally delete address object: " . $object->name();
                    PH::ACTIONlog( $context, $string );
                }


            } catch(Exception $e)
            {
                PH::disableExceptionSupport();
                PH::print_stdout();
                PH::print_stdout();
                $string = PH::boldText("  ***** an error occured : ") . $e->getMessage();
                PH::ACTIONlog( $context, $string );

                $string = PH::boldText("address object: " . $object->name() . " can not be removed. Check error message above.");
                PH::ACTIONlog( $context, $string );

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
            $string = "because object is not temporary or not an IP address/netmask";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->nameIsValidRuleIPEntry() )
        {
            $string = "because object is not an IP address/netmask or range";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $prefix = array();
        $prefix['host'] = "H-";

        $prefix['network'] = "N-";
        $prefix['networkmask'] = "-";

        $prefix['range'] = "R-";
        $prefix['rangeseparator'] = "-";

        $object->replaceIPbyObject( $context, $prefix );
        /*
        $objectRefs = $object->getReferences();
        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            {
                $clearForAction = FALSE;
                $string = "because its used in unsupported class $class";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                $string = "because of invalid mask detected : '$mask'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            if( filter_var($name, FILTER_VALIDATE_IP) === FALSE )
            {
                $string = "because of invalid IP detected : '$name'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
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

        $string = "new object name will be $newName";
        PH::ACTIONlog( $context, $string );

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
                $string = "because an object with same name exists but has different value";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
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
        /*
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    if( $objectRef->owner->isNatRule()
                        && $objectRef->name == 'snathosts'
                        && $objectRef->owner->sourceNatTypeIs_DIPP()
                        && $objectRef->owner->snatinterface !== null )
                    {
                        $string = "because it's a SNAT with Interface IP address";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
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
        /*
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

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
        */
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
            $string = "because object is not an address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $address0bjectToAdd = $object->owner->find($addressObjectName);
        if( $address0bjectToAdd === null )
        {
            $string = "because address object name: " . $addressObjectName . " not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->has($address0bjectToAdd) )
        {
            $string = "because address object is already a member of this address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $address0bjectToAdd->isType_ipWildcard() )
        {
            $string = "because wildcard address object can not be added as a member to a address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "because address group can not added to itself";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                    $string = "because address object is configured in Child DeviceGroup";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }
                if( !isset($object->owner->owner->parentDeviceGroups()[$deviceGroupName]) )
                {
                    $string = "because address object is configured at another child DeviceGroup at same level";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "because address group name: " . $addressGroupName . " not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $addressGroupToAdd->isDynamic() )
        {
            $string = "because address group name: " . $addressGroupName . " is not static.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $addressGroupToAdd->has($object) )
        {
            $string = "because address object is already a member of this address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "replacing in {$objectRef->toString()}";
            PH::ACTIONlog( $context, $string );
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
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        foreach( $object->tags->tags() as $tag )
        {
            $text = $context->padding . "  - removing tag {$tag->name()}... ";
            if( $context->isAPI )
                $object->tags->API_removeTag($tag);
            else
                $object->tags->removeTag($tag);

            PH::ACTIONlog( $context, $text );
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
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                $text = $context->padding . "  - removing tag {$tag->name()}... ";
                if( $context->isAPI )
                    $object->tags->API_removeTag($tag);
                else
                    $object->tags->removeTag($tag);

                PH::ACTIONlog( $context, $text );
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
            $string = "because object is not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->isDynamic() )
        {
            $string = "because group is dynamic";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $newObject = $object->owner->find($objectName, null, false);
            if( $newObject === null )
                $newObject = $object->owner->newAddress($objectName, 'ip-range', long2ip($entry['start']) . '-' . long2ip($entry['start']));
            $object->addMember($newObject);
        }

        $string = "group had " . count($members) . " expanded members vs {$mapping->count()} IP4 entries and " . count($listOfNotConvertibleObjects) . " unsupported objects";
        PH::ACTIONlog( $context, $string );

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

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addResolveGroupIPCoverage = FALSE;
        $addNestedMembers = FALSE;
        $addResolveIPNestedMembers = FALSE;
        $addNestedMembersCount = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;

        if( isset($optionalFields['ResolveIP']) )
            $addResolveGroupIPCoverage = TRUE;

        if( isset($optionalFields['NestedMembers']) )
        {
            $addNestedMembers = TRUE;
            $addResolveIPNestedMembers = TRUE;
            $addNestedMembersCount = TRUE;
        }


        $headers = '<th>location</th><th>name</th><th>type</th><th>value</th><th>description</th><th>Memberscount</th><th>IPcount</th><th>tags</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addResolveGroupIPCoverage )
            $headers .= '<th>ip resolution</th>';
        if( $addNestedMembers )
            $headers .= '<th>nested members</th>';
        if( $addResolveIPNestedMembers )
            $headers .= '<th>nested members ip resolution</th>';
        if( $addNestedMembersCount )
            $headers .= '<th>nested members count</th>';

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
                        #$lines .= $encloseFunction('');
                        $lines .= $encloseFunction($object->members());
                    }
                    else
                    {
                        $lines .= $encloseFunction('group-static');
                        $lines .= $encloseFunction($object->members());
                    }
                    $lines .= $encloseFunction($object->description(), FALSE);
                    if( $object->isGroup() )
                        $lines .= $encloseFunction( (string)count( $object->members() ));
                    else
                        $lines .= $encloseFunction( '---' );

                    $counter = 0;
                    $members = $object->expand(FALSE);
                    foreach( $members as $member )
                        $counter += $member->getIPcount();
                    $lines .= $encloseFunction((string)$counter);

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
                        $lines .= $encloseFunction('');
                    }
                    else
                    {
                        $lines .= $encloseFunction($object->type());
                        $lines .= $encloseFunction($object->value());
                        $lines .= $encloseFunction($object->description(), FALSE);
                        $lines .= $encloseFunction( '---' );
                        $lines .= $encloseFunction( (string)$object->getIPcount() );
                        $lines .= $encloseFunction($object->tags->tags());
                    }
                }
                elseif( $object->isRegion() )
                {
                    //swaschkut - 20220417
                    //what to do here?
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
                        $members = $object->expand(FALSE);
                        $lines .= $encloseFunction($members);
                    }
                    else
                        $lines .= $encloseFunction('');
                }
                if( $addResolveIPNestedMembers )
                {
                    if( $object->isGroup() )
                    {   $resolve = array();
                        $members = $object->expand(FALSE);
                        foreach( $members as $member )
                            $resolve[] = $member->value();
                        $lines .= $encloseFunction($resolve);
                    }
                    else
                        $lines .= $encloseFunction('');
                }
                if( $addNestedMembersCount )
                {
                    if( $object->isGroup() )
                    {   $resolve = array();
                        $members = $object->expand(FALSE);
                        $lines .= $encloseFunction( (string)count($members) );
                    }
                    else
                        $lines .= $encloseFunction('');
                }

                $lines .= "</tr>\n";

            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

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

        if( !$object->isGroup() )
        {
            $string = "it's not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->owner === null )
        {
            $string = "object was previously removed";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object->replaceByMembersAndDelete($context, $context->isAPI);
    },
    'args' => array(
        'keepgroupname' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'choices' => array('tag', 'description'),
            'help' =>
                "- replaceByMembersAndDelete:tag -> create Tag with name from AddressGroup name and add to the object\n" .
                "- replaceByMembersAndDelete:description -> create Tag with name from AddressGroup name and add to the object\n"
        )
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-Rename',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->isGroup() )
        {
            $string = "not applicable to Group objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                $string = "'netmask' alias is not compatible with this type of objects";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
            $replace = $object->getNetworkMask();

            $newName = str_replace('$$netmask$$', $replace, $newName);
        }
        if( strpos($newName, '$$netmask.blank32$$') !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                $string = "'netmask' alias is not compatible with this type of objects";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                $string = "'reverse-dns' alias is compatible with ip-netmask type objects";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
            if( $object->getNetworkMask() != 32 )
            {
                $string = "'reverse-dns' actions only works on /32 addresses";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            $ip = $object->getNetworkValue();
            $reverseDns = gethostbyaddr($ip);

            if( $ip == $reverseDns )
            {
                $string = "'reverse-dns' could not be resolved";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            $newName = str_replace('$$reverse-dns$$', $reverseDns, $newName);
        }


        if( $object->name() == $newName )
        {
            $string = "new name and old name are the same";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $findObject = $object->owner->find($newName, null, false);
        if( $findObject !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
        {
            $text = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $text );
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
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $characterToreplace = $context->arguments['search'];
        $characterForreplace = $context->arguments['replace'];


        $newName = str_replace($characterToreplace, $characterForreplace, $object->name());


        if( $object->name() == $newName )
        {
            $string = "new name and old name are the same";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $findObject = $object->owner->find($newName, null, false);
        if( $findObject !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
        {
            $text = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $text );
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
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $newName = $context->arguments['prefix'] . $object->name();
        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 63 )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName, null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $newName = $object->name() . $context->arguments['suffix'];
        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 63 )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName, null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $prefix = $context->arguments['prefix'];

        if( strpos($object->name(), $prefix) !== 0 )
        {
            $string = "prefix not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $newName = substr($object->name(), strlen($prefix));

        if( !preg_match("/^[a-zA-Z0-9]/", $newName[0]) )
        {
            $string = "object name contains not allowed character at the beginning";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName , null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( substr($object->name(), $suffixStartIndex, strlen($object->name())) != $suffix )
        {
            $string = "suffix not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $newName = substr($object->name(), 0, $suffixStartIndex);

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName, null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
            $string = "this is a temporary object";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $localLocation = 'shared';

        if( !$object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            $string = "because original and target destinations are the same: $targetLocation";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                        $string = "moving from SHARED to sub-level is NOT possible because of references on higher DG level";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
        }

        if( $localLocation != 'shared' && $targetLocation != 'shared' )
        {
            if( $context->baseObject->isFirewall() )
            {
                $string = "moving between VSYS is not supported";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }


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
                        $string = "moving between 2 VSYS/DG is not possible because of references on higher DG level";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                {
                    if( $targetStore->find($memberObject->name(), null, true ) === null )
                    {
                        $string = "this group has an object named '{$memberObject->name()} that does not exist in target location '{$targetLocation}'";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }

            $string = "moved, no conflict";
            PH::ACTIONlog( $context, $string );

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
            $string = "there is an object with same name. Choose another mode to resolve this conflict";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = "there is a conflict with an object of same name and type. Please use address-merger.php script with argument 'allowmergingwithupperlevel'";
        if( $conflictObject->isGroup() )
            $text .= " - Group";
        else
            $text .= " - ".$conflictObject->type();
        PH::ACTIONlog( $context, $text );

        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            $string = "because conflict has mismatching types";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $conflictObject->isTmpAddr() )
        {
            $string = "because the conflicting object is TMP| value: ".$conflictObject->value();
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            //normally the $object must be moved and the conflicting TMP object must be replaced by this $object
            return;
        }

        if( $object->isGroup() )
        {
            $localMap = $object->getIP4Mapping();
            $targetMap = $conflictObject->getIP4Mapping();

            if( $object->equals($conflictObject) && $localMap->equals($targetMap) )
            //if( $object->equals($conflictObject) )
            {
                //
                //bug; deep matching ip4mapping needed

                $string = "Removed because target has same content";
                PH::ACTIONlog( $context, $string );

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
                    $string = "because of mismatching group content";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }

                if( !$localMap->equals($targetMap) )
                {
                    $string = "because of mismatching group content and numerical values";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }

                $string = "Removed because it has same numerical value";
                PH::ACTIONlog( $context, $string );

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
            $string = "Removed because target has same content";
            PH::ACTIONlog( $context, $string );

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
                $string = "Removed because target has same content";
                PH::ACTIONlog( $context, $string );

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
            $string = "because of mismatching content and numerical values";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "Removed because target has same numerical value";
        PH::ACTIONlog( $context, $string );

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
            $string = "{$resolvMap->count()} entries";
            PH::ACTIONlog( $context, $string );


            foreach( $resolvMap->getMapArray() as &$resolvRecord )
            {
                //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
                $string = str_pad(long2ip($resolvRecord['start']), 14) . " - " . long2ip($resolvRecord['end']);
                PH::ACTIONlog( $context, $string );
            }
            $unresolvedCount = count($resolvMap->unresolved);
            $string = "unresolved: {$unresolvedCount} entries";
            if( $unresolvedCount > 0 )
            {
                PH::print_stdout();
                PH::ACTIONlog( $context, $string );

                foreach($resolvMap->unresolved as &$resolvRecord)
                {
                    if( get_class( $resolvRecord ) == "AddressGroup" )
                        $type = "AddressGroup";
                    else
                        $type = $resolvRecord->type();
                    $string ="UNRESOLVED: objname: '{$resolvRecord->name()}' of type: ".$type;
                    PH::ACTIONlog( $context, $string );
                }
            }
        }
        elseif( $object->isRegion() )
        {
            $string = "UNSUPPORTED";
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $type = $object->type();

            if( $type == 'ip-netmask' || $type == 'ip-range' )
            {
                $resolvMap = $object->getIP4Mapping()->getMapArray();
                $resolvMap = reset($resolvMap);
                //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
                $string = str_pad(long2ip($resolvMap['start']), 14) . " - " . long2ip($resolvMap['end']);
                PH::ACTIONlog($context, $string);
            }
            else
            {
                $string = "UNSUPPORTED";
                PH::ACTIONlog( $context, $string );
            }
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

        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();

        if( $object->isGroup() )
        {
            if( $object->isDynamic() )
            {
                $tag_string = "";
                if( count($object->tags->tags()) > 0 )
                {
                    $toStringInline = $object->tags->toString_inline();
                    TAG::revertreplaceNamewith( $toStringInline );
                    $tag_string = "tag: '".$toStringInline."'";
                }


                $tmpFilter = $object->filter;
                TAG::revertreplaceNamewith( $tmpFilter );
                PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' (DYNAMIC)  ({$object->count()} members)  desc: '{$object->description()}' $tag_string filter: '{$tmpFilter}" );
                PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object)." (DYNAMIC)";

                PH::$JSON_TMP['sub']['object'][$object->name()]['tag'] = $tag_string;
                PH::$JSON_TMP['sub']['object'][$object->name()]['filter'] = $object->filter;
            }
            else
            {
                PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' ({$object->count()} members)   desc: '{$object->description()}'" );
                PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
            }

            PH::$JSON_TMP['sub']['object'][$object->name()]['memberscount'] = $object->count();
            PH::$JSON_TMP['sub']['object'][$object->name()]['description'] = $object->description();

            foreach( $object->members() as $member )
            {
                PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['name'] = $member->name();
                PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['type'] = get_class( $member );

                if( $member->isAddress() )
                {
                    PH::print_stdout( "          - {$member->name()}  value: '{$member->value()}'" );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['value'] = $member->value();
                }
                else
                    PH::print_stdout( "          - {$member->name()}" );
            }
        }
        elseif( $object->isAddress() )
        {
            $tag_string = "";
            if( count($object->tags->tags()) > 0 )
            {
                $toStringInline = $object->tags->toString_inline();
                TAG::revertreplaceNamewith( $toStringInline );
                $tag_string = "tag: '".$toStringInline."'";
            }

            PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}'  value: '{$object->value()}'  desc: '{$object->description()}' IPcount: '{$object->getIPcount()}' $tag_string" );
            PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
            PH::$JSON_TMP['sub']['object'][$object->name()]['value'] = $object->value();
            PH::$JSON_TMP['sub']['object'][$object->name()]['tag'] = $tag_string;
            PH::$JSON_TMP['sub']['object'][$object->name()]['description'] = $object->description();
            PH::$JSON_TMP['sub']['object'][$object->name()]['ipcount'] = $object->getIPcount();
        }
        elseif( $object->isRegion() )
        {
            PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}'  " );
            PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
            #PH::$JSON_TMP['sub']['object'][$object->name()]['value'] = $object->value();

        }


        PH::print_stdout(  "" );
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'description-Append',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;

        if( $address->isTmpAddr() )
        {
            $string = "object is of type TMP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $address->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $description = $address->description();

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
            $string = "resulting description is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new description will be: '{$description}{$textToAppend}' ... ";

        if( $context->isAPI )
            $address->API_setDescription($description . $textToAppend);
        else
            $address->setDescription($description . $textToAppend);
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
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

        if( $address->isTmpAddr() )
        {
            $string = "object is of type TMP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $address->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $description = $address->description();
        if( $description == "" )
        {
            $string = "no description available";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new description will be: '' ... ";
        if( $context->isAPI )
            $address->API_setDescription("");
        else
            $address->setDescription("");
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    },
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'description-Replace-Character',
    'MainFunction' => function (AddressCallContext $context) {

        $object = $context->object;

        $characterToreplace = $context->arguments['search'];
        if( strpos($characterToreplace, '$$comma$$') !== FALSE )
            $characterToreplace = str_replace('$$comma$$', ",", $characterToreplace);
        if( strpos($characterToreplace, '$$pipe$$') !== FALSE )
            $characterToreplace = str_replace('$$pipe$$', "|", $characterToreplace);

        $characterForreplace = $context->arguments['replace'];
        if( strpos($characterForreplace, '$$comma$$') !== FALSE )
            $characterForreplace = str_replace('$$comma$$', ",", $characterForreplace);
        if( strpos($characterForreplace, '$$pipe$$') !== FALSE )
            $characterForreplace = str_replace('$$pipe$$', "|", $characterForreplace);

        $description = $object->description();

        $newDescription = str_replace($characterToreplace, $characterForreplace, $description);
        //todo add regex replacement 20210305
        //$desc = preg_replace('/appRID#[0-9]+/', '', $rule->description());

        if( $description == $newDescription )
        {
            $string = "new and old description are the same" ;
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new description will be '{$newDescription}'";
        PH::ACTIONlog( $context, $string );

        if( $context->isAPI )
            $object->API_setDescription($newDescription);
        else
            $object->setDescription($newDescription);


    },
    'args' => array(
        'search' => array('type' => 'string', 'default' => '*nodefault*'),
        'replace' => array('type' => 'string', 'default' => '')
    ),
    'help' => 'possible variable $$comma$$ or $$pipe$$; example "actions=description-Replace-Character:$$comma$$word1"'
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'value-host-object-add-netmask-m32',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;

        if( $address->isGroup() )
        {
            $string = "object is of type GROUP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $address->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$address->isType_ipNetmask() )
        {
            $string = "object is not IP netmask";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $value = $address->value();

        if( strpos($value, "/") !== FALSE )
        {
            $string = "object: " . $address->name() . " with value: " . $value . " is not a host object.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }


        //
        $new_value = $value . "/32";

        $text = $context->padding . " - new value will be: '" . $new_value . "'";
        if( $context->isAPI )
            $address->API_editValue($new_value);
        else
            $address->setValue($new_value);
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    }
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'value-set-reverse-dns',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            $string = "object is of type GROUP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->isType_ipNetmask() )
        {
            $string = "'value-set-reverse-dns' alias is compatible with ip-netmask type objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->getNetworkMask() != 32 )
        {
            $string = "'value-set-reverse-dns' actions only works on /32 addresses";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $ip = $object->getNetworkValue();
        $reverseDns = gethostbyaddr($ip);

        if( $ip == $reverseDns )
        {
            $string = "'value-set-reverse-dns' could not be resolved";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new value will be: '" . $reverseDns . " with type: fqdn'";
        $object->setType( 'fqdn' );
        $object->setValue($reverseDns);

        if( $context->isAPI )
            $object->API_sync();

        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    }
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'value-set-ip-for-fqdn',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            $string = "object is of type GROUP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->isType_FQDN() )
        {
            $string = "object is NOT of type FQDN";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }


        $fqdn = $object->value();

        $reverseDns = gethostbynamel($fqdn);
        if( $reverseDns === FALSE || count( $reverseDns ) == 0 )
        {
            $string = "'value-set-ip-for-fqdn' could not be resolved";
            return;
        }
        elseif( count( $reverseDns ) > 1 )
        {
            $string = "'value-set-ip-for-fqdn' resolved more than one IP-Address [".implode(",",$reverseDns)."]";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new value will be: '" . $reverseDns[0] . " with type: ip-netmask'";

        $object->setType( 'ip-netmask' );
        $object->setValue($reverseDns[0]);

        if( $context->isAPI )
            $object->API_sync();

        $text .= "OK";
        PH::ACTIONlog( $context, $text );
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
                $string = "AddressGroup named '" . $group->name() . "' with $membersCount members";
                PH::ACTIONlog( $context, $string );

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
                        $string = "New AddressGroup object created with name: " . $newGroup->name();
                        PH::ACTIONlog( $context, $string );

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

                $string = "AddressGroup count after split: " . $group->count();
                PH::ACTIONlog( $context, $string );
                PH::print_stdout();
            }
            else
            {

                $string = "ADDRESS GROUP members count is smaller as largeGroupsCount argument is set: " . $largeGroupsCount;
                PH::ACTIONstatus( $context, "SKIPPED", $string );
            }
        }
        else
        {
            $string = "address object is not a ADDRESS GROUP.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
        }


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
            $string = "because object is already tmp address";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->isGroup() || $object->isRegion() )
        {
            $string = "because object is or GROUP or REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->isType_ipRange() && !$object->isType_ipNetmask() && !$object->isAddress() )
        {
            $string = "because object is not an IP address/netmask";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $rangeDetected = FALSE;

        /*
        if( !$object->nameIsValidRuleIPEntry() )
        {
            PH::print_stdout( $context->padding . "     *  SKIPPED because object is not an IP address/netmask or range" );
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
                $string = "because its used in unsupported class $class";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                $string = "because of invalid mask detected : '$mask'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            if( filter_var($name, FILTER_VALIDATE_IP) === FALSE )
            {
                $string = "because of invalid IP detected : '$name'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
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

        $string = "new object name will be $newName";
        PH::ACTIONlog( $context, $string );


        $objToReplace = $object->owner->find($newName, null, false );
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
                    $string = "because an object with same name exists but has different value";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    if( $objectRef->owner->isNatRule()
                        && $objectRef->name == 'snathosts'
                        && $objectRef->owner->sourceNatTypeIs_DIPP()
                        && $objectRef->owner->snatinterface !== null )
                    {
                        $string = "because it's a SNAT with Interface IP address";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        continue;
                    }


                    if( $context->isAPI )
                        $objectRef->API_add($objToReplace);
                    else
                        $objectRef->addObject($objToReplace);

                    if( $context->isAPI )
                        $objectRef->API_remove($object, FALSE, $context);
                    else
                        $objectRef->remove($object, TRUE, FALSE, $context);
                }
                elseif( $class == 'NatRule' )
                {
                    /** @var NatRule $objectRef */
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

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
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
                $string = "it is not used in NAT rule";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            #PH::print_stdout( "name: ".$objectRef->name() );


            if( isset($objectRef->owner) && $objectRef->owner !== null )
            {
                $objRef_owner = $objectRef->owner;
                $class = get_class($objRef_owner);
                $class = strtolower($class);
                #PH::print_stdout( "CLASS: ".$class );
                if( $class != "natrule" )
                {
                    $string = "it is not used in NAT rule";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }

                PH::print_stdout();

                if( $objRef_owner->sourceNatIsEnabled() )
                {
                    //SNAT

                    $text = $context->padding . $objRef_owner->source->toString_inline()."";
                    $text .= " => ".$objRef_owner->snathosts->toString_inline()."";
                    PH::ACTIONlog( $context, $text );

                    $text = "";
                    foreach( $objRef_owner->source->members() as $key =>$member )
                    {
                        if( $object === $member )
                        {
                            if( $member->isAddress() )
                                $text .= $context->padding . PH::boldText( $member->value() );
                            else
                                $text .= $context->padding . "GROUP: ".$member->name()." missing IPv4";
                        }

                        else
                        {
                            if( $member->isAddress() )
                                $text .= $context->padding . $member->value();
                            else
                                $text .= $context->padding . "GROUP: ".$member->name()." missing IPv4";
                        }

                    }
                    foreach( $objRef_owner->snathosts->members() as $key => $member )
                    {
                        $text .= " => ";
                        if( $object === $member )
                            if( $member->isAddress() )
                                $text .= PH::boldText( $member->value() );
                            else
                                $text .= " GROUP: ".$member->name()." missing IPv4";
                        else
                        {
                            if( $member->isAddress() )
                                $text .= $member->value();
                            else
                                $text .= " GROUP: ".$member->name()." missing IPv4";
                        }
                    }


                    if( $objRef_owner->isBiDirectional() )
                    {
                        //Bidir
                        $text .= $context->padding . "rule is bidir-NAT";
                        $text .= $context->padding . "name: ".$objRef_owner->name();
                    }
                    PH::ACTIONlog( $context, $text );
                }
                elseif( $objRef_owner->destinationNatIsEnabled() )
                {
                    //DNAT

                    $text = $context->padding . $objRef_owner->destination->toString_inline()."";
                    $text .= " => ".$objRef_owner->dnathost->name()."";
                    PH::ACTIONlog( $context, $text );

                    $text = "";
                    foreach( $objRef_owner->destination->members() as $key => $member )
                    {
                        if( $object === $member )
                            $text .= $context->padding . PH::boldText( $member->value() );
                        else
                            $text .= $context->padding .  $member->value();
                    }
                    $text .= " => ";
                    $text .= $objRef_owner->dnathost->value();
                    PH::ACTIONlog( $context, $text );
                }
            }
        }
    },
);

AddressCallContext::$supportedActions['create-Address'] = array(
    'name' => 'create-address',
    'MainFunction' => function (AddressCallContext $context) {
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {

        $addressStore = $context->subSystem->addressStore;

        $newName = $context->arguments['name'];

        $value = $context->arguments['value'];
        $type = $context->arguments['type'];

        if( !in_array( $type, Address::$AddressTypes) )
        {
            $string = "Address named '" . $newName . "' cannot create as type: ".$type." is not allowed";
            PH::ACTIONlog( $context, $string );
            return;
        }

        /** @var Address $tmpAddress */
        $tmpAddress = $addressStore->find( $newName );
        if( $tmpAddress === null )
        {
            $string = "create Address object : '" . $newName . "'";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
                $addressStore->API_newAddress($newName, $type, $value);
            else
                $addressStore->newAddress( $newName, $type, $value);
        }
        else
        {
            if( $tmpAddress->isType_TMP() )
            {
                $prefix = array();
                $prefix['host'] = "";

                $prefix['network'] = "";
                $prefix['networkmask'] = "m";

                $prefix['range'] = "";
                $prefix['rangeseparator'] = "-";

                $tmpAddress->replaceIPbyObject( $context, $prefix );
            }
            else
            {
                $string = "Address named '" . $newName . "' already exists, cannot create";
                PH::ACTIONlog( $context, $string );
            }
        }

    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => '*nodefault*'),
        'value' => array('type' => 'string', 'default' => '*nodefault*'),
        'type' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'create-address-from-file',
    'GlobalInitFunction' => function(AddressCallContext $context){},
    'MainFunction' => function(AddressCallContext $context){},
    'GlobalFinishFunction' => function(AddressCallContext $context)
    {
        /*

        file syntax:
            AddressObjectName,IP-Address,Address-group

        example:
            h-192.168.0.1,192.168.0.1/32,private-network-AddressGroup
            n-192.168.2.0m24,192.168.2.0/24,private-network-AddressGroup

        */
        $create_addressGroup = false;
        $address_addressgroup = "";

        $object = $context->object;
        if( !is_object( $object ) )
        {
            derr( 'addressStore is empty - create first an address object via the Palo Alto Networks GUI' );
            #how to access the addressstore????
        }

        $addressStore = $object->owner;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents( $context->arguments['file'] );

            if( $text === false )
                derr("cannot open file '{$context->arguments['file']}");

            $lines = explode("\n", $text);
            foreach( $lines as  $line)
            {
                $line = trim($line);
                if(strlen($line) == 0)
                    continue;
                $list[$line] = true;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;


        if( count( $list ) == 0 )
            derr( 'called file: '.$context->arguments['file'].' is empty' );


        foreach( $list as $key => $item )
        {
            $create_addressGroup = false;

            $address_information = explode(",", $key);

            $address_name = $address_information[0];
            $address_value = $address_information[1];
            if( count($address_information) == 3 )
            {
                $create_addressGroup = true;
                $address_addressgroup = $address_information[2];

                $newAddressGroup = $addressStore->find( $address_addressgroup );

                if( $newAddressGroup == null )
                {
                    $string = $context->padding."- object: '{$address_addressgroup}'\n";
                    $string .= $context->padding.$context->padding." *** create addressgroup with name: '{$address_addressgroup}'\n";
                    PH::ACTIONlog( $context, $string );
                    if( $context->isAPI )
                        $addressStore->API_newAddressGroup( $address_addressgroup );
                    else
                        $addressStore->newAddressGroup( $address_addressgroup );
                }
                else
                {
                    $string = $context->padding . "- object: '{$address_addressgroup}'\n";
                    $string .= $context->padding . $context->padding . " *** SKIPPED addressgroup name: '{$address_addressgroup}' already available\n";
                    PH::ACTIONlog( $context, $string );
                    #maybe print out the members of the group
                }
            }


            $key = $address_value;

            $addressstring = "";
            $networkvalue = "";
            //VALIDATION for $key
            if( substr_count($key, '.') == 3 )
            {
                $testvalue = CIDR::stringToStartEnd( $key );
                $range = CIDR::range2network( $testvalue['start'], $testvalue['end'] );

                $networkvalue = long2ip( $range['network'] );
                $networkmask = $range['mask'];
                $addressstring = $range['string'];
            }
            elseif( strpos( $key, ":") !== false )
            {
                /*
                if( substr_count($key, '/') == 0 )
                    $key = $key."/64";

                $test = Ipv6_Prefix2Range( $key );
                if( $test === false )
                    print "FALSE\n";
                else
                {
                    print "TRUE\n";
                    print_r( $test );
                }
                */

                derr( "IPv6 addresses are not supported yet." );
            }
            else
                derr( "not a valid IPv4 or IPv6 address." );


            $new_address_name = $address_name;
            $new_address_value = $addressstring;

            $new_address = $addressStore->find( $new_address_name );
            if( $new_address == null )
            {
                $string = $context->padding."- object: '{$new_address_name}'\n";
                $string .= $context->padding.$context->padding." *** create addressobject with name: '{$new_address_name}' and value: '{$new_address_value}'\n";
                PH::ACTIONlog( $context, $string );

                if( $context->isAPI )
                    $newObj = $addressStore->API_newAddress( $new_address_name, 'ip-netmask', $new_address_value );
                else
                    $newObj = $addressStore->newAddress( $new_address_name, 'ip-netmask', $new_address_value );
            }
            else
            {
                if( $new_address->isType_TMP() )
                {
                    $prefix = array();
                    $prefix['host'] = "";

                    $prefix['network'] = "";
                    $prefix['networkmask'] = "m";

                    $prefix['range'] = "";
                    $prefix['rangeseparator'] = "-";

                    $new_address->replaceIPbyObject( $context, $prefix );
                }
                else
                {
                    $string = $context->padding."- object: '{$new_address_name}'\n";
                    $string .= $context->padding.$context->padding." *** SKIPPED creating; addressobject with name: '{$new_address_name}' already available. old-value: '{$new_address->value()}' - new-value:'{$new_address_value}'\n\n";
                    PH::ACTIONlog( $context, $string );

                    if( $new_address_value != $new_address->value() )
                    {
                        mwarning( "address value differ from existing address object: existing-value: '{$new_address->value()}' - new-value:'{$new_address_value}'\n", null, false);
                        continue;
                    }
                }

                $newObj = $new_address;
            }

            if( $create_addressGroup )
            {
                $newgrpObj = $addressStore->find( $address_addressgroup );
                if( $newgrpObj != null )
                {
                    if( $newgrpObj->has( $newObj ) == false )
                    {
                        $string = $context->padding.$context->padding." *** add addressobject with name: '{$new_address_name}' as member to addressgroup: '{$address_addressgroup}'\n\n";
                        PH::ACTIONlog( $context, $string );
                        if( $context->isAPI )
                            $newgrpObj->API_addMember( $newObj );
                        else
                            $newgrpObj->addMember( $newObj );
                    }
                }
                else
                {
                    $string = "addressgroup: ".$address_addressgroup." not available";
                    PH::ACTIONstatus( $context, 'SKIPPED', $string);
                }
            }
        }

    },
    'args' => Array(
        'file' => Array( 'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                "file syntax:   AddressObjectName,IP-Address,Address-group

example:
    h-192.168.0.1,192.168.0.1/32,private-network-AddressGroup
    n-192.168.2.0m24,192.168.2.0/24,private-network-AddressGroup\n"
        )
    ),
);

AddressCallContext::$supportedActions['create-AddressGroup'] = array(
    'name' => 'create-addressgroup',
    'MainFunction' => function (AddressCallContext $context) {
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {

        $addressStore = $context->subSystem->addressStore;

        $newName = $context->arguments['name'];


        if( $addressStore->find( $newName ) === null )
        {
            $string = "create AddressGroup object : '" . $newName . "'";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
                $addressStore->API_newAddressGroup($newName);
            else
                $addressStore->newAddressGroup( $newName);
        }
        else
        {
            $string = "AddressGroup named '" . $newName . "' already exists, cannot create";
            PH::ACTIONlog( $context, $string );
        }

    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions['move-range2network'] = array(
    'name' => 'move-range2network',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() || $object->isRegion() || !$object->isType_ipRange() )
        {
            $string = "Address object is not of type ip-range";
            PH::ACTIONstatus( $context, 'skipped', $string);
            return false;
        }


        $array = explode( "-", $object->value() );
        $start = ip2long( $array[0] );
        $end = ip2long( $array[1] );

        $range = CIDR::range2network( $start, $end );

        if( $range !== false )
        {
            //network' => $start, 'mask' => $netmask, 'string' => long2ip($start) . '/' . $netmask
            $object->setType( "ip-netmask" );
            $object->setValue( $range['string'] );

            if( $context->isAPI )
                $object->API_sync();
            $string = "moved to type ip-netmask with value: ".$range['string'];
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $string = "Address object of type ip-range named '" . $object->name() . "' cannot moved to an ip-netmask object type. value: ".$object->value();
            PH::ACTIONlog( $context, $string );
        }

    }
);