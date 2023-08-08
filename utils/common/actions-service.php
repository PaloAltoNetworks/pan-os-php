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


ServiceCallContext::$supportedActions[] = array(
    'name' => 'delete',
    'MainFunction' => function (ServiceCallContext $context) {
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

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'delete-Force',
    'MainFunction' => function ( ServiceCallContext $context ) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus($context, "WARNING", $string);
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'decommission',
    'MainFunction' => function (ServiceCallContext $context) {
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

ServiceCallContext::$supportedActions[] = array(
    'name' => 'addObjectWhereUsed',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'ServiceRuleContainer' && $class != 'ServiceGroup' )
            {
                $clearForAction = FALSE;
                $string = "because its used in unsupported class $class";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                break;
            }
        }
        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);
                if( $class == 'ServiceRuleContainer' || $class == 'ServiceGroup' )
                {
                    $string = "adding in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    if( $context->isAPI )
                        $objectRef->API_add($foundObject);
                    else
                        $objectRef->add($foundObject);
                }
                else
                {
                    derr('unsupported class');
                }

            }
        }
    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*')),
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'replaceWithObject',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        /** @var ServiceGroup|ServiceRuleContainer $objectRef */

        foreach( $objectRefs as $objectRef )
        {
            $string = "replacing in {$objectRef->toString()}";
            PH::ACTIONlog( $context, $string );

            if( $objectRef === $foundObject || $objectRef->name() == $foundObject->name() )
            {
                $string = "cannot replace an object by itself";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                continue;
            }
            if( $context->isAPI )
                $objectRef->API_replaceReferencedObject($object, $foundObject);
            else
                $objectRef->replaceReferencedObject($object, $foundObject);
        }

    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*')),
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (ServiceCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (ServiceCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addResolveGroupSRVCoverage = FALSE;
        $addNestedMembers = FALSE;
        $addResolveSRVNestedMembers = FALSE;
        $addNestedMembersCount = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;

        if( isset($optionalFields['ResolveSRV']) )
            $addResolveGroupSRVCoverage = TRUE;

        if( isset($optionalFields['NestedMembers']) )
        {
            $addNestedMembers = TRUE;
            $addResolveSRVNestedMembers = TRUE;
            $addNestedMembersCount = TRUE;
        }

        $headers = '<th>ID</th><th>location</th><th>name</th><th>type</th><th>dport</th><th>sport</th><th>timeout</th><th>members</th><th>members count</th><th>description</th><th>tags</th>';

        $headers .= '<th>port.count</th><th>port.tcp.count</th><th>port.udp.count</th>';
        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addResolveGroupSRVCoverage )
            $headers .= '<th>srv resolution</th>';
        if( $addNestedMembers )
            $headers .= '<th>nested members</th>';
        if( $addResolveSRVNestedMembers )
            $headers .= '<th>nested members srv resolution</th>';
        if( $addNestedMembersCount )
            $headers .= '<th>nested members count</th>';

        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Service|ServiceGroup $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                $lines .= $context->encloseFunction(PH::getLocationString($object));

                $lines .= $context->encloseFunction($object->name());

                if( $object->isGroup() )
                {
                    $lines .= $context->encloseFunction('group');
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction($object->members());
                    $lines .= $context->encloseFunction( (string)count( $object->members() ));
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction($object->tags->tags());
                }
                elseif( $object->isService() )
                {
                    if( $object->isTmpSrv() )
                    {
                        if( $object->name() == "service-http" )
                        {
                            $lines .= $context->encloseFunction('service-tcp');
                            $lines .= $context->encloseFunction('40');
                        }
                        elseif( $object->name() == "service-https" )
                        {
                            $lines .= $context->encloseFunction('service-tcp');
                            $lines .= $context->encloseFunction('443');
                        }
                        else
                        {
                            $lines .= $context->encloseFunction('unknown');
                            $lines .= $context->encloseFunction('');
                        }


                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction( '---' );
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                    }
                    else
                    {
                        if( $object->isTcp() )
                            $lines .= $context->encloseFunction('service-tcp');
                        else
                            $lines .= $context->encloseFunction('service-udp');

                        $lines .= $context->encloseFunction($object->getDestPort());
                        $lines .= $context->encloseFunction($object->getSourcePort());
                        $lines .= $context->encloseFunction($object->getTimeout());
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction( '---' );
                        $lines .= $context->encloseFunction($object->description(), FALSE);
                        $lines .= $context->encloseFunction($object->tags->tags());
                    }
                }

                $calculatedCounter = $context->ServiceCount( $object, "both" );
                $lines .= $context->encloseFunction((string)$calculatedCounter);

                $calculatedCounter = $context->ServiceCount( $object, "tcp" );
                $lines .= $context->encloseFunction((string)$calculatedCounter);

                $calculatedCounter = $context->ServiceCount( $object, "udp" );
                $lines .= $context->encloseFunction((string)$calculatedCounter);


                if( $addWhereUsed )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $context->encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $context->encloseFunction($refTextArray);
                }
                if( $addResolveGroupSRVCoverage )
                {
                    $port_mapping_text = array();
                    $mapping_text_array = array();

                    $port_mapping = $object->dstPortMapping();
                    $mapping_texts = $port_mapping->mappingToText();

                    //TODO: handle predefined service objects in a different way
                    if( $object->name() == 'service-http' )
                        $mapping_texts = 'tcp/80';
                    if( $object->name() == 'service-https' )
                        $mapping_texts = 'tcp/443';


                    if( strpos($mapping_texts, " ") !== FALSE )
                        $mapping_text_array = explode(" ", $mapping_texts);
                    else
                        $mapping_text_array[] = $mapping_texts;


                    $protocol = "tmp";
                    foreach( $mapping_text_array as $mapping_text )
                    {
                        if( strpos($mapping_text, "tcp/") !== FALSE )
                            $protocol = "tcp/";
                        elseif( strpos($mapping_text, "udp/") !== FALSE )
                            $protocol = "udp/";

                        $mapping_text = str_replace($protocol, "", $mapping_text);
                        $mapping_text = explode(",", $mapping_text);

                        foreach( $mapping_text as $mapping )
                        {
                            if( !in_array( $protocol . $mapping, $port_mapping_text ) )
                            {
                                $port_mapping_text[$protocol . $mapping] = $protocol . $mapping;

                                if( strpos($mapping, "-") !== FALSE )
                                {
                                    $array[$protocol . $mapping] = $protocol . $mapping;
                                    $range = explode("-", $mapping);
                                    for( $i = $range[0]; $i <= $range[1]; $i++ )
                                        $array[$protocol . $i] = $protocol . $i;
                                }
                                else
                                    $array[$protocol . $mapping] = $protocol . $mapping;
                            }
                        }
                    }

                    $lines .= $context->encloseFunction($port_mapping_text);
                }

                if( $addNestedMembers )
                {
                    if( $object->isGroup() )
                    {
                        $members = $object->expand(FALSE);
                        $lines .= $context->encloseFunction($members);
                    }
                    else
                        $lines .= $context->encloseFunction('');
                }
                if( $addResolveSRVNestedMembers )
                {
                    if( $object->isGroup() )
                    {   $resolve = array();
                        $members = $object->expand(FALSE);
                        foreach( $members as $member )
                        {
                            $srcport = "";
                            if( $member->getSourcePort() !== "" )
                                $srcport = "srcp:".$member->getSourcePort();
                            $resolve[] = $member->protocol()."/".$member->getDestPort().$srcport;
                        }

                        $lines .= $context->encloseFunction($resolve);
                    }
                    else
                        $lines .= $context->encloseFunction('');
                }
                if( $addNestedMembersCount )
                {
                    if( $object->isGroup() )
                    {   $resolve = array();
                        $members = $object->expand(FALSE);
                        $lines .= $context->encloseFunction( (string)count($members) );
                    }
                    else
                        $lines .= $context->encloseFunction('');
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
                'choices' => array('WhereUsed', 'UsedInLocation', 'ResolveSRV', 'NestedMembers'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n".
                    "  - NestedMembers: lists all members, even the ones that may be included in nested groups\n" .
                    "  - ResolveSRV\n"

            )
    )
);

// TODO replaceByApp with file list

ServiceCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
        {
            $string = "because this object is Tmp";
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
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $rootObject->serviceStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->serviceStore;
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
                        $string = "moving from SHARED to sub-level is NOT possible because of references";
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
            if( $object->isGroup() )
            {
                foreach( $object->members() as $memberObject )
                    if( $targetStore->find($memberObject->name(), null, true) === null )
                    {
                        $string = "this group has an object named '{$memberObject->name()} that does not exist in target location '{$targetLocation}'";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
            }

            //validation if upper/lower level is not changed
            $tmplocalSub = $rootObject->findSubSystemByName($localLocation);
            if( $tmplocalSub->isPanorama() )
            {
                /** @var PanoramaConf $tmplocalSub */
                $tmpChildSubs = $tmplocalSub->deviceGroups;
            }
            else
                $tmpChildSubs = $tmplocalSub->childDeviceGroups();
            $lowerLevelMove = false;
            foreach( $tmpChildSubs as $childDG )
            {
                if( $targetLocation == $childDG->name() )
                    $lowerLevelMove = true;
            }

            if( !$lowerLevelMove )
            {
                $startLocation = $tmplocalSub;
                $endLocation = $findSubSystem;
            }
            else
            {
                $endLocation = $tmplocalSub;
                $startLocation = $findSubSystem;
            }
            $skipped = FALSE;
            do
            {
                if( !isset($startLocation->parentDeviceGroup->serviceStore) )
                    break;

                $tmpObject = $startLocation->parentDeviceGroup->serviceStore->find($object->name(), null, FALSE);
                if( $tmpObject != null )
                {
                    if( ($object->isGroup() and !$tmpObject->isGroup()) || (!$object->isGroup() and $tmpObject->isGroup()) )
                        $skipped = TRUE;
                    elseif( $object->protocol() != $tmpObject->protocol() )
                        $skipped = TRUE;
                    elseif( $object->getDestPort() != $tmpObject->getDestPort() || $object->getSourcePort() != $tmpObject->getSourcePort() )
                        $skipped = TRUE;
                }

                if( !$skipped )
                    $startLocation = $startLocation->parentDeviceGroup;
                else
                {
                    if( !$lowerLevelMove )
                        $string = "moving to upper level DG is not possible because of object available at lower DG level with same name but different object type or value";
                    else
                        $string = "moving to lower level DG is not possible because of object available at upper DG level with same name but different object type or value";
                    PH::ACTIONstatus($context, "SKIPPED", $string);
                    return;
                }
            } while( $startLocation != $endLocation );

            ///////////////////////////////


            $string =  "   * moved, no conflict";
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
            $string = "there is an object with same name. Choose another mode to to resolve this conflict";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . "   - there is a conflict with an object of same name and type. Please use service-merger.php script with argument 'allowmergingwithupperlevel'";
        if( $conflictObject->isGroup() )
            $text .= "Group";
        else
            $text .= "Service";
        PH::ACTIONlog( $context, $text );

        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            $string = "because conflict has mismatching types";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $conflictObject->isTmpSrv() && !$object->isTmpSrv() )
        {
            derr("unsupported situation with a temporary object");
            return;
        }

        if( $object->isGroup() )
        {
            $localMap = $object->dstPortMapping();
            $targetMap = $conflictObject->dstPortMapping();

            if( $object->equals($conflictObject) && $localMap->equals($targetMap) )
            {
                $string = "Removed because target has same content";
                PH::ACTIONlog( $context, $string );

                goto do_replace;
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

                goto do_replace;

            }
            return;
        }

        if( $object->equals($conflictObject) )
        {
            $string = "Removed because target has same content";
            PH::ACTIONlog( $context, $string );

            goto do_replace;
        }

        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $localMap = $object->dstPortMapping();
        $targetMap = $conflictObject->dstPortMapping();

        if( !$localMap->equals($targetMap) )
        {
            $string = "because of mismatching content and numerical values";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "Removed because target has same numerical value";
        PH::ACTIONlog( $context, $string );

        do_replace:

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

ServiceCallContext::$supportedActions[] = array(
    'name' => 'removeWhereUsed',
    'MainFunction' => function (ServiceCallContext $context) {
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

ServiceCallContext::$supportedActions[] = array(
    'name' => 'replaceGroupByService',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $context->isAPI )
            derr("action 'replaceGroupByService' is not support in API/online mode yet");

        if( $object->isService() )
        {
            $string = "this is not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object->replaceGroupbyService( $context );
    },
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'replaceByMembersAndDelete',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            $string = "this is not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object->replaceByMembersAndDelete($context, $context->isAPI);
    },
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
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

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
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

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $prefix = $context->arguments['prefix'];

        if( $object->isTmpSrv() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

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

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $suffix = $context->arguments['suffix'];

        if( $object->isTmpSrv() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

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

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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

ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-Rename',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
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

        if( strpos($newName, '$$protocol$$') !== FALSE )
        {
            $newName = str_replace('$$protocol$$', $object->protocol(), $newName);
        }
        if( strpos($newName, '$$destinationport$$') !== FALSE )
        {
            $newName = str_replace('$$destinationport$$', $object->getDestPort(), $newName);
        }
        if( strpos($newName, '$$sourceport$$') !== FALSE )
        {
            $newName = str_replace('$$sourceport$$', $object->getSourcePort(), $newName);
        }
        if( strpos($newName, '$$timeout$$') !== FALSE )
        {
            $newName = str_replace('$$timeout$$', $object->getTimeout(), $newName);
        }


        if( $object->name() == $newName )
        {
            $string = "new name and old name are the same";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $max_length = 63;
        if( strlen($newName) > $max_length )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $newName = str_replace(",", "_", $newName);

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
            $string = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $string );
        }

    },
    'args' => array('stringFormula' => array(
        'type' => 'string',
        'default' => '*nodefault*',
        'help' =>
            "This string is used to compose a name. You can use the following aliases :\n" .
            "  - \$\$current.name\$\$ : current name of the object\n" .
            "  - \$\$destinationport\$\$ : destination Port\n" .
            "  - \$\$protocol\$\$ : service protocol\n" .
            "  - \$\$sourceport\$\$ : source Port\n" .
            "  - \$\$value\$\$ : value of the object\n" .
            "  - \$\$timeout\$\$ : timeout value of the object\n"
    )
    ),
    'help' => ''
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-Replace-Character',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
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
            $string = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $string );
        }

    },
    'args' => array('search' => array(
        'type' => 'string',
        'default' => '*nodefault*'),
        'replace' => array(
            'type' => 'string',
            'default' => '')
    ),
    'help' => ''
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'display',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);


        if( $object->isGroup() )
        {
            PH::print_stdout( "     * " . get_class($object) . " '{$object->name()}'" );
            foreach( $object->members() as $member )
            {
                PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['name'] = $member->name();

                if( $member->isGroup() )
                    $tmp_txt = "          - {$member->name()}";
                else
                {
                    $tmp_txt = "          - {$member->name()}";
                    $tmp_txt .= "    value: '{$member->protocol()}/{$member->getDestPort()}'";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['value'] = "{$member->protocol()}/{$member->getDestPort()}";

                    if( $member->description() != "" )
                        $tmp_txt .= "    desc: '{$member->description()}'";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['description'] = $member->description();

                    if( $member->getSourcePort() != "" )
                        $tmp_txt .= "    sourceport: '" . $member->getSourcePort() . "'";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['sourceport'] = $member->getSourcePort();


                    if( $member->getTimeout() != "" )
                        $tmp_txt .= "    timeout: '" . $member->getTimeout() . "'";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['timeout'] = $member->getTimeout();

                    if( $member->getHalfcloseTimeout() != "" )
                        $tmp_txt .= "    HalfcloseTimeout: '" . $member->getHalfcloseTimeout() . "'";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['halfclosetimeout'] = $member->getHalfcloseTimeout();

                    if( $member->getTimewaitTimeout() != "" )
                        $tmp_txt .= "    TimewaitTimeout: '" . $member->getTimewaitTimeout() . "'";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['timewaittimeout'] = $member->getTimewaitTimeout();

                    if( strpos($member->getDestPort(), ",") !== FALSE )
                        $tmp_txt .= "    count values: '" . (substr_count($member->getDestPort(), ",") + 1) . "' length: " . strlen($member->getDestPort());
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['count values'] = (substr_count($member->getDestPort(), ",") + 1);
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['string legth'] = strlen($member->getDestPort());
                }
                PH::print_stdout( $tmp_txt );
            }
        }
        else
        {
            $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'     value: '{$object->protocol()}/{$object->getDestPort()}'";
            PH::$JSON_TMP['sub']['object'][$object->name()]['value'] = "{$object->protocol()}/{$object->getDestPort()}";

            if( $object->description() != "" )
                $tmp_txt .= "    desc: '{$object->description()}'";
            PH::$JSON_TMP['sub']['object'][$object->name()]['description'] = $object->description();

            if( $object->getSourcePort() != "" )
                $tmp_txt .= "    sourceport: '" . $object->getSourcePort() . "'";
            PH::$JSON_TMP['sub']['object'][$object->name()]['sourceport'] = $object->getSourcePort();

            if( $object->getTimeout() != "" )
                $tmp_txt .= "    timeout: '" . $object->getTimeout() . "'";
            PH::$JSON_TMP['sub']['object'][$object->name()]['timeout'] = $object->getTimeout();

            if( $object->getHalfcloseTimeout() != "" )
                $tmp_txt .= "    HalfcloseTimeout: '" . $object->getHalfcloseTimeout() . "'";
            PH::$JSON_TMP['sub']['object'][$object->name()]['halfclosetimeout'] = $object->getHalfcloseTimeout();

            if( $object->getTimewaitTimeout() != "" )
                $tmp_txt .= "    TimewaitTimeout: '" . $object->getTimewaitTimeout() . "'";
            PH::$JSON_TMP['sub']['object'][$object->name()]['timewaittimeout'] = $object->getTimewaitTimeout();

            if( strpos($object->getDestPort(), ",") !== FALSE )
                $tmp_txt .= "    count values: '" . (substr_count($object->getDestPort(), ",") + 1) . "' length: " . strlen($object->getDestPort());
            PH::$JSON_TMP['sub']['object'][$object->name()]['count values'] = (substr_count($object->getDestPort(), ",") + 1);
            PH::$JSON_TMP['sub']['object'][$object->name()]['string legth'] = strlen($object->getDestPort());

            PH::print_stdout( $tmp_txt );
        }

        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
        }
    },
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'tag-Add',
    'section' => 'tag',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'tag-Add-Force',
    'section' => 'tag',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove',
    'section' => 'tag',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove-All',
    'section' => 'tag',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        foreach( $object->tags->tags() as $tag )
        {
            $string = $context->padding . "  - removing tag {$tag->name()}... ";
            if( $context->isAPI )
                $object->tags->API_removeTag($tag);
            else
                $object->tags->removeTag($tag);

            PH::ACTIONlog( $context, $string );
        }
    },
    //'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove-Regex',
    'section' => 'tag',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $pattern = '/' . $context->arguments['regex'] . '/';
        foreach( $object->tags->tags() as $tag )
        {
            $result = preg_match($pattern, $tag->name());
            if( $result === FALSE )
                derr("'$pattern' is not a valid regex");
            if( $result == 1 )
            {
                $string = $context->padding . "  - removing tag {$tag->name()}... ";
                if( $context->isAPI )
                    $object->tags->API_removeTag($tag);
                else
                    $object->tags->removeTag($tag);

                PH::ACTIONlog( $context, $string );
            }
        }
    },
    'args' => array('regex' => array('type' => 'string', 'default' => '*nodefault*')),
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'description-Append',
    'MainFunction' => function (ServiceCallContext $context) {
        $service = $context->object;
        if( $service->isGroup() )
        {
            $string = "a service group has no description";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $service->isTmpSrv() )
        {
            $string = "object is tmp" ;
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $description = $service->description();

        $textToAppend = "";
        if( $description != "" )
            $textToAppend = " ";

        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $textToAppend .= str_replace('$$current.name$$', $service->name(), $newName);
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
            $service->API_setDescription($description . $textToAppend);
        else
            $service->setDescription($description . $textToAppend);
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'description-Delete',
    'MainFunction' => function (ServiceCallContext $context) {
        $service = $context->object;

        if( $service->isGroup() )
        {
            $string = "a service group has no description";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $service->isTmpSrv() )
        {
            $string = "object is tmp";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $description = $service->description();
        if( $description == "" )
        {
            $string = "no description available";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new description will be: '' ... ";

        if( $context->isAPI )
            $service->API_setDescription("");
        else
            $service->setDescription("");
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    },
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'timeout-set',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $newTimeout = $context->arguments['timeoutValue'];
        $newTimeout = intval($newTimeout);

        $class = get_class($object);
        if( $class === 'ServiceGroup' )
        {
            $string = "because object is ServiceGroup";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return null;
        }

        $tmp_timeout = $object->getTimeout();

        if( $tmp_timeout != $newTimeout )
        {
            if( $context->isAPI )
                $object->API_setTimeout($newTimeout);
            else
                $object->setTimeout($newTimeout);
        }
    },
    'args' => array('timeoutValue' => array('type' => 'string', 'default' => '*nodefault*')),
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'timeout-halfclose-set',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $newTimeout = $context->arguments['timeoutValue'];
        $newTimeout = intval($newTimeout);

        $class = get_class($object);
        if( $class === 'ServiceGroup' )
        {
            $string = "because object is ServiceGroup";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return null;
        }

        $tmp_timeout = $object->getTimeout();

        if( $tmp_timeout != $newTimeout )
        {
            if( $context->isAPI )
                $object->API_setHalfCloseTimeout($newTimeout);
            else
                $object->setHalfCloseTimeout($newTimeout);
        }
    },
    'args' => array('timeoutValue' => array('type' => 'string', 'default' => '*nodefault*')),
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'timeout-timewait-set',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $newTimeout = $context->arguments['timeoutValue'];
        $newTimeout = intval($newTimeout);

        $class = get_class($object);
        if( $class === 'ServiceGroup' )
        {
            $string = "because object is ServiceGroup";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return null;
        }

        $tmp_timeout = $object->getTimeout();

        if( $tmp_timeout != $newTimeout )
        {
            if( $context->isAPI )
                $object->API_setTimeWaitTimeout($newTimeout);
            else
                $object->setTimeWaitTimeout($newTimeout);
        }
    },
    'args' => array('timeoutValue' => array('type' => 'string', 'default' => '*nodefault*')),
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'timeout-inherit',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        $class = get_class($object);
        if( $class === 'ServiceGroup' )
        {
            $string = "because object is ServiceGroup";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return null;
        }
        if( $object->isTmpSrv() )
        {
            $string = "because object is TMP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return null;
        }

        if( $object->overrideroot !== FALSE )
        {
            $override_noyes = DH::findFirstElement('yes', $object->overrideroot);
            if( $override_noyes !== FALSE )
            {
                if( $context->isAPI )
                    $ret = $object->API_removeTimeout();
                else
                    $ret = $object->removeTimeout();

                if( !$ret )
                {
                    $string = "because timeout is not set";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return null;
                }
                else
                {
                    $string = "timeout removed - now inherit from application";
                    PH::ACTIONlog( $context, $string );
                }
            }
        }
    }
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'sourceport-set',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $newSourcePort = $context->arguments['sourceportValue'];

        $class = get_class($object);
        if( $class === 'ServiceGroup' )
        {
            $string = "because object is ServiceGroup";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return null;
        }

        $tmp_sourceport = $object->getSourcePort();

        if( $tmp_sourceport != $newSourcePort )
        {
            if( $context->isAPI )
                $object->API_setSourcePort($newSourcePort);
            else
                $object->setSourcePort($newSourcePort);
        }
    },
    'args' => array('sourceportValue' => array('type' => 'string', 'default' => '*nodefault*')),
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'sourceport-delete',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        $class = get_class($object);
        if( $class === 'ServiceGroup' )
        {
            $string = "because object is ServiceGroup";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return null;
        }

        if( $context->isAPI )
            $object->API_setSourcePort("");
        else
            $object->setSourcePort("");
    }
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'show-dstportmapping',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        $tmp_array = array();
        $tmp_array[] = $object;
        $dst_port_mapping = new ServiceDstPortMapping();
        $dst_port_mapping->mergeWithArrayOfServiceObjects( $tmp_array);

        $dst_port_mapping->countPortmapping();

        if( count( $dst_port_mapping->tcpPortMap ) > 0 )
        {
            $string = str_replace( "tcp/", "", $dst_port_mapping->tcpMappingToText());
            PH::print_stdout( $context->padding."  TCP: ".$string );
            PH::print_stdout( $context->padding."  TCP-counter: ".$dst_port_mapping->tcpPortCounter );
        }

        if( count( $dst_port_mapping->udpPortMap ) > 0 )
        {
            $string = str_replace( "udp/", "", $dst_port_mapping->udpMappingToText());
            PH::print_stdout( $context->padding."  UDP: ".$string );
            PH::print_stdout( $context->padding."  UDP-counter: ".$dst_port_mapping->udpPortCounter );
        }

    }
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'create-service',
    'MainFunction' => function (ServiceCallContext $context) {
    },
    'GlobalFinishFunction' => function (ServiceCallContext $context) {
        $serviceStore = $context->subSystem->serviceStore;

        $newName = $context->arguments['name'];

        $protocol = $context->arguments['protocol'];
        $port = $context->arguments['port'];
        $sport = $context->arguments['sport'];

        if( $protocol !== "tcp" && $protocol !== "udp" )
        {
            $string = "Service named '" . $newName . "' cannot create as protool: ".$protocol." is not allowed";
            PH::ACTIONlog( $context, $string );
            return;
        }

        if( $serviceStore->find( $newName, null, false ) === null )
        {
            $string = "create Service object : '" . $newName . "'";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
            {
                if( $sport !== "*nodefault*" )
                    $serviceStore->API_newService( $newName, $protocol, $port, $sport );
                else
                    $serviceStore->API_newService( $newName, $protocol, $port );
            }
            else
            {
                if( $sport !== "*nodefault*" )
                    $serviceStore->newService( $newName, $protocol, $port, $sport );
                else
                    $serviceStore->newService( $newName, $protocol, $port);
            }
        }
        else
        {
            $string = "Service named '" . $newName . "' already exists, cannot create";
            PH::ACTIONlog( $context, $string );
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => '*nodefault*'),
        'protocol' => array('type' => 'string', 'default' => '*nodefault*'),
        'port' => array('type' => 'string', 'default' => '*nodefault*'),
        'sport' => array('type' => 'string', 'default' => '*nodefault*'),
    )
);

ServiceCallContext::$supportedActions['create-ServiceGroup'] = array(
    'name' => 'create-servicegroup',
    'MainFunction' => function (ServiceCallContext $context) {
    },
    'GlobalFinishFunction' => function (ServiceCallContext $context) {

        $serviceStore = $context->subSystem->serviceStore;

        $newName = $context->arguments['name'];


        if( $serviceStore->find( $newName ) === null )
        {
            $string = "create ServiceGroup object : '" . $newName . "'";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
                $serviceStore->API_newServiceGroup($newName);
            else
                $serviceStore->newServiceGroup( $newName);
        }
        else
        {
            $string = "ServiceGroup named '" . $newName . "' already exists, cannot create";
            PH::ACTIONlog( $context, $string );
        }

    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

//starting with 7.0 PAN-OS support max. 2500 members per group, but if any service with timeout is available only 128 members
ServiceCallContext::$supportedActions[] = array(
    'name' => 'split-large-service-groups',
    'MainFunction' => function (ServiceCallContext $context) {
        $largeGroupsCount = $context->arguments['largeGroupsCount'];
        $splitCount = $largeGroupsCount - 1;

        $group = $context->object;


        if( $group->isGroup() )
        {
            $membersCount = $group->count();

            // if this group has more members than $largeGroupsCount then we must split it
            if( $membersCount > $largeGroupsCount )
            {
                $string = "ServiceGroup named '" . $group->name() . "' with $membersCount members";
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
                            $newGroup = $group->owner->API_newServiceGroup($group->name() . '--' . ($i / $splitCount));
                        else
                            $newGroup = $group->owner->newServiceGroup($group->name() . '--' . ($i / $splitCount));
                        $string = "New ServiceGroup object created with name: " . $newGroup->name();
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

                $string = "ServiceGroup count after split: " . $group->count();
                PH::ACTIONlog( $context, $string );
                PH::print_stdout();
            }
            else
            {

                $string = "SERVICE GROUP members count is smaller as largeGroupsCount argument is set: " . $largeGroupsCount;
                PH::ACTIONstatus( $context, "SKIPPED", $string );
            }
        }
        else
        {
            $string = "service object is not a SERVICE GROUP.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
        }


    },
    'args' => array('largeGroupsCount' => array('type' => 'string', 'default' => '2490')
    )
);