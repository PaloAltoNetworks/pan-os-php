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


ServiceCallContext::$supportedActions[] = array(
    'name' => 'delete',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding . "  * SKIPPED: this object is used by other objects and cannot be deleted (use deleteForce to try anyway)\n";
            return;
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'deleteForce',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        mwarning( 'this action "deleteForce" is deprecated, you should use "delete-Force" instead!' );

        if( $object->countReferences() != 0 )
            print $context->padding."  * WARNING : this object seems to be used so deletion may fail.\n";

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
    'deprecated' => 'this filter "secprof is.profile" is deprecated, you should use "secprof type.is.profile" instead!'
);

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'delete-Force',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0 )
            print $context->padding . "  * WARNING : this object seems to be used so deletion may fail.\n";

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
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
                print "     *  skipped because its used in unsupported class $class\n";
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
                    print $context->padding . " - adding in {$objectRef->toString()}\n";
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
            print $context->padding . " * replacing in {$objectRef->toString()}\n";
            if( $objectRef === $foundObject || $objectRef->name() == $foundObject->name() )
            {
                print $context->padding . "   - SKIPPED : cannot replace an object by itself\n";
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


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        $headers = '<th>location</th><th>name</th><th>type</th><th>dport</th><th>sport</th><th>timeout</th><th>members</th><th>description</th><th>tags</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

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

                $lines .= $encloseFunction(PH::getLocationString($object));

                $lines .= $encloseFunction($object->name());

                if( $object->isGroup() )
                {
                    $lines .= $encloseFunction('group');
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction($object->members());
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction($object->tags->tags());
                }
                elseif( $object->isService() )
                {
                    if( $object->isTmpSrv() )
                    {
                        $lines .= $encloseFunction('unknown');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                    }
                    else
                    {
                        if( $object->isTcp() )
                            $lines .= $encloseFunction('service-tcp');
                        else
                            $lines .= $encloseFunction('service-udp');

                        $lines .= $encloseFunction($object->getDestPort());
                        $lines .= $encloseFunction($object->getSourcePort());
                        $lines .= $encloseFunction($object->getTimeout());
                        $lines .= $encloseFunction('');
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
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n")
    )
);

// TODO replaceByApp with file list

ServiceCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
        {
            print $context->padding . "   * SKIPPED because this object is Tmp\n";
            return;
        }

        $localLocation = 'shared';

        if( !$object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            print $context->padding . "   * SKIPPED because original and target destinations are the same: $targetLocation\n";
            return;
        }

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $targetLocation == 'shared' )
        {
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
                        echo $context->padding . "   * SKIPPED : moving from SHARED to sub-level is NOT possible because of references\n";
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

            #print $context->padding."   * SKIPPED : moving between 2 VSYS/DG is not supported yet\n";
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
            if( $object->isGroup() )
            {
                foreach( $object->members() as $memberObject )
                    if( $targetStore->find($memberObject->name()) === null )
                    {
                        echo $context->padding . "   * SKIPPED : this group has an object named '{$memberObject->name()} that does not exist in target location '{$targetLocation}'\n";
                        return;
                    }
            }

            print $context->padding . "   * moved, no conflict\n";
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
            print $context->padding . "   * SKIPPED : there is an object with same name. Choose another mode to to resolve this conflict\n";
            return;
        }

        print $context->padding . "   - there is a conflict with an object of same name and type. Please use service-merger.php script with argument 'allowmergingwithupperlevel'";
        if( $conflictObject->isGroup() )
            print "Group\n";
        else
            print "Service\n";

        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            print $context->padding . "   * SKIPPED because conflict has mismatching types\n";
            return;
        }

        if( $conflictObject->isTmpSrv() && !$object->isTmpSrv() )
        {
            derr("unsupported situation with a temporary object");
            return;
        }

        if( $object->isGroup() )
        {
            if( $object->equals($conflictObject) )
            {
                print "    * Removed because target has same content\n";
                goto do_replace;
            }
            else
            {
                $object->displayValueDiff($conflictObject, 9);
                if( $context->arguments['mode'] == 'removeifmatch' )
                {
                    print $context->padding . "    * SKIPPED because of mismatching group content\n";
                    return;
                }

                $localMap = $object->dstPortMapping();
                $targetMap = $conflictObject->dstPortMapping();

                if( !$localMap->equals($targetMap) )
                {
                    print $context->padding . "    * SKIPPED because of mismatching group content and numerical values\n";
                    return;
                }

                print "    * Removed because it has same numerical value\n";

                goto do_replace;

            }
            return;
        }

        if( $object->equals($conflictObject) )
        {
            print "    * Removed because target has same content\n";
            goto do_replace;
        }

        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $localMap = $object->dstPortMapping();
        $targetMap = $conflictObject->dstPortMapping();

        if( !$localMap->equals($targetMap) )
        {
            print $context->padding . "    * SKIPPED because of mismatching content and numerical values\n";
            return;
        }

        print "    * Removed because target has same numerical value\n";

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
            print $context->padding." *** SKIPPED : this is not a group\n";
            return;
        }

        $object->replaceGroupbyService($context->padding);
    },
);

ServiceCallContext::$supportedActions[] = array(
    'name' => 'replaceByMembersAndDelete',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            print $context->padding."     *  skipped it's not a group\n";
            return;
        }

        $object->replaceByMembersAndDelete($context->padding, $context->isAPI);
        /*
                if( !$object->isGroup() )
                {
                    print $context->padding."     *  skipped it's not a group\n";
                    return;
                }


                $objectRefs = $object->getReferences();

                $clearForAction = true;
                foreach( $objectRefs as $objectRef )
                {
                    $class = get_class($objectRef);
                    if( $class != 'ServiceRuleContainer' && $class != 'ServiceGroup' )
                    {
                        $clearForAction = false;
                        print "     *  skipped because its used in unsupported class $class\n";
                        return;
                    }
                }
                if( $clearForAction )
                {
                    foreach ($objectRefs as $objectRef)
                    {
                        $class = get_class($objectRef);
                        if( $class == 'ServiceRuleContainer' )
                        {
                            /** @var ServiceRuleContainer $objectRef */
        /*
                print $context->padding."    - in Reference: {$objectRef->toString()}\n";
                foreach ($object->members() as $objectMember)
                {
                    print $context->padding."      - adding {$objectMember->name()}\n";
                    if( $context->isAPI )
                        $objectRef->API_add($objectMember);
                    else
                        $objectRef->add($objectMember);
                }
                if( $context->isAPI )
                    $objectRef->API_remove($object);
                else
                    $objectRef->remove($object);
            }
                        elseif( $class == 'ServiceGroup' )
        {
            */
        /** @var ServiceGroup $objectRef */

        /*
    print $context->padding."    - in Reference: {$objectRef->toString()}\n";
                        foreach ($object->members() as $objectMember)
                        {
                            print $context->padding."      - adding {$objectMember->name()}\n";
                            if( $context->isAPI )
                                $objectRef->API_addMember($objectMember);
                            else
                                $objectRef->addMember($objectMember);
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

ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $newName = $context->arguments['prefix'] . $object->name();
        print $context->padding . " - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            print " *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            print " *** SKIPPED : an object with same name already exists\n";
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
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $newName = $object->name() . $context->arguments['suffix'];
        print $context->padding . " - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            print " *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            print " *** SKIPPED : an object with same name already exists\n";
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
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

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

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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
ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;
        $suffix = $context->arguments['suffix'];

        if( $object->isTmpSrv() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( substr($object->name(), $suffixStartIndex, strlen($object->name())) != $suffix )
        {
            echo $context->padding . " *** SKIPPED : suffix not found\n";
            return;
        }
        $newName = substr($object->name(), 0, $suffixStartIndex);

        echo $context->padding . " - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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

ServiceCallContext::$supportedActions[] = array(
    'name' => 'name-Rename',
    'MainFunction' => function (ServiceCallContext $context) {
        $object = $context->object;

        if( $object->isTmpSrv() )
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
            "  - \$\$destinationport\$\$ : destination Port\n" .
            "  - \$\$protocol\$\$ : service protocol\n" .
            "  - \$\$sourceport\$\$ : source Port\n" .
            "  - \$\$value\$\$ : value of the object\n"
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
    'args' => array('search' => array(
        'type' => 'string',
        'default' => '*nodefault*'),
        'replace' => array(
            'type' => 'string',
            'default' => '*nodefault*')
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
        #PH::print_stdout( "     * " . get_class($object) . " '{$object->name()}'    " );
        if( $object->isGroup() )
        {
            PH::print_stdout( "     * " . get_class($object) . " '{$object->name()}'" );
            foreach( $object->members() as $member )
            {
                if( $member->isGroup() )
                    $tmp_txt = "          - {$member->name()}";
                else
                {
                    $tmp_txt = "          - {$member->name()}";
                    $tmp_txt .= "    value: '{$member->protocol()}/{$member->getDestPort()}'";

                    if( $member->description() != "" )
                        $tmp_txt .= "    desc: '{$member->description()}'";

                    if( $member->getSourcePort() != "" )
                        $tmp_txt .= "    sourceport: '" . $member->getSourcePort() . "'";

                    if( $member->getTimeout() != "" )
                        $tmp_txt .= "    timeout: '" . $member->getTimeout() . "'";

                    if( strpos($member->getDestPort(), ",") !== FALSE )
                    {
                        $tmp_txt .= "    count values: '" . (substr_count($member->getDestPort(), ",") + 1) . "' length: " . strlen($member->getDestPort());
                    }
                }
                PH::print_stdout( $tmp_txt );
            }
        }
        else
        {
            $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'     value: '{$object->protocol()}/{$object->getDestPort()}'";

            if( $object->description() != "" )
                $tmp_txt .= "    desc: '{$object->description()}'";

            if( $object->getSourcePort() != "" )
                $tmp_txt .= "    sourceport: '" . $object->getSourcePort() . "'";

            if( $object->getTimeout() != "" )
                $tmp_txt .= "    timeout: '" . $object->getTimeout() . "'";

            if( $object->getHalfcloseTimeout() != "" )
                $tmp_txt .= "    HalfcloseTimeout: '" . $object->getHalfcloseTimeout() . "'";

            if( $object->getTimewaitTimeout() != "" )
                $tmp_txt .= "    TimewaitTimeout: '" . $object->getTimewaitTimeout() . "'";

            if( strpos($object->getDestPort(), ",") !== FALSE )
            {
                $tmp_txt .= "    count values: '" . (substr_count($object->getDestPort(), ",") + 1) . "' length: " . strlen($object->getDestPort());
            }

            PH::print_stdout( $tmp_txt );
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

ServiceCallContext::$supportedActions[] = array(
    'name' => 'description-Append',
    'MainFunction' => function (ServiceCallContext $context) {
        $service = $context->object;
        if( $service->isGroup() )
        {
            echo $context->padding . " *** SKIPPED : a service group has no description\n";
            return;
        }
        if( $service->isTmpSrv() )
        {
            echo $context->padding . " *** SKIPPED : object is tmp\n";
            return;
        }
        $description = $service->description();

        $textToAppend = "";
        if( $description != "" )
            $textToAppend = " ";
        $textToAppend .= $context->rawArguments['text'];

        if( $context->object->owner->owner->version < 71 )
            $max_length = 253;
        else
            $max_length = 1020;

        if( strlen($description) + strlen($textToAppend) > $max_length )
        {
            echo $context->padding . " - SKIPPED : resulting description is too long\n";
            return;
        }

        echo $context->padding . " - new description will be: '{$description}{$textToAppend}' ... ";

        if( $context->isAPI )
            $service->API_setDescription($description . $textToAppend);
        else
            $service->setDescription($description . $textToAppend);

        echo "OK";
    },
    'args' => array('text' => array('type' => 'string', 'default' => '*nodefault*'))
);
ServiceCallContext::$supportedActions[] = array(
    'name' => 'description-Delete',
    'MainFunction' => function (ServiceCallContext $context) {
        $service = $context->object;

        if( $service->isGroup() )
        {
            echo $context->padding . " *** SKIPPED : a service group has no description\n";
            return;
        }
        if( $service->isTmpSrv() )
        {
            echo $context->padding . " *** SKIPPED : object is tmp\n";
            return;
        }
        $description = $service->description();
        if( $description == "" )
        {
            echo $context->padding . " *** SKIPPED : no description available\n";
            return;
        }

        echo $context->padding . " - new description will be: '' ... ";

        if( $context->isAPI )
            $service->API_setDescription("");
        else
            $service->setDescription("");

        echo "OK";
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
            print "     *  skipped because object is ServiceGroup\n";
            return null;
        }

        $tmp_timeout = $object->getTimeout();

        if( $tmp_timeout != $newTimeout )
        {
            if( $context->isAPI )
                $object->API_setTimeout($newTimeout);
            else
                $object->setTimeout($newTimeout);
            echo "OK";
        }


    },
    'args' => array('timeoutValue' => array('type' => 'string', 'default' => '*nodefault*')),
);

