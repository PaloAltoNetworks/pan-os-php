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

ScheduleCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use deleteForce to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
        {
            derr("action delete via API not available yet");
            # $object->owner->API_removeZone($object);
        }
        else
        {
            derr("action delete not available yet");
            #$object->owner->removeZone($object);
        }
    },
);

ScheduleCallContext::$supportedActions['deleteforce'] = array(
    'name' => 'deleteForce',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus( $context, "WARNING", $string );
        }
        if( $context->isAPI )
        {
            derr("action delete via API not available yet");
            # $object->owner->API_removeZone($object);
        }
        else
        {
            derr("action delete not available yet");
            #$object->owner->removeZone($object);
        }
    },
);


ScheduleCallContext::$supportedActions['name-addprefix'] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $newName = $context->arguments['prefix'] . $object->name();

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = " - new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 127 )
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
ScheduleCallContext::$supportedActions['name-addsuffix'] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $newName = $object->name() . $context->arguments['suffix'];

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = " - new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 127 )
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
ScheduleCallContext::$supportedActions['name-removeprefix'] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $prefix = $context->arguments['prefix'];

        if( $object->isTmp() )
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

        $string = " - new name will be '{$newName}'";
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
ScheduleCallContext::$supportedActions['name-removesuffix'] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( substr($object->name(), $suffixStartIndex, strlen($object->name())) != $suffix )
        {
            $string = "suffix not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $newName = substr($object->name(), 0, $suffixStartIndex);

        $string = " - new name will be '{$newName}'";
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

ScheduleCallContext::$supportedActions['name-touppercase'] = array(
    'name' => 'name-toUpperCase',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtoupper($object->name(), 'UTF8');

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = " - new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            $string = "object is already uppercase";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

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
    }
);
ScheduleCallContext::$supportedActions['name-tolowercase'] = array(
    'name' => 'name-toLowerCase',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower($object->name(), 'UTF8');

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            return;
        }

        $string = " - new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            $string = "object is already lowercase";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

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
    }
);
ScheduleCallContext::$supportedActions['name-toucwords'] = array(
    'name' => 'name-toUCWords',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower($object->name(), 'UTF8');
        $newName = ucwords($newName);

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = " - new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            $string = "object is already UCword";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

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
    }
);

ScheduleCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

ScheduleCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'  ";

        PH::print_stdout( $tmp_txt );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);


        $tmp_array = $object->getRecurring();

        if( isset($tmp_array['daily']) )
        {
            PH::print_stdout( $context->padding . "  daily:");
            foreach( $tmp_array['daily'] as $entry )
            {
                $string = $entry['start']."-".$entry['end'];
                PH::print_stdout( $context->padding . "   - ".$string );
                PH::$JSON_TMP['sub']['object'][$object->name()]['daily'][$string]['start'] = $entry['start'];
                PH::$JSON_TMP['sub']['object'][$object->name()]['daily'][$string]['end'] = $entry['end'];
            }
        }

        if( isset($tmp_array['weekly']) )
        {
            PH::print_stdout( $context->padding . "  weekly:");
            foreach( $tmp_array['weekly'] as $key => $entry )
            {
                $string = $key." | ";
                foreach( $entry as $day_entry )
                {
                    $string2 = $day_entry['start']."-".$day_entry['end'];
                    PH::print_stdout( $context->padding . "   - ".$string.$string2 );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['weekly'][$key][$string2]['start'] = $day_entry['start'];
                    PH::$JSON_TMP['sub']['object'][$object->name()]['weekly'][$key][$string2]['end'] = $day_entry['end'];
                }
            }
        }

        if( isset($tmp_array['non-recurring']) )
        {
            PH::print_stdout( $context->padding . "  non-recurring:");
            $string = "  non-recurring: ";
            foreach( $tmp_array['non-recurring'] as $entry )
            {
                PH::print_stdout( $context->padding . "   - ".$entry['start']." - ".$entry['end'] );

                PH::$JSON_TMP['sub']['object'][$object->name()]['non-recurring'][$entry['start']." - ".$entry['end']]['start'] = $entry['start'];
                PH::$JSON_TMP['sub']['object'][$object->name()]['non-recurring'][$entry['start']." - ".$entry['end']]['end'] = $entry['end'];
            }
        }
    },
);



ScheduleCallContext::$supportedActions[] = array(
    'name' => 'replaceWithObject',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        /** @var ZoneRuleContainer $objectRef */
        foreach( $objectRefs as $objectRef )
        {
            $tmp_class = get_class($objectRef);

            if( $tmp_class == "ZoneRuleContainer" )
            {
                $string = " * replacing in {$objectRef->toString()}";
                PH::ACTIONlog( $context, $string );

                if( $context->isAPI )
                    $objectRef->API_replaceReferencedObject($object, $foundObject);
                else
                    $objectRef->replaceReferencedObject($object, $foundObject);
            }
            else
            {
                $string = "CLASS: " . $tmp_class . " is not supported";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
            }
        }
    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*')),
);

