<?php


ScheduleCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding . "  * SKIPPED: this object is used by other objects and cannot be deleted (use deleteForce to try anyway)\n";
            return;
        }
        if( $context->isAPI )
        {
            # $object->owner->API_removeZone($object);
        }
        else
        {
            #$object->owner->removeZone($object);
        }
    },
);

ScheduleCallContext::$supportedActions['deleteforce'] = array(
    'name' => 'deleteForce',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
            print $context->padding . "  * WARNING : this object seems to be used so deletion may fail.\n";
        if( $context->isAPI )
        {
            # $object->owner->API_removeZone($object);
        }
        else
        {
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
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding . " - new name will be '{$newName}'\n";
        if( strlen($newName) > 127 )
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
ScheduleCallContext::$supportedActions['name-addsuffix'] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $newName = $object->name() . $context->arguments['suffix'];

        if( $object->isTmp() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding . " - new name will be '{$newName}'\n";
        if( strlen($newName) > 127 )
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
ScheduleCallContext::$supportedActions['name-removeprefix'] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $prefix = $context->arguments['prefix'];

        if( $object->isTmp() )
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
ScheduleCallContext::$supportedActions['name-removesuffix'] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( $object->isTmp() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

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

ScheduleCallContext::$supportedActions['name-touppercase'] = array(
    'name' => 'name-toUpperCase',
    'MainFunction' => function (ScheduleCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtoupper($object->name(), 'UTF8');

        if( $object->isTmp() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding . " - new name will be '{$newName}'\n";
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            print " *** SKIPPED : object is already uppercase\n";
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            #use existing uppercase TAG and replace old lowercase where used with this existing uppercase TAG
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
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding . " - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            print " *** SKIPPED : object is already lowercase\n";
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            #use existing lowercase TAG and replace old uppercase where used with this
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
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding . " - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            print " *** SKIPPED : object is already UCword\n";
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            #use existing lowercase TAG and replace old uppercase where used with this
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

        $tmp_array = $object->getRecurring();

        if( isset($tmp_array['daily']) )
        {
            PH::print_stdout( $context->padding . "  daily:");
            $string = "";
            foreach( $tmp_array['daily'] as $entry )
            {
                PH::print_stdout( $context->padding . "   - ".$entry['start']." - ".$entry['end'] );
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

        /** @var Zone $objectRef */

        foreach( $objectRefs as $objectRef )
        {
            $tmp_class = get_class($objectRef);

            if( $tmp_class == "ZoneRuleContainer" )
            {
                echo $context->padding . " * replacing in {$objectRef->toString()}\n";
                if( $context->isAPI )
                    $objectRef->API_replaceReferencedObject($object, $foundObject);
                else
                    $objectRef->replaceReferencedObject($object, $foundObject);
            }
            else
            {
                print $context->padding . "  * SKIPPED: CLASS: " . $tmp_class . " is not supported\n";
            }


        }

    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*')),
);

