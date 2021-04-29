<?php


ZoneCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding . "  * SKIPPED: this object is used by other objects and cannot be deleted (use deleteForce to try anyway)\n";
            return;
        }
        if( $context->isAPI )
            $object->owner->API_removeZone($object);
        else
            $object->owner->removeZone($object);
    },
);

ZoneCallContext::$supportedActions['deleteforce'] = array(
    'name' => 'deleteForce',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
            print $context->padding . "  * WARNING : this object seems to be used so deletion may fail.\n";
        if( $context->isAPI )
            $object->owner->API_removeZone($object);
        else
            $object->owner->removeZone($object);
    },
);


ZoneCallContext::$supportedActions['name-addprefix'] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (ZoneCallContext $context) {
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
ZoneCallContext::$supportedActions['name-addsuffix'] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (ZoneCallContext $context) {
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
ZoneCallContext::$supportedActions['name-removeprefix'] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (ZoneCallContext $context) {
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
ZoneCallContext::$supportedActions['name-removesuffix'] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (ZoneCallContext $context) {
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

ZoneCallContext::$supportedActions['name-touppercase'] = array(
    'name' => 'name-toUpperCase',
    'MainFunction' => function (ZoneCallContext $context) {
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
ZoneCallContext::$supportedActions['name-tolowercase'] = array(
    'name' => 'name-toLowerCase',
    'MainFunction' => function (ZoneCallContext $context) {
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
ZoneCallContext::$supportedActions['name-toucwords'] = array(
    'name' => 'name-toUCWords',
    'MainFunction' => function (ZoneCallContext $context) {
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

ZoneCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

ZoneCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'   ( type: " . $object->_type . " )   ";
        if( $object->zoneProtectionProfile !== null )
            $tmp_txt .= "ZPP: " . $object->zoneProtectionProfile;

        PH::print_stdout( $tmp_txt );

        //DISPLAY interfaces attached to zones
        $interfaces = $object->attachedInterfaces;
        foreach( $interfaces->getAll() as $interface )
        {
            $tmp_txt = "         " . $interface->type . " - ";
            $tmp_txt .= $interface->name();
            /*if( $interface->type == "layer3" )
            {
                if( count( $interface->getLayer3IPv4Addresses() ) > 0 )
                    print ", ip-addresse(s): ";
                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                    print $ip_address.",";
            }*/
            if( $interface->type == "layer3" )
            {
                $tmp_txt .= ", ip-addresse(s): ";
                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                    $tmp_txt .= $ip_address . ",";
                foreach( $interface->getLayer3IPv6Addresses() as $ip_address )
                    $tmp_txt .= $ip_address . ",";
            }
            elseif( $interface->type == "tunnel" || $interface->type == "loopback" || $interface->type == "vlan" )
            {
                $tmp_txt .= ", ip-addresse(s): ";
                foreach( $interface->getIPv4Addresses() as $ip_address )
                {
                    if( strpos($ip_address, ".") !== FALSE )
                        $tmp_txt .= $ip_address . ",";
                    else
                    {
                        #$object = $sub->addressStore->find( $ip_address );
                        #print $ip_address." ({$object->value()}) ,";
                        $tmp_txt .= 'XXX,';
                    }
                }
            }
            elseif( $interface->type == "auto-key" )
            {
                $tmp_txt .= " - IPsec config";
                $tmp_txt .= " - IKE gateway: " . $interface->gateway;
                $tmp_txt .= " - interface: " . $interface->interface;
            }
            PH::print_stdout( $tmp_txt );

        }
        #print "\n\n";
    },
);

ZoneCallContext::$supportedActions['zpp-set'] = array(
    'name' => 'zpp-Set',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $newzpp = $context->arguments['ZPP-name'];

        if( $object->isTmp() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding . " - new ZPP will be '{$newzpp}'\n";


        if( $context->isAPI )
            $object->API_setZPP($newzpp);
        else

            $object->setZPP($newzpp);
    },
    'args' => array('ZPP-name' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);

ZoneCallContext::$supportedActions['packetbufferprotection-set'] = array(
    'name' => 'PacketBufferProtection-Set',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $newzpp = $context->arguments['PacketBufferProtection'];

        if( $object->isTmp() )
        {
            echo $context->padding . " *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        if( $newzpp )
            $value = "enabled";
        else
            $value = "disabled";

        print $context->padding . " - PacketBufferProtection will be '{$value}'\n";


        if( $context->isAPI )
            $object->API_setPaketBufferProtection($newzpp);
        else

            $object->setPaketBufferProtection($newzpp);
    },
    'args' => array('PacketBufferProtection' => array('type' => 'bool', 'default' => '*nodefault*')
    ),
);

ZoneCallContext::$supportedActions[] = array(
    'name' => 'replaceWithObject',
    'MainFunction' => function (ZoneCallContext $context) {
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

ZoneCallContext::$supportedActions['logsetting-set'] = array(
    'name' => 'logsetting-Set',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $newLogSetting = $context->arguments['logforwardingprofile-name'];

        print $context->padding . " - new Log Setting will be '{$newLogSetting}'\n";


        if( $context->isAPI )
            $object->API_setLogSetting($newLogSetting);
        else
            $object->setLogSetting($newLogSetting);
    },
    'args' => array('logforwardingprofile-name' =>
        array('type' => 'string',
            'default' => '*nodefault*',
            'help' => "this argument can be also 'none' to remove the Log Setting back to PAN-OS default."
        )
    ),
);

