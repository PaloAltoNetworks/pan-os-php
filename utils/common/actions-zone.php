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

ZoneCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use deleteForce to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
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
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus( $context, "WARNING", $string);
        }
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
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
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
ZoneCallContext::$supportedActions['name-addsuffix'] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $newName = $object->name() . $context->arguments['suffix'];

        if( $object->isTmp() )
        {
            $string = $context->padding . "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
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
ZoneCallContext::$supportedActions['name-removeprefix'] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (ZoneCallContext $context) {
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
ZoneCallContext::$supportedActions['name-removesuffix'] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (ZoneCallContext $context) {
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

ZoneCallContext::$supportedActions['name-touppercase'] = array(
    'name' => 'name-toUpperCase',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtoupper($object->name(), 'UTF8');

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
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
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
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
ZoneCallContext::$supportedActions['name-toucwords'] = array(
    'name' => 'name-toUCWords',
    'MainFunction' => function (ZoneCallContext $context) {
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

        $string = "new name will be '{$newName}'";
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
ZoneCallContext::$supportedActions[] = array(
    'name' => 'name-Rename',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;


        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $newName = str_replace('$$current.name$$', $object->name(), $newName);
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
            "  - \$\$current.name\$\$ : current name of the object\n"
        )
    ),
    'help' => ''
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
        /** @var Zone $object */
        $object = $context->object;
        $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'   ( type: " . $object->type . " )";
        if( $object->zoneProtectionProfile !== null )
            $tmp_txt .= ", ZPP: " . $object->zoneProtectionProfile;
        if( $object->logsetting !== null )
            $tmp_txt .= ", Log Setting: " . $object->logsetting;
        if( $object->userID )
            $tmp_txt .= ", UserID: enabled";
        PH::print_stdout( $tmp_txt );

        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
        PH::$JSON_TMP['sub']['object'][$object->name()]['zpp'] = $object->zoneProtectionProfile;
        PH::$JSON_TMP['sub']['object'][$object->name()]['log'] = $object->logsetting;

        //DISPLAY interfaces attached to zones
        $interfaces = $object->attachedInterfaces;
        foreach( $interfaces->getAll() as $interface )
        {
            $tmp_txt = "         " . $interface->type . " - ";
            $tmp_txt .= $interface->name();
            /*if( $interface->type == "layer3" )
            {
                if( count( $interface->getLayer3IPv4Addresses() ) > 0 )
                    PH::print_stdout( ", ip-addresse(s): ";
                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                    PH::print_stdout( $ip_address.",";
            }*/
            $tmp_ips = "";
            if( $interface->type == "layer3" )
            {
                $tmp_txt .= ", ip-addresse(s): ";
                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                {
                    $tmp_txt .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['interfaces'][$interface->type][$interface->name()]['ip-address'][] = $ip_address;
                }
                foreach( $interface->getLayer3IPv6Addresses() as $ip_address )
                {
                    $tmp_txt .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['interfaces'][$interface->type][$interface->name()]['ip-address'][] = $ip_address;
                }

            }
            elseif( $interface->type == "tunnel" || $interface->type == "loopback" || $interface->type == "vlan" )
            {
                $tmp_txt .= ", ip-addresse(s): ";
                foreach( $interface->getIPv4Addresses() as $ip_address )
                {
                    if( strpos($ip_address, ".") !== FALSE )
                    {
                        $tmp_txt .= $ip_address . ",";
                        PH::$JSON_TMP['sub']['object'][$object->name()]['interfaces'][$interface->type][$interface->name()]['ip-address'][] = $ip_address;
                    }

                    else
                    {
                        #$object = $sub->addressStore->find( $ip_address );
                        #PH::print_stdout( $ip_address." ({$object->value()}) ,";
                        $tmp_txt .= 'XXX,';
                        PH::$JSON_TMP['sub']['object'][$object->name()]['interfaces'][$interface->type][$interface->name()]['ip-address'][] = "XXX";
                    }
                }
            }
            elseif( $interface->type == "auto-key" )
            {
                $tmp_txt .= " - IPsec config";
                $tmp_txt .= " - IKE gateway: " . $interface->gateway;
                $tmp_txt .= " - interface: " . $interface->interface;
                PH::$JSON_TMP['sub']['object'][$object->name()]['interfaces'][$interface->type][$interface->name()]['ike']['gw'] = $interface->gateway;
                PH::$JSON_TMP['sub']['object'][$object->name()]['interfaces'][$interface->type][$interface->name()]['ike']['interface'] = $interface->interface;
            }
            PH::print_stdout( $tmp_txt );
            PH::$JSON_TMP['sub']['object'][$object->name()]['interfaces'][$interface->type][$interface->name()]['name'] = $interface->name();

        }
    },
);

ZoneCallContext::$supportedActions['zpp-set'] = array(
    'name' => 'zpp-Set',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $newzpp = $context->arguments['ZPP-name'];

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new ZPP will be '{$newzpp}'";
        PH::ACTIONlog( $context, $string );


        if( $context->isAPI )
            $object->API_setZPP($newzpp);
        else

            $object->setZPP($newzpp);
    },
    'args' => array('ZPP-name' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);

ZoneCallContext::$supportedActions['userid-enable'] = array(
    'name' => 'UserID-enable',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $enableBool = $context->arguments['enable'];

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
            $object->API_useridEnable( $enableBool );
        else
            $object->useridEnable( $enableBool );
    },
    'args' => array('enable' => array('type' => 'bool', 'default' => 'TRUE')
    ),
);

ZoneCallContext::$supportedActions['packetbufferprotection-set'] = array(
    'name' => 'PacketBufferProtection-Set',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $newzpp = $context->arguments['PacketBufferProtection'];

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $newzpp )
            $value = "enabled";
        else
            $value = "disabled";

        $string = "PacketBufferProtection will be '{$value}'";
        PH::ACTIONlog( $context, $string );


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

        /** @var ZoneRuleContainer $objectRef */
        foreach( $objectRefs as $objectRef )
        {
            $tmp_class = get_class($objectRef);

            if( $tmp_class == "ZoneRuleContainer" )
            {
                $string = "replacing in {$objectRef->toString()}";
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

ZoneCallContext::$supportedActions['logsetting-set'] = array(
    'name' => 'logsetting-Set',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $newLogSetting = $context->arguments['logforwardingprofile-name'];

        $string = "new Log Setting will be '{$newLogSetting}'";
        PH::ACTIONlog( $context, $string );


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

ZoneCallContext::$supportedActions['exportToExcel'] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (ZoneCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (ZoneCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (ZoneCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

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

        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th><th>type</th><th>interfaces</th><th>log-setting</th><th>zone-protection-profile</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addResolveGroupIPCoverage )
            $headers .= '<th>ip resolution</th>';
        if( $addNestedMembers )
            $headers .= '<th>nested members</th>';

        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Zone $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                if( $object->owner->owner->owner->owner  !== null && get_class( $object->owner->owner->owner->owner ) == "Template" )
                {
                    $lines .= $context->encloseFunction($object->owner->owner->owner->owner->name());
                    $lines .= $context->encloseFunction($object->owner->owner->name());
                }
                else
                {
                    $lines .= $context->encloseFunction( "" );
                    $lines .= $context->encloseFunction($object->owner->owner->name());
                }


                $lines .= $context->encloseFunction($object->name());

                    if( $object->isTmp() )
                    {
                        $lines .= $context->encloseFunction('unknown');
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                    }
                    else
                    {
                        $lines .= $context->encloseFunction($object->type());
                        $lines .= $context->encloseFunction( $object->attachedInterfaces->getAll() );

                        if( $object->logsetting == null )
                            $tmpLogprof = "";
                        else
                            $tmpLogprof = $object->logsetting;
                        $lines .= $context->encloseFunction( $tmpLogprof );

                        if( $object->zoneProtectionProfile == null )
                            $tmpZPP = "";
                        else
                            $tmpZPP = $object->zoneProtectionProfile;
                        $lines .= $context->encloseFunction( $tmpZPP );
                    }

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
                if( $addResolveGroupIPCoverage )
                {
                    $mapping = $object->getIP4Mapping();
                    $strMapping = explode(',', $mapping->dumpToString());

                    foreach( array_keys($mapping->unresolved) as $unresolved )
                        $strMapping[] = $unresolved;

                    $lines .= $context->encloseFunction($strMapping);
                }
                if( $addNestedMembers )
                {
                    if( $object->isGroup() )
                    {
                        $members = $object->expand(TRUE);
                        $lines .= $context->encloseFunction($members);
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

