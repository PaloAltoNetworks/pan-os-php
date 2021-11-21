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

//Todo: introduce actions:
//      display
//      set custom timeout, tcp-timeout, udp-timeout, tcp_half_closed_timeout, tcp_time_wait_timeout
//      enable app-id

ApplicationCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);



ApplicationCallContext::$supportedActions[] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (ApplicationCallContext $context) {
        $context->counter_containers = 0;
        $context->tmpcounter = 0;
        $context->counter_predefined = 0;
        $context->counter_dependencies = 0;

        $context->counter_custom_app = 0;
        $context->counter_app_filter = 0;
        $context->counter_app_group = 0;

        $context->print_container = true;
        $context->print_dependencies = true;
        $context->print_explicit = true;
        $context->print_implicit = true;
    },
    'MainFunction' => function (ApplicationCallContext $context) {
        $app = $context->object;

        PH::print_stdout( $context->padding . "* " . get_class($app) . " '{$app->name()}' " );
        PH::$JSON_TMP['sub']['object'][$app->name()]['name'] = $app->name();
        PH::$JSON_TMP['sub']['object'][$app->name()]['type'] = get_class($app);


        if( $app->isContainer() )
        {
            $context->counter_containers++;
            if( $context->print_container )
            {
                $tmparray = array();
                PH::$JSON_TMP['sub']['object'][$app->name()]['container'] = $tmparray;

                PH::print_stdout( $context->padding." - is container: " );
                foreach( $app->containerApps() as $app1 )
                {
                    $tmparray = array();
                    #PH::print_stdout( "     ->" . $app1->type . " | " );
                    $app1->print_appdetails( $context->padding, true, $tmparray );
                    PH::$JSON_TMP['sub']['object'][$app->name()]['container']['app'][] = $tmparray;

                    PH::print_stdout("" );
                }
            }
        }
        elseif( $app->isApplicationGroup() )
        {
            foreach( $app->groupApps() as $app1 )
            {
                $tmparray = array();
                #PH::print_stdout( "     ->" . $app1->type . " | " );
                $app1->print_appdetails( $context->padding, true, $tmparray );
                PH::$JSON_TMP['sub']['object'][$app->name()]['group']['app'][] = $tmparray;
                PH::print_stdout("" );
            }
        }
        elseif( $app->isApplicationFilter() )
        {
            foreach( $app->filteredApps() as $app1 )
            {
                $tmparray = array();
                #PH::print_stdout( "     ->" . $app1->type . " | " );
                $app1->print_appdetails( $context->padding, true, $tmparray );
                PH::$JSON_TMP['sub']['object'][$app->name()]['filter']['app'][] = $tmparray;
                PH::print_stdout("" );
            }
        }
        else
        {
            $tmparray = array();
            PH::print_stdout( $context->padding." - ".$app->type );
            $printflag = true;
            $app->print_appdetails( $context->padding, $printflag, $tmparray );
            PH::$JSON_TMP['sub']['object'][$app->name()]['app'][] = $tmparray;
        }

        if( $app->type == 'tmp' )
            $context->tmpcounter++;

        if( $app->type == 'predefined' )
            $context->counter_predefined++;


        if( $app->isApplicationCustom() )
        {
            $context->counter_custom_app++;
            if( $app->custom_signature )
            {
                PH::print_stdout( "custom_signature is set" );
                PH::$JSON_TMP['sub']['object'][$app->name()]['custom_signature'] = "available";
            }

        }

        if( $app->isApplicationFilter() )
            $context->counter_app_filter++;


        if( $app->isApplicationGroup() )
            $context->counter_app_group++;


        // Explicit / Implicti difference
        $app_explicit = array();
        $app_implicit = array();
        if( isset($app->explicitUse) )
        {
            foreach( $app->explicitUse as $explApp )
            {
                $app_explicit[$explApp->name()] = $explApp;
            }
        }

        if( isset($app->implicitUse) )
        {
            foreach( $app->implicitUse as $implApp )
            {
                $app_implicit[$implApp->name()] = $implApp;
            }
        }

        $dependency_app = array();
        foreach( $app_implicit as $implApp )
        {
            if( isset($app_explicit[$implApp->name()]) )
            {
                PH::print_stdout( str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as explicit and implicit used" );
                PH::$JSON_TMP['sub']['object'][$app->name()]['explicitANDimplicit'][] = $implApp->name();
                if( isset($app->implicitUse) && $context->print_dependencies )
                {
                    if( !isset($dependency_app[$app->name()]) )
                    {
                        if( count($app->calculateDependencies()) > 0 )
                        {
                            $dependency_app[$app->name()] = $app->name();
                            $text = str_pad($app->name(), 30);
                            $text .= "     dependencies: ";
                            $context->counter_dependencies++;
                        }

                        foreach( $app->calculateDependencies() as $dependency )
                        {
                            $text .= $dependency->name() . ",";
                            PH::$JSON_TMP['sub']['object'][$app->name()]['dependencies'][] = $dependency->name();
                        }
                        if( count($app->calculateDependencies()) > 0 )
                        {
                            PH::print_stdout( $text );
                        }
                    }
                }
            }
        }


        foreach( $app_explicit as $implApp )
        {
            if( !isset($app_implicit[$implApp->name()]) )
            {
                if( count($app_implicit) > 0 )
                {
                    PH::print_stdout( str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as explicit but NOT implicit used" );
                    PH::$JSON_TMP['sub']['object'][$app->name()]['explicitNOTimplicit'][] = $implApp->name();
                }

            }
        }

        foreach( $app_implicit as $implApp )
        {
            if( !isset($app_explicit[$implApp->name()]) )
            {
                PH::print_stdout( str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as implicit but NOT explicit used" );
                PH::$JSON_TMP['sub']['object'][$app->name()]['implicitNOTexplicit'][] = $implApp->name();
            }
        }

        #PH::print_stdout( "#############################################" );
    },
    'GlobalFinishFunction' => function (ApplicationCallContext $context) {
        PH::print_stdout( "tmp_counter: ".$context->tmpcounter."" );
        PH::print_stdout( "predefined_counter: ".$context->counter_predefined."" );
        PH::print_stdout( "dependency_app_counter: ".$context->counter_dependencies."" );

        PH::print_stdout( "container_counter: ".$context->counter_containers."" );

        PH::print_stdout( "custom_app_counter: ".$context->counter_custom_app."" );
        PH::print_stdout( "app_filter_counter: ".$context->counter_app_filter."" );
        PH::print_stdout( "app_group_counter: ".$context->counter_app_group."" );


        PH::$JSON_TMP['tmp_counter'] = $context->tmpcounter;
        PH::$JSON_TMP['predefined_counter'] = $context->counter_predefined;
        PH::$JSON_TMP['dependency_app_counter'] = $context->counter_dependencies;

        PH::$JSON_TMP['container_counter'] = $context->counter_containers;

        PH::$JSON_TMP['custom_app_counter'] = $context->counter_custom_app;
        PH::$JSON_TMP['app_filter_counter'] = $context->counter_app_filter;
        PH::$JSON_TMP['app_group_counter'] = $context->counter_app_group;

        PH::print_stdout( PH::$JSON_TMP, false, "appcounter" );
        PH::$JSON_TMP = array();
    }
);

ApplicationCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;

        if( !$object->isApplicationCustom() && !$object->isApplicationFilter() && !$object->isApplicationGroup() )
        {
            $string = "this is NOT a custom application object. TYPE: ".$object->type."";
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
            $targetStore = $rootObject->appStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->appStore;
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

        $conflictObject = $targetStore->find($object->name(), null);
        if( $conflictObject === null )
        {
            $string = "moved, no conflict";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->remove($object);
                $targetStore->addApp($object);
                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->remove($object);
                $targetStore->addApp($object);
            }
            return;
        }

        if( $context->arguments['mode'] == 'skipifconflict' )
        {
            $string = "there is an object with same name. Choose another mode to resolve this conflict";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "there is a conflict with an object of same name and type. Please use address-merger.php script with argument 'allowmergingwithupperlevel'";
        PH::ACTIONlog( $context, $string );
        #if( $conflictObject->isGroup() )
        #    PH::print_stdout( " - Group" );
        #else
            $string = $conflictObject->type() . "";
            PH::ACTIONlog( $context, $string );

        /*
        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            PH::print_stdout( $context->padding . "   * SKIPPED because conflict has mismatching types" );
            return;
        }*/

        /*
        if( $conflictObject->isTmpAddr() )
        {
            PH::print_stdout( $context->padding . "   * SKIPPED because the conflicting object is TMP| value: ".$conflictObject->value()."" );
            //normally the $object must be moved and the conflicting TMP object must be replaced by this $object
            return;
        }
        */

        /*
        if( $object->equals($conflictObject) )
        {
            PH::print_stdout( "    * Removed because target has same content" );
            $object->replaceMeGlobally($conflictObject);

            if( $context->isAPI )
                $object->owner->API_remove($object);
            else
                $object->owner->remove($object);
            return;
        }*/


        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $string ="    * Removed because target has same numerical value";
        PH::ACTIONlog( $context, $string );

        $object->replaceMeGlobally($conflictObject);
        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);


    },
    'args' => array('location' => array('type' => 'string', 'default' => '*nodefault*'),
        #'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict', 'removeIfMatch'))
        'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict'))
    ),
);