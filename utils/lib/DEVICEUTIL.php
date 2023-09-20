<?php
/**
 * ISC License
 *
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

class DEVICEUTIL extends UTIL
{
    public $deviceTypes = null;

    public function utilStart()
    {
        $this->utilInit();
        //unique for DEVICEUTIL
        $this->deviceTypes();

        $this->utilActionFilter();


        $this->location_filter_object();


        $this->time_to_process_objects();


        $this->GlobalFinishAction();

        PH::print_stdout();
        PH::print_stdout( " **** PROCESSED $this->totalObjectsProcessed objects over {$this->totalObjectsOfSelectedStores} available ****" );
        PH::print_stdout();
        PH::print_stdout();

        $this->stats();

        $this->save_our_work(TRUE);

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            //print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }

    public function supportedArguments()
    {
        parent::supportedArguments();
        $this->supportedArguments['devicetype'] = array('niceName' => 'deviceType', 'shortHelp' => 'specify which type(s) of your device want to edit, (default is "dg". ie: devicetype=any  devicetype=vsys,devicegroup,templatestack,template,container,devicecloud,manageddevice,deviceonprem,snippet', 'argDesc' => 'all|any|vsys|devicegroup|templatestack|template|container|devicecloud|manageddevice|deviceonprem|snippet');
    }

    public function location_filter_object()
    {
        $sub = null;

        foreach( $this->objectsLocation as $location )
        {
            $locationFound = FALSE;

            if( $this->configType == 'panos' )
            {
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('vsys', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getVirtualSystems());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('vsys', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getSharedGateways());
            }
            elseif( $this->configType == 'panorama' )
            {
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('devicegroup', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getDeviceGroups());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('template', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getTemplates());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('templatestack', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getTemplatesStacks());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('manageddevice', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan->managedFirewallsStore, 'objects' => $this->pan->managedFirewallsStore->getAll());
            }
            elseif( $this->configType == 'fawkes' )
            {
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('container', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getContainers());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('devicecloud', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getDeviceClouds());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('manageddevice', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan->managedFirewallsStore, 'objects' => $this->pan->managedFirewallsStore->getAll());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('deviceonprem', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getDeviceOnPrems());
                if( array_search('any', $this->deviceTypes) !== FALSE || array_search('snippet', $this->deviceTypes) !== FALSE )
                    $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getSnippets());
            }

                
            self::GlobalInitAction($this->pan);
        }
    }

    public function deviceTypes()
    {
        //
        // Determine device types
        //
        $supportedRuleTypes = array( 'any', 'vsys', 'devicegroup', 'template', 'templatestack', 'container', 'devicecloud', 'manageddevice', 'deviceonprem', 'snippet');
        if( !isset(PH::$args['devicetype']) )
        {
            if( $this->configType == 'panos' )
                $tmpType = 'vsys';
            elseif( $this->configType == 'panorama' )
                $tmpType = 'devicegroup';
            elseif( $this->configType == 'fawkes' )
                $tmpType = 'container';
            PH::print_stdout( " - No 'deviceType' specified, using '".$tmpType."' by default" );
            $this->deviceTypes = array($tmpType);
        }
        else
        {
            $this->deviceTypes = explode(',', PH::$args['devicetype']);
            foreach( $this->deviceTypes as &$rType )
            {
                $rType = strtolower($rType);
                if( array_search($rType, $supportedRuleTypes) === FALSE )
                {
                    $this->display_error_usage_exit("'deviceType' has unsupported value: '" . $rType . "'. Supported values are: " . PH::list_to_string($supportedRuleTypes));
                }
                if( $rType == 'all' )
                    $rType = 'any';
            }

            $this->deviceTypes = array_unique($this->deviceTypes);
        }
        PH::print_stdout( $this->deviceTypes, false, "devicetype");
    }
    
    public function time_to_process_objects()
    {
        //
        // It's time to process Rules !!!!
        //

        // <editor-fold desc="Rule Processing" defaultstate="collapsed" >


        foreach( $this->objectsToProcess as &$rulesRecord )
        {
            /** @var RuleStore $store */

            $store = $rulesRecord['store'];
            $objects = &$rulesRecord['objects'];
            $subObjectsProcessed = 0;
            if( isset($objects[0]) )
            {
                if( get_class($objects[0]) == "DeviceGroup" )
                    $counter = count($store->getDeviceGroups());
                elseif( get_class($objects[0]) == "Template" )
                    $counter= count($store->getTemplates());
                elseif( get_class($objects[0]) == "TemplateStack" )
                    $counter = count($store->getTemplatesStacks());
                elseif( get_class($objects[0]) == "ManagedDevice" )
                    $counter = count($store->getAll());
                else
                    $counter = 0;
            }
            else
                $counter = 0;

            $this->totalObjectsOfSelectedStores += $counter;

            foreach( $this->doActions as $doAction )
            {
                #$doAction->subSystem = $store->owner;
                $doAction->subSystem = $store;
            }

            PH::print_stdout();
            #PH::print_stdout( "* processing deviceset '" . $store->toString() . "' that holds " . count($objects) );
            if( isset($objects[0]) )
                $name = get_class($objects[0]);
            else
                $name = "";
            $string = "* processing deviceset '" . $name."'";
            PH::print_stdout( $string );

            PH::$JSON_TMP = array();
            PH::$JSON_TMP['header'] = $string;
            PH::$JSON_TMP['sub']['name'] = $store->name();
            PH::$JSON_TMP['sub']['store'] = $store->name();
            PH::$JSON_TMP['sub']['type'] = get_class( $store );

            foreach( $objects as $object )
            {
                // If a filter query was input and it doesn't match this object then we simply skip it
                if( $this->objectFilterRQuery !== null )
                {
                    $queryResult = $this->objectFilterRQuery->matchSingleObject(array('object' => $object, 'nestedQueries' => &$this->nestedQueries));
                    if( !$queryResult )
                        continue;
                }

                $this->totalObjectsProcessed++;
                $subObjectsProcessed++;

                // object will pass through every action now
                foreach( $this->doActions as $doAction )
                {
                    $doAction->padding = '      ';
                    $doAction->executeAction($object);

                    PH::print_stdout();
                }
            }

            if( isset($store->owner->owner) && is_object($store->owner->owner) )
                $tmp_platform = get_class( $store->owner->owner );
            elseif( isset($store->owner) && is_object($store->owner) )
                $tmp_platform = get_class( $store->owner );
            else
                $tmp_platform = get_class( $store );

            //what todo for devicetype???
            PH::print_stdout( "* objects processed  : $subObjectsProcessed filtered over {$counter} available" );
            PH::$JSON_TMP['sub']['summary']['processed'] = $subObjectsProcessed;
            PH::$JSON_TMP['sub']['summary']['available'] = $counter;

            PH::print_stdout( PH::$JSON_TMP, false, $tmp_platform );
            PH::$JSON_TMP = array();
        }
        PH::print_stdout();
        // </editor-fold>
    }
}