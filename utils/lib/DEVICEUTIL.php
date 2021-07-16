<?php


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

        PH::print_stdout( "" );
        PH::print_stdout( " **** PROCESSED $this->totalObjectsProcessed objects over {$this->totalObjectsOfSelectedStores} available ****" );
        PH::print_stdout( "" );
        PH::print_stdout( "" );

        $this->stats();

        $this->save_our_work(TRUE);
    }

    public function supportedArguments()
    {
        parent::supportedArguments();
        $this->supportedArguments['devicetype'] = array('niceName' => 'deviceType', 'shortHelp' => 'specify which type(s) of your device want to edit, (default is "dg". ie: devicetype=any  devicetype=vsys,devicegroup,templatestack,template,container,devicecloud,manageddevice', 'argDesc' => 'all|any|vsys|devicegroup|templatestack|template|container|devicecloud|manageddevice');
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
                
                
                /*
                foreach( $subGroups as $sub )
                {
                    if( isset(PH::$args['loadpanoramapushedconfig']) )
                    {
                    }
                    else
                    {
                    }
                }
                */
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
            }

                
            self::GlobalInitAction($this->pan);

            
            //if( !$locationFound )
            //    DEVICEUTIL::locationNotFound($location, $this->configType, $this->pan);
        }
    }

    public function deviceTypes()
    {
        //
        // Determine device types
        //
        $supportedRuleTypes = array( 'any', 'vsys', 'devicegroup', 'template', 'templatestack', 'container', 'devicecloud', 'manageddevice');
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
            #$this->totalObjectsOfSelectedStores += $store->count();

            foreach( $this->doActions as $doAction )
            {
                #$doAction->subSystem = $store->owner;
                $doAction->subSystem = $store;
            }

            PH::print_stdout( "" );
            #PH::print_stdout( "* processing deviceset '" . $store->toString() . "' that holds " . count($objects) . " rules" );
            PH::print_stdout( "* processing deviceset '" . $store->name()."'" );


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

                    PH::print_stdout( "" );
                }
            }

            //what todo for devicetype???
            #PH::print_stdout( "* objects processed in DG/Vsys '{$store->owner->name()}' : $subObjectsProcessed filtered over {$store->count()} available" );
            #PH::print_stdout( "* objects processed in DG/Vsys/Template/TemplateStack/Container/ " );
            PH::print_stdout( "" );
        }
        PH::print_stdout( "" );
        // </editor-fold>
    }
}