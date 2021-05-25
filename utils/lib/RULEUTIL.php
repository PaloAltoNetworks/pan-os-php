<?php


class RULEUTIL extends UTIL
{
    public $ruleTypes = null;

    public function utilStart()
    {
        $this->utilInit();
        //unique for RULEUTIL
        $this->ruleTypes();

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
        $this->supportedArguments['ruletype'] = array('niceName' => 'ruleType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: ruletype=any  ruletype=security,nat', 'argDesc' => 'all|any|security|nat|decryption|pbf|qos|dos|appoverride');
    }

    public function location_filter_object()
    {
        $sub = null;

        foreach( $this->objectsLocation as $location )
        {
            $locationFound = FALSE;

            if( $this->configType == 'panos' )
            {
                foreach( $this->pan->getVirtualSystems() as $sub )
                {
                    if( isset(PH::$args['loadpanoramapushedconfig']) )
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('security', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->securityRules, 'rules' => $sub->securityRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('nat', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->natRules, 'rules' => $sub->natRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('qos', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->qosRules, 'rules' => $sub->qosRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('pbf', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->pbfRules, 'rules' => $sub->pbfRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('decryption', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->decryptionRules, 'rules' => $sub->decryptionRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('appoverride', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->appOverrideRules, 'rules' => $sub->appOverrideRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('captiveportal', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->captivePortalRules, 'rules' => $sub->captivePortalRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('authentication', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->authenticationRules, 'rules' => $sub->authenticationRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('dos', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->dosRules, 'rules' => $sub->dosRules->resultingRuleSet());
                            }
                            $locationFound = TRUE;
                        }
                    }
                    else
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('security', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->securityRules, 'rules' => $sub->securityRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('nat', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->natRules, 'rules' => $sub->natRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('qos', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->qosRules, 'rules' => $sub->qosRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('pbf', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->pbfRules, 'rules' => $sub->pbfRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('decryption', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->decryptionRules, 'rules' => $sub->decryptionRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('appoverride', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->appOverrideRules, 'rules' => $sub->appOverrideRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('captiveportal', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->captivePortalRules, 'rules' => $sub->captivePortalRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('authentication', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->authenticationRules, 'rules' => $sub->authenticationRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('dos', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->dosRules, 'rules' => $sub->dosRules->rules());
                            }
                            $locationFound = TRUE;
                        }
                    }

                    self::GlobalInitAction($sub);
                }
            }
            else
            {
                #if( $this->configType == 'panorama' && ( $location == 'shared' || $location == 'any' || $location == 'all' ) )
                if( $this->configType == 'panorama' && ( $location == 'shared' || $location == 'any' ) )
                {
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('security', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->securityRules, 'rules' => $this->pan->securityRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('nat', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->natRules, 'rules' => $this->pan->natRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('qos', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->qosRules, 'rules' => $this->pan->qosRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('pbf', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->pbfRules, 'rules' => $this->pan->pbfRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('decryption', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->decryptionRules, 'rules' => $this->pan->decryptionRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('appoverride', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->appOverrideRules, 'rules' => $this->pan->appOverrideRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('captiveportal', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->captivePortalRules, 'rules' => $this->pan->captivePortalRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('authentication', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->authenticationRules, 'rules' => $this->pan->authenticationRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('dos', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->dosRules, 'rules' => $this->pan->dosRules->rules());
                    }
                    $locationFound = TRUE;
                }

                if( $this->configType == 'panorama' )
                    $subGroups = $this->pan->getDeviceGroups();
                elseif( $this->configType == 'fawkes' )
                {
                    $subGroups = $this->pan->getContainers();
                    $subGroups2 = $this->pan->getDeviceClouds();

                    $subGroups = array_merge( $subGroups, $subGroups2 );
                }


                foreach( $subGroups as $sub )
                {
                    #if( $location == 'any' || $location == 'all' || $location == $sub->name() )
                    if( $location == 'any' || $location == $sub->name() )
                    {
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('security', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->securityRules, 'rules' => $sub->securityRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('nat', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->natRules, 'rules' => $sub->natRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('qos', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->qosRules, 'rules' => $sub->qosRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('pbf', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->pbfRules, 'rules' => $sub->pbfRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('decryption', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->decryptionRules, 'rules' => $sub->decryptionRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('appoverride', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->appOverrideRules, 'rules' => $sub->appOverrideRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('captiveportal', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->captivePortalRules, 'rules' => $sub->captivePortalRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('authentication', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->authenticationRules, 'rules' => $sub->authenticationRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('dos', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->dosRules, 'rules' => $sub->dosRules->rules());
                        }
                        $locationFound = TRUE;
                    }

                    self::GlobalInitAction($sub);
                }
            }

            if( !$locationFound )
                RULEUTIL::locationNotFound($location, $this->configType, $this->pan);
        }
    }

    public function ruleTypes()
    {
        //
        // Determine rule types
        //
        #$supportedRuleTypes = array('all', 'any', 'security', 'nat', 'decryption', 'appoverride', 'captiveportal', 'authentication', 'pbf', 'qos', 'dos');
        $supportedRuleTypes = array( 'any', 'security', 'nat', 'decryption', 'appoverride', 'captiveportal', 'authentication', 'pbf', 'qos', 'dos');
        if( !isset(PH::$args['ruletype']) )
        {
            PH::print_stdout( " - No 'ruleType' specified, using 'security' by default" );
            $this->ruleTypes = array('security');
        }
        else
        {
            $this->ruleTypes = explode(',', PH::$args['ruletype']);
            foreach( $this->ruleTypes as &$rType )
            {
                $rType = strtolower($rType);
                if( array_search($rType, $supportedRuleTypes) === FALSE )
                {
                    $this->display_error_usage_exit("'ruleType' has unsupported value: '" . $rType . "'. Supported values are: " . PH::list_to_string($supportedRuleTypes));
                }
                if( $rType == 'all' )
                    $rType = 'any';
            }

            $this->ruleTypes = array_unique($this->ruleTypes);
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
            $rules = &$rulesRecord['rules'];
            $subObjectsProcessed = 0;
            $this->totalObjectsOfSelectedStores += $store->count();

            foreach( $this->doActions as $doAction )
            {
                $doAction->subSystem = $store->owner;
            }

            PH::print_stdout( "" );
            PH::print_stdout( "* processing ruleset '" . $store->toString() . "' that holds " . count($rules) . " rules" );


            foreach( $rules as $rule )
            {
                // If a filter query was input and it doesn't match this object then we simply skip it
                if( $this->objectFilterRQuery !== null )
                {
                    $queryResult = $this->objectFilterRQuery->matchSingleObject(array('object' => $rule, 'nestedQueries' => &$this->nestedQueries));
                    if( !$queryResult )
                        continue;
                }

                $this->totalObjectsProcessed++;
                $subObjectsProcessed++;

                // object will pass through every action now
                foreach( $this->doActions as $doAction )
                {
                    $doAction->padding = '      ';
                    $doAction->executeAction($rule);

                    PH::print_stdout( "" );
                }
            }

            PH::print_stdout( "* objects processed in DG/Vsys '{$store->owner->name()}' : $subObjectsProcessed filtered over {$store->count()} available" );
            PH::print_stdout( "" );
        }
        PH::print_stdout( "" );
        // </editor-fold>
    }
}