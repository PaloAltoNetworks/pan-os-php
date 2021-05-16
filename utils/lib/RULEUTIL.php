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
        $this->supportedArguments['ruletype'] = array('niceName' => 'ruleType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: ruletype=any  ruletype=security,nat', 'argDesc' => 'all|any|security|nat|decryption|pbf|qos|dos|appoverride');
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
        $this->supportedArguments['listactions'] = array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
        $this->supportedArguments['listfilters'] = array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
        $this->supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['filter'] = array('niceName' => 'Filter', 'shortHelp' => "filters rules based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator value)');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['stats'] = array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
        $this->supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');
        $this->supportedArguments['loadplugin'] = array('niceName' => 'loadPlugin', 'shortHelp' => 'a PHP file which contains a plugin to expand capabilities of this script');
        $this->supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
        $this->supportedArguments['expedition'] = array('niceName' => 'expedition', 'shortHelp' => 'only used if called from Expedition Tool');
        $this->supportedArguments['git'] = array('niceName' => 'Git', 'shortHelp' => 'if argument git is used, git repository is created to track changes for input file');
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