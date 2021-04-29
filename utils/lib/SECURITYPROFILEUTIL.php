<?php


class SECURITYPROFILEUTIL extends UTIL
{
    public $securityProfileTypes = null;

    public function utilStart()
    {
        $this->utilInit();
        //unique for SECURITYPROFILEUTIL
        $this->securityProfileTypes();


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
        $this->supportedArguments['securityprofiletype'] = array('niceName' => 'securityProfileType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: securityprofiletype=any  securityprofiletype=url, customurl', 'argDesc' => 'all|any|url-filtering|virus|vulnerability|spyware|file-blocking|wildfire-analysis|custom-url-category|predefined-url');
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
    }

    public function location_filter_object()
    {
        $sub = null;

        foreach( $this->objectsLocation as $location )
        {
            $locationFound = FALSE;

            if( $this->configType == 'panos' )
            {
                #if( $location == 'shared' || $location == 'any' || $location == 'all' )
                if( $location == 'shared' || $location == 'any' )
                {
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-url', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->urlStore, 'rules' => $this->pan->urlStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->URLProfileStore, 'rules' => $this->pan->URLProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiVirusProfileStore, 'rules' => $this->pan->AntiVirusProfileStore->securityProfiles());
                    }


                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->VulnerabilityProfileStore, 'rules' => $this->pan->VulnerabilityProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->FileBlockingProfileStore, 'rules' => $this->pan->FileBlockingProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiSpywareProfileStore, 'rules' => $this->pan->AntiSpywareProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysing', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->WildfireProfileStore, 'rules' => $this->pan->WildfireProfileStore->securityProfiles());
                    }


                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->customURLProfileStore, 'rules' => $this->pan->customURLProfileStore->securityProfiles());
                    }
                    $locationFound = TRUE;
                }

                foreach( $this->pan->getVirtualSystems() as $sub )
                {
                    if( isset(PH::$args['loadpanoramapushedconfig']) )
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            //Todo: Validation needed,cmpare to rule no pre/post rule but check if something else needed
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->URLProfileStore, 'rules' => $sub->URLProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiVirusProfileStore, 'rules' => $sub->AntiVirusProfileStore->securityProfiles());
                            }


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->VulnerabilityProfileStore, 'rules' => $sub->VulnerabilityProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->FileBlockingProfileStore, 'rules' => $sub->FileBlockingProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiSpywareProfileStore, 'rules' => $sub->AntiSpywareProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysing', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->WildfireProfileStore, 'rules' => $sub->WildfireProfileStore->securityProfiles());
                            }


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->customURLProfileStore, 'rules' => $sub->customURLProfileStore->securityProfiles());
                            }
                            $locationFound = TRUE;
                        }
                    }
                    else
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->URLProfileStore, 'rules' => $sub->URLProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiVirusProfileStore, 'rules' => $sub->AntiVirusProfileStore->securityProfiles());
                            }


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->VulnerabilityProfileStore, 'rules' => $sub->VulnerabilityProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->FileBlockingProfileStore, 'rules' => $sub->FileBlockingProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiSpywareProfileStore, 'rules' => $sub->AntiSpywareProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysing', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->WildfireProfileStore, 'rules' => $sub->WildfireProfileStore->securityProfiles());
                            }


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->customURLProfileStore, 'rules' => $sub->customURLProfileStore->securityProfiles());
                            }
                            $locationFound = TRUE;
                        }
                    }

                    self::GlobalInitAction($sub);
                }
            }
            else
            {
                #if( $this->configType == 'panorama' && ($location == 'shared' || $location == 'any' || $location == 'all') )
                if( $this->configType == 'panorama' && ($location == 'shared' || $location == 'any' ) )
                {
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-url', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->urlStore, 'rules' => $this->pan->urlStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->URLProfileStore, 'rules' => $this->pan->URLProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiVirusProfileStore, 'rules' => $this->pan->AntiVirusProfileStore->securityProfiles());
                    }


                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->VulnerabilityProfileStore, 'rules' => $this->pan->VulnerabilityProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->FileBlockingProfileStore, 'rules' => $this->pan->FileBlockingProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiSpywareProfileStore, 'rules' => $this->pan->AntiSpywareProfileStore->securityProfiles());
                    }
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysing', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->WildfireProfileStore, 'rules' => $this->pan->WildfireProfileStore->securityProfiles());
                    }


                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->customURLProfileStore, 'rules' => $this->pan->customURLProfileStore->securityProfiles());
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
                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->URLProfileStore, 'rules' => $sub->URLProfileStore->securityProfiles());
                        }

                        //Panorama
                        if( $this->configType == 'fawkes' )
                        {
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virusandwildfire', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->VirusAndWildfireProfileStore, 'rules' => $sub->VirusAndWildfireProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('dnssecurity', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->DNSSecurityProfileStore, 'rules' => $sub->DNSSecurityProfileStore->securityProfiles());
                            }
                        }
                        else
                        {
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiVirusProfileStore, 'rules' => $sub->AntiVirusProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysing', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->WildfireProfileStore, 'rules' => $sub->WildfireProfileStore->securityProfiles());
                            }
                        }






                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->VulnerabilityProfileStore, 'rules' => $sub->VulnerabilityProfileStore->securityProfiles());
                        }
                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->FileBlockingProfileStore, 'rules' => $sub->FileBlockingProfileStore->securityProfiles());
                        }
                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->AntiSpywareProfileStore, 'rules' => $sub->AntiSpywareProfileStore->securityProfiles());
                        }



                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->customURLProfileStore, 'rules' => $sub->customURLProfileStore->securityProfiles());
                        }
                        $locationFound = TRUE;
                    }

                    self::GlobalInitAction($sub);
                }
            }

            if( !$locationFound )
                self::locationNotFound($location, $this->configType, $this->pan);
        }
    }

    public function securityProfileTypes()
    {
        //
        // Determine rule types
        //
        #$supportedSecurityProfileTypes = array('all', 'any', 'url-filtering', 'virus', 'vulnerability', 'spyware', 'file-blocking', 'wildfire-analysis', 'custom-url-category', 'predefined-url');
        $supportedSecurityProfileTypes = array('any', 'url-filtering', 'virus', 'vulnerability', 'spyware', 'file-blocking', 'wildfire-analysis', 'custom-url-category', 'predefined-url');
        if( !isset(PH::$args['securityprofiletype']) )
        {
            PH::print_stdout( " - No 'securityProfileType' specified, using 'any' by default" );
            $this->securityProfileTypes = array('any');
        }
        else
        {
            $this->securityProfileTypes = explode(',', PH::$args['securityprofiletype']);
            foreach( $this->securityProfileTypes as &$rType )
            {
                $rType = strtolower($rType);
                if( array_search($rType, $supportedSecurityProfileTypes) === FALSE )
                {
                    $this->display_error_usage_exit("'securityProfileType' has unsupported value: '" . $rType . "'. Supported values are: " . PH::list_to_string($supportedSecurityProfileTypes));
                }
                if( $rType == 'all' )
                    $rType = 'any';
            }

            $this->securityProfileTypes = array_unique($this->securityProfileTypes);
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
            PH::print_stdout( "* processing SecurityProfileset '" . $store->toString() . " that holds " . count($rules) . "' SecurityProfiles" );

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

            if( is_object($store->owner) )
            {
                $tmp_name = $store->owner->name();
            }
            elseif( is_object($store) )
            {
                $tmp_name = $store->name();

            }

            PH::print_stdout( "" );
            PH::print_stdout( "* objects processed in DG/Vsys '{$tmp_name}' : $subObjectsProcessed" );
            PH::print_stdout( "" );

            #PH::print_stdout( "* objects processed in DG/Vsys '{$store->owner->name()}' : $subObjectsProcessed filtered over {$store->count()} available\n\n" );
        }
        PH::print_stdout( "" );
        // </editor-fold>
    }
}