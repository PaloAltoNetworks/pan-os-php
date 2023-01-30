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
        $this->supportedArguments['ruletype'] = array('niceName' => 'ruleType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: ruletype=any  ruletype=security,nat', 'argDesc' => 'any|security|nat|decryption|pbf|qos|dos|appoverride|tunnelinspection|defaultsecurity');
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
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('tunnelinspection', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->tunnelInspectionRules, 'rules' => $sub->tunnelInspectionRules->resultingRuleSet());
                            }

                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('defaultsecurity', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->defaultSecurityRules, 'rules' => $sub->defaultSecurityRules->resultingRuleSet());
                            }

                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('networkpacketbroker', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->networkPacketBrokerRules, 'rules' => $sub->networkPacketBrokerRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('sdwan', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->sdWanRules, 'rules' => $sub->sdWanRules->resultingRuleSet());
                            }
                            $locationFound = TRUE;
                        }
                    }
                    else
                    {
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
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('tunnelinspection', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->tunnelInspectionRules, 'rules' => $sub->tunnelInspectionRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('defaultsecurity', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->defaultSecurityRules, 'rules' => $sub->defaultSecurityRules->resultingRuleSet());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('networkpacketbroker', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->networkPacketBrokerRules, 'rules' => $sub->networkPacketBrokerRules->rules());
                            }
                            if( array_search('any', $this->ruleTypes) !== FALSE || array_search('sdwan', $this->ruleTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->sdWanRules, 'rules' => $sub->sdWanRules->rules());
                            }
                            $locationFound = TRUE;
                        }
                    }

                    self::GlobalInitAction($sub, $this->ruleTypes);
                }
            }
            else
            {
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
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('tunnelinspection', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->tunnelInspectionRules, 'rules' => $this->pan->tunnelInspectionRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('defaultsecurity', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->defaultSecurityRules, 'rules' => $this->pan->defaultSecurityRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('networkpacketbroker', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->networkPacketBrokerRules, 'rules' => $this->pan->networkPacketBrokerRules->rules());
                    }
                    if( array_search('any', $this->ruleTypes) !== FALSE || array_search('sdwan', $this->ruleTypes) !== FALSE )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->sdWanRules, 'rules' => $this->pan->sdWanRules->rules());
                    }
                    $locationFound = TRUE;

                    self::GlobalInitAction($this->pan, $this->ruleTypes);
                }

                if( $this->configType == 'panorama' )
                    $subGroups = $this->pan->getDeviceGroups();
                elseif( $this->configType == 'fawkes' )
                {
                    $subGroups = $this->pan->getContainers();
                    $subGroups2 = $this->pan->getDeviceClouds();

                    $subGroups = array_merge( $subGroups, $subGroups2 );

                    $subGroups2 = $this->pan->getDeviceOnPrems();
                    $subGroups = array_merge( $subGroups, $subGroups2 );
                }


                foreach( $subGroups as $sub )
                {
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
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('tunnelinspection', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->tunnelInspectionRules, 'rules' => $sub->tunnelInspectionRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('defaultsecurity', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->defaultSecurityRules, 'rules' => $sub->defaultSecurityRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('networkpacketbroker', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->networkPacketBrokerRules, 'rules' => $sub->networkPacketBrokerRules->rules());
                        }
                        if( array_search('any', $this->ruleTypes) !== FALSE || array_search('sdwan', $this->ruleTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->sdWanRules, 'rules' => $sub->sdWanRules->rules());
                        }
                        $locationFound = TRUE;
                    }

                    self::GlobalInitAction($sub, $this->ruleTypes);
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
        $supportedRuleTypes = array( 'any', 'security', 'nat', 'decryption', 'appoverride', 'captiveportal', 'authentication', 'pbf', 'qos', 'dos', 'tunnelinspection', 'defaultsecurity', 'networkpacketbroker', 'sdwan');
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
                    $this->display_error_usage_exit("'ruleType' has unsupported value: '" . $rType . "'. Supported values are: " . PH::list_to_string($supportedRuleTypes, ','));
                }
                if( $rType == 'all' )
                    $rType = 'any';
            }

            $this->ruleTypes = array_unique($this->ruleTypes);
        }
        PH::print_stdout( $this->ruleTypes, false, "ruletype");
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
                $doAction->store = $store;
            }

            PH::print_stdout();
            $string = "* processing ruleset '" . $store->toString() . "' that holds " . count($rules) . " rules";
            PH::print_stdout( $string );

            PH::$JSON_TMP = array();
            PH::$JSON_TMP['header'] = $string;
            PH::$JSON_TMP['sub']['name'] = $store->owner->name();
            PH::$JSON_TMP['sub']['store'] = $store->name();
            PH::$JSON_TMP['sub']['type'] = get_class( $store->owner );

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

                    PH::print_stdout();
                }
            }

            if( isset($store->owner->owner) && is_object($store->owner->owner) )
                $tmp_platform = get_class( $store->owner->owner );
            elseif( isset($store->owner) && is_object($store->owner) )
                $tmp_platform = get_class( $store->owner );
            else
                $tmp_platform = get_class( $store );

            PH::print_stdout( "* objects processed in DG/Vsys '{$store->owner->name()}' : $subObjectsProcessed filtered over {$store->count()} available" );
            PH::print_stdout();
            PH::$JSON_TMP['sub']['summary']['processed'] = $subObjectsProcessed;
            PH::$JSON_TMP['sub']['summary']['available'] = $store->count();
            PH::print_stdout( PH::$JSON_TMP, false, $tmp_platform );
            PH::$JSON_TMP = array();
        }
        PH::print_stdout();
        // </editor-fold>
    }
}