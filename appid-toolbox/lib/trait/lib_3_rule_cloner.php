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

#####################################

trait lib_3_rule_cloner
{
    function display_usage_and_exit_p3()
    {
        PH::print_stdout();
        PH::print_stdout(PH::boldText("USAGE: ") . "pan-os-php type=appid-toolbox phase=rule-cloner  in=api://xxxx location=deviceGroup2 [bundleApiCalls] [ignoreApps=app1,app2...]");

        PH::print_stdout();

        exit(1);
    }


    function ruleCloner_Phase3_init()
    {
        if( isset(PH::$args['help']) )
            $this->display_usage_and_exit_p3();

        $supportedOptions = array('phase', 'in', 'out', 'location', 'bundleapicalls', 'ignoreapps', 'serial');
        $supportedOptions = array_flip($supportedOptions);

        foreach( PH::$args as $arg => $argvalue )
        {
            if( !isset($supportedOptions[strtolower($arg)]) )
                display_error_usage_exit("unknown argument '{$arg}'");
        }
        unset($arg);

        $debugAPI = FALSE;
        $bundleApiCalls = FALSE;


        $return = AppIDToolbox_common::location();
        $configInput = $return['configInput'];
        $location = $return['location'];


        if( isset(PH::$args['bundleapicalls']) || $configInput['type'] == 'file' )
        {
            PH::print_stdout(" - BundleApiCalls is ON");
            $bundleApiCalls = TRUE;
        }
        else
            PH::print_stdout(" - BundleApiCalls is OFF");


        $return = AppIDToolbox_common::getConfig($configInput, $debugAPI, TRUE);
        $xmlDoc = $return['xmlDoc'];
        $configOutput = $return['configOutput'];
        $inputConnector = $return['inputConnector'];


        $ruleStats = new DeviceGroupRuleAppUsage();

        if( $configInput['type'] == 'api' )
        {
            $inputConnector->refreshSystemInfos();
            $device_serial = $inputConnector->info_serial;
        }
        else
            $device_serial = PH::$args['serial'];

        $ruleStatFile = $device_serial . '-' . $location . '-stats.xml';

        if( file_exists($ruleStatFile) )
        {
            PH::print_stdout(" - Previous rule stats found, loading from file $ruleStatFile... ");
            $ruleStats->load_from_file($ruleStatFile);

        }
        else
            PH::print_stdout(" - No cached stats found (missing file '$ruleStatFile')");


        $manualIgnoreApps = array();
        if( isset(PH::$args['ignoreApps']) )
        {
            $explode = explode(',', PH::$args['ignoreApps']);
            foreach( $explode as $i )
            {
                if( strlen($i) > 0 )
                {
                    $manualIgnoreApps[] = $i;
                }
            }
            unset($explode);
            unset($i);
            if( count($manualIgnoreApps) > 0 )
            {
                PH::print_stdout(" - The following applications will be ignored : " . PH::list_to_string($manualIgnoreApps));
            }
        }


        $return = AppIDToolbox_common::determineConfig($xmlDoc, $configInput, $inputConnector, $location);
        $subSystem = $return['subSystem'];
        $pan = $return['pan'];


        PH::print_stdout(" - Found DG/Vsys '$location'");
        PH::print_stdout(" - Looking/creating for necessary Tags to mark rules");
        TH::createTags($pan, $configInput['type']);

        //
        // REAL JOB STARTS HERE
        //
        $this->ruleCloner_Phase3_main($subSystem, $configInput, $pan, $inputConnector, $configOutput, $ruleStats, $bundleApiCalls);
    }


    function ruleCloner_Phase3_main($subSystem, $configInput, $pan, $inputConnector, $configOutput, $ruleStats, $bundleApiCalls)
    {
        $rules = $subSystem->securityRules->rules("(description regex /" . RuleIDTagLibrary::$tagBaseName . "/) and !(tag has " . TH::$tag_misc_convertedRule . ") and !(tag has " . TH::$tag_misc_ignore . ") and !(tag has.regex /^" . TH::$tagNtbrBase . "/) and !(tag has " . TH::$tag_misc_clonedRule . ")");

        PH::print_stdout(" - Total number of rules: {$subSystem->securityRules->count()} vs " . count($rules) . " potentially clonable");
        PH::print_stdout("");
        PH::print_stdout("*** PROCESSING !!!");

        $count_ClonedRules = 0;
        $array_ClonedRules = array();

        $count_unused = 0;
        $count_notUnusedAnymore = 0;

        $count_NTBR = 0;
        $count_revised_NTBR = 0;

        $loopCount = 0;

        foreach( $rules as $legacyRule )
        {
            /** @var SecurityRule $legacyRule */
            $loopCount++;
            PH::print_stdout("Rule #{$loopCount} out of " . count($rules));
            PH::print_stdout($legacyRule->display(1));
            $apps = $ruleStats->getRuleStats($legacyRule->name());
            if( $apps === null )
            {
                PH::print_stdout("  - NO STATS AVAILABLE FOR THIS RULE");
                continue;
            }

            if( count($apps) == 0 )
            {
                $count_unused++;
                if( $legacyRule->tags->hasTag(TH::$tag_misc_unused) )
                {
                    PH::print_stdout("  - This rule was and is still unused");
                    continue;
                }
                PH::print_stdout("  - This rule seems to be unused, tagging it...");
                if( !$bundleApiCalls )
                    $legacyRule->tags->API_addTag(TH::$tag_misc_unused_tagObject);
                else
                    $legacyRule->tags->addTag(TH::$tag_misc_unused_tagObject);

                continue;
            }

            $ruleToBeRevised = FALSE;

            if( $legacyRule->tags->hasTag(TH::$tag_misc_unused) )
            {
                $ruleToBeRevised = TRUE;
                $count_notUnusedAnymore++;
                PH::print_stdout(" - This rule was marked as Unused but is not anymore, removing unused Tag...");
                if( !$bundleApiCalls )
                    $legacyRule->tags->API_removeTag(TH::$tag_misc_unused_tagObject);
                else
                    $legacyRule->tags->removeTag(TH::$tag_misc_unused_tagObject);
            }


            if( !$legacyRule->apps->isAny() )
            {
                PH::print_stdout("  - original rule apps != ANY , tagging");
                if( !$bundleApiCalls )
                    $legacyRule->tags->API_addTag(TH::$tag_NTBR_appNotAny_tagObject);
                else
                    $legacyRule->tags->addTag(TH::$tag_NTBR_appNotAny_tagObject);

                $count_NTBR++;
                if( $ruleToBeRevised )
                    $count_revised_NTBR++;

                continue;
            }

            $string = " - Found the following apps : ";
            foreach( $apps as $app )
            {
                $string .= $app['name'] . ',';
            }
            PH::print_stdout($string);

            $appsToPutInRule = array();

            $manualIgnoreApps[] = 'aproach.ov';

            foreach( $apps as $app )
            {
                if( $app['name'] == 'incomplete' || $app['name'] == 'insufficient-data' || $app['name'] == 'non-syn-tcp' || in_array($app['name'], $manualIgnoreApps) )
                    continue;

                $appsToPutInRule[$app['name']] = $app['name'];
            }


            if( count($appsToPutInRule) == 0 )
            {
                if( !$legacyRule->tags->hasTag(TH::$tag_NTBR_onlyInvalidApps) )
                {
                    PH::print_stdout(" - This rule has only invalid applications, tagging it");
                    if( !$bundleApiCalls )
                        $legacyRule->tags->API_addTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
                    else
                        $legacyRule->tags->addTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
                }
                else
                    PH::print_stdout(" - only invalid apps, but it was already the case");


                if( isset($apps['insufficient-data']) )
                {
                    if( !$bundleApiCalls )
                        $legacyRule->tags->API_addTag(TH::$tag_NTBR_hasInsufficientData_tagObject);
                    else
                        $legacyRule->tags->addTag(TH::$tag_NTBR_hasInsufficientData_tagObject);
                }

                $count_NTBR++;
                if( $ruleToBeRevised )
                    $count_revised_NTBR++;

                continue;
            }

            if( $legacyRule->tags->hasTag(TH::$tag_NTBR_onlyInvalidApps) )
            {
                $ruleToBeRevised = TRUE;
                $count_revised_NTBR++;

                PH::print_stdout(" - removed tag '" . TH::$tag_NTBR_onlyInvalidApps . "'");
                if( !$bundleApiCalls )
                    $legacyRule->tags->API_removeTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
                else
                    $legacyRule->tags->removeTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
            }


            $string = " - The following apps will be added : ";
            foreach( $appsToPutInRule as $app )
            {
                $string .= $app . ',';
            }
            PH::print_stdout($string);
            PH::print_stdout(" - now calculating dependencies");
            foreach( $appsToPutInRule as $app )
            {
                PH::print_stdout("  - $app");
                $appObject = $pan->appStore->find($app);
                if( $appObject !== null )
                {
                    $explicits = $appObject->calculateDependencies();
                    if( count($explicits) > 0 )
                    {
                        PH::print_stdout("    - " . PH::list_to_string($explicits));
                        foreach( $explicits as $explicit )
                            $appsToPutInRule[$explicit->name()] = $explicit->name();
                    }
                }
            }

            $newName = $legacyRule->owner->findAvailableName($legacyRule->name(), '-app');
            PH::print_stdout(" - cloned rule name will be '{$newName}'");
            if( !$bundleApiCalls )
                $appidRule = $subSystem->securityRules->API_cloneRule($legacyRule, $newName);
            else
                $appidRule = $subSystem->securityRules->cloneRule($legacyRule, $newName);

            PH::print_stdout(" - created rule '{$appidRule->name()}'");
            if( !$bundleApiCalls )
            {
                $appidRule->API_setDisabled(TRUE);
                $appidRule->tags->API_addTag(TH::$tag_misc_clonedRule_tagObject);
            }
            else
            {
                $appidRule->setDisabled(TRUE);
                $appidRule->tags->addTag(TH::$tag_misc_clonedRule_tagObject);
            }


            foreach( $appsToPutInRule as $app )
            {
                $appObject = $subSystem->appStore->findOrCreate($app);
                if( !$bundleApiCalls )
                    $appidRule->apps->API_addApp($appObject);
                else
                    $appidRule->apps->addApp($appObject);
            }

            if( $appidRule->apps->count() > 10 )
            {
                PH::print_stdout(" - cloned rule has too many apps, NTBR");
                if( !$bundleApiCalls )
                    $appidRule->tags->API_addTag(TH::$tag_NTBR_tooManyApps_tagObject);
                else
                    $appidRule->tags->addTag(TH::$tag_NTBR_tooManyApps_tagObject);
            }

            if( isset($appsToPutInRule['unknown-tcp']) || isset($appsToPutInRule['unknown-udp']) || isset($appsToPutInRule['unknown-p2p']) )
            {
                PH::print_stdout(" - cloned rule has unknown apps, NTBR");
                if( !$bundleApiCalls )
                    $appidRule->tags->API_addTag(TH::$tag_NTBR_hasUnknownApps_tagObject);
                else
                    $appidRule->tags->addTag(TH::$tag_NTBR_hasUnknownApps_tagObject);
            }

            if( $legacyRule->services->isApplicationDefault() )
            {
                if( !$bundleApiCalls )
                {
                    $appidRule->services->API_setAny();
                }
                else
                {
                    $appidRule->services->setAny();
                }
            }

            //$appidRule->owner->remove($appidRule);

            if( !$bundleApiCalls )
            {
                //$subSystem->securityRules->API_addRule($appidRule);
                $subSystem->securityRules->API_moveRuleBefore($appidRule, $legacyRule);
            }
            else
            {
                //$subSystem->securityRules->addRule($appidRule);
                $subSystem->securityRules->moveRuleBefore($appidRule, $legacyRule);
            }

            if( !$bundleApiCalls )
                $legacyRule->tags->API_addTag(TH::$tag_misc_convertedRule_tagObject);
            else
                $legacyRule->tags->addTag(TH::$tag_misc_convertedRule_tagObject);

            $count_ClonedRules++;
            $array_ClonedRules[] = $legacyRule;

            PH::print_stdout("- * RULE IS CLONED *");

            PH::print_stdout("");

        }

        if( $bundleApiCalls )
        {
            if( $configInput['type'] == 'api' )
            {
                PH::print_stdout("*** NOW DOING BUNDLED API CALL TO SYNC RULES ****");

                if( $pan->isPanorama() )
                {
                    $xpath = $subSystem->getXPath() . '/pre-rulebase/security/rules';
                    PH::print_stdout(" - syncing pre-rulebase ... ");
                    $pan->connector->sendEditRequest($xpath, DH::dom_to_xml($subSystem->securityRules->xmlroot));


                    $xpath = $subSystem->getXPath() . '/post-rulebase/security/rules';
                    PH::print_stdout(" - syncing post-rulebase ... ");
                    $pan->connector->sendEditRequest($xpath, DH::dom_to_xml($subSystem->securityRules->postRulesRoot));

                }
                else
                    derr("unsupported yet");
            }
            else
                // save our work !!!
                if( $configOutput !== null )
                {
                    if( $configOutput != '/dev/null' )
                    {
                        $pan->save_to_file($configOutput);
                    }
                }

        }


        PH::print_stdout("\nlist of cloned Rules:");

        foreach( $array_ClonedRules as $rule )
        {
            PH::print_stdout(" - {$rule->name()}");
        }

        PH::print_stdout("\n\n**** SUMMARY *****");

        PH::print_stdout(" - cloned rules : {$count_ClonedRules}");
        PH::print_stdout(" - unused : {$count_unused}");
        PH::print_stdout(" - rules with fatal NTBR : {$count_NTBR}");
        PH::print_stdout(" - revised unused rules : {$count_notUnusedAnymore}");
        PH::print_stdout(" - revised rules fatal NTBR: {$count_revised_NTBR}");


        PH::print_stdout();
    }
}
