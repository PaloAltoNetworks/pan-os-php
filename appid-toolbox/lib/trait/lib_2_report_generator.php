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

########################################

trait lib_2_report_generator
{
    function display_usage_and_exit_p2()
    {
        PH::print_stdout();
        PH::print_stdout(PH::boldText("USAGE: ") . "pan-os-php type=appid-toolbox phase=report-generator  in=api://xxxx location=deviceGroup2 [OPTIONAL ARGS]");

        PH::print_stdout("");
        PH::print_stdout("Listing optional arguments:");

        PH::print_stdout(" - debugapi : outputs API calls live to help debugging");
        PH::print_stdout(" - logHistory=XX : script will generate rules usage reports based on the XX last days time period(default=60)");
        PH::print_stdout(" - updateOnlyUnusedTagRules : only the rules which have tag appid#NTBR#unused will have a usage report generated");
        PH::print_stdout(" - updateOnlyActivatedRules : useful to check if legacy rules are still unused");
        PH::print_stdout(" - resetPreviousData : if previous data was found, erase them and insert newly generated statistics instead (incompatible with update flag)");
        PH::print_stdout(" - skipIfLastReportLessThanXDays : if previous data was found, erase them and insert newly generated statistics instead (incompatible with update flag)");
        PH::print_stdout(" - updatePreviousData : if previous data was found, merge with previous statistics (incompatible with reset flag)");

        PH::print_stdout();


        exit(1);
    }


    function logAnalysis_Phase2()
    {
        if( isset(PH::$args['help']) )
            $this->display_usage_and_exit_p2();

        $supportedOptions = array('phase', 'debugapi', 'in', 'location', 'loghistory', 'resetpreviousdata', 'updatepreviousdata', 'updateonlyunusedtagrules', 'updateonlyactivatedrules', 'skipiflastreportlessthanxdays');
        $supportedOptions = array_flip($supportedOptions);

        foreach( PH::$args as $arg => $argvalue )
        {
            if( !isset($supportedOptions[strtolower($arg)]) )
                display_error_usage_exit("unknown argument '{$arg}'");
        }
        unset($arg);


        $debugAPI = FALSE;
        $logHistory = 60;
        $resetPreviousData = FALSE;
        $updatePreviousData = FALSE;
        $updateOnlyUnusedTagRules = FALSE;
        $updateOnlyActivatedRules = FALSE;
        $skipIfLastReportLessThanXDays = 1;

        $ruleStats = new DeviceGroupRuleAppUsage();


        if( !isset(PH::$args['location']) )
            display_error_usage_exit("missing argument 'location'");

        $location = PH::$args['location'];

        if( strlen($location) < 0 || !is_string($location) )
            display_error_usage_exit("'location' argument must be a valid string");

        if( isset(PH::$args['debugapi']) )
        {
            $debugAPI = TRUE;
        }

        if( isset(PH::$args['loghistory']) )
        {
            $logHistory = PH::$args['loghistory'];
            if( !is_numeric($logHistory) )
            {
                display_error_usage_exit("'logHistory' argument was provided but it's not a number");
            }
            PH::print_stdout(" - 'logHistory' overridden from CLI : {$logHistory} days");
        }
        else
            PH::print_stdout(" - no logHistory value was provided, using default= {$logHistory} days");


        if( isset(PH::$args['skipiflastreportlessthanxdays']) )
        {
            $skipIfLastReportLessThanXDays = PH::$args['skipiflastreportlessthanxdays'];
            PH::print_stdout(" - skipIfLastReportLessThanXDays set to {$skipIfLastReportLessThanXDays} days");
        }
        else
            PH::print_stdout(" - skipIfLastReportLessThanXDays not set, using default ({$skipIfLastReportLessThanXDays} days)");


        if( isset(PH::$args['resetpreviousdata']) )
        {
            $resetPreviousData = TRUE;
            PH::print_stdout(" - resetPreviousData enabled");
        }
        else
            PH::print_stdout(" - resetPreviousData disabled");

        if( isset(PH::$args['updatepreviousdata']) )
        {
            $updatePreviousData = TRUE;
            PH::print_stdout(" - updatePreviousData enabled");
        }
        else
            PH::print_stdout(" - updatePreviousData disabled");

        if( isset(PH::$args['updateonlyunusedtagrules']) )
        {
            $updateOnlyUnusedTagRules = TRUE;
            PH::print_stdout(" - updateOnlyUnusedTagRules enabled");
            if( !$resetPreviousData && !$updatePreviousData )
                display_error_usage_exit("when updateOnlyUnusedTagRules mode is used you need to use one of the following too: resetPreviousData or updatePreviousData");
        }
        else
            PH::print_stdout(" - updateOnlyUnusedTagRules disabled");

        if( isset(PH::$args['updateonlyactivatedrules']) )
        {
            $updateOnlyActivatedRules = TRUE;
            PH::print_stdout(" - updateOnlyActivatedRules enabled");
            $updatePreviousData = TRUE;
        }
        else
            PH::print_stdout(" - updateOnlyActivatedRules disabled");


        if( $resetPreviousData && $updatePreviousData )
        {
            display_error_usage_exit("'reset' and 'update' flags are exclusive and can't both be set at the same time");
        }


        if( !isset(PH::$args['in']) )
            display_error_usage_exit('"in" is missing from arguments');
        $configInput = PH::$args['in'];
        if( !is_string($configInput) || strlen($configInput) < 1 )
            display_error_usage_exit('"in" argument is not a valid string');

        $configInput = PH::processIOMethod($configInput, TRUE);
        if( $configInput['status'] != 'ok' )
        {
            derr($configInput['msg']);
        }
        if( $configInput['type'] == 'file' )
        {
            derr("file type input is not supported, only API");
        }
        elseif( $configInput['type'] != 'api' )
            derr('unsupported yet');

        /** @var PanAPIConnector $inputConnector */
        $inputConnector = $configInput['connector'];
        if( $debugAPI )
            $inputConnector->setShowApiCalls(TRUE);
        PH::print_stdout(" - Downloading config from API... ");
        $xmlDoc = $inputConnector->getCandidateConfig();


        $return = AppIDToolbox_common::determineConfig($xmlDoc, $configInput, $inputConnector, $location);
        $subSystem = $return['subSystem'];
        $pan = $return['pan'];


        $inputConnector->refreshSystemInfos();
        $ruleStatFile = $inputConnector->info_serial . '-' . $location . '-stats.xml';
        $ruleStatFile_SrcDst = $inputConnector->info_serial . '-' . $location . '-statsSrcDst.xml';
        $ruleStatHtmlFile = $inputConnector->info_serial . '-' . $location . '-stats.html';

        if( file_exists($ruleStatFile) )
        {
            PH::print_stdout(" - Previous rule stats found, loading from file $ruleStatFile... ");
            $ruleStats->load_from_file($ruleStatFile);
        }
        else
            PH::print_stdout(" - No cached stats found (missing file '$ruleStatFile')");

        if( file_exists($ruleStatFile_SrcDst) )
        {
            PH::print_stdout(" - Previous rule stats found, loading from file $ruleStatFile_SrcDst... ");
            $ruleStats->load_from_file($ruleStatFile_SrcDst, true);
        }
        else
            PH::print_stdout(" - No cached stats found (missing file '$ruleStatFile_SrcDst')");

//
// Cooking additional query parameters
//
        $additionalQueryString = '';
        if( $updateOnlyUnusedTagRules )
        {
            if( strlen($additionalQueryString) > 0 )
                $additionalQueryString .= ' or ';

            $additionalQueryString .= '(tag has ' . TH::$tag_misc_unused . ') or (tag has ' . TH::$tag_NTBR_onlyInvalidApps . ')';
        }
        if( $updateOnlyActivatedRules )
        {
            if( strlen($additionalQueryString) > 0 )
                $additionalQueryString .= ' or ';

            $additionalQueryString .= '(tag has.regex /^' . TH::$tagBase . 'activated#' . '/) and (tag has ' . TH::$tag_misc_convertedRule . ')';
        }

        if( strlen($additionalQueryString) > 0 )
            $additionalQueryString = ' and ( ' . $additionalQueryString . ' )';


        $rules = $subSystem->securityRules->rules("(description regex /" . RuleIDTagLibrary::$tagBaseName . "/) and !(tag has " . TH::$tag_misc_ignore . " )" . $additionalQueryString );

        PH::print_stdout(" - Found " . count($rules) . " rules which will potentially be processed for log statistics");

        PH::print_stdout("**** PROCESSING RULES ****");

        $ruleCount = 0;

        foreach( $rules as $rule )
        {
            /** @var SecurityRule $rule */
            $ruleCount++;
            $rule->display();
            PH::print_stdout(" * rule #$ruleCount out of " . count($rules) . "");

            if( $rule->isDisabled() )
            {
                PH::print_stdout("    * SKIPPED : it's disabled");
                PH::print_stdout();
                continue;
            }

            $stats = $ruleStats->getRuleStats($rule->name());

            if( $stats !== null && !$updatePreviousData && !$resetPreviousData )
            {
                PH::print_stdout("    * SKIPPED : found in cache");
                PH::print_stdout();
                continue;
            }

            $lastReportTime = (time() - $ruleStats->getRuleUpdateTimestamp($rule->name())) / (60 * 60 * 24);
            if( $lastReportTime < $skipIfLastReportLessThanXDays )
            {
                $lastReportTime = round($lastReportTime, 2);
                PH::print_stdout("    * SKIPPED : last report was run {$lastReportTime} days ago which is less then skipIfLastReportLessThanXDays value");
                PH::print_stdout();
                continue;
            }

            if( $resetPreviousData && $stats !== null )
            {
                PH::print_stdout(" * reset of existing statistics from previous run");
            }

            PH::print_stdout("   * Generating report... ");
            //if fastMode: panorama-trsum/trsum ELSE: panorama-traffic/traffic
            $oldWay = true;

            if( $oldWay )
            {
                $reports = $rule->API_getAppContainerStats2(time() - ($logHistory * 24 * 3600), time() + 0, TRUE);
                if( count($reports) == 0 )
                {
                    $reports = $rule->API_getAppContainerStats2(time() - ($logHistory * 24 * 3600), time() + 0, FALSE);
                }


                $ruleStats->createRuleStats($rule->name());

                PH::print_stdout("     * Results (" . count($reports) . "):");

                $ruleStats->updateRuleUpdateTimestamp($rule->name());

                foreach( $reports as $line )
                {
                    $count = array_pop($line);
                    $app = array_pop($line);

                    // if container of app is valid, we want to use this container rather than
                    $container = array_pop($line);
                    if( $container != null && strlen($container) > 0 && $container != 'none' && $container != '(null)' )
                        $app = $container;

                    PH::print_stdout("      - $app ($count)");

                    $ruleStats->addRuleStats($rule->name(), $app, $count);
                }
            }
            else
            {
                $reports = $rule->API_apps_seen();

                if(isset($reports['apps-seen']))
                {
                    $ruleStats->createRuleStats($rule->name());

                    PH::print_stdout("     * Results (" . $reports['apps-seen-count'] . "):");

                    foreach( $reports['apps-seen'] as $app => $line )
                    {
                        #if( $line['bytes'] > 0 ) {
                        #PH::print_stdout("      - $app ($count)");
                        $count = 0;
                        PH::print_stdout("      - $app ()");

                        $ruleStats->addRuleStats($rule->name(), $app, $count);
                        #}
                    }
                }
            }


            //not performant to write file for each rule
            #$ruleStats->save_to_file($ruleStatFile);

            PH::print_stdout();

            #######################################################
            //enalbe if fully published
            $srcOrDst = false;
            if( $srcOrDst )
            {
                PH::print_stdout("   * Generating SRC report... ");
                $reports = $rule->API_getAddressStats(time() - ($logHistory * 24 * 3600), time() + 0, 'src', TRUE);
                #print_r($reports);
                PH::print_stdout("     * Results (" . count($reports) . "):");


                $ruleStats->createRuleStats($rule->name(), true);
                $ruleStats->updateRuleUpdateTimestamp($rule->name(), true);


                foreach( $reports as $line )
                {
                    $count = array_pop($line);
                    $app = array_pop($line);

                    // if container of app is valid, we want to use this container rather than
                    $container = array_pop($line);
                    if( $container != null && strlen($container) > 0 && $container != 'none' && $container != '(null)' )
                        $app = $container;

                    PH::print_stdout("      - $app ($count)");

                    $ruleStats->addRuleStats_SrcDst($rule->name(), 'src', $app, $count);
                }

                PH::print_stdout("   * Generating DST report... ");
                $reports_dst = $rule->API_getAddressStats(time() - ($logHistory * 24 * 3600), time() + 0, 'dst', TRUE);
                #print_r($reports_dst);
                PH::print_stdout("     * Results (" . count($reports_dst) . "):");

                foreach( $reports_dst as $line )
                {
                    $count = array_pop($line);
                    $app = array_pop($line);

                    // if container of app is valid, we want to use this container rather than
                    $container = array_pop($line);
                    if( $container != null && strlen($container) > 0 && $container != 'none' && $container != '(null)' )
                        $app = $container;

                    PH::print_stdout("      - $app ($count)");

                    $ruleStats->addRuleStats_SrcDst($rule->name(), 'dst', $app, $count);
                }
                ###################


                //not performant to write file for each rule
                $ruleStats->save_to_file($ruleStatFile_SrcDst, true);
            }
        }


        $ruleStats->save_to_file($ruleStatFile);

        if( $srcOrDst )
            $ruleStats->save_to_file($ruleStatFile_SrcDst, true);


        //Todo - export not working for HTML but tool is using XML file - HTML is only for user
        #PH::print_stdout( "\n\nExporting stats to html file '{$ruleStatHtmlFile}'... " );
        #$ruleStats->exportToCSV($ruleStatHtmlFile);
    }
}
