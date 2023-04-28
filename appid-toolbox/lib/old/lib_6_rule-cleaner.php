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

/*
function display_usage_and_exit()
{
    PH::print_stdout( PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [confirm] [daysSinceLastReport=XX]");


    PH::print_stdout( "Listing optional arguments:");
    PH::print_stdout( "");
    PH::print_stdout( " - confirm : no change will be made to the config unless you use this argument");
    PH::print_stdout( " - daysSinceLastReport=X : (default=1) if a legacy rule last report is older than X days, it will not be cleaned");

    PH::print_stdout( "");

    exit(1);
}
*/

function ruleCleaner_Phase6_init()
{
    if( isset(PH::$args['help']) )
        display_usage_and_exit();

    $supportedOptions = array('phase', 'in', 'out', 'location', 'confirm', 'dayssincelastreport', 'serial');
    $supportedOptions = array_flip($supportedOptions);

    foreach( PH::$args as $arg => $argvalue )
    {
        if( !isset($supportedOptions[strtolower($arg)]) )
            display_error_usage_exit("unknown argument '{$arg}'");
    }
    unset($arg);

    $debugAPI = FALSE;
    $dryRun = TRUE;
    $skipIfLastReportIsMoreThanX_DaysOld = 1;


    $return = AppIDToolbox_common::location();
    $configInput = $return['configInput'];
    $location = $return['location'];


    if( isset(PH::$args['confirm']) )
        $dryRun = FALSE;


    if( isset(PH::$args['dayssincelastreport']) )
    {
        $skipIfLastReportIsMoreThanX_DaysOld = PH::$args['dayssincelastreport'];
        if( !is_numeric($skipIfLastReportIsMoreThanX_DaysOld) )
            derr("'daysSinceLastReport' value must be an integer, default is 1, provided '{$skipIfLastReportIsMoreThanX_DaysOld}'");

        PH::print_stdout(" - skipCleaningIfReportOlderThan {$skipIfLastReportIsMoreThanX_DaysOld} days");
    }
    else
        PH::print_stdout(" - skipCleaningIfReportOlderThan {$skipIfLastReportIsMoreThanX_DaysOld} days (default)");


    $return = AppIDToolbox_common::getConfig($configInput, $debugAPI, True);
    $xmlDoc = $return['xmlDoc'];
    $configOutput = $return['configOutput'];
    $inputConnector = $return['inputConnector'];

    if( $configInput['type'] == 'api' )
    {
        $inputConnector->refreshSystemInfos();
        $device_serial = $inputConnector->info_serial;
    }
    else
        $device_serial = PH::$args['serial'];

    $ruleStatFile = $device_serial . '-' . $location . '-stats.xml';

    $ruleStats = new DeviceGroupRuleAppUsage();

    if( file_exists($ruleStatFile) )
    {
        PH::print_stdout(" - Previous rule stats found, loading from file $ruleStatFile... ");
        $ruleStats->load_from_file($ruleStatFile);

    }
    else
        derr("No cached stats found (missing file '$ruleStatFile')");


    $return = AppIDToolbox_common::determineConfig($xmlDoc, $configInput, $inputConnector, $location);
    $subSystem = $return['subSystem'];
    $pan = $return['pan'];

    PH::print_stdout(" - Found DG/Vsys '$location'");
    PH::print_stdout(" - Looking/creating for necessary Tags to mark rules");
    TH::createTags($pan, $configInput['type']);

    //
    // REAL JOB STARTS HERE
    //
    ruleCleaner_Phase6_main($subSystem, $configInput, $pan, $inputConnector, $configOutput, $ruleStats, $skipIfLastReportIsMoreThanX_DaysOld, $dryRun );
}

function ruleCleaner_Phase6_main($subSystem, $configInput, $pan, $inputConnector, $configOutput, $ruleStats, $skipIfLastReportIsMoreThanX_DaysOld, $dryRun )
{


    $ridTagLibrary = new RuleIDTagLibrary();
    $ridTagLibrary->readFromRuleArray($subSystem->securityRules->rules());

    PH::print_stdout(" - Total number of RID tags found: {$ridTagLibrary->tagCount()}");

    PH::print_stdout("\n*** PROCESSING !!!");

    $countCleaned = 0;
    $countSkipped1_TooManyRules = 0;
    $countSkipped2_OnlyOneRule = 0;
    $countSkipped3_OriginalRuleNotFound = 0;
    $countSkipped4_ClonedRuleNotFound = 0;
    $countSkipped5_ClonedRuleHasNTBR = 0;
    $countSkipped6_OriginalRuleHasNTBR = 0;
    $countSkipped7_AppidRuleDisabled = 0;
    $countSkipped8_RulesMismatch = 0;
    $countSkipped9_MisOrderedRules = 0;
    $countSkipped10_ignore = 0;
    $countSkipped11_stillUsed = 0;
    $countSkipped12_noStats = 0;
    $countSkipped13_ruleUnused = 0;
    $countSkipped14_statsTimeStampNotFoundOrTooOld = 0;
    $countSkipped15_ruleUsedToBeUnused = 0;

    foreach( $ridTagLibrary->_tagsToObjects as $tagName => &$taggedRules )
    {
        /** @var SecurityRule $rule */

        PH::print_stdout("\n\n* tag {$tagName} with " . count($taggedRules) . " rules");

        foreach( $taggedRules as $rule )
        {
            PH::print_stdout(" - rule '{$rule->name()}'");
        }
        PH::print_stdout(" ");

        if( count($taggedRules) > 2 )
        {
            PH::print_stdout(" - SKIPPED#1 : more than 2 rules are tagged with this appRID, please fix");
            $countSkipped1_TooManyRules++;
            continue;
        }

        // for the case where original rule is alone (not cloned for appid)
        if( count($taggedRules) < 2 )
        {
            $rule = reset($taggedRules);
            if( $rule->tags->hasTag(TH::$tag_misc_ignore) )
            {
                PH::print_stdout(" - SKIPPED#10 : appid#ignore flag");
                $countSkipped10_ignore++;
                continue;
            }
            elseif( $rule->apps->isAny() && $rule->tags->hasTagRegex('/^' . TH::$tag_misc_unused . '/') )
            {
                if( !$ruleStats->isRuleUsed($rule->name()) === FALSE )
                {
                    $string = " - SKIPPED#15 : rule was marked as unused but is now used with the following apps: ";
                    $apps = $ruleStats->getRuleStats($rule->name());
                    $string .= ".  You should run it through cloner&activation scripts now";
                    PH::print_stdout($string);
                    PH::print_stdout(" - removed 'appid#unused' tag");
                    $rule->tags->removeTag(TH::$tag_misc_unused_tagObject);
                    $countSkipped15_ruleUsedToBeUnused++;
                    continue;
                }

                PH::print_stdout(" - SKIPPED#13 : original rule is unused");
                $countSkipped13_ruleUnused++;
                continue;
            }
            elseif( $rule->apps->isAny() && $rule->tags->hasTagRegex('/^' . TH::$tagNtbrBase . '/') )
            {
                PH::print_stdout(" - SKIPPED#6 : original rule has NTBR tags");
                $countSkipped6_OriginalRuleHasNTBR++;
                continue;
            }
            else
            {
                PH::print_stdout(" - SKIPPED#2 : only 1 rule is part of this appRID, needs manual cleaning?");
                $countSkipped2_OnlyOneRule++;
                continue;
            }
        }

        $legacyRule = null;
        $appidRule = null;
        /** @var SecurityRule $legacyRule */
        /** @var SecurityRule $appidRule */

        $alreadyActivated = FALSE;

        foreach( $taggedRules as $rule )
        {
            if( $rule->tags->hasTag(TH::$tag_misc_convertedRule) )
            {
                $legacyRule = $rule;
            }
            elseif( $rule->tags->hasTag(TH::$tag_misc_clonedRule) )
            {
                $appidRule = $rule;
            }
        }

        if( $legacyRule === null && $appidRule === null )
        {
            PH::print_stdout("SKIPPED#8 : rules mismatch, please fix manually ");
            continue;
        }

        if( $legacyRule === null )
        {
            PH::print_stdout(" - SKIPPED#3 : original rule not found, cleaning appRID now ");
            $countSkipped3_OriginalRuleNotFound++;
            PH::print_stdout(" - cleaning tagRID ");
            RuleIDTagLibrary::cleanRuleDescription($appidRule);
            PH::print_stdout(" - cleaning activationTag ");
            TH::cleanActivatedTag($appidRule);
            continue;
        }

        if( $legacyRule->tags->hasTag(TH::$tag_misc_ignore) )
        {
            PH::print_stdout(" - SKIPPED#10 : appid#ignore flag ");
            $countSkipped10_ignore++;

            if( $appidRule !== null )
            {
                PH::print_stdout(" - removed AppID rule ");
                $appidRule->owner->remove($appidRule);
            }

            PH::print_stdout(" - cleaning tagRID ");
            RuleIDTagLibrary::cleanRuleDescription($legacyRule);
            continue;
        }

        if( $appidRule === null )
        {
            PH::print_stdout(" - SKIPPED#4 : appID rule not found ");
            $countSkipped4_ClonedRuleNotFound++;
            PH::print_stdout(" - cleaning tagRID ");
            RuleIDTagLibrary::cleanRuleDescription($legacyRule);
            PH::print_stdout(" - cleaning activationTag ");
            TH::cleanActivatedTag($legacyRule);

            continue;
        }

        if( $legacyRule->tags->hasTagRegex('/^' . TH::$tagNtbrBase . '/') )
        {
            PH::print_stdout(" - SKIPPED#6 : original rule has NTBR tags ");
            $countSkipped6_OriginalRuleHasNTBR++;
            continue;
        }

        if( $appidRule->isDisabled() || !$appidRule->tags->hasTagRegex('/^' . TH::$tagActivatedBase . '/') )
        {
            PH::print_stdout(" - SKIPPED#7 : appidID rule is disabled or was not activated. ");
            $countSkipped7_AppidRuleDisabled++;
            continue;
        }

        if( $appidRule->tags->hasTag(TH::$tag_misc_ignore) )
        {
            PH::print_stdout(" - SKIPPED#10 : appid#ignore flag ");
            $countSkipped10_ignore++;
            if( $appidRule !== null )
            {
                PH::print_stdout(" - removed appID rule ");
                $appidRule->owner->remove($appidRule);
            }
            PH::print_stdout(" - cleaning tagRID ");
            RuleIDTagLibrary::cleanRuleDescription($legacyRule);
            continue;
        }

        $statsUpdateTimestamp = $ruleStats->getRuleUpdateTimestamp($legacyRule->name());
        if( $statsUpdateTimestamp === null )
        {
            PH::print_stdout(" - SKIPPED#14 : no timestamp found please run a report ");
            $countSkipped14_statsTimeStampNotFoundOrTooOld++;
            continue;
        }
        $daysSinceLastReport = days_between_timestamps(time(), $statsUpdateTimestamp);
        if( $daysSinceLastReport > $skipIfLastReportIsMoreThanX_DaysOld )
        {
            PH::print_stdout(" - SKIPPED#14 : report was generated a long time ago (" . timestamp_to_date($statsUpdateTimestamp) . "), please run reports again ");
            $countSkipped14_statsTimeStampNotFoundOrTooOld++;
            continue;
        }


        $apps = $ruleStats->getRuleStats($legacyRule->name());
        if( $apps === null )
        {
            PH::print_stdout(" - SKIPPED#12 : no stats available please run a report ");
            $countSkipped12_noStats++;
            continue;
        }

        // filter out unwanted apps
        foreach( $apps as $appName => $appRecord )
        {
            if( $appName == 'non-syn-tcp' )
                unset($apps[$appName]);
        }

        if( count($apps) > 0 )
        {
            PH::print_stdout(" - SKIPPED#11: legacy rule still in use with the following app(s): ");
            $apps = array_keys($apps);
            PH::print_stdout(PH::list_to_string($apps, ','));

            $appidRule->display(4);
            $countSkipped11_stillUsed++;
            continue;
        }


        PH::print_stdout(" * Good for cleaning !!!!! ");
        PH::print_stdout(" - removing legacy rule ");
        $legacyRule->owner->remove($legacyRule);
        PH::print_stdout(" - remove activationTag ");
        TH::cleanActivatedTag($appidRule);

        PH::print_stdout(" - remove clonedRule tag ");
        TH::cleanClonedTag($appidRule);

        PH::print_stdout(" - removeing appRID# from description ");
        RuleIDTagLibrary::cleanRuleDescription($appidRule);


        $countCleaned++;
    }

    PH::print_stdout("\n**** SYNCING RULES WITH DEVICE ****");

    if( !$dryRun )
    {
        if( $configInput['type'] == 'api' )
        {
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
            {
                $xpath = $subSystem->getXPath() . '/rulebase/security/rules';
                PH::print_stdout(" - syncing rulebase ... ");
                $pan->connector->sendEditRequest($xpath, DH::dom_to_xml($subSystem->securityRules->xmlroot));

            }
        }


    }


    PH::print_stdout("\n**** SUMMARY ****\n ");

    PH::print_stdout("Number of tags: " . count($ridTagLibrary->_tagsToObjects));
    if( $dryRun )
    {
        PH::print_stdout("Cleaned: $countCleaned (( if 'confirm' option had been used )) ");
    }
    else
    {
        PH::print_stdout("Cleaned: $countCleaned ");
    }

    PH::print_stdout();

    $lineLength = 50;
    PH::print_stdout(str_pad("SKIPPED#1 Too many rules :", $lineLength) . str_pad($countSkipped1_TooManyRules, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#2 Only 1 rule found :", $lineLength) . str_pad($countSkipped2_OnlyOneRule, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#3 Original rule not found:", $lineLength) . str_pad($countSkipped3_OriginalRuleNotFound, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#4 Cloned rule not found:", $lineLength) . str_pad($countSkipped4_ClonedRuleNotFound, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#5 Cloned rule has NTBR tags:", $lineLength) . str_pad($countSkipped5_ClonedRuleHasNTBR, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#6 Original rule has NTBR tags:", $lineLength) . str_pad($countSkipped6_OriginalRuleHasNTBR, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#7 AppID rule is disabled or not activated:", $lineLength) . str_pad($countSkipped7_AppidRuleDisabled, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#8 rules mismatch:", $lineLength) . str_pad($countSkipped8_RulesMismatch, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#9 legacy rule placed before AppID:", $lineLength) . str_pad($countSkipped9_MisOrderedRules, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#10 appid#ignore flag:", $lineLength) . str_pad($countSkipped10_ignore, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#11 legacy still in use:", $lineLength) . str_pad($countSkipped11_stillUsed, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#12 no stats available", $lineLength) . str_pad($countSkipped12_noStats, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#13 rule is unused", $lineLength) . str_pad($countSkipped13_ruleUnused, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#14 report was too old", $lineLength) . str_pad($countSkipped14_statsTimeStampNotFoundOrTooOld, 8, ' ', STR_PAD_LEFT));
    PH::print_stdout(str_pad("SKIPPED#15 legacy rule is not unused anymore:", $lineLength) . str_pad($countSkipped15_ruleUsedToBeUnused, 8, ' ', STR_PAD_LEFT));
    if( $dryRun )
    {
        PH::print_stdout("\n\n**** WARNING : no changes were made because you didn't use 'confirm' argument in the command line ****");
    }
    elseif( $configInput['type'] == 'file' )
    {
        // save our work !!!
        if( $configOutput !== null )
        {
            if( $configOutput != '/dev/null' )
            {
                PH::print_stdout("\n ");
                $pan->save_to_file($configOutput);
            }
        }
    }
    PH::print_stdout();
    PH::print_stdout();
}

