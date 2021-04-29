<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

echo "\n************* START OF SCRIPT ".basename(__FILE__)." ************\n\n";

require_once dirname(__FILE__) . "/lib/common.php";

$debugAPI = false;
$dryRun = true;
$skipIfLastReportIsMoreThanX_DaysOld = 1;

PH::processCliArgs();

function display_usage_and_exit()
{
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [confirm] [daysSinceLastReport=XX]".
        "\n\n";


    echo "Listing optional arguments:\n\n";

    echo " - confirm : no change will be made to the config unless you use this argument\n";
    echo " - daysSinceLastReport=X : (default=1) if a legacy rule last report is older than X days, it will not be cleaned\n";

    echo "\n\n";

    exit(1);
}

if( isset(PH::$args['help']))
    display_usage_and_exit();

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit();
}

$supportedOptions = Array( 'in', 'out', 'location', 'confirm', 'dayssincelastreport', 'serial' );
$supportedOptions = array_flip($supportedOptions);

foreach( PH::$args as $arg => $argvalue )
{
    if( !isset($supportedOptions[strtolower($arg)]) )
        display_error_usage_exit("unknown argument '{$arg}''");
}
unset($arg);

if( !isset(PH::$args['location']) )
    display_error_usage_exit("missing argument 'location'");

$location = PH::$args['location'];

if( strlen($location) < 0 || !is_string($location) )
    display_error_usage_exit("'location' argument must be a valid string");

if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

$configInput = PH::processIOMethod($configInput, true);
if( $configInput['status'] != 'ok' )
{
    derr($configInput['msg']);
}
if( $configInput['type'] == 'file' )
{
    #derr("file type input is not supported, only API");
}
elseif ( $configInput['type'] != 'api'  )
    derr('unsupported yet');

if( isset(PH::$args['confirm']) )
    $dryRun = false;


if( isset(PH::$args['dayssincelastreport']) )
{
    $skipIfLastReportIsMoreThanX_DaysOld = PH::$args['dayssincelastreport'];
    if( !is_numeric($skipIfLastReportIsMoreThanX_DaysOld) )
        derr("'daysSinceLastReport' value must be an integer, default is 1, provided '{$skipIfLastReportIsMoreThanX_DaysOld}'");

    echo " - skipCleaningIfReportOlderThan {$skipIfLastReportIsMoreThanX_DaysOld} days\n";
}
else
    echo " - skipCleaningIfReportOlderThan {$skipIfLastReportIsMoreThanX_DaysOld} days (default)\n";


/** @var $inputConnector PanAPIConnector */
$inputConnector = null;

if( $configInput['type'] == 'file' )
{
    if(isset(PH::$args['out']) )
    {
        $configOutput = PH::$args['out'];
        if (!is_string($configOutput) || strlen($configOutput) < 1)
            display_error_usage_exit('"out" argument is not a valid string');
    }
    else
        display_error_usage_exit('"out" is missing from arguments');

    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    if( ! isset(PH::$args['serial']) )
        display_error_usage_exit('"serial" is missing from arguments');

    $xmlDoc = new DOMDocument();
    if( ! $xmlDoc->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{
    $inputConnector = $configInput['connector'];
    if($debugAPI)
        $inputConnector->setShowApiCalls(true);
    print " - Downloading config from API... ";
    $xmlDoc = $inputConnector->getCandidateConfig();
    print "OK!\n";
}
else
    derr('not supported yet');

if ( $configInput['type'] == 'api'  )
{
    $inputConnector->refreshSystemInfos();
    $device_serial = $inputConnector->info_serial;
}
else
    $device_serial = PH::$args['serial'];

$ruleStatFile = $device_serial.'-'.$location.'-stats.xml';

$ruleStats = new DeviceGroupRuleAppUsage();

if( file_exists($ruleStatFile) )
{
    echo " - Previous rule stats found, loading from file $ruleStatFile... ";
    $ruleStats->load_from_file($ruleStatFile);
    echo "OK!\n";
}
else
    derr("No cached stats found (missing file '$ruleStatFile')");




//
// Determine if PANOS or Panorama
//
$xpathResult = DH::findXPath('/config/devices/entry/vsys', $xmlDoc);
if( $xpathResult === FALSE )
    derr('XPath error happened');
if( $xpathResult->length <1 )
    $configType = 'panorama';
else
    $configType = 'panos';
unset($xpathResult);


if( $configType == 'panos' )
    $pan = new PANConf();
else
    $pan = new PanoramaConf();

echo " - Detected platform type is '{$configType}'\n";

if( $configInput['type'] == 'api' )
    $pan->connector = $inputConnector;


//
// load the config
//
echo " - Loading configuration through PAN-PHP-framework library... ";
$loadStartMem = memory_get_usage(true);
$loadStartTime = microtime(true);
$pan->load_from_domxml($xmlDoc);
$loadEndTime = microtime(true);
$loadEndMem = memory_get_usage(true);
$loadElapsedTime = number_format( ($loadEndTime - $loadStartTime), 2, '.', '');
$loadUsedMem = convert($loadEndMem - $loadStartMem);
echo "OK! ($loadElapsedTime seconds, $loadUsedMem memory)\n";
// --------------------

$subSystem  = $pan->findSubSystemByName($location);

if( $subSystem === null )
    derr("cannot find vsys/dg named '$location', available locations list is : ");

echo " - Found DG/Vsys '$location'\n";

echo " - Looking/creating for necessary Tags to mark rules\n";
TH::createTags($pan, $configInput['type']);


//
// REAL JOB STARTS HERE
//

$ridTagLibrary = new RuleIDTagLibrary();
$ridTagLibrary->readFromRuleArray($subSystem->securityRules->rules());

echo " - Total number of RID tags found: {$ridTagLibrary->tagCount()}\n";

echo "\n*** PROCESSING !!!\n\n";

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
$countSkipped12_noStats =0;
$countSkipped13_ruleUnused = 0;
$countSkipped14_statsTimeStampNotFoundOrTooOld = 0;
$countSkipped15_ruleUsedToBeUnused = 0;

foreach( $ridTagLibrary->_tagsToObjects as $tagName => &$taggedRules )
{
    /** @var SecurityRule $rule */

    echo "\n\n* tag {$tagName} with " . count($taggedRules) . " rules\n";

    foreach ($taggedRules as $rule)
    {
        echo " - rule '{$rule->name()}'\n";
    }
    echo "\n";

    if( count($taggedRules) > 2 )
    {
        echo " - SKIPPED#1 : more than 2 rules are tagged with this appRID, please fix\n";
        $countSkipped1_TooManyRules++;
        continue;
    }

    // for the case where original rule is alone (not cloned for appid)
    if( count($taggedRules) < 2 )
    {
        $rule = reset($taggedRules);
        if( $rule->tags->hasTag(TH::$tag_misc_ignore) )
        {
            echo " - SKIPPED#10 : appid#ignore flag\n";
            $countSkipped10_ignore++;
            continue;
        }
        elseif( $rule->apps->isAny() && $rule->tags->hasTagRegex('/^'.TH::$tag_misc_unused.'/')  )
        {
            if( !$ruleStats->isRuleUsed($rule->name() ) === FALSE )
            {
                echo " - SKIPPED#15 : rule was marked as unused but is now used with the following apps: ";
                $apps = $ruleStats->getRuleStats( $rule->name() );
                echo ".  You should run it through cloner&activation scripts now\n";
                echo " - removed 'appid#unused' tag\n";
                $rule->tags->removeTag(TH::$tag_misc_unused_tagObject);
                $countSkipped15_ruleUsedToBeUnused++;
                continue;
            }

            echo " - SKIPPED#13 : original rule is unused\n";
            $countSkipped13_ruleUnused++;
            continue;
        }
        elseif( $rule->apps->isAny() && $rule->tags->hasTagRegex('/^'.TH::$tagNtbrBase.'/') )
        {
            echo " - SKIPPED#6 : original rule has NTBR tags\n";
            $countSkipped6_OriginalRuleHasNTBR++;
            continue;
        }
        else
        {
            echo " - SKIPPED#2 : only 1 rule is part of this appRID, needs manual cleaning?\n";
            $countSkipped2_OnlyOneRule++;
            continue;
        }
    }

    $legacyRule = null;
    $appidRule = null;
    /** @var SecurityRule $legacyRule */
    /** @var SecurityRule $appidRule */

    $alreadyActivated = false;

    foreach($taggedRules as $rule)
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
        echo "SKIPPED#8 : rules mismatch, please fix manually\n";
        continue;
    }

    if( $legacyRule === null )
    {
        echo " - SKIPPED#3 : original rule not found, cleaning appRID now\n";
        $countSkipped3_OriginalRuleNotFound++;
        echo " - cleaning tagRID\n";
        RuleIDTagLibrary::cleanRuleDescription($appidRule);
        echo " - cleaning activationTag\n";
        TH::cleanActivatedTag($appidRule);
        continue;
    }

    if( $legacyRule->tags->hasTag(TH::$tag_misc_ignore) )
    {
        echo " - SKIPPED#10 : appid#ignore flag\n";
        $countSkipped10_ignore++;

        if( $appidRule !== null )
        {
            echo " - removed AppID rule\n";
            $appidRule->owner->remove($appidRule);
        }

        echo " - cleaning tagRID\n";
        RuleIDTagLibrary::cleanRuleDescription($legacyRule);
        continue;
    }

    if( $appidRule === null )
    {
        echo " - SKIPPED#4 : appID rule not found\n";
        $countSkipped4_ClonedRuleNotFound++;
        echo " - cleaning tagRID\n";
        RuleIDTagLibrary::cleanRuleDescription($legacyRule);
        echo " - cleaning activationTag\n";
        TH::cleanActivatedTag($legacyRule);

        continue;
    }

    if( $legacyRule->tags->hasTagRegex('/^'.TH::$tagNtbrBase.'/') )
    {
        echo " - SKIPPED#6 : original rule has NTBR tags\n";
        $countSkipped6_OriginalRuleHasNTBR++;
        continue;
    }

    if( $appidRule->isDisabled() || !$appidRule->tags->hasTagRegex('/^'.TH::$tagActivatedBase.'/') )
    {
        echo " - SKIPPED#7 : appidID rule is disabled or was not activated.\n";
        $countSkipped7_AppidRuleDisabled++;
        continue;
    }

    if( $appidRule->tags->hasTag(TH::$tag_misc_ignore) )
    {
        echo " - SKIPPED#10 : appid#ignore flag\n";
        $countSkipped10_ignore++;
        if( $appidRule !== null )
        {
            echo " - removed appID rule\n";
            $appidRule->owner->remove($appidRule);
        }
        echo " - cleaning tagRID\n";
        RuleIDTagLibrary::cleanRuleDescription($legacyRule);
        continue;
    }

    $statsUpdateTimestamp = $ruleStats->getRuleUpdateTimestamp($legacyRule->name());
    if( $statsUpdateTimestamp === null )
    {
        echo " - SKIPPED#14 : no timestamp found please run a report\n";
        $countSkipped14_statsTimeStampNotFoundOrTooOld++;
        continue;
    }
    $daysSinceLastReport = days_between_timestamps(time(), $statsUpdateTimestamp);
    if(  $daysSinceLastReport > $skipIfLastReportIsMoreThanX_DaysOld )
    {
        echo " - SKIPPED#14 : report was generated a long time ago (".timestamp_to_date($statsUpdateTimestamp)."), please run reports again\n";
        $countSkipped14_statsTimeStampNotFoundOrTooOld++;
        continue;
    }


    $apps = $ruleStats->getRuleStats($legacyRule->name());
    if( $apps === null )
    {
        echo " - SKIPPED#12 : no stats available please run a report\n";
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
        echo " - SKIPPED#11: legacy rule still in use with the following app(s): ";
        $apps = array_keys($apps);
        print PH::list_to_string($apps, ',');
        echo "\n";
        $appidRule->display(4);
        $countSkipped11_stillUsed++;
        continue;
    }


    echo " * Good for cleaning !!!!!\n";
    echo " - removing legacy rule\n";
    $legacyRule->owner->remove($legacyRule);
    echo " - remove activationTag\n";
    TH::cleanActivatedTag($appidRule);

    echo " - remove clonedRule tag\n";
    TH::cleanClonedTag($appidRule);

    echo " - removeing appRID# from description\n";
    RuleIDTagLibrary::cleanRuleDescription($appidRule);


    $countCleaned++;
}

echo "\n**** SYNCING RULES WITH DEVICE ****\n\n";

if( !$dryRun )
{
    if( $configInput['type'] == 'api' )
    {
        if( $pan->isPanorama() )
        {
            $xpath = $subSystem->getXPath().'/pre-rulebase/security/rules';
            echo " - syncing pre-rulebase ... ";
            $pan->connector->sendEditRequest($xpath, DH::dom_to_xml($subSystem->securityRules->xmlroot));
            echo "OK!\n";

            $xpath = $subSystem->getXPath().'/post-rulebase/security/rules';
            echo " - syncing post-rulebase ... ";
            $pan->connector->sendEditRequest($xpath, DH::dom_to_xml($subSystem->securityRules->postRulesRoot));
            echo "OK!\n";
        }
        else
        {
            $xpath = $subSystem->getXPath().'/rulebase/security/rules';
            echo " - syncing rulebase ... ";
            $pan->connector->sendEditRequest($xpath, DH::dom_to_xml($subSystem->securityRules->xmlroot));
            echo "OK!\n";
        }
    }


}


echo "\n**** SUMMARY ****\n\n";

echo "Number of tags: ".count($ridTagLibrary->_tagsToObjects)."\n";
if( $dryRun )
{
    echo "Cleaned: $countCleaned (( if 'confirm' option had been used ))\n";
}
else
{
    echo "Cleaned: $countCleaned\n";
}

echo "\n";

$lineLength = 50;
print str_pad("SKIPPED#1 Too many rules :", $lineLength).str_pad($countSkipped1_TooManyRules,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#2 Only 1 rule found :",$lineLength).str_pad($countSkipped2_OnlyOneRule,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#3 Original rule not found:",$lineLength).str_pad($countSkipped3_OriginalRuleNotFound,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#4 Cloned rule not found:",$lineLength).str_pad($countSkipped4_ClonedRuleNotFound,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#5 Cloned rule has NTBR tags:",$lineLength).str_pad($countSkipped5_ClonedRuleHasNTBR,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#6 Original rule has NTBR tags:",$lineLength).str_pad($countSkipped6_OriginalRuleHasNTBR,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#7 AppID rule is disabled or not activated:",$lineLength).str_pad($countSkipped7_AppidRuleDisabled,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#8 rules mismatch:",$lineLength).str_pad($countSkipped8_RulesMismatch,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#9 legacy rule placed before AppID:",$lineLength).str_pad($countSkipped9_MisOrderedRules,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#10 appid#ignore flag:",$lineLength).str_pad($countSkipped10_ignore,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#11 legacy still in use:",$lineLength).str_pad($countSkipped11_stillUsed,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#12 no stats available",$lineLength).str_pad($countSkipped12_noStats,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#13 rule is unused",$lineLength).str_pad($countSkipped13_ruleUnused,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#14 report was too old",$lineLength).str_pad($countSkipped14_statsTimeStampNotFoundOrTooOld,8,' ',STR_PAD_LEFT)."\n";
print str_pad("SKIPPED#15 legacy rule is not unused anymore:",$lineLength).str_pad($countSkipped15_ruleUsedToBeUnused,8,' ',STR_PAD_LEFT)."\n";
if( $dryRun )
{
    echo "\n\n**** WARNING : no changes were made because you didn't use 'confirm' argument in the command line ****\n\n";
}
elseif( $configInput['type'] == 'file' )
{
    // save our work !!!
    if( $configOutput !== null )
    {
        if( $configOutput != '/dev/null' )
        {
            print "\n\n";
            $pan->save_to_file($configOutput);
        }
    }
}
echo "\n\n";


echo "\n\n";

echo "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";
