<?php

/**
 * ISC License
 *
  * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

require_once dirname(__FILE__) . "/lib/common.php";

PH::print_stdout( "************* START OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() . " [".PH::frameworkInstalledOS()."]" );

$debugAPI = false;
$dryRun = true;
$tagIssues = false;

PH::processCliArgs();


function display_usage_and_exit()
{
    global $argv;
    PH::print_stdout( PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [confirm] [tagIssues]");


    PH::print_stdout( "Listing optional arguments:" );

    PH::print_stdout( " - confirm : no change will be made to the config unless you use this argument" );
    PH::print_stdout( " - tagIssues : adds a tag to rules which cannot be activated" );

    PH::print_stdout( "" );


    exit(1);
}

function display_error_usage_exit($msg)
{
    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
        fwrite(STDERR, PH::boldText("**ERROR** ").$msg."");
    display_usage_and_exit();
}

$supportedOptions = Array( 'in', 'out', 'location', 'confirm' );
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
    //derr("file type input is not supported, only API");
}
elseif ( $configInput['type'] != 'api'  )
    derr('unsupported yet');

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

    $xmlDoc = new DOMDocument();
    if( ! $xmlDoc->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{
    $inputConnector = $configInput['connector'];
    if($debugAPI)
        $inputConnector->setShowApiCalls(true);
    PH::print_stdout( " - Downloading config from API... ");
    $xmlDoc = $inputConnector->getCandidateConfig();

}
else
    derr('not supported yet');

if( isset(PH::$args['confirm']) )
    $dryRun = false;


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

PH::print_stdout( " - Detected platform type is '{$configType}'" );

if( $configInput['type'] == 'api' )
    $pan->connector = $inputConnector;

//
// load the config
//
PH::print_stdout( " - Loading configuration through PAN-OS-PHP library... ");
$loadStartMem = memory_get_usage(true);
$loadStartTime = microtime(true);
$pan->load_from_domxml($xmlDoc);
$loadEndTime = microtime(true);
$loadEndMem = memory_get_usage(true);
$loadElapsedTime = number_format( ($loadEndTime - $loadStartTime), 2, '.', '');
$loadUsedMem = convert($loadEndMem - $loadStartMem);
PH::print_stdout( "($loadElapsedTime seconds, $loadUsedMem memory)" );
// --------------------

$subSystem  = $pan->findSubSystemByName($location);

if( $subSystem === null )
    derr("cannot find vsys/dg named '$location', available locations list is : ");

PH::print_stdout( " - Found DG/Vsys '$location'" );
PH::print_stdout( " - Looking/creating for necessary Tags to mark rules" );
TH::createTags($pan, $configInput['type']);


//
// REAL JOB STARTS HERE
//

$ridTagLibrary = new RuleIDTagLibrary();
$ridTagLibrary->readFromRuleArray($subSystem->securityRules->rules());

PH::print_stdout( " - Total number of RID tags found: {$ridTagLibrary->tagCount()}" );


PH::print_stdout( "*** PROCESSING !!!" );

$countAlreadyActivated = 0;
$countActivated = 0;
$countSkipped1_TooManyRules = 0;
$countSkipped2_OnlyOneRule = 0;
$countSkipped3_OriginalRuleNotFound = 0;
$countSkipped4_ClonedRuleNotFound = 0;
$countSkipped5_ClonedRuleHasNTBR = 0;
$countSkipped6_OriginalRuleHasNTBR = 0;
$countSkipped7_OriginalRuleDisabled = 0;
$countSkipped8_RulesMismatch = 0;
$countSkipped9_MisOrderedRules = 0;
$countSkipped10_ignore = 0;
$countSkipped13_ruleUnused = 0;


$todayActivationTag = null;

mt_srand(44);
foreach( $ridTagLibrary->_tagsToObjects as $tagName => &$taggedRules )
{
    /** @var SecurityRule $rule */

    PH::print_stdout( "* tag {$tagName} with ".count($taggedRules)." rules" );

    foreach( $taggedRules as $rule )
    {
        PH::print_stdout( " - rule '{$rule->name()}'" );
    }
    PH::print_stdout( "" );

    if( count($taggedRules) > 2 )
    {
        PH::print_stdout( " - SKIPPED#1 : more than 2 rules are tagged with this appRID, please fix" );
        $countSkipped1_TooManyRules++;
        continue;
    }

    if( count($taggedRules) < 2 )
    {
        $rule = reset($taggedRules);
        if( $rule->tags->hasTag(TH::$tag_misc_ignore) )
        {
            PH::print_stdout( " - SKIPPED#10 : appid#ignore flag" );
            $countSkipped10_ignore++;
        }
        elseif( $rule->apps->isAny() && $rule->tags->hasTagRegex('/^'.TH::$tag_misc_unused.'/') )
        {
            PH::print_stdout( " - SKIPPED#13 : original rule is unused" );
            $countSkipped13_ruleUnused++;
        }
        elseif( $rule->apps->isAny() && $rule->tags->hasTagRegex('/^'.TH::$tagNtbrBase.'/') )
        {
            PH::print_stdout( " - SKIPPED#6 : original rule has NTBR tags" );
            $countSkipped6_OriginalRuleHasNTBR++;
        }
        else
        {
            PH::print_stdout( " - SKIPPED#2 : only 1 rule is part of this appRID, needs cleaning?" );
            $countSkipped2_OnlyOneRule++;
        }
        continue;
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

    if( $legacyRule === null )
    {
        PH::print_stdout( " - SKIPPED#3 : original rule not found, please fix" );
        $countSkipped3_OriginalRuleNotFound++;
        continue;
    }

    if( $legacyRule->tags->hasTag(TH::$tag_misc_ignore) )
    {
        PH::print_stdout( " - SKIPPED#10 : appid#ignore flag" );
        $countSkipped10_ignore++;
        continue;
    }

    if( $appidRule === null )
    {
        PH::print_stdout( " - SKIPPED#4 : cloned rule not found, please fix" );
        $countSkipped4_ClonedRuleNotFound++;
        continue;
    }

    if( $appidRule->tags->hasTag(TH::$tag_misc_ignore) )
    {
        PH::print_stdout( " - SKIPPED#10 : appid#ignore flag" );
        $countSkipped10_ignore++;
        continue;
    }

    if( $appidRule->isEnabled() )
    {
        PH::print_stdout( " - SKIPPED : already activated" );
        $countAlreadyActivated++;
        continue;
    }

    if( $legacyRule->isDisabled() )
    {
        PH::print_stdout( " - SKIPPED#7 : original rule is disabled" );
        $countSkipped7_OriginalRuleDisabled++;
        continue;
    }

    if( $appidRule->tags->hasTagRegex('/^appid#NTBR/') )
    {
        PH::print_stdout( " - SKIPPED#5 cloned rule has NTBR tags" );
        $countSkipped5_ClonedRuleHasNTBR++;
        continue;
    }

    if( $legacyRule->tags->hasTagRegex('/^appid#NTBR/') )
    {
        PH::print_stdout( " - SKIPPED#6 cloned rule has NTBR tags" );
        $countSkipped6_OriginalRuleHasNTBR++;
        continue;
    }

    // Let's compare rules
    if( ! $legacyRule->from->equals($appidRule->from)
        || ! $legacyRule->to->equals($appidRule->to)
        || ! $legacyRule->source->equals($appidRule->source)
        || ! $legacyRule->destination->equals($appidRule->destination)
        || $legacyRule->destinationIsNegated() != $appidRule->destinationIsNegated()
        || $legacyRule->securityProfileType() != $appidRule->securityProfileType()
        || $legacyRule->securityProfileType() == 'group' && $legacyRule->securityProfileGroup() != $appidRule->securityProfileGroup()
        //|| ! $originalRule->services->equals($clonedRule->services)
      )
    {
        PH::print_stdout( " - SKIPPED#8 original and cloned rules aren't the same" );
        if( !$legacyRule->source->equals($appidRule->source) )
        {
            $legacyRule->source->displayMembersDiff($appidRule->source, 4);
        }
        if( !$legacyRule->destination->equals($appidRule->destination) )
        {
            $legacyRule->destination->displayMembersDiff($appidRule->destination, 4);
        }
        $countSkipped8_RulesMismatch++;
        continue;
    }

    if( $subSystem->securityRules->getRulePosition($legacyRule) < $subSystem->securityRules->getRulePosition($appidRule) )
    {
        PH::print_stdout( " - SKIPPED#9 legacy rule is placed before AppID one" );
        $countSkipped9_MisOrderedRules++;
        continue;
    }

    // TODO: check appidRule app is not Any

    $countActivated++;

    // TODO: 20180216 for diff between files the rand() operation is a problem - search for something different
    //$legacyRuleNewName = str_replace('#', '-',$tagName).'-'.rand(10000,99999);
    $legacyRuleNewName = str_replace('#', '-',$tagName).'-'.mt_rand(10000,99999);
    $legacyRuleNewName = $subSystem->securityRules->findAvailableName($legacyRuleNewName);
    $legacyRuleOldName = $legacyRule->name();

    PH::print_stdout( " - legacy rule will be renamed to '{$legacyRuleNewName}'" );

    if( $todayActivationTag === null )
    {
        $todayActivationTagName = TH::$tagBase.'activated#'.date("Ymd");
        $todayActivationTag = $subSystem->tagStore->find($todayActivationTagName);
        if( $todayActivationTag === null )
        {
            PH::print_stdout( " - created today activation tag: '{$todayActivationTagName}'" );
            if( $dryRun || $configInput['type'] == 'file')
                $todayActivationTag = $subSystem->tagStore->createTag($todayActivationTagName);
            elseif( $configInput['type'] == 'api' )
                $todayActivationTag = $subSystem->tagStore->API_createTag($todayActivationTagName);
        }

        unset($todayActivationTagName);
    }



    if( $dryRun )
    {
        PH::print_stdout( " - no action taken because 'confirm' argument was not used" );
        continue;
    }

    if( $configInput['type'] == 'api' )
    {
        PH::print_stdout( " - renaming legacy rule... ");
        $legacyRule->API_setName($legacyRuleNewName);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - applying log at start on legacy rule... ");
        $legacyRule->API_setLogStart(true);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - tagging legacy rule with activation day... ");
        $legacyRule->tags->API_addTag($todayActivationTag);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - renaming appID rule with legacy rule name... ");
        $appidRule->API_setName($legacyRuleOldName);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - tagging appID rule with activation day... ");
        $appidRule->tags->API_addTag($todayActivationTag);
        PH::print_stdout( "OK" );

        $appidRule->API_setEnabled(true);
        PH::print_stdout( " - enabling appID rule... ");
        PH::print_stdout( "OK" );
    }
    else
    {
        PH::print_stdout( " - renaming legacy rule... ");
        $legacyRule->setName($legacyRuleNewName);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - applying log at start on legacy rule... ");
        $legacyRule->setLogStart(true);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - tagging legacy rule with activation day... ");
        $legacyRule->tags->addTag($todayActivationTag);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - renaming appID rule with legacy rule name... ");
        $appidRule->setName($legacyRuleOldName);
        PH::print_stdout( "OK" );

        PH::print_stdout( " - tagging appID rule with activation day... ");
        $appidRule->tags->addTag($todayActivationTag);
        PH::print_stdout( "OK" );

        $appidRule->setEnabled(true);
        PH::print_stdout( " - enabling appID rule... ");
        PH::print_stdout( "OK" );
    }




}

PH::print_stdout( "**** SUMMARY ****" );

PH::print_stdout( "Number of tags: ".count($ridTagLibrary->_tagsToObjects) );
if( $dryRun )
{
    PH::print_stdout( "Activated: $countActivated (( if 'confirm' option had been used ))" );
}
else
{
    PH::print_stdout( "Activated: $countActivated" );
}
PH::print_stdout( "Already Activated: $countAlreadyActivated" );
PH::print_stdout( str_pad("SKIPPED#1 Too many rules :", 40).str_pad($countSkipped1_TooManyRules,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#2 Only 1 rule :",40).str_pad($countSkipped2_OnlyOneRule,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#3 Original rule not found:",40).str_pad($countSkipped3_OriginalRuleNotFound,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#4 Cloned rule not found:",40).str_pad($countSkipped4_ClonedRuleNotFound,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#5 Cloned rule has NTBR tags:",40).str_pad($countSkipped5_ClonedRuleHasNTBR,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#6 Original rule has NTBR tags:",40).str_pad($countSkipped6_OriginalRuleHasNTBR,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#7 Original rule is disabled:",40).str_pad($countSkipped7_OriginalRuleDisabled,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#8 rules mismatch:",40).str_pad($countSkipped8_RulesMismatch,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#9 legacy rule placed before AppID:",40).str_pad($countSkipped9_MisOrderedRules,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#10 appid#ignore flag:",40).str_pad($countSkipped10_ignore,8,' ',STR_PAD_LEFT) );
PH::print_stdout( str_pad("SKIPPED#13 legacy rule unused:",40).str_pad($countSkipped13_ruleUnused,8,' ',STR_PAD_LEFT) );


if( $dryRun )
{
    PH::print_stdout( "**** WARNING : no changes were made because you didn't use 'confirm' argument in the command line ****" );
}
elseif( $configInput['type'] == 'file' )
{
    // save our work !!!
    if( $configOutput !== null )
    {
        if( $configOutput != '/dev/null' )
        {
            PH::print_stdout( "" );
            $pan->save_to_file($configOutput);
        }
    }
}
PH::print_stdout( "" );

PH::print_stdout( "************* END OF SCRIPT ".basename(__FILE__)." ************" );

