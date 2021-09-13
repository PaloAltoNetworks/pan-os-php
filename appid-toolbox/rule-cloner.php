<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

print "\n************* START OF SCRIPT ".basename(__FILE__)." ************\n\n";
PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() );

$debugAPI = false;
$bundleApiCalls = false;

PH::processCliArgs();


function display_usage_and_exit()
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [bundleApiCalls] [ignoreApps=app1,app2...]".
        "\n";

    print "\n\n";

    exit(1);
}

if( isset(PH::$args['help']))
    display_usage_and_exit();

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit();
}

$supportedOptions = Array( 'in', 'out', 'location', 'bundleapicalls', 'ignoreapps', 'serial' );
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
elseif( $configInput['type'] == 'api' )
{
    #continue;
}
elseif ( $configInput['type'] != 'api' )
    derr('unsupported yet');

if( isset(PH::$args['bundleapicalls']) ||  $configInput['type'] == 'file' )
{
    print " - BundleApiCalls is ON\n";
    $bundleApiCalls = true;
}
else
    print " - BundleApiCalls is OFF\n";


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

}
else
    derr('not supported yet');


$ruleStats = new DeviceGroupRuleAppUsage();

if ( $configInput['type'] == 'api'  )
{
    $inputConnector->refreshSystemInfos();
    $device_serial = $inputConnector->info_serial;
}
else
    $device_serial = PH::$args['serial'];

$ruleStatFile = $device_serial.'-'.$location.'-stats.xml';

if( file_exists($ruleStatFile) )
{
    print " - Previous rule stats found, loading from file $ruleStatFile... ";
    $ruleStats->load_from_file($ruleStatFile);

}
else
    print " - No cached stats found (missing file '$ruleStatFile')\n";


$manualIgnoreApps = Array();
if( isset(PH::$args['ignoreApps']) )
{
    $explode = explode(',',PH::$args['ignoreApps']);
    foreach($explode as $i)
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
        print " - The following applications will be ignored : ".PH::list_to_string($manualIgnoreApps)."\n";
    }
}


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

print " - Detected platform type is '{$configType}'\n";

if( $configInput['type'] == 'api' )
    $pan->connector = $inputConnector;

//
// load the config
//
print " - Loading configuration through PAN-PHP-framework library... ";
$loadStartMem = memory_get_usage(true);
$loadStartTime = microtime(true);
$pan->load_from_domxml($xmlDoc);
$loadEndTime = microtime(true);
$loadEndMem = memory_get_usage(true);
$loadElapsedTime = number_format( ($loadEndTime - $loadStartTime), 2, '.', '');
$loadUsedMem = convert($loadEndMem - $loadStartMem);
print "($loadElapsedTime seconds, $loadUsedMem memory)\n";
// --------------------

$subSystem  = $pan->findSubSystemByName($location);

if( $subSystem === null )
    derr("cannot find vsys/dg named '$location', available locations list is : ");

print " - Found DG/Vsys '$location'\n";

print " - Looking/creating for necessary Tags to mark rules\n";
TH::createTags($pan, $configInput['type']);


//
// REAL JOB STARTS HERE
//
$string =
$rules = $subSystem->securityRules->rules("(description regex /".RuleIDTagLibrary::$tagBaseName."/) and !(tag has ".TH::$tag_misc_convertedRule.") and !(tag has ".TH::$tag_misc_ignore.") and !(tag has.regex /^".TH::$tagNtbrBase."/) and !(tag has ".TH::$tag_misc_clonedRule.")");

print " - Total number of rules: {$subSystem->securityRules->count()} vs ".count($rules)." potentially clonable\n";

print "\n*** PROCESSING !!!\n\n";

$count_ClonedRules = 0;
$array_ClonedRules = Array();

$count_unused = 0;
$count_notUnusedAnymore = 0;

$count_NTBR = 0;
$count_revised_NTBR = 0;

$loopCount = 0;

foreach($rules as $legacyRule)
{
    /** @var SecurityRule $legacyRule */
    $loopCount++;
    print "\nRule #{$loopCount} out of ".count($rules)."\n";
    print $legacyRule->display(1);
    $apps = $ruleStats->getRuleStats($legacyRule->name());
    if( $apps === null )
    {
        print "  - NO STATS AVAILABLE FOR THIS RULE\n";
        continue;
    }

    if( count($apps) == 0 )
    {
        $count_unused++;
        if( $legacyRule->tags->hasTag(TH::$tag_misc_unused) )
        {
            print "  - This rule was and is still unused\n";
            continue;
        }
        print "  - This rule seems to be unused, tagging it...";
        if( !$bundleApiCalls )
            $legacyRule->tags->API_addTag(TH::$tag_misc_unused_tagObject);
        else
            $legacyRule->tags->addTag(TH::$tag_misc_unused_tagObject);

        continue;
    }

    $ruleToBeRevised = false;

    if( $legacyRule->tags->hasTag(TH::$tag_misc_unused) )
    {
        $ruleToBeRevised = true;
        $count_notUnusedAnymore++;
        print " - This rule was marked as Unused but is not anymore, removing unused Tag...\n";
        if( !$bundleApiCalls )
            $legacyRule->tags->API_removeTag(TH::$tag_misc_unused_tagObject);
        else
            $legacyRule->tags->removeTag(TH::$tag_misc_unused_tagObject);
    }


    if( !$legacyRule->apps->isAny() )
    {
        print "  - original rule apps != ANY , tagging\n";
        if( !$bundleApiCalls )
            $legacyRule->tags->API_addTag(TH::$tag_NTBR_appNotAny_tagObject);
        else
            $legacyRule->tags->addTag(TH::$tag_NTBR_appNotAny_tagObject);

        $count_NTBR++;
        if( $ruleToBeRevised )
            $count_revised_NTBR++;

        continue;
    }

    print " - Found the following apps : ";
    foreach($apps as $app)
    {
        print $app['name'].',';
    }
    print "\n";

    $appsToPutInRule = Array();

    $manualIgnoreApps[] = 'aproach.ov';

    foreach($apps as $app)
    {
        if( $app['name'] == 'incomplete' || $app['name'] == 'insufficient-data' || $app['name'] == 'non-syn-tcp' || in_array($app['name'], $manualIgnoreApps) )
            continue;

        $appsToPutInRule[$app['name']] = $app['name'];
    }


    if( count($appsToPutInRule) == 0 )
    {
        if( !$legacyRule->tags->hasTag(TH::$tag_NTBR_onlyInvalidApps) )
        {
            print " - This rule has only invalid applications, tagging it\n";
            if( !$bundleApiCalls )
                $legacyRule->tags->API_addTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
            else
                $legacyRule->tags->addTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
        }
        else
            print " - only invalid apps, but it was already the case\n";


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
        $ruleToBeRevised = true;
        $count_revised_NTBR++;

        print " - removed tag '".TH::$tag_NTBR_onlyInvalidApps."'";
        if( !$bundleApiCalls )
            $legacyRule->tags->API_removeTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
        else
            $legacyRule->tags->removeTag(TH::$tag_NTBR_onlyInvalidApps_tagObject);
    }


    print " - The following apps will be added : ";
    foreach($appsToPutInRule as $app)
    {
        print $app.',';
    }
    print "\n";
    print " - now calculating dependencies\n";
    foreach($appsToPutInRule as $app)
    {
        print "  - $app\n";
        $appObject = $pan->appStore->find($app);
        if( $appObject !== null )
        {
            $explicits =  $appObject->calculateDependencies();
            if( count($explicits) > 0 )
            {
                print "    - ".PH::list_to_string($explicits)."\n";
                foreach($explicits as $explicit)
                    $appsToPutInRule[$explicit->name()] = $explicit->name();
            }
        }
    }

    $newName = $legacyRule->owner->findAvailableName($legacyRule->name(), '-app');
    print " - cloned rule name will be '{$newName}'\n";
    if( !$bundleApiCalls )
        $appidRule = $subSystem->securityRules->API_cloneRule($legacyRule, $newName);
    else
        $appidRule = $subSystem->securityRules->cloneRule($legacyRule, $newName);

    print " - created rule '{$appidRule->name()}'\n";
    if( !$bundleApiCalls )
    {
        $appidRule->API_setDisabled(true);
        $appidRule->tags->API_addTag(TH::$tag_misc_clonedRule_tagObject);
    }
    else
    {
        $appidRule->setDisabled(true);
        $appidRule->tags->addTag(TH::$tag_misc_clonedRule_tagObject);
    }

    foreach($appsToPutInRule as $app)
    {
        $appObject = $subSystem->appStore->findOrCreate($app);
        if( !$bundleApiCalls )
            $appidRule->apps->API_addApp($appObject);
        else
            $appidRule->apps->addApp($appObject);
    }

    if( $appidRule->apps->count() > 10 )
    {
        print " - cloned rule has too many apps, NTBR\n";
        if( !$bundleApiCalls )
            $appidRule->tags->API_addTag(TH::$tag_NTBR_tooManyApps_tagObject);
        else
            $appidRule->tags->addTag(TH::$tag_NTBR_tooManyApps_tagObject);
    }

    if( isset($appsToPutInRule['unknown-tcp']) || isset($appsToPutInRule['unknown-udp']) || isset($appsToPutInRule['unknown-p2p']) )
    {
        print " - cloned rule has unknown apps, NTBR\n";
        if( !$bundleApiCalls )
            $appidRule->tags->API_addTag(TH::$tag_NTBR_hasUnknownApps_tagObject);
        else
            $appidRule->tags->addTag(TH::$tag_NTBR_hasUnknownApps_tagObject);
    }

    if( $legacyRule->services->isApplicationDefault() )
    {if( !$bundleApiCalls )
            {$appidRule->services->API_setAny();}
        else
            {$appidRule->services->setAny();}
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

    print "- * RULE IS CLONED *\n";

    print "\n\n";

}

if( $bundleApiCalls  )
{
    if( $configInput['type'] == 'api' )
    {
        print "*** NOW DOING BUNDLED API CALL TO SYNC RULES ****\n";

        if( $pan->isPanorama() )
        {
            $xpath = $subSystem->getXPath().'/pre-rulebase/security/rules';
            print " - syncing pre-rulebase ... ";
            $pan->connector->sendEditRequest($xpath, DH::dom_to_xml($subSystem->securityRules->xmlroot));


            $xpath = $subSystem->getXPath().'/post-rulebase/security/rules';
            print " - syncing post-rulebase ... ";
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


print "\nlist of cloned Rules: \n";

foreach( $array_ClonedRules as $rule )
{
    print " - {$rule->name()}\n";
}

print "\n\n**** SUMMARY *****\n\n";

print " - cloned rules : {$count_ClonedRules}\n";
print " - unused : {$count_unused}\n";
print " - rules with fatal NTBR : {$count_NTBR}\n";
print " - revised unused rules : {$count_notUnusedAnymore}\n";
print " - revised rules fatal NTBR: {$count_revised_NTBR}\n";



print "\n\n";
print "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";

