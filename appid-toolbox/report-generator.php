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

print "\n************* START OF SCRIPT ".basename(__FILE__)." ************\n\n";

require_once dirname(__FILE__) . "/lib/common.php";
PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() );
PH::processCliArgs();

function display_usage_and_exit()
{
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [OPTIONAL ARGS]".
        "\n\n";

    print "Listing optional arguments:\n\n";

    print " - debugapi : outputs API calls live to help debugging\n";
    print " - logHistory=XX : script will generate rules usage reports based on the XX last days time period(default=60)\n";
    print " - updateOnlyUnusedTagRules : only the rules which have tag appid#NTBR#unused will have a usage report generated\n";
    print " - updateOnlyActivatedRules : useful to check if legacy rules are still unused\n";
    print " - resetPreviousData : if previous data was found, erase them and insert newly generated statistics instead (incompatible with update flag)\n";
    print " - skipIfLastReportLessThanXDays : if previous data was found, erase them and insert newly generated statistics instead (incompatible with update flag)\n";
    print " - updatePreviousData : if previous data was found, merge with previous statistics (incompatible with reset flag)\n";

    print "\n\n";


    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit();
}
$supportedOptions = Array( 'debugapi', 'in', 'location', 'loghistory', 'resetpreviousdata', 'updatepreviousdata', 'updateonlyunusedtagrules', 'updateonlyactivatedrules', 'skipiflastreportlessthanxdays' );
$supportedOptions = array_flip($supportedOptions);

foreach( PH::$args as $arg => $argvalue )
{
    if( !isset($supportedOptions[strtolower($arg)]) )
        display_error_usage_exit("unknown argument '{$arg}''");
}
unset($arg);



$debugAPI = false;
$logHistory = 60;
$resetPreviousData = false;
$updatePreviousData = false;
$updateOnlyUnusedTagRules = false;
$updateOnlyActivatedRules = false;
$skipIfLastReportLessThanXDays = 1;

$ruleStats = new DeviceGroupRuleAppUsage();


if( !isset(PH::$args['location']) )
    display_error_usage_exit("missing argument 'location'");

$location = PH::$args['location'];

if( strlen($location) < 0 || !is_string($location) )
    display_error_usage_exit("'location' argument must be a valid string");

if( isset(PH::$args['debugapi']) )
{
    $debugAPI = true;
}

if( isset(PH::$args['loghistory']) )
{
    $logHistory = PH::$args['loghistory'];
    if( ! is_numeric($logHistory) )
    {
        display_error_usage_exit("'logHistory' argument was provided but it's not a number");
    }
    print " - 'logHistory' overridden from CLI : {$logHistory} days\n";
}
else
    print " - no logHistory value was provided, using default= {$logHistory} days\n";


if( isset(PH::$args['skipiflastreportlessthanxdays']) )
{
    $skipIfLastReportLessThanXDays = PH::$args['skipiflastreportlessthanxdays'];
    print " - skipIfLastReportLessThanXDays set to {$skipIfLastReportLessThanXDays} days\n";
}
else
    print " - skipIfLastReportLessThanXDays not set, using default ({$skipIfLastReportLessThanXDays} days)\n";



if( isset(PH::$args['resetpreviousdata']) )
{
    $resetPreviousData = true;
    print " - resetPreviousData enabled\n";
}
else
    print " - resetPreviousData disabled\n";

if( isset(PH::$args['updatepreviousdata']) )
{
    $updatePreviousData = true;
    print " - updatePreviousData enabled\n";
}
else
    print " - updatePreviousData disabled\n";

if( isset(PH::$args['updateonlyunusedtagrules']) )
{
    $updateOnlyUnusedTagRules = true;
    print " - updateOnlyUnusedTagRules enabled\n";
    if( !$resetPreviousData && !$updatePreviousData )
        display_error_usage_exit("when updateOnlyUnusedTagRules mode is used you need to use one of the following too: resetPreviousData or updatePreviousData");
}
else
    print " - updateOnlyUnusedTagRules disabled\n";

if( isset(PH::$args['updateonlyactivatedrules']) )
{
    $updateOnlyActivatedRules = true;
    print " - updateOnlyActivatedRules enabled\n";
    $updatePreviousData = true;
}
else
    print " - updateOnlyActivatedRules disabled\n";


if( $resetPreviousData && $updatePreviousData )
{
    display_error_usage_exit("'reset' and 'update' flags are exclusive and can't both be set at the same time");
}


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
    derr("file type input is not supported, only API");
}
elseif ( $configInput['type'] != 'api'  )
    derr('unsupported yet');

/** @var PanAPIConnector $connector */
$connector = $configInput['connector'];
if($debugAPI)
    $connector->setShowApiCalls(true);
print " - Downloading config from API... ";
$xmlDoc = $connector->getCandidateConfig();



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
    $pan->connector = $connector;
// --------------------


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
    derr("cannot find vsys/dg named '$location', available locations list is : ".PH::list_to_string($pan->deviceGroups));

$connector->refreshSystemInfos();
$ruleStatFile = $connector->info_serial.'-'.$location.'-stats.xml';
$ruleStatHtmlFile = $connector->info_serial.'-'.$location.'-stats.html';

if( file_exists($ruleStatFile) )
{
    print " - Previous rule stats found, loading from file $ruleStatFile... ";
    $ruleStats->load_from_file($ruleStatFile);

}
else
    print " - No cached stats found (missing file '$ruleStatFile')\n";


//
// Cooking additional query parameters
//
$additionalQueryString = '';
if( $updateOnlyUnusedTagRules )
{
    if( strlen($additionalQueryString) > 0 )
        $additionalQueryString .= ' or ';

    $additionalQueryString .= '(tag has '.TH::$tag_misc_unused.') or (tag has '.TH::$tag_NTBR_onlyInvalidApps.')';
}
if( $updateOnlyActivatedRules )
{
    if( strlen($additionalQueryString) > 0 )
        $additionalQueryString .= ' or ';

    $additionalQueryString .= '(tag has.regex /^'.TH::$tagBase.'activated#'.'/) and (tag has '.TH::$tag_misc_convertedRule.')';
}

if( strlen($additionalQueryString) > 0 )
    $additionalQueryString = ' and ( '.$additionalQueryString.' )';



$rules = $subSystem->securityRules->rules( "(description regex /".RuleIDTagLibrary::$tagBaseName."/) and !(tag has ".TH::$tag_misc_ignore." )".$additionalQueryString
                                          );

print " - Found ".count($rules)." rules which will potentially be processed for log statistics\n";

print "\n**** PROCESSING RULES ****\n\n";

$ruleCount = 0;

foreach($rules as $rule)
{
    /** @var SecurityRule $rule */
    $ruleCount++;
    $rule->display();
    print " * rule #$ruleCount out of ".count($rules)."\n";

    if( $rule->isDisabled() )
    {
        print "\n    * SKIPPED : it's disabled\n\n";
        continue;
    }

    $stats = $ruleStats->getRuleStats($rule->name());

    if( $stats !== null && ! $updatePreviousData && ! $resetPreviousData )
    {
        print "\n    * SKIPPED : found in cache\n\n";
        continue;
    }

    $lastReportTime = ( time() - $ruleStats->getRuleUpdateTimestamp($rule->name()) ) / (60*60*24);
    if( $lastReportTime < $skipIfLastReportLessThanXDays )
    {
        $lastReportTime = round($lastReportTime, 2);
        print "\n    * SKIPPED : last report was run {$lastReportTime} days ago which is less then skipIfLastReportLessThanXDays value\n\n";
        continue;
    }

    if( $resetPreviousData && $stats !== null )
    {
        print " * reset of existing statistics from previous run\n";
    }

    print "\n   * Generating report... ";
    //if fastMode: panorama-trsum/trsum ELSE: panorama-traffic/traffic
    $reports = $rule->API_getAppContainerStats2(time() - ($logHistory * 24 * 3600), time()+0, true);
    if (count($reports) == 0)
    {
        $reports = $rule->API_getAppContainerStats2(time() - ($logHistory * 24 * 3600),time()+0, false);
    }


    $ruleStats->createRuleStats($rule->name());

    print "     * Results (".count($reports)."):\n";

    $ruleStats->updateRuleUpdateTimestamp($rule->name());

    foreach( $reports as $line)
    {
        $count = array_pop($line);
        $app = array_pop($line);

        // if container of app is valid, we want to use this container rather than
        $container = array_pop($line);
        if( strlen($container) > 0 && $container != 'none' )
            $app = $container;

        print "      - $app ($count)\n";

        $ruleStats->addRuleStats($rule->name() , $app, $count);
    }

    $ruleStats->save_to_file($ruleStatFile);

    print "\n\n";
}

//print "\n\nExporting stats to html file '{$ruleStatHtmlFile}'... \n\n";
//$ruleStats->exportToCSV($ruleStatHtmlFile);




print "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";
