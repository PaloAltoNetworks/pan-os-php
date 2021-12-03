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

PH::print_stdout( "\n************* START OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() . " [".PH::frameworkInstalledOS()."]" );
PH::processCliArgs();

function display_usage_and_exit()
{
    PH::print_stdout( PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [OPTIONAL ARGS]" );

    PH::print_stdout( "Listing optional arguments:" );

    PH::print_stdout( " - debugapi : outputs API calls live to help debugging" );
    PH::print_stdout( " - logHistory=XX : script will generate rules usage reports based on the XX last days time period(default=60)" );
    PH::print_stdout( " - updateOnlyUnusedTagRules : only the rules which have tag appid#NTBR#unused will have a usage report generated" );
    PH::print_stdout( " - updateOnlyActivatedRules : useful to check if legacy rules are still unused" );
    PH::print_stdout( " - resetPreviousData : if previous data was found, erase them and insert newly generated statistics instead (incompatible with update flag)" );
    PH::print_stdout( " - skipIfLastReportLessThanXDays : if previous data was found, erase them and insert newly generated statistics instead (incompatible with update flag)" );
    PH::print_stdout( " - updatePreviousData : if previous data was found, merge with previous statistics (incompatible with reset flag)" );

    PH::print_stdout( "" );


    exit(1);
}

function display_error_usage_exit($msg)
{
    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
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
    PH::print_stdout( " - 'logHistory' overridden from CLI : {$logHistory} days" );
}
else
    PH::print_stdout( " - no logHistory value was provided, using default= {$logHistory} days" );


if( isset(PH::$args['skipiflastreportlessthanxdays']) )
{
    $skipIfLastReportLessThanXDays = PH::$args['skipiflastreportlessthanxdays'];
    PH::print_stdout( " - skipIfLastReportLessThanXDays set to {$skipIfLastReportLessThanXDays} days" );
}
else
    PH::print_stdout( " - skipIfLastReportLessThanXDays not set, using default ({$skipIfLastReportLessThanXDays} days)" );



if( isset(PH::$args['resetpreviousdata']) )
{
    $resetPreviousData = true;
    PH::print_stdout( " - resetPreviousData enabled" );
}
else
    PH::print_stdout( " - resetPreviousData disabled" );

if( isset(PH::$args['updatepreviousdata']) )
{
    $updatePreviousData = true;
    PH::print_stdout( " - updatePreviousData enabled" );
}
else
    PH::print_stdout( " - updatePreviousData disabled" );

if( isset(PH::$args['updateonlyunusedtagrules']) )
{
    $updateOnlyUnusedTagRules = true;
    PH::print_stdout( " - updateOnlyUnusedTagRules enabled" );
    if( !$resetPreviousData && !$updatePreviousData )
        display_error_usage_exit("when updateOnlyUnusedTagRules mode is used you need to use one of the following too: resetPreviousData or updatePreviousData");
}
else
    PH::print_stdout( " - updateOnlyUnusedTagRules disabled" );

if( isset(PH::$args['updateonlyactivatedrules']) )
{
    $updateOnlyActivatedRules = true;
    PH::print_stdout( " - updateOnlyActivatedRules enabled" );
    $updatePreviousData = true;
}
else
    PH::print_stdout( " - updateOnlyActivatedRules disabled" );


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
PH::print_stdout( " - Downloading config from API... ");
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

PH::print_stdout( " - Detected platform type is '{$configType}'" );

if( $configInput['type'] == 'api' )
    $pan->connector = $connector;
// --------------------


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
    derr("cannot find vsys/dg named '$location', available locations list is : ".PH::list_to_string($pan->deviceGroups));

$connector->refreshSystemInfos();
$ruleStatFile = $connector->info_serial.'-'.$location.'-stats.xml';
$ruleStatHtmlFile = $connector->info_serial.'-'.$location.'-stats.html';

if( file_exists($ruleStatFile) )
{
    PH::print_stdout( " - Previous rule stats found, loading from file $ruleStatFile... ");
    $ruleStats->load_from_file($ruleStatFile);

}
else
    PH::print_stdout( " - No cached stats found (missing file '$ruleStatFile')" );


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

PH::print_stdout( " - Found ".count($rules)." rules which will potentially be processed for log statistics" );

PH::print_stdout( "**** PROCESSING RULES ****" );

$ruleCount = 0;

foreach($rules as $rule)
{
    /** @var SecurityRule $rule */
    $ruleCount++;
    $rule->display();
    PH::print_stdout( " * rule #$ruleCount out of ".count($rules)."" );

    if( $rule->isDisabled() )
    {
        PH::print_stdout( "    * SKIPPED : it's disabled" );
        continue;
    }

    $stats = $ruleStats->getRuleStats($rule->name());

    if( $stats !== null && ! $updatePreviousData && ! $resetPreviousData )
    {
        PH::print_stdout( "    * SKIPPED : found in cache" );
        continue;
    }

    $lastReportTime = ( time() - $ruleStats->getRuleUpdateTimestamp($rule->name()) ) / (60*60*24);
    if( $lastReportTime < $skipIfLastReportLessThanXDays )
    {
        $lastReportTime = round($lastReportTime, 2);
        PH::print_stdout( "    * SKIPPED : last report was run {$lastReportTime} days ago which is less then skipIfLastReportLessThanXDays value" );
        continue;
    }

    if( $resetPreviousData && $stats !== null )
    {
        PH::print_stdout( " * reset of existing statistics from previous run" );
    }

    PH::print_stdout( "   * Generating report... ");
    //if fastMode: panorama-trsum/trsum ELSE: panorama-traffic/traffic
    $reports = $rule->API_getAppContainerStats2(time() - ($logHistory * 24 * 3600), time()+0, true);
    if (count($reports) == 0)
    {
        $reports = $rule->API_getAppContainerStats2(time() - ($logHistory * 24 * 3600),time()+0, false);
    }


    $ruleStats->createRuleStats($rule->name());

    PH::print_stdout( "     * Results (".count($reports)."):" );

    $ruleStats->updateRuleUpdateTimestamp($rule->name());

    foreach( $reports as $line)
    {
        $count = array_pop($line);
        $app = array_pop($line);

        // if container of app is valid, we want to use this container rather than
        $container = array_pop($line);
        if( strlen($container) > 0 && $container != 'none' )
            $app = $container;

        PH::print_stdout( "      - $app ($count)" );

        $ruleStats->addRuleStats($rule->name() , $app, $count);
    }

    $ruleStats->save_to_file($ruleStatFile);

    PH::print_stdout( "" );
}

//Todo - export not working for HTML but tool is using XML file - HTML is only for user
#PH::print_stdout( "\n\nExporting stats to html file '{$ruleStatHtmlFile}'... " );
#$ruleStats->exportToCSV($ruleStatHtmlFile);




PH::print_stdout( "\n************* END OF SCRIPT ".basename(__FILE__)." ************" );
