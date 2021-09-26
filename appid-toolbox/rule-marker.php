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

PH::print_stdout( "************* START OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() );

$debugAPI = false;

PH::processCliArgs();


function display_usage_and_exit()
{
    PH::print_stdout(PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [OPTIONAL ARGS]" );

    PH::print_stdout("Listing optional arguments:");

    PH::print_stdout("");


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

if( !isset(PH::$args['location']) )
    display_error_usage_exit("missing argument 'device-group'");

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
    PH::print_stdout(" - Downloading config from API... ");
    $xmlDoc = $inputConnector->getCandidateConfig();

}
else
    derr('not supported yet');


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

PH::print_stdout(" - Detected platform type is '{$configType}'");

if( $configInput['type'] == 'api' )
    $pan->connector = $inputConnector;

//
// load the config
//
PH::print_stdout(" - Loading configuration through PAN-PHP-framework library... ");
$loadStartMem = memory_get_usage(true);
$loadStartTime = microtime(true);
$pan->load_from_domxml($xmlDoc);
$loadEndTime = microtime(true);
$loadEndMem = memory_get_usage(true);
$loadElapsedTime = number_format( ($loadEndTime - $loadStartTime), 2, '.', '');
$loadUsedMem = convert($loadEndMem - $loadStartMem);
PH::print_stdout("($loadElapsedTime seconds, $loadUsedMem memory)" );
// --------------------

$subSystem  = $pan->findSubSystemByName($location);

if( $subSystem === null )
    derr("cannot find vsys/dg named '$location', available locations list is : ");

PH::print_stdout(" - Found DG/Vsys '$location'" );
PH::print_stdout(" - Looking/creating for necessary Tags to mark rules" );
TH::createTags($pan, $configInput['type']);


$rules = $subSystem->securityRules->rules('!(action is.negative) and (app is.any) and !(rule is.disabled) and !(tag has appid#ignore)');
PH::print_stdout(" - Total number of rules: {$subSystem->securityRules->count()} vs ".count($rules)." potentially taggable" );

$ridTagLibrary = new RuleIDTagLibrary();
$ridTagLibrary->readFromRuleArray($subSystem->securityRules->rules());


PH::print_stdout("\n\n*** BEGIN TAGGING RULES ***" );

$xmlPreRules = '';
$xmlPostRules = '';

$markedRules = 0;
$alreadyMarked = 0;

foreach($rules as $rule)
{
    PH::print_stdout(" - rule '{$rule->name()}'");

    if( $ridTagLibrary->ruleIsTagged($rule) )
    {
        PH::print_stdout(" SKIPPED : already tagged" );
        $alreadyMarked++;
        continue;
    }

    $markedRules++;


    $newTagName = $ridTagLibrary->findAvailableTagName('appRID#');
    PH::print_stdout("" );
    PH::print_stdout("    * creating Virtual TAG '$newTagName' ... ");

    PH::print_stdout("    * applying tag to rule description... ");

    $newDescription = $rule->description().' '.$newTagName;
    if( strlen($newDescription) > 253 )
        derr('description is too long, please review and edit');
    $ridTagLibrary->addRuleToTag($rule, $newTagName);
    $rule->setDescription($newDescription);

    if( $rule->isPostRule() )
        $xmlPostRules .= "<entry name=\"{$rule->name()}\"><description>".htmlspecialchars($rule->description())."</description></entry>";
    else
        $xmlPreRules .= "<entry name=\"{$rule->name()}\"><description>".htmlspecialchars($rule->description())."</description></entry>";


}

PH::print_stdout("\n\nNumber of rules marked: {$markedRules}    (vs already marked: {$alreadyMarked}" );

if( $markedRules < 1 )
    PH::print_stdout("\n\n No change to push as not rule is set to be marked" );
else
{
    if( $configInput['type'] == 'api' )
        PH::print_stdout("\n\n**** Pushing all changes at once through API... ");


    if ($pan->isPanorama())
        $xml = "<pre-rulebase><security><rules>{$xmlPreRules}</rules></security></pre-rulebase><post-rulebase><security><rules>{$xmlPostRules}</rules></security></post-rulebase>";
    else
        $xml = "<rulebase><security><rules>{$xmlPreRules}</rules></security></rulebase>";

    if( $configInput['type'] == 'api' )
        $inputConnector->sendSetRequest(DH::elementToPanXPath($subSystem->xmlroot), $xml);
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

PH::print_stdout("\n" );

PH::print_stdout("\n************* END OF SCRIPT ".basename(__FILE__)." ************\n" );

