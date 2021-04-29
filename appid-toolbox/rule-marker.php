<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

print "\n************* START OF SCRIPT ".basename(__FILE__)." ************\n\n";

require_once dirname(__FILE__) . "/lib/common.php";

$debugAPI = false;

PH::processCliArgs();


function display_usage_and_exit()
{
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://xxxx location=deviceGroup2 [OPTIONAL ARGS]".
        "\n\n";

    print "Listing optional arguments:\n\n";

    print "\n\n";


    exit(1);
}

function display_error_usage_exit($msg)
{
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
    print " - Downloading config from API... ";
    $xmlDoc = $inputConnector->getCandidateConfig();
    print "OK!\n";
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
print "OK! ($loadElapsedTime seconds, $loadUsedMem memory)\n";
// --------------------

$subSystem  = $pan->findSubSystemByName($location);

if( $subSystem === null )
    derr("cannot find vsys/dg named '$location', available locations list is : ");

print " - Found DG/Vsys '$location'\n";
print " - Looking/creating for necessary Tags to mark rules\n";
TH::createTags($pan, $configInput['type']);


$rules = $subSystem->securityRules->rules('!(action is.negative) and (app is.any) and !(rule is.disabled) and !(tag has appid#ignore)');
print " - Total number of rules: {$subSystem->securityRules->count()} vs ".count($rules)." potentially taggable\n";

$ridTagLibrary = new RuleIDTagLibrary();
$ridTagLibrary->readFromRuleArray($subSystem->securityRules->rules());


print "\n\n*** BEGIN TAGGING RULES ***\n";

$xmlPreRules = '';
$xmlPostRules = '';

$markedRules = 0;
$alreadyMarked = 0;

foreach($rules as $rule)
{
    print " - rule '{$rule->name()}'";

    if( $ridTagLibrary->ruleIsTagged($rule) )
    {
        print " SKIPPED : already tagged\n";
        $alreadyMarked++;
        continue;
    }

    $markedRules++;


    $newTagName = $ridTagLibrary->findAvailableTagName('appRID#');
    print "\n";
    print "    * creating Virtual TAG '$newTagName' ... ";
    print "OK!\n";
    print "    * applying tag to rule description... ";

    $newDescription = $rule->description().' '.$newTagName;
    if( strlen($newDescription) > 253 )
        derr('description is too long, please review and edit');
    $ridTagLibrary->addRuleToTag($rule, $newTagName);
    $rule->setDescription($newDescription);

    if( $rule->isPostRule() )
        $xmlPostRules .= "<entry name=\"{$rule->name()}\"><description>".htmlspecialchars($rule->description())."</description></entry>";
    else
        $xmlPreRules .= "<entry name=\"{$rule->name()}\"><description>".htmlspecialchars($rule->description())."</description></entry>";

    print "OK!\n";
}

print "\n\nNumber of rules marked: {$markedRules}    (vs already marked: {$alreadyMarked}\n";

if( $markedRules < 1 )
    print "\n\n No change to push as not rule is set to be marked\n";
else
{
    if( $configInput['type'] == 'api' )
        print "\n\n**** Pushing all changes at once through API... ";


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

    print "OK!\n";
}

print "\n\n";

print "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";

