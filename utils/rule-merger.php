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


PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";



$supportedArguments = array();
$supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '=[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments[] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes, API is not supported because it could be a heavy duty on management. ie: out=save-config.xml', 'argDesc' => '=[filename]');
$supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1');
$supportedArguments[] = array('niceName' => 'Method', 'shortHelp' => 'rules will be merged if they match given a specific method, available methods are: ', 'argDesc' => '=method1');
$supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = array('niceName' => 'panoramaPreRules', 'shortHelp' => 'when using panorama, select pre-rulebase for merging');
$supportedArguments[] = array('niceName' => 'panoramaPostRules', 'shortHelp' => 'when using panorama, select post-rulebase for merging');
$supportedArguments[] = array('niceName' => 'mergeDenyRules', 'shortHelp' => 'deny rules wont be merged', 'argDesc' => '=[yes|no|true|false]');
$supportedArguments[] = array('niceName' => 'stopMergingIfDenySeen', 'shortHelp' => 'deny rules wont be merged', 'argDesc' => '=[yes|no|true|false]');
$supportedArguments[] = array('niceName' => 'mergeAdjacentOnly', 'shortHelp' => 'merge only rules that are adjacent to each other', 'argDesc' => '=[yes|no|true|false]');
$supportedArguments[] = array('niceName' => 'filter', 'shortHelp' => 'filter rules that can be converted');
$supportedArguments[] = array('niceName' => 'additionalMatch', 'shortHelp' => 'add additional matching criterial; only =tag is supported yet', 'argDesc' => '=tag');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');

$tmpArray = array();
foreach( $supportedArguments as &$arg )
{
    $tmpArray[strtolower($arg['niceName'])] = &$arg;
}
$supportedArguments = &$tmpArray;



$usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml|api://... location=shared|sub [out=outputfile.xml]" .
    " ['filter=(from has external) or (to has dmz)']";



//
//  methods array preparation
//
$supportedMethods_tmp = array(
    'matchFromToSrcDstApp' => 1,
    'matchFromToSrcDstSvc' => 2,
    'matchFromToSrcSvcApp' => 3,
    'matchFromToDstSvcApp' => 4,
    'matchFromSrcDstSvcApp' => 5,
    'matchToSrcDstSvcApp' => 6,
    'matchToDstSvcApp' => 7,
    'matchFromSrcSvcApp' => 8,
    'identical' => 9,
);
$supportedMethods = array();
foreach( $supportedMethods_tmp as $methodName => $method )
{
    $supportedMethods[strtolower($methodName)] = $method;
}
$methodsNameList = array_flip($supportedMethods_tmp);
$supportedArguments['method']['shortHelp'] .= PH::list_to_string($methodsNameList);


$rulemerger = new RULEMERGER("custom", $argv, __FILE__, $supportedArguments, $usageMsg);

########################################################################################################################
#       INPUT validation
########################################################################################################################


PH::processCliArgs();
$rulemerger->help(PH::$args);
$rulemerger->arg_validation();
$rulemerger->inDebugapiArgument();


if( isset(PH::$args['additionalmatch']) )
{
    $rulemerger->UTIL_additionalMatch = strtolower( PH::$args['additionalmatch'] );
    if( $rulemerger->UTIL_additionalMatch != "tag" )
        derr( "additionalMatch argument support until now ONLY 'tag'" );
}


$rulemerger->inputValidation();


$errorMessage = '';
if( isset(PH::$args['filter']) )
{
    $rulemerger->UTIL_filterQuery = new RQuery('rule');
    if( !$rulemerger->UTIL_filterQuery->parseFromString(PH::$args['filter'], $errorMessage) )
        derr($errorMessage);
    PH::print_stdout( " - rule filter after sanitizing : ");
    $rulemerger->UTIL_filterQuery->display();
}


$rulemerger->load_config();
$rulemerger->location_provided();


$processedLocation = null;

if( $rulemerger->pan->isPanorama() )
{
    $rulemerger->panoramaPreRuleSelected = TRUE;
    if( !isset(PH::$args[strtolower('panoramaPreRules')]) && !isset(PH::$args[strtolower('panoramaPostRules')]) )
        $rulemerger->display_error_usage_exit("Panorama was detected but no Pre or Post rules were selected, use CLI argument 'panoramaPreRules' or 'panoramaPostRules'");

    if( isset(PH::$args[strtolower('panoramaPreRules')]) && isset(PH::$args[strtolower('panoramaPostRules')]) )
        $rulemerger->display_error_usage_exit("both panoramaPreRules and panoramaPostRules were selected, please choose one of them");

    if( isset(PH::$args[strtolower('panoramaPostRules')]) )
        $rulemerger->panoramaPreRuleSelected = FALSE;

    if( $rulemerger->objectsLocation == 'any' )
    {
        #derr( "ANY is not supported yet" );
        $rulemerger->locationNotFound($rulemerger->objectsLocation);
    }
    elseif( $rulemerger->objectsLocation == 'shared' )
    {
        $processedLocation = $rulemerger->pan;
        if( $rulemerger->panoramaPreRuleSelected )
            $rulemerger->UTIL_rulesToProcess = $rulemerger->pan->securityRules->preRules();
        else
            $rulemerger->UTIL_rulesToProcess = $rulemerger->pan->securityRules->postRules();
    }
    else
    {
        $sub = $rulemerger->pan->findDeviceGroup($rulemerger->objectsLocation);
        if( $sub === null )
            $rulemerger->locationNotFound($rulemerger->objectsLocation);

        if( $rulemerger->panoramaPreRuleSelected )
            $rulemerger->UTIL_rulesToProcess = $sub->securityRules->preRules();
        else
            $rulemerger->UTIL_rulesToProcess = $sub->securityRules->postRules();

        $processedLocation = $sub;
    }
}
elseif( $rulemerger->pan->isFawkes() )
{
    if( $rulemerger->objectsLocation == 'any' )
        #derr( "ANY is not supported yet" );
        $rulemerger->locationNotFound($rulemerger->objectsLocation);

    $sub = $rulemerger->pan->findContainer($rulemerger->objectsLocation);
    if( $sub === null )
        $sub = $rulemerger->pan->findDeviceCloud($rulemerger->objectsLocation);
    if( $sub === null )
        $rulemerger->locationNotFound($rulemerger->objectsLocation);


    if( $sub->isContainer() )
    {
        $rulemerger->panoramaPreRuleSelected = TRUE;
        if( !isset(PH::$args[strtolower('panoramaPreRules')]) && !isset(PH::$args[strtolower('panoramaPostRules')]) )
            $rulemerger->display_error_usage_exit("Fawkes Container was detected but no Pre or Post rules were selected, use CLI argument 'panoramaPreRules' or 'panoramaPostRules'");

        if( isset(PH::$args[strtolower('panoramaPreRules')]) && isset(PH::$args[strtolower('panoramaPostRules')]) )
            $rulemerger->display_error_usage_exit("both panoramaPreRules and panoramaPostRules were selected, please choose one of them");

        if( isset(PH::$args[strtolower('panoramaPostRules')]) )
            $rulemerger->panoramaPreRuleSelected = FALSE;

        if( $rulemerger->panoramaPreRuleSelected )
            $rulemerger->UTIL_rulesToProcess = $sub->securityRules->preRules();
        else
            $rulemerger->UTIL_rulesToProcess = $sub->securityRules->postRules();
    }
    else
    {
        $rulemerger->UTIL_rulesToProcess = $sub->securityRules->rules();
    }

    $processedLocation = $sub;
}
else
{
    $sub = $rulemerger->pan->findVirtualSystem($rulemerger->objectsLocation);
    if( $sub === null )
        #derr("VirtualSystem named '{$rulemerger->objectsLocation}' not found");
        $rulemerger->locationNotFound($rulemerger->objectsLocation);
    $rulemerger->UTIL_rulesToProcess = $sub->securityRules->rules();
    $processedLocation = $sub;
}


if( !isset(PH::$args['method']) )
    $rulemerger->display_error_usage_exit(' no method was provided');
$rulemerger->UTIL_method = strtolower(PH::$args['method']);
if( !isset($supportedMethods[$rulemerger->UTIL_method]) )
    $rulemerger->display_error_usage_exit("unsupported method '" . PH::$args['method'] . "' provided");
$rulemerger->UTIL_method = $supportedMethods[$rulemerger->UTIL_method];


if( !isset(PH::$args['mergedenyrules']) )
{
    PH::print_stdout( " - No 'mergeDenyRule' argument provided, using default 'no'");
    $rulemerger->UTIL_mergeDenyRules = FALSE;
}
else
{
    if( PH::$args['mergedenyrules'] === null || strlen(PH::$args['mergedenyrules']) == 0 )
        $rulemerger->UTIL_mergeDenyRules = TRUE;
    elseif( strtolower(PH::$args['mergedenyrules']) == 'yes' || strtolower(PH::$args['mergedenyrules']) == 'true' )
        $rulemerger->UTIL_mergeDenyRules = TRUE;
    elseif( strtolower(PH::$args['mergedenyrules']) == 'no' || strtolower(PH::$args['mergedenyrules']) == 'false' )
        $rulemerger->UTIL_mergeDenyRules = FALSE;
    else
        $rulemerger->display_error_usage_exit("'mergeDenyRules' argument was given unsupported value '" . PH::$args['mergedenyrules'] . "'");
}


if( !isset(PH::$args['stopmergingifdenyseen']) )
{
    PH::print_stdout( " - No 'stopMergingIfDenySeen' argument provided, using default 'yes'");
    $rulemerger->UTIL_stopMergingIfDenySeen = TRUE;
}
else
{
    if( PH::$args['stopmergingifdenyseen'] === null || strlen(PH::$args['stopmergingifdenyseen']) == 0 )
        $rulemerger->UTIL_stopMergingIfDenySeen = TRUE;
    elseif( strtolower(PH::$args['stopmergingifdenyseen']) == 'yes'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 'true'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 1 )
        $rulemerger->UTIL_stopMergingIfDenySeen = TRUE;
    elseif( strtolower(PH::$args['stopmergingifdenyseen']) == 'no'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 'false'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 0 )
        $rulemerger->UTIL_stopMergingIfDenySeen = FALSE;
    else
        $rulemerger->display_error_usage_exit("'stopMergingIfDenySeen' argument was given unsupported value '" . PH::$args['stopmergingifdenyseen'] . "'");
}

if( !isset(PH::$args['mergeadjacentonly']) )
{
    PH::print_stdout( " - No 'mergeAdjacentOnly' argument provided, using default 'no'");
    $rulemerger->UTIL_mergeAdjacentOnly = FALSE;
}
else
{
    if( PH::$args['mergeadjacentonly'] === null || strlen(PH::$args['mergeadjacentonly']) == 0 )
        $rulemerger->UTIL_mergeAdjacentOnly = TRUE;

    elseif( strtolower(PH::$args['mergeadjacentonly']) == 'yes'
        || strtolower(PH::$args['mergeadjacentonly']) == 'true'
        || strtolower(PH::$args['mergeadjacentonly']) == 1 )

        $rulemerger->UTIL_mergeAdjacentOnly = TRUE;

    elseif( strtolower(PH::$args['mergeadjacentonly']) == 'no'
        || strtolower(PH::$args['mergeadjacentonly']) == 'false'
        || strtolower(PH::$args['mergeadjacentonly']) == 0 )

        $rulemerger->UTIL_mergeAdjacentOnly = FALSE;
    else
        $rulemerger->display_error_usage_exit("(mergeAdjacentOnly' argument was given unsupported value '" . PH::$args['mergeadjacentonly'] . "'");
    PH::print_stdout( " - mergeAdjacentOnly = " . boolYesNo($rulemerger->UTIL_mergeAdjacentOnly) );
}

########################################################################################################################
#      Rule merging functions from UTIL
########################################################################################################################

########################################################################################################################
#      merging
########################################################################################################################

$rulemerger->UTIL_hashTable = array();

/** @var SecurityRule[] $denyRules */
$rulemerger->UTIL_denyRules = array();

$rulemerger->UTIL_calculate_rule_hash();


PH::print_stdout("");
PH::print_stdout( "Stats before merging :");
$processedLocation->display_statistics();

##################

$rulemerger->UTIL_rule_merging( );

##################

PH::print_stdout("");
PH::print_stdout( "Stats after merging :");
$processedLocation->display_statistics();


##################
#    save to file
##################
$rulemerger->save_our_work( true );

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
