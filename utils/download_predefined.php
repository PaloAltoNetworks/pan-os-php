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

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() );


function display_usage_and_exit($shortMessage = FALSE)
{
    global $argv;
    PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml location=vsys1 " .
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']" );
    PH::print_stdout( "php " . basename(__FILE__) . " help          : more help messages" );


    if( !$shortMessage )
    {
        PH::print_stdout( PH::boldText("\nListing available arguments") );

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            $text = " - " . PH::boldText($arg['niceName']);
            if( isset($arg['argDesc']) )
                $text .= '=' . $arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']) )
                $text .= "\n     " . $arg['shortHelp'];
            PH::print_stdout($text);
        }

        PH::print_stdout("");
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(TRUE);
}


$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = FALSE;
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = FALSE;
$inputConnector = null;


$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['location'] = array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');


PH::processCliArgs();

foreach( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


if( !isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');


if( isset(PH::$args['debugapi']) )
{
    $debugAPI = TRUE;
}

if( isset(PH::$args['folder']) )
{
    $offline_folder = PH::$args['folder'];
}


################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, TRUE);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");
    exit(1);
}

if( $configInput['type'] == 'file' )
{
    #derr( "offline file not supported\n" );
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( !$xmlDoc1->load($configInput['filename'], XML_PARSE_BIG_LINES) )
        derr("error while reading xml config file");

}
elseif( $configInput['type'] == 'api' )
{

    if( $debugAPI )
        $configInput['connector']->setShowApiCalls(TRUE);
    PH::print_stdout( " - Downloading config from API... " );

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        PH::print_stdout( " - 'loadPanoramaPushedConfig' was requested, downloading it through API..." );
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    $hostname = $configInput['connector']->info_hostname;

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );

}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult1 = DH::findXPath('/config/devices/entry/vsys', $xmlDoc1);
if( $xpathResult1 === FALSE )
    derr('XPath error happened');
if( $xpathResult1->length < 1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length < 1 )
        $configType = 'panorama';
    else
        $configType = 'pushed_panorama';
}
else
    $configType = 'panos';
unset($xpathResult1);

PH::print_stdout( " - Detected platform type is '{$configType}'" );

############## actual not used

if( $configType == 'panos' )
{
    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        PH::print_stdout(" - 'loadPanoramaPushedConfig' was requested, downloading it through API..." );
        $panoramaDoc = $inputConnector->getPanoramaPushedConfig();

        $xpathResult = DH::findXPath('/panorama/vsys', $panoramaDoc);

        if( $xpathResult === FALSE )
            derr("could not find any VSYS");

        if( $xpathResult->length != 1 )
            derr("found more than 1 <VSYS>");

        $fakePanorama = new PanoramaConf();
        $fakePanorama->_fakeMode = TRUE;
        $inputConnector->refreshSystemInfos();
        $newDGRoot = $xpathResult->item(0);
        $panoramaString = "<config version=\"{$inputConnector->info_PANOS_version}\"><shared></shared><devices><entry name=\"localhost.localdomain\"><device-group>" . DH::domlist_to_xml($newDGRoot->childNodes) . "</device-group></entry></devices></config>";
        #PH::print_stdout( $panoramaString);
        $fakePanorama->load_from_xmlstring($panoramaString);

        $pan = new PANConf($fakePanorama);
    }
    else $pan = new PANConf();
}
else
    $pan = new PanoramaConf();

if( $inputConnector !== null )
    $pan->connector = $inputConnector;


// </editor-fold>

################


//
// Location provided in CLI ?
//
if( isset(PH::$args['location']) )
{
    $objectslocation = PH::$args['location'];
    if( !is_string($objectslocation) || strlen($objectslocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        PH::print_stdout( " - No 'location' provided so using default ='vsys1'" );
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'panorama' )
    {
        PH::print_stdout( " - No 'location' provided so using default ='shared'" );
        $objectslocation = 'shared';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        PH::print_stdout( " - No 'location' provided so using default ='vsys1'" );
        $objectslocation = 'vsys1';
    }
}


##########################################
##########################################

#$request = 'type=config&action=get&xpath=%2Fconfig%2Fpredefined';

$request = 'type=op&cmd=<show><predefined><xpath>%2Fpredefined<%2Fxpath><%2Fpredefined><%2Fshow>';

try
{
    $candidateDoc = $configInput['connector']->sendSimpleRequest($request);
} catch(Exception $e)
{
    PH::disableExceptionSupport();
    PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
}


//make XMLroot for <predefined>
$predefinedRoot = DH::findFirstElement('response', $candidateDoc);
if( $predefinedRoot === FALSE )
    derr("<response> was not found", $candidateDoc);

$predefinedRoot = DH::findFirstElement('result', $predefinedRoot);
if( $predefinedRoot === FALSE )
    derr("<result> was not found", $predefinedRoot);

$predefinedRoot = DH::findFirstElement('predefined', $predefinedRoot);
if( $predefinedRoot === FALSE )
    derr("<predefined> was not found", $predefinedRoot);


$xmlDoc = new DomDocument;
$xmlDoc->appendChild($xmlDoc->importNode($predefinedRoot, TRUE));


################################################################################################


$cursor = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);


$exernal_version = $cursor->nodeValue;
$panc_version = $pan->appStore->predefinedStore_appid_version;


$external_appid = explode("-", $exernal_version);
$pan_c_appid = explode("-", $panc_version);


if( intval($pan_c_appid[0]) > intval($external_appid[0]) )
{
    PH::print_stdout( "\n\n - PAN-PHP-FRAMEWORK has already a newer APP-id version '" . $panc_version . "' installed. Device App-ID version: " . $exernal_version );
}
elseif( intval($pan_c_appid[0]) == intval($external_appid[0]) )
{
    PH::print_stdout( " - same app-id version '" . $panc_version . "' available => do nothing");
}
else
{
    PH::print_stdout( " - PAN-PHP-FRAMEWORK has an old app-id version '" . $panc_version . "' available. Device App-ID version: " . $exernal_version );

    $predefined_path = '/../lib/object-classes/predefined.xml';

    PH::print_stdout( " *** predefined.xml is saved to '" . __DIR__ . $predefined_path . "''" );
    file_put_contents(__DIR__ . $predefined_path, $xmlDoc->saveXML());
}

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");

