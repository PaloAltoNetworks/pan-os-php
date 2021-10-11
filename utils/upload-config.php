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

PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() . " [".PH::frameworkInstalledOS()."]" );

function dirname_cleanup_win()
{
    $tmp_dirname = dirname(__FILE__);
    $tmp_dirname = str_replace("\\", "/", $tmp_dirname);

    #PH::print_stdout( $tmp_dirname );

    $tmp_search = "pan-os-php/utils";
    $tmp_replace = "git";

    $tmp_dirname = str_replace($tmp_search, $tmp_replace, $tmp_dirname);

    return $tmp_dirname;
}

function display_usage_and_exit($shortMessage = FALSE)
{
    PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=file.xml|api://... out=file.xml|api://... [more arguments]");

    PH::print_stdout( PH::boldText("\nExamples:") );
    PH::print_stdout( " - php " . basename(__FILE__) . " help          : more help messages" );
    PH::print_stdout( " - php " . basename(__FILE__) . " in=api://192.169.50.10/running-config out=local.xml'" );
    PH::print_stdout( " - php " . basename(__FILE__) . " in=local.xml out=api://192.169.50.10 preserveMgmtsystem injectUserAdmin2" );
    PH::print_stdout( " - php " . basename(__FILE__) . " in=local.xml out=api://192.169.50.10 toXpath=/config/shared/address" );

    PH::print_stdout( " - php " . basename(__FILE__) . " in=local.xml out=api://192.168.50.10" );
    PH::print_stdout( "            'fromXpath=/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"vsys1\"]/*[name()=\"address\" or name()=\"address-group\" or name()=\"service\" or name()=\"service-group\" or name()=\"tag\"]'" );
    PH::print_stdout( "            'toXpath=/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"vsys1\"]' shadow-apikeynohidden" );

    PH::print_stdout( " - php " . basename(__FILE__) . " in=staging/proserv-xpath.xml out=api://192.168.50.10 'fromXpath=/config/tag/*' 'toXpath=/config/devices/entry/device-group/entry[@name=\"DG-NAME\"]/tag' apiTimeout=2000" );
    PH::print_stdout( " - php " . basename(__FILE__) . " in=staging/proserv-xpath.xml out=api://192.168.50.13 'fromXpath=/config/*[name()=\"rules\"]' 'toXpath=/config/devices/entry/device-group/entry[@name=\"DG-NAME\"]/pre-rulebase/security' apiTimeout=2000" );

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
    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
        fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(TRUE);
}

function recursive_XML( &$doc2, $toXpath, $test = 0 )
{
    PH::print_stdout( $test);
    $test++;

    $explode = explode( "/", $toXpath );

    $string = "";
    for( $i = 0; $i < count( $explode )-1; $i++ )
    {
        $string .= $explode[$i];
        if( $i+1 < count( $explode )-1 )
            $string .= "/";
    }
    PH::print_stdout( "find string: ".$string);
    $foundOutputXpathList = DH::findXPath($string, $doc2);

    PH::print_stdout( "length: ".$foundOutputXpathList->length);
    if( $foundOutputXpathList->length == 1 )
    {
        /** @var DOMElement $entryNode */
        $entryNode = $foundOutputXpathList[0];

        $string = str_replace( "]", "", $explode[ count( $explode )-1 ]  );
        $str_array = explode( "[", $string);

        PH::print_stdout( "create Element: ".$str_array[0]);
        $newNode = $doc2->createElement( $str_array[0] );

        if( isset($str_array[1]) && strpos( $str_array[1], "@" ) !== false )
        {
            $string = str_replace( "@", "", $str_array[1] );

            $str_array = explode( "=", $string );
            $name = $str_array[0];
            $value = str_replace( "'", "", $str_array[1] );

            PH::print_stdout( "set Attribute: Name: ".$name." value: ".$value);
            $newNode->setAttribute( $name, $value );
        }
        $entryNode->appendChild( $newNode );
    }

    $foundOutputXpathList = DH::findXPath($toXpath, $doc2);

    if( $foundOutputXpathList->length == 0 )
        $foundOutputXpathList = recursive_XML( $doc2, $string, $test );

    return $foundOutputXpathList;
}
PH::print_stdout("");

$configInput = null;
$configOutput = null;
$errorMessage = '';
$debugAPI = FALSE;
$loadConfigAfterUpload = FALSE;
$extraFiltersOut = null;


$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['fromxpath'] = array('niceName' => 'fromXpath', 'shortHelp' => 'select which part of the config to inject in destination');
$supportedArguments['toxpath'] = array('niceName' => 'toXpath', 'shortHelp' => 'inject xml directly in some parts of the candidate config');
$supportedArguments['loadafterupload'] = array('niceName' => 'loadAfterUpload', 'shortHelp' => 'load configuration after upload happened');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to answer, increase this value (default=60)');
$supportedArguments['preservemgmtconfig'] = array('niceName' => 'preserveMgmtConfig', 'shortHelp' => "tries to preserve most of management settings like IP address, admins and passwords etc. note it's not a smart feature and may break your config a bit and requires manual fix in GUI before you can actually commit");
$supportedArguments['preservemgmtusers'] = array('niceName' => 'preserveMgmtUsers', 'shortHelp' => "preserve administrators so they are not overwritten and you don't loose access after a commit");
$supportedArguments['preservemgmtsystem'] = array('niceName' => 'preserveMgmtSystem', 'shortHelp' => 'preserves what is in /config/devices/entry/deviceconfig/system');
$supportedArguments['injectuseradmin2'] = array('niceName' => 'injectUserAdmin2', 'shortHelp' => 'adds user "admin2" with password "admin" in administrators');
$supportedArguments['extrafiltersout'] = array('niceName' => 'extraFiltersOut', 'shortHelp' => 'list of xpath separated by | character that will be stripped from the XML before going to output');


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

if( !isset(PH::$args['out']) )
    display_error_usage_exit('"out" is missing from arguments');
$configOutput = PH::$args['out'];
if( !is_string($configOutput) || strlen($configOutput) < 1 )
    display_error_usage_exit('"out" argument is not a valid string');


if( isset(PH::$args['debugapi']) )
    $debugAPI = TRUE;
else
    $debugAPI = FALSE;

if( isset(PH::$args['loadafterupload']) )
{
    $loadConfigAfterUpload = TRUE;
}

if( isset(PH::$args['fromxpath']) )
{
    if( !isset(PH::$args['toxpath']) )
    {
        display_error_usage_exit("'fromXpath' option must be used with 'toXpath'");
    }
    $fromXpath = PH::$args['fromxpath'];
    //$fromXpath = str_replace('"', "'", PH::$args['fromxpath']);

    if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
    {
        $tmp_dirname = dirname_cleanup_win();

        $fromXpath = str_replace($tmp_dirname, "", $fromXpath);
        PH::print_stdout( "|" . $fromXpath . "|");
    }
}
if( isset(PH::$args['toxpath']) )
{
    $toXpath = str_replace('"', "'", PH::$args['toxpath']);
    if( $loadConfigAfterUpload )
        $loadConfigAfterUpload = FALSE;

    if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
    {
        $tmp_dirname = dirname_cleanup_win();

        $toXpath = str_replace($tmp_dirname, "", $toXpath);
        PH::print_stdout( "|" . $toXpath . "|");
    }
}

if( !isset(PH::$args['apiTimeout']) )
    $apiTimeoutValue = 30;
else
    $apiTimeoutValue = PH::$args['apiTimeout'];

if( isset(PH::$args['extrafiltersout']) )
{
    $extraFiltersOut = explode('|', PH::$args['extrafiltersout']);
}


$doc = new DOMDocument();

PH::print_stdout( "Opening/downloading original configuration...");

//
// What kind of config input do we have.
//     File or API ?
//
$configInput = PH::processIOMethod($configInput, TRUE);

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");
    exit(1);
}

if( $configInput['type'] == 'file' )
{
    PH::print_stdout( "{$configInput['filename']} ... ");
    $doc->Load($configInput['filename'], XML_PARSE_BIG_LINES);
}
elseif( $configInput['type'] == 'api' )
{
    if( $debugAPI )
        $configInput['connector']->setShowApiCalls(TRUE);

    PH::print_stdout( "{$configInput['connector']->apihost} ... ");

    /** @var PanAPIConnector $inputConnector */
    $inputConnector = $configInput['connector'];

    if( !isset($configInput['filename']) || $configInput['filename'] == '' || $configInput['filename'] == 'candidate-config' )
        $doc = $inputConnector->getCandidateConfig();
    elseif( $configInput['filename'] == 'running-config' )
        $doc = $inputConnector->getRunningConfig();
    elseif( $configInput['filename'] == 'merged-config' || $configInput['filename'] == 'merged' )
        $doc = $inputConnector->getMergedConfig();
    elseif( $configInput['filename'] == 'panorama-pushed-config' || $configInput['filename'] == 'panorama-pushed' )
        $doc = $inputConnector->getPanoramaPushedConfig();
    else
        $doc = $inputConnector->getSavedConfig($configInput['filename']);
}
else
    derr('not supported yet');


if( $extraFiltersOut !== null )
{
    PH::print_stdout( " * extraFiltersOut was specified and holds '" . count($extraFiltersOut) . " queries'");
    foreach( $extraFiltersOut as $filter )
    {
        PH::print_stdout( "  - processing XPath '''{$filter} ''' ");
        $xpathQ = new DOMXPath($doc);
        $results = $xpathQ->query($filter);

        if( $results->length == 0 )
            PH::print_stdout( " 0 results found!");
        else
        {
            PH::print_stdout( " {$results->length} matching nodes found!");
            foreach( $results as $node )
            {
                /** @var DOMElement $node */
                $panXpath = DH::elementToPanXPath($node);
                PH::print_stdout( "     - deleting $panXpath");
                $node->parentNode->removeChild($node);
            }
        }
        unset($xpathQ);
    }
}


if( isset($fromXpath) )
{
    PH::print_stdout( " * fromXPath is specified with value '" . $fromXpath . "'");
    $foundInputXpathList = DH::findXPath($fromXpath, $doc);

    if( $foundInputXpathList === FALSE )
        derr("invalid xpath syntax");

    if( $foundInputXpathList->length == 0 )
        derr("xpath returned empty results");

    PH::print_stdout( "    * found " . $foundInputXpathList->length . " results from Xpath:");

    foreach( $foundInputXpathList as $xpath )
    {
        PH::print_stdout( "       - " . DH::elementToPanXPath($xpath) );
    }

    PH::print_stdout( "");
}


//
// What kind of config output do we have.
//     File or API ?
//
$configOutput = PH::processIOMethod($configOutput, FALSE);

if( $configOutput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configOutput['msg'] . "\n\n");
    exit(1);
}

if( $configOutput['type'] == 'file' )
{
    if( isset($toXpath) )
    {
         derr("toXpath options was used, it's incompatible with a file output. Make a feature request !!!  ;)");

        $doc2 = new DOMDocument();
        if( !file_exists( $configOutput['filename'] ) )
        {
            PH::print_stdout( "strpos|".strpos( $toXpath, "/config/devices/entry/vsys" )."|");
            if( strpos( $toXpath, "/vsys/entry[" ) !== false )
                $doc2->Load( dirname(__FILE__) . "/../parser/panos_baseconfig.xml", XML_PARSE_BIG_LINES);
            else
                $doc2->Load( dirname(__FILE__) . "/../parser/panorama_baseconfig.xml", XML_PARSE_BIG_LINES);
        }
        elseif( file_exists( $configOutput['filename'] ) )
        {
            PH::print_stdout( "{$configOutput['filename']} ... ");
            $doc2 = new DOMDocument();
            $doc2->Load($configOutput['filename'], XML_PARSE_BIG_LINES);
        }

        PH::print_stdout( " * toXPath is specified with value '" . $toXpath . "'");
        PH::print_stdout( "toXpath from above");
        $foundOutputXpathList = DH::findXPath($toXpath, $doc2);

        if( $foundOutputXpathList === FALSE )
            derr("invalid xpath syntax");

        if( $foundOutputXpathList->length == 0 )
        {
            $foundOutputXpathList = recursive_XML( $doc2, $toXpath );
        }


        if( strpos( $toXpath, "/device-group/entry[" ) != false )
        {
            $explode = explode( "/", $toXpath );

            $string = "";
            for( $i = 0; $i < 6; $i++ )
            {
                if( $i == 2 )
                    $string .= "readonly/";

                $string .= $explode[$i];

                if( $i == 4 )
                    $path = $string;

                if( $i+1 < 6 )
                    $string .= "/";
            }
            PH::print_stdout( "DG: ".$string );
            PH::print_stdout( "path: ".$path );
            //how to update -> /config/readonly/max-internal-id - handle different PAN-OS
            //how to create -> /config/readonly/devices/entry/device-group/XYZ

            mwarning( "Panorama used, but readonly section is not yet supported for update" );
        }

        if( $foundOutputXpathList->length != 1 )
            derr("toXpath returned too many results");

        PH::print_stdout( "    * found " . $foundOutputXpathList->length . " results from Xpath:");

        foreach( $foundOutputXpathList as $xpath )
            PH::print_stdout( "       - " . DH::elementToPanXPath($xpath) );


        /** @var DOMElement $entryNode */
        $entryNode = $foundOutputXpathList[0];

        //Todo: what happen if xpath is already available; e.g. import of objects into DG/address; actual it creates another DG/address(objects), address(objects)
        #PH::print_stdout( "import" );
        $node = $doc2->importNode($foundInputXpathList[0], true);
        #PH::print_stdout( "append" );
        $entryNode->appendChild( $node );

        PH::print_stdout( "Now saving configuration to ");
        PH::print_stdout( "{$configOutput['filename']}... " );
        $doc2->save($configOutput['filename']);
    }
    else
    {
        PH::print_stdout( "Now saving configuration to ");
        PH::print_stdout( "{$configOutput['filename']}... ");
        $doc->save($configOutput['filename']);
    }

}
elseif( $configOutput['type'] == 'api' )
{
    if( $debugAPI )
        $configOutput['connector']->setShowApiCalls(TRUE);

    if( isset($toXpath) )
    {
        PH::print_stdout( "Sending SET command to API...");
        if( isset($toXpath) )
        {
            $stringToSend = '';
            foreach( $foundInputXpathList as $xpath )
            {
                $stringToSend .= DH::dom_to_xml($xpath, -1, FALSE);
            }
        }
        else
            $stringToSend = DH::dom_to_xml(DH::firstChildElement($doc), -1, FALSE);

        $configOutput['connector']->sendSetRequest($toXpath, $stringToSend);

    }
    else
    {
        if( isset(PH::$args['preservemgmtconfig']) ||
            isset(PH::$args['preservemgmtusers']) ||
            isset(PH::$args['preservemgmtsystem']) )
        {
            PH::print_stdout( "Option 'preserveXXXXX was used, we will first download the running config of target device...");
            $runningConfig = $configOutput['connector']->getRunningConfig();


            $xpathQrunning = new DOMXPath($runningConfig);
            $xpathQlocal = new DOMXPath($doc);

            $xpathQueryList = array();

            if( isset(PH::$args['preservemgmtconfig']) ||
                isset(PH::$args['preservemgmtusers']) )
            {
                $xpathQueryList[] = '/config/mgt-config/users';
            }

            if( isset(PH::$args['preservemgmtconfig']) ||
                isset(PH::$args['preservemgmtsystem']) )
            {
                $xpathQueryList[] = '/config/devices/entry/deviceconfig/system';
            }


            if( isset(PH::$args['preservemgmtconfig']) )
            {
                $xpathQueryList[] = '/config/mgt-config';
                $xpathQueryList[] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig";
                $xpathQueryList[] = '/config/shared/authentication-profile';
                $xpathQueryList[] = '/config/shared/authentication-sequence';
                $xpathQueryList[] = '/config/shared/certificate';
                $xpathQueryList[] = '/config/shared/log-settings';
                $xpathQueryList[] = '/config/shared/local-user-database';
                $xpathQueryList[] = '/config/shared/admin-role';
            }

            foreach( $xpathQueryList as $xpathQuery )
            {
                $xpathResults = $xpathQrunning->query($xpathQuery);
                if( $xpathResults->length > 1 )
                {
                    //var_dump($xpathResults);
                    derr('more than one one results found for xpath query: ' . $xpathQuery);
                }
                if( $xpathResults->length == 0 )
                    $runningNodeFound = FALSE;
                else
                    $runningNodeFound = TRUE;

                $xpathResultsLocal = $xpathQlocal->query($xpathQuery);
                if( $xpathResultsLocal->length > 1 )
                {
                    //var_dump($xpathResultsLocal);
                    derr('none or more than one one results found for xpath query: ' . $xpathQuery);
                }
                if( $xpathResultsLocal->length == 0 )
                    $localNodeFound = FALSE;
                else
                    $localNodeFound = TRUE;

                if( $localNodeFound == FALSE && $runningNodeFound == FALSE )
                {
                    continue;
                }

                if( $localNodeFound && $runningNodeFound )
                {
                    $localParentNode = $xpathResultsLocal->item(0)->parentNode;
                    $localParentNode->removeChild($xpathResultsLocal->item(0));
                    $newNode = $doc->importNode($xpathResults->item(0), TRUE);
                    $localParentNode->appendChild($newNode);
                    continue;
                }

                if( $localNodeFound == FALSE && $runningNodeFound )
                {
                    $newXpath = explode('/', $xpathQuery);
                    if( count($newXpath) < 2 )
                        derr('unsupported, debug xpath query: ' . $xpathQuery);

                    unset($newXpath[count($newXpath) - 1]);
                    $newXpath = implode('/', $newXpath);

                    $xpathResultsLocal = $xpathQlocal->query($newXpath);
                    if( $xpathResultsLocal->length != 1 )
                    {
                        derr('unsupported, debug xpath query: ' . $newXpath);
                    }

                    $newNode = $doc->importNode($xpathResults->item(0), TRUE);
                    $localParentNode = $xpathResultsLocal->item(0);
                    $localParentNode->appendChild($newNode);


                    continue;
                }

                //derr('unsupported');
            }

        }

        if( isset(PH::$args['injectuseradmin2']) )
        {
            $usersNode = DH::findXPathSingleEntryOrDie('/config/mgt-config/users', $doc);
            $newUserNode = DH::importXmlStringOrDie($doc, '<entry name="admin2"><phash>$1$bgnqjgob$HmenJzuuUAYmETzsMcdfJ/</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>');
            $usersNode->appendChild($newUserNode);
            PH::print_stdout( "Injected 'admin2' with 'admin' password");
        }

        if( $debugAPI )
            $configOutput['connector']->setShowApiCalls(TRUE);

        if( $configOutput['filename'] !== null )
            $saveName = $configOutput['filename'];
        else
            $saveName = 'stage0.xml';

        PH::print_stdout( "Now saving/uploading that configuration to ");
        PH::print_stdout( "{$configOutput['connector']->apihost}/$saveName ... ");
        $configOutput['connector']->uploadConfiguration(DH::firstChildElement($doc), $saveName, FALSE);

    }
}
else
    derr('not supported yet');


if( $loadConfigAfterUpload && $configInput['type'] != 'api' )
{
    PH::print_stdout( "Loading config in the firewall (will display warnings if any) ...");
    /** @var PanAPIConnector $targetConnector */
    $targetConnector = $configOutput['connector'];
    $xmlResponse = $targetConnector->sendCmdRequest('<load><config><from>' . $saveName . '</from></config></load>', TRUE, 600);

    if( $xmlResponse === null )
    {
        derr('unexpected error !');
    }

    $xmlResponse = DH::firstChildElement($xmlResponse);

    if( $xmlResponse === FALSE )
        derr('unexpected error !');





    $msgElement = DH::findFirstElement('msg', $xmlResponse);
    $msgElement = DH::findFirstElement('line', $msgElement);
    $msgElement = DH::findFirstElement('msg', $msgElement);

    if( $msgElement !== FALSE )
    {
        foreach( $msgElement->childNodes as $key => $msg )
        {
            if( $msg->nodeType != 1 )
                continue;

            PH::print_stdout( " - " . $msg->nodeValue );
        }
    }
}


PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");
