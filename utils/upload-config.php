<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

print "***********************************************\n";
print "************ UPLOAD CONFIG UTILITY ************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");

function dirname_cleanup_win()
{
    $tmp_dirname = dirname(__FILE__);
    $tmp_dirname = str_replace("\\", "/", $tmp_dirname);

    #print $tmp_dirname."\n";

    $tmp_search = "pan-os-php/utils";
    $tmp_replace = "git";

    $tmp_dirname = str_replace($tmp_search, $tmp_replace, $tmp_dirname);

    return $tmp_dirname;
}

function display_usage_and_exit($shortMessage = FALSE)
{
    print PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=file.xml|api://... out=file.xml|api://... [more arguments]\n";

    print PH::boldText("\nExamples:\n");
    print " - php " . basename(__FILE__) . " help          : more help messages\n";
    print " - php " . basename(__FILE__) . " in=api://192.169.50.10/running-config out=local.xml'\n";
    print " - php " . basename(__FILE__) . " in=local.xml out=api://192.169.50.10 preserveMgmtsystem injectUserAdmin2\n";
    print " - php " . basename(__FILE__) . " in=local.xml out=api://192.169.50.10 toXpath=/config/shared/address\n";

    if( !$shortMessage )
    {
        print PH::boldText("\nListing available arguments\n\n");

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            print " - " . PH::boldText($arg['niceName']);
            if( isset($arg['argDesc']) )
                print '=' . $arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']) )
                print "\n     " . $arg['shortHelp'];
            print "\n\n";
        }

        print "\n\n";
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(TRUE);
}

function recursive_XML( &$doc2, $toXpath, $test = 0 )
{
    print $test."\n";
    $test++;

    $explode = explode( "/", $toXpath );

    $string = "";
    for( $i = 0; $i < count( $explode )-1; $i++ )
    {
        $string .= $explode[$i];
        if( $i+1 < count( $explode )-1 )
            $string .= "/";
    }
    print "find string: ".$string."\n";
    $foundOutputXpathList = DH::findXPath($string, $doc2);

    print "length: ".$foundOutputXpathList->length."\n";
    if( $foundOutputXpathList->length == 1 )
    {
        /** @var DOMElement $entryNode */
        $entryNode = $foundOutputXpathList[0];

        $string = str_replace( "]", "", $explode[ count( $explode )-1 ]  );
        $str_array = explode( "[", $string);

        print "create Element: ".$str_array[0]."\n";
        $newNode = $doc2->createElement( $str_array[0] );

        if( isset($str_array[1]) && strpos( $str_array[1], "@" ) !== false )
        {
            $string = str_replace( "@", "", $str_array[1] );

            $str_array = explode( "=", $string );
            $name = $str_array[0];
            $value = str_replace( "'", "", $str_array[1] );

            print "set Attribute: Name: ".$name." value: ".$value."\n";
            $newNode->setAttribute( $name, $value );
        }
        $entryNode->appendChild( $newNode );
    }

    $foundOutputXpathList = DH::findXPath($toXpath, $doc2);

    if( $foundOutputXpathList->length == 0 )
        $foundOutputXpathList = recursive_XML( $doc2, $string, $test );

    return $foundOutputXpathList;
}
print "\n";

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
        print "|" . $fromXpath . "|\n";
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
        print "|" . $toXpath . "|\n";
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

print "Opening/downloading original configuration...";

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
    print "{$configInput['filename']} ... ";
    $doc->Load($configInput['filename'], XML_PARSE_BIG_LINES);
}
elseif( $configInput['type'] == 'api' )
{
    if( $debugAPI )
        $configInput['connector']->setShowApiCalls(TRUE);

    print "{$configInput['connector']->apihost} ... ";

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

print " OK!!\n\n";


if( $extraFiltersOut !== null )
{
    print " * extraFiltersOut was specified and holds '" . count($extraFiltersOut) . " queries'\n";
    foreach( $extraFiltersOut as $filter )
    {
        print "  - processing XPath '''{$filter} ''' ";
        $xpathQ = new DOMXPath($doc);
        $results = $xpathQ->query($filter);

        if( $results->length == 0 )
            print " 0 results found!\n";
        else
        {
            print " {$results->length} matching nodes found!\n";
            foreach( $results as $node )
            {
                /** @var DOMElement $node */
                $panXpath = DH::elementToPanXPath($node);
                print "     - deleting $panXpath\n";
                $node->parentNode->removeChild($node);
            }

        }
        unset($xpathQ);
    }
}


if( isset($fromXpath) )
{
    print " * fromXPath is specified with value '" . $fromXpath . "'\n";
    $foundInputXpathList = DH::findXPath($fromXpath, $doc);

    if( $foundInputXpathList === FALSE )
        derr("invalid xpath syntax");

    if( $foundInputXpathList->length == 0 )
        derr("xpath returned empty results");

    print "    * found " . $foundInputXpathList->length . " results from Xpath:\n";

    foreach( $foundInputXpathList as $xpath )
    {
        print "       - " . DH::elementToPanXPath($xpath) . "\n";
    }

    print "\n";
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
            print "strpos|".strpos( $toXpath, "/config/devices/entry/vsys" )."|\n";
            if( strpos( $toXpath, "/vsys/entry[" ) !== false )
                $doc2->Load( dirname(__FILE__) . "/../parser/panos_baseconfig.xml", XML_PARSE_BIG_LINES);
            else
                $doc2->Load( dirname(__FILE__) . "/../parser/panorama_baseconfig.xml", XML_PARSE_BIG_LINES);
        }
        elseif( file_exists( $configOutput['filename'] ) )
        {
            print "{$configOutput['filename']} ... \n";
            $doc2 = new DOMDocument();
            $doc2->Load($configOutput['filename'], XML_PARSE_BIG_LINES);
        }

        print " * toXPath is specified with value '" . $toXpath . "'\n";
        print "toXpath from above\n";
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
            print "\nDG: ".$string."\n";
            print "path: ".$path."\n";
            //how to update -> /config/readonly/max-internal-id - handle different PAN-OS
            //how to create -> /config/readonly/devices/entry/device-group/XYZ

            mwarning( "Panorama used, but readonly section is not yet supported for update" );
        }

        if( $foundOutputXpathList->length != 1 )
            derr("toXpath returned too many results");

        print "    * found " . $foundOutputXpathList->length . " results from Xpath:\n";

        foreach( $foundOutputXpathList as $xpath )
            print "       - " . DH::elementToPanXPath($xpath) . "\n";


        /** @var DOMElement $entryNode */
        $entryNode = $foundOutputXpathList[0];

        //Todo: what happen if xpath is already available; e.g. import of objects into DG/address; actual it creates another DG/address(objects), address(objects)
        #print "import\n";
        $node = $doc2->importNode($foundInputXpathList[0], true);
        #print "append\n";
        $entryNode->appendChild( $node );

        print "\nNow saving configuration to ";
        print "{$configOutput['filename']}... ";
        $doc2->save($configOutput['filename']);
        print "OK!\n";


    }
    else
    {
        print "\nNow saving configuration to ";
        print "{$configOutput['filename']}... ";
        $doc->save($configOutput['filename']);
        print "OK!\n";
    }

}
elseif( $configOutput['type'] == 'api' )
{
    if( $debugAPI )
        $configOutput['connector']->setShowApiCalls(TRUE);

    if( isset($toXpath) )
    {
        print "Sending SET command to API...";
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
        print "OK!";
    }
    else
    {
        if( isset(PH::$args['preservemgmtconfig']) ||
            isset(PH::$args['preservemgmtusers']) ||
            isset(PH::$args['preservemgmtsystem']) )
        {
            print "Option 'preserveXXXXX was used, we will first download the running config of target device...";
            $runningConfig = $configOutput['connector']->getRunningConfig();
            print "OK!\n";

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
            print "Injected 'admin2' with 'admin' password\n";
        }

        if( $debugAPI )
            $configOutput['connector']->setShowApiCalls(TRUE);

        if( $configOutput['filename'] !== null )
            $saveName = $configOutput['filename'];
        else
            $saveName = 'stage0.xml';

        print "Now saving/uploading that configuration to ";
        print "{$configOutput['connector']->apihost}/$saveName ... ";
        $configOutput['connector']->uploadConfiguration(DH::firstChildElement($doc), $saveName, FALSE);
        print "OK!\n";
    }
}
else
    derr('not supported yet');


if( $loadConfigAfterUpload && $configInput['type'] != 'api' )
{
    print "Loading config in the firewall (will display warnings if any) ...\n";
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

            print " - " . $msg->nodeValue . "\n";
        }
    }
}


print "\n************ DONE: UPLOAD CONFIG UTILITY ************\n";
print   "*****************************************************";
print "\n\n";




