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
PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() );

function display_usage_and_exit($shortMessage = FALSE)
{
    PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=file.xml|api://... [more arguments]" );
    PH::print_stdout( "php " . basename(__FILE__) . " help          : more help messages" );
    PH::print_stdout( PH::boldText("Examples:") );
    PH::print_stdout( " - php " . basename(__FILE__) . " in=api://192.169.50.10 cycleConnectedFirewalls'" );
    PH::print_stdout( " - php " . basename(__FILE__) . " in=api://001C55663D@panorama-host" );

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
            {
                PH::print_stdout( $text );
                $text = "     " . $arg['shortHelp'];
            }
            PH::print_stdout( $text );
        }

        PH::print_stdout("" );
    }

    PH::print_stdout("" );
    exit(1);
}

function display_error_usage_exit($msg)
{
    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
        fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(FALSE);
}


PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');
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
    $debugAPI = TRUE;
else
    $debugAPI = FALSE;

if( isset(PH::$args['cycleconnectedfirewalls']) )
    $cycleConnectedFirewalls = TRUE;
else
    $cycleConnectedFirewalls = FALSE;

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
    derr("Only API mode is supported, please provide an API input");
}
elseif( $configInput['type'] == 'api' )
{
    /** @var PanAPIConnector $inputConnector */
    $inputConnector = $configInput['connector'];

    if( $debugAPI )
        $inputConnector->setShowApiCalls(TRUE);
}
else
    derr('not supported yet');

function diffNodes(DOMElement $template, DOMElement $candidate, $padding)
{
    static $excludeXpathList = array('/config/devices/entry/deviceconfig/system/update-schedule/*/recurring'

    );

    if( $candidate->hasAttribute('src') && $candidate->getAttribute('src') == 'tpl' )
    {
        foreach( $template->childNodes as $templateNode )
        {
            if( $templateNode->nodeType != XML_ELEMENT_NODE )
                continue;

            /** @var DOMElement $templateNode */

            if( $templateNode->hasAttribute('name') )
                $candidateNode = DH::findFirstElementByNameAttrOrDie($templateNode->tagName, $templateNode->getAttribute('name'), $candidate);
            else
                $candidateNode = DH::findFirstElement($templateNode->tagName, $candidate);

            if( $candidateNode === FALSE )
            {
                $exclusionFound = FALSE;
                foreach( $excludeXpathList as $excludeXPath )
                {
                    $xpathResults = DH::findXPath('/config/template' . $excludeXPath, $template->ownerDocument);

                    foreach( $xpathResults as $searchNode )
                    {
                        /** @var DOMNode $searchNode */
                        if( $searchNode->isSameNode($template) )
                        {
                            $exclusionFound = TRUE;
                            break;
                        }
                    }
                    if( $exclusionFound )
                        break;
                }


                if( $exclusionFound )
                {
                    PH::print_stdout( $padding . "* " . DH::elementToPanXPath($candidate) );
                }
                else
                    PH::print_stdout( $padding . "* " . DH::elementToPanXPath($templateNode) . " (defined in template but missing in Firewall config)" );
            }
            else
                diffNodes($templateNode, $candidateNode, $padding);
        }
    }
    else
    {
        static $manualCheckXpathList = array('/config/mgt-config/users/entry/phash',
            '/config/shared/local-user-database/user/entry/phash',
            '/config/shared/certificate/entry/private-key'

        );

        $exclusionFound = FALSE;
        foreach( $manualCheckXpathList as $excludeXPath )
        {
            $xpathResults = DH::findXPath('/config/template' . $excludeXPath, $template->ownerDocument);
            #$xpathResults = DH::findXPath( $excludeXPath, $template);

            foreach( $xpathResults as $searchNode )
            {
                /** @var DOMNode $searchNode */
                if( $searchNode->isSameNode($template) )
                {
                    $exclusionFound = TRUE;
                    break;
                }
            }
            if( $exclusionFound )
                break;
        }

        if( $exclusionFound )
        {
            if( $template->nodeValue != $candidate->nodeValue )
                $exclusionFound = FALSE;
        }

        if( $exclusionFound )
            return;

        if( $template->nodeValue == $candidate->nodeValue )
            $identicalText = '  (but same value as template)';
        else
            $identicalText = '';

        PH::print_stdout( $padding . "* " . DH::elementToPanXPath($candidate) . "{$identicalText}" );
    }
}

/**
 * @param PanAPIConnector $apiConnector
 * @param string $padding
 */
function checkFirewallOverride($apiConnector, $padding)
{
    PH::enableExceptionSupport();
    $text = $padding . " - Downloading candidate config...";
    $request = 'type=config&action=get&xpath=/config';

    try
    {
        $candidateDoc = $apiConnector->sendSimpleRequest($request);


        PH::print_stdout( $text );

        $text = $padding . " - Looking for root /config xpath...";
        $configRoot = DH::findXPathSingleEntryOrDie('/response/result/config', $candidateDoc);

        PH::print_stdout( $text );

        DH::makeElementAsRoot($configRoot, $candidateDoc);

        $text = $padding . " - Looking for root /config/template/config xpath...";
        $templateRoot = DH::findXPathSingleEntry('template/config', $configRoot);


        PH::print_stdout( $text );

        if( $templateRoot === FALSE )
        {
            PH::print_stdout( $padding . " - SKIPPED because no template applied!" );
        }
        else
        {
            PH::print_stdout( "" );

            PH::print_stdout( $padding . " ** Looking for overrides **" );

            diffNodes($templateRoot, $configRoot, $padding);
        }
    } catch(Exception $e)
    {
        PH::disableExceptionSupport();
        PH::print_stdout( $padding . " ***** an error occured : " . $e->getMessage() );
        return;
    }

    PH::disableExceptionSupport();
}

if( $cycleConnectedFirewalls )
{
    $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();

    $countFW = 0;
    foreach( $firewallSerials as $fw )
    {
        $countFW++;
        PH::print_stdout( " ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **" );
        $tmpConnector = $inputConnector->cloneForPanoramaManagedDevice($fw['serial']);
        checkFirewallOverride($tmpConnector, '    ');
    }
}
else
{
    checkFirewallOverride($inputConnector, ' ');
}


PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");

