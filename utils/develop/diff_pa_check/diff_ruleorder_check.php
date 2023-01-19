<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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

require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

#PH::print_stdout();
#PH::print_stdout("***********************************************");
#PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
#PH::print_stdout();

#PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$displayAttributeName = false;

$supportedArguments = Array();
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file1'] = Array('niceName' => 'file1', 'shortHelp' => 'orig file');
$supportedArguments['file2'] = Array('niceName' => 'file1', 'shortHelp' => 'new file');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );

PH::processCliArgs();

##########################################
##########################################

########################################################################################################################
//file1
if( !isset(PH::$args['file1']) )
    $util->display_error_usage_exit('"file1" is missing from arguments');
$file1 = PH::$args['file1'];
if( !file_exists($file1) )
    derr( "FILE: ". $file1. " not available", null, false);
if( !is_string($file1) || strlen($file1) < 1 )
    $util->display_error_usage_exit('"file1" argument is not a valid string');

#PH::print_stdout( "Opening ORIGINAL '{$file1}' XML file... ");
$doc1 = new DOMDocument();
if( $doc1->load($file1) === FALSE )
    derr('Error while parsing xml:' . libxml_get_last_error()->message , null, false);


//file2
if( !isset(PH::$args['file2']) )
    $util->display_error_usage_exit('"file2" is missing from arguments');
$file2 = PH::$args['file2'];
if( !file_exists($file2) )
    derr( "FILE: ". $file2. " not available", null, false);
if( !is_string($file2) || strlen($file2) < 1 )
    $util->display_error_usage_exit('"file1" argument is not a valid string');

#PH::print_stdout( "Opening COMPARE '{$file2}' XML file... ");
$doc2 = new DOMDocument();
if( $doc2->load($file2) === FALSE )
    derr('Error while parsing xml:' . libxml_get_last_error()->message, null, false);

########################################################################################################################

//preparation

//file1
$filename1 = "file1.xml";
$file1Combined = getCombinedPrePostXML( $doc1 );
#saveXML( $file1Combined, $filename1 );

//file2
$filename2 = "file2.xml";
$file2Combined = getCombinedPrePostXML( $doc2 );
#saveXML( $file2Combined, $filename2 );

#debugDisplayXML( $file2Combined );
########################################################################################################################

if( $file1Combined == null || $file2Combined == null )
{
    mwarning( "this is not a DG config", null, FALSE );
    exit();
}

$el1rulebase = array();
$el2rulebase = array();
calculateRuleorder( $file1Combined, $file2Combined, $el1rulebase, $el2rulebase);

//check security Rules
checkRuleOrder( 'security', $el1rulebase, $el2rulebase );

########################################################################################################################
#PH::print_stdout();
#PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
#PH::print_stdout();
########################################################################################################################


function calculateRuleorder( $el1Elements, $el2Elements, &$el1rulebase, &$el2rulebase)
{
    foreach( $el1Elements->childNodes as $childNode )
    {
        /** @var null|DOMElement $childNode*/
        if( $childNode->nodeType != XML_ELEMENT_NODE )
            continue;

        #debugDisplayXML( $childNode );
        $content = $childNode->nodeName;
        $rules = DH::findFirstElement("rules", $childNode);

        if( $rules != FALSE )
            foreach( $rules->childNodes as $key => $rule )
            {
                /** @var null|DOMElement $rule*/
                if( $rule->nodeType != XML_ELEMENT_NODE )
                    continue;

                #debugDisplayXML( $rule );
                #$name = $rule->getAttribute('name');
                $name = $rule->getAttribute('uuid');
                $el1rulebase[$content][$name] = $name;
            }
    }

    foreach( $el2Elements->childNodes as $childNode )
    {
        /** @var null|DOMElement $childNode */
        if( $childNode->nodeType != XML_ELEMENT_NODE )
            continue;
        $content = $childNode->nodeName;
        $rules = DH::findFirstElement("rules", $childNode);

        if( $rules != FALSE )
            foreach( $rules->childNodes as $key => $rule )
            {
                /** @var null|DOMElement $rule*/
                if( $rule->nodeType != XML_ELEMENT_NODE )
                    continue;

                #$name = $rule->getAttribute('name');
                $name = $rule->getAttribute('uuid');
                $el2rulebase[$content][$name] = $name;
            }
    }
}

function checkRuleOrder( $type, $el1rulebase, $el2rulebase )
{
    foreach( $el1rulebase[$type] as $key => $rule )
    {
        $posFile1 = array_search($key, array_keys($el1rulebase[$type]));
        $posFile2 = array_search($key, array_keys($el2rulebase[$type]));

        if( $posFile1 !== $posFile2 )
        {
            PH::print_stdout( "\n".$type." Rule: ". $rule);
            PH::print_stdout( "x different RULE position: file1: pos".$posFile1." / file2: pos".$posFile2 );
        }
    }
}

function debugDisplayXML( $element)
{
    $doc2 = new DOMDocument();
    $node = $doc2->importNode($element, true);
    $doc2->appendChild($node);
    PH::print_stdout( $doc2->saveXML( $doc2->documentElement) );
    PH::print_stdout( "");
}

function saveXML( $element, $filename)
{
    $doc2 = new DOMDocument();
    $node = $doc2->importNode($element, true);
    $doc2->appendChild($node);

    $doc2->save( $filename );
    #PH::print_stdout( $doc2->saveXML( $doc2->documentElement) );
}

function getCombinedPrePostXML($doc )
{
    $docpre = false;
    $docpost = false;

    // - get pre-rulebase XML
    $docxmlroot = DH::findFirstElement('policy', $doc);
    if($docxmlroot === false  )
    {
        return null;
    }

    $docpanorama = DH::findFirstElement('panorama', $docxmlroot);
    if( $docpanorama !== false )
        $docpre = DH::findFirstElement('pre-rulebase', $docpanorama);


    // - get post-rulebase XML
    if( $docpanorama !== false )
        $docpost = DH::findFirstElement('post-rulebase', $docpanorama);


    $finalDoc = new DOMDocument();
    $nodeconfig = $finalDoc->createElement( "config" );
    $finalDoc->appendChild($nodeconfig);



    #$node = $finalDoc->importNode($doc1pre, true);
    #print "1---------------------\n";
    foreach($docpre->childNodes as $childNode)
    {
        /** @var null|DOMElement $childNode*/
        if( $childNode->nodeType != XML_ELEMENT_NODE )
            continue;

        #debugDisplayXML( $childNode );
        $node2 = $finalDoc->importNode($childNode, true);
        $nodeconfig->appendChild($node2);
    }
    #debugDisplayXML( $nodeconfig );



    #print "2---------------------\n";
    #debugDisplayXML( $element );
    foreach( $nodeconfig->childNodes as $node )
    {
        /** @var null|DOMElement $node*/
        if( $node->nodeType != XML_ELEMENT_NODE )
            continue;

        $content = $node->nodeName;
        $preRules = DH::findFirstElement( "rules", $node);

        $ruletypepost = false;
        if( $docpost !== false )
            $ruletypepost = DH::findFirstElement($content, $docpost);

        if( $ruletypepost !== false )
        {
            $postRules = DH::findFirstElement( "rules", $ruletypepost);
            $node = $finalDoc->importNode($postRules, true);
            foreach( $node->childNodes as $childNode )
            {
                /** @var null|DOMElement $childNode*/
                if( $childNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $preRules->appendChild($childNode);
            }
        }
    }

    return $nodeconfig;
}