<?php
/**
 * ISC License
 *
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

class DIFF extends UTIL
{
    public $el1rulebase = array();
    public $el2rulebase = array();

    public $filters = array();
    public $excludes = array();

    public $ruleorderCHECK = TRUE;

    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " file1=ORIGINAL.xml file2=NEWESTFILE.xml";

        #$this->prepareSupportedArgumentsArray();
        PH::processCliArgs();

        #$this->arg_validation();


        $this->main();

        if( $this->outputFormatSet )
        {
            PH::print_stdout();
            PH::print_stdout();
            foreach( $this->diff_set as $set )
                PH::print_stdout( $set );

            $deleteArray = array( "rulebase", "address-group", "address", "service-group", "service", "misc" );

            foreach( $deleteArray as $item )
            {
                if( isset( $this->diff_delete[$item] ) )
                    foreach( $this->diff_delete[$item] as $key => $delete )
                        PH::print_stdout( $delete );
            }
        }

        
    }

    public function main()
    {
        if( isset(PH::$args['debugapi']) )
            $this->debugAPI = TRUE;
        else
            $this->debugAPI = FALSE;

        if( isset(PH::$args['outputFormatSet']) )
            $this->outputFormatSet = TRUE;
        else
            $this->outputFormatSet = FALSE;
        //$this->outputFormatSet = TRUE;

        if( isset(PH::$args['noruleordercheck']) )
            $this->ruleorderCHECK = FALSe;

        if( isset(PH::$args['in']) )
        {
            $configInput = PH::processIOMethod(PH::$args['in'], TRUE);
            if( $configInput['status'] == 'fail' )
                derr($configInput['msg'], null, false);

            if( $configInput['type'] == 'api' )
            {
                $apiMode = TRUE;
                /** @var PanAPIConnector $connector */
                $connector = $configInput['connector'];
                if( $this->debugAPI )
                    $connector->setShowApiCalls(TRUE);
                PH::print_stdout( " - Downloading config from API... ");

                PH::print_stdout( "Opening ORIGINAL 'RunningConfig' XML file... ");
                $doc1 = $connector->getRunningConfig();


                PH::print_stdout( "Opening COMPARE 'Candidate' XML file... ");
                $doc2 = $connector->getCandidateConfig();

            }
            else
                false('only API is supported', null, false);
        }
        else
        {
            if( !isset(PH::$args['file1']) )
                $this->display_error_usage_exit('"file1" is missing from arguments');
            $file1 = PH::$args['file1'];
            if( !file_exists($file1) )
                derr( "FILE: ". $file1. " not available", null, false);
            if( !is_string($file1) || strlen($file1) < 1 )
                $this->display_error_usage_exit('"file1" argument is not a valid string');

            PH::print_stdout( "Opening ORIGINAL '{$file1}' XML file... ");
            $doc1 = new DOMDocument();
            if( $doc1->load($file1) === FALSE )
                derr('Error while parsing xml:' . libxml_get_last_error()->message , null, false);


            //Todo:
            // if filter isset and filter include $$NAME$$
            // check if name1 and name2 is available
            $replace = "13982";
            if( isset(PH::$args['filter']) and strpos( PH::$args['filter'], $replace."name".$replace ) !== FALSE )
            #if( isset(PH::$args['filter']) )
            {
                $doc2 = new DOMDocument();
                if( $doc2->load($file1) === FALSE )
                    derr('Error while parsing xml:' . libxml_get_last_error()->message , null, false);

                $filterArgument = PH::$args['filter'];
                $xpath = $filterArgument;
                #print "filter: ".$filterArgument."\n";

                $name1 = PH::$args['name1'];
                if( isset( $name1 ) )
                {
                    #print "name1: ".$name1."\n";
                    $xpath1 = str_replace( $replace."name".$replace, $name1, $xpath );
                    $doc1Root = DH::findXPathSingleEntry($xpath1, $doc1);

                    DH::makeElementAsRoot( $doc1Root, $doc1 );
                }
                else
                    $this->display_error_usage_exit('"name1" is missing from arguments');

                $name2 = PH::$args['name2'];
                if( isset($name2) )
                {
                    #print "name2: ".$name2."\n";
                    $xpath2 = str_replace( $replace."name".$replace, $name2, $xpath );
                    $doc2Root = DH::findXPathSingleEntry($xpath2, $doc2);

                    DH::makeElementAsRoot( $doc2Root, $doc2 );
                }
                else
                     $this->display_error_usage_exit('"name2" is missing from arguments');
                #exit();
            }
            else
            {
                if( !isset(PH::$args['file2']) )
                    $this->display_error_usage_exit('"file2" is missing from arguments');
                $file2 = PH::$args['file2'];
                if( !file_exists($file2) )
                    derr( "FILE: ". $file2. " not available", null, false);
                if( !is_string($file2) || strlen($file2) < 1 )
                    $this->display_error_usage_exit('"file1" argument is not a valid string');

                PH::print_stdout( "Opening COMPARE '{$file2}' XML file... ");
                $doc2 = new DOMDocument();
                if( $doc2->load($file2) === FALSE )
                    derr('Error while parsing xml:' . libxml_get_last_error()->message, null, false);
            }
        }

        if( isset(PH::$args['filter']) and strpos( PH::$args['filter'], $replace."name".$replace ) === FALSE )
        #if( isset(PH::$args['filter']) )
        {
            //Todo: check if filter is filename:
            if( file_exists( PH::$args['filter'] ) )
            {
                $strJsonFileContents = file_get_contents(PH::$args['filter']);

                $array = json_decode($strJsonFileContents, true);

                $this->filters = $array['include'];
                PH::print_stdout( "");
                foreach( $this->filters as $filter )
                    PH::print_stdout( "FILTER is set to: '" . PH::boldText( $filter ) . "'");

                PH::print_stdout( "");

                $this->excludes = $array['exclude'];

                if( !empty( $this->excludes ) )
                {
                    PH::print_stdout( "");
                    foreach( $this->excludes as $exclude )
                        PH::print_stdout( "exclude is set to: '" . PH::boldText( $exclude ) . "'");

                    PH::print_stdout( "");
                }
                #exit();
            }
            else
            {
                $this->filters[] = PH::$args['filter'];
                #$filter = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/tag';

                PH::print_stdout( "");
                PH::print_stdout( "FILTER is set to: '" . PH::boldText( PH::$args['filter'] ) . "'");
                PH::print_stdout( "");
            }



        }

        PH::print_stdout( "*** NOW DISPLAY DIFF ***");
        $this->runDiff( $doc1, $doc2 );
    }

    public function runDiff( $doc1, $doc2 )
    {
        if( empty( $this->filters ) )
        {
            $doc1Root = DH::firstChildElement($doc1);
            $doc2Root = DH::firstChildElement($doc2);

            $this->compareElements($doc1Root, $doc2Root);
        }
        else
        {
            //Todo: 20200507 bring in xpath as filter
            foreach( $this->filters as $filter )
            {
                $continue = false;
                foreach( $this->excludes as $exclude )
                {
                    if( strpos( $filter, $exclude ) !== FALSE )
                        $continue = true;
                }
                if( $continue )
                    continue;

                $doc1Root = DH::findXPathSingleEntry($filter, $doc1);
                $doc2Root = DH::findXPathSingleEntry($filter, $doc2);

                ##########################################

                if( $doc1Root == FALSE || $doc2Root == FALSE )
                {
                    $xmlDoc1 = new DOMDocument();
                    $xmlDoc1->preserveWhiteSpace = FALSE;
                    $xmlDoc1->formatOutput = TRUE;

                    $filter_array = explode("/", $filter);
                    $item = end($filter_array);

                    $element = $xmlDoc1->createElement($item);
                    $config = $xmlDoc1->appendChild($element);
                }
                if( $doc1Root == FALSE )
                {
                    $doc1Root = $config;
                    PH::print_stdout( "doc1Root : false" );
                }

                if( $doc2Root == FALSE )
                {
                    $doc2Root = $config;
                    PH::print_stdout( "doc2Root : false" );
                }

                $this->compareElements($doc1Root, $doc2Root, $filter);
            }
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments[] = array();

    }


    function endsWith($haystack, $needle) {
        $length = strlen($needle);
        return $length > 0 ? substr($haystack, -$length) === $needle : true;
    }

    function calculateRuleorder( $el1Elements, $el2Elements)
    {
        $this->el1rulebase = array();
        foreach( $el1Elements['entry'] as $key => $rule )
        {
            $name = $rule->getAttribute('name');
            $this->el1rulebase[$name] = $name;
        }
        $this->el2rulebase = array();
        foreach( $el2Elements['entry'] as $key => $rule )
        {
            $name = $rule->getAttribute('name');
            $this->el2rulebase[$name] = $name;
        }
    }
    function checkRuleOrder( $xpath )
    {
        $start = strpos( $xpath, '/rules/entry[@name=\'' );
        $name_string =  substr( $xpath, $start+20);
        $name_string = str_replace( "']", '', $name_string );

        $posFile1 = array_search($name_string, array_keys($this->el1rulebase));
        $posFile2 = array_search($name_string, array_keys($this->el2rulebase));
        if( $posFile1 !== $posFile2 )
        {
            PH::print_stdout( "\nXPATH: $xpath");
            PH::print_stdout( "x different RULE position: file1: pos".$posFile1." / file2: pos".$posFile2 );
        }
    }

    /**
     * @param DOMElement $el1
     * @param DOMElement $el2
     */
    function compareElements($el1, $el2, $xpath = null)
    {
        //PH::print_stdout( "argument XPATH: ".$xpath );
        if( $xpath == null )
            $xpath = DH::elementToPanXPath($el1);

        //PH::print_stdout( "*** COMPARING {$xpath}" );

        /** @var DOMElement[][] $el1Elements */
        $el1Elements = array();
        /** @var DOMElement[][] $el2Elements */
        $el2Elements = array();

        /** @var DOMElement[][] $plus */
        $plus = array();
        /** @var DOMElement[][] $minus */
        $minus = array();

        foreach( $el1->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $el1Elements[$node->tagName][] = $node;
        }

        foreach( $el2->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $el2Elements[$node->tagName][] = $node;
        }

        //calculating rule order
        if( $this->ruleorderCHECK && $this->endsWith( $xpath, "/rules" ) && strpos( $xpath, "rulebase/") !== false )
        {
            if( isset( $el1Elements['entry'] ) && isset( $el2Elements['entry'] ) )
                $this->calculateRuleorder( $el1Elements, $el2Elements);
        }



        if( count($el1Elements) == 0 && count($el2Elements) == 0 )
        {
            $el1Trim = trim($el1->textContent);
            $el2Trim = trim($el2->textContent);

            if( $el1Trim != $el2Trim )
            {
                $text = '';

                $tmp = DH::dom_to_xml($el1);
                $text .= '+' . str_replace("\n", "\n", $tmp);

                $tmp = DH::dom_to_xml($el2);
                $text .= '-' . str_replace("\n", "\n", $tmp);

                //same xpath different content
                //$this->displayDIFF( $xpath, $text, array( $el1 ), array($el2) );
                $this->displayDIFF( $xpath, $text, array( $el2 ), array( $el1 ), array( $el1 ) );
            }
            return;
        }

        //
        //  nodes missing entirely in one or the other
        //
        foreach( $el1Elements as $tagName => &$nodeArray1 )
        {
            if( !isset($el2Elements[$tagName]) )
            {
                foreach( $nodeArray1 as $node )
                    $minus[] = $node;
                unset($el1Elements[$tagName]);
            }
        }
        foreach( $el2Elements as $tagName => &$nodeArray2 )
        {
            if( !isset($el1Elements[$tagName]) )
            {
                foreach( $nodeArray2 as $node )
                    $plus[] = $node;
                unset($el2Elements[$tagName]);
            }
        }

        // conflicting objects
        foreach( $el1Elements as $tagName => &$nodeArray1 )
        {
            $nodeArray2 = &$el2Elements[$tagName];

            $el1BasicNode = null;
            foreach( $nodeArray1 as $nodeIndex => $node )
            {
                if( !$node->hasAttribute('name') )
                {
                    if( $el1BasicNode === null )
                    {
                        $el1BasicNode = $node;
                    }
                    else
                    {
                        if( is_array($el1BasicNode) )
                        {
                            $el1BasicNode[] = $node;
                        }
                        else
                        {
                            $el1BasicNode = array($el1BasicNode);
                            $el1BasicNode[] = $node;
                        }
                    }

                    unset($nodeArray1[$nodeIndex]);
                }
            }
            if( $el1BasicNode !== null && count($nodeArray1) > 0 )
                derr('unsupported situation where <node> and <node name=""> were both seen', $el1, false);

            $el2BasicNode = null;
            foreach( $nodeArray2 as $nodeIndex => $node )
            {
                if( !$node->hasAttribute('name') )
                {
                    if( $el2BasicNode === null )
                    {
                        $el2BasicNode = $node;
                    }
                    else
                    {
                        if( is_array($el2BasicNode) )
                        {
                            $el2BasicNode[] = $node;
                        }
                        else
                        {
                            $el2BasicNode = array($el2BasicNode);
                            $el2BasicNode[] = $node;
                        }
                    }

                    unset($nodeArray2[$nodeIndex]);
                }
            }
            if( $el2BasicNode !== null && count($nodeArray2) > 0 )
                derr('unsupported situation where <node> and <node name=""> where both seen in same document', $el2, false);

            if( $el1BasicNode === null && $el2BasicNode !== null )
                mwarning('found an issue where file1 has <node> but file2 has <node name="">', null, false);
            if( $el1BasicNode !== null && $el2BasicNode === null )
                mwarning('found an issue where file2 has <node> but file1 has <node name="">', null, false);


            if( $el1BasicNode !== null && $el2BasicNode !== null )
            {
                if( is_object($el1BasicNode) && is_object($el2BasicNode) )
                {
                    $this->compareElements($el1BasicNode, $el2BasicNode);
                }
                else
                {
                    if( is_object($el1BasicNode) )
                        $el1BasicNode = array($el1BasicNode);
                    if( is_object($el2BasicNode) )
                        $el2BasicNode = array($el2BasicNode);

                    $el1ContentSorted = array();
                    $el2ContentSorted = array();

                    foreach( $el1BasicNode as $node )
                    {
                        $nodeContent = $node->textContent;
                        if( isset($el1ContentSorted[$nodeContent]) )
                            mwarning('cannot have <node>'.$nodeContent.'</node> nodes with same content. file1', $el1, false, FALSE);
                        else
                            $el1ContentSorted[$nodeContent] = $node;
                    }
                    foreach( $el2BasicNode as $node )
                    {
                        $nodeContent = $node->textContent;
                        if( isset($el2ContentSorted[$nodeContent]) )
                            mwarning('cannot have <node>'.$nodeContent.'</node> nodes with same content. file2', $el2, false, FALSE);
                        else
                            $el2ContentSorted[$nodeContent] = $node;
                    }

                    foreach( $el1ContentSorted as $content => $node )
                    {
                        if( isset($el2ContentSorted[$content]) )
                            continue;
                        $minus[] = $node;
                    }
                    foreach( $el2ContentSorted as $content => $node )
                    {
                        if( isset($el1ContentSorted[$content]) )
                            continue;
                        $plus[] = $node;
                    }

                }
            }
            elseif( $el1BasicNode !== null && $el2BasicNode === null )
            {
                if( is_object($el1BasicNode) )
                    $minus[] = $el1BasicNode;
                else
                    foreach( $el1BasicNode as $node )
                        $minus[] = $node;
            }
            elseif( $el1BasicNode === null && $el2BasicNode !== null )
            {
                if( is_object($el2BasicNode) )
                    $minus[] = $el2BasicNode;
                else
                    foreach( $el2BasicNode as $node )
                        $minus[] = $node;
            }
            else
            {
                $el1NameSorted = array();
                $el2NameSorted = array();

                foreach( $nodeArray1 as $nodeIndex => $node )
                {
                    $nodeName = $node->getAttribute('name');
                    if( isset($el1NameSorted[$nodeName]) )
                    {
                        mwarning('<node name="' . $nodeName . '"> was found twice in file1', $el1, false, FALSE);
                    }

                    else
                        $el1NameSorted[$nodeName] = $node;
                }
                foreach( $nodeArray2 as $nodeIndex => $node )
                {
                    $nodeName = $node->getAttribute('name');
                    if( isset($el2NameSorted[$nodeName]) )
                    {
                        mwarning('<node name="' . $nodeName . '"> was found twice in file2', $el2, false, FALSE);
                    }
                    else
                        $el2NameSorted[$nodeName] = $node;
                }

                foreach( $el1NameSorted as $nodeName => $node )
                {
                    if( !isset($el2NameSorted[$nodeName]) )
                    {
                        $minus[] = $node;
                        unset($el1NameSorted[$nodeName]);

                        $nodeName = $node->getAttribute('name');
                        if( isset( $this->el1rulebase[$nodeName] ) )
                            unset( $this->el1rulebase[$nodeName] );
                    }
                }
                foreach( $el2NameSorted as $nodeName => $node )
                {
                    if( !isset($el1NameSorted[$nodeName]) )
                    {
                        $plus[] = $node;
                        unset($el2NameSorted[$nodeName]);

                        $nodeName = $node->getAttribute('name');
                        if( isset( $this->el2rulebase[$nodeName] ) )
                            unset( $this->el2rulebase[$nodeName] );
                    }
                }

                foreach( $el1NameSorted as $nodeName => $node1 )
                {
                    $node2 = $el2NameSorted[$nodeName];

                    $this->compareElements($node1, $node2);
                }

            }

            unset($el1Elements[$tagName]);
            unset($el2Elements[$tagName]);
        }


        //check if ruleorder is same
        if( $this->endsWith( $xpath, "']" ) && strpos( $xpath, "rulebase/") !== false && strpos( $xpath, "/rules") !== false )
            $this->checkRuleOrder( $xpath );


        $text = '';

        foreach( $plus as $node )
        {
            $tmp = DH::dom_to_xml($node);
            $text .= '+' . str_replace("\n", "\n+", $tmp);
        }

        foreach( $minus as $node )
        {
            $tmp = DH::dom_to_xml($node);
            $text .= '-' . str_replace("\n", "\n-", $tmp);
        }

        $this->displayDIFF( $xpath, $text, $plus, $minus );
    }

    public function displayDIFF( $xpath, $text, $plus, $minus, $edit = array() )
    {
        if( $text != '' )
        {
            if( $this->outputFormatSet )
            {
                if( $this->debugAPI )
                {
                    //intermediate, remove it later on
                    PH::print_stdout("\nXPATH: $xpath");
                    /////////////
                    //PH::print_stdout("\nTEXT: $text");
                }

                /*
                foreach( $edit as $element )
                {
                    if( $element === null )
                        continue;

                    $array = array();

                    if( $this->debugAPI )
                    {
                        PH::print_stdout( "EDIT");
                        //intermediate, remove it later on

                        $doc2 = new DOMDocument();
                        $node = $doc2->importNode($element, true);
                        $doc2->appendChild($node);
                        PH::print_stdout( $doc2->saveXML( $doc2->documentElement) );
                        PH::print_stdout( "");

                    }

                    DH::elementToPanSetCommand( 'edit', $element, $array );


                    foreach( $array as $entry )
                    {
                        if( !in_array( $entry, $this->diff_set ) )
                            $this->diff_edit[] = $entry;
                    }

                }
                */

                foreach( $plus as $element )
                {
                    if( $element === null )
                        continue;

                    $array = array();

                    if( $this->debugAPI )
                    {
                        PH::print_stdout( "ADD");
                        //intermediate, remove it later on

                        $doc2 = new DOMDocument();
                        $node = $doc2->importNode($element, true);
                        $doc2->appendChild($node);
                        PH::print_stdout( $doc2->saveXML( $doc2->documentElement) );
                        PH::print_stdout( "");

                    }

                    DH::elementToPanSetCommand( 'set', $element, $array );

                    //manipulation needed based on flood xyz red issue in PAN-OS
                    self::fixFloodSetCommand($array);

                    self::arraySetCommand( $array, "diff_set" );
                }

                foreach( $minus as $element )
                {
                    if( $element === null )
                        continue;

                    $array = array();

                    if( $this->debugAPI )
                    {
                        PH::print_stdout( "REMOVE");
                        //intermediate, remove it later on


                        $doc2 = new DOMDocument();
                        $node = $doc2->importNode($element, true);
                        $doc2->appendChild($node);
                        PH::print_stdout( $doc2->saveXML( $doc2->documentElement) );
                        PH::print_stdout( "");

                    }

                    DH::elementToPanSetCommand( 'delete', $element, $array );

                    self::arraySetCommand( $array, "diff_delete" );
                }
            }
            else
            {
                PH::print_stdout("\nXPATH: $xpath");
                PH::print_stdout("$text");
            }
        }
    }


    public function arraySetCommand( $array, $type )
    {
        foreach(  $array as $entry )
        {
            if( !in_array( $entry, $this->$type ) )
            {
                if( strpos( $entry, "rulebase " ) !== false )
                    $this->$type['rulebase'][] = $entry;
                elseif( strpos( $entry, " address-group " ) !== false )
                    $this->$type['address-group'][] = $entry;
                elseif( strpos( $entry, " address " ) !== false )
                    $this->$type['address'][] = $entry;
                elseif( strpos( $entry, " service-group " ) !== false )
                    $this->$type['service-group'][] = $entry;
                elseif( strpos( $entry, " service " ) !== false )
                    $this->$type['service'][] = $entry;
                elseif( strpos( $entry, " profile-group " ) !== false )
                    $this->$type['profile-group'][] = $entry;
                elseif( strpos( $entry, " profiles " ) !== false )
                    $this->$type['profiles'][] = $entry;
                else
                    $this->$type['misc'][] = $entry;
            }

        }
    }

    public function fixFloodSetCommand( &$array)
    {
        $tmpArray = array( " flood tcp-syn red", " flood icmpv6 red", " flood icmp red", " flood other-ip red", " flood udp red" );
        foreach( $tmpArray as $tmpString )
        {
            $endstring = "";
            $tmpKey = "";
            foreach( $array as $key => $string )
            {
                if( strpos($string, $tmpString) !== FALSE )
                {
                    $pos = strpos($string, $tmpString);
                    $fixpos = strlen($tmpString);
                    $mainstring = substr($string, 0, $pos + $fixpos);

                    if( $endstring === "" )
                    {
                        $tmpKey = $key;
                        $endstring .= trim($mainstring);
                    }
                    elseif( strpos($endstring, $mainstring) === FALSE )
                    {
                        //print "KEY: ".$tmpKey."  END: ".$endstring."\n";
                        $array[ $tmpKey ] = $endstring;
                        $tmpKey = $key;
                        $endstring = trim($mainstring);
                    }

                    $substring = substr($string, $pos + $fixpos);
                    $endstring .= $substring;
                    if( $key !== $tmpKey )
                        unset( $array[ $key ] );
                }
            }
            if( !empty($endstring)  )
                $array[ $tmpKey ] = $endstring;
            //print "KEY: ".$tmpKey."  END: ".$endstring."\n";
        }
    }
}

