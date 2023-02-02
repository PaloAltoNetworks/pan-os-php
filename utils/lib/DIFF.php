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

    public $move = array();
    public $added = array();
    public $deleted = array();
    public $empty = array();

    public $failStatus_diff = false;

    public $ruleorderCHECK = TRUE;
    public $avoidDisplayWhitspaceDiffCertificate = false;

    public $additionalruleOrderCHECK = FALSE;
    public $additionalRuleOrderpreXpath = array();
    public $additionalRuleOrderpostXpath = array();
    public $failStatus_additionalruleorder = false;

    //needed for CLI input of argument filter=...$$name$$...
    public $replace = "";

    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') ."\n".
            "  - php " . basename(__FILE__) . " file1=ORIGINAL.xml file2=NEWESTFILE.xml\n".
            "  - php " . basename(__FILE__) . " file1=ORIGINAL.xml file2=NEWESTFILE.xml \"filter=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DG-name']/pre-rules\"\n".
            "  - php " . basename(__FILE__) . " file1=ORIGINAL.xml file2=NEWESTFILE.xml filter=file.json\n".
            "JSON file structure:\n".
            "{
    \"include\": [
        \"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='testDG']/address\",
        \"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='testDG']/tag\",
        \"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='testDG']/service\",
        \"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='testDG']/address-group\"
    ],
    \"exclude\": [
    	\"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='testDG']/service-group\",
    	\"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$\$name$$']/address\"
    ],
    \"move\": [
        {
            \"from\": \"/template/config/shared/ssl-decrypt\",
            \"to\": \"/template/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/ssl-decrypt\"
        }
    ],
    \"added\": [
    	\"/template/config/devices/entry[@name='localhost.localdomain']/network/routing-profile\"
    ],
    \"deleted\": [
    	\"/template/config/shared/response-page\"
    ],
    \"empty\": [
    	\"/policy/post-rulebase/tunnel-inspect\"
    ],
    \"combinedruleordercheck\": [
        {
            \"pre\": \"/policy/panorama/pre-rulebase/security\",
            \"post\": \"/policy/panorama/post-rulebase/security\"
        }
    ]
}\n".
            "\n".
            "  - php " . basename(__FILE__) . " file1=diff.xml \"filter=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$\$name$$']/pre-rules\" name1=testDG name2=testDG1"
        ;

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

            //second document needed for combinedRuleOrderCheck at the end of the diff
            $origDoc1 = new DOMDocument();
            $origDoc1->load($file1);

            $pattern = "/(.*)[0-9]{5}name[0-9]{5}(.*)/i";
            $matches = null;
            if( isset(PH::$args['filter']) and preg_match( $pattern, PH::$args['filter'], $matches  ) )
            {
                $substring = str_replace( $matches[1], "", PH::$args['filter'] );
                $substring = str_replace( $matches[2], "", $substring );
                $pid = explode( "name", $substring );
                $this->replace = $pid[0];


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
                    $xpath1 = str_replace( $this->replace."name".$this->replace, $name1, $xpath );
                    $doc1Root = DH::findXPathSingleEntry($xpath1, $doc1);

                    if( $doc1Root )
                        DH::makeElementAsRoot( $doc1Root, $doc1 );
                    else
                        $this->display_error_usage_exit('"filter" argument is not a valid xPATH');
                }
                else
                    $this->display_error_usage_exit('"name1" is missing from arguments');

                $name2 = PH::$args['name2'];
                if( isset($name2) )
                {
                    #print "name2: ".$name2."\n";
                    $xpath2 = str_replace( $this->replace."name".$this->replace, $name2, $xpath );
                    $doc2Root = DH::findXPathSingleEntry($xpath2, $doc2);

                    DH::makeElementAsRoot( $doc2Root, $doc2 );
                }
                else
                     $this->display_error_usage_exit('"name2" is missing from arguments');
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

                //second document needed for combinedRuleOrderCheck at the end of the diff
                $origDoc2 = new DOMDocument();
                $origDoc2->load($file2);
            }
        }

        if( isset(PH::$args['filter']) and strpos( PH::$args['filter'], $this->replace."name".$this->replace ) === FALSE )
        {
            if( file_exists( PH::$args['filter'] ) )
            {
                $this->avoidDisplayWhitspaceDiffCertificate = TRUE;
                $strJsonFileContents = file_get_contents(PH::$args['filter']);

                $array = json_decode($strJsonFileContents, true);
                if( $array === null )
                    derr( "invalid JSON file provided", null, FALSE );

                if( isset( $array['include'] ) )
                    $this->filters = $array['include'];
                PH::print_stdout( "");
                foreach( $this->filters as $filter )
                    PH::print_stdout( "FILTER is set to: '" . PH::boldText( $filter ) . "'");

                if( isset( $array['added'] ) )
                    $this->added = $array['added'];
                if( isset( $array['deleted'] ) )
                    $this->deleted = $array['deleted'];
                if( isset( $array['empty'] ) )
                    $this->empty = $array['empty'];

                if( isset( $array['move'] ) )
                {
                    $this->move = $array['move'];

                    foreach( $this->move as $entry )
                    {
                        //check moved XML Nodes
                        PH::print_stdout(PH::boldText("check moved XML node:") );
                        PH::print_stdout( " - fromXpath: ".$entry['from'] );
                        PH::print_stdout( " - toXpath:   ".$entry['to'] );
                        $doc1Root = DH::findXPathSingleEntry($entry['from'], $doc1);
                        $doc2Root = DH::findXPathSingleEntry($entry['to'], $doc2);

                        if( $doc1Root !== False && $doc2Root !== False )
                            $this->compareElements($doc1Root, $doc2Root);

                        if( isset($entry['from']) )
                            $this->excludes[] = $entry['from'];
                        if( isset($entry['to']) )
                            $this->excludes[] = $entry['to'];
                    }
                }

                if( isset( $array['combinedruleordercheck'] ) )
                {
                    $this->additionalruleOrderCHECK = TRUE;
                    $this->additionalRuleOrderArray = $array['combinedruleordercheck'];



                    foreach( $this->additionalRuleOrderArray as $key => $entry )
                    {
                        if( isset( $entry['pre'] ) && isset( $entry['post'] ) )
                        {
                            $this->additionalRuleOrderpreXpath[$key] = $entry['pre'];
                            $this->additionalRuleOrderpostXpath[$key] = $entry['post'];
                        }
                    }
                }

                PH::print_stdout( "");

                if( isset( $array['exclude'] ) and empty($this->excludes) )
                    $this->excludes = $array['exclude'];
                elseif( isset( $array['exclude'] ) and !empty($this->excludes) )
                    $this->excludes = array_merge( $this->excludes, $array['exclude'] );

                if( !empty( $this->excludes ) )
                {
                    PH::print_stdout( "");
                    foreach( $this->excludes as $exclude )
                    {
                        PH::print_stdout( "exclude is set to: '" . PH::boldText( $exclude ) . "'");

                        if( strpos( $exclude, "*" ) !== FALSE )
                        {
                            $excludeXpath = $exclude;
                            $excludeXpath = str_replace( "entry[@name='*']/", "entry/", $excludeXpath );

                            $domXpath1 = new DOMXPath($doc1);
                            foreach( $domXpath1->query($excludeXpath) as $node )
                                $this->deleteNodeReverseAlsoParent($node);
                            $domXpath2 = new DOMXPath($doc2);
                            foreach( $domXpath2->query($excludeXpath) as $node )
                                $this->deleteNodeReverseAlsoParent($node);
                        }
                        else
                        {
                            $doc1Root = DH::findXPathSingleEntry($exclude, $doc1);
                            if( $doc1Root )
                                $this->deleteNodeReverseAlsoParent($doc1Root);

                            $doc2Root = DH::findXPathSingleEntry($exclude, $doc2);
                            if( $doc2Root )
                                $this->deleteNodeReverseAlsoParent($doc2Root);
                        }
                    }

                    PH::print_stdout( "");
                }
            }
            else
            {
                $this->filters[] = PH::$args['filter'];

                PH::print_stdout( "");
                PH::print_stdout( "FILTER is set to: '" . PH::boldText( PH::$args['filter'] ) . "'");
                PH::print_stdout( "");
            }
        }

        PH::print_stdout( "*** NOW DISPLAY DIFF ***");
        PH::print_stdout( array(), false, "diff" );

        $this->runDiff( $doc1, $doc2 );

        if( $this->additionalruleOrderCHECK )
        {
            PH::print_stdout();
            PH::print_stdout();
            PH::print_stdout( "*** additional Rule order check ***");

            foreach( $this->additionalRuleOrderpreXpath as $key => $entry)
            {
                PH::print_stdout( " - preXpath: ".$this->additionalRuleOrderpreXpath[$key]);
                PH::print_stdout( " - postXpath: ".$this->additionalRuleOrderpostXpath[$key]);
                PH::print_stdout();

                $combinedArray1 = array();
                $file1Element = $this->additionalRuleOrderCalculateXpathGetElement( "file1", $origDoc1, $this->additionalRuleOrderpreXpath[$key], $this->additionalRuleOrderpostXpath[$key], $combinedArray1 );
                if( $this->debugAPI )
                {
                    #print "PRE\n";
                    #DH::DEBUGprintDOMDocument( $file1Element );
                    print "FILE1\n";
                    print_r($combinedArray1);
                }

                $combinedArray2 = array();
                $file2Element = $this->additionalRuleOrderCalculateXpathGetElement( "file2", $origDoc2, $this->additionalRuleOrderpreXpath[$key], $this->additionalRuleOrderpostXpath[$key], $combinedArray2 );
                if( $this->debugAPI )
                {
                    #print "POST\n";
                    #DH::DEBUGprintDOMDocument( $file2Element );
                    print "FILE2\n";
                    print_r($combinedArray2);
                }

                ########################################################################################################################

                if( $file1Element == null || $file2Element == null )
                {
                    mwarning( "this is not a DG config - or filter JSON 'combinedruleordercheck' xpath not found", null, FALSE );
                    break;
                }

                $combinedArray = array_merge_recursive($combinedArray1, $combinedArray2);


                $el1rulebase = array();
                $el2rulebase = array();
                $this->additionalCalculateRuleorder( $file1Element, $el1rulebase);
                $this->additionalCalculateRuleorder( $file2Element, $el2rulebase);

                if( $this->debugAPI )
                {
                    #print_r( $combinedArray );
                }

                $this->failStatus_additionalruleorder = $this->checkAdditionalRuleOrderArray( $combinedArray );

                $this->additionalruleorderOUTPUT( $combinedArray );

                //check Rules
                /*
                if( isset( $el1rulebase['rules'] ) )
                    $this->failStatus_additionalruleorder = $this->additionalCheckRuleOrder( $el1rulebase, $el2rulebase );
                else
                {
                    foreach( $el1rulebase as $key => $entry )
                        $this->failStatus_additionalruleorder = $this->additionalCheckRuleOrder( $el1rulebase, $el2rulebase, $key );
                    foreach( $el2rulebase as $key => $entry )
                        $this->failStatus_additionalruleorder = $this->additionalCheckRuleOrder( $el1rulebase, $el2rulebase, $key );
                }
                */
            }
        }

        PH::print_stdout( "\n####################################################################\n");

        if( !$this->failStatus_diff && !$this->failStatus_additionalruleorder )
        {
            //must be in this format as check is needed
            PH::print_stdout( "- FinalResult:   PASS" );
            PH::print_stdout( array('PASS'), false, "finalresult" );
        }
        else#if( $this->failStatus_diff || $this->failStatus_additionalruleorder )
        {
            PH::print_stdout("- FinalResult:   FAIL");
            PH::print_stdout( array('FAIL'), false, "finalresult" );
        }
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
            foreach( $this->filters as $filter )
            {
                $continue = false;
                $this->filter_exclude( $continue, $filter );
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


                    if( strpos( $item, "[@name='" ) !== False )
                    {
                        $orig = $item;

                        $pos = strpos($item, "[@name='");
                        $item = substr( $item, 0 , $pos);
                        $element = $xmlDoc1->createElement($item);

                        $nameattribute = substr( $orig, $pos+8,strpos($orig, "']"));
                        $nameattribute = str_replace( "']", "", $nameattribute );
                        $element->setAttribute( "name", $nameattribute);
                    }
                    else
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
            $this->failStatus_diff = TRUE;
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

        $continue = false;
        $this->filter_exclude( $continue, $xpath );
        if( $continue )
            return null;

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

            if( $this->avoidDisplayWhitspaceDiffCertificate )
            {
                if( $el1Trim != $el2Trim && strpos($xpath, "/certificate/") !== FALSE )
                {
                    $el1Trim = preg_replace('/\s+/', ' ', $el1Trim);
                    $el2Trim = preg_replace('/\s+/', ' ', $el2Trim);
                }
            }


            if( $el1Trim != $el2Trim )
            {
                $text = '';
                PH::$JSON_TMP = array();
                PH::$JSON_TMP['plus'] = array();
                PH::$JSON_TMP['minus'] = array();
                PH::$JSON_TMP['xpath'] = $xpath;

                $continue = $this->ignoreAddDeleteXpath( $xpath, $el1, $this->deleted );
                if( $continue )
                    return;

                $tmp = DH::dom_to_xml($el1);
                $text .= '-' . $tmp;
                PH::$JSON_TMP['minus'][] = $tmp;


                $continue = $this->ignoreAddDeleteXpath( $xpath, $el1, $this->added );
                if( $continue )
                    return;

                $tmp = DH::dom_to_xml($el2);
                $text .= '+' . $tmp;
                PH::$JSON_TMP['plus'][] = $tmp;


                PH::print_stdout( PH::$JSON_TMP, false, "diff" );
                PH::$JSON_TMP = array();

                //same xpath different content
                $this->displayDIFF( $xpath, $text, array( $el2 ), array( $el1 ), array( $el1 ) );
                $this->failStatus_diff = TRUE;
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
                $fullXpathName = $xpath."/".$tagName;
                #PH::print_stdout( $fullXpathName );

                $continue = false;
                $this->filter_exclude( $continue, $fullXpathName );
                $this->filter_deleted( $continue, $fullXpathName );
                if( !$continue )
                    foreach( $nodeArray1 as $node )
                    {
                        $continue = false;
                        $attribute = DH::findAttribute('name', $node);
                        if( $attribute !== FALSE )
                        {
                            $this->filter_exclude( $continue, $fullXpathName."[@name='".$attribute."']" );
                            $this->filter_deleted( $continue, $fullXpathName."[@name='".$attribute."']" );
                        }

                        if( !$continue )
                            $minus[] = $node;
                    }
                unset($el1Elements[$tagName]);
            }
        }
        foreach( $el2Elements as $tagName => &$nodeArray2 )
        {
            if( !isset($el1Elements[$tagName]) )
            {
                $fullXpathName = $xpath."/".$tagName;
                #PH::print_stdout( $fullXpathName );

                $continue = false;
                $this->filter_exclude( $continue, $fullXpathName );
                $this->filter_added( $continue, $fullXpathName );
                if( !$continue )
                    foreach( $nodeArray2 as $node )
                    {
                        $continue = false;
                        $attribute = DH::findAttribute('name', $node);
                        if( $attribute !== FALSE )
                        {
                            $this->filter_exclude( $continue, $fullXpathName."[@name='".$attribute."']" );
                            $this->filter_added( $continue, $fullXpathName."[@name='".$attribute."']" );
                        }

                        if( !$continue )
                            $plus[] = $node;
                    }
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
                        #mwarning('<node name="' . $nodeName . '"> was found twice in file1', $el1, false, FALSE);
                        mwarning('<node name="' . $nodeName . '"> was found twice in file1', $node, false, FALSE);
                    }

                    else
                        $el1NameSorted[$nodeName] = $node;
                }
                foreach( $nodeArray2 as $nodeIndex => $node )
                {
                    $nodeName = $node->getAttribute('name');
                    if( isset($el2NameSorted[$nodeName]) )
                    {
                        #mwarning('<node name="' . $nodeName . '"> was found twice in file2', $el2, false, FALSE);
                        mwarning('<node name="' . $nodeName . '"> was found twice in file2', $node, false, FALSE);
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

        PH::$JSON_TMP = array();
        #if( count($plus) > 0 || count( $minus ) > 0 )
        #    PH::$JSON_TMP['xpath'] = $xpath;

        PH::$JSON_TMP['plus'] = array();
        foreach( $plus as $key => $node )
        {
            //check if xpath should be ignored as added to JSON file
            $continue = $this->ignoreAddDeleteXpath( $xpath, $node, $this->added );
            if( $continue )
                continue;

            $tmp = DH::dom_to_xml($node);
            $tmp = $this->str_lreplace( "\n", "", $tmp );
            PH::$JSON_TMP['plus'][] = $tmp;

            $text .= "\n+" . str_replace("\n", "\n+", $tmp);
            $this->failStatus_diff = TRUE;
        }

        if( count($plus) > 0 && count( $minus ) > 0 )
            $text .= "\n";

        PH::$JSON_TMP['minus'] = array();
        foreach( $minus as $key => $node )
        {
            //check if xpath should be ignored as added to JSON file
            $continue = $this->ignoreAddDeleteXpath( $xpath, $node, $this->deleted );
            if( $continue )
                continue;

            $tmp = DH::dom_to_xml($node);
            $tmp = $this->str_lreplace( "\n", "", $tmp );
            PH::$JSON_TMP['minus'][] = $tmp;

            $text .= "\n-" . str_replace("\n", "\n-", $tmp);
            $this->failStatus_diff = TRUE;
        }

        if( count($plus) > 0 || count( $minus ) > 0 )
        {
            if( count(PH::$JSON_TMP['plus']) > 0 || count( PH::$JSON_TMP['minus'] ) > 0 )
            {
                PH::$JSON_TMP['xpath'] = $xpath;
                PH::$JSON_TMP = array_merge(array('xpath' => $xpath), PH::$JSON_TMP);

                PH::print_stdout( PH::$JSON_TMP, false, "diff" );
            }
        }

        PH::$JSON_TMP = array();

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
                    //Todo: swaschkut 20220728
                    // - rulebase on parts below where it is planned to set to ANY:
                    // - remove all other other objects before set command .... any
                    // - service
                    // - application
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
                    //Todo: swaschkut 20220728
                    // - part which were already set earlier, so it got manipulated, must not be delete anymore -> response "Invalid syntax."
                    // - description - if it was set earlier to a different value
                }
            }
            else
            {
                if( !empty( trim($text) ) )
                {
                    PH::print_stdout("\nXPATH: $xpath");
                    PH::print_stdout("$text");
                }
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

    function str_lreplace($search, $replace, $subject)
    {
        $pos = strrpos($subject, $search);

        if($pos !== false)
        {
            $subject = substr_replace($subject, $replace, $pos, strlen($search));
        }

        return $subject;
    }

    function filter_exclude( &$continue, $string )
    {
        $this->parsingFilter( $this->excludes, $continue, $string );
    }

    function filter_added( &$continue, $string )
    {
        $this->parsingFilter( $this->added, $continue, $string );
    }

    function filter_deleted( &$continue, $string )
    {
        $this->parsingFilter( $this->deleted, $continue, $string );
    }

    function parsingFilter( $typeArray, &$continue, $string )
    {
        foreach( $typeArray as $exclude )
        {
            if( strpos( $exclude, "\$\$name\$\$" ) !== FALSE )
            {
                $escapedString = preg_quote( $exclude, '/' );
                $escapedString = str_replace( "\\\$\\\$name\\\$\\\$", "(.*)", $escapedString );

                $pattern = "/".$escapedString."/i";

                $match = preg_match($pattern, $string); // Outputs 1 if match
                $continue = $match;
            }
            else
            {
                if( strpos( $string, $exclude ) !== FALSE )
                    $continue = true;
            }
        }
    }

    function additionalRuleOrderCalculateXpathGetElement( $tmp, $doc, $preXpath, $postXpath, &$combinedArray )
    {
        $preElement = false;
        $postElement = false;
        $preXpathArray = explode("/", $preXpath);
        $postXpathArray = explode("/", $postXpath);

        $root = $doc->documentElement;
        $set = FALSE;
        foreach( $preXpathArray as $key => $item )
        {
            if( $item === "" )
                continue;
            $demo = DH::findFirstElement($item, $root);
            if( $demo !== FALSE )
            {
                if( array_key_last($preXpathArray) == $key )
                    $set = TRUE;
                $root = $demo;
            }
        }
        if( $set )
            $preElement = $root;
        #DH::DEBUGprintDOMDocument($preElement);


        $root = $doc->documentElement;
        $set = FALSE;
        foreach( $postXpathArray as $key => $item )
        {
            if( $item === "" )
                continue;
            $demo = DH::findFirstElement($item, $root);
            if( $demo !== FALSE )
            {
                if( array_key_last($postXpathArray) == $key )
                    $set = TRUE;
                $root = $demo;
            }
        }
        if( $set )
            $postElement = $root;
        #DH::DEBUGprintDOMDocument($postElement);

        #############
        $finalDoc = new DOMDocument();
        $nodeconfig = $finalDoc->createElement("config");
        $finalDoc->appendChild($nodeconfig);

        #if( $preElement === false )
        #    return false;

        $preArray = array();
        $preRules = DH::findFirstElement("rules", $preElement);
        $i=1;
        if( $preRules !== FALSE && $preElement->parentNode->nodeName == "pre-rulebase" )
        {

            foreach( $preRules->childNodes as $childNode )
            {
                /** @var null|DOMElement $childNode */
                if( $childNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $childNode->setAttribute( "ruletype", "pre" );
                $name = DH::findAttribute("name", $childNode);
                $preArray[$name] = $tmp."-pre-".$i;
                $node2 = $finalDoc->importNode($childNode, TRUE);
                /** @var DOMElement $node2 */

                $nodeconfig->appendChild($node2);
                $i++;
            }
        }

        $postArray = array();
        if( $postElement !== false )
        {
            //rules element from new config file
            $preRules = DH::findFirstElementOrCreate( "rules", $nodeconfig);

            $postRules = DH::findFirstElement("rules", $postElement);

            foreach( $postRules->childNodes as $childNode )
            {
                /** @var null|DOMElement $childNode */
                if( $childNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $childNode->setAttribute( "ruletype", "post" );
                $name = DH::findAttribute("name", $childNode);
                $postArray[$name] = $tmp."-post-".$i;
                $node = $finalDoc->importNode($childNode, TRUE);

                $preRules->appendChild($node);
                #DH::DEBUGprintDOMDocument($node);
                $i++;
            }
        }

        $combinedArray = array_merge($preArray, $postArray);

        return $nodeconfig;
    }

    function additionalCalculateRuleorder( $Elements, &$rulebase)
    {
        foreach( $Elements->childNodes as $childNode )
        {
            /** @var null|DOMElement $childNode*/
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $content = $childNode->nodeName;

            if( $content !== "rules" )
                $rules = DH::findFirstElement("rules", $childNode);
            else
                $rules = $childNode;

            if( $rules != FALSE )
                foreach( $rules->childNodes as $key => $rule )
                {
                    /** @var null|DOMElement $rule*/
                    if( $rule->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $uuid = $rule->getAttribute('uuid');
                    $name = $rule->getAttribute('name');
                    if( $content !== "config" )
                        $rulebase[$content][$name] = $name;
                    else
                        $rulebase[$name] = $name;
                }
        }
    }

    function additionalCheckRuleOrder( $el1rulebase, $el2rulebase, $type = null )
    {
        $fail = false;

        if( $type === null )
        {
            foreach( $el1rulebase['rules'] as $key => $rule )
            {
                $posFile1 = array_search($key, array_keys($el1rulebase['rules']));
                $posFile2 = array_search($key, array_keys($el2rulebase['rules']));

                if( $posFile1 !== $posFile2 )
                {
                    $fail = true;
                    PH::print_stdout( "\n Rule: ". $rule);
                    PH::print_stdout( "x different RULE position: file1: pos".$posFile1." / file2: pos".$posFile2 );
                }
            }
        }
        elseif( $type !== null )
        {
            if( isset( $el1rulebase[$type] ) )
                foreach( $el1rulebase[$type] as $key => $rule )
                {
                    if( isset( $el1rulebase[$type] ) )
                        $posFile1 = array_search($key, array_keys($el1rulebase[$type]));
                    else
                        $posFile1 = "---";
                    if( isset( $el2rulebase[$type] ) )
                        $posFile2 = array_search($key, array_keys($el2rulebase[$type]));
                    else
                        $posFile2 = "---";

                    if( $posFile1 !== $posFile2 )
                    {
                        $fail = true;
                        PH::print_stdout( "\n ".$type." Rule: ". $rule);
                        PH::print_stdout( "x different RULE position: file1: pos".$posFile1." / file2: pos".$posFile2 );
                    }
                    if( isset( $el2rulebase[$type] ) )
                        unset( $el2rulebase[$type] );
                }

            if( isset( $el2rulebase[$type] ) )
                foreach( $el2rulebase[$type] as $key => $rule )
                {
                    if( isset( $el1rulebase[$type] ) )
                        $posFile1 = array_search($key, array_keys($el1rulebase[$type]));
                    else
                        $posFile1 = "---";
                    if( isset( $el2rulebase[$type] ) )
                        $posFile2 = array_search($key, array_keys($el2rulebase[$type]));
                    else
                        $posFile2 = "---";

                    if( $posFile1 !== $posFile2 )
                    {
                        $fail = true;
                        PH::print_stdout( "\n ".$type." Rule: ". $rule);
                        PH::print_stdout( "x different RULE position: file1: pos".$posFile1." / file2: pos".$posFile2 );
                    }
                }
        }

        return $fail;
    }

    function checkAdditionalRuleOrderArray( $array )
    {
        foreach( $array as $entry )
        {
            if( !is_array($entry) )
                return false;
        }
        return true;
    }

    function moveElement(&$array, $a, $b) {
        $out = array_splice($array, $a, 1);
        array_splice($array, $b, 0, $out);
    }

    function additionalruleorderOUTPUT($combinedArray)
    {
        $finalArray = array();
        foreach( $combinedArray as $key => $entry )
        {
            if( !is_array($entry) )
            {
                $info = explode( "-", $entry );
                $file = $info[0];
                $prepost = $info[1];
                if( $file == "file1" )
                {
                    $pos1 = $info[2];
                    $pos2 = "-";
                }
                else
                {
                    $pos1 = "-";
                    $pos2 = $info[2];
                }

                $rulename = str_pad($key,  60, " ");
                $type = str_pad($prepost,  10, " ");
                #PH::print_stdout( " - ".$rulename." | ".$file." |".$type."|".$pos );
                $tmpArray = array( "rule"=>$rulename, "file"=>$file, "type"=>$type, "pos1"=>$pos1, "pos2"=>$pos2, "check"=>"" );
            }
            else
            {
                #print_r($entry);
                $info = "";
                $file1 = "";
                $file2 = "";
                $prepost1 = "";
                $prepost2 = "";
                $pos1 = "";
                $pos2 = "";
                foreach( $entry as $key2 => $item )
                {
                    if( $key2 == 0 )
                    {
                        $info = explode( "-", $item );
                        $file1 = $info[0];
                        $prepost1 = $info[1];
                        $pos1 = $info[2];
                    }
                    else
                    {
                        $info = explode( "-", $item );
                        $file2 = $info[0];
                        $prepost2 = $info[1];
                        $pos2 = $info[2];
                    }
                }
                $rulename = str_pad($key,  60, " ");
                $type = str_pad($prepost1."/".$prepost2,  10, " ");
                #PH::print_stdout( " - ".$rulename." |       |".$type."|".$pos1."/".$pos2 );
                $tmpArray = array( "rule"=>$rulename, "file"=>"", "type"=>$type, "pos1"=>$pos1, "pos2"=>$pos2, "check"=>"" );
            }
            $finalArray[] = $tmpArray;
        }

        #print_r($finalArray);
        $move = array();
        foreach( $finalArray as $key => $item )
        {
            if( $item['file'] == "file2" )
            {
                $finalArray[$key]['check'] = "<<<<<<<<<<";
                $move[] = array( $key, $item['pos2']+1 );
            }

        }
        foreach( $move as $item )
        {
            $this->moveElement($finalArray, $item[0], $item[1]);
        }
        #print_r($finalArray);
        foreach( $finalArray as $entry )
        {
            $char = " ";
            if( strpos( $entry['check'], "<" ) !== false )
                $char = "<";
            $rulename = str_pad($entry['rule'],  70, $char);
            $file = str_pad($entry['file'],  5, " ");
            $type = $entry['type'];
            $pos = str_pad($entry['pos1']."/".$entry['pos2'],  10, " ");
            PH::print_stdout( "   - ".$rulename." | ".$file." |".$type."|".$pos."|".$entry['check'] );
        }
    }

    function ignoreAddDeleteXpath( $xpath, &$node, $typeArray )
    {
        $newdoc = new DOMDocument;
        $node = $newdoc->importNode($node, true);
        $newdoc->appendChild($node);

        $origXpath = $xpath;

        $continue = false;
        foreach( $typeArray as $add )
        {
            $xpath = $origXpath;
            $newXpath = "";
            $textContainsremoved = false;
            $string_Containsremoved = "";
            ###########################
            ###########################
            //new approach
            if( strpos( $add, "'*'" ) !== FALSE )
            {
                if($this->debugAPI)
                {
                    print "---------------------\n";
                    print "ORIGXPATH: ".$origXpath."\n";
                    print "ORIGADD: ".$add."\n";
                }

                if( strpos( $add, "entry[@name='*']" ) !== FALSE )
                {
                    if( strpos( $add, "[text()[contains(.,'") !== false )
                    {
                        $string_array = explode( "/", $add );
                        $lastkey = array_key_last($string_array);
                        $string_Containsremoved = $string_array[$lastkey];
                        $add = str_replace( "/".$string_Containsremoved, "", $add );

                        if($this->debugAPI)
                        {
                            print "removed: ".$string_Containsremoved."\n";
                            print "ADD0: ".$add."\n";
                        }

                        $textContainsremoved = true;
                    }

                    $searchEntry = "entry[@name='";

                    $subXpath = substr( $xpath, 0, strpos( $xpath, $searchEntry ) );
                    $subAddXpath = substr( $add, 0, strpos( $add, $searchEntry ) );
                    if( $subXpath === $subAddXpath )
                    {
                        $xpath = str_replace( $subXpath, "", $xpath );
                        $add = str_replace( $subAddXpath, "", $add );
                    }
                    else
                        continue;


                    $xpath_array = explode( "/", $xpath );
                    $addXpath_array = explode( "/", $add );
                    if( isset($xpath_array[1]) && isset( $addXpath_array[1] ) && ($xpath_array[1] === $addXpath_array[1]) )
                    {
                        $xpath = str_replace($xpath_array[0] . "/" . $xpath_array[1], "", $xpath);
                        $add = str_replace($addXpath_array[0] . "/" . $addXpath_array[1], "", $add);

                        do
                        {
                            $xpath_array = explode("/", $xpath);
                            $addXpath_array = explode("/", $add);
                            unset($xpath_array[0]);
                            unset($addXpath_array[0]);

                            #print_r($xpath_array);
                            #print_r($addXpath_array);
                            //why does while loop not exist with statement at end?
                            if( empty($xpath_array) || empty($addXpath_array) )
                                break;

                            $xpath = str_replace("/" . $xpath_array[1], "", $xpath);
                            $add = str_replace("/" . $addXpath_array[1], "", $add);
                        } while( empty($xpath_array) || empty($addXpath_array) );
                    }

                    if( $textContainsremoved )
                    {
                        #print "---------------------\n";
                        #print "2XPATH: ".$xpath."\n";
                        #print "2ADD: ".$add."\n";
                        $newXpath = $add."/".$string_Containsremoved;
                    }
                    else
                        $newXpath = str_replace($xpath, "", $add);


                }
                elseif( strpos( $add, "[text()[contains(.,'") !== false )
                {
                    print "text contains only found - no entry *\n";
                }
            }
            ###########################
            ###########################
            else
                $newXpath = str_replace( $xpath, "", $add );



            if( strpos( $newXpath, "[" ) === 0 )
            {
                $string_array = explode( "/", $xpath );
                $lastkey = array_key_last($string_array);
                $string = $string_array[$lastkey];
                $newXpath = "/".$string.$newXpath;
            }

            if( $this->debugAPI )
                print "NEWXPATH: ".$newXpath."\n";


            //////textnode search
            $textNodeFound = FALSE;
            if( !empty($newXpath) )
            {
                $domXpath = new DOMXPath($newdoc);
                foreach( $domXpath->query($newXpath) as $textNode )
                {
                    #$this->deleteNodeReverseAlsoParent($textNode);

                    if( $textContainsremoved )
                    {
                        if( $textNode !== FALSE && !DH::hasChild($textNode) )
                        {
                            #$this->deleteNodeReverseAlsoParent($textNode);
                            $textNodeFound = TRUE;
                        }

                    }
                    else
                    {
                        if( $textNode !== FALSE )
                        {
                            #$this->deleteNodeReverseAlsoParent($textNode);
                            $textNodeFound = TRUE;
                        }

                    }

                }
            }


            if( $textNodeFound )
                $continue = true;
            elseif( empty( $newXpath ) )
                $continue = true;
            elseif( $node->nodeName == "entry" )
            {
                $name = DH::findAttribute( "name", $node);
                if( $newXpath == "/entry[@name='".$name."']" )
                    $continue = true;
                elseif( strpos( $newXpath, "'*'" ) !== FALSE && $newXpath == "/entry[@name='*']" )
                        $continue = true;
            }
            elseif( $xpath !== $newXpath )
            {
                #print "XPATH: ".$xpath."\n";
                #print "NEWXPATH: ".$newXpath."\n";

                if( strpos( $newXpath, "'*'" ) !== FALSE )
                {
                    /*
                    $string_array = explode( "/", $newXpath );
                    if( isset( $string_array[1] ) )
                    {

                        if( $node->nodeName == $string_array[1] )
                        {
                            if( $string_array[2] == "entry[@name='*']" )
                            {
                                $nodeList = $node->getElementsByTagName("entry");
                                $nodeArray = iterator_to_array($nodeList);
                                foreach( $nodeArray as $entry )
                                    DH::removeChild( $node, $entry );
                            }
                        }
                    }
                    */
                }
                else
                {
                    /*
                    //find newXpath within a node somewhere as a subnode, and remove this node
                    $doc1Root = DH::findXPathSingleEntry($newXpath, $node);
                    if( $doc1Root )
                        DH::removeChild( $doc1Root->parentNode, $doc1Root );
                    */
                }
            }
        }


        if( !empty( $this->empty ) )
        {
            foreach( $this->empty as $empty )
            {
                $xpath = $origXpath;
                #print "ORIGXPATH: ".$xpath."\n";
                #print "ORIGEMPTY: ".$empty."\n";
                if(strpos( $empty, "entry[@name='*']" ) !== FALSE )
                {
                    $xpath = substr( $xpath, 0, strpos( $empty, "entry[@name='*']" )-1 );
                    #print "2XPATH: ".$empty."\n";
                }

                $empty = str_replace( $xpath, "", $empty );
                #print "2EMPTY: ".$empty."\n";

                $excludeXpath = $empty;
                $excludeXpath = str_replace( "entry[@name='*']/", "entry/", $excludeXpath );
                if( $excludeXpath !== "" )
                {
                    $domXpath1 = new DOMXPath($newdoc);
                    #print "excludeXPATH: ".$excludeXpath."\n";
                    foreach( $domXpath1->query($excludeXpath) as $node )
                    {
                        #DH::DEBUGprintDOMDocument($node);
                        if( !DH::hasChild($node) )
                            $this->deleteNodeReverseAlsoParent($node);
                    }
                }
            }
        }


        return $continue;
    }

    function deleteNodeReverseAlsoParent( &$node )
    {
        if( $node !== FALSE && $node !== null )
        {
            $parent = $node->parentNode;
            if( $parent === False || $parent === null )
                return;
            $parent->removeChild( $node );
            if( !DH::hasChild($parent) )
                $this->deleteNodeReverseAlsoParent($parent);
        }
    }

    function OLD_asterisksearch( $add, $xpath, &$node)
    {
        if( strpos( $add, "'*'" ) !== FALSE )
        {
            $textContainsremoved = false;
            $string_Containsremoved = "";
            if( strpos( $add, "[text()[contains(.,'") !== false )
            {
                $string_array = explode( "/", $add );
                $lastkey = array_key_last($string_array);
                $string_Containsremoved = $string_array[$lastkey];
                #print "removed: ".$string_Containsremoved."\n";
                $add = str_replace( "/".$string_Containsremoved, "", $add );
                #print "\nADD0: ".$add."\n";
                $textContainsremoved = true;
            }

            ###############################################################
            //if $add xpath is longer then $xpath
            $count1 = substr_count($xpath, '/');
            $count2 = substr_count($add, '/');
            if( $this->debugAPI )
            {
                #print "\nMAINXPATH: ".$xpath."\n";
                #print "\nADD0: ".$add."\n";
                #print "count1: ".$count1."\n";
                #print "count2: ".$count2."\n";
            }


            $substring = "'*']";
            $length = strlen($substring);
            $endwithstring = false;
            if ( substr_compare($add, $substring, -$length) === 0 )
            {
                #$endwithstring=true;
            }



            if( $count2-1 > $count1 )#&& !$endwithstring )
            {
                print "manipulation of xpath\n";
                #Todo: validation needed!!!!!!!!!!
                # newly added for specific part
                $xpath .= $node->getNodePath();
                $xpathsearchmanipulation = true;
            }
            ###############################################################

            $search2 = preg_quote($add, '/');
            $search2 = str_replace( "'\*'", "(.*?)", $search2);
            if( $this->debugAPI )
                print "searchstring: ".$search2."\n";

            $pattern = '/'.$search2.'/is';
            if( preg_match($pattern, $xpath, $matches) )
            {
                if( $this->debugAPI )
                    print_r($matches);
                #print "\nXPATH1: ".$xpath."\n";
                #print "\nADD1: ".$add."\n";
                //CASE2 - '*' somewhere in between
                $newXpath = str_replace( $matches[0], "", $xpath );
                if( $textContainsremoved )
                    $newXpath = $newXpath."/".$string_Containsremoved;
                #print "NEWXPATH1: ".$newXpath."\n";
            }

            else
            {
                //CASE1 - '*' at end, eg. "/PATH/entry[@name='*']"
                #print "\nXPATH2: ".$xpath."\n";
                #print "\nADD2: ".$add."\n";
                $newXpath = str_replace( $xpath, "", $add );
                if( $textContainsremoved )
                    $newXpath = $newXpath."/".$string_Containsremoved;
                #print "NEWXPATH2: ".$newXpath."\n";
            }
        }
        #else
    }
}
