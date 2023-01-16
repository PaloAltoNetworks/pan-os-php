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

class XPATH extends UTIL
{

    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
            "        \"node-filter=certificate\"\n".
            "        \"[nameattribute-filter=address_object_name]\"\n".
            "        \"[xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-server]\"\n".
            "        \"[display-fullxpath]\"\n".
            "        \"[display-xmlnode]\"\n".
            "        \"[display-attributename]\"\n".
            "php ".basename(__FILE__)." help          : more help messages\n";

        $this->add_supported_arguments();
        
        $this->prepareSupportedArgumentsArray();


        PH::processCliArgs();
        $this->help(PH::$args);
        $this->init_arguments();


        #$this->load_config();


        $this->main();

    }

    public function main()
    {
        $fullxpath = false;
        $xpath = null;
        $displayXMLnode = false;
        $displayAttributeName = false;

        if( !isset( PH::$args['node-filter'] ) && !isset( PH::$args['nameattribute-filter'] ) && !isset( PH::$args['xpath-filter'] ) )
            $this->display_error_usage_exit('"node-filter" argument is not set: example "certificate"');
        elseif( !isset( PH::$args['node-filter'] ) && isset( PH::$args['nameattribute-filter'] ) )
            $qualifiedNodeName = "entry";
        elseif( !isset( PH::$args['xpath-filter'] ) )
            $qualifiedNodeName = PH::$args['node-filter'];

        if( isset( PH::$args['xpath-filter'] ) )
            $xpath = PH::$args['xpath-filter'];

        if( isset( PH::$args['display-fullxpath'] ) )
            $fullxpath = true;

        if( isset( PH::$args['display-xmlnode'] ) )
            $displayXMLnode = true;

        if( isset( PH::$args['nameattribute-filter'] ) )
            $nameattribute = PH::$args['nameattribute-filter'];
        else
            $nameattribute = null;

        if( isset( PH::$args['display-nameattribute'] ) )
            $displayAttributeName = true;
        ########################################################################################################################

        if( !isset( PH::$args['xpath-filter'] ) )
        {
            //todo: missing connector support
            $nodeList = $this->xmlDoc->getElementsByTagName($qualifiedNodeName);
            $nodeArray = iterator_to_array($nodeList);

            $templateEntryArray = array();
            foreach( $nodeArray as $item )
            {
                if( $nameattribute !== null )
                {
                    $XMLnameAttribute = DH::findAttribute("name", $item);
                    if( $XMLnameAttribute === FALSE )
                        continue;

                    if( $XMLnameAttribute !== $nameattribute )
                        continue;
                }
                $text = DH::elementToPanXPath($item);
                $replace_template = "/config/devices/entry[@name='localhost.localdomain']/template/";

                if( $xpath !== null && strpos($text, $xpath) === FALSE )
                    continue;

                if( strpos($text, $replace_template) !== FALSE )
                {
                    $tmpArray['xpath'] = $text;
                    $text = str_replace($replace_template, "", $text);


                    $templateXpathArray = explode("/", $text);
                    //"entry[@name='CALEPA-TMS-PAN_Template01']"
                    $templateName = str_replace("entry[@name='", "", $templateXpathArray[0]);
                    $templateName = str_replace("']", "", $templateName);

                    $replace = "entry[@name='" . $templateName . "']";
                    $text = str_replace($replace, "", $text);

                    $tmpArray['text'] = $text;
                    $tmpArray['node'] = $item;

                    $templateEntryArray['template'][$templateName][] = $tmpArray;

                }
                else
                {
                    $tmpArray['text'] = $text;
                    $tmpArray['node'] = $item;

                    $templateEntryArray['misc'][] = $tmpArray;
                }

            }


            if( isset($templateEntryArray['template']) )
            {
                foreach( $templateEntryArray['template'] as $templateName => $templateEntry )
                {
                    PH::print_stdout();
                    PH::print_stdout("TEMPLATE: " . $templateName);
                    foreach( $templateEntry as $item )
                    {
                        PH::print_stdout();
                        PH::print_stdout("---------");
                        if( !$displayXMLnode && !$displayAttributeName )
                            PH::print_stdout( "   * XPATH: ".$item['text'] );

                        if( $fullxpath )
                            PH::print_stdout("     |" . $item['xpath'] . "|");

                        if( $displayXMLnode )
                            $this->getXpathDisplay( $item['xpath'], "");
                        if( $displayAttributeName )
                            $this->getXpathDisplay( $item['xpath'], "", true);
                    }
                }
            }

            if( isset($templateEntryArray['misc']) )
            {
                PH::print_stdout("MISC:");

                foreach( $templateEntryArray['misc'] as $miscEntry )
                {
                    $xpath = $miscEntry['text'];
                    PH::print_stdout();
                    PH::print_stdout("---------");

                    if( !$displayXMLnode && !$displayAttributeName )
                        PH::print_stdout( "   * XPATH: ".$xpath );

                    if( $displayXMLnode )
                        $this->getXpathDisplay( $xpath, "");
                    if( $displayAttributeName )
                        $this->getXpathDisplay( $xpath, "", true);
                }
            }

            PH::print_stdout();
        }
        else
        {
            if( $this->pan->connector !==  null )
            {
                $this->pan->connector->refreshSystemInfos();

                PH::print_stdout();
                PH::print_stdout( "##########################################" );
                PH::print_stdout( 'MASTER device serial: '.$this->pan->connector->info_serial );
                PH::print_stdout();

                PH::$JSON_TMP['serial'] = $this->pan->connector->info_serial;
                PH::print_stdout(PH::$JSON_TMP, false, "master device");
                PH::$JSON_TMP = array();

                if( $this->configType == 'panos' )
                {
                    if( $this->pan->connector->serial != "" )
                    {
                        $fw_con = $this->pan->connector->cloneForPanoramaManagedDevice($this->pan->connector->serial);
                        $fw_con->refreshSystemInfos();
                        if( $this->debugAPI )
                            $fw_con->setShowApiCalls( $this->debugAPI );
                        if( $displayAttributeName )
                            $this->getXpathDisplay( $xpath, $this->pan->connector->serial, true);
                        else
                            $this->getXpathDisplay( $xpath, $this->pan->connector->serial);
                    }
                    else
                    {
                        $this->pan->connector->refreshSystemInfos();
                        if( $displayAttributeName )
                            $this->getXpathDisplay( $xpath, $this->pan->connector->serial, true);
                        else
                            $this->getXpathDisplay( $xpath, $this->pan->connector->info_serial);
                    }
                }
                elseif( $this->configType == 'panorama' )
                {
                    $device_serials = $this->pan->connector->panorama_getConnectedFirewallsSerials();

                    $i=0;
                    foreach( $device_serials as $child )
                    {
                        $fw_con = $this->pan->connector->cloneForPanoramaManagedDevice($child['serial']);
                        $fw_con->refreshSystemInfos();
                        if( $this->debugAPI )
                            $fw_con->setShowApiCalls( $this->debugAPI );

                        $string = " - SERIAL: ".$child['serial'];
                        $string .= "  -  ".$child['hostname']." - ";
                        $string .= $fw_con->info_mgmtip;

                        PH::print_stdout( $string );
                        $i++;

                        if( $displayAttributeName )
                            $this->getXpathDisplay( $xpath, $child['serial'], true);
                        else
                            $this->getXpathDisplay( $xpath, $child['serial']);
                    }
                }
            }
            else
            {
                if( $displayAttributeName )
                    $this->getXpathDisplay( $xpath, "", true);
                else
                    $this->getXpathDisplay( $xpath, "");
            }
        }
    }

    function add_supported_arguments()
    {
        $this->supportedArguments = array();
        $this->supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->supportedArguments[] = Array('niceName' => 'node-filter', 'shortHelp' => 'specify the node-filter to get all xPath within this configuration file');
        $this->supportedArguments[] = Array('niceName' => 'xpath-filter', 'shortHelp' => 'specify the xpath to get the value defined on this config');
        $this->supportedArguments[] = Array('niceName' => 'nameattribute-filter', 'shortHelp' => 'specify the nameattribute to get only XMLnode where nameattribute match');

        $this->supportedArguments[] = Array('niceName' => 'display-fullxpath', 'shortHelp' => 'display full xpath for templates');
        $this->supportedArguments[] = Array('niceName' => 'display-NameAttribute', 'shortHelp' => 'display not full Xpath content, only attribute name');
        $this->supportedArguments[] = Array('niceName' => 'display-xmlnode', 'shortHelp' => 'display XML node configuration');
        
    }
    
    function getXpathDisplay( $xpath, $serial, $entry = false)
    {
        PH::$JSON_TMP[$serial]['serial'] = $serial;
        //check Xpath
        $xpathResult = DH::findXPath( $xpath, $this->xmlDoc);
        PH::print_stdout( "   * XPATH: ".$xpath );
        PH::$JSON_TMP[$serial]['xpath'] = $xpath;

        foreach( $xpathResult as $xpath1 )
        {
            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($xpath1, true);
            $newdoc->appendChild($node);

            if( $entry === false )
            {
                PH::print_stdout( "   * VALUE: ".$newdoc->saveXML( $newdoc->documentElement ) );
                PH::$JSON_TMP[$serial]['value'] = $newdoc->saveXML( $newdoc->documentElement );
            }
            else
            {
                foreach( $node->childNodes as $child )
                {
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;
                    if( $child->getAttribute('name') !== "" )
                        PH::print_stdout( "     - name: ". $child->getAttribute('name') );
                }
            }
        }

        if( count($xpathResult) == 0 )
        {
            PH::print_stdout( "   * VALUE: not set" );
            PH::$JSON_TMP[$serial]['value'] = "---";
        }


        PH::print_stdout();
    }
}