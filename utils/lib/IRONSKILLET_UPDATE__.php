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



class IRONSKILLET_UPDATE__
{
    public $ironskillet_pathString;
    public $url;

    function __construct()
    {

        $this->url = "https://raw.githubusercontent.com/PaloAltoNetworks/iron-skillet/";
        $this->ironskillet_pathString = dirname(__FILE__)."/../../iron-skillet";


#$url = "https://github.com/PaloAltoNetworks/iron-skillet/blob/";

        $download_array = array();


//AS
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_spyware.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_spyware.xml
        $download_array['as']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_spyware.xml";
        $download_array['as']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_spyware.xml";
        #$download_array['as']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_spyware.xml";

//AV
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_virus.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_virus.xml
        $download_array['av']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_virus.xml";
        $download_array['av']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_virus.xml";
        #$download_array['av']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_virus.xml";

//URL
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml
        $download_array['url']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_url_filtering.xml";
        $download_array['url']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml";
        #$download_array['url']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml";

//FB
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml
        #$download_array['fb']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml";

//VB
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml
        #$download_array['vb']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml";

//WF
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml
        #$download_array['wf']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml";

//customerURL
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v8.1/templates/panorama/snippets/profiles_custom_url_category.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_custom_url_category.xml
        $download_array['customURL']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_custom_url_category.xml";
        #$download_array['customURL']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_custom_url_category.xml";

//SECgroup
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profile_group.xml
        #$download_array['secgroup']['100'] = "panos_v10.0/templates/panorama/snippets/profile_group.xml";


//LFP
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml
        #$download_array['lfp']['100'] = "panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml";

//ZPP
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml
        #$download_array['zpp']['100'] = "panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml";




        foreach( $download_array as $type )
        {

            foreach( $type as $key => $version )
            {
                $this->createIronSkilletMainFolder();

                $filename = $this->ironskillet_pathString."/".$version;
                #print "storefile: ".$filename."\n";

                $this->createIronSkilletSubFolder( $version );



                $fullurl = $this->url.$version;
                PH::print_stdout( "URL: ".$fullurl );

                $arrContextOptions=array(
                    "ssl"=>array(
                        "verify_peer"=>false,
                        "verify_peer_name"=>false,
                    ),
                );


                $origFile = file_get_contents( $this->url.$version, false, stream_context_create($arrContextOptions));
                if( $key < 90 )
                    $sinkholeIP = "72.5.65.111";
                else
                    $sinkholeIP = "sinkhole.paloaltonetworks.com";


                $origFile = str_replace( "{{ SINKHOLE_IPV4 }}", $sinkholeIP, $origFile);
                $origFile = str_replace( "{{ SINKHOLE_IPV6 }}", "2600:5200::1", $origFile);

                $origFile = "<root>".$origFile."</root>";

                file_put_contents( $this->ironskillet_pathString."/".$version, $origFile);
            }
        }


        //new iron-skillet method yaml file
        //download

        $download_array = array();
        //yaml file pointing to snippet xml so exclude it
        //$download_array['80'] = "panos_v8.0/templates/panorama/snippets/.meta-cnc.yaml";
        //$download_array['81'] = "panos_v8.1/templates/panorama/snippets/.meta-cnc.yaml";
        //$download_array['90'] = "panos_v9.0/templates/panorama/snippets/.meta-cnc.yaml";
        //$download_array['91'] = "panos_v9.1/templates/panorama/snippets/.meta-cnc.yaml";
        $download_array['100'] = "panos_v10.0/templates/panorama/snippets/.meta-cnc.yaml";
        $download_array['101'] = "panos_v10.1/templates/panorama/snippets/.meta-cnc.yaml";
        $download_array['102'] = "panos_v10.2/templates/panorama/snippets/.meta-cnc.yaml";
        $download_array['110'] = "panos_v11.0/templates/panorama/snippets/.meta-cnc.yaml";

        //download all yaml files
        foreach( $download_array as $key => $version )
        {
            $end = strrpos( $version, "/" );
            $path = substr( $version, 0, $end);

            $this->createIronSkilletMainFolder();

            $this->createIronSkilletSubFolder( $version);



            $fullurl = $this->url.$version;
            PH::print_stdout("\n---------------------------------");
            PH::print_stdout( "URL: ".$fullurl );
            PH::print_stdout();

            $origFile = file_get_contents( $this->url.$version, false, stream_context_create($arrContextOptions));
            file_put_contents( $this->ironskillet_pathString."/".$version, $origFile);

            //now go through YAML file
            $yamlcontent = file_get_contents( $this->ironskillet_pathString."/".$version);

            //trigger exception in a "try" block
            PH::enableExceptionSupport();
            try
            {
                $parsed = yaml_parse($yamlcontent);

                /*
                $xml = new SimpleXMLElement('<root/>');
                array_walk_recursive($parsed, array ($xml, 'addChild'));
                $filename = $this->ironskillet_pathString."/".$path."/ironskillet_full_yaml.xml";
                file_put_contents( $filename, $xml->asXML());
                //print $xml->asXML();
                */

                $ironskillet_name_finding = array();
                $ironskillet_name_finding[] = "profiles_spyware";
                $ironskillet_name_finding[] = "profiles_virus";
                $ironskillet_name_finding[] = "profiles_url_filtering";
                $ironskillet_name_finding[] = "profiles_file_blocking";
                $ironskillet_name_finding[] = "profiles_vulnerability";
                $ironskillet_name_finding[] = "profiles_wildfire_analysis";
                $ironskillet_name_finding[] = "profiles_custom_url_category";
                $ironskillet_name_finding[] = "profile_group";
                $ironskillet_name_finding[] = "log_settings_profiles";
                $ironskillet_name_finding[] = "zone_protection_profile";

                foreach( $ironskillet_name_finding as $profilename )
                {

                    PH::print_stdout( "check ironskillet: ".$profilename);

                    $elementArray = $this->find_ironskillet_entry_basedonname($parsed['snippets'], $profilename);
                    if( !empty( $elementArray ) )
                    {
                        $filename = $this->ironskillet_pathString . "/" . $path . "/" . $profilename . ".xml";
                        if( !file_exists($filename) )
                        {
                            $xmlString = "<root>";
                            foreach( $elementArray as $element )
                            {
                                if( isset($element['element']) )
                                {
                                    $xmlString .= $element['element'];
                                }
                            }
                            $xmlString .= "</root>";

                            $sinkholeIP = "sinkhole.paloaltonetworks.com";
                            $xmlString = str_replace("{{ SINKHOLE_IPV4 }}", $sinkholeIP, $xmlString);
                            $xmlString = str_replace("{{ SINKHOLE_IPV6 }}", "2600:5200::1", $xmlString);

                            if( !file_exists($filename) )
                            {
                                PH::print_stdout( "new file: ".$filename );
                                file_put_contents($filename, $xmlString);
                            }
                        }
                        else
                        {
                            //read XML file
                            $newdoc1 = new DOMDocument;
                            $newdoc1->load($filename, XML_PARSE_BIG_LINES);

                            /** @var DOMElement $rootNode1 */
                            $rootNode1 = $newdoc1->firstChild;
                            #DH::DEBUGprintDOMDocument( $rootNode1 );
                            #print "------------\n";

                            $changed = FALSE;
                            foreach( $elementArray as $element )
                            {
                                if( isset($element['element']) )
                                {
                                    $xmlString = $element['element'];

                                    $sinkholeIP = "sinkhole.paloaltonetworks.com";
                                    $xmlString = str_replace("{{ SINKHOLE_IPV4 }}", $sinkholeIP, $xmlString);
                                    $xmlString = str_replace("{{ SINKHOLE_IPV6 }}", "2600:5200::1", $xmlString);


                                    /*
                                    print "\n-----------------\n";
                                    print $xmlString."\n";
                                    print "\n-----------------\n";
                                    */


                                    $xmlString = "<root>" . $xmlString . "</root>";

                                    //read new XML string
                                    $newdoc2 = new DOMDocument;
                                    $newdoc2->loadXML($xmlString);

                                    /** @var DOMElement $rootNode2 */
                                    $rootNode2 = $newdoc2->firstChild;
                                    foreach( $rootNode2->childNodes as $entry )
                                    {
                                        /** @var DOMElement $entry */
                                        if( $entry->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        #print "check entry: \n";
                                        #DH::DEBUGprintDOMDocument( $entry );

                                        $name = DH::findAttribute("name", $entry);
                                        #print "\n nodename: |".$name."|\n";
                                        $existingNode = DH::findFirstElementByNameAttr("entry", $name, $rootNode1);
                                        if( $existingNode == null || $existingNode == FALSE )
                                        {
                                            PH::print_stdout($profilename . " new Node added - " . $name);


                                            $entrynew = $newdoc1->importNode($entry, TRUE);

                                            $rootNode1->appendChild($entrynew);
                                            #DH::DEBUGprintDOMDocument($entrynew);
                                            $changed = TRUE;
                                        }
                                        else
                                        {
                                            $string1 = $existingNode->textContent;
                                            $string2 = $entry->textContent;
                                            if( $string1 !== $string2 )
                                            {
                                                PH::print_stdout($profilename . " Node changed - " . $name);
                                                #DH::DEBUGprintDOMDocument($existingNode);
                                                #print "\n------------\n";
                                                #DH::DEBUGprintDOMDocument($entry);
                                                #print "\n------------\n";

                                                $entrynew = $newdoc1->importNode($entry, TRUE);
                                                $rootNode1->removeChild($existingNode);
                                                $rootNode1->appendChild($entrynew);
                                                #DH::DEBUGprintDOMDocument($entrynew);
                                                $changed = TRUE;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if( $changed )
                        {
                            file_put_contents($filename, $newdoc1->saveXML($rootNode1));
                        }
                        else
                        {
                            PH::print_stdout("nothing updated for : " . $profilename);
                        }
                    }
                }
            }
            //catch exception
            catch(Error $e)
            {
                PH::disableExceptionSupport();
                PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
                PH::print_stdout();
            }
        }

    }

    function endOfScript()
    {
        PH::$JSON_TMP = array();
        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
            #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
        }
    }

    function createIronSkilletMainFolder()
    {
        if (!is_dir($this->ironskillet_pathString )) {
            // dir doesn't exist, make it
            #print "FOLDER: ".$this->ironskillet_pathString."\n";
            mkdir($this->ironskillet_pathString);
        }
    }

    function createIronSkilletSubFolder( $version)
    {
        $explodeArray = explode( "/", $version );

        $pathString = $this->ironskillet_pathString."/";
        for( $i = 0; $i < count( $explodeArray )-1; $i++ )
        {
            if (!is_dir( $pathString.$explodeArray[$i] )) {
                // dir doesn't exist, make it
                mkdir($pathString.$explodeArray[$i] );
            }

            $pathString = $pathString.$explodeArray[$i]."/";
        }
    }

    function find_ironskillet_entry_basedonname( $snippet, $name )
    {
        $array = array();
        foreach( $snippet as $key => $entry )
        {
            if( strpos( $entry['name'], $name ) !== false )
                $array[] = $entry;
        }
        return $array;
    }
}
