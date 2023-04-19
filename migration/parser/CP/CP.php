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


require_once("CPmisc.php");
require_once("CP_objects.php");
require_once("CP_services.php");
require_once("CP_accessrules.php");
require_once("CP_natrules.php");
require_once ("CP_staticroute.php");


class CP extends PARSER
{
    public $folder_path = "";
    public $print = FALSE;

    public $rulebases = null;
    public $policyName = null;
    public $objectName = null;

    use CPmisc;
    use CP_objects;
    use CP_services;
    use CP_accessrules;
    use CP_natrules;

    use CP_staticroute;


    use SHAREDNEW;

    function vendor_main()
    {
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done
        $this->print = TRUE;
        $this->print = FALSE;


        $this->clean_config();




        $this->import_config(); //This should update the $source
        //------------------------------------------------------------------------

        echo PH::boldText("\nload custom application:\n");
        $this->load_custom_application();

        echo PH::boldText("Zone Calculation for Security and NAT policy");
        Converter::calculate_zones($this->template, $this->sub, "append");

        //missing steps:
        //add network part: interfaces, routing, IPsec
        echo PH::boldText("\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n");
        CONVERTER::validate_interface_names($this->template);
        #

        echo PH::boldText("\nVALIDATION - Region name must not be used as a address / addressgroup object name\n");
        CONVERTER::validation_region_object( $this->sub);
        #

        //if security rule count is very high => memory leak problem
        //Todo: where to place custom table for app-migration if needed
        echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
        print "todo\n";
        CONVERTER::AppMigration($this->sub, $this->configType);
        #

        //todo delete all created files and folders

        CONVERTER::deleteDirectory( );
    }

    function clean_config()
    {

        $configFolder = $this->configFile;



        $files1 = scandir($configFolder);
        #print_r( $files1 );


        $this->rulebases = null;
        $this->policyName = null;
        $this->objectName = null;

        //Todo: 20200604 other possible way: argument "file=[objects]/[policy]/[rulebase]"
        //what about advanced options??? add more arguments ????

        foreach( $files1 as $item )
        {
            if( strpos($item, "rulebases") !== FALSE )
            {
                $tmp_check = explode(".", $item);
                if( $tmp_check[1] == "fws" )
                    $this->rulebases = $configFolder . "/" . $item;
            }
            elseif( strpos($item, "PolicyName") !== FALSE )
            {
                $tmp_check = explode(".", $item);
                if( $tmp_check[1] == "W" )
                    $this->policyName = $configFolder . "/" . $item;
            }
            elseif( strpos($item, "objects") !== FALSE )
            {
                #$tmp_check = explode(".", $item);
                #if( $tmp_check[0] == "objects_5_0" && $tmp_check[1] == "C" )
                #    $this->objectName = $configFolder . "/" . $item;
                #elseif( $tmp_check[0] == "objects" && $tmp_check[1] == "C" )

                if( $this->objectName == null || strpos($item, "objects_5_0") !== FALSE )
                {
                    $tmp_check = explode(".", $item);
                    if( $tmp_check[1] == "C" )
                        $this->objectName = $configFolder . "/" . $item;
                }

            }
            elseif( strpos($item, ".W") !== FALSE )
            {
                $tmp_check = explode(".", $item);
                if( $tmp_check[1] == "W" )
                    $this->policyName = $configFolder . "/" . $item;
            }
            elseif( strpos($item, "Object.C") !== FALSE )
            {
                $tmp_check = explode(".", $item);
                if( $tmp_check[1] == "C" )
                    $this->objectName = $configFolder . "/" . $item;
            }
            elseif( strpos($item, "Rules.C") !== FALSE )
            {
                $tmp_check = explode(".", $item);
                if( $tmp_check[1] == "C" )
                {
                    $this->policyName = $configFolder . "/" . $item;


                    $rules = file($this->policyName);

                    $my_file = $this->policyName."new";
                    $handle = fopen($my_file, 'a') or die('Cannot open file:  ' . $my_file);

                    $entering_rules = FALSE;
                    $entering_natrules = FALSE;

                    foreach ($rules as $num => $rule)
                    {
                        #print "LINE:|".$rule."|";
                        if (preg_match("/^\t:rules \(/i", $rule))
                        {
                            $entering_rules = TRUE;
                            #print "RULES found\n";
                            continue;
                        }
                        elseif( preg_match("/^\t\)/i", $rule) AND ($entering_rules==TRUE) )
                        {
                            $entering_rules = FALSE;
                            #print "RULES END found\n";
                            continue;
                        }

                        if ($entering_rules == TRUE)
                        {
                            if (preg_match("/\t\t\: \(rule/i", $rule))
                            {
                                $string = "\t:rule (\n";
                            }
                            else
                            {
                                $string = preg_replace("/^\t\t/", "\t", $rule);
                            }
                            #print "write1:|".$string."|\n";
                            fwrite($handle, $string);

                        }

                        ########################

                        if (preg_match("/^\t:rules-adtr \(/i", $rule))
                        {
                            $entering_natrules = TRUE;
                            #print "NAT found\n";
                            continue;
                        }

                        elseif ( preg_match("/^\t\)/i", $rule) AND ($entering_natrules==TRUE) )
                        #elseif ((preg_match("/^\t\)/i", $rule)) )
                        {
                            $entering_natrules = FALSE;
                            #print "NAT END found\n";
                            continue;
                        }

                        if ($entering_natrules == TRUE)
                        {
                            if( preg_match("/\t\t\: \(rule/i", $rule))
                            {
                                #$string = "\t:rule_adtr (\n";
                                $string = "\t:rule_adtr (\n";
                            }
                            else
                            {
                                $string = preg_replace("/^\t\t/", "\t", $rule);
                            }
                            #print "write2:|".$string."|\n";
                            fwrite($handle, $string);
                        }

                        if( $entering_rules == FALSE && $entering_natrules == FALSE )
                        {
                            $string = $rule;
                            #print "write3:|".$string."|\n";
                            fwrite($handle, $string);
                        }

                    }

                    unlink( $this->policyName );
                    copy( $my_file, $this->policyName );
                    unlink( $my_file );
                }

            }
            else
                continue;

        }


        if( $this->policyName == null )
            $this->policyName = $this->rulebases;


        print "POLICY: " . $this->policyName . "\n";
#$policyName = $configFolder."/PolicyName.W";
#print "POLICY2: ".$policyName."\n";


        print "RULEBASE: " . $this->rulebases . "\n";
#$rulebases = $configFolder."/rulebases_5_0.fws";
#print "RULEBASE2: ".$rulebases."\n";


        print "OBJECT: " . $this->objectName . "\n";
#$objectName = $configFolder."/objects_5_0.C";
#print "OBJECT2: ".$objectName."\n";

        print "-------------------------------------------\n";

        if( file_exists($this->rulebases) )
            $migratecomments = "--merge_AI=" . $this->rulebases;
        else
            $migratecomments = "";

        $this->policyName = str_replace(' ', '_', $this->policyName);


        $script_folder = dirname(__FILE__);
        $ParserPath = $script_folder . "/checkpoint-parser.pl";


        $fwdoc = $this->newfolder . "/conf.fwdoc";

        $Parse = "/usr/bin/perl $ParserPath --rules=$this->policyName --objects=$this->objectName $migratecomments > $fwdoc";

        print "PARSE: |".$Parse."|\n";

        if( file_exists($configFolder) )
            shell_exec($Parse);
        else
        {
            derr("Folder: '" . $configFolder . "' not available\n");
        }



        $someArray = array();
        if( (file_exists($fwdoc)) and (filesize($fwdoc) != 0) )
        {
            print "\n#####################################################\n\n";
            print "FILE: '" . $fwdoc . "' successfully created\n";
            print "\n#####################################################\n\n";


            //load file
            $someJSON = file_get_contents($fwdoc);
            //replace all hidden characters  // especially if they are available in comments
            $someJSON = $this->strip_hidden_chars($someJSON);


            // Convert JSON string to Array
            $someArray = json_decode($someJSON, TRUE);

            #$someArray = $this->safe_json_decode( $someJSON );

            //JSON validation
            #$this->jsonERROR();
            if( !is_array($someArray) )
                derr("json_decode not working");


            #print_r($someArray);        // Dump all data of the Array
            #print "||".count( $someArray )."\n";

        }

        $this->data = $someArray;
    }


    function safe_json_decode($value, $options = 0, $depth = 512, $utfErrorFlag = false) {
        $encoded = json_decode($value, $options, $depth);
        switch (json_last_error()) {
            case JSON_ERROR_NONE:
                echo 'no error';
                return $encoded;
            case JSON_ERROR_DEPTH:
                echo 'Maximum stack depth exceeded'; // or trigger_error() or throw new Exception()
                break;
            case JSON_ERROR_STATE_MISMATCH:
                echo 'Underflow or the modes mismatch'; // or trigger_error() or throw new Exception()
                break;
            case JSON_ERROR_CTRL_CHAR:
                echo 'Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                echo 'Syntax error, malformed JSON'; // or trigger_error() or throw new Exception()
                break;
            case JSON_ERROR_UTF8:
                $clean = $this->utf8ize($value);
                if ($utfErrorFlag) {
                    echo 'UTF8 encoding error'; // or trigger_error() or throw new Exception()
                    break;
                }
                return $this->safe_json_decode($clean, $options, $depth, true);
            default:
                echo 'Unknown error'; // or trigger_error() or throw new Exception()
                break;

        }
    }

    function utf8ize($mixed) {
        if (is_array($mixed)) {
            foreach ($mixed as $key => $value) {
                $mixed[$key] = $this->utf8ize($value);
            }
        } else if (is_string ($mixed)) {
            return utf8_encode($mixed);
        }
        return $mixed;
    }

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


    function import_config()
    {
        global $projectdb;
        global $source;

        global $debug;


        if( $this->routetable != "" )
        {
            echo PH::boldText("\nimport dynamic Routing\n");
            $cisco = file_get_contents($this->routetable);
            $this->importRoutes( $cisco);
        }

        //Todo: temp exit, because of wrong static route import
        #exit;

        $padding = "";
        $data = $this->data;

        foreach( array_keys($data) as $KEYS )
        {
            #print "|" . $KEYS . "|" . count($data[$KEYS]) . "\n";

            #print_r(array_keys($data[$KEYS]));
            #print_r( $data[$KEYS] );

            //print out all keys, first normal then recursive:
            if( $KEYS == "firewall" )
            {
                /*
                [brand] => CheckPoint
                [type] => FireWall-1 / VPN-1
                [version] => 3.0 - 4.1 - NG R65
                [date] => 2020-5-4
                [identifier] => PolicyName.W_FWS
                [filter] => Array
                    (
                    )

                [comment] => Generated: by
                 */
            }
            elseif( $KEYS == "objects" )
            {
                print "\n\n ADD ADDRESS OBJECTS:\n";
                $this->add_host_objects($KEYS, $data[$KEYS]);
            }
            elseif( $KEYS == "services" )
            {
                print "\n\n ADD SERVICES:\n";
                $this->add_services($KEYS, $data[$KEYS]);


            }
            elseif( $KEYS == "layer7filter" )
            {
                #print_r(array_keys($data[$KEYS]));
                #print_r( $data[$KEYS] );
                /*
                 *
                 *   [SunRPC_yppasswd] => Array
                    (
                        [name] => SunRPC_yppasswd
                        [protocol] => SunRPC
                        [comment] => Sun Yellow Pages protocol (NIS), password server
                    )

                [SunRPC_ypserv] => Array
                    (
                        [name] => SunRPC_ypserv
                        [protocol] => SunRPC
                        [comment] => Sun Yellow Pages directory service (YP) protocol, now known as NIS
                    )

                [SunRPC_ypupdated] => Array
                    (
                        [name] => SunRPC_ypupdated
                        [protocol] => SunRPC
                        [comment] => Sun Yellow Pages protocol (NIS), update service
                    )

                [SunRPC_ypxfrd] => Array
                    (
                        [name] => SunRPC_ypxfrd
                        [protocol] => SunRPC
                        [comment] => Sun Yellow Pages protocol (NIS), transfers NIS maps
                    )

                 */
            }
            elseif( $KEYS == "accessrules" )
            {
                //do nothing, check later
            }
            elseif( $KEYS == "natrules" )
            {
                //do nothing, check later
            }
            elseif( $KEYS == "users" )
            {
                //do nothing, check later
            }
            else
            {
                derr("NOT supported: " . $KEYS);
            }
        }


        foreach( array_keys($data) as $KEYS )
        {
            #print "|" . $KEYS . "|" . count($data[$KEYS]) . "\n";

            #print_r(array_keys($data[$KEYS]));
            #print_r( $data[$KEYS] );

            //print out all keys, first normal then recursive:
            if( $KEYS == "accessrules" )
            {
                print "\n\n ADD Security Rules:\n";
                $this->add_access_rules($KEYS, $data[$KEYS]);


            }
            elseif( $KEYS == "natrules" )
            {
                #print_r(array_keys($data[$KEYS]));
                #print_r( $data[$KEYS] );

                print "\n\n ADD NAT Rules:\n";
                $this->add_nat_rules($KEYS, $data[$KEYS]);

            }


        }

    }





}


