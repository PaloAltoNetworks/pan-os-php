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


#require_once("CPmisc.php");
require_once("CPnew_object.php");
require_once("CPnew_service.php");
require_once("CPnew_ipsec.php");
#require_once ("CP_accessrules.php");
#require_once ("CP_natrules.php");


class CPnew extends PARSER
{
    public $folder_path = "";
    public $print = FALSE;

    #use CPmisc;
    use CPnew_object;
    use CPnew_service;
    use CPnew_ipsec;

    #use CP_accessrules;
    #use CP_natrules;


    public $checkArray = false;

    //this array is for OBJECTS FILE
    public $objects_key = array(

        #'anyobj',
        #'superanyobj',
        'serverobj',
        #'translations',
        #'servgen',
        #'log-props',
        #'state-act',
        #'SPIobj',
        #'version',
        #'globals',
        #'setup',
        'network_objects',
        'netobj',
        #'vs_slot_objects',
        'services',
        'servobj',
        'servers',
        #'times',
        #'ldap',
        #'opsec',
        #'graph_objects',
        #'resources',
        #'keys',
        #'encryption',
        #'svn',
        #'qos',
        'properties',
        'props',
        #'ce_properties',
        #'customers',
        #'accounting_schemes',
        'resources_types',
        'resourcesobj',
        #'protocols',
        #'tracks',
        #'HitCountSeverity',
        #'statuses',
        #'securemote',
        #'products',
        #'credentials_manager',
        'communities',
        'communitie',
        #'desktop_profiles',
        #'cp_administrators',
        #'policies_collections',
        #'methods',
        #'trusts',
        #'web_authority_must_rules',
        #'web_authority_allow_rules',
        #'web_authority_effect_rules',
        #'web_authority_URLs',
        #'web_sites',
        #'sofaware_gw_types',
        #'external_exported_domains',
        #'0',
        #'SmartCenterDBFiles',
        'netobjadtr'


    );

    public $policy_key = array(
        '0',
        'AdminInfo',
        'default',
        'globally_enforced',
        'queries',
        'queries_adtr',
        'collection',
        'use_VPN_communities',
        'rule'
    );

    use SHAREDNEW;

    function vendor_main()
    {

        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################

        //swaschkut - tmp, until class migration is done
        $this->print = TRUE;
        $this->print = FALSE;


        //CP specific
        //------------------------------------------------------------------------
        $path = "";
        $project = "";

        $config_path = $path . $config_filename;
        $filename = $config_filename;
        $filenameParts = pathinfo($config_filename);
        $verificationName = $filenameParts['filename'];



        $data = $this->clean_config($config_path, $project, $config_filename);





        $this->import_config($data, $routetable); //This should update the $source
        //------------------------------------------------------------------------


        //todo delete all created files and folders

        CONVERTER::deleteDirectory( );
    }

    function clean_config($config_path, $project, $config_filename)
    {

        $configFolder = $config_filename;


        $files1 = scandir($configFolder);
        #print_r( $files1 );


        //Todo: 20200604 other possible way: argument "file=[objects]/[policy]/[rulebase]"
        //what about advanced options??? add more arguments ????

        $this->rulebases = null;
        $this->policyName = null;
        $this->objectName = null;

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


        /////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////

        #$this->print = true;

        if( !empty( $this->policyName ) )
        {
            $end_array['policy'] = $this->readFiles( $this->policyName );

            print_r(array_keys( $end_array['policy'][0] ));
            #print_r( $end_array['policy'][0] );
        }



        if( !empty( $this->rulebases ) )
        {
            $end_array['rulebase'] = $this->readFiles( $this->rulebases );

            print_r(array_keys( $end_array['rulebase'][0] ));
            #print_r( $end_array['rulebase'][0] );
        }


        if( !empty( $this->objectName ) )
        {
            $end_array['objects'] = $this->readFiles( $this->objectName );

            print_r(array_keys( $end_array['objects'][0] ));
            #print_r( $end_array['objects'][0] );
        }
        #derr( "STOP" );

        /////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////


        //Todo: contains only one file // e.g. only OBJECTS find general solution
        return $end_array;
    }

    function readFiles( $fileName )
    {
        print "\nread FILE: " . $fileName . "\n\n";
        $string = file_get_contents($fileName);
        $filesize = filesize($fileName);

        $count_byte = 1;
        while( $filesize > 1024 )
        {
            $filesize = $filesize / 1024;
            $count_byte++;
        }

        print "FILESIZE: " . number_format(($filesize), 2, '.', '') . " ";


        switch ($count_byte)
        {
            case 0:
                echo "i is eq 0";
                break;
            case 1:
                echo "";
                break;
            case 2:
                echo "K";
                break;
            case 3:
                echo "M";
                break;
            case 4:
                echo "G";
                break;
            case 5:
                echo "T";
                break;
        }
        print "Byte\n";


        if( $this->checkArray )
        {
            #print "use only the following information:\n";
            #print_r($this->objects_key);
        }


        print "\noptimize content\n";

        $array = $this->delimeterSplit($string, "start");

        print "----------------------------------------------------------------\n";
        print "#################################################################\n";

        return $this->callRecursive($array);
    }


//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


    function import_config($data, $routetable)
    {
        global $projectdb;
        global $source;

        global $debug;


        if( $routetable != "" )
        {
            echo PH::boldText("\nimport dynamic Routing\n");

            $cisco = file_get_contents($routetable);
            #$this->importRoutes( $cisco, $pan, $this->v);
        }

        if( isset($data['objects'][0]['network_objects']) )
        {
            print "using network_objects\n";
            $tmp_array = $data['objects'][0]['network_objects'];
            echo PH::boldText("\nimport address objects\n");
            $this->addHost($tmp_array);
        }
        elseif( isset($data['objects'][0]['netobj']) )
        {
            print "using netobj\n";
            $tmp_array = $data['objects'][0]['netobj'];
            echo PH::boldText("\nimport address objects\n");
            $this->addHost($tmp_array);
        }



        if( isset($data['objects'][0]['services']) )
        {
            $tmp_array = $data['objects'][0]['services'];
            echo PH::boldText("\nimport service objects\n");
            $this->addService($tmp_array);
        }


        echo PH::boldText("\nimport IPsec VPN\n");
        $this->addIPsec($data['objects']);


        foreach( $data['objects'][0] as $key => $value )
        {
            #print "|".$key."|\n";
        }

        print_r( $data['objects'][0] );

    }





    function delimeterSplit($input, $previous_key = null )
    {
        $str = '';
        $key = '';
        $output = array();
        $counter = array();

        $op = 0;
        $cp = 0;

        $found = FALSE;

        foreach( str_split($input) as $k => $v )
        {
            #print "KEY:".$k."|V:|".$v."|\n";

            if( $k === 0 && $v == '"' )
                $found = TRUE;

            if( $v === '(' && !$found )
            {
                ++$op;
            }
            if( isset($input[$k]) && $input[$k] === ')' && !$found )
            {
                ++$cp;
            }


            if( ($op === 0 && $v !== '(') )
            {
                if( $v == ':' && trim($key) != "" && !$found )
                {
                    $output[] = trim($key);
                    $key = '';
                }
                else
                    $key .= $v;

            }
            if(     (  ($op === 1 && $v !== '(')     ||       ($op === 1 && $found)    ||  $op > 1 )       && $op !== $cp )
            {
                $str .= $v;
                if( $v == '"' && !$found )
                    $found = TRUE;
                elseif( $v == '"' && $found )
                {
                    $found = FALSE;
                    #print "STR: ".$str."\n";
                    #print "OP: ".$op."\n";
                    #print "CP: ".$cp."\n";
                    if( $op == 1 && $cp == 0 )
                    {
                        #print "KEY VALUE: ".$previous_key."\n";
                        if( $previous_key === 0 )
                        {
                            $output[] = $str;
                            $str = "";
                        }

                    }
                }

            }

            if( $op > 0 && $op === $cp )
            {
                $op = 0;
                $cp = 0;

                $key = trim($key);
                $key = str_replace(":", "", $key);
                if( $key == "" )
                    $output[] = $str;
                else
                {
                    if( isset($output[$key]) )
                    {
                        if( isset($counter[$key]) )
                        {
                            $tmp_key = $counter[$key];
                            $counter[$key]++;
                        }
                        else
                        {
                            $tmp_key = 0;
                            $counter[$key] = $tmp_key;

                            $tmp_array = $output[$key];
                            $output[$key] = "fixit";
                            #unset( $output[ $key] );
                            $output[$key . $tmp_key] = $tmp_array;
                            $counter[$key]++;
                            $tmp_key = $counter[$key];

                        }

                        $output[$key . $tmp_key] = $str;
                    }
                    else
                        $output[$key] = $str;
                }

                $str = '';
                $key = '';
            }


        }

        return $output;
    }


    function callRecursive($array, $depth = -1, $padding = "")
    {
        #global $print;
        #global $objects_key;
        #global $checkArray;

        $depth++;
        $final = array();

        $fixit = FALSE;
        $fixit_value = "";

        #print "DEPTH1: ".$depth. " -- \n";


        foreach( $array as $item => $entry )
        {
            if( $entry == "fixit" )
            {
                $fixit = TRUE;
                $fixit_value = $item;
                #mwarning( $item." - is also available with counter" );
            }

            $array1 = $this->delimeterSplit($entry, $item);

            if( !is_numeric($item) )
            {
                $key_finalPrint = "|" . $depth . "|" . $item;
                $key_final = $item;
                if( $this->print )
                    print $padding . PH::boldText($key_finalPrint) . "\n";

                if( $key_finalPrint == "|1|rule-base" )
                {
                    #print "COUNT: ".count($array1)."\n";
                    #print_r( $array1 );
                }
            }

            else
            {
                $key_finalPrint = "|" . $depth . "|";
                $key_final = $item;
                if( $this->print )
                    print $padding . PH::boldText($key_finalPrint) . "\n";
            }



            if( count($array1) > 0 )
            {
                if( $depth == 1 && $this->checkArray )
                {
                    if( in_array($key_final, $this->objects_key) )
                    {
                        if( $fixit )
                        {
                            $tmp_fixit = explode($fixit_value, $key_final);
                            if( $key_final == $fixit_value )
                            {

                            }
                            elseif( $tmp_fixit[0] == "" && is_numeric($tmp_fixit[1]) )
                            {
                                $final[$fixit_value][$tmp_fixit[1]] = $this->callRecursive($array1, $depth++, str_pad($padding, strlen($padding) + 5));
                            }
                        }
                        else
                            $final[$key_final] = $this->callRecursive($array1, $depth++, str_pad($padding, strlen($padding) + 5));
                        $depth--;
                    }
                }
                else
                {
                    if( $fixit )
                    {
                        $tmp_fixit = explode($fixit_value, $key_final);
                        if( $key_final == $fixit_value )
                        {

                        }
                        elseif( $tmp_fixit[0] == "" && is_numeric($tmp_fixit[1]) )
                        {
                            $final[$fixit_value][$tmp_fixit[1]] = $this->callRecursive($array1, $depth++, str_pad($padding, strlen($padding) + 5));
                        }
                    }
                    else
                        $final[$key_final] = $this->callRecursive($array1, $depth++, str_pad($padding, strlen($padding) + 5));
                    $depth--;
                }

                $padding = str_pad($padding, strlen($padding) - 5);
            }
            elseif( trim($entry) != "" )
            {
                #print "ITEM: ".$item."\n";
                if( $key_finalPrint == "|1|rule-base" )
                {
                    #$array1 = $this->delimeterSplit($entry);

                    #print "ENTRY: ".$entry."\n";

                    #print_r( $array1 );

                    #derr( "STOP5" );
                }




                if( $this->print )
                    print $padding . $entry . "\n";

                if( $depth == 1 && $this->checkArray )
                {
                    if( in_array($key_final, $this->objects_key) )
                    {
                        if( $this->print )
                            print $key_final . "\n";
                        if( $key_final == $fixit_value )
                            $final[$key_final] = array($entry);
                        else

                            $final[$key_final] = $entry;
                    }
                }
                else
                {
                    if( $key_final == $fixit_value )
                        $final[$key_final] = array($entry);
                    else

                        $final[$key_final] = $entry;
                }
            }
            else
            {
                if( $depth == 1 && $this->checkArray )
                {
                    if( in_array($key_final, $this->objects_key) )
                    {
                        if( $this->print )
                            print $key_final . "\n";
                        if( $key_final == $fixit_value )
                            $final[$key_final] = array($entry);
                        else
                            $final[$key_final] = "";
                    }
                }
                else
                {
                    if( $key_final == $fixit_value )
                        $final[$key_final] = array($entry);
                    else
                        $final[$key_final] = "";
                }
            }
        }

        return $final;
    }

}


