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

class RULE_COMPARE extends UTIL
{
    public $ruleTypes = null;

    public function utilStart()
    {
        $this->supportedArguments = array();
        //PREDEFINED arguments:
        #$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=filename.xml | api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        #$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');

        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


        //YOUR OWN arguments if needed
        $this->supportedArguments['file1'] = array('niceName' => 'File1', 'shortHelp' => 'original PAN-OS XML configuration file');
        $this->supportedArguments['file2'] = array('niceName' => 'File2', 'shortHelp' => 'manipulate/optimised former orginal PAN-OS XML configuration file');


        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] argument1 [optional_argument2]";



        $this->main();
    }

    public function main()
    {

        PH::processCliArgs();
        PH::print_stdout();
        PH::print_stdout();


        $ruleDiff = FALSE;


        $type = 'resolved';
        #$type = 'unresolved';

        $file1_name = PH::$args['file1'];
        $file2_name = PH::$args['file2'];

        $path1_parts = pathinfo($file1_name);
        $path2_parts = pathinfo($file2_name);


        $json_file1_name = "/tmp/" . $path1_parts['filename'] . ".json";
        $json_file2_name = "/tmp/" . $path2_parts['filename'] . ".json";

        ############################################################
        //check if file exists
        if( !file_exists($file1_name) )
            derr("cannot read configuration file '{$file1_name}''", null, FALSE);
        if( !file_exists($file2_name) )
            derr("cannot read configuration file '{$file2_name}''", null, FALSE);

        ############################################################
        $shadow_json = "shadow-json";
        $cli1 = "php " . dirname(__FILE__) . "/../../utils/pan-os-php.php type=rule 'actions=display:ResolveAddressSummary|ResolveServiceSummary' location=any in=" . $file1_name . " " . $shadow_json . " shadow-ignoreinvalidaddressobjects | tee " . $json_file1_name;
        PH::print_stdout(" - run command: '" . $cli1 . "'");
        PH::print_stdout();
        PH::print_stdout("     running this command will take some time");
        $retValue = null;
        exec($cli1, $output, $retValue);
        foreach( $output as $line )
        {
            $string = '   ##  ';
            $string .= $line;
            #PH::print_stdout( $string );
        }

        if( $retValue != 0 )
            derr("CLI exit with error code '{$retValue}'");

        PH::print_stdout();

        ############################################################
        $shadow_json = "shadow-json";
        $cli2 = "php " . dirname(__FILE__) . "/../../utils/pan-os-php.php type=rule 'actions=display:ResolveAddressSummary|ResolveServiceSummary' location=any in=" . $file2_name . " " . $shadow_json . " shadow-ignoreinvalidaddressobjects | tee " . $json_file2_name;
        PH::print_stdout(" - run command: '" . $cli2 . "'");
        PH::print_stdout();
        PH::print_stdout("     running this command will take some time");
        $retValue = null;
        exec($cli2, $output, $retValue);
        foreach( $output as $line )
        {
            $string = '   ##  ';
            $string .= $line;

            #PH::print_stdout( $string );
        }

        if( $retValue != 0 )
            derr("CLI exit with error code '{$retValue}'");

        PH::print_stdout();

        ############################################################
        #$file1 = file_get_contents($file1_name);
        #$file2 = file_get_contents($file2_name);

        PH::print_stdout("compare JSON filename1: " . $json_file1_name);
        PH::print_stdout("with    JSON filename2: " . $json_file2_name);


        $file1 = file_get_contents($json_file1_name);
        $file2 = file_get_contents($json_file2_name);

        $array1 = json_decode($file1, TRUE);
        $array2 = json_decode($file2, TRUE);


        if( isset($array1['PANConf']) )
            $confType = 'PANConf';
        elseif( isset($array1['PanoramaConf']) )
            $confType = 'PanoramaConf';

        if( !isset($array1['PANConf']) && !isset($array2['PANConf']) )
        {
            if( !isset($array1['PanoramaConf']) && !isset($array2['PanoramaConf']) )
                derr("problems");
        }

        $finalArray = array();
        foreach( $array1[$confType] as $key1 => $tmpArray )
        {
            if( !isset($tmpArray['sub']) )
                continue;
            if( !isset($tmpArray['sub']['object']) )
                continue;

            $subName = $tmpArray['sub']['name'];

            $tmp1 = $tmpArray['sub']['object'];
            $tmp2 = $array2[$confType][$key1]['sub']['object'];
            foreach( $tmp1 as $key => $rule )
            {
                if( isset($tmp2[$key]) )
                    $rule2 = $tmp2[$key];
                else
                {
                    mwarning("SUB: '" . $subName . "' | RULE in jsonfile2 not found: " . $key, null, false);
                    continue;
                }



                $diff_src = array();
                $field = 'src_resolved_sum';
                if( isset($rule[$field]) && isset($rule2[$field]) )
                {
                    $src1 = $rule[$field][$type];
                    $src2 = $rule2[$field][$type];
                    $diff_src = $this->array_diff_recursive($src1, $src2);
                }


                $diff_dst = array();
                $field = 'dst_resolved_sum';
                if( isset($rule[$field]) && isset($rule2[$field]) )
                {
                    $dst1 = $rule[$field][$type];
                    $dst2 = $rule2[$field][$type];
                    $diff_dst = $this->array_diff_recursive($dst1, $dst2);
                }


                $diff_srv = array();
                $field = 'srv_resolved_sum';
                if( isset($rule[$field]) && isset($rule2[$field]) )
                {
                    $srv1 = $rule[$field];
                    $srv2 = $rule2[$field];
                    $diff_srv = $this->array_diff_recursive($srv1, $srv2);
                }


                if( !empty($diff_src) || !empty($diff_dst) || !empty($diff_srv) )
                {
                    $ruleDiff = TRUE;

                    PH::print_stdout("--------------------------------------------------");
                    PH::print_stdout("SUB: '" . $subName . "' | Rule diff found: '" . PH::boldText($key)."'");
                    $finalArray[$subName][$key] = array();
                    if( !empty($diff_src) )
                    {
                        $keyword = "source";
                        $compareArray = array();
                        PH::print_stdout( PH::boldText("  ".$keyword) );
                        $this->printArray($src1, $src2, $compareArray);
                        $finalArray[$subName][$key][$keyword] = $compareArray;
                    }

                    if( !empty($diff_dst) )
                    {
                        $keyword = "destination";
                        $compareArray = array();
                        PH::print_stdout( PH::boldText("  ".$keyword) );
                        $this->printArray($dst1, $dst2, $compareArray);
                        $finalArray[$subName][$key][$keyword] = $compareArray;
                    }

                    if( !empty($diff_srv) )
                    {
                        $keyword = "service";
                        $compareArray = array();
                        PH::print_stdout( PH::boldText("  ".$keyword) );
                        $this->printArray($srv1, $srv2, $compareArray);
                        $finalArray[$subName][$key][$keyword] = $compareArray;
                    }
                }
            }
        }
        if( !$ruleDiff )
        {
            PH::print_stdout();
            PH::print_stdout();
            $text = "NO Rule diff for SOURCE / DESTINATION / SERVICE";
            PH::print_stdout( PH::boldText($text) );
            $finalArray['info'] = $text;
            PH::print_stdout();
            PH::print_stdout();
        }
        else
        {
            $text = "Rule diff available | check details";
            $finalArray['info'] = $text;
        }



        PH::$JSON_TMP = array();
        if( PH::$shadow_json )
            PH::$JSON_OUT['rule-compare'] = $finalArray;

        //cleanup
        unlink($json_file1_name);
        unlink($json_file2_name);
        unset($file1);
        unset($file2);
        unset($array1);
        unset($array2);
    }

    function array_diff_recursive($arr1, $arr2)
    {
        $outputDiff = [];

        foreach( $arr1 as $key => $value )
        {
            //if the key exists in the second array, recursively call this function
            //if it is an array, otherwise check if the value is in arr2
            if( array_key_exists($key, $arr2) )
            {
                if( is_array($value) )
                {
                    $recursiveDiff = array_diff_recursive($value, $arr2[$key]);

                    if( count($recursiveDiff) )
                    {
                        $outputDiff[$key] = $recursiveDiff;
                    }
                }
                else if( !in_array($value, $arr2) )
                {
                    $outputDiff[$key] = $value;
                }
            }
            //if the key is not in the second array, check if the value is in
            //the second array (this is a quirk of how array_diff works)
            else if( !in_array($value, $arr2) )
            {
                $outputDiff[$key] = $value;
            }
        }

        return $outputDiff;

    }

    function checkArrayClean( $array1, $array2 )
    {
        foreach( $array1 as $key => $entry )
        {
            if( in_array($entry, $array2) )
                unset($array1[$key]);
        }

        return $array1;
    }

    function printArray($array1, $array2, &$compareArray)
    {
        $tmp1 = $this->checkArrayClean($array1, $array2);
        $tmp2 = $this->checkArrayClean($array2, $array1);

        if( !empty($tmp1) || !empty($tmp2))
        {
            PH::print_stdout("  * file1");
            #print_r($tmp1);
            foreach( $tmp1 as $entry )
            {
                PH::print_stdout("    - ".$entry);
                $compareArray['file1'][] = $entry;
            }
            if( empty($tmp1) )
                $compareArray['file1'] = array();
        }

        if( !empty($tmp2) || !empty($tmp1) )
        {
            PH::print_stdout("   * file2");
            #print_r($tmp2);
            foreach( $tmp2 as $entry )
            {
                PH::print_stdout("    - ".$entry);
                $compareArray['file2'][] = $entry;
            }
            if( empty($tmp2) )
                $compareArray['file2'] = array();
        }

        if( empty($tmp1) && empty($tmp2) )
        {
            PH::print_stdout("   only the order of information was different");
            $compareArray['file1'] = array();
            $compareArray['file2'] = array();
        }
    }
}