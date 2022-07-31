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

class STATSUTIL extends RULEUTIL
{
    function __construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "")
    {
        $_usageMsg =  PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] [location=vsys2]";;
        parent::__construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments, $_usageMsg);
    }

    public function utilStart()
    {

        $this->utilInit();
        //unique for RULEUTIL
        $this->ruleTypes();

        //no need to do actions on every single rule
        $this->doActions = array();

        $this->createRQuery();
        $this->load_config();
        $this->location_filter();


        $this->location_filter_object();
        $this->time_to_process_objects();




        PH::$args['stats'] = "stats";
        PH::$JSON_TMP = array();
        $this->stats();
        PH::print_stdout(PH::$JSON_TMP, false, "statistic");

        if( isset(PH::$args['exportcsv'])  )
        {
            if( !isset(PH::$args['location']) )
            {
                $this->exportcsvFile = PH::$args['exportcsv'];

                if( $this->projectFolder !== null )
                    $this->exportcsvFile = $this->projectFolder."/".$this->exportcsvFile;


                $string = json_encode( PH::$JSON_TMP, JSON_PRETTY_PRINT );


                $jqFile = dirname(__FILE__)."/json2csv.jq";

                //store string into tmp file:
                $tmpJsonFile = $this->exportcsvFile."tmp_jq_string.json";
                file_put_contents($tmpJsonFile, $string);

                #$cli = "jq -rf $jqFile <<< $string >> ".$this->exportcsvFile;
                #$cli = "jq -rf $jqFile <<< \"$string\" >> ".$this->exportcsvFile;
                #$cli = "jq -rf $jqFile <echo \"$string\") >> ".$this->exportcsvFile;
                //jq '.key' <(echo \"$json_data\")

                ##working
                $cli = "jq -rf $jqFile $tmpJsonFile >> ".$this->exportcsvFile;

                #$cli = "echo \"$string\" | jq -rf $jqFile >> ".$this->exportcsvFile;

                exec($cli, $output, $retValue);

                unlink($tmpJsonFile);
            }
            else
                mwarning( "exportcsv is right now only supported without argument location=... ", null, false );
        }


        PH::$JSON_TMP = array();

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            //print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }

    public function supportedArguments()
    {
        parent::supportedArguments();
        $this->supportedArguments['exportcsv'] = array('niceName' => 'deviceType', 'shortHelp' => 'specify which type(s) of your device want to edit, (default is "dg". ie: devicetype=any  devicetype=vsys,devicegroup,templatestack,template,container,devicecloud,manageddevice,deviceonprem', 'argDesc' => 'all|any|vsys|devicegroup|templatestack|template|container|devicecloud|manageddevice|deviceonprem');
    }

}