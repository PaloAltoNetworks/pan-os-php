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

class PLAYBOOK__
{

    public $isAPI = false;
    public $debugAPI = false;
    public $outputformatset = false;

    public $mainLocation = null;

    public $projectFolder = null;

    function __construct( $argv, $argc )
    {

        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => 'sub1[,sub2]');
        $this->supportedArguments['type'] = array('niceName' => 'pan-os-php type=');
        $this->supportedArguments['json'] = array('niceName' => 'json=PLAYBOOK.json');
        $this->supportedArguments['projectfolder'] = array('niceName' => 'projectfolder=PROJECTFOLDER');

###############################################################################
//PLAYBOOK
###############################################################################
//example of an JSON file syntax
        $visibility_pathString = dirname(__FILE__)."/../api/v1/playbook";
        $JSONarray = file_get_contents( $visibility_pathString."/visibility.json");

        $tmp_ph = new PH($argv, $argc);

###############################################################################
//playbook arguments
###############################################################################
        PH::processCliArgs();

        foreach( PH::$args as $index => &$arg )
        {
            if( !isset($this->supportedArguments[$index]) )
            {
                //var_dump($supportedArguments);
                $this->display_error_usage_exit("unsupported argument provided: '$index'");
            }
        }

        $PHP_FILE = __FILE__;

        if( isset(PH::$args['help']) )
        {
            $help_string = PH::boldText("USAGE: ") . "php " . $PHP_FILE . " in=inputfile.xml out=outputfile.xml [json=JSONfile]\n";

            PH::print_stdout( $help_string );

            exit();
        }


        if( isset(PH::$args['in']) )
            $input = PH::$args['in'];

//define out to save the final file into this file
        if( isset(PH::$args['out']) )
            $output = PH::$args['out'];

        if( isset(PH::$args['stagename']) )
            $stage_name = PH::$args['stagename'];
        else
            $stage_name = "";

        //check if $input argument has "api://"
        if( isset(PH::$args['in'] ) && strpos( PH::$args['in'], "api://" ) !== FALSE )
            $this->isAPI = TRUE;

        if( isset(PH::$args['debugapi']) )
            $this->debugAPI = TRUE;

        if( isset(PH::$args['projectfolder']) )
        {
            $this->projectFolder = PH::$args['projectfolder'];
            if (!file_exists($this->projectFolder)) {
                mkdir($this->projectFolder, 0777, true);
            }
        }

        if( isset(PH::$args['outputformatset']) )
        {
            $this->outputformatset = TRUE;
            $this->outputformatsetFile = PH::$args['outputformatset'];

            if( $this->projectFolder !== null )
                $this->outputformatsetFile = $this->projectFolder."/".$this->outputformatsetFile;

            if( $this->outputformatsetFile !== null )
                file_put_contents($this->outputformatsetFile, "" );
        }



        if( isset(PH::$args['json']) )
        {
            $jsonFile = PH::$args['json'];
            $filedata = file_get_contents($jsonFile);
            $details = json_decode( $filedata, true );

            if( $details === null )
                derr( "invalid JSON file provided", null, FALSE );

            if( !isset(PH::$args['in']) )
            {
                if( !isset( $details['in'] ) )
                    derr( "argument 'in=inputconfig.xml' missing", null, false );
                else
                    $input = $details['in'];
            }

            if( !isset(PH::$args['out']) && !$this->isAPI )
            {
                if( isset( $details['out'] ) )
                    $output = $details['out'];
                else
                    $output = "/dev/null";

            }

            if( !isset(PH::$args['stagename']) && !$this->isAPI )
            {
                if( !isset( $details['stagename'] ) )
                    derr( "argument 'stagename' missing ", null, false );
                else
                {
                    if( isset(PH::$args['projectfolder']) )
                        $stage_name = PH::$args['projectfolder']."/".$details['stagename'];
                    elseif( isset( $details['projectfolder'] ) )
                        $stage_name = $details['projectfolder']."/".$details['stagename'];
                    else
                        $stage_name = $details['stagename'];
                }

            }


            $command_array = $details['command'];
        }
        else
        {
            $details = json_decode($JSONarray, true);

            if( $details === null )
                derr( "invalid JSON file provided", null, FALSE );

            if( !isset(PH::$args['in']) )
                $input = $details['in'];

            if( !isset(PH::$args['out']) )
            {
                if( isset($details['out']) )
                    $output = $details['out'];
                else
                    $output= "/dev/null";
            }

            if( !isset(PH::$args['stagename']) )
            {
                if( isset( $details['projectfolder'] ) )
                    $stage_name = $details['projectfolder']."/".$details['stagename'];
                else
                    $stage_name = $details['stagename'];
            }

            $command_array = $details['command'];
        }

        if( isset(PH::$args['location']) )
        {
            $this->mainLocation = PH::$args['location'];
        }

###############################################################################
//EXECUTION
###############################################################################
        $out = "";
        $in = "";

        $in_exclude = array(
            'ironskillet-update',
            "maxmind-update",
            "util_get-action-filter",
            "protocoll-number-download"
        );

        $out_exclude = array(
            'stats',
            'download-predefined',
            'config-size',
            "xml-op-json",
            "bpa-generator",
            "ironskillet-update",
            "maxmind-update",
            "util_get-action-filter",
            "protocoll-number-download"
        );

        if( isset($details['header-comment']) && !empty($details['header-comment']) )
        {
            self::printCOMMENTS( $details['header-comment'] );
        }

        $out_counter = 0;
        foreach( $command_array as $key => $command )
        {
            $arguments = array();
            $arguments[0] = "";


            $script = $command['type'];
            unset( $command['type'] );
            $arg_string = "";

            if( isset( $command['comment'] ) )
            {
                $comment = $command['comment'];
                unset( $command['comment'] );
            }
            else
                $comment = "";

            if( isset( $command['location'] ) )
            {
                #$arguments[] = "location=".$command['location'];
                $arguments[] = $command['location'];
                unset( $command['location'] );
            }
            else
            {
                if( $this->mainLocation !== null )
                    $arguments[] = "location=".$this->mainLocation;
            }

            foreach( $command as $arg )
                $arguments[] = $arg;

            if( $this->debugAPI )
                $arguments[] = "debugapi";

            if( $this->outputformatset )
            {
                $string = "";
                if( $this->outputformatsetFile !== null)
                    $string = "=".$this->outputformatsetFile;

                $arguments[] = "outputformatset".$string;
            }

            if( $this->projectFolder !== null )
            {
                $string = "";
                if( $this->projectFolder !== null)
                    $string = "=".$this->projectFolder;

                $arguments[] = "projectfolder".$string;
            }


            ###############################################################################
            //IN / OUT specification
            ###############################################################################
            //what to do with playbook, stats, all script which do not need output

            if( $key == 0 )
            {
                $out_counter = 0;
                $in = $input;
                if( $output == "/dev/null" )
                {
                    $out = "/dev/null";
                }
                elseif( !in_array( $script, $out_exclude ) )
                {
                    $out = $stage_name.$out_counter.".xml";
                    $out_counter = $out_counter+10;
                }
                else
                    $out = $in;
            }
            elseif( $key > 0 )
            {
                if( $output == "/dev/null" )
                    $in = $input;
                elseif( !in_array( $script, $in_exclude ) && !$this->isAPI )
                    $in = $out;

                if( $output == "/dev/null" )
                    $out = "/dev/null";
                elseif( !in_array( $script, $out_exclude ) )
                {
                    $out = $stage_name.$out_counter.".xml";
                    $out_counter = $out_counter+10;
                }
                else
                    $out = $in;
            }

            if( !in_array( $script, $in_exclude ) )
                $arguments[] = "in=".$in;

            if( !in_array( $script, $out_exclude ) && !$this->isAPI )
                $arguments[] = "out=".$out;


            PH::resetCliArgs( $arguments);

            if( $comment !== null && !empty( $comment ) )
            {
                self::printCOMMENTS( $comment );
            }

            $tool = "pan-os-php type=".$script;
            PH::print_stdout();
            PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
            PH::print_stdout();

            $util = PH::callPANOSPHP( $script, PH::$argv, $argc, $PHP_FILE );

            PH::print_stdout();
            PH::print_stdout( "############################################################################");
            PH::print_stdout();
        }

        if( isset(PH::$args['out']) && PH::$args['out'] !== "/dev/null" )
        {
            //now save the latest out= from the foreach loop "$out" into "$output" file;
            PH::print_stdout("FINAL script task: the processed PAN-OS configuration are copy to file: ".$output);
            PH::print_stdout("please use this file: ".$output." and upload it to your device");
            PH::print_stdout();
            PH::print_stdout( "############################################################################");
            copy( $out, $output );
        }


        if( isset($details['footer-comment']) && !empty($details['footer-comment']) )
        {
            self::printCOMMENTS( $details['footer-comment'] );
        }
    }

    function endOfScript()
    {
    }

    function printCOMMENTS( $string )
    {
        PH::print_stdout();

        $array = explode( "/n", $string );
        foreach( $array as $line )
            PH::print_stdout($line );

        PH::print_stdout();
    }

    public function display_error_usage_exit($msg)
    {
        if( PH::$shadow_json )
            PH::$JSON_OUT['error'] = $msg;
        else
            fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
        #$this->display_usage_and_exit(TRUE);
        exit();
    }
}