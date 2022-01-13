<?php


class PLAYBOOK__
{

    public $isAPI = false;
    public $debugAPI = false;

    function __construct( $argv, $argc )
    {

###############################################################################
//PLAYBOOK
###############################################################################
//example of an JSON file syntax
        $visibility_pathString = dirname(__FILE__)."/../develop/api/v1/playbook";
        $JSONarray = file_get_contents( $visibility_pathString."/visibility_PS.json");

        $tmp_ph = new PH($argv, $argc);

###############################################################################
//playbook arguments
###############################################################################
        PH::processCliArgs();

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

        //check if $input argument has "api://"
        if( strpos( PH::$args['in'], "api://" ) !== FALSE )
            $this->isAPI = TRUE;

        if( isset(PH::$args['debugapi']) )
            $this->debugAPI = TRUE;

        if( isset(PH::$args['json']) )
        {
            $jsonFile = PH::$args['json'];
            $filedata = file_get_contents($jsonFile);
            $details = json_decode( $filedata, true );

            if( !isset(PH::$args['in']) )
                $input = $details['in'];

            if( !isset(PH::$args['out']) )
                $output = $details['out'];

            if( !isset(PH::$args['stagename']) )
                $stage_name = $details['stagename'];

            $command_array = $details['command'];
        }
        else
        {
            $details = json_decode($JSONarray, true);

            if( !isset(PH::$args['in']) )
                $input = $details['in'];

            if( !isset(PH::$args['out']) )
                $output = $details['out'];
            if( !isset(PH::$args['stagename']) )
                $stage_name = $details['stagename'];

            $command_array = $details['command'];
        }

###############################################################################
//EXECUTION
###############################################################################
        $out = "";
        $in = "";

        $in_exclude = array(
            'ironskillet-update',
            "maxmind-update",
            "util_get-action-filter"
        );

        $out_exclude = array(
            'stats',
            'download-predefined',
            'config-size',
            "xml-op-json",
            "bpa-generator",
            "ironskillet-update",
            "maxmind-update",
            "util_get-action-filter"
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

            foreach( $command as $arg )
                $arguments[] = $arg;

            if( $this->debugAPI )
                $arguments[] = "debugapi";

            ###############################################################################
            //IN / OUT specification
            ###############################################################################
            //what to do with playbook, stats, all script which do not need output

            if( $key == 0 )
            {
                $out_counter = 0;
                $in = $input;
                if( !in_array( $script, $out_exclude ) )
                {
                    $out = $stage_name.$out_counter.".xml";
                    $out_counter = $out_counter+10;
                }
                else
                    $out = $in;
            }
            elseif( $key > 0 )
            {
                if( !in_array( $script, $in_exclude ) && !$this->isAPI )
                    $in = $out;

                if( !in_array( $script, $out_exclude ) )
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
            PH::print_stdout("");
            PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
            PH::print_stdout("");

            $util = PH::callPANOSPHP( $script, PH::$argv, $argc, $PHP_FILE );

            PH::print_stdout("");
            PH::print_stdout( "############################################################################");
            PH::print_stdout("");
        }

        if( isset(PH::$args['out']) )
        {
            //now save the latest out= from the foreach loop "$out" into "$output" file;
            PH::print_stdout("FINAL script task: the processed PAN-OS configuration are copy to file: ".$output);
            PH::print_stdout("please use this file: ".$output." and upload it to your device");
            PH::print_stdout("");
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
        PH::print_stdout("");

        $array = explode( "/n", $string );
        foreach( $array as $line )
            PH::print_stdout($line );

        PH::print_stdout("");
    }
}