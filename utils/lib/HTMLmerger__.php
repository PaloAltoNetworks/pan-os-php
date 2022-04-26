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

class HTMLmerger__
{
    private $projectfolder = null;

    function __construct( $argv, $argc )
    {
        $tmp_ph = new PH($argv, $argc);

        PH::processCliArgs();

        $PHP_FILE = __FILE__;

        if( isset(PH::$args['help']) )
        {
            $help_string = PH::boldText('USAGE: ')."php ".basename(__FILE__)." projectfolder=[DIRECTORY]";

            PH::print_stdout( $help_string );

            exit();
        }


        if( isset(PH::$args['projectfolder']) )
            $this->projectfolder = PH::$args['projectfolder'];

        $this->supportedArguments = Array();
        $this->supportedArguments['projectfolder'] = Array('niceName' => 'projectFolder', 'shortHelp' => 'define the projectfolder', 'argDesc' => 'projectfolder=[DIRECTORY]');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');


        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." projectfolder=[DIRECTORY]";

        $this->main( $argv, $argc );
    }


    public function main( $argv, $argc )
    {
        $excelfilename = "excel.xlsx";
        $output = array();
        $retValue = 0;

        $filename = dirname(__FILE__) . '/../common/html/HTMLExcelMerge.py';

        PH::print_stdout( );
        PH::print_stdout( "check projectfolder: ".$this->projectfolder." for files with ending '.html'" );
        PH::print_stdout( );

        $cli = "python3 ".$filename." ".$this->projectfolder." ".$excelfilename;

        exec($cli, $output, $retValue);

        foreach( $output as $line )
        {
            $string = '   ##  ';
            $string .= $line;
            print $string."\n" ;
        }

        PH::print_stdout( );
        PH::print_stdout( "Excel file created: ".$this->projectfolder."/".$excelfilename );
        PH::print_stdout( );
    }

    function endOfScript()
    {
    }
}