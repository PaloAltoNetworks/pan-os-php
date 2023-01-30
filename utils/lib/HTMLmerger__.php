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
            $help_string = PH::boldText('USAGE: ')."php ".basename(__FILE__)." exportCSV=[spreadsheet.xlsx] projectfolder=[DIRECTORY]";

            PH::print_stdout( $help_string );

            exit();
        }


        if( isset(PH::$args['projectfolder']) )
        {
            $this->projectfolder = PH::$args['projectfolder'];
            if( substr("$this->projectfolder", -1) !== "/" )
                $this->projectfolder .= "/";
        }
        else
            $this->projectfolder = "./";


        $this->supportedArguments = Array();
        $this->supportedArguments['projectfolder'] = Array('niceName' => 'projectFolder', 'shortHelp' => 'define the projectfolder', 'argDesc' => 'projectfolder=[DIRECTORY]');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['exportcsv'] = array('niceName' => 'exportCSV', 'shortHelp' => 'when this argument is specified, it instructs the script to display the kept and removed objects per value');
        $this->supportedArguments['adddefaulthtml'] = array('niceName' => 'addDefaultHTML', 'shortHelp' => 'adding default HTML as an explanation for the EXCEL file');

        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." projectfolder=[DIRECTORY]";

        $this->main( $argv, $argc );
    }


    public function main( $argv, $argc )
    {
        if( isset(PH::$args['exportcsv'])  )
            $excelfilename = PH::$args['exportcsv'];
        else
            $excelfilename = "excel.xlsx";

        $output = array();
        $retValue = 0;

        $filename = dirname(__FILE__) . '/../common/html/HTMLExcelMerge.py';

        PH::print_stdout( );
        PH::print_stdout( "check projectfolder: ".$this->projectfolder." for files with ending '.html'" );
        PH::print_stdout( );

        if( isset(PH::$args['adddefaulthtml']) )
        {
            if( empty(PH::$args['adddefaulthtml']) || PH::$args['adddefaulthtml'] == "adddefaulthtml" )
            {
                $defaultfile = dirname(__FILE__) . '/../common/html/Introduction.html';
                $defaultfilenname = "0_Introduction.html";
            }
            else
            {
                //get own defaultfile from anywhere outside container/panosphp environment
                $defaultfile = PH::$args['adddefaulthtml'];
                $pathArray = explode("/", $defaultfile);
                $tmpname = end( $pathArray );
                $defaultfilenname = "0_".$tmpname;
            }

            //copy default html file into projectfolder;
            $projectdefaultfile = file_get_contents( $defaultfile );
            #bug how to get only file name if $defaultfilename is specified
            file_put_contents($this->projectfolder . "/".$defaultfilenname, $projectdefaultfile);
        }

        /*
        if( empty($excelfilename ) )
        {
            $help_string = PH::boldText('USAGE: ')."php ".basename(__FILE__)." exportCSV=[spreadsheet.xls] projectfolder=[DIRECTORY]";

            PH::print_stdout( $help_string );

            exit();
        }
        */

        if( file_exists($this->projectfolder . "" . $excelfilename) )
            $excelFileWasThere = true;
        else
            $excelFileWasThere = false;

        PH::enableExceptionSupport();
        try
        {
            $cli = "python3 " . $filename . " " . $this->projectfolder . " " . $excelfilename;

            exec($cli, $output, $retValue);

            foreach( $output as $line )
            {
                $string = '   ##  ';
                $string .= $line;
                print $string . "\n";
            }

            if( file_exists($this->projectfolder . "" . $excelfilename) && !$excelFileWasThere )
            {
                PH::print_stdout();
                PH::print_stdout("Excel file created: " . $this->projectfolder . "" . $excelfilename);
                PH::print_stdout();
            }
            elseif( file_exists($this->projectfolder . "" . $excelfilename) && $excelFileWasThere )
            {
                PH::print_stdout();
                PH::print_stdout("Excel file updated: " . $this->projectfolder . "" . $excelfilename);
                PH::print_stdout();
            }

        }
        //catch exception
        catch(Exception $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
            PH::print_stdout();
        }
        catch(Error $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
            PH::print_stdout();
        }
    }

    function endOfScript()
    {
    }
}