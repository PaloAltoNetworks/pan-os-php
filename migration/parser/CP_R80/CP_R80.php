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


require_once("CPtest.php");
require_once("CP_R80_objects.php");
require_once("CP_R80_accesslayer.php");
require_once("CP_R80_natlayer.php");
require_once("CP_R80_staticroute.php");


class CP_R80 extends PARSER
{


    public $v = null;

    use CPtest;
    use CP_R80_objects;
    use CP_R80_accesslayer;
    use CP_R80_staticroute;
    use CP_R80_natlayer;


    use SHAREDNEW;

    function vendor_main()
    {




        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done
        global $print;
        $print = TRUE;


        //Fortinet specific
        //------------------------------------------------------------------------
        $path = "";
        $project = "";

        $config_path = $path . $this->configFile;
        $filename = $this->configFile;
        $filenameParts = pathinfo($this->configFile);
        $verificationName = $filenameParts['filename'];



        $this->clean_config();




        $this->import_config(); //This should update the $source
        //------------------------------------------------------------------------

        echo PH::boldText("\nload custom application:\n");
        $this->load_custom_application();

        //Todo: validation if GLOBAL rule
        echo PH::boldText( "Zone Calculation for Security and NAT policy" );
        Converter::calculate_zones( $this->template, $this->sub, "append" );


        echo PH::boldText( "\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n" );
        CONVERTER::validate_interface_names($this->template);

        //Todo: where to place custom table for app-migration if needed
        echo PH::boldText( "\nVALIDATION - replace tmp services with APP-id if possible\n" );
        CONVERTER::AppMigration( $this->sub, $this->configType );



        //todo delete all created files and folders

        CONVERTER::deleteDirectory( );
    }

    function clean_config()
    {
        $config_filename = $this->configFile;
        //validation if file has .tar.gz
        if( strpos($config_filename, ".tar.gz") === FALSE && strpos($config_filename, ".tgz") === FALSE )
        {
            derr("specified filename with argument 'FILE' is not 'tar.gz' ");
        }
        else
        {
            $srcfile = $config_filename;


            //Todo check if it is better to create this under Tool folder and clean it up at the end

            $destfile = $this->newfolder . '/test1.tar.gz';

            if( !copy($srcfile, $destfile) )
            {
                echo "File cannot be copied! \n";
            }
            else
            {
                #echo "File has been copied!\n";
            }

            //extract into specified folder
            exec('tar -C ' . $this->newfolder . '/' . ' -zxvf ' . $destfile . ' 2>&1');

            #print "sleep 15 seconds: wait for tar extract complete";
            #sleep(15);
        }

        $this->folder_path = $this->newfolder . "/";
        $config_path = "index.json";

        if( !file_exists($this->folder_path . $config_path) )
        {
            //print out all file / folder information
            $files10 = scandir($this->newfolder);
            unset($files10[0]);
            unset($files10[1]);
            print_r($files10);


            $this->folder_path = $this->newfolder . "/" . $files10[2] . "/";


            $files10 = scandir($this->folder_path);
            unset($files10[0]);
            unset($files10[1]);
            print_r($files10);

            foreach( $files10 as $tarFile )
            {
                exec('tar -C ' . $this->folder_path . '/' . ' -zxvf ' . $this->folder_path . "/" . $tarFile . ' 2>&1');
            }

            $files10 = scandir($this->folder_path);
            unset($files10[0]);
            unset($files10[1]);
            print_r($files10);

        }


        #$someJSON = file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $someJSON = file_get_contents($this->folder_path . $config_path);


        // Convert JSON string to Array
        $someArray = json_decode($someJSON, TRUE);
        #print_r($someArray);        // Dump all data of the Array

        if( count( $someArray['policyPackages'] ) > 1 )
        {
            print "Packages counter: ".count( $someArray['policyPackages'] )."\n";
            print "available Packages:\n";
            foreach( $someArray['policyPackages'] as $package )
            {
                print " - '".PH::boldText( $package['packageName'] )."'\n";
            }
            derr( "this CP R80 configuration contain multiple Policy Packages, which is not yet supported." );
        }


        $this->jsonERROR();

        if( !is_array($someArray) )
            derr("json_decode not working");

        $this->data = $someArray;
    }


//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


    function import_config()
    {
        global $projectdb;
        global $source;

        global $debug;
        global $print;


        if( $this->routetable != "" )
        {
            echo PH::boldText("\nimport dynamic Routing\n");

            $cisco = file_get_contents($this->routetable);
            $this->importRoutes($cisco);
        }


        $padding = "";
        $this->print_array($this->data, $padding);

    }




    function anything_to_utf8($var, $deep = TRUE)
    {
        if( is_array($var) )
        {
            foreach( $var as $key => $value )
            {
                if( $deep )
                {
                    $var[$key] = anything_to_utf8($value, $deep);
                }
                elseif( !is_array($value) && !is_object($value) && !mb_detect_encoding($value, 'utf-8', TRUE) )
                {
                    $var[$key] = utf8_encode($var);
                }
            }
            return $var;
        }
        elseif( is_object($var) )
        {
            foreach( $var as $key => $value )
            {
                if( $deep )
                {
                    $var->$key = anything_to_utf8($value, $deep);
                }
                elseif( !is_array($value) && !is_object($value) && !mb_detect_encoding($value, 'utf-8', TRUE) )
                {
                    $var->$key = utf8_encode($var);
                }
            }
            return $var;
        }
        else
        {
            return (!mb_detect_encoding($var, 'utf-8', TRUE)) ? utf8_encode($var) : $var;
        }
    }



}


