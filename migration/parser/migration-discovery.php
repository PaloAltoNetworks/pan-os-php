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

//This script check if the CP R80 config file has multiple policy package available.
//respone should be JSON with all the package in it;

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());

require_once dirname(__FILE__)."/../pan-os-php/lib/pan_php_framework.php";

require_once dirname(__FILE__)."/mapper/cp_mapping.php";
require_once dirname(__FILE__)."/mapper/cpR80_mapping.php";
require_once dirname(__FILE__)."/mapper/stonesoft_mapping.php";

require_once dirname(__FILE__)."/mapper/discovery_misc.php";


PH::processCliArgs();




$expedition = false;

$mainfolder = "/tmp/expconverter";
$newfolder = null;

//Todo: use the one available in CONVERTER, here it is copy past
if( isset(PH::$args['file']) )
{
    $newfolder = $mainfolder . "/".uniqid();
    if( !file_exists($newfolder) )
        mkdir($newfolder, 0700, TRUE);

    if( isset(PH::$args['expedition']) )
    {
        if( !isset(PH::$args['testing']) )
            $mainfolder = "/home/userSpace/tmp";
        else
            $mainfolder = "/tmp/expapi/tmp";

        if( !file_exists($mainfolder) )
            mkdir($mainfolder, 0700, TRUE);

        if( $newfolder !=  null && file_exists($newfolder) )
            delete_directory($newfolder);
        $newfolder = $mainfolder . "/".uniqid();
        if( !file_exists($newfolder) )
            mkdir($newfolder, 0700, TRUE);


        $config_filename = PH::$args['file'];
        //Todo: check if file is ZIP file;
        if( strpos($config_filename, ".zip") === FALSE && strpos($config_filename, ".tgz") === FALSE )
        {
            derr("expedition argument is used, but there is no ZIP file provide in file argument");
        }
        else
        {
            $srcfile = $config_filename;


            $destfile = $newfolder . '/'.uniqid().'.zip';

            if( !copy($srcfile, $destfile) )
            {
                PH::print_stdout( "File cannot be copied! ");
            }
            else
            {
                #echo "File has been copied!\n";
            }

            //extract into specified folder
            #print "try to extract: |".'unzip -o '.$destfile."|\n";
            exec('unzip -o ' . $destfile . " -d " . $newfolder . ' 2> /dev/null' );

            #print "sleep 15 seconds: wait for tar extract complete";
            #sleep(5);
        }


        $folder_path = $newfolder . "/";
        #$config_path = "expedition_mapping.json";
        $config_path = "mapping.json";

        if( !file_exists($folder_path . $config_path) )
        {
            //print out all file / folder information
            #derr( "expedition_mapping.json not found" );
            derr($config_path . " not found");
        }
        else
        {

            $string = file_get_contents($folder_path . $config_path);

            #print "TEST\n";
            #print $string . "\n";

            #print "JSON:\n";
            $json_a = json_decode($string, TRUE);

            #print_r($json_a);

            /*
             //OLD stuff
            if( isset($json_a['policy']) and $json_a['policy'] != "" )
            {
                $this->configFile = $this->folder_path . $json_a['policy'];
            }
            else
            {
                derr("something wrong by parsing ".$config_path." file");
            }

            if( isset($json_a['routes']) )
            {
                if( isset($json_a['routes'][0]) and $json_a['routes'][0] != "" and !isset($json_a['routes'][1]) )
                    $this->routetable = $this->folder_path . $json_a['routes'][0];
            }

            if( isset(PH::$args['vendor']) and PH::$args['vendor'] == "cp" )
            {
                if( isset($json_a['objects']) and $json_a['objects'] != "" )
                {
                    $this->configFile = $this->newfolder;
                }
            }
            */
            #print "BASECONFIG: " . $json_a['baseConfig'] . "\n"; // wrong in JSON file, must be .XML
            #print "VERSION: " . $json_a['version'] . "\n";

            $panorama_config = FALSE;
            $new_in = "";

            $config_counter = count($json_a['configs']);
            #print "config COUNTER: " . $config_counter . "\n";

            #foreach( $json_a['configs'] as $key => $config ){

                $config = $json_a['configs'][0];

                /*
                print "VENDOR: '" . $config['vendor'] . "'\n";

                print_r($config['mapping']);

                print "object: '" . $config['object'] . "'\n";
                print "policy: '" . $config['policy'] . "'\n";
                print "rulebase: '" . $config['rulebase'] . "'\n";

                print_r($config['routes']);

                print "name: '" . $config['name'] . "'\n";

                print "############################################\n";

                */

                PH::$args = array();
                PH::$argv = array();
                PH::$args['vendor'] = $config['vendor'];

                #PH::$args['out'] = $arg_array['out'];
                #PH::$args['out'] = "/tmp/" . $config['vendor'] . ".xml";

                #if( $key == 0 )
                #    PH::$args['in'] = $this->folder_path . $json_a['baseConfig'];
                #else
                #    PH::$args['in'] = $new_in;


                if( PH::$args['vendor'] == "cp" )
                {
                    PH::$args['file'] = $folder_path . $config['policy'];

                    //todo: check if needed swaschkut 20201119
                    #PH::$args['routetable'] = $folder_path . $config['routes'][0];
                }
                else
                {
                    PH::$args['file'] = $folder_path . $config['policy'];


                    if( isset($config['routes']) )
                    {
                        if( isset($config['routes'][0]) and $config['routes'][0] != "" and !isset($config['routes'][1]) )
                            PH::$args['routetable'] = $folder_path . $config['routes'][0];
                    }
                }


                PH::$args['print'] = '1';
                PH::$args['debug'] = '1';


                #if( $panorama_config ){
                PH::$args['location'] = $config['name'];
                PH::$args['template'] = $config['name'];
                //}

                PH::$args['expedition'] = true;

                if( isset($arg_array['ruleorder']) )
                    PH::$args['ruleorder'] = $arg_array['ruleorder'];

                #PH::$args['location'] = "vsys1";

                #print_r(PH::$args);

                #$converter = new CONVERTER();

                #$new_in = PH::$args['out'];

            #}

            $config_filename = PH::$args['file'];
        }
    }
    else
    {
        $config_filename = PH::$args['file'];
    }
}
else
    derr( "file argument is missing");


if( isset(PH::$args['vendor']) )
    $vendor = PH::$args['vendor'];
else
    derr( "vendor argument is missing");


if( isset(PH::$args['routetable']) )
{
    $routetable = PH::$args['routetable'];
    //todo:
    //file must be of type ZIP because the mapper expect multiple firewalls which map to multiple routetable
    //but it could be also one routetable file, so that customer choose one firewall from central mgmt
}
else
{
    //todo: CP is multip vsys; so multiple routefile in ZIP is needed
    #if( $vendor == "cp" )
        #derr( "routetable argument is missing");
}


if( isset(PH::$args['expedition']) )
    $expedition = true;


if( !$expedition )
{
    PH::print_stdout( "***********************************************" );
    PH::print_stdout(  "************ Migration Discovery UTILITY ****************" );
}


if( $vendor == "cp" )
{
    $someArray = array();
    $file_parts = pathinfo($config_filename);
    cp_filecheck( $file_parts['dirname'], $someArray );


    #print_r( $someArray );
    ####################################################################
####################################################################
//Todo: task done - prepare JSON from the information above
    $test = array();
    $test['vendor'] = "cp";

    if( count($someArray) == 0 )
        $test['comment'] = "only one firewall policy found";

    foreach( $someArray as $key => $map )
        $test['policies'][] =   $map ;


    $json_text = json_encode($test, JSON_PRETTY_PRINT);
//Todo: this file is for expedition-api
    print $json_text;
    print "\n";

}
elseif( $vendor == "cp-r80" )
{
    $someArray = array();
    cpr80_filecheck( $config_filename, $someArray );


    $test = array();
    $test['vendor'] = "cp-r80";

    if( !$expedition )
        print "available Packages:\n\n";

    if( count($someArray['policyPackages']) == 1 )
        $test['comment'] = "only one firewall policy found";

    foreach( $someArray['policyPackages'] as $package )
    {
        if( !$expedition )
            print " - '".PH::boldText( $package['packageName'] )."'\n";

        $test['policies'][]['name'] =   $package['packageName'] ;
    }

    ###########################
    //todo: missing steps is route files
    //foreach( $policy as $key => $map )
    //    $test['configs'][] =   $map ;

    $json_text = json_encode($test, JSON_PRETTY_PRINT);
    //Todo: this file is for expedition-api
    print $json_text;
    print "\n";
}
elseif( $vendor == "stonesoft" )
{

    $firewalls = array();
    $mapping = array();
    $policy = array();

    stonesoft_checkfile( $config_filename, $firewalls, $policy, $mapping );

####################################################################
####################################################################
//Todo: task done - prepare JSON from the information above
    $test = array();
    $test['vendor'] = "stonesoft";
    foreach( $firewalls as $key => $map )
        $test['routes'][] =   $map ;
###########################
    foreach( $policy as $key => $map )
        $test['policies'][] =   $map ;

    $json_text = json_encode($test, JSON_PRETTY_PRINT);
//Todo: this file is for expedition-api
    print $json_text;
    print "\n";





    if( !$expedition )
    {
        ####################################################################
####################################################################
//Todo: task done - get information and ask for correct mapping
        stonesoft_mapping( $firewalls, $policy, $mapping );

//create final mapping

        $test = array();

        foreach( $mapping as $key => $map )
        {
            $test['mapping'][] = array( "firewall" => $firewalls[$key]['name'], "config" => $policy[$map]['name'] );
        }

        $json_text = json_encode($test, JSON_PRETTY_PRINT);
        print $json_text;
        print "\n";
    }




}


if( $newfolder !=  null && file_exists($newfolder) )
    delete_directory($newfolder);