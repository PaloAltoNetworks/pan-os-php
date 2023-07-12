<?php


require_once("SOPHOS.php");
require_once("SOPHOSaddress.php");
require_once("SOPHOSservice.php");
require_once("SOPHOSrule.php");

//USAGE:
//php SOPHOS_parser.php
//  file=/Users/swaschkut/Documents/Expedition_config/XYZ output\ DMZ.txt
//  out=/tmp/sophos.xml in=/Users/swaschkut/Documents/VM300-Baseline.xml
//  ruleorder=/Users/swaschkut/Documents/Expedition_config/XYZ/packetfilter\ order.txt


/*
//Todo: NEEDED config files:
Sophos UTM API export (copy / past)
https://www.sophos.com/en-us/medialibrary/PDFs/documentation/UTMonAWS/Sophos-UTM-RESTful-API.pdf?la=en
https://ip_address_of_ UTM:4444/api/



//copy all these information into one file
network/host
network/dns_host
network/dns_group
network/group
network/range
network/network
network/interface_network

service/group
service/tcp
service/udp
service/tcpudp

packetfilter/packetfilter




//rule order information MUST be placed in a separate file
rule order
nodes/packetfilter.rules



//Todo: missing feature:
- get all information directly via script from the Sophos Firewall
 */

class SOPHOS extends PARSER
{

    use SOPHOSaddress;
    use SOPHOSrule;
    use SOPHOSservice;

    use SHAREDNEW;

    public function vendor_main()
    {





        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done
        global $print;
        $print = TRUE;


        $this->clean_config();




        //Todo:
        //Specific Sophos extension how to get this running
        //right now only working if directly called via SOPHOS_parser.php
        if( isset(PH::$args['ruleorder']) )
            $rule_order_file = PH::$args['ruleorder'];
        else
        {
            $rule_order_file = '';
            $this->display_error_usage_exit("ruleorder is missing");
        }

        $this->import_config($rule_order_file); //This should update the $source

        CONVERTER::deleteDirectory( );
    }

    public function import_config($rule_order_file)
    {


        ////////////////////////////////////////////////////////////////
        //
        //prepare rule order information => all rule REF into one array
        //
        ////////////////////////////////////////////////////////////////
        $rulesort = $this->rulesort($rule_order_file);


        ////////////////////////////////////////////////////////////////
        //
        //prepare network/...    service/...   packetfilter/packetfiler information
        // => all information into one array [  $master_array with $master_array['network'] - $master_array['service'] - $master_array['packetfilter']   ]
        //
        ////////////////////////////////////////////////////////////////
        $master_array = $this->parserNEW($this->data);


        ////////////////////////////////////////////////////////////////
        //
        //generate network objects based on information in array $master_array['network']
        //
        ////////////////////////////////////////////////////////////////
        $this->address($master_array);

        ////////////////////////////////////////////////////////////////
        //
        //generate network group objects based on information in array $master_array['network']
        //
        ////////////////////////////////////////////////////////////////
        $this->addressgroup($master_array);


        ////////////////////////////////////////////////////////////////
        //
        //generate service objects based on information in array $master_array['service']
        //
        ////////////////////////////////////////////////////////////////
        $this->service($master_array);


        ////////////////////////////////////////////////////////////////
        //
        //generate service group objects based on information in array $master_array['service']
        //
        ////////////////////////////////////////////////////////////////
        $this->servicegroup($master_array);


        ////////////////////////////////////////////////////////////////
        //
        //generate security rules  based on information in array $master_array['packetfilter']
        // no NAT rule migration until now
        //
        ////////////////////////////////////////////////////////////////
        $this->rule($master_array, $rulesort);


    }

    function clean_config()
    {

        $config_file = file($this->configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->data = array();
        foreach( $config_file as $line => $names_line )
        {

            /*
            if( (preg_match("/description/", $names_line)) OR (preg_match("/remark/", $names_line)) )
            {
                #$data[] = $names_line;

                //Todo: SVEN 20191203 - problem with config "
                $tmp_array = explode("\r", $names_line);
                foreach( $tmp_array as $tmp_line )
                    $data[] = $tmp_line;
            }
            else
            {
                #"<--- More --->"
                if( preg_match("/^<--- More --->/", $names_line) || preg_match("/^              /", $names_line) )
                {

                }
                elseif( preg_match("/\'/", $names_line) )
                {
                    $data[] = str_replace("'", "_", $names_line);
                }
                elseif( preg_match("/\\r/", $names_line) )
                {
                    $tmp_array = explode("\r", $names_line);
                    foreach( $tmp_array as $tmp_line )
                        $data[] = $tmp_line;
                }
                else
                {
                    $data[] = $names_line;
                }
            }
            */

            $this->data[] = $names_line;
        }

    }

    public function rulesort($rule_order_file)
    {
        $file_content2 = file($rule_order_file) or die("Unable to open rule_order_file!");

        $rulesort = array();


        ////////////////////////////////////////////////////////////////
        //
        //prepare rule order information => all rule REF into one array
        //
        ////////////////////////////////////////////////////////////////
        foreach( $file_content2 as $line )
        {
            $line = $this->strip_hidden_chars($line);
            $line = str_replace(" \\", "", $line);    #|-> \
            $line = str_replace("\\\"", "", $line);   #|->\"
            $line = str_replace("\"", "", $line);     #|->"
            $line = str_replace("\\'", "", $line);    #|->\'
            $line = str_replace(" ", "", $line);
            $line = str_replace(",", "", $line);

            if( strpos($line, "[") !== FALSE || strpos($line, "]") !== FALSE )
            {

            }
            else
            {
                $rulesort[] = $line;
                #print "line|".$line."|\n";
            }

        }

        #print_r( $rulesort );
        return $rulesort;
    }


    public function parserNEW($file_content)
    {
        $start = FALSE;
        $start2 = FALSE;
        $tmp_start2_value = "";
        $tmp_start2 = "";


        $master_array = array();

        $i = 0;
        $j = 0;
        $k = 0;
        $string_array = array();


        ////////////////////////////////////////////////////////////////
        //
        //prepare network/...    service/...   packetfilter/packetfiler information
        // => all information into one array [  $master_array with $master_array['network'] - $master_array['service'] - $master_array['packetfilter']   ]
        //
        ////////////////////////////////////////////////////////////////
        foreach( $file_content as $line )
        {
            #print "line|".$line."|\n";

            $line = $this->strip_hidden_chars($line);
            $line = str_replace(" \\", "", $line);    #|-> \
            $line = str_replace("\\\"", "", $line);   #|->\"
            $line = str_replace("\"", "", $line);     #|->"
            $line = str_replace("\\'", "", $line);    #|->\'


            if( strpos($line, "{") !== FALSE )
            {
                #print "START\n";
                $start = TRUE;
                $tmp_array = array();
                continue;
            }
            elseif( strpos($line, "}") !== FALSE )
            {
                #print "END\n";
                $start = FALSE;

                if( isset($tmp_array['_type']) )
                {
                    #print_r( $tmp_array );
                    #print    "type:".$tmp_array['_type']."\n";

                    $array_type = explode("/", $tmp_array['_type']);

                    $master_array[$array_type[0]][] = $tmp_array;
                }


                continue;
            }
            elseif( strpos($line, ": [],") !== FALSE )
            {
                continue;
            }
            elseif( strpos($line, ": [") !== FALSE )
            {
                $start2 = TRUE;
                $tmp_start2 = "";
                $tmp_start2_value = "";
            }
            elseif( strpos($line, "],") !== FALSE )
            {
                $start2 = FALSE;

                if( $tmp_start2 != "" )
                {
                    #print "|".$tmp_start2."|".$tmp_start2_value."\n";
                    $tmp_array[$tmp_start2] = $tmp_start2_value;
                    $tmp_start2 = "";
                    $tmp_start2_value = "";
                }

                continue;
            }


            if( $start )
            {
                $ex = explode(": ", $line);
                if( !isset($ex[1]) )
                    //print "line|".$line."|\n";

                    foreach( $ex as $key => $item )
                    {
                        $temp_item = str_replace('"', "", $item);
                        $temp_item = str_replace(' ', "", $temp_item);
                        $ex[$key] = str_replace(',', "", $temp_item);
                        #$ex[$key] = str_replace('"',"",$item);
                    }

                if( isset($ex[1]) )
                {
                    $tmp_key = str_replace(' ', "", $ex[0]);
                    $tmp_array[$tmp_key] = $ex[1];
                }

                if( strpos($line, ": [") !== FALSE )
                {
                    $tmp_start2 = str_replace(' ', "", $ex[0]);
                }


                if( $start2 && !isset($ex[1]) )
                {
                    $temp_item = str_replace('"', "", $line);
                    $temp_item = str_replace(',', "", $temp_item);

                    #$tmp_start2_value = str_replace(' ',"",$temp_item);

                    if( $tmp_start2_value == "" )
                        $tmp_start2_value = str_replace(' ', "", $temp_item);
                    else
                        $tmp_start2_value .= "," . str_replace(' ', "", $temp_item);

                }
                #$tmp_array[] = $ex;

            }
        }

        return $master_array;
    }
}