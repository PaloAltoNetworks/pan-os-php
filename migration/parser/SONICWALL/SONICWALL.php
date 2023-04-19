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

//Todo: SonicOS >= 6.5.0 implementation

//Todo: EXP support
//https://www.sonicwall.com/support/knowledge-base/how-to-get-the-configurations-of-the-firewall-based-on-the-exporting-exp-file/170503330364045/



require_once('SONICWALLaddress.php');
require_once('SONICWALLaddressgroup.php');
require_once('SONICWALLservice.php');
require_once('SONICWALLservicegroup.php');

require_once('SONICWALLzone.php');
require_once('SONICWALLinterface.php');

require_once('SONICWALLaccessRuleParser.php');
require_once('SONICWALLnatpolicy.php');

require_once('SONICWALLroute.php');


class SONICWALL extends PARSER
{
    use SONICWALLaccessRuleParser;
    use SONICWALLaddress;
    use SONICWALLaddressgroup;
    use SONICWALLinterface;
    use SONICWALLroute;
    use SONICWALLnatpolicy;
    use SONICWALLservice;
    use SONICWALLservicegroup;
    use SONICWALLzone;

    use SHAREDNEW;

    //Todo: 20190529
    //import routing, schedule, rbl

    //fix NAT issue for DST-nat, especially zone - related to routeing
    //fix interface -> change int name, change zone where int belong to, change vsys where int is member, change all NAT policy where int is used
    //      maybe introduce int references for zone, vsys, NAT policy
    //problem with not allowed object name: address-group -> __select '__select'
    //DST NAT, if translated-destination is group -> check if only one member and use this member

    public $debug = FALSE;
    public $print = FALSE;


    #public $string = file_get_contents ($config_filename);


//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


    function vendor_main()
    {




        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done
        global $print;
        $print = TRUE;


        $this->clean_config();


        $this->import_config(); //This should update the $source
        //------------------------------------------------------------------------

        CONVERTER::deleteDirectory( );
    }

    function clean_config()
    {
        #CLEAN CONFIG FROM EMPTY LINES AND CTRL+M
        #$data =  implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

        $this->data = file_get_contents($this->configFile);

        #$data = str_replace("'", "_", $data);
        //– / -
        #$data = str_replace("–", "-", $data);

        /*
                $demo_array = array();
                $screenos_config_file = explode("\n", $data);
                $array_counter = count($screenos_config_file);
                foreach ($screenos_config_file as $line => $names_line)
                {
                    if(  $line > 15 && $line < $array_counter - 15 )
                    {
                        $tmp_data = $this->name_preg_split( $names_line );
                        if( isset($tmp_data[0]) )
                            $demo_array[$tmp_data[0]] = $line;
                    }
                }

                if( count($demo_array) > 3 )
                {
                    print_r( $demo_array );
                    derr( "Juniper Netscreen config file is not well exported, please check " );
                }
        */

    }

    public function prepare_address($address, $output_array)
    {
        foreach( $output_array as $tmp_address_entry )
        {
            $tmp_address_entry = $this->strip_hidden_chars($tmp_address_entry);
            $tmp_address_entry = str_replace("address-object ", "", $tmp_address_entry);
            $tmp_address_entry = str_replace("    ", " ", $tmp_address_entry);
            $tmp_address_entry = str_replace(" exit", "", $tmp_address_entry);

            $address[] = $tmp_address_entry;
        }
        return $address;
    }


    public function import_config()
    {

        $address = array();
        $fqdn = array();
        $addressgroup = array();

        $service = array();
        $servicegroup = array();

        $zones = array();
        $interface = array();

        $routing = array();

        $access_rule = array();
        $nat_policy = array();


        $string = $this->data;

        #if( preg_match_all('#^([a-zA-Z0-9_-]+) (.*)$#m', $string, $output_array, PREG_OFFSET_CAPTURE) )
        if( preg_match_all('#^([a-zA-Z0-9_-]+) (.*)$#m', $string, $output_array) )
        {


            #$output_array = array_unique( $output_array[1] );
            $result = array_unique($output_array[1]);

            print_r($result);
            $array_done = array('address-object', 'address-group', 'service-object', 'service-group',
                'access-rule', 'nat-policy', 'zone', 'interface', 'routing', 'schedule', 'rbl',
                'login', 'Copyright', 'Using', 'firmware-version', 'rom-version', 'model', 'serial-number', 'system-time', 'system-uptime',
                'last-modified-by', 'cli', 'no', 'checksum', 'firmware'
            );
            $result = array_diff($result, $array_done);
            print_r($result);
        }


        //FIRMWARE validation
        if( preg_match('#^firmware-version(.*)#m', $string, $output_array) )
        {
            print_r($output_array);
            $firmware = $output_array[1];

            $firmware = trim($firmware);
            $firmware = str_replace('"', "", $firmware);
            $firmware = str_replace("SonicOS Enhanced ", "", $firmware);
            $tmp_firmware = explode(".", $firmware);


            foreach( $tmp_firmware as $key => $value )
            {
                if( $key < 3 )
                    if( !is_numeric($value) )
                    {
                        print "Firmware could not be identified: " . $key . " - " . $value . "\n";
                        print $output_array[1] . "\n";
                        print_r($tmp_firmware);
                        exit(1);
                    }
            }

            $not_supported = FALSE;
            if( $tmp_firmware[0] > 6 )
                $not_supported = TRUE;
            elseif( ($tmp_firmware[0] == 6) && ($tmp_firmware[1] >= 5) )
                $not_supported = TRUE;

            if( $not_supported )
            {
                derr("This Sonicwall parser do not yet support SonicOS >= 6.5.0");
            }

        }

        //ADDRESS

        //FQDN ADDRESS
        if( preg_match_all('#^address-object fqdn(.*?)$#m', $string, $output_array) )
        {
            print "ENTRY - FQDN\n";
            $fqdn = $this->prepare_address($fqdn, $output_array[0]);
            #print_r( $fqdn );
        }


        if( preg_match_all('#^address-object (ipv4 |ipv6 )(.*)( host | network | range )(.*)$#m', $string, $output_array) )
        {
            #print "ENTRY1\n";
            $address = $this->prepare_address($address, $output_array[0]);
            #print_r( $address );
        }
        elseif( preg_match_all('#^address-object (ipv4 |ipv6 )(.*?)^    exit#ms', $string, $output_array) )
        {
            #print "ENTRY2\n";
            $address = $this->prepare_address($address, $output_array[0]);
            #print_r( $address_problem );
        }
        elseif( preg_match_all('#^address-object (.*?)^    exit#ms', $string, $output_array) )
        {
            #print "ENTRY3\n";
            $address = $this->prepare_address($address, $output_array[0]);

            #print_r($output_array[0]);
        }
        /////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////
        /// OBJECTS

        //ADDRESSGROUP
        if( preg_match_all('#^address-group(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $addressgroup = $output_array[1];
        }


        //SERVICE
        if( preg_match_all('#^service-object (.*)$#m', $string, $output_array) )
        {
            #print_r( $output_array );
            $service = $output_array[1];
        }

        //SERVICEGROUP
        if( preg_match_all('#^service-group(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $servicegroup = $output_array[1];
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////
        /// RULES

        //ACCESS RULE
        if( preg_match_all('#^access-rule(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $access_rule = $output_array[1];
        }

        //NAT
        //nat-policy
        if( preg_match_all('#^nat-policy(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $nat_policy = $output_array[1];
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////
        /// ZONES / INTERFACE / ROUTING / SCHEDULE

        //ZONE
        if( preg_match_all('#^zone(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $zones = $output_array[1];
        }

        //INTERFACE
        if( preg_match_all('#^interface(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $interface = $output_array[1];
        }

        //ROUTING
        if( preg_match_all('#^routing(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $routing = $output_array[1];
        }


        //SCHEDULE
        if( preg_match_all('#^schedule(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        ///
        //RBL
        if( preg_match_all('#^rbl(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////


        #if( $print )
        print PH::boldText("\nadd address objects:\n");
        $this->add_address( $address);

        #if( $print )
        print PH::boldText("\nadd address fqdn objects:\n");
        $this->add_address_fqdn( $fqdn);


        #if( $print )
        print PH::boldText("\nadd addressgroup objects:\n");
        $this->add_addressgroup( $addressgroup);

        #if( $print )
        print PH::boldText("\nadd service objects:\n");
        $this->add_service( $service);

        #if( $print )
        print PH::boldText("\nadd servicegroup objects:\n");
        $this->add_servicegroup( $servicegroup);

        ///////////////////////////////////////////////////////////////////////////////////////////

        #if( $print )
        print PH::boldText("\nadd zones:\n");
        $this->add_zone( $zones);

        #if( $print )
        print PH::boldText("\nadd interfaces:\n");
        $this->add_interface($interface);


        #if( $print )
        print PH::boldText("\nadd routing:\n");
        $this->add_routing( $routing);

        ///////////////////////////////////////////////////////////////////////////////////////////

        #if( $print )
        print PH::boldText("\nadd access rules:\n");
        $this->add_accessrule( $access_rule);

        #if( $print )
        print PH::boldText("\nadd nat policy:\n");
        $this->add_natpolicy( $nat_policy);


        print PH::boldText("\nvalidate interface name:\n");
        CONVERTER::validate_interface_names( $this->template );


    }

}
