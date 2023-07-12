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




require_once('HUAWEIaddress.php');
require_once('HUAWEIservice.php');
require_once('HUAWEIdomain.php');
require_once('HUAWEI_securityrules.php');

require_once("parser/CISCOISR/CISCOISRmisc.php");


class HUAWEI extends PARSER
{
    use HUAWEIaddress;
    use HUAWEIservice;
    use HUAWEIdomain;
    use HUAWEI_securityrules;

    use CISCOISRmisc;
    use SHAREDNEW;

    public $debug = FALSE;
    public $print = FALSE;



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

        //HUAWEI specific
        //------------------------------------------------------------------------
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
            //Todo: swaschkut 20200911 - how to validate config???

            #$output_array = array_unique( $output_array[1] );
            $result = array_unique($output_array[1]);

            #print_r($result);


            $array_done = array('address-object', 'address-group', 'service-object', 'service-group',
                'access-rule', 'nat-policy', 'zone', 'interface', 'routing', 'schedule', 'rbl',
                'login', 'Copyright', 'Using', 'firmware-version', 'rom-version', 'model', 'serial-number', 'system-time', 'system-uptime',
                'last-modified-by', 'cli', 'no', 'checksum', 'firmware'
            );
            $result = array_diff($result, $array_done);
            #print_r($result);
        }


        //FIRMWARE validation
        if( preg_match('#^!Software Version(.*)#m', $string, $output_array) )
        {
            #!Software Version V500R001C30SPC600
            #print_r($output_array);
            $firmware = $output_array[1];

            print "HUAWEI FIRMWARE: ".$firmware."\n";


        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////
        /// OBJECTS


        //ADDRESS

        if( preg_match_all('/ip address-set (.*?)\n#/ms', $string, $output_array) )
        {
            #print "ENTRY1\n";
            #$address = $this->prepare_address($address, $output_array[0]);
            $address = $output_array[0];
            //Todo: check if it is possible to ue [1]

            #print_r( $output_array[0] );
            #print_r( $address );
        }

        //SERVICE
        if( preg_match_all('/ip service-set (.*?)\n#/ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $service = $output_array[1];

            #print_r( $service );
        }

        //SERVICE
        if( preg_match_all('/ domain-set (.*?)location/ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $domain = $output_array[0];

            $domain = $domain[0];
            #print_r( $domain );
        }



        /////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////
        /// RULES

        //ACCESS RULE
        if( preg_match_all('/security-policy(.*)auth-policy/ms', $string, $output_array) )
        {
            #print_r( $output_array );
            #$access_rule = $output_array[0];

            #print_r( $output_array[0] );

            $string1 = $output_array[0][0];
            #preg_match_all('#^ rule name (.*?)^  action #ms', $string1, $output_array);

            //Todo: problem that after "action" there is no match to end of line
            preg_match_all('#^ rule name (.*?)^  action (.*?)$#ms', $string1, $output_array);

            #print_r( $output_array );

            //[1] has everything but not action
            //[2] has only value for action
            $access_rule = $output_array;
        }

/*
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

            firewall zone name sec_mgmt id 15
             set priority 40
             add interface Eth-Trunk0.24
            #
        }

        //INTERFACE
        if( preg_match_all('#^interface(.*?)^    exit#ms', $string, $output_array) )
        {
            #print_r( $output_array );
            $interface = $output_array[1];

            #
            interface GigabitEthernet2/0/2
             undo shutdown
             lldp enable
             lldp tlv-enable basic-tlv all
            #
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
*/

        #if( $print )
        print PH::boldText("\nadd address objects:\n");
        $this->add_address( $address);

        $this->addServicePredefined( "huawei" );
        #if( $print )
        print PH::boldText("\nadd service objects:\n");
        $this->add_service( $service);


        #if( $print )
        print PH::boldText("\nadd custom URL objects:\n");
        $this->add_domain( $domain);
/*

        ///////////////////////////////////////////////////////////////////////////////////////////

        #if( $print )
        print PH::boldText("\nadd zones:\n");
        $this->add_zone($v, $zones);

        #if( $print )
        print PH::boldText("\nadd interfaces:\n");
        $this->add_interface($v, $interface);


        #if( $print )
        print PH::boldText("\nadd routing:\n");
        $this->add_routing($v, $routing);

        ///////////////////////////////////////////////////////////////////////////////////////////
*/

        #if( $print )
        print PH::boldText("\nadd access rules:\n");
        $this->add_accessrule( $access_rule);

/*
        #if( $print )
        print PH::boldText("\nadd nat policy:\n");
        $this->add_natpolicy($v, $nat_policy);


        print PH::boldText("\nvalidate interface name:\n");
        CONVERTER::validate_interface_names($pan);
*/

        //Todo: replace TMP service with app-id

    }

}
