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


require_once("SCREENOSaddresses.php");
require_once("SCREENOSipsec.php");
require_once("SCREENOSnat.php");
require_once("SCREENOSnetwork.php");
require_once("SCREENOSsecrule.php");
require_once("SCREENOSservice.php");

class SCREENOS extends PARSER
{
    use SCREENOSaddresses;
    use SCREENOSipsec;
    use SCREENOSnat;
    use SCREENOSnetwork;
    use SCREENOSsecrule;
    use SCREENOSservice;

    use SHAREDNEW;

    public $addDip = array();
    public $dip = array();
    public $add_srv = array();
    public $debug = FALSE;
    public $print = FALSE;
    public $servicegroup = array();
    public $natdst_array = array();


//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


    function vendor_main()
    {




        $tmp_template_vsys = array();

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

        echo PH::boldText("\nload custom application:\n");
        $this->load_custom_application();

        //Todo: validation if GLOBAL rule
        echo PH::boldText("Zone Calculation for Security and NAT policy");
        #Converter::calculate_zones($this->template, $this->sub, "append");

        //Todo: SVEN 20190522
        //Validate if ethernet interfaces are well named
        // not allowed:
        // ethernet 0/0 / bgroup aso.

        echo PH::boldText("\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n");
        CONVERTER::validate_interface_names($this->template);


        echo PH::boldText("\nVALIDATION - Region name must not be used as a address / addressgroup object name\n");
        CONVERTER::validation_region_object($this->sub);
        #


        //if security rule count is very high => memory leak problem
        //Todo: where to place custom table for app-migration if needed
        echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
        print "todo\n";
        CONVERTER::AppMigration($this->sub, $this->configType);
        #





        CONVERTER::deleteDirectory( );
    }


    function clean_config()
    {
        #CLEAN CONFIG FROM EMPTY LINES AND CTRL+M
        $this->data = implode(PHP_EOL, file($this->configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

        $this->data = str_replace("'", "_", $this->data);
        //– / -
        $this->data = str_replace("–", "-", $this->data);


        $demo_array = array();
        $screenos_config_file = explode("\n", $this->data);
        $array_counter = count($screenos_config_file);
        foreach( $screenos_config_file as $line => $names_line )
        {
            if( $line > 15 && $line < $array_counter - 15 )
            {
                $tmp_data = $this->name_preg_split($names_line);
                if( isset($tmp_data[0]) )
                    $demo_array[$tmp_data[0]] = $line;
            }
        }

        if( count($demo_array) > 3 )
        {
            print_r($demo_array);
            derr("Juniper Netscreen config file is not well exported, please check ");
        }
    }

    function import_config( )
    {
        global $debug;
        global $print;
        global $tmp_template_vsys;


        $addDip = array();
        $dip = array();
        $add_srv = array();
        $servicegroup = array();
        $natdst_array = array();


        #LOAD THE FILE
        $screenos_config_file = explode("\n", $this->data);


        $found_vsys = FALSE;
        $vsysName = "";
        $vsysID = "";
        foreach( $screenos_config_file as $line => $names_line )
        {
            if( preg_match("/^set vsys /i", $names_line) )
            {
                $data = $this->name_preg_split($names_line);
                $vsysName = $data[2];
                $found_vsys = TRUE;

                #print "found vsys: ".$vsysName."\n";
            }

            if( preg_match("/^set vsys-id /i", $names_line) && $found_vsys )
            {
                $data = $this->name_preg_split($names_line);
                if( !isset($data[2]) )
                {
                    #derr( "data[2] not set: '".$names_line."'\n" );
                    $data[2] = '1111';
                }

                $vsysID = $data[2];
                $found_vsys = FALSE;

                // Did we find VSYS1 ?
                $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
                if( $this->template_vsys === null )
                {
                    $this->template_vsys = $this->template->createVirtualSystem(intval($vsysID), $vsysName);
                    $tmp_template_vsys[ $vsysName ] = intval($vsysID);

                    if( $this->template_vsys === null )
                    {
                        derr("vsys" . $vsysID . " could not be created ? Exit\n");
                    }
                    #print "create VSYS: ".$vsysID." - ".$vsysName."\n";
                }
                else
                {
                    $v2 = $this->template->findVSYS_by_displayName($vsysName);
                    if( $v2 === null )
                    {
                        #print "VSYS: ".$vsysID." already available - check displayName ".$vsysName."\n";
                        $this->template_vsys->setAlternativeName($vsysName);
                        $tmp_template_vsys[ $vsysName ] = intval($vsysID);
                    }
                }
            }
        }

        print "###\n";
        print PH::boldText("   add netscreen default services\n");
        $this->addServicePredefined( "screenos" );




        print "###\n";
        print PH::boldText("   INTERFACES\n");
        $this->get_interfaces($screenos_config_file );
        #update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Reading Address and Groups',$jobid);



        print "###\n";
        print PH::boldText("   import netscreen ipsec / ike\n");
        $this->netscreen_ipsec($screenos_config_file );


        /*
            $vsys="root";
            update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Reading Interfaces',$jobid);
        */



        print "###\n";
        print PH::boldText("   address objects\n");
        $this->get_address_SCREENOS($screenos_config_file );
        //get_address_SCREENOS($screenos_config_file, $source, $vsys, $ismultiornot);

        print "###\n";
        print PH::boldText("   address groups\n");
        $this->get_address_groups($screenos_config_file );
        //get_address_groups($screenos_config_file, $source, $vsys, $ismultiornot);

        #update_progress($project, '0.30', 'File:' . $filename . ' Phase 3 Reading Services and Groups',$jobid);
        print "###\n";
        print PH::boldText("   service objects\n");
        $this->get_services($screenos_config_file );
        //get_services($screenos_config_file, $source, $vsys, $ismultiornot);

        print "###\n";
        print PH::boldText("   service groups\n");
        $servicegroup = $this->get_services_groups($screenos_config_file, $servicegroup);
        //get_services_groups($screenos_config_file, $source, $vsys, $ismultiornot);


        /*
            #echo "Fix Services with Multiple Protocol".PHP_EOL;
            fix_services_multiple_protocol($vsys, $source);
            #update_progress($project, '0.40', 'File:' . $filename . ' Phase 4 Reading Routes',$jobid);
        */
        #echo "Read Routes".PHP_EOL;
        print "###\n";
        print PH::boldText("   static routes\n");
        $this->get_routes($screenos_config_file);
        #update_progress($project, '0.45', 'File:' . $filename . ' Phase 4.2 Mapping Virtual Router',$jobid);

        #echo "MAP VR".PHP_EOL;
        //20190508 Sven not needed - done other way around
        print "###\n";
        print PH::boldText("   virtualrouter\n");
        $this->map_vr($screenos_config_file);
        #update_progress($project, '0.50', 'File:' . $filename . ' Phase 5 Reading Security Rules',$jobid);



        print "###\n";
        print PH::boldText("   MIP\n");
        $this->get_nat_MIP($screenos_config_file);

        print "###\n";
        print PH::boldText("   VIP\n");
        $this->get_nat_VIP($screenos_config_file);

        #echo "Read Security Policies".PHP_EOL;
        print "###\n";
        print PH::boldText("   security rules\n");
        $this->get_Security_Rules($screenos_config_file);
        /*    #update_progress($project, '0.60', 'File:' . $filename . ' Phase 6 Reading Nat Rules',$jobid);

            $getDM = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename' LIMIT 1;");
            while ($data = $getDM->fetch_assoc()) {
                $vsys = $data['vsys'];

        */



        print "###\n";
        print PH::boldText("   DIP\n");
        $this->get_nat_DIP( );

        print "###\n";
        print PH::boldText("   generate natdst\n");
        #echo "generate NAT DST $vsys".PHP_EOL;
        $this->generate_natdst( $natdst_array);


        //Todo: 20190522 implement NAT policy fix
        /*
                #echo "Fix Destination NAT $vsys".PHP_EOL;
                fix_destination_nat($source, $vsys);

                #echo "Split DNAT Rules $vsys".PHP_EOL;
                split_dnat_rules($source, $vsys, $filename);

                #echo "Check DNAT Cidr $vsys".PHP_EOL;
                check_dnat_cidr($source, $vsys, $filename);

        */


        print "###\n";
        print PH::boldText("   fix servicegroups\n");
        $this->fix_servicegroup_tmp_service( $servicegroup);
    }


    function name_preg_split($names_line)
    {
        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
        return $data;
    }

    function vsys_parser($names_line )
    {
        $data = $this->name_preg_split($names_line);
        $vsys = $data[2];

        // Did we find VSYS1 ?
        $this->template_vsys = $this->template->findVSYS_by_displayName($vsys);
        if( $this->template_vsys === null )
        {
            derr("vsys: " . $vsys . " could not be found ! Exit\n");
        }
    }

}

