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





require_once('STONESOFTaddress.php');
require_once('STONESOFTservice.php');
require_once('STONESOFTpolicy.php');
require_once ('STONESOFTvsys.php');



class STONESOFT extends PARSER
{
    use STONESOFTaddress;
    use STONESOFTservice;
    use STONESOFTpolicy;
    use STONESOFTvsys;

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

    public $LSYS_bool = false;

    public $filtered_fw = array();
    public $filtered_policy = array();
    public $mapping_array = array();

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

        if( $this->mapping !== null )
        {
            $json = file_get_contents($this->mapping);
            $mapping_array = json_decode($json, TRUE);
            print_r( $mapping_array );
            foreach( $mapping_array['mapping'] as $entry )
            {
                $this->filtered_policy[ $entry['config'] ] = $entry['config'];
            }
        }

        #print_r( $this->filtered_policy );
        //Todo: create for each ENTRY part a single vsys / DG + template
        // all objects must be migrated into shared


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

        $data = file_get_contents($this->configFile);



        $doc = new DOMDocument();
        $doc->loadXML($data, XML_PARSE_BIG_LINES);


        $root = $doc->documentElement; // Root node
        $configRoot = $root;

        //how to print out all XML?

        $test = array();
        foreach( $root->childNodes as $childNode )
        {
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            #print $childNode->nodeName."\n";
            $test[ $childNode->nodeName ] = $childNode->nodeName;
        }


        /*
        [host] => host
        [alias] => alias
        [network] => network
        [service_tcp] => service_tcp
        [service_udp] => service_udp
        [inspection_template_policy] => inspection_template_policy
        [tcp_service_group] => tcp_service_group
        [domain_name] => domain_name
        [group] => group
        [gen_service_group] => gen_service_group
        [fw_sub_policy] => fw_sub_policy
        [category] => category
        [fw_cluster] => fw_cluster
        [granted_policy_ref] => granted_policy_ref
        [fw_policy] => fw_policy
        [address_range] => address_range
        [certificate_authority] => certificate_authority
        [log_server] => log_server
        [mgt_server] => mgt_server
        [expression] => expression
        [file_filtering_policy] => file_filtering_policy
        [router] => router
        [tools_profile] => tools_profile
        [location] => location
        [interface_zone] => interface_zone
        [smtp_server] => smtp_server
        [active_directory_server] => active_directory_server
        [qos_class] => qos_class
        [qos_policy] => qos_policy
        [dhcp_server] => dhcp_server
        [snmp_agent] => snmp_agent
         */

        print_r( $test );


        /*
        $configRoot = DH::findFirstElement('rpc-reply', $configRoot);
        if( $configRoot === FALSE )
            derr("<rpc-reply> was not found", $root);
*/

        #$configRoot = DH::findFirstElement('generic_import_export', $configRoot);


        $this->data = $configRoot;
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


    public function import_config( )
    {
        global $LSYS_bool;

        $root = $this->data;





        $lsystems = array();
        if( count($lsystems) > 0 )
        {
            $LSYS_bool = true;
            //import the below info into shared
            $this->template_vsys = $this->create_vsys( );
            $this->import_lsys( $root, true );

            //create new vsys per lsys and import

            foreach( $lsystems as $lsys )
            {
                if( $lsys->nodeType != 1 ) continue;


                $name = DH::findFirstElement('name', $lsys);

                #if( !$groups ){
                    print "create LSYS: ".$name->nodeValue."\n";
                $this->template_vsys = $this->create_vsys( $name->nodeValue);
                #}

                #$this->import_lsys( $v, $lsys, false, $groups );

            }
        }
        else
        {
            //import the below info into vsys1
            $this->template_vsys = $this->create_vsys();
            #$this->import_lsys( $v, $root );
        }


        //add all kind of address objects
        $this->get_XML_Zones_Address_All_new2( $root );

        $this->addServicePredefined( "stonesoft" );


        //add all kind of address objects
        $this->add_services(  $root );

        //add all kind of address objects
        $this->add_service_groups(  $root );



        //Todo: TMP needed as I like to import this into 'vsys1', because objects are also already there
        //Todo: can I not use argument 'location-' for this???????
        #$this->sub = $this->template_vsys->findVirtualSystem('vsys1');

        $this->addDomainNames( $root );

        $this->addAddressGroups( $root );

        #
        $this->add_policy( $root );

        /*
        echo PH::boldText("\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n");
        CONVERTER::validate_interface_names($pan);

        #

        echo PH::boldText("\nVALIDATION - Region name must not be used as a address / addressgroup object name\n");
        CONVERTER::validation_region_object($this->sub);
        #

        //if security rule count is very high => memory leak problem
        //Todo: where to place custom table for app-migration if needed
        echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
        print "todo\n";
        CONVERTER::AppMigration($pan);
        #

        */
    }

    public function import_lsys( $root, $shared = false, $groups = false )
    {
        //IMPORT all which can be also none LSYS info


        if( !$groups )
        {
            print "\nadd_junos_services:\n";
            $this->add_junos_services();
        }



        print "\nInterfaces:\n";
        $interfaceRoot = DH::findFirstElement('interfaces', $root);
        if( $interfaceRoot === FALSE )
            mwarning("<interfaces> was not found", $root);
        else
            $this->get_Interfaces_new($interfaceRoot, $shared);


        print "\nstatic Routes:\n";
// - static routes
//    $vr = $configuration->xpath("//configuration/routing-instances/instance");
        $staticrouteRoot = DH::findFirstElement('routing-instances', $root);
        if( $staticrouteRoot === FALSE )
            mwarning("<routing-instances> was not found", $root);
        else
            $this->get_XML_staticRoutes($staticrouteRoot, $shared);


        $securityRoot = DH::findFirstElement('security', $root);
        if( $securityRoot === FALSE )
            mwarning("<security> was not found", $root);


        if( $securityRoot !== FALSE )
        {
            print "\nAddress objects:\n";
            $addressbookRoot = DH::findFirstElement('address-book', $securityRoot);
            if( $addressbookRoot !== FALSE )
            {
                $this->get_XML_Zones_Address_All_new2($addressbookRoot);
            }
            else
            {
                mwarning("<address-book> was not found directly under SECURITY", null, FALSE);
            }



            print "\nZone objects: \n";
            $zonesRoot = DH::findFirstElement('zones', $securityRoot);
            if( $zonesRoot === FALSE )
            {
                mwarning("<zones> was not found", null, FALSE);
            }
            else
                $this->get_XML_Zones($zonesRoot, $shared);


            print "\nService objects:\n";
            $applicationsRoot = DH::findFirstElement('applications', $root);
            if( $applicationsRoot === FALSE )
                mwarning("<applications> was not found", $root);
            else
                $this->get_XML_Applications2($applicationsRoot);

            print "\npolicies: \n";
            $policiesRoot = DH::findFirstElement('policies', $securityRoot);
            //$address = $configuration->xpath("/configuration/security/policies/global");
            //$address = $configuration->xpath("/configuration/security/policies/policy");
            if( $policiesRoot === FALSE )
                mwarning("<policies> was not found", $securityRoot);
            else
                $this->get_XML_policies2($policiesRoot);

            //security -> ike
            print "\nIKE objects:\n";
            $ikeRoot = DH::findFirstElement('ike', $securityRoot);
            if( $ikeRoot === FALSE )
                mwarning("<ike> was not found", null, FALSE);
            else
                $this->get_XML_IKE($ikeRoot, $shared);

            //security -> ipsec
            print "\nIPSEC objects:\n";
            $ipsecRoot = DH::findFirstElement('ipsec', $securityRoot);
            if( $ipsecRoot === FALSE )
                mwarning("<ipsec> was not found", null, FALSE);
            else
                $this->get_XML_IPSEC($ipsecRoot, $shared);




            //Todo: move global rules to TOP

            print "\nnat: \n";
            $natRoot = DH::findFirstElement('nat', $securityRoot);
            if( $natRoot === FALSE )
                mwarning("<nat> was not found", $securityRoot);
            else
            {
                //Todo: static nat rules, recalculate zones, check if settings are correct as orig DNAT with bidir was moved to SNAT with bidir
                //Todo: if source nat rule name is already available, add source destination snat to  dest rule nat, and disable source nat rule
                $this->get_XML_nat2($natRoot);
            }
        }



        //Todo: nat rule move : static, destination, source


        //calculate zones
        //zone recalculation based on NAT rules
        //rename interfaces

    }
}
