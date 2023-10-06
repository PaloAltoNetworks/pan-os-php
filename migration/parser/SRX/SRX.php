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



require_once("lib/pan_php_framework.php");

require_once('SRXinterfaces.php');
require_once('SRXvsys.php');

require_once('SRXaddress.php');
require_once('SRXapplications.php');
require_once('SRXzone.php');
require_once('SRXstaticRoute.php');
require_once('SRXpolicy.php');
require_once('SRXnat.php');

require_once('SRXmisc_functions.php');

require_once('SRXike.php');
require_once('SRXipsec.php');

require_once('SRXfilter.php');


class SRX extends PARSER
{
    use SRXaddress;
    use SRXapplications;
    use SRXinterfaces;
    use SRXnat;
    use SRXpolicy;
    use SRXstaticRoute;
    use SRXvsys;
    use SRXzone;
    use SRXmisc_functions;
    use SRXike;
    use SRXipsec;
    use SRXfilter;

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
    public $filterInputInterface = array();
    public $filterOutputInterface = array();


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

        $this->import_config( ); //This should update the $source
        //------------------------------------------------------------------------

        echo PH::boldText("\nload custom application:\n");
        $this->load_custom_application();


        echo PH::boldText("\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n");
        CONVERTER::validate_interface_names($this->template);

        #

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
        #$data =  implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

        $data = file_get_contents($this->configFile);
        

/*

        print "POS: |".strpos($data, "rpc-reply")."|\n";
        if( strpos($data, "rpc-reply") === FALSE )
            print "FALSE\n";

        print "__________________________________\n";
        print $data;
        print "__________________________________\n";
*/
        if( strpos($data, "rpc-reply xmlns:junos=") === FALSE )
        {
            $tmp_version = $this->find_string_between($data, "<version>", "</version>");
            $tmp_version_arr = explode("-", $tmp_version);
            #print_r( $tmp_version_arr );
            $tmp_version = $tmp_version_arr[0];
            //"<version>12.3X48-D35.7</version>"

            $tmp_start = "<rpc-reply xmlns:junos=\"http://xml.juniper.net/junos/" . $tmp_version . "/junos\">\n";
            $tmp_end = "\n</rpc-reply>";

            $data = $tmp_start . $data . $tmp_end;
        }



/*
        derr( ' fix it');
*/


        $doc = new DOMDocument();
        $doc->loadXML($data, XML_PARSE_BIG_LINES);


        $root = $doc->documentElement; // Root node
        $configRoot = $root;

        /*
        $configRoot = DH::findFirstElement('rpc-reply', $configRoot);
        if( $configRoot === FALSE )
            derr("<rpc-reply> was not found", $root);
*/

        print "NAME: '".$configRoot->nodeName."'\n";

        if( $configRoot->nodeName == "rpc-reply" )
        {
            $configRoot = DH::findFirstElement('configuration', $configRoot);
            if( $configRoot === FALSE )
            {
                derr("<configuration> was not found", $root);
            }

            DH::makeElementAsRoot($configRoot, $root);
        }
        elseif( $configRoot->nodeName == "configuration" )
        {

        }
        else
            derr("<configuration> was not found", $root);



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


    public function import_config()
    {
        global $LSYS_bool;

        $root = $this->data;

        $this->xml_validation($this->data);


        //todo: import all logical-systems


        $lsystems = DH::findXPath( '/logical-systems', $root );
        #print "counter: ".count($lsystems)."\n";

        $groups = false;
        if( count($lsystems) == 0 )
        {
            //check if groups are available and import groups into different vsys
            $lsystems = DH::findXPath( '/groups', $root );
            #$lsystems = DH::findXPath( '/system', $lsystems );
            $groups = true;
        }


        if( count($lsystems) > 0 )
        {
            $LSYS_bool = true;
            //import the below info into shared
            $this->create_vsys();
            $this->import_lsys(  $root, true );

            //create new vsys per lsys and import

            foreach( $lsystems as $lsys )
            {
                if( $lsys->nodeType != 1 ) continue;


                $name = DH::findFirstElement('name', $lsys);
                $system = DH::findFirstElement('system', $lsys);

                if( $system )
                {
                    #if( !$groups ){
                    print "create LSYS: ".$name->nodeValue."\n";
                    $this->create_vsys( $name->nodeValue);
                    #}

                    $this->import_lsys(  $lsys, false, $groups );
                }


            }
        }
        else
        {
            //import the below info into vsys1
            $this->create_vsys();
            $this->import_lsys( $root );

            //Todo: XML node groups are not migrated
        }


    }

    public function import_lsys( $root, $shared = false, $groups = false )
    {
        //IMPORT all which can be also none LSYS info


        if( !$groups )
        {
            print "\nadd_junos_services:\n";
            $this->addServicePredefined( "junos" );
        }


        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter( $this->template_vsys->name()."_router" );
        if( $tmp_vr == null )
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($this->template_vsys->name()."_router");

        $this->template_vsys->importedVirtualRouter->addVirtualRouter($tmp_vr);


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
            $this->get_XML_staticRoutes($staticrouteRoot, $shared, $tmp_vr);

        $staticrouteRoot = DH::findFirstElement('routing-options', $root);
        if( $staticrouteRoot === FALSE )
            mwarning("<routing-options> was not found", $root);
        else
        {
            $this->addRoutingOptions( $staticrouteRoot, $tmp_vr );
        }




        $filterRoot = false;
        $filterRoot6 = false;
        $firewallRoot = DH::findFirstElement('firewall', $root);
        if( $firewallRoot !== FALSE )
        {
            $familyRoot = DH::findFirstElement('family', $firewallRoot);
            if( $familyRoot !== FALSE )
            {
                $inetRoot = DH::findFirstElement('inet', $familyRoot);
                if( $inetRoot !== FALSE )
                {
                    #$filterRoot = DH::findFirstElement('filter', $inetRoot);

                    $filterRoot = $inetRoot->getElementsByTagName('filter');
                }

                $inetRoot6 = DH::findFirstElement('inet6', $familyRoot);
                if( $inetRoot6 !== FALSE )
                {
                    #$filterRoot = DH::findFirstElement('filter', $inetRoot);

                    $filterRoot6 = $inetRoot6->getElementsByTagName('filter');
                }
            }

        }




        $securityRoot = DH::findFirstElement('security', $root);
        if( $securityRoot === FALSE )
            mwarning("<security> was not found", $root);


        if( $securityRoot !== FALSE )
        {
            $addressbookRoots = $securityRoot->getElementsByTagName( 'address-book' );

            foreach( $addressbookRoots as $addressbookRoot )
            {
                print "\nAddress objects:\n";
                #$addressbookRoots = DH::findFirstElement('address-book', $securityRoot);
                #if( $addressbookRoot !== FALSE )
                    $this->get_XML_Zones_Address_All_new2($addressbookRoot);
                #else mwarning("<address-book> was not found directly under SECURITY", null, FALSE);
            }




            print "\nZone objects: \n";
            $zonesRoot = DH::findFirstElement('zones', $securityRoot);
            if( $zonesRoot === FALSE )
            {
                mwarning("<zones> was not found", null, FALSE);
            }
            else
                $this->get_XML_Zones($zonesRoot, $shared);


            //////////
            if( $filterRoot !== false )
            {
                foreach( $this->filterInputInterface as $filter => $interfaces )
                {
                    foreach( $interfaces as $key => $interface )
                    {
                        $tmp_zone = $this->template_vsys->zoneStore->findZoneMatchingInterfaceName($interface);
                        $this->filterInputInterface[$filter][$key] = $tmp_zone;
                    }
                }
                foreach( $this->filterOutputInterface as $filter => $interfaces )
                {
                    foreach( $interfaces as $key => $interface )
                    {
                        $tmp_zone = $this->template_vsys->zoneStore->findZoneMatchingInterfaceName($interface);
                        $this->filterOutputInterface[$filter][$key] = $tmp_zone;
                    }
                }

                $this->get_XML_filter( $filterRoot );

                if( $filterRoot6 !== false )
                    $this->get_XML_filter( $filterRoot6, "ipv6_" );
            }
            ////////////////


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
                $this->get_XML_IPSEC($ipsecRoot,  $shared);




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
