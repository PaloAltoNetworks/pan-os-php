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


require_once("FORTINETaddresses.php");

require_once("FORTINETnatrules.php");
require_once("FORTINETnetwork.php");

require_once("FORTINETsecurityrules.php");
require_once("FORTINETservices.php");

require_once ( "FORTINETipsec.php" );


class FORTINET extends PARSER
{

    use FORTINETaddresses;
    use FORTINETnatrules;
    use FORTINETnetwork;
    use FORTINETsecurityrules;
    use FORTINETservices;
    use FORTINETipsec;
    use SHAREDNEW;

    public $tunnelinterface = array();

    function vendor_main()
    {

        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done
        global $print;
        $print = TRUE;
        global $tmp_template_vsys;

        $tmp_template_vsys = array();

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
        echo PH::boldText("Zone Calculation for Security and NAT policy");
        Converter::calculate_zones($this->template, $this->sub, "append");


        echo PH::boldText("\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n");
        CONVERTER::validate_interface_names($this->template);

        //Todo: where to place custom table for app-migration if needed
        echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
        CONVERTER::AppMigration($this->sub, $this->configType);

        CONVERTER::deleteDirectory( );
    }

    function clean_config()
    {

        $config_file = file($this->configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->data = array();
        foreach( $config_file as $line => $names_line )
        {
            $this->data[] = $names_line;
            /*
                if ((preg_match("/description/", $names_line)) OR ( preg_match("/remark/", $names_line))) {
                    $data[] = $names_line;
                }
                else {
                    #"<--- More --->"
                    if( preg_match("/^<--- More --->/", $names_line) || preg_match("/^              /", $names_line) )
                    {

                    }
                    elseif (preg_match("/\'/", $names_line)) {
                        $data[] = str_replace("'", "_", $names_line);
                    } else {
                        $data[] = $names_line;
                    }
                }
            */
        }
    }

    function check_vdom_start(&$START, &$VDOM, $names_line, $lastline, $vsys)
    {
        global $tmp_template_vsys;

        if( $START == FALSE )
        {
            if( preg_match("/^config vdom/i", $names_line) )
            {
                $VDOM = TRUE;
            }
            if( $VDOM == TRUE )
            {
                #if (preg_match("/^edit $vsys/i", $names_line)) {
                if( "edit " . $vsys == $names_line )
                {
                    $START = TRUE;
                }
            }
        }
        else
        {
            if( (preg_match("/^end/i", $lastline)) and (preg_match("/^end/i", $names_line)) )
            {
                $START = FALSE;
                $VDOM = FALSE;
            }
            elseif( (preg_match("/^edit/i", $lastline)) and (preg_match("/^end/i", $names_line)) )
            {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }
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

        global $tmp_template_vsys;




        # Capture Sources Filename+vsys(vdom)
        $invdom = FALSE;
        $vsysID = 1;
        $ismultiornot = "singlevsys";

        foreach( $this->data as $line => $names_line )
        {
            if( preg_match("/^config vdom/i", $names_line) )
            {
                $invdom = TRUE;
            }
            elseif( (preg_match("/^end/i", $names_line)) and ($invdom == TRUE) )
            {
                $invdom = FALSE;
            }
            elseif( preg_match("/config\-version=/i", $names_line) )
            {
                $getVer = explode(":", $names_line);
                $ver = explode("=", $getVer[0]);
                $version = $ver[1];
            }

            if( ($invdom) and (preg_match("/^edit /i", $names_line)) )
            {
                $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                $vsys = $data1[1];
                $vsysName = $data1[1];

                $this->template_vsys = $this->template->findVSYS_by_displayName($vsysName);

                if( $this->template_vsys === null && $vsysID == 1 )
                {
                    $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);

                    if( $this->template_vsys !== null )
                    {
                        if( $print )
                            print "set vsys" . $vsysID . " alternativeName to: " . $vsysName . "\n";


                        $this->template_vsys->setAlternativeName($vsysName);
                        //carefull - not set if Panroama template vsys!!!! workarond
                        $tmp_template_vsys[ $vsysName ] = intval($vsysID);
                        $vsysID++;
                    }
                }

                if( $this->template_vsys === null )
                {
                    //Panorama template does not have vsys displayname:
                    //workaround

                    if( isset( $tmp_template_vsys[ $vsysName ] ) )
                        continue;

                    /*
                    //create new vsys, search for latest ID
                    do
                    {
                        $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
                        if( $this->template_vsys !== null )
                            $vsysID++;
                    } while( $this->template_vsys !== null );

                    if( $this->template_vsys === null )
                    {
                        */
                        if( $print )
                            print " * create vsys: " . $vsysID . " - " . $vsysName . "\n";
                        $this->template_vsys = $this->template->createVirtualSystem(intval($vsysID), $vsysName);
                        $tmp_template_vsys[ $vsysName ] = intval($vsysID);

                        $vsysID++;
                        if( $this->template_vsys === null )
                        {
                            derr("vsys" . $vsysID . " could not be created ? Exit\n");
                        }
                    //}
                }

                //vsys created

                //panorama DG
                //validation part 20201202 SVEN
                if( $this->configType == "panorama" )
                {
                    $this->sub = $this->pan->findDeviceGroup( $vsysName );
                    if( $this->sub == null )
                    {
                        print " * create DG: ".$vsysName."\n";
                        $this->sub = $this->pan->createDeviceGroup( $vsysName );
                    }
/*
                    else
                    {
                        do
                        {
                            $this->objectsLocationCounter++;
                            $this->sub = $this->pan->findDeviceGroup( $vsysName.$this->objectsLocationCounter );
                        }
                        while( $this->sub != null );

                        print " * create DG: ".$vsysName.$this->objectsLocationCounter."\n";
                        $this->sub = $this->pan->createDeviceGroup(  $vsysName.$this->objectsLocationCounter );
                    }
*/
                }



                /*
                $getDup = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' AND vsys='$vsys';");
                if ($getDup->num_rows == 0) {
                    $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','$vsys','0','FORTINET')");
                    $config_filename = $projectdb->insert_id;
                    $source = $config_filename;
                }
                */
            }
        }

        $all_vsys = $this->template->getVirtualSystems();
        $counter = 0;
        foreach( $all_vsys as $vsys )
        {
            #print "vsys: ".$vsys->name()." - ".$vsys->alternativeName()."\n";
            $counter++;
        }

        if( $counter == 1 )
        {
            $ismultiornot = "singlevsys";
        }
        elseif( $counter > 1 )
        {
            $ismultiornot = "multivsys";
        }

        #derr( "stop vsys" );

        /*
            #Check if Vdoms were created or its a simple config, then create a default vsys1
            $isVdom = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename'");
            if ($isVdom->num_rows == 0) {
                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','root','0','FORTINET')");
                $config_filename = $projectdb->insert_id;
                $source = $config_filename;
            }


            # Bucle from Devices_mappings to get Objects and Rules
            $getDM = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
            if ($getDM->num_rows == 1) {
                $ismultiornot = "singlevsys";
            } elseif ($getDM->num_rows > 1) {
                $ismultiornot = "multivsys";
                #Add Shared context
                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','shared','0','FORTINET')");
            }
            #Get Source (First row for this filename)
            $getSource = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' GROUP by filename;");
            $getSourceData = $getSource->fetch_assoc();
            $source = $getSourceData['id'];
        */


        #Add Defautl Services
        print "\nadd fortinet services:\n";
        $this->add_fortinet_services($ismultiornot, $source);
#    add_default_services($source);
        //add_default_profiles($source);
        #Config Template
        /*
        $template_name = "default_template" . $source;
        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
        $template = $projectdb->insert_id;
    */



        #Add Interfaces
        #get_interfaces($fortinet_config_file, $vsys, $source, $template, $ismultiornot);
        print "\nget interfaces:\n";
        $this->get_interfaces( $ismultiornot);


        #Add IPsec
        #get_interfaces($fortinet_config_file, $vsys, $source, $template, $ismultiornot);
        print "\nget IPsec:\n";
        $this->get_ipsec( $ismultiornot);


        //Validation

        $all_vsys = $this->template->getVirtualSystems();

        foreach( $all_vsys as $v )
        {
            if( $this->configType == "panos" )
                $this->sub = $v;
            else
            {
                $tmp_search = str_replace( "vsys", "", $v->name() );
                $vsys_name = array_search( $tmp_search, $tmp_template_vsys);
                $this->sub = $this->pan->findDeviceGroup( $vsys_name );

                if( $this->sub == null )
                {
                    print " * create DG: ".$vsys_name."\n";
                    $this->sub = $this->pan->createDeviceGroup( $vsys_name );
                }
            }

            $this->template_vsys = $v;



            //Todo: panorama->DG
            #$this->sub

            $regions = array();
            $addVIP = array();

            if( $this->configType == "panos" )
                print PH::boldText("\n\ndo migration for VSYS: " . $v->name() . "\n");
            else
            {
                print PH::boldText("\n\ndo migration for template_vsys: " . $v->name() . " and DG ".$this->sub->name()."\n");
            }

            #update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Reading Zones ('.$vsys_name.')',$jobid);
            print PH::boldText("\nget zones:\n");

            //$this->template_vsys
            $this->get_zones( $ismultiornot);


            #update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Reading IP Pools and VIPs ('.$vsys_name.')',$jobid);
            print PH::boldText("\nget ippools:\n");
            $this->get_ippools(  $ismultiornot);

            print PH::boldText("\nget vip:\n");
            $this->get_vip( $ismultiornot, $addVIP);

            print PH::boldText("\nget vipgrp:\n");
            $this->get_vipgrp( $ismultiornot, $addVIP);


            #update_progress($project, '0.30', 'File:' . $filename . ' Phase 3 Reading Address and Groups ('.$vsys_name.')',$jobid);

            #get_address_Fortinet($fortinet_config_file, $source, $vsys_name, $ismultiornot, $regions);
            print PH::boldText("\nget address objects:\n");
            $this->get_address_Fortinet( $ismultiornot, $regions);

            print PH::boldText("\nget IPv6 address objects:\n");
            $this->get_addressv6(  $ismultiornot, $regions);

            print PH::boldText("\nget addressgroup objects:\n");
            $this->get_address_groups(  $ismultiornot, $regions);
            //Todo: SWASCHKUT 20190920
            //WHAT about "config firewall addrgrp6" ?????
            //check in multivsys devices why so many objects are already available within one VSYS


            #update_progress($project, '0.40', 'File:' . $filename . ' Phase 4 Reading Services and Groups ('.$vsys.')',$jobid);
            print PH::boldText("\nget service objects:\n");
            $this->get_services2($this->data, $source, $ismultiornot);

            print PH::boldText("\nget servicegroup objects:\n");
            $this->get_services_groups($this->data, $source, $ismultiornot);
            #clean_duplicated_services($source, $vsys, $ismultiornot);


            #update_progress($project, '0.50', 'File:' . $filename . ' Phase 5 Reading Security Policies ('.$vsys.')',$jobid);
            print PH::boldText("\nget security policy:\n");
            $this->get_security_policy($this->data, $source, $ismultiornot, $regions);


            #update_progress($project, '0.60', 'File:' . $filename . ' Phase 6 Reading Nat Policies ('.$vsys.')',$jobid);
            //Todo: SWASCHKUT 20191009
            //continue here:
            print PH::boldText("\nadd nat from VIP:\n");
            $this->add_nat_from_vip($this->data,  $source, $ismultiornot, $addVIP);

                //    fix_dupli1cated_rulenames($source,$vsys,'security_rules',0);
                  //  fix_duplicated_rulenames($source,$vsys,'nat_rules',0);

                //    remove_regions_from_nat($source,$vsys);

        }


        return null;

        /*
        $getDM = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
        while ($data = $getDM->fetch_assoc()) {
            $vsys = $data['vsys'];
            update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Reading Zones ('.$vsys.')',$jobid);
            get_zones($fortinet_config_file, $vsys, $source, $template, $ismultiornot);
            update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Reading IP Pools and VIPs ('.$vsys.')',$jobid);
            get_ippools($fortinet_config_file, $source, $vsys, $ismultiornot);
            get_vip($fortinet_config_file, $source, $vsys, $ismultiornot);
            get_vipgrp($fortinet_config_file, $source, $vsys, $ismultiornot);
            update_progress($project, '0.30', 'File:' . $filename . ' Phase 3 Reading Address and Groups ('.$vsys.')',$jobid);
            $regions=array();
            get_address_Fortinet($fortinet_config_file, $source, $vsys, $ismultiornot, $regions);
            get_addressv6($fortinet_config_file, $source, $vsys, $ismultiornot, $regions);
            get_address_groups($fortinet_config_file, $source, $vsys, $ismultiornot, $regions);
            update_progress($project, '0.40', 'File:' . $filename . ' Phase 4 Reading Services and Groups ('.$vsys.')',$jobid);
            get_services2($fortinet_config_file, $source, $vsys, $ismultiornot);
            get_services_groups($fortinet_config_file, $source, $vsys, $ismultiornot);
            clean_duplicated_services($source, $vsys, $ismultiornot);
            update_progress($project, '0.50', 'File:' . $filename . ' Phase 5 Reading Security Policies ('.$vsys.')',$jobid);
            get_security_policy($fortinet_config_file, $source, $vsys, $ismultiornot,$regions);
            update_progress($project, '0.60', 'File:' . $filename . ' Phase 6 Reading Nat Policies ('.$vsys.')',$jobid);
            add_nat_from_vip($fortinet_config_file, $vsys, $source, $template, $ismultiornot);
            fix_dupli1cated_rulenames($source,$vsys,'security_rules',0);
            fix_duplicated_rulenames($source,$vsys,'nat_rules',0);
            remove_regions_from_nat($source,$vsys);
            #check_used_objects($source);
        }
        */
        ##check_used_objects_new();
// Call function to generate initial consumptions
        ##deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);
    }

    /*
     * not needed anymore
    function clean_duplicated_services($source, $vsys, $ismultiornot){

        global $projectdb;

        $table = "services";
        $table_group = "services_groups";
        $table_group_id = "services_groups_id";

        if ($ismultiornot == "multivsys") {
            $vsys = "shared";
        } else {
            $vsys = "root";
        }

        $getDup=$projectdb->query("SELECT name,count(id) as t FROM $table WHERE source='$source' AND vsys='$vsys' GROUP BY name HAVING t>1 ORDER BY id;");
        if ($getDup->num_rows > 0){
            $srvname=[];
            while($data=$getDup->fetch_assoc()){
                $srvname[]=$data['name'];
            }
            foreach ($srvname as $name){
                $projectdb->query("DELETE FROM $table WHERE source='$source' AND vsys='$vsys' AND name='$name' AND devicegroup='predefined';");
            }
        }

        $getDup=$projectdb->query("SELECT name,count(id) as t FROM $table_group_id WHERE source='$source' AND vsys='$vsys' GROUP BY name HAVING t>1 ORDER BY id;");
        if ($getDup->num_rows > 0){
            $srvname=[];
            while($data=$getDup->fetch_assoc()){
                $srvname[]=$data['name'];
            }
            foreach ($srvname as $name){
                $getMembers=$projectdb->query("SELECT id FROM $table_group_id WHERE source='$source' AND vsys='$vsys' AND name='$name' AND devicegroup='predefined';");
                if ($getMembers->num_rows==1){
                    $getMembersData=$getMembers->fetch_assoc();
                    $glid=$getMembersData['id'];
                    $projectdb->query("DELETE FROM $table_group_id WHERE source='$source' AND vsys='$vsys' AND name='$name' AND devicegroup='predefined';");
                    $projectdb->query("DELETE FROM $table_group WHERE lid='$glid';");
                }

            }
        }

    }

    function add_vsys($source, $projectdb, $vsys) {
    # ADD VSYS
        $getVsys = $projectdb->query("SELECT name FROM virtual_systems WHERE source='$source' ORDER BY name DESC LIMIT 1;");

        if ($getVsys->num_rows == 0) {
            $vsys_name = "root";
            $projectdb->query("INSERT INTO virtual_systems (source,name,display_name) VALUES ('$source','$vsys_name','$vsys')");
        } else {
            $getVsysData = $getVsys->fetch_assoc();
            $thename = $getVsysData['name'];
            $getVsysData1 = str_replace("vsys", "", $thename);
            $result = intval($getVsysData1) + 1;
            $vsys_name = "vsys" . $result;
            $projectdb->query("INSERT INTO virtual_systems (source,name,display_name) VALUES ('$source','$vsys_name','$vsys')");
        }
    }
    */

}


