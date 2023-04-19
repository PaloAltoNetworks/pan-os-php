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



require_once("CISCOnetwork.php");
require_once("CISCOaddresses.php");
require_once("CISCOservices.php");
require_once("CISCOvpn.php");
require_once("CISCOsecurityrules.php");
require_once("CISCOnat.php");
require_once("CISCOtimerange.php");


class CISCOASA extends PARSER
{
    use CISCOaddresses;
    use CISCOnat;
    use CISCOnetwork;
    use CISCOsecurityrules;
    use CISCOservices;
    use CISCOvpn;
    use CISCOtimerange;

    use SHAREDNEW;

    public $isFirePower = 0;
    public $checkFirePower = 0;

    function addPrefixSuffix($check_prefix, $text_prefix, $check_suffix, $text_suffix, $name_pan, $max_char)
    {

        $name_pan_fin = $name_pan;

        if( $check_prefix == "on" )
        {
            $name_pan_fin = $text_prefix . $name_pan;
            if( strlen($name_pan_fin) > $max_char )
            {
                $total_name_pan_fin = strlen($name_pan_fin);
                $total_subs = $total_name_pan_fin - $max_char;
                $name_pan = substr($name_pan, 0, -$total_subs);
                $name_pan_fin = $text_prefix . $name_pan;
            }
        }
        if( $check_suffix == "on" )
        {
            $name_pan = $name_pan_fin;
            $name_pan_fin = $name_pan_fin . $text_suffix;
            if( strlen($name_pan_fin) > $max_char )
            {
                $total_name_pan_fin = strlen($name_pan_fin);
                $total_subs = $total_name_pan_fin - $max_char;
                $name_pan = substr($name_pan, 0, -$total_subs);
                $name_pan_fin = $name_pan . $text_suffix;
            }
        }
        return $name_pan_fin;
    }


    public function vendor_main()
    {



        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done
        global $print;
        $print = TRUE;
        global $tmp_template_vsys;

        $tmp_template_vsys = array();

        //CISCO specific
        //------------------------------------------------------------------------
        $this->clean_config();


        $this->import_config( ); //This should update the $source


        if( $this->isFirePower == 0 )
        {
            //Todo: validation if GLOBAL rule
            echo PH::boldText("Zone Calculation for Security and NAT policy");
            Converter::calculate_zones($this->template, $this->sub, "append");
        }



        echo PH::boldText("\nAuto Zone Assignment - before it was called: fix destination NAT:\n");
        //[0] -> $source; [1] -> $vsys
        //-> fix_destination_nat($config_path, $getSourceVsys[0], $getSourceVsys[1]);

        //disabled as calculate_zones() was done before
        #$this->fix_destination_nat( $this->data, $v );


        //fix needed for:
        //Todo: NAT - security NAT calculation in specific object change
        echo PH::boldText("\nrecalculation DST based on NAT:\n");
        echo "implementation missing\n";
        //Todo: if
        //????require_once INC_ROOT.'/libs/common/lib-rules.php';
        //-> recalculate_Dst_basedOn_NAT($projectdb, $getSourceVsys[0], $getSourceVsys[1], $vr_id, $project, 'Cisco');
        #$this->recalculate_Dst_basedOn_NAT( VirtualSystem $vsys, VirtualRouter $vr, STRING $vendor=null)





        echo PH::boldText("\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n");
        CONVERTER::validate_interface_names($this->template);


        echo PH::boldText("\nVALIDATION - cleanup Cisco predefined services - which are unused in PAN-OS\n");
        CONVERTER::cleanup_unused_predefined_services($this->sub, "default");


        //CISCO ASA specific  best practise set
        echo PH::boldText("\nreplace DM_INLINE address-/service-group by members [these are create from Cisco Device Manager]\n");
        $this->replaceByMembersAndDelete();


        echo PH::boldText("\nVALIDATION -  bidir NAT rules, disable bidir if not possible (e.g. SRC IP has addressgroup)\n");
        CONVERTER::validation_nat_bidir($this->template, $this->sub);

        echo PH::boldText("\nVALIDATION - Region name must not be used as a address / addressgroup object name\n");
        CONVERTER::validation_region_object($this->sub);

        //if security rule count is very high => memory leak problem
        //Todo: where to place custom table for app-migration if needed
        echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
        CONVERTER::AppMigration( $this->sub, $this->configType );


        //Todo: service with IP/tcp/udp - ANY are migrated as any;
        //DONE: BUT
        // if protocol ip found -> right now TCP is used !!!!!


        //Todo: global is not handled
        //Todo: bring in all warnings into XML file

        /*
                echo PH::boldText("\nrecalculation DST based on NAT:\n");
                echo "move up - not at the end\n";
                #$this->recalculate_Dst_basedOn_NAT( VirtualSystem $vsys, VirtualRouter $vr, STRING $vendor=null)
                $this->recalculate_Dst_basedOn_NAT( $pan, "cisco");
                */

        if( $this->isFirePower == 1 )
        {
            //instead of zone calculation perform rule merging / grouping
            $configInput = array();
            $configInput['type'] = 'file';
            $configInput['filename'] = $this->configInput;

            CONVERTER::rule_merging( $this->sub, $configInput, true, true, true, "tag", array( "1", "6", "5" ) );
        }



        CONVERTER::deleteDirectory( );
    }


    function clean_config()
    {

        $configFile = file($this->configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->data = array();
        foreach( $configFile as $line => $names_line )
        {

            if( (preg_match("/description/", $names_line)) or (preg_match("/remark/", $names_line)) )
            {
                #$this->data[] = $names_line;

                //Todo: SVEN 20191203 - problem with config "
                $tmp_array = explode("\r", $names_line);
                foreach( $tmp_array as $tmp_line )
                    $this->data[] = $tmp_line;
            }
            else
            {
                #"<--- More --->"
                if( preg_match("/^<--- More --->/", $names_line) || preg_match("/^              /", $names_line) )
                {

                }
                elseif( preg_match("/\'/", $names_line) )
                {
                    $this->data[] = str_replace("'", "_", $names_line);
                }
                elseif( preg_match("/\\r/", $names_line) )
                {
                    $tmp_array = explode("\r", $names_line);
                    foreach( $tmp_array as $tmp_line )
                        $this->data[] = $tmp_line;
                }
                else
                {
                    $this->data[] = $names_line;
                }
            }
        }
    }

    /**
     * @param PANConf $pan
     */

    function import_config( )
    {
        global $tmp_template_vsys;

        $routetable = $this->routetable;

        $vsysName = "Cisco";
        $vsysID = 1;

        $this->template_vsys = $this->template->findVSYS_by_displayName($vsysName);
        if( $this->template_vsys === null )
        {
            #print "VSYS: ".$vsysID." already available - check displayName ".$vsysName."\n";
            $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            $this->template_vsys->setAlternativeName($vsysName);

            $tmp_template_vsys[ $vsysName ] = intval($vsysID);
        }
        else
        {
            //create new vsys, search for latest ID
            do
            {
                $vsysID++;
                $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            } while( $this->template_vsys !== null );

            if( $this->template_vsys === null )
            {
                $this->template_vsys = $this->template->createVirtualSystem(intval($vsysID), $vsysName . $vsysID);
                if( $this->template_vsys === null )
                {
                    derr("vsys" . $vsysID . " could not be created ? Exit\n");
                }
                #print "create VSYS: ".$vsysID." - ".$vsysName."\n";

                $tmp_template_vsys[ $vsysName ] = intval($vsysID);

            }
        }

        echo PH::boldText("\ntime-range loaded\n");
        $this->get_time_range();

        //get all ACL where timeout is defined
        $timeouts = $this->getTimeOutClass();

        $aclsWithTimeouts = $timeouts['acls'];
        $servicesWithTimouts = $timeouts['services'];



        if( $routetable != "" )
        {
            echo PH::boldText("\nimport dynamic Routing:\n");
            $cisco = file_get_contents($routetable);
            $this->importDynamicRoutes($cisco);
        }


        echo PH::boldText("\nObject_network loaded\n");
        $this->get_object_network();


        echo PH::boldText("\nsave_names:\n");
        $this->save_names();


        echo PH::boldText("\nload custome application:\n");
        $this->load_custom_application();


        #get_interfaces($this->data, $source, $vsys, $template);
        echo PH::boldText("\nget interfaces:\n");
        $this->get_interfaces();

        #get_static_routes($this->data, $source, $vsys, $template);
        echo PH::boldText("\nget static routes\n");
        $this->get_static_routes();

        /* moved because of existing objects problem
            #get_object_network($this->data, $source, $vsys, $filename);
            get_object_network($this->data, $v);
            #$objectsInMemory->load_addresses_inMemory($parametersProject);
            echo "Object_network loaded\n";
        */

        #get_objectgroup_network2($this->data, $source, $vsys, $objectsInMemory, $filename);
        echo PH::boldText("\nObjectGroup_network loaded\n");
        $this->get_objectgroup_network2();

        #update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Loading Service Objects',$jobid);

        echo PH::boldText("\nCisco Services loaded\n");
        $this->addServicePredefined( "cisco" );


        echo PH::boldText("\nServices loaded\n");
        #get_object_service($this->data, $source, $vsys, $filename);
        $this->get_object_service();
        #$objectsInMemory->load_services_inMemory($parametersProject);


        echo PH::boldText("\nObject_services loaded\n");
        #get_objectgroup_service($this->data, $source, $vsys, $filename);
        $this->get_objectgroup_service();


        echo PH::boldText("\nProtocol groups loaded\n");
        #get_protocol_groups($this->data, $source, $vsys);
        $this->get_protocol_groups();


        #get_icmp_groups($this->data, $source, $vsys);
        echo PH::boldText("\nICMPGroups loaded\n");
        $this->get_icmp_groups();




        #update_progress($project, '0.30', 'File:' . $filename . ' Phase 2 Loading Nat Rules',$jobid);


        //Todo: continue working Sven Waschkut
        #get_twice_nats($this->data, $source, $vsys, $template,"before");
        echo PH::boldText("\nNAT twice 'before':\n");
        //Todo swaschkut 20210202
        //Firepower fixed needed for security rule reading
        $this->get_twice_nats("before");


        #get_objects_nat($this->data, $source, $vsys);
        echo PH::boldText("\nNAT objects:'\n");
        $this->get_objects_nat();


        #get_twice_nats($this->data, $source, $vsys, $template,"after");
        echo PH::boldText("\nNAT twice 'after':\n");
        $this->get_twice_nats("after");


        //Todo: SWASCHKUT if NAT rules count == 0 use old natpre83

        print "NAT counter: " . $this->sub->natRules->count() . "\n";

        if( $this->sub->natRules->count() == 0 )
        {
            echo PH::boldText("\nNAT pre83:\n");
            $this->natpre83();
        }


        /*
         *     $getNats=$projectdb->query("SELECT id FROM nat_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
            if ($getNats->num_rows==0){
                natpre83($source,$vsys,$this->data,$template);
            }
            */
        //update_progress($project, '0.45', 'File:' . $filename . ' Phase 2 Loading Security Rules',$jobid);


        $userObj = array();
        #get_objectgroup_user($this->data, $source, $vsys, $userObj);
        echo PH::boldText("\nget objectgroup user\n");
        $this->get_objectgroup_user( $userObj);


        /*
         * //Todo: needed??? Sven Waschkut
        $devicegroup = $filename;

        $objectsInMemory->createAllPortServices($devicegroup, $projectdb, $source, $vsys);
        $objectsInMemory->load_AllObjects_inMemory($parametersProject);
        echo "Objects loaded\n";
        //TODO: Remove this print_r
    //    print_r($objectsInMemory);
        $objectsInMemory->explodeAllGroups2Addresses($source, $vsys);
        echo "Groups expanded\n";
        $objectsInMemory->explodeAllGroups2Services($source, $vsys);
        echo "Services Expanded\n";
        $objectsInMemory->updateAddressGroupReferences($projectdb,$source, $vsys);
        echo "Address Groups updated\n";
        $objectsInMemory->updateServiceGroupReferences($projectdb,$source, $vsys);
        echo "Service Groups updated\n";
        $objectsInMemory->addUsers($devicegroup, $source, $vsys, $userObj);
    */


//    print_r($objectsInMemory);
        #get_security_policies2($devicegroup, $this->data, $source, $vsys, $objectsInMemory);
        echo PH::boldText("\nget security Policy\n");
        $this->get_security_policies2();


        //this is old one, replace with get_ipsec_vpn2
        //-> get_ipsec_vpn($config_path, $getSourceVsys[0], $getSourceVsys[1],$getSourceVsys[2],$jobid,$project);
        #get_ipsec_vpn2($config_path, $getSourceVsys[0], $getSourceVsys[1],$getSourceVsys[2],$jobid,$project);
        echo PH::boldText("\nget IPsec config - Reading VPN Rules\n");

        $this->get_ipsec_vpn2();



        echo "Fixing Service Timeouts based on ACL Groups\n";
        $this->fixServiceTimeouts( $aclsWithTimeouts, $servicesWithTimouts);




        //Todo: temp for working script
        return null;

#    update_progress($project, '0.65', 'File:' . $filename . ' Phase 2 Cleaning Zones',$jobid);

//    optimize_names2($this->data, $source, $vsys);
//    add_filename_to_objects($source, $vsys, $filename);
        //Todo: SVEN what to do here???????
        #$this->clean_zone_any($source, $vsys);

        /*
        check_invalid($source,$vsys,$template);
        // Call function to generate initial consumptions
        //deviceUsage("initial", "get", $project, $dusage_platform, $dusage_version, $vsys, $source, $dusage_template);
        deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);
        return array("$source", "$vsys","$template");
        */
    }

    static public function removeEnclosingQuotes( $value)
    {
        return trim($value, '"');
    }

    /***
     * @param STRING $value Such as US\\myUser
     * @return string        US\myUser
     */
    static public function removeDoubleBackSlash( $value)
    {
        $value = preg_replace('/\\\\+/', '\\', $value);
        return $value;
    }


    function get_objectgroup_user( array &$userObj)
    {
        global $projectdb;
        $isObjGroupUser = FALSE;
        $userObj = array();
        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);
            if( preg_match("/object-group user /", $names_line) )
            {
                $names = explode(" ", $names_line);
                $isObjGroupUser = TRUE;
                $name = $names[2];
                $userObj[$name] = array();
                continue;
            }
            if( $isObjGroupUser === TRUE )
            {
                if( preg_match("/user /", $names_line) )
                {
                    $user = str_replace("user ", "", $names_line);
                    $userObj[$name][] = trim($user, '"');
                }
                elseif( preg_match("/user-group /", $names_line) )
                {
                    $usergroup = str_replace("user-group ", "", $names_line);
                    $userObj[$name][] = trim($usergroup, '"');
                }
                else
                {
                    $isObjGroupUser = FALSE;
                }
            }
        }
    }

/*
    function add_filename_to_objects($source, $filename)
    {
        global $projectdb;

        $projectdb->query("UPDATE address SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
        $projectdb->query("UPDATE address_groups_id SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
        $projectdb->query("UPDATE services SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
        $projectdb->query("UPDATE services_groups_id SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
        $projectdb->query("UPDATE tag SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
    }
*/
/*
    function removeUnusedLabels(MySQLi $projectdb, STRING $source, STRING $vsys)
    {
        $objects = array();
        $labelObjects = array();
        $query = "SELECT * FROM address WHERE source='$source' AND vsys='$vsys'";
        $results = $projectdb->query($query);
        if( $results->num_rows > 0 )
        {
            while( $this->data = $results->fetch_assoc() )
            {
                $name = $this->data['name'];
                $objects[$name]['objects'][] = [
                    'name' => $this->data['name'],
                    'id' => $this->data['id'],
                    'vtype' => $this->data['vtype'],
                    'ipaddress' => $this->data['ipaddress'],
                    'cidr' => $this->data['cidr'],
                ];

                if( $this->data['vtype'] == 'label' )
                {
                    $labelObjects[$name] = [
                        'name' => $this->data['name'],
                        'id' => $this->data['id'],
                        'cidr' => $this->data['cidr'],
                    ];
                }
            }
        }

        $deleteableLables = array();
        foreach( $labelObjects as $labelName => $labelArray )
        {
            $count = $objects[$labelName]['objects'];
            if( $count > 1 )
            {
                $deleteableLables[] = $labelArray['id'];
            }
        }

        $query = "DELETE FROM address WHERE id in (" . implode(',', $deleteableLables) . ") AND description ='' AND cidr=0 ";
//    echo $query;
//    $projectdb->query($query);

    }
*/

#function save_names($this->data, $source, $vsys, $filename) {
    function save_names()
    {
        #global $projectdb;
        #$addName = array();

        global $debug;
        global $print;

        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);
            if( preg_match("/^name /i", $names_line) )
            {
                print "LINE: " . $names_line . "\n";

                $ipaddress = "";
                $name = "";
                $descriptiontrimmed = "";
                $description = "";

                $names = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $count = count($names);

                $ipaddress = $names[1];
                $ipversion = $this->ip_version($ipaddress);

                if( $ipversion == "v4" )
                {
                    $hostCidr = "32";
                }
                elseif( $ipversion == "v6" )
                {
                    //Todo: swaschkut 20191014 fix it
                    $hostCidr = "0";
                }
                else
                {
                    $ipversion = "v4";
                    $hostCidr = "32";
                }

                $name = rtrim($names[2]);
                $name_int = $this->truncate_names($this->normalizeNames($name));

                if( ($count > 3) and ($names[3] == "description") )
                {
                    $descriptiontrimmed = $names[4];
                    for( $i = 5; $i <= $count; $i++ )
                    {
                        if( isset($names[$i]) )
                        {
                            $descriptiontrimmed .= " " . $names[$i];
                        }
                    }
                }

                $description = addslashes($this->normalizeComments($descriptiontrimmed));
                $description = str_replace("\n", '', $description); // remove new lines
                $description = str_replace("\r", '', $description);

                $tmp_address = $this->sub->addressStore->find($name_int);
                if( $tmp_address === null )
                {
                    #newAddress($name , $type, $value, $description = '')
                    if( $print )
                        print " * create address object: " . $name_int . " , value: " . $ipaddress . ", CIDR: " . $hostCidr . "\n";
                    $tmp_address = $this->sub->addressStore->newAddress($name_int, 'ip-netmask', $ipaddress . "/" . $hostCidr);
                    $tmp_address->setDescription($description);
                }

                /*
                $getDup = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$name' AND source='$source';");
                if ($getDup->num_rows == 0) {
                    if ($ipversion == "v6") {
                        $addName[] = "('$name_int','ip-netmask','$ipaddress','$hostCidr','$name','0','$description','$source','0','1','label')";
                    } else {
                        $addName[] = "('$name_int','ip-netmask','$ipaddress','$hostCidr','$name','0','$description','$source','1','0','label')";
                    }
                }
                */
            }
        }

        /*
        if (count($addName) > 0) {
            $projectdb->query("INSERT INTO address (name,type,ipaddress,cidr,name_ext,checkit,description,source,v4,v6,vtype) values" . implode(",", $addName) . ";");
            unset($addName);
        }
        */
    }


    function optimize_names2( $source, $vsys)
    {
        global $projectdb;

        $get32s = $projectdb->query("SELECT id,name,ipaddress,cidr FROM address WHERE source='$source' AND vsys='$vsys' AND type='ip-netmask' AND name like '%-32';");
        if( $get32s->num_rows > 0 )
        {

        }

    }


    function clean_zone_any($source, $vsys)
    {

        global $projectdb;

        $getZoneAny = $projectdb->query("SELECT id FROM zones WHERE source = '$source' AND vsys = '$vsys' AND name = 'any';");
        if( $getZoneAny->num_rows > 0 )
        {
            $this->dataZ = $getZoneAny->fetch_assoc();
            $id_zone_any = $this->dataZ['id'];
            $projectdb->query("UPDATE zones SET name = 'any1' WHERE id = '$id_zone_any';");
            $projectdb->query("UPDATE nat_rules_from SET name = 'any1' WHERE source = '$source' AND vsys = '$vsys' AND name = 'any';");
            $projectdb->query("UPDATE nat_rules SET op_zone_to = 'any1' WHERE source = '$source' AND vsys = '$vsys' AND op_zone_to = 'any';");
        }
        else
        {
            // Clean any's
            $projectdb->query("DELETE FROM nat_rules_from WHERE source = '$source' AND vsys = '$vsys' AND name = 'any';");
            $projectdb->query("UPDATE nat_rules SET op_zone_to = '' WHERE source = '$source' AND vsys = '$vsys' AND op_zone_to = 'any';");
        }

    }

    function array_orderby()
    {
        $args = func_get_args();
        $this->data = array_shift($args);
        foreach( $args as $n => $field )
        {
            if( is_string($field) )
            {
                $tmp = array();
                foreach( $this->data as $key => $row )
                    $tmp[$key] = $row[$field];
                $args[$n] = $tmp;
            }
        }
        $args[] = &$this->data;
        call_user_func_array('array_multisort', $args);
        return array_pop($args);
    }

    function whatipaddress($ipaddress)
    {

        if( $this->ip_version($ipaddress) == "noip" )
        {
            $tmp_address = $this->sub->addressStore->find($ipaddress);
            if( $tmp_address !== null )
            {
                return $tmp_address->value();
            }
            else
            {
                mwarning("natpre83 - object: " . $ipaddress . " not found");
                return null;
            }
            /*
            $getIP = $projectdb->query("SELECT ipaddress FROM address WHERE BINARY name_ext='$ipaddress' AND source='$source' AND vsys='$vsys' LIMIT 1;");
            if ($getIP->num_rows == 1) {
                $getIPData = $getIP->fetch_assoc();
                return $getIPData['ipaddress'];
            }
            */
        }
        else
        {
            return $ipaddress;
        }
    }


# Library Functions
    static public function convertLifeTime($input, $entero, &$output_unit, &$output_value)
    {
        $output_value = $input;
        $output_unit = 1;
        //Seconds
        if( $output_value > 65535 )
        {
            $output_value = $output_value / 60;
            $output_unit++;
        }
        //Minutes
        if( $output_value > 65535 )
        {
            $output_value = $output_value / 60;
            $output_unit++;
        }
        //Hours
        if( $output_value > 65535 )
        {
            $output_value = $output_value / 24;
            $output_unit++;
        }
        //Days

        switch ($output_unit)
        {
            case 1:
                $output_unit = "seconds";
                break;
            case 2:
                $output_unit = "minutes";
                break;
            case 3:
                $output_unit = "hours";
                break;
            case 4:
                $output_unit = "days";
                break;
            default:
                $output_unit = "seconds";
                break;
        }

        if( $entero )
        {
            $output_value = round($output_value);
        }
    }

    function convertLifeSize($input, $entero, &$output_unit, &$output_value)
    {
        $output_value = $input;
        $output_unit = 1;
        while( $output_value > 65535 )
        {
            $output_value = $output_value / 1024;
            $output_unit++;
        }

        switch ($output_unit)
        {
            case 1:
                $output_unit = "kb";
                break;
            case 2:
                $output_unit = "mb";
                break;
            case 3:
                $output_unit = "gb";
                break;
            case 4:
                $output_unit = "tb";
                break;
            default:
                $output_unit = "kb";
                break;
        }

        if( $entero )
        {
            $output_value = round($output_value);
        }
    }


    /**
     * @param PANConf $pan
     */
    public function replaceByMembersAndDelete()
    {
        //difference between PAN-OS and Panorama
        if( $this->configType == "panos" )
            $vsyss = $this->pan->getVirtualSystems();
        else
            $vsyss = $this->pan->getDeviceGroups();

        foreach( $vsyss as $v )
        {
            foreach( $this->sub->addressStore->addressGroups() as $group )
            {
                if( strpos($group->name(), "INLINE") !== FALSE )
                {
                    $context = new AddressCallContext( null, "");

                    $context->padding = "   ";
                    $context->object = $group;
                    $context->arguments['keepgroupname'] = "*nodefault*";

                    $group->replaceByMembersAndDelete( $context, FALSE, TRUE, TRUE);
                }

            }

            foreach( $this->sub->serviceStore->serviceGroups() as $group )
            {
                if( strpos($group->name(), "INLINE") !== FALSE )
                {
                    $context = new ServiceCallContext( null, "");

                    $context->padding = "   ";
                    $context->object = $group;
                    $context->arguments['keepgroupname'] = "*nodefault*";

                    $group->replaceByMembersAndDelete($context, FALSE, TRUE, TRUE);
                }

            }
        }
    }

}
