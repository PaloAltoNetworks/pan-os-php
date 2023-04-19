<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/shared.php';
require_once INC_ROOT . '/libs/projectdb.php';
require_once INC_ROOT . '/libs/common/lib-rules.php';
require_once INC_ROOT . '/libs/objects/SecurityRulePANObject.php';

$checkpointName = "";

require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
global $app;
//Capture request paramenters
include INC_ROOT . '/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);


//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

$sourcesAdded = array();
global $source;

if( $action == "import" )
{
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    if( is_dir(USERSPACE_PATH . "/projects/" . $project . "/XGS") )
    {
        update_progress($project, '0.00', 'Reading config files', $jobid);

        if( $checkpointName == "" )
        {
            $filename = unique_id(10);
        }
        else
        {
            $filename = $checkpointName;
        }

        $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
        if( $getVsys->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','vsys1','xgs')");
            $vsys = "vsys1";
            $source = $projectdb->insert_id;
        }
        else
        {
            $getVsysData = $getVsys->fetch_assoc();
            $vsys = $getVsysData['vsys'];
            $source = $getVsysData['id'];
        }

        $sourcesAdded[] = $source;

        #Config Template
        $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
        $template_name = $filename . "_template";
        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
        $template = $projectdb->insert_id;

        # Init vars
        $common = [];
        $fullObject = [];

        $addNetworksv4 = array();
        $addNetworksv6 = array();
        $addServices = array();
        $addAddressGroups = array();
        $addAddressMembers = array();
        $addServicesGroups = array();
        $addServicesMembers = array();
        $remoteServers = array();
        $remoteGroups = array();

        $base_folder = USERSPACE_PATH . "/projects/" . $project . "/XGS/etc/policies/cml/alps";

        # Max id from Address
        $get_glid = $projectdb->query("SELECT max(id) as glid FROM address;");
        if( $get_glid->num_rows == 1 )
        {
            $get_glidData = $get_glid->fetch_assoc();
            $address_lid = $get_glidData['glid'] + 1;
        }
        else
        {
            $address_lid = 1;
        }

        # Max id from Services
        $get_glid = $projectdb->query("SELECT max(id) as glid FROM services;");
        if( $get_glid->num_rows == 1 )
        {
            $get_glidData = $get_glid->fetch_assoc();
            $services_lid = $get_glidData['glid'] + 1;
        }
        else
        {
            $services_lid = 1;
        }

        # Max id for Address Groups aglid
        $get_glid = $projectdb->query("SELECT max(id) as glid FROM address_groups_id;");
        if( $get_glid->num_rows == 1 )
        {
            $get_glidData = $get_glid->fetch_assoc();
            $aglid = $get_glidData['glid'] + 1;
        }
        else
        {
            $aglid = 1;
        }

        # Max id for Services Groups sglid
        $get_glid = $projectdb->query("SELECT max(id) as glid FROM services_groups_id;");
        if( $get_glid->num_rows == 1 )
        {
            $get_glidData = $get_glid->fetch_assoc();
            $sglid = $get_glidData['glid'] + 1;
        }
        else
        {
            $sglid = 1;
        }

        # Max id for Profiles pglid
        $get_glid = $projectdb->query("SELECT max(id) as plid FROM profiles;");
        if( $get_glid->num_rows == 1 )
        {
            $get_glidData = $get_glid->fetch_assoc();
            $plid = $get_glidData['plid'] + 1;
        }
        else
        {
            $plid = 1;
        }

        # Read addr_host
        if( is_dir($base_folder . "/addr_host") )
        {
            $files = scandir($base_folder . "/addr_host");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/addr_host/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                foreach( $xml->HostAddressObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $value = $b['Value'];
                    $name_int = truncate_names(normalizeNames(trim($b['Name'])));
                    $description = addslashes($b['Comment']);
                    $type = $b['ObjType'];

                    if( !isset($fullObject[$name]) )
                    {
                        $ipversion = ip_version($value);
                        if( $ipversion == "v4" )
                        {
                            $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$value','','$name','$name_int','0','1','$description','$source','$filename')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                        elseif( $ipversion == "v6" )
                        {
                            $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$value','','$name','$name_int','0','1','$description','$source','$filename')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                        else
                        {
                            print "ERROR NO IP " . $name_int . " value:" . $value . "\n";
                        }
                    }
                }

                foreach( $xml->AnyAddress as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $common["any"][] = $name;
                }
            }
        }

        # Read addr_mask
        if( is_dir($base_folder . "/addr_mask") )
        {
            $files = scandir($base_folder . "/addr_mask");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/addr_mask/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                foreach( $xml->MaskAddressObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    list($ip0, $mask0) = explode("/", $b['Value']);
                    $name_int = truncate_names(normalizeNames(trim($b['Name'])));
                    $description = addslashes($b['Comment']);
                    $type = $b['ObjType'];

                    if( !isset($fullObject[$name]) )
                    {
                        $ipversion = ip_version($value);
                        if( $ipversion == "v4" )
                        {
                            $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip0','$mask0','$name','$name_int','0','1','$description','$source','$filename')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                        elseif( $ipversion == "v6" )
                        {
                            $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip0','$mask0','$name','$name_int','0','1','$description','$source','$filename')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                        else
                        {
                            print "ERROR NO IP " . $name_int . " value:" . $value . "\n";
                        }
                    }
                }
            }
        }

        # Read IP-Ranges
        if( is_dir($base_folder . "/addr_range") )
        {
            $files = scandir($base_folder . "/addr_range");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/addr_range/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                foreach( $xml->RangeAddressObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $value = $b['Value'];
                    $name_int = truncate_names(normalizeNames(trim($b['Name'])));
                    $description = addslashes($b['Comment']);
                    $type = $b['ObjType'];

                    if( !isset($fullObject[$name]) )
                    {
                        list($ip0, $ip1) = explode("-", $value);
                        $ipversion = ip_version($ip0);
                        if( $ipversion == "v4" )
                        {
                            $addNetworksv4[] = "('$address_lid','ip-range','ip-range','$value','','$name','$name_int','0','1','$description','$source','$filename')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                        elseif( $ipversion == "v6" )
                        {
                            $addNetworksv6[] = "('$address_lid','ip-range','ip-range','$value','','$name','$name_int','0','1','$description','$source','$filename')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                        else
                        {
                            print "ERROR NO IP " . $name_int . " value:" . $value . "\n";
                        }
                    }
                }

            }
        }

        # Read Addr_List
        if( is_dir($base_folder . "/addr_list") )
        {
            $files = scandir($base_folder . "/addr_list");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/addr_list/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                foreach( $xml->ListAddressObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $value = $b['Value'];
                    $name_int = truncate_names(normalizeNames(trim($b['Name'])));
                    $description = addslashes($b['Comment']);
                    $type = $b['ObjType'];
                    $ExcludeAddresses = $b['ExcludeAddresses'];
                    # ToDo: Take in consideration ExcludeAddresses
                    # ToDo: Now is not considered
                    if( !isset($fullObject[$name]) )
                    {
                        $addAddressGroups[] = "('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                        $fullObject[$name]["member_lid"] = $aglid;
                        $fullObject[$name]["table_name"] = "address_groups_id";
                        $parentAG = $aglid;
                        $aglid++;
                        $value_exploded = explode(",", $value);
                        foreach( $value_exploded as $vvalue )
                        {
                            if( isset($fullObject[$vvalue]) )
                            {
                                $member_lid = $fullObject[$vvalue]["member_lid"];
                                $table_name = $fullObject[$vvalue]["table_name"];
                                $addAddressMembers[] = "('$vsys','" . $vvalue . "','$parentAG','$source','$member_lid','$table_name')";
                            }
                            else
                            {
                                $ipversion = ip_version($vvalue);
                                $name = "IP-" . $vvalue;
                                if( $ipversion == "v4" )
                                {
                                    $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$vvalue','','$vvalue','$name','0','1','IP Created by Expedition From List $name_int','$source','$filename')";
                                    $fullObject[$vvalue]["table_name"] = "address";
                                    $fullObject[$vvalue]["member_lid"] = $address_lid;
                                    $address_lid++;
                                    $member_lid = $fullObject[$vvalue]["member_lid"];
                                    $table_name = $fullObject[$vvalue]["table_name"];
                                    $addAddressMembers[] = "('$vsys','" . $vvalue . "','$parentAG','$source','$member_lid','$table_name')";
                                }
                                elseif( $ipversion == "v6" )
                                {
                                    $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$vvalue','','$vvalue','$name','0','1','IP Created by Expedition From List $name_int','$source','$filename')";
                                    $fullObject[$vvalue]["table_name"] = "address";
                                    $fullObject[$vvalue]["member_lid"] = $address_lid;
                                    $address_lid++;
                                    $member_lid = $fullObject[$vvalue]["member_lid"];
                                    $table_name = $fullObject[$vvalue]["table_name"];
                                    $addAddressMembers[] = "('$vsys','" . $vvalue . "','$parentAG','$source','$member_lid','$table_name')";
                                }
                                else
                                {
                                    print "ERROR NO IP " . $name_int . " value:" . $value . "\n";
                                }
                            }

                        }
                    }
                }

            }
        }

        # Read Address Groups
        if( is_dir($base_folder . "/address_collection") )
        {
            $files = scandir($base_folder . "/address_collection");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/address_collection/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                foreach( $xml->AddressCollectionObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $value = $b['Value'];
                    $name_int = truncate_names(normalizeNames(trim($b['Name'])));
                    $description = addslashes($b['Comment']);
                    $type = $b['ObjType'];

                    if( !isset($fullObject[$name]) )
                    {
                        $addAddressGroups[] = "('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                        $fullObject[$name]["member_lid"] = $aglid;
                        $fullObject[$name]["table_name"] = "address_groups_id";
                        $parentAG = $aglid;
                        $aglid++;

                        foreach( $b->Address as $bb )
                        {
                            $memberUID = trim($bb['UUID']);

                            if( isset($fullObject[$memberUID]) )
                            {
                                $member_lid = $fullObject[$memberUID]["member_lid"];
                                $table_name = $fullObject[$memberUID]["table_name"];
                                $addAddressMembers[] = "('$vsys','" . $vvalue . "','$parentAG','$source','$member_lid','$table_name')";
                            }
                            else
                            {
                                print "ERROR NOT FOUND MEMBER BY UUID $memberUID in Group " . $name_int . "\n";
                            }
                        }
                    }
                }

            }
        }

        # Read Services / Apps
        if( is_dir($base_folder . "/app_pam") )
        {
            $files = scandir($base_folder . "/app_pam");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/app_pam/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                $loadApps = $projectdb->query("SELECT id,name FROM default_applications;");
                if( $loadApps->num_rows > 0 )
                {
                    $applications = array();
                    while( $loadAppsData = $loadApps->fetch_assoc() )
                    {
                        $appName = $loadAppsData['name'];
                        $appLid = $loadAppsData['id'];
                        $applications[$appName] = $appLid;
                    }
                }

                foreach( $xml->PamAppObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $name_int = trim(truncate_names(normalizeNames(trim($b['Name']))));
                    $description = addslashes($b['Comment']);
                    $type = $b['ObjType'];
                    $serviceprotocol = trim($b['Protocol']);
                    if( isset($b['DestinationPorts']) )
                    {
                        $dport = trim($b['DestinationPorts']);
                    }
                    else
                    {
                        $dport = "";
                    }
                    if( isset($b['SourcePorts']) )
                    {
                        $sport = trim($b['SourcePorts']);
                    }
                    else
                    {
                        $sport = "";
                    }

                    if( !isset($fullObject[$name]) )
                    {
                        if( $dport != "" )
                        {
                            if( ($serviceprotocol == "tcp") or ($serviceprotocol == "udp") )
                            {
                                $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','$dport','0','$description','$source','0','$filename','$sport')";
                                $fullObject[$name]["table_name"] = "services";
                                $fullObject[$name]["member_lid"] = $services_lid;
                                $services_lid++;
                            }
                            elseif( $serviceprotocol == "any" )
                            {
                                #Create a ServiceGroup
                                $addServicesGroups[] = "('$sglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                                $fullObject[$name]["member_lid"] = $sglid;
                                $fullObject[$name]["table_name"] = "services_groups_id";
                                $parentAG = $sglid;
                                $sglid++;
                                $name_ext = trim(truncate_names('TCP-' . $name));
                                if( isset($fullObject[$name_ext]) )
                                {
                                    $member_lid2 = $fullObject[$name_ext]["member_lid"];
                                    $table_name2 = $fullObject[$name_ext]["table_name"];
                                    $addServicesMembers[] = "('$vsys','TCP-$name_int','$parentAG','$source','$member_lid2','$table_name2')";
                                }
                                else
                                {
                                    $addServices[] = "('$services_lid','TCP-$name_int','TCP-$name_int','tcp','$dport','1','$description','$source','0','$filename','$sport')";
                                    $fullObject[$name_ext]["table_name"] = "services";
                                    $fullObject[$name_ext]["member_lid"] = $services_lid;
                                    $addServicesMembers[] = "('$vsys','TCP-$name_int','$parentAG','$source','$services_lid','services')";
                                    $services_lid++;
                                }
                                $name_ext = trim(truncate_names('UDP-' . $name));
                                if( isset($fullObject[$name_ext]) )
                                {
                                    $member_lid2 = $fullObject[$name_ext]["member_lid"];
                                    $table_name2 = $fullObject[$name_ext]["table_name"];
                                    $addServicesMembers[] = "('$vsys','UDP-$name_int','$parentAG','$source','$member_lid2','$table_name2')";
                                }
                                else
                                {
                                    $addServices[] = "('$services_lid','UDP-$name_int','UDP-$name_int','udp','$dport','1','$description','$source','0','$filename','$sport')";
                                    $fullObject[$name_ext]["table_name"] = "services";
                                    $fullObject[$name_ext]["member_lid"] = $services_lid;
                                    $addServicesMembers[] = "('$vsys','UDP-$name_int','$parentAG','$source','$services_lid','services')";
                                    $services_lid++;
                                }

                            }
                            else
                            {
                                print "Protocol with dport not TCP/UDP/ANY $name_int\n";
                            }
                        }
                        else
                        {
                            if( ($serviceprotocol == "tcp") or ($serviceprotocol == "udp") )
                            {
                                if( $sport != "" )
                                {
                                    $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','0-65535','0','$description','$source','0','$filename','$sport')";
                                    $fullObject[$name]["table_name"] = "services";
                                    $fullObject[$name]["member_lid"] = $services_lid;
                                    $services_lid++;
                                }
                                else
                                {
                                    $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','0-65535','1','$description','$source','0','$filename','')";
                                    $fullObject[$name]["table_name"] = "services";
                                    $fullObject[$name]["member_lid"] = $services_lid;
                                    //add_log2('error', 'Importing Services/Apps', 'Service/App Protocol/Port Not found ['.$name_int.'] ['.$name.']', $source, 'Service Created '.$name_int.' Add Service/Protocol or replace by App-ID', 'objects', $services_lid, 'services');
                                    $services_lid++;
                                }
                            }
                            else
                            {
                                if( $sport != "" )
                                {
                                    #Create a ServiceGroup
                                    $addServicesGroups[] = "('$sglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                                    $fullObject[$name]["member_lid"] = $sglid;
                                    $fullObject[$name]["table_name"] = "services_groups_id";
                                    $parentAG = $sglid;
                                    $sglid++;
                                    $name_ext = trim(truncate_names('TCP-' . $name));
                                    if( isset($fullObject[$name_ext]) )
                                    {
                                        $member_lid2 = $fullObject[$name_ext]["member_lid"];
                                        $table_name2 = $fullObject[$name_ext]["table_name"];
                                        $addServicesMembers[] = "('$vsys','TCP-$name_int','$parentAG','$source','$member_lid2','$table_name2')";
                                    }
                                    else
                                    {
                                        $addServices[] = "('$services_lid','TCP-$name_int','TCP-$name_int','tcp','0-65535','1','$description','$source','0','$filename','$sport')";
                                        $fullObject[$name_ext]["table_name"] = "services";
                                        $fullObject[$name_ext]["member_lid"] = $services_lid;
                                        $addServicesMembers[] = "('$vsys','TCP-$name_int','$parentAG','$source','$services_lid','services')";
                                        $services_lid++;
                                    }
                                    $name_ext = trim(truncate_names('UDP-' . $name));
                                    if( isset($fullObject[$name_ext]) )
                                    {
                                        $member_lid2 = $fullObject[$name_ext]["member_lid"];
                                        $table_name2 = $fullObject[$name_ext]["table_name"];
                                        $addServicesMembers[] = "('$vsys','UDP-$name_int','$parentAG','$source','$member_lid2','$table_name2')";
                                    }
                                    else
                                    {
                                        $addServices[] = "('$services_lid','UDP-$name_int','UDP-$name_int','udp','0-65535','1','$description','$source','0','$filename','$sport')";
                                        $fullObject[$name_ext]["table_name"] = "services";
                                        $fullObject[$name_ext]["member_lid"] = $services_lid;
                                        $addServicesMembers[] = "('$vsys','UDP-$name_int','$parentAG','$source','$services_lid','services')";
                                        $services_lid++;
                                    }
                                }
                                else
                                {
                                    switch ($b['Name'])
                                    {
                                        case "DHCP-DNS":
                                            $fullObject[$name]['app'] = "dhcp,dns";
                                            break;
                                        case "SSL/TLS":
                                            $fullObject[$name]['app'] = "ssl,tlsp";
                                            break;
                                        case "AOL Instant Messenger":
                                            $fullObject[$name]['app'] = "aim";
                                            break;
                                        case "Secure Shell (SSH)":
                                            $fullObject[$name]['app'] = "ssh";
                                            break;
                                        case "FTP":
                                            $fullObject[$name]['app'] = "ftp";
                                            break;
                                        case "Skype":
                                            $fullObject[$name]['app'] = "skype,skype-probe";
                                            break;
                                        case "Yahoo Messenger":
                                            $fullObject[$name]['app'] = "yahoo-im";
                                            break;
                                        case "Remote Desktop Protocol":
                                            $fullObject[$name]['app'] = "ms-rdp";
                                            break;
                                        case "Internet Relay Chat":
                                            $fullObject[$name]['app'] = "irc";
                                            break;
                                        case "Bit Torrent":
                                            $fullObject[$name]['app'] = "bittorrent";
                                            break;
                                        case "ICMP":
                                            $fullObject[$name]['app'] = "icmp";
                                            break;
                                        case "SMB":
                                            $fullObject[$name]['app'] = "ms-ds-smb";
                                            break;
                                        case "MSRPC":
                                            $fullObject[$name]['app'] = "msrpc";
                                            break;
                                        case "NBNS":
                                            $fullObject[$name]['app'] = "netbios-ns";
                                            break;
                                        case "RFB-VNC":
                                            $fullObject[$name]['app'] = "vnc";
                                            break;
                                        case "Netbios":
                                            $fullObject[$name]['app'] = "netbios-dg,netbios-ns,netbios-ss";
                                            break;
                                        case "HTTP":
                                            $fullObject[$name]['app'] = "web-browsing";
                                            break;
                                        case "ORACLE TNS":
                                            $fullObject[$name]['app'] = "oracle";
                                            break;
                                        case "LDAP":
                                            $fullObject[$name]['app'] = "ldap";
                                            break;
                                        case "Kerberos":
                                            $fullObject[$name]['app'] = "kerberos";
                                            break;
                                        case "SNMP":
                                            $fullObject[$name]['app'] = "snmp";
                                            break;
                                        case "DCOM (for WMI)":
                                            $fullObject[$name]['app'] = "msrpc";
                                            break;
                                        case "VNC":
                                            $fullObject[$name]['app'] = "vnc";
                                            break;
                                        case "MySQL":
                                            $fullObject[$name]['app'] = "mysql";
                                            break;
                                        case "SNTP":
                                            $fullObject[$name]['app'] = "ntp";
                                            break;
                                        case "Teamviewer":
                                            $fullObject[$name]['app'] = "teamviewer";
                                            break;
                                        case "PostgreSQL":
                                            $fullObject[$name]['app'] = "postgres";
                                            break;
                                        case "DNS":
                                            $fullObject[$name]['app'] = "dns";
                                            break;
                                        case "SIP":
                                            $fullObject[$name]['app'] = "sip";
                                            break;
                                        case "TFTP":
                                            $fullObject[$name]['app'] = "tftp";
                                            break;
                                        case "IPSEC":
                                            $fullObject[$name]['app'] = "ipsec";
                                            break;
                                        case "syslog":
                                            $fullObject[$name]['app'] = "syslog";
                                            break;
                                        case "RTP":
                                            $fullObject[$name]['app'] = "rtp";
                                            break;
                                        case "IRC":
                                            $fullObject[$name]['app'] = "irc";
                                            break;
                                        case "Rsync":
                                            $fullObject[$name]['app'] = "rsync";
                                            break;
                                        case "informix":
                                            $fullObject[$name]['app'] = "informix";
                                            break;
                                        case "ICMP (ALL types)":
                                            $fullObject[$name]['app'] = "icmp";
                                            break;
                                        default:
                                            $addServices[] = "('$services_lid','$name','$name_int','','','1','$description','$source','0','$filename','')";
                                            $fullObject[$name]["table_name"] = "services";
                                            $fullObject[$name]["member_lid"] = $services_lid;
                                            add_log2('error', 'Importing Services/Apps', 'Service/App Protocol/Port Not found [' . $name_int . '] [' . $name . ']', $source, 'Service Created ' . $name_int . ' Add Service/Protocol or replace by App-ID', 'objects', $services_lid, 'services');
                                            $services_lid++;
                                    }
                                }

                            }
                        }

                    }
                }
            }
        }

        # Read Remote Servers
        if( is_dir($base_folder . "/remote_auth_servers") )
        {
            $files = scandir($base_folder . "/remote_auth_servers");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/remote_auth_servers/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);
                foreach( $xml->Server as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $domain = trim($b['Name']);

                    if( !isset($remoteServers[$name]) )
                    {
                        $remoteServers[$name]["domain"] = $domain;
                    }
                }
            }
        }

        # Read Identities Users
        if( is_dir($base_folder . "/identity_remote") )
        {
            $files = scandir($base_folder . "/identity_remote");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/identity_remote/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                foreach( $xml->RemoteIdentityObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $groups = array();
                    $user_raw = trim($b['Name']);
                    foreach( $b->Identity as $identity )
                    {
                        $identityType = $identity['Type'];
                        $AuthServer = trim($identity->AuthServer['UUID']);
                        if( $identityType == "user" )
                        {
                            $groups[] = $remoteServers[$AuthServer]['domain'] . "\\" . $user_raw;
                        }
                        else
                        {
                            $groups[] = $remoteServers[$AuthServer]['domain'] . "\\" . $identity['Name'];
                        }

                    }
                    $remoteGroups[$name] = implode(",", $groups);
                }

            }
        }

        # Read Custom URL Categories
        if( is_dir($base_folder . "/url_custom") )
        {
            $files = scandir($base_folder . "/url_custom");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);
            $sql = array();
            $filename2 = $base_folder . "/url_custom/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                foreach( $xml->UrlCustomObject as $a => $b )
                {
                    $name = trim($b['UUID']);
                    $groups = array();
                    $url_category = normalizeNames(trim($b['Name']));
                    if( !isset($fullObject[$name]) )
                    {
                        $fullObject[$name]['category'] = $url_category;
                    }
                    $description = addslashes($b['Comment']);
                    if( $description != "" )
                    {
                        $description = "<description>$description</description>";
                    }
                    else
                    {
                        $description = "";
                    }
                    $xmlstring = "<entry name=\"$url_category\">$description<list/></entry>";
                    $xmlcode = simplexml_load_string($xmlstring);
                    $old_raw = "";
                    foreach( $b->Url as $url )
                    {
                        $url_raw = $url['Value'];
                        $url_raw = str_replace("https://", "", $url_raw);
                        $url_raw = str_replace("http://", "", $url_raw);
                        $url_raw = str_replace("*://", "", $url_raw);
                        if( $url_raw != $old_raw )
                        {
                            $xmlcode->list->addChild("member", $url_raw);
                        }
                        $old_raw = $url_raw;
                    }
                    $theProfilecontent = addslashes(str_replace("<?xml version=\"1.0\"?>", "", $xmlcode->asXML()));
                    $sql[] = "('$plid','$source','$url_category','$theProfilecontent','custom-url-category','$filename','$vsys')";
                    $plid++;
                }

            }
            if( count($sql) > 0 )
            {
                $projectdb->query("INSERT INTO profiles (id,source,name,xml,type,devicegroup, vsys) VALUES " . implode(",", $sql) . ";");
                unset($sql);
            }
        }

        # Read POLICY
        if( is_dir($base_folder . "/acl") )
        {
            $files = scandir($base_folder . "/acl");
            sort($files, SORT_LOCALE_STRING);
            $last_file = array_pop($files);

            $filename2 = $base_folder . "/acl/" . $last_file;
            if( isXML($filename2) === TRUE )
            {
                $xml = simplexml_load_file($filename2);

                $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
                $getLID1 = $getlastlid->fetch_assoc();
                $lid = intval($getLID1['max']) + 1;
                $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules WHERE source='$source' AND vsys='$vsys';");
                $getLID1 = $getlastlid->fetch_assoc();
                $position = intval($getLID1['max']) + 1;

                $add_rule = array();
                $rule_source = array();
                $rule_destination = array();
                $rule_app = array();
                $rule_service = array();
                $rule_app = array();
                $rule_category = array();

                foreach( $xml->Rule as $a => $b )
                {
                    $enabled = $b['Enabled'];
                    $action = $b['Action'];
                    $priority = $b['Priority'];
                    $description = addslashes($b['Comment']);
                    $type = $b['ObjType'];
                    $name = "Rule " . $priority;

                    if( isset($b->Source) )
                    {
                        foreach( $b->Source as $sources )
                        {
                            $objtype = $sources['ObjType'];
                            if( $objtype != "any-address" )
                            {
                                $search = trim($sources['UUID']);

                                if( $objtype == "identity_remote" )
                                {
                                    if( isset($remoteGroups[$search]) )
                                    {
                                        $users = explode(",", $remoteGroups[$search]);
                                        foreach( $users as $user )
                                        {
                                            $userC = addslashes($user);
                                            $rule_usr[] = "('$source','$vsys','$lid','$userC')";
                                        }
                                        $checkit = 0;
                                    }
                                    else
                                    {
                                        print "ERROR in $name SOURCE USER not found $search\n";
                                        $checkit = 1;
                                    }
                                }
                                else
                                {
                                    if( isset($fullObject[$search]) )
                                    {
                                        $table_name = $fullObject[$search]['table_name'];
                                        $member_lid = $fullObject[$search]['member_lid'];
                                        $rule_source[] = "('$source','$vsys','$lid','$table_name','$member_lid')";
                                        $checkit = 0;
                                    }
                                    else
                                    {
                                        add_log2('error', 'Importing Security Rules', 'Source Object not found [' . $objtype . '] [' . $search . ']', $source, 'Check the Rule ' . $name, 'rules', $lid, 'security_rules');
                                        //print "ERROR in $name SOURCE not found $search\n";
                                        $checkit = 1;
                                    }
                                }
                            }
                        }
                    }

                    if( isset($b->Dest) )
                    {
                        foreach( $b->Dest as $sources )
                        {
                            $objtype = $sources['ObjType'];
                            if( $objtype != "any-address" )
                            {
                                $search = trim($sources['UUID']);
                                if( isset($fullObject[$search]) )
                                {
                                    $table_name = $fullObject[$search]['table_name'];
                                    $member_lid = $fullObject[$search]['member_lid'];
                                    $rule_destination[] = "('$source','$vsys','$lid','$table_name','$member_lid')";
                                    $checkit = 0;
                                }
                                else
                                {
                                    print "ERROR in $name DESTINATION not found $search\n";
                                    $checkit = 1;
                                }

                            }
                        }
                    }

                    if( isset($b->App) )
                    {
                        $rule_with_app = FALSE;
                        foreach( $b->App as $sources )
                        {
                            $search = trim($sources['UUID']);
                            $objtype = trim($sources['ObjType']);
                            if( $objtype == "any-application" )
                            {
                            }
                            elseif( $objtype == "url_custom" )
                            {
                                if( isset($fullObject[$search]) )
                                {
                                    $category = $fullObject[$search]['category'];
                                    $rule_category[] = "('$source','$vsys','$lid','$category')";
                                    $checkit = 0;
                                }
                                else
                                {
                                    print "ERROR in $name CUSTOM URL CATEGORY not found $search\n";
                                    $checkit = 1;
                                }
                            }
                            elseif( $objtype == "url_category" )
                            {
                                add_log2('error', 'Importing Security Rules', 'Default URL Categories are not supported [' . $search . ']', $source, 'Attach a URL Category and apply it to Rule ' . $name, 'rules', $lid, 'security_rules');
                            }
                            elseif( $objtype == "webapplication" )
                            {
                                add_log2('error', 'Importing Security Rules', 'Web Application is not supported [' . $search . ']', $source, 'Create a new Application Filter and apply it to Rule ' . $name, 'rules', $lid, 'security_rules');
                            }

                            elseif( $objtype == "application_collection" )
                            {
                                add_log2('error', 'Importing Security Rules', 'Application Groups are not supported [' . $search . ']', $source, 'Create a new Application Group and apply it to Rule ' . $name, 'rules', $lid, 'security_rules');
                            }
                            else
                            {
                                if( isset($fullObject[$search]['app']) )
                                {

                                    $rule_with_app = TRUE;
                                    foreach( explode(",", $fullObject[$search]['app']) as $appl )
                                    {
                                        $member_lid = $applications[$appl];
                                        $table_name = "default_applications";
                                        $rule_app[] = "('$source','$vsys','$lid','$table_name','$member_lid')";
                                    }
                                }
                                else
                                {
                                    if( isset($fullObject[$search]) )
                                    {
                                        $table_name = $fullObject[$search]['table_name'];
                                        $member_lid = $fullObject[$search]['member_lid'];
                                        $rule_service[] = "('$source','$vsys','$lid','$table_name','$member_lid')";
                                        $checkit = 0;
                                    }
                                    else
                                    {
                                        print "ERROR in $name APP/SERVICE not found $search\n";
                                        $checkit = 1;
                                    }
                                }
                            }
                        }
                    }

                    if( $enabled == "true" )
                    {
                        $rule_enabled = 0;
                    }
                    else
                    {
                        $rule_enabled = 1;
                    }
                    if( $action == "accept" )
                    {
                        $action = "allow";
                    }
                    else
                    {
                        $action = "deny";
                    }
                    $add_rule[] = "('$lid','$rule_enabled','','','$action','','$name','$description','$source','$vsys','$position','','$checkit')";
                    $lid++;
                    $position++;
                }


            }
        }

        # INSERT
        if( count($addNetworksv4) > 0 )
        {
            $unique = array_unique($addNetworksv4);
            $projectdb->query("INSERT INTO address (id,type,vtype,ipaddress,cidr,name_ext,name,checkit,v4,description,source,devicegroup) VALUES " . implode(",", $unique) . ";");
            unset($addNetworksv4);
            unset($unique);
        }
        if( count($addNetworksv6) > 0 )
        {
            $unique = array_unique($addNetworksv6);
            $projectdb->query("INSERT INTO address (id,type,vtype,ipaddress,cidr,name_ext,name,checkit,v6,description,source,devicegroup) VALUES " . implode(",", $unique) . ";");
            unset($addNetworksv6);
            unset($unique);
        }
        if( count($addAddressGroups) > 0 )
        {
            $projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,type,devicegroup,source,vsys,description) VALUES " . implode(",", $addAddressGroups) . ";");
            unset($addAddressGroups);
            if( count($addAddressMembers) > 0 )
            {
                $projectdb->query("INSERT INTO address_groups (vsys,member,lid,source,member_lid,table_name) VALUES " . implode(",", $addAddressMembers) . ";");
                unset($addAddressMembers);
            }
        }
        # Add Services and Groups
        if( count($addServices) > 0 )
        {
            $unique = array_unique($addServices);
            $projectdb->query("INSERT INTO services (id,name_ext,name,protocol,dport,checkit,description,source,icmp,devicegroup,sport) VALUES " . implode(",", $unique) . ";");
            unset($services);
            unset($unique);
        }
        if( count($addServicesGroups) > 0 )
        {
            $projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,type,devicegroup,source,vsys,description) VALUES " . implode(",", $addServicesGroups) . ";");
            unset($addServicesGroups);
            if( count($addServicesMembers) > 0 )
            {
                $projectdb->query("INSERT INTO services_groups (vsys,member,lid,source,member_lid,table_name) VALUES " . implode(",", $addServicesMembers) . ";");
                unset($addServicesMembers);
            }
        }

        if( count($add_rule) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules (id,disabled,negate_source,negate_destination,action,target,name,description,source,vsys,position,preorpost,checkit) VALUES " . implode(",", $add_rule) . ";");
            unset($add_rule);
        }
        if( count($rule_source) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $rule_source) . ";");
            unset($rule_source);
        }
        if( count($rule_usr) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_usr (source,vsys,rule_lid,name) VALUES " . implode(",", $rule_usr) . ";");
            unset($rule_usr);
        }
        if( count($rule_category) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_categories (source,vsys,rule_lid,name) VALUES " . implode(",", $rule_category) . ";");
            unset($rule_category);
        }
        if( count($rule_destination) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $rule_destination) . ";");
            unset($rule_destination);
        }
        if( count($rule_service) > 0 )
        {
            $unique = array_unique($rule_service);
            $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $unique) . ";");
            unset($rule_service);
            unset($unique);
        }
        if( count($rule_app) > 0 )
        {
            $unique = array_unique($rule_app);
            $projectdb->query("INSERT INTO security_rules_app (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $unique) . ";");
            unset($rule_app);
            unset($unique);
        }

        #Calculate Layer4-7
        $queryRuleIds = "SELECT id from security_rules WHERE source = $source;";
        $resultRuleIds = $projectdb->query($queryRuleIds);
        if( $resultRuleIds->num_rows > 0 )
        {
            $rules = array();
            while( $dataRuleIds = $resultRuleIds->fetch_assoc() )
            {
                $rules[] = $dataRuleIds['id'];
            }
            $rulesString = implode(",", $rules);
            $securityRulesMan = new \SecurityRulePANObject();
            $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
        }


        update_progress($project, '0.90', 'Phase 9 of 11 - Checking Used and Unused Objects', $jobid);
        check_used_objects_new($sourcesAdded);

        update_progress($project, '1.0', 'Done', $jobid);
    }
    else
    {
        update_progress($project, '-1.0', 'Imposible to find the XGS Folder', $jobid);
    }

    deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);


}