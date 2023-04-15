<?php

# Copyright (c) 2015 Palo Alto Networks, Inc.
# All rights reserved.
#HEADER
$debug = FALSE;
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/shared.php';
require_once INC_ROOT . '/libs/objects/SecurityRulePANObject.php';

require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
global $app;
//Capture request paramenters
include INC_ROOT . '/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);

if( $action == "import" )
{
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    require_once INC_ROOT . '/libs/projectdb.php';
    global $projectdb;
    $projectdb = selectDatabase($project);

    $path = USERSPACE_PATH . "/projects/" . $project . "/";
    $i = 0;
    $dirrule = opendir($path);

    update_progress($project, '0.00', 'Reading config files', $jobid);
    while( $config_filename = readdir($dirrule) )
    {
        //if (($config_filename != ".") AND ($config_filename != "..") AND ($config_filename != "parsers.txt") AND ($config_filename != "Backups") AND ($config_filename != "Pcaps") AND ($config_filename != "Reports") AND ($config_filename != "MT-" . $project . ".xml") AND ($config_filename != "CPviewer.html") AND (!preg_match("/^MT-/", $config_filename))) {
        if( checkFiles2Import($config_filename) )
        {
            $config_path = $path . $config_filename;
            $filename = $config_filename;
            $filenameParts = pathinfo($config_filename);
            $verificationName = $filenameParts['filename'];
            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$verificationName';");
//            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename';");
            if( $isUploaded->num_rows == 0 )
            {
                import_config($config_path, $project, $config_filename, $jobid);
                update_progress($project, '0.80', 'File:' . $filename . ' Phase 8 Referencing Groups', $jobid);
                //GroupMember2IdAddress($config_filename);
                GroupMember2IdAddress_improved($config_filename);
                GroupMember2IdServices($config_filename);
                GroupMember2IdApplications($config_filename);
            }
            else
            {
                update_progress($project, '-1.00', 'This filename ' . $filename . ' its already uploaded. Skipping...', $jobid);
            }
        }
    }

    #Calculate Layer4-7
    $queryRuleIds = "SELECT id from security_rules WHERE source = $config_filename;";
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
        $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $config_filename);
    }

    #Check used
    check_used_objects_new();
    update_progress($project, '1.00', 'Done.', $jobid);

}

function import_config($config_path, $project, $config_filename, $jobid)
{
    global $projectdb;

    $filename = $config_filename;
    if( isXML($config_path) === TRUE )
    {
        $xml = simplexml_load_file($config_path);

        $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
        if( isset($xml->{'for-version'}) )
        {
            $version = $xml->{'for-version'};
        }
        else
        {
            $version = '';
        }
        if( $getVsys->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','vsys1','Watchguard')");
            $vsys = "vsys1";
            $source = $projectdb->insert_id;
        }
        else
        {
            $getVsysData = $getVsys->fetch_assoc();
            $thename = $getVsysData['vsys'];
            $getVsysData1 = str_replace("vsys", "", $thename);
            $result = intval($getVsysData1) + 1;
            $vsys = "vsys" . $result;
            $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','$vsys','Watchguard')");
            #Get Source (First row for this filename)
            $getSource = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' GROUP by filename;");
            $getSourceData = $getSource->fetch_assoc();
            $source = $getSourceData['id'];
        }

        #Config Template
        $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
        $template_name = $filename . "_template";
        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
        $template = $projectdb->insert_id;

        // DEBUG $out="csv";
        get_address($xml, $source, $vsys, $filename, $out = '');
        get_services($xml, $source, $vsys, $filename, $out = '');
        //get_interfaces($xml,$source,$vsys,$filename,$out='');
        $alias = get_alias($xml, $source, $vsys, $filename, $out = '');
        print_r($alias);
        get_security_policies($xml, $source, $vsys, $filename, $out = '', $alias);

        deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);

    }
}

function get_address($xml, $source, $vsys, $devicegroup, $out)
{
    global $projectdb;
    if( isset($xml->{'address-group-list'}) )
    {
        $address = $xml->xpath("//address-group-list");
        if( count($address[0]) > 0 )
        {
            $allAddress = array();
            foreach( $address[0] as $element )
            {
                if( isset($element->name) )
                {
                    $name = $element->name;
                }
                $count_members = count($element->{'addr-group-member'}->member);
                switch ($count_members)
                {
                    case '0':
                        print "$name has no information\n";
                        break;
                    case '1':
                        $allAddress[] = add_address($name, $element, $source, $vsys, $devicegroup, $out);
                        break;
                    default:
                        print "$name is a Group\n";
                        break;
                }
            }
            if( count($allAddress) > 0 )
            {
                $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,v6,vsys,vtype,devicegroup,description) VALUES " . implode(",", $allAddress) . ";");
            }
        }
    }
}

function add_address($name, $element, $source, $vsys, $devicegroup, $out)
{
    if( $element )
    {
        $address = array();
        $name_int = truncate_names(normalizeNames($name));
        if( isset($element->description) )
        {
            $description = addslashes(normalizeComments($element->description));
        }
        else
        {
            $description = "";
        }
        $description = str_replace("\n", '', $description); // remove new lines
        $description = str_replace("\r", '', $description);

        $type = $element->{'addr-group-member'}->member->type;
        switch ($type)
        {
            case '1':
                # host
                $ipaddress = $element->{'addr-group-member'}->member->{'host-ip-addr'};
                $ipversion = ip_version($ipaddress);
                $addrtype = "ip-netmask";
                if( $ipversion == "v4" )
                {
                    $hostCidr = "";
                }
                elseif( $ipversion == "v6" )
                {
                    $hostCidr = "";
                }
                else
                {
                    $ipversion = "v4";
                    $hostCidr = "";
                }
                break;
            case '2':
                # Network
                $ipaddress = $element->{'addr-group-member'}->member->{'ip-network-addr'};
                $netmask = $element->{'addr-group-member'}->member->{'ip-mask'};
                $ipversion = ip_version($ipaddress);
                $addrtype = "ip-netmask";
                if( $ipversion == "v4" )
                {
                    $hostCidr = mask2cidrv4(rtrim($netmask));
                }
                elseif( $ipversion == "v6" )
                {
                    $hostCidr = "0";
                }
                else
                {
                    $ipversion = "v4";
                    $hostCidr = mask2cidrv4(rtrim($netmask));
                }
                break;
            case '3':
                # Ip Range
                $startip = $element->{'addr-group-member'}->member->{'start-ip-addr'};
                $endip = $element->{'addr-group-member'}->member->{'end-ip-addr'};
                $ipversion = ip_version($startip);
                $ipaddress = $startip . "-" . $endip;
                $addrtype = "ip-range";
                if( $ipversion == "v4" )
                {
                    $hostCidr = '';
                }
                elseif( $ipversion == "v6" )
                {
                    $hostCidr = "";
                }
                else
                {
                    $ipversion = "v4";
                    $hostCidr = '';
                }
                break;
            default:
                print "$name: I dont know address type\n";
        }

        if( $out == "csv" )
        {
            $address = "$name;$addrtype;$ipaddress;$hostCidr;$description";
        }
        else
        {
            # (name, type, name, checkit, source, used, ipaddress, cidr, v4, v6, vsys, vtype, devicegroup)
            if( $ipversion == "v4" )
            {
                $address = "('$name_int','$addrtype','$name','0','$source','0','$ipaddress','$hostCidr','1','0','$vsys','address','$devicegroup','$description')";
            }
            elseif( $ipversion == "v6" )
            {
                $address = "('$name_int','$addrtype','$name','0','$source','0','$ipaddress','$hostCidr','0','1','$vsys','address','$devicegroup','$description')";
            }
        }

        return $address;
    }
}

function get_services($xml, $source, $vsys, $devicegroup, $out)
{
    global $projectdb;
    if( isset($xml->{'service-list'}) )
    {
        $address = $xml->xpath("//service-list");
        if( count($address[0]) > 0 )
        {
            $allAddress = array();
            foreach( $address[0] as $element )
            {
                if( isset($element->name) )
                {
                    $name = $element->name;
                }
                $count_members = count($element->{'service-item'}->member);
                switch ($count_members)
                {
                    case '0':
                        print "$name has no information\n";
                        break;
                    case '1':
                        $allAddress[] = add_service($name, $element, $source, $vsys, $devicegroup, $out);
                        break;
                    default:
                        #Check if all the elements has the same protocol
                        $check = check_service_protocol($name, $element, $source, $vsys, $devicegroup, $out, $count_members);
                        if( $check != null )
                        {
                            $allAddress[] = $check;
                        }
                        else
                        {
                            print $name . "is GROUP\n";
                        }
                        break;
                }
            }
            if( count($allAddress) > 0 )
            {
                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys,devicegroup,description) VALUES " . implode(",", $allAddress) . ";");
            }
        }
    }
}

function add_service($name, $element, $source, $vsys, $devicegroup, $out)
{
    if( $element )
    {
        $address = array();
        $checkit = 0;
        $name_int = truncate_names(normalizeNames($name));
        $description = addslashes(normalizeComments($element->description));
        $description = str_replace("\n", '', $description); // remove new lines
        $description = str_replace("\r", '', $description);
        $idle_timeout = $element->{'idle-timeout'};
        if( $idle_timeout != "0" )
        {
            print "Service $name has a idle timeout: $idle_timeout\n";
        }
        $type = $element->{'service-item'}->member->type;
        $protocol = $element->{'service-item'}->member->protocol;
        if( isset($element->{'service-item'}->member->{'server-port'}) )
        {
            $dport = $element->{'service-item'}->member->{'server-port'};
        }
        # Range
        if( (isset($element->{'service-item'}->member->{'start-server-port'})) and (isset($element->{'service-item'}->member->{'end-server-port'})) )
        {
            $dport = $element->{'service-item'}->member->{'start-server-port'} . "-" . $element->{'service-item'}->member->{'end-server-port'};
        }

        if( ($protocol == 0) and ($dport == 0) )
        {
            $checkit = 1;
            $dport = "0-65535";
        }

        $proto = calculate_protocol($protocol);
        $protocol = $proto["protocol"];
        $checkit = $proto["checkit"];

        if( $out == "csv" )
        {
            $address = "$name;$protocol;$dport;$description";
        }
        else
        {
            # (name,name_ext,protocol,dport,checkit,source,vsys,devicegroup)
            $address = "('$name_int','$name','$protocol','$dport','$checkit','$source','$vsys','$devicegroup','$description')";
        }
        return $address;
    }
}

function check_service_protocol($name, $element, $source, $vsys, $devicegroup, $out, $count_members)
{
    if( $element )
    {
        $proto_old = "";
        $port = array();
        $checkit = 0;
        $name_int = truncate_names(normalizeNames($name));
        if( isset($element->description) )
        {
            $description = $element->description;
        }
        else
        {
            $description = "";
        }
        foreach( $element->{'service-item'}->member as $key => $item )
        {
            if( (intval($proto_old) == intval($item->protocol)) or ($proto_old == "") )
            {
                if( isset($item->{'server-port'}) )
                {
                    $port[] = $item->{'server-port'};
                }
                elseif( (isset($item->{'start-server-port'})) and (isset($item->{'end-server-port'})) )
                {
                    $port[] = $item->{'start-server-port'} . "-" . $item->{'end-server-port'};
                }

            }
            else
            {
                return null;
            }

            $proto_old = $item->protocol;
        }

        $proto = calculate_protocol($proto_old);
        $proto_old = $proto["protocol"];
        $checkit = $proto["checkit"];

        $dport = implode(",", $port);
        $address = "('$name_int','$name','$proto_old','$dport','$checkit','$source','$vsys','$devicegroup','$description')";
    }
    return $address;
}

function calculate_protocol($protocolID)
{

    $checkit = 0;
    switch ($protocolID)
    {
        case '0':
            $protocolID = "ip";
            $checkit = 1;
            break;
        case '17':
            # UDP
            $protocolID = "udp";
            break;
        case '6':
            # TCP
            $protocolID = "tcp";
            break;
        case '47':
            # TCP
            $protocolID = "gre";
            $checkit = 1;
            break;
        case '2':
            # TCP
            $protocolID = "igmp";
            $checkit = 1;
            break;
        case '89':
            # TCP
            $protocolID = "ospf";
            $checkit = 1;
            break;
        case '1':
            # TCP
            $protocolID = "icmp";
            $checkit = 1;
            break;
        case '0':
            # TCP
            $protocolID = "ip";
            $checkit = 1;
            break;
        default:
            print "aaaaaaaa" . $protocolID . "\n";
            $protocolID = "ip";
            $checkit = 1;
            break;
    }

    return array("protocol" => $protocolID, "checkit" => $checkit);

}

function get_interfaces($xml, $source, $vsys, $devicegroup, $out)
{
    global $projectdb;
    if( isset($xml->{'interface-list'}) )
    {
        $address = $xml->xpath("//interface-list");
        if( count($address[0]) > 0 )
        {
            $allAddress = array();
            foreach( $address[0] as $element )
            {
                if( isset($element->{'if-item-list'}->item->{'physical-if'}) )
                {
                    $name = $element->name;
                    print_r($element);
                }

                #Vlan-IF
                if( isset($element->{'if-item-list'}->item->{'vlan-if'}) )
                {
                    $name = $element->name;
                    print_r($element);
                }
            }
        }
    }
}

function get_alias($xml, $source, $vsys, $devicegroup, $out)
{
    global $projectdb;
    $address = array();
    if( isset($xml->{'alias-list'}) )
    {
        $address = $xml->xpath("//alias-list");
    }
    return $address;
}

function add_alias($xml, $source, $vsys, $devicegroup, $out)
{
    global $projectdb;
    if( isset($xml->{'alias-list'}) )
    {
        $address = $xml->xpath("//alias-list");
        if( count($address[0]) > 0 )
        {
            $allAddress = array();
            foreach( $address[0] as $element )
            {
                $name = $element->name;
                $name_int = truncate_names(normalizeNames($name));
                if( isset($element->description) )
                {
                    $description = addslashes(normalizeComments($element->description));
                }
                else
                {
                    $description = "";
                }
                $description = str_replace("\n", '', $description); // remove new lines
                $description = str_replace("\r", '', $description);
                print "ALIAS: " . $name . "\n";
                $property[] = $element->property;
            }
            $unique = array_unique($property);
            print_r($unique);
        }
    }
}

function get_security_policies($xml, $source, $vsys, $devicegroup, $out, $alias)
{
    global $projectdb;
    if( isset($xml->{'policy-list'}) )
    {
        $address = $xml->xpath("//policy-list");
        if( count($address[0]) > 0 )
        {
            $allAddress = array();
            foreach( $address[0] as $element )
            {
                $name = $element->name;
                $name_int = truncate_names(normalizeNames($name));
                if( isset($element->description) )
                {
                    $description = addslashes(normalizeComments($element->description));
                }
                else
                {
                    $description = "";
                }
                $description = str_replace("\n", '', $description); // remove new lines
                $description = str_replace("\r", '', $description);
                print "ALIAS: " . $name . "\n";
                $property[] = $element->property;
            }
            $unique = array_unique($property);
            print_r($unique);
        }
    }
}