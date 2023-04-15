<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/shared.php';
require_once INC_ROOT . '/libs/xmlapi.php';
require_once INC_ROOT . '/libs/paloalto.php';
require_once INC_ROOT . '/libs/common/lib-objects.php';
require_once INC_ROOT . '/libs/projectdb.php';
include_once INC_ROOT . '/libs/objects/SecurityRulePANObject.php';


class FwInterface
{
    public $name;
    public $address;

    public $media;
    public $interfaceName;
    public $interfaceType;
    public $comment;
    public $unitName;
    public $vlan_tag;
    public $ipaddresses;
    public $vsys;
    public $zone;

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if( method_exists($this, $f = '__construct' . $i) )
        {
            call_user_func_array(array($this, $f), $a);
        }
    }

    public function __construct2($name, $address)
    {
        $this->name = $name;
        $this->address = $address;
        $this->ipaddresses = array();
    }

    public function __construct7($media, $interfaceName, $interfaceType, $comment, $unitName, $vlan_tag, $ipaddresses)
    {
        $this->media = $media;
        $this->interfaceName = $interfaceName;
        $this->interfaceType = $interfaceType;
        $this->comment = $comment;
        $this->unitName = $unitName;
        $this->vlan_tag = $vlan_tag;
        $this->ipaddresses = array();
        if( isset($ipaddresses) && strcmp($ipaddresses, "") != 0 )
        {
            foreach( $ipaddresses as $ip )
            {
                $this->ipaddresses[] = $ip;
            }
        }
    }

    public function addIPaddress($ipaddress)
    {
        $this->ipaddresses[] = $ipaddress;
    }

    public function setVsys($vsys)
    {
        $this->vsys = $vsys;
    }

    public function setZone($zone)
    {
        $this->zone = $zone;
    }

    public function addZone($zone)
    {
        $this->zone = $this->zone . ',' . $zone;
        $zones = explode(',', $this->zone);
        $zones = array_unique($zones);
        $this->zone = implode(',', $zones);
    }

}

require_once INC_ROOT . '/libs/Security/OpenSSLTools.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
global $app;
//Capture request paramenters
include INC_ROOT . '/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);

#DEBUG
//$project="test";
//$action="import";
#DEBUG

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

$sourcesAdded = array();
global $source;

if( $action == "import" )
{
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $path = USERSPACE_PATH . "/projects/" . $project . "/toImport/";

    $i = 0;
    $dirrule = opendir($path);

    update_progress($project, '0.00', 'Reading config files', $jobid);
    while( $config_filename = readdir($dirrule) )
    {
        //if (($config_filename != ".") AND ( $config_filename != "..") AND ( $config_filename != "parsers.txt") AND ( $config_filename != "Backups") AND ( $config_filename != "Pcaps") AND ( $config_filename != "Reports") AND ( $config_filename != "MT-" . $project . ".xml.dat") AND ( $config_filename != "XGS") AND ( $config_filename != "CPviewer.html") AND ( !preg_match("/^MT-/", $config_filename))) {
        if( checkFiles2Import($config_filename, "Paloalto Networks") )
        {

            $config_path = $path . $config_filename;
            //Decrypt the file if necessary
            $encrypter = null;
            $file_parts = pathinfo($config_filename);
            $config_OriginalFilename = $config_filename;

            $content = null;

            if( $file_parts['extension'] == "dat" )
            {  //Example: config_backup.xml.dat
                $config_filename = $file_parts['filename']; //We will use as config_filename the non-encrypted filename: config_backup.xml
                if( !$projectObj = $app->project->where("name", $project)->get()->first() )
                {
                    update_progress($project, '1.00', 'This filename ' . $config_filename . ' cannot be decrypted', $jobid);
                    return;
                }
                $keyObj = $app->accessKey->where("type", "project")->where("lid", $projectObj->id)->get()->first();
                $encrypter = new OpenSSLTools($keyObj->key, $keyObj->iv);
                $content = $encrypter->decryptFromFile($path . $config_filename . ".dat");
                file_put_contents("/tmp/myfichero.xml", $content);

                //Verify if we need to rename the config file because it already exists
                $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename';");
                if( $isUploaded->num_rows != 0 )
                {
                    $today = date("Y.m.d_h\hi\m");
                    $oldName = $config_filename;
                    $config_filename .= "_$today";
                    rename($path . $oldName . ".dat", $path . $config_filename . ".dat");
                    $config_OriginalFilename = $config_filename . ".dat";
                }
            }


//            $filenameParts = pathinfo($config_filename);
//            $verificationName = $filenameParts['filename'];
//            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$verificationName';");
            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename';");
            if( $isUploaded->num_rows == 0 )
            {
                #Added 9/5/18 by Aestevez
                update_progress($project, '0.70', 'File:' . $config_filename . ' Phase 8 Referencing Address Groups', $jobid);
                $objectsInMemoryR = import_config($content, $config_path, $project, $config_filename, $jobid);
                if( $objectsInMemoryR != FALSE )
                {
                    $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename' GROUP BY filename;");
                    if( $getSourceID->num_rows == 1 )
                    {
                        $devicegroup = $config_filename;
                        $data = $getSourceID->fetch_assoc();
                        $source = $data['id'];
                    }
                    $sourcesAdded[] = $source;
                    GroupMember2IdPanos("address", $source, $objectsInMemoryR);
                    update_progress($project, '0.80', 'File:' . $config_filename . ' Phase 8 Referencing Services Groups', $jobid);
                    GroupMember2IdPanos("service", $source, $objectsInMemoryR);
                    update_progress($project, '0.90', 'File:' . $config_filename . ' Phase 8 Referencing Application Groups', $jobid);
                    GroupMember2IdPanos("application", $source, $objectsInMemoryR);

                    update_progress($project, '0.97', 'File:' . $config_filename . ' Phase 9 Identify Layer7 Security Rules', $jobid);

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
                }

                RelationsTagsObjects($config_filename);
            }
            else
            {
                update_progress($project, '0.00', 'This filename ' . $config_filename . ' its already uploaded. Skipping...', $jobid);
            }

            //Move this config into the parent folder
            $destinationPath = USERSPACE_PATH . "/projects/" . $project . "/";
            $configFile_orig_path = $path . $config_OriginalFilename;
            $configFile_dest_path = $destinationPath . $config_OriginalFilename;
            rename($configFile_orig_path, $configFile_dest_path);
        }
    }


    #Check used
    update_progress($project, '0.98', 'File:' . $config_filename . ' Phase 10 Check for Used Objects', $jobid);
    check_used_objects_new($sourcesAdded);
    update_progress($project, '1.00', 'Done.', $jobid);

}

function import_config(STRING $content = null, STRING $config_path, STRING $project, STRING $config_filename, INT $jobid)
{
    global $projectdb;
    global $pandbRBAC;
    global $app;

    libxml_use_internal_errors(TRUE);
    $xml = simplexml_load_string($content);

    $filename = $config_filename;
//    if (isXML($config_path) === TRUE) {
    if( $xml )
    {     //Validate $content is a valid XML string
//        $xml = simplexml_load_file($config_path);

        # Clean result tag from exported configs
        if( isset($xml->result->config) )
        {
            $xml1 = $xml->result->config;
            $xml = $xml1;
            $dom = new DOMDocument('1.0');
            $dom->preserveWhiteSpace = FALSE;
            $dom->formatOutput = TRUE;
            $dom->loadXML($xml->asXML());
            $xml_out = $dom->saveXML($dom->documentElement);
            $projectObj = $app->project->where("name", $project)->first();
            $keyObj = $app->accessKey->where("type", "project")->where("lid", $projectObj->id)->first();
            $encrypter = new OpenSSLTools($keyObj->key, $keyObj->iv);
            $encrypter->encryptToFile($xml_out, $config_path); //Save the modified XML into the encrypted file
            $xml = simplexml_load_string($xml_out);
//            $fileOut = $config_path;
//            $dom->save($fileOut);
//
//            #Remove first line
//            $contents = file_get_contents($fileOut);
//            $first_line = substr($contents, 0, 32);
//            file_put_contents($fileOut, substr($contents, 22));
//            $xml = simplexml_load_file($config_path);
        }

        $full_version = xml_attribute($xml, 'version');
        #CHECK INVALID CONTENT
        if( $full_version == "false" )
        {
            echo "NO version found";
            update_progress($project, '-1.00', 'The content is not a valid PANOS configuration. No version Found:' . $config_path, $jobid);
            unlink($config_path);
            exit(0);
        }
        else
        {
            echo "Valid PANOS Config file";
        }

        $devicegroup = $config_filename;
        $urldb = xml_attribute($xml, 'urldb');

        $version = getVersion($full_version);


        # Generate IDs for Groups
        $getMax = $projectdb->query("SELECT max(id) as max FROM address_groups_id;");
        if( $getMax->num_rows == 1 )
        {
            $getMaxData = $getMax->fetch_assoc();
            $aglid = $getMaxData['max'] + 1;
        }
        $getMax = $projectdb->query("SELECT max(id) as max FROM services_groups_id;");
        if( $getMax->num_rows == 1 )
        {
            $getMaxData = $getMax->fetch_assoc();
            $sglid = $getMaxData['max'] + 1;
        }
        $getMax = $projectdb->query("SELECT max(id) as max FROM applications_groups_id;");
        if( $getMax->num_rows == 1 )
        {
            $getMaxData = $getMax->fetch_assoc();
            $appglid = $getMaxData['max'] + 1;
        }

        #Check if there is a Baseconfig
        $result = $projectdb->query("SELECT filename FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
        if( $result->num_rows == 0 )
        {
            $baseconfig = 1;
        }
        else
        {
            $get = $result->fetch_assoc();
            $baseconfig_file = $get['filename'];
            if( $baseconfig_file == $config_filename )
            {
                $baseconfig = 1;
            }
            else
            {
                $baseconfig = 0;
            }
        }
        $result->free();

        $allDG = array();
        $allTemplate = array();
        $template_map = array();
        if( isset($xml->{'mgt-config'}->devices) )
        {
            $device = "panorama";
            $ispanorama = 1;
            $projectdb->query("INSERT INTO device_mapping (device,urldb,version,ispanorama,active,project,filename,vsys,baseconfig) VALUES ('$devicegroup','$urldb','$full_version',1,1,'$project','$config_filename','shared','$baseconfig')");
            $config_filename = $projectdb->insert_id;
            $source = $config_filename;

            # Save Panorama tag
            $panorama_xml = addslashes($xml->panorama->asXML());
            $projectdb->query("INSERT INTO panorama (source,xml) VALUES ('$config_filename','$panorama_xml');");
            $template = 0;

            # ADD DEVICE-GROUP INFO
            $platform = "device-group";
            $policies = array("pre-rulebase", "post-rulebase");

            //Adding the Shared
            $sharedID = $projectdb->query("SELECT id FROM device_mapping WHERE vsys = 'shared' AND filename='$filename'");
            if( $sharedID->num_rows > 0 )
            {
                $dataSharedID = $sharedID->fetch_assoc();
                $device_mapping_id = $dataSharedID['id'];
                $projectdb->query("INSERT INTO devicegroups (master_device,description,source,device_mapping_id) VALUES ('None','Shared DG','$config_filename','$device_mapping_id');");
            }

            $vsys0 = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/device-group/entry");
            if( count($vsys0) > 0 )
            {
                foreach( $vsys0 as $key => $value )
                {
                    $new_vsys = $value->attributes()->name;
                    $allDG[] = $new_vsys;
                    $projectdb->query("INSERT INTO device_mapping (device,urldb,version,ispanorama,active,project,filename,vsys,baseconfig) VALUES ('$devicegroup','$urldb','$full_version',1,1,'$project','$filename','$new_vsys','$baseconfig')");
                    $device_mapping_id = $projectdb->insert_id;
                    $dg0 = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$new_vsys']");
                    foreach( $dg0 as $mykey => $myvalue )
                    {
                        $dg0description = addslashes($myvalue->description);
                        $dg0devices = addslashes($myvalue->devices->asXML());
                        if( isset($myvalue->{'master-device'}) )
                        {
                            $dg0master_device = addslashes($myvalue->{'master-device'}->asXML());
                        }
                        else
                        {
                            $dg0master_device = "None";
                        }
                        $projectdb->query("INSERT INTO devicegroups (devices,master_device,description,source,device_mapping_id) VALUES ('$dg0devices','$dg0master_device','$dg0description','$config_filename','$device_mapping_id');");
                    }
                    $dg = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$new_vsys']/devices/entry");
                    foreach( $dg as $mykey => $myvalue )
                    {
                        $serialnumber = $myvalue->attributes()->name;
                        if( isset($myvalue->vsys) )
                        {
                            $getVsys = $myvalue->vsys->entry;
                            $serialnumber_vsys = $getVsys->attributes()->name;
                        }
                        else
                        {
                            $serialnumber_vsys = "vsys1";
                        }
                        $projectdb->query("INSERT INTO devicegroup_mapping (device_mapping_id,serial,vsys,source) VALUES ('$device_mapping_id','$serialnumber','$serialnumber_vsys','$config_filename');");
                    }
                }
            }

            # Read the readonly tag
            if( isset($xml->readonly) )
            {
                if( $version >= 8 )
                {
                    $readonly = $xml->xpath('//readonly/devices/entry[@name="localhost.localdomain"]/device-group');
                    if( isset($xml->readonly->{'max-internal-id'}) )
                    {
                        $max_internal_id = $xml->readonly->{'max-internal-id'};
                    }
                    else
                    {
                        $max_internal_id = 1;
                    }

                    foreach( $readonly[0] as $myentry )
                    {
                        $getParentid = 0;
                        $dgroupname = $myentry->attributes()->name;
                        $parent_dg = $myentry->{'parent-dg'};
                        $parent_dg = (isset($myentry->{'parent-dg'}) && $myentry->{'parent-dg'} != '') ? $myentry->{'parent-dg'} : 'shared';
                        $internal_id = $myentry->id;
                        $getDG = $projectdb->query("SELECT id FROM device_mapping WHERE vsys='$parent_dg' AND filename='$filename';");
                        if( $getDG->num_rows == 1 )
                        {
                            $getDGData = $getDG->fetch_assoc();
                            $getParentid = $getDGData['id'];
                        }

                        $getDG = $projectdb->query("SELECT id FROM device_mapping WHERE vsys='$dgroupname' AND filename='$filename';");
                        if( $getDG->num_rows == 1 )
                        {
                            $getDGData = $getDG->fetch_assoc();
                            $getDGid = $getDGData['id'];
                            $projectdb->query("UPDATE devicegroups SET parent_dg='$getParentid', internal_id='$internal_id', max_internal_id='$max_internal_id' WHERE device_mapping_id='$getDGid';");
                        }

                    }
                }
                elseif( $version >= 7 )
                {
                    $readonly = $xml->xpath('//readonly/dg-meta-data/dginfo');
                    if( isset($xml->readonly->{'dg-meta-data'}->{'max-dg-id'}) )
                    {
                        $max_internal_id = $xml->readonly->{'dg-meta-data'}->{'max-dg-id'};
                    }
                    else
                    {
                        $max_internal_id = 1;
                    }
                    foreach( $readonly[0] as $myentry )
                    {
                        $getParentid = 0;
                        $dgroupname = $myentry->attributes()->name;
                        $parent_dg = $myentry->{'parent-dg'};
                        $internal_id = $myentry->{'dg-id'};
                        $getDG = $projectdb->query("SELECT id FROM device_mapping WHERE vsys='$parent_dg' AND filename='$filename';");
                        if( $getDG->num_rows == 1 )
                        {
                            $getDGData = $getDG->fetch_assoc();
                            $getParentid = $getDGData['id'];
                        }

                        $getDG = $projectdb->query("SELECT id FROM device_mapping WHERE vsys='$dgroupname' AND filename='$filename';");
                        if( $getDG->num_rows == 1 )
                        {
                            $getDGData = $getDG->fetch_assoc();
                            $getDGid = $getDGData['id'];
                            $projectdb->query("UPDATE devicegroups SET parent_dg='$getParentid', internal_id='$internal_id', max_internal_id='$max_internal_id' WHERE device_mapping_id='$getDGid';");
                        }

                    }
                }
            }

            # ADD TEMPLATE INFO
            # Template 0 es for the device it self (panorama this case)
            $allTemplate[] = array("id" => 0);
            $templates = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry");
            foreach( $templates as $key => $value )
            {
                $template_name = $value->attributes()->name;

                # SETTINGS
                if( isset($value->settings) )
                {
                    $multi_vsys = "";
                    $operational_mode = "";
                    $vpn_disable_mode = "";
                    if( isset($value->settings->{'multi-vsys'}) )
                    {
                        $multi_vsys = $value->settings->{'multi-vsys'};
                    }
                    if( isset($value->settings->{'operational-mode'}) )
                    {
                        $operational_mode = $value->settings->{'operational-mode'};
                    }
                    if( isset($value->settings->{'vpn-disable-mode'}) )
                    {
                        $vpn_disable_mode = $value->settings->{'vpn-disable-mode'};
                    }

                    if( isset($value->settings->{'default-vsys'}) )
                    {
                        $default_vsys = $value->settings->{'default-vsys'};
                    }
                    else
                    {
                        $default_vsys = "vsys1";
                    }
                }
                else
                {
                    $multi_vsys = "";
                    $operational_mode = "";
                    $vpn_disable_mode = "";
                }

                # DEVICES
                if( isset($value->devices) )
                {
                    $devices = addslashes($value->devices->asXML());
                }
                else
                {
                    $devices = "";
                }

                # DESCRIPTION
                if( isset($value->description) )
                {
                    $template_desc = addslashes($value->description);
                }
                else
                {
                    $template_desc = "";
                }

                $projectdb->query("INSERT INTO templates_mapping (name,filename,source,project) VALUES ('$template_name','$filename','$config_filename','$project')");
                $templates_mapping_id = $projectdb->insert_id;
                $templateQuery = "INSERT INTO templates (name,description,multi_vsys,operational_mode,vpn_disable_mode,devices,source,templates_mapping_id,default_vsys) VALUES ('$template_name','$template_desc','$multi_vsys','$operational_mode','$vpn_disable_mode','$devices','$config_filename','$templates_mapping_id','$default_vsys');";
                $projectdb->query($templateQuery);
                if( $template_name != "" )
                {
                    $template_map["$template_name"]['id'] = $templates_mapping_id;
                }

                $allTemplate[] = array("id" => $templates_mapping_id, "name" => (string)$template_name);
            }

            # Template Stack
            $template_stack_array = array();
            $templates_stack = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template-stack/entry");
            foreach( $templates_stack as $key => $value1 )
            {
                $template_name = $value1->attributes()->name;
                # DEVICES
                if( isset($value1->devices) )
                {
                    $devices = addslashes($value1->devices->asXML());
                }
                else
                {
                    $devices = "";
                }

                # DESCRIPTION
                if( isset($value1->description) )
                {
                    $template_desc = addslashes($value1->description);
                }
                else
                {
                    $template_desc = "";
                }

                $projectdb->query("INSERT INTO templates_stacks_id (name,description,devices,source) VALUES ('$template_name','$template_desc','$devices','$config_filename')");
                $templateStackID = $projectdb->insert_id;

                # MEMBERS
                if( isset($value1->templates) )
                {
                    foreach( $value1->templates->member as $kk => $stack_member )
                    {
                        $template_map_id = $template_map["$stack_member"]['id'];
                        $template_stack_array[] = "('$templateStackID','$stack_member','$template_map_id','$config_filename')";
                    }
                }
            }
            if( count($template_stack_array) > 0 )
            {
                $projectdb->query("INSERT INTO templates_stacks (lid,name,templates_mapping_id,source) VALUES " . implode(",", $template_stack_array) . ";");
                unset($template_stack_array);
            }

            // Update view from user_settings to panorama
            $getIdProject = $pandbRBAC->query("SELECT id FROM projects WHERE name = '$project';");
            if( $getIdProject->num_rows == 1 )
            {
                $dataID = $getIdProject->fetch_array();
                $id_project = $dataID['id'];

                $pandbRBAC->query("UPDATE user_settings SET view = 'panorama' WHERE project_id = '$id_project';");
            }

        }
        else
        {
            $device = "firewall";
            $ispanorama = 0;
            $projectdb->query("INSERT INTO device_mapping (device,urldb,version,ispanorama,active,project,filename,vsys,baseconfig) VALUES ('$devicegroup','$urldb','$full_version',0,1,'$project','$config_filename','shared','$baseconfig')");
            $config_filename = $projectdb->insert_id;
            $source = $config_filename;

            # ADD TEMPLATE INFO
            $template_name = "template" . $config_filename;
            $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$config_filename');");
            $template = $projectdb->insert_id;
            # Case Firewall template is an ID
            $allTemplate[] = array("id" => $template);
            //$allTemplate[]=array("id"=>0);
            //$template=0;
            $platform = "vsys";
            $policies = array("rulebase");
            $vsys0 = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/vsys/entry");
            if( count($vsys0) > 0 )
            {
                foreach( $vsys0 as $key => $value )
                {
                    $new_vsys = $value->attributes()->name;
                    $allDG[] = $new_vsys;
                    $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig) VALUES ('$devicegroup','$full_version',0,1,'$project','$filename','$new_vsys','$baseconfig')");
                    # ADD VSYS INFORMATION
                    $displayName = $value->{'display-name'};
                    $VsysInterface = "";
                    $VsysVR = "";
                    $VsysVWire = "";
                    $VsysVlan = "";
                    if( isset($value->import->network->interface) )
                    {
                        $vsysInt = array();
                        foreach( $value->import->network->interface->member as $kkkey => $int )
                        {
                            $vsysInt[] = $int;
                        }
                        $VsysInterface = implode(",", $vsysInt);
                    }
                    if( isset($value->import->network->{'virtual-router'}) )
                    {
                        $vsysInt = array();
                        foreach( $value->import->network->{'virtual-router'}->member as $kkkey => $int )
                        {
                            $vsysInt[] = $int;
                        }
                        $VsysVR = implode(",", $vsysInt);
                    }
                    if( isset($value->import->network->{'virtual-wire'}) )
                    {
                        $vsysInt = array();
                        foreach( $value->import->network->{'virtual-wire'}->member as $kkkey => $int )
                        {
                            $vsysInt[] = $int;
                        }
                        $VsysVWire = implode(",", $vsysInt);
                    }
                    if( isset($value->import->network->vlan) )
                    {
                        $vsysInt = array();
                        foreach( $value->import->network->vlan->member as $kkkey => $int )
                        {
                            $vsysInt[] = $int;
                        }
                        $VsysVlan = implode(",", $vsysInt);
                    }
                    if( isset($value->import->resource) )
                    {
                        $max_application_override_rules = $value->import->resource->{'max-application-override-rules'};
                        $max_concurrent_ssl_vpn_tunnels = $value->import->resource->{'max-concurrent-ssl-vpn-tunnels'};
                        if( $version >= 8 )
                        {
                            $max_cp_rules = $value->import->resource->{'max-auth-rules'};
                        }
                        else
                        {
                            $max_cp_rules = $value->import->resource->{'max-cp-rules'};
                        }
                        $max_dos_rules = $value->import->resource->{'max-dos-rules'};
                        $max_nat_rules = $value->import->resource->{'max-nat-rules'};
                        $max_pbf_rules = $value->import->resource->{'max-pbf-rules'};
                        $max_qos_rules = $value->import->resource->{'max-qos-rules'};
                        $max_security_rules = $value->import->resource->{'max-security-rules'};
                        $max_sessions = $value->import->resource->{'max-sessions'};
                        $max_site_to_site_vpn_tunnels = $value->import->resource->{'max-site-to-site-vpn-tunnels'};
                        $max_ssl_decryption_rules = $value->import->resource->{'max-ssl-decryption-rules'};
                    }
                    else
                    {
                        $max_application_override_rules = "";
                        $max_concurrent_ssl_vpn_tunnels = "";
                        $max_cp_rules = "";
                        $max_dos_rules = "";
                        $max_nat_rules = "";
                        $max_pbf_rules = "";
                        $max_qos_rules = "";
                        $max_security_rules = "";
                        $max_sessions = "";
                        $max_site_to_site_vpn_tunnels = "";
                        $max_ssl_decryption_rules = "";
                    }
                    if( isset($value->import->{'visible-vsys'}) )
                    {
                        $vsysInt = array();
                        foreach( $value->import->{'visible-vsys'}->member as $kkkey => $int )
                        {
                            $vsysInt[] = $int;
                        }
                        $visible_vsys = implode(",", $vsysInt);
                    }
                    else
                    {
                        $visible_vsys = "";
                    }
                    $dns_proxy = $value->import->{'dns-proxy'};
                    if( isset($value->setting->{'ssl-decrypt'}->{'allow-forward-decrypted-content'}) )
                    {
                        $allow_forward_decrypted_content = $value->setting->{'ssl-decrypt'}->{'allow-forward-decrypted-content'};
                    }
                    else
                    {
                        $allow_forward_decrypted_content = "";
                    }
                    $projectdb->query("INSERT INTO virtual_systems (template,source,name,display_name,interfaces,virtual_router,virtual_wire,vlan,max_application_override_rules,max_concurrent_ssl_vpn_tunnels,max_cp_rules,max_dos_rules,max_nat_rules,max_pbf_rules,max_qos_rules,max_security_rules,max_sessions,max_site_to_site_vpn_tunnels,max_ssl_decryption_rules,visible_vsys,dns_proxy,allow_forward_decrypted_content) VALUES ('$template','$config_filename','$new_vsys','$displayName','$VsysInterface','$VsysVR','$VsysVWire','$VsysVlan','$max_application_override_rules','$max_concurrent_ssl_vpn_tunnels','$max_cp_rules','$max_dos_rules','$max_nat_rules','$max_pbf_rules','$max_qos_rules','$max_security_rules','$max_sessions','$max_site_to_site_vpn_tunnels','$max_ssl_decryption_rules','$visible_vsys','$dns_proxy','$allow_forward_decrypted_content');");

                }
            }
        }

        update_progress($project, '0.10', 'File:' . $filename . ' Phase 0 Loading Pre-defined Objects', $jobid);

        add_default_services($source);
        add_default_profiles($source, $version);
        add_default_tags($source, $version);
        add_default_external_list($source, $version);
        $count_total_templates = count($allTemplate);
        $count_templates = 1;

        // Set url categories according to urldb
        setUrlCategories($source, $urldb);

        # SHARED OBJECTS
        update_progress($project, '0.12', 'File:' . $filename . ' Phase 1 Loading Shared Objects', $jobid);
        if( isset($xml->shared) )
        {

            # ADMIN ROLES FW
            if( isset($xml->shared->{'admin-role'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Admin Role, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/admin-role/entry");
                xml_add_admin_role($projectdb, $profiles, $source, '0');
            }

            #LOG SETTINGS
            if( isset($xml->shared->{'log-settings'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Log Settings, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/log-settings");
                xml_add_log_settings($projectdb, $source, 'shared', '0', $profiles, $devicegroup);
            }

            # BOTNET
            if( isset($xml->shared->botnet) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Botnet Settings, Shared ', $jobid);
                $botnet = addslashes($xml->shared->botnet->asXML());
                $projectdb->query("INSERT INTO botnet (xml,source) VALUES ('$botnet','$source')");
                $botnet = "";
            }

            # SERVER PROFILES
            if( isset($xml->shared->{'server-profile'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Server Profiles, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/server-profile");
                xml_add_server_profile($projectdb, $source, 'shared', '0', $profiles);
            }

            # CERTIFICATE
            if( isset($xml->shared->certificate) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Certificates, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/certificate");
                xml_add_certificate($projectdb, $source, 'shared', '0', $profiles);
            }

            # CERTIFICATE PROFILES
            if( isset($xml->shared->{'certificate-profile'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Certificate Profiles, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/certificate-profile");
                xml_add_certificate_profile($projectdb, $source, 'shared', '0', $profiles);
            }

            # Panorama
            if( isset($xml->shared->panorama) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Panorama Config, Shared ', $jobid);
                $sql = array();
                $profiles = $xml->xpath("/config/shared/panorama");
                $theProfilecontent = addslashes($profiles[0]->asXML());
                $sql[] = "('$source','$theProfilecontent')";

                if( count($sql) > 0 )
                {
                    $projectdb->query("INSERT INTO panorama (source,xml) VALUES " . implode(",", $sql) . ";");
                }
            }

            # TAG
            if( isset($xml->shared->{'tag'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Tag, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/tag/entry");
                xml_add_tag($profiles, $config_filename, "shared", $devicegroup);
            }

            # RESPONSE PAGES
            if( isset($xml->shared->{'response-page'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Response Page, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/response-page");
                xml_add_response_page($profiles, $config_filename, 'shared', $template);
            }

            # ADDRESS
            if( isset($xml->shared->address) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Address, Shared ', $jobid);
                $shared_address = $xml->xpath("/config/shared/address/entry");
                xml_add_address($shared_address, $config_filename, "shared", $devicegroup);
            }

            # SERVICES
            if( isset($xml->shared->service) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Services, Shared ', $jobid);
                $address = $xml->xpath("/config/shared/service/entry");
                xml_add_services($address, $config_filename, 'shared', $devicegroup);
            }

            # ADDRESS GROUPS
            if( isset($xml->shared->{'address-group'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Address Groups, Shared ', $jobid);
                $address = $xml->xpath("/config/shared/address-group/entry");
                xml_add_address_groups($aglid, $address, $config_filename, 'shared', $devicegroup);
            }

            # SERVICES GROUPS
            if( isset($xml->shared->{'service-group'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Service Groups, Shared ', $jobid);
                $address = $xml->xpath("/config/shared/service-group/entry");
                xml_add_services_groups($sglid, $address, $config_filename, 'shared', $devicegroup);
            }

            # APPLICATION CUSTOM
            if( isset($xml->shared->{'application'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Custom Applications, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/application/entry");
                xml_add_applications($projectdb, $profiles, $source, 'shared', $devicegroup, $version);
            }

            # APPLICATIONS FILTER
            if( isset($xml->shared->{'application-filter'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Application Filters, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/application-filter/entry");
                xml_add_applications_filters($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

            # APPLICATION GROUPS
            if( isset($xml->shared->{'application-group'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Application Groups, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/application-group/entry");
                xml_add_applications_groups($appglid, $profiles, $config_filename, 'shared', $devicegroup, $version);
            }

            # GLOBAL PROTECT PORTAL
            if( isset($xml->shared->{'global-protect'}->{'global-protect-portal'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Global Protect Portal, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/global-protect/global-protect-portal/entry");
                xml_add_gp_portal($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

            # GLOBAL PROTECT GATEWAY
            if( isset($xml->shared->{'global-protect'}->{'global-protect-gateway'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Global Protect Gateways, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/global-protect/global-protect-gateway/entry");
                xml_add_gp_gateway($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

            # GLOBAL PROTECT MDM
            if( isset($xml->shared->{'global-protect'}->{'global-protect-mdm'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Global Protect MDM, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/global-protect/global-protect-mdm/entry");
                xml_add_gp_mdm($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

            # SCHEDULES
            if( isset($xml->shared->{'schedule'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Schedules, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/schedule/entry");
                xml_add_schedule($profiles, $config_filename, 'shared', $devicegroup);
            }

            # PROFILES
            if( isset($xml->shared->{'profiles'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Profiles, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/profiles");
                xml_add_profiles($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

            # PROFILES GROUPS
            if( isset($xml->shared->{'profile-group'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Profile Groups, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/profile-group/entry");
                xml_add_profiles_groups($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

            # REGIONS
            if( isset($xml->shared->{'region'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Custom Regions, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/region/entry");
                xml_add_regions($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

            # EXTERNAL LISTS
            if( isset($xml->shared->{'external-list'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading External Lists, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/external-list/entry");
                xml_add_external_lists($projectdb, $profiles, $source, 'shared', $devicegroup);
            }

//            # CUSTOM URL CATEGORY
//            if (isset($xml->shared->{'custom-url-category'})){
//                update_progress($project, '0.50', 'File:' . $filename . ' Phase 3 Loading Custom URL Category, Shared ',$jobid);
//                $profiles = $xml->xpath("/config/shared/custom-url-category/entry");
//                xml_add_custom_url_category($projectdb,$profiles,$source,'shared',$devicegroup);
//            }
            # REPORTS
            if( isset($xml->shared->{'reports'}) )
            {
                update_progress($project, '0.12', 'File:' . $filename . ' Phase 3 Loading Reports, Shared ', $jobid);
                $profiles = $xml->xpath("/config/shared/reports/entry");
                xml_add_reports($projectdb, $profiles, $source, 'shared');
            }

            # LOAD ALL OBJECTS TO INMEMORY
            $objectsInMemory = array();
            $data = array("projectdb" => $projectdb, "source" => $source);
            load_default_objects_byname($objectsInMemory, $data);

            # POLICIES
            foreach( $policies as $key => $policy )
            {
                if( $policy == "post-rulebase" )
                {
                    $preorpost = 1;
                }
                else
                {
                    $preorpost = 0;
                }

                # SECURITY
                if( isset($xml->shared->{$policy}->security->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Security Policies, Shared ', $jobid);
                    $address = $xml->xpath("/config/shared/$policy/security/rules/entry");
                    pan_read_rules_security($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);
                }

                # DEFAULT SECURITY
                if( isset($xml->shared->{$policy}->{'default-security-rules'}->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Default Security Policies, Shared ', $jobid);
                    $address = $xml->xpath("/config/shared/$policy/default-security-rules");
                    pan_read_rules_default($preorpost, $address, $source, 'shared', $version, $devicegroup);
                }

                # NAT POLICIES
                if( isset($xml->shared->{$policy}->nat->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading NAT Policies, Shared ', $jobid);
                    $address = $xml->xpath("/config/shared/$policy/nat/rules/entry");
                    pan_read_rules_nat2($preorpost, $address, $source, 'shared', $version, $devicegroup, $objectsInMemory);
                }

                # APPLICATION OVERRIDE
                if( isset($xml->shared->{$policy}->{'application-override'}->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Application Override Policies, Shared ', $jobid);
                    $address = $xml->xpath("/config/shared/$policy/application-override/rules/entry");
                    pan_read_rules_appoverride($preorpost, $address, $source, 'shared', $version, $devicegroup, $objectsInMemory);
                }

                # PBF RULES
                if( isset($xml->shared->{$policy}->pbf->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Policy Based Forwarding Policies, Shared ', $jobid);
                    $address = $xml->xpath("/config/shared/$policy/pbf");
                    //pan_read_rules_pbf($preorpost, $address, $source, 'shared', $version, $devicegroup);
                    //pan_read_rules_pbf($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);

                    $address_other_rules = $xml->xpath("/config/shared/$policy/pbf");
                    $address = $xml->xpath("/config/shared/$policy/pbf/rules/entry");
                    pan_read_rules_pbf_other_rules($preorpost, $address_other_rules, $source, 'shared', $version, $devicegroup);
                    pan_read_rules_pbf($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);
                }

                # DECRYPTION RULES
                if( isset($xml->shared->{$policy}->decryption->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Decryption Policies, Shared ', $jobid);
                    $address_other_rules = $xml->xpath("/config/shared/$policy/decryption");
                    $address = $xml->xpath("/config/shared/$policy/decryption/rules/entry");
                    pan_read_rules_decryption_other_rules($preorpost, $address_other_rules, $source, 'shared', $version, $devicegroup);
                    pan_read_rules_decryption($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);

                }

                # QoS RULES
                if( isset($xml->shared->{$policy}->qos->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading QoS Policies, Shared ', $jobid);
                    $address_other_rules = $xml->xpath("/config/shared/$policy/qos");
                    $address = $xml->xpath("/config/shared/$policy/qos/rules/entry");
                    pan_read_rules_qos_other_rules($preorpost, $address_other_rules, $source, 'shared', $version, $devicegroup);
                    pan_read_rules_qos($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);
                }

                # TUNNEL INSPECTION RULES
                if( isset($xml->shared->{$policy}->{'tunnel-inspect'}->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Tunnel Inspection Policies, Shared ', $jobid);
                    $address_other_rules = $xml->xpath("/config/shared/$policy/tunnel-inspect");
                    $address = $xml->xpath("/config/shared/$policy/tunnel-inspect/rules/entry");
                    pan_read_rules_tunnel_inspect_other_rules($preorpost, $address_other_rules, $source, 'shared', $version, $devicegroup);
                    pan_read_rules_tunnel_inspect($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);
                }

                if( $version >= 8 )
                {
                    # NEW VERSION 8
                    # AUTHENTICATION RULES
                    if( isset($xml->shared->{$policy}->authentication->rules) )
                    {
                        update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Authentication Policies, Shared ', $jobid);
                        $address_other_rules = $xml->xpath("/config/shared/$policy/authentication");
                        $address = $xml->xpath("/config/shared/$policy/authentication/rules/entry");
                        pan_read_rules_authentication_other_rules($preorpost, $address_other_rules, $source, 'shared', $version, $devicegroup);
                        pan_read_rules_authentication($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);
                    }
                }
                else
                {
                    # VERSION 7
                    # CAPTIVE PORTAL RULES
                    if( isset($xml->shared->{$policy}->{'captive-portal'}->rules) )
                    {
                        update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading Captive Portal Policies, Shared ', $jobid);
                        $address_other_rules = $xml->xpath("/config/shared/$policy/captive-portal");
                        $address = $xml->xpath("/config/shared/$policy/captive-portal/rules/entry");
                        pan_read_rules_captiveportal_other_rules($preorpost, $address_other_rules, $source, 'shared', $version, $devicegroup);
                        pan_read_rules_captiveportal($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);
                    }
                }

                # DOS RULES
                if( isset($xml->shared->{$policy}->dos->rules) )
                {
                    update_progress($project, '0.14', 'File:' . $filename . ' Phase 3 Loading DoS Policies, Shared ', $jobid);
                    $address_other_rules = $xml->xpath("/config/shared/$policy/dos");
                    $address = $xml->xpath("/config/shared/$policy/dos/rules/entry");
                    pan_read_rules_dos_other_rules($preorpost, $address_other_rules, $source, 'shared', $version, $devicegroup);
                    pan_read_rules_dos($preorpost, $address, $source, 'shared', $version, $devicegroup, $urldb, $objectsInMemory);
                }
            }
        }

        update_progress($project, '0.15', 'File:' . $filename . ' Phase 2 Loading Templates/Device/Network', $jobid);
        foreach( $allTemplate as $tkey => $tvalue )
        {
            if( isset($tvalue['name']) )
            {
                # Panorama Template
                $value0 = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $tvalue['name'] . "']/config");
                $value = $value0[0];
            }
            else
            {
                # Panorama Device or Firewall. is Integer and It could be 0.
                $value = $xml;
            }

            if( !isset($tvalue['name']) )
            {
                $templatename = "Device";
            }
            else
            {
                $templatename = $tvalue['name'];
            }
            $template = $tvalue['id'];
            $percentage_total = round($count_templates / $count_total_templates, 2) * 0.5;

            $profiles = array();

            # Administrators
            if( isset($value->{'mgt-config'}->users) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading MGT-CONFIG Users, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("mgt-config/users/entry");
                xml_add_mgtconfig_users($projectdb, $source, '', $template, $profiles);
            }

            #DeviceConfig
            if( isset($value->devices->entry->deviceconfig) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading MGT-CONFIG Users, Template: ' . $templatename, $jobid);
                $xxml = addslashes($value->devices->entry->deviceconfig->asXML());
                $projectdb->query("INSERT INTO deviceconfig (source,template,xml) VALUES ('$source',$template,'$xxml');");
            }

            # MGT-CONFIG password-complexity
            if( isset($value->{'mgt-config'}->{'password-complexity'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading MGT-CONFIG Password Complexity, Template: ' . $templatename, $jobid);
                $xxml = addslashes($value->{'mgt-config'}->{'password-complexity'}->asXML());
                $projectdb->query("INSERT INTO password_complexity (source,template,xml) VALUES ('$source',$template,'$xxml');");
            }

            ### NETWORK ###

            # MONITOR PROFILES
            if( isset($value->devices->entry->network->profiles->{'monitor-profile'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Profiles, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/profiles/monitor-profile/entry");
                xml_add_network_monitor_profile($projectdb, $profiles, $source, $template);
            }

            # ZONE PROTECTION PROFILES
            if( isset($value->devices->entry->network->profiles->{'zone-protection-profile'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Zone Protection Profiles, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/profiles/zone-protection-profile/entry");
                xml_add_network_zone_protection($projectdb, $profiles, $source, '', $template);
            }

            # QoS PROFILES
            if( isset($value->devices->entry->network->qos->profile) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK QoS Profiles, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/qos/profile/entry");
                xml_add_network_qos_profile($projectdb, $profiles, $source, '', $template);
            }

            # QoS INTERFACE
            if( isset($value->devices->entry->network->qos->interface) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK QoS Interface, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/qos/interface/entry");
                xml_add_network_qos_interface($projectdb, $profiles, $source, '', $template);
            }

            # DHCP Server and Relay
            if( isset($value->devices->entry->network->dhcp) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK DHCP, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/dhcp/interface/entry");
                xml_add_network_dhcp($projectdb, $profiles, $source, '', $template);
            }

            # INTERFACES
            if( isset($value->devices->entry->network->interface->loopback) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Interface Loopback, Template: ' . $templatename, $jobid);
                add_interface_loopback($template, $source, "loopback", $value);
            }
            if( isset($value->devices->entry->network->interface->tunnel) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Interface Tunnel, Template: ' . $templatename, $jobid);
                add_interface_tunnel($template, $source, "tunnel", $value);
            }
            if( isset($value->devices->entry->network->interface->ethernet) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Interface Ethernet, Template: ' . $templatename, $jobid);
                add_interfaces_ethernet_and_aggregated($template, $source, "ethernet", $value);
            }
            if( isset($value->devices->entry->network->interface->{'aggregate-ethernet'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Interface Aggregate Ethernet, Template: ' . $templatename, $jobid);
                add_interfaces_ethernet_and_aggregated($template, $source, "aggregate-ethernet", $value);
            }
            if( isset($value->devices->entry->network->interface->vlan) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Interface Vlan, Template: ' . $templatename, $jobid);
                add_interfaces_vlan($template, $source, "vlan", $value);
            }

            # VLANS
            if( isset($value->devices->entry->network->vlan) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Vlan, Template: ' . $templatename, $jobid);
                add_vlans($template, $source, "vlan", $value);
            }

            # VIRTUAL WIRES
            if( isset($value->devices->entry->network->{'virtual-wire'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Virtual-Wire, Template: ' . $templatename, $jobid);
                add_vwires($template, $source, "virtual-wire", $value);
            }

            # VIRTUAL ROUTERS
            if( isset($value->devices->entry->network->{'virtual-router'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Virtual Router, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/virtual-router/entry");
                xml_add_network_virtual_router($projectdb, $profiles, $source, '', $template, $version);
            }

            # INTERFACE MANAGEMENT PROFILE
            if( isset($value->devices->entry->network->profiles->{'interface-management-profile'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Management Profiles, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile/entry");
                xml_add_network_interface_management_profiles($projectdb, $profiles, $source, '', $template, $version);
            }

            # IKE CRYPTO
            if( isset($value->devices->entry->network->ike->{'crypto-profiles'}->{'ike-crypto-profiles'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK IKE Crypto Profiles, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry");
                xml_add_network_ike_crypto_profile($projectdb, $profiles, $source, '', $template, $version);
            }

            # IPSEC CRYPTO
            if( isset($value->devices->entry->network->ike->{'crypto-profiles'}->{'ipsec-crypto-profiles'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK IPSEC Crypto Profiles, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry");
                xml_add_network_ike_crypto_ipsec_profile($projectdb, $profiles, $source, '', $template, $version);
            }

            # IKE GATEWAYS
            if( isset($value->devices->entry->network->ike->gateway) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK IKE Gateway, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry");
                xml_add_network_ike_gateway($projectdb, $profiles, $source, '', $template, $version);
            }

            # IPSEC TUNNEL
            if( isset($value->devices->entry->network->tunnel->ipsec) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Tunnel IPSEC, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry");
                xml_add_network_tunnel_ipsec($projectdb, $profiles, $source, '', $template, $version);
            }

            # GLOBAL PROTECT IPSEC CRYPTO
            if( isset($value->devices->entry->network->ike->{'crypto-profiles'}->{'global-protect-app-crypto-profiles'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK Global Protect App Crypto Profile, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/global-protect-app-crypto-profiles/entry");
                xml_add_network_gp_app_crypto_profiles($projectdb, $profiles, $source, '', $template);
            }

            # DNS PROXY
            if( isset($value->devices->entry->network->{'dns-proxy'}) )
            {
                update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading NETWORK DNS-PROXY, Template: ' . $templatename, $jobid);
                $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/network/dns-proxy/entry");
                xml_add_dns_proxy($projectdb, $source, 'shared', $template, $profiles);
            }

            # SHARED Inside Template
            if( (isset($value->shared)) and ($ispanorama == 1) and ($template != 0) )
            {
                $new_vsyst = "shared";

                # SERVER PROFILES
                if( isset($value->shared->{'server-profile'}) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Server Profiles VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/server-profile");
                    xml_add_server_profile($projectdb, $source, $new_vsyst, $template, $profiles);
                }

                # ADMIN ROLES FW
                if( isset($value->shared->{'admin-role'}) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Admin Roles VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/admin-role/entry");
                    xml_add_admin_role($projectdb, $profiles, $source, $template);
                }

                #LOG SETTINGS
                if( isset($value->shared->{'log-settings'}) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Log Settings VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/log-settings");
                    xml_add_log_settings($projectdb, $source, $new_vsyst, $template, $profiles, $devicegroup);
                }

                # AUTHENTICATION PROFILE
                if( isset($value->shared->{'authentication-profile'}) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Authentication Profiles VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/authentication-profile/entry");
                    xml_add_authentication_profile($projectdb, $source, $new_vsyst, $template, $profiles);
                }

                # AUTHENTICATION SEQUENCE
                if( isset($value->shared->{'authentication-sequence'}) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Authentication Sequence VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/authentication-sequence/entry");
                    xml_add_authentication_sequence($projectdb, $source, $new_vsyst, $template, $profiles);
//                    foreach ($profiles as $key => $profilesArray) {
//                        $GroupName = $profilesArray->attributes()->name;
//                        $content = addslashes($profilesArray->asXML());
//                        $sql[] = "('$source','$GroupName','$content','shared','$templates_mapping_id')";
//                    }
//                    if (count($sql) > 0) {
//                        $projectdb->query("INSERT INTO authentication_sequence (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
//                    }
                }

                # CERTIFICATE
                if( isset($value->shared->certificate) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Certificates VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/certificate/entry");
                    xml_add_certificate($projectdb, $source, $new_vsyst, $template, $profiles);
//                    foreach ($profiles as $key => $profilesArray) {
//                        $GroupName = $profilesArray->attributes()->name;
//                        $content = addslashes($profilesArray->asXML());
//                        $sql[] = "('$source','$GroupName','$content','shared','$templates_mapping_id')";
//                    }
//                    if (count($sql) > 0) {
//                        $projectdb->query("INSERT INTO certificate (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
//                    }
                }

                # CERTIFICATE Profile
                if( isset($value->shared->{'certificate-profile'}) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Certificate Profiles VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/certificate-profile/entry");
                    xml_add_certificate_profile($projectdb, $source, $new_vsyst, $template, $profiles);
//                    foreach ($profiles as $key => $profilesArray) {
//                        $GroupName = $profilesArray->attributes()->name;
//                        $content = addslashes($profilesArray->asXML());
//                        $sql[] = "('$source','$GroupName','$content','shared','$templates_mapping_id')";
//                    }
//                    if (count($sql) > 0) {
//                        $projectdb->query("INSERT INTO certificate_profile (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
//                    }
                }

                # SHARED RESPONSE PAGES
                if( isset($value->shared->{'response-page'}) )
                {
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Certificate Profiles VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("shared/response-page");
                    xml_add_response_page($profiles, $source, $new_vsyst, $template);
//                    foreach ($profiles as $key => $profilesArray) {
//                        foreach ($profilesArray as $kkey => $vvalue) {
//                            if (!preg_match("/global-protect/", $kkey)) {
//                                $sql[] = "('$config_filename','shared','$kkey','$vvalue','$templates_mapping_id','')";
//                            } else {
//                                foreach ($vvalue->entry as $mmkey => $mmvalue) {
//                                    $responsePageName = $mmvalue->attributes()->name;
//                                    $content = $mmvalue->page;
//                                    $sql[] = "('$config_filename','shared','$kkey','$content','$templates_mapping_id','$responsePageName')";
//                                }
//                            }
//                        }
//                    }
//                    if (count($sql) > 0) {
////                        $projectdb->query("INSERT INTO shared_response_pages (source,vsys,type,html,template,name) VALUES " . implode(",", $sql) . ";");
//                        $projectdb->query("INSERT INTO response_pages (source,vsys,type,html,template,name) VALUES " . implode(",", $sql) . ";");
//                    }
                }
            }

            # VSYS
            if( (isset($value->devices->entry->vsys)) and ($ispanorama == 1) )
            {
                $vsyst = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry");
                $netflow_profile = "";
                foreach( $vsyst as $key => $new_value )
                {
                    $new_vsyst = $new_value->attributes()->name;
                    //$devicegroup=$devicegroup."-".$new_vsyst;
                    $getDM = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' AND vsys='$new_vsyst' AND device='$devicegroup' AND project='$project'");
                    if( $getDM->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,urldb) VALUES ('$devicegroup','$full_version',1,1,'$project','$filename','$new_vsyst','$baseconfig','$urldb')");
                    }

                    # ADD VSYS INFORMATION
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    xml_add_vsys($projectdb, $source, $new_vsyst, $template, $new_value, $version);

                    # AUTHENTICATION PROFILE
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Authentication Profile, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/authentication-profile/entry");
                    xml_add_authentication_profile($projectdb, $source, $new_vsyst, $template, $profiles);

                    # AUTHENTICATION SEQUENCE
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Authentication Sequence, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/authentication-sequence/entry");
                    xml_add_authentication_sequence($projectdb, $source, $new_vsyst, $template, $profiles);

                    # CERTIFICATE
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Certificates, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/certificate/entry");
                    xml_add_certificate($projectdb, $source, $new_vsyst, $template, $profiles);

                    # CERTIFICATE PROFILE
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Certificate Profile, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/certificate-profile/entry");
                    xml_add_certificate_profile($projectdb, $source, $new_vsyst, $template, $profiles);

                    # OCSP RESPONDER
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading OCSP Responder, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/ocsp-responder/entry");
                    xml_add_ocsp_responder($projectdb, $source, $new_vsyst, $template, $profiles);

                    #LOG SETTINGS
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Log Settings, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/log-settings");
                    xml_add_log_settings($projectdb, $source, $new_vsyst, $template, $profiles, $devicegroup);

                    # DNS PROXY
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading DNS-PROXY, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/dns-proxy/entry");
                    xml_add_dns_proxy($projectdb, $source, $new_vsyst, $template, $profiles);

                    # USER-ID Agent
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading User-ID Agent, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/user-id-agent/entry");
                    xml_add_userid_agent($projectdb, $source, $new_vsyst, $template, $profiles);

                    # USER-ID TS Agent
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading User-ID TS Agent, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/ts-agent/entry");
                    xml_add_tsagent($projectdb, $source, $new_vsyst, $template, $profiles);

                    # USER-ID Group Mapping
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading User-ID Group Mapping, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/group-mapping/entry");
                    xml_add_group_mapping($projectdb, $source, $new_vsyst, $template, $profiles);

                    # USER-ID Captive Portal
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading User-ID Captive Portal, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/captive-portal");
                    xml_add_captive_portal($projectdb, $source, $new_vsyst, $template, $profiles);

                    # USER-ID Collector
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading User-ID Collector, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/user-id-collector");
                    xml_add_userid_collector($projectdb, $source, $new_vsyst, $template, $profiles);

                    # ZONES
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Zones, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/zone/entry");
                    xml_add_zones($projectdb, $source, $new_vsyst, $template, $profiles);

                    # RESPONSE PAGE
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Response Pages, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/response-page");
                    xml_add_response_page($profiles, $source, $new_vsyst, $template);

                    # SERVER PROFILES
                    update_progress($project, $percentage_total, 'File:' . $filename . ' Phase 2 Loading Server Profiles, VSYS: ' . $new_vsyst . ', Template: ' . $templatename, $jobid);
                    $profiles = $value->xpath("devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$new_vsyst']/server-profile");
                    xml_add_server_profile($projectdb, $source, $new_vsyst, $template, $profiles);
                }
            }

            $count_templates++;
            # End Templates
        }

        # VSYS OBJECTS
        foreach( $allDG as $key => $tvalue )
        {
            $localpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$tvalue']";
            $value0 = $xml->xpath($localpath);
            $value = $value0[0];

            $new_vsys = $value->attributes()->name;

            if( !empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']")) )
            {

                # SERVER PROFILES
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Server Profiles, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/server-profile");
                xml_add_server_profile($projectdb, $source, $new_vsys, $template, $profiles);

                # CERTIFICATE PROFILES
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Certificate Profiles, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/certificate-profile");
                xml_add_profiles($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                #LOG SETTINGS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Log Settings, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/log-settings");
                xml_add_log_settings($projectdb, $source, $new_vsys, $template, $profiles, $devicegroup);

                # ZONES
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Zones, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/zone/entry");
                xml_add_zones($projectdb, $source, $new_vsys, $template, $profiles);

                # TAG
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading TAGs, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/tag/entry");
                xml_add_tag($profiles, $source, $new_vsys, $devicegroup);

                # REGIONS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Regions, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/region/entry");
                xml_add_regions($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # RESPONSE PAGE
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Response Pages, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/response-page");
                xml_add_response_page($profiles, $source, $new_vsys, $template);

                #ADDRESS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Address, VSYS/DG: ' . $new_vsys, $jobid);
                $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/address/entry");
                xml_add_address($address, $source, $new_vsys, $devicegroup);

                #ADDRESS-GROUPS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Address Groups, VSYS/DG: ' . $new_vsys, $jobid);
                $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/address-group/entry");
                xml_add_address_groups($aglid, $address, $source, $new_vsys, $devicegroup);

                #SERVICES
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Services, VSYS/DG: ' . $new_vsys, $jobid);
                $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/service/entry");
                xml_add_services($address, $source, $new_vsys, $devicegroup);

                #SERVICES GROUPS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Services Groups, VSYS/DG: ' . $new_vsys, $jobid);
                $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/service-group/entry");
                xml_add_services_groups($sglid, $address, $source, $new_vsys, $devicegroup);

                # APPLICATION CUSTOM
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Custom Applications, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/application/entry");
                xml_add_applications($projectdb, $profiles, $source, $new_vsys, $devicegroup, $version);

                # APPLICATIONS FILTER
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Application Filters, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/application-filter/entry");
                xml_add_applications_filters($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # APPLICATION GROUPS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Application Groups, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/application-group/entry");
                xml_add_applications_groups($appglid, $profiles, $source, $new_vsys, $devicegroup, $version);

                # GLOBAL PROTECT PORTAL
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Global Protect Portal, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/global-protect/global-protect-portal/entry");
                xml_add_gp_portal($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # GLOBAL PROTECT GATEWAY
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Global Protect Gateways, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/global-protect/global-protect-gateway/entry");
                xml_add_gp_gateway($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # GLOBAL PROTECT MDM
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Global Protect MDM, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/global-protect/global-protect-mdm/entry");
                xml_add_gp_mdm($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # SCHEDULES
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Schedules, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/schedule/entry");
                xml_add_schedule($profiles, $source, $new_vsys, $devicegroup);

                # PROFILES
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Profiles, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/profiles");
                xml_add_profiles($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # PROFILES GROUPS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Profile Groups, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/profile-group/entry");
                xml_add_profiles_groups($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # EXTERNAL LISTS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading External Lists, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/external-list/entry");
                xml_add_external_lists($projectdb, $profiles, $source, $new_vsys, $devicegroup);

                # USER-ID Agent
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading User-ID Agent, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/user-id-agent/entry");
                xml_add_userid_agent($projectdb, $source, $new_vsys, $template, $profiles);

                # USER-ID TS Agent
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading User-ID TS Agent, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/ts-agent/entry");
                xml_add_tsagent($projectdb, $source, $new_vsys, $template, $profiles);

                # USER-ID Group Mapping
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading User-ID Group Mapping, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/group-mapping/entry");
                xml_add_group_mapping($projectdb, $source, $new_vsys, $template, $profiles);

                # USER-ID Captive Portal
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading User-ID Captive Portal, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/captive-portal");
                xml_add_captive_portal($projectdb, $source, $new_vsys, $template, $profiles);

                # USER-ID Collector
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading User-ID Collector, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/user-id-collector");
                xml_add_userid_collector($projectdb, $source, $new_vsys, $template, $profiles);

                # DNS-PROXY VSYS
                update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading DNS-PROXY, VSYS/DG: ' . $new_vsys, $jobid);
                $profiles = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/dns-proxy/entry");
                xml_add_dns_proxy($projectdb, $source, $new_vsys, $template, $profiles);

                load_default_objects_byname($objectsInMemory, $data, $new_vsys);

                # POLICIES ALL

            }
        }

        # VSYS POLICIES
        foreach( $allDG as $key => $tvalue )
        {
            $localpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$tvalue']";
            $value0 = $xml->xpath($localpath);
            $value = $value0[0];

            $new_vsys = $value->attributes()->name;
            if( !empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']")) )
            {
                foreach( $policies as $key => $policy )
                {
                    if( $policy == "post-rulebase" )
                    {
                        $preorpost = 1;
                    }
                    else
                    {
                        $preorpost = 0;
                    }

                    # SECURITY
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Security Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/security/rules/entry");
                    pan_read_rules_security($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);

                    # APPLICATION OVERRIDE
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading Application Override Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/application-override/rules/entry");
                    pan_read_rules_appoverride($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $objectsInMemory);

                    # NAT POLICIES
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Loading NAT Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/nat/rules/entry");
                    pan_read_rules_nat2($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $objectsInMemory);

                    # DEFAULT SECURITY
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Default Security Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/default-security-rules");
                    pan_read_rules_default($preorpost, $address, $source, $new_vsys, $version, $devicegroup);

                    # PBF RULES
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Policy Based Forwarding Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/pbf");
                    //pan_read_rules_pbf($preorpost, $address, $source, $new_vsys, $version, $devicegroup);
                    $address_other_rules = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/pbf");
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/pbf/rules/entry");
                    pan_read_rules_pbf_other_rules($preorpost, $address_other_rules, $source, $new_vsys, $version, $devicegroup);
                    pan_read_rules_pbf($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);

                    # DECRYPTION RULES
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Decryption Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address_other_rules = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/decryption");
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/decryption/rules/entry");
                    pan_read_rules_decryption_other_rules($preorpost, $address_other_rules, $source, $new_vsys, $version, $devicegroup);
                    pan_read_rules_decryption($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);

                    # QoS RULES
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 QoS Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address_other_rules = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/qos");
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/qos/rules/entry");
                    pan_read_rules_qos_other_rules($preorpost, $address_other_rules, $source, $new_vsys, $version, $devicegroup);
                    pan_read_rules_qos($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);

                    # TUNNEL INSPECTION RULES
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Tunnel Inspection Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address_other_rules = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/tunnel-inspect");
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/tunnel-inspect/rules/entry");
                    pan_read_rules_tunnel_inspect_other_rules($preorpost, $address_other_rules, $source, $new_vsys, $version, $devicegroup);
                    pan_read_rules_tunnel_inspect($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);

                    if( $version >= 8 )
                    {
                        # NEW VERSION 8
                        # AUTHENTICATION RULES
                        update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Authentication Rules, VSYS/DG: ' . $new_vsys, $jobid);
                        $address_other_rules = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/authentication");
                        $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/authentication/rules/entry");
                        pan_read_rules_authentication_other_rules($preorpost, $address_other_rules, $source, $new_vsys, $version, $devicegroup);
                        pan_read_rules_authentication($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);

                    }
                    else
                    {
                        # VERSION 7
                        # CAPTIVE PORTAL RULES
                        update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 Captive Portal Rules, VSYS/DG: ' . $new_vsys, $jobid);
                        $address_other_rules = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/captive-portal");
                        $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/captive-portal/rules/entry");
                        pan_read_rules_captiveportal_other_rules($preorpost, $address_other_rules, $source, $new_vsys, $version, $devicegroup);
                        pan_read_rules_captiveportal($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);
                    }

                    # DOS RULES
                    update_progress($project, '0.65', 'File:' . $filename . ' Phase 4 DoS Rules, VSYS/DG: ' . $new_vsys, $jobid);
                    $address_other_rules = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/dos");
                    $address = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$new_vsys']/$policy/dos/rules/entry");
                    pan_read_rules_dos_other_rules($preorpost, $address_other_rules, $source, $new_vsys, $version, $devicegroup);
                    pan_read_rules_dos($preorpost, $address, $config_filename, $new_vsys, $version, $devicegroup, $urldb, $objectsInMemory);

                }
            }
        }
    }
    else
    {
        update_progress($project, '-1.00', 'Invalid XML file.', $jobid);
        unlink($config_path);
        exit(0);
    }
    // Call function to generate initial consumptions
    deviceUsage("initial", "get", $project, "", "", "all", $source, $template_name);
    if( isset($objectsInMemory) )
    {
        return $objectsInMemory;
    }
    else
    {
        return FALSE;
    }

}

function xml_attribute($object, $attribute)
{
    if( isset($object[$attribute]) )
    {
        return (string)$object[$attribute];
    }
    else
    {
        return "false";
    }
}

function add_interfaces_ethernet_from_zones($template, $source, $media, $xml)
{
    global $projectdb;

    $newIpInterfaces = array();
    $existingIpInterfaces = array();
    $add_interface = array();

    # INTERFACES FOUND IN TEMPLATES
    //Look for all defined interfaces in the configuration. Prior templates may have inserted entries in the Interfaces table
    $query = "SELECT * FROM interfaces;";
    $getInterfaces = $projectdb->query($query);
    if( $getInterfaces->num_rows > 0 )
    {
        while( $data = $getInterfaces->fetch_assoc() )
        {
            $interface = new FwInterface($data['media'], $data['name'], $data['type'], $data['comment'], $data['unitname'], "", "");
            $interface->setVsys($data['vsys']);
            $interface->setZone($data['zone']);
            $existingIpInterfaces[$data['name']] = $interface;
        }
    }

    foreach( $xml->devices->entry->vsys->entry as $key => $vsysEntryValue )
    {
        $vsysName = $vsysEntryValue->attributes()->name;
        if( isset($vsysEntryValue->zone) )
        {

            foreach( $vsysEntryValue->zone->entry as $zoneEntry )
            {
                $zoneName = $zoneEntry->attributes()->name;
                $ipv6 = $map_name = $unittag = $map_unitname = $map_unittag = $unitipaddress = $comment = $vr_id = $map_vr = $mtu = $arp = $aggregate_group = $vlan = $ppoe = $dhcp_client = $vwire_id = $dhcp_client_default_route_metric = $lacp_port_priority = $lacp = $ip_classifier = $netflow_profile = $log_card = $lldp = $ndpproxy = '';

                if( isset($zoneEntry->network->layer2) )
                {
                    $type = "layer2";
                }
                elseif( isset($zoneEntry->network->layer3) )
                {
                    $type = "layer3";
                }
                $interfaceMembers = array();
                foreach( $zoneEntry->network->{$type}->member as $keyInterfaceMember => $interfaceMember )
                {
                    $unitName = $interfaceMember;
                    $interfaceName = $interfaceMember;
                    if( !isset($existingIpInterfaces["$interfaceName"]) )
                    {
                        $interface = new FwInterface("ethernet", $interfaceName, "$type", $comment, $unitName, "", "");
                        $interface->setVsys($vsysName);
                        $interface->setZone($zoneName);
                        $newIpInterfaces["$interfaceName"] = $interface;
                    }
                    else
                    {
                        $interface = $existingIpInterfaces["$interfaceName"];
                        $interface->addZone($zoneName);
                        $existingIpInterfaces["$interfaceName"] = $interface;
                    }
                    //Check if this $interfaceMember has already been declared. If so, we may have to extend the zones it has.
                    //$newInterfaceEntry = "('$template','$interfaceName','$zoneName','$type','$ipv6','$media','$source','$vsysName', '$map_name', '$unitName', '$unittag', '$map_unitname', '$map_unittag', '$unitipaddress', '$comment', '$vr_id', '$map_vr', '$mtu', '$arp', '$aggregate_group', '$vlan', '$ppoe', '$dhcp_client', '$vwire_id', '$dhcp_client_default_route_metric', '$lacp_port_priority', '$lacp', '$ip_classifier', '$netflow_profile', '$log_card', '$lldp', '$ndpproxy')";
                    //$add_interface[] = $newInterfaceEntry;
                }
            }
        }
    }

    foreach( $newIpInterfaces as $interfaceName => $ipInterface )
    {
        $ipaddresses = array_unique($ipInterface->ipaddresses);
        $all_ipaddress = implode(",", $ipaddresses);
        //(media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys, zone)
        //$newInterfaceEntry = "('$template','$interfaceName','$zoneName','$type','$ipv6','$media','$source','$vsysName', '$map_name', '$unitName', '$unittag', '$map_unitname', '$map_unittag', '$unitipaddress', '$comment', '$vr_id', '$map_vr', '$mtu', '$arp', '$aggregate_group', '$vlan', '$ppoe', '$dhcp_client', '$vwire_id', '$dhcp_client_default_route_metric', '$lacp_port_priority', '$lacp', '$ip_classifier', '$netflow_profile', '$log_card', '$lldp', '$ndpproxy')";
        //$add_interface[] = $newInterfaceEntry;

        $add_interface[] = "('','$ipInterface->media','$source','$ipInterface->interfaceName','$ipInterface->interfaceType',"
            . "'$ipInterface->comment','$ipInterface->unitName','$ipInterface->vlan_tag','$all_ipaddress','$template','$ipInterface->vsys','$ipInterface->zone')";

        //Add zones with Interface name
        //(source,name,vsys,type,interfaces,template)
        //$zones[] = "('$source','Zone$zoneNumber','$ipInterface->vsys','$ipInterface->interfaceType','$ipInterface->unitName','$template')";
        //$zoneNumber++;
    }

    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $query = "INSERT INTO interfaces (vr_id, media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys, zone) VALUES " . $out . ";";
        $projectdb->query($query);
    }

    foreach( $existingIpInterfaces as $interfaceName => $ipInterface )
    {
        $ipaddresses = array_unique($ipInterface->ipaddresses);
        $all_ipaddress = implode(",", $ipaddresses);

        $query = "UPDATE interfaces SET zone = '$ipInterface->zone', unitipaddress='$all_ipaddress' WHERE name='$ipInterface->interfaceName'";
        $projectdb->query($query);
    }

//    if (count($zones)>0){
//        $out = implode(",", $zones);
//        $projectdb->query("INSERT INTO zones (source,name,vsys,type,interfaces,template) VALUES " . $out . ";");
//    }

//    if (count($add_interface) > 0) {
//        $out = implode(",", $add_interface);
//        $query = "INSERT INTO interfaces (template, name, zone, type, ipv6, media, source, vsys, map_name, unitname, unittag, map_unitname, map_unittag, unitipaddress, comment, vr_id, map_vr, mtu, arp, aggregate_group, vlan, ppoe, dhcp_client, vwire_id, dhcp_client_default_route_metric, lacp_port_priority, lacp, ip_classifier, netflow_profile, log_card, lldp, ndpproxy) VALUES " . $out . ";";
//        $projectdb->query($query);
//    }

}

function add_interfaces_ethernet_and_aggregated($template, $source, $media, $xml)
{
    global $projectdb;
    $add_interface = array();
    foreach( $xml->devices->entry->network->interface->{$media}->entry as $key => $value )
    {
        $unitname = "";
        $unittag = "";
        $ipv6 = "";
        $mtu = "";
        $interface_management_profile = "";
        $adjust_tcp_mss = "";
        $ipv4_adjust_tcp_mss = "";
        $ipv6_adjust_tcp_mss = "";
        $dhcp_client = "";
        $unitipaddress = "";
        $aggregate_group = "";
        $arp = "";
        $untagged_sub_interface = "";
        $ppoe = "";
        $comment = "";
        $lldp = "";
        $ndpproxy = "";
        $lacp = "";
        $etherName = $value->attributes()->name;
        #$media="ethernet";
        $link_speed = $value->{'link-speed'};
        $link_duplex = $value->{'link-duplex'};
        $link_state = $value->{'link-state'};
        if( isset($value->comment) )
        {
            $comment = $value->comment;
        }

        if( isset($value->{'aggregate-group'}) )
        {
            $unitname = "";
            $unittag = "";
            $ipv6 = "";
            $mtu = "";
            $interface_management_profile = "";
            $adjust_tcp_mss = "";
            $dhcp_client = "";
            $unitipaddress = "";
            $etherType = "aggregate-group";
            $aggregate_group = $value->{'aggregate-group'};
            $unittag = 0;
            $unitname = $etherName;
            if( isset($value->lacp->{'port-priority'}) )
            {
                $lacp_port_priority = $value->lacp->{'port-priority'};
            }
            else
            {
                $lacp_port_priority = "";
            }
            $newInterface = "('','','','','','','$lacp_port_priority','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
            $add_interface[] = $newInterface;
        }
        elseif( isset($value->tap) )
        {
            $unitname = "";
            $unittag = "";
            $ipv6 = "";
            $mtu = "";
            $interface_management_profile = "";
            $adjust_tcp_mss = "";
            $dhcp_client = "";
            $unitipaddress = "";
            $etherType = "tap";
            $unittag = 0;
            $unitname = $etherName;
            if( isset($value->tap->{'netflow-profile'}) )
            {
                $netflow_profile = $value->tap->{'netflow-profile'};
            }
            else
            {
                $netflow_profile = "";
            }
            $add_interface[] = "('','','$netflow_profile','','','','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
        }
        elseif( isset($value->ha) )
        {
            $unitname = "";
            $unittag = "";
            $ipv6 = "";
            $mtu = "";
            $interface_management_profile = "";
            $adjust_tcp_mss = "";
            $dhcp_client = "";
            $unitipaddress = "";
            $etherType = "ha";
            $unittag = 0;
            $unitname = $etherName;
            if( $media == "aggregate-ethernet" )
            {
                if( isset($value->ha->lacp) )
                {
                    $lacp = addslashes($value->ha->lacp->asXML());
                }
                else
                {
                    $lacp = "";
                }
            }
            $add_interface[] = "('','','','','','$lacp','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
        }
        elseif( isset($value->layer2) )
        {
            $lldp = "";
            if( $media == "aggregate-ethernet" )
            {
                if( isset($value->layer2->lacp) )
                {
                    $lacp = addslashes($value->layer2->lacp->asXML());
                }
                else
                {
                    $lacp = "";
                }
            }
            $lldp = addslashes($value->layer2->lldp->asXML());
            $etherType = "layer2";
            $unitname = $etherName;
            #get Vlan ID
            $getVWIRE = $projectdb->query("SELECT id,interface FROM vlans WHERE template='$template' AND source='$source' AND interface LIKE '%$unitname%';");
            if( $getVWIRE->num_rows > 0 )
            {
                while( $getVWIREData = $getVWIRE->fetch_assoc() )
                {
                    $interfaces = $getVWIREData['interface'];
                    $myinterfaces = explode(",", $interfaces);
                    if( in_array($unitname, $myinterfaces) )
                    {
                        $vwire_id = $getVWIREData['id'];
                        break;
                    }
                    else
                    {
                        $vwire_id = 0;
                    }
                }
            }
            else
            {
                $vwire_id = 0;
            }
            if( isset($value->layer2->{'netflow-profile'}) )
            {
                $netflow_profile = $value->layer2->{'netflow-profile'};
            }
            else
            {
                $netflow_profile = "";
            }

            #Create it
            $add_interface[] = "('$lldp','','$netflow_profile','','$vwire_id','$lacp','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";

            if( isset($value->layer2->units->entry) )
            {
                foreach( $value->layer2->units->entry as $akey => $avalue )
                {
                    $unitname = "";
                    $unittag = "";
                    $ipv6 = "";
                    $mtu = "";
                    $comment = "";
                    $interface_management_profile = "";
                    $adjust_tcp_mss = "";
                    $dhcp_client = "";
                    $unitipaddress = "";
                    $unitname = $avalue->attributes()->name;
                    if( isset($avalue->{'netflow-profile'}) )
                    {
                        $netflow_profile = $avalue->{'netflow-profile'};
                    }
                    else
                    {
                        $netflow_profile = "";
                    }
                    if( isset($avalue->tag) )
                    {
                        $unittag = $avalue->tag;
                    }
                    else
                    {
                        $unittag = "0";
                    }
                    if( isset($avalue->comment) )
                    {
                        $comment = addslashes($avalue->comment);
                    }
                    $add_interface[] = "('','','$netflow_profile','','$vwire_id','','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
                }
            }
        }
        elseif( isset($value->layer3) )
        {
            $lldp = "";
            $ndpproxy = "";
            $adjust_tcp_mss = "";
            $ipv4_adjust_tcp_mss = "";
            $ipv6_adjust_tcp_mss = "";
            $etherType = "layer3";

            if( $media == "aggregate-ethernet" )
            {
                if( isset($value->layer3->lacp) )
                {
                    $lacp = addslashes($value->layer3->lacp->asXML());
                }
                else
                {
                    $lacp = "";
                }
            }

            if( isset($value->layer3->{'netflow-profile'}) )
            {
                $netflow_profile = $value->layer3->{'netflow-profile'};
            }
            else
            {
                $netflow_profile = "";
            }
            $ipv6 = addslashes($value->layer3->ipv6->asXML());
            $lldp = addslashes($value->layer3->lldp->asXML());
            $ndpproxy = addslashes($value->layer3->{'ndp-proxy'}->asXML());

            if( isset($value->layer3->{'untagged-sub-interface'}) )
            {
                $untagged_sub_interface = $value->layer3->{'untagged-sub-interface'};
            }
            if( isset($value->layer3->mtu) )
            {
                $mtu = $value->layer3->mtu;
            }
            if( isset($value->layer3->{'interface-management-profile'}) )
            {
                $interface_management_profile = $value->layer3->{'interface-management-profile'};
            }
            if( isset($value->layer3->arp) )
            {
                $arp = addslashes($value->layer3->arp->asXML());
            }
            if( isset($value->layer3->{'adjust-tcp-mss'}) )
            {
                $adjust_tcp_mss = $value->layer3->{'adjust-tcp-mss'};

                # Updated for Panos 7.1
                if( isset($value->layer3->{'adjust-tcp-mss'}->enable) )
                {
                    $adjust_tcp_mss = $value->layer3->{'adjust-tcp-mss'}->enable;
                }
                if( isset($value->layer3->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
                {
                    $ipv4_adjust_tcp_mss = $value->layer3->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
                }
                if( isset($value->layer3->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
                {
                    $ipv6_adjust_tcp_mss = $value->layer3->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
                }

            }
            if( isset($value->layer3->ppoe) )
            {
                $ppoe = addslashes($value->layer3->ppoe->asXML());
                $ipv4_type = "ppoe";
                if( ($unittag == "") or (!isset($unittag)) )
                {
                    $unittag = 0;
                }
                $add_interface[] = "('$lldp','$ndpproxy','$netflow_profile','','','','','','','ppoe','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
            }
            if( isset($value->layer3->{'dhcp-client'}) )
            {
                $dhcp_client = addslashes($value->layer3->{'dhcp-client'}->asXML());
                if( isset($value->layer3->{'dhcp-client'}->{'default-route-metric'}) )
                {
                    $dhcp_client_default_route_metric = $value->layer3->{'dhcp-client'}->{'default-route-metric'};
                }
                else
                {
                    $dhcp_client_default_route_metric = "yes";
                }

                if( isset($value->layer3->{'dhcp-client'}->{'create-default-route'}) )
                {
                    $dhcp_client_create_default_route = $value->layer3->{'dhcp-client'}->{'create-default-route'};
                }
                else
                {
                    $dhcp_client_create_default_route = "yes";
                }

                if( isset($value->layer3->{'dhcp-client'}->{'enable'}) )
                {
                    $dhcp_client_enable = $value->layer3->{'dhcp-client'}->{'enable'};
                }
                else
                {
                    $dhcp_client_enable = "yes";
                }
                if( ($unittag == "") or (!isset($unittag)) )
                {
                    $unittag = 0;
                }
                if( $unitname == "" )
                {
                    $unitname = $etherName;
                }
                $add_interface[] = "('$lldp','$ndpproxy','$netflow_profile','','','','','$dhcp_client_default_route_metric','$dhcp_client_create_default_route','$dhcp_client_enable','dhcp-client','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
            }
            if( isset($value->layer3->ip) )
            {
                $ipaddress = array();
                foreach( $value->layer3->ip->entry as $kkkkey => $vvvvalue )
                {
                    $ipaddress[] = $vvvvalue->attributes()->name;
                }
                $unitipaddress = implode(",", $ipaddress);
                $unitname = $etherName;
                if( ($unittag == "") or (!isset($unittag)) )
                {
                    $unittag = 0;
                }
                $add_interface[] = "('$lldp','$ndpproxy','$netflow_profile','','','$lacp','','','','','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
            }

            if( (!isset($value->layer3->ip)) and (!isset($value->layer3->ppoe)) and (!isset($value->layer3->{'dhcp-client'})) )
            {
                $projectdb->query("INSERT INTO interfaces (lldp,ndpproxy,netflow_profile,ipv4_type,media,source,template,name,type,link_speed,link_duplex,link_state,ipv6,untagged_sub_interface,adjust_tcp_mss,interface_management_profile,unitipaddress,comment,mtu,arp,unitname,unittag,lacp,ipv4_mss_adjustment,ipv6_mss_adjustment) VALUES ('$lldp','$ndpproxy','$netflow_profile','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','','$comment','$mtu','$arp','$etherName','0','$lacp','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss');");
            }

            if( isset($value->layer3->units->entry) )
            {
                foreach( $value->layer3->units->entry as $akey => $avalue )
                {
                    $unitname = "";
                    $unittag = "";
                    $ipv6 = "";
                    $mtu = "";
                    $interface_management_profile = "";
                    $adjust_tcp_mss = "";
                    $ipv4_adjust_tcp_mss = "";
                    $ipv6_adjust_tcp_mss = "";
                    $dhcp_client = "";
                    $unitipaddress = "";
                    $ndpproxy = "";
                    $lldp = "";
                    $comment = "";
                    $ipv6 = addslashes($avalue->ipv6->asXML());
                    $lldp = addslashes($avalue->lldp->asXML());
                    $ndpproxy = addslashes($avalue->{'ndp-proxy'}->asXML());
                    $unitname = $avalue->attributes()->name;
                    $unittag = $avalue->tag;
                    if( isset($avalue->{'netflow-profile'}) )
                    {
                        $netflow_profile = $avalue->{'netflow-profile'};
                    }
                    else
                    {
                        $netflow_profile = "";
                    }
                    if( isset($avalue->mtu) )
                    {
                        $mtu = $avalue->mtu;
                    }
                    if( isset($avalue->comment) )
                    {
                        $comment = addslashes($avalue->comment);
                    }
                    if( isset($avalue->{'interface-management-profile'}) )
                    {
                        $interface_management_profile = $avalue->{'interface-management-profile'};
                    }
                    if( isset($avalue->arp) )
                    {
                        $arp = addslashes($avalue->arp->asXML());
                    }
                    if( isset($avalue->{'adjust-tcp-mss'}) )
                    {
                        $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'};

                        # Updated for Panos 7.1
                        if( isset($avalue->{'adjust-tcp-mss'}->enable) )
                        {
                            $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->enable;
                        }
                        if( isset($avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
                        {
                            $ipv4_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
                        }
                        if( isset($avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
                        {
                            $ipv6_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
                        }
                    }
                    if( isset($avalue->{'dhcp-client'}) )
                    {
                        $dhcp_client = addslashes($avalue->{'dhcp-client'}->asXML());
                        if( isset($avalue->{'dhcp-client'}->{'default-route-metric'}) )
                        {
                            $dhcp_client_default_route_metric = $avalue->{'dhcp-client'}->{'default-route-metric'};
                        }
                        else
                        {
                            $dhcp_client_default_route_metric = "yes";
                        }

                        if( isset($avalue->{'dhcp-client'}->{'create-default-route'}) )
                        {
                            $dhcp_client_create_default_route = $avalue->{'dhcp-client'}->{'create-default-route'};
                        }
                        else
                        {
                            $dhcp_client_create_default_route = "yes";
                        }

                        if( isset($avalue->{'dhcp-client'}->{'enable'}) )
                        {
                            $dhcp_client_enable = $avalue->{'dhcp-client'}->{'enable'};
                        }
                        else
                        {
                            $dhcp_client_enable = "yes";
                        }
                        if( ($unittag == "") or (!isset($unittag)) )
                        {
                            $unittag = 0;
                        }
                        $add_interface[] = "('$lldp','$ndpproxy','$netflow_profile','','','','','$dhcp_client_default_route_metric','$dhcp_client_create_default_route','$dhcp_client_enable','dhcp-client','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
                    }
                    if( isset($avalue->ip) )
                    {
                        $ipaddress = array();
                        foreach( $avalue->ip->entry as $kkkkey => $vvvvalue )
                        {
                            $ipaddress[] = $vvvvalue->attributes()->name;
                        }
                        $unitipaddress = implode(",", $ipaddress);
                        if( ($unittag == "") or (!isset($unittag)) )
                        {
                            $unittag = 0;
                        }
                        $add_interface[] = "('$lldp','$ndpproxy','','','','','','','','','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
                    }
                    if( isset($avalue->comment) )
                    {
                        $comment = addslashes($avalue->comment);
                    }
                    if( (!isset($avalue->ip)) and (!isset($avalue->{'dhcp-client'})) )
                    {
                        $projectdb->query("INSERT INTO interfaces (lldp,ndpproxy,netflow_profile,ipv4_type,media,source,template,name,type,link_speed,link_duplex,link_state,ipv6,untagged_sub_interface,adjust_tcp_mss,interface_management_profile,unitipaddress,comment,mtu,arp,unitname,unittag,ipv4_mss_adjustment,ipv6_mss_adjustment) VALUES ('$lldp','$ndpproxy','$netflow_profile','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','','$comment','$mtu','$arp','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss');");
                    }

                }
            }
        }
        elseif( isset($value->{'virtual-wire'}) )
        {
            $lldp = "";
            $etherType = "virtual-wire";
            $unittag = 0;
            $unitname = $etherName;

            #get VWIRE ID
            $getVWIRE = $projectdb->query("SELECT id FROM virtual_wires WHERE template='$template' AND source='$source' AND (interface1='$unitname' OR interface2='$unitname');");
            if( $getVWIRE->num_rows == 1 )
            {
                $getVWIREData = $getVWIRE->fetch_assoc();
                $vwire_id = $getVWIREData['id'];
            }
            else
            {
                $vwire_id = 0;
            }
            if( isset($value->{'virtual-wire'}->{'netflow-profile'}) )
            {
                $netflow_profile = $value->{'virtual-wire'}->{'netflow-profile'};
            }
            else
            {
                $netflow_profile = "";
            }
            $lldp = addslashes($value->{'virtual-wire'}->lldp->asXML());
            $add_interface[] = "('$lldp','','$netflow_profile','','$vwire_id','','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
            if( isset($value->{'virtual-wire'}->units->entry) )
            {
                foreach( $value->{'virtual-wire'}->units->entry as $akey => $avalue )
                {
                    # Tag ip-classifier Comment plus->
                    if( isset($avalue->comment) )
                    {
                        $comment = addslashes($avalue->comment);
                    }
                    else
                    {
                        $comment = "";
                    }
                    if( isset($avalue->{'ip-classifier'}) )
                    {
                        $ipaddress = array();
                        foreach( $avalue->{'ip-classifier'}->member as $kkkkey => $vvvvalue )
                        {
                            $ipaddress[] = $vvvvalue;
                        }
                        $ip_classifier = implode(",", $ipaddress);
                        unset($ipaddress);
                    }
                    $etherType = "virtual-wire";
                    $unittag = $avalue->tag;
                    $unitname = $avalue->attributes()->name;
                    #get VWIRE ID
                    $getVWIRE = $projectdb->query("SELECT id FROM virtual_wires WHERE template='$template' AND source='$source' AND (interface1='$unitname' OR interface2='$unitname');");
                    if( $getVWIRE->num_rows == 1 )
                    {
                        $getVWIREData = $getVWIRE->fetch_assoc();
                        $vwire_id = $getVWIREData['id'];
                    }
                    else
                    {
                        $vwire_id = 0;
                    }

                    $add_interface[] = "('','','','$ip_classifier','$vwire_id','','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
                }
            }
        }
        elseif( isset($value->{'decrypt-mirror'}) )
        {
            $unitname = "";
            $unittag = "";
            $ipv6 = "";
            $mtu = "";
            $interface_management_profile = "";
            $adjust_tcp_mss = "";
            $dhcp_client = "";
            $unitipaddress = "";
            $etherType = "decrypt-mirror";
            $unittag = 0;
            $unitname = $etherName;

            $add_interface[] = "('','','','','','','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','','')";
        }
        elseif( isset($value->{'log-card'}) )
        {
            $unitname = "";
            $unittag = "";
            $ipv6 = "";
            $mtu = "";
            $interface_management_profile = "";
            $adjust_tcp_mss = "";
            $dhcp_client = "";
            $unitipaddress = "";
            $etherType = "log-card";
            $unittag = 0;
            $unitname = $etherName;
            $logcard = addslashes($value->{'log-card'}->asXML());
            $projectdb->query("INSERT INTO interfaces (template,source,link_speed,link_duplex,link_state,comment,name,unitname,unittag,type,media,log_card) "
                . " VALUES ('$template','$source','$link_speed','$link_duplex','$link_state','$comment','$etherName','$unitname','$unittag','$etherType','$media','$logcard')");
            #$add_interface[] = "('','','','','','','','','','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag')";
        }
    }

    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $query = "INSERT INTO interfaces (lldp,ndpproxy,netflow_profile,ip_classifier,vwire_id,lacp,lacp_port_priority,dhcp_client_default_route_metric,dhcp_client_create_default_route,dhcp_client_enable,ipv4_type,media,source,template,name,type,link_speed,link_duplex,link_state,ipv6,untagged_sub_interface,adjust_tcp_mss,interface_management_profile,unitipaddress,comment,mtu,arp,aggregate_group,ppoe,dhcp_client,unitname,unittag,ipv4_mss_adjustment,ipv6_mss_adjustment) VALUES " . $out . ";";
        $projectdb->query($query);
    }
}

function add_vwires($template, $source, $media, $xml)
{
    global $projectdb;
    $add_interface = array();
    foreach( $xml->devices->entry->network->{$media}->entry as $key => $value )
    {

        $name = $value->attributes()->name;
        if( isset($value->{'multicast-firewalling'}->enable) )
        {
            $multicast_firewalling = $value->{'multicast-firewalling'}->enable;
        }
        else
        {
            $multicast_firewalling = "";
        }
        if( isset($value->{'link-state-pass-through'}->enable) )
        {
            $link_state_pass_through = $value->{'link-state-pass-through'}->enable;
        }
        else
        {
            $link_state_pass_through = "";
        }
        if( isset($value->interface1) )
        {
            $interface1 = $value->interface1;
        }
        else
        {
            $interface1 = "";
        }
        if( isset($value->interface2) )
        {
            $interface2 = $value->interface2;
        }
        else
        {
            $interface2 = "";
        }
        if( isset($value->{'tag-allowed'}) )
        {
            $tag_allowed = $value->{'tag-allowed'};
        }
        else
        {
            $tag_allowed = "";
        }
        $add_interface[] = "('$source','','$template','$name','$interface1','$interface2','$multicast_firewalling','$tag_allowed','$link_state_pass_through')";
        $name = "";
        $interface1 = "";
        $interface2 = "";
        $multicast_firewalling = "";
        $tag_allowed = "";
        $link_state_pass_through = "";
    }
    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO virtual_wires (source,vsys,template,name,interface1,interface2,multicast_firewalling,tag_allowed,link_state_pass_through) VALUES " . $out . ";");
    }
}

function add_vlans($template, $source, $media, $xml)
{
    global $projectdb;
    $add_interface = array();
    foreach( $xml->devices->entry->network->{$media}->entry as $key => $value )
    {
        $name = $value->attributes()->name;
        if( isset($value->{'interface'}) )
        {
            $interface = array();
            foreach( $value->interface->member as $kkkkey => $vvvvalue )
            {
                $interface[] = $vvvvalue;
            }
            $allinterfaces = implode(",", $interface);
        }
        else
        {
            $allinterfaces = "";
        }

        if( $allinterfaces != "" )
        {
            $intarray = explode(",", $allinterfaces);
            foreach( $intarray as $k => $v )
            {
                $projectdb->query("UPDATE interfaces SET vlan='$name' WHERE template='$template' AND source='$source' AND unitname='$v' AND unittag=0;");
            }
        }
        if( isset($value->mac) )
        {
            foreach( $value->mac->entry as $mmkey => $mvaluemac )
            {

                $mac_name[] = $mvaluemac->attributes()->name;

                if( isset($mvaluemac->interface) )
                {
                    $interface_mac[] = $mvaluemac->interface;
                }
            }
            $all_mac_name = implode(",", $mac_name);
            $all_mac_interface = implode(",", $interface_mac);
        }
        else
        {
            $all_mac_name = "";
            $all_mac_interface = "";
        }


        if( $value->{'virtual-interface'}->interface )
        {
            $virtual_interface = $value->{'virtual-interface'}->interface;
        }
        else
        {
            $virtual_interface = "";
        }

        if( $value->{'virtual-interface'}->{'l3-forwarding'} )
        {
            $virtual_interface_l3_forwarding = $value->{'virtual-interface'}->{'l3-forwarding'};
        }
        else
        {
            $virtual_interface_l3_forwarding = "";
        }

        $add_interface[] = "('$source','','$template','$name','$allinterfaces','$all_mac_name', '$all_mac_interface', '$virtual_interface', '$virtual_interface_l3_forwarding')";
        $name = "";
        $allinterfaces = "";
        $mac = "";
        $virtual_interface = "";
    }
    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO vlans (source,vsys,template,name,interface,mac,mac_interfaces,virtual_interface, l3_forwarding) VALUES " . $out . ";");
    }
}

function add_interface_loopback($template, $source, $media, $xml)
{
    global $projectdb;
    $add_interface = array();
    foreach( $xml->devices->entry->network->interface->{$media} as $key => $value )
    {
        $unitname = "";
        $unittag = "0";
        $ipv6 = "";
        $mtu = "";
        $interface_management_profile = "";
        $adjust_tcp_mss = "";
        $ipv4_adjust_tcp_mss = "";
        $ipv6_adjust_tcp_mss = "";
        $dhcp_client = "";
        $unitipaddress = "";
        $comment = "";
        $etherName = "loopback";
        $unitname = $etherName;
        $arp = "";
        $untagged_sub_interface = "";
        if( isset($value->comment) )
        {
            $comment = $value->comment;
        }
        if( isset($value->{'netflow-profile'}) )
        {
            $netflow_profile = $value->{'netflow-profile'};
        }
        else
        {
            $netflow_profile = "";
        }
        $etherType = "layer3";
        $ipv6 = addslashes($value->ipv6->asXML());
        if( isset($value->{'untagged-sub-interface'}) )
        {
            $untagged_sub_interface = $value->{'untagged-sub-interface'};
        }
        if( isset($value->mtu) )
        {
            $mtu = $value->mtu;
        }
        if( isset($value->{'interface-management-profile'}) )
        {
            $interface_management_profile = $value->{'interface-management-profile'};
        }
        if( isset($value->{'adjust-tcp-mss'}) )
        {
            $adjust_tcp_mss = $value->{'adjust-tcp-mss'};
            # Updated for Panos 7.1
            if( isset($value->{'adjust-tcp-mss'}->enable) )
            {
                $adjust_tcp_mss = $value->{'adjust-tcp-mss'}->enable;
            }
            if( isset($value->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
            {
                $ipv4_adjust_tcp_mss = $value->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
            }
            if( isset($value->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
            {
                $ipv6_adjust_tcp_mss = $value->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
            }
        }
        if( isset($value->ip) )
        {
            $ipaddress = array();
            foreach( $value->ip->entry as $kkkkey => $vvvvalue )
            {
                $ipaddress[] = $vvvvalue->attributes()->name;
            }
            $unitipaddress = implode(",", $ipaddress);
            $unitname = $etherName;
        }
        if( ($unittag == "") or (!isset($unittag)) )
        {
            $unittag = 0;
        }
        $add_interface[] = "('$netflow_profile','static','$media','$source','$template','loopback','$etherType','','','','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";

        if( isset($value->units->entry) )
        {
            foreach( $value->units->entry as $akey => $avalue )
            {
                $unitname = "";
                $unittag = "0";
                $ipv6 = "";
                $mtu = "";
                $interface_management_profile = "";
                $adjust_tcp_mss = "";
                $ipv4_adjust_tcp_mss = "";
                $ipv6_adjust_tcp_mss = "";
                $dhcp_client = "";
                $unitipaddress = "";
                $comment = "";
                $etherName = $avalue->attributes()->name;
                $etherNameSplit = explode(".", $etherName);
                $unitname = $etherName;
                //$unittag = $etherNameSplit[1];
                if( isset($avalue->comment) )
                {
                    $comment = addslashes($avalue->comment);
                }
                if( isset($avalue->{'netflow-profile'}) )
                {
                    $netflow_profile = $avalue->{'netflow-profile'};
                }
                else
                {
                    $netflow_profile = "";
                }
                if( isset($avalue->mtu) )
                {
                    $mtu = $avalue->mtu;
                }
                if( isset($avalue->{'interface-management-profile'}) )
                {
                    $interface_management_profile = $avalue->{'interface-management-profile'};
                }
                if( isset($avalue->{'adjust-tcp-mss'}) )
                {
                    $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'};
                    # Updated for Panos 7.1
                    if( isset($avalue->{'adjust-tcp-mss'}->enable) )
                    {
                        $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->enable;
                    }
                    if( isset($avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
                    {
                        $ipv4_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
                    }
                    if( isset($avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
                    {
                        $ipv6_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
                    }

                }
                if( isset($avalue->ip) )
                {
                    $ipaddress = array();
                    foreach( $avalue->ip->entry as $kkkkey => $vvvvalue )
                    {
                        $ipaddress[] = $vvvvalue->attributes()->name;
                    }
                    $unitipaddress = implode(",", $ipaddress);
                }


                if( ($unittag == "") or (!isset($unittag)) )
                {
                    $unittag = 0;
                }
                $add_interface[] = "('$netflow_profile','static','$media','$source','$template','loopback','$etherType','','','','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
            }
        }
    }
    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO interfaces (netflow_profile,ipv4_type,media,source,template,name,type,link_speed,link_duplex,link_state,ipv6,untagged_sub_interface,adjust_tcp_mss,interface_management_profile,unitipaddress,comment,mtu,arp,unitname,unittag,ipv4_mss_adjustment,ipv6_mss_adjustment) VALUES " . $out . ";");
    }
}

function add_interface_tunnel($template, $source, $media, $xml)
{
    global $projectdb;
    $add_interface = array();
    foreach( $xml->devices->entry->network->interface->{$media} as $key => $value )
    {
        $unitname = "";
        $unittag = "";
        $ipv6 = "";
        $mtu = "";
        $interface_management_profile = "";
        $adjust_tcp_mss = "";
        $ipv4_adjust_tcp_mss = "";
        $ipv6_adjust_tcp_mss = "";
        $dhcp_client = "";
        $unitipaddress = "";
        $comment = "";
        $etherName = "tunnel";
        $unitname = $etherName;
        $untagged_sub_interface = "";
        $arp = "";
        if( isset($value->comment) )
        {
            $comment = addslashes($value->comment);
        }
        $etherType = "layer3";
        $ipv6 = addslashes($value->ipv6->asXML());
        if( isset($value->{'untagged-sub-interface'}) )
        {
            $untagged_sub_interface = $value->{'untagged-sub-interface'};
        }
        if( isset($value->{'netflow-profile'}) )
        {
            $netflow_profile = $value->{'netflow-profile'};
        }
        else
        {
            $netflow_profile = "";
        }
        if( isset($value->mtu) )
        {
            $mtu = $value->mtu;
        }
        if( isset($value->{'interface-management-profile'}) )
        {
            $interface_management_profile = $value->{'interface-management-profile'};
        }
        if( isset($value->{'adjust-tcp-mss'}) )
        {
            $adjust_tcp_mss = $value->{'adjust-tcp-mss'};
            # Updated for Panos 7.1
            if( isset($value->{'adjust-tcp-mss'}->enable) )
            {
                $adjust_tcp_mss = $value->{'adjust-tcp-mss'}->enable;
            }
            if( isset($value->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
            {
                $ipv4_adjust_tcp_mss = $value->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
            }
            if( isset($value->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
            {
                $ipv6_adjust_tcp_mss = $value->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
            }
        }
        if( isset($value->ip) )
        {
            $ipaddress = array();
            foreach( $value->ip->entry as $kkkkey => $vvvvalue )
            {
                $ipaddress[] = $vvvvalue->attributes()->name;
            }
            $unitipaddress = implode(",", $ipaddress);
            $unitname = $etherName;
        }
        if( ($unittag == "") or (!isset($unittag)) )
        {
            $unittag = 0;
        }
        $add_interface[] = "('$netflow_profile','static','$media','$source','$template','tunnel','$etherType','','','','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$unitname','$unittag')";

        if( isset($value->units->entry) )
        {
            foreach( $value->units->entry as $akey => $avalue )
            {
                $unitname = "";
                $unittag = "0";
                $ipv6 = "";
                $mtu = "";
                $interface_management_profile = "";
                $adjust_tcp_mss = "";
                $ipv4_adjust_tcp_mss = "";
                $ipv6_adjust_tcp_mss = "";
                $dhcp_client = "";
                $unitipaddress = "";
                $comment = "";
                $etherName = $avalue->attributes()->name;
                $etherNameSplit = explode(".", $etherName);
                $unitname = $etherName;
                $arp = "";
                //$unittag = $etherNameSplit[1];
                if( isset($avalue->comment) )
                {
                    $comment = addslashes($avalue->comment);
                }
                if( isset($avalue->mtu) )
                {
                    $mtu = $avalue->mtu;
                }
                if( isset($avalue->{'netflow-profile'}) )
                {
                    $netflow_profile = $avalue->{'netflow-profile'};
                }
                else
                {
                    $netflow_profile = "";
                }
                if( isset($avalue->{'interface-management-profile'}) )
                {
                    $interface_management_profile = $avalue->{'interface-management-profile'};
                }
                if( isset($avalue->{'adjust-tcp-mss'}) )
                {
                    $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'};
                    # Updated for Panos 7.1
                    if( isset($avalue->{'adjust-tcp-mss'}->enable) )
                    {
                        $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->enable;
                    }
                    if( isset($avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
                    {
                        $ipv4_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
                    }
                    if( isset($avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
                    {
                        $ipv6_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
                    }
                }
                if( isset($avalue->ip) )
                {
                    $ipaddress = array();
                    foreach( $avalue->ip->entry as $kkkkey => $vvvvalue )
                    {
                        $ipaddress[] = $vvvvalue->attributes()->name;
                    }
                    $unitipaddress = implode(",", $ipaddress);
                }


                if( ($unittag == "") or (!isset($unittag)) )
                {
                    $unittag = 0;
                }
                $add_interface[] = "('$netflow_profile','static','$media','$source','$template','tunnel','$etherType','','','','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$unitname','$unittag')";
            }
        }
    }
    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO interfaces (netflow_profile,ipv4_type,media,source,template,name,type,link_speed,link_duplex,link_state,ipv6,untagged_sub_interface,adjust_tcp_mss,interface_management_profile,unitipaddress,comment,mtu,arp,unitname,unittag) VALUES " . $out . ";");
    }
}

function add_interfaces_vlan($template, $source, $media, $xml)
{
    global $projectdb;
    $add_interface = array();
    foreach( $xml->devices->entry->network->interface->{$media} as $key => $value )
    {
        $unitname = "";
        $unittag = "";
        $ipv6 = "";
        $mtu = "";
        $interface_management_profile = "";
        $adjust_tcp_mss = "";
        $ipv4_adjust_tcp_mss = "";
        $ipv6_adjust_tcp_mss = "";
        $dhcp_client = "";
        $unitipaddress = "";
        $aggregate_group = "";
        $arp = "";
        $untagged_sub_interface = "";
        $ppoe = "";
        $comment = "";
        $etherName = "vlan";
        #$media="ethernet";
        $link_speed = "";
        $link_duplex = "";
        $link_state = "";
        $lacp = "";
        $ndpproxy = "";
        if( isset($value->comment) )
        {
            $comment = addslashes($value->comment);
        }
        $ndpproxy = $value->{'ndp-proxy'}->asXML();
        $etherType = "vlan";

        if( isset($value->{'netflow-profile'}) )
        {
            $netflow_profile = $value->{'netflow-profile'};
        }
        else
        {
            $netflow_profile = "";
        }
        $ipv6 = addslashes($value->ipv6->asXML());
        if( isset($value->mtu) )
        {
            $mtu = $value->mtu;
        }
        if( isset($value->{'interface-management-profile'}) )
        {
            $interface_management_profile = $value->{'interface-management-profile'};
        }
        if( isset($value->arp) )
        {
            $arp = addslashes($value->arp->asXML());
        }
        if( isset($value->{'adjust-tcp-mss'}) )
        {
            $adjust_tcp_mss = $value->{'adjust-tcp-mss'};
            # Updated for Panos 7.1
            if( isset($value->{'adjust-tcp-mss'}->enable) )
            {
                $adjust_tcp_mss = $value->{'adjust-tcp-mss'}->enable;
            }
            if( isset($value->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
            {
                $ipv4_adjust_tcp_mss = $value->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
            }
            if( isset($value->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
            {
                $ipv6_adjust_tcp_mss = $value->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
            }
        }

        if( isset($value->{'dhcp-client'}) )
        {
            $dhcp_client = addslashes($value->{'dhcp-client'}->asXML());
            if( isset($value->{'dhcp-client'}->{'default-route-metric'}) )
            {
                $dhcp_client_default_route_metric = $value->{'dhcp-client'}->{'default-route-metric'};
            }
            else
            {
                $dhcp_client_default_route_metric = "yes";
            }

            if( isset($value->{'dhcp-client'}->{'create-default-route'}) )
            {
                $dhcp_client_create_default_route = $value->{'dhcp-client'}->{'create-default-route'};
            }
            else
            {
                $dhcp_client_create_default_route = "yes";
            }

            if( isset($value->{'dhcp-client'}->{'enable'}) )
            {
                $dhcp_client_enable = $value->{'dhcp-client'}->{'enable'};
            }
            else
            {
                $dhcp_client_enable = "yes";
            }
            if( ($unittag == "") or (!isset($unittag)) )
            {
                $unittag = 0;
            }
            if( $unitname == "" )
            {
                $unitname = $etherName;
            }
            $add_interface[] = "('$ndpproxy','$netflow_profile','','','','','$dhcp_client_default_route_metric','$dhcp_client_create_default_route','$dhcp_client_enable','dhcp-client','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
        }
        if( isset($value->ip) )
        {
            $ipaddress = array();
            foreach( $value->ip->entry as $kkkkey => $vvvvalue )
            {
                $ipaddress[] = $vvvvalue->attributes()->name;
            }
            $unitipaddress = implode(",", $ipaddress);
            $unitname = $etherName;
            if( ($unittag == "") or (!isset($unittag)) )
            {
                $unittag = 0;
            }
            $add_interface[] = "('$ndpproxy','$netflow_profile','','','$lacp','','','','','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
        }

        if( (!isset($value->ip)) and (!isset($value->{'dhcp-client'})) )
        {
            $projectdb->query("INSERT INTO interfaces (ndpproxy,netflow_profile,ipv4_type,media,source,template,name,type,link_speed,link_duplex,link_state,ipv6,untagged_sub_interface,adjust_tcp_mss,interface_management_profile,unitipaddress,comment,mtu,arp,unitname,unittag,ipv4_mss_adjustment,ipv6_mss_adjustment) VALUES ('$ndpproxy','$netflow_profile','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','','$comment','$mtu','$arp','$etherName','0','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss');");
        }

        if( isset($value->units->entry) )
        {
            foreach( $value->units->entry as $akey => $avalue )
            {
                $unitname = "";
                $unittag = "";
                $ipv6 = "";
                $mtu = "";
                $interface_management_profile = "";
                $adjust_tcp_mss = "";
                $ipv4_adjust_tcp_mss = "";
                $ipv6_adjust_tcp_mss = "";
                $dhcp_client = "";
                $unitipaddress = "";
                $ipv6 = addslashes($avalue->ipv6->asXML());
                $unitname = $avalue->attributes()->name;
                $comment = "";
                $unittag = 0;
                if( isset($avalue->comment) )
                {
                    $comment = addslashes($avalue->comment);
                }
                if( isset($avalue->{'netflow-profile'}) )
                {
                    $netflow_profile = $avalue->{'netflow-profile'};
                }
                else
                {
                    $netflow_profile = "";
                }
                if( isset($avalue->mtu) )
                {
                    $mtu = $avalue->mtu;
                }
                if( isset($avalue->{'interface-management-profile'}) )
                {
                    $interface_management_profile = $avalue->{'interface-management-profile'};
                }
                if( isset($avalue->arp) )
                {
                    $arp = addslashes($avalue->arp->asXML());
                }
                if( isset($avalue->{'adjust-tcp-mss'}) )
                {
                    $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'};
                    # Updated for Panos 7.1
                    if( isset($avalue->{'adjust-tcp-mss'}->enable) )
                    {
                        $adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->enable;
                    }
                    if( isset($avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'}) )
                    {
                        $ipv4_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv4-mss-adjustment'};
                    }
                    if( isset($avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'}) )
                    {
                        $ipv6_adjust_tcp_mss = $avalue->{'adjust-tcp-mss'}->{'ipv6-mss-adjustment'};
                    }
                }
                if( isset($avalue->{'dhcp-client'}) )
                {
                    $dhcp_client = addslashes($avalue->{'dhcp-client'}->asXML());
                    if( isset($avalue->{'dhcp-client'}->{'default-route-metric'}) )
                    {
                        $dhcp_client_default_route_metric = $avalue->{'dhcp-client'}->{'default-route-metric'};
                    }
                    else
                    {
                        $dhcp_client_default_route_metric = "yes";
                    }

                    if( isset($avalue->{'dhcp-client'}->{'create-default-route'}) )
                    {
                        $dhcp_client_create_default_route = $avalue->{'dhcp-client'}->{'create-default-route'};
                    }
                    else
                    {
                        $dhcp_client_create_default_route = "yes";
                    }

                    if( isset($avalue->{'dhcp-client'}->{'enable'}) )
                    {
                        $dhcp_client_enable = $avalue->{'dhcp-client'}->{'enable'};
                    }
                    else
                    {
                        $dhcp_client_enable = "yes";
                    }
                    if( ($unittag == "") or (!isset($unittag)) )
                    {
                        $unittag = 0;
                    }
                    $add_interface[] = "('','$netflow_profile','','','','','$dhcp_client_default_route_metric','$dhcp_client_create_default_route','$dhcp_client_enable','dhcp-client','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
                }

                if( isset($avalue->ip) )
                {
                    $ipaddress = array();
                    foreach( $avalue->ip->entry as $kkkkey => $vvvvalue )
                    {
                        $ipaddress[] = $vvvvalue->attributes()->name;
                    }
                    $unitipaddress = implode(",", $ipaddress);
                    if( ($unittag == "") or (!isset($unittag)) )
                    {
                        $unittag = 0;
                    }
                    $add_interface[] = "('','','','','','','','','','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
                }

                if( (!isset($avalue->ip)) and (!isset($avalue->{'dhcp-client'})) )
                {
                    $add_interface[] = "('','','','','','','','','','static','$media','$source','$template','$etherName','$etherType','$link_speed','$link_duplex','$link_state','$ipv6','$untagged_sub_interface','$adjust_tcp_mss','$interface_management_profile','$unitipaddress','$comment','$mtu','$arp','$aggregate_group','$ppoe','$dhcp_client','$unitname','$unittag','$ipv4_adjust_tcp_mss','$ipv6_adjust_tcp_mss')";
                }
            }
        }
    }
    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO interfaces (ndpproxy,netflow_profile,ip_classifier,vwire_id,lacp,lacp_port_priority,dhcp_client_default_route_metric,dhcp_client_create_default_route,dhcp_client_enable,ipv4_type,media,source,template,name,type,link_speed,link_duplex,link_state,ipv6,untagged_sub_interface,adjust_tcp_mss,interface_management_profile,unitipaddress,comment,mtu,arp,aggregate_group,ppoe,dhcp_client,unitname,unittag,ipv4_mss_adjustment,ipv6_mss_adjustment) VALUES " . $out . ";");
    }
}

function add_response_pages($source, $vsys, $template)
{
    global $projectdb;

    $table = "response_pages";
//    if ($vsys == "shared") {
////        $table = "shared_response_pages";
//        $table = "response_pages";
//    }
//    else {
//        $table = "response_pages";
//    }


    $response_pages = array();
    $type = "application-block-page";
    $html = "PGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5BcHBsaWNhdGlvbiBCbG9ja2VkPC90aXRsZT4NCjxtZXRh
IGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0idGV4dC9odG1sOyBjaGFyc2V0PXV0
Zi04Ij4NCjxNRVRBIEhUVFAtRVFVSVY9IlBSQUdNQSIgQ09OVEVOVD0iTk8tQ0FDSEUiPg0KPHN0
eWxlPg0KI2NvbnRlbnR7Ym9yZGVyOjNweCBzb2xpZCNhYWE7YmFja2dyb3VuZC1jb2xvcjojZmZm
O21hcmdpbjo0MDtwYWRkaW5nOjQwO2ZvbnQtZmFtaWx5OlRhaG9tYSxIZWx2ZXRpY2EsQXJpYWws
c2Fucy1zZXJpZjtmb250LXNpemU6MTJweDt9DQogIGgxe2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2Vp
Z2h0OmJvbGQ7Y29sb3I6IzE5NjM5MDt9DQogIGJ7Zm9udC13ZWlnaHQ6Ym9sZDtjb2xvcjojMTk2
MzkwO30NCjwvc3R5bGU+DQo8L2hlYWQ+DQo8Ym9keSBiZ2NvbG9yPSIjZTdlOGU5Ij4NCjxkaXYg
aWQ9ImNvbnRlbnQiPg0KPGgxPkFwcGxpY2F0aW9uIEJsb2NrZWQ8L2gxPg0KPHA+QWNjZXNzIHRv
IHRoZSBhcHBsaWNhdGlvbiB5b3Ugd2VyZSB0cnlpbmcgdG8gdXNlIGhhcyBiZWVuIGJsb2NrZWQg
aW4gYWNjb3JkYW5jZSB3aXRoIGNvbXBhbnkgcG9saWN5LiBQbGVhc2UgY29udGFjdCB5b3VyIHN5
c3RlbSBhZG1pbmlzdHJhdG9yIGlmIHlvdSBiZWxpZXZlIHRoaXMgaXMgaW4gZXJyb3IuPC9wPg0K
PHA+PGI+VXNlcjo8L2I+IDx1c2VyLz4gPC9wPg0KPHA+PGI+QXBwbGljYXRpb246PC9iPiA8YXBw
bmFtZS8+IDwvcD4NCjwvZGl2Pg0KPC9ib2R5Pg0KPC9odG1sPg0K";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "captive-portal-text";
    $html = "PGh0bWw+DQo8aGVhZD4NCjxtZXRhIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0i
dGV4dC9odG1sOyBjaGFyc2V0PXV0Zi04Ij4NCjxNRVRBIEhUVFAtRVFVSVY9IlBSQUdNQSIgQ09O
VEVOVD0iTk8tQ0FDSEUiPg0KPHRpdGxlPlVzZXIgSWRlbnRpZmljYXRpb24gUG9ydGFsPC90aXRs
ZT4NCjxzdHlsZT4NCiAgICAgICAgYm9keSB7DQogICAgICAgICAgICAgICAgY29sb3I6ICMxMTE7
DQogICAgICAgICAgICAgICAgZm9udC1mYW1pbHk6IFZlcmRhbmEsQXJpYWwsSGVsdmV0aWNhLHNh
bnMtc2VyaWY7DQogICAgICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjojRjJGNkZBOw0KICAg
ICAgICB9DQogICAgICAgICNoZWFkaW5nIHsNCiAgICAgICAgICAgICAgICBmb250LXNpemU6IDI0
cHg7DQogICAgICAgICAgICAgICAgZm9udC13ZWlnaHQ6IGJvbGQ7DQogICAgICAgICAgICAgICAg
bWFyZ2luOiA1cHg7DQogICAgICAgICAgICAgICAgbWFyZ2luLWxlZnQ6IGF1dG87DQogICAgICAg
ICAgICAgICAgbWFyZ2luLXJpZ2h0OiBhdXRvOw0KICAgICAgICB9DQogICAgICAgICNkZXNjIHsN
CiAgICAgICAgICAgICAgICBmb250LXNpemU6IDExcHg7DQogICAgICAgICAgICAgICAgbWFyZ2lu
OiAxNXB4Ow0KICAgICAgICAgICAgICAgIHRleHQtYWxpZ246IGxlZnQ7DQogICAgICAgICAgICAg
ICAgbWFyZ2luLWxlZnQ6IGF1dG87DQogICAgICAgICAgICAgICAgbWFyZ2luLXJpZ2h0OiBhdXRv
Ow0KICAgICAgICB9DQogICAgICAgIGZvcm0gdGQsIGZvcm0gaW5wdXQgew0KICAgICAgICAgICAg
ICAgIGZvbnQtc2l6ZTogMTFweDsNCiAgICAgICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDsN
CiAgICAgICAgfQ0KICAgICAgICAjZm9ybXRhYmxlIHsNCiAgICAgICAgICAgICAgICBoZWlnaHQ6
IDEwMCU7DQogICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7DQogICAgICAgIH0NCiAgICAgICAg
I2Zvcm10ZCB7DQogICAgICAgICAgICAgICAgdmVydGljYWwtYWxpZ246IG1pZGRsZTsNCiAgICAg
ICAgfQ0KICAgICAgICAjZm9ybWRpdiB7DQogICAgICAgICAgICAgICAgbWFyZ2luLWxlZnQ6IGF1
dG87DQogICAgICAgICAgICAgICAgbWFyZ2luLXJpZ2h0OiBhdXRvOw0KICAgICAgICB9DQo8L3N0
eWxlPg0KPC9oZWFkPg0KPGJvZHk+DQo8dGFibGUgaWQ9ImZvcm10YWJsZSI+DQo8dHI+PHRkIGFs
aWduPSJjZW50ZXIiIHZhbGlnbj0ibWlkZGxlIj4NCiAgICAgICAgPGRpdiBpZD0iaGVhZGluZyI+
VXNlciBJZGVudGlmaWNhdGlvbiBQb3J0YWw8L2Rpdj4NCjwvdGQ+PC90cj4NCjx0cj48dGQgYWxp
Z249ImNlbnRlciIgdmFsaWduPSJtaWRkbGUiPg0KICAgICAgICA8ZGl2IGlkPSJkZXNjIj5UaGUg
cmVzb3VyY2UgeW91IGFyZSB0cnlpbmcgdG8gYWNjZXNzIHJlcXVpcmVzIHByb3BlciB1c2VyIGlk
ZW50aWZpY2F0aW9uIHByaW9yIHRvIGFjY2Vzcy4gUGxlYXNlIGVudGVyIHlvdXIgY3JlZGVudGlh
bHMuPC9kaXY+DQo8L3RkPjwvdHI+DQo8dHI+PHRkIGFsaWduPSJjZW50ZXIiIHZhbGlnbj0ibWlk
ZGxlIj4NCjxkaXYgaWQ9ImZvcm1kaXYiPg0KPHBhbl9mb3JtLz4NCjwvZGl2Pg0KPC90ZD48L3Ry
Pg0KPC90YWJsZT4NCjwvYm9keT4NCjwvaHRtbD4NCg0K";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "file-block-continue-page";
    $html = "PGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5GaWxlIERvd25sb2FkIEJsb2NrZWQ8L3RpdGxlPg0KPG1l
dGEgaHR0cC1lcXVpdj0iQ29udGVudC1UeXBlIiBjb250ZW50PSJ0ZXh0L2h0bWw7IGNoYXJzZXQ9
dXRmLTgiPg0KPE1FVEEgSFRUUC1FUVVJVj0iUFJBR01BIiBDT05URU5UPSJOTy1DQUNIRSI+DQo8
c3R5bGU+DQojY29udGVudHtib3JkZXI6M3B4IHNvbGlkI2FhYTtiYWNrZ3JvdW5kLWNvbG9yOiNm
ZmY7bWFyZ2luOjQwO3BhZGRpbmc6NDA7Zm9udC1mYW1pbHk6VGFob21hLEhlbHZldGljYSxBcmlh
bCxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxMnB4O30NCiAgaDF7Zm9udC1zaXplOjIwcHg7Zm9udC13
ZWlnaHQ6Ym9sZDtjb2xvcjojMTk2MzkwO30NCiAgYntmb250LXdlaWdodDpib2xkO2NvbG9yOiMx
OTYzOTA7fQ0KPC9zdHlsZT4NCjwvaGVhZD4NCjxib2R5IGJnY29sb3I9IiNlN2U4ZTkiPg0KPGRp
diBpZD0iY29udGVudCI+DQo8aDE+RmlsZSBEb3dubG9hZCBCbG9ja2VkPC9oMT4NCjxwPkFjY2Vz
cyB0byB0aGUgZmlsZSB5b3Ugd2VyZSB0cnlpbmcgdG8gZG93bmxvYWQgaGFzIGJlZW4gYmxvY2tl
ZCBpbiBhY2NvcmRhbmNlIHdpdGggY29tcGFueSBwb2xpY3kuIFBsZWFzZSBjb250YWN0IHlvdXIg
c3lzdGVtIGFkbWluaXN0cmF0b3IgaWYgeW91IGJlbGlldmUgdGhpcyBpcyBpbiBlcnJvci48L3A+
DQo8cD48Yj5GaWxlIG5hbWU6PC9iPiA8Zm5hbWUvPiA8L3A+DQo8L2Rpdj4NCjwvYm9keT4NCjwv
aHRtbD4NCg==";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "file-block-page";
    $html = "PGh0bWw+DQo8aGVhZD4NCjxtZXRhIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0i
dGV4dC9odG1sOyBjaGFyc2V0PXV0Zi04Ij4NCjxNRVRBIEhUVFAtRVFVSVY9IlBSQUdNQSIgQ09O
VEVOVD0iTk8tQ0FDSEUiPg0KPHRpdGxlPkNlcnRpZmljYXRlIEVycm9yPC90aXRsZT4NCjxzdHls
ZT4NCiNjb250ZW50e2JvcmRlcjozcHggc29saWQjYWFhO2JhY2tncm91bmQtY29sb3I6I2ZmZjtt
YXJnaW46NDA7cGFkZGluZzo0MDtmb250LWZhbWlseTpUYWhvbWEsSGVsdmV0aWNhLEFyaWFsLHNh
bnMtc2VyaWY7Zm9udC1zaXplOjEycHg7fQ0KICBoMXtmb250LXNpemU6MjBweDtmb250LXdlaWdo
dDpib2xkO2NvbG9yOiMxOTYzOTA7fQ0KICBie2ZvbnQtd2VpZ2h0OmJvbGQ7Y29sb3I6IzE5NjM5
MDt9DQo8L3N0eWxlPg0KPC9oZWFkPg0KPGJvZHkgYmdjb2xvcj0iI2U3ZThlOSI+DQo8ZGl2IGlk
PSJjb250ZW50Ij4NCjxoMT5DZXJ0aWZpY2F0ZSBFcnJvcjwvaDE+DQo8cD5UaGVyZSBpcyBhbiBp
c3N1ZSB3aXRoIHRoZSBTU0wgY2VydGlmaWNhdGUgb2YgdGhlIHNlcnZlciB5b3UgYXJlIHRyeWlu
ZyB0byBjb250YWN0LjwvcD4NCjxwPjxiPkNlcnRpZmljYXRlIE5hbWU6PC9iPiA8Y2VydG5hbWUv
PiA8L3A+DQo8cD48Yj5JUDo8L2I+IDx1cmwvPiA8L3A+DQo8cD48Yj5Jc3N1ZXI6PC9iPiA8aXNz
dWVyLz4gPC9wPg0KPHA+PGI+U3RhdHVzOjwvYj4gPHN0YXR1cy8+IDwvcD4NCjxwPjxiPlJlYXNv
bjo8L2I+IDxyZWFzb24vPiA8L3A+DQo8L2Rpdj4NCjwvYm9keT4NCjwvaHRtbD4NCg0K";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "ssl-optout-text";
    $html = "PGgxPlNTTCBJbnNwZWN0aW9uPC9oMT4NCjxwPkluIGFjY29yZGFuY2Ugd2l0aCBjb21wYW55IHNl
Y3VyaXR5IHBvbGljeSwgdGhlIFNTTCBlbmNyeXB0ZWQgY29ubmVjdGlvbiB5b3UgaGF2ZSBpbml0
aWF0ZWQgd2lsbCBiZSB0ZW1wb3JhcmlseSB1bmVuY3J5cHRlZCBzbyB0aGF0IGl0IGNhbiBiZSBp
bnNwZWN0ZWQgZm9yIHZpcnVzZXMsIHNweXdhcmUsIGFuZCBvdGhlciBtYWx3YXJlLjwvcD4NCjxw
PkFmdGVyIHRoZSBjb25uZWN0aW9uIGlzIGluc3BlY3RlZCBpdCB3aWxsIGJlIHJlLWVuY3J5cHRl
ZCBhbmQgc2VudCB0byBpdHMgZGVzdGluYXRpb24uIE5vIGRhdGEgd2lsbCBiZSBzdG9yZWQgb3Ig
bWFkZSBhdmFpbGFibGUgZm9yIG90aGVyIHB1cnBvc2VzLjwvcD4NCjxwPjxiPklQOjwvYj4gPHVy
bC8+IDwvcD4NCjxwPjxiPkNhdGVnb3J5OjwvYj4gPGNhdGVnb3J5Lz4gPC9wPg0K";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "url-block-page";
    $html = "PGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5XZWIgUGFnZSBCbG9ja2VkPC90aXRsZT4NCjxtZXRhIGh0
dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0idGV4dC9odG1sOyBjaGFyc2V0PXV0Zi04
Ij4NCjxNRVRBIEhUVFAtRVFVSVY9IlBSQUdNQSIgQ09OVEVOVD0iTk8tQ0FDSEUiPg0KPHN0eWxl
Pg0KI2NvbnRlbnR7Ym9yZGVyOjNweCBzb2xpZCNhYWE7YmFja2dyb3VuZC1jb2xvcjojZmZmO21h
cmdpbjo0MDtwYWRkaW5nOjQwO2ZvbnQtZmFtaWx5OlRhaG9tYSxIZWx2ZXRpY2EsQXJpYWwsc2Fu
cy1zZXJpZjtmb250LXNpemU6MTJweDt9DQogIGgxe2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2VpZ2h0
OmJvbGQ7Y29sb3I6IzE5NjM5MDt9DQogIGJ7Zm9udC13ZWlnaHQ6Ym9sZDtjb2xvcjojMTk2Mzkw
O30NCjwvc3R5bGU+DQo8L2hlYWQ+DQo8Ym9keSBiZ2NvbG9yPSIjZTdlOGU5Ij4NCjxkaXYgaWQ9
ImNvbnRlbnQiPg0KPGgxPldlYiBQYWdlIEJsb2NrZWQ8L2gxPg0KPHA+QWNjZXNzIHRvIHRoZSB3
ZWIgcGFnZSB5b3Ugd2VyZSB0cnlpbmcgdG8gdmlzaXQgaGFzIGJlZW4gYmxvY2tlZCBpbiBhY2Nv
cmRhbmNlIHdpdGggY29tcGFueSBwb2xpY3kuIFBsZWFzZSBjb250YWN0IHlvdXIgc3lzdGVtIGFk
bWluaXN0cmF0b3IgaWYgeW91IGJlbGlldmUgdGhpcyBpcyBpbiBlcnJvci48L3A+DQo8cD48Yj5V
c2VyOjwvYj4gPHVzZXIvPiA8L3A+DQo8cD48Yj5VUkw6PC9iPiA8dXJsLz4gPC9wPg0KPHA+PGI+
Q2F0ZWdvcnk6PC9iPiA8Y2F0ZWdvcnkvPiA8L3A+DQo8L2Rpdj4NCjwvYm9keT4NCjwvaHRtbD4N
Cg==";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "url-coach-text";
    $html = "PGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5XZWIgUGFnZSBCbG9ja2VkPC90aXRsZT4NCjxtZXRhIGh0
dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0idGV4dC9odG1sOyBjaGFyc2V0PXV0Zi04
Ij4NCjxNRVRBIEhUVFAtRVFVSVY9IlBSQUdNQSIgQ09OVEVOVD0iTk8tQ0FDSEUiPg0KPHN0eWxl
Pg0KI2NvbnRlbnR7Ym9yZGVyOjNweCBzb2xpZCNhYWE7YmFja2dyb3VuZC1jb2xvcjojZmZmO21h
cmdpbjo0MDtwYWRkaW5nOjQwO2ZvbnQtZmFtaWx5OlRhaG9tYSxIZWx2ZXRpY2EsQXJpYWwsc2Fu
cy1zZXJpZjtmb250LXNpemU6MTJweDt9DQogIGgxe2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2VpZ2h0
OmJvbGQ7Y29sb3I6IzE5NjM5MDt9DQogIGJ7Zm9udC13ZWlnaHQ6Ym9sZDtjb2xvcjojMTk2Mzkw
O30NCiAgICAgICAgZm9ybSB0ZCwgZm9ybSBpbnB1dCB7DQogICAgICAgICAgICAgICAgZm9udC1z
aXplOiAxMXB4Ow0KICAgICAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkOw0KICAgICAgICB9
DQogICAgICAgICNmb3JtdGFibGUgew0KICAgICAgICAgICAgICAgIGhlaWdodDogMTAwJTsNCiAg
ICAgICAgICAgICAgICB3aWR0aDogMTAwJTsNCiAgICAgICAgfQ0KICAgICAgICAjZm9ybXRkIHsN
CiAgICAgICAgICAgICAgICB2ZXJ0aWNhbC1hbGlnbjogbWlkZGxlOw0KICAgICAgICB9DQogICAg
ICAgICNmb3JtZGl2IHsNCiAgICAgICAgICAgICAgICBtYXJnaW4tbGVmdDogYXV0bzsNCiAgICAg
ICAgICAgICAgICBtYXJnaW4tcmlnaHQ6IGF1dG87DQogICAgICAgIH0NCjwvc3R5bGU+DQo8c2Ny
aXB0IHR5cGU9InRleHQvamF2YXNjcmlwdCI+DQpmdW5jdGlvbiBwd2RDaGVjaygpIHsNCglpZihk
b2N1bWVudC5nZXRFbGVtZW50QnlJZCgicHdkIikpIHsNCgkJZG9jdW1lbnQuZ2V0RWxlbWVudEJ5
SWQoImNvbnRpbnVlVGV4dCIpLmlubmVySFRNTCA9ICJJZiB5b3UgcmVxdWlyZSBhY2Nlc3MgdG8g
dGhpcyBwYWdlLCBoYXZlIGFuIGFkbWluaXN0cmF0b3IgZW50ZXIgdGhlIG92ZXJyaWRlIHBhc3N3
b3JkIGhlcmU6IjsNCgl9CQ0KfQ0KPC9zY3JpcHQ+DQo8L2hlYWQ+DQo8Ym9keSBiZ2NvbG9yPSIj
ZTdlOGU5Ij4NCjxkaXYgaWQ9ImNvbnRlbnQiPg0KPGgxPldlYiBQYWdlIEJsb2NrZWQ8L2gxPg0K
PHA+QWNjZXNzIHRvIHRoZSB3ZWIgcGFnZSB5b3Ugd2VyZSB0cnlpbmcgdG8gdmlzaXQgaGFzIGJl
ZW4gYmxvY2tlZCBpbiBhY2NvcmRhbmNlIHdpdGggY29tcGFueSBwb2xpY3kuIFBsZWFzZSBjb250
YWN0IHlvdXIgc3lzdGVtIGFkbWluaXN0cmF0b3IgaWYgeW91IGJlbGlldmUgdGhpcyBpcyBpbiBl
cnJvci48L3A+DQo8cD48Yj5Vc2VyOjwvYj4gPHVzZXIvPiA8L3A+DQo8cD48Yj5VUkw6PC9iPiA8
dXJsLz4gPC9wPg0KPHA+PGI+Q2F0ZWdvcnk6PC9iPiA8Y2F0ZWdvcnkvPiA8L3A+DQoNCjxocj4N
CjxwIGlkPSJjb250aW51ZVRleHQiPklmIHlvdSBmZWVsIHRoaXMgcGFnZSBoYXMgYmVlbiBpbmNv
cnJlY3RseSBibG9ja2VkLCB5b3UgbWF5IGNsaWNrIENvbnRpbnVlIHRvIHByb2NlZWQgdG8gdGhl
IHBhZ2UuIEhvd2V2ZXIsIHRoaXMgYWN0aW9uIHdpbGwgYmUgbG9nZ2VkLjwvcD4NCjxkaXYgaWQ9
ImZvcm1kaXYiPg0KPHBhbl9mb3JtLz4NCjwvZGl2Pg0KPGEgaHJlZj0iIyIgb25jbGljaz0iaGlz
dG9yeS5iYWNrKCk7cmV0dXJuIGZhbHNlOyI+UmV0dXJuIHRvIHByZXZpb3VzIHBhZ2U8L2E+DQo8
L2Rpdj4NCjwvYm9keT4NCjwvaHRtbD4NCg==";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "virus-block-page";
    $html = "PGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5WaXJ1cyBEb3dubG9hZCBCbG9ja2VkPC90aXRsZT4NCjxt
ZXRhIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0idGV4dC9odG1sOyBjaGFyc2V0
PXV0Zi04Ij4NCjxNRVRBIEhUVFAtRVFVSVY9IlBSQUdNQSIgQ09OVEVOVD0iTk8tQ0FDSEUiPg0K
PHN0eWxlPg0KI2NvbnRlbnR7Ym9yZGVyOjNweCBzb2xpZCNhYWE7YmFja2dyb3VuZC1jb2xvcjoj
ZmZmO21hcmdpbjo0MDtwYWRkaW5nOjQwO2ZvbnQtZmFtaWx5OlRhaG9tYSxIZWx2ZXRpY2EsQXJp
YWwsc2Fucy1zZXJpZjtmb250LXNpemU6MTJweDt9DQogIGgxe2ZvbnQtc2l6ZToyMHB4O2ZvbnQt
d2VpZ2h0OmJvbGQ7Y29sb3I6IzE5NjM5MDt9DQogIGJ7Zm9udC13ZWlnaHQ6Ym9sZDtjb2xvcjoj
MTk2MzkwO30NCjwvc3R5bGU+DQo8L2hlYWQ+DQo8Ym9keSBiZ2NvbG9yPSIjZTdlOGU5Ij4NCjxk
aXYgaWQ9ImNvbnRlbnQiPg0KPGgxPlZpcnVzIERvd25sb2FkIEJsb2NrZWQ8L2gxPg0KPHA+RG93
bmxvYWQgb2YgdGhlIHZpcnVzIGhhcyBiZWVuIGJsb2NrZWQgaW4gYWNjb3JkYW5jZSB3aXRoIGNv
bXBhbnkgcG9saWN5LiBQbGVhc2UgY29udGFjdCB5b3VyIHN5c3RlbSBhZG1pbmlzdHJhdG9yIGlm
IHlvdSBiZWxpZXZlIHRoaXMgaXMgaW4gZXJyb3IuPC9wPg0KPHA+PGI+RmlsZSBuYW1lOjwvYj4g
PGZuYW1lLz4gPC9wPg0KPC9kaXY+DQo8L2JvZHk+DQo8L2h0bWw+DQo=";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $type = "ssl-cert-status-page";
    $html = "PGh0bWw+DQo8aGVhZD4NCjxtZXRhIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0i
dGV4dC9odG1sOyBjaGFyc2V0PXV0Zi04Ij4NCjxNRVRBIEhUVFAtRVFVSVY9IlBSQUdNQSIgQ09O
VEVOVD0iTk8tQ0FDSEUiPg0KPHRpdGxlPkNlcnRpZmljYXRlIEVycm9yPC90aXRsZT4NCjxzdHls
ZT4NCiNjb250ZW50e2JvcmRlcjozcHggc29saWQjYWFhO2JhY2tncm91bmQtY29sb3I6I2ZmZjtt
YXJnaW46NDA7cGFkZGluZzo0MDtmb250LWZhbWlseTpUYWhvbWEsSGVsdmV0aWNhLEFyaWFsLHNh
bnMtc2VyaWY7Zm9udC1zaXplOjEycHg7fQ0KICBoMXtmb250LXNpemU6MjBweDtmb250LXdlaWdo
dDpib2xkO2NvbG9yOiMxOTYzOTA7fQ0KICBie2ZvbnQtd2VpZ2h0OmJvbGQ7Y29sb3I6IzE5NjM5
MDt9DQo8L3N0eWxlPg0KPC9oZWFkPg0KPGJvZHkgYmdjb2xvcj0iI2U3ZThlOSI+DQo8ZGl2IGlk
PSJjb250ZW50Ij4NCjxoMT5DZXJ0aWZpY2F0ZSBFcnJvcjwvaDE+DQo8cD5UaGVyZSBpcyBhbiBp
c3N1ZSB3aXRoIHRoZSBTU0wgY2VydGlmaWNhdGUgb2YgdGhlIHNlcnZlciB5b3UgYXJlIHRyeWlu
ZyB0byBjb250YWN0LjwvcD4NCjxwPjxiPkNlcnRpZmljYXRlIE5hbWU6PC9iPiA8Y2VydG5hbWUv
PiA8L3A+DQo8cD48Yj5JUDo8L2I+IDx1cmwvPiA8L3A+DQo8cD48Yj5Jc3N1ZXI6PC9iPiA8aXNz
dWVyLz4gPC9wPg0KPHA+PGI+U3RhdHVzOjwvYj4gPHN0YXR1cy8+IDwvcD4NCjxwPjxiPlJlYXNv
bjo8L2I+IDxyZWFzb24vPiA8L3A+DQo8L2Rpdj4NCjwvYm9keT4NCjwvaHRtbD4NCg0K";
    $response_pages[] = "('$source','$vsys','$template','$type','$html')";

    $projectdb->query("INSERT INTO $table (source,vsys,template,type,html) VALUES " . implode(",", $response_pages) . ";");
}
