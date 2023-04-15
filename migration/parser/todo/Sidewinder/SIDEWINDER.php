<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
#HEADER
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//User management control
//require_once INC_ROOT.'/userManager/start.php';
//include INC_ROOT.'/bin/authentication/sessionControl.php';

//Dependencies
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/shared.php';
require_once INC_ROOT . '/libs/projectdb.php';
require_once INC_ROOT . '/libs/objects/SecurityRulePANObject.php';
//require_once INC_ROOT.'/libs/common/lib-rules.php';

require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
global $app;
//Capture request paramenters
include INC_ROOT . '/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);


require_once("sidewinder_address.php");
require_once("sidewinder_natrules.php");
require_once("sidewinder_network.php");
require_once("sidewinder_securityrules.php");
require_once("sidewinder_service.php");


//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

$sourcesAdded = array();
global $source;

if( $action == "import" )
{
    ini_set('pcre.backtrack_limit', '10000');
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);
    $path = USERSPACE_PATH . "/projects/" . $project . "/";
    $i = 0;
    $dirrule = opendir($path);

    update_progress($project, '0.00', 'Reading config files', $jobid);
    while( $config_filename = readdir($dirrule) )
    {
        //if ( ($config_filename != ".") && ($config_filename != "..") && ($config_filename != "parsers.txt") && ($config_filename != "Backups") && ($config_filename != "Pcaps") && ($config_filename != "Reports") AND ($config_filename != "CPviewer.html") AND (!preg_match("/^MT-/",$config_filename))) {
        if( checkFiles2Import($config_filename) )
        {
            $config_path = $path . $config_filename;
            $filename = $config_filename;
            $filenameParts = pathinfo($config_filename);
            $verificationName = $filenameParts['filename'];
            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$verificationName';");
//            $isUploaded=$projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename';");
            if( $isUploaded->num_rows == 0 )
            {
                clean_config($config_path);
                import_config($config_path, $project, $config_filename, $jobid); //This should update the $source
                //This import_config calculates used objects inside
//                $sourcesAdded[] = $source;
                update_progress($project, '0.30', 'File:' . $filename . ' Phase 3 Referencing Groups', $jobid);

            }
            else
            {
                update_progress($project, '0.00', 'This filename ' . $filename . ' its already uploaded. Skipping...', $jobid);
                //unlink($config_path);
            }
        }
    }
    #Check used
    update_progress($project, '0.90', 'File:' . $filename . ' Calculating Used Objects', $jobid);
//    check_used_objects_new($sourcesAdded);
    update_progress($project, '1.00', 'Done.', $jobid);
    unlink($config_path);
}


function clean_config($config_path)
{
    #CLEAN CONFIG FROM EMPTY LINES AND CTRL+M
    file_put_contents($config_path, implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));
    $kkk = str_replace("\r\n", "\n",
        str_replace("     ", " ",
            str_replace("\\\r", "",
                str_replace("\\\n", "",
                    str_replace("\\\r\n", "",
                        str_replace("\\\n\r", "",
                            file_get_contents($config_path)
                        )))))
    );
    //$ro = preg_replace('/\s+/', ' ',$kkk);
    file_put_contents($config_path, $kkk);

}

function import_config($config_path, $project, $config_filename, $jobid)
{
    global $projectdb;
    global $source;
    $filename = $config_filename;

    $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
    if( $getVsys->num_rows == 0 )
    {
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','vsys1','Sidewinder')");
        $vsys = "vsys1";
        $source = $projectdb->insert_id;
    }
    else
    {
        $getVsysData = $getVsys->fetch_assoc();
        $source = $getVsysData['id'];
    }

    #Config Template
    $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
    if( $getTemplate->num_rows == 0 )
    {
        $template_name = $filename . "_template";
        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
        $template = $projectdb->insert_id;
    }
    else
    {
        $getTemplateData = $getTemplate->fetch_assoc();
        $template = $getTemplateData['id'];
    }

    update_progress($project, '0.10', 'Reading Network Interfaces', $jobid);
    get_interfaces($source, $vsys, $template, $config_path);
    update_progress($project, '0.20', 'Reading Address and Groups', $jobid);
    get_address_SIDEWINDER($source, $vsys, $template, $config_path);
    get_addressGroups($source, $vsys, $template, $config_path);
    GroupMember2IdAddress($config_filename);
    update_progress($project, '0.40', 'Reading Services and Groups', $jobid);
    get_services($source, $vsys, $template, $config_path);
    get_servicesGroups($source, $vsys, $template, $config_path);
    GroupMember2IdServices($config_filename);
    update_progress($project, '0.60', 'Reading Security Policies', $jobid);
    get_security_policy($source, $vsys, $template, $config_path);
    update_progress($project, '0.80', 'Phase 8 of 10', $jobid);
    get_normalized_names($source, $vsys);
    update_progress($project, '0.9', 'Calculating Used Objects', $jobid);
    check_used_objects_new([$source]);
    optimization($source, $vsys, $template, $config_path);

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


    update_progress($project, '1.0', 'Done', $jobid);

    // Call function to generate initial consumptions
    deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);


}

function optimization($source, $vsys, $template, $config_path)
{
    global $projectdb;
    #Check if we have zones created or not. if not grab from the rules

    $ids_rules = getSecurityIdsBySourceVsys($source, $vsys);

    $getZones = $projectdb->query("SELECT id FROM zones WHERE source='$source' AND template='$template';");
    if( $getZones->num_rows == 0 )
    {

        $zone = array();
        $getZonesRules = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid IN (" . implode(',', $ids_rules) . ") GROUP BY name;");
        if( $getZonesRules->num_rows > 0 )
        {
            while( $getZonesRulesData = $getZonesRules->fetch_assoc() )
            {
                $zone[] = "('Layer3','None','$source','$vsys','$template','" . $getZonesRulesData['name'] . "')";
            }
        }
        $getZonesRules = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid IN (" . implode(',', $ids_rules) . ") GROUP BY name;");
        if( $getZonesRules->num_rows > 0 )
        {
            while( $getZonesRulesData = $getZonesRules->fetch_assoc() )
            {
                $zone[] = "('Layer3','None','$source','$vsys','$template','" . $getZonesRulesData['name'] . "')";
            }
        }
        $unique = array_unique($zone);
        if( count($unique) > 0 )
        {
            $projectdb->query("INSERT INTO zones (type,zone_protection_profile,source,vsys,template,name) VALUES " . implode(",", $unique) . ";");
            unset($unique);
            unset($zone);
        }
    }
    else
    {
        $getZonesRules = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid IN (" . implode(',', $ids_rules) . ") GROUP BY name;");
        if( $getZonesRules->num_rows > 0 )
        {
            while( $getZonesRulesData = $getZonesRules->fetch_assoc() )
            {
                $check_zone = $getZonesRulesData['name'];
                $check = $projectdb->query("SELECT id FROM zones WHERE source='$source' AND vsys='$vsys' AND name='$check_zone';");
                if( $check->num_rows == 0 )
                {
                    $zone[] = "('Layer3','None','$source','$vsys','$template','" . $getZonesRulesData['name'] . "')";
                }
            }
        }
        $getZonesRules = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid IN (" . implode(',', $ids_rules) . ") GROUP BY name;");
        if( $getZonesRules->num_rows > 0 )
        {
            while( $getZonesRulesData = $getZonesRules->fetch_assoc() )
            {
                $check_zone = $getZonesRulesData['name'];
                if( $check->num_rows == 0 )
                {
                    $zone[] = "('Layer3','None','$source','$vsys','$template','" . $getZonesRulesData['name'] . "')";
                }
            }
        }
        $unique = array_unique($zone);
        if( count($unique) > 0 )
        {
            $projectdb->query("INSERT INTO zones (type,zone_protection_profile,source,vsys,template,name) VALUES " . implode(",", $unique) . ";");
            unset($unique);
            unset($zone);
        }
    }
}


?>