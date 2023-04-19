<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

require_once INC_ROOT . '/libs/projectdb.php';

require_once INC_ROOT . '/libs/common/MemberObject.php';
require_once INC_ROOT . '/libs/Security/OpenSSLTools.php';

require_once INC_ROOT . '/libs/backups.php';
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/definitions/intersections.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;
use PaloaltoNetworks\Policy\Objects\MemberObject;

function check_invalid($source, $vsys, $template)
{
    global $projectdb;

    $version = calcVersion($source);

    # CHECK Zones Legnth 15
    $projectdb->query("UPDATE zones SET invalid=0 WHERE source='$source' AND template='$template' AND vsys='$vsys';");
    $getZones = $projectdb->query("SELECT id,name FROM zones WHERE source='$source' AND template='$template' AND vsys='$vsys';");
    if( $getZones->num_rows > 0 )
    {
        while( $getZonesData = $getZones->fetch_assoc() )
        {
            $zoneName = $getZonesData['name'];
            $zoneID = $getZonesData['id'];

            if( $version < 7 )
            {
                $max = 15;
            }
            elseif( $version >= 7 )
            {
                $max = 31;
            }

            if( strlen($zoneName) > $max )
            {
                $projectdb->query("UPDATE zones SET invalid=1 WHERE id='$zoneID';");
            }
        }
    }
}

function unique_id($l = 8)
{
    return substr(md5(uniqid(mt_rand(), TRUE)), 0, $l);
}

function delete_unused($source, $vsys)
{

    global $projectdb;

    if( $source == 0 )
    {

        if( $vsys == "all" )
        {

            $selected = "";

            $projectdb->query("DELETE FROM address WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM services WHERE used = 0 AND dummy = '0' $selected AND name NOT IN ('application-default', 'service-http', 'service-https') ;");

            $projectdb->query("DELETE FROM regions WHERE used = 0 $selected;");

            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE used=0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM applications_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $projectdb->query("DELETE FROM applications_filters WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM applications WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM tag WHERE used = 0 AND dummy = '0' $selected;");

        }
        elseif( $vsys == "shared" )
        {

            $selected = "";

            $projectdb->query("DELETE FROM address WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM services WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected AND name NOT IN ('application-default', 'service-http', 'service-https') ;");

            $projectdb->query("DELETE FROM regions WHERE used = 0 AND vsys = 'shared' $selected;");

            $getGRP = $projectdb->query("SELECT id FROM shared_address_groups_id WHERE used = 0 AND vsys = 'shared' $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE used=0 AND vsys = 'shared' $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM applications_groups_id WHERE used = 0 AND vsys = 'shared' $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $projectdb->query("DELETE FROM applications_filters WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM applications WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM tag WHERE used = 0 AND vsys = 'shared'  AND dummy = '0' $selected;");

        }
        else
        {

            $selected = " AND vsys = '$vsys'";

            $projectdb->query("DELETE FROM address WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM services WHERE used = 0 AND dummy = '0' $selected AND name NOT IN ('application-default', 'service-http', 'service-https') ;");

            $projectdb->query("DELETE FROM regions WHERE used = 0 $selected;");

            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM applications_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $projectdb->query("DELETE FROM applications_filters WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM applications WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM tag WHERE used = 0 AND dummy = '0' $selected;");
        }

    }
    else
    {

        if( $vsys == "all" )
        {

            $selected = " AND source = '$source'";

            $projectdb->query("DELETE FROM address WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM services WHERE used = 0 AND dummy = '0' $selected AND name NOT IN ('application-default', 'service-http', 'service-https') ;");

            $projectdb->query("DELETE FROM regions WHERE used = 0 $selected;");

            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE used=0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM applications_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $projectdb->query("DELETE FROM applications_filters WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM applications WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM tag WHERE used = 0 AND dummy = '0' $selected;");
        }
        elseif( $vsys == "shared" )
        {

            $selected = " AND source = '$source'";

            $projectdb->query("DELETE FROM address WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM services WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected AND name NOT IN ('application-default', 'service-http', 'service-https') ;");

            $projectdb->query("DELETE FROM regions WHERE used = 0 AND vsys = 'shared' $selected;");

            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE used = 0 AND vsys = 'shared' $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE used=0 AND vsys = 'shared' $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM applications_groups_id WHERE used = 0 AND vsys = 'shared' $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $projectdb->query("DELETE FROM applications_filters WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM applications WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM tag WHERE used = 0 AND vsys = 'shared' AND dummy = '0' $selected;");

        }
        else
        {

            $selected = " AND source = '$source' AND vsys = '$vsys'";

            $projectdb->query("DELETE FROM address WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM services WHERE used = 0 AND dummy = '0' $selected AND name NOT IN ('application-default', 'service-http', 'service-https') ;");

            $projectdb->query("DELETE FROM regions WHERE used = 0 $selected;");

            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $getGRP = $projectdb->query("SELECT id FROM applications_groups_id WHERE used = 0 $selected;");
            if( $getGRP->num_rows > 0 )
            {
                while( $data = $getGRP->fetch_assoc() )
                {
                    $lid[] = $data['id'];
                }
                $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $lid) . ");");
                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $lid) . ");");
            }
            unset($lid);

            $projectdb->query("DELETE FROM applications_filters WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM applications WHERE used = 0 AND dummy = '0' $selected;");

            $projectdb->query("DELETE FROM tag WHERE used = 0 AND dummy = '0' $selected;");
        }
    }
}

function get_normalized_names($source, $vsys)
{
    global $projectdb;

    $getAddress = $projectdb->query("SELECT id,name FROM address WHERE source='$source' AND vsys='$vsys';");
    if( $getAddress->num_rows != 0 )
    {
        while( $names = $getAddress->fetch_assoc() )
        {
            $nameOld = $names['name'];
            $id = $names['id'];
            $nameNormalized = normalizeNames($nameOld);
            $nameTruncated = truncate_names($nameNormalized);
            if( $nameTruncated != "" )
            {
                $projectdb->query("UPDATE address SET name='$nameTruncated' WHERE id='$id';");
            }
        }
    }

    $getAddress = $projectdb->query("SELECT id,name FROM address_groups_id WHERE source='$source' AND vsys='$vsys';");
    if( $getAddress->num_rows != 0 )
    {
        while( $names = $getAddress->fetch_assoc() )
        {
            $nameOld = $names['name'];
            $id = $names['id'];
            $nameNormalized = normalizeNames($nameOld);
            $nameTruncated = truncate_names($nameNormalized);
            if( $nameTruncated != "" )
            {
                $projectdb->query("UPDATE address_groups_id SET name='$nameTruncated' WHERE id='$id';");
            }
        }
    }

    $getAddress = $projectdb->query("SELECT id,name FROM services WHERE source='$source' AND vsys='$vsys';");
    if( $getAddress->num_rows != 0 )
    {
        while( $names = $getAddress->fetch_assoc() )
        {
            $nameOld = $names['name'];
            $id = $names['id'];
            $nameNormalized = normalizeNames($nameOld);
            $nameTruncated = truncate_names($nameNormalized);
            if( $nameTruncated != "" )
            {
                $projectdb->query("UPDATE services SET name='$nameTruncated' WHERE id='$id';");
            }
        }
    }

    $getAddress = $projectdb->query("SELECT id,name FROM services_groups_id WHERE source='$source' AND vsys='$vsys';");
    if( $getAddress->num_rows != 0 )
    {
        while( $names = $getAddress->fetch_assoc() )
        {
            $nameOld = $names['name'];
            $id = $names['id'];
            $nameNormalized = normalizeNames($nameOld);
            $nameTruncated = truncate_names($nameNormalized);
            if( $nameTruncated != "" )
            {
                $projectdb->query("UPDATE services_groups_id SET name='$nameTruncated' WHERE id='$id';");
            }
        }
    }
}

function auto_rule_name($vsys, $policy, $project, $source)
{
    global $projectdb;

    if( $vsys == "" )
    {
        $vsys = "vsys1";
    }
    if( $policy == "rules" )
    {
        $policyrules = "security_rules";
    }
    elseif( $policy == "nat" )
    {
        $policyrules = "nat_rules";
    }
    elseif( $policy == "appoverride" )
    {
        $policyrules = "appoverride_rules";
    }

    $getAllRules = $projectdb->query("SELECT id,name FROM $policyrules WHERE source='$source' AND vsys='$vsys' ORDER BY position ASC;");
    $j = 0;
    while( $rules = $getAllRules->fetch_assoc() )
    {
        $j++;
        $id = $rules['id'];
        $nameOriginal = $rules['name'];
        if( $nameOriginal == "" )
        {
            $projectdb->query("UPDATE $policyrules SET name='Rule $j' WHERE id='$id';");
        }
        else
        {
            if( checkNamesStartAlphaNum($nameOriginal) == FALSE )
            {
                $nameOriginal = truncate_rulenames(normalizeNames("MT-" . $nameOriginal));
                $projectdb->query("UPDATE $policyrules SET name='$nameOriginal' WHERE id='$id';");
            }
        }
    }


    # Fix Rule Name Duplications
    $getDup = $projectdb->query("SELECT name, count(id) as t FROM $policyrules WHERE source='$source' AND vsys='$vsys' GROUP BY name HAVING t>1;");
    if( $getDup->num_rows > 0 )
    {
        while( $data = $getDup->fetch_assoc() )
        {
            $name = $data['name'];
            $getDup1 = $projectdb->query("SELECT id FROM $policyrules WHERE name='$name' AND source='$source' AND vsys='$vsys';");
            if( $getDup1->num_rows > 0 )
            {
                $x = 0;
                while( $data2 = $getDup1->fetch_assoc() )
                {
                    $lid = $data2['id'];
                    if( $x == 0 )
                    {

                    }
                    else
                    {
                        $newname = truncate_rulenames($name . "-" . $x);
                        $projectdb->query("UPDATE $policyrules SET name='$newname' WHERE id='$lid';");
                    }
                    $x++;
                }
            }
        }
    }
}

# LOGS RELATED
function add_log($level, $task, $message, $source, $action, $type = '')
{
    // Type = 1 --> Migration Logs
    // Type = 2 --> Audit Logs
    global $projectdb;
    if( $level == "ok" )
    {
        $level = "1";
    }
    elseif( $level == "warning" )
    {
        $level = "2";
    }
    elseif( $level == "error" )
    {
        $level = "3";
    }
    else
    {
        $level = "0";
    }

    try
    {
        $query = "INSERT INTO logs (datetime,level,task,message,source,action,type) values (NOW(),'$level','$task','$message','$source','$action','$type')";
        if( !is_null($projectdb) )
        {
            $projectdb->query($query);
        }
        else
        {
            echo "Could not execute $query<br>";
        }

    } catch(PDOException $e)
    {
        echo "Could not execute $query<br>";
    }
}

function add_audit_log($level, $task, $message, $action, $type = '')
{
    // Type = 1 --> Migration Logs
    // Type = 2 --> Audit Logs
    global $pandbRBAC;
    if( $level == "ok" )
    {
        $level = "1";
    }
    elseif( $level == "warning" )
    {
        $level = "2";
    }
    elseif( $level == "error" )
    {
        $level = "3";
    }
    else
    {
        $level = "0";
    }

    try
    {
        $query = "INSERT INTO auditlogs (datetime,level,task,message,action,type) values (NOW(),'$level','$task','$message','$action','$type')";
        if( !is_null($pandbRBAC) )
        {
            $pandbRBAC->query($query);
        }
        else
        {
            echo "Could not execute $query<br>";
        }

    } catch(PDOException $e)
    {
        echo "Could not execute $query<br>";
    }
}


function add_log2($level, $task, $message, $source, $action, $obj_type, $obj_id, $obj_table)
{
    global $projectdb;

    # Type= rule  table=security_rules  id= ruleid
    if( $level == "ok" )
    {
        $level = "1";
    }
    elseif( $level == "warning" )
    {
        $level = "2";
    }
    elseif( $level == "error" )
    {
        $level = "3";
    }
    elseif( $level == "conflict" )
    {
        $level = '4';
    }
    else
    {
        $level = "0";
    }
    $query = "INSERT INTO logs (datetime,level,task,message,source,action,obj_type,obj_id,obj_table) values (NOW(),'$level','$task','$message','$source','$action','$obj_type','$obj_id','$obj_table')";
    $projectdb->query($query);
}

function add_log_bulk(mysqli $connection, array $data)
{
    $query = "INSERT INTO logs (datetime,level,task,message,source,action,obj_type,obj_id,obj_table) values " . implode(',', $data);
    $connection->query($query);
}

function add_log_pandb($level, $task, $message, $action, $type = '')
{
    // Type = 1 --> Migration Logs
    // Type = 2 --> Audit Logs
    global $pandb;
    if( $level == "ok" )
    {
        $level = "1";
    }
    elseif( $level == "warning" )
    {
        $level = "2";
    }
    elseif( $level == "error" )
    {
        $level = "3";
    }
    else
    {
        $level = "0";
    }

    $getNow = $pandb->query("SELECT NOW() as now; ");
    if( $getNow->num_rows == 1 )
    {
        $getN = $getNow->fetch_assoc();
        $now = $getN['now'];
    }
    $query = "INSERT INTO logs (datetime,level,task,message,action,type) values (NOW(),'$level','$task','$message $now','$action','$type')";

    $pandb->query($query);
}

function generate_query_cli($type, STRING $projectName, $userID)
{
//$type objects or template or policies
    global $projectdb;
    global $app;
    $projectdb = selectDatabase($projectName);

    if( !($project = $app->project->where('name', '=', $projectName)->get()->first()) )
    {
        $message['code'] = FALSE;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }
    if( !$userSettings = $app->userSettings->where('user_id', '=', $userID)->where('project_id', '=', $project->id)->first() )
    {
        $query = "AND 1 = 0";
        return $query;
    }

    $view = $userSettings['view'];
    if( $view == "panorama" )
    {
        $vsys = $userSettings['panos_vsys'];
        $preorpost = $userSettings['panorama_rules'];
        $template = $userSettings['panorama_template'];
    }
    else
    {
        $vsys = $userSettings['panos_vsys'];
        $preorpost = "all";
        $template = "all";
    }
    $source = $userSettings['source'];

    if( $type == "objects" )
    {
        if( ($source == 0) and ($vsys == "all") )
        {
            $query = "";
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            $query = " WHERE (vsys='$vsys' OR vsys='shared') ";
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND (vsys='$vsys' OR vsys='shared')";
            }
        }

        return $query;
    }
    elseif( $type == "template" )
    {
        if( ($source == 0) and ($template == 0) )
        {
            $query = "";
        }
        elseif( ($source == 0) and ($template != 0) )
        {
            $query = " WHERE template='$template'";
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $template != 0 )
            {
                $query .= " AND (template='$template')";
            }
        }
        return $query;
    }
    elseif( $type == "policies" )
    {
        if( ($source == 0) and ($vsys == "all") )
        {
            if( $preorpost == "all" )
            {
                $query = "";
            }
            else
            {
                $query = " WHERE preorpost='$preorpost'";
            }
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            if( $preorpost == "all" )
            {
                $query = " WHERE vsys='$vsys'";
            }
            else
            {
                $query = " WHERE (vsys='$vsys' AND preorpost='$preorpost') ";
            }
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND vsys='$vsys'";
            }
            if( $preorpost != "all" )
            {
                $query .= " AND preorpost='$preorpost'";
            }
        }
        return $query;
    }
}

#Query Generation
function generate_query($type, $vsys = null, $preorpost = null)
{
//$type objects or template or policies
#generate Queries
    require_once INC_ROOT . '/libs/common/lib-objects.php';
    require_once INC_ROOT . '/userManager/API/projects/manageSettings.php';
    global $projectdb;
    global $app;
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;

    $query = "SELECT DATABASE() as data FROM DUAL";
    $getParams = $projectdb->query($query);
    if( $getParams->num_rows == 1 )
    {
        $data = $getParams->fetch_assoc();
        $projectName = $data['data'];
    }
    $settings = get_UserSettings($projectName, $userID);

    if( !$settings['code'] )
    {
        $query = " WHERE 1 = 0 ";
        return $query;
    }
//    print_r($settings);
    $userSettings = $settings['msg'];

    if( is_null($vsys) )
    {
        $vsys = $userSettings['panos_vsys'];
    }

    $query = "";
    $view = $userSettings['view'];

    if( is_null($preorpost) )
    {
        if( $view == "panorama" )
        {
            $preorpost = $userSettings['panorama_rules'];
            $template = $userSettings['panorama_template'];
        }
        else
        {
            $preorpost = "all";
            $template = "all";
        }
    }

    if( $view == "panorama" )
    {
        $template = $userSettings['panorama_template'];
    }
    else
    {
        $template = "all";
    }
    //echo "TEMPLATE: " .$template. "\n";
    $source = $userSettings['source'];
    //echo "DEntro: ".$view, $source, $vsys, $preorpost, $template."\n";

    if( $type == "objects" )
    {
        if( ($source == 0) and ($vsys == "all") )
        {
            $query = "";
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            $query = " WHERE (vsys='$vsys' OR vsys='shared') ";
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND (vsys='$vsys' OR vsys='shared')";
            }
        }
//        return $query;
    }
    elseif( $type == "objects_vsyses" )
    {
        require_once INC_ROOT . '/libs/common/lib-objects.php';
        $vsyses = getVsyses($projectdb, $vsys, $source, 'quoted');
        if( ($source == 0) and ($vsys == "all") )
        {
            $query = "";
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            $query = " WHERE vsys in (" . implode(",", $vsyses) . ") ";
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND vsys in (" . implode(",", $vsyses) . ")";
            }
        }
    }
    elseif( $type == "zones" )
    {
        # Todo: Fix for Panorama. If shared show all zones for the entire Source
        if( $view == "panorama" )
        {
            $query = " WHERE source='$source' ";
        }
        else
        {
            $query = " WHERE source='$source' AND vsys='$vsys' ";
        }
    }
    elseif( $type == "template" )
    {
        if( ($source == 0) and ($template == 0) )
        {
            $query = "";
            if( $vsys != "all" )
            {
                $query = " WHERE vsys='$vsys'";
            }
        }
        elseif( ($source == 0) and ($template != 0) )
        {
            $query = " WHERE template='$template'";
            if( $vsys != "all" )
            {
                $query .= " AND vsys='$vsys'";
            }
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $template != 0 )
            {
                $query .= " AND (template='$template')";
            }
            if( $vsys != "all" )
            {
                $query .= " AND vsys='$vsys'";
            }
        }
    }
    elseif( $type == "template_not_vsys" )
    {
        if( ($source == 0) and ($template == 0) )
        {
            $query = "";
        }
        elseif( ($source == 0) and ($template != 0) )
        {
            $query = " WHERE template='$template'";
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $template != 0 )
            {
                $query .= " AND (template='$template')";
            }
            if( ($view == "panorama") && ($vsys != "all") )
            {
                $query .= " AND vsys='$vsys'";
            }
        }
    }
    elseif( $type == "policies" )
    {
        if( ($source == 0) and ($vsys == "all") )
        {
            if( $preorpost == "all" )
            {
                $query = "";
            }
            else
            {
                $query = " WHERE preorpost='$preorpost'";
            }
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            if( $preorpost == "all" )
            {
                $query = " WHERE vsys='$vsys'";
            }
            else
            {
                $query = " WHERE (vsys='$vsys' AND preorpost='$preorpost') ";
            }
        }
        elseif( $source != 0 )
        {
            $query = " WHERE source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND vsys='$vsys'";
            }
            if( $preorpost != "all" )
            {
                $query .= " AND preorpost='$preorpost'";
            }
        }
//        return $query;
    }

    return $query;
}

function generate_query_multitable($type)
{

//$type objects or template or policies
#generate Queries
    require_once INC_ROOT . '/userManager/API/projects/manageSettings.php';
    global $projectdb;
    global $app;
    $user = $app->sentinel->getUser();
    //echo "CON \n";
    //print_r($app->container->sentinel->getUser());

    //echo "SIN \n";
    //print_r($app->sentinel->getUser());

    $userID = $user->id;

    $query = "SELECT DATABASE() as data FROM DUAL";
    $getParams = $projectdb->query($query);
    if( $getParams->num_rows == 1 )
    {
        $data = $getParams->fetch_assoc();
        $projectName = $data['data'];
    }
    $settings = get_UserSettings($projectName, $userID);

    if( !$settings['code'] )
    {
        $query = " WHERE 1 = 0 ";
        return $query;
    }
//    print_r($settings);
    $userSettings = $settings['msg'];

    $query = "";
    $view = $userSettings['view'];
    if( $view == "panorama" )
    {
        $vsys = $userSettings['panos_vsys'];
        $preorpost = $userSettings['panorama_rules'];
        $template = $userSettings['panorama_template'];
    }
    else
    {
        $vsys = $userSettings['panos_vsys'];
        $preorpost = "all";
        $template = "all";
    }
    $source = $userSettings['source'];

    if( $type == "objects" )
    {
        /*if (($source == 0) AND ( $vsys == "all")) {
            $query = "";
        } elseif (($source == 0) AND ( $vsys != "")) {
            $query = " WHERE (a.vsys='$vsys' OR a.vsys='shared') ";
        } elseif ($source != 0) {
            $query = " WHERE a.source='$source'";
            if ($vsys != "all") {
                $query.=" AND (a.vsys='$vsys' OR a.vsys='shared')";
            }
        }*/

        if( ($source == 0) and ($vsys == "all") )
        {
            $query = "";
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            $query = " WHERE (a.vsys='$vsys') ";
        }
        elseif( $source != 0 )
        {
            $query = " WHERE a.source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND (a.vsys='$vsys')";
            }
        }

        return $query;
    }
    elseif( $type == "objects_vsyses" )
    {
        require_once INC_ROOT . '/libs/common/lib-objects.php';
        $vsyses = getVsyses($projectdb, $vsys, $source, 'quoted');
        if( ($source == 0) and ($vsys == "all") )
        {
            $query = "";
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            $query = " WHERE a.vsys in (" . implode(",", $vsyses) . ") ";
        }
        elseif( $source != 0 )
        {
            $query = " WHERE a.source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND a.vsys in (" . implode(",", $vsyses) . ") ";
            }
        }

        return $query;
    }
    elseif( $type == "template" )
    {
        if( ($source == 0) and ($template == 0) )
        {
            $query = "";
            //if ($vsys!="all"){
            //$query=" WHERE vsys='$vsys'";
            //}
        }
        elseif( ($source == 0) and ($template != 0) )
        {
            $query = " WHERE a.template='$template'";
            //if ($vsys!="all"){
            //$query.=" AND vsys='$vsys'";
            //}
        }
        elseif( $source != 0 )
        {
            $query = " WHERE a.source='$source'";
            if( $template != 0 )
            {
                $query .= " AND (a.template='$template')";
            }
            //if ($vsys!="all"){
            //$query.=" AND vsys='$vsys'";
            //}
        }

        return $query;
    }
    elseif( $type == "policies" )
    {
        if( ($source == 0) and ($vsys == "all") )
        {
            if( $preorpost == "all" )
            {
                $query = "";
            }
            else
            {
                $query = " WHERE a.preorpost='$preorpost'";
            }
        }
        elseif( ($source == 0) and ($vsys != "") )
        {
            if( $preorpost == "all" )
            {
                $query = " WHERE a.vsys='$vsys'";
            }
            else
            {
                $query = " WHERE (a.vsys='$vsys' AND a.preorpost='$preorpost') ";
            }
        }
        elseif( $source != 0 )
        {
            $query = " WHERE a.source='$source'";
            if( $vsys != "all" )
            {
                $query .= " AND a.vsys='$vsys'";
            }
            if( $preorpost != "all" )
            {
                $query .= " AND a.preorpost='$preorpost'";
            }
        }
        return $query;
    }
}

#Cleaning

function clean_duplicated_members($table)
{
    global $projectdb;

    if( ($table == "address_groups") || ($table == "services_groups") || ($table == "applications_groups") )
    {

        $getDup = $projectdb->query("SELECT id,count(id) as t FROM $table GROUP BY lid,member_lid,table_name HAVING t>1;");
        if( $getDup->num_rows > 0 )
        {
            $id = array();
            while( $data = $getDup->fetch_assoc() )
            {
                $id[] = $data['id'];
            }
            $projectdb->query("DELETE FROM $table WHERE id IN (" . implode(",", $id) . ")");
        }
    }
    elseif( $table == "tag_relations" )
    {

        $getDup = $projectdb->query("SELECT id, count(id) AS t, tag_id, member_lid, table_name FROM $table GROUP BY tag_id, member_lid, table_name HAVING t>1;");

        if( $getDup->num_rows > 0 )
        {

            $id = array();
            while( $data = $getDup->fetch_assoc() )
            {
                $id[] = $data['id'];
            }
            $projectdb->query("DELETE FROM $table WHERE id IN (" . implode(",", $id) . ")");
        }
    }
    else
    {
        $getDup = $projectdb->query("SELECT id, count(id) AS t, rule_lid, member_lid, table_name FROM $table GROUP BY rule_lid, member_lid, table_name HAVING t>1;");

        if( $getDup->num_rows > 0 )
        {

            $id = array();
            while( $data = $getDup->fetch_assoc() )
            {
                $id[] = $data['id'];
            }
            $projectdb->query("DELETE FROM $table WHERE id IN (" . implode(",", $id) . ")");
        }
    }


}


// Cleaned duplicated members when merging objects
function clean_duplicated_members_merging($table, $member_lid, $table_name)
{

    global $projectdb;

    if( ($table == "address_groups") || ($table == "services_groups") || ($table == "applications_groups") )
    {

        $getDup = $projectdb->query("SELECT id, count(id) AS t, lid, member_lid, table_name FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY lid, member_lid, table_name HAVING t>1;");
        //echo "SELECT id, count(id) AS t, lid, member_lid, table_name FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY lid, member_lid, table_name HAVING t>1;\n";

        if( $getDup->num_rows > 0 )
        {

            while( $data = $getDup->fetch_assoc() )
            {

                $lid = $data['lid'];
                $id_ok = $data['id'];

                $projectdb->query("DELETE FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND lid = '$lid' AND id != '$id_ok'; ");
            }
        }
    }
    elseif( $table == "tag_relations" )
    {

        $getDup = $projectdb->query("SELECT id, count(id) AS t, tag_id, member_lid, table_name FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY tag_id, member_lid, table_name HAVING t>1;");

        if( $getDup->num_rows > 0 )
        {

            while( $data = $getDup->fetch_assoc() )
            {

                $lid = $data['tag_id'];
                $id_ok = $data['id'];

                $projectdb->query("DELETE FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND tag_id = '$lid' AND id != '$id_ok'; ");
            }
        }
    }
    else
    {
        $getDup = $projectdb->query("SELECT id, count(id) AS t, rule_lid, member_lid, table_name FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY rule_lid, member_lid, table_name HAVING t>1;");
        //echo "SELECT id, count(id) AS t, rule_lid, member_lid, table_name FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY rule_lid, member_lid, table_name HAVING t>1;\n";

        if( $getDup->num_rows > 0 )
        {

            while( $data = $getDup->fetch_assoc() )
            {

                $rule_lid = $data['rule_lid'];
                $id_ok = $data['id'];

                $projectdb->query("DELETE FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid' AND id != '$id_ok'; ");
            }
        }
    }

}


// Cleaned duplicated members when merging objects
function cleanDuplicatedUsages($table, $table_name)
{

    global $projectdb;

    if( ($table == "address_groups") || ($table == "services_groups") || ($table == "applications_groups") )
    {

        $getDup = $projectdb->query("SELECT id, count(id) AS t, lid, member_lid, table_name FROM $table WHERE table_name = '$table_name' GROUP BY lid, member_lid, table_name HAVING t>1;");
        //echo "3. SELECT id, count(id) AS t, lid, member_lid, table_name FROM $table WHERE table_name = '$table_name' GROUP BY lid, member_lid, table_name HAVING t>1;\n";

        if( $getDup->num_rows > 0 )
        {

            while( $data = $getDup->fetch_assoc() )
            {

                $lid = $data['lid'];
                $id_ok = $data['id'];
                $member_lid = $data['member_lid'];

                $projectdb->query("DELETE FROM $table WHERE table_name = '$table_name' AND member_lid = '$member_lid' AND lid = '$lid' AND id != '$id_ok'; ");
                //echo "4. DELETE FROM $table WHERE table_name = '$table_name' AND member_lid = '$member_lid' AND lid = '$lid' AND id != '$id_ok'; \n";
            }
        }
    }
    elseif( $table == "tag_relations" )
    {

        $getDup = $projectdb->query("SELECT id, count(id) AS t, tag_id, member_lid, table_name FROM $table WHERE table_name = '$table_name' GROUP BY tag_id, member_lid, table_name HAVING t>1;");

        if( $getDup->num_rows > 0 )
        {

            while( $data = $getDup->fetch_assoc() )
            {

                $lid = $data['tag_id'];
                $id_ok = $data['id'];
                $member_lid = $data['member_lid'];

                $projectdb->query("DELETE FROM $table WHERE table_name = '$table_name' AND member_lid = '$member_lid' AND tag_id = '$lid' AND id != '$id_ok'; ");
            }
        }
    }
    else
    {
        $getDup = $projectdb->query("SELECT id, count(id) AS t, rule_lid, member_lid, table_name FROM $table WHERE table_name = '$table_name' GROUP BY rule_lid, member_lid, table_name HAVING t>1;");

        if( $getDup->num_rows > 0 )
        {

            while( $data = $getDup->fetch_assoc() )
            {

                $rule_lid = $data['rule_lid'];
                $id_ok = $data['id'];
                $member_lid = $data['member_lid'];

                $projectdb->query("DELETE FROM $table WHERE table_name = '$table_name' AND member_lid = '$member_lid' AND rule_lid = '$rule_lid' AND id != '$id_ok'; ");
            }
        }
    }

}

#Names
function checkNamesStartAlphaNum($nameToCheck)
{
    if( preg_match("/^[A-Za-z0-9]/", $nameToCheck) )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

function checkNamesStartNum($nameToCheck)
{
    if( preg_match("/^[0-9]/", $nameToCheck) )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

function normalizeNames($nameToNormalize)
{
    //$nameToNormalize = preg_replace('/(.*) (&#x2013;) (.*)/i', '$0 --> $1 - $3', $nameToNormalize);
    //$nameToNormalize = preg_replace("/&#x2013;/", "-", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\/]+/", "_", $nameToNormalize);
    $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_. ]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\s]+/", " ", $nameToNormalize);
    //$nameToNormalize = preg_replace("/[-]+/", "-", $nameToNormalize);
    //$nameToNormalize = preg_replace("/[_]+/", "_", $nameToNormalize);
    return $nameToNormalize;
}

function normalizeComments($nameToNormalize)
{
    $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_.:\,\s]+/", "", $nameToNormalize);
    return $nameToNormalize;
}

function normalizeTagNames($tagName)
{

    $tagName = str_replace('&#x2013;', '-', $tagName);
    $tagName = str_replace('&ndash;', '-', $tagName);
    $tagName = str_replace('–', '-', $tagName);

    return $tagName;
}

function truncate_names($longString)
{
    global $source;
    $variable = strlen($longString);

    if( $variable <= 63 )
    {
        return $longString;
    }
    else
    {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = 63 - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if( $salida != $longString )
        {
            add_log('warning', 'Names Normalization', 'Object Name exceeded >63 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
        }
        return $salida;
    }
}


function truncate_descriptions($longString, $version = "8")
{
    global $source;
    $variable = strlen($longString);
    if( $version < 8 )
    {
        $check = 254;
    }
    else
    {
        $check = 1023;
    }

    if( $variable <= $check )
    {
        return $longString;
    }
    else
    {
//        $separator = '';
//        $separatorlength = strlen($separator);
//        $maxlength = $check - $separatorlength;
//        $start = $maxlength;
//        $trunc = strlen($longString) - $maxlength;
//        $salida = substr_replace($longString, $separator, $start, $trunc);
        $salida = substr($longString, 0, $check);
        return $salida;
    }
}

function truncate_names_zones($longString, $version = "8")
{
    global $source;
    $variable = strlen($longString);

    //echo "La version es: " .$version. "\n";
    //echo "La variable es: " .$variable. "\n";
    if( $version < 7 )
    {
        $check = 15;
    }
    else
    {
        $check = 31;
    }

    if( $variable <= $check )
    {
        return $longString;
    }
    else
    {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = $check - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if( $salida != $longString )
        {
            add_log('warning', 'Zones: Names Normalization', 'Object Name exceeded > ' . $check . ' chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
        }
        return $salida;
    }
}

function truncate_tags($longString)
{
    global $source;
    $variable = strlen($longString);

    if( $variable <= 127 )
    {
        return $longString;
    }
    else
    {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = 127 - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if( $salida != $longString )
        {
            add_log2('warning', 'Names Normalization', 'Object Name exceeded >127 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required', '', '', '');
        }
        return $salida;
    }
}


function truncate_rulenames($longString)
{

    global $source;

    $variable = strlen($longString);

    $max = getMaxLengthRuleName($source);

    /*$version = calcVersion($source);

    if($version < 8.1){
        $max = 31;
    }elseif($version >= 8.1){
        $max = 63;
    }*/

    if( $variable <= $max )
    {
        return $longString;
    }
    else
    {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = $max - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if( $salida != $longString )
        {
            add_log('warning', 'Names Normalization', 'Object Name exceeded > ' . $max . ' chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
        }
        return $salida;
    }
}

function truncate_zone_names_cisco($longString, $version = "6")
{
    global $projectname;
    global $source;
    global $projectdb;
    $projectdb = selectDatabase($projectname);

    $variable = strlen($longString);

    if( $variable < 14 )
    {
        //return $longString;
    }
    else
    {
        $maxChars = 15;
        $salida = substr_replace($longString, '', $maxChars / 2, $variable - $maxChars);
        if( $salida != $longString )
        {
            add_log('warning', 'Names Normalization', 'Zone Name exceeded >15 chars Original:[' . $longString . '] NewName:[' . $salida . ']', $source, 'No Action Required');
            $projectdb->query("UPDATE security_rules_from SET name='$salida' WHERE name='$longString';");
            $projectdb->query("UPDATE security_rules_to SET name='$salida' WHERE name='$longString';");
            $projectdb->query("UPDATE nat_rules_from SET name='$salida' WHERE name='$longString';");
            $projectdb->query("UPDATE nat_rules SET op_zone_to='$salida' WHERE source='$source' AND op_zone_to='$longString';");
            $projectdb->query("UPDATE routes_static SET zone='$salida' WHERE source='$source' AND zone='$longString';");
        }
        //return $salida;
    }
}


function convertWildcards(STRING $wildcard, STRING $type)
{
    # @type cidr or netmask

    switch ($wildcard)
    {

        case "0.255.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.0.0.0";
                    break;
                case "cidr":
                    return "8";
                    break;
            }
            break;
        case "0.127.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.128.0.0";
                    break;
                case "cidr":
                    return "9";
                    break;
            }
            break;
        case "0.63.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.192.0.0";
                    break;
                case "cidr":
                    return "10";
                    break;
            }
            break;
        case "0.31.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.224.0.0";
                    break;
                case "cidr":
                    return "11";
                    break;
            }
            break;
        case "0.15.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.240.0.0";
                    break;
                case "cidr":
                    return "12";
                    break;
            }
            break;
        case "0.7.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.248.0.0";
                    break;
                case "cidr":
                    return "13";
                    break;
            }
            break;
        case "0.3.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.252.0.0";
                    break;
                case "cidr":
                    return "14";
                    break;
            }
            break;
        case "0.1.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.254.0.0";
                    break;
                case "cidr":
                    return "15";
                    break;
            }
            break;
        case "0.0.255.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.0.0";
                    break;
                case "cidr":
                    return "16";
                    break;
            }
            break;
        case "0.0.127.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.128.0";
                    break;
                case "cidr":
                    return "17";
                    break;
            }
            break;
        case "0.0.63.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.192.0";
                    break;
                case "cidr":
                    return "18";
                    break;
            }
            break;
        case "0.0.31.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.224.0";
                    break;
                case "cidr":
                    return "19";
                    break;
            }
            break;
        case "0.0.15.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.240.0";
                    break;
                case "cidr":
                    return "20";
                    break;
            }
            break;
        case "0.0.7.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.248.0";
                    break;
                case "cidr":
                    return "21";
                    break;
            }
            break;
        case "0.0.3.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.252.0";
                    break;
                case "cidr":
                    return "22";
                    break;
            }
            break;
        case "0.0.1.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.254.0";
                    break;
                case "cidr":
                    return "23";
                    break;
            }
            break;
        case "0.0.0.255":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.0";
                    break;
                case "cidr":
                    return "24";
                    break;
            }
            break;
        case "0.0.0.127":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.128";
                    break;
                case "cidr":
                    return "25";
                    break;
            }
            break;
        case "0.0.0.63":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.192";
                    break;
                case "cidr":
                    return "26";
                    break;
            }
            break;
        case "0.0.0.31":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.224";
                    break;
                case "cidr":
                    return "27";
                    break;
            }
            break;
        case "0.0.0.15":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.240";
                    break;
                case "cidr":
                    return "28";
                    break;
            }
            break;
        case "0.0.0.7":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.248";
                    break;
                case "cidr":
                    return "29";
                    break;
            }
            break;
        case "0.0.0.3":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.252";
                    break;
                case "cidr":
                    return "30";
                    break;
            }
            break;
        case "0.0.0.1":
            switch ($type)
            {
                case "netmask":
                    return "255.255.255.254";
                    break;
                case "cidr":
                    return "31";
                    break;
            }
            break;
        default:
            return FALSE;

    }


}

function fix_duplicated_rulenames($source, $vsys, $table, $ids = 0)
{

    global $projectdb;

    if( ($table == "security_rules") or ($table == "nat_rules") )
    {
        if( $ids != 0 )
        {
            # Todo: Finish consider if we receive a list of Rule IDS.
            $addIDs = " AND id IN (" . $ids . ") ";
        }
        $getRulesDup = $projectdb->query("SELECT name,count(id) as t FROM $table WHERE source='$source' AND vsys='$vsys' GROUP BY name HAVING t>1;");
        if( $getRulesDup->num_rows > 0 )
        {
            while( $data = $getRulesDup->fetch_assoc() )
            {
                $originalName = $data['name'];
                $ori_length = strlen($originalName);
                $getRules = $projectdb->query("SELECT id FROM $table WHERE source='$source' AND vsys='$vsys' AND name='$originalName';");
                if( $getRules->num_rows > 0 )
                {
                    $x = 0;
                    while( $getRulesData = $getRules->fetch_assoc() )
                    {
                        $theid = $getRulesData['id'];
                        if( $x == 0 )
                        {
                        }
                        else
                        {
                            $x_length = strlen($x) + 1;
                            $check = $ori_length + $x_length;
                            if( $check > 30 )
                            {
                                $originalName2 = substr($originalName, 0, -$x_length);
                                $newName = $originalName2 . "_" . $x;
                            }
                            else
                            {
                                $newName = $originalName . "_" . $x;
                            }
                            $projectdb->query("UPDATE $table SET name='$newName' WHERE id='$theid';");
                        }
                        $x++;
                    }
                }
            }
        }
    }
}


# Progress
function add_progress($project, $percentage, $message)
{
    global $projectdb;
    $projectdb = selectDatabase($project);

    $projectdb->query("DELETE from project_status WHERE project='$project' AND percentage='1.00';");
    $query = "INSERT INTO project_status (datetime,project,percentage,message) values (NOW(),'$project','$percentage','$message')";
    $projectdb->query($query);
}

function del_progress($project)
{
    global $projectdb;
    $projectdb = selectDatabase($project);

    $projectdb->query("TRUNCATE project_status;");
}

function update_progress($project, $percentage, $message, $jobid = -1)
{
    global $projectdb;
    $projectdb = selectDatabase($project);
    if( $jobid == -1 )
    {
        $query = $projectdb->query("SELECT id FROM project_status WHERE id=-1;");
        if( $query->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO project_status (id,datetime,project,percentage,message) VALUES ('-1',NOW(),'$project','$percentage','$message');");
        }
        else
        {
            $query = "UPDATE project_status set percentage='$percentage', message='$message' WHERE project='$project' AND id='$jobid'";
            $projectdb->query($query);
        }
    }
    else
    {
        $query = "UPDATE project_status set percentage='$percentage', message='$message' WHERE project='$project' AND id='$jobid'";
        $projectdb->query($query);
    }


}

function ip_version($ip)
{
    if( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) )
    {
        return "v4";
    }
    elseif( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
    {
        return "v6";
    }
    else
    {
        return "noip";
    }
}

function validateIpAddress($ip_addr, $version)
{
    if( $version == "v4" )
    {
        if( preg_match("/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/", $ip_addr) )
        {
            $parts = explode(".", $ip_addr);
            foreach( $parts as $ip_parts )
            {
                if( intval($ip_parts) > 255 || intval($ip_parts) < 0 )
                    return FALSE;
            }
            return TRUE;
        }
        else
            return FALSE;
    }
    elseif( $version == "v6" )
    {
        $check = filter_var($ip_addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        return $check;
    }
}

function checkNetmask($ip)
{
    if( !ip2long($ip) )
    {
        return FALSE;
    }
    elseif( strlen(decbin(ip2long($ip))) != 32 && ip2long($ip) != 0 )
    {
        return FALSE;
    }
    elseif( preg_match('/01/', decbin(ip2long($ip))) || !preg_match('/0/', decbin(ip2long($ip))) )
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

function isXML($url)
{
    if( $url != "" )
    {
        libxml_use_internal_errors(TRUE);
        $doc = new DOMDocument('1.0', 'utf-8');
        $doc->loadXML(file_get_contents($url));

        $errors = libxml_get_errors();
        if( empty($errors) )
        {
            return TRUE;
        }
        return FALSE;
    }
    else
    {
        return FALSE;
    }

}

function unzip($target_path, $path)
{
//$path = pathinfo(realpath($file), PATHINFO_DIRNAME);
    $zip = new ZipArchive;
    $res = $zip->open($target_path);
    if( $res === TRUE )
    {
        // extract it to the path we determined above
        $zip->extractTo($path);
        $zip->close();

        $dirrule = opendir($path);
        while( $rule = readdir($dirrule) )
        {
            if( (($rule != ".") && ($rule != "..") && ($rule != "Backups") && ($rule != "Pcaps") && (!preg_match("/.zip/i", $rule) && ($rule != "Reports"))) )
            {
                $rulepath = $path . $rule;
                if( is_dir($rulepath) )
                {
                    move_to_folder($rulepath . "/", $path);
                    rmdir($rulepath);
                    unlink($target_path);
                }
            }
        }

        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

function move_to_folder($source, $destination)
{
    $files = scandir($source);
// Cycle through all source files
    foreach( $files as $file )
    {
        if( in_array($file, array(".", "..")) )
            continue;
        // If we copied this successfully, mark it for deletion
        if( copy($source . $file, $destination . $file) )
        {
            $delete[] = $source . $file;
        }
    }
// Delete all successfully-copied files
    foreach( $delete as $file )
    {
        unlink($file);
    }
}

function GroupMember2IdAddress($source)
{
    global $project;
    global $projectdb;

    if( !is_numeric($source) )
    {
        $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source' GROUP BY filename;");
        if( $getSourceID->num_rows == 1 )
        {
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        }
        else
        {
            add_log('error', 'Mapping members with Address Groups', 'Invalid Source File', $source, 'Process finished unexpectly');
            exit(0);
        }
    }

    //This loop includes now the shared objects
    $sqlgroups = $projectdb->query("SELECT member,vsys FROM address_groups WHERE source='$source' AND member!='' AND table_name!='default_regions' GROUP BY BINARY member,vsys;");
    if( $sqlgroups->num_rows > 0 )
    {
        while( $getmember = $sqlgroups->fetch_assoc() )
        {
            $vsys = $getmember['vsys'];
            $member_name = $getmember['member'];
            if( preg_match("/^_mtobj_/", $member_name) )
            {
                $member_without_obj = str_replace("_mtobj_", "", $member_name);
                $search_member_id = $projectdb->query("SELECT id FROM address WHERE BINARY name='$member_without_obj' AND source='$source' AND vsys='$vsys' AND vtype='object' LIMIT 1;");
            }
            else
            {
                $search_member_id = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$member_name' AND source='$source' AND vsys='$vsys' AND vtype='' LIMIT 1;");
            }

            if( $search_member_id->num_rows == 1 )
            {
                $search_member_id_assoc = $search_member_id->fetch_assoc();
                $member_id = $search_member_id_assoc['id'];
                $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
            }
            else
            {
                #Check if its the negate object , if was object check nonobject
                if( preg_match("/^_mtobj_/", $member_name) )
                {
                    $member_without_obj = str_replace("_mtobj_", "", $member_name);
                    $search_member_id2 = $projectdb->query("SELECT id FROM address WHERE BINARY name='$member_without_obj' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                }
                else
                {
                    $search_member_id2 = $projectdb->query("SELECT id FROM address WHERE BINARY name='$member_name' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                }
                if( $search_member_id2->num_rows == 1 )
                {
                    $search_member_id_assoc2 = $search_member_id2->fetch_assoc();
                    $member_id = $search_member_id_assoc2['id'];
                    $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                }
                else
                {
                    $getShared = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$member_name' AND vsys='shared' LIMIT 1;");
                    if( $getShared->num_rows == 1 )
                    {
                        $search_member_id_assoc = $getShared->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                    }
                    else
                    {
                        $isGroup = $projectdb->query("SELECT id,name FROM address_groups_id WHERE BINARY name = '$member_name' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        $getGroupData = $isGroup->fetch_assoc();
                        $namegroup = $getGroupData['name'];
                        if( $isGroup->num_rows == 1 )
                        {
                            $idgroup = $isGroup->fetch_assoc();
                            $member_id = $getGroupData['id'];
                            $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address_groups_id' WHERE BINARY member = '$member_name'  AND source='$source' AND vsys='$vsys';");
                        }
                        else
                        {
                            $getSharedGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$member_name' AND vsys='shared' LIMIT 1");
                            if( $getSharedGroup->num_rows == 1 )
                            {
                                $search_member_id_assoc = $getSharedGroup->fetch_assoc();
                                $member_id = $search_member_id_assoc['id'];
                                $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address_groups_id' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                            }
                            else
                            {
                                $getRegion = $projectdb->query("SELECT id FROM default_regions WHERE name='$member_name'");
                                if( $getRegion->num_rows == 1 )
                                {
                                    $myregion = $getRegion->fetch_assoc();
                                    $lid2 = $myregion['id'];
                                    $projectdb->query("UPDATE address_groups SET member_lid='$lid2', table_name='default_regions' WHERE member = '$member_name' AND source='$source' AND vsys='$vsys';");
                                }
                                else
                                {
                                    #Is not in the config create as a DUMMY
                                    $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,vtype,vsys, ipaddress,cidr, dummy, devicegroup) VALUES ('ip-netmask','$member_name','$member_name','1','$source','1','dummy','$vsys','','', '1', 'MT_Panorama');");

                                    $flid = $projectdb->insert_id;
                                    $projectdb->query("UPDATE address_groups SET member_lid='$flid', table_name='address' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #Shared
    $sqlgroups = $projectdb->query("SELECT member,vsys FROM address_groups WHERE source='$source' AND vsys = 'shared' AND member!='' GROUP BY member,vsys;");
    if( $sqlgroups->num_rows > 0 )
    {
        while( $getmember = $sqlgroups->fetch_assoc() )
        {
            $member_name = $getmember['member'];
            $vsys = $getmember['vsys'];
            $search_member_id = $projectdb->query("SELECT id FROM address WHERE BINARY name='$member_name' AND source='$source' AND vsys = 'shared'  LIMIT 1;");
            if( $search_member_id->num_rows == 1 )
            {
                $search_member_id_assoc = $search_member_id->fetch_assoc();
                $member_id = $search_member_id_assoc['id'];
                $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
            }
            else
            {
                $getSharedGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$member_name' AND vsys = 'shared' LIMIT 1");
                if( $getSharedGroup->num_rows == 1 )
                {
                    $search_member_id_assoc = $getSharedGroup->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address_groups_id' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                    $projectdb->query("UPDATE address_groups SET member_lid='$member_id', table_name='address_groups_id' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                }
                else
                {
                    $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,vtype,vsys) VALUES ('host','$member_name','$member_name','1','$source','1','ip-netmask','shared');");
                    $flid = $projectdb->insert_id;
                    $projectdb->query("UPDATE address_groups SET member_lid='$flid', table_name='address' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                }
            }
        }
    }
}

function GroupMember2IdServices_improved($source)
{
    global $projectdb;

    if( !is_numeric($source) )
    {
        $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source' GROUP BY filename;");
        if( $getSourceID->num_rows == 1 )
        {
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        }
        else
        {
            add_log('error', 'Mapping members with Services Groups', 'Invalid Source File', $source, 'Process finished unexpectly');
            exit(0);
        }
    }

    $getMembers = $projectdb->query("SELECT * FROM services_groups WHERE source='$source';");
    if( $getMembers->num_rows > 0 )
    {

        $mytablesSource = array(
            "services",
            "services_groups_id"
        );

        foreach( $mytablesSource as $key => $table_name )
        {
            $loadApps = $projectdb->query("SELECT id,name,vsys FROM $table_name WHERE source='$source';");
            if( $loadApps->num_rows > 0 )
            {
                while( $data = $loadApps->fetch_assoc() )
                {
                    $lid = $data['id'];
                    $name = $data['name'];
                    $vsys = $data['vsys'];
                    $objectsInMemory[$table_name][$vsys][$name] = $lid;
                }
            }
        }
        $myArray = [];
        $member_name_array = [];
        while( $getMembersData = $getMembers->fetch_assoc() )
        {
            $vsys = $getMembersData['vsys'];
            $checkName = $getMembersData['member'];
            $member_name_array[] = $checkName;
            $lid = $getMembersData['lid'];
            $devicegroup = $getMembersData['devicegroup'];
            $myArray[$checkName]["lid"][] = $getMembersData['lid'];
            $myArray[$checkName]["id"] = $getMembersData['id'];
            $myArray[$checkName]["vsys"] = $vsys;
            $myArray[$checkName]["member"] = $checkName;
        }

        if( count($member_name_array) > 0 )
        {
            $address_array = array();
            foreach( $myArray as $arrayName => $arrayData )
            {
                $vsys = $arrayData['vsys'];
                $checkName = $arrayData['member'];
                $allVSYS = getVsyses($projectdb, $vsys, $source);

                foreach( $allVSYS as $newVsys )
                {
                    if( isset($objectsInMemory['services'][$newVsys][$checkName]) )
                    {
                        $myArray[$checkName]["member_lid"] = $objectsInMemory['services'][$newVsys][$checkName];
                        $myArray[$checkName]["table_name"] = "services";
                        $address_array[] = $checkName;
                    }
                    elseif( isset($objectsInMemory['services_groups_id'][$newVsys][$checkName]) )
                    {
                        $myArray[$checkName]["member_lid"] = $objectsInMemory['services_groups_id'][$newVsys][$checkName];
                        $myArray[$checkName]["table_name"] = "services_groups_id";
                        $address_array[] = $checkName;
                    }
                }
                $member_name_array = array_diff($member_name_array, $address_array);
            }


        }

        if( count($member_name_array) > 0 )
        {
            $max = 1;
            $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
            if( $getMaxID->num_rows == 1 )
            {
                $max1 = $getMaxID->fetch_assoc();
                $max = $max1['max'];
                $max++;
            }
            $addHost = array();
            foreach( $myArray as $arrayName => $arrayData )
            {
                $vsys = $arrayData['vsys'];
                $checkName = $arrayData['member'];
                if( !isset($arrayData['member_lid']) )
                {
                    $addHost[] = "('$max','$source','$vsys',1,'$checkName','$checkName','dummy', 'MT_Panorama', '')";
                    $myArray[$checkName]["member_lid"] = $max;
                    $myArray[$checkName]["table_name"] = "services";
                    $max++;
                }
            }
            $member_name_array = [];
        }


        # Write the Output
        if( count($member_name_array) == 0 )
        {

            if( count($addHost) > 0 )
            {
                $projectdb->query("INSERT INTO services (id,source,vsys,dummy,name_ext,name,vtype, devicegroup, protocol) VALUES " . implode(",", $addHost) . ";");
                unset($addHost);
            }

            foreach( $myArray as $member => $valueArray )
            {
                $member_lid = $valueArray["member_lid"];
                $table_name = $valueArray["table_name"];
                //$devicegroup = $valueArray["devicegroup"];
                foreach( $valueArray["lid"] as $lid )
                {
                    if( ($member_lid != "") and ($table_name != "") )
                    {
                        $add_mapp[] = "('$source','','$lid','$devicegroup','$member','$table_name','$member_lid')";
                    }
                }
            }

            if( count($add_mapp) > 0 )
            {
                $projectdb->query("DELETE FROM services_groups WHERE source='$source' AND member!='';");
                $projectdb->query("INSERT INTO services_groups (source,vsys,lid,devicegroup,member,table_name,member_lid) VALUES " . implode(",", $add_mapp) . ";");
                unset($add_mapp);
                unset($myArray);
            }
        }
    }


}

function GroupMember2IdServices($source)
{
    global $projectdb;

    if( !is_numeric($source) )
    {
        $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source' GROUP BY filename;");
        if( $getSourceID->num_rows == 1 )
        {
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        }
        else
        {
            add_log('error', 'Mapping members with Services Groups', 'Invalid Source File', $source, 'Process finished unexpectly');
            exit(0);
        }
    }
    $version = calcVersion($source);

    //This loop already includes shared vsys
    $sqlgroups = $projectdb->query("SELECT member,vsys FROM services_groups WHERE source='$source'  AND ((member!='') AND (member!='0')) GROUP BY BINARY member,vsys;");
    while( $getmember = $sqlgroups->fetch_assoc() )
    {
        $vsys = $getmember['vsys'];
        $member_name = $getmember['member'];
        if( ($member_name == "application-default") or ($member_name == "service-http") or ($member_name == "service-https") )
        {
            $search_member_id = $projectdb->query("SELECT id FROM services WHERE vsys='shared' AND BINARY name='$member_name' LIMIT 1;");
            $search_member_id_assoc = $search_member_id->fetch_assoc();
            $member_id = $search_member_id_assoc['id'];
            $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
        }
        else
        {
            $search_member_id = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$member_name' AND source='$source' AND vsys='$vsys' LIMIT 1;");
            if( $search_member_id->num_rows == 1 )
            {
                $search_member_id_assoc = $search_member_id->fetch_assoc();
                $member_id = $search_member_id_assoc['id'];
                $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services' WHERE BINARY member='$member_name' AND source='$source' AND vsys='$vsys';");
            }
            else
            {
                $getShared = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$member_name' AND source='$source' AND vsys='shared' LIMIT 1;");
                if( $getShared->num_rows == 1 )
                {
                    $search_member_id_assoc = $getShared->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services' WHERE BINARY member='$member_name' AND source='$source' AND vsys='$vsys';");
                }
                else
                {
                    $isGroup = $projectdb->query("SELECT id,name FROM services_groups_id WHERE BINARY name_ext = '$member_name' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                    $getGroupData = $isGroup->fetch_assoc();
                    $namegroup = $getGroupData['name'];
                    if( $isGroup->num_rows == 1 )
                    {
                        $idgroup = $isGroup->fetch_assoc();
                        $member_id = $getGroupData['id'];
                        $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services_groups_id' WHERE BINARY member = '$member_name'  AND source='$source' AND vsys='$vsys';");
                    }
                    else
                    {
                        $getSharedGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$member_name' AND source='$source' AND vsys='shared' LIMIT 1");
                        if( $getSharedGroup->num_rows == 1 )
                        {
                            $search_member_id_assoc = $getSharedGroup->fetch_assoc();
                            $member_id = $search_member_id_assoc['id'];
                            $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services_groups_id' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                        }
                        else
                        {
                            if( $version == "" )
                            {
                                $projectdb->query("INSERT INTO services (name_ext,name,checkit,source,vsys, vtype, dummy, devicegroup, protocol,invalid) VALUES ('$member_name','$member_name','1','$source','$vsys', 'service', 0, 'default', '','1');");
                            }
                            else
                            {
                                $projectdb->query("INSERT INTO services (name_ext,name,checkit,source,vsys, vtype, dummy, devicegroup, protocol) VALUES ('$member_name','$member_name','1','$source','$vsys', 'dummy', 1, 'MT_Panorama', '');");
                            }

                            $flid = $projectdb->insert_id;
                            $projectdb->query("UPDATE services_groups SET member_lid='$flid', table_name='services' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                        }
                    }
                }
            }
        }
    }

//    #Shared
    $sqlgroups = $projectdb->query("SELECT member,vsys FROM services_groups WHERE source='$source' AND vsys = 'shared'  AND (member!='' AND member!='0') GROUP BY member,vsys;");
    while( $getmember = $sqlgroups->fetch_assoc() )
    {
        $vsys = $getmember['vsys'];
        $member_name = $getmember['member'];
        if( ($member_name == "application-default") or ($member_name == "service-http") or ($member_name == "service-https") )
        {
            $search_member_id = $projectdb->query("SELECT id FROM services WHERE BINARY name='$member_name' AND vsys = 'shared' LIMIT 1;");
            $search_member_id_assoc = $search_member_id->fetch_assoc();
            $member_id = $search_member_id_assoc['id'];
            $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
        }
        else
        {
            $search_member_id = $projectdb->query("SELECT id FROM services WHERE BINARY name='$member_name' AND source='$source' AND vsys = 'shared' LIMIT 1;");
            if( $search_member_id->num_rows == 1 )
            {
                $search_member_id_assoc = $search_member_id->fetch_assoc();
                $member_id = $search_member_id_assoc['id'];
                $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
            }
            else
            {
                $getSharedGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys = 'shared' AND BINARY name='$member_name' LIMIT 1");
                if( $getSharedGroup->num_rows == 1 )
                {
                    $search_member_id_assoc = $getSharedGroup->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $projectdb->query("UPDATE services_groups SET member_lid='$member_id', table_name='services_groups_id' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                }
                else
                {
                    $projectdb->query("INSERT INTO services (name_ext,name,checkit,source,vsys) VALUES ('$member_name','$member_name','1','$source','shared');");
                    $flid = $projectdb->insert_id;
                    $projectdb->query("UPDATE services_groups SET member_lid='$flid', table_name='services' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                }
            }
        }
    }
}

function GroupMember2IdApplications($source)
{
    global $project;
    global $projectdb;

    if( !is_numeric($source) )
    {
        $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source' GROUP BY filename;");
        if( $getSourceID->num_rows == 1 )
        {
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        }
        else
        {
            add_log('error', 'Mapping members with Applications Groups', 'Invalid Source File', $source, 'Process finished unexpectly');
            exit(0);
        }
    }

    //Considers both specific vsys and shared vsys
    $sqlgroups = $projectdb->query("SELECT member,vsys FROM applications_groups WHERE source='$source' AND member!='' GROUP BY BINARY member,vsys;");
    if( $sqlgroups->num_rows > 0 )
    {
        while( $getmember = $sqlgroups->fetch_assoc() )
        {
            $vsys = $getmember['vsys'];
            $member_name = $getmember['member'];

            $search_member_id = $projectdb->query("SELECT id FROM applications WHERE BINARY name='$member_name' AND source='$source' AND vsys='$vsys' LIMIT 1;");
            if( $search_member_id->num_rows == 1 )
            {
                $search_member_id_assoc = $search_member_id->fetch_assoc();
                $member_id = $search_member_id_assoc['id'];
                $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';\n");
            }
            else
            {
                $getShared = $projectdb->query("SELECT id FROM applications WHERE BINARY name='$member_name' AND source='$source' AND vsys='shared' LIMIT 1;");
                if( $getShared->num_rows == 1 )
                {
                    $search_member_id_assoc = $getShared->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                }
                else
                {
                    $isGroup = $projectdb->query("SELECT id,name FROM applications_groups_id WHERE BINARY name = '$member_name' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                    $getGroupData = $isGroup->fetch_assoc();
                    $namegroup = $getGroupData['name'];
                    if( $isGroup->num_rows == 1 )
                    {
                        $idgroup = $isGroup->fetch_assoc();
                        $member_id = $getGroupData['id'];
                        $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications_groups_id' WHERE BINARY member = '$member_name'  AND source='$source' AND vsys='$vsys';");
                    }
                    else
                    {
                        $getSharedGroup = $projectdb->query("SELECT id FROM applications_groups_id WHERE BINARY name='$member_name' AND source='$source' AND vsys='shared' LIMIT 1");
                        if( $getSharedGroup->num_rows == 1 )
                        {
                            $search_member_id_assoc = $getSharedGroup->fetch_assoc();
                            $member_id = $search_member_id_assoc['id'];
                            $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications_groups_id' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                        }
                        else
                        {
                            $getRegion = $projectdb->query("SELECT id FROM default_applications WHERE name='$member_name'");
                            if( $getRegion->num_rows == 1 )
                            {
                                $myregion = $getRegion->fetch_assoc();
                                $lid2 = $myregion['id'];
                                $projectdb->query("UPDATE applications_groups SET member_lid='$lid2', table_name='default_applications' WHERE member = '$member_name' AND source='$source' AND vsys='$vsys';");
                            }
                            else
                            {
                                $getAppFilters = $projectdb->query("SELECT id FROM applications_filters WHERE source='$source' AND BINARY name='$member_name' LIMIT 1");
                                if( $getAppFilters->num_rows == 1 )
                                {
                                    $search_member_id_assoc = $getAppFilters->fetch_assoc();
                                    $member_id = $search_member_id_assoc['id'];
                                    $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications_filters' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                                }
                                else
                                {
                                    $getAppSharedFilters = $projectdb->query("SELECT id FROM applications_filters WHERE BINARY name='$member_name' AND source='$source' AND  LIMIT 1");
                                    if( $getAppSharedFilters->num_rows == 1 )
                                    {
                                        $search_member_id_assoc = $getAppSharedFilters->fetch_assoc();
                                        $member_id = $search_member_id_assoc['id'];
                                        $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications_filters' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                                    }
                                    else
                                    {
                                        #Is not in the config create as a DUMMY
                                        $projectdb->query("INSERT INTO applications (name, source, vsys, vtype, dummy, devicegroup) values('$member_name','$source','$vsys','dummy','1', 'MT_Panorama');");

                                        $flid = $projectdb->insert_id;
                                        $projectdb->query("UPDATE applications_groups SET member_lid='$flid', table_name='applications' WHERE BINARY member = '$member_name' AND source='$source' AND vsys='$vsys';");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
//    #Shared
    $sqlgroups = $projectdb->query("SELECT member,vsys FROM applications_groups WHERE source='$source' AND vsys = 'shared' AND member!='' GROUP BY member,vsys;");
    if( $sqlgroups->num_rows > 0 )
    {
        while( $getmember = $sqlgroups->fetch_assoc() )
        {
            $member_name = $getmember['member'];
            $vsys = $getmember['vsys'];
            $search_member_id = $projectdb->query("SELECT id FROM default_applications WHERE BINARY name='$member_name' LIMIT 1;");
            if( $search_member_id->num_rows == 1 )
            {
                $search_member_id_assoc = $search_member_id->fetch_assoc();
                $member_id = $search_member_id_assoc['id'];
                $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='default_applications' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
            }
            else
            {
                $search_member_id = $projectdb->query("SELECT id FROM applications WHERE BINARY name='$member_name' AND source='$source' AND vsys = 'shared'  LIMIT 1;");
                if( $search_member_id->num_rows == 1 )
                {
                    $search_member_id_assoc = $search_member_id->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                }
                else
                {
                    $getSharedGroup = $projectdb->query("SELECT id FROM applications_groups_id WHERE source='$source' AND vsys = 'shared' AND BINARY name='$member_name' LIMIT 1");
                    if( $getSharedGroup->num_rows == 1 )
                    {
                        $search_member_id_assoc = $getSharedGroup->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications_groups_id' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                    }
                    else
                    {
                        $getSharedGroup = $projectdb->query("SELECT id FROM applications_filters WHERE source='$source' AND BINARY name='$member_name' AND vsys = 'shared' LIMIT 1");
                        if( $getSharedGroup->num_rows == 1 )
                        {
                            $search_member_id_assoc = $getSharedGroup->fetch_assoc();
                            $member_id = $search_member_id_assoc['id'];
                            $projectdb->query("UPDATE applications_groups SET member_lid='$member_id', table_name='applications_filters' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                        }
                        else
                        {
                            $projectdb->query("INSERT INTO applications (name,source,used,vtype,vsys,dummy,devicegroup) values('$member_name','$source','1','dummy','shared',1,'MT_Panorama');");
                            $flid = $projectdb->insert_id;
                            $projectdb->query("UPDATE applications_groups SET member_lid='$flid', table_name='applications' WHERE BINARY member = '$member_name' AND source='$source' AND vsys = 'shared';");
                        }
                    }
                }
            }
        }
    }
}

# New Functions to Mapp
function GroupMember2IdAddress_improved($source)
{
    global $project;
    global $projectdb;

    if( !is_numeric($source) )
    {
        $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source' GROUP BY filename;");
        if( $getSourceID->num_rows == 1 )
        {
            $devicegroup = $source;
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        }
        else
        {
            add_log('error', 'Mapping members with Address Groups', 'Invalid Source File', $source, 'Process finished unexpectly');
            exit(0);
        }
    }

    //This includes both specific vsys and shaered vsys
    $getVsys = $projectdb->query("SELECT vsys FROM address_groups_id WHERE source='$source' GROUP BY vsys;");
    if( $getVsys->num_rows > 0 )
    {
        while( $getVsysData = $getVsys->fetch_assoc() )
        {
            #Inititalize vars
            $myArray = [];
            $member_name_array = [];
            $address_array = [];
            $ciscoArray = [];

            $vsys = $getVsysData['vsys'];
            $sqlgroups = $projectdb->query("SELECT id,member,lid,devicegroup FROM address_groups WHERE source='$source' AND vsys='$vsys' AND member!='';");
            if( $sqlgroups->num_rows > 0 )
            {
                while( $getmember = $sqlgroups->fetch_assoc() )
                {
                    if( preg_match("/^_mtobj_/", $getmember['member']) )
                    {
                        $member_without_obj = str_replace("_mtobj_", "", $getmember['member']);
                        $ciscoArray[] = $member_without_obj;
                    }
                    $member_name_array[] = $getmember['member'];
                    $myArray[$getmember['member']]["lid"][] = $getmember['lid'];
                    $myArray[$getmember['member']]["id"] = $getmember['id'];
                }

                # Cisco Objects Case
                if( count($member_name_array) > 0 )
                {
                    $getAddress = $projectdb->query("SELECT id,name FROM address WHERE source='$source' AND vsys='$vsys' AND vtype='object' AND BINARY name IN ('" . implode("','", $ciscoArray) . "');");
                    if( $getAddress->num_rows > 0 )
                    {
                        while( $data = $getAddress->fetch_assoc() )
                        {
                            $member_name = "_mtobj_" . $data['name'];
                            $member_lid = $data['id'];
                            $table_name = "address";
                            $address_array[] = "_mtobj_" . $data['name'];
                            $myArray[$member_name]["member_lid"] = $member_lid;
                            $myArray[$member_name]["table_name"] = $table_name;
                        }
                        $ciscoArray = array_diff($ciscoArray, $address_array);
                        $member_name_array = array_diff($member_name_array, $address_array);
                        $address_array = [];
                        if( count($ciscoArray) > 0 )
                        {
                            $getAddress = $projectdb->query("SELECT id,name FROM address WHERE source='$source' AND vsys='$vsys' AND vtype='' AND BINARY name IN ('" . implode("','", $ciscoArray) . "');");
                            if( $getAddress->num_rows > 0 )
                            {
                                while( $data = $getAddress->fetch_assoc() )
                                {
                                    $member_name = "_mtobj_" . $data['name'];
                                    $member_lid = $data['id'];
                                    $table_name = "address";
                                    $address_array[] = "_mtobj_" . $data['name'];
                                    $myArray[$member_name]["member_lid"] = $member_lid;
                                    $myArray[$member_name]["table_name"] = $table_name;
                                }
                                $ciscoArray = array_diff($ciscoArray, $address_array);
                                if( count($ciscoArray) > 0 )
                                {
                                    add_log2('error', 'Mapping Groups with Members', 'The Group Members [' . implode(",", $ciscoArray) . '] were not found in the Database', $source, 'fix it manually.', 'objects', '', '');
                                }
                            }
                        }
                        $member_name_array = array_diff($member_name_array, $ciscoArray);
                        unset($address_array);
                        unset($ciscoArray);
                    }
                }

                # Case is Address
                if( count($member_name_array) > 0 )
                {
                    $getAddress = $projectdb->query("SELECT id,name FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if( $getAddress->num_rows > 0 )
                    {
                        while( $data = $getAddress->fetch_assoc() )
                        {
                            $member_name = $data['name'];
                            $member_lid = $data['id'];
                            $table_name = "address";
                            $address_array[] = $data['name'];
                            $myArray[$member_name]["member_lid"] = $member_lid;
                            $myArray[$member_name]["table_name"] = $table_name;
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Case is Shared Address
                if( count($member_name_array) > 0 )
                {
                    $getAddress = $projectdb->query("SELECT id,name FROM address WHERE source='$source' AND vsys = 'shared' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if( $getAddress->num_rows > 0 )
                    {
                        while( $data = $getAddress->fetch_assoc() )
                        {
                            $member_name = $data['name'];
                            $member_lid = $data['id'];
                            //$table_name = "shared_address";
                            $table_name = "address";
                            $address_array[] = $data['name'];
                            $myArray[$member_name]["member_lid"] = $member_lid;
                            $myArray[$member_name]["table_name"] = $table_name;
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Case is Address Groups
                if( count($member_name_array) > 0 )
                {
                    $getAddress = $projectdb->query("SELECT id,name FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if( $getAddress->num_rows > 0 )
                    {
                        while( $data = $getAddress->fetch_assoc() )
                        {
                            $member_name = $data['name'];
                            $member_lid = $data['id'];
                            $table_name = "address_groups_id";
                            $address_array[] = $data['name'];
                            $myArray[$member_name]["member_lid"] = $member_lid;
                            $myArray[$member_name]["table_name"] = $table_name;
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Case is Shared Address Groups
                if( count($member_name_array) > 0 )
                {
                    $getAddress = $projectdb->query("SELECT id,name FROM address_groups_id WHERE source='$source' AND vsys = 'shared' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if( $getAddress->num_rows > 0 )
                    {
                        while( $data = $getAddress->fetch_assoc() )
                        {
                            $member_name = $data['name'];
                            $member_lid = $data['id'];
                            //$table_name = "shared_address_groups_id";
                            $table_name = "address_groups_id";
                            $address_array[] = $data['name'];
                            $myArray[$member_name]["member_lid"] = $member_lid;
                            $myArray[$member_name]["table_name"] = $table_name;
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Objects doesnt exist and need to be added
                if( count($member_name_array) != 0 )
                {
                    # Objects needs to be added
                    $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
                    if( $getMaxID->num_rows == 1 )
                    {
                        $max1 = $getMaxID->fetch_assoc();
                        $max = $max1['max'];
                        $max++;
                    }


                    #Check if the object is using the name_ext instead the name so load again with name_ext


                    foreach( $member_name_array as $key => $member_name )
                    {
                        $addHost[] = "('$max','host','$member_name','$member_name','1','$source','0','ip-netmask','$vsys',0)";
                        $myArray[$member_name]["member_lid"] = $max;
                        $myArray[$member_name]["table_name"] = "address";
                        $max++;
                    }
                    if( count($addHost) > 0 )
                    {
                        $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy) VALUES " . implode(",", $addHost) . ";");
                        unset($addHost);
                    }
                    $member_name_array = [];
                }

                # Write the Output
                if( count($member_name_array) == 0 )
                {
                    foreach( $myArray as $member => $valueArray )
                    {
                        $member_lid = $valueArray["member_lid"];
                        $table_name = $valueArray["table_name"];
                        //$devicegroup = $valueArray["devicegroup"];
                        foreach( $valueArray["lid"] as $lid )
                        {
                            if( ($member_lid != "") and ($table_name != "") )
                            {
                                $add_mapp[] = "('$source','$vsys','$lid','$devicegroup','$member','$table_name','$member_lid')";
                            }
                        }
                    }

                    if( count($add_mapp) > 0 )
                    {
                        $projectdb->query("DELETE FROM address_groups WHERE source='$source' AND vsys='$vsys' AND member!='';");
                        $projectdb->query("INSERT INTO address_groups (source,vsys,lid,devicegroup,member,table_name,member_lid) VALUES " . implode(",", $add_mapp) . ";");
                        unset($add_mapp);
                        unset($myArray);
                    }
                }
            }
        }
    }

//    # Shared Groups
    $sqlgroups = $projectdb->query("SELECT member,lid,devicegroup FROM address_groups WHERE source='$source' AND vsys = 'shared' AND member!='';");
    if( $sqlgroups->num_rows > 0 )
    {

        #Inititalize vars
        $myArray = [];
        $member_name_array = [];
        $address_array = [];

        while( $getmember = $sqlgroups->fetch_assoc() )
        {
            $member_name_array[] = $getmember['member'];
            $myArray[$getmember['member']]["lid"][] = $getmember['lid'];
            $myArray[$getmember['member']]["devicegroup"] = $getmember['devicegroup'];
        }

        # Case is Shared Address
        if( count($member_name_array) > 0 )
        {
            $getAddress = $projectdb->query("SELECT id,name FROM address WHERE source='$source' AND vsys = 'shared' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
            if( $getAddress->num_rows > 0 )
            {
                while( $data = $getAddress->fetch_assoc() )
                {
                    $member_name = $data['name'];
                    $member_lid = $data['id'];
                    //$table_name = "shared_address";
                    $table_name = "address";
                    $address_array[] = $data['name'];
                    $myArray[$member_name]["member_lid"] = $member_lid;
                    $myArray[$member_name]["table_name"] = $table_name;
                }
                $member_name_array = array_diff($member_name_array, $address_array);
                unset($address_array);
            }
        }

        # Case is Shared Address Groups
        if( count($member_name_array) > 0 )
        {
            $getAddress = $projectdb->query("SELECT id,name FROM address_groups_id WHERE source='$source' AND vsys = 'shared' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
            if( $getAddress->num_rows > 0 )
            {
                while( $data = $getAddress->fetch_assoc() )
                {
                    $member_name = $data['name'];
                    $member_lid = $data['id'];
                    //$table_name = "shared_address_groups_id";
                    $table_name = "address_groups_id";
                    $address_array[] = $data['name'];
                    $myArray[$member_name]["member_lid"] = $member_lid;
                    $myArray[$member_name]["table_name"] = $table_name;
                }
                $member_name_array = array_diff($member_name_array, $address_array);
                unset($address_array);
            }
        }

        # Objects doesnt exist and need to be added
        if( count($member_name_array) != 0 )
        {
            $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
            if( $getMaxID->num_rows == 1 )
            {
                $max1 = $getMaxID->fetch_assoc();
                $max = $max1['max'];
                $max++;
            }
            foreach( $member_name_array as $key => $member_name )
            {
                $addHost[] = "('$max','host','$member_name','$member_name','1','$source','0','dummy','shared',1,'MT_Panorama')";
                $myArray[$member_name]["member_lid"] = $max;
                //$myArray[$member_name]["table_name"] = "shared_address";
                $myArray[$member_name]["table_name"] = "address";
                $max++;
            }
            if( count($addHost) > 0 )
            {
                $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup) VALUES " . implode(",", $addHost) . ";");
                unset($addHost);
            }
            $member_name_array = [];
        }

        # Write the Output
        if( count($member_name_array) == 0 )
        {
            foreach( $myArray as $member => $valueArray )
            {
                $member_lid = $valueArray["member_lid"];
                $table_name = $valueArray["table_name"];
                $devicegroup = $valueArray["devicegroup"];
                foreach( $valueArray["lid"] as $lid )
                {
                    $add_mapp[] = "('$source','shared','$lid','$devicegroup','$member','$table_name','$member_lid')";
                }
            }

            if( count($add_mapp) > 0 )
            {
                $projectdb->query("DELETE FROM address_groups WHERE source='$source' AND vsys='shared';");
                $projectdb->query("INSERT INTO address_groups (source,vsys,lid,devicegroup,member,table_name,member_lid) VALUES " . implode(",", $add_mapp) . ";");
                unset($add_mapp);
                unset($myArray);
            }
        }
    }
}

function copy_device($deviceSerial, $project)
{

    global $app;

    if( !file_exists(USERSPACE_PATH . "/projects/$project/toImport/") )
    {
        mkdir(USERSPACE_PATH . "/projects/$project/toImport/", 0777, TRUE);
    }

    $deviceObj = $app->device->where('serial', '=', $deviceSerial)->get()->first();
    $deviceName = $deviceObj->devicename;
    $source = USERSPACE_PATH . "/devices/" . $deviceSerial . "/ConfigBackup.xml.dat";
    $destination = USERSPACE_PATH . "/projects/" . $project . "/toImport/" . $deviceName . "_" . $deviceSerial . ".xml.dat";
    $result = FALSE;
    //Decrypt the file
    if( !$deviceObj = $app->device->where("serial", $deviceSerial)->get()->first() )
    {
        echo("Device not found in our registry");
    }
    else
    {
        $keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->get()->first();
        $encrypterDevice = new OpenSSLTools($keyObj->key, $keyObj->iv);
        $contents = $encrypterDevice->decryptFromFile($source);

        if( !$projectObj = $app->project->where("name", $project)->get()->first() )
        {
            echo("Project not found in our registry");
        }
        else
        {
            // print_r($projectObj);
            $keyObj = $app->accessKey->where("type", "project")->where("lid", $projectObj->id)->get()->first();
            $encrypterProject = new OpenSSLTools($keyObj->key, $keyObj->iv);
            $result = $encrypterProject->encryptToFile($contents, $destination);
        }
    }

//    $result = copy($source, $destination);
    return $result;
}

function copy_baseconfig($baseconfig, $project)
{
    $source = USERSPACE_PATH . "/Templates/" . $baseconfig;
    $destination = USERSPACE_PATH . "/projects/" . $project . "/toImport/" . $baseconfig;
    $result = copy($source, $destination);
    return $result;
}

function add_default_services($source)
{
    global $projectdb;
    $exists = $projectdb->query("SELECT id FROM services WHERE name IN ('application-default','service-http','service-https') AND source='$source' AND vsys='shared';");
    if( $exists->num_rows == 3 )
    {

    }
    else
    {
        $projectdb->query("INSERT INTO services (name_ext,name,dport,protocol,vsys,source,devicegroup) VALUES ('application-default','application-default','0','tcp','shared','$source','predefined'),('service-http','service-http','80','tcp','shared','$source','predefined'),('service-https','service-https','443','tcp','shared','$source','predefined');");
    }
}

function add_default_profiles($source, $version)
{
    global $projectdb;
    $exists = $projectdb->query("SELECT id FROM profiles WHERE name IN ('strict','predefined') AND source='$source' AND vsys='shared';");
    if( $exists->num_rows == 6 )
    {

    }
    else
    {
        $projectdb->query("INSERT INTO profiles (name,type,devicegroup,vsys,source) VALUES ('strict','vulnerability','predefined','shared','$source'),('default','vulnerability','predefined','shared','$source'),('default','url-filtering','predefined','shared','$source'),('default','virus','predefined','shared','$source'),('default','spyware','predefined','shared','$source'),('strict','spyware','predefined','shared','$source');");
    }
    if( $version >= 7 )
    {
        $exists = $projectdb->query("SELECT id FROM profiles WHERE name ='default' AND type='wildfire-analysis' AND source='$source' AND vsys='shared';");
        if( $exists->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO profiles (name,type,devicegroup,vsys,source) VALUES ('default','wildfire-analysis','predefined','shared','$source');");
        }
    }
    if( $version >= 8 )
    {
        $exists = $projectdb->query("SELECT id FROM profiles WHERE name IN ('basic file blocking','strict file blocking') AND source='$source' AND vsys='shared';");
        if( $exists->num_rows == 2 )
        {

        }
        else
        {
            $projectdb->query("INSERT INTO profiles (name,type,devicegroup,vsys,source) VALUES ('basic file blocking','file-blocking','predefined','shared','$source'),('strict file blocking','file-blocking','predefined','shared','$source');");
        }
    }
}

function add_default_tags($source, $version)
{
    global $projectdb;
    $exists = $projectdb->query("SELECT id FROM tag WHERE devicegroup='predefined' AND source='$source' AND vsys='shared';");
    if( $exists->num_rows == 0 )
    {
        if( $version >= 7 )
        {
            $projectdb->query("INSERT INTO tag (name_ext,name,devicegroup,vsys,source) VALUES ('Sanctioned','Sanctioned','predefined','shared','$source'),('empty','empty','predefined','shared','$source');");
        }
    }
}

function add_default_external_list($source, $version)
{
    global $projectdb;
    $exists = $projectdb->query("SELECT id FROM external_list WHERE devicegroup='predefined' AND source='$source' AND vsys='shared';");
    if( $exists->num_rows == 0 )
    {
        if( $version >= 8 )
        {
            $projectdb->query("INSERT INTO external_list (name_ext,name,devicegroup,vsys,source,type) VALUES ('panw-highrisk-ip-list','panw-highrisk-ip-list','predefined','shared','$source','external_lists'),('panw-known-ip-list','panw-known-ip-list','predefined','shared','$source','external_lists');");
        }
    }
}

function clone_security_rule($initialPosition, $finalPosition, $vsys, $source, $rule_lid, $message, $project)
{

    global $projectdb;

    $max_length_rule_name = getMaxLengthRuleName($source);

    if( $initialPosition == "" )
    {
        $getPos = $projectdb->query("SELECT position FROM security_rules WHERE id='$rule_lid';");
        if( $getPos->num_rows == 1 )
        {
            $data = $getPos->fetch_assoc();
            $initialPosition = $data['position'];
        }
    }

    if( $finalPosition == "" )
    {
        $finalPosition = intval($initialPosition) + 1;
    }
    if( $finalPosition == "-1" )
    {
        $finalPosition = intval($initialPosition) - 1;
    }
    if( $message == "" )
    {
        $message = "Cl-";
    }
    elseif( $message == "Unk-" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='Unknown Traffic';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('Unknown Traffic','color1','Identify Unknown Traffic','$source','$vsys','$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }
    elseif( $message == "App-Ovrr" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='App Override';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('App Override','color2','From Phase2. Application Override Rule assoc','$source','$vsys','$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }
    elseif( $message == "Appid" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='Appid Adoption';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('Appid Adoption','color2','Appid Adoption by MT3','$source','$vsys','$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }
    elseif( $message == "Usr-" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='Unknown Users';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('Unknown Users','color1','Identify Unknown Users','$source','$vsys','$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }


    $update_lid = array();
    $clone_rule = array();

    //$getALL=$projectdb->query("SELECT position,id FROM security_rules WHERE source='$source'  AND vsys='$vsys' AND position > '$initialPosition';");
    $position = "";
    $newPosition = "";

    if( $initialPosition > $finalPosition )
    {
        $projectdb->query("UPDATE security_rules SET position=position+1 WHERE position >= '$initialPosition';");
        $thePosition = $initialPosition + 1;
    }
    else
    {
        $projectdb->query("UPDATE security_rules SET position=position+1 WHERE position >= '$finalPosition';");
        $thePosition = "$initialPosition";
    }

    /* while($ALL=$getALL->fetch_assoc()){
      $position=$ALL['position'];
      $newPosition=intval($position)+1;
      $getRuleLid=$ALL['id'];

      if (!$projectdb->query("UPDATE security_rules SET position='$newPosition' WHERE id='$getRuleLid' AND source='$source' AND vsys='$vsys';")){
      printf("Errormessage: %s\n", $projectdb->error);
      }
      } */

    $getMaxLid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getMax = $getMaxLid->fetch_assoc();
    $lid = intval($getMax['max']) + 1;
    $entity1 = $projectdb->query("SELECT * FROM security_rules WHERE position='$thePosition' AND source='$source' AND vsys='$vsys';");
    $entity = $entity1->fetch_assoc();
    $entity["id"] = $lid;
    $entity["lid"] = "";
    $name = $entity["name"];
    $entity["description"] = addslashes($entity["description"]);

    if( $name == "" )
    {
        $name = $lid;
    }
    $thename = truncate_rulenames($message . $name);

    //Check if exist name
    /*$i = 0;
    $exist = 0;
    while($exist == 0){
        $thename_final = "";
        if($i != 0){
            $thename_final = $thename."_".$i;
        }else{$thename_final = $thename;}
        $getExistName = $projectdb->query("SELECT id FROM security_rules WHERE BINARY name = '$thename_final' AND source='$source' AND vsys='$vsys';");
        if ($getExistName->num_rows == 0) {
            $exist = 1;
            $thename = $thename_final;
        }
        $i++;
    }*/

    //Check if exist name
    $i = 0;
    $exist = 0;
    $ori_length = strlen($thename);
    while( $exist == 0 )
    {
        $thename_final = "";
        if( $i != 0 )
        {
            $x_length = strlen($i) + 1;
            $check = $ori_length + $x_length;

            if( $check > $max_length_rule_name )
            {
                $originalName2 = substr($thename, 0, -$x_length);
                $thename_final = $originalName2 . "_" . $i;
            }
            else
            {
                $thename_final = $thename . "_" . $i;
            }
        }
        else
        {
            $thename_final = $thename;
        }

        $getExistName = $projectdb->query("SELECT id FROM security_rules WHERE BINARY name = '$thename_final' AND source='$source' AND vsys='$vsys';");
        if( $getExistName->num_rows == 0 )
        {
            $exist = 1;
            $thename = $thename_final;
        }
        $i++;
    }

    $entity["name"] = $thename;

    if( $initialPosition > $finalPosition )
    {
        $entity["position"] = "$initialPosition";
    }
    else
    {
        $entity["position"] = "$finalPosition";
    }

    $my = fopen("/tmp/aaa", "a");
    fwrite($my, "INSERT INTO security_rules (" . implode(", ", array_keys($entity)) . ") VALUES ('" . implode("', '", array_values($entity)) . "')\n");
    fclose($my);
    $projectdb->query("INSERT INTO security_rules (" . implode(", ", array_keys($entity)) . ") VALUES ('" . implode("', '", array_values($entity)) . "')");

    #Start Clone the rest of the rules adr, src, to, from, srv, APP

    //$getDST = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,counter,devicegroup from security_rules_dst where source='$source' and rule_lid='$rule_lid' AND vsys='$vsys';");
    $getDST = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,counter,devicegroup from security_rules_dst where rule_lid='$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            //$projectdb->query("INSERT INTO security_rules_dst (".implode(", ",array_keys($DST)).") VALUES ('".implode("', '",array_values($DST))."')");
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_dst (id,source,rule_lid,member_lid,table_name,vsys,counter,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getSRC = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,counter,devicegroup FROM security_rules_src WHERE rule_lid = '$rule_lid' ;");
    if( $getSRC->num_rows > 0 )
    {
        $rules = array();
        while( $SRC = $getSRC->fetch_assoc() )
        {
            $SRC["id"] = "";
            $SRC["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($SRC)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_src (id,source,rule_lid,member_lid,table_name,vsys,counter,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,vsys,name,rule_lid,devicegroup FROM security_rules_from WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_from (id,source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,vsys,name,rule_lid,devicegroup FROM security_rules_to WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_to (id,source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,counter,devicegroup FROM security_rules_srv WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_srv (id,source,rule_lid,member_lid,table_name,vsys,counter,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,devicegroup FROM security_rules_tag WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_tag (id,source,rule_lid,member_lid,table_name,vsys,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,devicegroup FROM security_rules_app WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_app (id,source,rule_lid,member_lid,table_name,vsys,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,devicegroup, type FROM security_rules_profiles WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_profiles (id,source,rule_lid,member_lid,table_name,vsys,devicegroup,type) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,rule_lid,member_lid,table_name,vsys,devicegroup FROM security_rules_hip WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_hip (id,source,rule_lid,member_lid,table_name,vsys,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,vsys,name,rule_lid,devicegroup FROM security_rules_categories WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_categories (id,source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,vsys,name,rule_lid,devicegroup FROM security_rules_usr WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $name_usr = $DST["name"];
            $DST["name"] = $projectdb->real_escape_string($name_usr);
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_usr (id,source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id,source,vsys,name,rule_lid,device_vsys FROM security_rules_target WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO security_rules_target (id,source,vsys,name,rule_lid,devicegroup,device_vsys) VALUES " . implode(",", $rules) . ";");
    }

    if( $message == "Unk-" )
    {
        $dup = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid='$lid' AND table_name='$tagTable' AND member_lid='$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO security_rules_tag (source,table_name,member_lid,rule_lid,vsys,devicegroup) VALUES ('$source','$tagTable','$tagId','$lid','$vsys','$project');");
        }
    }
    elseif( $message == "App-Ovrr" )
    {
        $dup = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid='$lid' AND table_name='$tagTable' AND member_lid='$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO security_rules_tag (source,table_name,member_lid,rule_lid,vsys,devicegroup) VALUES ('$source','$tagTable','$tagId','$lid','$vsys','$project');");
        }
    }
    elseif( $message == "Appid" )
    {
        $dup = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid='$lid' AND table_name='$tagTable' AND member_lid='$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO security_rules_tag (source,table_name,member_lid,rule_lid,vsys,devicegroup) VALUES ('$source','$tagTable','$tagId','$lid','$vsys','$project');");
        }
    }
    elseif( $message == "Usr-" )
    {
        $dup = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid='$lid' AND table_name='$tagTable' AND member_lid='$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO security_rules_tag (source,table_name,member_lid,rule_lid,vsys,devicegroup) VALUES ('$source','$tagTable','$tagId','$lid','$vsys','$project');");
        }
    }
    add_log('ok', 'Rule Cloned', 'RuleID [' . $rule_lid . '] has been cloned in new RuleID [' . $lid . ']', $source, 'No Action Required');
    // var_dump( debug_backtrace());

    // Insert relation rule origin with rule clone
    $projectdb->query("INSERT INTO appid_rule_relation (origin, clone) VALUES ('$rule_lid', '$lid');");

    return $lid;
}

function clone_nat_rule($initialPosition, $finalPosition, $vsys, $source, $rule_lid, $message, $project)
{

    global $projectdb;

    if( $initialPosition == "" )
    {
        $getPos = $projectdb->query("SELECT position FROM nat_rules WHERE id = '$rule_lid';");
        if( $getPos->num_rows == 1 )
        {
            $data = $getPos->fetch_assoc();
            $initialPosition = $data['position'];
        }
    }

    if( $finalPosition == "" )
    {
        $finalPosition = intval($initialPosition) + 1;
    }
    if( $finalPosition == "-1" )
    {
        $finalPosition = intval($initialPosition) - 1;
    }
    if( $message == "" )
    {
        $message = "Cl-";
    }
    elseif( $message == "Unk-" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source = '$source' AND vsys = '$vsys' AND name = 'Unknown Traffic';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup) VALUES ('Unknown Traffic', 'color1', 'Identify Unknown Traffic', '$source', '$vsys', '$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }
    elseif( $message == "App-Ovrr" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source = '$source' AND vsys = '$vsys' AND name = 'App Override';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup) VALUES ('App Override', 'color2', 'From Phase2. Application Override Rule assoc', '$source', '$vsys', '$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }
    elseif( $message == "Appid" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source = '$source' AND vsys = '$vsys' AND name = 'Appid Adoption';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup) VALUES ('Appid Adoption', 'color2', 'Appid Adoption by MT3', '$source', '$vsys', '$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }


    $update_lid = array();
    $clone_rule = array();

    //$getALL=$projectdb->query("SELECT position,id FROM security_rules WHERE source='$source'  AND vsys='$vsys' AND position > '$initialPosition';");
    $position = "";
    $newPosition = "";

    if( $initialPosition > $finalPosition )
    {
        $projectdb->query("UPDATE nat_rules SET position = position+1 WHERE position >= '$initialPosition';");
        $thePosition = $initialPosition + 1;
    }
    else
    {
        $projectdb->query("UPDATE nat_rules SET position = position+1 WHERE position >= '$finalPosition';");
        $thePosition = $initialPosition;
    }

    $getMaxLid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
    $getMax = $getMaxLid->fetch_assoc();
    $lid = intval($getMax['max']) + 1;
    $entity1 = $projectdb->query("SELECT * FROM nat_rules WHERE position = '$thePosition' AND source = '$source' AND vsys = '$vsys';");
    $entity = $entity1->fetch_assoc();
    $entity["id"] = $lid;
    $entity["lid"] = "";
    $name = $entity["name"];
    $entity["description"] = addslashes($entity["description"]);

    if( $name == "" )
    {
        $name = $lid;
    }
    $thename = truncate_rulenames($message . $name);
    $entity["name"] = $thename;

    if( $initialPosition > $finalPosition )
    {
        $entity["position"] = $initialPosition;
    }
    else
    {
        $entity["position"] = $finalPosition;
    }

    $projectdb->query("INSERT INTO nat_rules (" . implode(", ", array_keys($entity)) . ") VALUES ('" . implode("', '", array_values($entity)) . "')");
    //echo "Dentro del clone: INSERT INTO nat_rules (" . implode(", ", array_keys($entity)) . ") VALUES ('" . implode("', '", array_values($entity)) . "')\n";

    #Start Clone the rest of the rules adr, src, to, from, srv, APP

    $getDST = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup FROM nat_rules_dst WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO nat_rules_dst (id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getSRC = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup FROM nat_rules_src WHERE rule_lid = '$rule_lid';");
    if( $getSRC->num_rows > 0 )
    {
        $rules = array();
        while( $SRC = $getSRC->fetch_assoc() )
        {
            $SRC["id"] = "";
            $SRC["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($SRC)) . "')";
        }
        $projectdb->query("INSERT INTO nat_rules_src (id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id, source, vsys, name, rule_lid, devicegroup FROM nat_rules_from WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO nat_rules_from (id, source, vsys, name, rule_lid, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, devicegroup FROM nat_rules_tag WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO nat_rules_tag (id, source, rule_lid, member_lid, table_name, vsys, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, devicegroup FROM nat_rules_translated_address WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO nat_rules_translated_address (id, source, rule_lid, member_lid, table_name, vsys, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, devicegroup FROM nat_rules_translated_address_fallback WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO nat_rules_translated_address_fallback (id, source, rule_lid, member_lid, table_name, vsys, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    if( $message == "Unk-" )
    {
        $dup = $projectdb->query("SELECT id FROM nat_rules_tag WHERE rule_lid = '$lid' AND table_name = '$tagTable' AND member_lid = '$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO nat_rules_tag (source, table_name, member_lid, rule_lid, vsys, devicegroup) VALUES ('$source', '$tagTable', '$tagId', '$lid', '$vsys', '$project');");
        }
    }
    elseif( $message == "App-Ovrr" )
    {
        $dup = $projectdb->query("SELECT id FROM nat_rules_tag WHERE rule_lid = '$lid' AND table_name = '$tagTable' AND member_lid = '$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO nat_rules_tag (source, table_name, member_lid, rule_lid, vsys, devicegroup) VALUES ('$source', '$tagTable', '$tagId', '$lid', '$vsys', '$project');");
        }
    }
    elseif( $message == "Appid" )
    {
        $dup = $projectdb->query("SELECT id FROM nat_rules_tag WHERE rule_lid = '$lid' AND table_name = '$tagTable' AND member_lid = '$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO nat_rules_tag (source, table_name, member_lid, rule_lid, vsys, devicegroup) VALUES ('$source', '$tagTable', '$tagId', '$lid', '$vsys', '$project');");
        }
    }
    add_log('ok', 'NAT Rule Cloned', 'RuleID [' . $rule_lid . '] has been cloned in new RuleID [' . $lid . ']', $source, 'No Action Required');
    return $lid;
}

function clone_appoverride_rule($initialPosition, $finalPosition, $vsys, $source, $rule_lid, $message, $project)
{

    global $projectdb;

    if( $initialPosition == "" )
    {
        $getPos = $projectdb->query("SELECT position FROM appoverride_rules WHERE id = '$rule_lid';");
        if( $getPos->num_rows == 1 )
        {
            $data = $getPos->fetch_assoc();
            $initialPosition = $data['position'];
        }
    }

    if( $finalPosition == "" )
    {
        $finalPosition = intval($initialPosition) + 1;
    }
    if( $finalPosition == "-1" )
    {
        $finalPosition = intval($initialPosition) - 1;
    }
    if( $message == "" )
    {
        $message = "Cl-";
    }
    elseif( $message == "Unk-" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source = '$source' AND vsys = '$vsys' AND name = 'Unknown Traffic';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup) VALUES ('Unknown Traffic', 'color1', 'Identify Unknown Traffic', '$source', '$vsys', '$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }
    elseif( $message == "App-Ovrr" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source = '$source' AND vsys = '$vsys' AND name = 'App Override';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup) VALUES ('App Override', 'color2', 'From Phase2. Application Override Rule assoc', '$source', '$vsys', '$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }
    elseif( $message == "Appid" )
    {
        $getTag = $projectdb->query("SELECT id FROM tag WHERE source = '$source' AND vsys = '$vsys' AND name = 'Appid Adoption';");
        if( $getTag->num_rows == 1 )
        {
            $data = $getTag->fetch_assoc();
            $tagId = $data['id'];
            $tagTable = "tag";
        }
        else
        {
            $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup) VALUES ('Appid Adoption', 'color2', 'Appid Adoption by MT3', '$source', '$vsys', '$project');");
            $tagId = $projectdb->insert_id;
            $tagTable = "tag";
        }
    }

    $update_lid = array();
    $clone_rule = array();

    if( $initialPosition > $finalPosition )
    {
        $projectdb->query("UPDATE appoverride_rules SET position = position+1 WHERE position >= '$initialPosition';");
        $thePosition = $initialPosition + 1;
    }
    else
    {
        $projectdb->query("UPDATE appoverride_rules SET position = position+1 WHERE position >= '$finalPosition';");
        $thePosition = $initialPosition;
    }

    $getMaxLid = $projectdb->query("SELECT max(id) as max FROM appoverride_rules;");
    $getMax = $getMaxLid->fetch_assoc();
    $lid = intval($getMax['max']) + 1;
    $entity1 = $projectdb->query("SELECT * FROM appoverride_rules WHERE position = '$thePosition' AND source = '$source' AND vsys = '$vsys';");
    $entity = $entity1->fetch_assoc();
    $entity["id"] = $lid;
    //$entity["lid"] = "";
    $name = $entity["name"];
    $entity["description"] = addslashes($entity["description"]);
    if( $name == "" )
    {
        $name = $lid;
    }
    $thename = truncate_rulenames($message . $name);
    $entity["name"] = $thename;

    if( $initialPosition > $finalPosition )
    {
        $entity["position"] = $initialPosition;
    }
    else
    {
        $entity["position"] = $finalPosition;
    }

    $projectdb->query("INSERT INTO appoverride_rules (" . implode(", ", array_keys($entity)) . ") VALUES ('" . implode("', '", array_values($entity)) . "')");
    //echo "INSERT INTO appoverride_rules (" . implode(", ", array_keys($entity)) . ") VALUES ('" . implode("', '", array_values($entity)) . "')";

    #Start Clone the rest of the rules adr, src, to, from, srv, APP

    $getDST = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup FROM appoverride_rules_dst WHERE rule_lid = '$rule_lid';");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO appoverride_rules_dst (id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getSRC = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup FROM appoverride_rules_src WHERE rule_lid = '$rule_lid';");
    if( $getSRC->num_rows > 0 )
    {
        $rules = array();
        while( $SRC = $getSRC->fetch_assoc() )
        {
            $SRC["id"] = "";
            $SRC["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($SRC)) . "')";
        }
        $projectdb->query("INSERT INTO appoverride_rules_src (id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id, source, vsys, name, rule_lid, devicegroup FROM appoverride_rules_from WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO appoverride_rules_from (id, source, vsys, name, rule_lid, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id, source, vsys, name, rule_lid, devicegroup FROM appoverride_rules_to WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO appoverride_rules_to (id, source, vsys, name, rule_lid, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    $getDST = $projectdb->query("SELECT id, source, rule_lid, member_lid, table_name, vsys, devicegroup FROM appoverride_rules_tag WHERE rule_lid = '$rule_lid' ;");
    if( $getDST->num_rows > 0 )
    {
        $rules = array();
        while( $DST = $getDST->fetch_assoc() )
        {
            $DST["id"] = "";
            $DST["rule_lid"] = "$lid";
            $rules[] = "('" . implode("', '", array_values($DST)) . "')";
        }
        $projectdb->query("INSERT INTO appoverride_rules_tag (id, source, rule_lid, member_lid, table_name, vsys, devicegroup) VALUES " . implode(",", $rules) . ";");
    }

    if( $message == "Unk-" )
    {
        $dup = $projectdb->query("SELECT id FROM appoverride_rules_tag WHERE rule_lid = '$lid' AND table_name = '$tagTable' AND member_lid = '$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO appoverride_rules_tag (source, table_name, member_lid, rule_lid, vsys, devicegroup) VALUES ('$source', '$tagTable', '$tagId', '$lid', '$vsys', '$project');");
        }
    }
    elseif( $message == "App-Ovrr" )
    {
        $dup = $projectdb->query("SELECT id FROM appoverride_rules_tag WHERE rule_lid = '$lid' AND table_name = '$tagTable' AND member_lid = '$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO appoverride_rules_tag (source, table_name, member_lid, rule_lid, vsys, devicegroup) VALUES ('$source', '$tagTable', '$tagId', '$lid', '$vsys', '$project');");
        }
    }
    elseif( $message == "Appid" )
    {
        $dup = $projectdb->query("SELECT id FROM appoverride_rules_tag WHERE rule_lid = '$lid' AND table_name = '$tagTable' AND member_lid = '$tagId' ");
        if( $dup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO appoverride_rules_tag (source, table_name, member_lid, rule_lid, vsys, devicegroup) VALUES ('$source', '$tagTable', '$tagId', '$lid', '$vsys', '$project');");
        }
    }
    add_log('ok', 'Application Override Rule Cloned', 'RuleID [' . $rule_lid . '] has been cloned in new RuleID [' . $lid . ']', $source, 'No Action Required');
    return $lid;
}


function delete_appoverride_rule($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM appoverride_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM appoverride_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM appoverride_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM appoverride_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM appoverride_rules_to WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM appoverride_rules WHERE id IN ($rule_lid);");
}

function delete_address_group($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM address_groups WHERE lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM address_groups_id WHERE id IN ($rule_lid);");
}

function delete_service_group($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM services_groups WHERE lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM services_groups_id WHERE id IN ($rule_lid);");
}

function delete_application_group($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM applications_groups WHERE lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM applications_groups_id WHERE id IN ($rule_lid);");
}

function delete_decryption_rule($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM decryption_rules_categories WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules_srv WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules_to WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules_usr WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM decryption_rules WHERE id IN ($rule_lid);");
}

function delete_qos_rule($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM qos_rules_app WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_categories WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_srv WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_to WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules_usr WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM qos_rules WHERE id IN ($rule_lid);");
}

function delete_pbf_rule($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM pbf_rules_app WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules_nal WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules_srv WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules_usr WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM pbf_rules WHERE id IN ($rule_lid);");
}

function delete_tunnel_inspect_rules($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM tunnel_inspect_rules_app WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_target WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_to WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_usr WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM tunnel_inspect_rules WHERE id IN ($rule_lid);");
}

function delete_authentication_rules($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM authentication_rules_categories WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_hip WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_srv WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_target WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_to WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules_usr WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM authentication_rules WHERE id IN ($rule_lid);");
}

function delete_captiveportal_rules($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM captiveportal_rules_categories WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules_srv WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules_target WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules_to WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM captiveportal_rules WHERE id IN ($rule_lid);");
}

function delete_security_rule($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM security_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_categories WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_hip WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM security_rules_target WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM split_rules_unknown WHERE source='$source'");
    $projectdb->query("DELETE FROM security_rules WHERE id IN ($rule_lid) ;");
    #Clean LOGS
    $projectdb->query("DELETE FROM logs WHERE obj_id IN ($rule_lid) AND obj_table='security_rules';");
}

function delete_nat_rule($vsys, $source, $rule_lid)
{
    global $projectdb;
    $projectdb->query("DELETE FROM nat_rules_tag WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM nat_rules_dst WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM nat_rules_from WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM nat_rules_src WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM nat_rules_translated_address WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM nat_rules_translated_address_fallback WHERE rule_lid IN ($rule_lid);");
    $projectdb->query("DELETE FROM nat_rules WHERE id IN ($rule_lid);");
    #Clean LOGS
    $projectdb->query("DELETE FROM logs WHERE obj_id IN ($rule_lid) AND obj_table='nat_rules';");
}


# Match IPv4  cidr_match("1.2.3.4", "0.0.0.0/0"): true
function cidr_match($ip, $cidr)
{
    $list = explode('/', $cidr);
    $subnet = $list[0];
    $mask = $list[1];
    if( (ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet) )
    {
        return TRUE;
    }

    return FALSE;
}

function mask2cidrv4($mask)
{
    $long = ip2long($mask);
    $base = ip2long('255.255.255.255');
    return 32 - log(($long ^ $base) + 1, 2);
}

//#Backups
////MT-306: Encrypt backup taken from triggered change
//function take_snapshot_last($project) {
//    global $app;
//    //$file = USERSPACE_PATH."/projects/$project/Backups/last_saved_MT_".date("Y-m-d_H-i-s").".sql";
//    $projectObj = $app->project->where("name",$project)->first();
//    $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();
//    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);
//
//    $file = USERSPACE_PATH."/projects/$project/Backups/last_saved_MT_.sql";
//    $Command = "mysqldump -u ".DBUser." -p".DBPass." $project > ".$file;
//    exec($Command);
//
//    $encryptor->encryptFiletoFile($file, "$file.dat");
//    unlink($file);
//}

# AppID Adoption
function export_apps_form_log($project)
{
    //global $DBUser;
    //global $DBPass;
    //global $DBServer;
    $outsql = USERSPACE_PATH . "/projects/$project/MT-appid_adoption.sql";
    $Command = "mysqldump -u " . DBUser . " -p" . DBPass . " $project applications_from_log > $outsql";
    exec($Command);
    if( file_exists($outsql) )
    {
        $zip = new ZipArchive();
        $filename = USERSPACE_PATH . "/projects/$project/MT-appid_adoption.zip";
        if( $zip->open($filename, ZipArchive::CREATE) !== TRUE )
        {
            exit("cannot open <$filename>\n");
        }
        $zip->addFile($outsql, "/MT-appid_adoption.sql");
        $zip->close();
        unlink($outsql);
    }
}


function getMatchingSecurityIds($ruleids, $source, $vsyse, $project, $preorpost, $filter, $vsys, $start = '', $limit = '')
{

    global $projectdb;
    $ruleidsInFilters = array();

    $query = generate_query("policies", $vsyse, $preorpost);
    //echo "$vsyse:  ";

    if( ($start == "") and ($limit == "") )
    {
        $theLimit = "";
    }
    else
    {
        $theLimit = " LIMIT $start, $limit";
    }

    $params = array();

    if( ($filter != "none") && ($filter != "0") )
    {

        $params['tools_where_columns_id'] = $filter;
        $params['tools_operator_id'] = "contains";
        $params['search'] = "";
        $params['tools_where_id'] = "2";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";
        $params['source'] = $source;
        $params['vsys'] = $vsys;
        $params['case_sensitive'] = "0";

        setFilter($project, $params);
        executeSQL($project, $params);

    }
    elseif( ($filter == "none") || ($filter == "0") )
    {
    }

    $query = generateQueryConsolidation($project, "security_rules", $query, $source);

    list($query, $orderby) = generateQueryFilters($project, "security_rules", "", $query, $source);

    $order = " ORDER BY source,vsys,preorpost,position ASC ";
    $sec_query = "SELECT id FROM security_rules $query $order $theLimit;";
    //echo $sec_query.PHP_EOL;
    $result = $projectdb->query($sec_query);
    //echo $sec_query;
    $listOfIds = array();
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $listOfIds[] = $data['id'];
        }
    }

    return $listOfIds;
}


function getIconMemory(&$objectsInMemory = null)
{

    global $projectdb;

    #Calculate for Address
    if( isset($objectsInMemory["address"]) )
    {
        foreach( $objectsInMemory["address"] as $objid => &$obj )
        {
            $vtype = $obj['vtype'];
            $type = $obj['type'];
            $ipaddress = $obj['ipaddress'];
            $cidr = $obj['cidr'];
            if( $vtype == "" )
            {
                if( $type == "ip-netmask" )
                {
                    $obj['icon'] = "fa fa-desktop";
                    $obj['myip'] = $ipaddress . "-" . $cidr;
                }
                elseif( $type == "ip-range" )
                {
                    $obj['icon'] = "fa fa-sitemap";
                    $obj['myip'] = $ipaddress;
                }
                elseif( $type == "fqdn" )
                {
                    $obj['icon'] = "fa fa-book";
                    $obj['myip'] = $ipaddress;
                }
                else
                {
                    $obj['icon'] = "fa fa-desktop";
                    $obj['myip'] = $ipaddress;
                }
            }
            else
            {
                if( ($vtype == "gateway_cluster") or ($vtype == "cluster_member") or ($vtype == "gateway_fw") or ($vtype == "gateway") )
                {
                    $obj['icon'] = "checkpointp.png";
                    $obj['myip'] = $ipaddress . "-" . $cidr;
                }
                elseif( $vtype == "ip-range" )
                {
                    $obj['icon'] = "fa fa-sitemap";
                    $obj['myip'] = $ipaddress;
                }
                elseif( $vtype == "dummy" )
                {
                    $obj['icon'] = "fa fa-at";
                    $obj['myip'] = "IP_address";
                }
                else
                {
                    $obj['icon'] = "fa fa-desktop";
                    $obj['myip'] = $ipaddress . "-" . $cidr;
                }
            }
        }
    }

    if( isset($objectsInMemory["address_groups_id"]) )
    {
        foreach( $objectsInMemory["address_groups_id"] as $objid => &$obj )
        {
            $type = $obj['type'];
            $filter = $obj['filter'];
            if( $type == "dynamic" )
            {
                $obj['icon'] = "fa fa-object-group";
                $obj['myip'] = $filter;
            }
            else
            {
                $obj['icon'] = "fa fa-object-ungroup";
                $obj['myip'] = "Static Group";
            }
        }
    }


    if( isset($objectsInMemory["default_regions"]) )
    {
        foreach( $objectsInMemory["default_regions"] as $objid => &$obj )
        {
            $name = $obj['name'];
            if( !preg_match("/-/", $name) )
            {
                $obj['icon'] = "../flags/$name.gif";
                $obj['myip'] = "Default Region";
            }
            else
            {
                $obj['icon'] = "fa fa-globe";
                $obj['myip'] = "Default Region";
            }
        }
    }

    if( isset($objectsInMemory["regions"]) )
    {
        foreach( $objectsInMemory["regions"] as $objid => &$obj )
        {
            $obj['icon'] = "fa fa-globe";
            $obj['myip'] = "Custom Region";
        }
    }

    if( isset($objectsInMemory["external_list"]) )
    {
        foreach( $objectsInMemory["external_list"] as $objid => &$obj )
        {
            $obj['icon'] = "fa fa-list";
            $obj['myip'] = "External List";
        }
    }

    if( isset($objectsInMemory["services"]) )
    {
        foreach( $objectsInMemory["services"] as $objid => &$obj )
        {
            $name = $obj['name'];
            $vtype = $obj['vtype'];
            $protocol = $obj['protocol'];
            $sport = $obj['sport'];
            $dport = $obj['dport'];
            if( $vtype == "dummy" )
            {
                $obj['icon'] = "pan16.gif";
                $obj['myip'] = "dummy";
            }
            else
            {
                $obj['icon'] = "fa fa-cog";
                if( ($name == "application-default") or ($name == "service-http") or ($name == "service-https") )
                {
                    $obj['myip'] = "default application";
                }
                else
                {
                    $obj['myip'] = "$protocol:[$sport]-[$dport]";
                }
            }
        }
    }

    if( isset($objectsInMemory["services_groups_id"]) )
    {
        foreach( $objectsInMemory["services_groups_id"] as $objid => &$obj )
        {
            $obj['icon'] = "fa fa-cogs";
            $obj['myip'] = "Group";
        }
    }

    if( isset($objectsInMemory["default_applications"]) )
    {
        foreach( $objectsInMemory["default_applications"] as $objid => &$obj )
        {
            $obj['icon'] = "fa fa-list-alt";
            $obj['myip'] = "Default Application";
        }
    }

    if( isset($objectsInMemory["applications"]) )
    {
        foreach( $objectsInMemory["applications"] as $objid => &$obj )
        {
            $vtype = $obj['vtype'];
            if( $vtype == "dummy" )
            {
                $obj['icon'] = "pan16.gif";
                $obj['myip'] = "dummy";
            }
            else
            {
                $obj['icon'] = "fa fa-list-alt";
                $obj['myip'] = "Custom Application";
            }
        }
    }

    if( isset($objectsInMemory["applications_groups_id"]) )
    {
        foreach( $objectsInMemory["applications_groups_id"] as $objid => &$obj )
        {
            $obj['icon'] = "fa fa-object-ungroup";
            $obj['myip'] = "Group";
        }
    }

    if( isset($objectsInMemory["applications_filters"]) )
    {
        foreach( $objectsInMemory["applications_filters"] as $objid => &$obj )
        {
            $obj['icon'] = "fa fa-filter";
            $obj['myip'] = "Filter";
        }
    }

    if( isset($objectsInMemory["profiles"]) )
    {
        foreach( $objectsInMemory["profiles"] as $objid => &$obj )
        {
            $type = $obj['type'];
            $vsys_ = $obj['vsys'];
            $image_prefix = ($vsys_ == 'shared') ? 'shared_' : '';
            switch ($type)
            {
                case 'hip':
                    if( $obj['vsys'] != "shared" )
                    {
                        $obj['icon'] = "global-protect.png";
                    }
                    else
                    {
                        $obj['icon'] = "shared_global-protect.gif";
                    }
                    break;
                case 'virus':
                    $obj['icon'] = $image_prefix . "virus.gif";
                    break;
                case 'spyware':
                    $obj['icon'] = $image_prefix . "spyware.gif";
                    break;
                case 'url-filtering':
                    $obj['icon'] = $image_prefix . "url_filter.gif";
                    break;
                case 'file-blocking':
                    $obj['icon'] = $image_prefix . "url_filter.gif";
                    break;
                case 'data-filtering':
                    $obj['icon'] = $image_prefix . "dlp_data_filter.gif";
                    break;
                case 'vulnerability':
                    $obj['icon'] = $image_prefix . "vulnerability.gif";
                    break;
                case 'wildfire-analysis':
                    $obj['icon'] = $image_prefix . "wildfire_analysis.gif";
                    break;
                default:
                    $obj['icon'] = "global-protect.png";
                    break;
            }
        }
    }

    if( isset($objectsInMemory["profiles_groups"]) )
    {
        foreach( $objectsInMemory["profiles_groups"] as $objid => &$obj )
        {
            $obj['icon'] = "profile_group.gif";
            $obj['myip'] = "Group";
        }
    }
//    return $objectsInMemory;
}

function search_security_policies($ruleids, $source, $vsys, $project, $preorpost, $start, $limit, $color, $level, $label, $objectsInMemory = null)
{
    global $projectdb;

    $ruleids2 = implode(",", $ruleids);
    $sec_query = "SELECT * FROM security_rules WHERE id IN ($ruleids2) ORDER BY position;";
    $getLimit = $projectdb->query($sec_query);


    $rule = array();

    if( $getLimit->num_rows == 0 )
    {
        $result = [
            "total" => 0,
            "security" => null
        ];
    }
    else
    {
        if( !is_array($objectsInMemory) && $objectsInMemory == null )
        {
            while( $row = $getLimit->fetch_assoc() )
            {
                $position = $row['position'];
                $rulename = $row['name'];
                $negate_source = $row['negate_source'];
                $negate_destination = $row['negate_destination'];
                $description = $row['description'];
                $action = $row['action'];
                $schedule = $row['schedule'];
                $disabled = $row['disabled'];
                $log_start = $row['log_start'];
                $log_end = $row['log_end'];
                $log_forwarding = $row['log_forwarding'];
                $vsys = $row['vsys'];
                $lid = $row['id'];
                $source = $row['source'];
                $dsri = $row['dsri'];
                $chk_target = $row['target'];
                $target_negate = $row['target_negate'];
                $checkit = $row['checkit'];
                $migrate = $row['migrate'];
                $qos = $row['qos'];
                $qos_value = $row['qos_value'];
                $counter = $row['counter'];
                $profile_type = $row['profile_type'];
                $profile_group = $row['profile_group'];
                $preorpost = $row['preorpost'];
                $devicegroup = $row['devicegroup'];
                $id = $row['id'];
                $blocked = $row['blocked'];
                $rule_type = $row['rule_type'];
                $target_negate = $row['target_negate'];
                if( $log_end == "1" )
                {
                    $log_end = "on";
                }
                else
                {
                    $log_end = "off";
                }
                if( $log_start == "1" )
                {
                    $log_start = "on";
                }
                else
                {
                    $log_start = "off";
                }

                $searchTarget = $projectdb->query("SELECT name,device_vsys FROM security_rules_target WHERE rule_lid='$lid'");
                if( $searchTarget->num_rows > 0 )
                {
                    $targetArray = array();
                    while( $Tags = $searchTarget->fetch_assoc() )
                    {
                        if( $Tags['device_vsys'] != null )
                        {
                            $targetArray[] = "<img valign=middle src=/resources/images/icons/device.gif>&nbsp;" . $Tags['name'] . '/' . $Tags['device_vsys'];
                        }
                        else
                        {
                            $targetArray[] = "<img valign=middle src=/resources/images/icons/device.gif>&nbsp;" . $Tags['name'];
                        }

                    }
                    $TargetOK = implode(",", $targetArray);
                }
                else
                {
                    $TargetOK = "Any";
                }

                $searchUsers = $projectdb->query("SELECT name, rule_lid FROM security_rules_usr WHERE rule_lid in ($ruleids2)");
                if( $searchUsers->num_rows > 0 )
                {
                    $i = 1;
                    $User = array();
                    while( $Tags = $searchUsers->fetch_assoc() )
                    {
                        //$rules[$Tags['rule_lid']]['usr'][] = $Tags['name'];
                        //$User[] = $Tags['name'];
                        $name_original = $Tags['name'];
                        $name = addslashes($Tags['name']);
                        $isGroup = $projectdb->query("SELECT name FROM userid_group WHERE name = '$name' OR short_name = '$name';");
                        if( $isGroup->num_rows > 0 )
                        {
                            $image = 'user-groups.png';
                        }
                        else
                        {
                            $image = 'userp.png';
                        }
                        $i++;
                        $User[] = array('img' => $image, 'name' => $name_original);
                    }
                    if( $i > 10 )
                    {
                        //$User[] = "more...";
                        $User[] = array('img' => 'more.png', 'name' => 'more...');
                    }
                    $UserOK = $User;
                }
                else
                {
                    $UserOK = "any";
                }

                $searchTag = $projectdb->query("SELECT tag.id as id,tag.name as name, tag.color as color FROM security_rules_tag srt, tag WHERE srt.rule_lid=$lid AND tag.id=srt.member_lid;");
                if( $searchTag->num_rows > 0 )
                {
                    $Tag = array();
                    while( $Ttag = $searchTag->fetch_assoc() )
                    {
                        $TagName = $Ttag['name'];
                        $TagColor = $Ttag['color'];
                        $tagid = $Ttag['id'];
                        if( $TagColor == "color1" )
                        {
                            $TagColor = "#CD383F";
                        }
                        elseif( $TagColor == "color2" )
                        {
                            $TagColor = "#72A392";
                        }
                        elseif( $TagColor == "color3" )
                        {
                            $TagColor = "#569BBD";
                        }
                        elseif( $TagColor == "color4" )
                        {
                            $TagColor = "#EBD722";
                        }
                        elseif( $TagColor == "color5" )
                        {
                            $TagColor = "#C27D2A";
                        }
                        elseif( $TagColor == "color6" )
                        {
                            $TagColor = "#FF6A00";
                        }
                        elseif( $TagColor == "color7" )
                        {
                            $TagColor = "#7D3953";
                        }
                        elseif( $TagColor == "color8" )
                        {
                            $TagColor = "#5B6F7B";
                        }
                        elseif( $TagColor == "color9" )
                        {
                            $TagColor = "#C9D6A6";
                        }
                        elseif( $TagColor == "color10" )
                        {
                            $TagColor = "#8AD3DF";
                        }
                        elseif( $TagColor == "color11" )
                        {
                            $TagColor = "#C2D1D3";
                        }
                        elseif( $TagColor == "color12" )
                        {
                            $TagColor = "#80A1B6";
                        }
                        elseif( $TagColor == "color13" )
                        {
                            $TagColor = "#C1D72F";
                        }
                        elseif( $TagColor == "color14" )
                        {
                            $TagColor = "#000000";
                        }
                        elseif( $TagColor == "color15" )
                        {
                            $TagColor = "#FFC425";
                        }
                        elseif( $TagColor == "color16" )
                        {
                            $TagColor = "#918A75";
                        }
                        else
                        {
                            $TagColor = "";
                        }
                        $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                        $Tag[] = $thenewtagcolor;
                    }
                    $TagOK = $Tag;
                }
                else
                {
                    $TagOK = "none";
                }

                $searchZoneSrc = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$lid'");
                if( $searchZoneSrc->num_rows > 0 )
                {
                    $From = array();
                    while( $Tags = $searchZoneSrc->fetch_assoc() )
                    {
                        $From[] = $Tags['name'];
                    }
                    $FromOK = implode(",", $From);
                }
                else
                {
                    $FromOK = "Any";
                }

                $searchCategories = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid='$lid'");
                if( $searchCategories->num_rows > 0 )
                {
                    $Category = array();
                    while( $Tags = $searchCategories->fetch_assoc() )
                    {
                        $Category[] = $Tags['name'];
                    }
                    $categoryOK = implode(",", $Category);
                }
                else
                {
                    $categoryOK = "Any";
                }

                $searchZoneSrc = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$lid'");
                if( $searchZoneSrc->num_rows > 0 )
                {
                    $To = array();
                    while( $Tags = $searchZoneSrc->fetch_assoc() )
                    {
                        $To[] = $Tags['name'];
                    }
                    $ToOK = implode(",", $To);
                }
                else
                {
                    $ToOK = "Any";
                }

                $getServices = $projectdb->query("SELECT table_name,member_lid FROM security_rules_srv WHERE rule_lid='$lid' LIMIT 10");
                if( $getServices->num_rows > 0 )
                {
                    $Service = array();
                    while( $srv = $getServices->fetch_assoc() )
                    {
                        $srv_table_name = $srv['table_name'];
                        $srv_member_lid = $srv['member_lid'];
                        $name = "";

                        list($image, $vsys_member, $name, $myip) = getIcon("services", $srv_table_name, $srv_member_lid, "");

                        if( $name != "" )
                        {
                            $Service[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member);
                            $name = "";
                        }
                    }
                    if( $getServices->num_rows == 10 )
                    {
                        $Service[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '');
                    }
                    $serviceOK = $Service;
                }
                else
                {
                    $serviceOK = "any";
                }

                $getSource = $projectdb->query("SELECT table_name,member_lid FROM security_rules_src WHERE rule_lid='$lid' LIMIT 10");
                if( $getSource->num_rows > 0 )
                {
                    $Source = array();
                    while( $src = $getSource->fetch_assoc() )
                    {
                        $src_table_name = $src['table_name'];
                        $src_member_lid = $src['member_lid'];

                        list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                        $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
                    }
                    if( $getSource->num_rows == 10 )
                    {
                        $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
                    }
                    $SourceOK = $Source;
                }
                else
                {
                    $SourceOK = "any";
                }

                $getSource = $projectdb->query("SELECT table_name,member_lid FROM security_rules_dst WHERE rule_lid='$lid' LIMIT 10");
                if( $getSource->num_rows > 0 )
                {
                    $Destination = array();
                    while( $src = $getSource->fetch_assoc() )
                    {
                        $src_table_name = $src['table_name'];
                        $src_member_lid = $src['member_lid'];

                        list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                        $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
                    }
                    if( $getSource->num_rows == 10 )
                    {
                        $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
                    }
                    $DestinationOK = $Destination;
                }
                else
                {
                    $DestinationOK = "any";
                }

                $getApplications = $projectdb->query("SELECT table_name,member_lid FROM security_rules_app WHERE rule_lid='$lid' LIMIT 10");
                if( $getApplications->num_rows > 0 )
                {
                    $Application = array();
                    while( $srv = $getApplications->fetch_assoc() )
                    {
                        $srv_table_name = $srv['table_name'];
                        $srv_member_lid = $srv['member_lid'];

                        list($image, $vsys_member, $name, $myip) = getIcon("applications", $srv_table_name, $srv_member_lid, "");

                        $Application[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $srv_table_name);
                    }
                    if( $getApplications->num_rows == 10 )
                    {
                        $Application[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
                    }
                    $applicationOK = $Application;
                }
                else
                {
                    $applicationOK = "any";
                }

                $getHIP = $projectdb->query("SELECT table_name,member_lid,name FROM security_rules_hip WHERE rule_lid='$lid' LIMIT 10");
                if( $getHIP->num_rows > 0 )
                {
                    $Application = array();
                    while( $srv = $getHIP->fetch_assoc() )
                    {
                        $srv_table_name = $srv['table_name'];
                        $srv_member_lid = $srv['member_lid'];
                        if( $srv['name'] == "no-hip" )
                        {
                            $name = "no-hip";
                            $image = "shared_global-protect.gif";
                            $myip = "no-hip";
                        }
                        else
                        {
                            if( $srv_table_name == "profiles" )
                            {
                                $getSRV = $projectdb->query("SELECT name, vsys FROM profiles WHERE id='$srv_member_lid';");
                                $dataSRV = $getSRV->fetch_assoc();
                                $name = $dataSRV['name'];
                                $vsys_ = $dataSRV['vsys'];
                                $image_prefix = ($vsys_ == 'shared') ? 'shared_' : '';
                                $image = $image_prefix . "global-protect.png";
                                $myip = $dataSRV['name'];
                            }
                        }
                        $Application[] = array('img' => $image, 'name' => $name, 'ip' => $myip);
                    }
                    if( $getApplications->num_rows == 10 )
                    {
                        $Application[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none');
                    }
                    $hipOK = $Application;
                }
                else
                {
                    $hipOK = "any";
                }

                #Apps from LOGS
                //$getApplications = $projectdb->query("SELECT app,dport,bytes,packets,source,proto FROM applications_from_log WHERE rule_lid='$lid' ORDER BY bytes DESC LIMIT 10");
                $getApplications = $projectdb->query("SELECT app,dport,bytes,packets,source,proto FROM applications_from_log WHERE rule_lid='$lid' GROUP BY app ORDER BY bytes DESC LIMIT 10");

                if( $getApplications->num_rows > 0 )
                {
                    $Application = array();
                    while( $srv = $getApplications->fetch_assoc() )
                    {
                        $app = $srv['app'];
                        $dport = $srv['dport'];
                        $bytes = $srv['bytes'];
                        $packets = $srv['packets'];
                        $proto = $srv['proto'];
                        $image = "applications.gif";
                        $Application[] = array('img' => $image, 'app' => $app, 'dport' => $dport, 'bytes' => $bytes, 'packets' => $packets, 'proto' => $proto);
                    }
                    if( $getApplications->num_rows == 10 )
                    {
                        $Application[] = array('img' => 'more.png', 'app' => 'more...', 'dport' => '0', 'bytes' => '0', 'packets' => '0', 'proto' => '0');
                    }
                    $applicationfromlogOK = $Application;
                }
                else
                {
                    $applicationfromlogOK = "any";
                }

                #Users from LOGS
                $getUsersID = $projectdb->query("SELECT name, bytes, sessions, source FROM userid_from_log WHERE rule_lid = '$lid' GROUP BY name ORDER BY bytes DESC LIMIT 10");

                if( $getUsersID->num_rows > 0 )
                {
                    $UsersID = array();
                    while( $dataUI = $getUsersID->fetch_assoc() )
                    {
                        $name = $dataUI['name'];
                        $sessions = $dataUI['sessions'];
                        $bytes = $dataUI['bytes'];
                        $image = "userp.gif";
                        $UsersID[] = array('img' => $image, 'name' => $name, 'bytes' => $bytes, 'sessions' => $sessions);
                    }
                    if( $getUsersID->num_rows == 10 )
                    {
                        $UsersID[] = array('img' => 'more.png', 'name' => 'more...', 'bytes' => '0', 'sessions' => '0');
                    }
                    $useridfromlogOK = $UsersID;
                }
                else
                {
                    $useridfromlogOK = "any";
                }

                #Profiles
                $Profiles = array();
                if( $profile_type == "group" )
                {
                    $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                    if( $getProfiles->num_rows > 0 )
                    {
                        while( $k = $getProfiles->fetch_object() )
                        {
                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                            if( $getMember->num_rows > 0 )
                            {
                                while( $kk = $getMember->fetch_object() )
                                {
                                    $profileName = $kk->name;
                                    $image = "profile_group.gif";
                                    $Profiles[] = array('img' => $image, 'name' => $profileName);
                                }
                            }
                        }
                        $ProfilesOK = $Profiles;
                    }
                    else
                    {
                        $ProfilesOK = "";
                    }
                }
                elseif( $profile_type == "profiles" )
                {
                    $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                    if( $getProfiles->num_rows > 0 )
                    {
                        while( $k = $getProfiles->fetch_object() )
                        {
                            $getMember = $projectdb->query("SELECT name,type, vsys FROM $k->table_name WHERE id='$k->member_lid';");
                            if( $getMember->num_rows > 0 )
                            {
                                while( $kk = $getMember->fetch_object() )
                                {
                                    $vsys_ = $kk->{'vsys'};
                                    $image_prefix = ($vsys_ == 'shared') ? 'shared_' : '';
                                    $thetype = $kk->{'type'};
                                    if( $thetype == "virus" )
                                    {
                                        $image = $image_prefix . "virus.gif";
                                    }
                                    elseif( $thetype == "spyware" )
                                    {
                                        $image = $image_prefix . "spyware.gif";
                                    }
                                    elseif( $thetype == "url-filtering" )
                                    {
                                        $image = $image_prefix . "url_filter.gif";
                                    }
                                    elseif( $thetype == "file-blocking" )
                                    {
                                        $image = $image_prefix . "fileblocking.gif";
                                    }
                                    elseif( $thetype == "data-filtering" )
                                    {
                                        $image = $image_prefix . "dlp_data_filter.gif";
                                    }
                                    elseif( $thetype == "vulnerability" )
                                    {
                                        $image = $image_prefix . "vulnerability.gif";
                                    }
                                    elseif( $thetype == "wildfire-analysis" )
                                    {
                                        $image = $image_prefix . "wildfire_analysis.gif";
                                    }
                                    $Profiles[] = array('img' => $image, 'name' => $kk->name, 'type' => $thetype);
                                }
                            }
                            else
                            {
                                $getMember = $projectdb->query("SELECT name,type, vsys FROM $k->table_name WHERE source=0 AND id='$k->member_lid';");
                                if( $getMember->num_rows > 0 )
                                {
                                    while( $kk = $getMember->fetch_object() )
                                    {
                                        $vsys_ = $kk->{'vsys'};
                                        $image_prefix = ($vsys_ == 'shared') ? 'shared_' : '';
                                        $thetype = $kk->{'type'};
                                        if( $thetype == "virus" )
                                        {
                                            $image = $image_prefix . "virus.gif";
                                        }
                                        elseif( $thetype == "spyware" )
                                        {
                                            $image = $image_prefix . "spyware.gif";
                                        }
                                        elseif( $thetype == "url-filtering" )
                                        {
                                            $image = $image_prefix . "url_filter.gif";
                                        }
                                        elseif( $thetype == "file-blocking" )
                                        {
                                            $image = $image_prefix . "fileblocking.gif";
                                        }
                                        elseif( $thetype == "data-filtering" )
                                        {
                                            $image = $image_prefix . "dlp_data_filter.gif";
                                        }
                                        elseif( $thetype == "vulnerability" )
                                        {
                                            $image = $image_prefix . "vulnerability.gif";
                                        }
                                        $Profiles[] = array('img' => $image, 'name' => $kk->name, 'type' => $thetype);
                                    }
                                }
                            }
                        }
                        $ProfilesOK = $Profiles;
                    }
                    else
                    {
                        $ProfilesOK = "";
                    }
                }
                elseif( ($profile_type == "None") or ($profile_type == "") or ($profile_type == "none") )
                {
                    $Profiles = "";
                    $ProfilesOK = $Profiles;
                }

                #Docs From Algosec
                $getDocs = $projectdb->query("SELECT tag_id,tag_value FROM algosec_tags_values WHERE tag_mapping='$lid';");
                $doc_out = array();
                $algosec = "";
                if( $getDocs->num_rows > 0 )
                {
                    while( $mydocs = $getDocs->fetch_assoc() )
                    {
                        $tag_value = $mydocs['tag_value'];
                        $tag_id = $mydocs['tag_id'];
                        if( $tag_value != "" )
                        {
                            $getDoc = $projectdb->query("SELECT name FROM algosec_tags WHERE id='$tag_id';");
                            $mydoc = $getDoc->fetch_assoc();
                            $tag_name = $mydoc['name'];
                            $doc_out[] = "<b>" . $tag_name . "</b> - <b><font color=red>" . $tag_value . "</font></b>";
                        }
                    }
                }
                if( count($doc_out) > 0 )
                {
                    $algosec = $doc_out;
                }
                else
                {
                    $doc_out = "";
                    $algosec = $doc_out;
                }

                $warn = $projectdb->query("SELECT id FROM logs WHERE source='$source' AND fixed=0 AND obj_type='rules' AND obj_id='$lid' AND obj_table='security_rules';");
                if( $warn->num_rows > 0 )
                {
                    $warning = 1;
                }
                else
                {
                    $warning = 0;
                }

                $rule[] = [
                    "rule_type" => $rule_type,
                    "blocked" => $blocked,
                    "warning" => $warning,
                    "algosec" => $algosec,
                    "profile_type" => $profile_type,
                    "profile" => $ProfilesOK,
                    "hip_profile" => $hipOK,
                    "log_forwarding" => $log_forwarding,
                    "vsys" => $vsys,
                    "devicegroup" => $devicegroup,
                    "source" => $source,
                    "schedule" => $schedule,
                    "qos_value" => $qos_value,
                    "dsri" => $dsri,
                    "qos" => $qos,
                    "checkit" => $checkit,
                    "log_end" => $log_end,
                    "log_start" => $log_start,
                    "tag" => $TagOK,
                    "application" => $applicationOK,
                    "applicationfromlog" => $applicationfromlogOK,
                    "service" => $serviceOK,
                    "user" => $UserOK,
                    "useridfromlog" => $useridfromlogOK,
                    "src" => $SourceOK,
                    "dst" => $DestinationOK,
                    "from" => $FromOK,
                    "to" => $ToOK,
                    "url_category" => $categoryOK,
                    "id" => $id,
                    "lid" => $lid,
                    "name" => $rulename,
                    "position" => $position,
                    "action" => $action,
                    "disabled" => $disabled,
                    "description" => $description,
                    "preorpost" => $preorpost,
                    "negate_source" => $negate_source,
                    "negate_destination" => $negate_destination,
                    "preorpost" => $preorpost,
                    "color" => $color,
                    "groupby" => $level,
                    "label" => $label,
                    "target_negate" => $target_negate,
                    "chk_target" => $chk_target
                ];
            }
            $result = [
                "total" => count($rule),
                "security" => $rule
            ];
        }
        else
        {

            $rules = array();
            while( $row = $getLimit->fetch_assoc() )
            {
//                if ($objectsInMemory != null) {
                if( $row['log_end'] == "1" )
                {
                    $row['log_end'] = "on";
                }
                else
                {
                    $row['log_end'] = "off";
                }
                if( $row['log_start'] == "1" )
                {
                    $row['log_start'] = "on";
                }
                else
                {
                    $row['log_start'] = "off";
                }

                if( $row['schedule'] == "" )
                {
                    $row['schedule'] = "None";
                }
                $row['color'] = $color;
                $row['label'] = $label;
                $row['groupby'] = $level;
                //Default values
                $row["warning"] = 0;
                $row["chk_target"] = $row["target"];
                $row["target"] = "";
                $rules[$row['id']] = $row;
//                }
            }

            # Target
            $searchTarget = $projectdb->query("SELECT name,device_vsys,rule_lid FROM security_rules_target WHERE rule_lid IN ($ruleids2)");
            $processed = array();
            if( $searchTarget->num_rows > 0 )
            {
                $targetArray = array();
                while( $Tags = $searchTarget->fetch_assoc() )
                {
                    $processed[] = $Tags['rule_lid'];
                    if( $Tags['device_vsys'] != null )
                    {
                        $rules[$Tags['rule_lid']]["target"][] = "<img valign=middle src=/resources/images/icons/device.gif>&nbsp;" . $Tags['name'] . '/' . $Tags['device_vsys'];
                    }
                    else
                    {
                        $rules[$Tags['rule_lid']]["target"][] = "<img valign=middle src=/resources/images/icons/device.gif>&nbsp;" . $Tags['name'];
                    }
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['src'] = null;
            }

            # Warnings
            $warn = $projectdb->query("SELECT obj_id FROM logs WHERE fixed=0 AND obj_type='rules' AND obj_id in ($ruleids2) AND obj_table='security_rules';");
            if( $warn->num_rows > 0 )
            {
                while( $data = $warn->fetch_assoc() )
                {
                    $rules[$data['obj_id']]['warning'] = '1';
                }
            }

            # Read Security Rules SRC
            $getSource = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM security_rules_src WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $getSource->num_rows > 0 )
            {
                while( $src = $getSource->fetch_assoc() )
                {
                    $processed[] = $src['rule_lid'];
                    $addressObject = $objectsInMemory[$src['table_name']][$src['member_lid']];
                    $rules[$src['rule_lid']]["src"][] = array('img' => $addressObject['icon'], 'name' => $addressObject['name'], 'ip' => $addressObject['myip'], 'vsys_member' => $addressObject['vsys'], 'table_name' => $src['table_name']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['src'] = null;
            }

            # Read Security Rules DST
            $getSource = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM security_rules_dst WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $getSource->num_rows > 0 )
            {
                while( $src = $getSource->fetch_assoc() )
                {
                    $processed[] = $src['rule_lid'];
                    $addressObject = $objectsInMemory[$src['table_name']][$src['member_lid']];
                    $rules[$src['rule_lid']]["dst"][] = array('img' => $addressObject['icon'], 'name' => $addressObject['name'], 'ip' => $addressObject['myip'], 'vsys_member' => $addressObject['vsys'], 'table_name' => $src['table_name']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['dst'] = null;
            }

            # Read Security Rules FROM
            $searchZoneSrc = $projectdb->query("SELECT name,rule_lid FROM security_rules_from WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $searchZoneSrc->num_rows > 0 )
            {
                while( $Tags = $searchZoneSrc->fetch_assoc() )
                {
                    $processed[] = $Tags['rule_lid'];
                    $rules[$Tags['rule_lid']]["from"][] = $Tags['name'];
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['from'] = null;
            }

            # Read Security Rules TO
            $searchZoneSrc = $projectdb->query("SELECT name,rule_lid FROM security_rules_to WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $searchZoneSrc->num_rows > 0 )
            {
                while( $Tags = $searchZoneSrc->fetch_assoc() )
                {
                    $processed[] = $Tags['rule_lid'];
                    $rules[$Tags['rule_lid']]["to"][] = $Tags['name'];
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['to'] = null;
            }

            # Read the Users
            $searchUsers = $projectdb->query("SELECT name, rule_lid FROM security_rules_usr WHERE rule_lid in ($ruleids2)");
            $processed = array();
            if( $searchUsers->num_rows > 0 )
            {
                $i = 1;
//                $User = array();
                while( $User = $searchUsers->fetch_assoc() )
                {
                    $processed[] = $User['rule_lid'];
//                    $name_original=$User['name'];
                    $name = $User['name'];
//                    $isGroup = $projectdb->query("SELECT name FROM userid_group WHERE name = '$name' OR short_name = '$name';");
//                    if ($isGroup->num_rows > 0) {
//                        $image = 'user-groups.png';
//                    }else{
                    $image = 'userp.png';
//                    }
//                    $i++;
                    $rules[$User['rule_lid']]['user'][] = array("img" => $image, "name" => $name);
                    //$User[] = array('img' => $image, 'name' => $name_original);
                }
//                if ($i > 10) {
//                    $rules[$Tags['rule_lid']]['usr'][]=array("img"=>"more.png","name"=>"more...");
//                    //$User[] = array('img' => 'more.png', 'name' => 'more...');
//                }
//                $UserOK = $User;
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['user'] = null;
            }

            # Read the Tags
            $getSource = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM security_rules_tag WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $getSource->num_rows > 0 )
            {
                while( $src = $getSource->fetch_assoc() )
                {
                    $processed[] = $src['rule_lid'];
//                    $src_table_name = $src['table_name'];
//                    $src_member_lid = $src['member_lid'];
                    $tagObject = $objectsInMemory[$src['table_name']][$src['member_lid']];
                    $rules[$src['rule_lid']]["tag"][] = [
                        "id" => $tagObject['id'],
                        "name" => $tagObject['name'],
                        "color" => $tagObject['rgb']
                    ];
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['tag'] = null;
            }

            # Read the Categories
            $getCategories = $projectdb->query("SELECT name, rule_lid FROM security_rules_categories WHERE rule_lid IN ($ruleids2)");
            $processed = array();
            if( $getCategories->num_rows > 0 )
            {
                while( $cate = $getCategories->fetch_assoc() )
                {
                    $processed[] = $cate['rule_lid'];
                    $name = $cate['name'];
                    $rules[$cate['rule_lid']]['url_category'][] = [
                        "name" => $name,
                    ];
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['url_category'] = null;
            }

            # Read the Services
            $getService = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM security_rules_srv WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $getService->num_rows > 0 )
            {
                while( $srv = $getService->fetch_assoc() )
                {
                    $processed[] = $srv['rule_lid'];
                    $serviceObject = $objectsInMemory[$srv['table_name']][$srv['member_lid']];
                    $rules[$srv['rule_lid']]["service"][] =
                        array('img' => $serviceObject['icon'], 'name' => $serviceObject['name'], 'ip' => $serviceObject['myip'], 'vsys_member' => $serviceObject['vsys']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['service'] = null;
            }

            # Read the Applications
            $getApplication = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM security_rules_app WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $getApplication->num_rows > 0 )
            {
                while( $app = $getApplication->fetch_assoc() )
                {
                    $processed[] = $app['rule_lid'];
                    $appObject = $objectsInMemory[$app['table_name']][$app['member_lid']];
                    $rules[$app['rule_lid']]["application"][] =
                        array('img' => $appObject['icon'], 'name' => $appObject['name'], 'ip' => $appObject['myip'], 'vsys_member' => $appObject['vsys'], 'table_name' => $app['table_name']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['application'] = null;
            }

            # Read the Hip
            $getHip = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM security_rules_hip WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $getHip->num_rows > 0 )
            {
                while( $hip = $getHip->fetch_assoc() )
                {
                    $processed[] = $hip['rule_lid'];
                    $hipObject = $objectsInMemory[$hip['table_name']][$hip['member_lid']];
                    $rules[$hip['rule_lid']]["hip_profile"][] =
                        array('img' => $hipObject['icon'], 'name' => $hipObject['name'], 'ip' => $hipObject['myip']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['hip_profile'] = null;
            }

            # Read the User From Log
            $query = "SELECT * FROM userid_from_log WHERE rule_lid IN ($ruleids2);";
//            echo "$query\n";
            $getUFL = $projectdb->query($query);
            $processed = array();
            if( $getUFL->num_rows > 0 )
            {
                $image = "userp.gif";
                while( $ufl = $getUFL->fetch_assoc() )
                {
                    $processed[] = $ufl['rule_lid'];
                    $rules[$ufl['rule_lid']]['useridfromlog'][] =
                        array('img' => $image, 'name' => addslashes($ufl['name']), 'bytes' => $ufl['bytes'], 'sessions' => $ufl['sessions']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['useridfromlog'] = null;
            }

            # Read the Application From Log
            $getAFL = $projectdb->query("SELECT app,dport,sum(bytes) as bytes,sum(packets) as packets,source,proto, rule_lid FROM applications_from_log WHERE rule_lid IN ($ruleids2) GROUP BY app,rule_lid;");
            $processed = array();
            if( $getAFL->num_rows > 0 )
            {


                while( $afl = $getAFL->fetch_assoc() )
                {
                    if( ($afl['app'] == "unknown-udp") or ($afl['app'] == "unknown-tcp") or ($afl['app'] == "unknown-p2p") )
                    {
                        $image = "fa-question-circle";
                    }
                    else
                    {
                        $image = "fa-pie-chart";
                    }
                    $processed[] = $afl['rule_lid'];
                    $rules[$afl['rule_lid']]['applicationfromlog'][] =
                        array('img' => $image, 'app' => $afl['app'], 'dport' => $afl['dport'], 'bytes' => $afl['bytes'], 'packets' => $afl['packets'], 'proto' => $afl['proto']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['applicationfromlog'] = null;
            }

            # Read the Security Rules Profiles
            $getProfiles = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM security_rules_profiles WHERE rule_lid IN ($ruleids2);");
            $processed = array();
            if( $getProfiles->num_rows > 0 )
            {
                while( $hip = $getProfiles->fetch_assoc() )
                {
                    $processed[] = $hip['rule_lid'];
                    $profiObject = $objectsInMemory[$hip['table_name']][$hip['member_lid']];
                    $rules[$hip['rule_lid']]["profile"][] =
                        array('img' => $profiObject['icon'], 'name' => $profiObject['name'], 'type' => $profiObject['type']);
                }
            }
            $notprocessed = array_diff($ruleids, $processed);
            foreach( $notprocessed as $ruleid )
            {
                $rules[$ruleid]['profile'] = null;
            }

            $result = [
                "total" => count($rules),
                "security" => $rules
            ];
        }
    }


    return $result;
}

function search_appOverride_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    if( ($filter != "none") && ($filter != "0") )
    {

        $params['tools_where_columns_id'] = $filter;
        $params['tools_operator_id'] = "contains";
        $params['search'] = "";
        $params['tools_where_id'] = "4";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";
        $params['source'] = $source;
        $params['vsys'] = $vsys;
        $params['case_sensitive'] = "0";

        setFilter($project, $params);
        executeSQL($project, $params);

    }
    elseif( ($filter == "none") || ($filter == "0") )
    {
    }

    $query = generateQueryConsolidation($project, "appoverride_rules", $query, $source);

    list($query, $orderby) = generateQueryFilters($project, "appoverride_rules", "", $query, $source);

    $getAll = $projectdb->query("SELECT id FROM appoverride_rules $query;");
    $count = $getAll->num_rows;

    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup,port,protocol,app_id,app_table 
                FROM appoverride_rules $query ORDER BY source,position ASC";
    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $port = $row['port'];
        $protocol = $row['protocol'];
        $app_id = $row['app_id'];
        $vsys = $row['vsys'];
        $app_table = $row['app_table'];
        $source = $row['source'];
        $target = $row['target'];
        $checkit = $row['checkit'];
        $migrate = $row['migrate'];
        $counter = $row['counter'];
        $preorpost = $row['preorpost'];
        $devicegroup = $row['devicegroup'];
        $id = $row['id'];
        $target = $row['target'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM appoverride_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $From[] = $Tags['name'];
            }
            $FromOK = implode(",", $From);
        }
        else
        {
            $FromOK = "any";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $To = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $To[] = $Tags['name'];
            }
            $ToOK = implode(",", $To);
        }
        else
        {
            $ToOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM appoverride_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM appoverride_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }


        if( ($app_id != "") and ($app_table != "") )
        {
            $Application = array();

            $srv_table_name = $app_table;
            $srv_member_lid = $app_id;
            //$Application[] = array('img' => $image, 'name' => $name, 'ip' => $myip);
            list($image, $vsys_member, $name, $myip) = getIcon("applications", $srv_table_name, $srv_member_lid, "");

            $Application[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $srv_table_name);

            $applicationOK = $Application;
        }
        else
        {
            $applicationOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "port" => $port,
            "protocol" => $protocol,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "app" => $applicationOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "from" => $FromOK,
            "to" => $ToOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }

    $result = [
        "total" => $count,
        "appoverride" => $rule
    ];

    return $result;

}


function search_authentication_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    $getAll = $projectdb->query("SELECT id FROM authentication_rules $query;");
    $count = $getAll->num_rows;

    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup
                FROM authentication_rules $query ORDER BY source,position ASC";
    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $checkit = $row['checkit'];
        $preorpost = $row['preorpost'];
        $id = $row['id'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM authentication_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM authentication_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $From[] = $Tags['name'];
            }
            $FromOK = implode(",", $From);
        }
        else
        {
            $FromOK = "any";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM authentication_rules_to WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $To = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $To[] = $Tags['name'];
            }
            $ToOK = implode(",", $To);
        }
        else
        {
            $ToOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM authentication_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM authentication_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }


        $getService = $projectdb->query("SELECT table_name,member_lid FROM authentication_rules_srv WHERE rule_lid='$id' LIMIT 10");
        if( $getService->num_rows > 0 )
        {
            $Service = array();
            while( $srv = $getService->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("services", $src_table_name, $src_member_lid, "");
                $Service[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getService->num_rows == 10 )
            {
                $Service[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $ServiceOK = $Service;
        }
        else
        {
            $ServiceOK = "any";
        }

        $searchUsr = $projectdb->query("SELECT name FROM authentication_rules_usr WHERE rule_lid='$id';");
        if( $searchUsr->num_rows > 0 )
        {
            $Usr = array();
            while( $Tags = $searchUsr->fetch_assoc() )
            {
                $Usr[] = $Tags['name'];
            }
            $UsrOK = implode(",", $Usr);
        }
        else
        {
            $UsrOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "srv" => $ServiceOK,
            "from" => $FromOK,
            "to" => $ToOK,
            "usr" => $UsrOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }
    $result = [
        "total" => $count,
        "authentication" => $rule
    ];

    return $result;

}


function search_captiveportal_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    $getAll = $projectdb->query("SELECT id FROM authentication_rules $query;");
    $count = $getAll->num_rows;

    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup
                FROM captiveportal_rules $query ORDER BY source,position ASC";
    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $checkit = $row['checkit'];
        $preorpost = $row['preorpost'];
        $id = $row['id'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM captiveportal_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM captiveportal_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $From[] = $Tags['name'];
            }
            $FromOK = implode(",", $From);
        }
        else
        {
            $FromOK = "any";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM captiveportal_rules_to WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $To = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $To[] = $Tags['name'];
            }
            $ToOK = implode(",", $To);
        }
        else
        {
            $ToOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM captiveportal_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM captiveportal_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }


        $getService = $projectdb->query("SELECT table_name,member_lid FROM captiveportal_rules_srv WHERE rule_lid='$id' LIMIT 10");
        if( $getService->num_rows > 0 )
        {
            $Service = array();
            while( $srv = $getService->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("services", $src_table_name, $src_member_lid, "");
                $Service[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getService->num_rows == 10 )
            {
                $Service[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $ServiceOK = $Service;
        }
        else
        {
            $ServiceOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "srv" => $ServiceOK,
            "from" => $FromOK,
            "to" => $ToOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }
    $result = [
        "total" => $count,
        "captiveportal" => $rule
    ];

    return $result;

}


function search_pbf_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    $getAll = $projectdb->query("SELECT id FROM pbf_rules $query;");
    $count = $getAll->num_rows;

    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup
                FROM pbf_rules $query ORDER BY source,position ASC";

    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $checkit = $row['checkit'];
        $preorpost = $row['preorpost'];
        $id = $row['id'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM pbf_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name, type FROM pbf_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                //$From[] = $Tags['name'];
                $name_from = $Tags['name'];
                $type = $Tags['type'];
                $From[] = array('type' => $type, 'name' => $name_from);
            }
            //$FromOK = implode(",", $From);
            $FromOK = $From;
        }
        else
        {
            $FromOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM pbf_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM pbf_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }


        $getService = $projectdb->query("SELECT table_name,member_lid FROM pbf_rules_srv WHERE rule_lid='$id' LIMIT 10");
        if( $getService->num_rows > 0 )
        {
            $Service = array();
            while( $srv = $getService->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("services", $src_table_name, $src_member_lid, "");
                $Service[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);

            }
            if( $getService->num_rows == 10 )
            {
                $Service[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $ServiceOK = $Service;
        }
        else
        {
            $ServiceOK = "any";
        }

        $getApp = $projectdb->query("SELECT table_name,member_lid FROM pbf_rules_app WHERE rule_lid='$id' LIMIT 10");
        if( $getApp->num_rows > 0 )
        {
            $Applications = array();
            while( $srv = $getApp->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("applications", $src_table_name, $src_member_lid, "");
                $Applications[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getApp->num_rows == 10 )
            {
                $Applications[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $AppOK = $Applications;
        }
        else
        {
            $AppOK = "any";
        }

        $searchUsr = $projectdb->query("SELECT name FROM pbf_rules_usr WHERE rule_lid='$id';");
        if( $searchUsr->num_rows > 0 )
        {
            $Usr = array();
            while( $Tags = $searchUsr->fetch_assoc() )
            {
                $Usr[] = $Tags['name'];
            }
            $UsrOK = implode(",", $Usr);
        }
        else
        {
            $UsrOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "srv" => $ServiceOK,
            "app" => $AppOK,
            "from" => $FromOK,
            "usr" => $UsrOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }
    $result = [
        "total" => $count,
        "pbf" => $rule
    ];

    return $result;

}


function search_qos_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    $getAll = $projectdb->query("SELECT id FROM pbf_rules $query;");
    $count = $getAll->num_rows;

    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup
                FROM qos_rules $query ORDER BY source,position ASC";
    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $checkit = $row['checkit'];
        $preorpost = $row['preorpost'];
        $id = $row['id'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM qos_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM qos_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $From[] = $Tags['name'];
            }
            $FromOK = implode(",", $From);
        }
        else
        {
            $FromOK = "any";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM qos_rules_to WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $To = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $To[] = $Tags['name'];
            }
            $ToOK = implode(",", $To);
        }
        else
        {
            $ToOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM qos_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM qos_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }

        $getService = $projectdb->query("SELECT table_name,member_lid FROM qos_rules_srv WHERE rule_lid='$id' LIMIT 10");
        if( $getService->num_rows > 0 )
        {
            $Service = array();
            while( $srv = $getService->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("services", $src_table_name, $src_member_lid, "");
                $Service[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);

            }
            if( $getService->num_rows == 10 )
            {
                $Service[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $ServiceOK = $Service;
        }
        else
        {
            $ServiceOK = "any";
        }

        $getApp = $projectdb->query("SELECT table_name,member_lid FROM qos_rules_app WHERE rule_lid='$id' LIMIT 10");
        if( $getApp->num_rows > 0 )
        {
            $Applications = array();
            while( $srv = $getApp->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("applications", $src_table_name, $src_member_lid, "");
                $Applications[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);

            }
            if( $getApp->num_rows == 10 )
            {
                $Applications[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $AppOK = $Applications;
        }
        else
        {
            $AppOK = "any";
        }

        $searchUsr = $projectdb->query("SELECT name FROM qos_rules_usr WHERE rule_lid='$id';");
        if( $searchUsr->num_rows > 0 )
        {
            $Usr = array();
            while( $Tags = $searchUsr->fetch_assoc() )
            {
                $Usr[] = $Tags['name'];
            }
            $UsrOK = implode(",", $Usr);
        }
        else
        {
            $UsrOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "srv" => $ServiceOK,
            "app" => $AppOK,
            "from" => $FromOK,
            "to" => $ToOK,
            "usr" => $UsrOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }
    $result = [
        "total" => $count,
        "qos" => $rule
    ];

    return $result;

}


function search_decryption_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    $getAll = $projectdb->query("SELECT id FROM pbf_rules $query;");
    $count = $getAll->num_rows;
    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup
                FROM decryption_rules $query ORDER BY source,position ASC";

    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $checkit = $row['checkit'];
        $preorpost = $row['preorpost'];
        $id = $row['id'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM decryption_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM decryption_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $From[] = $Tags['name'];
            }
            $FromOK = implode(",", $From);
        }
        else
        {
            $FromOK = "any";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM decryption_rules_to WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $To = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $To[] = $Tags['name'];
            }
            $ToOK = implode(",", $To);
        }
        else
        {
            $ToOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM decryption_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM decryption_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }


        $getService = $projectdb->query("SELECT table_name,member_lid FROM decryption_rules_srv WHERE rule_lid='$id' LIMIT 10");
        if( $getService->num_rows > 0 )
        {
            $Service = array();
            while( $srv = $getService->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("services", $src_table_name, $src_member_lid, "");
                $Service[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getService->num_rows == 10 )
            {
                $Service[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $ServiceOK = $Service;
        }
        else
        {
            $ServiceOK = "any";
        }

        $searchUsr = $projectdb->query("SELECT name FROM decryption_rules_usr WHERE rule_lid='$id';");
        if( $searchUsr->num_rows > 0 )
        {
            $Usr = array();
            while( $Tags = $searchUsr->fetch_assoc() )
            {
                $Usr[] = $Tags['name'];
            }
            $UsrOK = implode(",", $Usr);
        }
        else
        {
            $UsrOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "srv" => $ServiceOK,
            "from" => $FromOK,
            "to" => $ToOK,
            "usr" => $UsrOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }
    $result = [
        "total" => $count,
        "decryption" => $rule
    ];

    return $result;

}


function search_tunnel_inspect_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    $getAll = $projectdb->query("SELECT id FROM pbf_rules $query;");
    $count = $getAll->num_rows;
    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup
                FROM tunnel_inspect_rules $query ORDER BY source,position ASC";

    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $checkit = $row['checkit'];
        $preorpost = $row['preorpost'];
        $id = $row['id'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM tunnel_inspect_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM tunnel_inspect_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $From[] = $Tags['name'];
            }
            $FromOK = implode(",", $From);
        }
        else
        {
            $FromOK = "any";
        }

        $searchZoneSrc = $projectdb->query("SELECT name FROM tunnel_inspect_rules_to WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $To = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                $To[] = $Tags['name'];
            }
            $ToOK = implode(",", $To);
        }
        else
        {
            $ToOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM tunnel_inspect_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM tunnel_inspect_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }


        $getApp = $projectdb->query("SELECT table_name,member_lid FROM tunnel_inspect_rules_app WHERE rule_lid='$id' LIMIT 10");
        if( $getApp->num_rows > 0 )
        {
            $Applications = array();
            while( $srv = $getApp->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("applications", $src_table_name, $src_member_lid, "");
                $Applications[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);

            }
            if( $getApp->num_rows == 10 )
            {
                $Applications[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $AppOK = $Applications;
        }
        else
        {
            $AppOK = "any";
        }

        $searchUsr = $projectdb->query("SELECT name FROM tunnel_inspect_rules_usr WHERE rule_lid='$id';");
        if( $searchUsr->num_rows > 0 )
        {
            $Usr = array();
            while( $Tags = $searchUsr->fetch_assoc() )
            {
                $Usr[] = $Tags['name'];
            }
            $UsrOK = implode(",", $Usr);
        }
        else
        {
            $UsrOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "app" => $AppOK,
            "from" => $FromOK,
            "to" => $ToOK,
            "usr" => $UsrOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }
    $result = [
        "total" => $count,
        "tunnel" => $rule
    ];

    return $result;

}


function search_dos_policies($ruleids, $source, $vsyse, $project, $preorpost, $start, $limit, $color, $level, $label, $filter, $vsys)
{

    global $projectdb;

    $query = generate_query("policies", $vsyse, $preorpost);

    $getAll = $projectdb->query("SELECT id FROM authentication_rules $query;");
    $count = $getAll->num_rows;

    $query = "SELECT id,position,name,negate_source,negate_destination,description,disabled,vsys,source,target,checkit,migrate,counter,preorpost,devicegroup
                FROM dos_rules $query ORDER BY source,position ASC";
    $getLimit = $projectdb->query($query);
    $rule = array();

    while( $row = $getLimit->fetch_assoc() )
    {
        $position = $row['position'];
        $rulename = $row['name'];
        $negate_source = $row['negate_source'];
        $negate_destination = $row['negate_destination'];
        $description = addslashes($row['description']);
        $disabled = $row['disabled'];
        $checkit = $row['checkit'];
        $preorpost = $row['preorpost'];
        $id = $row['id'];
        $source = $row['source'];
        $vsys = $row['vsys'];

        $searchTag = $projectdb->query("SELECT t.id as id,t.name as name, t.color as color, tc.color AS color_name FROM dos_rules_tag srt, tag t, tag_colors tc WHERE srt.rule_lid=$id AND t.id=srt.member_lid AND t.color = tc.name;");
        if( $searchTag->num_rows > 0 )
        {
            $Tag = array();
            while( $Ttag = $searchTag->fetch_assoc() )
            {
                $TagName = $Ttag['name'];
                $tagid = $Ttag['id'];
                $TagColor = $Ttag['color_name'];
                $thenewtagcolor = array("id" => $tagid, "name" => $TagName, "color" => $TagColor);
                $Tag[] = $thenewtagcolor;
            }
            $TagOK = $Tag;
        }
        else
        {
            $TagOK = "none";
        }

        $searchZoneSrc = $projectdb->query("SELECT name, type FROM dos_rules_from WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $From = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                //$From[] = $Tags['name'];
                $name_from = $Tags['name'];
                $type = $Tags['type'];
                $From[] = array('type' => $type, 'name' => $name_from);
            }
            //$FromOK = implode(",", $From);
            $FromOK = $From;
        }
        else
        {
            $FromOK = "any";
        }

        $searchZoneSrc = $projectdb->query("SELECT name, type FROM dos_rules_to WHERE rule_lid='$id';");
        if( $searchZoneSrc->num_rows > 0 )
        {
            $To = array();
            while( $Tags = $searchZoneSrc->fetch_assoc() )
            {
                //$From[] = $Tags['name'];
                $name_to = $Tags['name'];
                $type = $Tags['type'];
                $To[] = array('type' => $type, 'name' => $name_to);
            }
            //$FromOK = implode(",", $From);
            $ToOK = $To;
        }
        else
        {
            $ToOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM dos_rules_src WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Source = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Source[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Source[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $SourceOK = $Source;
        }
        else
        {
            $SourceOK = "any";
        }

        $getSource = $projectdb->query("SELECT table_name,member_lid FROM dos_rules_dst WHERE rule_lid='$id' LIMIT 10");
        if( $getSource->num_rows > 0 )
        {
            $Destination = array();
            while( $src = $getSource->fetch_assoc() )
            {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                $Destination[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);
            }
            if( $getSource->num_rows == 10 )
            {
                $Destination[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $DestinationOK = $Destination;
        }
        else
        {
            $DestinationOK = "any";
        }


        $getService = $projectdb->query("SELECT table_name,member_lid FROM dos_rules_srv WHERE rule_lid='$id' LIMIT 10");
        if( $getService->num_rows > 0 )
        {
            $Service = array();
            while( $srv = $getService->fetch_assoc() )
            {
                $src_table_name = $srv['table_name'];
                $src_member_lid = $srv['member_lid'];

                list($image, $vsys_member, $name, $myip) = getIcon("services", $src_table_name, $src_member_lid, "");
                $Service[] = array('img' => $image, 'name' => $name, 'ip' => $myip, 'vsys_member' => $vsys_member, 'table_name' => $src_table_name);

            }
            if( $getService->num_rows == 10 )
            {
                $Service[] = array('img' => 'more.png', 'name' => 'more...', 'ip' => 'none', 'vsys_member' => '', 'table_name' => '');
            }
            $ServiceOK = $Service;
        }
        else
        {
            $ServiceOK = "any";
        }

        $searchUsr = $projectdb->query("SELECT name FROM dos_rules_usr WHERE rule_lid='$id';");
        if( $searchUsr->num_rows > 0 )
        {
            $Usr = array();
            while( $Tags = $searchUsr->fetch_assoc() )
            {
                $Usr[] = $Tags['name'];
            }
            $UsrOK = implode(",", $Usr);
        }
        else
        {
            $UsrOK = "any";
        }

        $rule[] = [
            "source" => $source,
            "vsys" => $vsys,
            "checkit" => $checkit,
            "tags" => $TagOK,
            "src" => $SourceOK,
            "dst" => $DestinationOK,
            "srv" => $ServiceOK,
            "from" => $FromOK,
            "to" => $ToOK,
            "usr" => $UsrOK,
            "id" => $id,
            "name" => $rulename,
            "position" => $position,
            "disabled" => $disabled,
            "description" => $description,
            "negate_source" => $negate_source,
            "negate_destination" => $negate_destination,
            "preorpost" => $preorpost,
            "color" => $color,
            "groupby" => $level,
            "label" => $label,
        ];
    }

    if( $count == 0 )
    {
        $myData = "";
    }
    $result = [
        "total" => $count,
        "dos" => $rule
    ];

    return $result;

}


function convertNetmaskv4($cidr_mask)
{
    return long2ip(0xFFFFFFFF ^ (pow(2, 32 - $cidr_mask) - 1));
}

# Auto Zone Assign
function netMatchV4($network, $ip)
{

    $network = trim($network);
    $ip = trim($ip);
    $d = strpos($network, "-");

    if( $d === FALSE )
    {
        $ip_arr = explode('/', $network);
        if( !preg_match("@\d*\.\d*\.\d*\.\d*@", $ip_arr[0], $matches) )
        {
            $ip_arr[0] .= ".0";    // Alternate form 194.1.4/24
        }

        $network_long = ip2long($ip_arr[0]);
        $x = ip2long($ip_arr[1]);

        $mask = long2ip($x) == $ip_arr[1] ? $x : (0xffffffff << (32 - $ip_arr[1]));
        $ip_long = ip2long($ip);

        //echo ($ip_long & $mask) == ($network_long & $mask);
        return ($ip_long & $mask) == ($network_long & $mask);
    }
    else
    {
        $from = trim(ip2long(substr($network, 0, $d)));
        $to = trim(ip2long(substr($network, $d + 1)));

        $ip = ip2long($ip);
        return ($ip >= $from and $ip <= $to);
    }
}

function search_zone_address($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat)
{
#Can be a Host, Network or Range Or FQDN
    global $projectdb;
    $zones = array();
    $Zone = "";
    $next = 0;

    require_once INC_ROOT . "/bin/projects/tools/prepareQuery.php";
    $addVsys = prepareVsysQuery($projectdb, $vsys, $source);

    $getType = $projectdb->query("SELECT v4,v6,type,ipaddress,cidr FROM $table_name WHERE source='$source' $addVsys AND id='$member_lid'");
    if( $getType->num_rows == 1 )
    {
        $next = 0;
        $Address = $getType->fetch_assoc();
        $AddressType = $Address["type"];

        if( $rule_or_nat == "rule" )
        {
            if( $from_or_to == "from" )
            {
                $out_table = "security_rules_from";
            }
            else
            {
                $out_table = "security_rules_to";
            }
        }
        else
        {
            if( $from_or_to == "from" )
            {
                $out_table = "nat_rules_from";
            }
            else
            {
                $out_table = "nat_rules_to";
            }
        }


        if( $AddressType == "ip-range" )
        {
            $IPAddress = $Address["ipaddress"];
            $list = explode("-", $IPAddress);
            $first = $list[0];
            $last = $list[1];
            $next = 1;
        }
        elseif( $AddressType == "fqdn" )
        {
            # Do NOTHING with FQDN Objects
            $Zone = "";
            $next = 0;
        }
        else
        {
            # ip-netmask
            $first = $Address["ipaddress"];
            $next = 1;
        }

        if( $next == 1 )
        {
            #Load the static-routes

            $ccidr = 0;
            $czone = "not found";
            $encontrado = "0";

            #Check first against the Interfaces
            $getInterface = $projectdb->query("SELECT unitipaddress,zone FROM interfaces WHERE unitipaddress!='' AND source='$source' AND vr_id='$vr' AND vsys='$vsys';");
            if( $getInterface->num_rows > 0 )
            {
                while( $getInterfaceData = $getInterface->fetch_assoc() )
                {
                    #The unitipadddress can be 1.1.1.1/24,1.1.1.2
                    $getUnique = explode(",", $getInterfaceData['unitipaddress']);
                    foreach( $getUnique as $key => $value )
                    {
                        $unitipaddress = explode("/", $value);
                        $interface_ip = $unitipaddress[0];
                        if( isset($unitipaddress[1]) )
                        {
                            $interface_cidr = $unitipaddress[1];
                        }
                        else
                        {
                            $interface_cidr = "32";
                        }
                        $zone_from = $getInterfaceData['zone'];
                        $network1 = cidr2network($interface_ip, $interface_cidr);
                        $network = $network1 . "/" . $interface_cidr;
                        $ip = $first;
                        $hoes = netMatchV4($network, $ip);
                        if( $hoes == 1 )
                        {
                            if( $ccidr < $interface_cidr )
                            {
                                $czone = $zone_from;
                                $ccidr = $interface_cidr;
                            }
                            $encontrado = "1";
                        }
                    }
                }
            }

            if( $encontrado == "0" )
            {
                #To be Fixed, Only supported one VR = one default gw from vr1 only
                $get_routes = $projectdb->query("SELECT destination,zone FROM routes_static WHERE destination != '0.0.0.0/0' AND source='$source' AND vsys='$vsys' AND vr_id='$vr' AND nexthop='ip-address' ORDER BY nexthop_value DESC;");
                while( $get_routes_var = $get_routes->fetch_assoc() )
                {
                    $zone_from = $get_routes_var['zone'];
                    $network_match = $get_routes_var['destination'];
                    $myroute = explode("/", $network_match);
                    $network_route = $myroute[0];
                    $netmask_route = $myroute[1];
                    $network = $network_match;
                    $ip = $first;
                    $hoes = netMatchV4($network, $ip);

                    if( $hoes == 1 )
                    {
                        if( $ccidr < $netmask_route )
                        {
                            $czone = $zone_from;
                            $ccidr = $netmask_route;
                        }
                        $encontrado = "1";
                    }
                }
            }

            if( $encontrado == 1 )
            {
                if( $czone == "not found" )
                {

                }
                else
                {
                    //$zones=array($rule_lid,$czone);
                    if( $rule_or_nat == "rule" )
                    {
                        $getDup = $projectdb->query("SELECT id FROM $out_table WHERE name='$czone' AND rule_lid='$rule_lid';");
                        if( $getDup->num_rows == 0 )
                        {
                            $projectdb->query("INSERT INTO $out_table (source,vsys,rule_lid,name) VALUES ('$source','$vsys','$rule_lid','$czone');");
                        }
                    }
                    else
                    {
                        # NAT
                        if( $from_or_to == "to" )
                        {
                            $getDup = $projectdb->query("SELECT op_zone_to FROM nat_rules WHERE id='$rule_lid';");
                            $getIT = $getDup->fetch_assoc();
                            if( $getIT['op_zone_to'] == "" )
                            {
                                $projectdb->query("UPDATE nat_rules SET op_zone_to='$czone' WHERE id='$rule_lid'");
                            }
                            elseif( $getIT['op_zone_to'] == $czone )
                            {

                            }
                            else
                            {
                                $message = "Nat RuleID [" . $rule_lid . "] is usign more than one Zone as a Destination [" . $czone . "]";
                                $getDup = $projectdb->query("SELECT id FROM logs WHERE message LIKE '%$message%' obj_id='$rule_lid' AND obj_table='nat_rules';");
                                if( $getDup->num_rows == 0 )
                                {
                                    add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_lid . '] is usign more than one Zone as a Destination [' . $czone . ']', $source, 'Only one Destination Zone is allowed', 'rules', $rule_lid, 'nat_rules');
                                }
                            }
                        }
                        else
                        {
                            $getDup = $projectdb->query("SELECT id FROM $out_table WHERE name='$czone' AND rule_lid='$rule_lid';");
                            if( $getDup->num_rows == 0 )
                            {
                                $projectdb->query("INSERT INTO $out_table (source,vsys,rule_lid,name) VALUES ('$source','$vsys','$rule_lid','$czone');");
                            }
                        }
                    }
                }
            }
            else
            {
                $get_defaultgw = $projectdb->query("SELECT zone FROM routes_static WHERE name = 'default' AND source='$source' AND vsys='$vsys' AND vr_id='$vr' limit 1");
                if( $get_defaultgw->num_rows == 1 )
                {
                    $get_defaultgwname = $get_defaultgw->fetch_assoc();
                    $zone_default = $get_defaultgwname['zone'];
                    //$zones=array($rule_lid,$zone_default);
                    if( $rule_or_nat == "rule" )
                    {
                        $getDup = $projectdb->query("SELECT id FROM $out_table WHERE rule_lid='$rule_lid' AND name='$zone_default';");
                        if( $getDup->num_rows == 0 )
                        {
                            $projectdb->query("INSERT INTO $out_table (source,vsys,name,rule_lid) VALUES ('$source','$vsys','$zone_default','$rule_lid')");
                        }
                    }
                    else
                    {
                        if( $from_or_to == "to" )
                        {
                            $getDup = $projectdb->query("SELECT op_zone_to FROM nat_rules WHERE id='$rule_lid';");
                            $getIT = $getDup->fetch_assoc();
                            if( $getIT['op_zone_to'] == "" )
                            {
                                $projectdb->query("UPDATE nat_rules SET op_zone_to='$zone_default' WHERE id='$rule_lid'");
                            }
                            elseif( $getIT['op_zone_to'] == $zone_default )
                            {

                            }
                            else
                            {
                                $message = "Nat RuleID [" . $rule_lid . "] is usign more than one Zone as a Destination [" . $zone_default . "]";
                                $getDup = $projectdb->query("SELECT id FROM logs WHERE message LIKE '%$message%' obj_id='$rule_lid' AND obj_table='nat_rules';");
                                if( $getDup->num_rows == 0 )
                                {
                                    add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_lid . '] is usign more than one Zone as a Destination [' . $zone_default . ']', $source, 'Only one Destination Zone is allowed', 'rules', $rule_lid, 'nat_rules');
                                }
                            }
                        }
                        else
                        {
                            $getDup = $projectdb->query("SELECT id FROM $out_table WHERE rule_lid='$rule_lid' AND name='$zone_default';");
                            if( $getDup->num_rows == 0 )
                            {
                                $projectdb->query("INSERT INTO $out_table (source,vsys,name,rule_lid) VALUES ('$source','$vsys','$zone_default','$rule_lid')");
                            }
                        }
                    }

                }
                else
                {

                    $getDup = $projectdb->query("SELECT id FROM logs WHERE message LIKE '%There is no default-gw.%' AND source='$source';");
                    if( $getDup->num_rows == 1 )
                    {

                    }
                    else
                    {
                        add_log(3, 'Auto Zone Assign', 'We cannot calculate some Zones becasue There is no default-gw.', $source, 'Add a default gw in your Virtual Router and name it as default');
                    }

                }
            }
        }
    }
}

function cidr2network($ip, $cidr)
{
    $network = long2ip((ip2long($ip)) & ((-1 << (32 - (int)$cidr))));
    return $network;
}

function search_zone_group($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat)
{
    global $projectdb;

//    if ($table_name == "shared_address_groups_id") {
//        $addVsys = "";
//        $table = "shared_address_groups";
//    } else {
    $addVsys = "AND vsys='$vsys'";

    $table = "address_groups";
//    }

    $search_members = $projectdb->query("SELECT member_lid, table_name FROM $table WHERE lid='$member_lid';");
    while( $members = $search_members->fetch_assoc() )
    {
        $member_ID = $members['member_lid'];
        $member_Table = $members['table_name'];
        if( $member_Table == 'address_groups_id' )
        {
            search_zone_group($rule_lid, $member_ID, $vsys, $source, $vr, $member_Table, $from_or_to, $rule_or_nat);
        }
        else
        {
            search_zone_address($rule_lid, $member_ID, $vsys, $source, $vr, $member_Table, $from_or_to, $rule_or_nat);
        }
    }
}


function check_used_objects_by_source($source)
{
    global $projectdb;

    $array_address = array();
    $array_address_groups = array();
    $array_services = array();
    $array_services_groups = array();
    $array_regions = array();
    $array_default_regions = array();
    $array_applications = array();
    $array_applications_groups = array();
    $array_applications_filters = array();
    $array_default_applications = array();
    $array_tag = array();

    $FILE = array();
    $FILE[] = "security_rules_src";
    $FILE[] = "security_rules_dst";
    $FILE[] = "security_rules_srv";
    $FILE[] = "security_rules_app";
    $FILE[] = "security_rules_tag";
    $FILE[] = "nat_rules_src";
    $FILE[] = "nat_rules_dst";
    $FILE[] = "nat_rules_translated_address";
    $FILE[] = "nat_rules_translated_address_fallback";
    $FILE[] = "nat_rules_tag";
    $FILE[] = "appoverride_rules_dst";
    $FILE[] = "appoverride_rules_src";
    $FILE[] = "appoverride_rules_tag";

    #Clean all Used Objects
    $projectdb->query("UPDATE address SET used='0' WHERE source='$source';");
    $projectdb->query("UPDATE address_groups_id SET used='0',checkit='0' WHERE source='$source';");
    $projectdb->query("UPDATE services SET used='0' WHERE source='$source';");
    $projectdb->query("UPDATE services_groups_id SET used='0',checkit='0' WHERE source='$source';");
    $projectdb->query("UPDATE applications SET used='0' WHERE source='$source';");
    $projectdb->query("UPDATE applications_groups_id SET used='0' WHERE source='$source';");
    $projectdb->query("UPDATE applications_filters SET used='0' WHERE source='$source';");
    #$projectdb->query("UPDATE default_applications SET used='0';");
    $projectdb->query("UPDATE regions SET used='0' WHERE source='$source';");
    #$projectdb->query("UPDATE default_regions SET used='0';");
    $projectdb->query("UPDATE tag SET used='0' WHERE source='$source';");

    # Must be done by rule_lid by rule type
    foreach( $FILE as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name FROM $value GROUP BY member_lid,table_name;");

        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {

                $member_id = $getRuleSourceData["member_lid"];
                $table_name = $getRuleSourceData['table_name'];

                if( $table_name == "address" )
                {
                    $array_address[] = $member_id;
                }
                elseif( $table_name == "address_groups_id" )
                {
                    $array_address_groups[] = $member_id;
                }
                elseif( $table_name == "services" )
                {
                    $array_services[] = $member_id;
                }
                elseif( $table_name == "services_groups_id" )
                {
                    $array_services_groups[] = $member_id;
                }
                elseif( $table_name == "regions" )
                {
                    $array_regions[] = $member_id;
                }
                elseif( $table_name == "default_regions" )
                {
                    $array_default_regions[] = $member_id;
                }
                elseif( $table_name == "applications" )
                {
                    $array_applications[] = $member_id;
                }
                elseif( $table_name == "applications_groups_id" )
                {
                    $array_applications_groups[] = $member_id;
                }
                elseif( $table_name == "applications_filters" )
                {
                    $array_applications_filters[] = $member_id;
                }
                elseif( $table_name == "default_applications" )
                {
                    $array_default_applications[] = $member_id;
                }
                elseif( $table_name == "tag" )
                {
                    $array_tag[] = $member_id;
                }
            }
        }
    }

    $getVsys = $projectdb->query("SELECT id,filename,ispanorama FROM device_mapping WHERE id='$source';");
    if( $getVsys->num_rows > 0 )
    {
        while( $theVsys = $getVsys->fetch_assoc() )
        {
            $ispanorama = $theVsys['ispanorama'];

            #get from nats
            $getFromNat = $projectdb->query("SELECT op_service_lid,op_service_table,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE source='$source';");
            while( $DATA = $getFromNat->fetch_assoc() )
            {
                $op_service_lid = $DATA['op_service_lid'];
                $op_service_table = $DATA['op_service_table'];
                $tp_dat_address_lid = $DATA['tp_dat_address_lid'];
                $tp_dat_address_table = $DATA['tp_dat_address_table'];
                if( ($op_service_lid != "") and ($op_service_table != "") )
                {
                    if( $op_service_table == "services" )
                    {
                        $array_services[] = $op_service_lid;
                    }
                    elseif( $op_service_table == "services_groups_id" )
                    {
                        $array_services_groups[] = $op_service_lid;
                    }
                }
                if( ($tp_dat_address_lid != "") and ($tp_dat_address_table != "") )
                {
                    if( $tp_dat_address_table == "address" )
                    {
                        $array_address[] = $tp_dat_address_lid;
                    }
                    elseif( $tp_dat_address_table == "address_groups_id" )
                    {
                        $array_address_groups[] = $tp_dat_address_lid;
                    }
                }
            }

            // Search in Interfaces
            $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE source = '$source' AND unitipaddress != '';");

            if( $getInterface->num_rows > 0 )
            {

                while( $dataI = $getInterface->fetch_array() )
                {

                    $all_interfaces = $dataI['unitipaddress'];
                    $interfaces_exp = explode(",", $all_interfaces);

                    foreach( $interfaces_exp as $name_int )
                    {

                        $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "address");

                        if( $get_mem_table != "" )
                        {
                            $member_id = $get_mem_table["member_lid"];
                            $table_name = $get_mem_table["table_name"];
                            if( $table_name == "address" )
                            {
                                $array_address[] = $member_id;
                            }
                            elseif( $table_name == "address_groups_id" )
                            {
                                $array_address_groups[] = $member_id;
                            }
                        }
                    }
                }
            }

            // Search in Zones
            $getZones = $projectdb->query("SELECT include_list, exclude_list FROM zones WHERE source = '$source' AND (include_list != '' OR exclude_list != '');");

            if( $getZones->num_rows > 0 )
            {

                while( $dataZ = $getZones->fetch_array() )
                {

                    $all_include_list = $dataZ['include_list'];
                    $all_exclude_list = $dataZ['exclude_list'];
                    $incl_exp = explode(",", $all_include_list);
                    $exc_exp = explode(",", $all_exclude_list);
                    $final_zone = array_merge($incl_exp, $exc_exp);

                    foreach( $final_zone as $name_int )
                    {

                        $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "address");

                        if( $get_mem_table != "" )
                        {
                            $member_id = $get_mem_table["member_lid"];
                            $table_name = $get_mem_table["table_name"];
                            if( $table_name == "address" )
                            {
                                $array_address[] = $member_id;
                            }
                            elseif( $table_name == "address_groups_id" )
                            {
                                $array_address_groups[] = $member_id;
                            }
                        }
                    }
                }
            }

            // Search in other_rules, xml
            $getOtherRules = $projectdb->query("SELECT xml FROM other_rules WHERE source = '$source';");

            if( $getOtherRules->num_rows > 0 )
            {

                $other_rules_address = array();
                $other_rules_services = array();
                $other_rules_tag = array();

                while( $dataO = $getOtherRules->fetch_array() )
                {

                    $xml_bbdd = $dataO['xml'];
                    $xml = simplexml_load_string($xml_bbdd);

                    foreach( $xml as $data )
                    {
                        if( isset($data->source) )
                        {
                            foreach( $data->source->member as $member )
                            {
                                if( $member != "any" )
                                {
                                    $other_rules_address[] = $member;
                                }
                            }
                        }
                        if( isset($data->destination) )
                        {
                            foreach( $data->destination->member as $member )
                            {
                                if( $member != "any" )
                                {
                                    $other_rules_address[] = $member;
                                }
                            }
                        }
                        if( isset($data->service) )
                        {
                            foreach( $data->service->member as $member )
                            {
                                if( $member != "any" )
                                {
                                    $other_rules_services[] = $member;
                                }
                            }
                        }

                        if( isset($data->tag) )
                        {
                            foreach( $data->tag->member as $member )
                            {
                                if( $member != "any" )
                                {
                                    $other_rules_tag[] = $member;
                                }
                            }
                        }
                    }
                }

                $other_rules_address = array_unique($other_rules_address);

                foreach( $other_rules_address as $name_int )
                {
                    $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "address");
                    if( $get_mem_table != "" )
                    {
                        $member_id = $get_mem_table["member_lid"];
                        $table_name = $get_mem_table["table_name"];
                        if( $table_name == "address" )
                        {
                            $array_address[] = $member_id;
                        }
                        elseif( $table_name == "address_groups_id" )
                        {
                            $array_address_groups[] = $member_id;
                        }
                    }
                }

                $other_rules_services = array_unique($other_rules_services);

                foreach( $other_rules_services as $name_int )
                {
                    $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "service");
                    if( $get_mem_table != "" )
                    {
                        $member_id = $get_mem_table["member_lid"];
                        $table_name = $get_mem_table["table_name"];
                        if( $table_name == "services" )
                        {
                            $array_services[] = $member_id;
                        }
                        elseif( $table_name == "services_groups_id" )
                        {
                            $array_services_groups[] = $member_id;
                        }
                    }
                }
            }

            #get from appoverride rules app
            $getFromNat = $projectdb->query("SELECT app_id, app_table FROM appoverride_rules WHERE source='$source';");
            while( $DATA = $getFromNat->fetch_assoc() )
            {
                $app_id = $DATA['app_id'];
                $app_table = $DATA['app_table'];
                if( ($app_id != "") and ($app_table != "") )
                {
                    if( $app_table == "applications" )
                    {
                        $array_applications[] = $app_id;
                    }
                    elseif( $app_table == "applications_groups_id" )
                    {
                        $array_applications_groups[] = $app_id;
                    }
                    elseif( $app_table == "applications_filters" )
                    {
                        $array_applications_filters[] = $app_id;
                    }
                    elseif( $app_table == "default_applications" )
                    {
                        $array_default_applications[] = $app_id;
                    }
                }
            }

            #Panos 8
            # Check in Static Routes Path Monitoring
            $getStatic = $projectdb->query("SELECT dst_member_lid FROM routes_static_monitor_destinations;");
            if( $getStatic->num_rows > 0 )
            {
                while( $getStaticData = $getStatic->fetch_assoc() )
                {
                    $array_address[] = $getStaticData['dst_member_lid'];
                }
            }

            # Check on tag_relations
            $getTagRelations = $projectdb->query("SELECT DISTINCT(tr.tag_id) FROM tag_relations tr, tag t WHERE t.id = tr.tag_id AND t.source = '$source';");

            if( $getTagRelations->num_rows > 0 )
            {
                while( $dataTR = $getTagRelations->fetch_array() )
                {
                    $array_tag[] = $dataTR['tag_id'];
                }
            }

        }

        if( count($array_address) > 0 )
        {
            $unique = array_unique($array_address);
            $projectdb->query("UPDATE address SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_address_groups) > 0 )
        {
            $unique = array_unique($array_address_groups);
            $projectdb->query("UPDATE address_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_services) > 0 )
        {
            $unique = array_unique($array_services);
            $projectdb->query("UPDATE services SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_services_groups) > 0 )
        {
            $unique = array_unique($array_services_groups);
            $projectdb->query("UPDATE services_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_regions) > 0 )
        {
            $unique = array_unique($array_regions);
            $projectdb->query("UPDATE regions SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_default_regions) > 0 )
        {
            $unique = array_unique($array_default_regions);
            $projectdb->query("UPDATE default_regions SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_applications) > 0 )
        {
            $unique = array_unique($array_applications);
            $projectdb->query("UPDATE applications SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_applications_groups) > 0 )
        {
            $unique = array_unique($array_applications_groups);
            $projectdb->query("UPDATE applications_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_applications_filters) > 0 )
        {
            $unique = array_unique($array_applications_filters);
            $projectdb->query("UPDATE applications_filters SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_default_applications) > 0 )
        {
            $unique = array_unique($array_default_applications);
            $projectdb->query("UPDATE default_applications SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_tag) > 0 )
        {
            $unique = array_unique($array_tag);
            $projectdb->query("UPDATE tag SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        # Calculate nested Groups Used
        $mytables = array();
        $mytables[] = array("tablename" => "address_groups_id", "tablename2" => "address_groups");
        $mytables[] = array("tablename" => "services_groups_id", "tablename2" => "services_groups");
        $mytables[] = array("tablename" => "applications_groups_id", "tablename2" => "applications_groups");

        foreach( $mytables as $thekey => $thevalue )
        {
            $tablename = $mytables[$thekey]['tablename'];
            $tablename2 = $mytables[$thekey]['tablename2'];
            $name = array();
            $setused = array();
            $getGR = $projectdb->query("SELECT id,name FROM $tablename WHERE used='1' AND checkit='0'");
            if( $getGR->num_rows > 0 )
            {
                while( $data = $getGR->fetch_assoc() )
                {
                    $lid = $data['id'];
                    $name[] = array("id" => $data['id']);
                }
            }

            $x = 0;
            $alreadyseen = array();
            while( count($name) > 0 )
            {
                $grplid = $name[$x]['id'];
                $getMember = $projectdb->query("SELECT table_name,member_lid FROM $tablename2 WHERE lid='$grplid';");
                if( $getMember->num_rows > 0 )
                {
                    while( $data2 = $getMember->fetch_assoc() )
                    {
                        $member_lid = $data2['member_lid'];
                        $table_name = $data2['table_name'];
                        if( $table_name == $tablename )
                        {
                            if( !in_array($member_lid, $alreadyseen) )
                            {
                                $name[] = array("id" => $data2['member_lid']);
                                $setused[$table_name][] = $member_lid;
                                $alreadyseen[] = $member_lid;
                            }
                        }
                        else
                        {
                            $setused[$table_name][] = $member_lid;
                        }
                    }
                }
                unset($name[$x]);
                $x++;
            }
            foreach( $setused as $key => $value )
            {
                $unique_tablename = array_unique($value);
                $projectdb->query("UPDATE $key SET used=1 WHERE id IN (" . implode(',', $unique_tablename) . ");");
            }
        }

        $start = 0;
        $end = 1;
        while( $start != $end )
        {
            #Check for Dynamic Address Groups based on Tags
            $getDyn = $projectdb->query("SELECT id,filter,source,vsys FROM address_groups_id WHERE used='1' AND checkit='0' AND type='dynamic' AND filter!='';");
            $start1 = $getDyn->num_rows;
            if( $getDyn->num_rows > 0 )
            {
                while( $getDyndata = $getDyn->fetch_assoc() )
                {
                    $filter = $getDyndata['filter'];
                    $new_sql = generate_sql_query_bytag($filter);
                    //$filter = str_replace("'", "", $filter);
                    $lid = $getDyndata['id'];
                    $source = $getDyndata['source'];
                    $vsys = $getDyndata['vsys'];

                    #Update Address
                    $projectdb->query("UPDATE address SET used=1 WHERE source='$source' AND vsys='$vsys' $new_sql;");

                    #Update Address_groups_id
                    $projectdb->query("UPDATE address_groups_id SET used=1 WHERE source='$source' AND vsys='$vsys' $new_sql;");

                }
            }

            $start = $start1;
            # Calculate nested Groups Used after tags
            $mytables = array();
            $mytables[] = array("tablename" => "address_groups_id", "tablename2" => "address_groups");

            foreach( $mytables as $thekey => $thevalue )
            {
                $tablename = $mytables[$thekey]['tablename'];
                $tablename2 = $mytables[$thekey]['tablename2'];
                $name = array();
                $setused = array();
                $getGR = $projectdb->query("SELECT id,name FROM $tablename WHERE used='1' AND checkit='0'");
                if( $getGR->num_rows > 0 )
                {
                    while( $data = $getGR->fetch_assoc() )
                    {
                        $lid = $data['id'];
                        $name[] = array("id" => $data['id']);
                    }
                }

                $x = 0;
                $alreadyseen = array();
                while( count($name) > 0 )
                {
                    $grplid = $name[$x]['id'];
                    $getMember = $projectdb->query("SELECT table_name,member_lid FROM $tablename2 WHERE lid='$grplid'");
                    if( $getMember->num_rows > 0 )
                    {
                        while( $data2 = $getMember->fetch_assoc() )
                        {
                            $member_lid = $data2['member_lid'];
                            $table_name = $data2['table_name'];
                            if( $table_name == $tablename )
                            {
                                if( !in_array($member_lid, $alreadyseen) )
                                {
                                    $name[] = array("id" => $data2['member_lid']);
                                    $setused[$table_name][] = $member_lid;
                                    $alreadyseen[] = $member_lid;
                                }
                            }
                            else
                            {
                                $setused[$table_name][] = $member_lid;
                            }
                        }
                    }
                    unset($name[$x]);
                    $x++;
                }
                foreach( $setused as $key => $value )
                {
                    $unique_tablename = array_unique($value);
                    $projectdb->query("UPDATE $key SET used=1 WHERE id IN (" . implode(',', $unique_tablename) . ");");
                }
            }

            #calc end
            $getDyn = $projectdb->query("SELECT id,filter,source,vsys FROM address_groups_id WHERE used='1' AND checkit='0' AND type='dynamic' AND filter!='';");
            $end1 = $getDyn->num_rows;
            $end = $end1;
        }

    }


}

/***
 * Returns the name of the selected database
 * @param Mysqli $projectdb
 * @return string
 */
function getProjectName(Mysqli $projectdb): string
{
    $query = "SELECT database() AS the_db";
    $result = $projectdb->query($query);
    if( $result->num_rows > 0 )
    {
        $data = $result->fetch_assoc();
        $projectName = $data['the_db'];
    }
    else
    {
        $projectName = '';
    }
    return $projectName;
}

function check_used_objects_new(array $sources = [])
{

    global $projectdb;

    $array_address = array();
    $array_address_groups = array();
    $array_services = array();
    $array_services_groups = array();
    $array_regions = array();
    $array_default_regions = array();
    $array_applications = array();
    $array_applications_groups = array();
    $array_applications_filters = array();
    $array_default_applications = array();
    $array_tag = array();

    if( count($sources) > 0 )
    {
        $sourceScope = implode(", ", $sources);
        $sourceScopeWhere = " WHERE source in ($sourceScope) ";
        $sourceScopeAnd = " AND source in ($sourceScope) ";
        $sourceScopeIDWhere = " WHERE id in ($sourceScope) ";
        $sourceScopeIDAnd = " AND id in ($sourceScope) ";
        $sourceScopeIDAndTable = "AND relation.member_lid=a.id AND a.source in ($sourceScope)";

    }
    else
    {
        $sourceScopeWhere = '';
        $sourceScopeAnd = '';
        $sourceScopeIDWhere = '';
        $sourceScopeIDAnd = '';
        $sourceScopeIDAndTable = '';
    }


//    $FILE = array();
//    $FILE[] = "security_rules_src";
//    $FILE[] = "security_rules_dst";
//    $FILE[] = "security_rules_srv";
//    $FILE[] = "security_rules_app";
//    $FILE[] = "security_rules_tag";
//    $FILE[] = "nat_rules_src";
//    $FILE[] = "nat_rules_dst";
//    $FILE[] = "nat_rules_translated_address";
//    $FILE[] = "nat_rules_translated_address_fallback";
//    $FILE[] = "nat_rules_tag";
//    $FILE[] = "appoverride_rules_dst";
//    $FILE[] = "appoverride_rules_src";
//    $FILE[] = "appoverride_rules_tag";
//
//    # NEW OTHER RULES
//    $FILE[] = "authentication_rules_src";
//    $FILE[] = "authentication_rules_dst";
//    $FILE[] = "authentication_rules_srv";
//    $FILE[] = "authentication_rules_tag";
//    $FILE[] = "decryption_rules_dst";
//    $FILE[] = "decryption_rules_src";
//    $FILE[] = "decryption_rules_srv";
//    $FILE[] = "decryption_rules_tag";
//    $FILE[] = "dos_rules_dst";
//    $FILE[] = "dos_rules_src";
//    $FILE[] = "dos_rules_srv";
//    $FILE[] = "dos_rules_tag";
//    $FILE[] = "pbf_rules_src";
//    $FILE[] = "pbf_rules_dst";
//    $FILE[] = "pbf_rules_app";
//    $FILE[] = "pbf_rules_srv";
//    $FILE[] = "pbf_rules_tag";
//    $FILE[] = "qos_rules_dst";
//    $FILE[] = "qos_rules_src";
//    $FILE[] = "qos_rules_srv";
//    $FILE[] = "qos_rules_app";
//    $FILE[] = "qos_rules_tag";
//    $FILE[] = "tunnel_inspect_rules_dst";
//    $FILE[] = "tunnel_inspect_rules_src";
//    $FILE[] = "tunnel_inspect_rules_app";
//    $FILE[] = "tunnel_inspect_rules_tag";
//    $FILE[] = "captiveportal_rules_dst";
//    $FILE[] = "captiveportal_rules_src";
//    $FILE[] = "captiveportal_rules_srv";
//    $FILE[] = "captiveportal_rules_tag";


    $FILE_ADDRESS = array();
    $FILE_SERVICES = array();
    $FILE_APPLICATIONS = array();
    $FILE_TAGS = array();
    $FILE_ADDRESS[] = "security_rules_src";
    $FILE_ADDRESS[] = "security_rules_dst";
    $FILE_SERVICES[] = "security_rules_srv";
    $FILE_APPLICATIONS[] = "security_rules_app";
    $FILE_TAGS[] = "security_rules_tag";
    $FILE_ADDRESS[] = "nat_rules_src";
    $FILE_ADDRESS[] = "nat_rules_dst";
    $FILE_ADDRESS[] = "nat_rules_translated_address";
    $FILE_ADDRESS[] = "nat_rules_translated_address_fallback";
    $FILE_TAGS[] = "nat_rules_tag";
    $FILE_ADDRESS[] = "appoverride_rules_dst";
    $FILE_ADDRESS[] = "appoverride_rules_src";
    $FILE_TAGS[] = "appoverride_rules_tag";

    # NEW OTHER RULES
    $FILE_ADDRESS[] = "authentication_rules_src";
    $FILE_ADDRESS[] = "authentication_rules_dst";
    $FILE_SERVICES[] = "authentication_rules_srv";
    $FILE_TAGS[] = "authentication_rules_tag";
    $FILE_ADDRESS[] = "decryption_rules_dst";
    $FILE_ADDRESS[] = "decryption_rules_src";
    $FILE_SERVICES[] = "decryption_rules_srv";
    $FILE_TAGS[] = "decryption_rules_tag";
    $FILE_ADDRESS[] = "dos_rules_dst";
    $FILE_ADDRESS[] = "dos_rules_src";
    $FILE_SERVICES[] = "dos_rules_srv";
    $FILE_TAGS[] = "dos_rules_tag";
    $FILE_ADDRESS[] = "pbf_rules_src";
    $FILE_ADDRESS[] = "pbf_rules_dst";
    $FILE_APPLICATIONS[] = "pbf_rules_app";
    $FILE_SERVICES[] = "pbf_rules_srv";
    $FILE_TAGS[] = "pbf_rules_tag";
    $FILE_ADDRESS[] = "qos_rules_dst";
    $FILE_ADDRESS[] = "qos_rules_src";
    $FILE_SERVICES[] = "qos_rules_srv";
    $FILE_APPLICATIONS[] = "qos_rules_app";
    $FILE_TAGS[] = "qos_rules_tag";
    $FILE_ADDRESS[] = "tunnel_inspect_rules_dst";
    $FILE_ADDRESS[] = "tunnel_inspect_rules_src";
    $FILE_APPLICATIONS[] = "tunnel_inspect_rules_app";
    $FILE_TAGS[] = "tunnel_inspect_rules_tag";
    $FILE_ADDRESS[] = "captiveportal_rules_dst";
    $FILE_ADDRESS[] = "captiveportal_rules_src";
    $FILE_SERVICES[] = "captiveportal_rules_srv";
    $FILE_TAGS[] = "captiveportal_rules_tag";


    //$FILE[] = "tag_relations";

    #Clean all Used Objects
    $projectdb->query("UPDATE address SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE services SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE address_groups_id SET used='0',checkit='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE services_groups_id SET used='0',checkit='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE applications SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE applications_groups_id SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE applications_filters SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE default_applications SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE regions SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE default_regions SET used='0' $sourceScopeWhere;");
    $projectdb->query("UPDATE tag SET used='0' $sourceScopeWhere;");


    foreach( $FILE_ADDRESS as $key => $value )
    {
        $DATA = $projectdb->query(
            "SELECT member_lid,table_name 
            FROM $value relation,
                 address a 
            WHERE table_name = 'address' $sourceScopeIDAndTable
            GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_address[] = $member_id;
            }
        }
    }

    foreach( $FILE_ADDRESS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
            FROM $value relation,
            address_groups_id a 
            WHERE table_name = 'address_groups_id' $sourceScopeIDAndTable
            GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_address_groups[] = $member_id;
            }
        }
    }

    foreach( $FILE_SERVICES as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
              services a
              WHERE table_name = 'services' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_services[] = $member_id;
            }
        }
    }

    foreach( $FILE_SERVICES as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                  services_groups_id a
              WHERE table_name = 'services_groups_id' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_services_groups[] = $member_id;
            }
        }
    }

    foreach( $FILE_ADDRESS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   regions a
              WHERE table_name = 'regions' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_regions[] = $member_id;
            }
        }
    }

    foreach( $FILE_ADDRESS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value 
              WHERE table_name = 'default_regions' 
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_default_regions[] = $member_id;
            }
        }
    }

    foreach( $FILE_APPLICATIONS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   applications a
              WHERE table_name = 'applications' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_applications[] = $member_id;
            }
        }
    }

    foreach( $FILE_APPLICATIONS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   applications_groups_id a
              WHERE table_name = 'applications_groups_id' $sourceScopeIDAndTable  
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_applications_groups[] = $member_id;
            }
        }
    }

    foreach( $FILE_APPLICATIONS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   applications_filters a
              WHERE table_name = 'applications_filters' $sourceScopeIDAndTable  
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_applications_filters[] = $member_id;
            }
        }
    }

    foreach( $FILE_APPLICATIONS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value 
              WHERE table_name = 'default_applications'   
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_default_applications[] = $member_id;
            }
        }
    }

    foreach( $FILE_TAGS as $key => $value )
    {
        $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   tag a
              WHERE table_name = 'tag'   $sourceScopeIDAndTable
              GROUP BY member_lid,table_name;");
        if( $DATA->num_rows > 0 )
        {
            while( $getRuleSourceData = $DATA->fetch_array() )
            {
                $member_id = $getRuleSourceData["member_lid"];
                $array_tag[] = $member_id;
            }
        }
    }

    $getVsys = $projectdb->query("SELECT id,filename FROM device_mapping $sourceScopeIDWhere GROUP BY filename;");
    if( $getVsys->num_rows > 0 )
    {

        while( $theVsys = $getVsys->fetch_assoc() )
        {
            $filename = $theVsys['filename'];
            $source = $theVsys['id'];
            $getVsysAll = $projectdb->query("SELECT vsys FROM device_mapping WHERE filename='$filename' $sourceScopeIDAnd;");

            while( $data = $getVsysAll->fetch_assoc() )
            {
                $vsys = $data['vsys'];
                $addVsys = " AND vsys='$vsys'";

                #get from nats
                $getFromNat = $projectdb->query("SELECT op_service_lid,op_service_table,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE source='$source' AND vsys='$vsys';");
                while( $DATA = $getFromNat->fetch_assoc() )
                {
                    $op_service_lid = $DATA['op_service_lid'];
                    $op_service_table = $DATA['op_service_table'];
                    $tp_dat_address_lid = $DATA['tp_dat_address_lid'];
                    $tp_dat_address_table = $DATA['tp_dat_address_table'];
                    if( ($op_service_lid != "") and ($op_service_table != "") )
                    {
                        if( $op_service_table == "services" )
                        {
                            $array_services[] = $op_service_lid;
                        }
                        elseif( $op_service_table == "services_groups_id" )
                        {
                            $array_services_groups[] = $op_service_lid;
                        }
                    }
                    if( ($tp_dat_address_lid != "") and ($tp_dat_address_table != "") )
                    {
                        if( $tp_dat_address_table == "address" )
                        {
                            $array_address[] = $tp_dat_address_lid;
                        }
                        elseif( $tp_dat_address_table == "address_groups_id" )
                        {
                            $array_address_groups[] = $tp_dat_address_lid;
                        }
                    }
                }

                // Search in Interfaces
                $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE source = '$source' $addVsys AND unitipaddress != '';");

                if( $getInterface->num_rows > 0 )
                {

                    while( $dataI = $getInterface->fetch_array() )
                    {

                        $all_interfaces = $dataI['unitipaddress'];
                        $interfaces_exp = explode(",", $all_interfaces);

                        foreach( $interfaces_exp as $name_int )
                        {

                            $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "address");

                            if( $get_mem_table != "" )
                            {
                                $member_id = $get_mem_table["member_lid"];
                                $table_name = $get_mem_table["table_name"];
                                if( $table_name == "address" )
                                {
                                    $array_address[] = $member_id;
                                }
                                elseif( $table_name == "address_groups_id" )
                                {
                                    $array_address_groups[] = $member_id;
                                }
                            }
                        }
                    }
                }

                // Search in Zones
                $getZones = $projectdb->query("SELECT include_list, exclude_list FROM zones WHERE source = '$source' $addVsys AND (include_list != '' OR exclude_list != '');");

                if( $getZones->num_rows > 0 )
                {

                    while( $dataZ = $getZones->fetch_array() )
                    {

                        $all_include_list = $dataZ['include_list'];
                        $all_exclude_list = $dataZ['exclude_list'];
                        $incl_exp = explode(",", $all_include_list);
                        $exc_exp = explode(",", $all_exclude_list);
                        $final_zone = array_merge($incl_exp, $exc_exp);

                        foreach( $final_zone as $name_int )
                        {

                            $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "address");

                            if( $get_mem_table != "" )
                            {
                                $member_id = $get_mem_table["member_lid"];
                                $table_name = $get_mem_table["table_name"];
                                if( $table_name == "address" )
                                {
                                    $array_address[] = $member_id;
                                }
                                elseif( $table_name == "address_groups_id" )
                                {
                                    $array_address_groups[] = $member_id;
                                }
                            }
                        }
                    }
                }

                #get from appoverride rules app
                $getFromNat = $projectdb->query("SELECT app_id, app_table FROM appoverride_rules WHERE source='$source' AND vsys='$vsys';");
                //echo "2. SELECT app_id, app_table FROM appoverride_rules WHERE source='$source' AND vsys='$vsys';\n";
                while( $DATA = $getFromNat->fetch_assoc() )
                {
                    $app_id = $DATA['app_id'];
                    $app_table = $DATA['app_table'];
                    if( ($app_id != "") and ($app_table != "") )
                    {
                        if( $app_table == "applications" )
                        {
                            $array_applications[] = $app_id;
                        }
                        elseif( $app_table == "applications_groups_id" )
                        {
                            $array_applications_groups[] = $app_id;
                        }
                        elseif( $app_table == "applications_filters" )
                        {
                            $array_applications_filters[] = $app_id;
                        }
                        elseif( $app_table == "default_applications" )
                        {
                            $array_default_applications[] = $app_id;
                        }
                    }
                }

                #Panos 8
                # Check in Static Routes Path Monitoring
                $getStatic = $projectdb->query("SELECT dst_member_lid FROM routes_static_monitor_destinations;");
                if( $getStatic->num_rows > 0 )
                {
                    while( $getStaticData = $getStatic->fetch_assoc() )
                    {
                        $array_address[] = $getStaticData['dst_member_lid'];
                    }
                }

                # Check on tag_relations
                $getTagRelations = $projectdb->query("SELECT DISTINCT(tr.tag_id) FROM tag_relations tr, tag t WHERE t.id = tr.tag_id AND t.source = '$source' AND t.vsys = '$vsys';");

                if( $getTagRelations->num_rows > 0 )
                {
                    while( $dataTR = $getTagRelations->fetch_array() )
                    {
                        $array_tag[] = $dataTR['tag_id'];
                    }
                }
            }
        }

        //echo "ADDRESS: \n";
        //print_r($array_address);
        //echo "El count: ".count($array_address)."";

        if( count($array_address) > 0 )
        {
            $unique = array_unique($array_address);
            //echo "EL UNIQUE DEL ADDRESS \n";
            //print_r($unique);
            //echo "El count unique: ".count($unique)."";

            $projectdb->query("UPDATE address SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            //echo "1. UPDATE address SET used='1' WHERE id IN (" . implode(',', $unique) . ")\n";
        }

        //echo "ADDRESS GROUPS: \n";
        //print_r($array_address_groups);
        if( count($array_address_groups) > 0 )
        {
            $unique = array_unique($array_address_groups);
            $projectdb->query("UPDATE address_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        //echo "SERVICES: \n";
        //print_r($array_services);
        if( count($array_services) > 0 )
        {
            $unique = array_unique($array_services);
            //echo "UNIQUE de SERVICES: \n";
            //print_r($unique);
            $projectdb->query("UPDATE services SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        //echo "SERVICES GROUPS ID: \n";
        //print_r($array_services_groups);
        if( count($array_services_groups) > 0 )
        {
            $unique = array_unique($array_services_groups);
            $projectdb->query("UPDATE services_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_regions) > 0 )
        {
            $unique = array_unique($array_regions);
            $projectdb->query("UPDATE regions SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_default_regions) > 0 )
        {
            $unique = array_unique($array_default_regions);
            $projectdb->query("UPDATE default_regions SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        //echo "APPLICATIONS: ";
        //print_r($array_applications);
        if( count($array_applications) > 0 )
        {
            $unique = array_unique($array_applications);
            $projectdb->query("UPDATE applications SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_applications_groups) > 0 )
        {
            $unique = array_unique($array_applications_groups);
            $projectdb->query("UPDATE applications_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_applications_filters) > 0 )
        {
            $unique = array_unique($array_applications_filters);
            $projectdb->query("UPDATE applications_filters SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_default_applications) > 0 )
        {
            $unique = array_unique($array_default_applications);
            $projectdb->query("UPDATE default_applications SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        if( count($array_tag) > 0 )
        {
            $unique = array_unique($array_tag);
            $projectdb->query("UPDATE tag SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
        }

        # Calculate nested Groups Used
        $mytables = array();
        $mytables[] = array("tablename" => "address_groups_id", "tablename2" => "address_groups");
        $mytables[] = array("tablename" => "services_groups_id", "tablename2" => "services_groups");
        $mytables[] = array("tablename" => "applications_groups_id", "tablename2" => "applications_groups");

        foreach( $mytables as $thekey => $thevalue )
        {
            $tablename = $mytables[$thekey]['tablename'];
            $tablename2 = $mytables[$thekey]['tablename2'];
            $name = array();
            $setused = array();
            $getGR = $projectdb->query("SELECT id,name FROM $tablename WHERE used='1' AND checkit='0' $sourceScopeAnd;");
            if( $getGR->num_rows > 0 )
            {
                while( $data = $getGR->fetch_assoc() )
                {
                    $lid = $data['id'];
                    $name[] = array("id" => $data['id']);
                }
            }

            $x = 0;
            $alreadyseen = array();
            while( count($name) > 0 )
            {
                $grplid = $name[$x]['id'];
                $getMember = $projectdb->query("SELECT table_name,member_lid FROM $tablename2 WHERE lid='$grplid';");
                if( $getMember->num_rows > 0 )
                {
                    while( $data2 = $getMember->fetch_assoc() )
                    {
                        $member_lid = $data2['member_lid'];
                        $table_name = $data2['table_name'];
                        if( $table_name == $tablename )
                        {
                            if( !in_array($member_lid, $alreadyseen) )
                            {
                                $name[] = array("id" => $data2['member_lid']);
                                $setused[$table_name][] = $member_lid;
                                $alreadyseen[] = $member_lid;
                            }
                        }
                        else
                        {
                            $setused[$table_name][] = $member_lid;
                        }
                    }
                }
                unset($name[$x]);
                $x++;
            }
            foreach( $setused as $key => $value )
            {
                $unique_tablename = array_unique($value);
                $projectdb->query("UPDATE $key SET used=1 WHERE id IN (" . implode(',', $unique_tablename) . ");");
            }
        }

        $start = 0;
        $end = 1;
        while( $start != $end )
        {
            #Check for Dynamic Address Groups based on Tags
            $getDyn = $projectdb->query("SELECT id,filter,source,vsys FROM address_groups_id WHERE used='1' AND checkit='0' AND type='dynamic' AND filter!='' $sourceScopeAnd;");
            $start1 = $getDyn->num_rows;
            if( $getDyn->num_rows > 0 )
            {
                while( $getDyndata = $getDyn->fetch_assoc() )
                {
                    $filter = $getDyndata['filter'];
                    $new_sql = generate_sql_query_bytag($filter);
                    //$filter = str_replace("'", "", $filter);
                    $lid = $getDyndata['id'];
                    $source = $getDyndata['source'];
                    $vsys = $getDyndata['vsys'];

                    #Update Address
                    $projectdb->query("UPDATE address SET used=1 WHERE source='$source' AND vsys='$vsys' $new_sql;");

                    #Update Address_groups_id
                    $projectdb->query("UPDATE address_groups_id SET used=1 WHERE source='$source' AND vsys='$vsys' $new_sql;");

                }
            }

            $start = $start1;
            # Calculate nested Groups Used after tags
            $mytables = array();
            $mytables[] = array("tablename" => "address_groups_id", "tablename2" => "address_groups");

            foreach( $mytables as $thekey => $thevalue )
            {
                $tablename = $mytables[$thekey]['tablename'];
                $tablename2 = $mytables[$thekey]['tablename2'];
                $name = array();
                $setused = array();
                $getGR = $projectdb->query("SELECT id,name FROM $tablename WHERE used='1' AND checkit='0' $sourceScopeAnd;");
                if( $getGR->num_rows > 0 )
                {
                    while( $data = $getGR->fetch_assoc() )
                    {
                        $lid = $data['id'];
                        $name[] = array("id" => $data['id']);
                    }
                }

                $x = 0;
                $alreadyseen = array();
                while( count($name) > 0 )
                {
                    $grplid = $name[$x]['id'];
                    $getMember = $projectdb->query("SELECT table_name,member_lid FROM $tablename2 WHERE lid='$grplid';");
                    if( $getMember->num_rows > 0 )
                    {
                        while( $data2 = $getMember->fetch_assoc() )
                        {
                            $member_lid = $data2['member_lid'];
                            $table_name = $data2['table_name'];
                            if( $table_name == $tablename )
                            {
                                if( !in_array($member_lid, $alreadyseen) )
                                {
                                    $name[] = array("id" => $data2['member_lid']);
                                    $setused[$table_name][] = $member_lid;
                                    $alreadyseen[] = $member_lid;
                                }
                            }
                            else
                            {
                                $setused[$table_name][] = $member_lid;
                            }
                        }
                    }
                    unset($name[$x]);
                    $x++;
                }
                foreach( $setused as $key => $value )
                {
                    $unique_tablename = array_unique($value);
                    $projectdb->query("UPDATE $key SET used=1 WHERE id IN (" . implode(',', $unique_tablename) . ");");
                }
            }

            #calc end
            $getDyn = $projectdb->query("SELECT id,filter,source,vsys FROM address_groups_id WHERE used='1' AND checkit='0' AND type='dynamic' AND filter!='' $sourceScopeAnd;");
            $end1 = $getDyn->num_rows;
            $end = $end1;
        }

    }
}

function generate_sql_query_bytag($filter)
{
    $filter_string = "";
    if( $filter != "" )
    {
        $filter_split = explode(" ", $filter);
        $filter_string = "AND (";
        foreach( $filter_split as $key => $value )
        {
            if( preg_match("/^'/", $value) )
            {
                $filter_no_quote = str_replace("'", "", $value);
                $filter_string .= "(tag = '" . $filter_no_quote . "' OR tag LIKE '" . $filter_no_quote . ",%' OR tag LIKE '%," . $filter_no_quote . ",%' OR tag LIKE '%," . $filter_no_quote . "')";
            }
            else
            {
                if( strtolower($value) == "or" )
                {
                    $filter_string .= " OR ";
                }
                elseif( strtolower($value) == "and" )
                {
                    $filter_string .= " AND ";
                }
            }
        }
        $filter_string .= ")";
    }

    return $filter_string;
}

function set_used_object($member_lid, $table_name)
{
    global $projectdb;
    $projectdb->query("UPDATE $table_name SET used=1 WHERE id='$member_lid';");
}

function set_used_group($member_lid, $table_name)
{
    global $projectdb;
    $getMember = $projectdb->query("SELECT member_lid,table_name FROM $table_name WHERE lid='$member_lid';");
    if( $getMember->num_rows > 0 )
    {
        while( $data = $getMember->fetch_assoc() )
        {
            $new_member_lid = $data['member_lid'];
            $new_table_name = $data['table_name'];

            if( $new_table_name == "address_groups_id" )
            {
                $new_table_name2 = "address_groups";
            }
            elseif( $new_table_name == "services_groups_id" )
            {
                $new_table_name2 = "services_groups";
            }

            if( preg_match("/_id/", $new_table_name) )
            {

                set_used_group($new_member_lid, $new_table_name2);
            }
            else
            {
                $projectdb->query("UPDATE $new_table_name SET used=1 WHERE id='$new_member_lid';");
            }
        }
    }
}

function check_used_objects_in_groups($projectdb, $member_lid, $table_name, $table_name_group)
{

    $is_used = 0;

    $getMember = $projectdb->query("SELECT id FROM $table_name_group WHERE member_lid = '$member_lid' AND table_name = '$table_name';");


    if( $getMember->num_rows > 0 )
    {
        $is_used = 1;
    }

    return $is_used;

}

function rename_interface_unit($originalname, $newname, $source, $template)
{
    global $projectdb;
    global $project;
    take_snapshot_last($project);

    #Modify Virtual Routers
    $getVR = $projectdb->query("SELECT id,interfaces FROM virtual_routers WHERE source='$source' AND template='$template' AND interfaces LIKE '%$originalname%';");
    if( $getVR->num_rows > 0 )
    {
        while( $mdata = $getVR->fetch_assoc() )
        {
            $vrid = $mdata['id'];
            $vrinterfaces = explode(",", $mdata['interfaces']);
            $newInterfaces = array();
            foreach( $vrinterfaces as $key => $value )
            {
                if( $value == $originalname )
                {
                    $newInterfaces[] = $newname;
                }
                else
                {
                    $newInterfaces[] = $value;
                }
            }
            $unique = array_unique($newInterfaces);
            $vrinterfaces = implode(",", $unique);
            $projectdb->query("UPDATE virtual_routers SET interfaces='$vrinterfaces' WHERE id='$vrid';");
        }
    }
    #Modify VSYS
    $getVR = $projectdb->query("SELECT id,interfaces FROM virtual_systems WHERE source='$source' AND template='$template' AND interfaces LIKE '%$originalname%';");
    if( $getVR->num_rows > 0 )
    {
        while( $mdata = $getVR->fetch_assoc() )
        {
            $vrid = $mdata['id'];
            $vrinterfaces = explode(",", $mdata['interfaces']);
            $newInterfaces = array();
            foreach( $vrinterfaces as $key => $value )
            {
                if( $value == $originalname )
                {
                    $newInterfaces[] = $newname;
                }
                else
                {
                    $newInterfaces[] = $value;
                }
            }
            $unique = array_unique($newInterfaces);
            $vrinterfaces = implode(",", $unique);
            $projectdb->query("UPDATE virtual_systems SET interfaces='$vrinterfaces' WHERE id='$vrid';");
        }
    }


    #Modify Zones
    $getVR = $projectdb->query("SELECT id,interfaces FROM zones WHERE source='$source' AND template='$template' AND interfaces LIKE '%$originalname%';");
    if( $getVR->num_rows > 0 )
    {
        while( $mdata = $getVR->fetch_assoc() )
        {
            $vrid = $mdata['id'];
            $vrinterfaces = explode(",", $mdata['interfaces']);
            $newInterfaces = array();
            foreach( $vrinterfaces as $key => $value )
            {
                if( $value == $originalname )
                {
                    $newInterfaces[] = $newname;
                }
                else
                {
                    $newInterfaces[] = $value;
                }
            }
            $unique = array_unique($newInterfaces);
            $vrinterfaces = implode(",", $unique);
            $projectdb->query("UPDATE zones SET interfaces='$vrinterfaces' WHERE id='$vrid';");
        }
    }
    #modify Static Routing
    $projectdb->query("UPDATE routes_static SET tointerface='$newname' WHERE source='$source' AND template='$template' AND tointerface='$originalname';");
    #Modify Nats
    $projectdb->query("UPDATE nat_rules SET op_to_interface = '$newname' WHERE source = '$source' AND op_to_interface = '$originalname' ;");
    $projectdb->query("UPDATE nat_rules SET tp_sat_interface='$newname' WHERE source='$source'  AND tp_sat_interface='$originalname' AND tp_sat_address_type='interface-address';");
    $projectdb->query("UPDATE nat_rules SET tp_sat_interface_fallback='$newname' WHERE source='$source'  AND tp_sat_interface_fallback='$originalname' AND tp_fallback_type='interface-address';");

    # Clean from Pending_tasks
    $getFilename = $projectdb->query("SELECT filename FROM device_mapping WHERE id='$source';");
    if( $getFilename->num_rows == 1 )
    {
        $getFilenameData = $getFilename->fetch_assoc();
        $filename = $getFilenameData['filename'];
        $projectdb->query("DELETE FROM pending_tasks WHERE type='interfaces' AND element='$originalname' AND template='$template' AND filename='$filename';");
    }
}

function rename_interface($originalname, $newname, $media, $source, $template)
{
    global $projectdb;
    global $project;
    $getInt = $projectdb->query("SELECT unitname,unittag FROM interfaces WHERE template='$template' AND source='$source' AND name='$originalname' AND media IN ('ethernet','aggregate-ethernet');");
    if( $getInt->num_rows > 0 )
    {
        take_snapshot_last($project);
        while( $data = $getInt->fetch_assoc() )
        {
            $oldunitname = $data['unitname'];
            $unittag = $data['unittag'];
            if( $unittag == 0 )
            {
                $renamename = $newname;
            }
            else
            {
                $renamename = str_replace(addslashes($originalname), $newname, $oldunitname);
            }
            $projectdb->query("UPDATE interfaces SET unitname='$renamename', name='$newname', media = '$media' WHERE source='$source' AND template='$template' AND name='$originalname' AND unitname='$oldunitname';");
            #Modify Virtual Routers
            $getVR = $projectdb->query("SELECT id,interfaces FROM virtual_routers WHERE source='$source' AND template='$template' AND interfaces LIKE '%$originalname%';");
            if( $getVR->num_rows > 0 )
            {
                while( $mdata = $getVR->fetch_assoc() )
                {
                    $vrid = $mdata['id'];
                    $vrinterfaces = explode(",", $mdata['interfaces']);
                    $newInterfaces = array();
                    foreach( $vrinterfaces as $key => $value )
                    {
                        //print $value;
                        if( $value == $oldunitname )
                        {
                            $newInterfaces[] = $renamename;
                        }
                        else
                        {
                            $newInterfaces[] = $value;
                        }
                    }
                    $vrinterfaces = implode(",", $newInterfaces);
                    $projectdb->query("UPDATE virtual_routers SET interfaces='$vrinterfaces' WHERE id='$vrid';");
                }
            }
            #Modify Zones
            $getVR = $projectdb->query("SELECT id,interfaces FROM zones WHERE source='$source' AND template='$template' AND interfaces LIKE '%$originalname%';");
            if( $getVR->num_rows > 0 )
            {
                while( $mdata = $getVR->fetch_assoc() )
                {
                    $vrid = $mdata['id'];
                    $vrinterfaces = explode(",", $mdata['interfaces']);
                    $newInterfaces = array();
                    foreach( $vrinterfaces as $key => $value )
                    {
                        //print $value;
                        if( $value == $oldunitname )
                        {
                            $newInterfaces[] = $renamename;
                        }
                        else
                        {
                            $newInterfaces[] = $value;
                        }
                    }
                    $vrinterfaces = implode(",", $newInterfaces);
                    $projectdb->query("UPDATE zones SET interfaces='$vrinterfaces' WHERE id='$vrid';");
                }
            }
            #modify Static Routing
            $projectdb->query("UPDATE routes_static SET tointerface='$renamename' WHERE source='$source' AND template='$template' AND tointerface='$oldunitname';");
            #Modify Nats
            $projectdb->query("UPDATE nat_rules SET op_to_interface = '$renamename' WHERE source = '$source' AND op_to_interface = '$oldunitname' ;");
            $projectdb->query("UPDATE nat_rules SET tp_sat_interface='$renamename' WHERE source='$source'  AND tp_sat_interface='$oldunitname' AND tp_sat_address_type='interface-address';");
            $projectdb->query("UPDATE nat_rules SET tp_sat_interface_fallback='$renamename' WHERE source='$source'  AND tp_sat_interface_fallback='$oldunitname' AND tp_fallback_type='interface-address';");

            #modify Other Rules
            $projectdb->query("UPDATE pbf_rules SET egress_interface = '$renamename' WHERE source = '$source' AND egress_interface = '$oldunitname' ;");

            $ids_rules = getIdsBySourceVsys("pbf_rules", $source, "all");
            $projectdb->query("UPDATE pbf_rules_from SET name='$renamename' WHERE name='$oldunitname' AND type = 'interface' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

            $ids_rules = getIdsBySourceVsys("dos_rules", $source, "all");
            $projectdb->query("UPDATE dos_rules_from SET name='$renamename' WHERE name='$oldunitname' AND type = 'interface' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
            $projectdb->query("UPDATE dos_rules_to SET name='$renamename' WHERE name='$oldunitname' AND type = 'interface' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

            #UPDATE IPSec Tunnels, Networks Profiles y VLANs
            $projectdb->query("UPDATE ipsec_tunnel SET tunnel_interface = '$renamename' WHERE source = '$source' AND template = '$template' AND tunnel_interface = '$oldunitname' ;");
            $projectdb->query("UPDATE ike_gateways_profiles SET interface = '$renamename' WHERE source = '$source' AND template = '$template' AND interface = '$oldunitname' ;");
            $projectdb->query("UPDATE vlans SET virtual_interface = '$renamename' WHERE source = '$source' AND template = '$template' AND virtual_interface = '$oldunitname' ;");

            $getInterfacesVlans = $projectdb->query("SELECT id, interface FROM vlans WHERE source = '$source' AND template = '$template';");
            if( $getInterfacesVlans->num_rows > 0 )
            {
                while( $dataA = $getInterfacesVlans->fetch_assoc() )
                {
                    $interface_vlans = $dataA['interface'];
                    $id_vlans = $dataA['id'];
                    $add_array = explode(",", $interface_vlans);
                    if( in_array($oldunitname, $add_array) )
                    {
                        $replace2 = str_replace($oldunitname, $renamename, $interface_vlans);
                        $projectdb->query("UPDATE vlans SET interface = '$replace2' WHERE id = '$id_vlans';");
                    }
                }
            }

            $getMacInterfaces = $projectdb->query("SELECT id, mac_interfaces FROM vlans WHERE source = '$source' AND template = '$template';");
            if( $getMacInterfaces->num_rows > 0 )
            {
                while( $dataA = $getMacInterfaces->fetch_assoc() )
                {
                    $interface_vlans = $dataA['mac_interfaces'];
                    $id_vlans = $dataA['id'];
                    $add_array = explode(",", $interface_vlans);
                    if( in_array($oldunitname, $add_array) )
                    {
                        $replace2 = str_replace($oldunitname, $renamename, $interface_vlans);
                        $projectdb->query("UPDATE vlans SET mac_interfaces = '$replace2' WHERE id = '$id_vlans';");
                    }
                }
            }

            $getInterfacesVlans = $projectdb->query("SELECT id, interfaces FROM virtual_systems WHERE source = '$source' AND template = '$template';");
            if( $getInterfacesVlans->num_rows > 0 )
            {
                while( $dataA = $getInterfacesVlans->fetch_assoc() )
                {
                    $interface_vlans = $dataA['interfaces'];
                    $id_vlans = $dataA['id'];
                    $add_array = explode(",", $interface_vlans);
                    if( in_array($oldunitname, $add_array) )
                    {
                        $replace2 = str_replace($oldunitname, $renamename, $interface_vlans);
                        $projectdb->query("UPDATE virtual_systems SET interfaces = '$replace2' WHERE id = '$id_vlans';");
                    }
                }
            }

            # Clean from Pending_tasks
            $getFilename = $projectdb->query("SELECT filename FROM device_mapping WHERE id='$source';");
            if( $getFilename->num_rows == 1 )
            {
                $getFilenameData = $getFilename->fetch_assoc();
                $filename = $getFilenameData['filename'];
                $projectdb->query("DELETE FROM pending_tasks WHERE type='interfaces' AND element='$originalname' AND template='$template' AND filename='$filename';");
            }
        }
    }
}

/* creates a compressed zip file */
function create_zip($files = array(), $destination = '', $overwrite = FALSE)
{
    //if the zip file already exists and overwrite is false, return false
    if( file_exists($destination) && !$overwrite )
    {
        return FALSE;
    }
    //vars
    $valid_files = array();
    //if files were passed in...
    if( is_array($files) )
    {
        //cycle through each file
        foreach( $files as $file )
        {
            //make sure the file exists
            if( file_exists($file) )
            {
                $valid_files[] = $file;
            }
        }
    }
    //if we have good files...
    if( count($valid_files) )
    {
        //create the archive
        $zip = new ZipArchive();
        if( $zip->open($destination, $overwrite ? ZIPARCHIVE::OVERWRITE : ZIPARCHIVE::CREATE) !== TRUE )
        {
            return FALSE;
        }
        //add the files
        foreach( $valid_files as $file )
        {
            $new_filename = substr($file, strrpos($file, '/') + 1);
            $zip->addFile($file, $new_filename);
        }
        //debug
        //echo 'The zip archive contains ',$zip->numFiles,' files with a status of ',$zip->status;
        //close the zip -- done!
        $zip->close();

        //check to make sure the file exists
        return file_exists($destination);
    }
    else
    {
        return FALSE;
    }
}

function search_zone_address_one($member_lid, $vsys, $source, $table_name)
{
#Can be a Host, Network or Range Or FQDN
    global $projectdb;
    $zones = "";
    $Zone = "";
    $next = 0;

    if( $table_name != "" )
    {
        $addVsys = "AND vsys='$vsys'";


        $getType = $projectdb->query("SELECT v4,v6,type,ipaddress,cidr FROM $table_name WHERE id='$member_lid';");

        if( $getType->num_rows == 1 )
        {
            $next = 0;
            $Address = $getType->fetch_assoc();
            $AddressType = $Address["type"];

            if( $AddressType == "ip-range" )
            {
                $IPAddress = $Address["ipaddress"];
                $list = explode("-", $IPAddress);
                $first = $list[0];
                $last = $list[1];
                $next = 1;
            }
            elseif( $AddressType == "fqdn" )
            {
                # Do NOTHING with FQDN Objects
                $Zone = "";
                $next = 0;
            }
            else
            {
                # ip-netmask
                $first = $Address["ipaddress"];
                $next = 1;
            }

            if( $next == 1 )
            {
                #Load the static-routes

                $ccidr = 0;
                $czone = "not found";
                $encontrado = "0";

                #Check first against the Interfaces
                $getInterface = $projectdb->query("SELECT unitipaddress,zone FROM interfaces WHERE unitipaddress!='' AND source='$source' AND vsys='$vsys';");
                if( $getInterface->num_rows > 0 )
                {
                    while( $getInterfaceData = $getInterface->fetch_assoc() )
                    {
                        #The unitipadddress can be 1.1.1.1/24,1.1.1.2
                        $getUnique = explode(",", $getInterfaceData['unitipaddress']);
                        foreach( $getUnique as $key => $value )
                        {
                            $unitipaddress = explode("/", $value);
                            $interface_ip = $unitipaddress[0];
                            if( isset($unitipaddress[1]) )
                            {
                                $interface_cidr = $unitipaddress[1];
                            }
                            else
                            {
                                $interface_cidr = "32";
                            }
                            $zone_from = $getInterfaceData['zone'];
                            $network1 = cidr2network($interface_ip, $interface_cidr);
                            $network = $network1 . "/" . $interface_cidr;
                            $ip = $first;
                            $hoes = netMatchV4($network, $ip);
                            if( $hoes == 1 )
                            {
                                if( $ccidr < $interface_cidr )
                                {
                                    $czone = $zone_from;
                                    $ccidr = $interface_cidr;
                                }
                                $encontrado = "1";
                            }
                        }
                    }
                }

                if( $encontrado == "0" )
                {
                    #To be Fixed, Only supported one VR = one default gw from vr1 only
                    $get_routes = $projectdb->query("SELECT destination,zone FROM routes_static WHERE destination != '0.0.0.0/0' AND source='$source' AND vsys='$vsys' AND nexthop='ip-address' ORDER BY nexthop_value DESC;");
                    while( $get_routes_var = $get_routes->fetch_assoc() )
                    {
                        $zone_from = $get_routes_var['zone'];
                        $network_match = $get_routes_var['destination'];
                        $myroute = explode("/", $network_match);
                        $network_route = $myroute[0];
                        $netmask_route = $myroute[1];
                        $network = $network_match;
                        $ip = $first;
                        $hoes = netMatchV4($network, $ip);

                        if( $hoes == 1 )
                        {
                            if( $ccidr < $netmask_route )
                            {
                                $czone = $zone_from;
                                $ccidr = $netmask_route;
                            }
                            $encontrado = "1";
                        }
                    }
                }

                if( $encontrado == 1 )
                {
                    if( $czone == "not found" )
                    {

                    }
                    else
                    {
                        $zones = $czone;
                    }
                }
                else
                {
                    $get_defaultgw = $projectdb->query("SELECT zone FROM routes_static WHERE name = 'default' AND source='$source' AND vsys='$vsys'  limit 1");
                    $get_defaultgwname = $get_defaultgw->fetch_assoc();
                    $zone_default = $get_defaultgwname['zone'];
                    $zones = $zone_default;
                }
            }
        }
    }


    return $zones;
}

function getZones($source, $vsys, $gateway)
{

    global $projectdb;

    require_once INC_ROOT . "/bin/projects/tools/prepareQuery.php";
    $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

    $getInterface = $projectdb->query("SELECT unitipaddress,zone "
        . "FROM interfaces "
        . "WHERE unitipaddress!='' "
        . "AND source='$source' $sql_vsys;");

    $czone = "";

    if( $getInterface->num_rows > 0 )
    {

        while( $getInterfaceData = $getInterface->fetch_assoc() )
        {
            #The unitipadddress can be 1.1.1.1/24,1.1.1.2
            $getUnique = explode(",", $getInterfaceData['unitipaddress']);

            foreach( $getUnique as $key => $value )
            {

                $unitipaddress = explode("/", $value);
                $interface_ip = $unitipaddress[0];

                if( isset($unitipaddress[1]) )
                {
                    $interface_cidr = $unitipaddress[1];
                }
                else
                {
                    $interface_cidr = "32";
                }

                $network1 = cidr2network($interface_ip, $interface_cidr);
                $network = $network1 . "/" . $interface_cidr;

                $zone_from = $getInterfaceData['zone'];
                $hoes = netMatchV4($network, $gateway);

                if( $hoes == 1 )
                {
                    //TODO: what is $ccidr
                    if( $ccidr < $interface_cidr )
                    {
                        $czone = $zone_from;
                        $ccidr = $interface_cidr;
                    }
                    $encontrado = "1";
                }
            }
        }
    }
    else
    {
        $czone = "";
    }
    return $czone;

    /* if (($czone == "") OR ( $czone == "not found")) {

      } else {
      $projectdb->query("UPDATE routes_static SET zone='$czone' WHERE id='$routeid';");
      } */
}

function arrayUnique($array, $preserveKeys = FALSE)
{
    // Unique Array for return
    $arrayRewrite = array();
    // Array with the md5 hashes
    $arrayHashes = array();
    foreach( $array as $key => $item )
    {
        // Serialize the current element and create a md5 hash
        $hash = md5(serialize($item));
        // If the md5 didn't come up yet, add the element to
        // to arrayRewrite, otherwise drop it
        if( !isset($arrayHashes[$hash]) )
        {
            // Save the current element hash
            $arrayHashes[$hash] = $hash;
            // Add element to the unique Array
            if( $preserveKeys )
            {
                $arrayRewrite[$key] = $item;
            }
            else
            {
                $arrayRewrite[] = $item;
            }
        }
    }
    return $arrayRewrite;
}

# DEVICE USAGE
# Calcular PERCENTATGES
function calculatePercentatges($total, $total_max)
{
    if( $total_max != "0" )
    {
        $percentages = round(($total * 100) / $total_max, 2);
    }
    else
    {
        $percentages = "0";
    }
    return $percentages;
}

# Calculate RecommendedPlatform
function calculateRecommendedPlatform($action, $dusage_version, $address_used, $address_groups_used, $services_used, $services_groups_used, $security_rulebase_used, $nat_rulebase_used, $zones_used, $virtual_routers_used, $vsys_used, $security_profiles_used, $appoverride_rulebase_used, $custom_appid_used, $ipsec_tunnel_used)
{

    global $pandb;

    $myData = array();

    if( $dusage_version == "" )
    {
        $dusage_version = "8.0";
    }

    # Sumar un 25% a los used para calcular el optimo
    $address_used_25 = $address_used * 1.25;
    $address_groups_used_25 = $address_groups_used * 1.25;
    $services_used_25 = $services_used * 1.25;
    $services_groups_used_25 = $services_groups_used * 1.25;
    $security_rulebase_used_25 = $security_rulebase_used * 1.25;
    $nat_rulebase_used_25 = $nat_rulebase_used * 1.25;
    $zones_used_25 = $zones_used * 1.25;
    $virtual_routers_used_25 = $virtual_routers_used * 1.25;
    $vsys_used_25 = $vsys_used * 1.25;
    $security_profiles_used_25 = $security_profiles_used * 1.25;
    $appoverride_rulebase_used_25 = $appoverride_rulebase_used * 1.25;
    $custom_appid_used_25 = $custom_appid_used * 1.25;
    $ipsec_tunnel_used_25 = $ipsec_tunnel_used * 1.25;

    $query = "SELECT pc.address_max AS rec_address_max, pc.address_groups_max AS rec_address_groups_max, pc.services_max AS rec_services_max, "
        . "pc.services_groups_max AS rec_services_groups_max, pc.security_rulebase_max AS rec_security_rulebase_max, pc.nat_rulebase_max AS rec_nat_rulebase_max, "
        . "pc.zones_max AS rec_zones_max, pc.virtual_routers_max AS rec_virtual_routers_max, pc.vsys_max AS rec_vsys_max, pc.security_profiles_max AS rec_security_profiles_max, "
        . "pc.appoverride_rulebase_max AS rec_appoverride_rulebase_max, pc.custom_appid_max AS rec_custom_appid_max, pc.ipsec_tunnels_max AS rec_ipsec_tunnels_max, "
        . "p.name AS platform_recommended, p.id AS platform_id "
        . "FROM panos_capacity pc, platforms p "
        . "WHERE p.id = pc.platform_id "
        . "AND pc.panos = '$dusage_version' "
        . "AND address_max > '$address_used_25' AND address_groups_max > '$address_groups_used_25' AND services_max > '$services_used_25' "
        . "AND services_groups_max > '$services_groups_used_25' AND security_rulebase_max > '$security_rulebase_used_25' "
        . "AND nat_rulebase_max > '$nat_rulebase_used_25' AND zones_max > '$zones_used_25' AND virtual_routers_max > '$virtual_routers_used_25'"
        . "AND vsys_max > '$vsys_used_25' AND security_profiles_max > '$security_profiles_used_25' AND appoverride_rulebase_max > '$appoverride_rulebase_used_25' "
        . "AND custom_appid_max > '$custom_appid_used_25' AND ipsec_tunnels_max > '$ipsec_tunnel_used_25' "
        . "ORDER BY pc.id ASC limit 1;";

    $getPanos = $pandb->query($query);

    if( $getPanos->num_rows == 1 )
    {
        $data = $getPanos->fetch_assoc();
        $platform_id = $data['platform_id'];
        $myData[] = $data;

    }
    else
    {
        // Si está vacio el platform_id significa que no hay plataforma recomendada, es decir, proponer la máxima PA-7050 (28)

        $getPanosMax = $pandb->query("SELECT pc.address_max AS rec_address_max, pc.address_groups_max AS rec_address_groups_max, pc.services_max AS rec_services_max, "
            . "pc.services_groups_max AS rec_services_groups_max, pc.security_rulebase_max AS rec_security_rulebase_max, pc.nat_rulebase_max AS rec_nat_rulebase_max, "
            . "pc.zones_max AS rec_zones_max, pc.virtual_routers_max AS rec_virtual_routers_max, pc.vsys_max AS rec_vsys_max, pc.security_profiles_max AS rec_security_profiles_max, "
            . "pc.appoverride_rulebase_max AS rec_appoverride_rulebase_max, pc.custom_appid_max AS rec_custom_appid_max, pc.ipsec_tunnels_max AS rec_ipsec_tunnels_max, "
            . "p.name AS platform_recommended, p.id AS platform_id "
            . "FROM panos_capacity pc, platforms p "
            . "WHERE p.id = pc.platform_id AND p.id = '28' AND pc.panos = '$dusage_version';");

        if( $getPanosMax->num_rows == 1 )
        {

            $data2 = $getPanosMax->fetch_assoc();
            $platform_id = $data2['platform_id'];
            $myData[] = $data2;
        }

    }

//return array ($myData, $percentages_objects, $percentages_rules, $percentages_network, $platform_id);
    //echo "Platform id: " .$platform_id. "<br>";
    return array($myData, $platform_id, $dusage_version);

}

function deviceUsage($action, $type, $project, $dusage_platform, $dusage_version, $vsys, $source, $dusage_template)
{

    global $projectdb;
    global $pandb;

    # Si $action = inicial es pq se acaba de cargar una configuracion y se calculan los datos iniciales para luego poder comparar
    //$action = "initial";
    if( $type == "get" )
    {
        $myDataPlatf = array();
        //Si no hay dusage_platform, significa que es cuando clica en el tabPanel por primera vez, por lo tanto, buscar el primer registro
        if( ($action == "statistics") && ($dusage_platform == "") )
        {
            $getPlatform = $projectdb->query("SELECT platform_id FROM device_usage ORDER BY id ASC limit 1;");

            if( $getPlatform->num_rows == 1 )
            {
                $data = $getPlatform->fetch_assoc();
                $dusage_platform = $data['platform_id'];
            }
        }

        if( $action != 'initial' )
        {
            if( $source == 'all' || $source == '0' )
            {
                $queryGlobal = ' WHERE dummy=0';
            }
            else
            {
                $queryGlobal = " WHERE source='$source' AND dummy=0 ";
            }
        }
        else
        {
            $queryGlobal = " WHERE source='$source' AND dummy=0 ";
        }

        ##############################################
        # ADDRESS
        $query = "SELECT id FROM address $queryGlobal AND vsys != 'shared'; ";
        $Address = $projectdb->query($query);
        $address = $Address->num_rows;

        # Not Used
        if( preg_match("/WHERE/", $queryGlobal) )
        {
            $query = $queryGlobal . " AND used = '0' ";
        }
        else
        {
            $query = " WHERE used = '0' ";
        }
        $query .= " AND vsys != 'shared' ";
        $Address = $projectdb->query("SELECT id FROM address $query ");
        $address_unused = $Address->num_rows;

        # Shared
        $Address = $projectdb->query("SELECT id FROM address WHERE vsys='shared' AND source='$source' AND dummy=0;");
        $address_shared = $Address->num_rows;

        $address_used = $address + $address_shared;

        #############################################
        # ADDRESS GROUPS
        $Address_groups = $projectdb->query("SELECT id FROM address_groups_id $queryGlobal AND vsys != 'shared';");
        $address_groups = $Address_groups->num_rows;

        # Not Used
        if( preg_match("/WHERE/", $queryGlobal) )
        {
            $query = $queryGlobal . " AND used = '0' ";
        }
        else
        {
            $query = " WHERE used = '0' ";
        }
        $query .= " AND vsys!='shared' ";
        $Address_groups = $projectdb->query("SELECT id FROM address_groups_id $query ");
        $address_groups_unused = $Address_groups->num_rows;

        # Shared
        $Address_groups = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='shared' AND source='$source' AND dummy=0;");
        $address_groups_shared = $Address_groups->num_rows;

        $address_groups_used = $address_groups + $address_groups_shared;

        #############################################
        # SERVICES
        $Services = $projectdb->query("SELECT id FROM services $queryGlobal AND vsys != 'shared';");
        $services = $Services->num_rows;

        # Not Used
        if( preg_match("/WHERE/", $queryGlobal) )
        {
            $query = $queryGlobal . " AND used = '0' ";
        }
        else
        {
            $query = " WHERE used = '0' ";
        }
        $query .= " AND vsys!='shared' ";
        $Services = $projectdb->query("SELECT id FROM services $query ");
        $services_unused = $Services->num_rows;

        $Services = $projectdb->query("SELECT id FROM services WHERE vsys='shared' AND source='$source' AND dummy=0;");
        $services_shared = $Services->num_rows;

        $services_used = $services + $services_shared;

        #############################################
        # SERVICES GROUPS
        $Services_groups = $projectdb->query("SELECT id FROM services_groups_id $queryGlobal AND vsys != 'shared';");
        $services_groups = $Services_groups->num_rows;

        # Not Used
        if( preg_match("/WHERE/", $queryGlobal) )
        {
            $query = $queryGlobal . " AND used = '0' ";
        }
        else
        {
            $query = " WHERE used = '0' ";
        }
        $query .= " AND vsys!='shared' ";

        $Services_groups = $projectdb->query("SELECT id FROM services_groups_id $query ");
        $services_groups_unused = $Services_groups->num_rows;

        $Services_groups = $projectdb->query("SELECT id FROM services_groups_id WHERE vsys='shared' AND source='$source' AND dummy=0;");
        $services_groups_shared = $Services_groups->num_rows;

        $services_groups_used = $services_groups + $services_groups_shared;

        #############################################
        # APPLICATIONS
        $Applications = $projectdb->query("SELECT id FROM applications $queryGlobal AND vsys != 'shared';");
        $applications = $Applications->num_rows;

        $Applications = $projectdb->query("SELECT id FROM applications WHERE vsys='shared' AND source='$source' AND dummy=0;");
        $shared_applications = $Applications->num_rows;

        $custom_appid_used = $applications + $shared_applications;

        #############################################
        # PROFILES
        $Profiles = $projectdb->query("SELECT id FROM profiles $queryGlobal AND vsys != 'shared';");
        $profiles = $Profiles->num_rows;

        $Profiles = $projectdb->query("SELECT id FROM profiles WHERE vsys='shared' AND source='$source';");
        $shared_profiles = $Profiles->num_rows;

        $security_profiles_used = $profiles + $shared_profiles;

        #############################################
        # SECURITY RULES
        $Security_rules = $projectdb->query("SELECT id FROM security_rules $queryGlobal");
        $security_rulebase_used = $Security_rules->num_rows;

        # Disabled
        if( preg_match("/WHERE/", $queryGlobal) )
        {
            $query = $queryGlobal . " AND disabled = '1' ";
        }
        else
        {
            $query = " WHERE disabled = '1' ";
        }
        $Security_rules_dis = $projectdb->query("SELECT id FROM security_rules $query ");
        $security_rulebase_disabled = $Security_rules_dis->num_rows;

        #############################################
        # NAT RULES
        $Nat_rules = $projectdb->query("SELECT id FROM nat_rules $queryGlobal");
        $nat_rulebase_used = $Nat_rules->num_rows;

        # Disabled
        if( preg_match("/WHERE/", $queryGlobal) )
        {
            $query = $query . " AND disabled = '1' ";
        }
        else
        {
            $query = " WHERE disabled = '1' ";
        }
        $Nat_rules_dis = $projectdb->query("SELECT id FROM nat_rules $query ");
        $nat_rulebase_disabled = $Nat_rules_dis->num_rows;

        #############################################
        # ZONES
        $Zones = $projectdb->query("SELECT id FROM zones $queryGlobal");
        $zones_used = $Zones->num_rows;

        # VIRTUAL ROUTERS
        $Virtual_rutes = $projectdb->query("SELECT id FROM virtual_routers $queryGlobal");
        $virtual_routers_used = $Virtual_rutes->num_rows;

        # APPOVERRIDE RULES
        $Appoverride_rules = $projectdb->query("SELECT id FROM appoverride_rules $queryGlobal");
        $appoverride_rulebase_used = $Appoverride_rules->num_rows;

        # Disabled
        if( preg_match("/WHERE/", $queryGlobal) )
        {
            $query = $queryGlobal . " AND disabled = '1' ";
        }
        else
        {
            $query = " WHERE disabled = '1' ";
        }
        $Appoverride_rules_dis = $projectdb->query("SELECT id FROM appoverride_rules $query ");
        $appoverride_rulebase_disabled = $Appoverride_rules_dis->num_rows;

        #####################################################################################
        # VSYS
        $Vsys = $projectdb->query("SELECT id FROM virtual_systems WHERE source='$source'");
        $vsys_used = $Vsys->num_rows;

        #####################################################################################
        # IPSEC TUNNELS
        $getIPSecTunnels = $projectdb->query("SELECT id FROM ipsec_tunnel WHERE source='$source'");
        $ipsec_tunnel_used = $getIPSecTunnels->num_rows;


        ######################################################################################
        # Función llamada desde los import de los php
        # Si es initial, significa que primero tenemos que saber que plataforma es la recomendada para
        # calcular los porcentajes, por lo tanto, llamar a la funcion

        $myData = array();
        $data_recomended_platform = array();

        if( $action == "initial" )
        {
            list($data_recomended_platform, $platform_id, $dusage_version) = calculateRecommendedPlatform($action, $dusage_version, $address_used, $address_groups_used, $services_used, $services_groups_used, $security_rulebase_used, $nat_rulebase_used, $zones_used, $virtual_routers_used, $vsys_used, $security_profiles_used, $appoverride_rulebase_used, $custom_appid_used, $ipsec_tunnel_used);

            $dusage_platform = $platform_id;
        }

        // No hacer nada si el platform id/dusage_platform es 0 (significa que aún no han hecho un import!!)
        if( $dusage_platform != 0 )
        {
            $getMAX = $pandb->query("SELECT pc.address_max, pc.address_groups_max, pc.services_max, pc.services_groups_max, pc.security_rulebase_max, pc.nat_rulebase_max,"
                . "pc.zones_max, pc.virtual_routers_max, pc.vsys_max, pc.security_profiles_max, pc.appoverride_rulebase_max, pc.custom_appid_max, pc.ipsec_tunnels_max, p.name AS platform_selected "
                . "FROM panos_capacity pc , platforms p "
                . "WHERE p.id = pc.platform_id "
                . "AND pc.platform_id='$dusage_platform' AND pc.panos='$dusage_version';");

            if( $getMAX->num_rows == 1 )
            {

                $getMAXData = $getMAX->fetch_assoc();

                $address_max = $getMAXData['address_max'];
                $address_groups_max = $getMAXData['address_groups_max'];
                $services_max = $getMAXData['services_max'];
                $services_groups_max = $getMAXData['services_groups_max'];
                $security_rulebase_max = $getMAXData['security_rulebase_max'];
                $nat_rulebase_max = $getMAXData['nat_rulebase_max'];
                $zones_max = $getMAXData['zones_max'];
                $virtual_routers_max = $getMAXData['virtual_routers_max'];
                $vsys_max = $getMAXData['vsys_max'];
                $security_profiles_max = $getMAXData['security_profiles_max'];
                $appoverride_rulebase_max = $getMAXData['appoverride_rulebase_max'];
                $custom_appid_max = $getMAXData['custom_appid_max'];
                $ipsec_tunnels_max = $getMAXData['ipsec_tunnels_max'];
                $platform_selected = $getMAXData['platform_selected'];
            }
            else
            {
                //echo json_encode(array("success" => false, "msg" => "There is no information regarding this platform and PanOS version."));
            }
        }

        //Blank values to avoid undefined variables
        $address_max = isset($address_max) ? $address_max : 0;
        $address_groups_max = isset($address_groups_max) ? $address_groups_max : 0;
        $services_max = isset($services_max) ? $services_max : 0;
        $services_groups_max = isset($services_groups_max) ? $services_groups_max : 0;
        $security_rulebase_max = isset($security_rulebase_max) ? $security_rulebase_max : 0;
        $nat_rulebase_max = isset($nat_rulebase_max) ? $nat_rulebase_max : 0;
        $zones_max = isset($zones_max) ? $zones_max : 0;
        $virtual_routers_max = isset($virtual_routers_max) ? $virtual_routers_max : 0;
        $vsys_max = isset($vsys_max) ? $vsys_max : 0;
        $security_profiles_max = isset($security_profiles_max) ? $security_profiles_max : 0;
        $appoverride_rulebase_max = isset($appoverride_rulebase_max) ? $appoverride_rulebase_max : 0;
        $custom_appid_max = isset($custom_appid_max) ? $custom_appid_max : 0;
        $ipsec_tunnels_max = isset($ipsec_tunnels_max) ? $ipsec_tunnels_max : 0;

        $getPlatform = $pandb->query("SELECT p.name AS platform_selected FROM panos_capacity pc , platforms p WHERE p.id = pc.platform_id "
            . "AND pc.platform_id='$dusage_platform' AND pc.panos='$dusage_version';");

        if( $getPlatform->num_rows == 1 )
        {
            $dataPlatf = $getPlatform->fetch_assoc();
            $myDataPlatf[] = $dataPlatf;

        }

        // Calcute recommended platform actual
        list($data_recomended_platform, $platform_id, $dusage_version) = calculateRecommendedPlatform($action, $dusage_version, $address_used, $address_groups_used, $services_used, $services_groups_used, $security_rulebase_used, $nat_rulebase_used, $zones_used, $virtual_routers_used, $vsys_used, $security_profiles_used, $appoverride_rulebase_used, $custom_appid_used, $ipsec_tunnel_used);

        # Calculate percentatges con los datos máximos de la plataforma actual seleccionada
        # Total Objects
        $total_objects = $address_used + $address_groups_used + $services_used + $services_groups_used + $custom_appid_used + $security_profiles_used;
        $total_objects_max = $address_max + $address_groups_max + $services_max + $services_groups_max + $custom_appid_max + $security_profiles_max;
        $percentages_objects = calculatePercentatges($total_objects, $total_objects_max);

        # Total Rules
        $total_rules = $security_rulebase_used + $nat_rulebase_used + $appoverride_rulebase_used;
        $total_rules_max = $security_rulebase_max + $nat_rulebase_max + $appoverride_rulebase_max;
        $percentages_rules = calculatePercentatges($total_rules, $total_rules_max);

        $total_network = $vsys_used + $virtual_routers_used + $zones_used + $ipsec_tunnel_used;
        $total_network_max = $vsys_max + $virtual_routers_max + $zones_max + $ipsec_tunnels_max;
        $percentages_network = calculatePercentatges($total_network, $total_network_max);

        if( $dusage_platform != 0 )
        {

            if( $source != 0 )
            {
                $query = "SELECT id FROM device_usage WHERE source = $source ORDER BY id LIMIT 1";
                $result = $projectdb->query($query);
                if( $result->num_rows > 0 )
                {
                    $rowData = $result->fetch_array();
                    $id = $rowData['id'];
                    $query = "DELETE FROM device_usage WHERE id != $id AND source = $source";
                    $projectdb->query($query);
                }

                # Insert historico device_usage
                $projectdb->query("INSERT INTO device_usage "
                    . "(datetime, source, vsys, platform_id, panos, address_max, address_used, address_unused, address_shared, "
                    . "address_groups_used, address_groups_max, address_groups_unused, address_groups_shared, "
                    . "services_max, services_used, services_unused, services_shared, "
                    . "services_groups_max, services_groups_used, services_groups_unused, services_groups_shared, "
                    . "security_rulebase_max, security_rulebase_used, security_rulebase_disabled, "
                    . "nat_rulebase_max, nat_rulebase_used, nat_rulebase_disabled, "
                    . "zones_max, zones_used, virtual_routers_max, virtual_routers_used, "
                    . "vsys_max, vsys_used, "
                    . "security_profiles_max, security_profiles_used, "
                    . "appoverride_rulebase_max, appoverride_rulebase_used, appoverride_rulebase_disabled,"
                    . "custom_appid_max, custom_appid_used, ipsec_tunnels_max, ipsec_tunnels_used, pct_objects, pct_rules, pct_network) "
                    . "VALUES "
                    . "(NOW(), '$source', '$vsys', '$dusage_platform', '$dusage_version', '$address_max', '$address_used', '$address_unused', '$address_shared', "
                    . "'$address_groups_used', '$address_groups_max', '$address_groups_unused', '$address_groups_shared', "
                    . "'$services_max', '$services_used', '$services_unused', '$services_shared', "
                    . "'$services_groups_max', '$services_groups_used', '$services_groups_unused', '$services_groups_shared', "
                    . "'$security_rulebase_max', '$security_rulebase_used', '$security_rulebase_disabled', "
                    . "'$nat_rulebase_max', '$nat_rulebase_used', '$nat_rulebase_disabled', "
                    . "'$zones_max', '$zones_used', '$virtual_routers_max', '$virtual_routers_used', "
                    . "'$vsys_max', '$vsys_used', "
                    . "'$security_profiles_max', '$security_profiles_used', "
                    . "'$appoverride_rulebase_max', '$appoverride_rulebase_used', '$appoverride_rulebase_disabled', "
                    . "'$custom_appid_max', '$custom_appid_used', '$ipsec_tunnels_max', '$ipsec_tunnel_used', '$percentages_objects', '$percentages_rules', '$percentages_network' ); ");

                $last = $projectdb->insert_id;
            }
            else
            {
                echo '{"total":"","statistics":""}';
                exit();
            }

            $getStatistics = $projectdb->query("SELECT * FROM device_usage WHERE id='$last';");
            $count = $getStatistics->num_rows;

            if( $count > 0 )
            {
                while( $data = $getStatistics->fetch_object() )
                {
                    $myData[] = $data;
                }
            }
            else
            {
                $myData = array();
            }
        }
        else
        {
            $myData = array();
        }

        # Calcular los porcentajes iniciales
        $getInitial = $projectdb->query("SELECT platform_id, panos, pct_objects AS pct_objects_ini, pct_rules AS pct_rules_ini, pct_network AS pct_network_ini "
            . "FROM device_usage WHERE source = '$source' ORDER BY id ASC limit 1 ;");

        if( $getInitial->num_rows == 1 )
        {
            $getInitialData = $getInitial->fetch_assoc();
            $myDataIni[] = $getInitialData;
            $platform_id_inicial = $getInitialData['platform_id'];
            $dusage_version_inicial = $getInitialData['panos'];
        }
        else
        {
            //Blanc values to avoid undefined variables.
            $platform_id_inicial = "";
            $dusage_version_inicial = "";
        }

        $getPlatformIni = $pandb->query("SELECT p.name AS platform_selected_ini FROM panos_capacity pc , platforms p WHERE p.id = pc.platform_id "
            . "AND pc.platform_id='$platform_id_inicial' AND pc.panos='$dusage_version_inicial';");

        $myDataPlatfIni = array();
        if( $getPlatformIni->num_rows == 1 )
        {
            $dataPlatfIni = $getPlatformIni->fetch_assoc();
            $myDataPlatfIni[] = $dataPlatfIni;
        }

        if( $action != "initial" )
        {
            if( count($myData) > 0 )
            {
                $myDataTotal = array_merge($myData, $data_recomended_platform, $myDataIni, $myDataPlatf, $myDataPlatfIni);
                echo '{"total":"' . $count . '","statistics":' . json_encode($myDataTotal) . '}';
            }
            else
            {
                echo '{"total":"","statistics":""}';
            }
        }
    }
}


function getHash($vsys, $source)
{

    global $projectdb;

    $rules_hash = array();
    $getRulesHash = $projectdb->query("SELECT rules_lid FROM hash_rules WHERE visible = '1' AND vsys = '$vsys' AND source = '$source'; ");

    if( $getRulesHash->num_rows > 0 )
    {
        while( $data = $getRulesHash->fetch_assoc() )
        {
            $rules_hash[] = $data['rules_lid'];
        }
    }

    return $rules_hash;
}

function setHashToMemberLid($rule_lid, $table_to_search, $filter_hash, $vsys, $source)
{

    global $projectdb;
    $names = array();

    if( $table_to_search == "nat_rules_srv" )
    {
        $getFilterHash = $projectdb->query("SELECT op_service_lid, op_service_table FROM nat_rules WHERE id = '$rule_lid' AND op_service_lid != '0'; ");
        if( $getFilterHash->num_rows != 0 )
        {
            while( $data = $getFilterHash->fetch_assoc() )
            {
                $member_lid = $data['op_service_lid'];
                $table_name = $data['op_service_table'];

                $getNamePan = $projectdb->query("SELECT name FROM $table_name WHERE id = '$member_lid'; ");
                if( $getNamePan->num_rows != 0 )
                {
                    $data = $getNamePan->fetch_assoc();
                    $names[] = $data['name'];
                }
            }
            array_multisort($names);
        }
        else
        {
            $names = "any";
        }
    }
    else if( $table_to_search == "appoverride_rules_app" )
    {
        $getFilterHash = $projectdb->query("SELECT app_id, app_table FROM appoverride_rules WHERE id = '$rule_lid' AND app_id != '0'; ");
        if( $getFilterHash->num_rows != 0 )
        {
            while( $data = $getFilterHash->fetch_assoc() )
            {
                $member_lid = $data['app_id'];
                $table_name = $data['app_table'];

                $getNamePan = $projectdb->query("SELECT name FROM $table_name WHERE id = '$member_lid'; ");
                if( $getNamePan->num_rows != 0 )
                {
                    $data = $getNamePan->fetch_assoc();
                    $names[] = $data['name'];
                }
            }
            array_multisort($names);
        }
        else
        {
            $names = "any";
        }
    }
    else
    {
        $getFilterHash = $projectdb->query("SELECT member_lid, table_name FROM $table_to_search WHERE rule_lid = '$rule_lid'; ");
        if( $getFilterHash->num_rows != 0 )
        {
            while( $data = $getFilterHash->fetch_assoc() )
            {
                $member_lid = $data['member_lid'];
                $table_name = $data['table_name'];

                $getNamePan = $projectdb->query("SELECT name FROM $table_name WHERE id = '$member_lid'; ");
                if( $getNamePan->num_rows != 0 )
                {
                    $data = $getNamePan->fetch_assoc();
                    $names[] = $data['name'];
                }
            }
            array_multisort($names);
        }
        else
        {
            $names = "any";
        }
    }

    return $names;
}

function setHashToName($rule_lid, $table_to_search, $filter_hash, $vsys, $source)
{

    global $projectdb;

    $names = array();

    if( $filter_hash == "Name" )
    {
        $getFilterHash = $projectdb->query("SELECT name FROM $table_to_search WHERE id = '$rule_lid' ; ");
    }
    elseif( $filter_hash == "Action" )
    {
        $getFilterHash = $projectdb->query("SELECT action FROM $table_to_search WHERE id = '$rule_lid' ; ");
    }
    elseif( ($table_to_search == "nat_rules") && ($filter_hash == "To") )
    {
        $getFilterHash = $projectdb->query("SELECT op_zone_to FROM $table_to_search WHERE id = '$rule_lid' ; ");
    }
    elseif( ($table_to_search == "appoverride_rules") && ($filter_hash == "Protocol") )
    {
        $getFilterHash = $projectdb->query("SELECT protocol FROM $table_to_search WHERE id = '$rule_lid' ; ");
    }
    elseif( ($table_to_search == "appoverride_rules") && ($filter_hash == "Port") )
    {
        $getFilterHash = $projectdb->query("SELECT port FROM $table_to_search WHERE id = '$rule_lid' ; ");
    }
    else
    {
        $getFilterHash = $projectdb->query("SELECT name FROM $table_to_search WHERE rule_lid = '$rule_lid' ; ");
    }

    if( $getFilterHash->num_rows != 0 )
    {
        while( $data = $getFilterHash->fetch_assoc() )
        {
            if( $filter_hash == "Action" )
            {
                $names[] = $data['action'];
            }
            elseif( ($table_to_search == "nat_rules") && ($filter_hash == "To") )
            {
                $names[] = $data['op_zone_to'];
            }
            elseif( ($table_to_search == "appoverride_rules") && ($filter_hash == "Protocol") )
            {
                $names[] = $data['protocol'];
            }
            elseif( ($table_to_search == "appoverride_rules") && ($filter_hash == "Port") )
            {
                $names[] = $data['port'];
            }
            else
            {
                $names[] = $data['name'];
            }
        }
        array_multisort($names);
    }
    return $names;
}

function getPanorama($vsys, $preorpost, $source)
{

    global $projectdb;

    $rules_panorama = array();

    if( ($preorpost == "all") && ($vsys == "all") )
    {

        $getLimit_shared_pre = $projectdb->query("SELECT id FROM security_rules  WHERE source = '$source' AND vsys='shared' AND preorpost = '0' ORDER BY position ASC ;");
        if( $getLimit_shared_pre->num_rows > 0 )
        {
            while( $data = $getLimit_shared_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_device_pre = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys != 'shared' AND preorpost = '0' ORDER BY vsys,position ASC ;");
        if( $getLimit_device_pre->num_rows > 0 )
        {
            while( $data = $getLimit_device_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_device_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys != 'shared' AND preorpost = '1' ORDER BY vsys,position ASC ;");
        if( $getLimit_device_post->num_rows > 0 )
        {
            while( $data = $getLimit_device_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_shared_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = 'shared' AND preorpost = '1' ORDER BY position ASC;");
        if( $getLimit_shared_post->num_rows > 0 )
        {
            while( $data = $getLimit_shared_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

    }
    elseif( ($preorpost == "all") && ($vsys != "all") )
    {

        $getLimit_shared_pre = $projectdb->query("SELECT id FROM security_rules  WHERE source = '$source' AND vsys='shared' AND preorpost = '0' ORDER BY position ASC;");
        if( $getLimit_shared_pre->num_rows > 0 )
        {
            while( $data = $getLimit_shared_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_device_pre = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = '$vsys' AND preorpost = '0' ORDER BY position ASC;");
        if( $getLimit_device_pre->num_rows > 0 )
        {
            while( $data = $getLimit_device_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_device_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = '$vsys' AND preorpost = '1' ORDER BY position ASC;");
        if( $getLimit_device_post->num_rows > 0 )
        {
            while( $data = $getLimit_device_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_shared_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = 'shared' AND preorpost = '1' ORDER BY position ASC;");
        if( $getLimit_shared_post->num_rows > 0 )
        {
            while( $data = $getLimit_shared_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }


    }
    elseif( ($preorpost == "0") && ($vsys == "all") )
    {

        $getLimit_shared_pre = $projectdb->query("SELECT id FROM security_rules  WHERE source = '$source' AND vsys = 'shared' AND preorpost = '0' ORDER BY position ASC;");
        if( $getLimit_shared_pre->num_rows > 0 )
        {
            while( $data = $getLimit_shared_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_device_pre = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys != 'shared' AND preorpost = '0' ORDER BY position ASC;");
        if( $getLimit_device_pre->num_rows > 0 )
        {
            while( $data = $getLimit_device_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }


    }
    elseif( ($preorpost == "0") && ($vsys != "all") )
    {

        $getLimit_shared_pre = $projectdb->query("SELECT id FROM security_rules  WHERE source = '$source' AND vsys = 'shared' AND preorpost = '0' ORDER BY position ASC;");
        if( $getLimit_shared_pre->num_rows > 0 )
        {
            while( $data = $getLimit_shared_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_device_pre = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = '$vsys' AND preorpost = '0' ORDER BY position ASC;");
        if( $getLimit_device_pre->num_rows > 0 )
        {
            while( $data = $getLimit_device_pre->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

    }
    elseif( ($preorpost == "1") && ($vsys == "all") )
    {

        $getLimit_device_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys != 'shared' AND preorpost = '1' ORDER BY position ASC;");
        if( $getLimit_device_post->num_rows > 0 )
        {
            while( $data = $getLimit_device_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_shared_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = 'shared' AND preorpost = '1' ORDER BY position ASC;");
        if( $getLimit_shared_post->num_rows > 0 )
        {
            while( $data = $getLimit_shared_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

    }
    elseif( ($preorpost == "1") && ($vsys != "all") )
    {

        $getLimit_device_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = '$vsys' AND preorpost = '1' ORDER BY position ASC;");
        if( $getLimit_device_post->num_rows > 0 )
        {
            while( $data = $getLimit_device_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

        $getLimit_shared_post = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' AND vsys = 'shared' AND preorpost = '1' ORDER BY position ASC;");
        if( $getLimit_shared_post->num_rows > 0 )
        {
            while( $data = $getLimit_shared_post->fetch_assoc() )
            {
                $rules_panorama[] = $data['id'];
            }
        }

    }

    return $rules_panorama;

}

function checkExistShared($source)
{

    global $projectdb;

    $getFilename = $projectdb->query("SELECT filename, device, ispanorama, active, project, baseconfig, vendor, urldb 
        FROM device_mapping WHERE id = '$source';");

    if( $getFilename->num_rows > 0 )
    {
        $dataF = $getFilename->fetch_assoc();
        $filename = $dataF['filename'];
        $device = $dataF['device'];
        $ispanorama = $dataF['ispanorama'];
        $active = $dataF['active'];
        $project = $dataF['project'];
        $baseconfig = $dataF['baseconfig'];
        $vendor = $dataF['vendor'];
        $urldb = $dataF['urldb'];

        $getExistShared = $projectdb->query("SELECT id FROM device_mapping WHERE filename = '$filename' AND vsys = 'shared'; ");
        if( $getExistShared->num_rows == 0 )
        {

            $projectdb->query("INSERT INTO device_mapping (id, filename, device, ispanorama, active, project, baseconfig, vendor, urldb, vsys ) 
                VALUES ('NULL', '$filename', '$device', '$ispanorama', '$active', '$project', '$baseconfig', '$vendor', '$urldb', 'shared');");
        }
    }
}

function convertAddressToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
        . "FROM address WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    //echo "1. SELECT id, name, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
    //    . "FROM address WHERE id IN (".implode(',',$ids).") AND vsys != 'shared';";

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $type = $data['type'];
            $ipaddress = $data['ipaddress'];
            $cidr = $data['cidr'];
            $description = $data['description'];
            $fqdn = $data['fqdn'];
            $v4 = $data['v4'];
            $v6 = $data['v6'];
            $vtype = $data['vtype'];
            $tag = $data['tag'];
            $dummy = $data['dummy'];

            //$getExistShared = $projectdb->query("SELECT id FROM address WHERE vsys = 'shared' AND BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND ipaddress = '$ipaddress' AND cidr = '$cidr' AND description = '$description' AND fqdn = '$fqdn' AND v4 = '$v4' AND v6 = '$v6' AND vtype = '$vtype' AND tag = '$tag' AND dummy = '$dummy' AND source = '$source';");
            $getExistShared = $projectdb->query("SELECT id FROM address WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND ipaddress = '$ipaddress' AND cidr = '$cidr' AND description = '$description' AND fqdn = '$fqdn' AND v4 = '$v4' AND v6 = '$v6' AND tag = '$tag' AND dummy = '$dummy' AND source = '$source';");
            //echo "2. SELECT id FROM address WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND ipaddress = '$ipaddress' AND cidr = '$cidr' AND description = '$description' AND fqdn = '$fqdn' AND v4 = '$v4' AND v6 = '$v6' AND tag = '$tag' AND dummy = '$dummy' AND source = '$source';";

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "address");

                cleanDuplicatedMembersMerging($first_member_lid, "address");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE address SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM address WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Address";
            }
            add_log('ok', 'Convert to Shared', 'Convert Address: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertAddressToSharedExport($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $addressAll = array();
    $addressAllShared = array();

    $getOriginal = $projectdb->query("SELECT id, name, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
        . "FROM address WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $type = $data['type'];
            $ipaddress = $data['ipaddress'];
            $cidr = $data['cidr'];

            $addressAll[$member_lid] = [
                "name" => $name,
                "type" => $type,
                "ipaddress" => $ipaddress,
                "cidr" => $cidr,
            ];

        }
    }

    // Coger todos los shared del source out
    $getShared = $projectdb->query("SELECT id, name, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
        . "FROM address WHERE vsys = 'shared' AND source = '$source';");

    if( $getShared->num_rows > 0 )
    {
        while( $dataS = $getShared->fetch_assoc() )
        {

            $first_member_lid = $dataS['id'];
            $name = $dataS['name'];
            $type = $dataS['type'];
            $ipaddress = $dataS['ipaddress'];
            $cidr = $dataS['cidr'];

            $addressAllShared[$first_member_lid] = [
                "name" => $name,
                "type" => $type,
                "ipaddress" => $ipaddress,
                "cidr" => $cidr,
            ];

        }
    }

    $updates_member_lids = array();

    foreach( $addressAll as $member_lid => $address_origen )
    {

        $first_member_lid = array_search($address_origen, $addressAllShared);
        if( $first_member_lid !== FALSE )
        {

            //echo "COINCIDE\n";
            updateMemberLid("", $first_member_lid, $member_lid, "address");

            $remove_objects[] = $member_lid;
        }
        else
        {
            $updates_member_lids[] = $member_lid;
        }
    }

    if( count($updates_member_lids) > 0 )
    {
        $projectdb->query("UPDATE address SET vsys = 'shared' WHERE id IN (" . implode(",", $updates_member_lids) . ");");
    }

    if( count($remove_objects) > 0 )
    {
        $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_objects) . ");");
    }

    return 1;
}

function convertAddressGroupsToShared($source, $ids, $where)
{

    global $projectdb;

    $member_object = array();
    $member_objectgroup = array();
    $remove_object = array();

    checkExistShared($source);

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, name_ext, used, devicegroup, vsys, source, tag, checkit, invalid, filter, type "
            . "FROM address_groups_id WHERE id = '$member_lid' AND vsys != 'shared';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $invalid = $data['invalid'];
            $tag = $data['tag'];
            $filter = addslashes($data['filter']);
            $type = $data['type'];

            #Check if the members are all shared
            $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member FROM address_groups WHERE lid = '$member_lid' "
                . "AND (table_name = 'address' OR table_name = 'address_groups_id');");

            if( $getAllmembers->num_rows > 0 )
            {
                while( $data = $getAllmembers->fetch_assoc() )
                {
                    $table_name_sql = $data['table_name'];
                    $member_lid_sql = $data['member_lid'];

                    if( $table_name_sql == "address_groups_id" )
                    {
                        $member_objectgroup[] = $member_lid_sql;
                    }
                    elseif( $table_name_sql == "address" )
                    {
                        $member_object[] = $member_lid_sql;
                    }
                }

                //if(count($member_object) > 0) {
                //    convertAddressToShared($source, $member_object, "notall");
                //}
                if( count($member_object) > 0 )
                {
                    convertAddressToSharedExport($source, $member_object, "notall");
                }
                if( count($member_objectgroup) > 0 )
                {
                    convertAddressGroupsToShared($source, $member_objectgroup, "notall");
                }
            }

            $getExistShared = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND filter = '$filter' AND invalid = '$invalid' AND tag = '$tag' AND source = '$source';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $shared_member_lid = $getESData['id'];

                $remove_object[] = $member_lid;
                $name_int_to_shared[] = $name;

                updateMemberLid("", $shared_member_lid, $member_lid, "address_groups_id");

                //cleanDuplicatedMembersMerging($shared_member_lid, "address_groups_id");

            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE address_groups_id SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM address_groups_id WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
    }

    //clean_duplicated_members("address_groups");

    if( count($remove_object) > 0 )
    {
        $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $remove_object) . ");");
        $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $remove_object) . ");");
        if( $where == "notall" )
        {
            $objects_to_shared = implode(",", $name_int_to_shared);
        }
        else
        {
            $objects_to_shared = "All Address Groups";
        }
        add_log('ok', 'Convert to Shared', 'Convert Address Groups: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');

    }
    return 1;
}

function convertServicesToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, name_ext, used, vsys, devicegroup, description, sport, dport, protocol, icmp, source, tag "
        . "FROM services WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");
    //echo "SELECT id, name, name_ext, used, vsys, devicegroup, description, sport, dport, protocol, icmp, source, tag "
    //    . "FROM services WHERE id IN (".implode(',',$ids).") AND vsys != 'shared';";

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $protocol = $data['protocol'];
            $description = $data['description'];
            $dport = $data['dport'];
            $sport = $data['sport'];
            $icmp = $data['icmp'];
            $tag = $data['tag'];

            //$getExistShared = $projectdb->query("SELECT id FROM services WHERE vsys = 'shared' AND BINARY name = '$name' AND devicegroup = '$devicegroup' AND description = '$description' AND protocol = '$protocol' AND dport = '$dport' AND sport = '$sport' AND icmp = '$icmp' AND tag = '$tag' AND source = '$source';");
            $getExistShared = $projectdb->query("SELECT id FROM services WHERE vsys = 'shared' AND BINARY name = '$name' AND description = '$description' AND protocol = '$protocol' AND dport = '$dport' AND sport = '$sport' AND icmp = '$icmp' AND tag = '$tag' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "services");

                //cleanDuplicatedMembersMerging($first_member_lid, "services");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE services SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM services WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Services";
            }
            add_log('ok', 'Convert to Shared', 'Convert Services: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertServicesGroupsToShared($source, $ids, $where)
{

    global $projectdb;

    $member_object = array();
    $member_objectgroup = array();
    $remove_object = array();

    checkExistShared($source);

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, name_ext, used, devicegroup, vsys, source, tag, type, invalid "
            . "FROM services_groups_id WHERE id = '$member_lid' AND vsys != 'shared';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $invalid = $data['invalid'];
            $tag = $data['tag'];

            #Check if the members are all shared
            $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member FROM services_groups WHERE lid = '$member_lid' "
                . "AND (table_name = 'services' OR table_name = 'services_groups_id');");

            if( $getAllmembers->num_rows > 0 )
            {
                while( $data = $getAllmembers->fetch_assoc() )
                {
                    $table_name_sql = $data['table_name'];
                    $member_lid_sql = $data['member_lid'];

                    if( $table_name_sql == "services_groups_id" )
                    {
                        $member_objectgroup[] = $member_lid_sql;
                    }
                    elseif( $table_name_sql == "services" )
                    {
                        $member_object[] = $member_lid_sql;
                    }
                }
                if( count($member_object) > 0 )
                {
                    convertServicesToShared($source, $member_object, "notall");
                }
                if( count($member_objectgroup) > 0 )
                {
                    convertServicesGroupsToShared($source, $member_objectgroup, "notall");
                }
            }

            $getExistShared = $projectdb->query("SELECT id FROM services_groups_id WHERE vsys = 'shared' AND BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND invalid = '$invalid' AND tag = '$tag' AND source = '$source';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $shared_member_lid = $getESData['id'];

                $remove_object[] = $member_lid;
                $name_int_to_shared[] = $name;

                updateMemberLid("", $shared_member_lid, $member_lid, "services_groups_id");

                //cleanDuplicatedMembersMerging($shared_member_lid, "services_groups_id");

            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE services_groups_id SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM services_groups_id WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
    }

    //clean_duplicated_members("services_groups");

    if( count($remove_object) > 0 )
    {
        $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $remove_object) . ");");
        $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $remove_object) . ");");
        if( $where == "notall" )
        {
            $objects_to_shared = implode(",", $name_int_to_shared);
        }
        else
        {
            $objects_to_shared = "All Services Groups";
        }
        add_log('ok', 'Convert to Shared', 'Convert Services Groups: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');

    }
    return 1;
}

function convertRegionsToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, used, vsys, devicegroup, source, latitude, longitude, address "
        . "FROM regions WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $used = $data['used'];
            $devicegroup = $data['devicegroup'];
            $latitude = $data['latitude'];
            $longitude = $data['longitude'];
            $address = $data['address'];

            $getExistShared = $projectdb->query("SELECT id FROM regions WHERE vsys = 'shared' AND BINARY name = '$name' AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "regions");

                cleanDuplicatedMembersMerging($first_member_lid, "regions");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE regions SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM regions WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Regions";
            }
            add_log('ok', 'Convert to Shared', 'Convert Regions: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertApplicationsToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, devicegroup, description, category, subcategory, parent_app, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout, spyware_ident "
        . "FROM applications WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $description = $data['description'];
            $category = $data['category'];
            $subcategory = $data['subcategory'];
            $parent_app = $data['parent_app'];
            $risk = $data['risk'];
            $technology = $data['technology'];
            $evasive_behavior = $data['evasive_behavior'];
            $consume_big_bandwidth = $data['consume_big_bandwidth'];
            $used_by_malware = $data['used_by_malware'];
            $able_to_transfer_file = $data['able_to_transfer_file'];
            $has_known_vulnerability = $data['has_known_vulnerability'];
            $tunnel_other_application = $data['tunnel_other_application'];
            $tunnel_applications = $data['tunnel_applications'];
            $prone_to_misuse = $data['prone_to_misuse'];
            $pervasive_use = $data['pervasive_use'];
            $file_type_ident = $data['file_type_ident'];
            $virus_ident = $data['virus_ident'];
            $data_ident = $data['data_ident'];
            $default_type = $data['default_type'];
            $value = $data['value'];
            $type = $data['type'];
            $code = $data['code'];
            $timeout = $data['timeout'];
            $tcp_timeout = $data['tcp_timeout'];
            $udp_timeout = $data['udp_timeout'];
            $tcp_half_closed_timeout = $data['tcp_half_closed_timeout'];
            $tcp_time_wait_timeout = $data['tcp_time_wait_timeout'];
            $spyware_ident = $data['spyware_ident'];

            $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE table_name = 'applications' AND member_lid = '$member_lid';");
            $signature = "";
            if( $getSignature->num_rows > 0 )
            {
                $dataS = $getSignature->fetch_assoc();
                $signature = $dataS['signature'];
            }

            $getExistShared = $projectdb->query("SELECT id FROM applications WHERE vsys = 'shared' AND BINARY name = '$name' AND description = '$description' AND category = '$category' AND subcategory = '$subcategory' AND parent_app = '$parent_app' AND risk = '$risk' AND technology = '$technology' AND evasive_behavior = '$evasive_behavior' AND consume_big_bandwidth = '$consume_big_bandwidth' AND used_by_malware = '$used_by_malware' AND able_to_transfer_file = '$able_to_transfer_file' AND has_known_vulnerability = '$has_known_vulnerability' AND tunnel_other_application = '$tunnel_other_application' AND tunnel_applications = '$tunnel_applications' AND prone_to_misuse = '$prone_to_misuse' AND pervasive_use = '$pervasive_use' AND file_type_ident = '$file_type_ident' AND virus_ident = '$virus_ident' AND data_ident = '$data_ident' AND default_type = '$default_type' ANd value = '$value' AND type = '$type' AND code = '$code' AND timeout = '$timeout' AND tcp_timeout = '$tcp_timeout' AND udp_timeout = '$udp_timeout' AND spyware_ident = '$spyware_ident' AND tcp_half_closed_timeout = '$tcp_half_closed_timeout' AND tcp_time_wait_timeout = '$tcp_time_wait_timeout' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "applications");

                cleanDuplicatedMembersMerging($first_member_lid, "applications");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE applications SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM applications WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM applications WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Applications";
            }
            add_log('ok', 'Convert to Shared', 'Convert Applications: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertApplicationsGroupsToShared($source, $ids, $where)
{

    global $projectdb;

    $member_object = array();
    $member_objectgroup = array();
    $member_objectfilter = array();
    $remove_object = array();

    checkExistShared($source);

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, used, devicegroup, vsys, source, invalid  "
            . "FROM applications_groups_id WHERE id = '$member_lid' AND vsys != 'shared';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $used = $data['used'];
            $devicegroup = $data['devicegroup'];
            $invalid = $data['invalid'];

            #Check if the members are all shared
            $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member FROM applications_groups WHERE lid = '$member_lid' "
                . "AND (table_name = 'applications' OR table_name = 'applications_groups_id' OR table_name = 'default_applications' OR table_name = 'applications_filters');");

            if( $getAllmembers->num_rows > 0 )
            {
                while( $data = $getAllmembers->fetch_assoc() )
                {
                    $table_name_sql = $data['table_name'];
                    $member_lid_sql = $data['member_lid'];

                    if( $table_name_sql == "applications_groups_id" )
                    {
                        $member_objectgroup[] = $member_lid_sql;
                    }
                    elseif( $table_name_sql == "applications" )
                    {
                        $member_object[] = $member_lid_sql;
                    }
                    elseif( $table_name_sql == "applications_filters" )
                    {
                        $member_objectfilter[] = $member_lid_sql;
                    }
                }
                if( count($member_object) > 0 )
                {
                    convertApplicationsToShared($source, $member_object, "notall");
                }
                if( count($member_objectgroup) > 0 )
                {
                    convertApplicationsGroupsToShared($source, $member_objectgroup, "notall");
                }
                if( count($member_objectfilter) > 0 )
                {
                    convertApplicationsFiltersToShared($source, $member_objectfilter, "notall");
                }
            }

            $getExistShared = $projectdb->query("SELECT id FROM applications_groups_id WHERE vsys = 'shared' AND BINARY name = '$name' AND devicegroup = '$devicegroup' AND invalid = '$invalid' AND source = '$source';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $shared_member_lid = $getESData['id'];

                $remove_object[] = $member_lid;
                $name_int_to_shared[] = $name;

                updateMemberLid("", $shared_member_lid, $member_lid, "applications_groups_id");

                cleanDuplicatedMembersMerging($shared_member_lid, "applications_groups_id");

            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE applications_groups_id SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM applications_groups_id WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
    }

    clean_duplicated_members("applications_groups");

    if( count($remove_object) > 0 )
    {
        $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $remove_object) . ");");
        $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $remove_object) . ");");
        if( $where == "notall" )
        {
            $objects_to_shared = implode(",", $name_int_to_shared);
        }
        else
        {
            $objects_to_shared = "All Applications Groups";
        }
        add_log('ok', 'Convert to Shared', 'Convert Applications Groups: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');

    }
    return 1;
}

function convertApplicationsFiltersToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name  "
        . "FROM applications_filters WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];

            $getExistShared = $projectdb->query("SELECT id FROM applications_filters WHERE vsys = 'shared' AND BINARY name = '$name' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "applications_filters");

                cleanDuplicatedMembersMerging($first_member_lid, "applications_filters");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE applications_filters SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM applications_filters WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM applications_filters WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Applications Filters";
            }
            add_log('ok', 'Convert to Shared', 'Convert Applications Filters: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertTagToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, color, comments, source, vsys, devicegroup "
        . "FROM tag WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $color = $data['color'];
            $comments = $data['comments'];
            $devicegroup = $data['devicegroup'];

            $getExistShared = $projectdb->query("SELECT id FROM tag WHERE vsys = 'shared' AND BINARY name = '$name' AND color = '$color' AND comments = '$comments' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "tag");

                cleanDuplicatedMembersMerging($first_member_lid, "tag");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE tag SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM tag WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM tag WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Tags";
            }
            add_log('ok', 'Convert to Shared', 'Convert Tags: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertExternalToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
        . "FROM external_list WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];

            $getExistShared = $projectdb->query("SELECT id FROM external_list WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND xml = '$xml' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "external_list");

                cleanDuplicatedMembersMerging($first_member_lid, "external_list");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE external_list SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM external_list WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM external_list WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All External List";
            }
            add_log('ok', 'Convert to Shared', 'Convert External List: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertLogSettingsToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
        . "FROM log_settings WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];

            $getExistShared = $projectdb->query("SELECT id FROM log_settings WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND xml = '$xml' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE log_settings SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM log_settings WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM external_list WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Log Settings";
            }
            add_log('ok', 'Convert to Shared', 'Convert Log Settings: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertSchedulesToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
        . "FROM schedules WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];

            $getExistShared = $projectdb->query("SELECT id FROM schedules WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND xml = '$xml' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE schedules SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM schedules WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM schedules WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Schedules";
            }
            add_log('ok', 'Convert to Shared', 'Convert Schedules: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertProfilesToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
        . "FROM profiles WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $type = $data['type'];
            $xml = $data['xml'];

            $getExistShared = $projectdb->query("SELECT id FROM profiles WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND xml = '$xml' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "profiles");

                cleanDuplicatedMembersMerging($first_member_lid, "profiles");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE profiles SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM profiles WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM profiles WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Profiles";
            }
            add_log('ok', 'Convert to Shared', 'Convert Profiles: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertProfilesGroupsToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
        . "FROM profiles_groups WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $type = $data['type'];
            $xml = $data['xml'];

            $getExistShared = $projectdb->query("SELECT id FROM profiles_groups WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND xml = '$xml' AND source = '$source';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                updateMemberLid("", $first_member_lid, $member_lid, "profiles_groups");

                cleanDuplicatedMembersMerging($first_member_lid, "profiles_groups");

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE profiles_groups SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM profiles_groups WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM profiles_groups WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Profiles Groups";
            }
            add_log('ok', 'Convert to Shared', 'Convert Profiles Groups: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function convertServerProfileToShared($source, $ids, $where)
{

    global $projectdb;
    $remove_objects = array();

    checkExistShared($source);

    $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, template "
        . "FROM server_profile WHERE id IN (" . implode(',', $ids) . ") AND vsys != 'shared';");

    if( $getOriginal->num_rows > 0 )
    {
        while( $data = $getOriginal->fetch_assoc() )
        {

            $member_lid = $data['id'];
            $name = $data['name'];
            $template = $data['template'];
            $type = $data['type'];
            $xml = $data['xml'];

            $getExistShared = $projectdb->query("SELECT id FROM server_profile WHERE vsys = 'shared' AND BINARY name = '$name' AND type = '$type' AND xml = '$xml' AND source = '$source' AND template = '$template';");

            if( $getExistShared->num_rows > 0 )
            {

                $getESData = $getExistShared->fetch_assoc();
                $first_member_lid = $getESData['id'];

                $remove_objects[] = $member_lid;
                $name_int_to_shared[] = $name;
            }
            elseif( $getExistShared->num_rows == 0 )
            {

                $projectdb->query("UPDATE server_profile SET vsys = 'shared' WHERE id = '$member_lid';");
                $getName = $projectdb->query("SELECT name FROM server_profile WHERE id = '$member_lid';");
                while( $dataN = $getName->fetch_assoc() )
                {
                    $name_int_to_shared[] = $dataN['name'];
                }
            }
        }
        if( count($remove_objects) > 0 )
        {
            $projectdb->query("DELETE FROM server_profile WHERE id IN (" . implode(",", $remove_objects) . ");");
            if( $where == "notall" )
            {
                $objects_to_shared = implode(",", $name_int_to_shared);
            }
            else
            {
                $objects_to_shared = "All Server Profiles";
            }
            add_log('ok', 'Convert to Shared', 'Convert Server Profile: [' . $objects_to_shared . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }

    return 1;
}

function updateMemberLid($projectName, $primary_member_lid, $member_lid, $table_name)
{

    global $projectdb;

    if( $projectName != "" )
    {
        $projectdb = selectDatabase($projectName);
    }

    if( ($table_name == "address") || ($table_name == "address_groups_id") || ($table_name == "external_list") )
    {

        if( $table_name == "address_groups_id" )
        {
            #UPDATE MEMBERS
            $projectdb->query("UPDATE address_groups SET lid = '$primary_member_lid' WHERE lid = '$member_lid';");
        }
        $projectdb->query("UPDATE address_groups SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_translated_address SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_translated_address_fallback SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid = '$primary_member_lid' WHERE tp_dat_address_lid = '$member_lid' AND tp_dat_address_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE authentication_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        $projectdb->query("UPDATE tag_relations SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

    }
    elseif( ($table_name == "services") || ($table_name == "services_groups_id") )
    {

        if( $table_name == "services_groups_id" )
        {
            #UPDATE MEMBERS
            $projectdb->query("UPDATE services_groups SET lid = '$primary_member_lid' WHERE lid = '$member_lid';");
        }

        $projectdb->query("UPDATE services_groups SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules SET op_service_lid = '$primary_member_lid' WHERE op_service_lid = '$member_lid' AND op_service_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        $projectdb->query("UPDATE tag_relations SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

    }
    elseif( ($table_name == "applications") || ($table_name == "applications_filters") || ($table_name == "applications_groups_id") )
    {

        if( $table_name == "applications_groups_id" )
        {
            #UPDATE MEMBERS
            $projectdb->query("UPDATE applications_groups SET lid = '$primary_member_lid' WHERE lid = '$member_lid';");
        }

        $projectdb->query("UPDATE applications_groups SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules SET app_id = '$primary_member_lid' WHERE app_id = '$member_lid' AND app_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE pbf_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        if( $table_name == "applications" )
        {
            $projectdb->query("UPDATE applications_signatures SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        }

    }
    elseif( $table_name == "regions" )
    {

        $projectdb->query("UPDATE security_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE decryption_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        $projectdb->query("UPDATE authentication_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE authentication_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

    }
    elseif( $table_name == "tag" )
    {

        $projectdb->query("UPDATE security_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");


    }
    elseif( ($table_name == "profiles") || ($table_name == "profiles_groups") )
    {

        $projectdb->query("UPDATE security_rules_hip SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_profiles SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_hip SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

    }
    elseif( $table_name == "log_settings" )
    {

        $projectdb->query("UPDATE security_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding = '$member_lid';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding = '$member_lid';");
        $projectdb->query("UPDATE decryption_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding = '$member_lid';");
        $projectdb->query("UPDATE dos_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding = '$member_lid';");
        $projectdb->query("UPDATE tunnel_inspect_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding = '$member_lid';");

    }

    #UPDATE LOGS TO THE NEW Rule
    $projectdb->query("UPDATE logs SET obj_id = '$primary_member_lid', obj_table = '$table_name' WHERE obj_id = '$member_lid' AND obj_table = '$table_name';");


}

function updateMemberLidBulks(MySQLi $projectdb, INT $primary_member_lid, array $member_lids, STRING $table_name)
{

    if( ($table_name == "address") || ($table_name == "address_groups_id") || ($table_name == "external_list") )
    {

        if( $table_name == "address_groups_id" )
        {
            #UPDATE MEMBERS
            $projectdb->query("UPDATE address_groups SET lid = '$primary_member_lid' WHERE lid IN (" . implode(",", $member_lids) . ");");
        }
        $projectdb->query("UPDATE address_groups SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_translated_address SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_translated_address_fallback SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid = '$primary_member_lid' WHERE tp_dat_address_lid IN (" . implode(",", $member_lids) . ") AND tp_dat_address_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE authentication_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");

    }
    elseif( ($table_name == "services") || ($table_name == "services_groups_id") )
    {

        if( $table_name == "services_groups_id" )
        {
            #UPDATE MEMBERS
            $projectdb->query("UPDATE services_groups SET lid = '$primary_member_lid' WHERE lid IN (" . implode(",", $member_lids) . ");");
        }

        $projectdb->query("UPDATE services_groups SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules SET op_service_lid = '$primary_member_lid' WHERE op_service_lid IN (" . implode(",", $member_lids) . ") AND op_service_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");

    }
    elseif( ($table_name == "applications") || ($table_name == "applications_filters") || ($table_name == "applications_groups_id") )
    {

        if( $table_name == "applications_groups_id" )
        {
            #UPDATE MEMBERS
            $projectdb->query("UPDATE applications_groups SET lid = '$primary_member_lid' WHERE lid IN (" . implode(",", $member_lids) . ");");
        }

        $projectdb->query("UPDATE applications_groups SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules SET app_id = '$primary_member_lid' WHERE app_id IN (" . implode(",", $member_lids) . ") AND app_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE pbf_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");

        if( $table_name == "applications" )
        {
            $projectdb->query("UPDATE applications_signatures SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        }

    }
    elseif( $table_name == "regions" )
    {

        $projectdb->query("UPDATE security_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE authentication_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");

    }
    elseif( $table_name == "tag" )
    {

        $projectdb->query("UPDATE security_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_tag SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
    }
    elseif( ($table_name == "profiles") || ($table_name == "profiles_groups") )
    {

        $projectdb->query("UPDATE security_rules_hip SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_profiles SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_hip SET member_lid = '$primary_member_lid' WHERE member_lid IN (" . implode(",", $member_lids) . ") AND table_name = '$table_name';");
    }
    elseif( $table_name == "log_settings" )
    {

        $projectdb->query("UPDATE security_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding IN (" . implode(",", $member_lids) . ");");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding IN (" . implode(",", $member_lids) . ");");
        $projectdb->query("UPDATE decryption_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding IN (" . implode(",", $member_lids) . ");");
        $projectdb->query("UPDATE dos_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding IN (" . implode(",", $member_lids) . ");");
        $projectdb->query("UPDATE tunnel_inspect_rules SET log_forwarding = '$primary_member_lid' WHERE log_forwarding IN (" . implode(",", $member_lids) . ");");
    }


    #UPDATE LOGS TO THE NEW Rule
    $projectdb->query("UPDATE logs SET obj_id = '$primary_member_lid', obj_table = '$table_name' WHERE obj_id IN (" . implode(",", $member_lids) . ") AND obj_table = '$table_name';");


}

function replaceMemberLid($projectName, $primary_member_lid, $member_lid, $table_name)
{

    global $projectdb;

    if( $projectName != "" )
    {
        $projectdb = selectDatabase($projectName);
    }

    if( ($table_name == "address") || ($table_name == "address_groups_id") || ($table_name == "external_list") )
    {

        $projectdb->query("UPDATE address_groups SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_translated_address SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules_translated_address_fallback SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid = '$primary_member_lid' WHERE tp_dat_address_lid = '$member_lid' AND tp_dat_address_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE authentication_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_dst SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_src SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
    }
    elseif( ($table_name == "services") || ($table_name == "services_groups_id") )
    {

        $projectdb->query("UPDATE services_groups SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE nat_rules SET op_service_lid = '$primary_member_lid' WHERE op_service_lid = '$member_lid' AND op_service_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE authentication_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE decryption_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE dos_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE pbf_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE captiveportal_rules_srv SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

    }
    elseif( ($table_name == "applications") || ($table_name == "applications_filters") || ($table_name == "applications_groups_id") )
    {

        $projectdb->query("UPDATE applications_groups SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE security_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE appoverride_rules SET app_id = '$primary_member_lid' WHERE app_id = '$member_lid' AND app_table = '$table_name';");

        # Add Other Rules
        $projectdb->query("UPDATE pbf_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE qos_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        $projectdb->query("UPDATE tunnel_inspect_rules_app SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");

        if( $table_name == "applications" )
        {
            $projectdb->query("UPDATE applications_signatures SET member_lid = '$primary_member_lid' WHERE member_lid = '$member_lid' AND table_name = '$table_name';");
        }

    }
    #UPDATE LOGS TO THE NEW Rule
    $projectdb->query("UPDATE logs SET obj_id = '$primary_member_lid', obj_table = '$table_name' WHERE obj_id = '$member_lid' AND obj_table = '$table_name';");


}

function cleanDuplicatedMembersMerging($primary_member_lid, $table_name)
{

    if( ($table_name == "address") || ($table_name == "address_groups_id") || ($table_name == "external_list") )
    {
        // Clean the duplicates member to security rules
        clean_duplicated_members_merging("security_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("security_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("nat_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("nat_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("nat_rules_translated_address", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("nat_rules_translated_address_fallback", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("appoverride_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("appoverride_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("address_groups", $primary_member_lid, $table_name);

        # Add Other Rules
        clean_duplicated_members_merging("authentication_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("authentication_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("decryption_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("decryption_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("dos_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("dos_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("pbf_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("pbf_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("qos_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("qos_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("tunnel_inspect_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("tunnel_inspect_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("captiveportal_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("captiveportal_rules_src", $primary_member_lid, $table_name);


        clean_duplicated_members_merging("tag_relations", $primary_member_lid, $table_name);

    }
    elseif( ($table_name == "services") || ($table_name == "services_groups_id") )
    {

        clean_duplicated_members_merging("security_rules_srv", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("services_groups", $primary_member_lid, $table_name);

        # Add Other Rules
        clean_duplicated_members_merging("authentication_rules_srv", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("decryption_rules_srv", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("dos_rules_srv", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("pbf_rules_srv", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("qos_rules_srv", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("captiveportal_rules_srv", $primary_member_lid, $table_name);

    }
    elseif( ($table_name == "applications") || ($table_name == "applications_filters") || ($table_name == "applications_groups_id") )
    {

        clean_duplicated_members_merging("security_rules_app", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("applications_groups", $primary_member_lid, $table_name);

        # Add Other Rules
        clean_duplicated_members_merging("pbf_rules_app", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("qos_rules_app", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("tunnel_inspect_rules_app", $primary_member_lid, $table_name);

    }
    elseif( $table_name == "regions" )
    {

        clean_duplicated_members_merging("security_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("security_rules_dst", $primary_member_lid, $table_name);

        # Add Other Rules
        clean_duplicated_members_merging("decryption_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("decryption_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("dos_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("dos_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("tunnel_inspect_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("tunnel_inspect_rules_src", $primary_member_lid, $table_name);

        clean_duplicated_members_merging("authentication_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("authentication_rules_dst", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("captiveportal_rules_src", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("captiveportal_rules_dst", $primary_member_lid, $table_name);

    }
    elseif( $table_name == "tag" )
    {

        clean_duplicated_members_merging("security_rules_tag", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("nat_rules_tag", $primary_member_lid, $table_name);

        # Add Other Rules
        clean_duplicated_members_merging("authentication_rules_tag", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("decryption_rules_tag", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("dos_rules_tag", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("pbf_rules_tag", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("qos_rules_tag", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("tunnel_inspect_rules_tag", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("captiveportal_rules_tag", $primary_member_lid, $table_name);

    }
    elseif( ($table_name == "profiles") || ($table_name == "profiles_groups") )
    {

        clean_duplicated_members_merging("security_rules_hip", $primary_member_lid, $table_name);
        clean_duplicated_members_merging("security_rules_profiles", $primary_member_lid, $table_name);

        # Add Other Rules
        clean_duplicated_members_merging("authentication_rules_hip", $primary_member_lid, $table_name);

    }

}

function duplicateAddressGroupsToShared($source, $ids)
{

    global $projectdb;

    $shared_group_duplicate_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name_ext, name, used, devicegroup, vsys, source, tag, checkit, invalid, filter, type "
            . "FROM address_groups_id WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $name_ext = $data['name_ext'];
            $devicegroup = $data['devicegroup'];
            $invalid = $data['invalid'];
            $tag = $data['tag'];
            $filter = addslashes($data['filter']);
            $type = $data['type'];

            $getExistShared = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name = '$name'"
                . " AND type = '$type' AND filter = '$filter' AND invalid = '$invalid' "
                . "AND tag = '$tag' AND source = '$source' AND vsys = 'shared';");

            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $shared_group_duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO address_groups_id (name_ext,name,devicegroup,vsys,source,tag,invalid,filter,type)  "
                    . "VALUES ('$name_ext','$name','$devicegroup','shared','$source','$tag','$invalid','$filter','$type');");
                $shared_group_duplicate_member_lid = $projectdb->insert_id;
            }
        }

        #Check if the members are all shared
        $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member, devicegroup FROM address_groups WHERE lid = '$member_lid' "
            . "AND (table_name = 'address' OR table_name = 'address_groups_id');");

        if( $getAllmembers->num_rows > 0 )
        {
            while( $data = $getAllmembers->fetch_assoc() )
            {

                $table_name_sql = $data['table_name'];
                $member_lid_sql = $data['member_lid'];
                $devicegroup = $data['devicegroup'];

                $member_lid_sql = explode(',', $member_lid_sql);
                if( $table_name_sql == "address_groups_id" )
                {

                    $shared_group_member_lid = duplicateAddressGroupsToShared($source, $member_lid_sql);
                    $getExistSharedMember = $projectdb->query("SELECT id FROM address_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$shared_group_member_lid' AND table_name = 'address_groups_id' ;");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO address_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$shared_group_member_lid', 'address_groups_id', 'shared', '$devicegroup', '');");

                    }
                }
                elseif( $table_name_sql == "address" )
                {
                    $duplicate_member_lid = cloneAddress($source, "", "shared", $member_lid_sql);
                    $getExistSharedMember = $projectdb->query("SELECT id FROM address_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$duplicate_member_lid' AND table_name = 'address' ;");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO address_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$duplicate_member_lid', 'address', 'shared', '$devicegroup', '');");
                    }
                }
            }
        }
        add_log('ok', 'Clone to Shared', 'Clone Address Group: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');


    }

    return $shared_group_duplicate_member_lid;
}

function duplicateServicesToShared($source, $ids)
{

    global $projectdb;

    $data = explode(",", $ids);
    $duplicate_member_lid = 0;

    foreach( $data as $key => $value )
    {

        $values = explode(";", $value);
        $member_lid = $values[0];
        $table_name = $values[1];
        $name_int = $values[2];

        $getMember = $projectdb->query("SELECT id,name_ext,name,vsys,devicegroup,description,sport,dport,protocol,icmp,source,tag "
            . "FROM $table_name WHERE id='$member_lid';");
        if( $getMember->num_rows > 0 )
        {
            $data = $getMember->fetch_assoc();
            $name_int = $data['name'];
            $name_ext = $data['name_ext'];
            $devicegroup = $data['devicegroup'];
            $protocol = $data['protocol'];
            $description = $data['description'];
            $dport = $data['dport'];
            $sport = $data['sport'];
            $icmp = $data['icmp'];
            $tag = $data['tag'];

            $getExistShared = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext = '$name_ext' AND BINARY name = '$name_int' "
                . "AND devicegroup = '$devicegroup' AND description = '$description' AND protocol = '$protocol' AND dport = '$dport' "
                . "AND sport = '$sport' AND icmp = '$icmp' AND tag = '$tag' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO services (name_ext,name,devicegroup,vsys,protocol,sport,description,dport,icmp,source,tag)  "
                    . "VALUES ('$name_int','$name_int','$devicegroup','shared','$protocol','$sport','$description','$dport','$icmp','$source','$tag');");
                $duplicate_member_lid = $projectdb->insert_id;
            }
        }
        add_log('ok', 'Clone to Shared', 'Clone Service: [' . $name_int . '] to Shared. ', $source, 'No Action Required', '2');

    }
    return $duplicate_member_lid;
}

function duplicateServicesGroupsToShared($source, $ids)
{

    global $projectdb;

    $shared_group_duplicate_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id,name_ext,name,used,devicegroup,vsys,source,tag,checkit,invalid,filter,type "
            . "FROM services_groups_id WHERE id='$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $name_ext = $data['name_ext'];
            $devicegroup = $data['devicegroup'];
            $invalid = $data['invalid'];
            $tag = $data['tag'];
            $filter = addslashes($data['filter']);
            $type = $data['type'];

            $getExistShared = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext = '$name_ext' "
                . "AND BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' "
                . "AND filter = '$filter' AND invalid = '$invalid' AND tag = '$tag' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $shared_group_duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO services_groups_id (name_ext,name,devicegroup,vsys,source,tag,invalid,filter,type)  "
                    . "VALUES ('$name_ext','$name','$devicegroup','shared','$source','$tag','$invalid','$filter','$type');");
                $shared_group_duplicate_member_lid = $projectdb->insert_id;
            }
        }

        #Check if the members are all shared
        $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member, devicegroup FROM services_groups WHERE lid = '$member_lid' "
            . "AND (table_name = 'services' OR table_name = 'services_groups_id');");

        if( $getAllmembers->num_rows > 0 )
        {
            while( $data = $getAllmembers->fetch_assoc() )
            {

                $table_name_sql = $data['table_name'];
                $member_lid_sql = $data['member_lid'];
                $devicegroup = $data['devicegroup'];

                $member_lid_sql = explode(',', $member_lid_sql);
                if( $table_name_sql == "services_groups_id" )
                {

                    $shared_group_member_lid = duplicateServicesGroupsToShared($source, $member_lid_sql);
                    $getExistSharedMember = $projectdb->query("SELECT id FROM services_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$shared_group_member_lid' AND table_name = 'services_groups_id' ;");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO services_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$shared_group_member_lid', 'services_groups_id', 'shared', '$devicegroup', '');");

                    }
                }
                elseif( $table_name_sql == "services" )
                {
                    $duplicate_member_lid = cloneServices($source, "", "shared", $member_lid_sql);
                    $getExistSharedMember = $projectdb->query("SELECT id FROM services_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$duplicate_member_lid' AND table_name = 'services' ;");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO services_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$duplicate_member_lid', 'services', 'shared', '$devicegroup', '');");
                    }
                }
            }
        }
        add_log('ok', 'Clone to Shared', 'Clone Service Group: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');


    }

    return $shared_group_duplicate_member_lid;
}

function duplicateTagToShared($source, $ids)
{

    global $projectdb;
    $data = explode(",", $ids);

    foreach( $data as $key => $value )
    {

        $values = explode(";", $value);
        $member_lid = $values[0];
        $table_name = $values[1];

        $getOriginal = $projectdb->query("SELECT id, name, color, comments, source, vsys, devicegroup "
            . "FROM $table_name WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $color = $data['color'];
            $comments = $data['comments'];
            $devicegroup = $data['devicegroup'];

            $getExistShared = $projectdb->query("SELECT id FROM tag WHERE BINARY name = '$name' AND color = '$color' "
                . "AND devicegroup = '$devicegroup' AND comments = '$comments' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup)  "
                    . "VALUES ('$name', '$color', '$comments', '$source', 'shared', '$devicegroup');");
                $duplicate_member_lid = $projectdb->insert_id;
            }
        }
        add_log('ok', 'Clone to Shared', 'Clone Tag: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');
    }
    return $duplicate_member_lid;
}

function duplicateRegionsToShared($source, $ids)
{

    global $projectdb;
    $data = explode(",", $ids);

    foreach( $data as $key => $value )
    {

        $values = explode(";", $value);
        $member_lid = $values[0];
        $table_name = $values[1];

        $getMember = $projectdb->query("SELECT name, xml, type, devicegroup FROM $table_name WHERE id = '$member_lid';");
        if( $getMember->num_rows > 0 )
        {
            $getMemData = $getMember->fetch_assoc();
            $name = $getMemData['name'];
            $xml = $getMemData['xml'];
            $type = $getMemData['type'];
            $devicegroup = $getMemData['devicegroup'];

            $getExistShared = $projectdb->query("SELECT id FROM regions WHERE BINARY name = '$name' AND xml = '$xml' "
                . "AND devicegroup = '$devicegroup' AND type = '$type' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO regions (name, xml, devicegroup, vsys, type, source)  "
                    . "VALUES ('$name', '$xml', '$devicegroup','shared', '$type', '$source');");
                $duplicate_member_lid = $projectdb->insert_id;
            }
            add_log('ok', 'Clone to Shared', 'Clone Region: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }
    return $duplicate_member_lid;
}

function duplicateExternalToShared($source, $ids)
{

    global $projectdb;
    $data = explode(",", $ids);

    foreach( $data as $key => $value )
    {

        $values = explode(";", $value);
        $member_lid = $values[0];
        $table_name = $values[1];

        $getMember = $projectdb->query("SELECT name, xml, type, devicegroup FROM $table_name WHERE id = '$member_lid';");
        if( $getMember->num_rows > 0 )
        {
            $getMemData = $getMember->fetch_assoc();
            $name = $getMemData['name'];
            $xml = $getMemData['xml'];
            $type = $getMemData['type'];
            $devicegroup = $getMemData['devicegroup'];

            $getExistShared = $projectdb->query("SELECT id FROM external_list WHERE BINARY name = '$name' AND xml = '$xml' "
                . "AND devicegroup = '$devicegroup' AND type = '$type' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO external_list (name, xml, devicegroup, vsys, type, source)  "
                    . "VALUES ('$name', '$xml', '$devicegroup','shared', '$type', '$source');");
                $duplicate_member_lid = $projectdb->insert_id;
            }
            add_log('ok', 'Clone to Shared', 'Clone External List: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }
    return $duplicate_member_lid;
}

function duplicateApplicationsFiltersToShared($source, $ids)
{

    global $projectdb;
    $data = explode(",", $ids);

    foreach( $data as $key => $value )
    {

        $values = explode(";", $value);
        $member_lid = $values[0];
        $table_name = $values[1];

        $getMember = $projectdb->query("SELECT name, devicegroup, category, subcategory, risk, technology, evasive_behavior, 
            consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, prone_to_misuse, 
            pervasive_use, type, vsys FROM $table_name WHERE id = '$member_lid';");

        if( $getMember->num_rows > 0 )
        {
            $data = $getMember->fetch_assoc();
            $name_int = $data['name'];
            $devicegroup = $data['devicegroup'];
            $category = $data['category'];
            $subcategory = $data['subcategory'];
            $risk = $data['risk'];
            $technology = $data['technology'];
            $evasive_behavior = $data['evasive_behavior'];
            $consume_big_bandwidth = $data['consume_big_bandwidth'];
            $used_by_malware = $data['used_by_malware'];
            $able_to_transfer_file = $data['able_to_transfer_file'];
            $has_known_vulnerability = $data['has_known_vulnerability'];
            $tunnel_other_application = $data['tunnel_other_application'];
            $prone_to_misuse = $data['prone_to_misuse'];
            $pervasive_use = $data['pervasive_use'];
            $type = $data['type'];

            $getExist = $projectdb->query("SELECT id FROM applications_filters WHERE BINARY name = '$name_int' "
                . "AND source = '$source' AND vsys = 'shared' AND category = '$category' AND subcategory = '$subcategory' "
                . "AND risk = '$risk' AND technology = '$technology' AND evasive_behavior = '$evasive_behavior' "
                . "AND consume_big_bandwidth = '$consume_big_bandwidth' AND used_by_malware = '$used_by_malware' "
                . "AND able_to_transfer_file = '$able_to_transfer_file' AND has_known_vulnerability = '$has_known_vulnerability' "
                . "AND tunnel_other_application = '$tunnel_other_application' AND prone_to_misuse = '$prone_to_misuse' "
                . "AND pervasive_use = '$pervasive_use' AND type = '$type';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $duplicate_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO applications_filters (name, vsys, source, devicegroup, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, prone_to_misuse, pervasive_use, type)  "
                    . "VALUES ('$name_int', 'shared', '$source', '$devicegroup', '$category', '$subcategory', '$risk', '$technology', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$prone_to_misuse', '$pervasive_use', '$type');");
                $duplicate_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Applications Filters', 'Clone Applications Filters: [' . $name_int . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $duplicate_member_lid;
}

function duplicateApplicationsToShared($source, $ids)
{

    global $projectdb;
    $data = explode(",", $ids);

    foreach( $data as $key => $value )
    {

        $values = explode(";", $value);
        $member_lid = $values[0];
        $table_name = $values[1];

        $getMember = $projectdb->query("SELECT name, devicegroup, description, category, subcategory, parent_app, risk, technology, evasive_behavior, 
            consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, 
            prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, 
            tcp_half_closed_timeout, tcp_time_wait_timeout, spyware_ident  FROM $table_name WHERE id = '$member_lid';");
        if( $getMember->num_rows > 0 )
        {
            $getMemData = $getMember->fetch_assoc();
            $name = $getMemData['name'];
            $devicegroup = $getMemData['devicegroup'];
            $description = $getMemData['description'];
            $category = $getMemData['category'];
            $subcategory = $getMemData['subcategory'];
            $parent_app = $getMemData['parent_app'];
            $risk = $getMemData['risk'];
            $technology = $getMemData['technology'];
            $evasive_behavior = $getMemData['evasive_behavior'];
            $consume_big_bandwidth = $getMemData['consume_big_bandwidth'];
            $used_by_malware = $getMemData['used_by_malware'];
            $able_to_transfer_file = $getMemData['able_to_transfer_file'];
            $has_known_vulnerability = $getMemData['has_known_vulnerability'];
            $tunnel_other_application = $getMemData['tunnel_other_application'];
            $tunnel_applications = $getMemData['tunnel_applications'];
            $prone_to_misuse = $getMemData['prone_to_misuse'];
            $pervasive_use = $getMemData['pervasive_use'];
            $file_type_ident = $getMemData['file_type_ident'];
            $virus_ident = $getMemData['virus_ident'];
            $data_ident = $getMemData['data_ident'];
            $default_type = $getMemData['default_type'];
            $value = $getMemData['value'];
            $type = $getMemData['type'];
            $code = $getMemData['code'];
            $timeout = $getMemData['timeout'];
            $tcp_timeout = $getMemData['tcp_timeout'];
            $udp_timeout = $getMemData['udp_timeout'];
            $tcp_half_closed_timeout = $getMemData['tcp_half_closed_timeout'];
            $tcp_time_wait_timeout = $getMemData['tcp_time_wait_timeout'];
            $spyware_ident = $getMemData['spyware_ident'];
            $signature = "";

            $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE table_name = '$table_name' AND member_lid = '$member_lid';");

            if( $getSignature->num_rows > 0 )
            {
                $dataS = $getSignature->fetch_assoc();
                $signature = $dataS['signature'];
            }

            $getExistShared = $projectdb->query("SELECT id FROM applications WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' "
                . "AND description = '$description' AND category = '$category' AND subcategory = '$subcategory' "
                . "AND parent_app = '$parent_app' AND risk = '$risk' AND technology = '$technology' AND evasive_behavior = '$evasive_behavior' "
                . "AND consume_big_bandwidth = '$consume_big_bandwidth' AND used_by_malware = '$used_by_malware' "
                . "AND able_to_transfer_file = '$able_to_transfer_file' AND has_known_vulnerability = '$has_known_vulnerability' "
                . "AND tunnel_other_application = '$tunnel_other_application' AND tunnel_applications = '$tunnel_applications' "
                . "AND prone_to_misuse = '$prone_to_misuse' AND pervasive_use = '$pervasive_use' AND file_type_ident = '$file_type_ident' "
                . "AND virus_ident = '$virus_ident' AND data_ident = '$data_ident' AND default_type = '$default_type' ANd value = '$value' "
                . "AND type = '$type' AND code = '$code' AND timeout = '$timeout' AND tcp_timeout = '$tcp_timeout' AND udp_timeout = '$udp_timeout' "
                . "AND spyware_ident = '$spyware_ident' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO applications (name, devicegroup, description, category, subcategory, parent_app, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout, spyware_ident, vsys, source)  "
                    . "VALUES ('$name', '$devicegroup', '$description', '$category', '$subcategory', '$parent_app', '$risk', '$technology', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$tunnel_applications', '$prone_to_misuse', '$pervasive_use', '$file_type_ident', '$virus_ident', '$data_ident', '$default_type', '$value', '$type', '$code', '$timeout', '$tcp_timeout', '$udp_timeout', '$tcp_half_closed_timeout', '$tcp_time_wait_timeout','$spyware_ident', 'shared', '$source');");
                $duplicate_member_lid = $projectdb->insert_id;

                $projectdb->query("INSERT INTO applications_signatures (vsys, source, devicegroup, signature, member_lid, table_name)  "
                    . "VALUES ('shared', '$source', '$devicegroup', '$signature', '$duplicate_member_lid', 'applications');");

            }
            add_log('ok', 'Clone to Shared', 'Clone Applications: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }
    return $duplicate_member_lid;
}

function duplicateApplicationsGroupsToShared($source, $ids)
{

    global $projectdb;
    $shared_group_duplicate_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, used, devicegroup, vsys, source, invalid "
            . "FROM applications_groups_id WHERE id='$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();

            $name = $data['name'];
            $name_int = $data['name'];
            $devicegroup = $data['devicegroup'];
            $invalid = $data['invalid'];

            $getExistShared = $projectdb->query("SELECT id FROM applications_groups_id WHERE BINARY name = '$name' "
                . "AND devicegroup = '$devicegroup' AND invalid = '$invalid' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $shared_group_duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO applications_groups_id (name, devicegroup, vsys, source, invalid)  "
                    . "VALUES ('$name', '$devicegroup', 'shared', '$source', '$invalid');");
                $shared_group_duplicate_member_lid = $projectdb->insert_id;
            }
        }

        #Check if the members are all shared
        $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member, devicegroup FROM applications_groups WHERE lid='$member_lid' "
            . "AND (table_name = 'applications' OR table_name = 'applications_groups_id' OR table_name = 'default_applications' OR table_name = 'applications_filters');");

        if( $getAllmembers->num_rows > 0 )
        {
            while( $data = $getAllmembers->fetch_assoc() )
            {
                $table_name_sql = $data['table_name'];
                $member_lid_sql = $data['member_lid'];
                $member_sql = $data['member'];
                $devicegroup = $data['devicegroup'];
                if( $member_sql == "" )
                {
                    $getNamePan = $projectdb->query("SELECT name FROM $table_name_sql WHERE id = '$member_lid_sql' ");
                    $data = $getNamePan->fetch_assoc();
                    $member_sql = $data['name'];
                }
                $data_function = $member_lid_sql . ";" . $table_name_sql . ";" . $member_sql;
                if( $table_name_sql == "applications_groups_id" )
                {
                    $shared_group_member_lid = duplicateApplicationsGroupsToShared($source, $data_function);
                    $getExistSharedMember = $projectdb->query("SELECT id FROM applications_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$shared_group_member_lid' AND table_name = 'applications_groups_id' ;");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO applications_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$shared_group_member_lid', 'applications_groups_id', 'shared', '$devicegroup', '$member_sql');");
                    }
                }
                elseif( $table_name_sql == "applications" )
                {

                    $duplicate_member_lid = duplicateApplicationsToShared($source, $data_function);
                    $getExistSharedMember = $projectdb->query("SELECT id FROM applications_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$duplicate_member_lid' AND table_name = 'applications';");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO applications_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$duplicate_member_lid', 'applications', 'shared', '$devicegroup', '$member_sql');");

                    }
                }
                elseif( $table_name_sql == "default_applications" )
                {

                    $getExistSharedMember = $projectdb->query("SELECT id FROM applications_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$member_lid_sql' AND table_name = 'default_applications';");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO applications_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$member_lid_sql', 'default_applications', 'shared', '$devicegroup', '$member_sql');");
                    }
                }
                elseif( $table_name_sql == "applications_filters" )
                {

                    $duplicate_member_lid = duplicateApplicationsFiltersToShared($source, $data_function);
                    $getExistSharedMember = $projectdb->query("SELECT id FROM applications_groups WHERE lid = '$shared_group_duplicate_member_lid' "
                        . "AND member_lid = '$duplicate_member_lid' AND table_name = 'applications_filters' ;");
                    if( $getExistSharedMember->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO applications_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                            . "VALUES ('$source', '$shared_group_duplicate_member_lid', '$duplicate_member_lid', 'applications_filters', 'shared', '$devicegroup', '$member_sql');");

                    }
                }
            }
        }
        add_log('ok', 'Clone to Shared', 'Clone Applications Group: [' . $name_int . '] to Shared. ', $source, 'No Action Required', '2');
    }
    return $shared_group_duplicate_member_lid;
}

function duplicateProfilesToShared($source, $ids)
{

    global $projectdb;
    $data = explode(",", $ids);

    foreach( $data as $key => $value )
    {

        $values = explode(";", $value);
        $member_lid = $values[0];
        $table_name = $values[1];

        $getMember = $projectdb->query("SELECT name, xml, type, devicegroup FROM $table_name WHERE id = '$member_lid';");
        if( $getMember->num_rows > 0 )
        {
            $getMemData = $getMember->fetch_assoc();
            $name = $getMemData['name'];
            $xml = $getMemData['xml'];
            $type = $getMemData['type'];
            $devicegroup = $getMemData['devicegroup'];

            $getExistShared = $projectdb->query("SELECT id FROM profiles WHERE BINARY name = '$name' AND xml = '$xml' AND devicegroup = '$devicegroup' "
                . "AND type = '$type' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO profiles (name, xml, devicegroup, vsys, type, source)  "
                    . "VALUES ('$name', '$xml', '$devicegroup', 'shared', '$type', '$source');");
                $duplicate_member_lid = $projectdb->insert_id;
            }
            add_log('ok', 'Clone to Shared', 'Clone Profiles: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }
    return $duplicate_member_lid;
}

function duplicateProfilesGroupsToShared($source, $ids)
{

    global $projectdb;
    $duplicate_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getMember = $projectdb->query("SELECT name, xml, type, devicegroup, vtype FROM profiles_groups WHERE id = '$member_lid';");
        if( $getMember->num_rows > 0 )
        {
            $getMemData = $getMember->fetch_assoc();
            $name = $getMemData['name'];
            $xml = $getMemData['xml'];
            $type = $getMemData['type'];
            $devicegroup = $getMemData['devicegroup'];
            $vtype = $getMemData['vtype'];

            $getExistShared = $projectdb->query("SELECT id FROM profiles_groups WHERE BINARY name = '$name' AND xml = '$xml' AND devicegroup = '$devicegroup' "
                . "AND type = '$type' AND vtype = '$vtype' AND source = '$source' AND vsys = 'shared';");
            if( $getExistShared->num_rows > 0 )
            {
                $getESData = $getExistShared->fetch_assoc();
                $duplicate_member_lid = $getESData['id'];
            }
            elseif( $getExistShared->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO profiles_groups (name, xml, devicegroup, vsys, type, vtype, source)  "
                    . "VALUES ('$name', '$xml', '$devicegroup', 'shared', '$type', '$vtype', '$source');");
                $duplicate_member_lid = $projectdb->insert_id;
            }
            add_log('ok', 'Clone to Shared', 'Clone Profiles Groups: [' . $name . '] to Shared. ', $source, 'No Action Required', '2');
        }
    }
    return $duplicate_member_lid;

}

function cloneAddress(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;
    $clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getMember = $projectdb->query("SELECT name_ext, name, checkit, devicegroup, type, ipaddress, cidr, description, fqdn, "
            . "v4, v6, vtype, tag, dummy, vsys FROM address WHERE id = '$member_lid' AND dummy = 0;");

        if( $getMember->num_rows > 0 )
        {
            $getMemData = $getMember->fetch_assoc();
            $name_ext = $getMemData['name_ext'];
            $name_int = $getMemData['name'];
            $checkit = $getMemData['checkit'];
            $devicegroup = $getMemData['devicegroup'];
            $type = $getMemData['type'];
            $ipaddress = $getMemData['ipaddress'];
            $cidr = $getMemData['cidr'];
            $description = $getMemData['description'];
            $fqdn = $getMemData['fqdn'];
            $v4 = $getMemData['v4'];
            $v6 = $getMemData['v6'];
            $vtype = $getMemData['vtype'];
            $tag = $getMemData['tag'];
            $dummy = $getMemData['dummy'];
            $vsys = $getMemData['vsys'];

            if( $vsys == $clone_to_vsys )
            {
                $name_int = "Cl-$name_int";
            }

            $getExist = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext = '$name_ext' AND BINARY name = '$name_int' "
                . "AND devicegroup = '$devicegroup' AND type = '$type' AND ipaddress = '$ipaddress' AND cidr = '$cidr' "
                . "AND description = '$description' AND fqdn = '$fqdn' AND v4 = '$v4' AND v6 = '$v6' AND vtype = '$vtype' "
                . "AND tag = '$tag' AND dummy = '$dummy' AND source = '$source' AND vsys = '$clone_to_vsys';");

            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO address (name_ext,name,checkit,devicegroup,vsys,type,ipaddress,cidr,description,fqdn,v4,v6,vtype,source,tag,dummy)  "
                    . "VALUES ('$name_ext','$name_int','$checkit','$devicegroup','$clone_to_vsys','$type','$ipaddress','$cidr','$description','$fqdn','$v4','$v6','$vtype','$source','$tag','$dummy');");

                $clone_member_lid = $projectdb->insert_id;

                $getTagRelations = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$member_lid' AND table_name = 'address';");
                if( $getTagRelations->num_rows > 0 )
                {
                    while( $dataTR = $getTagRelations->fetch_assoc() )
                    {
                        $tag_id = $dataTR['tag_id'];

                        $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('address', '$clone_member_lid', '$tag_id');");

                    }
                }

                add_log('ok', 'Clone Address', 'Clone Address: [' . $name_int . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;

}

function cloneAddressGroups(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;

    $group_clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id,name_ext,name,used,devicegroup,vsys,source,tag,checkit,invalid,filter,type  
                                          FROM address_groups_id WHERE id='$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name_int = $data['name'];
            $name_ext = $data['name_ext'];
            $devicegroup = $data['devicegroup'];
            $vsys = $data['vsys'];
            $invalid = $data['invalid'];
            $tag = $data['tag'];
            $filter = addslashes($data['filter']);
            $type = $data['type'];

            if( ($vsys != $clone_to_vsys) && ($clone_to_vsys == "shared") )
            {
                $ids = explode(',', $member_lid);
                $group_clone_member_lid = duplicateAddressGroupsToShared($source, $ids);
            }
            else
            {
                if( $vsys == $clone_to_vsys )
                {
                    $name_int = "Cl-$name_int";
                }

                $getExist = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext = '$name_ext' AND BINARY name = '$name_int' "
                    . "AND type = '$type' AND filter = '$filter' AND invalid = '$invalid' AND tag = '$tag' AND source = '$source' "
                    . "AND vsys = '$clone_to_vsys';");
                if( $getExist->num_rows > 0 )
                {
                    $getEData = $getExist->fetch_assoc();
                    $group_clone_member_lid = $getEData['id'];
                }
                elseif( $getExist->num_rows == 0 )
                {
                    $projectdb->query("INSERT INTO address_groups_id (name_ext,name,devicegroup,vsys,source,tag,invalid,filter,type)  "
                        . "VALUES ('$name_ext','$name_int','$devicegroup','$clone_to_vsys','$source','$tag','$invalid','$filter','$type');");
                    $group_clone_member_lid = $projectdb->insert_id;

                    $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member, devicegroup FROM address_groups WHERE lid='$member_lid';");

                    if( $getAllmembers->num_rows > 0 )
                    {
                        while( $data = $getAllmembers->fetch_assoc() )
                        {
                            $table_name_sql = $data['table_name'];
                            $member_lid_sql = $data['member_lid'];
                            $member_sql = $data['member'];
                            $devicegroup = $data['devicegroup'];

                            $projectdb->query("INSERT INTO address_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                                . "VALUES ('$source', '$group_clone_member_lid', '$member_lid_sql', '$table_name_sql', '$clone_to_vsys', '$devicegroup', '$member_sql');");

                        }
                    }

                    $getTagRelations = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$member_lid' AND table_name = 'address_groups_id';");
                    if( $getTagRelations->num_rows > 0 )
                    {
                        while( $dataTR = $getTagRelations->fetch_assoc() )
                        {
                            $tag_id = $dataTR['tag_id'];

                            $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('address_groups_id', '$group_clone_member_lid', '$tag_id');");

                        }
                    }

                    add_log('ok', 'Clone Address Group', 'Clone Address Group: [' . $name_int . ']. ', $source, 'No Action Required', '2');
                }
            }
        }
    }

    return $group_clone_member_lid;
}

function cloneServices(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;
    $clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getMember = $projectdb->query("SELECT id,name_ext,name,vsys,devicegroup,description,sport,dport,protocol,icmp,source,tag "
            . "FROM services WHERE id='$member_lid' AND dummy = 0;");

        if( $getMember->num_rows > 0 )
        {
            $data = $getMember->fetch_assoc();
            $name = $data['name'];
            $name_ext = $data['name_ext'];
            $vsys = $data['vsys'];
            $devicegroup = $data['devicegroup'];
            $protocol = $data['protocol'];
            $description = $data['description'];
            $dport = $data['dport'];
            $sport = $data['sport'];
            $icmp = $data['icmp'];
            $tag = $data['tag'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext = '$name_ext' AND BINARY name = '$name' "
                . "AND devicegroup = '$devicegroup' AND description = '$description' AND protocol = '$protocol' AND dport = '$dport' "
                . "AND sport = '$sport' AND icmp = '$icmp' AND tag = '$tag' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO services (name_ext,name,devicegroup,vsys,protocol,sport,description,dport,icmp,source,tag)  "
                    . "VALUES ('$name_ext','$name','$devicegroup','$clone_to_vsys','$protocol','$sport','$description','$dport','$icmp','$source','$tag');");
                $clone_member_lid = $projectdb->insert_id;

                $getTagRelations = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$member_lid' AND table_name = 'services';");
                if( $getTagRelations->num_rows > 0 )
                {
                    while( $dataTR = $getTagRelations->fetch_assoc() )
                    {
                        $tag_id = $dataTR['tag_id'];

                        $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services', '$clone_member_lid', '$tag_id');");

                    }
                }
                add_log('ok', 'Clone Service', 'Clone Service: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneRegions(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;

    $clone_member_lid = 0;
    foreach( $ids as $member_lid )
    {

        $getMember = $projectdb->query("SELECT id, name, vsys, devicegroup, source, latitude, longitude, address "
            . "FROM regions WHERE id='$member_lid';");

        if( $getMember->num_rows > 0 )
        {
            $data = $getMember->fetch_assoc();
            $name = $data['name'];
            $vsys = $data['vsys'];
            $devicegroup = $data['devicegroup'];
            $latitude = $data['latitude'];
            $longitude = $data['longitude'];
            $address = $data['address'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM regions WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' "
                . "AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO regions (name,devicegroup,vsys,source,latitude, longitude, address)  "
                    . "VALUES ('$name','$devicegroup','$clone_to_vsys','$source','$latitude','$longitude','$address');");
                $clone_member_lid = $projectdb->insert_id;
                add_log('ok', 'Clone Regions', 'Clone Regions: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneServicesGroups(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{
    global $projectdb;

    $group_clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id,name_ext,name,used,devicegroup,vsys,source,tag,checkit,invalid,filter,type "
            . "FROM services_groups_id WHERE id='$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name_int = $data['name'];
            $name_ext = $data['name_ext'];
            $devicegroup = $data['devicegroup'];
            $invalid = $data['invalid'];
            $vsys = $data['vsys'];
            $tag = $data['tag'];
            $filter = addslashes($data['filter']);
            $type = $data['type'];

            if( ($vsys != $clone_to_vsys) && ($clone_to_vsys == "shared") )
            {
                $group_clone_member_lid = duplicateServicesGroupsToShared($source, $ids);
            }
            else
            {
                if( $vsys == $clone_to_vsys )
                {
                    $name_int = "Cl-$name_int";
                }

                $getExist = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext = '$name_ext' AND BINARY name = '$name_int' "
                    . "AND type = '$type' AND filter = '$filter' AND invalid = '$invalid' AND tag = '$tag' AND source = '$source' "
                    . "AND vsys = '$clone_to_vsys';");
                if( $getExist->num_rows > 0 )
                {
                    $getEData = $getExist->fetch_assoc();
                    $group_clone_member_lid = $getEData['id'];
                }
                elseif( $getExist->num_rows == 0 )
                {
                    $projectdb->query("INSERT INTO services_groups_id (name_ext,name,devicegroup,vsys,source,tag,invalid,filter,type)  "
                        . "VALUES ('$name_ext','$name_int','$devicegroup','$clone_to_vsys','$source','$tag','$invalid','$filter','$type');");
                    $group_clone_member_lid = $projectdb->insert_id;

                    #Check if the members are all shared
                    $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member, devicegroup FROM services_groups WHERE lid='$member_lid';");

                    if( $getAllmembers->num_rows > 0 )
                    {
                        while( $data = $getAllmembers->fetch_assoc() )
                        {
                            $table_name_sql = $data['table_name'];
                            $member_lid_sql = $data['member_lid'];
                            $member_sql = $data['member'];
                            $devicegroup = $data['devicegroup'];
                            $projectdb->query("INSERT INTO services_groups (source,lid,member_lid,table_name,vsys,devicegroup,member) "
                                . "VALUES ('$source', '$group_clone_member_lid', '$member_lid_sql', '$table_name_sql', '$clone_to_vsys', '$devicegroup', '$member_sql');");
                        }
                    }

                    $getTagRelations = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$member_lid' AND table_name = 'services_groups_id';");
                    if( $getTagRelations->num_rows > 0 )
                    {
                        while( $dataTR = $getTagRelations->fetch_assoc() )
                        {
                            $tag_id = $dataTR['tag_id'];

                            $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services_groups_id', '$group_clone_member_lid', '$tag_id');");

                        }
                    }
                    add_log('ok', 'Clone Services Group', 'Clone Services Group: [' . $name_int . ']. ', $source, 'No Action Required', '2');
                }
            }
        }
    }

    return $group_clone_member_lid;
}

function cloneApplications(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{
    global $projectdb;

    $clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getMember = $projectdb->query("SELECT name, devicegroup, description, category, subcategory, parent_app, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout, spyware_ident, vsys "
            . " FROM applications WHERE id = '$member_lid' AND dummy = 0;");

        if( $getMember->num_rows > 0 )
        {
            $data = $getMember->fetch_assoc();
            $name_int = $data['name'];
            $devicegroup = $data['devicegroup'];
            $description = $data['description'];
            $category = $data['category'];
            $subcategory = $data['subcategory'];
            $parent_app = $data['parent_app'];
            $risk = $data['risk'];
            $technology = $data['technology'];
            $evasive_behavior = $data['evasive_behavior'];
            $consume_big_bandwidth = $data['consume_big_bandwidth'];
            $used_by_malware = $data['used_by_malware'];
            $able_to_transfer_file = $data['able_to_transfer_file'];
            $has_known_vulnerability = $data['has_known_vulnerability'];
            $tunnel_other_application = $data['tunnel_other_application'];
            $tunnel_applications = $data['tunnel_applications'];
            $prone_to_misuse = $data['prone_to_misuse'];
            $pervasive_use = $data['pervasive_use'];
            $file_type_ident = $data['file_type_ident'];
            $virus_ident = $data['virus_ident'];
            $data_ident = $data['data_ident'];
            $default_type = $data['default_type'];
            $value = $data['value'];
            $type = $data['type'];
            $code = $data['code'];
            $timeout = $data['timeout'];
            $tcp_timeout = $data['tcp_timeout'];
            $udp_timeout = $data['udp_timeout'];
            $tcp_half_closed_timeout = $data['tcp_half_closed_timeout'];
            $tcp_time_wait_timeout = $data['tcp_time_wait_timeout'];
            $spyware_ident = $data['spyware_ident'];
            $vsys = $data['vsys'];

            $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE table_name = 'applications' AND member_lid = '$member_lid';");

            if( $getSignature->num_rows > 0 )
            {
                $dataS = $getSignature->fetch_assoc();
                $signature = $dataS['signature'];
            }
            else
            {
                $signature = '';
            }

            if( $vsys == $clone_to_vsys )
            {
                $name_int = "Cl-$name_int";
            }

            $getExist = $projectdb->query("SELECT id FROM applications WHERE BINARY name = '$name_int' AND source = '$source' "
                . "AND vsys = '$clone_to_vsys';");

            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO applications (name, vsys, source, devicegroup, description, category, subcategory, parent_app, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout, spyware_ident)  "
                    . "VALUES ('$name_int', '$clone_to_vsys', '$source', '$devicegroup', '$description', '$category', '$subcategory', '$parent_app', '$risk', '$technology', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$tunnel_applications', '$prone_to_misuse', '$pervasive_use', '$file_type_ident', '$virus_ident', '$data_ident', '$default_type', '$value', '$type', '$code', '$timeout', '$tcp_timeout', '$udp_timeout', '$tcp_half_closed_timeout', '$tcp_time_wait_timeout', '$spyware_ident');");
                $clone_member_lid = $projectdb->insert_id;

                $projectdb->query("INSERT INTO applications_signatures (vsys, source, devicegroup, signature, member_lid, table_name)  "
                    . "VALUES ('$clone_to_vsys', '$source', '$devicegroup', '$signature', '$clone_member_lid', 'applications');");

                add_log('ok', 'Clone Applications', 'Clone Applications: [' . $name_int . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneApplicationsGroups(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;

    $group_clone_member_lid = 0;

    if( ($vsys != $clone_to_vsys) && ($clone_to_vsys == "shared") )
    {
        $group_clone_member_lid = duplicateApplicationsGroupsToShared($source, $ids);
    }
    else
    {
        foreach( $ids as $member_lid )
        {

            $getOriginal = $projectdb->query("SELECT id, name, used, devicegroup, vsys, source, invalid "
                . "FROM applications_groups_id WHERE id = '$member_lid';");

            if( $getOriginal->num_rows == 1 )
            {

                $data = $getOriginal->fetch_assoc();
                $name_int = $data['name'];
                $devicegroup = $data['devicegroup'];
                $invalid = $data['invalid'];
                $vsys = $data['vsys'];

                if( $vsys == $clone_to_vsys )
                {
                    $name_int = "Cl-$name_int";
                }

                $getExist = $projectdb->query("SELECT id FROM applications_groups_id WHERE BINARY name = '$name_int' AND invalid = '$invalid' "
                    . "AND source = '$source' AND vsys = '$clone_to_vsys';");
                if( $getExist->num_rows > 0 )
                {
                    $getEData = $getExist->fetch_assoc();
                    $group_clone_member_lid = $getEData['id'];
                }
                elseif( $getExist->num_rows == 0 )
                {
                    $projectdb->query("INSERT INTO applications_groups_id (name, devicegroup, vsys, source, invalid)  "
                        . "VALUES ('$name_int', '$devicegroup', '$clone_to_vsys', '$source', '$invalid');");
                    $group_clone_member_lid = $projectdb->insert_id;

                    #Check if the members are all shared
                    $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member, devicegroup FROM applications_groups "
                        . "WHERE lid='$member_lid';");

                    if( $getAllmembers->num_rows > 0 )
                    {
                        while( $data = $getAllmembers->fetch_assoc() )
                        {
                            $table_name_sql = $data['table_name'];
                            $member_lid_sql = $data['member_lid'];
                            $member_sql = $data['member'];
                            $devicegroup = $data['devicegroup'];
                            $projectdb->query("INSERT INTO applications_groups (source, lid, member_lid, table_name, vsys, devicegroup, member) "
                                . "VALUES ('$source', '$group_clone_member_lid', '$member_lid_sql', '$table_name_sql', '$clone_to_vsys', '$devicegroup', '$member_sql');");
                        }
                    }
                    add_log('ok', 'Clone Applications Group', 'Clone Applications Group: [' . $name_int . ']. ', $source, 'No Action Required', '2');
                }
            }
        }
    }
    return $group_clone_member_lid;
}

function cloneApplicationsFilters(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;

    $clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getMember = $projectdb->query("SELECT name, devicegroup, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, "
            . "used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, prone_to_misuse, pervasive_use, type, vsys "
            . "FROM applications_filters WHERE id = '$member_lid';");

        if( $getMember->num_rows > 0 )
        {
            $data = $getMember->fetch_assoc();
            $name_int = $data['name'];
            $devicegroup = $data['devicegroup'];
            $category = $data['category'];
            $subcategory = $data['subcategory'];
            $risk = $data['risk'];
            $technology = $data['technology'];
            $evasive_behavior = $data['evasive_behavior'];
            $consume_big_bandwidth = $data['consume_big_bandwidth'];
            $used_by_malware = $data['used_by_malware'];
            $able_to_transfer_file = $data['able_to_transfer_file'];
            $has_known_vulnerability = $data['has_known_vulnerability'];
            $tunnel_other_application = $data['tunnel_other_application'];
            $prone_to_misuse = $data['prone_to_misuse'];
            $pervasive_use = $data['pervasive_use'];
            $type = $data['type'];
            $vsys = $data['vsys'];

            if( $vsys == $clone_to_vsys )
            {
                $name_int = "Cl-$name_int";
            }

            $getExist = $projectdb->query("SELECT id FROM applications_filters WHERE BINARY name = '$name_int' AND source = '$source' "
                . "AND vsys = '$clone_to_vsys' AND category = '$category' AND subcategory = '$subcategory' AND risk = '$risk' "
                . "AND technology = '$technology' AND evasive_behavior = '$evasive_behavior' AND consume_big_bandwidth = '$consume_big_bandwidth' "
                . "AND used_by_malware = '$used_by_malware' AND able_to_transfer_file = '$able_to_transfer_file' AND has_known_vulnerability = '$has_known_vulnerability' "
                . "AND tunnel_other_application = '$tunnel_other_application' AND prone_to_misuse = '$prone_to_misuse' AND pervasive_use = '$pervasive_use' AND type = '$type';");

            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO applications_filters (name, vsys, source, devicegroup, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, prone_to_misuse, pervasive_use, type)  "
                    . "VALUES ('$name_int', '$clone_to_vsys', '$source', '$devicegroup', '$category', '$subcategory', '$risk', '$technology', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$prone_to_misuse', '$pervasive_use', '$type');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Applications Filters', 'Clone Applications Filters: [' . $name_int . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;

}

function cloneTags(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;
    $clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, color, comments, source, vsys, devicegroup "
            . "FROM tag WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $color = $data['color'];
            $comments = $data['comments'];
            $vsys = $data['vsys'];
            $devicegroup = $data['devicegroup'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM tag WHERE BINARY name = '$name' AND color = '$color' AND devicegroup = '$devicegroup' "
                . "AND comments = '$comments' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO tag (name, color, comments, source, vsys, devicegroup)  "
                    . "VALUES ('$name', '$color', '$comments', '$source', '$clone_to_vsys', '$devicegroup');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Tags', 'Clone Tag: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneLogSettings(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids, $clone_to_template)
{

    global $projectdb;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup, template "
            . "FROM log_settings WHERE id = '$member_lid'; ");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];
            $vsys = $data['vsys'];
            $template = $data['template'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            if( $clone_to_template != "" )
            {
                $getExist = $projectdb->query("SELECT id FROM log_settings WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND xml = '$xml' AND source = '$source' AND vsys = '$clone_to_vsys' AND template = '$clone_to_template';");
            }
            else
            {
                $getExist = $projectdb->query("SELECT id FROM log_settings WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND xml = '$xml' AND source = '$source' AND vsys = '$clone_to_vsys';");
            }
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO log_settings (name, xml, type, source, vsys, devicegroup, template)  "
                    . "VALUES ('$name', '$xml', '$type', '$source', '$clone_to_vsys', '$devicegroup', '$clone_to_template');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Log Settings', 'Clone Log Settings: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneServerProfiles(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, template "
            . "FROM server_profile WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $type = $data['type'];
            $xml = $data['xml'];
            $vsys = $data['vsys'];
            $template = $data['template'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM server_profile WHERE BINARY name = '$name' AND type = '$type' AND xml = '$xml' AND source = '$source' AND vsys = '$clone_to_vsys' AND template = '$template';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO server_profile (name, xml, type, source, vsys, template)  "
                    . "VALUES ('$name', '$xml', '$type', '$source', '$clone_to_vsys', '$template');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Server Profile', 'Clone Server Profile: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneExternalList(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;
    $clone_member_lid = 0;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
            . "FROM external_list WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];
            $vsys = $data['vsys'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM external_list WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND xml = '$xml' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO external_list (name, xml, type, source, vsys, devicegroup)  "
                    . "VALUES ('$name', '$xml', '$type', '$source', '$clone_to_vsys', '$devicegroup');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone External List', 'Clone External List: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneSchedules(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
            . "FROM schedules WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];
            $vsys = $data['vsys'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM schedules WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND xml = '$xml' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO schedules (name, xml, type, source, vsys, devicegroup)  "
                    . "VALUES ('$name', '$xml', '$type', '$source', '$clone_to_vsys', '$devicegroup');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Schedules', 'Clone Schedules: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneProfiles(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;


    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
            . "FROM profiles WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];
            $vsys = $data['vsys'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM profiles WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND xml = '$xml' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO profiles (name, xml, type, source, vsys, devicegroup)  "
                    . "VALUES ('$name', '$xml', '$type', '$source', '$clone_to_vsys', '$devicegroup');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Profiles', 'Clone Profiles: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function cloneProfilesGroups(STRING $source, STRING $vsys, STRING $clone_to_vsys, array $ids)
{

    global $projectdb;

    foreach( $ids as $member_lid )
    {

        $getOriginal = $projectdb->query("SELECT id, name, source, xml, type, vsys, devicegroup "
            . "FROM profiles_groups WHERE id = '$member_lid';");

        if( $getOriginal->num_rows == 1 )
        {

            $data = $getOriginal->fetch_assoc();
            $name = $data['name'];
            $devicegroup = $data['devicegroup'];
            $type = $data['type'];
            $xml = $data['xml'];
            $vsys = $data['vsys'];

            if( $vsys == $clone_to_vsys )
            {
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM profiles_groups WHERE BINARY name = '$name' AND devicegroup = '$devicegroup' AND type = '$type' AND xml = '$xml' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if( $getExist->num_rows > 0 )
            {
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif( $getExist->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO profiles_groups (name, xml, type, source, vsys, devicegroup)  "
                    . "VALUES ('$name', '$xml', '$type', '$source', '$clone_to_vsys', '$devicegroup');");
                $clone_member_lid = $projectdb->insert_id;

                add_log('ok', 'Clone Profiles Groups', 'Clone Profiles Groups: [' . $name . ']. ', $source, 'No Action Required', '2');
            }
        }
    }
    return $clone_member_lid;
}

function getImage($type, $table_name, $member_lid)
{

    global $projectdb;

    if( $type == "address" )
    {
        if( $table_name == "address" )
        {
            $getSRC = $projectdb->query("SELECT name,type,vtype,ipaddress,cidr,fqdn FROM address WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $type = $dataSRC['type'];
            $vtype = $dataSRC['vtype'];
            if( $vtype == "" )
            {
                if( $type == "ip-netmask" )
                {
                    $image = "address.gif";
                }
                elseif( $type == "ip-range" )
                {
                    $image = "ip_range.gif";
                }
                elseif( $type == "fqdn" )
                {
                    $image = "domain.png";
                }
                else
                {
                    $image = "address.gif";
                }
            }
            else
            {
                if( ($vtype == "gateway_cluster") or ($vtype == "cluster_member") or ($vtype == "gateway_fw") or ($vtype == "gateway") )
                {
                    $image = "checkpointp.png";
                }
                elseif( $vtype == "ip-range" )
                {
                    $image = "ip_range.gif";
                }
                elseif( $vtype == "dummy" )
                {
                    $image = "pan16.gif";
                }
                else
                {
                    $image = "address.gif";
                }
            }
        }
        elseif( $table_name == "address_groups_id" )
        {
            $getSRC = $projectdb->query("SELECT name,type,filter FROM address_groups_id WHERE  id='$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $type = $dataSRC['type']; // static dynamic
            if( $type == "dynamic" )
            {
                $image = "dynamic_group.png";
            }
            else
            {
                $image = "address_groups_id.gif";
            }
        }
        elseif( ($table_name == "default_regions") || ($table_name == "regions") )
        {
            $image = "regions.png";
        }
        elseif( $table_name == "external_list" )
        {
            $image = "external_list.png";
        }

    }
    elseif( $type == "services" )
    {
        if( $table_name == "services" )
        {
            $getSRC = $projectdb->query("SELECT vtype FROM services WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vtype = $dataSRC['vtype'];
            if( $vtype == "dummy" )
            {
                $image = "pan16.gif";
            }
            else
            {
                $image = "service.gif";
            }
        }
        elseif( $table_name == "services_groups_id" )
        {
            $image = "services_groups_id.gif";
        }
    }
    elseif( $type == "applications" )
    {
        if( $table_name == "default_applications" )
        {
            $image = "applications.gif";
        }
        elseif( $table_name == "applications" )
        {
            $getSRC = $projectdb->query("SELECT vtype FROM applications WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vtype = $dataSRC['vtype'];
            if( $vtype == "dummy" )
            {
                $image = "pan16.gif";
            }
            else
            {
                $image = "applications.gif";
            }
        }
        elseif( $table_name == "applications_groups_id" )
        {
            $image = "applications_groups.gif";
        }
        elseif( $table_name == "applications_filters" )
        {
            $image = "applications_filters.png";
        }
    }
    elseif( $type == "hip" )
    {
        if( $table_name == "profiles" )
        {
            $image = "global-protect.png";
        }
    }

    return $image;
}

function getImageNew($type, $table_name, $member_lid, $vsys)
{

    global $projectdb;

    if( $type == "address" )
    {
        if( $table_name == "address" )
        {
            $getSRC = $projectdb->query("SELECT name, type, vtype, ipaddress, cidr, fqdn, vsys FROM address WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $type = $dataSRC['type'];
            $vtype = $dataSRC['vtype'];
            $vsys = $dataSRC['vsys'];

            if( $vsys != "shared" )
            {
                if( $vtype == "" )
                {
                    if( $type == "ip-netmask" )
                    {
                        $image = "address.gif";
                    }
                    elseif( $type == "ip-range" )
                    {
                        $image = "ip_range.gif";
                    }
                    elseif( $type == "fqdn" )
                    {
                        $image = "domain.png";
                    }
                    else
                    {
                        $image = "address.gif";
                    }
                }
                else
                {
                    if( ($vtype == "gateway_cluster") or ($vtype == "cluster_member") or ($vtype == "gateway_fw") or ($vtype == "gateway") )
                    {
                        $image = "checkpointp.png";
                    }
                    elseif( $vtype == "ip-range" )
                    {
                        $image = "ip_range.gif";
                    }
                    elseif( $vtype == "dummy" )
                    {
                        $image = "pan16.gif";
                    }
                    else
                    {
                        $image = "address.gif";
                    }
                }
            }
            else
            {
                if( $vtype == "" )
                {
                    if( $type == "ip-netmask" )
                    {
                        $image = "shared_address.gif";
                    }
                    elseif( $type == "ip-range" )
                    {
                        $image = "shared-ranges.gif";
                    }
                    elseif( $type == "fqdn" )
                    {
                        $image = "shared_domain.gif";
                    }
                    else
                    {
                        $image = "shared_address.gif";
                    }
                }
                else
                {
                    if( ($vtype == "gateway_cluster") or ($vtype == "cluster_member") or ($vtype == "gateway_fw") or ($vtype == "gateway") )
                    {
                        $image = "checkpointp.png";
                    }
                    elseif( $vtype == "ip-range" )
                    {
                        $image = "ip_range.gif";
                    }
                    elseif( $vtype == "dummy" )
                    {
                        $image = "pan16.gif";
                    }
                    else
                    {
                        $image = "shared_address.gif";
                    }
                }
            }
        }
        elseif( $table_name == "address_groups_id" )
        {
            $getSRC = $projectdb->query("SELECT name, type, filter, vsys FROM address_groups_id WHERE id='$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $type = $dataSRC['type']; // static dynamic
            $vsys = $dataSRC['vsys'];
            if( $vsys != "shared" )
            {
                if( $type == "dynamic" )
                {
                    $image = "dynamic_group.png";
                }
                else
                {
                    $image = "address_groups_id.gif";
                }
            }
            else
            {
                if( $type == "dynamic" )
                {
                    $image = "dynamic_group.png";
                }
                else
                {
                    $image = "shared_address_groups_id.gif";
                }
            }
        }
        elseif( ($table_name == "default_regions") || ($table_name == "regions") )
        {
            if( $vsys != "shared" )
            {
                $image = "regions.png";
            }
            else
            {
                $image = "shared_regions.png";
            }
        }
        elseif( $table_name == "external_list" )
        {
            if( $vsys != "shared" )
            {
                $image = "external_list.png";
            }
            else
            {
                $image = "shared_external_list.png";
            }
        }
    }
    elseif( $type == "services" )
    {
        if( $table_name == "services" )
        {
            $getSRC = $projectdb->query("SELECT vtype, vsys FROM services WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vtype = $dataSRC['vtype'];
            $vsys = $dataSRC['vsys'];
            if( $vsys != "shared" )
            {
                if( $vtype == "dummy" )
                {
                    $image = "pan16.gif";
                }
                else
                {
                    $image = "service.gif";
                }
            }
            else
            {
                if( $vtype == "dummy" )
                {
                    $image = "pan16.gif";
                }
                else
                {
                    $image = "shared_services.gif";
                }
            }
        }
        elseif( $table_name == "services_groups_id" )
        {
            $getSRC = $projectdb->query("SELECT vsys FROM services_groups_id WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vsys = $dataSRC['vsys'];
            if( $vsys != "shared" )
            {
                $image = "services_groups_id.gif";
            }
            else
            {
                $image = "shared_services_groups_id.gif";
            }
        }
    }
    elseif( $type == "applications" )
    {
        if( $table_name == "default_applications" )
        {
            $image = "applications.gif";
        }
        elseif( $table_name == "applications" )
        {
            $getSRC = $projectdb->query("SELECT vtype, vsys FROM applications WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vtype = $dataSRC['vtype'];
            $vsys = $dataSRC['vsys'];
            if( $vsys != "shared" )
            {
                if( $vtype == "dummy" )
                {
                    $image = "pan16.gif";
                }
                else
                {
                    $image = "applications.gif";
                }
            }
            else
            {
                if( $vtype == "dummy" )
                {
                    $image = "pan16.gif";
                }
                else
                {
                    $image = "shared_applications.gif";
                }
            }
        }
        elseif( $table_name == "applications_groups_id" )
        {
            $getSRC = $projectdb->query("SELECT vsys FROM applications_groups_id WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vsys = $dataSRC['vsys'];
            if( $vsys != "shared" )
            {
                $image = "applications_groups.gif";
            }
            else
            {
                $image = "shared_applications_groups.gif";
            }
        }
        elseif( $table_name == "applications_filters" )
        {
            $getSRC = $projectdb->query("SELECT vsys FROM applications_filters WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vsys = $dataSRC['vsys'];
            if( $vsys != "shared" )
            {
                $image = "applications_filters.png";
            }
            else
            {
                $image = "shared_applications_filters.gif";
            }
        }
    }
    elseif( $type == "hip" )
    {
        if( $table_name == "profiles" )
        {
            $getSRC = $projectdb->query("SELECT vsys FROM profiles WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vsys = $dataSRC['vsys'];
            if( $vsys != "shared" )
            {
                $image = "global-protect.png";
            }
            else
            {
                $image = "shared_global-protect.gif";
            }
        }
    }

    return $image;
}

function getIcon($type, $table_name, $member_lid, $vsys, $objectsInMemory = null)
{

    global $projectdb;
    $icon = "";
    $myip = "";
    $name = "";
    if( $type == "address" )
    {
        if( $table_name == "address" )
        {
            if( isset($objectsInMemory['address'][$member_lid]) )
            {
                $name = $objectsInMemory['address'][$member_lid]['name'];
                $type = $objectsInMemory['address'][$member_lid]['type'];
                $vtype = $objectsInMemory['address'][$member_lid]['vtype'];
                $ipaddress = $objectsInMemory['address'][$member_lid]['ipaddress'];
                $cidr = $objectsInMemory['address'][$member_lid]['cidr'];
                $vsys = $objectsInMemory['address'][$member_lid]['vsys'];
            }
            else
            {
                $getSRC = $projectdb->query("SELECT name, type, vtype, ipaddress, cidr, fqdn, vsys FROM address WHERE id = '$member_lid';");
                $dataSRC = $getSRC->fetch_assoc();
                $name = $dataSRC['name'];
                $type = $dataSRC['type'];
                $vtype = $dataSRC['vtype'];
                $ipaddress = $dataSRC['ipaddress'];
                $cidr = $dataSRC['cidr'];
                $vsys = $dataSRC['vsys'];
            }

            if( $vtype == "" )
            {
                if( $type == "ip-netmask" )
                {
                    $icon = "fa fa-desktop";
                    $myip = $ipaddress . "-" . $cidr;
                }
                elseif( $type == "ip-range" )
                {
                    $icon = "fa fa-sitemap";
                    $myip = $ipaddress;
                }
                elseif( $type == "fqdn" )
                {
                    $icon = "fa fa-book";
                    $myip = $ipaddress;
                }
                else
                {
                    $icon = "fa fa-desktop";
                    $myip = $ipaddress;
                }
            }
            else
            {
                if( ($vtype == "gateway_cluster") or ($vtype == "cluster_member") or ($vtype == "gateway_fw") or ($vtype == "gateway") )
                {
                    $icon = "checkpointp.png";
                    $myip = $ipaddress . "-" . $cidr;
                }
                elseif( $vtype == "ip-range" )
                {
                    $icon = "fa fa-sitemap";
                    $myip = $ipaddress;
                }
                elseif( $vtype == "dummy" )
                {
                    $icon = "fa fa-at";
                    $myip = "IP_Address";
                }
                else
                {
                    $icon = "fa fa-desktop";
                    $myip = $ipaddress . "-" . $cidr;
                }
            }
        }
        elseif( $table_name == "address_groups_id" )
        {
            if( isset($objectsInMemory['address_groups_id'][$member_lid]) )
            {
                $name = $objectsInMemory['address_groups_id'][$member_lid]['name'];
                $type = $objectsInMemory['address_groups_id'][$member_lid]['type']; // static dynamic
                $filter = $objectsInMemory['address_groups_id'][$member_lid]['filter'];
                $vsys = $objectsInMemory['address_groups_id'][$member_lid]['vsys'];
            }
            else
            {
                $getSRC = $projectdb->query("SELECT name, type, filter, vsys FROM address_groups_id WHERE id='$member_lid';");
                $dataSRC = $getSRC->fetch_assoc();
                $name = $dataSRC['name'];
                $type = $dataSRC['type']; // static dynamic
                $filter = $dataSRC['filter'];
                $vsys = $dataSRC['vsys'];
            }
            if( $type == "dynamic" )
            {
                $icon = "fa fa-object-group";
                $myip = $filter;
            }
            else
            {
                $icon = "fa fa-object-ungroup";
                $myip = "Static Group";
            }
        }
        elseif( $table_name == "default_regions" )
        {
            $getSRC = $projectdb->query("SELECT name, help FROM default_regions WHERE id='$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $name = $dataSRC['name'];
            $help = $dataSRC['help'];
            if( !preg_match("/-/", $name) )
            {
                $icon = "../flags/$name.gif";
            }
            else
            {
                $icon = "fa fa-globe";
            }
            $myip = $help;
        }
        elseif( $table_name == "regions" )
        {
            $getSRC = $projectdb->query("SELECT name, vsys FROM regions WHERE id='$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $name = $dataSRC['name'];
            $vsys = $dataSRC['vsys'];
            $icon = "fa fa-globe";
            $myip = "Custom Region";
        }
        elseif( $table_name == "external_list" )
        {
            $getSRC = $projectdb->query("SELECT id, name, vsys FROM external_list WHERE id='$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $name = $dataSRC['name'];
            $vsys = $dataSRC['vsys'];
            $icon = "fa fa-list";
            $myip = "External List";
        }
    }
    elseif( $type == "services" )
    {
        if( $table_name == "services" )
        {
            if( isset($objectsInMemory['services'][$member_lid]) )
            {
                $name = $objectsInMemory['services'][$member_lid]['name'];
                $vtype = $objectsInMemory['services'][$member_lid]['vtype'];
                $sport = $objectsInMemory['services'][$member_lid]['sport'];
                $dport = $objectsInMemory['services'][$member_lid]['dport'];
                $protocol = $objectsInMemory['services'][$member_lid]['protocol'];
                $vsys = $objectsInMemory['services'][$member_lid]['vsys'];
            }
            else
            {
                $getSRC = $projectdb->query("SELECT name, vtype, sport, dport, protocol, vsys FROM services WHERE id = '$member_lid';");
                $dataSRC = $getSRC->fetch_assoc();
                $name = $dataSRC['name'];
                $vtype = $dataSRC['vtype'];
                $sport = $dataSRC['sport'];
                $dport = $dataSRC['dport'];
                $protocol = $dataSRC['protocol'];
                $vsys = $dataSRC['vsys'];
            }
            if( $vtype == "dummy" )
            {
                $icon = "pan16.gif";
                $myip = "dummy";
            }
            else
            {
                $icon = "fa fa-cog";
                if( ($name == "application-default") or ($name == "service-http") or ($name == "service-https") )
                {
                    $myip = "default application";
                }
                else
                {
                    $myip = "$protocol:[$sport]-[$dport]";
                }
            }

        }
        elseif( $table_name == "services_groups_id" )
        {
            if( isset($objectsInMemory['services_groups_id'][$member_lid]) )
            {
                $name = $objectsInMemory['services_groups_id'][$member_lid]['name'];
                $vsys = $objectsInMemory['services_groups_id'][$member_lid]['vsys'];
                $icon = "fa fa-cogs";
                $myip = "Group";
            }
            else
            {
                $getSRC = $projectdb->query("SELECT name, vsys FROM services_groups_id WHERE id = '$member_lid';");
                $dataSRC = $getSRC->fetch_assoc();
                $name = $dataSRC['name'];
                $vsys = $dataSRC['vsys'];
                $icon = "fa fa-cogs";
                $myip = "Group";
            }
        }
    }
    elseif( $type == "applications" )
    {
        if( $table_name == "default_applications" )
        {
            $getSRC = $projectdb->query("SELECT name FROM default_applications WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $name = $dataSRC['name'];
            $icon = "fa fa-list-alt";
            $myip = "Default Application";
        }
        elseif( $table_name == "applications" )
        {
            $getSRC = $projectdb->query("SELECT name, vtype, vsys FROM applications WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $name = $dataSRC['name'];
            $vtype = $dataSRC['vtype'];
            $vsys = $dataSRC['vsys'];
            if( $vtype == "dummy" )
            {
                $icon = "pan16.gif";
                $myip = "dummy";
            }
            else
            {
                $icon = "fa fa-list-alt";
                $myip = ($vsys == 'shared') ? "Shared Custom Application" : "Custom Application";
            }
        }
        elseif( $table_name == "applications_groups_id" )
        {
            $getSRC = $projectdb->query("SELECT vsys, name FROM applications_groups_id WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vsys = $dataSRC['vsys'];
            $name = $dataSRC['name'];
            $icon = "fa fa-object-ungroup";
            $myip = ($vsys == 'shared') ? "Shared Group" : "Group";
        }
        elseif( $table_name == "applications_filters" )
        {
            $getSRC = $projectdb->query("SELECT vsys, name FROM applications_filters WHERE id = '$member_lid';");
            $dataSRC = $getSRC->fetch_assoc();
            $vsys = $dataSRC['vsys'];
            $name = $dataSRC['name'];
            $icon = "fa fa-filter";
            $myip = ($vsys == 'shared') ? "Shared Filter" : "Filter";
        }
    }
    elseif( $type == "hip" )
    {
        if( $table_name == "profiles" )
        {
            if( $vsys != "shared" )
            {
                $icon = "global-protect.png";
            }
            else
            {
                $icon = "shared_global-protect.gif";
            }
        }
    }

    return array($icon, $vsys, $name, $myip);
}

function setMembersRules($rules_all, $table, $vsys, $source)
{

    global $projectdb;
    //Edit_update
    $rules = explode(",", $rules_all);

    foreach( $rules as $key => $rule_lid )
    {

        if( ($table == "security_rules_from") || ($table == "security_rules_to") ||
            ($table == "security_rules_usr") || ($table == "security_rules_categories") || ($table == "nat_rules_from") || ($table == "appoverride_rules_from") || ($table == "appoverride_rules_to") )
        {

            // Delete the members remove
            $getMembers = $projectdb->query("SELECT name FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '1';");
            if( $getMembers->num_rows > 0 )
            {
                while( $getMemData = $getMembers->fetch_assoc() )
                {
                    $name = addslashes($getMemData['name']);
                    $result_delete = $projectdb->query("DELETE FROM $table WHERE rule_lid = '$rule_lid' AND name = '$name';");
                    $sql = "DELETE FROM $table WHERE rule_lid = $rule_lid AND name = $name;";
                    if( $result_delete != 1 )
                    {
                        add_log('error', 'Edit Security Rules', 'SQL DELETE: [' . $sql . ']. ', $source, 'No Action Required', '2');
                    }
                }
            }

            if( $table == "security_rules_usr" )
            {
                $getSrcBridge = $projectdb->query("SELECT lid, name FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '0' AND name IN ('any', 'pre-logon', 'known-user', 'unknown') LIMIT 1;");
                if( $getSrcBridge->num_rows == 1 )
                {
                    // Are unique ('any', 'pre-logon', 'known-user', 'unknown')
                    $getSrcData = $getSrcBridge->fetch_assoc();
                    $name = addslashes($getSrcData['name']);
                    $getFrom = $projectdb->query("SELECT id FROM $table WHERE name = '$name' AND rule_lid = '$rule_lid'; ");
                    if( $getFrom->num_rows == 0 )
                    {
                        $result_insert = $projectdb->query("INSERT INTO $table (id, source, vsys, name, rule_lid) VALUES (NULL, '$source', '$vsys', '$name', '$rule_lid');");
                    }
                }
                else
                {
                    $getSrcBridge = $projectdb->query("SELECT lid, name FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '0';");
                    if( $getSrcBridge->num_rows > 0 )
                    {
                        while( $getSrcData = $getSrcBridge->fetch_assoc() )
                        {
                            $name = addslashes($getSrcData['name']);
                            $getFrom = $projectdb->query("SELECT id FROM $table WHERE name = '$name' AND rule_lid = '$rule_lid'; ");
                            if( $getFrom->num_rows == 0 )
                            {
                                $result_insert = $projectdb->query("INSERT INTO $table (id, source, vsys, name, rule_lid) VALUES (NULL, '$source', '$vsys', '$name', '$rule_lid');");
                            }
                        }
                    }
                }
            }
            else
            {
                $getSrcBridge = $projectdb->query("SELECT lid, name FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '0';");
                if( $getSrcBridge->num_rows > 0 )
                {
                    while( $getSrcData = $getSrcBridge->fetch_assoc() )
                    {
                        $name = addslashes($getSrcData['name']);
                        $getFrom = $projectdb->query("SELECT id FROM $table WHERE name = '$name' AND rule_lid = '$rule_lid'; ");
                        if( $getFrom->num_rows == 0 )
                        {
                            $result_insert = $projectdb->query("INSERT INTO $table (id, source, vsys, name, rule_lid) VALUES (NULL, '$source', '$vsys', '$name', '$rule_lid');");
                            $sql = "INSERT INTO $table (id, source, vsys, name, rule_lid) VALUES (NULL, '$source', '$vsys', '$name', '$rule_lid');";
                            if( $result_insert != 1 )
                            {
                                add_log('error', 'Edit Security Rules', 'SQL INSERT: [' . $sql . ']. ', $source, 'No Action Required', '2');
                            }
                        }
                    }
                }
            }
        }
        elseif( ($table == "security_rules_target") || ($table == "nat_rules_target") || ($table == "appoverride_rules_target") )
        {

            // Delete the members remove
            $getMembers = $projectdb->query("SELECT name, vsys_member FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '1';");
            if( $getMembers->num_rows > 0 )
            {
                while( $getMemData = $getMembers->fetch_assoc() )
                {
                    $name = addslashes($getMemData['name']);
                    $vsys_member = $getMemData['vsys_member'];

                    $result_delete = $projectdb->query("DELETE FROM $table WHERE rule_lid = '$rule_lid' AND name = '$name' AND device_vsys = '$vsys_member';");
                    $sql = "DELETE FROM $table WHERE rule_lid = '$rule_lid' AND name = '$name' AND device_vsys = '$vsys_member';";
                    if( $result_delete != 1 )
                    {
                        add_log('error', 'Edit Security Rules', 'SQL DELETE: [' . $sql . ']. ', $source, 'No Action Required', '2');
                    }
                }
            }

            $getSrcBridge = $projectdb->query("SELECT lid, name, vsys_member FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '0';");
            if( $getSrcBridge->num_rows > 0 )
            {
                while( $getSrcData = $getSrcBridge->fetch_assoc() )
                {
                    $name = addslashes($getSrcData['name']);
                    $vsys_member = $getSrcData['vsys_member'];

                    $getFrom = $projectdb->query("SELECT id FROM $table WHERE name = '$name' AND device_vsys = '$vsys_member' AND rule_lid = '$rule_lid'; ");
                    if( $getFrom->num_rows == 0 )
                    {
                        $result_insert = $projectdb->query("INSERT INTO $table (id, source, vsys, name, rule_lid, device_vsys) VALUES (NULL, '$source', '$vsys', '$name', '$rule_lid', '$vsys_member');");
                        $sql = "INSERT INTO $table (id, source, vsys, name, rule_lid, device_vsys) VALUES (NULL, '$source', '$vsys', '$name', '$rule_lid', '$vsys_member');";
                        if( $result_insert != 1 )
                        {
                            add_log('error', 'Edit Security Rules', 'SQL INSERT: [' . $sql . ']. ', $source, 'No Action Required', '2');
                        }
                    }
                }
            }
        }
        else
        {

            if( $table == "nat_rules_translated_address" )
            {
                //$projectdb->query("DELETE FROM nat_rules_translated_address WHERE rule_lid = '$rule_lid';");
            }

            // Delete the members remove
            $getMembers = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '1';");
            if( $getMembers->num_rows > 0 )
            {
                while( $getMemData = $getMembers->fetch_assoc() )
                {
                    $member_lid = $getMemData['member_lid'];
                    $table_name_lid = $getMemData['table_name_lid'];
                    $result_delete = $projectdb->query("DELETE FROM $table WHERE member_lid = '$member_lid' AND table_name = '$table_name_lid' AND rule_lid = '$rule_lid';");
                    $sql = "DELETE FROM $table WHERE member_lid = $member_lid AND table_name = $table_name_lid AND rule_lid = $rule_lid;";
                    if( $result_delete != 1 )
                    {
                        add_log('error', 'Edit Security Rules', 'SQL DELETE: [' . $sql . ']. ', $source, 'No Action Required', '2');
                    }
                }
            }
            $query = "SELECT lid, member_lid, table_name_lid FROM edit_table WHERE lid = '$rule_lid' AND type = '$table' AND remove = '0';";
            //echo "1. " .$query. "\n";
            $getSrcBridge = $projectdb->query($query);
            if( $getSrcBridge->num_rows > 0 )
            {
                while( $getSrcData = $getSrcBridge->fetch_assoc() )
                {
                    $lid = $getSrcData['lid'];
                    $member_lid = $getSrcData['member_lid'];
                    $table_name = $getSrcData['table_name_lid'];
                    $query = "SELECT id FROM $table WHERE table_name = '$table_name' AND member_lid = '$member_lid' AND rule_lid = '$rule_lid';";
                    $getExist = $projectdb->query($query);
                    if( $getExist->num_rows == 0 )
                    {

                        //$result_insert = $projectdb->query("INSERT INTO $table (id, source, vsys, member_lid, table_name, rule_lid) VALUES (NULL, '$source', '$vsys', '$member_lid', '$table_name', '$rule_lid');");
                        //$sql = "INSERT INTO $table (id, source, vsys, member_lid, table_name, rule_lid) VALUES (NULL, $source, $vsys, $member_lid, $table_name, $rule_lid);";
                        $result_insert = $projectdb->query("INSERT INTO $table (id, source, vsys, member_lid, table_name, rule_lid) VALUES (NULL, '$source', '$vsys', '$member_lid', '$table_name', '$rule_lid');");
                        $sql = "INSERT INTO $table (id, member_lid, table_name, rule_lid) VALUES (NULL, $member_lid, $table_name, $rule_lid);";
                        //echo "2. INSERT INTO $table (id, source, vsys, member_lid, table_name, rule_lid) VALUES (NULL, '$source', '$vsys', '$member_lid', '$table_name', '$rule_lid');\n";
                        if( $result_insert != 1 )
                        {
                            add_log('error', 'Edit Security Rules', 'SQL INSERT: [' . $sql . ']. ', $source, 'No Action Required', '2');
                        }
                        if( ($table == "security_rules_src") || ($table == "security_rules_dst") )
                        {
                            if( $table_name != "address_groups_id" )
                            {
                                $projectdb->query("UPDATE $table_name SET used=1 WHERE id = '$member_lid';");
                            }
                        }
                    }
                }
            }
        }
    }//fin foreach

}

function getIPtoZoneRouteMapping($contextVSYS, $source, $vr, $templateId = null)
{

    global $projectdb;

    $ipv4 = array();
    $ipv6 = array();

    $ipv4sort = array();

    $interfaces_in_VR = array();
    $interfaces_vsys_mapping = array();
    $getInterfaceToVR = $projectdb->query("SELECT unitname FROM interfaces WHERE vr_id = '$vr'");
    if( $getInterfaceToVR->num_rows > 0 )
    {
        while( $data = $getInterfaceToVR->fetch_assoc() )
        {
            $interfaces_in_VR[] = $data['unitname'];
        }
    }

    //TODO: Check that it is correct to use the default_vsys for a given template
    if( !is_null($templateId) )
    {
        $templateResult = $projectdb->query("SELECT name, interfaces FROM virtual_systems WHERE template = '$templateId';");
        if( $templateResult->num_rows > 0 )
        {
            while( $data = $templateResult->fetch_assoc() )
            {
                $interfacesString = $data['interfaces'];
                $vsys = $data['name'];
                $interfacesStringArr = explode(",", $interfacesString);
                foreach( $interfacesStringArr as $interfaceName )
                {
                    $interfaces_vsys_mapping[$interfaceName] = $vsys;
                }
            }
        }
    }


    $getStaticRoutes = $projectdb->query("SELECT ip_version, name, destination, tointerface, nexthop, nexthop_value FROM routes_static WHERE vr_id = '$vr';");

    if( $getStaticRoutes->num_rows >= 1 )
    {

        while( $getSRData = $getStaticRoutes->fetch_assoc() )
        {

            $destination = $getSRData['destination'];
            $ipv4Mapping = stringToStartEnd($destination);

            $nexthopIf = $getSRData['tointerface'];

            $nextHopType = $getSRData['nexthop'];
            $nexthopIP = $getSRData['nexthop_value'];

            if( $nexthopIf != "" )
            {

                // Comprobar que la interfaz del nexthop pertenece al virtual_router pasado
//                $getInterfaceToVR = $projectdb->query("SELECT unitname FROM interfaces WHERE vr_id = '$vr' AND unitname = '$nexthopIf' ;");
//                if ($getInterfaceToVR->num_rows > 0){
                if( in_array($nexthopIf, $interfaces_in_VR) )
                {
                    //TODO. The selected VSYS is not correct when it is a Panorama. The VSYS is actually a DG. We need to find out the Vsys that will reflect the DG for the selected devices.
                    if( isset($interfaces_vsys_mapping[$nexthopIf]) )
                    {
                        $contextVSYS = $interfaces_vsys_mapping[$nexthopIf];
                    }
                    $getInterfaceToVSYS = $projectdb->query("SELECT name, zone FROM interfaces WHERE vsys = '$contextVSYS' AND unitname = '$nexthopIf' AND  source='$source';");
                    if( $getInterfaceToVSYS->num_rows == 0 )
                    {
                        continue;
                    }
                    else
                    {
                        $getIntToVSYSData = $getInterfaceToVSYS->fetch_assoc();
                        $zone_name = $getIntToVSYSData['zone'];

                        $record = array('network' => $destination, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $zone_name, 'origin' => 'static', 'priority' => 2);
                        $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;

                        unset($record);
                    }

                }
                else
                {
                    $findZone = null;
                    $getInterfaces = $projectdb->query("SELECT name, unitipaddress, type, media, zone FROM interfaces WHERE vsys = '$contextVSYS' AND source = '$source' AND unitipaddress!='';");
                    if( $getInterfaces->num_rows >= 1 )
                    {
                        while( $getIData = $getInterfaces->fetch_assoc() )
                        {
                            $name_inferface = $getIData['name'];
                            $ip_interface = $getIData['unitipaddress'];
                            $type_interface = $getIData['type'];
                            $media = $getIData['media'];
                            $zone_interface = $getIData['zone'];
                            if( (($media == "ethernet") || ($media == "aggregate-ethernet") || ($media == "loopback")) && $type_interface == "layer3"
                                || $type_interface == 'vlan' )
                            {
                                $ip_interface_f = explode(",", $ip_interface);
                                foreach( $ip_interface_f as $interfaceIP )
                                {
                                    $return_match = netMatch($nexthopIP, $interfaceIP);
                                    if( $return_match > 0 )
                                    {
                                        if( $zone_interface == "" )
                                        {
                                            continue;
                                        }
                                        else
                                        {
                                            $findZone = $zone_interface;
                                        }
                                        break;
                                    }
                                }
                                if( $findZone !== null )
                                {
                                    break;
                                }
                            }
                            else
                            {
                                continue;
                            }
                        }
                    }
                    if( $findZone === null )
                    {
                        continue;
                    }
                    $record = array('network' => $destination, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone, 'origin' => 'static', 'priority' => 2);
                    $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                    unset($record);
                }
            }
            elseif( $nextHopType == 'ip-address' )
            {

                $findZone = null;

                $getInterfaces = $projectdb->query("SELECT name, unitipaddress, type, media, zone FROM interfaces WHERE vsys = '$contextVSYS' AND source = '$source' AND unitipaddress!='';");

                if( $getInterfaces->num_rows >= 1 )
                {
                    while( $getIData = $getInterfaces->fetch_assoc() )
                    {

                        $name_inferface = $getIData['name'];
                        $ip_interface = $getIData['unitipaddress'];
                        $type_interface = $getIData['type'];
                        $media = $getIData['media'];
                        $zone_interface = $getIData['zone'];

                        if( (($media == "ethernet") || ($media == "aggregate-ethernet") || ($media == "loopback")) && $type_interface == "layer3"
                            || $type_interface == 'vlan' )
                        {

                            $ip_interface_f = explode(",", $ip_interface);
                            foreach( $ip_interface_f as $interfaceIP )
                            {
                                $return_match = netMatch($nexthopIP, $interfaceIP);
                                if( $return_match > 0 )
                                {

                                    if( $zone_interface == "" )
                                    {
                                        continue;
                                    }
                                    else
                                    {
                                        $findZone = $zone_interface;
                                    }
                                    break;
                                }
                            }
                            if( $findZone !== null )
                            {
                                break;
                            }
                        }
                        else
                        {
                            continue;
                        }
                    }
                }
                if( $findZone === null )
                {
                    continue;
                }
                $record = array('network' => $destination, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone, 'origin' => 'static', 'priority' => 2);
                $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;

                //print_r($record);
                unset($record);
            }
        }// fin while principal
    }

    $getInterfaces = $projectdb->query("SELECT name, unitipaddress, type, media, zone FROM interfaces WHERE source = '$source' AND vr_id = '$vr';");

    if( $getInterfaces->num_rows >= 1 )
    {
        while( $getIData = $getInterfaces->fetch_assoc() )
        {
            $name_inferface = $getIData['name'];
            $ip_interface = $getIData['unitipaddress'];
            $type_interface = $getIData['type'];
            $media = $getIData['media'];
            $zone_interface = $getIData['zone'];

            if( (($media == "ethernet") || ($media == "aggregate-ethernet") || ($media == "loopback")) && $type_interface == "layer3" ||
                $type_interface == 'vlan' )
            {

                if( $zone_interface == "" )
                {
                    continue;
                }
                else
                {
                    $findZone = $zone_interface;
                }

                $ipAddresses = explode(",", $ip_interface);

                foreach( $ipAddresses as $interfaceIP )
                {

                    $ipv4Mapping = stringToStartEnd($interfaceIP);
                    if( isset($ipv4Mapping['start']) )
                    {
                        $start = $ipv4Mapping['start'];
                    }
                    else
                    {
                        $start = '';
                    }
                    if( isset($ipv4Mapping['end']) )
                    {
                        $end = $ipv4Mapping['end'];
                    }
                    else
                    {
                        $end = '';
                    }

                    $record = array('network' => $interfaceIP, 'start' => $start, 'end' => $end, 'zone' => $findZone, 'origin' => 'connected', 'priority' => 1);
                    $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                    unset($record);
                }
            }
        }
    }

    ksort($ipv4sort);

    foreach( $ipv4sort as &$record )
    {
        ksort($record);
        foreach( $record as &$subRecord )
        {
            foreach( $subRecord as &$subSubRecord )
            {
                $ipv4[] = &$subSubRecord;
            }
        }
    }

    $result = array('ipv4' => &$ipv4, 'ipv6' => &$ipv6);

    return $result;

}

/**
 * return NULL if not match, $sub if $sub is included in $ref, $ref if $ref is included in $sub
 * @param MemberObject $sub
 * @param MemberObject $ref
 * @param int $way
 * @return MemberObject
 */
function serviceMatchObjects2Ways($sub, $ref, &$way)
{


    $sub_local = "$sub->cidr/$sub->value";
    $ref_local = "$ref->cidr/$ref->value";

    //echo "Dentro de serviceMatchObjects2Ways: sub_local: " .$sub_local. "\n";
    //echo "Dentro de serviceMatchObjects2Ways: ref_local: " .$ref_local. "\n";

    if( ($ref->value == 0 || $ref->value == '0-65535') && ($ref->cidr == '' || $ref->cidr == 'any') )
    {
        $way = 1;
        return $sub;
    }

    if( ($sub->value == 0 || $sub->value == '0-65535') && ($sub->cidr == '' || $sub->cidr == 'any') )
    {
        $way = 2;
        return $ref;
    }

    if( $sub->cidr == $ref->cidr || $ref->cidr == '' )
    {
        $result = serviceMatch2Ways($sub_local, $ref_local, $way);
        //echo "Result: ".$result." AND way: ".$way."\n";
        //print_r($result);
        if( $way === 1 )
        {
            //echo "Way: " .$way. "\n";
            //echo "Return Sub: " .$sub. "\n";
            return $sub;
        }
        elseif( $way === 2 )
        {
            //echo "Way: " .$way. "\n";
            //echo "Return Sub: " .$ref. "\n";
            return $ref;
        }
        elseif( $way === -1 )
        {
            //echo "Way: " .$way. "\n";
            //echo "Return null\n";
            return null;
        }
        else
        {
            $serviceArr = explode("/", $result);
            $portsArr = explode("-", $serviceArr[1]);
            $start = $portsArr[0];
            $end = isset($portsArr[1]) ? $portsArr[1] : $portsArr[0];
            $protocol = $serviceArr[0];
            $member = new MemberObject('', '', "$start-$end", $protocol);
            //echo "Way: " .$way. "\n";
            //echo "Return member: \n";
            //print_r($member);
            return $member;
        }
    }
}

/**
 * return NULL if not match, $sub if $sub is included in $ref, $ref if $ref is included in $sub
 * @param string|int[] $sub ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
 * @param string|int[] $ref ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
 * @param int $way
 * @return string
 */
function serviceMatch2Ways($sub, $ref, &$way)
{
    $sub_local = $sub;
    $ref_local = $ref;

    if( is_array($sub_local) )
    {
        $subStart = $sub_local['start'];
        $subEnd = $sub_local['end'];
        $subProtocol = $sub_local['protocol'];
    }
    else
    {
        $array = explode("/", $sub_local);
        $subProtocol = $array[0];
        $array2 = explode("-", $array[1]);
        $subStart = $array2[0];
        if( isset($array2[1]) )
        {
            $subEnd = $array2[1];
        }
        else
        {
            $subEnd = $subStart;
        }
    }

    if( is_array($ref_local) )
    {
        $refStart = $ref_local['start'];
        $refEnd = $ref_local['end'];
        $refProtocol = $sub_local['protocol'];
    }
    else
    {
        $array = explode("/", $ref_local);
        $refProtocol = $array[0];
        $array2 = explode("-", $array[1]);
        $refStart = $array2[0];
        if( isset($array2[1]) )
        {
            $refEnd = $array2[1];
        }
        else
        {
            $refEnd = $refStart;
        }
    }

    if( $refProtocol === $subProtocol )
    {
        //Calculate overlapping
        //echo "Sub Start: " .$subStart. "\n";
        //echo "Ref Start: " .$refStart. "\n";
        //echo "Sub End: " .$subEnd. "\n";
        //echo "Ref End: " .$refEnd. "\n";
        if( $subStart >= $refStart && $subEnd <= $refEnd )
        {
            $way = 1;
            return $sub;
        }
        if( $subStart >= $refStart && $subStart <= $refEnd )
        {
            if( $subStart < $refEnd )
            {
                $a = "$refProtocol/$subStart-$refEnd";
            }
            else
            {
                $a = "$refProtocol/$subStart";
            }
            $way = 0;
            return $a;
        }
        if( $subEnd >= $refStart && $subEnd <= $refEnd )
        {
            if( $refStart < $subEnd )
            {
                $a = "$refProtocol/$refStart-$subEnd";
            }
            else
            {
                $a = "$refProtocol/$refStart";
            }
            $way = 0;
            return $a;
        }
        if( $subStart <= $refStart && $subEnd >= $refEnd )
        {
            $way = 2;
            return $ref;
        }
    }
    $way = -1;
    return null;
}

function netMatchObjects2Ways($sub, $ref, &$way)
{
    if( isset($sub->cidr) && !strcmp($sub->cidr, '') == 0 )
    {
        $sub_local = "$sub->value/$sub->cidr";
    }
    else
    {
        $sub_local = "$sub->value";
    }
    if( isset($ref->cidr) && !strcmp($ref->cidr, '') == 0 )
    {
        $ref_local = "$ref->value/$ref->cidr";
    }
    else
    {
        $ref_local = "$ref->value";
    }

    $result = netMatch2Ways($sub_local, $ref_local, $way);
    if( $way == AisinB ) return $sub;
    elseif( $way == BisinA ) return $ref;
    else
    {
        $start = $result['start'];
        $end = $result['end'];
        $member = new MemberObject('', '', "$start-$end", '32');
        return null;
    }
}

/**
 * return NULL if not match, $sub if $sub is included in $ref, $ref if $ref is included in $sub
 * @param string|int[] $sub ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
 * @param string|int[] $ref ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
 * @param int $way
 * @return string
 */
function netMatch2Ways($sub, $ref, &$way)
{
    $sub_local = $sub;
    $ref_local = $ref;

    if( is_array($sub_local) )
    {
        $subNetwork = $sub_local['start'];
        $subBroadcast = $sub_local['end'];
    }
    else
    {
        /*      //Check whether it is a IP/CIDR format
                $validIP = filter_var($sub_local, FILTER_VALIDATE_IP);
                //Check whether it is a domain
                if(!$validIP){
                    $valid = preg_match('/^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$/', $sub_local);
                    if($valid){
                        $sub_local= gethostbyname($sub_local);
                    }else{
                        $sub_local= "";
                    }
                }
                */
        $res = stringToStartEnd($sub_local);
        $subNetwork = $res['start'];
        $subBroadcast = $res['end'];
    }

    if( is_array($ref_local) )
    {
        $refNetwork = $ref_local['start'];
        $refBroadcast = $ref_local['end'];
    }
    else
    {
        /*
        //Check whether it is a IP/CIDR format
        $validIP = filter_var($ref_local, FILTER_VALIDATE_IP);
        //Check whether it is a domain
        if(!$validIP){
            $valid = preg_match('/^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$/', $ref_local);
            if($valid){
                $ref_local= gethostbyname($ref_local);
            }else{
                $ref_local="";
            }
        }
         */
        $res = stringToStartEnd($ref_local);
        $refNetwork = $res['start'];
        $refBroadcast = $res['end'];
    }

    //Calculate overlapping
    if( $subNetwork >= $refNetwork && $subBroadcast <= $refBroadcast )
    {
        $way = AisinB;
        return $sub;
    }
    if( $subNetwork >= $refNetwork && $subNetwork <= $refBroadcast )
    {
        $a['start'] = $subNetwork;
        $a['end'] = $refBroadcast;
        $way = AisPartiallyInB;
        return $a;
    }
    if( $subBroadcast >= $refNetwork && $subBroadcast <= $refBroadcast )
    {
        $a['start'] = $refNetwork;
        $a['end'] = $subBroadcast;
        $way = AisPartiallyInB;
        return $a;
    }
    if( $subNetwork <= $refNetwork && $subBroadcast >= $refBroadcast )
    {
        $way = BisinA;
        return $ref;
    }
    $way = AdoesNotIntersectB;
    return null;

}


/**
 * return 0 if not match, 1 if $sub is included in $ref, 2 if $sub is partially matched by $ref.
 * @param string|int[] $sub ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
 * @param string|int[] $ref
 * @return int
 */
function netMatch($sub, $ref)
{

    if( is_array($sub) )
    {
        $subNetwork = $sub['start'];
        $subBroadcast = $sub['end'];
    }
    else
    {
        $res = stringToStartEnd($sub);
        $subNetwork = $res['start'];
        $subBroadcast = $res['end'];
    }
    if( is_array($ref) )
    {
        $refNetwork = $ref['start'];
        $refBroadcast = $ref['end'];
    }
    else
    {
        $res = stringToStartEnd($ref);
        $refNetwork = $res['start'];
        $refBroadcast = $res['end'];
    }
    if( $subNetwork >= $refNetwork && $subBroadcast <= $refBroadcast )
    {
        return 1;
    }
    if( $subNetwork >= $refNetwork && $subNetwork <= $refBroadcast ||
        $subBroadcast >= $refNetwork && $subBroadcast <= $refBroadcast ||
        $subNetwork <= $refNetwork && $subBroadcast >= $refBroadcast )
    {
        return 2;
    }
    return 0;
}

function stringToStartEnd($value)
{
    global $source;

    $result = array();
    if( $value != "" )
    {
        $ex = explode('-', $value);
        if( count($ex) == 2 )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE )
                add_log('warning', 'Phase 2: Reading Address Objects and Groups', '{' . $ex[0] . '} is not a valid IP [' . $value . '].', $source, '');

            if( filter_var($ex[1], FILTER_VALIDATE_IP) === FALSE )
                add_log('warning', 'Phase 2: Reading Address Objects and Groups', '{' . $ex[1] . '} is not a valid IP [' . $value . '].', $source, '');

            $result['start'] = ip2long($ex[0]);
            $result['end'] = ip2long($ex[1]);

            return $result;
        }

        $ex = explode('/', $value);
        if( count($ex) > 1 && $ex[1] != '32' )
        {

            if( $ex[1] < 0 || $ex[1] > 32 )
                add_log('warning', 'Phase 2: Reading Address Objects and Groups', 'Invalid netmask in value {' . $value . '}.', $source, '');

            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE )
                add_log('warning', 'Phase 2: Reading Address Objects and Groups', '{' . $ex[0] . '} is not a valid IP[' . $value . '].', $source, '');

            $bmask = 0;
            for( $i = 1; $i <= (32 - $ex[1]); $i++ )
                $bmask += pow(2, $i - 1);

            $subNetwork = ip2long($ex[0]) & ((-1 << (32 - (int)$ex[1])));
            $subBroadcast = ip2long($ex[0]) | $bmask;

        }
        elseif( count($ex) > 1 && $ex[1] == '32' )
        {

            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE )
                add_log('warning', 'Phase 2: Reading Address Objects and Groups', '{' . $ex[0] . '} is not a valid IP [' . $value . '].', $source, '');
            $subNetwork = ip2long($ex[0]);
            $subBroadcast = $subNetwork;

        }
        else
        {
            if( filter_var($value, FILTER_VALIDATE_IP) === FALSE )
                add_log('warning', 'Phase 2: Reading Address Objects and Groups', '{' . $value . '} is not a valid IP [' . $value . '].', $source, '');

            $subNetwork = ip2long($value);
            $subBroadcast = ip2long($value);
        }

        $result['start'] = $subNetwork;
        $result['end'] = $subBroadcast;
    }
    return $result;
}

/********************************************************
 * Return an array['start']= startip and ['end']= endip  *
 * @return array                                         *
 *********************************************************/
function resolveIP_Start_End($member, $member_lid, $table_name, $ipaddress = null, $type = null)
{

    global $projectdb;

    if( is_null($ipaddress) || $member == 'Any' )
    {
        if( $member == "Any" )
        {
            $type = "ip-range";
            $ipaddress = "0.0.0.0-255.255.255.255";
            $cidr = "";
        }
        else
        {
            $getInfoMembers = $projectdb->query("SELECT id, name, type, ipaddress, cidr FROM address WHERE id = '$member_lid';");

            if( $getInfoMembers->num_rows > 0 )
            {
                while( $dataM = $getInfoMembers->fetch_assoc() )
                {
                    $type = $dataM['type'];
                    $ipaddress = $dataM['ipaddress'];
                    $cidr = $dataM['cidr'];
                    $cidr = ($cidr == '') ? '32' : $cidr;

                    if( $type == "ip-netmask" )
                    {
                        $ipaddress = $ipaddress . "/" . $cidr;
                    }
                }
            }
        }
    }
    $res = array();

    $ipArr = explode("/", $ipaddress);
    $ipArr = explode("-", $ipArr[0]);
    if( ip_version($ipArr[0]) != 'v4' )
    {
        return $res;
    }

    if( $type == 'ip-netmask' || $type == 'ip-range' )
    {
        $res = stringToStartEnd($ipaddress);
    }
    else
    {

    }
    return $res;
}

function getAutoZone($zoneIP4Mapping, $member_lid, $table_name, $is_negated)
{
//    global $projectdb;
//    $objectsMapping = Array();
    $fakeMapping = array();
    $zones = array();
    $member = "";

    $objectsMapping = getIP4Mapping($member, $member_lid, $table_name);
    if( count($objectsMapping['map']) == 0 && $member_lid > 0 && $table_name != '' )
    {
        //echo "correcting";
        $objectsMapping['map'][] = [
            'start' => 0,
            'end' => 0
        ];
    }

    //Calculate the inverse of a network
    if( $is_negated == "1" )
    {
        $fakeMapping['map'][] = array('start' => 0, 'end' => ip2long('255.255.255.255'));
        foreach( $objectsMapping['map'] as $entry )
        {
            //echo "LOS OBJECTS MAPPING MAP SON: " .$entry. "\n";
            //print_r($entry);
            removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
            //$objectsMapping = &$fakeMapping;
            $objectsMapping = $fakeMapping;
        }
    }

    //Prioritize the zoneMapping, sort them by priority and by narrowes
    $zoneMappingSortingTree = array();
    foreach( $zoneIP4Mapping as $zone )
    {
        //First the netmask
        //Then the priority
        //Finally the metric
        $network = $zone['network'];
        $networkParts = explode("/", $network);
        $cidr = (int)isset($networkParts[1]) ? $networkParts[1] : 32;
        $priority = (int)isset($zone['priority']) ? $zone['priority'] : 10;
        $metric = (int)isset($zone['metric']) ? $zone['metric'] : 10;

        $zoneMappingSortingTree[32 - $cidr][(int)$priority][(int)$metric][] = $zone;
    }


    $sortedZoneMapping = array();
    ksort($zoneMappingSortingTree);

    foreach( $zoneMappingSortingTree as $cidrsMappings )
    {
        ksort($cidrsMappings);
        foreach( $cidrsMappings as $priorityMappings )
        {
            ksort($priorityMappings);
            foreach( $priorityMappings as $mappings )
            {
                ksort($mappings);
                foreach( $mappings as $mapping )
                {
                    $sortedZoneMapping[] = $mapping;
                }
            }
        }
    }

    foreach( $sortedZoneMapping as &$zoneMapping )
    {
        $result = removeNetworkFromIP4Mapping($objectsMapping['map'], $zoneMapping);
        if( $result != 0 )
        {
            $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
        }
        if( count($objectsMapping) == 0 )
            break;
    }
    return $zones;
}

function getAutoZoneToVR($vr, $member_lid, $table_name, $vsys, $source)
{
//    global $projectdb;
//    $objectsMapping = Array();
    $zones = array();

    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    $member = "";
    $objectsMapping = getIP4Mapping($member, $member_lid, $table_name);

    $zoneIP4Mapping = $ipMapping['ipv4'];

    foreach( $zoneIP4Mapping as &$zoneMapping )
    {
        $result = removeNetworkFromIP4Mapping($objectsMapping['map'], $zoneMapping);
        if( $result != 0 )
        {
            $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
        }
        if( count($objectsMapping) == 0 )
            break;
    }
    return $zones;
}

/**
 * @return array  result['map'][] will contain all mapping in form of an array['start'] and ['end]. result['unresolved'][] will provide a list unresolved objects
 */
function getIP4Mapping($member, $member_lid, $table_name)
{
    global $projectdb;

    $result = array('unresolved' => array());
    $map = array();


    //if (($table_name == "address") or ( $table_name == "shared_address")) {
    if( $table_name == "address" )
    {

        $getInfoMembers = $projectdb->query("SELECT id, name, type, ipaddress, cidr FROM $table_name WHERE id = '$member_lid' AND v4='1';");

        if( $getInfoMembers->num_rows > 0 )
        {

            $dataM = $getInfoMembers->fetch_assoc();
            $type = $dataM['type'];
            $member = $dataM['name'];
            $ipaddress = $dataM['ipaddress'];
            $cidr = ($dataM['cidr'] == '') ? '32' : $dataM['cidr'];

            $ip = ($type == 'ip-netmask') ? $ipaddress . "/" . $cidr : $ipaddress;

            if( $type != 'ip-netmask' && $type != 'ip-range' )
            {
                $result['unresolved'][] = $ipaddress;
            }
            else
            {
                $map[] = resolveIP_Start_End($member, $member_lid, $table_name, $ip, $type);
            }
        }


    }
    elseif( $table_name == "address_groups_id" )
    {  // GROUPS
        $table_name = "address_groups";


        $query = "SELECT member, member_lid, table_name FROM $table_name WHERE lid = '$member_lid';";
        $getSRC = $projectdb->query($query);

        if( $getSRC->num_rows > 0 )
        {
            while( $getSRCData = $getSRC->fetch_assoc() )
            {
                $member = $getSRCData['member'];
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $subMap = getIP4Mapping($member, $member_lid, $table_name);

                foreach( $subMap['map'] as &$subMapRecord )
                {
                    $map[] = &$subMapRecord;
                }
                unset($subMapRecord);
                foreach( $subMap['unresolved'] as $subMapRecord )
                {
                    $result['unresolved'][] = $subMapRecord;
                }
            }
        }
    }
    else
    {
        //Error
        #Todo: Add the list of ips by regions and add the option here for default_regions and regions

    }

    $map = mergeOverlappingIP4Mapping($map);
    $result['map'] = &$map;

    return $result;
}

/**
 * @param $targetMapping The list of addresses to map
 * @param $zoneMapping
 * @return int
 */
function removeNetworkFromIP4Mapping(&$targetMapping, &$zoneMapping)
{

    $affectedRows = 0;

    $arrayCopy = $targetMapping;
    $targetMapping = array();

    foreach( $arrayCopy as &$entry )
    {
        if( $zoneMapping['start'] > $entry['end'] )
        {
            $targetMapping[] = &$entry;
            continue;
        }
        elseif( $zoneMapping['end'] < $entry['start'] )
        {
            $targetMapping[] = &$entry;
            continue;
        }
        else if( $zoneMapping['start'] <= $entry['start'] && $zoneMapping['end'] >= $entry['end'] )
        {

        }
        elseif( $zoneMapping['start'] > $entry['start'] )
        {
            if( $zoneMapping['end'] >= $entry['end'] )
            {
                $entry['end'] = $zoneMapping['start'] - 1;
                $targetMapping[] = &$entry;
            }
            else
            {
                $oldEnd = $entry['end'];
                $entry['end'] = $zoneMapping['start'] - 1;
                $targetMapping[] = &$entry;
                $targetMapping[] = array('start' => $zoneMapping['end'] + 1, 'end' => $oldEnd);
            }
        }
        else
        {
            $entry['start'] = $zoneMapping['end'] + 1;
            $targetMapping[] = &$entry;
        }
        $affectedRows++;
    }

    return $affectedRows;
}

function sortArrayByStartValue(&$arrayToSort)
{
    // Sort incl objects IP mappings by Start IP
    $returnMap = array();
    $tmp = array();
    foreach( $arrayToSort as &$incl )
    {
        $tmp[] = $incl['start'];
    }
    unset($incl);
    sort($tmp, SORT_NUMERIC);
    foreach( $tmp as &$value )
    {
        foreach( $arrayToSort as &$incl )
        {
            if( $value == $incl['start'] )
            {
                $returnMap[] = $incl;
            }
        }
    }

    return $returnMap;
}

function mergeOverlappingIP4Mapping(&$ip4mapping)
{

    $newMapping = sortArrayByStartValue($ip4mapping);

    $mapKeys = array_keys($newMapping);
    $mapCount = count($newMapping);

    for( $i = 0; $i < $mapCount; $i++ )
    {
        $current = &$newMapping[$mapKeys[$i]];
        for( $j = $i + 1; $j < $mapCount; $j++ )
        {
            $compare = &$newMapping[$mapKeys[$j]];
            if( $compare['start'] > $current['end'] + 1 )
                break;

            $current['end'] = $compare['end'];
            unset($newMapping[$mapKeys[$j]]);

            $i++;
        }
    }

    return $newMapping;
}

function get_member_and_lid($name, $source, $vsys, $object)
{

    global $projectdb;

    $member_lid = "";
    $table_name = "";

    if( ($object == "application") and ($name != "") )
    {
        $memberA = $name;
        $config_filename = $source;
        $new_vsys = $vsys;

        $isAPP = $projectdb->query("SELECT id FROM default_applications WHERE BINARY name='$memberA';");
        if( $isAPP->num_rows == 1 )
        {
            $appData = $isAPP->fetch_assoc();
            $member_lid = $appData['id'];
            $table_name = "default_applications";
        }
        else
        {
            $isAPP = $projectdb->query("SELECT id FROM applications WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys='$new_vsys';");
            if( $isAPP->num_rows == 1 )
            {
                $appData = $isAPP->fetch_assoc();
                $member_lid = $appData['id'];
                $table_name = "applications";
            }
            else
            {
                $isAPP = $projectdb->query("SELECT id FROM applications_groups_id WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys='$new_vsys';");
                if( $isAPP->num_rows == 1 )
                {
                    $appData = $isAPP->fetch_assoc();
                    $member_lid = $appData['id'];
                    $table_name = "applications_groups_id";
                }
                else
                {
                    $isAPP = $projectdb->query("SELECT id FROM applications_filters WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys='$new_vsys';");
                    if( $isAPP->num_rows == 1 )
                    {
                        $appData = $isAPP->fetch_assoc();
                        $member_lid = $appData['id'];
                        $table_name = "applications_filters";
                    }
                    else
                    {
                        $isAPP = $projectdb->query("SELECT id FROM applications WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                        if( $isAPP->num_rows == 1 )
                        {
                            $appData = $isAPP->fetch_assoc();
                            $member_lid = $appData['id'];
                            $table_name = "applications";
                        }
                        else
                        {
                            $isAPP = $projectdb->query("SELECT id FROM applications_groups_id WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                            if( $isAPP->num_rows == 1 )
                            {
                                $appData = $isAPP->fetch_assoc();
                                $member_lid = $appData['id'];
                                $table_name = "applications_groups_id";
                            }
                            else
                            {
                                $isAPP = $projectdb->query("SELECT id FROM applications_filters WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                                if( $isAPP->num_rows == 1 )
                                {
                                    $appData = $isAPP->fetch_assoc();
                                    $member_lid = $appData['id'];
                                    $table_name = "applications_filters";
                                }
                                else
                                {
                                    # No Matches
                                }
                            }
                        }
                    }
                }
            }
        }

    }
    elseif( ($object == "service") and ($name != "") )
    {
        $memberA = $name;
        $config_filename = $source;
        $new_vsys = $vsys;
        if( ($memberA == "service-http") or ($memberA == "service-https") or ($memberA == "application-default") )
        {
            $getAddress = $projectdb->query("SELECT id FROM services WHERE name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
            if( $getAddress->num_rows == 1 )
            {
                $data2 = $getAddress->fetch_assoc();
                $member_lid = $data2['id'];
                $table_name = "services";
            }
        }
        else
        {
            $getAddress = $projectdb->query("SELECT id FROM services WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA'");
            if( $getAddress->num_rows == 1 )
            {
                $data2 = $getAddress->fetch_assoc();
                $member_lid = $data2['id'];
                $table_name = "services";
            }
            else
            {
                $getGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA';");
                if( $getGroup->num_rows == 1 )
                {
                    $data2 = $getGroup->fetch_assoc();
                    $member_lid = $data2['id'];
                    $table_name = "services_groups_id";
                }
                else
                {
                    #search shareds
                    $getAddress = $projectdb->query("SELECT id FROM services WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
                    if( $getAddress->num_rows == 1 )
                    {
                        $data2 = $getAddress->fetch_assoc();
                        $member_lid = $data2['id'];
                        $table_name = "services";
                    }
                    else
                    {
                        $getGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
                        if( $getGroup->num_rows == 1 )
                        {
                            $data2 = $getGroup->fetch_assoc();
                            $member_lid = $data2['id'];
                            $table_name = "services_groups_id";
                        }
                    }
                }
            }
        }
    }
    elseif( ($object == "address") and ($name != "") )
    {
        $memberA = $name;
        $config_filename = $source;
        $new_vsys = $vsys;
        $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA';");
        if( $getAddress->num_rows == 1 )
        {
            $data2 = $getAddress->fetch_assoc();
            $member_lid = $data2['id'];
            $table_name = "address";
        }
        else
        {
            $getGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA';");
            if( $getGroup->num_rows == 1 )
            {
                $data2 = $getGroup->fetch_assoc();
                $member_lid = $data2['id'];
                $table_name = "address_groups_id";
            }
            else
            {
                #search shareds
                $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
                if( $getAddress->num_rows == 1 )
                {
                    $data2 = $getAddress->fetch_assoc();
                    $member_lid = $data2['id'];
                    $table_name = "address";
                }
                else
                {
                    $getGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
                    if( $getGroup->num_rows == 1 )
                    {
                        $data2 = $getGroup->fetch_assoc();
                        $member_lid = $data2['id'];
                        $table_name = "address_groups_id";
                    }
                    else
                    {
                        #Can be a REGION
                        $getRegion = $projectdb->query("SELECT id FROM default_regions WHERE name='$memberA'");
                        if( $getRegion->num_rows == 1 )
                        {
                            $myregion = $getRegion->fetch_assoc();
                            $member_lid = $myregion['id'];
                            $table_name = "default_regions";
                        }
                        else
                        {
                            $getRegion = $projectdb->query("SELECT id FROM regions WHERE name='$memberA' AND source='$config_filename' AND vsys='$new_vsys'");
                            if( $getRegion->num_rows == 1 )
                            {
                                $myregion = $getRegion->fetch_assoc();
                                $member_lid = $myregion['id'];
                                $table_name = "regions";
                            }
                            else
                            {
                                $getRegion = $projectdb->query("SELECT id FROM regions WHERE name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                                if( $getRegion->num_rows == 1 )
                                {
                                    $myregion = $getRegion->fetch_assoc();
                                    $member_lid = $myregion['id'];
                                    $table_name = "regions";
                                }
                                else
                                {
                                    $getRegion = $projectdb->query("SELECT id FROM external_list WHERE  name='$memberA' AND source='$config_filename' AND vsys='$new_vsys'");
                                    if( $getRegion->num_rows == 1 )
                                    {
                                        $myregion = $getRegion->fetch_assoc();
                                        $member_lid = $myregion['id'];
                                        $table_name = "external_list";
                                    }
                                    else
                                    {
                                        $getRegion = $projectdb->query("SELECT id FROM external_list WHERE name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                                        if( $getRegion->num_rows == 1 )
                                        {
                                            $myregion = $getRegion->fetch_assoc();
                                            $member_lid = $myregion['id'];
                                            $table_name = "external_list";
                                        }
                                        else
                                        {

                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    elseif( ($object == "ipaddress") and ($name != "") )
    {
        $name = explode("/", $name);
        $memberA = $name[0];
        $memberAcidr = $name[1];
        $config_filename = $source;
        $new_vsys = $vsys;
        $query = "SELECT id FROM address WHERE source='$config_filename' AND vsys='$new_vsys' AND ipaddress = '$memberA' and cidr='$memberAcidr';";
        $getAddress = $projectdb->query($query);
        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   Query :\n $query\n$getAddress->num_rows\n"); fclose($my);
        if( $getAddress->num_rows == 1 )
        {
            $data2 = $getAddress->fetch_assoc();
            $member_lid = $data2['id'];
            $table_name = "address";
        }
        else
        {
            #search shareds
            $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$config_filename' AND vsys = 'shared' AND ipaddress = '$memberA' and cidr='$memberAcidr'");
            if( $getAddress->num_rows == 1 )
            {
                $data2 = $getAddress->fetch_assoc();
                $member_lid = $data2['id'];
                $table_name = "address";
            }
        }
    }

    if( ($member_lid != "") and ($table_name != "") )
    {
        return array("member_lid" => $member_lid, "table_name" => $table_name);
    }
}

function get_member_and_lid_name_int($name, $source, $vsys, $object)
{
    require_once INC_ROOT . '/libs/common/address/address.php';
    /** var Mysqli*/
    global $projectdb;

    $projectName = getProjectName($projectdb);

    $member_lid = $table_name = "";
    if( ($object == "application") and ($name != "") )
    {
        $memberA = $name;
        $config_filename = $source;
        $new_vsys = $vsys;

        $isAPP = $projectdb->query("SELECT id FROM default_applications WHERE BINARY name='$memberA';");
        if( $isAPP->num_rows == 1 )
        {
            $appData = $isAPP->fetch_assoc();
            $member_lid = $appData['id'];
            $table_name = "default_applications";
        }
        else
        {
            $isAPP = $projectdb->query("SELECT id FROM applications WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys='$new_vsys';");
            if( $isAPP->num_rows == 1 )
            {
                $appData = $isAPP->fetch_assoc();
                $member_lid = $appData['id'];
                $table_name = "applications";
            }
            else
            {
                $isAPP = $projectdb->query("SELECT id FROM applications_groups_id WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys='$new_vsys';");
                if( $isAPP->num_rows == 1 )
                {
                    $appData = $isAPP->fetch_assoc();
                    $member_lid = $appData['id'];
                    $table_name = "applications_groups_id";
                }
                else
                {
                    $isAPP = $projectdb->query("SELECT id FROM applications_filters WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys='$new_vsys';");
                    if( $isAPP->num_rows == 1 )
                    {
                        $appData = $isAPP->fetch_assoc();
                        $member_lid = $appData['id'];
                        $table_name = "applications_filters";
                    }
                    else
                    {
                        $isAPP = $projectdb->query("SELECT id FROM applications WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                        if( $isAPP->num_rows == 1 )
                        {
                            $appData = $isAPP->fetch_assoc();
                            $member_lid = $appData['id'];
                            $table_name = "applications";
                        }
                        else
                        {
                            $isAPP = $projectdb->query("SELECT id FROM applications_groups_id WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                            if( $isAPP->num_rows == 1 )
                            {
                                $appData = $isAPP->fetch_assoc();
                                $member_lid = $appData['id'];
                                $table_name = "applications_groups_id";
                            }
                            else
                            {
                                $isAPP = $projectdb->query("SELECT id FROM applications_filters WHERE BINARY name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
                                if( $isAPP->num_rows == 1 )
                                {
                                    $appData = $isAPP->fetch_assoc();
                                    $member_lid = $appData['id'];
                                    $table_name = "applications_filters";
                                }
                                else
                                {
                                    # No Matches
                                }
                            }
                        }
                    }
                }
            }
        }

    }
    elseif( ($object == "service") and ($name != "") )
    {
        $memberA = $name;
        $config_filename = $source;
        $new_vsys = $vsys;
        if( ($memberA == "service-http") or ($memberA == "service-https") or ($memberA == "application-default") )
        {
            $getAddress = $projectdb->query("SELECT id FROM services WHERE name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
            if( $getAddress->num_rows == 1 )
            {
                $data2 = $getAddress->fetch_assoc();
                $member_lid = $data2['id'];
                $table_name = "services";
            }
        }
        else
        {
            $getAddress = $projectdb->query("SELECT id FROM services WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA'");
            if( $getAddress->num_rows == 1 )
            {
                $data2 = $getAddress->fetch_assoc();
                $member_lid = $data2['id'];
                $table_name = "services";
            }
            else
            {
                $getGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA';");
                if( $getGroup->num_rows == 1 )
                {
                    $data2 = $getGroup->fetch_assoc();
                    $member_lid = $data2['id'];
                    $table_name = "services_groups_id";
                }
                else
                {
                    #search shareds
                    $getAddress = $projectdb->query("SELECT id FROM services WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
                    if( $getAddress->num_rows == 1 )
                    {
                        $data2 = $getAddress->fetch_assoc();
                        $member_lid = $data2['id'];
                        $table_name = "services";
                    }
                    else
                    {
                        $getGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
                        if( $getGroup->num_rows == 1 )
                        {
                            $data2 = $getGroup->fetch_assoc();
                            $member_lid = $data2['id'];
                            $table_name = "services_groups_id";
                        }
                    }
                }
            }
        }
    }
    elseif( ($object == "address") and ($name != "") )
    {
        $params = [
            'project' => $projectName,
            'source' => $source,
            'vsys' => $vsys,
        ];

        $allAddresses = get_addressAll($projectName, 'override', $params);
        foreach( $allAddresses['msg'] as $addressObject )
        {
            if( $addressObject['name'] == $name )
            {
                return array("member_lid" => $addressObject['idx'], "table_name" => $addressObject['table_name']);
            }
        }
//        $memberA = $name;
//        $config_filename = $source;
//        $new_vsys = $vsys;
//        $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA';");
//        if ($getAddress->num_rows == 1) {
//            $data2 = $getAddress->fetch_assoc();
//            $member_lid = $data2['id'];
//            $table_name = "address";
//        } else {
//            $getGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$config_filename' AND vsys='$new_vsys' AND BINARY name = '$memberA';");
//            if ($getGroup->num_rows == 1) {
//                $data2 = $getGroup->fetch_assoc();
//                $member_lid = $data2['id'];
//                $table_name = "address_groups_id";
//            } else {
//                #search shareds
//                $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
//                if ($getAddress->num_rows == 1) {
//                    $data2 = $getAddress->fetch_assoc();
//                    $member_lid = $data2['id'];
//                    $table_name = "address";
//                } else {
//                    $getGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$config_filename' AND BINARY name = '$memberA' AND vsys = 'shared';");
//                    if ($getGroup->num_rows == 1) {
//                        $data2 = $getGroup->fetch_assoc();
//                        $member_lid = $data2['id'];
//                        $table_name = "address_groups_id";
//                    } else {
//                        #Can be a REGION
//                        $getRegion = $projectdb->query("SELECT id FROM default_regions WHERE name='$memberA'");
//                        if ($getRegion->num_rows == 1) {
//                            $myregion = $getRegion->fetch_assoc();
//                            $member_lid = $myregion['id'];
//                            $table_name = "default_regions";
//                        } else {
//                            $getRegion = $projectdb->query("SELECT id FROM regions WHERE name='$memberA' AND source='$config_filename' AND vsys='$new_vsys'");
//                            if ($getRegion->num_rows == 1) {
//                                $myregion = $getRegion->fetch_assoc();
//                                $member_lid = $myregion['id'];
//                                $table_name = "regions";
//                            } else {
//                                $getRegion = $projectdb->query("SELECT id FROM regions WHERE name='$memberA' AND source='$config_filename' AND vsys = 'shared';");
//                                if ($getRegion->num_rows == 1) {
//                                    $myregion = $getRegion->fetch_assoc();
//                                    $member_lid = $myregion['id'];
//                                    $table_name = "regions";
//                                } else {
//                                    $getRegion = $projectdb->query("SELECT id FROM external_list WHERE  name='$memberA' AND source='$config_filename' AND vsys='$new_vsys'");
//                                    if ($getRegion->num_rows == 1) {
//                                        $myregion = $getRegion->fetch_assoc();
//                                        $member_lid = $myregion['id'];
//                                        $table_name = "external_list";
//                                    } else {
//                                        $getRegion = $projectdb->query("SELECT id FROM external_list WHERE  name='$memberA' AND source='$config_filename' AND vsys = 'shared'");
//                                        if ($getRegion->num_rows == 1) {
//                                            $myregion = $getRegion->fetch_assoc();
//                                            $member_lid = $myregion['id'];
//                                            $table_name = "external_list";
//                                        } else {
//
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
    }

    if( ($member_lid != "") and ($table_name != "") )
    {
        return array("member_lid" => $member_lid, "table_name" => $table_name);
    }
}

function getRecommendedGroupsUserId($rule_lid, $data, $source)
{

    global $projectdb;

    $projectdb->query("TRUNCATE TABLE userid_group_recommended;");

    //$array1 = array(11,12,13,14);
    //$array3 = array(9,17,18);
    //$array2 = array(11,12,13);
    //$array3 = array(12);
    //$array5 = array(18);

    //$is_match_maybe = array_intersect($array1, $array3, $array4);
    //$is_match_diff = array_diff($array2, $array1);

    $data_array = array();
    $name_user = array();
    $name_user_bis = array();


    $flag_one_selection = 0;

    $sql_rule_lid = " rule_lid IN ($rule_lid) ";

    if( $data != "all" )
    {

        $users_selected = explode(";", $data);
        //echo "Total users: " .count($users_selected). "\n";
        $date = array();

        $date_sql = "";

        if( count($users_selected) != 1 )
        {
            foreach( $users_selected as $key => $value )
            {

                $data_array = explode(",", $value);

                if( strstr($data_array[0], ':') )
                {
                    $date_sql = " date_retrieve LIKE '$data_array[0]%' ";
                }
                else
                {
                    $name_u = addslashes($data_array[0]);
                    $name_user[] = " '$name_u' ";
                    $name_user_bis[] = $name_u;
                }
                if( !in_array($parser, $date) )
                {
                    $date[] = $parser;
                }

            }

        }
        else
        {
            // Only one selection --> return this.
            foreach( $users_selected as $key => $value )
            {
                $data_array = explode(",", $value);
                if( strstr($data_array[0], ':') )
                {
                    $getUsers = $projectdb->query("SELECT DISTINCT(name) FROM userid_from_log WHERE $sql_rule_lid AND date_retrieve LIKE '$data_array[0]%';");
                    if( $getUsers->num_rows > 0 )
                    {
                        while( $dataU = $getUsers->fetch_assoc() )
                        {
                            $name_u = addslashes($dataU['name']);
                            $name_user[] = " '$name_u' ";
                            $name_user_bis[] = $name_u;
                        }
                    }
                }
                else
                {
                    $name_u = addslashes($data_array[0]);
                    $name_user[] = " '$name_u' ";
                    $flag_one_selection = 1;
                }
            }

        }


    }
    else
    {
        // For all
        $getUsers = $projectdb->query("SELECT DISTINCT(name) FROM userid_from_log WHERE $sql_rule_lid;");
        if( $getUsers->num_rows > 1 )
        {
            while( $dataU = $getUsers->fetch_assoc() )
            {
                $name_u = addslashes($dataU['name']);
                $name_user[] = " '$name_u' ";
                $name_user_bis[] = $name_u;

            }
        }
        elseif( $getUsers->num_rows == 1 )
        {
            $dataU = $getUsers->fetch_assoc();
            $name_u = addslashes($dataU['name']);
            $name_user[] = " '$name_u' ";
            $name_user_bis[] = $name_u;
            $flag_one_selection = 1;
        }
    }
    //print_r($name_user);
    $name_user = array_unique($name_user);
    $total_users = count($name_user);


    $groups_recommended_1 = array();
    $groups_match = array();
    $groups_maybe = array();
    $is_match_maybe = array();
    $is_first = 1;
    $is_is_first = 0;

    $projectdb->query("DELETE FROM userid_calculate_recommended WHERE rule_lid = '$rule_lid';");

    $getTotalUsers = $projectdb->query("SELECT COUNT(lid) AS total_lid, name FROM userid_group_members WHERE name IN (" . implode(',', $name_user) . ")  GROUP BY name ORDER BY total_lid DESC;");
    //echo "SELECT COUNT(lid) AS total_lid, name FROM userid_group_members WHERE name IN (".implode(',', $name_user).") GROUP BY name ORDER BY total_lid DESC;";
    $total_users_with_groups = $getTotalUsers->num_rows;

    if( $getTotalUsers->num_rows > 0 )
    {
        while( $dataTU = $getTotalUsers->fetch_assoc() )
        {
            $groups_lid = array();
            $user = addslashes($dataTU['name']);
            //echo "User: " .$user. "\n";

            $groups_recommended_2 = array();
            $getGroupsUsers = $projectdb->query("SELECT lid FROM userid_group_members WHERE name = '$user';");

            if( $getGroupsUsers->num_rows > 0 )
            {
                while( $dataUG = $getGroupsUsers->fetch_assoc() )
                {

                    $lid_group = $dataUG['lid'];
                    $groups_lid[] = $lid_group;
                }
                sort($groups_lid);
                $projectdb->query("INSERT INTO userid_calculate_recommended (name, lid, rule_lid) VALUES ( '$user', '" . implode(",", $groups_lid) . "', '$rule_lid' );");

            }
        }
    }

    $groups_all = array();
    $groups_next = array();
    $groups_in_match = array();
    $groups_in_match_final = array();

    $getCalculate = $projectdb->query("SELECT id, name, lid FROM userid_calculate_recommended;");

    if( $getCalculate->num_rows > 0 )
    {
        while( $dataC = $getCalculate->fetch_assoc() )
        {
            $id = $dataC['id'];
            $name = $dataC['name'];
            if( $is_first == 1 )
            {
                $groups_all = explode(",", $dataC['lid']);
                sort($groups_all);
                $is_first = 0;
            }
            else
            {

                $groups_next = explode(",", $dataC['lid']);
                //echo "GROUPS NEXT: \n";
                //print_r($groups_next);
                $is_match = array_intersect($groups_all, $groups_next);
                //echo "IS MATCH\n";
                //print_r($is_match);

                if( count($is_match) == 0 )
                {
                    $groups_all = array_merge($groups_all, $groups_next);
                    sort($groups_all);
                }
                elseif( count($is_match) == 1 )
                {

                    $groups_in_match = array_merge($groups_in_match, $is_match);
                    sort($groups_in_match);
                    $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '" . implode(",", $is_match) . "' WHERE id = '$id';");
                }
                else
                {
                    $groups_in_match[] = current($is_match);
                    //$projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '".implode(",", $is_match)."',  is_match_many_groups = '1', lid_is_match_many_groups = '".implode(",", $is_match)."' WHERE id = '$id';");
                    //echo "UPDATE userid_calculate_recommended SET is_match = '1', is_match_many_groups = '1', lid_is_match_many_groups = '".implode(",", $is_match)."' WHERE id = '$id';";

                }
            }
            //echo "\n GROUPS ALL IN WHILE: \n";
            //print_r($groups_all);
            //echo "\n ------>GROUPS IN MATCH: \n";
            //print_r($groups_in_match);

        }// FIN WHILE
    }

    $groups_in_match_final = array_unique($groups_in_match);

    //echo "\n ---------------->GROUPS MACH FINAL: \n";
    //print_r($groups_in_match_final);
    $getNoMatch = $projectdb->query("SELECT id, name, lid FROM userid_calculate_recommended WHERE is_match = '0';");

    if( $getNoMatch->num_rows > 0 )
    {
        while( $dataNM = $getNoMatch->fetch_assoc() )
        {
            $id = $dataNM['id'];
            $name = $dataNM['name'];

            $groups_next = explode(",", $dataNM['lid']);
            //echo "GROUPS NEXT: \n";
            //print_r($groups_next);
            $is_match = array_intersect($groups_in_match_final, $groups_next);

            if( count($is_match) == 0 )
            {
                //$groups_in_match_final = array_merge($groups_in_match_final, $groups_next[0]);
                $groups_in_match_final[] = $groups_next[0];
                sort($groups_in_match_final);
                //$projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1' WHERE id = '$id';");
                $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '$groups_next[0]' WHERE id = '$id';");
            }
            elseif( count($is_match) == 1 )
            {
                $groups_in_match_final = array_merge($groups_in_match_final, $is_match);
                sort($groups_in_match_final);
                //$projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1' WHERE id = '$id';");
                $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '" . implode(",", $is_match) . "' WHERE id = '$id';");
            }
            else
            {
                $groups_in_match_final[] = current($is_match);
                $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '" . implode(",", $is_match) . "', is_match_many_groups = '1', lid_is_match_many_groups = '" . implode(",", $is_match) . "' WHERE id = '$id';");

            }
        }
    }

    $groups_in_match_final = array_unique($groups_in_match_final);
    //echo "\n ---------------------->GROUPS MACH FINAL FINAL: \n";
    //print_r($groups_in_match_final);

    /*******************************************************************************************************************************/
    /* echo "RECORRER A LA INVERSA--------------------------\n";*/
    /*******************************************************************************************************************************/
    $groups_all2 = array();
    $groups_next2 = array();
    $groups_in_match2 = array();
    $groups_in_match_final2 = array();
    $is_first = 1;

    $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '0';");
    $getCalculate = $projectdb->query("SELECT id, name, lid FROM userid_calculate_recommended ORDER BY id DESC;");

    if( $getCalculate->num_rows > 0 )
    {
        while( $dataC = $getCalculate->fetch_assoc() )
        {
            $id = $dataC['id'];
            $name = $dataC['name'];
            if( $is_first == 1 )
            {
                $groups_all2 = explode(",", $dataC['lid']);
                sort($groups_all2);
                $is_first = 0;
            }
            else
            {

                $groups_next2 = explode(",", $dataC['lid']);
                //echo "GROUPS NEXT: \n";
                //print_r($groups_next2);
                $is_match2 = array_intersect($groups_all2, $groups_next2);
                //echo "IS MATCH\n";
                //print_r($is_match2);
                if( count($is_match2) == 0 )
                {
                    $groups_all2 = array_merge($groups_all2, $groups_next2);
                    sort($groups_all2);
                }
                elseif( count($is_match2) == 1 )
                {
                    $groups_in_match2 = array_merge($groups_in_match2, $is_match2);
                    sort($groups_in_match2);
                    $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '" . implode(",", $is_match2) . "' WHERE id = '$id';");
                }
                else
                {
                    $groups_in_match2[] = current($is_match2);
                    //Comentado
                    //$projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '".implode(",", $is_match)."',  is_match_many_groups = '1', lid_is_match_many_groups = '".implode(",", $is_match)."' WHERE id = '$id';");
                    //echo "UPDATE userid_calculate_recommended SET is_match = '1', is_match_many_groups = '1', lid_is_match_many_groups = '".implode(",", $is_match2)."' WHERE id = '$id';";

                }


            }

            //echo "\n INVERSA GROUPS ALL IN WHILE: \n";
            //print_r($groups_all2);
            //echo "\n ------> INVERSA GROUPS IN MATCH: \n";
            //print_r($groups_in_match2);

        }// FIN WHILE
    }

    $groups_in_match_final2 = array_unique($groups_in_match2);

    //echo "\n ---------------->GROUPS MACH FINAL: \n";
    //print_r($groups_in_match_final2);

    $getNoMatch = $projectdb->query("SELECT id, name, lid FROM userid_calculate_recommended WHERE is_match = '0';");

    if( $getNoMatch->num_rows > 0 )
    {
        while( $dataNM = $getNoMatch->fetch_assoc() )
        {
            $id = $dataNM['id'];
            $name = $dataNM['name'];

            $groups_next2 = explode(",", $dataNM['lid']);
            //echo "GROUPS NEXT: \n";
            //print_r($groups_next2);
            $is_match2 = array_intersect($groups_in_match_final2, $groups_next2);

            if( count($is_match2) == 0 )
            {
                //$groups_in_match_final = array_merge($groups_in_match_final, $groups_next[0]);
                $groups_in_match_final2[] = $groups_next2[0];
                sort($groups_in_match_final2);
                //$projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1' WHERE id = '$id';");
                $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '$groups_next2[0]' WHERE id = '$id';");
            }
            elseif( count($is_match2) == 1 )
            {
                $groups_in_match_final2 = array_merge($groups_in_match_final2, $is_match2);
                sort($groups_in_match_final2);
                //$projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1' WHERE id = '$id';");
                $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '" . implode(",", $is_match2) . "' WHERE id = '$id';");
            }
            else
            {
                $groups_in_match_final2[] = current($is_match2);
                $projectdb->query("UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '" . implode(",", $is_match2) . "', is_match_many_groups = '1', lid_is_match_many_groups = '" . implode(",", $is_match) . "' WHERE id = '$id';");
                //echo "UPDATE userid_calculate_recommended SET is_match = '1', lid_is_match = '".implode(",", $is_match)."', is_match_many_groups = '1', lid_is_match_many_groups = '".implode(",", $is_match)."' WHERE id = '$id';";
                //echo "UPDATE userid_calculate_recommended SET is_match = '1', is_match_many_groups = '1', lid_is_match_many_groups = '".implode(",", $is_match)."' WHERE id = '$id';";

            }
        }
    }

    $groups_in_match_final2 = array_unique($groups_in_match_final2);
    //echo "\n ---------------------->INVERSA GROUPS MACH FINAL FINAL: \n";
    //print_r($groups_in_match_final2);

    if( count($groups_in_match_final) >= count($groups_in_match_final2) )
    {
        $groups_match = $groups_in_match_final2;
    }
    else
    {
        $groups_match = $groups_in_match_final;
    }
    //echo "\n--------------------------------------------->FINAL: Groups MATCH: \n";
    //print_r($groups_match);

    $groups_math_finish = array();
    $groups_math_finish_reco = array();

    if( $flag_one_selection == 1 )
    {
        $groups_math_finish[] = '{ "idx":"' . $name_u . '", "img":"userp.png", "name":"' . $name_u . '" }';
        $groups_math_finish_reco[] = $name_u;

        $projectdb->query("INSERT INTO userid_group_recommended (name, img, rule_lid) VALUES ( '$name_u', 'userp.png', '$rule_lid' );");

    }
    else
    {

        //if($total_users_with_groups == 1){
        //    $groups_match = $groups_recommended_1;
        //}

        $groups_match = array_unique($groups_match);
        //$groups_math_finish_reco = $groups_match;

        foreach( $groups_match as $key => $group_lid )
        {
            $getGroupsMatch = $projectdb->query("SELECT name, short_name FROM userid_group WHERE id = '$group_lid';");

            if( $getGroupsMatch->num_rows > 0 )
            {
                while( $dataGM = $getGroupsMatch->fetch_assoc() )
                {

                    $name_group = $dataGM['name'];
                    $short_name_group = $dataGM['short_name'];

                    if( $short_name_group == "" )
                    {
                        $short_name_group = $name_group;
                    }

                    $groups_math_finish[] = '{ "idx":"' . $group_lid . '", "img":"user-groups.png", "name":"' . addslashes($short_name_group) . '" }';
                    $name_group = addslashes($short_name_group);
                    $groups_math_finish_reco[] = $name_group;

                    $projectdb->query("INSERT INTO userid_group_recommended (name, img, rule_lid) VALUES ( '$name_group', 'user-groups.png', '$rule_lid' );");
                }
            }
        }

        // Comprobar si hay usuarios que no tienen grupo asociado
        if( $total_users != $total_users_with_groups )
        {
            foreach( $name_user_bis as $key => $user )
            {
                $getGroupsUsers = $projectdb->query("SELECT lid FROM userid_group_members WHERE name = '$user';");
                if( $getGroupsUsers->num_rows == 0 )
                {
                    $groups_math_finish[] = '{ "idx":"' . $user . '", "img":"userp.png", "name":"' . $user . '" }';
                    $groups_math_finish_reco[] = $user;
                    $projectdb->query("INSERT INTO userid_group_recommended (name, img, rule_lid) VALUES ( '$user', 'userp.png', '$rule_lid' );");
                }
            }
        }

        $groups_math_finish = array_unique($groups_math_finish);

    }

    //return $groups_math_finish;
    return array($groups_math_finish, $groups_math_finish_reco);

}

function calcVersion($source)
{
    global $projectdb;
    if( $source != "" )
    {
        $getSRC = $projectdb->query("SELECT version FROM device_mapping WHERE id='$source';");
        if( $getSRC->num_rows == 1 )
        {
            $getSRCData = $getSRC->fetch_assoc();
            $version_raw = $getSRCData['version'];
            $version = getVersion($version_raw);
            return $version;
        }
        else
        {
            return FALSE;
        }
    }
}

function getVersion($version)
{

    if( $version === "" )
    {
        $version_parser = "";
    }
    elseif( preg_match('/^6\.0/', $version) )
    {
        $version_parser = 6;
    }
    elseif( preg_match('/^6\.1/', $version) )
    {
        $version_parser = 6.1;
    }
    elseif( preg_match('/^5\./', $version) )
    {
        $version_parser = 5;
    }
    elseif( preg_match('/^7\.0/', $version) )
    {
        $version_parser = 7;
    }
    elseif( preg_match('/^7\.1/', $version) )
    {
        $version_parser = 7.1;
    }
    elseif( preg_match('/^8\.0/', $version) )
    {
        $version_parser = 8;
    }
    elseif( preg_match('/^8\.1/', $version) )
    {
        $version_parser = 8.1;
    }
    elseif( preg_match('/^9\.0/', $version) )
    {
        $version_parser = 9;
    }
    elseif( preg_match('/^9\.1/', $version) )
    {
        $version_parser = 9.1;
    }
    else
    {
        $version_parser = "";
    }

    return $version_parser;

}

function replace_dminline_by_members($vsys, $source, $rule_lid, $rules = 0)
{
    global $projectdb;
    $addSRC = array();
    $addDST = array();
    $addSRV = array();

    $getSRC = $projectdb->query("SELECT id,table_name, member_lid FROM security_rules_src WHERE rule_lid='$rule_lid' AND table_name='address_groups_id';");
    if( $getSRC->num_rows > 0 )
    {
        while( $getSRCData = $getSRC->fetch_assoc() )
        {
            $table_name = $getSRCData['table_name'];
            $member_lid = $getSRCData['member_lid'];
            $source_id = $getSRCData['id'];
            $checkDMINLINE = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid' AND (name LIKE 'DM_INLINE_%' OR name LIKE 'CSM_INLINE_%');");
            if( $checkDMINLINE->num_rows == 1 )
            {
                if( $table_name == "address_groups_id" )
                {
                    $member_table_name = "address_groups";
                }
                //elseif ($table_name=="shared_address_groups_id"){$member_table_name="shared_address_groups";}
                $getMembers = $projectdb->query("SELECT member_lid,table_name FROM $member_table_name WHERE lid='$member_lid';");
                if( $getMembers->num_rows > 0 )
                {
                    while( $getMembersData = $getMembers->fetch_assoc() )
                    {
                        $newMember = $getMembersData['member_lid'];
                        $newTable = $getMembersData['table_name'];
                        $addSRC[] = "('$source','$vsys','$newMember','$newTable','$rule_lid')";
                    }
                    $projectdb->query("DELETE FROM security_rules_src WHERE id='$source_id'");
                }
            }
        }
        if( count($addSRC) > 0 )
        {
            $unique = array_unique($addSRC);
            $projectdb->query("INSERT INTO security_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $unique) . ";");
            unset($unique);
            unset($addSRC);
        }
    }

    //$getDST=$projectdb->query("SELECT id,table_name, member_lid FROM security_rules_dst WHERE source='$source' AND vsys='$vsys' AND rule_lid='$rule_lid' AND (table_name='address_groups_id' OR table_name='shared_address_groups_id');");
    $getDST = $projectdb->query("SELECT id,table_name, member_lid FROM security_rules_dst WHERE rule_lid='$rule_lid' AND table_name='address_groups_id';");
    if( $getDST->num_rows > 0 )
    {
        while( $getSRCData = $getDST->fetch_assoc() )
        {
            $table_name = $getSRCData['table_name'];
            $member_lid = $getSRCData['member_lid'];
            $source_id = $getSRCData['id'];
            $checkDMINLINE = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid' AND (name LIKE 'DM_INLINE_%' OR name LIKE 'CSM_INLINE_%');");
            if( $checkDMINLINE->num_rows == 1 )
            {
                if( $table_name == "address_groups_id" )
                {
                    $member_table_name = "address_groups";
                }
                //elseif ($table_name=="shared_address_groups_id"){$member_table_name="shared_address_groups";}
                $getMembers = $projectdb->query("SELECT member_lid,table_name FROM $member_table_name WHERE lid='$member_lid';");
                if( $getMembers->num_rows > 0 )
                {
                    while( $getMembersData = $getMembers->fetch_assoc() )
                    {
                        $newMember = $getMembersData['member_lid'];
                        $newTable = $getMembersData['table_name'];
                        $addDST[] = "('$source','$vsys','$newMember','$newTable','$rule_lid')";
                    }
                    $projectdb->query("DELETE FROM security_rules_dst WHERE id='$source_id'");
                }
            }
        }
        if( count($addDST) > 0 )
        {
            $unique = array_unique($addDST);
            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $unique) . ";");
            unset($unique);
            unset($addDST);
        }
    }

    $getSRV = $projectdb->query("SELECT id,table_name, member_lid FROM security_rules_srv WHERE rule_lid='$rule_lid' AND table_name='services_groups_id';");
    if( $getSRV->num_rows > 0 )
    {
        while( $getSRCData = $getSRV->fetch_assoc() )
        {
            $table_name = $getSRCData['table_name'];
            $member_lid = $getSRCData['member_lid'];
            $source_id = $getSRCData['id'];
            $checkDMINLINE = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid' AND (name LIKE 'DM_INLINE_%' OR name LIKE 'CSM_INLINE_%');");
            if( $checkDMINLINE->num_rows == 1 )
            {
                if( $table_name == "services_groups_id" )
                {
                    $member_table_name = "services_groups";
                }
                $getMembers = $projectdb->query("SELECT member_lid,table_name FROM $member_table_name WHERE lid='$member_lid';");
                if( $getMembers->num_rows > 0 )
                {
                    while( $getMembersData = $getMembers->fetch_assoc() )
                    {
                        $newMember = $getMembersData['member_lid'];
                        $newTable = $getMembersData['table_name'];
                        $addSRV[] = "('$source','$vsys','$newMember','$newTable','$rule_lid')";
                    }
                    $projectdb->query("DELETE FROM security_rules_srv WHERE id='$source_id'");
                }
            }
        }
        if( count($addSRV) > 0 )
        {
            $unique = array_unique($addSRV);
            $projectdb->query("INSERT INTO security_rules_srv (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $unique) . ";");
            unset($unique);
            unset($addSRV);
        }
    }

}

function replace_nat_dminline_by_members($vsys, $source, $rule_lid, $rules = 0)
{

    global $projectdb;
    $addSRC = array();
    $addDST = array();
    $addSRV = array();

    $getSRC = $projectdb->query("SELECT id,table_name, member_lid FROM nat_rules_src WHERE rule_lid='$rule_lid' AND table_name='address_groups_id';");
    if( $getSRC->num_rows > 0 )
    {
        while( $getSRCData = $getSRC->fetch_assoc() )
        {
            $table_name = $getSRCData['table_name'];
            $member_lid = $getSRCData['member_lid'];
            $source_id = $getSRCData['id'];
            $checkDMINLINE = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid' AND (name LIKE 'DM_INLINE_%' OR name LIKE 'CSM_INLINE_%');");
            if( $checkDMINLINE->num_rows == 1 )
            {
                if( $table_name == "address_groups_id" )
                {
                    $member_table_name = "address_groups";
                }
                $getMembers = $projectdb->query("SELECT member_lid,table_name FROM $member_table_name WHERE lid='$member_lid';");
                if( $getMembers->num_rows > 0 )
                {
                    while( $getMembersData = $getMembers->fetch_assoc() )
                    {
                        $newMember = $getMembersData['member_lid'];
                        $newTable = $getMembersData['table_name'];
                        $addSRC[] = "('$source','$vsys','$newMember','$newTable','$rule_lid')";
                    }
                    $projectdb->query("DELETE FROM nat_rules_src WHERE id='$source_id'");
                }
            }
        }
        if( count($addSRC) > 0 )
        {
            $unique = array_unique($addSRC);
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $unique) . ";");
            unset($unique);
            unset($addSRC);
        }
    }

    $getDST = $projectdb->query("SELECT id,table_name, member_lid FROM nat_rules_dst WHERE rule_lid='$rule_lid' AND table_name='address_groups_id';");
    if( $getDST->num_rows > 0 )
    {
        while( $getSRCData = $getDST->fetch_assoc() )
        {
            $table_name = $getSRCData['table_name'];
            $member_lid = $getSRCData['member_lid'];
            $source_id = $getSRCData['id'];
            $checkDMINLINE = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid' AND name LIKE 'DM_INLINE_%';");
            if( $checkDMINLINE->num_rows == 1 )
            {
                if( $table_name == "address_groups_id" )
                {
                    $member_table_name = "address_groups";
                }
                $getMembers = $projectdb->query("SELECT member_lid,table_name FROM $member_table_name WHERE lid='$member_lid';");
                if( $getMembers->num_rows > 0 )
                {
                    while( $getMembersData = $getMembers->fetch_assoc() )
                    {
                        $newMember = $getMembersData['member_lid'];
                        $newTable = $getMembersData['table_name'];
                        $addDST[] = "('$source','$vsys','$newMember','$newTable','$rule_lid')";
                    }
                    $projectdb->query("DELETE FROM nat_rules_dst WHERE id='$source_id'");
                }
            }
        }
        if( count($addDST) > 0 )
        {
            $unique = array_unique($addDST);
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $unique) . ";");
            unset($unique);
            unset($addDST);
        }
    }
}

function getFoundRuleIdByMemberAndTableName($member_lid, $table_name, $position, $source, $vsys)
{

    global $projectdb;

    $ids = array();

    require_once INC_ROOT . "/bin/projects/tools/prepareQuery.php";
    $add_vsys = prepareVsysQuerySearch($projectdb, $vsys, $source, "security_rules");

    if( (preg_match("/address/i", $table_name)) || (preg_match("/regions/i", $table_name)) || (preg_match("/list/i", $table_name)) )
    {

        if( $position == "source" )
        {

            $getSecurityByAddressSrc = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_src srs "
                . " WHERE sr.source = '$source' $add_vsys AND srs.member_lid = '$member_lid' AND srs.table_name = '$table_name' "
                . " AND srs.rule_lid = sr.id;");

            if( $getSecurityByAddressSrc->num_rows > 0 )
            {
                while( $data = $getSecurityByAddressSrc->fetch_assoc() )
                {
                    $ids[] = $data['id'];
                }
            }
        }
        elseif( $position == "destination" )
        {

            $getSecurityByAddressDst = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_dst dst "
                . " WHERE sr.source = '$source' $add_vsys AND dst.member_lid = '$member_lid' AND dst.table_name = '$table_name' "
                . " AND dst.rule_lid = sr.id;");

            if( $getSecurityByAddressDst->num_rows > 0 )
            {
                while( $data = $getSecurityByAddressDst->fetch_assoc() )
                {
                    $ids[] = $data['id'];
                }
            }
        }

    }
    elseif( (preg_match("/services/i", $table_name)) )
    {

        $getSecurityByServices = $projectdb->query("SELECT sr.id AS id "
            . " FROM security_rules sr, security_rules_srv srv "
            . " WHERE sr.source = '$source' $add_vsys AND srv.member_lid = '$member_lid' AND srv.table_name = '$table_name' "
            . " AND srv.rule_lid = sr.id;");

        if( $getSecurityByServices->num_rows > 0 )
        {
            while( $data = $getSecurityByServices->fetch_assoc() )
            {
                $ids[] = $data['id'];
            }
        }
    }
    elseif( (preg_match("/applications/i", $table_name)) || ($table_name == "default_applications") )
    {


        if( $table_name != "default_applications" )
        {

            $getSecurityByApplications = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_app app "
                . " WHERE sr.source = '$source' $add_vsys AND app.member_lid = '$member_lid' AND app.table_name = '$table_name' "
                . " AND app.rule_lid = sr.id;");
        }
        elseif( $table_name == "default_applications" )
        {

            $getSecurityByApplications = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_app app "
                . " WHERE sr.source = '$source' AND app.member_lid = '$member_lid' AND app.table_name = '$table_name' "
                . " AND app.rule_lid = sr.id;");
        }

        if( $getSecurityByApplications->num_rows > 0 )
        {
            while( $data = $getSecurityByApplications->fetch_assoc() )
            {
                $ids[] = $data['id'];
            }
        }
    }

    return $ids;
}

function getMatchByMemberAndTableNameAndRuleLid($rule_lid, $member_lid, $table_name, $position, $source, $vsys)
{

    global $projectdb;

    $ids = array();

    $is_match = "false";

    require_once INC_ROOT . "/bin/projects/tools/prepareQuery.php";
    $add_vsys = prepareVsysQuerySearch($projectdb, $vsys, $source, "security_rules");

    if( (preg_match("/address/i", $table_name)) || (preg_match("/regions/i", $table_name)) || (preg_match("/list/i", $table_name)) )
    {

        if( $position == "source" )
        {

            $getSecurityByAddressSrc = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_src srs "
                . " WHERE sr.source = '$source' $add_vsys AND srs.member_lid = '$member_lid' AND srs.table_name = '$table_name' "
                . " AND srs.rule_lid = sr.id AND sr.id = '$rule_lid';");

            if( $getSecurityByAddressSrc->num_rows > 0 )
            {
                $is_match = "true";
            }
        }
        elseif( $position == "destination" )
        {

            $getSecurityByAddressDst = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_dst dst "
                . " WHERE sr.source = '$source' $add_vsys AND dst.member_lid = '$member_lid' AND dst.table_name = '$table_name' "
                . " AND dst.rule_lid = sr.id AND sr.id = '$rule_lid';");

            if( $getSecurityByAddressDst->num_rows > 0 )
            {
                $is_match = "true";
            }
        }

    }
    elseif( (preg_match("/services/i", $table_name)) )
    {

        $getSecurityByServices = $projectdb->query("SELECT sr.id AS id "
            . " FROM security_rules sr, security_rules_srv srv "
            . " WHERE sr.source = '$source' $add_vsys AND srv.member_lid = '$member_lid' AND srv.table_name = '$table_name' "
            . " AND srv.rule_lid = sr.id AND sr.id = '$rule_lid';");

        if( $getSecurityByServices->num_rows > 0 )
        {
            $is_match = "true";
        }
    }
    elseif( (preg_match("/applications/i", $table_name)) || ($table_name == "default_applications") )
    {


        if( $table_name != "default_applications" )
        {

            $getSecurityByApplications = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_app app "
                . " WHERE sr.source = '$source' $add_vsys AND app.member_lid = '$member_lid' AND app.table_name = '$table_name' "
                . " AND app.rule_lid = sr.id AND sr.id = '$rule_lid';");
        }
        elseif( $table_name == "default_applications" )
        {

            $getSecurityByApplications = $projectdb->query("SELECT sr.id AS id "
                . " FROM security_rules sr, security_rules_app app "
                . " WHERE sr.source = '$source' AND app.member_lid = '$member_lid' AND app.table_name = '$table_name' "
                . " AND app.rule_lid = sr.id AND sr.id = '$rule_lid';");
        }

        if( $getSecurityByApplications->num_rows > 0 )
        {
            $is_match = "true";
        }
    }

    return $is_match;
}


function getMaxLengthRuleName($source)
{

    $version = calcVersion($source);

    if( $version < 8.1 )
    {
        $max = 31;
    }
    elseif( $version >= 8.1 )
    {
        $max = 63;
    }
    else
    {
        $max = 63;
    }

    return $max;
}


function getIdsBySourceVsys($table_name, $source, $vsys)
{

    global $projectdb;

    require_once INC_ROOT . "/bin/projects/tools/prepareQuery.php";
    $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT id FROM $table_name WHERE source = '$source' $sql_vsys;";
    $result = $projectdb->query($query);

    $ids = array();
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $ids[] = $data['id'];
        }
    }

    return $ids;
}
