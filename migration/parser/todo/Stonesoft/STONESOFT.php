<?php

# Copyright (c) 2015 Palo Alto Networks, Inc.
# All rights reserved.
#HEADER
$debug = FALSE;

//Global Variables used for Policy Construction
$rule;            //List of policy rules
$sources;        //List of sources used in general
$destinations;    //List of destinations used in general
$services;        //List of services used in general
$addTag;        //List of tags used in general
$tagids;        //Set of tags used for a specific policy
$lid;            //ID of the last registered policy rule. Used for rule table relations
$position;        //Position of the last registered policy rule. Used to place the rules in order in the final policy

$vrid;

global $match_expressionsInMemory;
global $overrideSecurityZones;
$overrideSecurityZones = array();

global $overrideNatZones;
$overrideNatZones = array();

//Loads all global PHP definitions
//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once '/var/www/html/libs/common/definitions.php';

//User management control
//require_once INC_ROOT.'/userManager/start.php';
//include INC_ROOT.'/bin/authentication/sessionControl.php';

//Dependencies
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/shared.php';
require_once INC_ROOT . '/libs/xmlapi.php';

require_once INC_ROOT . '/libs/common/MemberObject.php';
require_once INC_ROOT . '/libs/common/lib-rules.php';
require_once INC_ROOT . '/libs/objects/SecurityRulePANObject.php';

use PaloaltoNetworks\Policy\Objects\MemberObject;

require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
global $app;
//Capture request paramenters
include INC_ROOT . '/bin/configurations/parsers/readVars.php';

if( isset($signatureid) )
    $signatureid = str_replace(';', ',', $signatureid);  //The IDs of policies to load came in ; separated, as readVars expected parameters separated by commas

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

    public function setZone($zone)
    {
        $this->zone = $zone;
    }

    public function addIPaddress($ipaddress)
    {
        $this->ipaddresses[] = $ipaddress;
    }

}

$action;
$project;

$lid;
$position;

//Capture request paramenters in case we get a call from the browser
if( isset($_SERVER['REQUEST_METHOD']) )
{
    switch ($_SERVER['REQUEST_METHOD'])
    {
        case 'GET':
            $action = (string)(isset($_GET['action']) ? $_GET['action'] : '');
            $type = (string)(isset($_GET['type']) ? $_GET['type'] : ''); // zip / xml / device
            $project = (string)(isset($_GET['project']) ? $_GET['project'] : '');
            $signatureid = (string)(isset($_GET['signatureid']) ? $_GET['signatureid'] : '');
            break;
        case 'POST':
            $action = (string)(isset($_POST['action']) ? $_POST['action'] : '');
            $type = (string)(isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
            $project = (string)(isset($_POST['project']) ? $_POST['project'] : '');
            $signatureid = (string)(isset($_POST['signatureid']) ? $_POST['signatureid'] : '');
            break;

        default:
            $action = (string)(isset($_POST['action']) ? $_POST['action'] : '');
            $type = (string)(isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
            $project = (string)(isset($_POST['project']) ? $_POST['project'] : '');
            $signatureid = (string)(isset($_POST['signatureid']) ? $_POST['signatureid'] : '');
            break;
    }
}

require_once INC_ROOT . '/libs/projectdb.php';

//list($project, $vendor, $action, $signatureid, $username, $password, $afa_hostname, $jobid, $checkpointName) = loadVars( $argv[1]);
global $projectdb;
$projectdb = selectDatabase($project);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

function time_elapsed_A($secs)
{
    $bit = array(
        'y' => $secs / 31556926 % 12,
        'w' => $secs / 604800 % 52,
        'd' => $secs / 86400 % 7,
        'h' => $secs / 3600 % 24,
        'm' => $secs / 60 % 60,
        's' => $secs % 60
    );

    foreach( $bit as $k => $v )
        if( $v > 0 ) $ret[] = $v . $k;

    return join(' ', $ret);
}

function GroupMember2IDStonesoft(STRING $type, $source, &$objectsInMemory)
{
    global $projectdb;
//    $myArray=array();
    $member_name_array = array();
    $addMap = array();
    switch ($type)
    {
        case "address":
            #Group Address Groups with Members
            $getV = $projectdb->query("SELECT vsys FROM address_groups_id WHERE source='$source' AND type='static' GROUP BY vsys");
            if( $getV->num_rows > 0 )
            {
                $addMap = array();
                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
                if( $getMaxID->num_rows == 1 )
                {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                while( $getVData = $getV->fetch_assoc() )
                {
                    $vsysO = $getVData['vsys'];
                    $getG = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsysO' AND type='static';");
                    if( $getG->num_rows > 0 )
                    {
                        $lids = array();
                        while( $getGData = $getG->fetch_assoc() )
                        {
                            $lids[] = $getGData['id'];
                        }
                        $vsyses = getVsyses($projectdb, $vsysO, $source);
                        $getA = $projectdb->query("SELECT * from address_groups WHERE lid IN (" . implode(",", $lids) . ");");
                        if( $getA->num_rows > 0 )
                        {
                            $myArray = array();
                            while( $getAData = $getA->fetch_assoc() )
                            {
                                $memberName = $getAData['member'];
                                $lid = $getAData['lid'];
                                $myArray[$memberName][] = $lid;
                                $member_name_array[] = $memberName;
                            }

                            $member_name_array = array_unique($member_name_array);

                            while( count($vsyses) > 0 && count($member_name_array) > 0 )
                            { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                                if( count($member_name_array) > 0 )
                                {
                                    $address_array = array();
                                    foreach( $member_name_array as $nameToCheck )
                                    {
                                        if( isset($objectsInMemory['address'][$vsys][$nameToCheck]) )
                                        {
                                            $address_array[] = $nameToCheck;
                                            foreach( $myArray[$nameToCheck] as $glid )
                                            {
                                                $addMap[] = "('$glid','" . $objectsInMemory['address'][$vsys][$nameToCheck]['id'] . "','address')";
                                            }
                                        }
                                        elseif( isset($objectsInMemory['address_groups_id'][$vsys][$nameToCheck]) )
                                        {
                                            $address_array[] = $nameToCheck;
                                            foreach( $myArray[$nameToCheck] as $glid )
                                            {
                                                $addMap[] = "('$glid','" . $objectsInMemory['address_groups_id'][$vsys][$nameToCheck]['id'] . "','address_groups_id')";
                                            }
                                        }
                                    }
                                    $member_name_array = array_diff($member_name_array, $address_array);
                                }
                            }
                            if( count($member_name_array) == 0 )
                            {
                                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lids) . ");");
                                $member_name_array = array();
                            }
                            else
                            {

                                # Check by name_ext


                                print "ERROR SOME ADDRESS OBJECTS HAS NOT BEEN CAPTURED" . PHP_EOL;
                                print_r($member_name_array);
                                # Objects doesnt exist and need to be added
                                $addHost = array();
                                foreach( $member_name_array as $key => $member_name )
                                {
                                    if( $member_name != "" )
                                    {
                                        $member_name = (string)$member_name;
                                        $ip_version0 = ip_version($member_name);
                                        if( ($ip_version0 != "noip") or (preg_match("/\//", $member_name)) )
                                        {
                                            $memberANetwork = explode("/", $member_name);
                                            $ip_version = ip_version($memberANetwork[0]);
                                            if( !isset($memberANetwork[1]) )
                                            {
                                                if( $ip_version == "v4" )
                                                {
                                                    $memberAmask = "32";
                                                }
                                                else
                                                {
                                                    $memberAmask = "128";
                                                }
                                            }
                                            else
                                            {
                                                $memberAmask = $memberANetwork[1];
                                            }
                                            if( $ip_version == "v4" )
                                            {
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$vsysO',1,'MT_Panorama','$memberANetwork[0]','$memberAmask',1,0)";
                                            }
                                            elseif( $ip_version == "v6" )
                                            {
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$vsysO',1,'MT_Panorama','$memberANetwork[0]','$memberAmask',0,1)";
                                            }
                                            foreach( $myArray[$member_name] as $glid )
                                            {
                                                $addMap[] = "('$glid','$max','address')";
                                            }
                                            $objectsInMemory['address'][$vsysO][$member_name]['id'] = $max;
                                            $objectsInMemory['address'][$vsysO][$member_name]['ipaddress'] = $memberANetwork[0];
                                            $objectsInMemory['address'][$vsysO][$member_name]['cidr'] = $memberAmask;
                                            $max++;
                                        }
                                        else
                                        {
                                            $split = explode("-", $member_name);
                                            if( (ip_version($split[0]) != "noip") and (ip_version($split[1]) != "noip") )
                                            {
                                                $ip_version = ip_version($split[0]);
                                                if( $ip_version == "v4" )
                                                {
                                                    $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$vsysO',1,'MT_Panorama','$member_name','',1,0)";
                                                }
                                                elseif( $ip_version == "v6" )
                                                {
                                                    $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$vsysO',1,'MT_Panorama','$member_name','',0,1)";
                                                }
                                                foreach( $myArray[$member_name] as $glid )
                                                {
                                                    $addMap[] = "('$glid','$max','address')";
                                                }
                                                $objectsInMemory['address'][$vsysO][$member_name]['id'] = $max;
                                                $max++;
                                            }
                                            else
                                            {
                                                //                                          $ip_version = "v4";
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','dummy','$vsysO',1,'MT_Panorama','','',1,0)";
                                                foreach( $myArray[$member_name] as $glid )
                                                {
                                                    $addMap[] = "('$glid','$max','address')";
                                                }
                                                $objectsInMemory['address'][$vsysO][$member_name]['id'] = $max;
                                                $objectsInMemory['address'][$vsysO][$member_name]['ipaddress'] = '';
                                                $objectsInMemory['address'][$vsysO][$member_name]['cidr'] = '';
                                                $max++;
                                            }
                                        }
                                    }
                                }
                                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lids) . ");");
                                if( count($addHost) > 0 )
                                {
                                    $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup,ipaddress,cidr,v4,v6) VALUES " . implode(",", $addHost) . ";");
                                    unset($addHost);
                                }
                                $member_name_array = array();

                            }
                        }

                    }
                }
            }

            # Let's do inserts by vsys/dg
            if( count($addMap) > 0 )
            {
                $unique = array_unique($addMap);
                $projectdb->query("INSERT INTO address_groups (lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                unset($addMap);
            }

            break;
        case "service":
            #Group Services Groups with Members
            $getV = $projectdb->query("SELECT vsys FROM services_groups_id WHERE source='$source' GROUP BY vsys");
            if( $getV->num_rows > 0 )
            {
                $addMap = array();

                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
                if( $getMaxID->num_rows == 1 )
                {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }

                while( $getVData = $getV->fetch_assoc() )
                {
                    $vsysO = $getVData['vsys'];
                    $getG = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsysO';");
                    if( $getG->num_rows > 0 )
                    {
                        $lids = array();
                        while( $getGData = $getG->fetch_assoc() )
                        {
                            $lids[] = $getGData['id'];
                        }
                        $vsyses = getVsyses($projectdb, $vsysO, $source);
                        $getA = $projectdb->query("SELECT * from services_groups WHERE lid IN (" . implode(",", $lids) . ");");
                        if( $getA->num_rows > 0 )
                        {
                            $myArray = array();
                            while( $getAData = $getA->fetch_assoc() )
                            {
                                $memberName = $getAData['member'];
                                $lid = $getAData['lid'];
                                $myArray[$memberName][] = $lid;
                                $member_name_array[] = $memberName;
                            }

                            $member_name_array = array_unique($member_name_array);

                            while( count($vsyses) > 0 && count($member_name_array) > 0 )
                            { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                                if( count($member_name_array) > 0 )
                                {
                                    $address_array = array();
                                    foreach( $member_name_array as $nameToCheck )
                                    {
                                        if( isset($objectsInMemory['services'][$vsys][$nameToCheck]) )
                                        {
                                            $address_array[] = $nameToCheck;
                                            foreach( $myArray[$nameToCheck] as $glid )
                                            {
                                                $addMap[] = "('$glid','" . $objectsInMemory['services'][$vsys][$nameToCheck]['id'] . "','services')";
                                            }
                                        }
                                        elseif( isset($objectsInMemory['services_groups_id'][$vsys][$nameToCheck]) )
                                        {
                                            $address_array[] = $nameToCheck;
                                            foreach( $myArray[$nameToCheck] as $glid )
                                            {
                                                $addMap[] = "('$glid','" . $objectsInMemory['services_groups_id'][$vsys][$nameToCheck]['id'] . "','services_groups_id')";
                                            }
                                        }
                                    }
                                    $member_name_array = array_diff($member_name_array, $address_array);
                                }
                            }
                            if( count($member_name_array) == 0 )
                            {
                                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lids) . ");");
                                $member_name_array = array();
                            }
                            else
                            {
                                print "ERROR SOME SERVICES OBJECTS HAS NOT BEEN CAPTURED" . PHP_EOL;
                                print_r($member_name_array);
                                # Objects doesnt exist and need to be added
                                $addHost = array();
                                foreach( $member_name_array as $key => $member_name )
                                {
                                    $member_name = (string)$member_name;
                                    if( $member_name != '' )
                                    {
                                        $addHost[] = "('$max','$source','$vsysO',1,'$member_name','$member_name','dummy', 'dummy', '')";

                                        foreach( $myArray[$member_name] as $glid )
                                        {
                                            $addMap[] = "('$glid','$max','services')";
                                        }
                                        $objectsInMemory['services'][$vsysO][$member_name]['id'] = $max;
                                        $objectsInMemory['services'][$vsysO][$member_name]['dport'] = "65000";
                                        $max++;
                                    }

                                }

                                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lids) . ");");
                                if( count($addHost) > 0 )
                                {
                                    $projectdb->query("INSERT INTO services (id,source,vsys,dummy,name_ext,name,vtype, devicegroup, protocol) VALUES " . implode(",", $addHost) . ";");
                                    unset($addHost);
                                }
                                $member_name_array = array();

                            }
                        }

                    }
                }
            }

            # Let's do inserts by vsys/dg
            if( count($addMap) > 0 )
            {
                $unique = array_unique($addMap);
                $projectdb->query("INSERT INTO services_groups (lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                unset($addMap);
            }

            break;
    }
}

function load_objects_byname(&$objectsInMemory, $data, $new_vsys = null)
{
    $projectdb = $data['projectdb'];
    $source = $data['source'];

    if( $new_vsys == null )
    {
        $andVSYS = "";
    }
    else
    {
        $andVSYS = " AND vsys='$new_vsys' ";
    }

    $loadApps = $projectdb->query("SELECT id,name,vsys,ipaddress,cidr,name_ext FROM address WHERE source='$source' $andVSYS;");
    if( $loadApps->num_rows > 0 )
    {
        while( $data = $loadApps->fetch_assoc() )
        {
            $lid = $data['id'];
            $vsys = $data['vsys'];
            $ipaddress = $data['ipaddress'];
            $cidr = $data['cidr'];
            $name_ext = $data['name_ext'];
            $objectsInMemory['address'][$vsys][$name_ext]['id'] = $lid;
            $objectsInMemory['address'][$vsys][$name_ext]['ipaddress'] = $ipaddress;
            $objectsInMemory['address'][$vsys][$name_ext]['cidr'] = $cidr;
        }
    }

    $loadApps = $projectdb->query("SELECT id,name,vsys,name_ext FROM address_groups_id WHERE source='$source' $andVSYS;");
    if( $loadApps->num_rows > 0 )
    {
        while( $data = $loadApps->fetch_assoc() )
        {
            $lid = $data['id'];
            $vsys = $data['vsys'];
            $name_ext = $data['name_ext'];
            $objectsInMemory['address_groups_id'][$vsys][$name_ext]['id'] = $lid;
        }
    }


    $loadApps = $projectdb->query("SELECT id,name,vsys,dport,name_ext FROM services WHERE source='$source' $andVSYS;");
    if( $loadApps->num_rows > 0 )
    {
        while( $data = $loadApps->fetch_assoc() )
        {
            $lid = $data['id'];
            $vsys = $data['vsys'];
            $dport = $data['dport'];
            $name_ext = $data['name_ext'];
            $objectsInMemory['services'][$vsys][$name_ext]['id'] = $lid;
            $objectsInMemory['services'][$vsys][$name_ext]['dport'] = $dport;
        }
    }

    $loadApps = $projectdb->query("SELECT id,name,vsys,name_ext FROM services_groups_id WHERE source='$source' $andVSYS;");
    if( $loadApps->num_rows > 0 )
    {
        while( $data = $loadApps->fetch_assoc() )
        {
            $lid = $data['id'];
            $vsys = $data['vsys'];
            $name_ext = $data['name_ext'];
            $objectsInMemory['services_groups_id'][$vsys][$name_ext]['id'] = $lid;
        }
    }

}


$sourcesAdded = array();
global $source;

if( $action == "import" )
{

    //$startTime = time();
    //echo $startTime;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);
    $path = USERSPACE_PATH . "/projects/" . $project . "/";

    $i = 0;
    $dirrule = opendir($path);


    //Update the relationship between Firewalls and Policies
    $ids_to_load = array();
    $policies = explode(',', $signatureid);
    foreach( $policies as $policy )
    {
        $tuple = explode('XPDT', $policy);
        $policyName = $tuple[1];
        $id = $tuple[0];
        $ids_to_load[] = $id;
        $query = "UPDATE policies_to_import SET policyname=\"$policyName\" WHERE id=$id ;";
        $projectdb->query($query);
    }

    $ids_to_load = implode(',', $ids_to_load);

    update_progress($project, '0.00', 'Reading config files', $jobid);

    while( $config_filename = readdir($dirrule) )
    {
        $query = "SELECT id FROM device_mapping WHERE device = '$config_filename';";
        $knownPolicies = $projectdb->query($query);
        if( $knownPolicies->num_rows == 0 )
        {
            if( checkFiles2Import($config_filename) )
            {
                $config_path = $path . $config_filename;
                $filename = $config_filename;

                //Check the existence of known policies to load
                // For that, we need to read the values that signatureid got. These are the IDs of the entries in the table policies_to_import.

                $query = "SELECT id FROM policies_to_import WHERE id in ($ids_to_load);";
                $knownPolicies = $projectdb->query($query);

                if( $knownPolicies->num_rows == 0 )
                {
                    get_FwNames($config_path, $config_filename);  //Update policies_to_import defining existing policies in the configuration
                }
                else
                {
                    //Check which policies have been selected for importing, and have not been imported yet.
                    $isimported = $projectdb->query("SELECT id, filename, policyname, firewall FROM policies_to_import " .
                        "WHERE ID in ($ids_to_load) AND (processed IS NULL OR processed='');");
                    $numberOfPoliciesToProcess = $isimported->num_rows;
                    $accumulatedProcess = 0.2;
                    $internalSteps = 3;
                    $stepSize = (0.9 - 0.2) / ($internalSteps * $numberOfPoliciesToProcess);
                    while( $policy = $isimported->fetch_assoc() )
                    {
                        $policy_to_load = $policy['policyname'];
                        $firewall = $policy['firewall'];
                        update_progress($project, $accumulatedProcess, 'File:' . $filename . '(' . $policy_to_load . ') Phase 2 Loading address objects', $jobid);
                        $accumulatedProcess += $stepSize;
                        import_config_FirstPart($config_path, $project, $config_filename, $policy_to_load, $firewall, $source, $vsys);
                        $sourcesAdded[] = $source;

                        # LOAD ALL OBJECTS TO INMEMORY
                        $objectsInMemory = array();
                        $data = array("projectdb" => $projectdb, "source" => $source);
                        load_objects_byname($objectsInMemory, $data);

                        //I need this information complete before procesing the rules :(
                        $policy_case = "$config_filename--$policy_to_load";
                        update_progress($project, $accumulatedProcess, 'File:' . $filename . '(' . $policy_to_load . ') Phase 3 Referencing Groups', $jobid);
                        $accumulatedProcess += $stepSize;
                        #GroupMember2IdAddress_improved($policy_case);


                        import_config_SecondPart($config_path, $source, $vsys);

                        GroupMember2IDStonesoft("address", $source, $objectsInMemory);
                        GroupMember2IDStonesoft("service", $source, $objectsInMemory);

                        #GroupMember2IdAddress_improved($policy_case);
                        #GroupMember2IdServices($policy_case);

                        //Importing the policies and subpolicies
                        update_progress($project, $accumulatedProcess, 'File:' . $filename . '(' . $policy_to_load . ') Phase 4 Reading Root and Nested policies', $jobid);
                        $accumulatedProcess += $stepSize;
                        import_config_ThirdPart($config_path, $project, $config_filename, $policy_to_load, $source, $vsys, $objectsInMemory);

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

                        //Update processed as completed
                        $projectdb->query("UPDATE policies_to_import SET processed=SYSDATE() WHERE filename=\"$config_filename\" AND policyname=\"$policy_to_load\";");
                        //$projectdb->query("DELETE FROM policies_to_import WHERE processed IS NULL;");
                    }
                    unlink($config_path);
                    $projectdb->query("DELETE FROM policies_to_import WHERE processed IS NULL;");
                }
            }
        }
    }

    #Check used
    update_progress($project, '0.90', 'Project:' . $project . ' Calculating Used Objects', $jobid);
    check_used_objects_new($sourcesAdded);
    update_progress($project, '1.00', 'Done.', $jobid);

    //$finishTime = time();
    //echo $finishTime;
    //echo "time_elapsed_A: ".time_elapsed_A($finishTime-$startTime)."\n";

    //sleep(4);
    //update_progress($project, '0', 'Ready');
}
elseif( $action == "get" )
{
    //global $DBUser;
    //global $DBPass;

    ini_set('max_execution_time', 10000);
    ini_set("memory_limit", "1000M");
    $path = USERSPACE_PATH . "/projects/" . $project . "/";

    $i = 0;
    $dirrule = opendir($path);

    $fwNames = array();
    if( $type == "existing_firewalls" )
    {
        while( $config_filename = readdir($dirrule) )
        {
            $fileFullPath = $path . $config_filename;
            //Check that the file is not a ZIP/Rar
            $gestor = @fopen($fileFullPath, "r");
            $blob = fgets($gestor, 5);
            fclose($gestor);
            if( strpos($blob, 'Rar') !== FALSE )
            {
                continue;
            }
            elseif( strpos($blob, 'PK') !== FALSE )
            {
                continue;
            }

            if( checkFiles2Import($config_filename) )
            {
                $config_path = $path . $config_filename;
                $filename = $config_filename;
                get_FwNames($config_path, $config_filename);  //Update policies_to_import defining existing policies in the configuration
                //get_DomainNames($config_path, $config_filename);  //Update the domain_names that are used in the policy
                $fwNames = get_PolicyNames($config_path, $config_filename);
            }
        }

        $getLimit = $projectdb->query("SELECT * FROM policies_to_import ORDER BY filename,policyname ASC;");
        if( $getLimit )
        {
            $count = $getLimit->num_rows;
            while( $data = $getLimit->fetch_object() )
            {
                $myData[] = $data;
            }
            if( !isset ($count) || is_null($count) || $count == 0 )
            {
                $count = 0;
                $myData = "";
            }
        }
        else
        {
            $count = 0;
            $myData = "";
        }

        $response = [
            'total' => $count,
            'fwNames' => $myData,
        ];
        echo json_encode($response);
    }
    elseif( $type == "existing_policies" )
    {
        $firewallID = $_GET['id'];

        $query = "SELECT filename FROM policies_to_import WHERE id=$firewallID";
        $result = $projectdb->query($query);
        if( $result->num_rows > 0 )
        {
            $data = $result->fetch_assoc();
            $selectedFile = $data['filename'];
        }
        while( $config_filename = readdir($dirrule) )
        {
            if( $config_filename == $selectedFile )
            {
                $fileFullPath = $path . $config_filename;
                //Check that the file is not a ZIP/Rar
                $gestor = @fopen($fileFullPath, "r");
                $blob = fgets($gestor, 5);
                fclose($gestor);
                if( strpos($blob, 'Rar') !== FALSE )
                {
                    continue;
                }
                elseif( strpos($blob, 'PK') !== FALSE )
                {
                    continue;
                }

                if( checkFiles2Import($config_filename) )
                {
                    $config_path = $path . $config_filename;
                    $filename = $config_filename;

                    $fwNames = array_merge($fwNames, get_PolicyNames($config_path, $config_filename));
                }
            }
        }
        $response = [
            'total' => count($fwNames),
            'policies' => $fwNames
        ];
        echo json_encode($response);
    }
    elseif( $type == "existing_domain_names" )
    {

        $getLimit = $projectdb->query("SELECT * FROM domain_names ORDER BY name ASC;");
        $count = $getLimit->num_rows;
        while( $data = $getLimit->fetch_object() )
        {
            $myData[] = $data;
        }
        if( $count == 0 )
        {
            $myData = "";
        }
        echo '{"total":"' . $count . '","domainNames":' . json_encode($myData) . '}';
    }
}

/**
 * THis method will load the objects necessary for this policy, and will set up the parameters to identify the policy $source and $vsys
 * @param string $config_path
 * @param unknown $project
 * @oaram mysqlConnection $config_filename
 * @param string $vsys
 * @param int $source
 *
 */
function import_config_FirstPart($config_path, STRING $project, $config_filename, $policy_to_load, $firewall, &$source, &$vsys)
{
    global $projectdb;
    global $match_expressionsInMemory;
    $filename = $config_filename;

    if( isXML($config_path) === TRUE )
    {
        $devicegroup = $config_filename;
        $xml = simplexml_load_file($config_path);
        $version = $xml->version;
        $configFilenamePolicy = addslashes($config_filename . "--" . $policy_to_load);
        #Add new $source and the default $vsys value.
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) " .
            "VALUES ('$devicegroup','$version',0,1,'$project','$configFilenamePolicy','vsys1','Stonesoft')");
        $source = $projectdb->insert_id;
        $vsys = "vsys1";
        add_default_services($source);
        add_default_profiles($source, $version);
        add_stonesoft_services($source, $vsys);  //Native defined services at the platform
        update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Loading Objects');

        #Config Template
        $template_name = "default_template" . $source;
        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) " .
            "VALUES ('$project','$template_name','$configFilenamePolicy','$source');");
        $template = $projectdb->insert_id;

        //Get the cluster name for the current policy to load
        $query = "SELECT firewall FROM policies_to_import WHERE policyname=\"$policy_to_load\" LIMIT 1 ";
        $results = $projectdb->query($query);
        if( $results->num_rows > 0 )
        {
            while( $data = $results->fetch_assoc() )
            {
                $nameCluster = $data['firewall'];
                get_Interfaces($xml, $nameCluster, $vsys, $source, $template);
            }
        }
        else
        {
            echo "QUERY FAILED: " . $query . PHP_EOL;
        }

//         get_XML_Zones_Address($xml, $vsys, $source, $template);
        get_Address_Stonesoft($xml, $vsys, $source, $template);
        get_Address_Group($xml, $vsys, $source, $policy_to_load, $firewall, $template);

        $query = "SELECT firewall FROM policies_to_import WHERE policyname=\"$policy_to_load\" LIMIT 1 ";
        $results = $projectdb->query($query);
        if( $results->num_rows > 0 )
        {
            while( $data = $results->fetch_assoc() )
            {
                $nameCluster = $data['firewall'];
                get_Static_Routes($xml, $nameCluster, $source, $vsys, $template);
            }
        }
        else
        {
            echo "QUERY FAILED: " . $query . PHP_EOL;
        }

//         get_XML_Zones_Address_Global($xml, $vsys, $source, $template);
//         get_VR_static_routes($xml, $vsys, $source, $template);
//         get_XML_Applications($xml, $vsys, $source);
        get_Services($xml, $vsys, $source);
        get_ServicesGroups($xml, $vsys, $source);
        get_AddressExpressions($xml, $vsys, $source, $template);
    }
    else
    {
        if( $source == "" )
        {
            $source = 1;
        }
        add_log('error', 'Start Parsing Files', 'Failed the file uploaded is not a Valid XML', $source, 'Review the format.');
        update_progress($project, '-1.00', 'XML is invalid.');
    }
}

function import_config_SecondPart(STRING $config_path, STRING $source, STRING $vsys)
{
    if( isXML($config_path) === TRUE )
    {
        $xml = simplexml_load_file($config_path);
        get_Exclusions($xml, $vsys, $source);
    }
}

function import_config_ThirdPart(STRING $config_path, STRING $project, STRING $config_filename, STRING $policy_to_load, STRING $source, STRING $vsys, array &$objectsInMemory)
{
    if( isXML($config_path) === TRUE )
    {
        $xml = simplexml_load_file($config_path);
        get_Policy($xml, $policy_to_load, $vsys, $source, $project, $objectsInMemory);
        get_NATs($xml, $policy_to_load, $vsys, $source, $project, $objectsInMemory);
//        get_VPN($xml, $vsys, $source, $project);

        // Call function to generate initial consumptions
        $template_name = "default_template" . $source;
        deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);
    }
}

/**
 * This method looks for interfaces defined for the firewall that is going to be processed.
 *  A firewall could be defined as a single node or as a cluster. It seems that the firewaal/cluster
 *  shares the name of the policy that contains.
 *
 * @param SimpleXMLElement $configuration
 * @param STRING $firewallName
 * @param STRING $vsys
 * @param STRING $source
 * @param STRING $template
 */
function get_Interfaces(SimpleXMLElement $configuration, STRING $firewallName, STRING $vsys, STRING $source, STRING $template)
{
    global $projectdb;

    $ipInterfaces = array();
    $add_interface = array();
    $zones = array();

    $vr = "vr_" . $vsys;
    $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr';");
    if( $isDup->num_rows == 0 )
    {
        $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
        $vrid = $projectdb->insert_id;
    }
    else
    {
        $get = $isDup->fetch_assoc();
        $vrid = $get['id'];
    }

    //Cluster Firewalls adn Single Firewalls
    $fw_single = $configuration->xpath("//fw_single");
    $fw_clusters = $configuration->xpath("//fw_cluster");
    $fw_cluster_and_single = array_merge($fw_single, $fw_clusters);
    foreach( $fw_cluster_and_single as $fw_cluster )
    {
        $clusterName = $fw_cluster['name'];
        if( strcasecmp($clusterName, $firewallName) == 0 )
        {
            $ipInterfaces = array();
            foreach( $fw_cluster->physical_interface as $physical_interface )
            {
                $comment = (isset($physical_interface['comment'])) ? $physical_interface['comment'] : '';
                $interface_id = $physical_interface['interface_id'] + 1;
                $interfaceName = "ethernet1/$interface_id";
                $unitName = $interfaceName;

                $interface = new FwInterface("ethernet", $interfaceName, "layer3", $comment, $unitName, "", "");
                if( isset($physical_interface['zone_ref']) )
                {
                    $zone = $physical_interface['zone_ref'];
                    $interface->setZone($zone);
                }
                $ipInterfaces["$interface_id"] = $interface;
            }

            foreach( $fw_cluster->cluster_virtual_interface as $cluster_virtual_interface )
            {
                $nicid = $cluster_virtual_interface['nicid'];
                $nicid2 = explode(".", $nicid);
                $interface_id = $nicid2[0] + 1;

                $network_value = $cluster_virtual_interface['network_value'];
                $network_value_cidr = explode("/", $network_value);

                if( isset($nicid2[1]) )
                {
                    //This is a VLAN
                    $vlan_tag = $nicid2[1];
                    $interface_id = $nicid2[0] + 1;
                    $unitName = "ethernet1/$interface_id";
                    $VunitName = "$unitName.$vlan_tag";
                    $new_interface = clone $ipInterfaces["$interface_id"];

                    $new_interface->interfaceName = $unitName;
                    $new_interface->unitName = $VunitName;
                    $new_interface->vlan_tag = $vlan_tag;

                    foreach( $cluster_virtual_interface->mvia_address as $mvia_address )
                    {
                        $new_interface->addIPaddress($mvia_address['address'] . "/" . $network_value_cidr[1]);
                    }
                    $ipInterfaces["$VunitName"] = $new_interface;
                }
                else
                {
                    $tmp_interface = $ipInterfaces["$interface_id"];
                    if( !is_null($tmp_interface) )
                    {
                        foreach( $cluster_virtual_interface->mvia_address as $mvia_address )
                        {
                            $tmp_interface->addIPaddress($mvia_address['address'] . "/" . $network_value_cidr[1]);
                        }
                        $ipInterfaces["$interface_id"] = $tmp_interface;
                    }
                }
            }

            foreach( $fw_cluster->firewall_node as $firewall_node )
            {
                if( strcmp($firewall_node['disabled'], 'false') == 0 )
                {
                    foreach( $firewall_node->node_interface as $node_interface )
                    {
                        $nicid = $node_interface['nicid'];
                        $nicid2 = explode(".", $nicid);
                        $interface_id = $nicid2[0] + 1;

                        $network_value = explode("/", $node_interface['network_value']);
                        $cidr = $network_value[1];

                        if( isset($nicid2[1]) )
                        {
                            //This is a VLAN
                            $vlan_tag = $nicid2[1];
                            $interface_id = $nicid2[0] + 1;
                            $unitName = "ethernet1/$interface_id";
                            $VunitName = "$unitName.$vlan_tag";

//                            echo print_r($nicid, true);
//                            echo "$VunitName\n";
//                            echo print_r($ipInterfaces, true);

                            if( isset($ipInterfaces["$VunitName"]) )
                            {
                                $tmp_interface = $ipInterfaces["$VunitName"];
                            }
                            else
                            {
                                echo "$VunitName was not defined\n";
                                echo print_r($node_interface, TRUE);
                                $tmp_interface = clone $ipInterfaces["$interface_id"];

                                $tmp_interface->interfaceName = $unitName;
                                $tmp_interface->unitName = $VunitName;
                                $tmp_interface->vlan_tag = $vlan_tag;
                                $tmp_interface->warning = 'Interface [' . $VunitName . '] was not defined in the cluster';
                                $ipInterfaces["$VunitName"] = $tmp_interface;

                            }

                            foreach( $node_interface->mvia_address as $mvia_address )
                            {
                                $tmp_interface->addIPaddress($mvia_address['address'] . "/" . $cidr);
                            }
                            $ipInterfaces["$VunitName"] = $tmp_interface;
                        }
                        else
                        {
                            $tmp_interface = $ipInterfaces["$interface_id"];
                            foreach( $node_interface->mvia_address as $mvia_address )
                            {
                                $tmp_interface->addIPaddress($mvia_address['address'] . "/" . $cidr);
                            }
                            $ipInterfaces["$interface_id"] = $tmp_interface;
                        }
                    }
                }
            }


            $zoneNumber = 1;
            $query = "SELECT max(id) as t FROM interfaces";
            $result = $projectdb->query($query);
            if( $result->num_rows > 0 )
            {
                $data = $result->fetch_assoc();
                $interfaceID = $data['t'] + 1;
            }
            else
            {
                $interfaceID = 1;
            }

            foreach( $ipInterfaces as $interfaceName => $ipInterface )
            {
                if( is_null($ipInterface->zone) )
                {
                    $ipInterface->setZone("Zone$zoneNumber");
                }
                $ipaddresses = array_unique($ipInterface->ipaddresses);
                $all_ipaddress = implode(",", $ipaddresses);
                //(media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys, zone)
                $add_interface[] = "($interfaceID,'$vrid','$ipInterface->media','$source','$ipInterface->interfaceName','$ipInterface->interfaceType',"
                    . "'$ipInterface->comment','$ipInterface->unitName','$ipInterface->vlan_tag','$all_ipaddress','$template','$vsys','$ipInterface->zone')";
                if( isset($ipInterface->warning) )
                {
                    add_log2("warning", 'Reading Device Interfaces', $ipInterface->warning, $source, 'Review', 'interfaces', $interfaceID, 'interfaces');
                }
                $interfaceID++;

                //Add zones with Interface name
                //(source,name,vsys,type,interfaces,template)
                $zones[] = "('$source','$ipInterface->zone','$vsys','$ipInterface->interfaceType','$ipInterface->unitName','$template')";
                $zoneNumber++;

            }

        }
    }

    if( count($add_interface) > 0 )
    {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO interfaces (id, vr_id, media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys, zone) VALUES " . $out . ";");
    }

    if( count($zones) > 0 )
    {
        $out = implode(",", $zones);
        $projectdb->query("INSERT INTO zones (source,name,vsys,type,interfaces,template) VALUES " . $out . ";");
    }

}

/***
 * @param SimpleXMLElement $configuration
 * @param STRING $policyName
 * @param STRING $source
 * @param STRING $vsys
 * @param STRING $template
 */
function get_static_routes(SimpleXMLElement $configuration, STRING $policyName, STRING $source, STRING $vsys, STRING $template)
{
    global $projectdb;
    global $vrid;


    $addRoutes = array();
    $used_interfaces = array();

    $routing_nodes = $configuration->xpath("//routing_node");
    foreach( $routing_nodes as $routing_node )
    {
        if( strcasecmp($policyName, $routing_node['name']) == 0 )
        {

            $addRoutes = array();
            $vr = "vr_" . $vsys;
            $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr' AND source='$source' AND vsys='$vsys';");
            if( $isDup->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
                $vrid = $projectdb->insert_id;
            }
            else
            {
                $get = $isDup->fetch_assoc();
                $vrid = $get['id'];
            }

            $x = 1;
            $count = "";

            $used_interfaces = array();

            //Loading the routes defined for each interface
            foreach( $routing_node->interface_rn_level as $interface_rn_level )
            {
                $interfaceI = explode(".", $interface_rn_level['nicid']);
                $interfaceNumber = $interfaceI[0] + 1;
                $interfaceID = "ethernet1/$interfaceNumber";

                if( isset($interfaceI[1]) )
                {
                    $interfaceID = "$interfaceID.$interfaceI[1]";
                }
                $used_interfaces[$vrid][] = $interfaceID;


                foreach( $interface_rn_level->network_rn_level as $network_rn_level )
                {
//                    $network_source = $network_rn_level['ne_ref'];
                    foreach( $network_rn_level->gateway_rn_level as $gateway_rn_level )
                    {
                        $ip_gateway = $gateway_rn_level['ipaddress'];
                        foreach( $gateway_rn_level->any_rn_level as $any_rn_level )
                        {
                            $destination = $any_rn_level['ne_ref'];
                            if( strcasecmp($destination, "Any network") == 0 )
                            {
                                $member = new MemberObject();
                                $member->value = "0.0.0.0";
                                $member->cidr = "0";
                                $found = 1;
                            }
                            else
                            {
                                $member = new MemberObject();
                                $found = searchAddressIPandCIDR($destination, $vsys, $source, $member, $objectsInMemory);
                            }

                            if( $found )
                            {
//                                $routename = "";
                                $metric = "10";

                                //Default routes
                                if( ($member->value == "0.0.0.0") and ($member->cidr == "0") )
                                {
                                    $routename = "default " . $count;
                                    $count++;
                                    $route_network = "0.0.0.0/0";
                                }
                                //Specific routes
                                else
                                {
                                    $routename = "Route " . $x;
                                    $x++;
                                    $route_network = "$member->value/$member->cidr";
                                }
                                $ip_version = ip_version($member->value);

                                //Create a static_route
                                $zoneName = '';
                                $route_text = "('$zoneName','$source','$vrid','$template','$ip_version','$routename','$route_network','$interfaceID','ip-address','$ip_gateway','$metric','$vsys' )";
                                //$used_interfaces[$vrid][]=$interfaceID;
                                $addRoutes[] = $route_text;
                            }
                        }
                    }
                }
            }
        }
    }

    //Insert all the static routes we have found so far
    if( count($addRoutes) > 0 )
    {
        $unique = array_unique($addRoutes);
        $query = "INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) "
            . "VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
        unset($addRoutes);
    }

    if( count($used_interfaces) )
    {
        foreach( $used_interfaces as $key => $interfaces )
        {
            $unique = array_unique($interfaces);
            $query = "UPDATE virtual_routers SET interfaces = CONCAT('" . implode(",", $unique) . "',interfaces) WHERE id='$key';";
            $projectdb->query($query);
        }
        unset($used_interfaces);
    }


}

/**
 * Method to identify the existing policies in the configuration file that are candidates to be imported
 * @param String $config_filename Name of the configuration file that we will process to look for policies
 */
function get_FwNames(STRING $config_path, STRING $config_filename)
{
    global $projectdb;

    $filename = $config_filename;

    if( isXML($config_path) === TRUE )
    {
        //Create the table policies_to_import if it doesn't exist
        $res = $projectdb->query("SHOW tables LIKE 'policies_to_import'");
        if( $res->num_rows == 0 )
        {
            $query = "CREATE TABLE `policies_to_import` ( 
                `id` INT NOT NULL AUTO_INCREMENT, 
                `filename` VARCHAR(255) NOT NULL,
                `firewall` VARCHAR(255) NOT NULL, 
                `policyname` VARCHAR(255), 
                `selected` INT(1) NOT NULL DEFAULT 0, 
                `processed` TIMESTAMP NULL, 
                PRIMARY KEY (`id`));";
            $projectdb->query($query);
        }

        //$devicegroup = $config_filename;
        $xml = simplexml_load_file($config_path);
        $fw_single = $xml->xpath("//fw_single");
        $fw_clusters = $xml->xpath("//fw_cluster");
        $fw_cluster_and_single = array_merge($fw_single, $fw_clusters);
        foreach( $fw_cluster_and_single as $fw_policy )
        {
            $fwName = $fw_policy["name"];
            //Check if this policy was already loaded before
            $query = "SELECT id FROM policies_to_import WHERE filename='$filename' AND firewall='$fwName';";
            $isDup = $projectdb->query($query);
            if( $isDup->num_rows == 0 )
            {
                $query = "INSERT into policies_to_import (filename, firewall, selected) VALUES ('$filename','$fwName','0');";
            }
            $projectdb->query($query);
        }
    }
}

function get_PolicyNames(STRING $config_path, STRING $config_filename)
{
    global $projectdb;

    $filename = $config_filename;
    $policies = array();

    if( isXML($config_path) === TRUE )
    {
        $xml = simplexml_load_file($config_path);
        $fw_policies = $xml->xpath("//fw_policy");
        foreach( $fw_policies as $fw_policy )
        {
            $policies[] = [
                'name' => $fw_policy["name"]->__toString()
            ];
        }
    }

    return $policies;
}

/**
 * Method to indeitify the existing domain_names that may be required in the policy
 */
function get_DomainNames($config_path, $config_filename)
{
    global $projectdb;
    //$filename = $config_filename;

    if( isXML($config_path) === TRUE )
    {
        //Create the table policies_to_import is it doesn't exist
        $res = $projectdb->query("SHOW tables LIKE 'domain_names'");
        if( $res->num_rows == 0 )
        {
            $query = "CREATE TABLE `domain_names` ( "
                . "`id` INT NOT NULL AUTO_INCREMENT, "
                . "`name` VARCHAR(255) NOT NULL, "
                . "`ipaddress` VARCHAR(255) NOT NULL, "
                . "`description` VARCHAR(255) NOT NULL, "
                . "PRIMARY KEY (`id`));";
            $projectdb->query($query);
        }
        //$devicegroup = $config_filename;
        $xml = simplexml_load_file($config_path);
        $domain_names = $xml->xpath("//domain_name");

        foreach( $domain_names as $domain_name )
        {
            $name = $domain_name["name"];
            $description = normalizeNames($domain_name["comment"]);
            //Get the main IP
            //$ipaddress = gethostbyname($name);
            $ipaddress = $name;
            $query = "INSERT INTO domain_names (name, ipaddress, description) VALUES ('$name','$ipaddress','$description');";
            $projectdb->query($query);
        }
    }


}



/**
 *
 * @param SimpleXMLElement $configuration XML file with the configuration
 * @param STRING $policy_to_load Name of the policy to load
 * @param STRING $vsys
 * @param int $source
 * @param STRING $project
 * @global mysqli $projectdb
 */
function get_NATs(SimpleXMLElement $configuration, STRING $policy_to_load, STRING $vsys, STRING $source, STRING $project, array &$objectsInMemory)
{
    global $projectdb;
    global $vrid;
    global $match_expressionsInMemory;
    global $overrideNatZones;

    $Natcounter = 0;
    $nat_lid = "";
    $nat_position = "";

    $nat_sources = array();
    $nat_destinations = array();
    $add_nat_translated_source_address = array();

    #Get Last lid from Profiles
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if( $getPosition->num_rows == 0 )
    {
        $nat_position = 1;
    }
    else
    {
        $ddata = $getPosition->fetch_assoc();
        $nat_position = $ddata['t'] + 1;
    }
    if( $nat_lid == "" )
    {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        if( $getlastlid->num_rows == 1 )
        {
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = intval($getLID1['max']) + 1;
        }
        else
        {
            $nat_lid = 1;
        }
    }


    $mappings = getPolicyMappings($configuration, $policy_to_load, "firewall");

    $fw_policies = $configuration->xpath("//fw_policy");
    $fw_template_policies = $configuration->xpath("//fw_template_policy");
    $fw_policies = array_merge($fw_policies, $fw_template_policies);
    foreach( $fw_policies as $fw_policy )
    {
        $isInMapping = in_array(strval($fw_policy['name']), $mappings);
        if( strcasecmp($fw_policy["name"], $policy_to_load) === 0 or $isInMapping )
        {


            //Check if this NAT policy has a template
            if( isset($fw_policy["template_policy_ref"]) )
            {
                $template_name = $fw_policy["template_policy_ref"];
                get_NATs($configuration, $template_name, $vsys, $source, $project, $objectsInMemory);

                $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
                if( $getPosition->num_rows == 0 )
                {
                    $nat_position = 1;
                }
                else
                {
                    $ddata = $getPosition->fetch_assoc();
                    $nat_position = $ddata['t'] + 1;
                }

                $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
                if( $getlastlid->num_rows == 1 )
                {
                    $getLID1 = $getlastlid->fetch_assoc();
                    $nat_lid = intval($getLID1['max']) + 1;
                }
                else
                {
                    $nat_lid = 1;
                }
            }

            $nat = array();

            $addTag = array();
            $comments = array();
            $tagids = array();

            $done_with_tags = TRUE;
            foreach( $fw_policy->nat_entry->rule_entry as $rule_entry )
            {
                $localtag = "";
                $is_nat_disabled = strcmp($rule_entry["is_disabled"], "true") === 0 ? 1 : 0;

                $rule_tag = $rule_entry["tag"];
                $name_int = "";
                $description = "";

                // rule_entry 's can be descriptions/tag of rules or rules themselves
                // Tags come consecutively before the tagged rules
                $done_with_tags = TRUE;

                //LOOKING FOR TAGS IN THE RULES
                // Empty rule_entry (empty meaning they do not have access_rule child) are threated as tags
                if( isset($rule_entry->comment_rule) )
                {
                    //echo "This is a covering COMMENT. It may be defining it, or removing the comment\n";
                    if( $done_with_tags == TRUE )
                    {
                        $done_with_tags = FALSE;
                        unset($tagids); //Reset the tag(s) used until now
                        unset($comments);
                    }

                    $comment = $rule_entry["comment"];
                    if( isset($comment) && strcmp($comment, "") != 0 )
                    {
                        $comments[] = $comment;
                    }

                }

                // NAT CONTENT
                else
                {
                    $done_with_tags = TRUE; //We found a rule with content. Therefore, we are done parsing tags

                    $nat_rule = $rule_entry->nat_rule;
                    $action = $nat_rule->action;
                    if( !isset($action) )
                    {
                        //TODO: "This rule is VPN\n";
                    }
                    else
                    {
                        // "This rule is NOT a covering Comment, but may have a comment\n";
                        $comment = addslashes($rule_entry["comment"]);
                        if( isset($comment) && strcmp($comment, "") != 0 )
                        {
                            $localComment = $comment;
                        }
                        else
                        {
                            $localComment = '';
                        }

                        $action_type = $nat_rule->action["type"];

                        if( !isset($nat_rule->match_part) )
                        {
                            //TODO: "Sorry, this NAT does not have rule to do a match. Something can't be right"
                        }
                        else
                        {
                            $match_part = $nat_rule->match_part;

                            $member_lid = "";
                            $table_name = "";
                            //NAT matching sources
                            foreach( $match_part->match_sources->match_source_ref as $match_source )
                            {
                                $source_type = trim($match_source["type"]);
                                $expressionName = $match_source["value"];
                                $value = trim(normalizeNames($match_source["value"]));
                                if( $source_type == "match_expression" )
                                {
                                    if( isset($match_expressionsInMemory["$expressionName"]['zones']) )
                                    {
                                        //There is a Source Zone override
                                        $overrideNatZones["$nat_lid"]['from'] = $match_expressionsInMemory["$expressionName"]['zones'];
                                    }
                                    foreach( $match_expressionsInMemory["$expressionName"]['objects'] as $member )
                                    {
                                        $nat_sources[] = $member;
                                    }
                                }
                                else
                                {
                                    if( strcmp($value, "ANY") == 0 || strcmp($value, "none") == 0 )
                                    {
                                    }
                                    else
                                    {
                                        searchAddress($value, $vsys, $source, $member_lid, $table_name, $objectsInMemory);
                                        $nat_sources[] = "('$source','$vsys','$table_name','$member_lid','$nat_lid')";
                                    }
                                }
                            }

                            //NAT matching destinations
                            foreach( $match_part->match_destinations->match_destination_ref as $match_destination )
                            {
                                $source_type = trim($match_destination["type"]);
                                $expressionName = $match_destination["value"];
                                $value = trim(normalizeNames($match_destination["value"]));
                                if( $source_type == "match_expression" )
                                {
                                    if( isset($match_expressionsInMemory["$expressionName"]['zones']) )
                                    {
                                        //There is a Source Zone override
                                        $overrideNatZones["$nat_lid"]['to'] = $match_expressionsInMemory["$expressionName"]['zones'];
                                    }
                                    foreach( $match_expressionsInMemory["$expressionName"]['objects'] as $member )
                                    {
                                        $nat_destinations[] = $member;
                                    }
                                }
                                else
                                {
                                    if( strcmp($value, "ANY") == 0 || strcmp($value, "none") == 0 )
                                    {
                                    }
                                    else
                                    {
                                        searchAddress($value, $vsys, $source, $member_lid, $table_name, $objectsInMemory);
                                        $nat_destinations[] = "('$source','$vsys','$table_name','$member_lid','$nat_lid')";
                                    }
                                }
                            }

                            $nat_services = array();
                            //NAT matching services
                            foreach( $match_part->match_services->match_service_ref as $match_service )
                            {
                                $value = normalizeNames($match_service["value"]);
                                if( strcmp($value, "ANY") == 0 )
                                {
                                    //TODO: Set here an empty Service
                                    $member = new MemberObject('', '', '');
                                    $nat_services[] = $member;
                                }
                                else
                                {
                                    $found = searchService($value, $vsys, $source, $member_lid, $table_name, $objectsInMemory);
                                    if( $found )
                                    {
                                        $member = new MemberObject($value, $table_name, $member_lid);
                                        $nat_services[] = $member;//"('$source','$vsys','$table_name','$member_lid','$nat_lid')";
                                    }
                                    else
                                    {
                                        $service_name_ext = $value;
                                        $service_name_int = truncate_names(normalizeNames($service_name_ext));
                                        $description = $service_name_ext;
                                        //Adding the service in the system as an invalid service
                                        $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid) VALUES ('','$service_name_ext','$service_name_int','','65000','1','$description','$source','','$vsys', '1');";
                                        $projectdb->query($query);
                                        $member_lid = $projectdb->insert_id;
                                        $member = new MemberObject($value, 'services', $member_lid);
                                        $nat_services[] = $member; //"('$source','$vsys','services','$member_lid','$nat_lid')";
                                        $valueNorm = normalizeNames($service_name_ext);
                                        $objectsInMemory['services'][$vsys][$valueNorm]['id'] = $member_lid;
                                        $objectsInMemory['services'][$vsys][$valueNorm]['dport'] = "65000";
                                    }
                                }
                            }

                            if( count($nat_services) > 1 )
                            {
                                //TODO: Make a group of services, and get the lid. THis will be the op_service_lid and  op_service_table
                                //      will be services_groups_id
                                $groupNumber = (int)$Natcounter + 1;
                                $Nat_Servicename_ext = normalizeNames("NAT-$policy_to_load-Group($groupNumber)");
                                $Nat_Servicename_int = truncate_names(normalizeNames($Nat_Servicename_ext));
                                $valueNorm = normalizeNames($Nat_Servicename_ext);

                                $query = "INSERT INTO services_groups_id (name_ext,name,checkit,source,vsys) values('$Nat_Servicename_ext','$Nat_Servicename_int','0','$source','$vsys');";
                                $projectdb->query($query);
                                $op_service_lid = $projectdb->insert_id;
                                $op_service_table = "services_groups_id";

                                $objectsInMemory['services_groups_id'][$vsys][$valueNorm]['id'] = $op_service_lid;

                                foreach( $nat_services as $nat_service )
                                {
                                    $query = "INSERT INTO services_groups (lid,member,source,member_lid,table_name,vsys) VALUES ('$op_service_lid','$nat_service->name','$source','$nat_service->value','$nat_service->location','$vsys');";
                                    $projectdb->query($query);
                                }

                                $Natcounter++;
                            }
                            else
                            {
                                $op_service_lid = $nat_services[0]->value;
                                $op_service_table = $nat_services[0]->location;
                            }

                            //NAT options
                            if( isset($nat_rule->option) )
                            {
                                $invalid_content = 1;
                                //Initialization of variables
                                $new_dest_member_lid = "";
                                $new_dest_table_name = "";

                                $table_name = "";
                                $member_lid = "";
                                $tp_sat_type = "";
                                $is_dat = 0;
                                $op_zone_to = "";
                                $tp_dat_port = "";
                                $name_int = "";
                                $tp_sat_address_type = "";
                                $tp_sat_bidirectional = 0;

                                $nat_option = $nat_rule->option;

                                //NAT Source
                                $nat_src = $nat_option->nat_src;

                                //Static source NAT, typically used for translating the internal (“real”) IP address of an internal host to a different
                                //IP address in the external network.
                                if( isset($nat_src->static_nat) )
                                {
                                    $invalid_content = 0;
                                    $static_nat = $nat_src->static_nat;
                                    //$generate_arp = $static_nat['$generate_arp'];

                                    //$packet_description = $static_nat->packet_description['ne_ref'];
                                    //searchAddress($packet_description, $vsys, $source, $member_lid, $table_name);
                                    //$add_nat_src[]="('$source','$vsys','$nat_lid','$member_lid','$table_name')";

                                    //The outside IP may be defined as a hardcoded value
                                    if( isset($static_nat->packet_description_new['min_ip']) )
                                    {
                                        $min_ip = $static_nat->packet_description_new['min_ip'];
                                        $netmask = $static_nat->packet_description['netmask'];
                                        $cidr = mask2cidrv4($netmask);
                                        if( $cidr == 0 )
                                        {
                                            $cidr = 32;
                                        }
                                        $packet_description_new = $min_ip;
                                        $name = "$packet_description_new/$cidr";
                                        $query = "INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys,dummy) VALUES ('$name', '$name', '$packet_description_new', '$cidr', 1, 0, 'ip-netmask', '', '', '$source','$vsys','1');";
                                        $projectdb->query($query);
                                        $member_lid = $projectdb->insert_id;
                                        $tp_sat_type = "static-ip";
                                        $add_nat_translated_source_address[] = "('$source','$vsys','$nat_lid','$member_lid','address')";

                                        $objectsInMemory['address'][$vsys][$name]['id'] = $member_lid;
                                        $objectsInMemory['address'][$vsys][$name]['ipaddress'] = $packet_description_new;
                                        $objectsInMemory['address'][$vsys][$name]['cidr'] = $cidr;
                                    }
                                    //The outside IP may be defined as an address already registered
                                    else
                                    {
                                        $packet_description_new = normalizeNames($static_nat->packet_description_new['ne_ref']);
                                        $tp_sat_type = "static-ip";
                                        $tp_sat_address_type = "translated_address";
                                        searchAddress($packet_description_new, $vsys, $source, $member_lid, $table_name, $objectsInMemory);
                                        $add_nat_translated_source_address[] = "('$source','$vsys','$nat_lid','$member_lid','$table_name')";
                                    }
                                }

                                //Dynamic source NAT, typically used to translate the internal IP addresses of several internal hosts to one or a few external
                                //IP addresses to hide the internal network structure from outsiders and to avoid acquiring a separate public IP address for each of the hosts.
                                if( isset($nat_src->dynamic_nat) )
                                {
                                    $invalid_content = 0;
                                    $dynamic_nat = $nat_src->dynamic_nat;
                                    //$generate_arp = $dynamic_nat['$generate_arp'];

                                    if( !isset($dynamic_nat->packet_description['first_port']) )
                                    {
                                        $tp_sat_type = "dynamic-ip";
                                        $packet_description_new = normalizeNames($dynamic_nat->packet_description['ne_ref']);
                                        searchAddress($packet_description_new, $vsys, $source, $member_lid, $table_name, $objectsInMemory);
                                        $add_nat_translated_source_address[] = "('$source','$vsys','$nat_lid','$member_lid','$table_name')";
                                    }
                                    else
                                    {
                                        $first_port = $dynamic_nat->packet_description['first_port'];
                                        $last_port = $dynamic_nat->packet_description['last_port'];
                                        $tp_sat_type = "dynamic-ip-and-port";
                                        $tp_sat_address_type = "translated-address";
                                        //$tp_dat_port = $first_port."-".$last_port;

                                        if( isset($dynamic_nat->packet_description['min_ip']) )
                                        {
                                            $min_ip = $dynamic_nat->packet_description['min_ip'];
                                            $netmask = $dynamic_nat->packet_description['netmask'];
                                            $cidr = mask2cidrv4($netmask);
                                            if( $cidr == 0 )
                                            {
                                                $cidr = 32;
                                            }
                                            $packet_description_new = $min_ip;
                                            $name = "$packet_description_new/$cidr";
                                            //Insert the new object into the address table
                                            $query = "INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys,dummy) VALUES ('$name', '$name', '$packet_description_new', '$cidr', 1, 0, 'ip-netmask', '', '', '$source','$vsys','1');";
                                            $projectdb->query($query);
                                            $member_lid = $projectdb->insert_id;
                                            $add_nat_translated_source_address[] = "('$source','$vsys','$nat_lid','$member_lid','address')";
                                            $objectsInMemory['address'][$vsys][$name]['id'] = $member_lid;
                                            $objectsInMemory['address'][$vsys][$name]['ipaddress'] = $packet_description_new;
                                            $objectsInMemory['address'][$vsys][$name]['cidr'] = $cidr;

                                        }
                                        else
                                        {
                                            $packet_description_new = normalizeNames($dynamic_nat->packet_description['ne_ref']);
                                            searchAddress($packet_description_new, $vsys, $source, $member_lid, $table_name, $objectsInMemory);
                                            $add_nat_translated_source_address[] = "('$source','$vsys','$nat_lid','$member_lid','$table_name')";
                                        }
                                    }
                                }


                                //NAT Destination
                                $nat_dst = $nat_option->nat_dst;
                                if( isset($nat_dst->static_nat) )
                                {
                                    $invalid_content = 0;
                                    $static_nat = $nat_dst->static_nat;
                                    $is_dat = 1;
                                    //$generate_arp = $static_nat['$generate_arp'];
                                    //$packet_description = $static_nat->packet_description['ne_ref'];
                                    //searchAddress($packet_description, $vsys, $source, $member_lid, $table_name);
                                    //$add_nat_dst[]="('$source','$vsys','$nat_lid','$member_lid','$table_name')";

                                    if( isset($static_nat->packet_description_new['ne_ref']) )
                                    {
                                        $packet_description_new = normalizeNames($static_nat->packet_description_new['ne_ref']);
                                        searchAddress($packet_description_new, $vsys, $source, $new_dest_member_lid, $new_dest_table_name, $objectsInMemory);
                                        //$first_port = $static_nat->packet_description['first_port'];
                                        //$last_port = $static_nat->packet_description['last_port'];
                                        $first_new_port = $static_nat->packet_description_new['first_port'];
                                        //$last_new_port = $static_nat->packet_description_new['last_port'];
                                        $tp_dat_port = $first_new_port;
                                    }
                                    else
                                    {
                                        $min_ip = $static_nat->packet_description_new['min_ip'];
                                        $netmask = $static_nat->packet_description['netmask'];
                                        $cidr = mask2cidrv4($netmask);
                                        if( $cidr == 0 )
                                        {
                                            $cidr = 32;
                                        }
                                        $packet_description_new = $min_ip;
                                        $name = "$packet_description_new/$cidr";

                                        $query = "INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys,dummy) VALUES ('$name', '$name', '$packet_description_new', '$cidr', 1, 0, 'ip-netmask', '', '', '$source','$vsys','1');";
                                        $projectdb->query($query);
                                        $new_dest_member_lid = $projectdb->insert_id;
                                        $new_dest_table_name = "address";

                                        $objectsInMemory['address'][$vsys][$name]['id'] = $new_dest_member_lid;
                                        $objectsInMemory['address'][$vsys][$name]['ipaddress'] = $packet_description_new;
                                        $objectsInMemory['address'][$vsys][$name]['cidr'] = $cidr;

                                        //$first_port = $static_nat->packet_description['first_port'];
                                        //$last_port = $static_nat->packet_description['last_port'];
                                        $first_new_port = $static_nat->packet_description_new['first_port'];
                                        //$last_new_port = $static_nat->packet_description_new['last_port'];
                                        $tp_dat_port = $first_new_port;
                                    }

                                    //$add_nat_translated_destination_address[]="('$source','$vsys','$nat_lid','$member_lid','$table_name')";
                                }

//                                if($invalid_content){
//                                    $is_nat_disabled = 1;
//                                    $nat_tag = $rule_entry['tag'];
//                                    //add_log2("warning", 'Reading NAT Policy', 'Rule[' . $nat_lid . ']. Does not have NAT information. Please verify NAT rule with original tag="'. $nat_tag. '"', $source, 'Remove rule','rules',$nat_lid,'nat_rules');
//                                }

                                $natDescription = 'Tag[' . $rule_tag . ']';
                                if( count($comments) > 0 )
                                {
                                    $natDescription .= ' ' . implode('. ', $comments);
                                    $natDescription .= '. ' . $localComment;
                                }

                                $nat[] = "('$is_nat_disabled','$nat_lid','$nat_position','$source','$vsys','$op_zone_to','NAT $nat_lid','$tp_sat_type','$tp_sat_address_type', '$op_service_lid','$op_service_table','$is_dat','$tp_dat_port','$new_dest_member_lid','$new_dest_table_name','$tp_sat_bidirectional','$natDescription')";
                                $nat_lid++;
                                $nat_position++;
                            }

                            //Convert from Array of Tag-strings to SQL string value
                            if( isset($tagids) )
                            {
                                foreach( $tagids as $tagid )
                                {
                                    $addTag[] = "('$source','$vsys','$nat_lid','$tagid','tag')";
                                }
                            }
                            if( isset($localtag) && strcmp($localtag, "") != 0 )
                            {
                                $addTag[] = "('$source','$vsys','$nat_lid','$localtag','tag')";
                            }

                        }

                    }
                }
            }


            //Insert NAT matching Rules
            if( count($nat) > 0 )
            {
                $query = "INSERT INTO nat_rules (disabled,id,position,source,vsys,op_zone_to,name,tp_sat_type,tp_sat_address_type,"
                    . "op_service_lid,op_service_table,is_dat,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,tp_sat_bidirectional, description) "
                    . "VALUES " . implode(",", $nat) . ";";
                $projectdb->query($query);
                $nat = "";

                if( count($addTag) > 0 )
                {
                    $query = "INSERT INTO nat_rules_tag (source,vsys,rule_lid,member_lid, table_name) VALUES " . implode(",", $addTag) . ";";
                    $projectdb->query($query);
                    $addTag = "";
                }

                if( count($nat_sources) > 0 )
                {
                    $query = "INSERT INTO nat_rules_src (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $nat_sources) . ";";
                    $projectdb->query($query);
                }

                if( count($nat_destinations) > 0 )
                {
                    $query = "INSERT INTO nat_rules_dst (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $nat_destinations) . ";";
                    $projectdb->query($query);
                }

                if( count($add_nat_translated_source_address) > 0 )
                {
                    $query = "INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $add_nat_translated_source_address) . ";";
                    $projectdb->query($query);
//                    $add_nat_translated_source_address="";
                }

//                if (count($add_nat_translated_destination_address)>0){
//                    $query = "INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES ". implode(",",$add_nat_translated_destination_address).";";
//                    $projectdb->query($query);
//                    $add_nat_translated_destination_address="";
//                }
            }
        }
    }

    set_Zones_Nat($project, $source, $vsys, $vrid);

    //apply Overriden zones
    if( count($overrideNatZones) > 0 )
    {
        foreach( $overrideNatZones as $lid => $overrideZone )
        {
            if( isset($overrideZone['from']) )
            {
                $zonesFrom = $overrideZone['from'];
                $query = "DELETE FROM nat_rules_from WHERE rule_lid = '$lid'";
                $projectdb->query($query);
                $zoneQuery = array();
                foreach( $zonesFrom as $zone )
                {
                    $zoneQuery[] = "('$zone','$lid')";
                }
                $query = "INSERT into nat_rules_from (name, rule_lid) VALUES " . implode(',', $zoneQuery);
                $projectdb->query($query);
            }

            if( isset($overrideZone['to']) )
            {
                $zonesTo = $overrideZone['to'];
                $zone = $zonesTo[0];
                $query = "UPDATE nat_rules SET op_zone_to='$zone' WHERE rule_lid = '$lid'";
                $projectdb->query($query);
            }
        }
    }

    fix_Zones_Policies($project, $source, $vsys, $vrid);
}

function set_Zones_Security_Rules($source, $vsys, $vr)
{
    global $projectdb;

    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

    $ids_rules = getSecurityIdsBySourceVsys($source, $vsys);


    if( count($ids_rules) > 0 )
    {
        //Zones FROM
        $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE rule_lid IN (" . implode(',', $ids_rules) . ");");
        if( $getSRC->num_rows > 0 )
        {
            while( $getSRCData = $getSRC->fetch_assoc() )
            {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if( $getDeviceGroup->num_rows > 0 )
                {
                    $getINData = $getDeviceGroup->fetch_assoc();
                    $devicegroup = $getINData['devicegroup'];
                }

                $negate_source = 0;

                $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                //$zones = getAutoZoneToVR($vr, $member_lid, $table_name, $vsys, $source);

                foreach( $zones as $zone )
                {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                    if( $getZone->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }

        //Zones TO
        $getDST = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE rule_lid IN (" . implode(',', $ids_rules) . ");");
        if( $getDST->num_rows > 0 )
        {
            while( $getDSTData = $getDST->fetch_assoc() )
            {
                $member_lid = $getDSTData['member_lid'];
                $table_name = $getDSTData['table_name'];
                $rule_lid = $getDSTData['rule_lid'];

                $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if( $getDeviceGroup->num_rows > 0 )
                {
                    $getINData = $getDeviceGroup->fetch_assoc();
                    $devicegroup = $getINData['devicegroup'];
                }

                $negate_source = 0;

                $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                //$zones = getAutoZoneToVR($vr, $member_lid, $table_name, $vsys, $source);
                foreach( $zones as $zone )
                {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid' ;");
                    if( $getZone->num_rows == 0 )
                    {
                        $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }
    }


}

/**
 * Method to identify Members that belong to two groups. A group can be a Member
 * @param MemberObject[] $childMembers .
 * @param MemberObject[] $parentMembers
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $vsys
 * @return MemberObject[]
 */
function getCommonMembers($childMembers, $parentMembers, $projectdb, $source, $vsys): array
{
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //No parent of children sources were defined, so they are ANY
    $tmp_Members = array();

    if( (!isset($parentMembers) || count($parentMembers) == 0) &&
        (!isset($childMembers) || count($childMembers) == 0) )
    {
        $member = new MemberObject('ANY', '', '0.0.0.0', '0');
        $tmp_Members = [$member];
    }
    //The Parent policy has an ANY. We use the Child's Sources's members
    elseif( !isset($parentMembers) || count($parentMembers) == 0 || strcmp($parentMembers[0]->name, "ANY") == 0 )
    {
        $tmp_Members = $childMembers;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif( !isset($childMembers) || count($childMembers) == 0 || strcmp($childMembers[0]->name, "ANY") == 0 )
    {  //The subpolicy has ANY as a source. We use the Parents source
        $tmp_Members = $parentMembers;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif( $parentMembers == $childMembers )
    {  //TODO: test with array_diff instead, because order of the members could be different
        $tmp_Members = $parentMembers;
    }

    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else
    {
        //To make it simple, we will explode all groups into its Members.
        $exploded_childMembers = explodeGroups2Members($childMembers, $projectdb, $source, $vsys, 0);
        $exploded_parentMembers = explodeGroups2Members($parentMembers, $projectdb, $source, $vsys, 0);

        foreach( $exploded_childMembers as $childNode )
        {
            foreach( $exploded_parentMembers as $parentMember )
            {
                $way = -1;
                $result = netMatchObjects2Ways($childNode, $parentMember, $way);
                if( isset($result) )
                {
//                    echo "               We found that $result->value/$result->cidr satisfies both. We can stop for this childNode\n";
                    $tmp_Members[] = $result;
                    if( $way == 1 )
                    {
                        break 1;
                    }
                }
            }
        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if( isset($tmp_Members) )
        {
            $replace_childGroup = TRUE;
            $replace_parentGroup = TRUE;
            foreach( $exploded_childMembers as $child )
            {
                if( !in_array($child, $tmp_Members) )
                {
                    $replace_childGroup = FALSE;
                    break;
                }
            }
            foreach( $exploded_parentMembers as $parent )
            {
                if( !in_array($parent, $tmp_Members) )
                {
                    $replace_parentGroup = FALSE;
                    break;
                }
            }

            if( $replace_childGroup )
            {
                foreach( $exploded_childMembers as $child )
                {
                    $key = array_search($child, $tmp_Members);
                    if( $key !== FALSE )
                    {
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members = $childMembers;
            }
            if( $replace_parentGroup )
            {
                foreach( $exploded_parentMembers as $parent )
                {
                    $key = array_search($parent, $tmp_Members);
                    if( $key !== FALSE )
                    {
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members = $parentMembers;
            }
            //All clean now with the common Members
        }
    }

//    if(is_null($tmp_Members)){
//        $my = fopen("/tmp/error2","a");
//        fwrite($my, "Child:");
//        fwrite($my, print_r($childMembers, true));
//        fwrite($my, "Parent:");
//        fwrite($my, print_r($parentMembers, true));
//        fclose($my);
//
//    }
    return $tmp_Members;
}

/**
 * Method to identify Services that belong to two groups. A group can be a Service
 * @param MemberObject[] $childServices .
 * @param MemberObject[] $parentServices
 * @param mysqli $projectdb
 * @param string $source
 * @param string $vsys
 * @return MemberObject[]
 */
function getCommonServices($childServices, $parentServices, mysqli $projectdb, string $source, string $vsys): array
{
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //The Parent policy has an ANY. We use the Child's Sources's members

    $tmp_Services = array();
    if( (!isset($parentServices) || count($parentServices) == 0) &&
        (!isset($childServices) || count($childServices) == 0) )
    {
        $member = new MemberObject('ANY', '', '', '');
        $tmp_Services = [$member];
    }
    elseif( !isset($parentServices) || count($parentServices) == 0 || strcmp($parentServices[0]->name, "ANY") == 0 )
    {
        $tmp_Services = $childServices;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif( !isset($childServices) || count($childServices) == 0 || strcmp($childServices[0]->name, "ANY") == 0 )
    {  //The subpolicy has ANY as a source. We use the Parents source
        $tmp_Services = $parentServices;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif( $parentServices == $childServices )
    {
        $tmp_Services = $parentServices;
    }

    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else
    {

        //To make it simple, we will explode all groups into its Members.
        $exploded_childServices = explodeGroups2Services($childServices, $projectdb, $source, $vsys, 0);
        $exploded_parentServices = explodeGroups2Services($parentServices, $projectdb, $source, $vsys, 0);

        foreach( $exploded_childServices as $childService )
        {
            foreach( $exploded_parentServices as $parentService )
            {
                $way = -1;
                $result = serviceMatchObjects2Ways($childService, $parentService, $way);
                if( isset($result) )
                {
                    $tmp_Services[] = $result;
                    if( $way == 1 )
                    {
                        break 1;
                    }
                }
            }

        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if( isset($tmp_Services) )
        {
            $replace_childGroup = TRUE;
            $replace_parentGroup = TRUE;
            foreach( $exploded_childServices as $child )
            {
                if( !in_array($child, $tmp_Services) )
                {
                    $replace_childGroup = FALSE;
                    break;
                }
            }
            foreach( $exploded_parentServices as $parent )
            {
                if( !in_array($parent, $tmp_Services) )
                {
                    $replace_parentGroup = FALSE;
                    break;
                }
            }

            if( $replace_childGroup )
            {
                foreach( $exploded_childServices as $child )
                {
                    $key = array_search($child, $tmp_Services);
                    if( $key !== FALSE )
                    {
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services = array_merge($tmp_Services, $childServices);
            }
            if( $replace_parentGroup )
            {
                foreach( $exploded_parentServices as $parent )
                {
                    $key = array_search($parent, $tmp_Services);
                    if( $key !== FALSE )
                    {
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services = array_merge($tmp_Services, $parentServices);
            }
            //All clean now with the common Services
        }

    }

    return $tmp_Services;
}

/***
 * @param $configuration
 * @param $fwName
 * @param $type
 * @return array String of policy names
 */
function getPolicyMappingsOld($configuration, $fwName, $type)
{
    $foundPolicies = array();
    $isThereMapping = FALSE;

    //Some Configurations have a granted_policy_ref node that gives a mapping between firewalls and policies
    $mappings = $configuration->xpath("//granted_policy_ref");
    foreach( $mappings as $mapNode )
    {
        $isThereMapping = TRUE;
        if( strcasecmp($mapNode['engine_ref'], $fwName) === 0 )
        {
            foreach( $mapNode->list->list_entry as $policyEntry )
            {
                $pol = $policyEntry["value"];
                $foundPolicies[] = $pol;
            }
        }
    }

    //Some Configurations have, for each firewall, a location_ref attribute that specifies the policy that is to be applied to that firewall
    $fw_policies = $configuration->xpath("//fw_policy");
    foreach( $fw_policies as $fw_policy )
    {
        if( strcasecmp($fw_policy["name"], $fwName) === 0 )
        {
            if( isset($fw_policy['location_ref']) )
            {
                $foundPolicies[] = $fw_policy['location_ref'];
            }
        }
    }

    if( !$isThereMapping )
    {
        //Check whether there is only one policy in the whole exported_data.xml configuration file. Is so, return this one to be applied to all the defined FWs in the config file.
        $policies = $configuration->xpath("//fw_policy");
        if( count($policies) == 1 )
        {
            $policy = $policies[0];
            $pol = $policy["name"];
            $foundPolicies[] = $pol;
        }
    }

    return $foundPolicies;

}

function getPolicyMappings($configuration, $policyName, $type)
{
    global $projectdb;
    $listFirewalls = array();
    $query = 'SELECT firewall FROM policies_to_import WHERE policyname="' . $policyName . '" ';
//    echo $query.PHP_EOL;
//    die;
    $results = $projectdb->query($query);
    if( $results->num_rows > 0 )
    {
        while( $data = $results->fetch_assoc() )
        {
            $listFirewalls[] = $data['firewall'];
        }
    }
    return $listFirewalls;
}

function get_Policy($configuration, $policy_to_load, $vsys, $source, $project, &$objectsInMemory)
{
    global $projectdb;
    global $match_expressionsInMemory;
    //global $DBUser;
    //global $DBPass;

    global $lid;
    global $position;
    global $debug;

    global $vrid;

    $validActions = array("allow", "deny", "drop", "reset", "reset-both", "reset-client", "reset-server");


    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $getlastlid2 = $projectdb->query("SELECT max(position) as max FROM security_rules;");
    $getLID2 = $getlastlid2->fetch_assoc();
    $position = intval($getLID2['max']) + 1;

    /*
     * Cleaning the variables for starting the policy collection
     */
    unset($rule);
    $rule = array();
    $sources = array();
    $destinations = array();
    $services = array();
    $addTag = array();
    $tagids = null;
    $comments = array();
    $overrideSecurityZones = array();

    $mappings = getPolicyMappings($configuration, $policy_to_load, "firewall");

    $fw_policies = $configuration->xpath("//fw_policy");
    $fw_template_policies = $configuration->xpath("//fw_template_policy");
    $fw_policies = array_merge($fw_policies, $fw_template_policies);
    foreach( $fw_policies as $fw_policy )
    {
        $isInMapping = in_array(strval($fw_policy['name']), $mappings);

        if( strcasecmp($fw_policy["name"], $policy_to_load) === 0 or $isInMapping )
        {
            $policy_name = $fw_policy["name"];

            //Check if this policy has a template
            if( isset($fw_policy["template_policy_ref"]) )
            {
                $template_name = $fw_policy["template_policy_ref"];
                get_Policy($configuration, $template_name, $vsys, $source, $project, $objectsInMemory);

                $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
                $getLID1 = $getlastlid->fetch_assoc();
                $lid = intval($getLID1['max']) + 1;
                $getlastlid2 = $projectdb->query("SELECT max(position) as max FROM security_rules;");
                $getLID2 = $getlastlid2->fetch_assoc();
                $position = intval($getLID2['max']) + 1;
            }

            $done_with_globalComments = TRUE;
            foreach( $fw_policy->access_entry->rule_entry as $rule_entry )
            {
                $is_fw_policy_disabled = strcmp($rule_entry["is_disabled"], "true") === 0 ? 1 : 0;

                $rule_name = (isset($rule_entry['name'])) ? $rule_entry['name'] : "";

                // rule_entry's can be descriptions/tag of rules or rules themselves
                // Tags come consecutively before the tagged rules

                //LOOKING FOR TAGS IN THE RULES
                // Empty rule_entry (empty meaning they do not have access_rule child) are threated as tags
                if( isset($rule_entry->comment_rule) )
                {
                    // "This is a covering COMMENT. It may be defining it, or removing the comment\n";
                    if( $done_with_globalComments == TRUE )
                    {
                        $done_with_globalComments = FALSE;
//                        unset($comments); //Reset the comment(s) used until now
                        $comments = array();
//                        unset($tagids); //Reset the tag(s) used until now
                        $tagids = array();
                    }

                    $comment = addslashes($rule_entry["comment"]);
                    if( isset($comment) && strcmp($comment, "") != 0 )
                    {
                        $comments[] = $comment;
                    }
                }

                // RULE CONTENT
                else
                {
                    $done_with_globalComments = TRUE; //We found a rule with content. Therefore, we are done parsing tags

                    $access_rule = $rule_entry->access_rule;
                    $action = $access_rule->action;

                    $rule_tag = $rule_entry["tag"];

                    $comment = addslashes($rule_entry["comment"]);
                    if( isset($comment) && strcmp($comment, "") != 0 )
                    {
                        $localComment = $comment;
                    }
                    else
                    {
                        $localComment = '';
                    }

                    if( isset($access_rule->vpn_action) )
                    {
                        $vpn_action = $access_rule->vpn_action;

                        if( count($vpn_action) > 0 )
                        {
                            $action_type = "allow";
                            $vpn_name = normalizeNames($access_rule->vpn_action->vpn_ref['ref']);
                            $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$vpn_name' AND source='$source' AND vsys='$vsys';");
                            if( $getTag->num_rows == 0 )
                            {
                                $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys) VALUES ('$vpn_name','color7','VPN $vpn_name','$source','$vsys');");
                                $localtag = $projectdb->insert_id;
                            }
                            else
                            {
                                $getTagData = $getTag->fetch_assoc();
                                $localtag = $getTagData['id'];
                            }
                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule related to VPN ' . $vpn_name, $source, 'Check.', 'rules', $lid, 'security_rules');
                        }
                    }
                    else
                    {
                        $action_type = $access_rule->action["type"];
                    }

                    if( !isset($access_rule->match_part) )
                    {
                        //TODO: echo "Sorry, $action_type. Please, check me later\n";
                    }
                    else
                    {
                        $match_part = $access_rule->match_part;
//                        unset($rule_origins);
                        $rule_origins = array();
//                        unset($rule_destinations);
                        $rule_destinations = array();
//                        unset($rule_services);
                        $rule_services = array();

                        //Checking sources
                        foreach( $match_part->match_sources->match_source_ref as $match_source )
                        {
                            $source_type = trim($match_source["type"]);
                            $expressionName = $match_source["value"];
                            $value = trim(normalizeNames($match_source["value"]));
                            if( $source_type == "match_expression" )
                            {
                                if( isset($match_expressionsInMemory["$expressionName"]['zones']) )
                                {
                                    //There is a Source Zone override
                                    $overrideSecurityZones["$lid"]['from'] = $match_expressionsInMemory["$expressionName"]['zones'];
                                }
                                foreach( $match_expressionsInMemory["$expressionName"]['objects'] as $member )
                                {
                                    $rule_origins[] = $member;
                                }
                            }
                            else
                            {
                                if( $value == "NOT Loopback network" || $value == "Loopback network" )
                                {
                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "' . $value . '" not supported', $source, 'Source ' . $value . ' not supported. Calculate the required objects', 'rules', $lid, 'security_rules');
                                }
                                elseif( $value != "ANY" )
                                {
                                    $valueNorm = normalizeNames($value);

                                    if( $valueNorm == "none" )
                                    {
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Source ', $source, 'Check it.', 'rules', $lid, 'security_rules');
                                    }

                                    if( isset($objectsInMemory['address'][$vsys][$valueNorm]) )
                                    {
                                        $member_lid = $objectsInMemory['address'][$vsys][$valueNorm]['id'];
                                        $member_ipaddress = $objectsInMemory['address'][$vsys][$valueNorm]['ipaddress'];
                                        $member_cidr = $objectsInMemory['address'][$vsys][$valueNorm]['cidr'];
                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);

                                        $rule_origins[] = $member;
                                    }
                                    elseif( isset($objectsInMemory['address_groups_id'][$vsys][$valueNorm]) )
                                    {
                                        $member_lid = $objectsInMemory['address_groups_id'][$vsys][$valueNorm]['id'];
                                        $member = new MemberObject($member_lid, "address_groups_id");

                                        $rule_origins[] = $member;
                                    }
                                    else
                                    {
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "' . $value . '" not supported', $source, 'Source ' . $value . ' not supported. Calculate the required objects', 'rules', $lid, 'security_rules');
                                    }

                                    /*$query = "SELECT id, ipaddress,cidr FROM address WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';";
                                    $getAddress = $projectdb->query($query);
                                    if ($getAddress->num_rows > 0) {
                                        $myData = $getAddress->fetch_assoc();
                                        $member_lid = $myData['id'];
                                        $member_ipaddress = $myData['ipaddress'];
                                        $member_cidr = $myData['cidr'];
                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);

                                        $rule_origins[] = $member;
                                    } else {
                                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';");
                                        if ($getGRP->num_rows == 1) {
                                            $myData = $getGRP->fetch_assoc();
                                            $member_lid = $myData['id'];
                                            $member = new MemberObject($member_lid, "address_groups_id");

                                            $rule_origins[] = $member;
                                        } else {
                                            //TODO:  "I couldn't find $value.!!\n";
                                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "'.$value.'" not supported', $source, 'Source '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                        }
                                    }*/
                                }
                            }
                        }

                        //Checking destinations
                        foreach( $match_part->match_destinations->match_destination_ref as $match_destination )
                        {
                            $source_type = trim($match_destination["type"]);
                            $expressionName = $match_destination["value"];
                            $value = trim(normalizeNames($match_destination["value"]));
                            if( $source_type == "match_expression" )
                            {
                                if( isset($match_expressionsInMemory["$expressionName"]['zones']) )
                                {
                                    //There is a Source Zone override
                                    $overrideSecurityZones["$lid"]['to'] = $match_expressionsInMemory["$expressionName"]['zones'];
                                }
                                foreach( $match_expressionsInMemory["$expressionName"]['objects'] as $member )
                                {
                                    $rule_destinations[] = $member;
                                }
                            }
                            else
                            {
                                if( $value == "NOT Loopback network" || $value == "Loopback network" )
                                {
                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "' . $value . '" not supported', $source, 'Destination ' . $value . ' not supported. Calculate the required objects', 'rules', $lid, 'security_rules');
                                }
                                elseif( $value != "ANY" )
                                {
                                    $valueNorm = normalizeNames($value);

                                    if( $valueNorm == "none" )
                                    {
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Destination ', $source, 'Check it.', 'rules', $lid, 'security_rules');
                                    }

                                    if( isset($objectsInMemory['address'][$vsys][$valueNorm]) )
                                    {
                                        $member_lid = $objectsInMemory['address'][$vsys][$valueNorm]['id'];
                                        $member_ipaddress = $objectsInMemory['address'][$vsys][$valueNorm]['ipaddress'];
                                        $member_cidr = $objectsInMemory['address'][$vsys][$valueNorm]['cidr'];
                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);

                                        $rule_destinations[] = $member;
                                    }
                                    elseif( isset($objectsInMemory['address_groups_id'][$vsys][$valueNorm]) )
                                    {
                                        $member_lid = $objectsInMemory['address_groups_id'][$vsys][$valueNorm]['id'];
                                        $member = new MemberObject($member_lid, "address_groups_id");

                                        $rule_destinations[] = $member;
                                    }
                                    else
                                    {
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "' . $value . '" not supported', $source, 'Destination ' . $value . ' not supported. Calculate the required objects', 'rules', $lid, 'security_rules');
                                    }

                                    /*$getAddress = $projectdb->query("SELECT id, ipaddress, cidr FROM address WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';");
                                    if ($getAddress->num_rows > 0) {
                                        $myData = $getAddress->fetch_assoc();
                                        $member_lid = $myData['id'];
                                        $member_ipaddress = $myData['ipaddress'];
                                        $member_cidr = $myData['cidr'];
                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);
                                        $rule_destinations[] = $member;
                                    } else {
                                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';");
                                        if ($getGRP->num_rows == 1) {
                                            $myData = $getGRP->fetch_assoc();
                                            $member_lid = $myData['id'];
                                            $member = new MemberObject($member_lid, "address_groups_id");
                                            $rule_destinations[] = $member;
                                        } else {
                                            //TODO: "I couln't find this ·value!!!!"
                                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "'.$value.'" not supported', $source, 'Destination '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                        }
                                    }*/
                                }
                            }
                        }

                        //Services
                        foreach( $match_part->match_services->match_service_ref as $match_service )
                        {
                            $value = normalizeNames($match_service["value"]);
                            if( strcmp($value, "ANY") == 0 )
                            {
                                $service = new MemberObject("ANY", '', '', '');
                                $rule_services[] = $service;
                            }
                            else
                            {
                                $valueNorm = normalizeNames($value);
                                if( isset($objectsInMemory['services'][$vsys][$valueNorm]) )
                                {
                                    $service_lid = $objectsInMemory['services'][$vsys][$valueNorm]['id'];
                                    $service_port = $objectsInMemory['services'][$vsys][$valueNorm]['dport'];
                                    $member = new MemberObject($service_lid, "services", $service_port);
                                    $rule_services[] = $member;
                                }
                                elseif( isset($objectsInMemory['services_groups_id'][$vsys][$valueNorm]) )
                                {
                                    $member_lid = $objectsInMemory['services_groups_id'][$vsys][$valueNorm]['id'];
                                    $member = new MemberObject($member_lid, "services_groups_id");
                                    $rule_services[] = $member;
                                }
                                else
                                {
                                    $service_name_ext = normalizeNames($value);
                                    $service_name_int = truncate_names(normalizeNames($service_name_ext));
                                    $serv_description = $service_name_ext;
                                    //Adding the service in the system as an invalid service
                                    $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid) " .
                                        "VALUES('','$service_name_ext','$service_name_int','','65000','1','$serv_description','$source','','$vsys', '1');";
//                                        echo $query.PHP_EOL;
//                                        echo "Line 1978\n";
                                    $projectdb->query($query);
                                    $member_lid = $projectdb->insert_id;
                                    $member = new MemberObject($member_lid, "services");
                                    $rule_services[] = $member;
                                    $objectsInMemory['services'][$vsys][$service_name_ext]['id'] = $member_lid;
                                    $objectsInMemory['services'][$vsys][$service_name_ext]['dport'] = "65000";
                                }

                                /*$query = "SELECT id, dport FROM services WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';";
                                $getService = $projectdb->query($query);
                                if ($getService->num_rows > 0) {
                                    $myData = $getService->fetch_assoc();
                                    $service_lid = $myData['id'];
                                    $service_port = $myData['dport'];
                                    $member = new MemberObject($service_lid, "services",$service_port);
                                    $rule_services[] = $member;
                                }
                                else{
                                    $getServiceGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';");
                                    if ($getServiceGRP->num_rows == 1) {
                                        $myData = $getServiceGRP->fetch_assoc();
                                        $member_lid = $myData['id'];
                                        $member = new MemberObject($member_lid, "services_groups_id");
                                        $rule_services[] = $member;
                                    }
                                    else{
                                        $service_name_ext = $value;
                                        $service_name_int = truncate_names(normalizeNames($service_name_ext));
                                        $serv_description = $service_name_ext;
                                        //Adding the service in the system as an invalid service
                                        $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid) ".
                                            "VALUES('','$service_name_ext','$service_name_int','','65000','1','$serv_description','$source','','$vsys', '1');";
//                                        echo $query.PHP_EOL;
//                                        echo "Line 1978\n";
                                        $projectdb->query($query);
                                        $member_lid = $projectdb->insert_id;
                                        $member = new MemberObject($member_lid, "services");
                                        $rule_services[] = $member;
                                    }
                                }*/
                            }
                        }

                        switch ($action_type)
                        {
                            case "allow":
                                $action = "allow";
                                break;

                            case "discard":
                                $action = "drop";
                                break;

                            case "reject":
                            case "refuse":
                                $action = "reset-both";
                                break;

                            case "jump":
                                $subrule_ref = $access_rule->action["subrule_ref"];
                                //Call get_sub_policy looking for the entry that matches this call, and recalculate the sources, destinations and services given the parent rule
                                get_sub_policy($configuration, $subrule_ref, $is_fw_policy_disabled, $tagids, $vsys,
                                    $source, $project, $rule_origins, $rule_destinations, $rule_services,
                                    $rule, $sources, $destinations, $services, $addTag, $comments, $objectsInMemory);

                                break;

                            case "terminate":
                            default:
                                $action = "deny";
                                $is_fw_policy_disabled = TRUE;
                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action "' . $action_type . '" that is unknown', $source, 'Using an action ' . $action . ' that is unknown', 'rules', $lid, 'security_rules');

                        }

                        //These rules can be directly input in the database
                        if( in_array($action, $validActions) )
                        {
                            foreach( $rule_origins as $rule_origin )
                            {
                                if( strcmp($rule_origin->name, "ANY") != 0 )
                                {
                                    $sources[] = "('$source','$vsys','$rule_origin->location','$rule_origin->name','$lid')";
                                }
                            }

                            foreach( $rule_destinations as $rule_destination )
                            {
                                if( strcmp($rule_destination->name, "ANY") != 0 )
                                {
                                    $destinations[] = "('$source','$vsys','$rule_destination->location','$rule_destination->name','$lid')";
                                }
                            }

                            foreach( $rule_services as $rule_service )
                            {
                                if( strcmp($rule_service->name, "ANY") != 0 )
                                {
                                    $services[] = "('$source','$vsys','$rule_service->location','$rule_service->name','$lid')";
                                }
                            }

                            $ruleDescription = 'Tag[' . $rule_tag . ']';
                            if( count($comments) > 0 )
                            {
                                $ruleDescription .= ' ' . implode('. ', $comments);
                                $ruleDescription .= '. ' . $localComment;
                                $ruleDescription = truncate_descriptions($ruleDescription);
                            }

                            $rule_name = ($rule_name == "") ? "Rule $lid" : truncate_rulenames(normalizeNames($rule_name));
                            $rule[] = "('$lid','$position','$rule_name','$ruleDescription','$action','$is_fw_policy_disabled','$vsys','$source')";
                            if( isset($tagids) )
                            {
                                foreach( $tagids as $tagid )
                                {
                                    $addTag[] = "('$source','$vsys','$lid','$tagid','tag')";
                                }
                            }
                            if( isset($localtag) && strcmp($localtag, "") != 0 )
                            {
                                $addTag[] = "('$source','$vsys','$lid','$localtag','tag')";
                            }
                            $lid++;
                            $position++;
                        }
                    }
                }
            }

            //Insert Rules and its Objects
            if( count($rule) > 0 )
            {
                $query = "INSERT INTO security_rules (id,position,name,description,action,disabled,vsys,source) VALUES " . implode(",", $rule) . ";";
                $projectdb->query($query);
            }

            if( count($services) > 0 )
            {
                $query = "INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $services) . ";";
                $projectdb->query($query);
            }

            if( count($destinations) > 0 )
            {
                $query = "INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $destinations) . ";";
                $projectdb->query($query);
            }

            if( count($sources) > 0 )
            {
                $query = "INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $sources) . ";";
                $projectdb->query($query);
            }

            if( count($addTag) > 0 )
            {
                $query = "INSERT INTO security_rules_tag (source,vsys,rule_lid,member_lid, table_name) VALUES " . implode(",", $addTag) . ";";
                $projectdb->query($query);
            }
            unset($addTag);
        }
    }

    set_Zones_Security_Rules($source, $vsys, $vrid);

    //apply Overriden zones
    if( count($overrideSecurityZones) > 0 )
    {
        foreach( $overrideSecurityZones as $lid => $overrideZone )
        {
            if( isset($overrideZone['from']) )
            {
                $zonesFrom = $overrideZone['from'];
                $query = "DELETE FROM security_rules_from WHERE rule_lid = '$lid'";
                $projectdb->query($query);
                $zoneQuery = array();
                foreach( $zonesFrom as $zone )
                {
                    $zoneQuery[] = "('$zone','$lid')";
                }
                $query = "INSERT into security_rules_from (name, rule_lid) VALUES " . implode(',', $zoneQuery);
                $projectdb->query($query);
            }

            if( isset($overrideZone['to']) )
            {
                $zonesTo = $overrideZone['to'];
                $query = "DELETE FROM security_rules_to WHERE rule_lid = '$lid'";
                $projectdb->query($query);
                $zoneQuery = array();
                foreach( $zonesTo as $zone )
                {
                    $zoneQuery[] = "('$zone','$lid')";
                }
                $query = "INSERT into security_rules_to (name, rule_lid) VALUES " . implode(',', $zoneQuery);
                $projectdb->query($query);
            }
        }
    }
}

/**
 * This method should include additional changes in $rule, and define the new origins, destinations, services and tagids for the new included rules
 * @param String $configuration
 * @param String $subrule_ref
 * @param int $is_fw_policy_disabled
 * @param MemberObject
 */
function get_sub_policy($configuration, $subrule_ref, $is_fw_policy_disabled, &$tagids, $vsys, $source, $project,
                        &$rule_origins, &$rule_destinations, &$rule_services, &$rule, &$sources, &$destinations, &$services, &$addTag, &$comments, &$objectsInMemory)
{

    global $lid;
    global $position;
    global $projectdb;
    global $match_expressionsInMemory;

    $validActions = array("allow", "deny", "drop", "reset", "reset-both", "reset-client", "reset-server", "jump");

    $description = '';

    //Defining variables I will globally use in this function
    $resultingSourceMembers = null;
    $resultingDestinationMembers = null;
    $resultingServices = null;

    /*
     * Here are the subpolicies that could be called from the fw_policy element
     */
    //$search_xpath="//fw_sub_policy[@name='0_DMZ_Proxy']";
    //$name=$fw_sub_policy["name"]
    //echo "The fw_sub_policy $name has rules with the options . . .\n";

    if( strcasecmp($subrule_ref, "DHCP Relay") == 0 )
    {
        foreach( $rule_origins as $rule_origin )
        {
            if( strcmp($rule_origin->name, "ANY") != 0 )
            {
                $sources[] = "('$source','$vsys','$rule_origin->location','$rule_origin->name','$lid')";
            }
        }

        foreach( $rule_destinations as $rule_destination )
        {
            if( strcmp($rule_destination->name, "ANY") != 0 )
            {
                $destinations[] = "('$source','$vsys','$rule_destination->location','$rule_destination->name','$lid')";
            }
        }

        $query = "SELECT id  FROM services WHERE source='$source' AND BINARY name_ext='DHCP TCP' AND vsys='$vsys';";
        $getService = $projectdb->query($query);
        if( $getService->num_rows > 0 )
        {
            $myData = $getService->fetch_assoc();
            $service_lid = $myData['id'];
            $service_port = $myData['dport'];
            $member = new MemberObject($service_lid, "services", $service_port);
            $sub_services[] = $member;
        }
        $query = "SELECT id  FROM services WHERE source='$source' AND BINARY name_ext='DHCP UDP' AND vsys='$vsys';";
        $getService = $projectdb->query($query);
        if( $getService->num_rows > 0 )
        {
            $myData = $getService->fetch_assoc();
            $service_lid = $myData['id'];
            $service_port = $myData['dport'];
            $member = new MemberObject($service_lid, "services", $service_port);
            $sub_services[] = $member;
        }

        foreach( $sub_services as $rule_service )
        {
            if( strcmp($rule_service->name, "ANY") != 0 )
            {
                $services[] = "('$source','$vsys','$rule_service->location','$rule_service->name','$lid')";
            }
        }
        $result_is_subrule_disabled = ($is_fw_policy_disabled == 1) ? 1 : 0;
        $rule[] = "('$lid','$position','Rule $lid','$description','allow','$result_is_subrule_disabled','$vsys','$source')";
        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. DHCP Relay rule applied.', $source, 'Check.', 'rules', $lid, 'security_rules');
        $lid++;
        $position++;
    }
    else
    {
        $fw_sub_policies = $configuration->xpath("//fw_sub_policy");
//        $fw_sub_policies = $configuration->xpath("//fw_sub_policy" or "//fw_template_policy");
        foreach( $fw_sub_policies as $fw_sub_policy )
        {
            if( strcmp($fw_sub_policy["name"], $subrule_ref) == 0 )
            {
//                echo "\nSUB_POLICY $subrule_ref\n";
                //$i=0;
                foreach( $fw_sub_policy->access_entry as $access_entry )
                {
                    //echo "\n - ACCESS ENTRY $i \n"; $i++;
                    $subRulePosition = 0;

                    $done_with_tags = TRUE;
                    foreach( $access_entry->rule_entry as $rule_entry )
                    {
                        $is_subrule_disabled = strcmp($rule_entry["is_disabled"], "true") === 0 ? 1 : 0;
                        $result_is_subrule_disabled = ($is_subrule_disabled == 1 || $is_fw_policy_disabled == 1) ? 1 : 0;  //If either the parent of the child are disabled, we disable the resulting rule

                        //Reseting the local variables for sub_rule definition
                        unset($sub_sources);
                        unset($sub_destinations);
                        unset($sub_services);
                        $sub_sources = array();
                        $sub_destinations = array();
                        $sub_services = array();
                        //unset($additionalTags);

                        //Is this entry does not have an access_rule inside, this can be considered as a Comment.
                        //$k=0;
                        if( isset($rule_entry->comment_rule) )
                        {
                            if( $done_with_tags == TRUE )
                            {
                                $done_with_tags = FALSE;
                                unset($additionalTags); //Reset the tag(s) used until now
                            }
                            //echo "    Rule Entry $subRulePosition:         Check that this is a rule entry for access, it could be for NAT, or VPN\n";$subRulePosition++;

                            $comment = addslashes($rule_entry["comment"]);
                            if( isset($comment) && strcmp($comment, "") != 0 )
                            {
                                $comments[] = $comment;
                            }
                        }

                        else
                        {
                            $done_with_tags = TRUE; //We found a rule with content. Therefore, we are done parsing tags
                            //echo "    Rule Entry $subRulePosition:         Done with the comments\n";
                            $subRulePosition++;

                            $rule_tag = $rule_entry["tag"];

                            $comment = addslashes($rule_entry["comment"]);
                            if( isset($comment) && strcmp($comment, "") != 0 )
                            {
                                $localComment = $comment;
                            }
                            else
                            {
                                $localComment = '';
                            }

                            foreach( $rule_entry->access_rule as $access_rule )
                            {
                                //Checking the action of this code
                                $action_type = $access_rule->action["type"];
                                if( isset($action_type) )
                                {
                                    switch ($action_type)
                                    {
                                        case "allow":
                                            $action = "allow";
                                            break;

                                        case "discard":
                                            $action = "drop";
                                            break;

                                        case "reject":
                                        case "refuse":
                                            $action = "reset-both";
                                            break;

                                        case "jump":
                                            $action = "jump";
                                            $subrule_ref2 = $access_rule->action["subrule_ref"];
                                            add_log2("info", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action *jump* of a second or deeper level.', $source, 'Using an action *jump* in a subpolicy. It is suggested to review multiple-level rule intersection', 'rules', $lid, 'security_rules');
                                            break;

                                        case "":
                                            //TODO "This may be a VPN rule. Let's leave it for a later version";
                                            break;

                                        case "terminate":
                                        default:
                                            $action = "deny";
                                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action "' . $action_type . '" that is unknown', $source, 'Using an action $action that is unknown', 'rules', $lid, 'security_rules');
                                    }
                                }
                                $vpn_action = $access_rule->vpn_action;
                                if( count($vpn_action) > 0 )
                                {
                                    $action = "allow";
                                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name='vpn' AND source='$source' AND vsys='$vsys';");
                                    if( $getTag->num_rows == 0 )
                                    {
                                        $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys) VALUES ('vpn','color7','vpn','$source','$vsys');");
                                        $additionalTags[] = $projectdb->insert_id;
                                    }
                                    else
                                    {
                                        $getTagData = $getTag->fetch_assoc();
                                        $additionalTags[] = $getTagData['id'];
                                    }
                                }


                                //These rules can be directly input in the database
                                if( in_array($action, $validActions) )
                                {

                                    //Checking the source
                                    //echo "           ORIGINS\n";
                                    foreach( $access_rule->match_part->match_sources->match_source_ref as $match_source )
                                    {
                                        $source_type = trim($match_source["type"]);
                                        $expressionName = $match_source["value"];
                                        $value = trim(normalizeNames($match_source["value"]));
                                        if( $source_type == "match_expression" )
                                        {
                                            if( isset($match_expressionsInMemory["$expressionName"]['zones']) )
                                            {
                                                //There is a Source Zone override
                                                $overrideSecurityZones["$lid"]['from'] = $match_expressionsInMemory["$expressionName"]['zones'];
                                            }
                                            foreach( $match_expressionsInMemory["$expressionName"]['objects'] as $member )
                                            {
                                                $sub_sources[] = $member;
                                            }
                                        }
                                        else
                                        {

                                            $valueNorm = normalizeNames($value);

                                            if( $valueNorm == "none" )
                                            {
                                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Source ', $source, 'Check it.', 'rules', $lid, 'security_rules');
                                            }

                                            if( strcmp($value, "ANY") == 0 )
                                            {
                                                $member = new MemberObject("ANY", '', '0.0.0.0', '0');
                                                $sub_sources[] = $member;
                                            }
                                            else
                                            {
                                                if( isset($objectsInMemory['address'][$vsys][$valueNorm]) )
                                                {
                                                    $member_lid = $objectsInMemory['address'][$vsys][$valueNorm]['id'];
                                                    $member_ipaddress = $objectsInMemory['address'][$vsys][$valueNorm]['ipaddress'];
                                                    $member_cidr = $objectsInMemory['address'][$vsys][$valueNorm]['cidr'];
                                                    $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);

                                                    $sub_sources[] = $member;
                                                }
                                                elseif( isset($objectsInMemory['address_groups_id'][$vsys][$valueNorm]) )
                                                {
                                                    $member_lid = $objectsInMemory['address_groups_id'][$vsys][$valueNorm]['id'];
                                                    $member = new MemberObject($member_lid, "address_groups_id");

                                                    $sub_sources[] = $member;
                                                }
                                                else
                                                {
                                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "' . $value . '" not supported', $source, 'Source ' . $value . ' not supported. Calculate the required objects', 'rules', $lid, 'security_rules');
                                                }
                                            }

                                            /*if (strcmp($value, "ANY") == 0) {
                                                $member = new MemberObject("ANY", '', '0.0.0.0', '0');
                                                $sub_sources[] = $member;
                                            } else {
                                                $getAddress = $projectdb->query("SELECT id, ipaddress, cidr FROM address WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';");
                                                if ($getAddress->num_rows > 0) {
                                                    $myData = $getAddress->fetch_assoc();
                                                    $member_lid = $myData['id'];
                                                    $member_ip = $myData['ipaddress'];
                                                    $member_cidr = $myData['cidr'];
                                                    $member = new MemberObject($member_lid, 'address', $member_ip, $member_cidr);
                                                    $sub_sources[] = $member;
                                                } else {
                                                    $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';");
                                                    if ($getGRP->num_rows == 1) {
                                                        $myData = $getGRP->fetch_assoc();
                                                        $member_lid = $myData['id'];
                                                        $member = new MemberObject($member_lid, 'address_groups_id');
                                                        $sub_sources[] = $member;
                                                    } else {
                                                        //TODO:   echo "I couldn't find $value!!\n";
                                                    }
                                                }
                                            }*/
                                        }
                                    }


                                    //echo "             We got ".count($sub_sources)." childsources and ".count($rule_origins)."  parentsources\n";
                                    $resultingSourceMembers = getCommonMembers($sub_sources, $rule_origins, $projectdb, $source, $vsys);
                                    //echo "             The matching resulted in ".count($resultingSourceMembers) ." new Members\n";

                                    //If the sources of Parent and Child do not overlap, we can disable this rule :)
                                    if( !isset($resultingSourceMembers) || count($resultingSourceMembers) == 0 )
                                    {
                                        $result_is_subrule_disabled = 1;
                                        $sub_rule_tag = $rule_entry['tag'];
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. The rule in subpolicy "' . $subrule_ref . '" position=' . $subRulePosition . ' with original tag="' . $sub_rule_tag . '" does not have sources matching the parent rule.  Disabled for precaution.', $source, 'Determine whether this rule can be deleted', 'rules', $lid, 'security_rules');
                                        $resultingSourceMembers = $rule_origins;
                                        //   break 1;  //This could speed up the parsing, if we don't want to load rules that are invalid and disabled
                                    }

                                    //Checking the destination
                                    //echo "           DESTINATIONS\n";
                                    $sub_destinations = array();
                                    foreach( $access_rule->match_part->match_destinations->match_destination_ref as $match_destination )
                                    {
                                        $source_type = trim($match_destination["type"]);
                                        $expressionName = $match_destination["value"];
                                        $value = trim(normalizeNames($match_destination["value"]));
                                        if( $source_type == "match_expression" )
                                        {
                                            if( isset($match_expressionsInMemory["$expressionName"]['zones']) )
                                            {
                                                //There is a Source Zone override
                                                $overrideSecurityZones["$lid"]['to'] = $match_expressionsInMemory["$expressionName"]['zones'];
                                            }
                                            foreach( $match_expressionsInMemory["$expressionName"]['objects'] as $member )
                                            {
                                                $sub_destinations[] = $member;
                                            }
                                        }
                                        else
                                        {
                                            $valueNorm = normalizeNames($value);

                                            if( $valueNorm == "none" )
                                            {
                                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Source ', $source, 'Check it.', 'rules', $lid, 'security_rules');
                                            }

                                            if( strcmp($value, "ANY") == 0 )
                                            {
                                                $member = new MemberObject("ANY", '', '0.0.0.0', '0');
                                                //echo "              get_sub_policy: The children are ANY\n";
                                                $sub_destinations[] = $member;
                                            }
                                            else
                                            {

                                                if( isset($objectsInMemory['address'][$vsys][$valueNorm]) )
                                                {
                                                    $member_lid = $objectsInMemory['address'][$vsys][$valueNorm]['id'];
                                                    $member_ipaddress = $objectsInMemory['address'][$vsys][$valueNorm]['ipaddress'];
                                                    $member_cidr = $objectsInMemory['address'][$vsys][$valueNorm]['cidr'];
                                                    $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);

                                                    $sub_destinations[] = $member;
                                                }
                                                elseif( isset($objectsInMemory['address_groups_id'][$vsys][$valueNorm]) )
                                                {
                                                    $member_lid = $objectsInMemory['address_groups_id'][$vsys][$valueNorm]['id'];
                                                    $member = new MemberObject($member_lid, "address_groups_id");

                                                    $sub_destinations[] = $member;
                                                }
                                                else
                                                {
                                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "' . $value . '" not supported', $source, 'Source ' . $value . ' not supported. Calculate the required objects', 'rules', $lid, 'security_rules');
                                                }


                                                /*//$getAddress = $projectdb->query("SELECT id, 'address' FROM address WHERE source='$source' AND BINARY name='$match_destination' AND vsys='$vsys' AND zone='$zone_src';");
                                                $query = "SELECT id, ipaddress, cidr FROM address WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';";
                                                $getAddress = $projectdb->query($query);
                                                if ($getAddress->num_rows > 0) {
                                                    $myData = $getAddress->fetch_assoc();
                                                    $member_lid = $myData['id'];
                                                    $member_ip = $myData['ipaddress'];
                                                    $member_cidr = $myData['cidr'];
                                                    $member = new MemberObject($member_lid, 'address', $member_ip, $member_cidr);
                                                    $sub_destinations[] = $member;
                                                } else {
                                                    //$getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$match_destination' AND vsys='$vsys' AND zone='$zone_src';");
                                                    $query = "SELECT id, zone FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';";
                                                    $getGRP = $projectdb->query($query);
                                                    if ($getGRP->num_rows == 1) {
                                                        $myData = $getGRP->fetch_assoc();
                                                        $member_lid = $myData['id'];
                                                        $member = new MemberObject($member_lid, 'address_groups_id');
                                                        $sub_destinations[] = $member;
                                                    } else {
                                                        //TODO:
                                                    }
                                                }*/
                                            }
                                        }
                                    }

                                    //echo "             We got ".count($sub_destinations)." childsources and ".count($rule_destinations)."  parentsources\n";
                                    $resultingDestinationMembers = getCommonMembers($sub_destinations, $rule_destinations, $projectdb, $source, $vsys);
                                    //echo "             The matching resulted in ".count($resultingDestinationMembers) ." new Members\n";

                                    //If the destinations of Parent and Child do not overlap, we can disable this rule :)
                                    if( !isset($resultingDestinationMembers) || count($resultingDestinationMembers) == 0 )
                                    {
                                        $result_is_subrule_disabled = 1;
                                        $sub_rule_tag = $rule_entry['tag'];
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. The rule in subpolicy "' . $subrule_ref . '" position=' . $subRulePosition . ' with original tag="' . $sub_rule_tag . '" does not have destinations matching the parent rule.  Disabled for precaution.', $source, 'Determine whether this rule can be deleted', 'rules', $lid, 'security_rules');
                                        $resultingDestinationMembers = $rule_destinations;
                                        //   break 1;   //This could speed up the parsing, if we don't want to load rules that are invalid and disabled
                                    }


                                    //Checking the service
                                    //echo "           SERVICES\n";
                                    foreach( $access_rule->match_part->match_services->match_service_ref as $match_service )
                                    {
                                        $value = normalizeNames($match_service["value"]);
                                        if( strcmp($value, "ANY") === 0 )
                                        {
                                            $service = new MemberObject("ANY", '', '', '');
                                            $sub_services[] = $service;
                                        }
                                        else
                                        {
                                            $valueNorm = $value;
                                            if( isset($objectsInMemory['services'][$vsys][$valueNorm]) )
                                            {
                                                $service_lid = $objectsInMemory['services'][$vsys][$valueNorm]['id'];
                                                $service_port = $objectsInMemory['services'][$vsys][$valueNorm]['dport'];
                                                $member = new MemberObject($service_lid, "services", $service_port);
                                                $sub_services[] = $member;
                                            }
                                            elseif( isset($objectsInMemory['services_groups_id'][$vsys][$valueNorm]) )
                                            {
                                                $member_lid = $objectsInMemory['services_groups_id'][$vsys][$valueNorm]['id'];
                                                $member = new MemberObject($member_lid, "services_groups_id");
                                                $sub_services[] = $member;
                                            }
                                            else
                                            {
                                                $service_name_ext = $value;
                                                $service_name_int = truncate_names(normalizeNames($service_name_ext));
                                                $serv_description = $service_name_ext;
                                                //Adding the service in the system as an invalid service
                                                $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid) " .
                                                    "VALUES('','$service_name_ext','$service_name_int','','65000','1','$serv_description','$source','','$vsys', '1');";
//                                        echo $query.PHP_EOL;
//                                        echo "Line 1978\n";
                                                $projectdb->query($query);
                                                $member_lid = $projectdb->insert_id;
                                                $member = new MemberObject($member_lid, "services");
                                                $sub_services[] = $member;
                                                $objectsInMemory['services'][$vsys][$valueNorm]['id'] = $member_lid;
                                                $objectsInMemory['services'][$vsys][$valueNorm]['dport'] = "65000";
                                            }

                                            /*$query = "SELECT id, dport FROM services WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';";
                                            $getService = $projectdb->query($query);
                                            if ($getService->num_rows > 0) {
                                                $myData = $getService->fetch_assoc();
                                                $service_lid = $myData['id'];
                                                $service_port = $myData['dport'];
                                                $member = new MemberObject($service_lid, "services",$service_port);
                                                $sub_services[] = $member;
                                            }else{
                                                $getServiceGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$value' AND vsys='$vsys';");
                                                if ($getServiceGRP->num_rows == 1) {
                                                    $myData = $getServiceGRP->fetch_assoc();
                                                    $member_lid = $myData['id'];
                                                    $member = new MemberObject($member_lid, "services_groups_id");
                                                    $sub_services[] = $member;
                                                }else{
                                                    $service_name_ext = $value;
                                                    $service_name_int = truncate_names(normalizeNames($service_name_ext));
                                                    $serv_description = $service_name_ext;
                                                    //Adding the service in the system as an invalid service
                                                    $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid) VALUES('','$service_name_ext','$service_name_int','','65000','1','$serv_description','$source','','$vsys', '1');";
//                                                    echo $query.PHP_EOL;
//                                                    echo "Line 2432\n";
                                                    $projectdb->query($query);   $member_lid = $projectdb->insert_id;
                                                    $member = new MemberObject($member_lid, "services");
                                                    $sub_services[] = $member;
                                                }
                                            }*/
                                        }
                                    }

                                    //echo "             We got ".count($sub_services)." childservices and ".count($rule_services)."  parentservices\n";
                                    $resultingServices = getCommonServices($sub_services, $rule_services, $projectdb, $source, $vsys);
                                    //echo "             The matching resulted in ".count($resultingServices) ." new Services\n";

                                    //If the Services of Parent and Child do not overlap, we can disable this rule :)
                                    if( !isset($resultingServices) || count($resultingServices) == 0 )
                                    {
                                        $result_is_subrule_disabled = 1;
                                        $sub_rule_tag = $rule_entry['tag'];
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. The rule in subpolicy "' . $subrule_ref . '" position=' . $subRulePosition . ' with original tag="' . $sub_rule_tag . '" does not have services matching the parent rule.  Disabled for precaution.', $source, 'Determine whether this rule can be deleted', 'rules', $lid, 'security_rules');
                                        $resultingServices = $rule_services;
                                        //  break 1;   //This could speed up the parsing, if we don't want to load rules that are invalid and disabled
                                    }
                                }


                                //If we managed to find IPs that satisfy the parent rule and child rule, then we should create a new Rule entry
                                if( count($resultingSourceMembers) > 0 && count($resultingDestinationMembers) > 0 && count($resultingServices) > 0 )
                                {
                                    if( $action == "jump" )
                                    {
                                        get_sub_policy($configuration, $subrule_ref2, $result_is_subrule_disabled, $tagids, $vsys,
                                            $source, $project, $resultingSourceMembers, $resultingDestinationMembers, $resultingServices,
                                            $rule, $sources, $destinations, $services, $addTag, $comments, $objectsInMemory);
                                    }
                                    else
                                    {

                                        //Add the sources
                                        foreach( $resultingSourceMembers as $rule_origin )
                                        {
                                            //                                        if(!isset($rule_origin->name)){
                                            //                                            print_r($rule_entry);
                                            //                                            print_r($resultingSourceMembers);
                                            //                                            print_r($rule_origin);
                                            //                                            die;
                                            //                                        }
                                            if( strcmp($rule_origin->name, "ANY") != 0 )
                                            {
                                                $sources[] = "('$source','$vsys','$rule_origin->location','$rule_origin->name','$lid')";
                                            }
                                        }

                                        //Add the destantions
                                        foreach( $resultingDestinationMembers as $rule_destination )
                                        {

                                            if( strcmp($rule_destination->name, "ANY") != 0 )
                                            {
                                                //TODO: Fix the comparision, because the $rule_destination is null at some cases.
                                                $destinations[] = "('$source','$vsys','$rule_destination->location','$rule_destination->name','$lid')";
                                            }
                                        }

                                        //Add the services
                                        foreach( $resultingServices as $rule_service )
                                        {
                                            //                                        if(!isset($rule_service->name)){
                                            //                                            print_r($rule_entry);
                                            //                                            print_r($resultingServices);
                                            //                                            print_r($rule_services);
                                            //                                            die;
                                            //                                        }
                                            if( strcmp($rule_service->name, "ANY") != 0 )
                                            {
                                                $services[] = "('$source','$vsys','$rule_service->location','$rule_service->name','$lid')";
                                            }
                                        }

                                        $ruleDescription = 'Tag[' . $rule_tag . ']';
                                        if( count($comments) > 0 )
                                        {
                                            $ruleDescription .= ' ' . implode('. ', $comments);
                                            $ruleDescription .= '. ' . $localComment;
                                        }

                                        //Add the new rules
                                        $rule[] = "('$lid','$position','Rule $lid','$ruleDescription','$action','$result_is_subrule_disabled','$vsys','$source')";

                                        //Add the tags
                                        if( isset($tagids) )
                                        {
                                            foreach( $tagids as $tagid )
                                            {
                                                $addTag[] = "('$source','$vsys','$lid','$tagid','tag')";
                                            }
                                        }
                                        if( isset($additionalTags) && count($additionalTags) > 0 )
                                        {
                                            foreach( $additionalTags as $tagid )
                                            {
                                                $addTag[] = "('$source','$vsys','$lid','$tagid','tag')";
                                            }
                                            unset($additionalTags);//="";
                                        }


                                        //Increment the rule counters
                                        $lid++;
                                        $position++;
                                    }

                                }
                                else
                                {
                                    $result_is_subrule_disabled = 1;
                                }
                            }
                        }
                    }
                }
                break;  //We found the sub_policy, so we do not need searching for it
            }
        }
    }

}

/**
 * Method to perform SQL Inserts into the services table. One Insert per service, tho.
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $name_ext
 * @param unknown $name_int
 * @param unknown $vsys
 * @param unknown $protocol
 * @param unknown $sport
 * @param unknown $dport
 * @param unknown $description
 */
function services_insert($projectdb, $source, $name_ext, $name_int, $vsys, $protocol, $sport, $dport, $description)
{

    $getDup = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='$name_ext' AND vsys='$vsys';");
    $service_type = null;
    if( $getDup->num_rows == 0 )
    {
        if( preg_match("#([0-9]+)\-([0-9]+)#", $dport) )
        {
            $service_type = "range";
        }
        else
        {
            $service_type = "service";
        }
        if( $sport == "1-65535" )
        {
            $sport = "";
        }
        $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys) VALUES('$service_type','$name_ext','$name_int','$protocol','$dport','0','$description','$source','$sport','$vsys');";
//        echo $query.PHP_EOL;
//        echo "Line 2553\n";
        $projectdb->query($query);
    }
}

function get_Services($configuration, $vsys, $source)
{

    global $projectdb;

    $vsys = "vsys1";

    //TCP services
    /*
     * Sample:
     *    	<service_tcp min_dst_port="1" max_dst_port="2" name="0_TCP-1and2" protocol_agent_ref="AnAgent" protocol_agent_ref_key="1">
                  <pa_value param_description="Allow related connections" value="true"/>
                  <pa_value param_description="Max. length allowed for one TNS packet" value="4096"/>
                  <pa_value param_description="Netmask for allowed server adresses" value="255.255.255.255"/>
                  <pa_value param_description="Set checksum to zero for modified TNS packets" value="Yes"/>
                  <pa_value param_description="Bytes allowed from client before Server ID" value="0"/>
                  <pa_value param_description="Bytes allowed from server before Client ID" value="0"/>
                  <pa_value param_description="Bytes allowed from server before Server ID" value="0"/>
                <pa_value param_description="Make protocol validation" value="true"/>
                  <pa_value param_description="Allow active mode" value="Yes"/>
                  <pa_value param_description="Allow passive mode" value="Yes"/>
                  <pa_value param_description="Allow related connections" value="true"/>
                  <pa_value param_description="Control data inspection mode" value="Loose"/>
                  <pa_value param_description="Highest allowed source port for Active data connection" value="0"/>
                  <pa_value param_description="Lowest allowed source port for Active data connection" value="0"/>
                  <pa_value cisserver_name="none" param_description="Redirect connections to CIS"/>
               </service_tcp>
     */
    $service_tcps = $configuration->xpath("//service_tcp");

    foreach( $service_tcps as $service_tcp )
    {
        $attributes = $service_tcp->attributes();
        $name_ext = normalizeNames($attributes["name"]);
        $name_int = truncate_names(normalizeNames($name_ext));
        $protocol = "tcp";
        $dport = $attributes["min_dst_port"];
        $service_type = null;
        if( isset($attributes["max_dst_port"]) && (int)$attributes["max_dst_port"] != (int)$dport )
        { //Checking is a range of ports is defined
            $dport = $dport . "-" . $attributes["max_dst_port"];
            $service_type = "range";
            //if ($dport == "1-65535") 	$dport = "";
        }
        else
        {
            $service_type = "service";
        }
        $description = addslashes($attributes["comment"]);
        $sport = $attributes["min_src_port"];
        if( isset($attributes["max_src_port"]) && (int)$attributes["max_src_port"] != (int)$dport )
        { //Checking is a range of ports is defined
            $sport = $sport . "-" . $attributes["max_src_port"];
            //if ($sport == "1-65535") 	$sport = "";
        }


        $srv[] = "('$service_type','$name_ext','$name_int','$protocol','$dport','0','$description','$source','$sport','$vsys')";
    }


    //UDP services
    /*
     * Sample:
     * 		   <service_udp max_dst_port="33" max_src_port="54" min_dst_port="22" min_src_port="1" name="UDP_service_1"/>
     */
    $service_udps = $configuration->xpath("//service_udp");

    foreach( $service_udps as $service_udp )
    {
        $attributes = $service_udp->attributes();
        $name_ext = normalizeNames($attributes["name"]);
        $name_int = truncate_names(normalizeNames($name_ext));
        $protocol = "udp";
        $dport = $attributes["min_dst_port"];
        $service_type = null;
        if( isset($attributes["max_dst_port"]) && (int)$attributes["max_dst_port"] != (int)$dport )
        { //Checking is a range of ports is defined
            $dport = $dport . "-" . $attributes["max_dst_port"];
            $service_type = "range";
            if( $dport == "1-65535" ) $dport = "";
        }
        else
        {
            $service_type = "service";
        }
        $description = addslashes($attributes["comment"]);
        $sport = $attributes["min_src_port"];
        if( isset($attributes["max_src_port"]) && (int)$attributes["max_src_port"] != (int)$dport )
        { //Checking is a range of ports is defined
            $sport = $sport . "-" . $attributes["max_src_port"];
            if( $sport == "1-65535" ) $sport = "";
        }

        $srv[] = "('$service_type','$name_ext','$name_int','$protocol','$dport','0','$description','$source','$sport','$vsys')";

    }

    //IP services
    /*
     * Sample:
     * 			<service_ip name="ICMP inspection" protocol_agent_ref="ICMP" protocol_agent_ref_key="4343" protocol_number="1"/>
     */
    $service_ips = $configuration->xpath("//service_ip");

    foreach( $service_ips as $service_ip )
    {
        $attributes = $service_ip->attributes();
        $name_ext = normalizeNames($attributes["name"]);
        $name_int = truncate_names(normalizeNames($name_ext));

        //Probably we would have to know the list of protocol numbers, and do the matching based on it.
        $protocol = $attributes["protocol_number"];

        $dport = $attributes["min_dst_port"];
        $service_type = null;
        if( isset($attributes["max_dst_port"]) && (int)$attributes["max_dst_port"] != (int)$dport )
        { //Checking is a range of ports is defined
            $dport = $dport . "-" . $attributes["max_dst_port"];
            $service_type = "range";
            if( $dport == "1-65535" ) $dport = "";
        }
        else
        {
            $service_type = "service";
        }

        $checkit = "0";
        $description = addslashes($attributes["comment"]);
        $sport = $attributes["min_src_port"];
        if( isset($attributes["max_src_port"]) && (int)$attributes["max_src_port"] != (int)$dport )
        { //Checking is a range of ports is defined
            $sport = $sport . "-" . $attributes["max_src_port"];
            if( $sport == "1-65535" ) $sport = "";
        }

        $srv[] = "('$service_type','$name_ext','$name_int','$protocol','$dport','$checkit','$description','$source','$sport','$vsys')";
    }

    if( count($srv) > 0 )
    {
        $uniq = array_unique($srv);
//        print_r($uniq);
        $out = implode(",", $uniq);
        $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys) VALUES " . $out . ";";
//        echo $query.PHP_EOL;
//        echo "Line 2687\n";
        $projectdb->query($query);
    }
}

function get_ServicesGroups(SimpleXMLElement $configuration, STRING $vsys, STRING $source)
{

    global $projectdb;

    $gen_service_groups = $configuration->xpath("//gen_service_group");
    $tcp_service_groups = $configuration->xpath("//tcp_service_group");
    $udp_service_groups = $configuration->xpath("//udp_service_group");

    $merge_arrays = array_merge($gen_service_groups, $tcp_service_groups, $udp_service_groups);

    $srv = array();
    foreach( $merge_arrays as $service_group )
    {
        $name_ext = trim(normalizeNames($service_group["name"]));
        $name_int = truncate_names(normalizeNames($name_ext));

        $getDup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$name_ext';");
        if( $getDup->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO services_groups_id (name_ext,name,source,vsys) VALUES ('$name_ext','$name_int','$source','$vsys');");
            $lid = $projectdb->insert_id;
            foreach( $service_group->service_ref as $service )
            {
//                $member = normalizeNames($service["ref"]);
                $member = normalizeNames($service["ref"]);
                $getDup = $projectdb->query("SELECT id FROM services_groups WHERE lid='$lid' AND member='$member'; ");
                if( $getDup->num_rows == 0 )
                {
                    $srv[] = "('$lid','$member','$source','$vsys')";
                }
                //Looking for predefined services
                $exist = $projectdb->query("SELECT id FROM services WHERE name_ext in ('$member')");
                if( $exist->num_rows == 0 )
                {
                    //TODO: echo "The service $member should be added by default\n";
                }
            }
        }
    }
    if( count($srv) > 0 )
    {
        $uniq = array_unique($srv);
        $out = implode(",", $uniq);
        $projectdb->query("INSERT INTO services_groups (lid,member,source,vsys) VALUES " . $out . ";");
    }
}

function get_Address_Group(SimpleXMLElement $configuration, STRING $vsys, STRING $source, STRING $policy_to_load, STRING $firewall, $template)
{
    global $projectdb;
    $address_groups = array();

    $query = "SELECT max(id) as lastID FROM address";
    $result = $projectdb->query($query);
    if( $result->num_rows == 1 )
    {
        $data = $result->fetch_assoc();
        $lastAddressID = $data['lastID'];
    }
    else
    {
        $lastAddressID = 1;
    }

    $query = "SELECT max(id) as lastID FROM address_groups_id";
    $result = $projectdb->query($query);
    if( $result->num_rows == 1 )
    {
        $data = $result->fetch_assoc();
        $lastAddress_groupsID = $data['lastID'];
    }
    else
    {
        $lastAddress_groupsID = 1;
    }

    $groups = $configuration->xpath("//group");
    foreach( $groups as $group )
    {
        $name_ext = trim(normalizeNames($group["name"]));
        $description = normalizeNames($group["comment"]);
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) " .
            "VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
        $lid = $projectdb->insert_id;

        foreach( $group->ne_list as $member )
        {
            $ip_address = trim(normalizeNames($member["ref"]));
            $name_int = truncate_names(normalizeNames($ip_address));
            $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys')";
        }
    }


    /*
     * Loading server_pools
     */
    $server_pools = $configuration->xpath("//server_pool");
    foreach( $server_pools as $server_pool )
    {
        $name_ext = trim(normalizeNames($server_pool["name"]));
        $description = normalizeNames($server_pool["comment"]);
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
        $lid = $projectdb->insert_id;

        foreach( $server_pool->ne_list as $ne_list )
        {
            $ip_address = trim(normalizeNames($ne_list["ref"]));
            $name_int = truncate_names(normalizeNames($ip_address));
            $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys')";
        }

    }


    /*
     * Loading log_servers
     */
    $log_servers = $configuration->xpath("//log_server");
    foreach( $log_servers as $log_server )
    {
        $name_ext = trim(normalizeNames($log_server["name"]));
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name, source,vsys) VALUES ('$name_ext','$name_int','$source','$vsys');");
        $lid = $projectdb->insert_id;

        //Get the primary IP
        foreach( $log_server->multi_contact_mvia as $ne_list )
        {
            $ip_address = trim(normalizeNames($ne_list["address"]));
            $name_address = trim(normalizeNames('LogServer_' . $ne_list["address"]));
            $name_internal = truncate_names(normalizeNames($name_address));

            //Search for the AddressObject
            $query = "SELECT id FROM address WHERE source = '$source' AND vsys='$vsys' AND name = '$name_address' LIMIT 1";
            $result_address = $projectdb->query($query);
            if( $result_address->num_rows == 1 )
            {
                $data = $result_address->fetch_assoc();
                $member_lid = $data['id'];
                $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$member_lid','address','$lid','$source','$vsys');");
            }
            else
            {
                $query_Insert_address = "INSERT INTO address (name, name_ext, devicegroup, ipaddress, cidr, source, vsys,vtype) VALUES ('$name_address','$name_internal','default','$ip_address','32','$source', '$vsys','ip-netmask');";
                $projectdb->query($query_Insert_address);
                $address_lid = $projectdb->insert_id;
                $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$address_lid','address','$lid','$source','$vsys');");
            }
        }

        //Get the secondary servers IPs
        foreach( $log_server->secondary_log_server_ref as $secondary )
        {
            $secondary_Name = $secondary['value'];
            $secondary_servers = $configuration->xpath("//log_server[@name='" . $secondary_Name . "']");
            foreach( $secondary_servers as $secondary_server )
            {
                $secondaryIP = $secondary_server->multi_contact_mvia["address"];

                $name_address = trim(normalizeNames('LogServer_' . $secondaryIP));
                $name_internal = truncate_names(normalizeNames($name_address));

                //Search for the AddressObject
                $query = "SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name='$name_address' LIMIT 1";
                $result_address = $projectdb->query($query);
                if( $result_address->num_rows == 1 )
                {
                    $data = $result_address->fetch_assoc();
                    $member_lid = $data['id'];
                    $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$member_lid','address','$lid','$source','$vsys');");
                }
                else
                {
                    $query_Insert_address = "INSERT INTO address (name, name_ext, devicegroup, ipaddress, cidr, source, vsys,vtype) VALUES ('$name_address','$name_internal','default','$ip_address','32', '$source','$vsys','ip-netmask');";
                    $projectdb->query($query_Insert_address);
                    $address_lid = $projectdb->insert_id;
                    $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$address_lid','address','$lid','$source','$vsys');");
                }
            }
        }
    }


    /*
     * Loading aliases
     */
    //<fw_cluster
//    $fw_policies = $configuration->xpath("//fw_policy");
//    $fw_template_policies = $configuration->xpath("//fw_template_policy");
//    $fw_policies = array_merge($fw_policies, $fw_template_policies);
//    foreach ($fw_policies as $fw_policy){
//        $isInMapping = in_array(strval($fw_policy['name']), $mappings);


    $firewall_alias_value = $configuration->xpath("//fw_cluster[@name='" . $firewall . "']/alias_value");

//    die;
//    $aliases = $configuration->xpath("//alias");
//    foreach ($aliases as $alias){
    foreach( $firewall_alias_value as $alias )
    {
        $name_ext = trim(normalizeNames($alias["alias_ref"]));
        $node = dom_import_simplexml($alias);
        $description = normalizeNames(isset($alias["comment"]) ? $alias["comment"] : 'Line ' . $node->getLineNo());
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
        $lid = $projectdb->insert_id;

        foreach( $alias->ne_list as $ne_list )
        {
            $member = trim(normalizeNames($ne_list["ref"]));
            $name_int = truncate_names(normalizeNames($ip_address));
            $address_groups[] = "('$lid','$member','$name_int','$member','$source', '$vsys')";
        }
    }


    //Insert all the relations
    if( count($address_groups) > 0 )
    {
        $uniq = array_unique($address_groups);
        $out = implode(",", $uniq);
        $query = "INSERT INTO address_groups (lid, name_ext,name,member,source,vsys) VALUES " . $out . ";";
        $projectdb->query($query);
    }

}

/**
 *
 */
function get_Exclusions(SimpleXMLElement $configuration, STRING $vsys, STRING $source)
{
    global $projectdb;

    $ip_address_ranges = array();
    $address_groups = array();
    /*
    * We start looking for exclusion groups
    * We will have to check whether a group is excluded or not during the rule creation
    */
    $expressions = $configuration->xpath("//expression");
    foreach( $expressions as $expression )
    {
        if( $expression["operator"] == "exclusion" )
        {
            $name_ext = trim(normalizeNames($expression["name"]));
            $description = normalizeNames($expression["comment"]);
            $name_int = truncate_names(normalizeNames($name_ext));

            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, filter, source,vsys) VALUES ('$name_ext','$name_int','$description','exclusion-group','$source','$vsys');");
            $lid = $projectdb->insert_id;

            $fakeMapping['map'][] = array('start' => 0, 'end' => ip2long('255.255.255.255'));


            foreach( $expression->expression_value as $expression_value )
            {
                $value = normalizeNames($expression_value["ne_ref"]);

                //Look for this member ONLY for IPv4 by now
                $getInfoMembers = $projectdb->query("SELECT id FROM address WHERE name_ext = '$value' AND v4=1;");
                if( $getInfoMembers->num_rows > 0 )
                {
                    $dataM = $getInfoMembers->fetch_assoc();
                    $member_lid = $dataM['id'];
                    $table_name = "address";
                }
                else
                {
                    $getInfoMembers = $projectdb->query("SELECT id FROM address_groups_id WHERE name_ext = '$value';");
                    if( $getInfoMembers->num_rows > 0 )
                    {
                        $dataM = $getInfoMembers->fetch_assoc();
                        $member_lid = $dataM['id'];
                        $table_name = "address_groups_id";
                    }
                    else
                    {
                        $member_lid = '';
                        $table_name = "address_groups_id";
                    }
                }

                $objectsMapping = getIP4Mapping("", $member_lid, $table_name);

                foreach( $objectsMapping['map'] as $entry )
                {
                    removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
                    //$objectsMapping = $fakeMapping;
                }
            }

            $descriptionRange = normalizeNames("Automatically generated from $name_ext. $description");
            foreach( $fakeMapping['map'] as $fakeRange )
            {
                $ipRange = long2ip($fakeRange['start']) . "-" . long2ip($fakeRange['end']);
                $nameRange = "$name_ext-Range_$ipRange";
                $name_int = truncate_names(normalizeNames($nameRange));
                $ip_address_ranges[] = "('$nameRange','$name_int', '$ipRange','', 1, 0, 'ip-range', 'ip-range', '$descriptionRange','$source', '$vsys')";
                $address_groups[] = "('$lid','$nameRange','$name_int','$nameRange','$source', '$vsys')";
            }

            //Insert all the ranges
            if( count($ip_address_ranges) > 0 )
            {
                $uniq = array_unique($ip_address_ranges);
                $out = implode(",", $uniq);
                $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys) VALUES " . $out . ";");
                $uniq = array_unique($address_groups);
                $out = implode(",", $uniq);
                $projectdb->query("INSERT INTO address_groups (lid, name_ext,name,member,source,vsys) VALUES " . $out . ";");
            }
        }
    }
}

function get_AddressExpressions(SimpleXMLElement $configuration, STRING $vsys, STRING $source, $template)
{
    global $projectdb;
    global $match_expressionsInMemory;

    $inMemory = array();
    $query = "SELECT * FROM address WHERE vsys='$vsys' AND source='$source'";
    $result = $projectdb->query($query);
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $nombre = $data['name'];
            $inMemory['address'][$nombre] = $data;
        }
    }

    $query = "SELECT * FROM address_groups_id WHERE vsys='$vsys' AND source='$source'";
    $result = $projectdb->query($query);
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $nombre = $data['name'];
            $inMemory['address_groups_id'][$nombre] = $data;
        }
    }

    $query = "SELECT * FROM zones WHERE vsys='$vsys' AND source='$source'";
    $result = $projectdb->query($query);
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $nombre = $data['name'];
            $inMemory['zones'][$nombre] = $data;
        }
    }

    $match_expressions = $configuration->xpath("//match_expression");
    foreach( $match_expressions as $match_expression )
    {
        $name = $match_expression['name'];
        foreach( $match_expression->match_element_entry as $element_entry )
        {
            $reference = $element_entry['ref'];
            if( isset($inMemory['zones']["$reference"]) )
            {
                $match_expressionsInMemory["$name"]['zones'][] = $reference->__toString();
            }
            else
            {
                if( isset($inMemory['address']["$reference"]) )
                {
                    $id = $inMemory['address']["$reference"]['id'];
                    $ip = $inMemory['address']["$reference"]['ipaddress'];
                    $cidr = $inMemory['address']["$reference"]['cidr'];
                    $member = new MemberObject($id, "address", $ip, $cidr);
                }
                elseif( isset($inMemory['address_groups_id']["$reference"]) )
                {
                    $id = $inMemory['address_groups_id']["$reference"]['id'];
                    $member = new MemberObject($id, "address_groups_id");
                }
                else
                {
                    $member = null;
                }
                $match_expressionsInMemory["$name"]['objects'][] = $member;
            }
        }
    }

}




?>
