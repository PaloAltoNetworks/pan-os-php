<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/shared.php';
require_once INC_ROOT . '/libs/common/lib-rules.php';
require_once INC_ROOT . '/libs/common/MemberObject.php';
require_once INC_ROOT . '/libs/projectdb.php';
require_once INC_ROOT . '/libs/objects/SecurityRulePANObject.php';

use PaloaltoNetworks\Policy\Objects\MemberObject;

# ONLY FOR TESTING REMOVE IT
//$checkpointName="";
//$project="testing2";
//$action="import";
//$jobid=1;
# ##########################

class Schedules
{
    public $name;
    public $recurrence;
    public $uid;
    public $startDate;
    public $startTime;
    public $endDate;
    public $endTime;
    public $vsys;
    public $source;

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if( method_exists($this, $f = '__construct' . $i) )
        {
            call_user_func_array(array($this, $f), $a);
        }
    }

    public function __construct4($uid, $name, $source, $vsys)
    {
        $this->name = $name;
        $this->uid = $uid;
        $this->source = $source;
        $this->vsys = $vsys;
    }

    public function addDateTime($startEnd, $date, $time)
    {
        switch ($startEnd)
        {
            case "start":
                $this->startDate = $date;
                $this->startTime = $time;
                break;
            case "end":
                $this->endDate = $date;
                $this->endTime = $time;
                break;

            default:

        }
    }

    public function addRecurrence()
    {

    }

}


require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
global $app;
include INC_ROOT . '/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);

$sourcesAdded = array();
global $source;

if( $noDNAT == "1" )
{
    $skipDNAT = TRUE;
}
else
{
    $skipDNAT = FALSE;
}

if( $action == "import" )
{
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    update_progress($project, '0.00', 'Reading config files', $jobid);

    $index = USERSPACE_PATH . "/projects/" . $project . "/security/index.json";
    $policiesList = read_index($project, $index);
    $domain = $policiesList['domain'];

    if( $policiesList['code'] == TRUE )
    {
        if( $policiesList['objects'] != "" )
        {
            $myObjects = load_policy($policiesList['objects'], $project, $jobid);

            #Check if is the first vsys
            if( $checkpointName == "" )
            {
                if( $policiesList['accessLayerName'] != "" )
                {
                    $filename = $policiesList['accessLayerName'];
                }
                else
                {
                    $filename = unique_id(10);
                }

            }
            else
            {
                $filename = $checkpointName;
            }

            $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
            if( $getVsys->num_rows == 0 )
            {
                $vsys = "vsys1";
                if( $domain != "" )
                {
                    $vsys = normalizeNames($domain);
                }
                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','$vsys','Checkpoint')");

                $source = $projectdb->insert_id;
                $sourcesAdded[] = $source;
            }
            else
            {
                echo "FILENAME $filename ALREADY IMPORTED. SKIPPING" . PHP_EOL;
                update_progress($project, '-1', 'configuration already imported. Skipping', $jobid);
                exit(0);
            }

            #Config Template
            $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
            $template_name = $filename . "_template";
            $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
            $template = $projectdb->insert_id;

            #Explode Members
            update_progress($project, '0.10', 'Phase 1 of 10 -  Reading Objects', $jobid);

            $myObjectsAll = explodeGroups2MembersCheckpoint($myObjects, 0);
            $getObjects = get_objects($myObjectsAll, $source, $vsys, $filename);

            # Calculate Excluded Groups
            calculateExclusionGroups($source);

        }

        if( $policiesList['accessLayers'] != "" )
        {

            $myRules = load_policy($policiesList['accessLayers'], $project, $jobid);
            # Read Security Rules
            update_progress($project, '0.20', 'Phase 2 of 10 - Reading Access Policies', $jobid);
            if( count($myRules) > 0 )
            {
                get_security_policies($myRules, $source, $vsys, $filename, $getObjects);
            }
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
        check_used_objects_new();

        update_progress($project, '1.0', 'Done', $jobid);
    }
    else
    {
        # No Index file
        echo "NO INDEX FILE FOUND" . PHP_EOL;
        update_progress($project, '-1', 'NO INDEX FILE FOUND', $jobid);
        exit(0);
    }


}

function load_policy($policy, $project, $jobid)
{

    $objectFile = str_replace(".html", ".json", $policy);
    $objectFile = USERSPACE_PATH . "/projects/" . $project . "/security/" . $objectFile;

    # Add the brackets at the end and begining of the file and decode correctly.
    $myRules[] = "[";
    $myRules[] = file_get_contents($objectFile);
    $myRules[] = "]";
    $json = implode("", $myRules);
    $json = anything_to_utf8($json);

    if( isValidJson($json) )
    {
        $myRules = json_decode($json, TRUE);
    }
    else
    {
        echo "INVALID RULES JSON FILE" . PHP_EOL;
        update_progress($project, '-1', 'RULES - JSON FILE IS INVALID', $jobid);
        exit(0);
    }
    return $myRules;
}

function get_security_policies(array $myRules, $source, $vsys, $filename, $getObjects)
{
    global $projectdb;
    global $jobid;
    global $project;
    global $domain;

    # Split the Objects from getObjects Array;
    $common = $objects = $schedules = $accessLayers = $accesRoles = array();

    if( isset($getObjects['common']) )
    {
        $common = $getObjects['common'];
    }

    if( isset($getObjects['objects']) )
    {
        $objects = $getObjects['objects'];
    }

    if( isset($getObjects['schedules']) )
    {
        $schedules = $getObjects['schedules'];
    }

    if( isset($getObjects['accessLayers']) )
    {
        $accessLayers = $getObjects['accessLayers'];
    }

    if( isset($getObjects['accessRole']) )
    {
        $accesRoles = $getObjects['accessRole'];
    }


    #Get Last lid from Rules
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules WHERE source='$source' AND vsys='$vsys';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;
    $uniqueRules = array();
    $add_tag = array();
    $add_rule = array();
    $rule_source = array();
    $rule_destination = array();
    $thecolor = 1;

    foreach( $myRules as $rule )
    {

        if( isset($rule['header']) )
        {
            if( $rule['header'] == "" )
            {
                $name = "";
            }
            else
            {
                $name = $rule['header'];
            }
        }
        else
        {
            $name = "";
        }
        $type = $rule['type'];

        switch ($type)
        {
            case "access-section":
                $ruleSection = $rule;
                if( (isset($ruleSection['rulebase'])) and (count($ruleSection['rulebase']) > 0) )
                {
                    $color = "color" . $thecolor;

                    if( isset($ruleSection['name']) )
                    {
                        $name = truncate_tags($ruleSection['name']);
                        $tag_id = add_tag($name, $source, $vsys, $color);
                        if( $thecolor == 16 )
                        {
                            $thecolor = 1;
                        }
                        else
                        {
                            $thecolor++;
                        }
                    }
                    else
                    {
                        $tag_id = "";
                    }

                    foreach( $ruleSection['rulebase'] as $ruleItem )
                    {
                        insert_security_policy($ruleItem, $tag_id, $source, $vsys, $lid, $position, $add_rule, $name, $thecolor, $add_tag,
                            $rule_source, $rule_destination, $rule_service, $objects, $accesRoles, $schedules, $accessLayers, $domain, $jobid,
                            $project, $common, $uniqueRules);
                    }
                }
                break;
            case "access-rule":
                insert_security_policy($rule, "", $source, $vsys, $lid, $position, $add_rule, $name, $thecolor, $add_tag,
                    $rule_source, $rule_destination, $rule_service, $objects, $accesRoles, $schedules, $accessLayers, $domain, $jobid,
                    $project, $common, $uniqueRules);

                break;
            default:
                print_r($rule);
                break;
        }
    }

    if( count($add_rule) > 0 )
    {
        $projectdb->query("INSERT INTO security_rules (id,disabled,negate_source,negate_destination,action,target,name,description,source,vsys,position,preorpost,checkit) VALUES " . implode(",", $add_rule) . ";");
        unset($add_rule);
    }
    if( count($add_tag) > 0 )
    {
        $projectdb->query("INSERT INTO security_rules_tag (rule_lid,source,member_lid,table_name,vsys) VALUES " . implode(",", $add_tag) . ";");
        unset($add_tag);
    }
    if( count($rule_source) > 0 )
    {
        $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $rule_source) . ";");
        unset($rule_source);
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
}

function insert_security_policy($ruleItem, $tag_id, $source, $vsys, &$lid, &$position, &$add_rule, $name, &$thecolor, &$add_tag, &$rule_source,
                                &$rule_destination, &$rule_service, $objects, $accesRoles, $schedules, $accessLayers, $domain, $jobid, $project, $common, &$uniqueRules)
{

    global $projectdb;

    $any = trim($common["any"]);
    $all = trim($common["all"]);

    $rule_origins = array();
    $rule_destinations = array();
    $rule_services = array();

    $uuid = $ruleItem['uid'];
    if( !isset($uniqueRules[$uuid]) )
    {
        $uniqueRules[$uuid] = $uuid;
        if( $ruleItem['type'] == "access-rule" )
        {
            $preorpost = 0;
            $checkit = 0;

            if( $name != "" )
            {
                $color = "color" . $thecolor;
                $tag_id = add_tag($name, $source, $vsys, $color);
                if( $thecolor == 16 )
                {
                    $thecolor = 1;
                }
                else
                {
                    $thecolor++;
                }
            }
            else
            {
                $tag_id = "";
            }

            if( $ruleItem['action'] )
            {
                $action_tmp = array_search($ruleItem['action'], $common);
                if( $action_tmp !== FALSE )
                {
                    $action = $action_tmp;
                }
                else
                {
                    # Create Error action is not in common and add action = deny
                    $action = "deny";
                    $checkit = 1;
                }
            }

            $ruleNumber = trim($ruleItem['rule-number']);

            if( !isset($ruleItem['name']) )
            {
                $ruleName = truncate_rulenames("Rule " . $ruleNumber);
            }
            else
            {
                $ruleName = truncate_rulenames(normalizeNames(trim($ruleItem['name'])));
            }

            $comments = addslashes($ruleItem['comments']);
            if( $tag_id != "" )
            {
                $add_tag[] = "('$lid','$source','$tag_id','tag','$vsys')";
            }
            if( $ruleItem['source-negate'] === FALSE )
            {
                $negate_source = 0;
            }
            else
            {
                $negate_source = 1;
            }
            if( $ruleItem['source'] )
            {
                foreach( $ruleItem['source'] as $src )
                {
                    if( $src != $any )
                    {
                        if( $ruleNumber == 1 )
                        {
                            // print_r($src);
                        }

                        if( isset($accesRoles[$src]) )
                        {
                            $userMapping[$lid] = $accesRoles[$src];
                        }
                        else
                        {
                            if( isset($objects[$src]) )
                            {
                                $table_name = $objects[$src]['table_name'];
                                $member_lid = $objects[$src]['member_lid'];

                                $rule_source[] = "('$source','$vsys','$lid','$table_name','$member_lid')";

                                if( $table_name == "address" )
                                {
                                    $member_ipaddress = $objects[$src]['ipaddress'];
                                    $member_cidr = $objects[$src]['cidr'];
                                    $member = new MemberObject($member_lid, $table_name, $member_ipaddress, $member_cidr);
                                    $rule_origins[] = $member;
                                }
                                else
                                {
                                    $member = new MemberObject($member_lid, $table_name);
                                    $rule_origins[] = $member;
                                }

                            }
                            else
                            {
                                echo "OBJECT NOT FOUND as SOURCE" . PHP_EOL;
                            }
                        }
                    }
                }
                if( $negate_source == 1 )
                {
                    echo "ORIGINAL SOURCE:" . PHP_EOL;
                    print_r($rule_origins);
                    echo "NEGATING IT" . PHP_EOL;
                    print_r(negateAddress($projectdb, $rule_origins));

                }
            }
            if( $ruleItem['destination-negate'] === FALSE )
            {
                $negate_destination = 0;
            }
            else
            {
                $negate_destination = 1;
            }
            if( $ruleItem['destination'] )
            {
                foreach( $ruleItem['destination'] as $src )
                {
                    if( $src != $any )
                    {

                        if( isset($accesRoles[$src]) )
                        {
                            echo "USER AS DESTINATION !!!!" . PHP_EOL;
                            //$userMapping[$lid]=$accesRoles[$src];
                        }
                        else
                        {
                            if( isset($objects[$src]) )
                            {
                                $table_name = $objects[$src]['table_name'];
                                $member_lid = $objects[$src]['member_lid'];

                                $rule_destination[] = "('$source','$vsys','$lid','$table_name','$member_lid')";

                                if( $table_name == "address" )
                                {
                                    $member_ipaddress = $objects[$src]['ipaddress'];
                                    $member_cidr = $objects[$src]['cidr'];
                                    $member = new MemberObject($member_lid, $table_name, $member_ipaddress, $member_cidr);
                                    $rule_destinations[] = $member;
                                }
                                else
                                {
                                    $member = new MemberObject($member_lid, $table_name);
                                    $rule_destinations[] = $member;
                                }
                            }
                            else
                            {
                                echo "OBJECT NOT FOUND as DESTINATION" . PHP_EOL;
                            }
                            //list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Security',$lid);
                            //$rule_destination[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                        }

                    }
                }
                if( $negate_destination == 1 )
                {
                    echo "ORIGINAL SOURCE:" . PHP_EOL;
                    print_r($rule_origins);
                    echo "NEGATING IT" . PHP_EOL;
                    print_r(negateAddress($projectdb, $rule_origins));

                }
            }
            if( $ruleItem['time'] )
            {
                foreach( $ruleItem['time'] as $src )
                {
                    if( ($src == $any) or ($src == $all) )
                    {
                    }
                    else
                    {
                        add_log2("error", "Importing Security Rules", "Time object found [" . $schedules[$src] . "] in Rule [" . $lid . "]", $source, "Fix it Manually", "rules", $lid, "security_rules");
                    }
                }
            }
            if( $ruleItem['service'] )
            {
                foreach( $ruleItem['service'] as $src )
                {
                    if( $src != $any )
                    {
                        if( isset($objects[$src]) )
                        {
                            $table_name = $objects[$src]['table_name'];
                            $member_lid = $objects[$src]['member_lid'];
                            $rule_service[] = "('$source','$vsys','$lid','$table_name','$member_lid')";
                        }
                        else
                        {
                            echo "OBJECT NOT FOUND as SERVICE " . $src . PHP_EOL;
                        }
                        //list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Security',$lid);
                        //$rule_service[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                    }
                }
            }
            if( $ruleItem['service-negate'] === TRUE )
            {
                # Generate Error Negated Service is not supported
                add_log2("error", "Importing Security Rules", "Negated Service found in Rule [" . $lid . "]", $source, "Fix it Manually", "rules", $lid, "security_rules");
                $checkit = 1;
            }
            if( $ruleItem['enabled'] === TRUE )
            {
                $rule_enabled = 0;
            }
            else
            {
                $rule_enabled = 1;
            }

            if( (isset($ruleItem['inline-layer'])) and (isset($accessLayers[$ruleItem['inline-layer']])) )
            {
                $rule_enabled = 0;
                $add_rule[] = "('$lid','$rule_enabled','$negate_source','$negate_destination','$action','','$ruleName','$comments','$source','$vsys','$position','$preorpost','$checkit')";
                $lid++;
                $position++;

                echo $ruleItem['inline-layer'];
                print_r($accessLayers[$ruleItem['inline-layer']]);
                $policy2load = $accessLayers[$ruleItem['inline-layer']]['name'] . "-" . $domain . ".html";
                echo "Loading Inline Rules from: " . $policy2load;
                $loadInlineRules = load_policy($policy2load, $project, $jobid);

                get_sub_policy($loadInlineRules, $ruleName, $rule_enabled, $tagids, $vsys,
                    $source, $project, $rule_origins, $rule_destinations, $rule_services,
                    $add_rule, $sources, $destinations, $services, $addTag, $comments, $objects, $accesRoles, $schedules, $accessLayers, $common);

            }
            else
            {
                $add_rule[] = "('$lid','$rule_enabled','$negate_source','$negate_destination','$action','','$ruleName','$comments','$source','$vsys','$position','$preorpost','$checkit')";
                $lid++;
                $position++;
            }


        }
    }
}

function get_sub_policy($loadInlineRules, $ruleName, $rule_enabled, &$tagids, $vsys,
                        $source, $project, $rule_origins, $rule_destinations, $rule_services,
                        &$rule, &$sources, &$destinations, &$services, &$addTag, &$comments, $objects, $accesRoles, $schedules, $accessLayers, $common)
{

    global $lid;
    global $position;
    global $projectdb;
    global $thecolor;
    global $jobid;
    global $domain;

    //Defining variables I will globally use in this function
    $resultingSourceMembers = null;
    $resultingDestinationMembers = null;
    $resultingServices = null;

    echo "Entering in Subpolicy" . PHP_EOL;
    echo "ORIGINAL SOURCES";
    print_r($rule_origins);
    echo "ORIGINAL DESTINATIONS";
    print_r($rule_destinations);
    echo "ORIGINAL SERVICE";
    print_r($rule_services);

    foreach( $loadInlineRules as $rule )
    {

        if( isset($rule['header']) )
        {
            if( $rule['header'] == "" )
            {
                $name = "";
            }
            else
            {
                $name = $rule['header'];
            }
        }
        else
        {
            $name = "";
        }
        $type = $rule['type'];

        switch ($type)
        {
            case "access-section":
                $ruleSection = $rule;
                if( (isset($ruleSection['rulebase'])) and (count($ruleSection['rulebase']) > 0) )
                {
                    $color = "color" . $thecolor;

                    if( isset($ruleSection['name']) )
                    {
                        $name = truncate_tags($ruleSection['name']);
                        $tag_id = add_tag($name, $source, $vsys, $color);
                        if( $thecolor == 16 )
                        {
                            $thecolor = 1;
                        }
                        else
                        {
                            $thecolor++;
                        }
                    }
                    else
                    {
                        $tag_id = "";
                    }

                    foreach( $ruleSection['rulebase'] as $ruleItem )
                    {
                        insert_security_policy($ruleItem, $tag_id, $source, $vsys, $lid, $position, $add_rule, $name, $thecolor, $add_tag,
                            $rule_source, $rule_destination, $rule_service, $objects, $accesRoles, $schedules, $accessLayers, $domain, $jobid,
                            $project, $common, $uniqueRules);
                    }
                }
                break;
            case "access-rule":
                insert_security_policy($rule, "", $source, $vsys, $lid, $position, $add_rule, $name, $thecolor, $add_tag,
                    $rule_source, $rule_destination, $rule_service, $objects, $accesRoles, $schedules, $accessLayers, $domain, $jobid,
                    $project, $common, $uniqueRules);

                break;
            default:
                echo "UNCAUGHT!!! ->>>" . PHP_EOL;
                print_r($rule);
                break;
        }
    }


}

function add_tag($name, $source, $vsys, $color)
{
    global $projectdb;
    $name = normalizeNames($name);
    $exist = $projectdb->query("SELECT id FROM tag WHERE name='$name' AND source='$source' AND vsys='$vsys'");
    if( $exist->num_rows == 0 )
    {
        $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$name','$source','$vsys','$color');");
        $id = $projectdb->insert_id;
    }
    else
    {
        $existsData = $exist->fetch_assoc();
        $id = $existsData['id'];
    }
    return $id;
}

function calculateExclusionGroups($source)
{

    global $projectdb;

    $getLid = $projectdb->query("SELECT id, vsys, source, devicegroup FROM address_groups_id WHERE type = 'group_with_exclusion' AND source='$source';");

    if( $getLid->num_rows > 0 )
    {
        while( $dataLid = $getLid->fetch_assoc() )
        {
            $lid = $dataLid['id'];
            $vsys = $dataLid['vsys'];
            $source = $dataLid['source'];
            $devicegroup = $dataLid['devicegroup'];

            $incGroupExpanded = array();
            $exclGroupExpanded = array();
            $res = array();

            $incGroupExpanded_p = expandMembersGroups($lid, "1");
            $exclGroupExpanded_p = expandMembersGroups($lid, "4");

            // create IP mappings for all objects
            foreach( $incGroupExpanded_p as $index => $object )
            {

                if( $object['table_name'] == "address_groups_id" )
                {
                    $incGroupExpanded = expandMembersGroups($object['member_lid'], "3");
                    foreach( $incGroupExpanded as $index => $object2 )
                    {

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        //long2IP not working IPv6 address
                        $incGroupExpanded[$index] = array('object' => $object2['member'], 'member_lid' => $object2['member_lid'], 'table_name' => $object2['table_name'], 'start' => $res['start'],
                            'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']), 'status' => 0);

                    }

                }
                else
                {

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    //long2IP not working IPv6 address
                    $incGroupExpanded[$index] = array('object' => $object['member'], 'member_lid' => $object['member_lid'], 'table_name' => $object['table_name'], 'start' => $res['start'],
                        'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']), 'status' => 0);
                }
            }

            foreach( $exclGroupExpanded_p as $index => $object )
            {

                if( $object['table_name'] == "address_groups_id" )
                {
                    $exclGroupExpanded = expandMembersGroups($object['member_lid'], "3");

                    foreach( $exclGroupExpanded as $index => $object2 )
                    {

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        //long2IP not working IPv6 address
                        $exclGroupExpanded[$index] = array('object' => $object2['member'], 'member_lid' => $object2['member_lid'], 'table_name' => $object2['table_name'], 'start' => $res['start'],
                            'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']));

                    }

                }
                else
                {

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    //long2IP not working IPv6 address
                    $exclGroupExpanded[$index] = array('object' => $object['member'], 'member_lid' => $object['member_lid'], 'table_name' => $object['table_name'], 'start' => $res['start'],
                        'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']));
                }
            }

            //  Now we need to match all excl vs inc objects
            foreach( $exclGroupExpanded as $index => &$excl )
            {
                foreach( $incGroupExpanded as &$incl )
                {
                    // this object was already fully matched so we skip
                    if( $incl['status'] == 2 ) continue;
                    if( $incl['start'] >= $excl['start'] && $incl['end'] <= $excl['end'] )
                    {
                        $incl['status'] = 2;
                    }
                    elseif( $incl['start'] >= $excl['start'] && $incl['start'] <= $excl['end'] || $incl['end'] >= $excl['start'] && $incl['end'] <= $excl['end']
                        || $incl['start'] <= $excl['start'] && $incl['end'] >= $excl['end'] )
                    {
                        $incl['status'] = 1;
                    }
                }
            }//fin foreach

            // First filter is done, now we make a list of Incl objects :
            // - Partial matches, these ones will require special treatment
            // - FULL matches, these ones will not be included in final group
            // - NO matches, these ones will be included in final group
            $inclPartial = array();
            $inclNo = array();


            foreach( $incGroupExpanded as &$incl )
            {

                if( ($incl['status'] == 1) || ($incl['status'] == 2) )
                {
                    $inclPartial[] = &$incl;
                }
                elseif( $incl['status'] == 0 )
                {
                    $inclNo[] = &$incl;
                }
            }

            // Sort incl objects IP mappings by Start IP
            $inclMapping = array();
            $tmp = array();
            foreach( $inclPartial as &$incl )
            {
                $tmp[] = $incl['start'];
            }
            unset($incl);
            sort($tmp, SORT_NUMERIC);
            foreach( $tmp as $value )
            {
                foreach( $inclPartial as &$incl )
                {
                    if( $value == $incl['start'] )
                    {
                        $inclMapping[] = $incl;
                    }
                }
            }
            unset($incl);

            // Sort excl objects IP mappings by Start IP
            $exclMapping = array();
            $tmp = array();
            foreach( $exclGroupExpanded as &$excl )
            {
                $tmp[] = $excl['start'];
            }
            unset($excl);
            sort($tmp, SORT_REGULAR);
            foreach( $tmp as $value )
            {
                foreach( $exclGroupExpanded as &$excl )
                {
                    if( $value == $excl['start'] )
                    {
                        $exclMapping[] = $excl;
                    }
                }
            }
            unset($excl);

            // Merge overlapping or Incl joint entries
            $mapKeys = array_keys($inclMapping);
            $mapCount = count($inclMapping);
            for( $i = 0; $i < $mapCount; $i++ )
            {
                $current = &$inclMapping[$mapKeys[$i]];
                for( $j = $i + 1; $j < $mapCount; $j++ )
                {
                    $compare = &$inclMapping[$mapKeys[$j]];

                    if( $compare['start'] > $current['end'] + 1 )
                        break;

                    $current['end'] = $compare['end'];
                    $current['endip'] = $compare['endip'];
                    unset($inclMapping[$mapKeys[$j]]);
                    $i++;
                }
            }

            // Merge overlapping or joint Excl entries
            $mapKeys = array_keys($exclMapping);
            $mapCount = count($exclMapping);
            for( $i = 0; $i < $mapCount; $i++ )
            {
                $current = &$exclMapping[$mapKeys[$i]];
                for( $j = $i + 1; $j < $mapCount; $j++ )
                {
                    $compare = &$exclMapping[$mapKeys[$j]];

                    if( $compare['start'] > $current['end'] + 1 )
                        break;

                    $current['end'] = $compare['end'];
                    $current['endip'] = $compare['endip'];
                    unset($exclMapping[$mapKeys[$j]]);
                    $i++;
                }
            }

            // Calculate IP RANGE HOLES !!!
            foreach( $inclMapping as $index => &$incl )
            {
                $current = &$incl;

                foreach( $exclMapping as &$excl )
                {
                    if( $excl['start'] > $current['end'] )
                        continue;
                    if( $excl['start'] < $current['start'] && $excl['end'] < $current['start'] )
                        continue;
                    // if this excl object is including ALL
                    if( $excl['start'] <= $current['start'] && $excl['end'] >= $current['end'] )
                    {
                        unset($inclMapping[$index]);
                        break;
                    }
                    elseif( $excl['start'] <= $current['start'] && $excl['end'] <= $current['end'] )
                    {
                        $current['start'] = $excl['end'];
                        $current['startip'] = $excl['endip'];
                    }
                    elseif( $excl['start'] > $current['start'] && $excl['end'] >= $current['end'] )
                    {
                        //long2IP not working IPv6 address
                        $current['end'] = $excl['start'] - 1;
                        $current['endip'] = long2ip($current['end']);
                        break;
                    }
                    elseif( $excl['start'] > $current['start'] && $excl['end'] < $current['end'] )
                    {
                        $oldEnd = $current['end'];
                        $oldEndIP = $current['endip'];
                        $current['end'] = $excl['start'] - 1;
                        $current['endip'] = long2ip($current['end']);
                        unset($current);

                        $current = array();
                        $inclMapping[] = &$current;
                        $current['start'] = $excl['end'] + 1;
                        $current['startip'] = long2ip($current['start']);
                        $current['end'] = $oldEnd;
                        $current['endip'] = $oldEndIP;
                    }
                }
            }

            // Sort incl objects IP mappings by Start IP
            $finalInclMapping = array();
            $tmp = array();
            foreach( $inclMapping as &$incl3 )
            {
                $tmp[] = $incl3['start'];
            }
            unset($incl3);

            sort($tmp, SORT_NUMERIC);
            $is_first = 0;
            $members_news = array();
            foreach( $tmp as $value )
            {
                foreach( $inclMapping as &$incl )
                {
                    if( $value == $incl['start'] )
                    {
                        $oValue = $incl['startip'] . "-" . $incl['endip'];

                        $oName = 'R-' . $incl['startip'] . "-" . $incl['endip'];
                        $finalInclMapping[] = $incl;

                        $members_news[] = $oName;

                        $getExistAddress = $projectdb->query("SELECT id FROM address WHERE name = '$oName' AND type = 'ip-range' AND ipaddress = '$oValue' AND vsys = '$vsys' AND source = '$source' ");
                        if( $getExistAddress->num_rows == 1 )
                        {
                            while( $data = $getExistAddress->fetch_assoc() )
                            {
                                $member_lid = $data['id'];
                            }
                        }
                        else
                        {
                            $projectdb->query("INSERT INTO address (id, name_ext, name, used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified) "
                                . "VALUES (NULL, '$oName', '$oName', '', '', '$devicegroup', '$vsys', 'ip-range','$oValue','', '', '', '', '', 'ip-range', '$source', '', '', '', '');");

                            $member_lid = $projectdb->insert_id;
                        }

                        if( $is_first == 0 )
                        {

                            $name_int_old = array();

                            $getNameGroup = $projectdb->query("SELECT name FROM address_groups_id WHERE id = '$lid' ");
                            if( $getNameGroup->num_rows == 1 )
                            {
                                $dataNG = $getNameGroup->fetch_assoc();
                                $group_name = $dataNG['name'];
                            }

                            $getMembersGroups = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid = '$lid' ");
                            if( $getMembersGroups->num_rows >= 1 )
                            {
                                while( $dataM = $getMembersGroups->fetch_assoc() )
                                {
                                    $member_lid_g = $dataM['member_lid'];
                                    $table_name_g = $dataM['table_name'];

                                    $getMembersGroupsN = $projectdb->query("SELECT name FROM $table_name_g WHERE id = '$member_lid_g' ");
                                    if( $getMembersGroupsN->num_rows == 1 )
                                    {
                                        $dataN = $getMembersGroupsN->fetch_assoc();
                                        $name_int_old[] = $dataN['name'];
                                    }
                                }
                            }

                            $projectdb->query("DELETE FROM address_groups WHERE lid = '$lid' ");
                            $is_first = 1;
                        }

                        $projectdb->query("INSERT INTO address_groups (id, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source) "
                            . "VALUES (NULL, '', '', '$devicegroup', '$vsys', '$oName', '$member_lid', 'address', '$lid', '$source');");

                    }
                }
            }

            // Añadir el resto de miembros
            foreach( $inclNo as &$incl2 )
            {

                $name_int_no = $incl2['object'];
                $member_lid_no = $incl2['member_lid'];
                $table_name_no = $incl2['table_name'];
                $getExistMember = $projectdb->query("SELECT id FROM address_groups WHERE member_lid = '$member_lid_no' AND table_name = '$table_name_no' AND lid = '$lid' AND vsys = '$vsys' AND source = '$source' ");

                if( $getExistMember->num_rows == 0 )
                {

                    $projectdb->query("INSERT INTO address_groups (id, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source) "
                        . "VALUES (NULL, '', '', '$devicegroup', '$vsys', '$name_int_no', '$member_lid_no', '$table_name_no', '$lid', '$source')");

                }
            }

            unset($incl);
            unset($incl2);
            unset($inclNo);

            if( count($members_news) > 0 )
            {
                add_log('ok', 'Phase 2: Reading Address Objects and Groups', 'Group with exclusion ' . $group_name . ': The members {' . implode(",", $name_int_old) . '} were replaced by {' . implode(",", $members_news) . '}.', $source, '');
            }
            $projectdb->query("UPDATE address_groups_id SET type = 'static' WHERE id = '$lid'");
        }
    }// fin if lid
}

function expandMembersGroups($lid, $position)
{

    global $projectdb;

    $myMembers = array();

    if( $position == "1" )
    {
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id ASC LIMIT 1 ;");
        if( $getFirstGroup->num_rows > 0 )
        {
            while( $data = $getFirstGroup->fetch_assoc() )
            {
                $myMembers[] = $data;
            }
        }
    }
    elseif( $position == "2" )
    {
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id DESC LIMIT 1 ;");
        if( $getFirstGroup->num_rows > 0 )
        {
            while( $data = $getFirstGroup->fetch_assoc() )
            {
                $myMembers[] = $data;
            }
        }
    }
    elseif( $position == "3" )
    {
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid';");
        if( $getFirstGroup->num_rows > 0 )
        {
            while( $data = $getFirstGroup->fetch_assoc() )
            {
                $myMembers[] = $data;
            }
        }
    }
    elseif( $position == "4" )
    {
        # Grab all the members but the first
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid';");
        if( $getFirstGroup->num_rows > 0 )
        {
            $count = 0;
            while( $data = $getFirstGroup->fetch_assoc() )
            {
                if( $count != 0 )
                {
                    $myMembers[] = $data;
                }
                $count++;
            }
        }
    }

    return $myMembers;

}

function explodeGroups2MembersCheckpoint($members, $level = 0)
{
    $tmp_members = array();

    foreach( $members as $member )
    {
        if( (isset($member['type'])) and ($member['type'] != "group") and ($member['type'] != "service-group") )
        {
            $tmp_members[] = $member;
        }
        else
        {
            if( isset($member['members']) )
            {
                $tmp_members[] = $member;
                $tmp_members = array_merge($tmp_members, explodeGroups2MembersCheckpoint($member['members'], $level + 1));
            }
            else
            {
                #Debug
                //print_r($member);
            }
        }
    }
    $input = array_map("unserialize", array_unique(array_map("serialize", $tmp_members)));
    return $input;
}

function get_objects(array $myObjectsAll, $source, $vsys, $filename)
{
    global $projectdb;

    $message = array();
    $common = array();
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

    # Init vars
    $addNetworksv4 = array();
    $addNetworksv6 = array();
    $addServices = array();
    $addAddressGroups = array();
    $addAddressMembers = array();
    $addServicesGroups = array();
    $addServicesMembers = array();

    $fullObject = array();

    $objectsGroups = array();
    $objectsExclusionGroups = array();
    $objectsServicesGroups = array();

    $schedules = array();
    $accessRoles = array();
    $accessLayers = array();

    foreach( $myObjectsAll as $key => $object )
    {
        $name_int = normalizeNames(truncate_names($object['name']));
        $name = $object['uid'];
        $description = addslashes($object['comments']);
        switch ($object['type'])
        {
            case "CpmiIcmpService":
                if( (!isset($fullObject[$name])) )
                {
                    $serviceprotocol = "icmp";
                    $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"] = "services";
                    $fullObject[$name]["member_lid"] = $services_lid;
                    $services_lid++;
                }
                break;
            case "service-icmp":
                if( (!isset($fullObject[$name])) )
                {
                    $serviceprotocol = "icmp";
                    $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"] = "services";
                    $fullObject[$name]["member_lid"] = $services_lid;
                    $fullObject[$name]["protocol"] = $serviceprotocol;
                    $services_lid++;
                }
                break;
            case "service-dce-rpc":
                if( (!isset($fullObject[$name])) )
                {
                    $serviceprotocol = "rpc";
                    $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"] = "services";
                    $fullObject[$name]["member_lid"] = $services_lid;
                    $fullObject[$name]["protocol"] = $serviceprotocol;
                    $services_lid++;
                }
                break;
            case "service-rpc":
                if( (!isset($fullObject[$name])) )
                {
                    $serviceprotocol = "rpc";
                    $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"] = "services";
                    $fullObject[$name]["member_lid"] = $services_lid;
                    $fullObject[$name]["protocol"] = $serviceprotocol;
                    $services_lid++;
                }
                break;
            case "service-tcp":
                if( !isset($fullObject[$name]) )
                {
                    $serviceprotocol = "tcp";

                    if( !isset($object['port']) )
                    {
                        $serviceport = "0";
                    }
                    else
                    {
                        $serviceport = $object['port'];
                    }

                    if( preg_match("/-/i", $serviceport) )
                    {
                        $newvar = explode("-", $serviceport);
                        $firstport = $newvar[0];
                        $lastport = $newvar[1];
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','$firstport-$lastport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["dport"] = "$firstport-$lastport";
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                    elseif( preg_match("/>/i", $serviceport) )
                    {
                        $newvar = explode(">", $serviceport);
                        $firstport = intval($newvar[1]) + 1;
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','$firstport-65535','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["dport"] = "$firstport-65535";
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                    elseif( preg_match("/</i", $serviceport) )
                    {
                        $newvar = explode("<", $serviceport);
                        $firstport = intval($newvar[1]) - 1;
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','0-$firstport','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["dport"] = "0-$firstport";
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                    else
                    {
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','$serviceport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["dport"] = $serviceport;
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                }
                break;
            case "service-other":
                if( !isset($fullObject[$name]) )
                {
                    $serviceprotocol = $object['ip-protocol'];
                    $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','','1','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"] = "services";
                    $fullObject[$name]["member_lid"] = $services_lid;
                    $fullObject[$name]["protocol"] = $serviceprotocol;
                    $services_lid++;
                }
                break;
            case "service-udp":
                if( !isset($fullObject[$name]) )
                {
                    $serviceprotocol = "udp";
                    $serviceport = $object['port'];
                    if( preg_match("/-/i", $serviceport) )
                    {
                        $newvar = explode("-", $serviceport);
                        $firstport = $newvar[0];
                        $lastport = $newvar[1];
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','$firstport-$lastport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["dport"] = "$firstport-$lastport";
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                    elseif( preg_match("/>/i", $serviceport) )
                    {
                        $newvar = explode(">", $serviceport);
                        $firstport = intval($newvar[1]) + 1;
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','$firstport-65535','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["dport"] = "$firstport-65535";
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                    elseif( preg_match("/</i", $serviceport) )
                    {
                        $newvar = explode("<", $serviceport);
                        $firstport = intval($newvar[1]) - 1;
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','1-$firstport','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["dport"] = "1-$firstport";
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                    else
                    {
                        $addServices[] = "('$services_lid','$name','$name_int','$serviceprotocol','$serviceport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"] = "services";
                        $fullObject[$name]["member_lid"] = $services_lid;
                        $fullObject[$name]["protocol"] = $serviceprotocol;
                        $services_lid++;
                    }
                }
                break;
            case "network":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['subnet4'])) and ($object['mask-length4'] != "") and ($object['subnet4'] != "") )
                    {
                        $ip = $object['subnet4'];
                        $mask = $object['mask-length4'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','$mask','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = $mask;
                        $address_lid++;
                    }
                    if( (isset($object['subnet6'])) and ($object['mask-length6'] != "") and ($object['subnet6'] != "") )
                    {
                        $ip = $object['subnet6'];
                        $mask = $object['mask-length6'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','$mask','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                    if( (isset($object['nat-settings'])) and ($object['nat-settings'] != "") )
                    {
                        $autoRule = FALSE;
                        foreach( $object['nat-settings'] as $objKey => $newObj )
                        {
                            if( $autoRule == TRUE )
                            {
                                if( ($objKey == "ipv4-address") and ($newObj != "") )
                                {
                                    $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"] = "address";
                                    $fullObject[$name]["member_lid"] = $address_lid;
                                    $address_lid++;
                                }
                                if( ($objKey == "ipv6-address") and ($newObj != "") )
                                {
                                    $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"] = "address";
                                    $fullObject[$name]["member_lid"] = $address_lid;
                                    $address_lid++;
                                }
                            }
                            if( ($objKey == "auto-rule") and ($newObj == TRUE) )
                            {
                                $autoRule = TRUE;
                            }

                        }
                    }

                    if( (isset($object['groups'])) and (count($object['groups']) > 0) )
                    {
                        foreach( $object['groups'] as $ikey => $newObjectGRoup )
                        {
                            if( is_array($newObjectGRoup) )
                            {
                                $objectsGroups[] = $newObjectGRoup;
                            }
                        }
                    }

                }
                break;
            case "host":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address'])) and ($object['ipv4-address'] != "") )
                    {
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "32";
                        $address_lid++;
                    }
                    if( (isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") )
                    {
                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                    if( (isset($object['nat-settings'])) and ($object['nat-settings'] != "") and (!isset($fullObject[$name])) )
                    {
                        $autoRule = FALSE;
                        foreach( $object['nat-settings'] as $objKey => $newObj )
                        {
                            if( $autoRule == TRUE )
                            {
                                if( ($objKey == "ipv4-address") and ($newObj != "") )
                                {
                                    $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"] = "address";
                                    $fullObject[$name]["member_lid"] = $address_lid;
                                    $address_lid++;
                                }
                                if( ($objKey == "ipv6-address") and ($newObj != "") )
                                {
                                    $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"] = "address";
                                    $fullObject[$name]["member_lid"] = $address_lid;
                                    $address_lid++;
                                }
                            }
                            if( ($objKey == "auto-rule") and ($newObj == TRUE) )
                            {
                                $autoRule = TRUE;
                            }

                        }
                    }

                    if( (isset($object['groups'])) and (count($object['groups']) > 0) )
                    {
                        foreach( $object['groups'] as $ikey => $newObjectGRoup )
                        {
                            if( is_array($newObjectGRoup) )
                            {
                                $objectsGroups[] = $newObjectGRoup;
                            }
                        }
                    }
                }
                break;
            case "CpmiVsClusterNetobj":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address'])) and ($object['ipv4-address'] != "") )
                    {
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "32";
                        $address_lid++;
                    }
                    if( (isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") )
                    {
                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                    if( (isset($object['nat-settings'])) and ($object['nat-settings'] != "") and (!isset($fullObject[$name])) )
                    {
                        $autoRule = FALSE;
                        foreach( $object['nat-settings'] as $objKey => $newObj )
                        {
                            if( $autoRule == TRUE )
                            {
                                if( ($objKey == "ipv4-address") and ($newObj != "") )
                                {
                                    $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"] = "address";
                                    $fullObject[$name]["member_lid"] = $address_lid;
                                    $address_lid++;
                                }
                                if( ($objKey == "ipv6-address") and ($newObj != "") )
                                {
                                    $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"] = "address";
                                    $fullObject[$name]["member_lid"] = $address_lid;
                                    $address_lid++;
                                }
                            }
                            if( ($objKey == "auto-rule") and ($newObj == TRUE) )
                            {
                                $autoRule = TRUE;
                            }

                        }
                    }
                }
                break;
            case "address-range":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address-first'])) and ($object['ipv4-address-first'] != "") )
                    {
                        $ip = $object['ipv4-address-first'] . "-" . $object['ipv4-address-last'];
                        $addNetworksv4[] = "('$address_lid','ip-range','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "";
                        $address_lid++;
                    }

                    if( (isset($object['ipv6-address-first'])) and ($object['ipv6-address-first'] != "") )
                    {
                        $ip = $object['ipv6-address-first'] . "-" . $object['ipv6-address-last'];
                        $addNetworksv6[] = "('$address_lid','ip-range','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }

                    if( (isset($object['groups'])) and (count($object['groups']) > 0) )
                    {
                        foreach( $object['groups'] as $ikey => $newObjectGRoup )
                        {
                            if( is_array($newObjectGRoup) )
                            {
                                $objectsGroups[] = $newObjectGRoup;
                            }
                        }
                    }
                }

                break;
            case "simple-gateway":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address'])) and ($object['ipv4-address'] != "") )
                    {
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "32";
                        $address_lid++;
                    }
                    if( (isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") )
                    {
                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "CpmiHostCkp":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address'])) and ($object['ipv4-address'] != "") )
                    {
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "32";
                        $address_lid++;
                    }
                    if( (isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") )
                    {
                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid''ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "CpmiGatewayCluster":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address'])) and ($object['ipv4-address'] != "") )
                    {
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "32";
                        $address_lid++;
                    }
                    if( (isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") )
                    {
                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid''ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "Track":
                # Generate Log so this object will not be migrated
                if( $object['name'] == "Log" )
                {
                    $common['log'] = $name;
                }
                elseif( $object['name'] == "None" )
                {
                    $common['none'] = $name;
                }
                break;
            case "CpmiAnyObject":
                if( $object['name'] == "Any" )
                {
                    $common["any"] = $name;
                }
                elseif( $object['name'] == "All" )
                {
                    $common["all"] = $name;
                }

                break;
            case "RulebaseAction":
                $action = $object['name'];
                if( $action == "Accept" )
                {
                    $action = "allow";
                }
                elseif( $action == "Drop" )
                {
                    $action = "drop";
                }
                elseif( $action == "Reject" )
                {
                    $action = "deny";
                }
                $common["$action"] = $name;
                break;
            case "Global":
                $global = $object['name'];
                if( $global == "Policy Targets" )
                {
                    $common["Policy Targets"] = $name;
                }
                elseif( $global == "Original" )
                {
                    $common["Original"] = $name;
                }
                elseif( $global == "Inner Layer" )
                {
                    $common["Inner Layer"] = $name;
                }
                break;
            case "CpmiGatewayPlain":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address'])) and ($object['ipv4-address'] != "") )
                    {
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "32";
                        $address_lid++;
                    }
                    if( (isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") )
                    {
                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "CpmiClusterMember":
                if( !isset($fullObject[$name]) )
                {
                    if( (isset($object['ipv4-address'])) and ($object['ipv4-address'] != "") )
                    {
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $fullObject[$name]["ipaddress"] = $ip;
                        $fullObject[$name]["cidr"] = "32";
                        $address_lid++;
                    }
                    if( (isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") )
                    {
                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"] = "address";
                        $fullObject[$name]["member_lid"] = $address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "time":
                echo "Unsupported Object TIME [" . $object['name'] . "]" . PHP_EOL;
                if( !isset($schedules[$name]) )
                {
                    $schedules[$name] = trim($object['name']);
                }
                break;
            case "vpn-community-meshed":
                echo "Unsupported Object VPN COMMUNITY MESHED [" . $object['name'] . "]" . PHP_EOL;
                #print_r($object);
                break;
//            case "CpmiLogicalServer":
//                if (!isset($fullObject[$name])){
//                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
//                        $ip=$object['ipv4-address'];
//                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
//                        $fullObject[$name]["table_name"]="address";
//                        $fullObject[$name]["member_lid"]=$address_lid;
//                        $address_lid++;
//                    }
//                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
//                        $ip=$object['ipv6-address'];
//                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
//                        $fullObject[$name]["table_name"]="address";
//                        $fullObject[$name]["member_lid"]=$address_lid;
//                        $address_lid++;
//                    }
//                }
//                break;
            case "access-role":
                if( !isset($accessRoles[$name]) )
                {
                    $accessRoles[$name] = array();
                    if( isset($object['users']) )
                    {
                        foreach( $object['users'] as $userObject )
                        {
                            if( isset($userObject['tooltiptext']) )
                            {
                                $tooltip = explode("\n", $userObject['tooltiptext']);
                                $Udomain = preg_replace("/\<B\>Domain Name = /", " ", $tooltip[0]);
                                $Udomain = preg_replace("/\<\/B\>/", " ", $Udomain);
                                if( $userObject['type'] == "CpmiAdUser" )
                                {
                                    $tooltip1 = preg_replace("/Username = /", " ", $tooltip[1]);
                                    $Uuser = trim($Udomain) . "\\" . trim($tooltip1);
                                    $accessRoles[$name][] = $Uuser;
                                }
                                elseif( $userObject['type'] == "CpmiAdGroup" )
                                {
                                    $tooltip1 = preg_replace("/Group Name = /", " ", $tooltip[1]);
                                    $Ugroup = trim($Udomain) . "\\" . trim($tooltip1);
                                    $accessRoles[$name][] = $Ugroup;
                                }

                            }


                        }

                    }


                }
                break;
            case "group-with-exclusion":
                if( !isset($fullObject[$name]) )
                {
                    $objectsExclusionGroups[] = $object;
                }
                break;
            case "access-layer":
                if( !isset($accessLayers[$name]) )
                {
                    $accessLayers[$name] = $object;
                }
                break;
            default:
                if( $object['type'] == "group" )
                {
                    $objectsGroups[] = $object;
                }
                elseif( $object['type'] == "service-group" )
                {
                    $objectsServicesGroups[] = $object;
                }
                else
                {
                    echo "#######Unsupported Object#####\n";
                    print $object['type'];
                    echo "########Unsupported Object####\n";
                }
                break;
        }
    }


    if( count($objectsGroups) > 0 )
    {
        $missingMembersPerAddressGroup = array(); //This will be a "list" of the missing members in each group after the first pass

        $input = array_map("unserialize", array_unique(array_map("serialize", $objectsGroups)));
        $objectsGroups = $input;
        foreach( $objectsGroups as $key => $object )
        {
            $name_int = normalizeNames(truncate_names($object['name']));
            $name = $object['uid'];
            if( !isset($fullObject[$name]) )
            {
                $description = addslashes($object['comments']);
                $addAddressGroups[] = "('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                $fullObject[$name]["member_lid"] = $aglid;
                $fullObject[$name]["table_name"] = "address_groups_id";
                if( isset($object['members']) )
                {
                    $parentAG = $aglid;
                    foreach( $object['members'] as $member )
                    {
                        if( is_array($member) )
                        {
                            if( (isset($member['uid'])) and (isset($fullObject[$member['uid']])) )
                            {
                                $member_lid = $fullObject[$member['uid']]["member_lid"];
                                $table_name = $fullObject[$member['uid']]["table_name"];
                                $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$member_lid','$table_name')";
                            }
                            else
                            {
                                if( $member['type'] == "group" )
                                {
                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                    $name1 = $member['uid'];
                                    $description = addslashes($member['comments']);
                                    $aglid++;
                                    $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                                    $addAddressGroups[] = "('$aglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                    $fullObject[$name1]["member_lid"] = $aglid;
                                    $fullObject[$name1]["table_name"] = "address_groups_id";
                                    if( isset($member['members']) )
                                    {
                                        foreach( $member['members'] as $member2 )
                                        {
                                            if( is_array($member2) )
                                            {
                                                if( (isset($member2['uid'])) and (isset($fullObject[$member2['uid']])) )
                                                {
                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                    $addAddressMembers[] = "('$vsys','" . $member2['uid'] . "','$aglid','$source','$member_lid2','$table_name2')";
                                                }
                                                else
                                                {
                                                    print "ERROR:";
                                                    print_r($member2);
                                                }
                                            }
                                            else
                                            {
                                                if( isset($fullObject[$member2]) )
                                                {
                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                    $addAddressMembers[] = "('$vsys','" . $member2 . "','$aglid','$source','$member_lid2','$table_name2')";
                                                }
                                                else
                                                {
                                                    //add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                    $missingMembersPerAddressGroup[$aglid]['members'][] = $member2; //This member may not have been created as a group yet
                                                    $missingMembersPerAddressGroup[$aglid]['name'] = $name_int1;
                                                }
                                            }
                                        }
                                    }
                                    $aglid++;
                                }
                                else
                                {
                                    print "ERROR---";
                                    print_r($member);
                                }

                                // add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.print_r($member),$source,'Check in your Checkpoint GUI','','','');
                            }
                        }
                        else
                        {
                            if( isset($fullObject[$member]) )
                            {
                                $member_lid = $fullObject[$member]["member_lid"];
                                $table_name = $fullObject[$member]["table_name"];
                                $addAddressMembers[] = "('$vsys','" . $member . "','$aglid','$source','$member_lid','$table_name')";
                            }
                            else
                            {
                                //add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.$member,$source,'Check in your Checkpoint GUI','','','');
                                $missingMembersPerAddressGroup[$aglid]['members'][] = $member; //This member may not have been created as a group yet
                                $missingMembersPerAddressGroup[$aglid]['name'] = $name_int;
                            }
                        }
                    }
                }
                $aglid++;

                if( isset($object['groups']) )
                {
                    foreach( $object['groups'] as $internalgroup )
                    {
                        if( isset($internalgroup['uid']) )
                        {
                            $name_int = normalizeNames(truncate_names($internalgroup['name']));
                            $name = $internalgroup['uid'];

                            if( !isset($fullObject[$name]) )
                            {
                                $description = addslashes($internalgroup['comments']);
                                $addAddressGroups[] = "('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                                $fullObject[$name]["member_lid"] = $aglid;
                                $fullObject[$name]["table_name"] = "address_groups_id";
                                if( isset($object['members']) )
                                {
                                    $parentAG = $aglid;
                                    foreach( $internalgroup['members'] as $member )
                                    {
                                        if( is_array($member) )
                                        {
                                            if( (isset($member['uid'])) and (isset($fullObject[$member['uid']])) )
                                            {
                                                $member_lid = $fullObject[$member['uid']]["member_lid"];
                                                $table_name = $fullObject[$member['uid']]["table_name"];
                                                $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$member_lid','$table_name')";
                                            }
                                            else
                                            {
                                                if( $member['type'] == "group" )
                                                {
                                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                                    $name1 = $member['uid'];
                                                    $description = addslashes($member['comments']);
                                                    $aglid++;
                                                    $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                                                    $addAddressGroups[] = "('$aglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                                    $fullObject[$name1]["member_lid"] = $aglid;
                                                    $fullObject[$name1]["table_name"] = "address_groups_id";
                                                    if( isset($member['members']) )
                                                    {
                                                        foreach( $member['members'] as $member2 )
                                                        {
                                                            if( is_array($member2) )
                                                            {
                                                                if( (isset($member2['uid'])) and (isset($fullObject[$member2['uid']])) )
                                                                {
                                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                                    $addAddressMembers[] = "('$vsys','" . $member2['uid'] . "','$aglid','$source','$member_lid2','$table_name2')";
                                                                }
                                                                else
                                                                {
                                                                    print "ERROR:";
                                                                    print_r($member2);
                                                                }
                                                            }
                                                            else
                                                            {
                                                                if( isset($fullObject[$member2]) )
                                                                {
                                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                                    $addAddressMembers[] = "('$vsys','" . $member2 . "','$aglid','$source','$member_lid2','$table_name2')";
                                                                }
                                                                else
                                                                {
                                                                    //add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                                    $missingMembersPerAddressGroup[$aglid]['members'][] = $member2; //This member may not have been created as a group yet
                                                                    $missingMembersPerAddressGroup[$aglid]['name'] = $name_int1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    $aglid++;
                                                }
                                                else
                                                {
                                                    print "ERROR---";
                                                    print_r($member);
                                                }

                                                // add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.print_r($member),$source,'Check in your Checkpoint GUI','','','');
                                            }
                                        }
                                        else
                                        {
                                            if( isset($fullObject[$member]) )
                                            {
                                                $member_lid = $fullObject[$member]["member_lid"];
                                                $table_name = $fullObject[$member]["table_name"];
                                                $addAddressMembers[] = "('$vsys','" . $member . "','$aglid','$source','$member_lid','$table_name')";
                                            }
                                            else
                                            {
                                                //add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.$member,$source,'Check in your Checkpoint GUI','','','');
                                                $missingMembersPerAddressGroup[$aglid]['members'][] = $member; //This member may not have been created as a group yet
                                                $missingMembersPerAddressGroup[$aglid]['name'] = $name_int;
                                            }
                                        }
                                    }
                                }
                                $aglid++;
                            }
                        }

                    }
                }

            }
        }
    }

    //Now that we have loaded all the groups, we could try to fix those missingMembersPerAddressGroup that we could not find
    foreach( $missingMembersPerAddressGroup as $aglid => $data )
    {
        $groupName = $data['name'];
        foreach( $data['members'] as $missingMember )
        {
            if( isset($fullObject[$missingMember]) )
            {
                $member_lid = $fullObject[$missingMember]["member_lid"];
                $table_name = $fullObject[$missingMember]["table_name"];
                $addAddressMembers[] = "('$vsys','" . $missingMember . "','$aglid','$source','$member_lid','$table_name')";
            }
            else
            {

                add_log2('error', 'Reading Member Groups', 'Group called ' . $groupName . ' is missing this member UID: ' . $missingMember, $source, 'Check in your Checkpoint GUI', '', '', '');
            }
        }
    }

    if( count($objectsExclusionGroups) > 0 )
    {

        foreach( $objectsExclusionGroups as $key => $object )
        {

            $name_int = normalizeNames(truncate_names($object['name']));
            $name = trim($object['uid']);
            $addAddressGroups[] = "('$aglid','$name','$name_int','group_with_exclusion','$filename','$source','$vsys','$description')";
            $fullObject[$name]["member_lid"] = $aglid;
            $fullObject[$name]["table_name"] = "address_groups_id";
            $parentAG = $aglid;
            $aglid++;

            if( isset($fullObject[trim($object['include']['uid'])]) )
            {
                $member_lid = $fullObject[$object['include']['uid']]["member_lid"];
                $table_name = $fullObject[$object['include']['uid']]["table_name"];
                $addAddressMembers[] = "('$vsys','" . $object['include']['uid'] . "','$parentAG','$source','$member_lid','$table_name')";
            }
            else
            {
                if( $object['include']['type'] == "group" )
                {
                    $name_int2 = normalizeNames(truncate_names($object['include']['name']));
                    $name2 = trim($object['include']['uid']);
                    $addAddressGroups[] = "('$aglid','$name2','$name_int2','static','$filename','$source','$vsys','$description')";
                    $fullObject[$name2]["member_lid"] = $aglid;
                    $fullObject[$name2]["table_name"] = "address_groups_id";
                    $newParentAG = $aglid;
                    $addAddressMembers[] = "('$vsys','" . $object['include']['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                    $aglid++;
                    $members = trim($object['include']['members'][0]);
                    if( isset($fullObject[$members]) )
                    {
                        $member_lid = $fullObject[$members]["member_lid"];
                        $table_name = $fullObject[$members]["table_name"];
                        $addAddressMembers[] = "('$vsys','$members','$newParentAG','$source','$member_lid','$table_name')";
                    }
                    else
                    {
                        echo "Exclusion Group $name_int: The [include] Member " . $object['include']['name'] . " [$members] was not found in the Objects Database\n";
                        print_r($object);
                    }
                }
            }
            if( isset($fullObject[$object['except']['uid']]) )
            {
                $member_lid = $fullObject[$object['except']['uid']]["member_lid"];
                $table_name = $fullObject[$object['except']['uid']]["table_name"];
                $addAddressMembers[] = "('$vsys','" . $object['except']['uid'] . "','$parentAG','$source','$member_lid','$table_name')";
            }
            else
            {
                if( $object['except']['type'] == "group" )
                {
                    $name_int2 = normalizeNames(truncate_names($object['except']['name']));
                    $name2 = trim($object['except']['uid']);
                    $addAddressGroups[] = "('$aglid','$name2','$name_int2','static','$filename','$source','$vsys','$description')";
                    $fullObject[$name2]["member_lid"] = $aglid;
                    $fullObject[$name2]["table_name"] = "address_groups_id";
                    $newParentAG = $aglid;
                    $addAddressMembers[] = "('$vsys','" . $object['except']['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                    $aglid++;
                    $members = trim($object['except']['members'][0]);
                    if( isset($fullObject[$members]) )
                    {
                        $member_lid = $fullObject[$members]["member_lid"];
                        $table_name = $fullObject[$members]["table_name"];
                        $addAddressMembers[] = "('$vsys','$members','$newParentAG','$source','$member_lid','$table_name')";
                    }
                    else
                    {
                        echo "Exclusion Group $name_int: The [except] Member " . $object['except']['name'] . " [$members] was not found in the Objects Database\n";
                        print_r($object);
                    }
                }
            }
            $aglid++;
        }
    }

    if( count($objectsServicesGroups) > 0 )
    {
        $input = array_map("unserialize", array_unique(array_map("serialize", $objectsServicesGroups)));
        $objectsServicesGroups = $input;
        foreach( $objectsServicesGroups as $key => $object )
        {
            $name_int = normalizeNames(truncate_names($object['name']));
            $name = $object['uid'];
            if( !isset($fullObject[$name]) )
            {
                $description = addslashes($object['comments']);
                $addServicesGroups[] = "('$sglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                $fullObject[$name]["member_lid"] = $sglid;
                $fullObject[$name]["table_name"] = "services_groups_id";
                if( isset($object['members']) )
                {
                    $parentSG = $sglid;
                    foreach( $object['members'] as $member )
                    {
                        if( is_array($member) )
                        {
                            if( (isset($member['uid'])) and (isset($fullObject[$member['uid']])) )
                            {
                                $member_lid = $fullObject[$member['uid']]["member_lid"];
                                $table_name = $fullObject[$member['uid']]["table_name"];
                                $addServicesMembers[] = "('$vsys','" . $member['uid'] . "','$parentSG','$source','$member_lid','$table_name')";
                            }
                            else
                            {
                                if( $member['type'] == "service-group" )
                                {
                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                    $name1 = $member['uid'];
                                    $description = addslashes($member['comments']);
                                    $sglid++;
                                    $addServicesMembers[] = "('$vsys','" . $member['uid'] . "','$parentSG','$source','$sglid','services_groups_id')";
                                    $addServicesGroups[] = "('$sglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                    $fullObject[$name1]["member_lid"] = $sglid;
                                    $fullObject[$name1]["table_name"] = "services_groups_id";
                                    if( isset($member['members']) )
                                    {
                                        foreach( $member['members'] as $member2 )
                                        {
                                            if( is_array($member2) )
                                            {
                                                if( (isset($member2['uid'])) and (isset($fullObject[$member2['uid']])) )
                                                {
                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                    $addServicesMembers[] = "('$vsys','" . $member2['uid'] . "','$sglid','$source','$member_lid2','$table_name2')";
                                                }
                                                else
                                                {
                                                    print "ERROR:";
                                                    print_r($member2);
                                                }
                                            }
                                            else
                                            {
                                                if( isset($fullObject[$member2]) )
                                                {
                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                    $addServicesMembers[] = "('$vsys','" . $member2 . "','$sglid','$source','$member_lid2','$table_name2')";
                                                }
                                                else
                                                {
                                                    add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                }
                                            }
                                        }
                                    }
                                    $sglid++;
                                }
                                else
                                {
                                    print "Error: " . print_r($member);
                                }


                                //add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int . ' is missing this member UID: ' . implode(",",$member), $source, 'Check in your Checkpoint GUI', '', '', '');
                            }
                        }
                        else
                        {
                            if( isset($fullObject[$member]) )
                            {
                                $member_lid = $fullObject[$member]["member_lid"];
                                $table_name = $fullObject[$member]["table_name"];
                                $addServicesMembers[] = "('$vsys','" . $member . "','$sglid','$source','$member_lid','$table_name')";
                            }
                            else
                            {
                                add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int . ' is missing this member UID: ' . $member, $source, 'Check in your Checkpoint GUI', '', '', '');
                            }
                        }

                    }
                }

                $sglid++;
            }
        }
    }

    # Add Address and Groups
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
        $projectdb->query("INSERT INTO services (id,name_ext,name,protocol,dport,checkit,description,source,icmp,devicegroup) VALUES " . implode(",", $unique) . ";");
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

    $message['common'] = $common;
    $message['objects'] = $fullObject;
    $message['schedules'] = $schedules;
    $message['accessRole'] = $accessRoles;
    $message['accessLayers'] = $accessLayers;

    return $message;

}

function isValidJson($strJson)
{
    json_decode($strJson);
    return (json_last_error() === JSON_ERROR_NONE);
}

function anything_to_utf8($var, $deep = TRUE)
{
    if( is_array($var) )
    {
        foreach( $var as $key => $value )
        {
            if( $deep )
            {
                $var[$key] = anything_to_utf8($value, $deep);
            }
            elseif( !is_array($value) && !is_object($value) && !mb_detect_encoding($value, 'utf-8', TRUE) )
            {
                $var[$key] = utf8_encode($var);
            }
        }
        return $var;
    }
    elseif( is_object($var) )
    {
        foreach( $var as $key => $value )
        {
            if( $deep )
            {
                $var->$key = anything_to_utf8($value, $deep);
            }
            elseif( !is_array($value) && !is_object($value) && !mb_detect_encoding($value, 'utf-8', TRUE) )
            {
                $var->$key = utf8_encode($var);
            }
        }
        return $var;
    }
    else
    {
        return (!mb_detect_encoding($var, 'utf-8', TRUE)) ? utf8_encode($var) : $var;
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
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $vsys
 * @return MemberObject[]
 */
function getCommonServices($childServices, $parentServices, $projectdb, $source, $vsys): array
{
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //The Parent policy has an ANY. We use the Child's Sources's members
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

function read_index($project, $index)
{
    $message = array();
    $message['code'] = FALSE;

    if( file_exists($index) )
    {
        $indexJson = json_decode(file_get_contents(USERSPACE_PATH . "/projects/" . $project . "/security/index.json"), TRUE);
        $message['gateways'] = $indexJson['policyPackages'][0]['htmlGatewaysFileName'];
        $message['objects'] = $indexJson['policyPackages'][0]['objects']['htmlObjectsFileName'];
        $message['packageName'] = $indexJson['policyPackages'][0]['packageName'];
        $message['accessLayers'] = $indexJson['policyPackages'][0]['accessLayers'][0]['htmlFileName'];
        $message['accessLayerName'] = $indexJson['policyPackages'][0]['accessLayers'][0]['name'];
        $message['natLayer'] = $indexJson['policyPackages'][0]['natLayer']['htmlFileName'];
        $message['domain'] = $indexJson['policyPackages'][0]['accessLayers'][0]['domain'];
        $message['code'] = TRUE;
    }

    return $message;
}