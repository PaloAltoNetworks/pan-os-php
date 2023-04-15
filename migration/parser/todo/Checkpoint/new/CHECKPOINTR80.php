<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';

$checkpointName="";

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
global $app;
include INC_ROOT.'/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

$sourcesAdded = array();
global $source;

if($noDNAT=="1"){
    $skipDNAT=true;
}
else{
    $skipDNAT=false;
}


if ($action=="import") {
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    update_progress($project, '0.00', 'Reading config files', $jobid);

    $rulebases = USERSPACE_PATH . "/projects/$project/rulebases.txt";
    $natrules = USERSPACE_PATH . "/projects/$project/nat.txt";

    $processNatRules=false;

    if (file_exists($rulebases)){
        $myRules_orig = file_get_contents($rulebases);


        for ($i = 0; $i <= 31; ++$i) {
            $myRules_orig = str_replace(chr($i), "", $myRules_orig);
        }

        $myRules_orig = str_replace(chr(127), "", $myRules_orig);

        // This is the most common part
        // Some file begins with 'efbbbf' to mark the beginning of the file. (binary level)
        // here we detect it and we remove it, basically it's the first 3 characters
        if (0 === strpos(bin2hex($myRules_orig), 'efbbbf')) {
            $myRules_orig = substr($myRules_orig, 3);
        }

        $json_error_message= '';
        $myRules = json_decode( $myRules_orig ,true, 2000);

        //If the document contained invalid chars, the $myRules is not valid. Let's try again with a prior UTF8 cleaning
        if(json_last_error() == JSON_ERROR_UTF8) {
            update_progress($project,'0.01',"This JSON document contains invalid chars. Cleaning the document ...",$jobid);
            $myRules = iconv("utf-8", "utf-8//ignore", $myRules_orig);
            $myRules = json_decode( $myRules ,true, 2000);
        }

        switch (json_last_error()) {
            case JSON_ERROR_NONE:
                $error = false;
                echo ' - No errors';
                break;
            case JSON_ERROR_DEPTH:
                $error = true;
                $json_error_message = ' JSON error - Maximum stack depth exceeded';
                echo $json_error_message;
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $error = true;
                $json_error_message = ' JSON error - Underflow or the modes mismatch';
                echo $json_error_message;
                break;
            case JSON_ERROR_CTRL_CHAR:
                $error = true;
                $json_error_message = ' JSON error - Unexpected control character found';
                echo $json_error_message;
                break;
            case JSON_ERROR_SYNTAX:
                $error = true;
                $json_error_message = ' JSON error - Syntax error, malformed JSON';
                echo $json_error_message;
                break;
            case JSON_ERROR_UTF8:
                $error = true;
                $json_error_message = 'Malformed UTF-8 characters, possibly incorrectly encoded.';
                $json_error_message .= " Use <b>iconv -f utf-8 -t utf-8 -c original.json > cleaned.json</b> to clean the file";
                echo $json_error_message;
                break;
            default:
                $error = true;
                $json_error_message = ' JSON error - Unknown error';
                echo $json_error_message;
                break;
        }

        if($error){
            update_progress($project,'-1.00',$json_error_message,$jobid);
            unlink($rulebases);
            if (file_exists($natrules)){unlink($natrules);}
            //if (file_exists((USERSPACE_PATH."/projects/$pronat-settingsject/routes.txt"))){
            if (file_exists((USERSPACE_PATH."/projects/$project/routes.txt"))){
                unlink(USERSPACE_PATH."/projects/$project/routes.txt");
                if (file_exists(USERSPACE_PATH."/projects/$project/routes.out")){
                    unlink(USERSPACE_PATH."/projects/$project/routes.out");
                }
            }
            exit(0);
        }

        $myObjects=$myRules['objects-dictionary'];
        if (file_exists($natrules)){
            $myNatRules = file_get_contents($natrules);

            for ($i = 0; $i <= 31; ++$i) {
                $myNatRules = str_replace(chr($i), "", $myNatRules);
            }
            $myNatRules = str_replace(chr(127), "", $myNatRules);

            // This is the most common part
            // Some file begins with 'efbbbf' to mark the beginning of the file. (binary level)
            // here we detect it and we remove it, basically it's the first 3 characters
            if (0 === strpos(bin2hex($myNatRules), 'efbbbf')) {
                $myNatRules = substr($myNatRules, 3);
            }

            $myNatRules = json_decode( $myNatRules ,true);

            if ($myNatRules!=""){
                $processNatRules=true;
            }

            $myNatObjects=$myNatRules['objects-dictionary'];
//            echo "Starting";
//            print_r($myNatObjects);

            $obt_tmp = array_merge($myNatObjects,$myObjects);

            $input = array_map("unserialize", array_unique(array_map("serialize", $obt_tmp)));
            $myObjects = $input;
//            print "after unique".PHP_EOL;
//            print_r($myObjects);
            unset($obt_tmp);unset($input);
        }
        if (count($myObjects)>0){
            #Check if is the first vsys
            if ($checkpointName==""){
                $filename=unique_id(10);
            }
            else{
                $filename=$checkpointName;
            }

            $getVsys=$projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
            if ($getVsys->num_rows==0){
                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','vsys1','Checkpoint')");
                $vsys="vsys1";
                $source=$projectdb->insert_id;
            }
            $sourceAdded[] = $source;

            #Config Template
            $getTemplate=$projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
            $template_name=$filename."_template";
            $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
            $template=$projectdb->insert_id;

            #Explode Members
            update_progress($project,'0.10','Phase 1 of 10 -  Reading Objects',$jobid);

            $myObjectsAll=explodeGroups2MembersCheckpoint($myObjects, 0);
            $common=get_objects($myObjectsAll,$source,$vsys,$filename);

            # Calculate Excluded Groups
            calculateExclusionGroups($source);

            # Read Security Rules
            update_progress($project,'0.20','Phase 2 of 10 - Reading Access Policies',$jobid);
            if (count($myRules['rulebase'])>0){
                get_security_policies($myRules['rulebase'], $source, $vsys, $filename, $common);
            }

            # Read Nat Rules
            update_progress($project,'0.30','Phase 3 of 10 - Reading NAT Policies',$jobid);

            # Import Interfaces and Routes
            get_routes($project,$source,$template,$vsys);

            if ((isset($myNatRules)) AND (count($myNatRules['rulebase'])>0)){
                get_nat_policies($myNatRules['rulebase'], $source, $vsys, $filename, $common);
            }

            //remap_groupmembers($myObjectsAll);
            update_progress($project,'0.70','Phase 7 of 10 - Referencing Address Groups Members',$jobid);
            remap_groupmembers($source,$vsys);

            # Fix DNAT
            $query = "SELECT id FROM virtual_routers WHERE template='$template' AND source='$source';";
            $getVR = $projectdb->query($query);
            if ($getVR->num_rows == 1) {
                $getVRData = $getVR->fetch_assoc();
                $vr_id = $getVRData['id'];

                $ipMapping = array();
                $rules=array();

                if ($processNatRules==true){
                    update_progress($project,'0.80','Phase 8 of 10 - Calculating NAT Rules Zones based on Static Routes and Interfaces',$jobid);
                    fix_Nat_Policy(-1, $project, $source, $vsys, $vr_id, $ipMapping, $rules, true, true);
                    if(!$skipDNAT) {
                        update_progress($project, '0.90', 'Phase 9 of 10 - Calculating Security Rules Zones based on NAT rules, Static Routes and Interfaces', $jobid);
                        recalculate_Dst_basedOn_NAT($projectdb, $source, $vsys, $vr_id, $project, 'CheckpointR80');
                    }
                    else{
                        update_progress($project, '0.90', 'Phase 9 of 10 - SKIP Calculating Security Rules Zones based on NAT rules, Static Routes and Interfaces', $jobid);
                    }
                    remove_duplicated_zones($source,$vsys);
                }
                else{
                    update_progress($project,'0.80','Phase 8 of 10 - Calculating NAT Rules Zones based on Static Routes and Interfaces',$jobid);
                    #CALCULATE ZONESSS
                    //recalculate_Dst_basedOn_NAT2($projectdb, $source, $vsys, $vr_id, $project, 'CheckpointR80');
                    recalculate_Dst_basedOn_NAT($projectdb, $source, $vsys, $vr_id, $project, 'CheckpointR80');
                    remove_duplicated_zones($source,$vsys);
                }

//                set_Zones_Security_Rules($source, $vsys, $vr_id, $ipMapping);
//                fix_Zones_Policies($project, $source, $vsys,$vr_id);
            }


            update_progress($project,'0.90','Phase 9 of 11 - Checking Used and Unused Objects',$jobid);
            check_used_objects_new($sourcesAdded);

            update_progress($project,'1.0','Done',$jobid);

            unlink($rulebases);
            if (file_exists($natrules)){unlink($natrules);}
            if (file_exists((USERSPACE_PATH."/projects/$project/routes.txt"))){
                unlink(USERSPACE_PATH."/projects/$project/routes.txt");
                if (file_exists(USERSPACE_PATH."/projects/$project/routes.out")){
                    unlink(USERSPACE_PATH."/projects/$project/routes.out");
                }
            }

            #Calculate Layer4-7
            $queryRuleIds = "SELECT id from security_rules WHERE source = $source;";
            $resultRuleIds = $projectdb->query($queryRuleIds);
            if($resultRuleIds->num_rows>0){
                $rules = array();
                while($dataRuleIds = $resultRuleIds->fetch_assoc()){
                    $rules[] = $dataRuleIds['id'];
                }
                $rulesString = implode(",", $rules);
                $securityRulesMan = new \SecurityRulePANObject();
                $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
            }
        }
        else{
            update_progress($project,'-1.00','There are not Objects defined. Import Failed!',$jobid);
            unlink($rulebases);
            if (file_exists($natrules)){unlink($natrules);}
            //if (file_exists((USERSPACE_PATH."/projects/$pronat-settingsject/routes.txt"))){
            if (file_exists((USERSPACE_PATH."/projects/$project/routes.txt"))){
                unlink(USERSPACE_PATH."/projects/$project/routes.txt");
                if (file_exists(USERSPACE_PATH."/projects/$project/routes.out")){
                    unlink(USERSPACE_PATH."/projects/$project/routes.out");
                }
            }
            exit(0);
        }
    }
}

function remove_duplicated_zones($source,$vsys){
    global $projectdb;
    $getDups=$projectdb->query("SELECT id,count(id) AS t FROM security_rules_to WHERE source='$source' AND vsys='$vsys' GROUP BY name,rule_lid,source,vsys having t>1; ");
    if ($getDups->num_rows>0){
        $remove=array();
        while($getDupsData=$getDups->fetch_assoc()){
            $remove[]=$getDupsData['id'];
        }
        $projectdb->query("DELETE FROM security_rules_to WHERE id IN (".implode(",",$remove).")");
    }


}

function remap_groupmembers($source,$vsys){
    global $projectdb;
    $getMembers=$projectdb->query("SELECT * FROM address_groups WHERE source='$source' AND vsys='$vsys';");
    if ($getMembers->num_rows>0){
        $remove=array();
        $newData=array();
        while ($data=$getMembers->fetch_assoc()){
            $uid=$data['member'];
            list($member_lid,$table_name)=getMemberlid("address",$uid,$source,$vsys,'','');
            $devicegroup=$data['devicegroup'];
            $lid=$data['lid'];
            $remove[]=$data['id'];
            $newData[]="('$member_lid','$table_name','$source','$vsys','$devicegroup','$lid')";
        }
        $projectdb->query("DELETE FROM address_groups WHERE id IN (".implode(",",$remove).");");unset($remove);
        $projectdb->query("INSERT INTO address_groups (member_lid,table_name,source,vsys,devicegroup,lid) VALUES ".implode(",",$newData).";");unset($newData);
    }

    $getMembers=$projectdb->query("SELECT * FROM services_groups WHERE source='$source' AND vsys='$vsys';");
    if ($getMembers->num_rows>0){
        $remove=array();
        $newData=array();
        while ($data=$getMembers->fetch_assoc()){
            $uid=$data['member'];
            list($member_lid,$table_name)=getMemberlid("services",$uid,$source,$vsys,'','');
            $devicegroup=$data['devicegroup'];
            $lid=$data['lid'];
            $remove[]=$data['id'];
            $newData[]="('$member_lid','$table_name','$source','$vsys','$devicegroup','$lid')";
        }
        $projectdb->query("DELETE FROM services_groups WHERE id IN (".implode(",",$remove).");");unset($remove);
        $projectdb->query("INSERT INTO services_groups (member_lid,table_name,source,vsys,devicegroup,lid) VALUES ".implode(",",$newData).";");unset($newData);
    }
}

class NatRule {
    public $name;
    public $position;
    public $id;
    public $disabled=0;
    public $preorpost=0;
    public $checkit=0;
    public $comments="";
    public $source;
    public $vsys;
    public $op_service_lid=0;
    public $op_service_table=0;
    public $method="None";
    public $op_zone_to="";
    public $op_to_interface="any";
    public $is_dat=0;
    public $tp_sat_interface;
    public $tp_sat_ipaddress;
    public $tp_sat_bidirectional=0;
    public $tp_fallback_type="None";
    public $tp_sat_interface_fallback;
    public $tp_sat_ipaddress_fallback;
    public $tp_dat_port;
    public $tp_dat_address_lid=0;
    public $tp_dat_address_table;
    public $tp_sat_type="None";
    public $tp_sat_address_type="";

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct9($lid,$position,$preorpost,$checkit,$ruleName,$comments,$rule_enabled,$source,$vsys){
        $this->name = $ruleName;
        $this->id = $lid;
        $this->position = $position;
        $this->preorpost = $preorpost;
        $this->checkit = $checkit;
        $this->comments = $comments;
        $this->disabled = $rule_enabled;
        $this->source = $source;
        $this->vsys = $vsys;
    }

    public function addOPService($member_lid,$table_name){
        $this->op_service_lid=$member_lid;
        $this->op_service_table=$table_name;
    }

    public function addDat($member_lid,$table_name){
        $this->is_dat=1;
        $this->tp_dat_address_lid=$member_lid;
        $this->tp_dat_address_table=$table_name;
    }

    public function addMethod($method){
        $this->method = $method;
        if ($method=="dynamic-ip-and-port"){
            $this->tp_sat_type="dynamic-ip-and-port";
            $this->tp_sat_address_type="translated-address";
        }
        elseif ($method=="static-ip"){
            $this->tp_sat_type="static-ip";
            $this->tp_sat_address_type="translated-address";
            $this->tp_sat_bidirectional=0;
        }
    }
    public function printObject() {
        var_dump(get_object_vars($this));
    }
    public function addTPService($port){
        if (intval($port)>0){$this->tp_dat_port=$port;}
    }
    public function getSQL(){
        $sql="('$this->id','$this->name','$this->position','$this->comments','$this->disabled','$this->source','$this->vsys','$this->preorpost','$this->checkit'," .
            "'$this->op_service_lid','$this->op_service_table', '$this->is_dat', '$this->tp_dat_address_lid' , '$this->tp_dat_address_table', '$this->tp_dat_port', '$this->tp_sat_type','$this->tp_sat_address_type')";

        return $sql;
    }
}

function get_nat_policies(ARRAY $myRules, $source, $vsys, $filename, $common){
    global $projectdb;
    $any=$common["any"];
    $original=$common["Original"];
    #Get Last lid from Rules
    $getlastlid=$projectdb->query("SELECT max(id) as max FROM nat_rules;");
    $getLID1=$getlastlid->fetch_assoc();
    $lid=intval($getLID1['max'])+1;
    $getlastlid=$projectdb->query("SELECT max(position) as max FROM nat_rules WHERE source='$source' AND vsys='$vsys';");
    $getLID1=$getlastlid->fetch_assoc();
    $position=intval($getLID1['max'])+1;
    $thecolor=1;
    $natRule=[];
    $rule_source=[];
    $rule_destination=[];
    $add_tag=[];
    $translated_address=[];

    foreach($myRules as $ruleSection){
       // if (isset($ruleSection['name'])){$name=$ruleSection['name'];}else{$name="Rule ";}
        $type=$ruleSection['type'];
        switch($type){
            case "nat-section":
                if ((isset($ruleSection['rulebase'])) AND (count($ruleSection['rulebase'])>0)) {
                    $name=normalizeNames($ruleSection['name']);
                    $color = "color" . $thecolor;
                    $tag_id = add_tag($name, $source, $vsys, $color);
                    if ($thecolor == 16) {
                        $thecolor = 1;
                    }
                    else {
                        $thecolor++;
                    }
                    foreach ($ruleSection['rulebase'] as $rule){
                        if ($rule['type']=="nat-rule"){
                            $preorpost=1;
                            $checkit=0;
                            $ruleNumber=$rule['rule-number'];
                            $ruleName=truncate_rulenames("Rule ".$ruleNumber);
                            $comments=addslashes($rule['comments']);
                            $automatic=$rule['auto-generated'];

                            if ($tag_id!=""){$add_tag[]="('$lid','$source','$tag_id','tag','$vsys')";}
                            if ($rule['enabled']===true){$rule_enabled=0;}else{$rule_enabled=1;}
                            # Original Packet
                            if (is_array($rule['original-source'])){
                                foreach ($rule['original-source'] as $src){
                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                                        if ($member_lid!=0){$rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                    }
                                }
                            }
                            else{
                                $src=$rule['original-source'];
                                if ($src!=$any){
                                    list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                                    if ($member_lid!=0){$rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                }
                            }
                            if (is_array($rule['original-destination'])){
                                foreach ($rule['original-destination'] as $src){
                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                                        if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                    }
                                }
                            }
                            else{
                                $src=$rule['original-destination'];
                                if ($src!=$any){
                                    list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                                    if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                }
                            }

                            $natRule["$lid"]=new NatRule($lid,$position,$preorpost,$checkit,$ruleName,$comments,$rule_enabled,$source,$vsys);

                            if (is_array($rule['original-service'])){
                                # TODO: ERROR must be a single service or convert into a group
                                foreach ($rule['original-service'] as $src){
                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid);
                                        if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                                    }
                                }
                            }
                            else{
                                $src=$rule['original-service'];
                                if ($src!=$any){
                                    list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid);
                                    if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                                }
                            }

                            if ($rule['translated-source']==$original) {
                                $nat_type="None";
                            }
                            else {
                                $checkIPversion=ip_version($rule['translated-source']);
                                if ($checkIPversion=="noip"){
                                    $src=$rule['translated-source'];
                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                                        if ($member_lid!=0){
                                            $translated_address[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                        }
                                    }
                                }
                                else {
                                    #is IP or v4 or v6 - Check if exists an object or create it.
                                    $getIP=$projectdb->query("SELECT id FROM address WHERE ipaddress='".$rule['translated-source']."' AND source='$source';");
                                    if ($getIP->num_rows==0){
                                        #Create it
                                        $translated_source = $rule['translated-source'];
                                        $name="H-$translated_source";
                                        if ($checkIPversion=="v4"){$hostCidr="32";}
                                        if ($checkIPversion=="v6"){$hostCidr="128";}
                                        $projectdb->query("INSERT into address (type,name_ext,name,checkit,source,used,ipaddress,cidr,$checkIPversion,vtype,vsys) values('ip-netmask','$name','$name','1','$source','1','$translated_source','$hostCidr','1','ip-netmask','$vsys');");
                                        $flid=$projectdb->insert_id;
                                        $translated_address[]="('$lid','$flid','address','$source','$vsys')";
                                    }
                                    else {
                                        $getData=$getIP->fetch_assoc();
                                        $flid=$getData['id'];
                                        $translated_address[]="('$lid','$flid','address','$source','$vsys')";
                                    }
                                }
                            }

                            $method=$rule['method'];
                            switch($method){
                                case "hide":
                                    $natRule["$lid"]->addMethod("dynamic-ip-and-port");
                                    break;

                                case "static":
                                    $natRule["$lid"]->addMethod("static-ip");

                                    $tp_sat_type="";
                                    $tp_sat_address_type="";
                                    $tp_sat_interface="";
                                    $tp_sat_ipaddress="";
                                    $tp_sat_bidirectional=0;
                                    $tp_fallback_type="None";
                                    $tp_sat_interface_fallback="";
                                    $tp_sat_ipaddress_fallback="";

                                    break;
                            }

                            #Destination Translation
                            if ($rule['translated-destination']==$original){}
                            else {
                                $src=$rule['translated-destination'];
                                if ($src!=$any){
                                    list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                                    if ($member_lid!=0){
                                        $natRule["$lid"]->addDat($member_lid,$table_name);
                                    }
                                }
                            }

                            #Get the translated port
                            if ($rule['translated-service']==$original){}
                            else{
                                $getPort=$projectdb->query("SELECT dport FROM services WHERE source='$source' AND name='".$rule['translated-service']."' LIMIT 1;");
                                if ($getPort->num_rows==1){
                                    $getPortData=$getPort->fetch_assoc();
                                    $port=$getPortData['dport'];
                                    $natRule["$lid"]->addTPService($port);
                                }
                            }



                            $lid++;$position++;
                        }
                    }
                }
                break;

            case "nat-rule":
                $rule=$ruleSection;
                $preorpost=0;
                $checkit=0;
                $ruleNumber=$rule['rule-number'];
                $ruleName=truncate_rulenames("Rule ".$ruleNumber);
                $comments=addslashes($rule['comments']);
                $automatic=$rule['auto-generated'];

                //if ($tag_id!=""){$add_tag[]="('$lid','$source','$tag_id','tag','$vsys')";}
                if ($rule['enabled']===true){$rule_enabled=0;}else{$rule_enabled=1;}
                # Original Packet
                if (is_array($rule['original-source'])){
                    foreach ($rule['original-source'] as $src){
                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                            if ($member_lid!=0){$rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                        }
                    }
                }
                else{
                    $src=$rule['original-source'];
                    if ($src!=$any){
                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                        if ($member_lid!=0){$rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                    }
                }
                if (is_array($rule['original-destination'])){
                    foreach ($rule['original-destination'] as $src){
                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                            if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                        }
                    }
                }
                else{
                    $src=$rule['original-destination'];
                    if ($src!=$any){
                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                        if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                    }
                }

                $natRule["$lid"]=new NatRule($lid,$position,$preorpost,$checkit,$ruleName,$comments,$rule_enabled,$source,$vsys);

                if (is_array($rule['original-service'])){
                    # TODO: ERROR must be a single service or convert into a group
                    foreach ($rule['original-service'] as $src){
                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid);
                            if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                        }
                    }
                }
                else{
                    $src=$rule['original-service'];
                    if ($src!=$any){
                        list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid);
                        if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                    }
                }

                if ($rule['translated-source']==$original) {
                    $nat_type="None";
                }
                else {
                    $checkIPversion=ip_version($rule['translated-source']);
                    if ($checkIPversion=="noip"){
                        $src=$rule['translated-source'];
                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                            if ($member_lid!=0){
                                $translated_address[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                            }
                        }
                    }
                    else {
                        #is IP or v4 or v6 - Check if exists an object or create it.
                        $getIP=$projectdb->query("SELECT id FROM address WHERE ipaddress='".$rule['translated-source']."' AND source='$source';");
                        if ($getIP->num_rows==0){
                            #Create it
                            $translated_source = $rule['translated-source'];
                            $name="H-$translated_source";
                            if ($checkIPversion=="v4"){$hostCidr="32";}
                            if ($checkIPversion=="v6"){$hostCidr="128";}
                            $projectdb->query("INSERT into address (type,name_ext,name,checkit,source,used,ipaddress,cidr,$checkIPversion,vtype,vsys) values('ip-netmask','$name','$name','1','$source','1','$translated_source','$hostCidr','1','ip-netmask','$vsys');");
                            $flid=$projectdb->insert_id;
                            $translated_address[]="('$lid','$flid','address','$source','$vsys')";
                        }
                        else {
                            $getData=$getIP->fetch_assoc();
                            $flid=$getData['id'];
                            $translated_address[]="('$lid','$flid','address','$source','$vsys')";
                        }
                    }
                }

                $method=$rule['method'];
                switch($method){
                    case "hide":
                        $natRule["$lid"]->addMethod("dynamic-ip-and-port");
                        break;

                    case "static":
                        $natRule["$lid"]->addMethod("static-ip");

                        $tp_sat_type="";
                        $tp_sat_address_type="";
                        $tp_sat_interface="";
                        $tp_sat_ipaddress="";
                        $tp_sat_bidirectional=0;
                        $tp_fallback_type="None";
                        $tp_sat_interface_fallback="";
                        $tp_sat_ipaddress_fallback="";

                        break;
                }

                #Destination Translation
                if ($rule['translated-destination']==$original){}
                else {
                    $src=$rule['translated-destination'];
                    if ($src!=$any){
                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid);
                        if ($member_lid!=0){
                            $natRule["$lid"]->addDat($member_lid,$table_name);
                        }
                    }
                }

                #Get the translated port
                if ($rule['translated-service']==$original){}
                else{
                    $getPort=$projectdb->query("SELECT dport FROM services WHERE source='$source' AND name='".$rule['translated-service']."' LIMIT 1;");
                    if ($getPort->num_rows==1){
                        $getPortData=$getPort->fetch_assoc();
                        $port=$getPortData['dport'];
                        $natRule["$lid"]->addTPService($port);
                    }
                }
                $lid++;$position++;
                break;
            default :
                break;

        }
     }
    # Save the Nat Rules
    if (count($natRule)>0){
        $sql=[];
        foreach ($natRule as $nat){
            $sql[]=$nat->getSQL();
        }
        $projectdb->query("INSERT INTO nat_rules (id,name,position,description,disabled,source,vsys,preorpost,checkit,op_service_lid,op_service_table,is_dat,tp_dat_address_lid,tp_dat_address_table,tp_dat_port,tp_sat_type,tp_sat_address_type) VALUES ".implode(",",$sql).";");
        unset($sql);unset($natRule);

        if (count($rule_source)){
            $projectdb->query("INSERT INTO nat_rules_src (rule_lid,member_lid,table_name,source,vsys) VALUES ".implode(",",$rule_source).";");
            unset($rule_source);
        }
        if (count($rule_destination)){
            $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,member_lid,table_name,source,vsys) VALUES ".implode(",",$rule_destination).";");
            unset($rule_destination);
        }

        if (count($add_tag)>0){
            $projectdb->query("INSERT INTO nat_rules_tag (rule_lid,source,member_lid,table_name,vsys) VALUES ".implode(",",$add_tag).";");
            unset($add_tag);
        }

        if(count($translated_address)>0){
            $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys) VALUES ".implode(",",$translated_address).";");
            unset($translated_address);
        }
    }
}

function get_security_policies(ARRAY $myRules, $source, $vsys, $filename, $common){
    global $projectdb;
    $any=trim($common["any"]);
    //$all=trim($common["all"]);

    #Get Last lid from Rules
    $getlastlid=$projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1=$getlastlid->fetch_assoc();
    $lid=intval($getLID1['max'])+1;
    $getlastlid=$projectdb->query("SELECT max(position) as max FROM security_rules WHERE source='$source' AND vsys='$vsys';");
    $getLID1=$getlastlid->fetch_assoc();
    $position=intval($getLID1['max'])+1;

    $add_tag=array();
    $add_rule=array();
    $rule_source=array();
    $rule_destination=array();
    $thecolor=1;

    foreach($myRules as $rule){

        if (isset($rule['header'])){
           if ($rule['header']==""){
               $name="";
           }
           else{
               $name=$rule['header'];
           }
        }
        else{
            $name="";
        }
        $type=$rule['type'];

        switch($type){
            case "access-section":
                $ruleSection=$rule;
                if ((isset($ruleSection['rulebase'])) AND (count($ruleSection['rulebase'])>0)){
                    $color="color".$thecolor;
                    $name=truncate_tags($ruleSection['name']);
                    $tag_id=add_tag($name,$source,$vsys,$color);
                    if ($thecolor==16){$thecolor=1;}else {$thecolor++;}
                    foreach ($ruleSection['rulebase'] as $ruleItem){
                        if ($ruleItem['type']=="access-rule"){
                            $preorpost=0;
                            $checkit=0;

                            if ($ruleItem['action']){
                                $action_tmp=array_search($ruleItem['action'],$common);
                                if ($action_tmp!==false){
                                    $action=$action_tmp;
                                }
                                else{
                                    # Create Error action is not in common and add action = deny
                                    $action="deny";
                                    $checkit=1;
                                }
                            }


                            $ruleNumber=trim($ruleItem['rule-number']);

                            if (!isset($ruleItem['name'])){
                                $ruleName=truncate_rulenames("Rule ".$ruleNumber);
                            }
                            else{
                                $ruleName=truncate_rulenames(normalizeNames(trim($ruleItem['name'])));
                            }



                            $comments=addslashes($ruleItem['comments']);
                            if ($tag_id!=""){$add_tag[]="('$lid','$source','$tag_id','tag','$vsys')";}
                            if ($ruleItem['source-negate']===false){$negate_source=0;}else{$negate_source=1;}
                            if ($ruleItem['source']){
                                foreach ($ruleItem['source'] as $src){
                                    if ($src!=$any){
//                                        if ($ruleNumber==1){
//                                            print_r($src);
//                                        }
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Security',$lid);
                                        $rule_source[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                                    }
                                }
                            }
                            if ($ruleItem['destination-negate']===false){$negate_destination=0;}else{$negate_destination=1;}
                            if ($ruleItem['destination']){
                                foreach ($ruleItem['destination'] as $src){
                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Security',$lid);
                                        $rule_destination[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                                    }
                                }
                            }

                            if ($ruleItem['service']){
                                foreach ($ruleItem['service'] as $src){

                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Security',$lid);
                                        $rule_service[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                                    }
                                }
                            }
                            if ($ruleItem['service-negate']===true){
                                # Generate Error Negated Service is not supported
                                $checkit=1;
                                add_log2("error","Importing Security Rules","Negated Service found in Rule [".$lid."]",$source,"Fix it Manually","rules",$lid,"security_rules");
                            }
                            if ($ruleItem['enabled']===true){$rule_enabled=0;}else{$rule_enabled=1;}
                            $add_rule[]="('$lid','$rule_enabled','$negate_source','$negate_destination','$action','','$ruleName','$comments','$source','$vsys','$position','$preorpost','$checkit')";
                            $lid++; $position++;
                        }
                    }
                }
                break;
            case "access-rule":

                if ($name!=""){
                    $color="color".$thecolor;
                    $tag_id=add_tag($name,$source,$vsys,$color);
                    if ($thecolor==16){$thecolor=1;}else {$thecolor++;}
                }
                else{
                    $tag_id="";
                }


                $preorpost=0;
                $checkit=0;
                $ruleNumber=trim($rule['rule-number']);

                if (!isset($rule['name'])){
                    $ruleName=truncate_rulenames("Rule ".$ruleNumber);
                }
                else{
                    $ruleName=truncate_rulenames(normalizeNames(trim($rule['name'])));
                }

                $comments=addslashes($rule['comments']);
                if ($tag_id!=""){$add_tag[]="('$lid','$source','$tag_id','tag','$vsys')";}
                if ($rule['source-negate']===false){$negate_source=0;}else{$negate_source=1;}
                if ($rule['source']){
                    foreach ($rule['source'] as $src){
                        if ($src!=$any){
                            if ($ruleNumber==1){
                                print_r($src);
                            }
                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Security',$lid);
                            $rule_source[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                        }
                    }
                }
                if ($rule['destination-negate']===false){$negate_destination=0;}else{$negate_destination=1;}
                if ($rule['destination']){
                    foreach ($rule['destination'] as $src){
                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Security',$lid);
                            $rule_destination[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                        }
                    }
                }
                if ($rule['action']){
                    $action_tmp=array_search($rule['action'],$common);
                    if ($action_tmp!==false){
                        $action=$action_tmp;
                    }
                    else{
                        # Create Error action is not in common and add action = deny
                        $action="deny";
                        $checkit=1;
                    }
                }
                if ($rule['service']){
                    foreach ($rule['service'] as $src){

                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Security',$lid);
                            $rule_service[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                        }
                    }
                }
                if ($rule['service-negate']===true){
                    # Generate Error Negated Service is not supported
                    $checkit=1;
                    add_log2("error","Importing Security Rules","Negated Service found in Rule [".$lid."]",$source,"Fix it Manually","rules",$lid,"security_rules");
                }
                if ($rule['enabled']===true){$rule_enabled=0;}else{$rule_enabled=1;}
                $add_rule[]="('$lid','$rule_enabled','$negate_source','$negate_destination','$action','','$ruleName','$comments','$source','$vsys','$position','$preorpost','$checkit')";
                $lid++; $position++;


                break;
            default:
                print_r($rule);
                break;
        }
    }

    if (count($add_rule)>0){
        $projectdb->query("INSERT INTO security_rules (id,disabled,negate_source,negate_destination,action,target,name,description,source,vsys,position,preorpost,checkit) VALUES ".implode(",",$add_rule).";");
        unset($add_rule);
    }
    if (count($add_tag)>0){
        $projectdb->query("INSERT INTO security_rules_tag (rule_lid,source,member_lid,table_name,vsys) VALUES ".implode(",",$add_tag).";");
        unset($add_tag);
    }
    if (count($rule_source)>0){
        $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$rule_source).";");
        unset($rule_source);
    }
    if (count($rule_destination)>0){
        $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$rule_destination).";");
        unset($rule_destination);
    }
    if (count($rule_service)>0){
        $unique=array_unique($rule_service);
        $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$unique).";");
        unset($rule_service); unset($unique);
    }
}

function add_tag($name,$source,$vsys,$color){
    global $projectdb;
    $name=normalizeNames($name);
    $exist=$projectdb->query("SELECT id FROM tag WHERE name='$name' AND source='$source' AND vsys='$vsys'");
    if ($exist->num_rows==0){
        $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$name','$source','$vsys','$color');");
        $id=$projectdb->insert_id;
    }
    else{
        $existsData=$exist->fetch_assoc();
        $id=$existsData['id'];
    }
    return $id;
}

function get_objects(ARRAY $myObjectsAll,$source,$vsys,$filename){
    global $projectdb;
    $common=array();
    # Max id from Address
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM address;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $address_lid=$get_glidData['glid'] + 1;
    }
    else{$address_lid=1;}

    # Max id from Services
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM services;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $services_lid=$get_glidData['glid'] + 1;
    }
    else{$services_lid=1;}

    # Max id for Address Groups aglid
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM address_groups_id;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $aglid=$get_glidData['glid'] + 1;
    }
    else{$aglid=1;}

    # Max id for Services Groups sglid
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM services_groups_id;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $sglid=$get_glidData['glid'] + 1;
    }
    else{$sglid=1;}

    # Init vars
    $addNetworksv4=array();
    $addNetworksv6=array();
    $addServices=array();
    $addAddressGroups=array();
    $addAddressMembers=array();
    $addServicesGroups=array();
    $addServicesMembers=array();

    $fullObject=array();

    $objectsGroups=array();
    $objectsExclusionGroups=array();
    $objectsServicesGroups=array();

    //print_r($myObjectsAll);

    foreach ($myObjectsAll as $key => $object){
        $name_int=normalizeNames(truncate_names($object['name']));
        $name=$object['uid'];
        $description=isset($object['comments'])?addslashes($object['comments']):'';
        switch($object['type']){
            case "CpmiIcmpService":
                if ((!isset($fullObject[$name]))){
                    $serviceprotocol="icmp";
                    $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $services_lid++;
                }
                break;
            case "service-icmp":
                if ((!isset($fullObject[$name]))){
                    $serviceprotocol="icmp";
                    $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $services_lid++;
                }
                break;
            case "service-dce-rpc":
                if ((!isset($fullObject[$name]))){
                    $serviceprotocol="rpc";
                    $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $services_lid++;
                }
                break;
            case "service-rpc":
                if ((!isset($fullObject[$name]))){
                    $serviceprotocol="rpc";
                    $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','0','0','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $services_lid++;
                }
                break;
            case "service-tcp":
                if (!isset($fullObject[$name])){
                    $serviceprotocol="tcp";

                    if (!isset($object['port'])){
                        $serviceport="0";
                    }
                    else{
                        $serviceport=$object['port'];
                    }

                    if (preg_match("/-/i", $serviceport)) {
                        $newvar=explode("-",$serviceport);
                        $firstport=$newvar[0];
                        $lastport=$newvar[1];
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','$firstport-$lastport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;
                    } elseif (preg_match("/>/i", $serviceport)) {
                        $newvar=explode(">",$serviceport);
                        $firstport=intval($newvar[1])+1;
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','$firstport-65535','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;
                    } elseif (preg_match("/</i", $serviceport)) {
                        $newvar=explode("<",$serviceport);
                        $firstport=intval($newvar[1])-1;
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','0-$firstport','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;
                    } else {
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','$serviceport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;
                    }
                }
                break;
            case "service-other":
                if (!isset($fullObject[$name])){
                    $serviceprotocol=$object['ip-protocol'];
                    $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','','1','$description','$source','0','$filename')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $services_lid++;
                }
                break;
            case "service-udp":
                if (!isset($fullObject[$name])){
                    $serviceprotocol="udp";
                    $serviceport=$object['port'];
                    if (preg_match("/-/i", $serviceport)) {
                        $newvar=explode("-",$serviceport);
                        $firstport=$newvar[0];
                        $lastport=$newvar[1];
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','$firstport-$lastport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;
                    } elseif (preg_match("/>/i", $serviceport)) {
                        $newvar=explode(">",$serviceport);
                        $firstport=intval($newvar[1])+1;
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','$firstport-65535','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;
                    } elseif (preg_match("/</i", $serviceport)) {
                        $newvar=explode("<",$serviceport);
                        $firstport=intval($newvar[1])-1;
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','1-$firstport','1','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;
                    } else{
                        $addServices[]="('$services_lid','$name','$name_int','$serviceprotocol','$serviceport','0','$description','$source','0','$filename')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $services_lid++;}
                }
                break;
            case "network":
                if (!isset($fullObject[$name])){
                    if ((isset($object['subnet4'])) AND ($object['mask-length4']!="") AND ($object['subnet4']!="")){
                        $ip=$object['subnet4'];
                        $mask=$object['mask-length4'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','$mask','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['subnet6'])) AND ($object['mask-length6']!="") AND ($object['subnet6']!="")){
                        $ip=$object['subnet6'];
                        $mask=$object['mask-length6'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','$mask','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="")){
                        $autoRule=false;
                        foreach($object['nat-settings'] as $objKey=>$newObj){
                            if ($autoRule==true){
                                if (($objKey=="ipv4-address") AND ($newObj!="")){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                                if (($objKey=="ipv6-address") AND ($newObj!="")){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if (($objKey=="auto-rule") AND ($newObj==true)){
                                $autoRule=true;
                            }

                        }
                    }
                }
                break;
            case "host":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="") AND (!isset($fullObject[$name]))){
                        $autoRule=false;
                        foreach($object['nat-settings'] as $objKey=>$newObj){
                            if ($autoRule==true){
                                if (($objKey=="ipv4-address") AND ($newObj!="")){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                                if (($objKey=="ipv6-address") AND ($newObj!="")){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if (($objKey=="auto-rule") AND ($newObj==true)){
                                $autoRule=true;
                            }

                        }
                    }
                }
                break;
            case "CpmiVsClusterNetobj":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="") AND (!isset($fullObject[$name]))){
                        $autoRule=false;
                        foreach($object['nat-settings'] as $objKey=>$newObj){
                            if ($autoRule==true){
                                if (($objKey=="ipv4-address") AND ($newObj!="")){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                                if (($objKey=="ipv6-address") AND ($newObj!="")){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if (($objKey=="auto-rule") AND ($newObj==true)){
                                $autoRule=true;
                            }

                        }
                    }
                }
                break;
            case "address-range":
                if (!isset($fullObject[$name])) {
                    if ((isset($object['ipv4-address-first'])) AND ($object['ipv4-address-first'] != "")) {
                        $ip=$object['ipv4-address-first']."-".$object['ipv4-address-last'];
                        $addNetworksv4[]="('$address_lid','ip-range','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }

                    if ((isset($object['ipv6-address-first'])) AND ($object['ipv6-address-first']!="")){
                        $ip=$object['ipv6-address-first']."-".$object['ipv6-address-last'];
                        $addNetworksv6[]="('$address_lid','ip-range','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "simple-gateway":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "CpmiHostCkp":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid''ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "CpmiGatewayCluster":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid''ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "Track":
                # Generate Log so this object will not be migrated
                if ($object['name']=="Log"){
                    $common['log']=$name;
                }
                elseif($object['name']=="None"){
                    $common['none']=$name;
                }
                break;
            case "CpmiAnyObject":
                if ($object['name']=="Any"){
                    $common["any"]=$name;
                }
                elseif($object['name']=="All"){
                    $common["all"]=$name;
                }
                break;
            case "RulebaseAction":
                $action=$object['name'];
                if ($action=="Accept"){$action="allow";}
                elseif($action=="Drop"){$action="drop";}
                elseif ($action=="Reject"){$action="deny";}
                $common["$action"]=$name;
                break;
            case "Global":
                $global=$object['name'];
                if ($global=="Policy Targets"){
                    $common["Policy Targets"]=$name;
                }
                elseif ($global=="Original"){
                    $common["Original"]=$name;
                }
                elseif ($global=="Inner Layer"){
                    $common["Inner Layer"]=$name;
                }
                break;
            case "CpmiGatewayPlain":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "CpmiClusterMember":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }
                }
                break;
            case "time":
                echo "Unsupported Object TIME".PHP_EOL;
                print_r($object);
                break;
            case "vpn-community-meshed":
                echo "Unsupported Object VPN COMMUNITY MESHED".PHP_EOL;
                print_r($object);
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
            case "group-with-exclusion":
                if (!isset($fullObject[$name])){
                    $objectsExclusionGroups[]=$object;
                }
                break;
            default:
                if ($object['type']=="group"){
                    $objectsGroups[]=$object;
                }
                elseif ($object['type']=="service-group"){
                    $objectsServicesGroups[]=$object;
                }
                else{
                    echo "#######Unsupported Object#####\n";
                    print $object['type'];
                    echo "########Unsupported Object####\n";
                }
                break;
        }
    }

    if (count($objectsGroups)>0){
        $missingMembersPerAddressGroup = array(); //This will be a "list" of the missing members in each group after the first pass

        foreach ($objectsGroups as $object) {
            $name_int = normalizeNames(truncate_names($object['name']));
            $name = $object['uid'];
            if (!isset($fullObject[$name])){
                $description = isset($object['comments'])? addslashes($object['comments']):'';
                $addAddressGroups[]="('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                $fullObject[$name]["member_lid"]=$aglid;
                $fullObject[$name]["table_name"]="address_groups_id";
                if (isset($object['members'])){
                    $parentAG=$aglid;
                    foreach ($object['members'] as $member){
                        if (is_array($member)) {
                            if ( (isset($member['uid'])) AND (isset($fullObject[$member['uid']])) ) {
                                $member_lid=$fullObject[$member['uid']]["member_lid"];
                                $table_name=$fullObject[$member['uid']]["table_name"];
                                $addAddressMembers[]="('$vsys','".$member['uid']."','$parentAG','$source','$member_lid','$table_name')";
                            }
                            else{
                                if ($member['type']=="group"){
                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                    $name1 = $member['uid'];
                                    $description = addslashes($member['comments']);
                                    $aglid++;
                                    $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                                    $addAddressGroups[]="('$aglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                    $fullObject[$name1]["member_lid"]=$aglid;
                                    $fullObject[$name1]["table_name"]="address_groups_id";
                                    if (isset($member['members'])) {
                                        foreach ($member['members'] as $member2) {
                                            if (is_array($member2)) {
                                                if ((isset($member2['uid'])) AND (isset($fullObject[$member2['uid']]))) {
                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                    $addAddressMembers[] = "('$vsys','" . $member2['uid'] . "','$aglid','$source','$member_lid2','$table_name2')";
                                                }
//                                                else {
//                                                    print "ERROR:";print_r($member2);
//                                                }
                                            }
                                            else{
                                                if (isset($fullObject[$member2])) {
                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                    $addAddressMembers[] = "('$vsys','" . $member2 . "','$aglid','$source','$member_lid2','$table_name2')";
                                                } else {
//                                                    add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                    $missingMembersPerAddressGroup[$aglid]['members'][] = $member2; //This member may not have been created as a group yet
                                                    $missingMembersPerAddressGroup[$aglid]['name'] = $name_int1;
                                                }
                                            }
                                        }
                                    }
                                    $aglid++;
                                }
//                                else{
//                                    print "ERROR---";print_r($member);
//                                }

                               // add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.print_r($member),$source,'Check in your Checkpoint GUI','','','');
                            }
                        }
                        else{
                            if (isset($fullObject[$member])){
                                $member_lid=$fullObject[$member]["member_lid"];
                                $table_name=$fullObject[$member]["table_name"];
                                $addAddressMembers[]="('$vsys','".$member."','$aglid','$source','$member_lid','$table_name')";
                            }
                            else{
//                                add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.$member,$source,'Check in your Checkpoint GUI','','','');
                                $missingMembersPerAddressGroup[$aglid]['members'][] = $member; //This member may not have been created as a group yet
                                $missingMembersPerAddressGroup[$aglid]['name'] = $name_int;
                            }
                        }
                    }
                }
                $aglid++;

                if (isset($object['groups'])){
                    foreach ($object['groups'] as $internalgroup){
                        if (isset($internalgroup['uid'])){
                            $name_int = normalizeNames(truncate_names($internalgroup['name']));
                            $name = $internalgroup['uid'];

                            if (!isset($fullObject[$name])){
                                $description = addslashes($internalgroup['comments']);
                                $addAddressGroups[]="('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                                $fullObject[$name]["member_lid"]=$aglid;
                                $fullObject[$name]["table_name"]="address_groups_id";
                                if (isset($object['members'])){
                                    $parentAG=$aglid;
                                    foreach ($internalgroup['members'] as $member){
                                        if (is_array($member)) {
                                            if ( (isset($member['uid'])) AND (isset($fullObject[$member['uid']])) ) {
                                                $member_lid=$fullObject[$member['uid']]["member_lid"];
                                                $table_name=$fullObject[$member['uid']]["table_name"];
                                                $addAddressMembers[]="('$vsys','".$member['uid']."','$parentAG','$source','$member_lid','$table_name')";
                                            }
                                            else{
                                                if ($member['type']=="group"){
                                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                                    $name1 = $member['uid'];
                                                    $description = addslashes($member['comments']);
                                                    $aglid++;
                                                    $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                                                    $addAddressGroups[]="('$aglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                                    $fullObject[$name1]["member_lid"]=$aglid;
                                                    $fullObject[$name1]["table_name"]="address_groups_id";
                                                    if (isset($member['members'])) {
                                                        foreach ($member['members'] as $member2) {
                                                            if (is_array($member2)) {
                                                                if ((isset($member2['uid'])) AND (isset($fullObject[$member2['uid']]))) {
                                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                                    $addAddressMembers[] = "('$vsys','" . $member2['uid'] . "','$aglid','$source','$member_lid2','$table_name2')";
                                                                }
//                                                                else {
//                                                                    print "ERROR:";print_r($member2);
//                                                                }
                                                            }
                                                            else{
                                                                if (isset($fullObject[$member2])) {
                                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                                    $addAddressMembers[] = "('$vsys','" . $member2 . "','$aglid','$source','$member_lid2','$table_name2')";
                                                                } else {
//                                                                    add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                                    $missingMembersPerAddressGroup[$aglid]['members'][] = $member2; //This member may not have been created as a group yet
                                                                    $missingMembersPerAddressGroup[$aglid]['name'] = $name_int1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    $aglid++;
                                                }
                                                else{
                                                    print "ERROR---";print_r($member);
                                                }

                                                // add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.print_r($member),$source,'Check in your Checkpoint GUI','','','');
                                            }
                                        }
                                        else{
                                            if (isset($fullObject[$member])){
                                                $member_lid=$fullObject[$member]["member_lid"];
                                                $table_name=$fullObject[$member]["table_name"];
                                                $addAddressMembers[]="('$vsys','".$member."','$aglid','$source','$member_lid','$table_name')";
                                            }
                                            else{
//                                                add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.$member,$source,'Check in your Checkpoint GUI','','','');
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

        //Now that we have loaded all the groups, we could try to fix those missingMembersPerAddressGroup that we could not find
        foreach ($missingMembersPerAddressGroup as $aglid => $data){
            $groupName = $data['name'];
            foreach ($data['members'] as $missingMember) {
                if (isset($fullObject[$missingMember])) {
                    $member_lid = $fullObject[$missingMember]["member_lid"];
                    $table_name = $fullObject[$missingMember]["table_name"];
                    $addAddressMembers[] = "('$vsys','" . $missingMember . "','$aglid','$source','$member_lid','$table_name')";
                } else {

                    add_log2('error', 'Reading Member Groups', 'Group called ' . $groupName . ' is missing this member UID: ' . $missingMember, $source, 'Check in your Checkpoint GUI', '', '', '');
                }
            }
        }
    }

    if (count($objectsExclusionGroups)>0){

        foreach ($objectsExclusionGroups as $key => $object) {

            $name_int = normalizeNames(truncate_names($object['name']));
            $name = trim($object['uid']);
            $addAddressGroups[]="('$aglid','$name','$name_int','group_with_exclusion','$filename','$source','$vsys','$description')";
            $fullObject[$name]["member_lid"]=$aglid;
            $fullObject[$name]["table_name"]="address_groups_id";
            $parentAG=$aglid;
            $aglid++;

            if(isset($fullObject[trim($object['include']['uid'])])){
                $member_lid=$fullObject[$object['include']['uid']]["member_lid"];
                $table_name=$fullObject[$object['include']['uid']]["table_name"];
                $addAddressMembers[]="('$vsys','".$object['include']['uid']."','$parentAG','$source','$member_lid','$table_name')";
            }
            else{
                if ($object['include']['type']=="group"){
                    $name_int2 = normalizeNames(truncate_names($object['include']['name']));
                    $name2 = trim($object['include']['uid']);
                    $addAddressGroups[]="('$aglid','$name2','$name_int2','static','$filename','$source','$vsys','$description')";
                    $fullObject[$name2]["member_lid"]=$aglid;
                    $fullObject[$name2]["table_name"]="address_groups_id";
                    $newParentAG=$aglid;
                    $addAddressMembers[]="('$vsys','".$object['include']['uid']."','$parentAG','$source','$aglid','address_groups_id')";
                    $aglid++;
                    $members=trim($object['include']['members'][0]);
                    if (isset($fullObject[$members])){
                        $member_lid=$fullObject[$members]["member_lid"];
                        $table_name=$fullObject[$members]["table_name"];
                        $addAddressMembers[]="('$vsys','$members','$newParentAG','$source','$member_lid','$table_name')";
                    }
                    else{
                        echo "The include Member is not found\n";
                        print_r($object);
                    }
                }
            }
            if(isset($fullObject[$object['except']['uid']])){
                $member_lid=$fullObject[$object['except']['uid']]["member_lid"];
                $table_name=$fullObject[$object['except']['uid']]["table_name"];
                $addAddressMembers[]="('$vsys','".$object['except']['uid']."','$parentAG','$source','$member_lid','$table_name')";
            }
            else{
                if ($object['except']['type']=="group"){
                    $name_int2 = normalizeNames(truncate_names($object['except']['name']));
                    $name2 = trim($object['except']['uid']);
                    $addAddressGroups[]="('$aglid','$name2','$name_int2','static','$filename','$source','$vsys','$description')";
                    $fullObject[$name2]["member_lid"]=$aglid;
                    $fullObject[$name2]["table_name"]="address_groups_id";
                    $newParentAG=$aglid;
                    $addAddressMembers[]="('$vsys','".$object['except']['uid']."','$parentAG','$source','$aglid','address_groups_id')";
                    $aglid++;
                    $members=trim($object['except']['members'][0]);
                    if (isset($fullObject[$members])){
                        $member_lid=$fullObject[$members]["member_lid"];
                        $table_name=$fullObject[$members]["table_name"];
                        $addAddressMembers[]="('$vsys','$members','$newParentAG','$source','$member_lid','$table_name')";
                    }
                    else{
                        echo "The Exclude Member is not found\n";
                        print_r($object);
                    }
                }
            }
            $aglid++;
        }
    }

    if (count($objectsServicesGroups)>0){
        foreach ($objectsServicesGroups as $key => $object) {
            $name_int = normalizeNames(truncate_names($object['name']));
            $name = $object['uid'];
            if (!isset($fullObject[$name])){
                $description = addslashes($object['comments']);
                $addServicesGroups[]="('$sglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                $fullObject[$name]["member_lid"]=$sglid;
                $fullObject[$name]["table_name"]="services_groups_id";
                if (isset($object['members'])) {
                    $parentSG=$sglid;
                    foreach ($object['members'] as $member) {
                        if (is_array($member)) {
                            if ((isset($member['uid'])) AND (isset($fullObject[$member['uid']]))) {
                                $member_lid = $fullObject[$member['uid']]["member_lid"];
                                $table_name = $fullObject[$member['uid']]["table_name"];
                                $addServicesMembers[] = "('$vsys','" . $member['uid'] . "','$parentSG','$source','$member_lid','$table_name')";
                            } else {
                                if ($member['type']=="service-group"){
                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                    $name1 = $member['uid'];
                                    $description = addslashes($member['comments']);
                                    $sglid++;
                                    $addServicesMembers[] = "('$vsys','" . $member['uid'] . "','$parentSG','$source','$sglid','services_groups_id')";
                                    $addServicesGroups[]="('$sglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                    $fullObject[$name1]["member_lid"]=$sglid;
                                    $fullObject[$name1]["table_name"]="services_groups_id";
                                    if (isset($member['members'])) {
                                        foreach ($member['members'] as $member2) {
                                            if (is_array($member2)) {
                                                if ((isset($member2['uid'])) AND (isset($fullObject[$member2['uid']]))) {
                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                    $addServicesMembers[] = "('$vsys','" . $member2['uid'] . "','$sglid','$source','$member_lid2','$table_name2')";
                                                }
//                                                else {
//                                                    print "ERROR:";print_r($member2);
//                                                }
                                            }
                                            else{
                                                if (isset($fullObject[$member2])) {
                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                    $addServicesMembers[] = "('$vsys','" . $member2 . "','$sglid','$source','$member_lid2','$table_name2')";
                                                } else {
                                                    add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                    $missingMembersPerAddressGroup[$aglid][] = $member2; //This member may not have been created as a group yet
                                                }
                                            }
                                        }
                                    }
                                    $sglid++;
                                }
//                                else{
//                                    print "Error: ".print_r($member);
//                                }


                                //add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int . ' is missing this member UID: ' . implode(",",$member), $source, 'Check in your Checkpoint GUI', '', '', '');
                            }
                        } else {
                            if (isset($fullObject[$member])) {
                                $member_lid = $fullObject[$member]["member_lid"];
                                $table_name = $fullObject[$member]["table_name"];
                                $addServicesMembers[] = "('$vsys','" . $member . "','$sglid','$source','$member_lid','$table_name')";
                            } else {
                                add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int . ' is missing this member UID: ' . $member, $source, 'Check in your Checkpoint GUI', '', '', '');
                                $missingMembersPerAddressGroup[$aglid][] = $member; //This member may not have been created as a group yet
                            }
                        }

                    }
                }

                $sglid++;
            }
        }
    }

    # Add Address and Groups
    if (count($addNetworksv4)>0){
        $unique=array_unique($addNetworksv4);
        $projectdb->query("INSERT INTO address (id,type,vtype,ipaddress,cidr,name_ext,name,checkit,v4,description,source,devicegroup) VALUES ".implode(",",$unique).";");
        unset($addNetworksv4);unset($unique);
    }
    if (count($addNetworksv6)>0){
        $unique=array_unique($addNetworksv6);
        $projectdb->query("INSERT INTO address (id,type,vtype,ipaddress,cidr,name_ext,name,checkit,v6,description,source,devicegroup) VALUES ".implode(",",$unique).";");
        unset($addNetworksv6);unset($unique);
    }
    if (count($addAddressGroups)>0){
        $projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,type,devicegroup,source,vsys,description) VALUES ".implode(",",$addAddressGroups).";");
        unset($addAddressGroups);
        if (count($addAddressMembers)>0){
            $projectdb->query("INSERT INTO address_groups (vsys,member,lid,source,member_lid,table_name) VALUES ".implode(",",$addAddressMembers).";");
            unset($addAddressMembers);
        }
    }
    # Add Services and Groups
    if (count($addServices)>0){
        $unique=array_unique($addServices);
        $projectdb->query("INSERT INTO services (id,name_ext,name,protocol,dport,checkit,description,source,icmp,devicegroup) VALUES ".implode(",",$unique).";");
        unset($services);unset($unique);
    }
    if (count($addServicesGroups)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,type,devicegroup,source,vsys,description) VALUES ".implode(",",$addServicesGroups).";");
        unset($addServicesGroups);
        if (count($addServicesMembers)>0){
            $projectdb->query("INSERT INTO services_groups (vsys,member,lid,source,member_lid,table_name) VALUES ".implode(",",$addServicesMembers).";");
            unset($addServicesMembers);
        }
    }
    unset($fullObject);
    return $common;

}

function getMemberlid($table,$name_ext,$source,$vsys,$policy,$lid){
    global $projectdb;

    if ($policy=="Nat"){$policy2="nat_rules";}
    elseif ($policy=="Security"){$policy2="security_rules";}
    else{
        $policy2="unknown:".$policy;
    }
    $output=array(0,0);
    if ($table=="services"){$tablegroup="services_groups_id";}
    elseif ($table=="address"){$tablegroup="address_groups_id";}
    $getID=$projectdb->query("SELECT id FROM $table WHERE name_ext='$name_ext' AND vsys='$vsys' AND source='$source' LIMIT 1;");
    if ($getID->num_rows==1){
        $getIDData=$getID->fetch_assoc();
        $output=array($getIDData['id'],$table);
    }
    else{
        $getID=$projectdb->query("SELECT id FROM $tablegroup WHERE name_ext='$name_ext' AND vsys='$vsys' AND source='$source' LIMIT 1;");
        if ($getID->num_rows==1) {
            $getIDData = $getID->fetch_assoc();
            $member_lid = $getIDData['id'];
            $output = array($getIDData['id'], $tablegroup);
        }
        else{
            # Needs to create one Raise Log as well
            if ($table=="address"){
                $checkExits=$projectdb->query("SELECT id FROM address WHERE name='$name_ext' AND source='$source';");
                if ($checkExits->num_rows==1){
                    $checkExitsData=$checkExits->fetch_assoc();
                    $output=array($checkExitsData['id'],$table);
                }
                else{
                    $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,v4) VALUES ('$name_ext','$name_ext','1.1.1.1','32','$source','$vsys',1);");
                    $output = array($projectdb->insert_id,"address");
                    add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$name_ext.'] but is not defined in my Database.',$source,'Adding to the DB [ip:1.1.1.1]. Fix IP Address','rules',$lid,$policy2);
                }
            }
            elseif($table=="services"){
                $checkExits=$projectdb->query("SELECT id FROM services WHERE name='$name_ext' AND source='$source';");
                if ($checkExits->num_rows==1){
                    $checkExitsData=$checkExits->fetch_assoc();
                    $output=array($checkExitsData['id'],$table);
                }
                else{
                    $projectdb->query("INSERT INTO services (name_ext,name,source,vsys) VALUES ('$name_ext','$name_ext','$source','$vsys');");
                    $output = array($projectdb->insert_id,"services");
                    add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$name_ext.'] but is not defined in my Database.',$source,'Adding to the DB. Fix Protocol/Port','rules',$lid,$policy2);
                }
            }
            else{
                add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$name_ext.'] but is not defined in my Database.',$source,'Add it manually','rules',$lid,$policy2);
            }

        }
    }
    return $output;
}

function explodeGroups2MembersCheckpoint($members, $level=0){
    $tmp_members=array();

    foreach($members as $member){
        if ((isset($member['type'])) AND ($member['type']!="group") AND ($member['type']!="service-group")){
            $tmp_members[]=$member;
        }
        else{
            if (isset($member['members'])){
                $tmp_members[]=$member;
                $tmp_members = array_merge($tmp_members, explodeGroups2MembersCheckpoint($member['members'], $level+1));
            }
            else{
                #Debug
                //print_r($member);
            }
        }
    }
    $input = array_map("unserialize", array_unique(array_map("serialize", $tmp_members)));
    return $input;
}

function get_routes($project,$source,$template,$vsys){
#Support for ipv4 by now
    global $projectdb;
    $count=0;
    $routes_file=USERSPACE_PATH."/projects/$project/routes.txt";
    $routes_out =USERSPACE_PATH."/projects/$project/routes.out";
    if (file_exists($routes_file)){
        #Trick to clean the file and align
        $command="cat $routes_file | awk '{print $1, $2, $3, $4, $5, $6, $7, $8}' > $routes_out";
        shell_exec($command);
        #clean the ctrl+M
        $command="tr -d \'\r\' < $routes_out > $routes_file";
        shell_exec($command);
        #Open the fixed file
        $routes = file($routes_file);
        #Log


        $whichtable="";
        $fields=array();

        #Create a VR
        $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
        if ($getVR->num_rows==0){
            $projectdb->query("INSERT INTO virtual_routers (name,source,template,vsys) VALUES ('chkpt-vr','$source','$template','$vsys');");
            $vr_id=$projectdb->insert_id;
        }
        else{
            $getVRData=$getVR->fetch_assoc();
            $vr_id=$getVRData['id'];
        }


        foreach ($routes as $line => $routes_line1){
            $routes_line=rtrim($routes_line1);
            $fields=explode(' ',$routes_line);
            if (($fields[0] == "Destination") and ($fields[1] == "Gateway") and ($fields[2] == "Genmask")){$whichtable="linux"; break;}
            elseif (preg_match("/^255./i", $fields[1])) { $whichtable="other"; break; }
            elseif (($fields[0] == "Destination") and ($fields[1] == "Type") and ($fields[2] == "Ref") and ($fields[3] == "NextHop")){$whichtable="gaia"; break;}
            elseif (($fields[0] == "Destination") and ($fields[1] == "Gateway") and ($fields[2] == "Flags") and ($fields[3] == "Refs")){$whichtable="ipso"; break;}
            elseif (($fields[0] == "Destination") AND ($fields[1] == "Type") AND ($fields[3] == "NextHop")){$whichtable="ipso2"; break;}
            elseif (preg_match("/255./i", $fields[2])) {$whichtable="splat"; break;}
            else {$whichtable="idontknow";}
        }

        $addRoutes=array();
        $i=0;
        $x=0;
        $y=0;
        foreach ($routes as $line => $routes_line) {
            $network="";
            $gateway="";
            $netmask="";
            $flags="";
            $metric="";
            $ref="";
            $use="";
            $interface="";
            $zone="";

            if ($whichtable == 'linux'){
                list($network,$gateway,$netmask,$flags,$metric,$ref,$use,$interface)=explode(" ",$routes_line);
            }
            elseif ($whichtable == 'splat'){
                list($network,$gateway,$netmask,$flags,$metric,$ref,$use,$interface)=explode(" ",$routes_line);
            }
            elseif ($whichtable == 'other'){
                list($network,$netmask,$gateway,$flags,$metric,$ref,$use,$interface)=explode(" ",$routes_line);
            }
            elseif ($whichtable == 'ipso'){
                list($network_and_mask,$gateway,$flags,$ref,$use,$interface)=explode(" ",$routes_line);
                if (($network_and_mask=="default") and ($gateway!="RCSU")){$network="default";}
                elseif(($flags=="lCGSU") or ($flags=="lCSU") or ($flags=="iCGSU") or ($flags=="lGC") or ($flags=="gCDSU")){$network="ignore";}
                elseif ($gateway=="RCSU"){$network="ignore";}
                elseif (($gateway=="rCGSU") or ($gateway=="CGUX")) {
                    #Interfaces
                    list($net,$mask)=explode("/",$network_and_mask);
                    list($a,$b,$c,$d)=explode(".",$net);
                    if ($b==""){$b=0;}
                    if ($c==""){$c=0;}
                    if ($d==""){$d=0;}
                    $network=$a.".".$b.".".$c.".".$d;
                    $netmask =convertNetmaskv4($mask);
                    $gateway ="0.0.0.0";
                    $metric=1;
                }
                elseif(($flags=="iCSU") or ($flags=="iSUW") or ($flags=="CU")){
                    if(validateIpAddress($network_and_mask,"v4")){
                        $network=$network_and_mask;
                        $netmask ="255.255.255.255";
                        $metric=1;
                    }
                    elseif (preg_match("/\//i",$network_and_mask)){
                        list($net,$mask)=explode("/",$network_and_mask);
                        list($a,$b,$c,$d)=explode(".",$net);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask =convertNetmaskv4($mask);
                        $metric=1;
                    }
                }
            }
            elseif ($whichtable == 'ipso2'){
                list($network_and_mask,$kk,$kk1,$gateway,$flags,$ref,$use,$interface)=explode(" ",$routes_line);
                if (($network_and_mask=="default") and ($gateway!="RCSU")){$network="default";}
                elseif($kk=="clon"){$network="ignore";}
                elseif (($gateway=="rCGSU") or ($gateway=="CGUX")) {
                    #Interfaces
                    list($net,$mask)=explode("/",$network_and_mask);
                    list($a,$b,$c,$d)=explode(".",$net);
                    if ($b==""){$b=0;}
                    if ($c==""){$c=0;}
                    if ($d==""){$d=0;}
                    $network=$a.".".$b.".".$c.".".$d;
                    $netmask =convertNetmaskv4($mask);
                    $gateway ="0.0.0.0";
                    $metric=1;
                }
                elseif(($flags=="iCSU") or ($flags=="iSUW") or ($flags=="CU")){
                    if(validateIpAddress($network_and_mask,"v4")){
                        $network=$network_and_mask;
                        $netmask ="255.255.255.255";
                        $metric=1;
                    }
                    elseif (preg_match("/\//i",$network_and_mask)){
                        list($net,$mask)=explode("/",$network_and_mask);
                        list($a,$b,$c,$d)=explode(".",$net);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask =convertNetmaskv4($mask);
                        $metric=1;
                    }
                }
            }
            elseif ($whichtable == 'gaia'){
                list($network_and_mask,$type,$ref,$gateway,$type2,$ref,$interface,$interface2)=explode(" ",$routes_line);
                if (($network_and_mask=="default") and ($gateway!="RCSU")){$network="default";}
                elseif($type=="clon"){$network="ignore";}
                elseif (($type=="dest") AND ($gateway=="rslv")) {
                    #Interfaces
                    list($net,$mask)=explode("/",$network_and_mask);
                    list($a,$b,$c,$d)=explode(".",$net);
                    if ($b==""){$b=0;}
                    if ($c==""){$c=0;}
                    if ($d==""){$d=0;}
                    $network=$a.".".$b.".".$c.".".$d;
                    $netmask =convertNetmaskv4($mask);
                    $gateway ="0.0.0.0";
                    $metric=1;
                }
                elseif(($type=="user") AND ($type2=="dest")){
                    if(validateIpAddress($network_and_mask,"v4")){
                        $network=$network_and_mask;
                        $netmask ="255.255.255.255";
                        $metric=1;
                    }
                    elseif (preg_match("/\//i",$network_and_mask)){
                        list($net,$mask)=explode("/",$network_and_mask);
                        list($a,$b,$c,$d)=explode(".",$net);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask =convertNetmaskv4($mask);
                        $metric=1;
                    }
                }
            }
            elseif ($whichtable == "idontknow") {
                if (preg_match("/ via /i",$routes_line)){
                    $keywords = preg_split("/[\s,]+/", $routes_line);
                    $key=array_search('via', $keywords);
                    if ($keywords[$key-1]=="0.0.0.0/0"){
                        if (validateIpAddress($keywords[$key+1],"v4")){
                            $gateway=$keywords[$key+1];
                            $network="0.0.0.0";
                            $netmask="0.0.0.0";
                        }
                    } else {
                        #check the IP address v4 or v6 and is not the default ? FIX THIS
                        $keywords = preg_split("/[\s,]+/", $routes_line);
                        $key=array_search('via', $keywords);
                        if (validateIpAddress($keywords[$key+1],"v4")){
                            $gateway=$keywords[$key+1];
                            $network_and_mask=$keywords[$key-1];
                            if (preg_match("/\//i",$network_and_mask)){
                                list($net,$mask)=explode("/",$network_and_mask);
                                list($a,$b,$c,$d)=explode(".",$net);
                                if ($b==""){$b=0;}
                                if ($c==""){$c=0;}
                                if ($d==""){$d=0;}
                                $network=$a.".".$b.".".$c.".".$d;
                                $netmask =convertNetmaskv4($mask);
                                $metric=1;
                            }
                        }
                    }

                }
                elseif (preg_match("/ is directly connected, /",$routes_line)){
                    $keywords = preg_split("/[\s,]+/", $routes_line);
                    $key=array_search('is', $keywords);
                    $network_and_mask=explode("/",$keywords[$key-1]);
                    $network=$network_and_mask[0];
                    if (validateIpAddress($network,"v4")){
                        $netmask=convertNetmaskv4($network_and_mask[1]);
                        $gateway="0.0.0.0";
                        $zone=$keywords[$key+3];
                    } else {
                        list($a,$b,$c,$d)=explode(".",$network);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask=convertNetmaskv4($network_and_mask[1]);
                        $gateway="0.0.0.0";
                        $zone=$keywords[$key+3];
                    }
                }
            }

            $int_tmp=trim($interface);
            $interface=$int_tmp;
            $unitname=$interface;

            if ($metric == "0"){$metric="1";}
            if ($metric==""){$metric="1";}
            if ($network == "Destination"){}
            elseif ($network == ""){}
            elseif ($network == "255.255.255.255"){}
            elseif (($flags=="CGU") or ($flags=="UW")){}
            elseif ($network == "ignore"){}
            elseif (preg_match("/\#/",$network)){}
            elseif (($gateway=="*") and ($netmask=="255.255.255.255") and ($network=="localhost")){}
            elseif (($gateway == "gCDSU") or ($gateway == "BCSU") or ($gateway == "RCGSU") or ($gateway == "lCSU") or ($gateway == "RCU") or ($gateway == "CDU") or ($gateway == "BCU") or ($gateway == "RGCU") or ($gateway == "CG") or ($gateway == "CU") or ($gateway == "CGU")){}
            elseif ($network == "Kernel"){}
            elseif (($network == "127.0.0.0") or ($network == "127.0.0.1")){
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Ignoring loopback interface '.$network);
            }
            elseif ($network == "224.0.0.2") {
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Ignoring Multicast interface '.$network);
            }
            elseif (($network == "0.0.0.0") and ($netmask == "0.0.0.0")) {
                $ip_version="v4";
                if (validateIpAddress($gateway,$ip_version)){
                    if ($count==0){
                        $addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }
                    else{
                        $newRouteName="default ".$count;
                        $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$newRouteName','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }

                }
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('$network','$gateway','$netmask','$metric','default','','$project');");
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / '.$netmask.' - '.$gateway);
            }
            elseif (($network == "0.0.0.0") and ($netmask == "255.255.255.255")) {
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('$network','$gateway','0.0.0.0','$metric','default','','$project');");
                $ip_version="v4";
                if (validateIpAddress($gateway,$ip_version)){
                    $addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                }
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / 0.0.0.0 - '.$gateway);
            }
            elseif ($network == "default"){
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('0.0.0.0','$gateway','0.0.0.0','$metric','default','','$project');");
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / 0.0.0.0 - '.$gateway);
                $ip_version="v4";
                if (validateIpAddress($gateway,$ip_version)){
                    if ($count==0){
                        $addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }
                    else{
                        $newRouteName="default ".$count;
                        $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$newRouteName','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }

                }
            }
            elseif(($gateway=="*") and ($flags=="U")){
                $x++;
                $zoneName="Zone".$x;
                $cidr=mask2cidrv4($netmask);
                $media="ethernet";
                $unittag=0;
                if ($interface==""){$y++;$interface="ethernet1/".$y;$unitname=$interface;}
                elseif (preg_match("/bond/",$interface)){
                    $int_tmp=str_replace("bond","",$interface);
                    $int_tmp2=explode(".",$int_tmp);
                    if (count($int_tmp2)==1){$unittag=0;}else{$unittag=intval($int_tmp2[1]);}
                    if ($int_tmp2[0]==0){$unitname_tmp="1";}else{$unitname_tmp=$int_tmp2[0]+1;}
                    $unitname="ae".$unitname_tmp.".".$unittag;
                    $interface="ae".$unitname_tmp;
                    $media="aggregate-ethernet";
                }
                else{
                    $interface=trim($interface);
                    $int_tmp2=explode(".",$interface);
                    if (count($int_tmp2)==1){$unittag="";}else{$unittag=intval($int_tmp2[1]);}
                    $interface=$int_tmp2[0];
                    if (($unittag=="") OR ($unittag==0)){
                        $unitname=$interface;
                    }
                    else{
                        $unitname=$interface.".".$unittag;
                        if (preg_match("/.0$/",$interface)){
                            $int_tmp2=explode(".",$interface);
                            $interface=$int_tmp2[0];
                        }
                    }

                }
                $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','$network/$cidr','$unitname','$zoneName','$unittag');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','layer3','$unitname');");
                $interface="";
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project) values ('$network','0.0.0.0','$netmask','$metric','$project');");
            }
            elseif(($gateway=="0.0.0.0") AND (($flags=="rCGSU") OR ($network!="0.0.0.0"))){
                $x++;
                $zoneName="Zone".$x;
                $cidr=mask2cidrv4($netmask);
                $media="ethernet";
                $unittag=0;
                if ($interface==""){$y++;$interface="ethernet1/".$y;$unitname=$interface;}
                elseif (preg_match("/bond/",$interface)){
                    $int_tmp=str_replace("bond","",$interface);
                    $int_tmp2=explode(".",$int_tmp);
                    if ($int_tmp2[0]==0){$unitname_tmp="1";}else{$unitname_tmp=$int_tmp2[0]+1;}
                    if (count($int_tmp2)==1){$unittag=0;}else{$unittag=intval($int_tmp2[1]);}
                    $unitname="ae".$unitname_tmp.".".$unittag;
                    $interface="ae".$unitname_tmp;
                    $media="aggregate-ethernet";
                }
                else{
                    $interface=trim($interface);
                    $int_tmp2=explode(".",$interface);
                    if (count($int_tmp2)==1){$unittag="";}else{$unittag=intval($int_tmp2[1]);}
                    $interface=$int_tmp2[0];
                    if (($unittag=="") OR ($unittag==0)){
                        $unitname=$interface;
                    }
                    else{
                        $unitname=$interface.".".$unittag;
                        if (preg_match("/.0$/",$interface)){
                            $int_tmp2=explode(".",$interface);
                            $interface=$int_tmp2[0];
                        }
                    }

                }


                $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','$network/$cidr','$unitname','$zoneName','$unittag');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','layer3','$unitname');");
                $interface="";
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project) values ('$network','0.0.0.0','$netmask','$metric','$project');");
            }
            else {
                $i++;
                $name="Route ".$i;
                $ip_version="v4";
                $cidr=mask2cidrv4($netmask);
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project,zone) values ('$network','$gateway','$netmask','$metric','$project','$zone');");
                #$addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$name','$network/$cidr','','ip-address','$gateway','$metric','$vsys')";
            }
        }

        if (count($addRoutes)>0){
            $unique=array_unique($addRoutes);
            $projectdb->query("INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES ".implode(",",$unique).";");
            unset($addRoutes);
        }
        #Clean the vars

        $routes="";

        # Get Interfaces to VR
        $getInterface=$projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id' AND source='$source';");
        if ($getInterface->num_rows>0){
            $myInterfaces = array();
            while ($data=$getInterface->fetch_assoc()){
                $myInterfaces[]=$data['unitname'];
            }
            $projectdb->query("UPDATE virtual_routers SET interfaces='".implode(",",$myInterfaces)."' WHERE id='$vr_id';");
        }
    }

}

function calculateExclusionGroups($source){

    global $projectdb;

    $getLid = $projectdb->query("SELECT id, vsys, source, devicegroup FROM address_groups_id WHERE type = 'group_with_exclusion' AND source='$source';");

    if ($getLid->num_rows > 0) {
        while ($dataLid = $getLid->fetch_assoc()) {
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
            foreach($incGroupExpanded_p as $index => $object){

                if($object['table_name'] == "address_groups_id"){
                    $incGroupExpanded = expandMembersGroups($object['member_lid'], "3");
                    foreach($incGroupExpanded as $index => $object2){

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        $incGroupExpanded[$index] = Array('object'=>$object2['member'], 'member_lid'=>$object2['member_lid'], 'table_name'=>$object2['table_name'], 'start'=>$res['start'],
                            'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']), 'status'=>0);

                    }

                }
                else{

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    $incGroupExpanded[$index] = Array('object'=>$object['member'], 'member_lid'=>$object['member_lid'], 'table_name'=>$object['table_name'], 'start'=>$res['start'],
                        'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']), 'status'=>0);
                }
            }

            foreach($exclGroupExpanded_p as $index => $object){

                if($object['table_name'] == "address_groups_id"){
                        $exclGroupExpanded = expandMembersGroups($object['member_lid'], "3");

                    foreach($exclGroupExpanded as $index => $object2){

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        $exclGroupExpanded[$index] = Array('object'=>$object2['member'], 'member_lid'=>$object2['member_lid'], 'table_name'=>$object2['table_name'], 'start'=>$res['start'],
                            'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']) );

                    }

                }
                else{

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    $exclGroupExpanded[$index] = Array('object'=>$object['member'], 'member_lid'=>$object['member_lid'], 'table_name'=>$object['table_name'], 'start'=>$res['start'],
                        'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']) );
                }
            }

            //  Now we need to match all excl vs inc objects
            foreach($exclGroupExpanded as $index => &$excl){
                foreach($incGroupExpanded as &$incl){
                    // this object was already fully matched so we skip
                    if($incl['status'] == 2) continue;
                    if($incl['start'] >= $excl['start'] && $incl['end'] <= $excl['end']){
                        $incl['status'] = 2;
                    }
                    elseif( $incl['start'] >= $excl['start'] &&  $incl['start'] <= $excl['end'] || $incl['end'] >= $excl['start'] && $incl['end'] <= $excl['end']
                        || $incl['start'] <= $excl['start'] && $incl['end'] >= $excl['end'] ){
                        $incl['status'] = 1;
                    }
                }
            }//fin foreach

            // First filter is done, now we make a list of Incl objects :
            // - Partial matches, these ones will require special treatment
            // - FULL matches, these ones will not be included in final group
            // - NO matches, these ones will be included in final group
            $inclPartial = Array();
            $inclNo = Array();


            foreach( $incGroupExpanded as &$incl ){

                if(($incl['status'] == 1 ) || ($incl['status'] == 2)){
                    $inclPartial[] = &$incl;
                }elseif( $incl['status'] == 0 ){
                    $inclNo[] = &$incl;
                }
            }

            // Sort incl objects IP mappings by Start IP
            $inclMapping = Array();
            $tmp = Array();
            foreach($inclPartial as &$incl){
                $tmp[] = $incl['start'];
            }
            unset($incl);
            sort($tmp, SORT_NUMERIC);
            foreach($tmp as $value){
                foreach($inclPartial as &$incl){
                    if( $value == $incl['start'] ){
                        $inclMapping[] = $incl;
                    }
                }
            }
            unset($incl);

            // Sort excl objects IP mappings by Start IP
            $exclMapping = Array();
            $tmp = Array();
            foreach($exclGroupExpanded as &$excl){
                $tmp[] = $excl['start'];
            }
            unset($excl);
            sort($tmp, SORT_REGULAR);
            foreach($tmp as $value){
                foreach($exclGroupExpanded  as &$excl){
                    if( $value == $excl['start'] ){
                        $exclMapping[] = $excl;
                    }
                }
            }
            unset($excl);

            // Merge overlapping or Incl joint entries
            $mapKeys = array_keys($inclMapping);
            $mapCount = count($inclMapping);
            for($i=0; $i < $mapCount; $i++){
                $current = &$inclMapping[$mapKeys[$i]];
                for($j=$i+1; $j<$mapCount; $j++){
                    $compare = &$inclMapping[$mapKeys[$j]];

                    if( $compare['start'] > $current['end']+1 )
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
            for($i=0; $i<$mapCount; $i++){
                $current = &$exclMapping[$mapKeys[$i]];
                for($j=$i+1; $j<$mapCount; $j++){
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
            foreach($inclMapping as $index => &$incl){
                $current = &$incl;

                foreach( $exclMapping as &$excl){
                    if($excl['start'] > $current['end'])
                        continue;
                    if($excl['start'] < $current['start'] && $excl['end'] < $current['start'])
                        continue;
                    // if this excl object is including ALL
                    if($excl['start'] <= $current['start'] && $excl['end'] >= $current['end']){
                        unset($inclMapping[$index]);
                        break;
                    }
                    elseif($excl['start'] <= $current['start'] && $excl['end'] <= $current['end']){
                        $current['start'] = $excl['end'];
                        $current['startip'] = $excl['endip'];
                    }
                    elseif($excl['start'] > $current['start'] && $excl['end'] >= $current['end']){
                        $current['end'] = $excl['start'] -1;
                        $current['endip'] = long2ip($current['end']);
                        break;
                    }
                    elseif($excl['start'] > $current['start'] && $excl['end'] < $current['end']){
                        $oldEnd = $current['end'];
                        $oldEndIP = $current['endip'];
                        $current['end'] = $excl['start']-1;
                        $current['endip'] =long2ip($current['end']);
                        unset($current);

                        $current = Array();
                        $inclMapping[] = &$current;
                        $current['start'] = $excl['end']+1;
                        $current['startip'] = long2ip($current['start']);
                        $current['end'] = $oldEnd;
                        $current['endip'] = $oldEndIP;
                    }
                }
            }

            // Sort incl objects IP mappings by Start IP
            $finalInclMapping = Array();
            $tmp = Array();
            foreach($inclMapping as &$incl3){
                $tmp[] = $incl3['start'];
            }
            unset($incl3);

            sort($tmp, SORT_NUMERIC);
            $is_first = 0;
            $members_news = array();
            foreach($tmp as $value){
                foreach($inclMapping as &$incl){
                    if($value == $incl['start']){
                        $oValue = $incl['startip']."-".$incl['endip'];

                        $oName = 'R-'.$incl['startip']."-".$incl['endip'];
                        $finalInclMapping[] = $incl;

                        $members_news[] = $oName;

                        $getExistAddress = $projectdb->query("SELECT id FROM address WHERE name = '$oName' AND type = 'ip-range' AND ipaddress = '$oValue' AND vsys = '$vsys' AND source = '$source' ");
                        if ($getExistAddress->num_rows == 1) {
                            while ($data = $getExistAddress->fetch_assoc()) {
                                $member_lid = $data['id'];
                            }
                        }else{
                            $projectdb->query("INSERT INTO address (id, name_ext, name, used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified) "
                                . "VALUES (NULL, '$oName', '$oName', '', '', '$devicegroup', '$vsys', 'ip-range','$oValue','', '', '', '', '', 'ip-range', '$source', '', '', '', '');");

                            $member_lid = $projectdb->insert_id;
                        }

                        if($is_first == 0){

                            $name_int_old = array();

                            $getNameGroup = $projectdb->query("SELECT name FROM address_groups_id WHERE id = '$lid' ");
                            if ($getNameGroup->num_rows == 1) {
                                $dataNG = $getNameGroup->fetch_assoc();
                                $group_name = $dataNG['name'];
                            }

                            $getMembersGroups = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid = '$lid' ");
                            if ($getMembersGroups->num_rows >= 1) {
                                while ($dataM = $getMembersGroups->fetch_assoc()) {
                                    $member_lid_g = $dataM['member_lid'];
                                    $table_name_g = $dataM['table_name'];

                                    $getMembersGroupsN = $projectdb->query("SELECT name FROM $table_name_g WHERE id = '$member_lid_g' ");
                                    if ($getMembersGroupsN->num_rows == 1) {
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
            foreach($inclNo as &$incl2){

                $name_int_no = $incl2['object'];
                $member_lid_no = $incl2['member_lid'];
                $table_name_no = $incl2['table_name'];
                $getExistMember = $projectdb->query("SELECT id FROM address_groups WHERE member_lid = '$member_lid_no' AND table_name = '$table_name_no' AND lid = '$lid' AND vsys = '$vsys' AND source = '$source' ");

                if ($getExistMember->num_rows == 0) {

                    $projectdb->query("INSERT INTO address_groups (id, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source) "
                        . "VALUES (NULL, '', '', '$devicegroup', '$vsys', '$name_int_no', '$member_lid_no', '$table_name_no', '$lid', '$source')");

                }
            }

            unset($incl);
            unset($incl2);
            unset($inclNo);

            if (count($members_news)>0){
                add_log('ok','Phase 2: Reading Address Objects and Groups','Group with exclusion '.$group_name.': The members {'.implode(",", $name_int_old).'} were replaced by {'.implode(",", $members_news).'}.', $source, '');
            }
            $projectdb->query("UPDATE address_groups_id SET type = 'static' WHERE id = '$lid'");
        }
    }// fin if lid
}

function expandMembersGroups($lid, $position){

    global $projectdb;

    $myMembers = array();

    if($position == "1"){
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id ASC LIMIT 1 ;");
        if ($getFirstGroup->num_rows > 0) {
            while ($data = $getFirstGroup->fetch_assoc()) {
                $myMembers[] = $data;
            }
        }
    }
    elseif($position == "2"){
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id DESC LIMIT 1 ;");
        if ($getFirstGroup->num_rows > 0) {
            while ($data = $getFirstGroup->fetch_assoc()) {
                $myMembers[] = $data;
            }
        }
    }
    elseif($position == "3"){
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid';");
        if ($getFirstGroup->num_rows > 0) {
            while ($data = $getFirstGroup->fetch_assoc()) {
                $myMembers[] = $data;
            }
        }
    }
    elseif($position == "4"){
        # Grab all the members but the first
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid';");
        if ($getFirstGroup->num_rows > 0) {
            $count=0;
            while ($data = $getFirstGroup->fetch_assoc()) {
                if ($count!=0){
                    $myMembers[] = $data;
                }
                $count++;
            }
        }
    }

    return $myMembers;

}