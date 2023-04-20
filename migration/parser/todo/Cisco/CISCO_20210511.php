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
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';

require_once INC_ROOT.'/libs/common/MemberObject.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';

require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/common/rules/SecurityGroup.php';
require_once INC_ROOT.'/libs/common/rules/SecurityRuleCisco.php';
require_once INC_ROOT.'/libs/common/MemberObject.php';

require_once INC_ROOT.'/libs/common/rules/MemoryObjectsHandlerCisco.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';
require_once INC_ROOT.'/bin/projects/tools/compactByDescription.php';
use \PaloAltoNetworks\Policy\Objects\SecurityGroup;
use \PaloAltoNetworks\Policy\Objects\SecurityRuleCisco;
use \PaloaltoNetworks\Policy\Objects\MemberObject;

global $vrid;

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
global $app;

//Capture request paramenters
include INC_ROOT.'/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);

$fixZones = $noDNAT;

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

# Classes


class IkeGateway {
    public $name;

    public $id;

    public $interface;
    public $local_address_ip;
    public $peerIPtype = "static";
    public $peer_ip_address;
    public $type_authentication ="pre-shared-key";
    public $pre_shared_key = null;
    public $localID ="none";
    public $localIDvalue="";
    public $peerID ="none";
    public $peerIDvalue="";
    public $version="ikev1";
    public $peer_ip_type="static";

    public $passive_mode='no';
    public $nat_traversal='yes';
    public $exchange_mode_ikev1="auto";
    public $dpd_ikev1="yes";
    public $ike_crypto_profile_ikev1;
    public $ike_interval_ikev1=2;
    public $retry_ikev1=2;

    public $address_type="ipv4";
    public $ike_crypto_profile_ikev2;
    public $dpd_ikev2;
    public $ike_interval_ikev2=2;
    public $require_cookie_ikev2='no';

    public $fragmentation;
    public $allow_id_payload_mismatch;
    public $strict_validation_revocation;

    function __construct() {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function getSQL($source,$template,$vsys){
        $sql="('$this->id','$this->address_type','$this->name','$vsys','$source','$template','$this->version','$this->dpd_ikev1','$this->ike_interval_ikev1','$this->retry_ikev1','$this->ike_crypto_profile_ikev1','$this->exchange_mode_ikev1','$this->dpd_ikev2','$this->ike_interval_ikev2','$this->ike_crypto_profile_ikev2','$this->require_cookie_ikev2','$this->local_address_ip','$this->interface','$this->type_authentication','$this->pre_shared_key','$this->allow_id_payload_mismatch','$this->strict_validation_revocation','$this->nat_traversal','$this->passive_mode','$this->fragmentation','$this->peer_ip_type','$this->peer_ip_address')";
        return $sql;
    }

    public function __construct13($name, $interface, $localIP, $peerIPtype, $peer_ip_address, $authentication, $pre_shared_key, $localID, $localIDvalue, $peerID, $peerIDvalue, $enablePassiveMode, $enableNatTraversal){
        $this->name = $name;
        $this->interface = $interface;
        $this->local_address_ip=$localIP;
        $this->peerIPtype=$peerIPtype;
        $this->peer_ip_address=$peer_ip_address;
        $this->type_authentication = $authentication;
        $this->pre_shared_key=$pre_shared_key;
        $this->localID = $localID;
        $this->localIDvalue = $localIDvalue;
        $this->peerID = $peerID;
        $this->peerIDvalue=$peerIDvalue;
        $this->enablePassiveMode=$enablePassiveMode;
        $this->enableNatTraversal=$enableNatTraversal;
    }

    public function __construct2($name,$peer_ip_address){
        $this->name = $name;
        $this->peer_ip_address=$peer_ip_address;
    }

    public function __construct3($id, $name,$peer_ip_address){
        $this->id = $id;
        $this->name = $name;
        $this->peer_ip_address=$peer_ip_address;
    }

    public function addPeer($peer_ip_address){
        $this->peer_ip_address=$peer_ip_address;
    }

    public function addInterface($interface){
        $this->interface=$interface;
    }

    public function addInterfaceIP($local_address_ip){
        $this->local_address_ip=$local_address_ip;
    }

    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }

}

class IkeCryptoProfile {
    public $name;

    public $id;

    public $dh_group;
    public $hash;
    public $encryption;
    public $keyLifeTimeType="hours";
    public $keyLifeTimeValue="24";
    public $authentication_multiple=0;

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct1($name){
        $this->name = $name;
    }

    public function __construct2($id, $name){
        $this->id = $id;
        $this->name = $name;
    }

    public function __construct7($name, $dhgroup, $hash, $encryption, $keyLifeTimeType, $keyLifeTimeValue, $ikev2AuthMulti){
        $this->name = $name;
        $this->dhgroup = array();
        if(isset($dhgroup) && is_array($dhgroup)){
            foreach ($dhgroup as $ip){
                $this->dhgroup[] = $ip;
            }
        }

        $this->authentication = array();
        if(isset($authentication) && is_array($authentication)){
            foreach ($authentication as $ip){
                $this->authentication[] = $ip;
            }
        }
        /*
        if(isset($hash) && is_array($hash)){
            foreach ($hash as $ip){
                $this->$hash[] = $ip;
            }
        }*/

        $this->encryption = array();
        if(isset($encryption) && is_array($encryption)){
            foreach ($encryption as $ip){
                $this->encryption[] = $ip;
            }
        }

        $this->keyLifeTimeType = $keyLifeTimeType;
        $this->keyLifeTimeValue = $keyLifeTimeValue;
        $this->ikev2AuthMulti = $ikev2AuthMulti;
    }

    public function addDHgroup($dh_group){
        $this->dh_group[]=$dh_group;
    }

    public function addHash($hash){
        if (($hash=="sha") OR ($hash=="sha-1")){
            $hash="sha1";
        }
        elseif ($hash=="sha-256"){
            $hash="sha256";
        }
        elseif ($hash=="sha-384"){
            $hash="sha384";
        }
        elseif ($hash=="sha-512"){
            $hash="sha512";
        }

        $this->hash[]=$hash;
    }

    public function addEncryption($encryption){
        $this->encryption[]=$encryption;
    }

    public function getSQL($source,$template,$vsys){
        $dh_group=implode(",",$this->dh_group);
        $encryption=implode(",",$this->encryption);
        $hash=implode(",",$this->hash);

        $seconds="";$minutes="";$hours="";$days="";
        if ($this->keyLifeTimeType=="seconds"){
            $seconds=$this->keyLifeTimeValue;
        }
        elseif($this->keyLifeTimeType=="minutes"){
            $minutes=$this->keyLifeTimeValue;
        }
        elseif($this->keyLifeTimeType=="hours"){
            $hours=$this->keyLifeTimeValue;
        }
        elseif($this->keyLifeTimeType=="days"){
            $days=$this->keyLifeTimeValue;
        }

        $sql="('$this->id','$this->name','$vsys','$source','$template','$encryption','$hash','$dh_group','$seconds','$minutes','$hours','$days')";
        return $sql;
    }

    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }

}

class IpsecCryptoProfile {
    public $name;

    public $id;

    public $ipsecProtocol="esp";
    public $dhgroup = "no-pfs";
    public $authentication;
    public $encryption;

    public $keyLifeTimeType;
    public $keyLifeTimeValue;
    public $lifeSizeType;
    public $lifeSizeValue;

    public $warnings;

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct1($id){
        $this->id = $id;
    }

    public function __construct8($name, $dhgroup, $authentication, $encryption, $keyLifeTimeType, $keyLifeTimeValue, $lifeSizeType, $lifeSizeValue){
        $this->name = $name;
        $this->dhgroup = $dhgroup;

        $this->authentication = array();
        if(isset($authentication) && is_array($authentication)){
            foreach ($authentication as $ip){
                $this->authentication[] = $ip;
            }
        }
        $this->encryption = array();
        if(isset($encryption) && is_array($encryption)){
            foreach ($encryption as $ip){
                $this->encryption[] = $ip;
            }
        }
        $this->keyLifeTimeType = $keyLifeTimeType;
        $this->keyLifeTimeValue = $keyLifeTimeValue;
        $this->lifeSizeType = $lifeSizeType;
        $this->lifeSizeValue = $lifeSizeValue;
    }

    public function addWarning($level, $task, $message, $source, $action){
        $this->warnings[]=[
            'level'   => $level,
            'task'    => $task,
            'message' => $message,
            'source'  => $source,
            'action'  => $action,
            'obj_type'=> 'ipsec',
            'obj_id' => $this->id,
            'obj_table' => 'ipsec_crypto_profiles'
        ];
    }

    public function getWarnings(){
        return $this->warnings;
    }

    public function addAuthentication($authentication){
        $this->authentication[]=$authentication;
    }

    public function addEncryption($encryption){
        $this->encryption[]=$encryption;
    }

    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }

    public function addDHgroup($dhgroup){
        $this->dhgroup=$dhgroup;
    }

    public function addLifeSize($lifeSizeType,$lifeSizeValue){
        $this->lifeSizeType=$lifeSizeType;
        $this->lifeSizeValue=$lifeSizeValue;
    }

    public function addLifeTime($keyLifeTimeType,$keyLifeTimeValue){
        $this->keyLifeTimeType=$keyLifeTimeType;
        $this->keyLifeTimeValue=$keyLifeTimeValue;
    }

    public function getHash(){
        $tmp=$this->ipsecProtocol.$this->dhgroup.implode(",",$this->authentication).implode(",",$this->encryption).$this->keyLifeTimeType.$this->keyLifeTimeValue.$this->lifeSizeType.$this->lifeSizeValue;
        return $tmp;
    }

    public function setID($id){
        $this->id = $id;
    }

}

class IpsecTunnel {
    public $id;
    public $name;
    public $priority;
    public $accesslist;
    public $peerIPaddress;
    public $transformSet;
    public $lifetime_seconds;
    public $lifetime_kilobytes;
    public $interface;
    public $tunnelInterface;
    public $address_type="ipv4";
    public $type_tunnel="auto-key";
    public $ipsecCryptoProfile;
    public $ike_gateway;

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct4($name,$priority,$accesslist,$tunnelInterface){
        $this->name = $name;
        $this->priority = $priority;
        $this->accesslist = $accesslist;
        $this->tunnelInterface=$tunnelInterface;
    }

    public function __construct5($id, $name,$priority,$accesslist,$tunnelInterface){
        $this->id = $id;
        $this->name = $name;
        $this->priority = $priority;
        $this->accesslist = $accesslist;
        $this->tunnelInterface=$tunnelInterface;
    }

    public function addPeer($peerIPaddress){
        $this->peerIPaddress=$peerIPaddress;
    }

    public function addTransformSet(IpsecCryptoProfile $transformSet){
        $this->transformSet=$transformSet;
        $this->ipsecCryptoProfile=$transformSet->name;
    }

    public function addLifetimeSeconds($lifetime_seconds){
        $this->lifetime_seconds=$lifetime_seconds;
    }

    public function addLifetime_kilobytes($lifetime_kilobytes){
        $this->lifetime_kilobytes=$lifetime_kilobytes;
    }

    public function addInterface($interface){
        $this->interface=$interface;
    }

    public function addInterfaceIP($interfaceIP){
        $this->interfaceIP=$interfaceIP;
    }

    public function getIpsecCryptoName(){
        return $this->transformSet->name;
    }

    public function getIpsecCrypto(){
        return $this->transformSet;
    }

    public function getSQL($source,$template,$vsys){
        $sql="('$this->id','$this->name','$vsys','$source','$template','$this->tunnelInterface','$this->address_type','$this->type_tunnel','$this->name','$this->ipsecCryptoProfile')";
        return $sql;
    }
}

function addPrefixSuffix($check_prefix, $text_prefix, $check_suffix, $text_suffix, $name_pan, $max_char){

    $name_pan_fin = $name_pan;

    if ($check_prefix == "on"){
        $name_pan_fin = $text_prefix.$name_pan;
        if (strlen($name_pan_fin) > $max_char){
            $total_name_pan_fin = strlen($name_pan_fin);
            $total_subs = $total_name_pan_fin - $max_char;
            $name_pan = substr($name_pan, 0, -$total_subs);
            $name_pan_fin = $text_prefix.$name_pan;
        }
    }
    if ($check_suffix == "on"){
        $name_pan = $name_pan_fin;
        $name_pan_fin = $name_pan_fin.$text_suffix;
        if (strlen($name_pan_fin) > $max_char){
            $total_name_pan_fin = strlen($name_pan_fin);
            $total_subs = $total_name_pan_fin - $max_char;
            $name_pan = substr($name_pan, 0, -$total_subs);
            $name_pan_fin = $name_pan.$text_suffix;
        }
    }
    return $name_pan_fin;
}

global $global_config_filename;
$sourcesAdded = array();
global $source;

global $aclsWithTimeouts;
global $servicesWithTimouts;

if ($action == "import") {
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $path = USERSPACE_PATH."/projects/" . $project . "/";
    $i = 0;
    $dirrule = opendir($path);
    if(!isset($jobid)){
        $jobid = 0;
    }
    update_progress($project, '0.00', 'Reading config files',$jobid);
    while ($config_filename = readdir($dirrule)) {
        $global_config_filename = $config_filename;

        if (checkFiles2Import($config_filename)){
            $config_path = $path . $config_filename;
            $filename = $config_filename;
            $filenameParts = pathinfo($config_filename);
            $verificationName = $filenameParts['filename'];
            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$verificationName';");
            if ($isUploaded->num_rows == 0) {
                $getSourceVsys = import_config($config_path, $project, $config_filename, $jobid);
                $source = $getSourceVsys[0];
                $sourcesAdded[] = $source;

                update_progress($project, '0.70', 'Replacing DM_INLINE groups by Members, can take minutes',$jobid);
                #Remove DM_INLINE
                $getRules = $projectdb->query("SELECT id FROM security_rules WHERE source='$getSourceVsys[0]' AND vsys='$getSourceVsys[1]';");
                if ($getRules->num_rows > 0) {
                    while ($getRulesData = $getRules->fetch_assoc()) {
                        $rule_lid = $getRulesData['id'];
                        replace_dminline_by_members($getSourceVsys[1], $getSourceVsys[0], $rule_lid);
                    }
                }
                #From Nat rules
                $getRules = $projectdb->query("SELECT id FROM nat_rules WHERE source='$getSourceVsys[0]' AND vsys='$getSourceVsys[1]';");
                if ($getRules->num_rows > 0) {
                    while ($getRulesData = $getRules->fetch_assoc()) {
                        $rule_lid = $getRulesData['id'];
                        replace_nat_dminline_by_members($getSourceVsys[1], $getSourceVsys[0], $rule_lid);
                    }
                }



                if($fixZones) {
                    update_progress($project, '0.80', 'Fixing rules based on Destination Nats',$jobid);
                    fix_destination_nat($config_path, $getSourceVsys[0], $getSourceVsys[1]);
                }

                $template_name = $filename . "_template";
                $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
                if($getTemplate->num_rows==1){
                    $data = $getTemplate->fetch_assoc();
                    $template = $data['id'];
                    $query = "SELECT id FROM virtual_routers WHERE template='$template' AND source='".$getSourceVsys[0]."';";
                    //$my = fopen("DNAT.txt",'a');
                    //fwrite($my, $query);
                    //fclose($my);
                    $getVR = $projectdb->query($query);
                    if ($getVR->num_rows == 1) {
                        $getVRData = $getVR->fetch_assoc();
                        $vr_id = $getVRData['id'];

                        require_once INC_ROOT.'/libs/common/lib-rules.php';
                        recalculate_Dst_basedOn_NAT($projectdb, $getSourceVsys[0], $getSourceVsys[1], $vr_id, $project, 'Cisco');
                    }
                }

                #Calculate Layer4-7
                $source = $getSourceVsys[0];
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


                update_progress($project, '0.95', 'Reading VPN Rules',$jobid);
                get_ipsec_vpn($config_path, $getSourceVsys[0], $getSourceVsys[1],$getSourceVsys[2],$jobid,$project);
                unlink($path.$config_filename);

                # In case Group By Description is enabled
                if ($groupbydescription==true){
                    update_progress($project, '0.99', 'Compacting Rules by Remark',$jobid);
                    compactByDescription($project,$getSourceVsys[0],$getSourceVsys[1],"security_rules");
                }
            }
            else {
                update_progress($project, '0.00', 'This filename '.$filename.' its already uploaded. Skipping...',$jobid);
                //if (!preg_match("/\.xml/",$filename)){unlink($path.$config_filename);}
            }
        }
    }
    #Check used
    update_progress($project, '0.97', 'Calculating Used Objects',$jobid);
    check_used_objects_new($sourcesAdded);

    # Remove zones if they dont have a name in security and nat and appoverride rules (happens when is not a default gateway
    $projectdb->query("DELETE FROM security_rules_from WHERE name='';");
    $projectdb->query("DELETE FROM security_rules_to WHERE name='';");
    $projectdb->query("DELETE FROM nat_rules_from WHERE name='';");
    $projectdb->query("DELETE FROM appoverride_rules_from WHERE name='';");
    $projectdb->query("DELETE FROM appoverride_rules_to WHERE name='';");



    update_progress($project, '1.00', 'Done.',$jobid);
//    unlink($path.$config_filename);  //Already deleted in the while loop
}

function clean_config($config_path, $project, $config_filename) {
    $cisco_config_file = file($config_path);
    $data = array();
    foreach ($cisco_config_file as $line => $names_line) {
        if ((preg_match("/description/", $names_line)) OR ( preg_match("/remark/", $names_line))) {
            $data[] = $names_line;
        } else {
            if (preg_match("/\'/", $names_line)) {
                $data[] = str_replace("'", "_", $names_line);
            } else {
                $data[] = $names_line;
            }
        }
    }
    file_put_contents($config_path, $data);
}

function import_config($config_path, $project, STRING $config_filename, INT $jobid) {
    global $projectdb;
    global $global_config_filename;

    global $aclsWithTimeouts;
    global $servicesWithTimouts;

    $objectsInMemory = new MemoryObjectsHandlerCisco();

    $filename = $config_filename;
    #CLEAN CONFIG FROM EMPTY LINES AND CTRL+M
    file_put_contents($config_path, implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));

    clean_config($config_path, $project, $config_filename);

    #LOAD THE FILE
    $cisco_config_file = file($config_path);

    #Check if is the first vsys
    $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
    if ($getVsys->num_rows == 0) {
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','vsys1','Cisco')");
        $vsys = "vsys1";
        $source = $projectdb->insert_id;
    }
    else {
        $getVsysData = $getVsys->fetch_assoc();
        $thename = $getVsysData['vsys'];
        $getVsysData1 = str_replace("vsys", "", $thename);
        $result = intval($getVsysData1) + 1;
        $vsys = "vsys" . $result;
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','$vsys','Cisco')");
        #Get Source (First row for this filename)
        $getSource = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' GROUP by filename;");
        $getSourceData = $getSource->fetch_assoc();
        $source = $getSourceData['id'];
    }

    $parametersProject = [
        "source"        =>$source,
        "projectdb"     =>$projectdb
    ];

    $timeouts = getTimeOutClass($vsys, $source, $cisco_config_file);
//    echo "This is the information about timeouts:\n";
//    print_r($timeouts);
    $aclsWithTimeouts = $timeouts['acls'];
    $servicesWithTimouts = $timeouts['services'];

    add_default_services($source);
    #add_default_profiles($source);
    #Config Template
    $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
    $template_name = $filename . "_template";
    $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
    $template = $projectdb->insert_id;

    update_progress($project, '0.01', 'File:' . $filename . ' Phase 2 Loading Address Objects',$jobid);
    save_names($cisco_config_file, $source, $vsys, $filename);
    get_interfaces($cisco_config_file, $source, $vsys, $template);
    get_static_routes($cisco_config_file, $source, $vsys, $template);
    get_object_network($cisco_config_file, $source, $vsys, $filename);
    $objectsInMemory->load_addresses_inMemory($parametersProject);
    echo "Object_network loaded\n";

    get_objectgroup_network2($cisco_config_file, $source, $vsys, $objectsInMemory, $filename);
    echo "ObjectGroup_network loaded\n";
    update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Loading Service Objects',$jobid);

    add_cisco_services($source, $vsys);
    echo "Cisco Services loaded\n";
    get_object_service($cisco_config_file, $source, $vsys, $filename);
    $objectsInMemory->load_services_inMemory($parametersProject);
    echo "Services loaded\n";

    get_objectgroup_service($cisco_config_file, $source, $vsys, $filename);
    echo "Object_services loaded\n";

    get_protocol_groups($cisco_config_file, $source, $vsys);
    echo "Protocol loaded\n";

    get_icmp_groups($cisco_config_file, $source, $vsys);
    echo "ICMPGroups loaded\n";
    update_progress($project, '0.30', 'File:' . $filename . ' Phase 2 Loading Nat Rules',$jobid);

    get_twice_nats($cisco_config_file, $source, $vsys, $template,"before");
    get_objects_nat($cisco_config_file, $source, $vsys);
    $getNats=$projectdb->query("SELECT id FROM nat_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
    if ($getNats->num_rows==0){
        natpre83($source,$vsys,$cisco_config_file,$template);
    }
    get_twice_nats($cisco_config_file, $source, $vsys, $template,"after");
    update_progress($project, '0.45', 'File:' . $filename . ' Phase 2 Loading Security Rules',$jobid);


    $userObj = array();
    get_objectgroup_user($cisco_config_file, $source, $vsys, $userObj);

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

//    print_r($objectsInMemory);
    get_security_policies2($devicegroup, $cisco_config_file, $source, $vsys, $objectsInMemory);
    update_progress($project, '0.65', 'File:' . $filename . ' Phase 2 Cleaning Zones',$jobid);

    echo "Fixing Service Timeouts based on ACL Groups\n";
    fixServiceTimeouts($devicegroup, $cisco_config_file, $source, $vsys, $objectsInMemory, $aclsWithTimeouts, $servicesWithTimouts);

   // echo "Generating Auth Rules\n";
   // generateAuthRules($devicegroup, $cisco_config_file, $source, $vsys, $objectsInMemory);

//    optimize_names2($cisco_config_file, $source, $vsys);
//    add_filename_to_objects($source, $vsys, $filename);

    clean_zone_any($source, $vsys);

    check_invalid($source,$vsys,$template);
    // Call function to generate initial consumptions
    //deviceUsage("initial", "get", $project, $dusage_platform, $dusage_version, $vsys, $source, $dusage_template);
    deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);
    return array("$source", "$vsys","$template");

}

function removeEnclosingQuotes(STRING $value):string{
    return trim($value,'"');
}

/***
 * @param STRING $value  Such as US\\myUser
 * @return string        US\myUser
 */
function removeDoubleBackSlash(STRING $value):string{
    $value = preg_replace('/\\\\+/','\\',$value);
    return $value;
}

function get_objectgroup_user($cisco_config_file,$source,$vsys,ARRAY &$userObj){
    global $projectdb;
    $isObjGroupUser=false;
    $userObj=array();
    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if (preg_match("/object-group user /",$names_line)){
            $names = explode(" ", $names_line);
           $isObjGroupUser=true;
           $name = $names[2];
           $userObj[$name]=array();
           continue;
       }
       if ($isObjGroupUser===true){
           if (preg_match("/user /",$names_line)){
               $user=str_replace("user ","",$names_line);
               $userObj[$name][]=trim($user,'"');
           }
           elseif (preg_match("/user-group /",$names_line)){
               $usergroup=str_replace("user-group ","",$names_line);
               $userObj[$name][]=trim($usergroup,'"');
           }
           else{
               $isObjGroupUser=false;
           }
       }
   }


}

function get_ipsec_vpn($config_path, $source, $vsys,$template,$jobid,$project){
    global $projectdb;
    $cryptoProfiles = [];
    $cryptoProfileID = 0;
    $ipsecTunnels = [];
    $ipsecTunnelID = 0;
    $checking_psk = FALSE;
    $tunnelInterfaces = [];
    $isIkev1Profile = FALSE;
    $IkeCryptoProfiles = [];
    $IkeCryptoProfileID = 0;
    $ikeGateways = array();
    $ikeGatewayID = 0;

    $query = "SELECT max(id) as lastID FROM ipsec_tunnel";
    $result = $projectdb->query($query);
    if($result->num_rows>0){
        $data = $result->fetch_assoc();
        $ipsecTunnelID = $data['lastID'];
        $ipsecTunnelID++;
    }
    else{
        $ipsecTunnelID=1;
    }

    $query = "SELECT max(id) as lastID FROM ike_gateways_profiles";
    $result = $projectdb->query($query);
    if($result->num_rows>0){
        $data = $result->fetch_assoc();
        $ikeGatewayID = $data['lastID'];
        $ikeGatewayID++;
    }
    else{
        $ikeGatewayID=1;
    }

    $query = "SELECT max(id) as lastID FROM ike_crypto_profiles";
    $result = $projectdb->query($query);
    if($result->num_rows>0){
        $data = $result->fetch_assoc();
        $IkeCryptoProfileID = $data['lastID'];
        $IkeCryptoProfileID++;
    }
    else{
        $IkeCryptoProfileID=1;
    }

    $query = "SELECT max(id) as lastID FROM ike_crypto_profiles";
    $result = $projectdb->query($query);
    if($result->num_rows>0){
        $data = $result->fetch_assoc();
        $cryptoProfileID = $data['lastID'];
        $cryptoProfileID++;
    }
    else{
        $cryptoProfileID=1;
    }


//    update_progress($project, '0.90', 'Importing IPSEC VPNs');
    # Get Base Config VERSION
    $getVersion = $projectdb->query("SELECT version FROM device_mapping WHERE active=1 AND baseconfig=1 GROUP BY filename;");
    if ($getVersion->num_rows == 1) {
        $getVersionData = $getVersion->fetch_assoc();
        $panos_version = $getVersionData['version'];
        if (preg_match("/^6\.0/", $panos_version)) {
            $version = 6;
        } elseif (preg_match("/^6\.1/", $panos_version)) {
            $version = 6.1;
        } elseif (preg_match("/^5\./", $panos_version)) {
            $version = 5;
        } elseif (preg_match("/^7\./", $panos_version)) {
            $version = 7;
        }
    }
    else {
        $version = 7;
    }

    # Check Tunnel Interfaces
    $getTunnel = $projectdb->query("SELECT unitname FROM interfaces WHERE media='tunnel' AND template='$template';");
    if ($getTunnel->num_rows > 0) {
        $old = 0;
        while ($getTunnelData = $getTunnel->fetch_assoc()) {
            $split = explode(".", $getTunnelData['unitname']);
            $new = intval($split[1]);
            if ($new > $old) {
                $old = $new;
            }
        }
        $tunnelID = $old + 1;
    }
    else {
        $tunnelID = 1;
    }

    # Read VR
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND source='$source';");
    if ($getVR->num_rows == 1) {
        $getVRData = $getVR->fetch_assoc();
        $vr_id = $getVRData['id'];
    }

    $cisco_config_file = file($config_path);

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if ((preg_match("/crypto isakmp enable/", $names_line)) OR ( preg_match("/crypto ikev1 enable/", $names_line))) {
            $split = $names_line;
            $ikeInterface = $split[3];
        }

        if (preg_match("/crypto ipsec ikev2 ipsec-proposal/", $names_line)) {
            $split = explode(" ", $names_line);
            $ikev2ProposalName = $split[4];
            $cryptoProfiles["$ikev2ProposalName"] = new IpsecCryptoProfile($cryptoProfileID);
            $cryptoProfileID++;
            $cryptoProfiles["$ikev2ProposalName"]->name = $ikev2ProposalName;
        }

        if (preg_match("/protocol esp encryption /", $names_line)) {
            $split = explode(" ", $names_line);
            unset($split[0]);
            unset($split[1]);
            unset($split[2]);
            $split_tmp = array_values($split);
            $split = $split_tmp;
            foreach ($split as $splitelement) {
                switch ($splitelement) {
                    case "des":
                        add_log2('error', 'Reading IPSEC Crypto Profiles', 'Encryption DES is not supported on Profile [' . $ikev2ProposalName . ']', $source, 'Automatically changed to 3des. Please update with your peer', '', '', '');
                        $cryptoProfiles["$ikev2ProposalName"]->addEncryption("3des");
                        break;
                    case "3des":
                        $cryptoProfiles["$ikev2ProposalName"]->addEncryption("3des");
                        break;
                    case "aes":
                        if ($version < 7) {
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes128");
                        } else {
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-128-cbc");
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', 'ipsec', $cryptoProfiles["$ikev2ProposalName"]->id, '');
                        }
                        break;
                    case "aes-192":
                        if ($version < 7) {
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes192");
                        } else {
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-192-cbc");
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                        }
                        break;
                    case "aes-256":
                        if ($version < 7) {
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes256");
                        } else {
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-256-cbc");
                        }
                        break;
                }
            }
        }

        if (preg_match("/protocol esp integrity /", $names_line)) {
            $split = explode(" ", $names_line);
            unset($split[0]);
            unset($split[1]);
            unset($split[2]);
            $split_tmp = array_values($split);
            $split = $split_tmp;
            foreach ($split as $splitelement) {
                switch ($splitelement) {
                    case "md5":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("md5");
                        break;
                    case "sha-1":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha1");
                        break;
                    case "sha256":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha256");
                        break;
                    case "sha384":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha384");
                        break;
                    case "sha512":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha512");
                        break;
                    case "sha-256":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha256");
                        break;
                    case "sha-384":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha384");
                        break;
                    case "sha-512":
                        $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha512");
                        break;
                }
            }
        }

        if ((preg_match("/crypto ipsec transform-set/i", $names_line)) OR ( preg_match("/crypto ipsec ikev1 transform-set/i", $names_line))) {
            # Read the IPSEC CRYPTO PROFILE
            //$my = fopen("vpn.txt","a"); fwrite($my, " $names_line \n"); fclose($my);
            $split = explode(" ", $names_line);
            if (preg_match("/crypto ipsec ikev1 transform-set/i", $names_line)) {
                unset($split[2]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
            }

            $cryptoProfiles["$split[3]"] = new IpsecCryptoProfile($cryptoProfileID);
            $cryptoProfileID++;
            # Attach Data to the Object
            $cryptoProfiles["$split[3]"]->name = $split[3];
            $next = 5;
            switch ($split[4]) {
                case "esp-null":
                    $cryptoProfiles["$split[3]"]->addEncryption("null");
                    break;
                case "esp-des":
                    $cryptoProfiles["$split[3]"]->addEncryption("3des");
                    $cryptoProfiles["$split[3]"]->addWarning('error', 'Reading IPSEC Crypto Profiles', 'Encryption DES is not supported on Profile [' . $split[3] . ']', $source, 'Automatically changed to 3des. Please update with your peer');
                    break;
                case "esp-3des":
                    $cryptoProfiles["$split[3]"]->addEncryption("3des");
                    break;
                case "esp-aes":
                    if (!preg_match("/-/", $split[5])) {
                        $next = 6;
                        if ($version < 7) {
                            $tmp = "aes" . $split[5];
                        } else {
                            $tmp = "aes-" . $split[5] . "-cbc";
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [' . $tmp . '] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', 'ipsec', $cryptoProfiles["$split[3]"]->id, 'ipsec_crypto_profiles');
                        }
                        $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                    } else {
                        if ($version < 7) {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes128");
                        } else {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes-128-cbc");
                            $cryptoProfiles["$split[3]"]->addWarning('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer');
                            //add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', 'ipsec', $cryptoProfiles["$split[3]"]->id, 'ipsec_crypto_profiles');
                        }
                    }
                    break;
                case "esp-aes-192":
                    if ($version < 7) {
                        $cryptoProfiles["$split[3]"]->addEncryption("aes192");
                    } else {
                        $cryptoProfiles["$split[3]"]->addEncryption("aes-192-cbc");
                        //add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', 'ipsec', $cryptoProfiles["$split[3]"]->id, 'ipsec_crypto_profiles');
                        $cryptoProfiles["$split[3]"]->addWarning('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer');
                    }
                    break;
                case "esp-aes-256":
                    if ($version < 7) {
                        $cryptoProfiles["$split[3]"]->addEncryption("aes256");
                    } else {
                        $cryptoProfiles["$split[3]"]->addEncryption("aes-256-cbc");
                        //add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', 'ipsec', $cryptoProfiles["$split[3]"]->id, 'ipsec_crypto_profiles');
                        $cryptoProfiles["$split[3]"]->addWarning('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer');
                    }

                    break;
                case "esp-aes":
                    if (is_int($split[5])) {
                        if ($version < 7) {
                            $tmp = "aes" . $split[5];
                            $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                        } else {
                            $tmp = "aes-" . $split[5] . "-cbc";
                            $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                            //add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES' . $split[5] . ' changed to [' . $tmp . '] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', 'ipsec', $cryptoProfiles["$split[3]"]->id, 'ipsec_crypto_profiles');
                            $cryptoProfiles["$split[3]"]->addWarning('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES' . $split[5] . ' changed to [' . $tmp . '] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer');
                        }
                    }
                    break;
                case "mode":
                    break;
                default:
                    add_log2('error', 'Reading IPSEC Crypto Profiles', $split[4] . ' Encryption not supported on MT yet', $source, 'Please send an email with the Encryption to fwmigrate at paloaltonetworks.com', '', '', '');
            }

            switch ($split[$next]) {
                case "esp-md5-hmac":
                    $cryptoProfiles["$split[3]"]->addAuthentication("md5");
                    break;
                case "esp-sha-hmac":
                    $cryptoProfiles["$split[3]"]->addAuthentication("sha1");
                    break;
                case "esp-sha256-hmac":
                    $cryptoProfiles["$split[3]"]->addAuthentication("sha256");
                    break;
                case "esp-sha384-hmac":
                    $cryptoProfiles["$split[3]"]->addAuthentication("sha384");
                    break;
                case "esp-sha512-hmac":
                    $cryptoProfiles["$split[3]"]->addAuthentication("sha512");
                    break;
                case "esp-none":
                    $cryptoProfiles["$split[3]"]->addAuthentication("none");
                    break;
            }
        }

        if (preg_match("/crypto ipsec security-association lifetime seconds /", $names_line)) {
            $split = explode(" ", $names_line);
            convertLifeTime($split[5], 1, $time_value, $time);
            foreach ($cryptoProfiles as $key => $cryptoProfilesObj) {
                $cryptoProfilesObj->addLifeTime($time, $time_value);
            }
        }

        if (preg_match("/crypto ipsec security-association lifetime kilobytes /", $names_line)) {
            $split = explode(" ", $names_line);
            convertLifeSize($split[5], 1, $size_value, $size);
            foreach ($cryptoProfiles as $key => $cryptoProfilesObj) {
                $cryptoProfilesObj->addLifeSize($size, $size_value);
            }
        }

        if (preg_match("/crypto map /", $names_line)) {
            //$cryptoMapPriority = $split[3];
            //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "$names_line\n"); fclose($my);

            $split = explode(" ", $names_line);

            if (($split[4] == "match") AND ( $split[5] == "address")) {
                $cryptoMapPriority = $split[3];
                //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "   $cryptoMapPriority\n"); fclose($my);
                $cryptoMapName = $split[2] . "-" . $cryptoMapPriority;
                $accesslist = $split[6];
                $tunnelName = "tunnel." . $tunnelID;
                $tunnelInterfaces[] = $tunnelName;
                $projectdb->query("INSERT INTO interfaces (name,template,source,vsys,unitname,zone,media,vr_id) VALUES ('tunnel','$template','$source','$vsys','$tunnelName','$cryptoMapName','tunnel','$vr_id');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,interfaces,type) VALUES ('$source','$template','$vsys','$cryptoMapName','$tunnelName','layer3');");

                # UPDATE VR_ID with Interface
                //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "ipsecTunnels inserting $cryptoMapPriority\n"); fclose($my);
                $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"] = new IpsecTunnel($ipsecTunnelID, $cryptoMapName, $cryptoMapPriority, $accesslist, $tunnelName);
                $ipsecTunnelID++;
                $tunnelID++;
            }
            elseif(isset($ipsecTunnels["$cryptoMapName-$cryptoMapPriority"])){
                if     (($split[4] == "set") AND ( $split[5] == "peer") ) {
                    if (ip_version($split[6]) == "noip") {
                        $getIP = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext ='$split[6]' LIMIT 1;");
                        if ($getIP->num_rows == 1) {
                            $getIPData = $getIP->fetch_assoc();
                            $split[6] = $getIPData['ipaddress'];
                        }
                    }
                    //$cryptoMapPriority = $split[3];
                    //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "   $cryptoMapPriority\n"); fclose($my);
                    $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->addPeer($split[6]);
                    $ikeGateways["$cryptoMapName-$cryptoMapPriority"] = new IkeGateway($ikeGatewayID,$cryptoMapName, $split[6]);
                    $ikeGatewayID++;
                }
                elseif (($split[4] == "set") AND ( $split[5] == "transform-set")) {
                    $transformSet = clone $cryptoProfiles["$split[6]"];
                    $transformSet->setID($cryptoProfileID++);
                    $transformSet->name = $transformSet->name . "-" . $cryptoMapName;
                    $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->addTransformSet($transformSet);
                }
                elseif (($split[4] == "set") AND ( isset($split[6]) && $split[6] == "transform-set")) {
                    $transformSet = clone $cryptoProfiles["$split[7]"];
                    $transformSet->setID($cryptoProfileID++);
                    $transformSet->name = $transformSet->name . "-" . $cryptoMapName;
                    $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->addTransformSet($transformSet);
                }
                elseif (($split[4] == "set") AND (($split[5] == "ikev2")) AND (($split[6] == "ipsec-proposal"))){
                    if ($ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->transformSet) {
                        add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found but ikev1 was seen before: ' . $names_line, $source, 'The tool is not attaching the ikev2 proposal to the Tunnel ' . $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->name, 'rules', $ipsecTunnelID, 'ipsec_tunnel');
                    } else {
                        $transformSet = clone $cryptoProfiles["$split[7]"];
                        $transformSet->setID($cryptoProfileID++);
                        $transformSet->name = $transformSet->name . "-" . $cryptoMapName;
                        $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->addTransformSet($transformSet);
                        add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found with more than one:' . $names_line, $source, 'Just Attaching the First One. You can create a new Profile combining all the options from all the Proposals', 'rules', $ipsecTunnelID, 'ipsec_tunnel');
                    }
                    add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found with more than one:'.$names_line, $source, 'Just Attaching the First One. You can create a new Profile combining all the options from all the Proposals', 'rules', $ipsecTunnelID, 'ipsec_tunnel');
                }
                elseif (($split[4] == "set") AND ( $split[5] == "security-association") AND ( $split[6] == "lifetime") AND ( $split[7] == "seconds")) {
                    $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->addLifetimeSeconds($split[8]);
                    convertLifeTime($split[8], 1, $time_value, $time);
                    if (isset($transformSet)) {
                        $transformSet->addLifeTime($time, $time_value);
                    }
                }
                elseif (($split[4] == "set") AND ( $split[5] == "security-association") AND ( $split[6] == "lifetime") AND ( $split[7] == "kilobytes")) {
                    if ($split[8] != "unlimited") {
                        $ipsecTunnels["$cryptoMapName-$cryptoMapPriority"]->addLifetime_kilobytes($split[8]);
                        convertLifeSize($split[8], 1, $size_value, $size);
                        if (isset($transformSet)) {
                            $transformSet->addLifeSize($size, $size_value);
                        }
                    } else {
                        if (isset($transformSet)) {
                            $transformSet->addLifeSize('65535', 'tb');
                        }
                    }
                }
                elseif (($split[4] == "set") AND ( $split[5] == "pfs")) {
                    if (isset($split[6])) {
                        $pfs = $split[6];
                    } else {
                        $pfs = "group2";
                    }
                    if (($pfs != "group21") AND ( $pfs != "group24")) {
                        if (isset($transformSet)) {
                            $transformSet->addDHgroup($pfs);
                        }
                    } else {
                        add_log2('error', 'Reading IKE-Crypto Profiles', 'The PFS group ' . $pfs . ' is not supported yet.', $source, 'Group20 has been assigned instead on Profile[' . $transformSet->name . ']', '', '', '');
                        $pfs = "group20";
                        if (isset($transformSet)) {
                            $transformSet->addDHgroup($pfs);
                        }
                    }
                }
                elseif ( $split[3] == "interface") {
                    $cryptoMapName_int = $split[2];
                    $interface_tmp = $split[4];
                    $getINT = $projectdb->query("SELECT unitname,unitipaddress FROM interfaces WHERE zone='$interface_tmp' AND template='$template' LIMIT 1;");
                    if ($getINT->num_rows == 1) {
                        $getINTData = $getINT->fetch_assoc();
                        foreach ($ikeGateways as $key => $ikeGWObj) {
                            if( strpos( $ikeGWObj->name, $cryptoMapName_int  ) !== false )
                            {
                                $ikeGWObj->addInterface($getINTData['unitname']);
                                $ikeGWObj->addInterfaceIP($getINTData['unitipaddress']);
                            }
                        }
                    }
                }
                elseif (($split[4] == "set") AND ( $split[5] == "phase1-mode") AND ( $split[6] == "aggressive")) {
                    $ikeGateways["$cryptoMapName-$cryptoMapPriority"]->exchange_mode_ikev1 = "aggressive";
                }
                elseif (($split[4] == "set") AND ( $split[5] == "phase1-mode") AND ( $split[6] == "main")) {
                    $ikeGateways["$cryptoMapName-$cryptoMapPriority"]->exchange_mode_ikev1 = "main";
                }
                elseif (($split[4] == "set") AND ( $split[5] == "nat-t-disable")) {
                    $ikeGateways["$cryptoMapName-$cryptoMapPriority"]->nat_traversal = "no";
                }
            }
        }

        if (preg_match("/no crypto isakmp nat-traversal/", $names_line)) {
            #Disable globally the nat-t
            foreach ($ikeGateways as $element) {
                $element->nat_traversal = "no";
            }
        }
        elseif (preg_match("/crypto isakmp nat-traversal/", $names_line)) {
            #Disable globally the nat-t
            foreach ($ikeGateways as $element) {
                $element->nat_traversal = "yes";
            }
        }


        if ((preg_match("/no crypto ikev1 am-disable/", $names_line)) OR ( preg_match("/no crypto isakmp am-disable/", $names_line))) {
            foreach ($ikeGateways as $element) {
                $element->exchange_mode_ikev1 = "aggressive";
            }
        }
        elseif ((preg_match("/crypto ikev1 am-disable/", $names_line)) OR ( preg_match("/crypto isakmp am-disable/", $names_line))) {
            foreach ($ikeGateways as $element) {
                $element->exchange_mode_ikev1 = "main";
            }
        }

        # Capture PSK
        if (preg_match("/tunnel-group /", $names_line)) {
            $split = explode(" ", $names_line);
            if (((ip_version($split[1]) == "v4") OR ( ip_version($split[1]) == "v6")) AND ( $split[2] == "ipsec-attributes")) {
                $last_peer_seen = $split[1];
                $checking_psk = TRUE;
            }
        }

        # Read Pre-Shared-Key for ikev1
        if (($checking_psk === TRUE) AND ( preg_match("/ikev1 pre-shared-key/", $names_line))) {
            $split = explode(" ", $names_line);
            $psk = $split[2];
            foreach ($ikeGateways as $key => $ikeGWObj) {
                if ($ikeGWObj->peer_ip_address == $last_peer_seen) {
                    if ($psk != "*****") {
                        $ikeGWObj->pre_shared_key = $psk;
                    } else {
                        $ikeGWObj->pre_shared_key = "";
                    }
                }
            }
            $checking_psk = FALSE;
        }
        elseif (($checking_psk === TRUE) AND ( preg_match("/pre-shared-key/", $names_line))) {
            $split = explode(" ", $names_line);
            $psk = $split[1];
            foreach ($ikeGateways as $key => $ikeGWObj) {
                if ($ikeGWObj->peer_ip_address == $last_peer_seen) {
                    if ($psk != "*****") {
                        $ikeGWObj->pre_shared_key = $psk;
                    } else {
                        $ikeGWObj->pre_shared_key = "";
                    }
                }
            }
            $checking_psk = FALSE;
        }

        # Import the ikev1 Crypto Profiles
        if ((preg_match("/crypto isakmp policy/", $names_line)) OR ( preg_match("/crypto ikev1 policy/", $names_line)) OR ( preg_match("/crypto ikev2 policy/", $names_line))) {
            $split = explode(" ", trim($names_line));
            $ikeCryptoProfileName = $split[1] . "-" . $split[3];
            $isIkev1Profile = TRUE;
        }

        if (($isIkev1Profile === TRUE) AND ( preg_match("/authentication /", $names_line))) {
            $split = explode(" ", $names_line);
            if (preg_match("/pre-share/", $names_line)) {
                $IkeCryptoProfiles[$ikeCryptoProfileName] = new IkeCryptoProfile($IkeCryptoProfileID, $ikeCryptoProfileName);
                $IkeCryptoProfileID++;
            }
            else {
                $isIkev1Profile = FALSE;
                add_log2('error', 'Reading IKE-Crypto Profiles', 'Only Pre-Shared key Profiles are supported', $source, 'Ignoring ' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name, '', '', '');
            }
        }

        if (($isIkev1Profile === TRUE) AND ( preg_match("/encryption /", $names_line))) {
            $split = explode(" ", $names_line);
            if (!isset($IkeCryptoProfiles[$ikeCryptoProfileName])){
                $IkeCryptoProfiles[$ikeCryptoProfileName] = new IkeCryptoProfile($IkeCryptoProfileID, $ikeCryptoProfileName);
                $IkeCryptoProfileID++;
            }
            switch ($split[1]) {
                case "des":
                    add_log2('error', 'Reading IKE Crypto Profiles', 'Encryption DES is not supported on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Automatically changed to 3des. Please update with your peer', 'ipsec', $IkeCryptoProfiles[$ikeCryptoProfileName]->id, 'ike_crypto_profiles');
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("3des");
                    break;
                case "3des":
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("3des");
                    break;
                case "aes":
                    if ($version < 7) {
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes128");
                    } else {
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-128-cbc");
                        add_log2('warning', 'Reading IKE Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Please update with your peer', 'ipsec', $IkeCryptoProfiles[$ikeCryptoProfileName]->id, 'ike_crypto_profiles');
                    }
                    break;
                case "aes-192":
                    if ($version < 7) {
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes192");
                    } else {
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-192-cbc");
                        add_log2('warning', 'Reading IKE Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Please update with your peer', 'ipsec', $IkeCryptoProfiles[$ikeCryptoProfileName]->id, 'ike_crypto_profiles');
                    }
                    break;
                case "aes-256":
                    if ($version < 7) {
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes256");
                    } else {
                        add_log2('warning', 'Reading IKE Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Please update with your peer', 'ipsec', $IkeCryptoProfiles[$ikeCryptoProfileName]->id, 'ike_crypto_profiles');
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-256-cbc");
                    }

                    break;
                default:
                    add_log2('error', 'Reading IKE Crypto Profiles', $split[4] . ' Encryption not supported on MT yet', $source, 'Please send an email with the Encryption to fwmigrate at paloaltonetworks.com', 'ipsec', $IkeCryptoProfiles[$ikeCryptoProfileName]->id, 'ike_crypto_profiles');
            }
        }

        if (($isIkev1Profile === TRUE) AND ( preg_match("/hash /", $names_line))) {
            $split = explode(" ", $names_line);
            unset($split[0]);
            $split_tmp = array_values($split);
            $split = $split_tmp;
            foreach ($split as $kkey => $vvalue) {
                if (($vvalue != "") and ($vvalue!=NULL)) {
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->addHash($vvalue);
                }
            }
        }

        if (($isIkev1Profile === TRUE) AND ( preg_match("/integrity /", $names_line))) {
            $split = explode(" ", $names_line);
            unset($split[0]);
            $split_tmp = array_values($split);
            $split = $split_tmp;
            foreach ($split as $kkey => $vvalue) {
                if ($vvalue != "") {
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->addHash($vvalue);
                }
            }
        }

        if (($isIkev1Profile === TRUE) AND ( preg_match("/group /", $names_line))) {
            $split = explode(" ", $names_line);
            unset($split[0]);
            $split_tmp = array_values($split);
            $split = $split_tmp;
            foreach ($split as $kkey => $vvalue) {
                if ($vvalue != "") {
                    $groupname = "group" . $vvalue;
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->addDHgroup($groupname);
                }
            }
        }

        if (($isIkev1Profile === TRUE) AND ( preg_match("/lifetime /", $names_line))) {
            $split = explode(" ", $names_line);
            if (is_numeric($split[1])) {
                convertLifeTime($split[1], 1, $time_value, $time);
                $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeType = $time_value;
                $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeValue = $time;
            } else {
                if ($split[1] == "seconds") {
                    convertLifeTime($split[1], 1, $time_value, $time);
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeType = $time_value;
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeValue = $time;
                }
            }
            $isIkev1Profile = FALSE;
        }
    }

    # OUTPUT
    # IKE Crypto Profile
    if (count($IkeCryptoProfiles) > 0) {
        $allsql = [];
        foreach ($IkeCryptoProfiles as $key => $object) {
            $sql_tmp = $object->getSQL($source, $template, $vsys);
            $allsql[] = $sql_tmp;
        }
        if (count($allsql) > 0) {
            $projectdb->query("INSERT INTO ike_crypto_profiles (id, name,vsys,source,template,encryption,hash,dh_group,seconds,minutes,hours,days) VALUES " . implode(",", $allsql) . ";");
        }
    }

    # Attach Tunnel Interfaces to the VR
    if (($vr_id != "") AND ( count($tunnelInterfaces) > 0)) {
        $getInt = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$vr_id';");
        if ($getInt->num_rows == 1) {
            $getIntData = $getInt->fetch_assoc();
            $vr_interfaces = $getIntData['interfaces'] . "," . implode(",", $tunnelInterfaces);
            $projectdb->query("UPDATE virtual_routers SET interfaces='$vr_interfaces' WHERE id='$vr_id';");
        }
    }

    #IKE GWS
    if (count($ikeGateways) > 0) {
//        $myFile = fopen("/tmp/error", "a");
//        fwrite($myFile, "Going to show the ikeGateways\n");
//        fwrite($myFile, print_r($ikeGateways, true));
        $allsql = [];
        /* @var $object IkeGateway*/
        foreach ($ikeGateways as $key => $object) {
            if(get_class ($object) == 'IkeGateway'){
                $sql_tmp = $object->getSQL($source, $template, $vsys);
                $allsql[] = $sql_tmp;
            }
            else{
                add_log2("warning", 'Reading IKE Gateways', "VPN $key not supported", $source, 'Please, review alternative', 'ike', $object->id, 'ike_gateways_profiles');
            }
        }

        if (count($allsql) > 0) {
            $projectdb->query("INSERT INTO ike_gateways_profiles (id, address_type,name,vsys,source,template,version,dpd_ikev1,ike_interval_ikev1,retry_ikev1,ike_crypto_profile_ikev1,exchange_mode_ikev1,dpd_ikev2,ike_interval_ikev2,ike_crypto_profile_ikev2,require_cookie_ikev2,local_address_ip,interface,type_authentication,pre_shared_key,allow_id_payload_mismatch,strict_validation_revocation,nat_traversal,passive_mode,fragmentation,peer_ip_type,peer_ip_address) VALUES " . implode(",", $allsql) . ";");
        }
        add_log2('info', 'Reading IKE Gateways', 'Please attach the proper IKEv1 / IKEv2 Profiles to your IKE Gateways', $source, 'You can use the Attach buttons from IKE Gateways View', 'ike', 0, 'ike_gateways_profiles');
    }

    #IPSEC tunnel
    if (count($ipsecTunnels) > 0) {
        # Check for VPN-l2l TAG. Create it and add it to all the Rules related to VPNs
        $getTAG = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='VPN-l2l' LIMIT 1;");
        if ($getTAG->num_rows == 1) {
            $getTAGData = $getTAG->fetch_assoc();
            $tag_id = $getTAGData['id'];
            $tag_table = "tag";
        }
        else {
            $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('VPN-l2l','$source','$vsys','color1');");
            $tag_id = $projectdb->insert_id;
            $tag_table = "tag";
        }
        $allsql = [];
        //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "Number of ipsecTunnels: ".count($ipsecTunnels)."\n"); fclose($my);
        foreach ($ipsecTunnels as $key => $object) {
            //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "    $key, $object->name\n"); fclose($my);
            $sql_tmp = $object->getSQL($source, $template, $vsys);
            $allsql[] = $sql_tmp;
            if (isset($object->transformSet)){
                $test[] = $object->transformSet->getHash();
            }
            else{
                add_log2('warning', 'IPSEC Tunnel', 'The transform set has not been found', $source, 'Please create a new IPSEC Crypto Profile and attach to '.$object->name, 'rules', $object->id, 'ipsec_tunnel');
            }

        }
        # Write the IPSEC Tunnels to the DB
        if (count($allsql) > 0) {
            $insertQuery = "INSERT INTO ipsec_tunnel (id, name,vsys,source,template,tunnel_interface,address_type,type_tunnel,ike_gateway,ipsec_crypto_profile) VALUES " . implode(",", $allsql) . ";";
            //echo $insertQuery;
            $projectdb->query($insertQuery);
        }

        # Reduce Crypto Ipsec Profiles
        $unique = array_unique($test);
        foreach ($unique as $key => $value) {
            $x = 0;
            foreach ($ipsecTunnels as $kkey => $object) {
                if ((isset($object->transformSet)) AND ($object->transformSet->getHash() == $value)) {
                    $x++;
                    if ($x == 1) {
                        # Get Name
                        $id_1 = $object->transformSet->id;
                        $replace = $object->transformSet->name;
                        # Store the CRypto Ipsec Profile
                        $encryption = implode(",", $object->transformSet->encryption);
                        $authentication = implode(",", $object->transformSet->authentication);
                        $dhgroup = $object->transformSet->dhgroup;
                        $protocol = strtoupper($object->transformSet->ipsecProtocol);
                        $keyLifeTimeValue = $object->transformSet->keyLifeTimeValue;
                        $keyLifeTimeType = $object->transformSet->keyLifeTimeType;
                        $lifeSizeValue = $object->transformSet->lifeSizeValue;
                        $lifeSizeType = $object->transformSet->lifeSizeType;

                        if ($keyLifeTimeValue == "") {
                            $keyLifeTimeValue = "seconds";
                        }
                        if ($lifeSizeValue == "") {
                            $lifeSizeValue = "kb";
                        }

                        $sql = "('$id_1','$replace','$vsys','$source','$template','$encryption','$authentication','$dhgroup','$protocol','$keyLifeTimeType','$lifeSizeType')";
                        $projectdb->query("INSERT INTO ipsec_crypto_profiles (id, name,vsys,source,template,encryption,hash,dh_group,protocol,$keyLifeTimeValue,$lifeSizeValue) VALUES " . $sql . ";");

                        $warnings = $object->transformSet->getWarnings();
                        if( count($warnings)>0 ){
                            foreach($warnings as $warning){
                                add_log2($warning['level'], $warning['task'], $warning['message'], $warning['source'], $warning['action'], $warning['obj_type'], $id_1, $warning['obj_table']);
                            }
                        }

                    }
                    else {
                        $original = $object->transformSet->name;
                        $projectdb->query("UPDATE ipsec_tunnel SET ipsec_crypto_profile='$replace' WHERE template='$template' AND source='$source' AND BINARY ipsec_crypto_profile='$original';");
                    }
                }
                else{
                    add_log2('warning', 'IPSEC Tunnel', 'The transform set has not been found', $source, 'Please create a new IPSEC Crypto Profile and attach to '.$object->name, 'rules', $object->id, 'ipsec_tunnel');
                }
            }
        }

        # Create the ProxyIDs to the IPSEC Tunnel.
        foreach ($ipsecTunnels as $key => $object) {
            # Accesslist
            $yy = 1;
            $accesslist = $object->accesslist;
            if ($accesslist != "") {
                $tunnelInterface = $object->tunnelInterface;
                $ipsecTunnelName = $object->name;
                # Calculate Tunnel ID
                $getTunnelID = $projectdb->query("SELECT id FROM ipsec_tunnel WHERE source='$source' AND template='$template' AND BINARY name='$ipsecTunnelName';");
                if ($getTunnelID->num_rows == 1) {
                    $getTunnelDataData = $getTunnelID->fetch_assoc();
                    $ipsecTunnelID = $getTunnelDataData['id'];

                    # Search The Rules by TAG = access-list
                    $getTAG = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='$accesslist';");
                    if ($getTAG->num_rows == 1) {
                        $getTAGData = $getTAG->fetch_assoc();
                        $tmp_id = $getTAGData['id'];
                        # Read Rules by TAG
                        $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_tag WHERE member_lid='$tmp_id' AND table_name='tag' ;");
                        if ($getRules->num_rows > 0) {
                            $rulesByAccesslist = [];
                            while ($getRulesData = $getRules->fetch_assoc()) {
                                $tmp_rule_lid = $getRulesData['rule_lid'];
                                $rulesByAccesslist[] = $tmp_rule_lid;
                                $projectdb->query("INSERT INTO security_rules_tag (source,vsys,member_lid,table_name,rule_lid) VALUES ('$source','$vsys','$tag_id','$tag_table','$tmp_rule_lid');");
                            }
                            if (count($rulesByAccesslist) > 0) {
                                $xx = 1;

                                foreach ($rulesByAccesslist as $rule_lid) {
                                    $srcbyrule = [];
                                    $dstbyrule = [];
                                    $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE rule_lid='$rule_lid' ;");
                                    if ($getZone->num_rows == 1) {
                                        $getZoneData = $getZone->fetch_assoc();
                                        $getZoneID = $getZoneData['id'];
                                        $projectdb->query("UPDATE security_rules_to SET name='$ipsecTunnelName' WHERE id='$getZoneID';");
                                    } elseif ($getZone->num_rows == 0) {
                                        $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES ('$source','$vsys','$ipsecTunnelName','$rule_lid');");
                                    }
                                    $getSRC = $projectdb->query("SELECT member_lid,table_name FROM security_rules_src WHERE rule_lid='$rule_lid';");
                                    if ($getSRC->num_rows > 0) {
                                        while ($getSRCData = $getSRC->fetch_assoc()) {
                                            $srcbyrule[] = array($getSRCData['member_lid'], $getSRCData['table_name']);
                                        }
                                    }
                                    $getDST = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$rule_lid';");
                                    if ($getDST->num_rows > 0) {
                                        while ($getDSTData = $getDST->fetch_assoc()) {
                                            $dstbyrule[] = array($getDSTData['member_lid'], $getDSTData['table_name']);
                                        }
                                    }
                                    #convert to memberObj
                                    $getAllSRCObj = [];
                                    $srcbyrule = array_map("unserialize", array_unique(array_map("serialize", $srcbyrule)));
                                    foreach ($srcbyrule as $key => $srcs) {
                                        $getAllSRCObj[] = new MemberObject($srcs[0], $srcs[1]);
                                    }

                                    $getAllSRC = explodeGroups2Members($getAllSRCObj, $projectdb, $source, $vsys, 0);
                                    #$dstbyrule = array_unique($dstbyrule);
                                    #convert to memberObj
                                    $getAllDSTObj = [];
                                    $dstbyrule = array_map("unserialize", array_unique(array_map("serialize", $dstbyrule)));
                                    foreach ($dstbyrule as $key => $dsts) {
                                        $getAllDSTObj[] = new MemberObject($dsts[0], $dsts[1]);
                                    }

                                    $getAllDST = explodeGroups2Members($getAllDSTObj, $projectdb, $source, $vsys, 0);


                                    foreach ($getAllSRC as $mySrcObj) {
                                        $mySrc = $mySrcObj->value . "/" . $mySrcObj->cidr;
                                        $type = ip_version($mySrcObj->value);
                                        if ($type == "noip") {
                                            $type = "v4";
                                        }
                                        $protocol = "Any";
                                        foreach ($getAllDST as $myDstObj) {
                                            $myDst = $myDstObj->value . "/" . $myDstObj->cidr;
                                            $proxyIDName = "ProxyID" . $xx;
                                            $xx++;
                                            $projectdb->query("INSERT INTO proxy_id_ipsec_tunnel (name,vsys,source,template,ipsec_tunnel_id,protocol,local,remote,type) VALUES ('$proxyIDName','$vsys','$source','$template','$ipsecTunnelID','$protocol','$mySrc','$myDst','$type');");
                                            # Check the Static Routes
                                            $getRoute = $projectdb->query("SELECT id,nexthop_value,nexthop,tointerface FROM routes_static WHERE vr_id='$vr_id' AND template='$template' AND source='$source' AND destination='$myDst';");
                                            if ($getRoute->num_rows == 0) {
                                                $routeName=$ipsecTunnelName.$yy; $yy++;
                                                $projectdb->query("INSERT INTO routes_static (vr_id,ip_version,source,template,name,destination,tointerface,nexthop) VALUES ('$vr_id','$type','$source','$template','$routeName','$myDst','$tunnelInterface','None');");
                                            } elseif ($getRoute->num_rows == 1) {
                                                $getRouteData = $getRoute->fetch_assoc();
                                                $routeID = $getRouteData['id'];
                                                $routeNH = $getRouteData['nexthop_value'];
                                                $projectdb->query("UPDATE routes_static SET nexthop_value='None', nexthop='None', tointerface='$tunnelInterface' WHERE id='$routeID';");
                                            } else {
                                                add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'Too many static routes for the destination [' . $myDst . ']', $source, 'Fix the routes to point to interface [' . $tunnelInterface . ']', '', '', '');
                                            }
                                        }
                                    }

                                }

                            } else {
                                add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No Rules found by TAG [' . $accesslist . '] related to IPSEC Tunnel [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                            }
                        } else {
                            add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No Rules found by TAG [' . $accesslist . '] related to IPSEC Tunnel [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                        }
                    } else {
                        add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No Rules found by TAG [' . $accesslist . '] related to IPSEC Tunnel [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                    }
                } else {
                    add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No tunnel id found in the DB for Tunnel name [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                }
            }
        }
    }

    // Check if name start with Num in IPSec Tunnels, IPSec Crypto, IKE Crypto and IKE Gateways
    // IKE Crypto Profiles
    $getIKECryptoProfiles = $projectdb->query("SELECT id, name, template, source FROM ike_crypto_profiles;");
    if($getIKECryptoProfiles->num_rows > 0){
        while($dataICP = $getIKECryptoProfiles->fetch_assoc()){
            $id_ike_c_p = $dataICP['id'];
            $name_ike_c_p = $dataICP['name'];
            $template_ike_c_p = $dataICP['template'];
            $source_ike_c_p = $dataICP['source'];

            if (checkNamesStartNum($name_ike_c_p) == TRUE) {
                $name_ike_c_p_new = addPrefixSuffix("on", "p", "", "", $name_ike_c_p, 31);
                $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev1 = '$name_ike_c_p_new' WHERE source = '$source_ike_c_p' AND template = '$template_ike_c_p' AND ike_crypto_profile_ikev1 = '$name_ike_c_p' ;");
                $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev2 = '$name_ike_c_p_new' WHERE source = '$source_ike_c_p' AND template = '$template_ike_c_p' AND ike_crypto_profile_ikev2 = '$name_ike_c_p' ;");
                $projectdb->query("UPDATE ike_crypto_profiles SET name = '$name_ike_c_p_new' WHERE id = '$id_ike_c_p';");
            }
        }
    }

    // IPSec Crypto Profiles
    $getIPSecCryptoProfiles = $projectdb->query("SELECT id, name, template, source FROM ipsec_crypto_profiles;");
    if($getIPSecCryptoProfiles->num_rows > 0){
        while($dataICP = $getIPSecCryptoProfiles->fetch_assoc()){
            $id_ipsec_c_p = $dataICP['id'];
            $name_ipsec_c_p = $dataICP['name'];
            $template_ipsec_c_p = $dataICP['template'];
            $source_ipsec_c_p = $dataICP['source'];

            if (checkNamesStartNum($name_ipsec_c_p) == TRUE) {
                $name_ipsec_c_p_new = addPrefixSuffix("on", "p", "", "", $name_ipsec_c_p, 31);
                $projectdb->query("UPDATE ipsec_tunnel SET ipsec_crypto_profile = '$name_ipsec_c_p_new' WHERE source = '$source_ipsec_c_p' AND template = '$template_ipsec_c_p' AND ipsec_crypto_profile = '$name_ipsec_c_p' ;");
                $projectdb->query("UPDATE ipsec_crypto_profiles SET name = '$name_ipsec_c_p_new' WHERE id = '$id_ipsec_c_p';");
            }
        }
    }

    // IKE Gateways Profiles
    $getIKEGatewaysProfiles = $projectdb->query("SELECT id, name, template, source FROM ike_gateways_profiles;");
    if($getIKEGatewaysProfiles->num_rows > 0){
        while($dataIGP = $getIKEGatewaysProfiles->fetch_assoc()){
            $id_ike_g_p = $dataIGP['id'];
            $name_ike_g_p = $dataIGP['name'];
            $template_ike_g_p = $dataIGP['template'];
            $source_ike_g_p = $dataIGP['source'];

            if (checkNamesStartNum($name_ike_g_p) == TRUE) {
                $name_ike_g_p_new = addPrefixSuffix("on", "p", "", "", $name_ike_g_p, 31);
                $projectdb->query("UPDATE ipsec_tunnel SET ike_gateway = '$name_ike_g_p_new' WHERE source = '$source_ike_g_p' AND template = '$template_ike_g_p' AND ike_gateway = '$name_ike_g_p' ;");
                $projectdb->query("UPDATE ike_gateways_profiles SET name = '$name_ike_g_p_new' WHERE id = '$id_ike_g_p';");
            }
        }
    }

    // IPSec Tunnels
    $getIPSecTunnels = $projectdb->query("SELECT id, name, template, source FROM ipsec_tunnel;");
    if($getIPSecTunnels->num_rows > 0){
        while($dataIT = $getIPSecTunnels->fetch_assoc()){
            $id_ipsec_t = $dataIT['id'];
            $name_ipsec_t = $dataIT['name'];
            $template_ipsec_t = $dataIT['template'];
            $source_ipsec_t = $dataIT['source'];

            if (checkNamesStartNum($name_ipsec_t) == TRUE) {
                $name_ipsec_t_new = addPrefixSuffix("on", "p", "", "", $name_ipsec_t, 31);
                $projectdb->query("UPDATE ipsec_tunnel SET name = '$name_ipsec_t_new' WHERE id = '$id_ipsec_t';");
            }
        }
    }

}

function add_filename_to_objects($source, $vsys, $filename) {
    global $projectdb;

    $projectdb->query("UPDATE address SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
    $projectdb->query("UPDATE address_groups_id SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
    $projectdb->query("UPDATE services SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
    $projectdb->query("UPDATE services_groups_id SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
    $projectdb->query("UPDATE tag SET devicegroup='$filename' WHERE source='$source' AND vsys='$vsys';");
}

function get_icmp_groups($cisco_config_file, $source, $vsys) {
    global $projectdb;
    $addName = array();
    $isIcmpGroup = 0;
    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if (!preg_match("/^icmp-object/", $names_line)) {
            $isIcmpGroup = 0;
        }

        if ($isIcmpGroup == 1) {
            if (preg_match("/\bicmp-object\b/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $addName[] = "('$netObj[1]','$source','$vsys','$IcmpGroupName')";
            }
        }

        if (preg_match("/^object-group icmp-type/i", $names_line)) {
            $isIcmpGroup = 1;
            $names = explode(" ", $names_line);
            $IcmpGroupName = rtrim($names[2]);
        }
    }
    if (count($addName) > 0) {
        $projectdb->query("INSERT INTO cisco_icmp_groups (member,source,vsys,name) values" . implode(",", $addName) . ";");
        unset($addName);
    }
}

function get_protocol_groups($cisco_config_file, $source, $vsys) {
    global $projectdb;
    $addName = array();
    $isProtocolGroup = 0;
    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);

        if (preg_match("/^object-group protocol/i", $names_line)) {
            $isProtocolGroup = 1;
            $names = explode(" ", $names_line);
            $ProtocolGroupName = rtrim($names[2]);
        }

        if ($isProtocolGroup == 1) {
            if (preg_match("/protocol-object/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $addName[] = "('$netObj[1]','$source','$vsys','$ProtocolGroupName')";
            }
        }


    }
    if (count($addName) > 0) {
        $projectdb->query("INSERT INTO cisco_protocol_groups (member,source,vsys,name) values" . implode(",", $addName) . ";");
        unset($addName);
    }

    //
}

function get_security_policies2(STRING $devicegroup, ARRAY $cisco_config_file, STRING $source, STRING $vsys, MemoryObjectsHandlerCisco &$inMemoryObjects=null):array{
    global $projectdb;
    global $global_config_filename;

    global $aclsWithTimeouts;
    global $servicesWithTimouts;

    $AccessGroups = array();
    $AccessGroups['global'] = new SecurityGroup('global');
    $thecolor = 1;
    $addTag=array();
    $allTags=array();

    $loadAllTags=$projectdb->query("SELECT * FROM tag WHERE source='$source' AND vsys='$vsys';");
    if ($loadAllTags->num_rows>0){
        while($loadAllTagsData=$loadAllTags->fetch_assoc()){
            $name=$loadAllTagsData['name'];
            $allTags[$name]=$name;
        }
    }

    $maxTagsResults=$projectdb->query("SELECT max(id) as max FROM tag");
    if($maxTagsResults->num_rows == 0){
        $tagID = 1;
    }
    else{
        $data = $maxTagsResults->fetch_assoc();
        $tagID = $data['max']+1;
    }

    //Create the AccessGroups and the Tags for the AccessGroup
    foreach ($cisco_config_file as $line => $names_line) {
        if (preg_match("/^access-group /i", $names_line)) {
            $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $group = new SecurityGroup($netObj[1]);
            $direction = $netObj[2];
            switch($direction){
                case "in":
                    $group->addZoneFrom($netObj[4]);
                    break;
                case "out":
                    $group->addZoneTo($netObj[4]);
                    break;
                default:
                    break;
            }
            $AccessGroups[$netObj[1]] = $group;

            #Add Tag
            $color = "color" . $thecolor;
            $tagname = truncate_tags($netObj[1]);
            $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name ='$tagname'";
            $result = $projectdb->query($query);
            if($result->num_rows == 0) {
                $addTag[]="('$tagID','$tagname','$source','$vsys','$color')";
                $tagID++;
            }
            if ($thecolor == 16) {
                $thecolor = 1;
            } else {
                $thecolor++;
            }
        }
        if (preg_match("/crypto map /",$names_line)){
            $split=explode(" ",$names_line);
            if ( ($split[4]=="match") AND ($split[5]=="address") ){
                $group = new SecurityGroup(trim($split[6]));
                $AccessGroups[trim($split[6])] = $group;

                #Add Tag
                $color = "color" . $thecolor;
                $tagname = truncate_tags(trim($split[6]));
                $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name ='$tagname'";
                $result = $projectdb->query($query);
                if($result->num_rows == 0) {
                    $addTag[$tagname]="('$tagID','$tagname','$source','$vsys','$color')";
                    $tagID++;
                }
                if ($thecolor == 16) {
                    $thecolor = 1;
                } else {
                    $thecolor++;
                }
            }
        }
    }

    if (count($addTag)>0){
        $unique=array_unique($addTag);
        $projectdb->query("INSERT INTO tag (id, name,source,vsys,color) VALUES ".implode(",",$unique).";");
        unset($unique);unset($addTag);
    }

    $inMemoryObjects->reloadTags($projectdb, $source, $vsys);

    /* @var $group SecurityGroup
     * @var $groupName string
     */

    foreach($AccessGroups as $groupName => &$group){
        $tagObj = $inMemoryObjects->getTag($source, $vsys, $groupName);
        $group->setTag($tagObj);
    }

    # Second Round to read the ACCESS-LISTS
    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    //TODO: Remove the load of application-default?
    //$getApplicationdefault = $projectdb->query("SELECT id FROM shared_services WHERE name='application-default' AND source='$source';");
    $getApplicationdefault = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared';");
    if ($getApplicationdefault->num_rows == 1) {
        $getApplicationdefaultData = $getApplicationdefault->fetch_assoc();
        $application_default = $getApplicationdefaultData['id'];
    }
    else {
        add_default_services($source);
        //$getApplicationdefault = $projectdb->query("SELECT id FROM shared_services WHERE name='application-default' AND source='$source';");
        $getApplicationdefault = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared';");
//            if ($getApplicationdefault->num_rows == 1) {
        $getApplicationdefaultData = $getApplicationdefault->fetch_assoc();
        $application_default = $getApplicationdefaultData['id'];
//            }
    }

    //LOAD required global services
    $any = new MemberObject('any','any','0.0.0.0','0');
    $allTcp = $inMemoryObjects->getServiceReference($devicegroup, $source, $vsys, "all_TCP_ports");
    $allUdp = $inMemoryObjects->getServiceReference($devicegroup, $source, $vsys, "all_UDP_ports");

    $newRuleComment = '';
    $needToResetComment = true;
    $checkFirepower=0;
    $isFirePower=0;
    foreach ($cisco_config_file as $line => $names_line) {
        $skip_acl = false;
        $names_line = trim($names_line);
        if (preg_match("/^access-list /i", $names_line)) {
//                echo "$names_line".PHP_EOL;
            preg_match_all('/"(?:\\\\.|[^\\\\"])*"|\S+/', $names_line,$netObj);
            $netObj=$netObj[0];
            if (isset($AccessGroups[$netObj[1]])) {
                array_shift($netObj); //Remove the "access-list" string
                $groupName = array_shift($netObj); //

//                echo "Rule: $groupName\n";
//                echo "Specials:\n";
//                print_r($aclsWithTimeouts);
                if(isset($aclsWithTimeouts[$groupName])){
                    $timeout =  $aclsWithTimeouts[$groupName]['timeout'];
                    $hasTimeout = true;
//                    echo "$groupName has timeout $timeout\n";
                }
                else{
                    $hasTimeout = false;
                }

                $newRule = new SecurityRuleCisco();
                $newRule->setRuleString($names_line);
                $newRule->setPosition($AccessGroups[$groupName]->getLastRulePosition()+1);
                $newRule->setOriginalName($groupName);
                $newRule->setName(substr($groupName, 0, 15) . "_" . $newRule->position);

                //COMMENTS
                $remark = $netObj[0];
                if($remark == "remark"){
//                    if($needToResetComment){
//                        $needToResetComment = false;
//                        $newRuleComment = '';
//                    }
                    array_shift($netObj);
                    $newRuleComment .= addslashes(" " . implode(" ",$netObj));
                    continue;
                }
                else{
//                    $needToResetComment = true;
                    $newRule->setComment($newRuleComment);
//                    print_r($newRule);
                    $newRuleComment = '';
                }

                //RULE NUMBER
                $lineNumber = $netObj[0];
                switch($lineNumber){
                    case "line":
                        array_shift($netObj);
                        array_shift($netObj);
                        break;
                }

                $extended = $netObj[0];
                switch($extended){
                    case "advanced":
                        if ($checkFirepower==0){
                            $checkFirepower=1;
                        }
                        $isFirePower=1;
                        $newRule->setIsFirepower(1);
                        //TODO: is here a break missing?

                    case "standard":
                    case "extended":
                        array_shift($netObj);
                        break;
                    case "ethertype":
                        add_log2('INFO',
                            'Reading Security Policies',
                            'The following ACL was not imported: "'.$names_line.'"',
                            $source,
                            'Level 2 rules are not supported',
                            'rules',
                            0,
                            'security_rules');
                        $skip_acl = true;
                        break;
                }

                if($skip_acl){
                    continue;
                }

                //ACTION
                $action = $netObj[0];
                switch($action){
                    case 'permit':
                        $newRule->setAction("allow");
                        array_shift($netObj);
                        break;
                    case "deny":
                        $newRule->setAction("deny");
                        array_shift($netObj);
                        break;

                    case "trust":
                        if($newRule->getIsFirepower()==1){
                            $newRule->setAction("allow");
                            array_shift($netObj);
                        }
                        break;

                    default:
                        break;
                }

                //PROTOCOL
                $protocolObject = array_shift($netObj); //
                switch($protocolObject){
                    case 'object-group':
                        $value = array_shift($netObj);
                        $object = $inMemoryObjects->getProtocolGroupReference($devicegroup, $source, $vsys, $value);
                        if($object['type'] == 'cisco_protocol_groups'){ //We received a set of protocols, such as ICMP, TCP
                            $newRule->setProtocol($object['value']);
                        }
                        elseif($object['type'] == 'services_groups_id'){  //The protocol is actually a set of services
                            $newRule->setProtocol(array());
                            $newRule->setService($object['value']);
                        }
                        break;

                    case 'object':
                        $value = array_shift($netObj);
                        $object = $inMemoryObjects->getServiceReference($devicegroup, $source, $vsys, $value);
                        $newRule->setProtocol(array());
                        $newRule->setService($object);
                        //echo "OBJECT-------------------------------\n";
                        //print_r($object);
                        break;

                    case 'ip':
                        $newRule->setProtocol(["ip"]);
                        $newRule->setService([$any]);
                        break;

                    case 'tcp':
                    case 'udp':
                        $newRule->setProtocol([$protocolObject]);
                        break;

                    case 'ah':
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('ipsec-ah');
                        $newRule->setApplications([$appObj]);
                        break;

                    case 'icmp6':
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('ipv6-icmp-base');
                        $newRule->setApplications([$appObj]);
                        break;

                    case "gre":
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('gre');
                        $newRule->setApplications([$appObj]);
                        break;

                    case 'esp';
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('ipsec-esp');
                        $newRule->setApplications([$appObj]);
                        break;

                    case 'igrp':
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('igp');
                        $newRule->setApplications([$appObj]);
                        break;

                    case 'ipinip':
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('ip-in-ip');
                        $newRule->setApplications([$appObj]);
                        break;

                    case 'nos':
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('ipip');
                        $newRule->setApplications([$appObj]);
                        break;

                    case 'pcp':
                        $newRule->setService([$any]);
                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        $appObj = $inMemoryObjects->getDefaultApplication('ipcomp');
                        $newRule->setApplications([$appObj]);
                        break;

                    default:  //This should be for ICMP/PIM/IPX
                        $newRule->setService([$any]);
//                        $newRule->setSourcePort([$any]);
                        $newRule->setProtocol([$protocolObject]);
                        break;
                }

//                    $localPosition = $AccessGroups[$groupName]->getLastRulePosition();
//                    $newRule->setPosition($localPosition+1);

                //OTHER FIELDS INCLUDING: Source, Destination, SourcePort, DestinationPort, User, Log
                # Adding experimental support for FirePower
                $ruleSeemsValid = false;
                while(count($netObj)>0){
                    $currentField = array_shift($netObj);
                    if($currentField != "webtype" && $currentField != "ethertype" ) {
                        $ruleSeemsValid = true;
                        //$newRuleComment = '';
                        switch ($currentField) {

                            case "ifc":
                                $value = array_shift($netObj);
                                $missingFields = $newRule->getMissingFields();
                                if(in_array('zoneFrom', $missingFields)){
                                    $newRule->addZoneFrom($value);
                                }
                                elseif(in_array('zoneTo', $missingFields)){
                                    $newRule->addZoneTo($value);
                                }
                                break;

                            case "rule-id":
                                $value = array_shift($netObj);
                                $newRule->setFirepowerId($value);
                                break;

                            case "any":
                            case "any4":
                            case "any6":
                                $missingFields = $newRule->getMissingFields();
                                if(in_array('source', $missingFields)){
                                    $newRule->setSource($any);
                                }
                                elseif(in_array('destination', $missingFields)){
                                    $newRule->setDestination($any);
                                }
                                elseif(in_array('service', $missingFields)){
                                    //$newRule->setService($any);
                                    $newRule->setService([$any]);
                                }
//                                $newRule->fillAddress($any);

                                break;

                            case "security-group":
                                $isName = array_shift($netObj);
                                if($isName != 'name'){
                                    array_unshift($netObj,$isName);
                                }
                                else{
                                    $securityGroupName = array_shift($netObj);
                                    $newRule->addLog('warning',
                                        'Reading Security Policies',
                                        'Security RuleID [_RuleLid_] is using an security-group name ['.$securityGroupName.'] but we did not load this object. ['.$names_line.']',
                                        'Review the security rule for precaution and create a DAG if necessary');

                                    //Is next group "any?"
                                    $isAny = array_shift($netObj);
                                    if($isAny == 'any'){
                                        array_unshift($netObj,$securityGroupName);
                                        array_unshift($netObj,'object-group');
//                                    array_unshift($netObj,'object');

                                        $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$securityGroupName' AND vsys='$vsys'");
                                        if ($getDup->num_rows == 0) {
                                            $HostGroupNamePan = truncate_names(normalizeNames($securityGroupName));
                                            $projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,vsys,type, devicegroup) values ('$HostGroupNamePan','$securityGroupName','$source','$vsys','dynamic','$global_config_filename');");
                                            $groupLid = $projectdb->insert_id;

                                            $addressGroupData = [
                                                'name'  => $securityGroupName,
                                                'type'  => 'dynamic',
                                                'id'    => $groupLid,
                                                'source'=> $source,
                                                'vsys'  => $vsys
                                            ];
                                            $response = $inMemoryObjects->addAddressGroup($addressGroupData);
                                        }
                                    }
                                    else{
                                        array_unshift($netObj,$isAny);
                                    }
                                }




                                //print_r($newRule);

                                break;
                            case "object":
                                $value = array_shift($netObj);
                                $value = removeEnclosingQuotes($value);
                                $missingFields = $newRule->getMissingFields();
                                //If we have filled in the Source, Destination and Service, we then missed the SourcePort in prior loads. We need to correct it :(
                                if($object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $value)){
                                    if(in_array('source', $missingFields)){
                                        $newRule->setSource($object);
                                    }
                                    elseif(in_array('destination', $missingFields)){
                                        $newRule->setDestination($object);
                                    }
                                    else{
                                        $newRule->addLog('warning',
                                            'Reading Security Policies',
                                            'Security RuleID [_RuleLid_] is using an object-group ['.$value.'] but both Source and Destination are filled. ['.$names_line.']',
                                            'Review the security rule for precaution');
                                        echo "Problem object:address:fields_full => This object is not recognized. [$names_line]\n";
                                    }
                                }
                                elseif($objects = $inMemoryObjects->getServiceReference($devicegroup, $source, $vsys, $value, $newRule->protocol)){
                                    if(in_array('destination', $missingFields)){
                                        $newRule->setSourcePort($objects);
                                    }
                                    elseif(in_array('service', $missingFields)){
                                        $newRule->setService($objects);
                                    }
                                    else{
                                        $newRule->addLog('warning',
                                            'Reading Security Policies',
                                            'Security RuleID [_RuleLid_] is using an object-group ['.$value.'] but both SourcePort and Service are filled. ['.$names_line.']',
                                            'Review the security rule for precaution');
                                        echo "Problem object:service:fields_full => This object is not recognized [$names_line]\n";
                                    }
                                }
                                else{
                                    $newRule->addLog('warning',
                                        'Reading Security Policies',
                                        'Security RuleID [_RuleLid_] is using an object ['.$value.'] but this Object is unknown. ['.$names_line.']',
                                        'Review the security rule for precaution');
                                    echo "Problem object:unknown_object => This object is not recognized [$names_line]\n";
                                }
//                                if(!in_array('source', $missingFields) && !in_array('destination', $missingFields) && !in_array('service', $missingFields)) {
//                                    $object = $inMemoryObjects->getServiceReference($devicegroup, $source, $vsys, $value, $newRule->protocol);
//                                    $newRule->correctSourcePort($devicegroup, $source, $vsys, $inMemoryObjects, $object);
//                                }
//                                else{
//                                    if(in_array('source', $missingFields)){
//                                        $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $value);
//                                        $newRule->setSource($object);
//                                    }
//                                    elseif(in_array('destination', $missingFields)){
//                                        $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $value);
//                                        $newRule->setDestination($object);
//                                    }
//                                    elseif(in_array('service', $missingFields)){
//                                        $object = $inMemoryObjects->getServiceReference($devicegroup, $source, $vsys, $value, $newRule->protocol);
//                                        $newRule->setService($object);
//                                    }
//                                    else{
//                                        echo "Problem 1894: This object is not recognized";
//                                    }
//                                }
                                break;

                            case "object-group":
                            case "object-group-security":
                                $value = array_shift($netObj);
                                $value = removeEnclosingQuotes($value);
                                $missingFields = $newRule->getMissingFields();

                                //Let's check it is a service or an address
                                if($object = $inMemoryObjects->getAddressGroupReference($devicegroup, $source, $vsys, $value)){
                                    if(in_array('source', $missingFields)){
                                        $newRule->setSource($object);
                                    }
                                    elseif(in_array('destination', $missingFields)){
                                        $newRule->setDestination($object);
                                    }
                                    else{
                                        $newRule->addLog('warning',
                                            'Reading Security Policies',
                                            'Security RuleID [_RuleLid_] is using an object-group ['.$value.'] but both Source and Destination are filled. ['.$names_line.']',
                                            'Review the security rule for precaution');
                                        echo "Problem object-group:address:fields_full => This object is not recognized [$names_line]\n";
                                    }
                                }
                                elseif($objects = $inMemoryObjects->getServiceGroupReference($devicegroup, $source, $vsys, $value)){

                                    if(in_array('destination', $missingFields)){
                                        $newRule->setSourcePort($objects);
                                    }
                                    elseif(in_array('service', $missingFields)){
                                        $newRule->setService($objects);
                                    }
                                    else{
                                        $newRule->addLog('warning',
                                            'Reading Security Policies',
                                            'Security RuleID [_RuleLid_] is using an object-group ['.$value.'] but both SourcePort and Service are filled. ['.$names_line.']',
                                            'Review the security rule for precaution');
                                        echo "Problem object-group:service:fields_full => This object is not recognized [$names_line]\n";
                                    }
                                }
                                else{
                                    $newRule->addLog('warning',
                                        'Reading Security Policies',
                                        'Security RuleID [_RuleLid_] is using an object-group ['.$value.'] but this Object is unknown. ['.$names_line.']',
                                        'Review the security rule for precaution');
                                    echo "Problem object-group:unknwon_object => This object is not recognized [$names_line]\n";
                                }

                                break;

                            case "host":
                                $value = array_shift($netObj);
                                $missingFields = $newRule->getMissingFields();
                                if(in_array('source', $missingFields)) {
                                    $ipversion = ip_version($value);
                                    if ($ipversion == 'ipv4') {
                                        $object = $inMemoryObjects->getIPAddressReference($devicegroup, $source, $vsys, $value, 32);
                                        $newRule->setSource($object);
                                    }
                                    if ($ipversion == 'ipv6') {
                                        $object = $inMemoryObjects->getIPAddressReference($devicegroup, $source, $vsys, $value, 128);
                                        $newRule->setSource($object);
                                    } else {
                                        $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $value, 32);
                                        $newRule->setSource($object);
                                    }
                                }
                                elseif(in_array('destination', $missingFields)) {
                                    $ipversion = ip_version($value);
                                    if ($ipversion == 'ipv4') {
                                        $object = $inMemoryObjects->getIPAddressReference($devicegroup, $source, $vsys, $value, 32);
                                        $newRule->setDestination($object);
                                    }
                                    if ($ipversion == 'ipv6') {
                                        $object = $inMemoryObjects->getIPAddressReference($devicegroup, $source, $vsys, $value, 128);
                                        $newRule->setDestination($object);
                                    } else {
                                        $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $value, 32);
                                        $newRule->setDestination($object);
                                    }
                                }
                                else{
                                    echo "Problem 1959: Host value in a wrong position? $names_line\n";
                                }

                                break;

                            case "interface":
                                $value = array_shift($netObj);
                                $missingFields = $newRule->getMissingFields();
                                if(in_array('source', $missingFields)){
                                    $newRule->setZoneFrom([$value]);
                                    $newRule->setSource($any);
                                }
                                elseif(in_array('destination', $missingFields)){
                                    $newRule->setZoneTo([$value]);
                                    $newRule->setDestination($any);
                                }

                                break;
                            case "inactive":
                                $newRule->setDisabled();
                                break;

                            case "user-group":
                            case "user":
                                $value = array_shift($netObj);
                                $value = removeEnclosingQuotes($value);
                                $value = removeDoubleBackSlash($value);
                                $newRule->setUser([$value]);
                                break;

                            case "object-group-user":
                                $value = array_shift($netObj);
                                $object = $inMemoryObjects->getUsers($devicegroup, $source, $vsys, $value);
                                $newRule->setUser($object);
                                break;

                            // Cases for SERVICES
                            case "neq":
                                $missingFields = $newRule->getMissingFields();
                                $value = array_shift($netObj);
                                $object = $inMemoryObjects->getServiceNEQ($devicegroup, $source, $vsys, $value, $newRule->protocol);
                                if(in_array('destination', $missingFields)){
                                    $newRule->setSourcePort($object);
                                }
                                else {
                                    $newRule->setService($object);
                                }
                                break;

                            case "eq":
                                $missingFields = $newRule->getMissingFields();
                                $value = array_shift($netObj);
                                $object = $inMemoryObjects->getServiceEQ($devicegroup, $source, $vsys, $value, $newRule->protocol);
                                if(in_array('destination', $missingFields)){
                                    $newRule->setSourcePort($object);
                                }
                                else {
                                    $newRule->setService($object);
                                }
                                break;

                            case "lt":
                                $missingFields = $newRule->getMissingFields();
                                $value = array_shift($netObj);
                                $object = $inMemoryObjects->getServiceLT($devicegroup, $source, $vsys, $value, $newRule->protocol);
                                if(in_array('destination', $missingFields)){
                                    $newRule->setSourcePort($object);
                                }
                                else {
                                    $newRule->setService($object);
                                }
                                break;

                            case "gt":
                                $missingFields = $newRule->getMissingFields();
                                $value = array_shift($netObj);
                                $object = $inMemoryObjects->getServiceGT($devicegroup, $source, $vsys, $value, $newRule->protocol);
                                if(in_array('destination', $missingFields)){
                                    $newRule->setSourcePort($object);
                                }
                                else {
                                    $newRule->setService($object);
                                }
                                break;

                            case "range":
                                $missingFields = $newRule->getMissingFields();
                                $valueStart = array_shift($netObj);
                                $valueEnd   = array_shift($netObj);
                                $object = $inMemoryObjects->getServiceRangeReference($devicegroup, $source, $vsys, $valueStart, $valueEnd, $newRule->protocol);
                                if(in_array('destination', $missingFields)){
                                    $newRule->setSourcePort($object);
                                }
                                else {
                                    $newRule->setService($object);
                                }
                                break;


                            case "echo":
                            case "echo-reply":
                                if(in_array('icmp',$newRule->protocol)){
                                    $object = $inMemoryObjects->getDefaultApplication('ping');
                                    if(!is_null($object)) {
                                        $newRule->addApplication($object);
                                    }
                                }
                                break;
                            case "source-quench":
                                //This is a type of icmp
                                break;

                            case "traceroute":
                                if(in_array('icmp',$newRule->protocol)){
                                    $object = $inMemoryObjects->getDefaultApplication('traceroute');
                                    if(!is_null($object)) {
                                        $newRule->addApplication($object);
                                    }
                                }
                                break;

                            case "unreachable":
                                if(in_array('icmp',$newRule->protocol)){
                                    $object = getApplicationSnippet($projectdb, 'icmp_destination_unreachable', $source, $vsys);
//                                    $object =new MemberObject('custom_application','applications','icmp_destination_unreachable','snippet');
                                    $newRule->addApplication($object);
                                }
                                break;

                            case "log":
                            case "disable":
                            case "warnings":
                            case "default":
                            case "debugging":
                            case "time-exceeded":
                            case "notifications":
                            case "critical":
//                            case "unreachable":
                                break;

                            case "interval":
                                $interval = array_shift($netObj);
                                break;

                            case "time-range":
                                $starting_date = array_shift($netObj);
                                $newRule->addLog('warning',
                                    'Reading Security Policies',
                                    'Security RuleID [_RuleLid_] is using a time-range field with value ['.$starting_date.']. This field has not been migrated',
                                    'Check whether this security rule needs to be activated');
                                break;


                            default:
                                //Check if it is an IP netmask
                                $currentIP = explode("/", $currentField);
                                if(isset($currentIP[1])){
                                    $ipv6Mask = $currentIP[1];
                                }
                                $versionCheck = ip_version($currentIP[0]);
                                if ($versionCheck == "v4") {
                                    $nextField = isset($netObj[0]) ? $netObj[0] : '';
                                    $cidr = convertWildcards($nextField,'cidr');
                                    if ($cidr==FALSE){
                                        $cidr = mask2cidrv4($nextField);
                                    }
                                    //$cidr = mask2cidrv4($nextField);
                                    //TODO: convert this function into missingFields and check if it is source or destination
                                    $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $currentField, $cidr);
//                                        echo "$names_line\n";
//                                        echo "CurrentField = $currentField\n";
//                                        print_r($object);
                                    $newRule->fillAddress($object);
                                    array_shift($netObj);
                                }
                                elseif ($versionCheck == "v6") {
                                    $memberObject = $inMemoryObjects->getIPv6AddressReference($devicegroup,$source, $vsys, $currentField, $ipv6Mask);
                                    $newRule->fillAddress($memberObject);
                                    array_shift($netObj);
                                }
                                else {
                                    //Check if it is a known label
                                    $nextField = isset($netObj[0]) ? $netObj[0] : '';
                                    $cidr = convertWildcards($nextField,'cidr');
                                    if ($cidr==FALSE){
                                        if(checkNetmask($nextField)) {
                                            $cidr = mask2cidrv4($nextField);
                                            array_shift($netObj);
                                        }
                                    }
                                    $missingFields = $newRule->getMissingFields();
                                    if(in_array('source', $missingFields)) {
                                        $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $currentField, $cidr);
                                        $newRule->setSource($object);
                                    }
                                    elseif(in_array('destination', $missingFields)) {
                                        $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $currentField, $cidr);
                                        $newRule->setDestination($object);
                                    }
                                    else{
                                        echo "Problem 2115: Field $currentField not recognized in [$names_line]\n";
                                    }
                                }

                                break;
                        }
                    }
                }

//                if($ruleSeemsValid){
//                    $newRule->setComment($newRuleComment);
//                }
//                $newRuleComment = '';

                //In case a Security Rule belongs to an Access Group that was not found (not declared), create the group here
                if(!isset($AccessGroups[$groupName])){
                    $AccessGroups[$groupName] = new SecurityGroup($groupName, false);
                }

                //Final check before adding this Rule into the Group (memory space still)
                if($newRule->isValid()) {
                    //Complementing the rule with information coming from the Access Group it belongs to
                    $from   = $AccessGroups[$groupName]->getZoneFrom();
                    $to     = $AccessGroups[$groupName]->getZoneTo();
                    if (count($from)>0){
                        $newRule->setZoneFrom($from);
                    }
                    if (count($to)>0){
                        $newRule->setZoneTo($to);
                    }

//                    print_r($newRule);
//                    print_r($AccessGroups[$groupName]);
                    $newRule->addTag($AccessGroups[$groupName]->getTag());

                    if(in_array('icmp',$newRule->protocol) && $newRule->application == null){
                        $object = $inMemoryObjects->getDefaultApplication('icmp');
                        if(!is_null($object)) {
                            $newRule->addApplication($object);
                        }
                    }

                    if(in_array('sctp',$newRule->protocol) && $newRule->application == null){
                        $object = $inMemoryObjects->getDefaultApplication('sctp');
                        if(!is_null($object)) {
                            $newRule->addApplication($object);
                        }
                    }

                    //Adding AllPorts for security rules with TCP and UDP protocols that do not specify a port
                    if(!isset($newRule->service)){
                        if(isset($newRule->protocol['ip'])){
                            $newRule->setService(array_merge($allTcp,$allUdp));
                        }
                        else {
                            if (isset($newRule->protocol['tcp'])) {
                                $newRule->addService($allTcp[0]);
                            }
                            if (isset($newRule->protocol['udp'])) {
                                $newRule->addService($allUdp[0]);
                            }
                        }
                    }

                    //Check if the rule needs to be split into Two due to Services that should be transformed into Apps
                    $tcpudpProtocols = array();     //TCP and UDP protocols
                    $networkProtocols = $newRule->protocol;  //Other protocols
                    //echo "-----------------\n";
                    //echo "Newrules->service: \n";
                    //print_r($newRule->service);
                    //echo "Newrules->protocol: \n";
                    //print_r($newRule->protocol);
                    
                    if(isset($networkProtocols['tcp'])) {
                        $tcpudpProtocols[]='tcp';
                        unset($networkProtocols['tcp']);
                    }
                    if(isset($networkProtocols['udp'])) {
                        $tcpudpProtocols[]='udp';
                        unset($networkProtocols['udp']);
                    }
                    if(isset($networkProtocols['ip'])) {
                        $tcpudpProtocols[]='tcp';
                        $tcpudpProtocols[]='udp';
                        unset($networkProtocols['ip']);
                    }

                    //If we have network protocols and TCP/UDP protocols, we need to split the rule
                    //print_r($networkProtocols);
                    //print_r($tcpudpProtocols);

                    if(count($networkProtocols)>0 && count($tcpudpProtocols)>0){
                        $networkProtocolRule = clone $newRule;

                        //Preparing and adding the TCP/UDP rule
                        $newRule->setApplications(array());
                        $newRule->setProtocol($tcpudpProtocols);


                        //Check that the services are from the Protocol that has been specified
                        //Initially the Service may have both UDP and TCP ports
                        //It only one of the two protocols is in this service, then we need to find out which ports we should keep
                        if(count($tcpudpProtocols)==1){
                            $protocol = array_pop($tcpudpProtocols);
                            $services = $newRule->service;

                            $explodedServices = explodeGroups2Services($services, $projectdb, $source, $vsys);
                            $validServices = array();
                            /* @var $service MemberObject*/
                            foreach ($explodedServices as $service){

                                //echo "Service cidr: " .$service->cidr. "\n";
                                //echo "Protocol: " .$protocol. "\n";
                                //print_r($service);
                                if($service->cidr == $protocol){  $validServices[] = $service;  }
                            }
                            if(count($validServices) == count($explodedServices)){   $newRule->setService($services);    }
                            else{                                                    $newRule->setService($validServices);  }
                        }

                        //Verify if the source port has been defined
                        if(count($newRule->sourcePort)>0 && $newRule->sourcePort[0]->name!='any'){
                            $sourcePorts = array();
                            /* @var $sourcePort MemberObject*/
                            foreach($newRule->sourcePort as $sourcePort){
                                $sourcePorts[] = $sourcePort->cidr."/".$sourcePort->value;
                            }
                            $newRule->addLog(
                                'warning',
                                'Reading Security Policies',
                                'This rule had the following source ports:'.implode(', ',$sourcePorts),
                                'Recommended to identify involved Applications and verify they are included in the rule');
                        }

                        $AccessGroups[$groupName]->addRule($newRule);

                        //Preparing and adding the NetworkProtocol rule
                        $networkProtocolRule->setProtocol($networkProtocols);
                        $networkProtocolRule->setService(array($any));
                        $AccessGroups[$groupName]->addRule($networkProtocolRule);
                    }
                    elseif(count($networkProtocols)>0){ //Preparing and adding the NetworkProtocol rule
                        $newRule->setProtocol($networkProtocols);
                        $newRule->setService(array($any));
                        $AccessGroups[$groupName]->addRule($newRule);
                    }
                    else { //Preparing and Adding the TPC/UDP Rule to the Group
                        $newRule->setApplications(array());
                        if(count($tcpudpProtocols)==1){
                            $protocol = array_pop($tcpudpProtocols);
                            $services = $newRule->service;
                            $explodedServices = $inMemoryObjects->explodeGroup2Services($services, $source, $vsys);
                            $validServices = array();
                            /* @var $service MemberObject*/
                            foreach ($explodedServices as $service){
                                if($service->cidr == $protocol){ $validServices[] = $service;  }
                            }
                            if(count($validServices) == count($explodedServices)){   $newRule->setService($services);    }
                            else{                                                    $newRule->setService($validServices);   }
                        }

                        //Verify if the source port has been defined
                        if(count($newRule->sourcePort)>0 && $newRule->sourcePort[0]->name !='any'){
                            $sourcePorts = array();
                            /* @var $sourcePort MemberObject*/
                            foreach($newRule->sourcePort as $sourcePort){
                                $sourcePorts[] = $sourcePort->cidr."/".$sourcePort->value;
                            }
                            $newRule->addLog(
                                'warning',
                                'Reading Security Policies',
                                'This rule had the following source ports: '.implode(', ',$sourcePorts),
                                'Recommended to identify involved Applications and verify they are included in the rule');
                        }

                        $AccessGroups[$groupName]->addRule($newRule);
                    }
                }

            }
        }
    }


//    print_r($AccessGroups);

    //Move the global access-group to the last entry
    // We have defined 'global' as the first element at the beginning of the function

    $globalGroup = array_shift($AccessGroups);
    $AccessGroups['global'] = $globalGroup;

    // Calculate the rule IDs
    $query = "SELECT max(id) as max FROM security_rules";
    $result = $projectdb->query($query);
    if($result->num_rows > 0){
        $data = $result->fetch_assoc();
        $initiGlobalPosition = is_null($data['max'])?0:$data['max'];
    }
    else {
        $initiGlobalPosition = 0;
    }

    /* @var $accessGroup SecurityGroup */
    foreach ($AccessGroups as $key => $accessGroup){
        if($accessGroup->getUsed()==true) {
            $AccessGroups[$key]->setInitialID($initiGlobalPosition);
            $initiGlobalPosition += $accessGroup->getLastRulePosition();
        }
    }

    //Insert new Addresses and Services
    $inMemoryObjects->insertNewAddresses($projectdb);
    $inMemoryObjects->insertNewServices($projectdb);

    //        $inMemoryObjects->removeUnusedLabels($projectdb, $source, $vsys);

    removeUnusedLabels($projectdb, $source, $vsys);

    //Generate Security Rules
    $sec_rules =            array();
    $sec_rules_srv =        array();
    $sec_rules_src =        array();
    $sec_rules_dst=         array();
    $sec_rules_from =       array();
    $sec_rules_to =         array();
    $sec_rules_usr =        array();
    $sec_rules_tags =       array();
    $sec_rules_app =        array();


        //print_r($AccessGroups);

    /* @var $accessGroup SecurityGroup
     * @var $rule SecurityRuleCisco
     * @var $srv MemberObject
     * @var $src MemberObject
     * @var $dst MemberObject
     * @var $from String
     * @var $to String
     * @var $user String
     * @var $app MemberObject
     */
    $firePowerTrack=array();

    foreach ($AccessGroups as $key=> $accessGroup){
        if($accessGroup->getUsed()) {
            /* @var  SecurityRule $rule */
            foreach($accessGroup->getRules() as $rule) {

                //( source, vsys, rule_lid, table_name, member_lid)
                $isFirePower=$rule->getIsFirepower();
                if ($isFirePower==1){
                    $firePowerId=$rule->getFirepowerId();
                    if (!isset($firePowerTrack[$firePowerId])){
                        $firePowerTrack[$firePowerId]=$firePowerId;
                        $rule_lid = $rule->globalPosition;
                        // (id, position, name, name_ext, description, action, disabled, vsys, source)
                        $sec_rules[] = "('$rule->globalPosition', '$rule->globalPosition', '$rule->name','$rule->name', '".normalizeComments($rule->comment)."','$rule->action', $rule->disabled, '$vsys', '$source')";
                    }
                    if (isset($rule->service)) {
                        foreach ($rule->service as $srv) {
                            if ($srv->location != 'any') {
                                //echo "Member lid service: " .$srv->name. "\n";
                                $sec_rules_srv[] = "('$source', '$vsys','$rule_lid','$srv->location','$srv->name')";
                            }
                        }
                    }

                    //( source, vsys, rule_lid, table_name, member_lid)
                    $src = $rule->source;
                    if($src->location != 'any'){
                        $sec_rules_src[] = "('$source', '$vsys','$rule_lid','$src->location','$src->name')";
                    }

                    //( source, vsys, rule_lid, table_name, member_lid)
                    $dst = $rule->destination;
                    if($dst->location != 'any'){
                        $sec_rules_dst[] = "('$source', '$vsys','$rule_lid','$dst->location','$dst->name')";
                    }

                    //(source, vsys, rule_lid, name)
                    if(isset($rule->zoneFrom)) {
                        foreach ($rule->zoneFrom as $from) {
                            $sec_rules_from[] = "('$source', '$vsys','$rule_lid','$from')";
                        }
                    }

                    //(source, vsys, rule_lid, name)
                    if(isset($rule->zoneTo)) {
                        foreach ($rule->zoneTo as $to) {
                            $sec_rules_to[] = "('$source', '$vsys','$rule_lid','$to')";
                        }
                    }

                    //(source, vsys, rule_lid, name)
                    if(isset($rule->user)) {
                        foreach ($rule->user as $user) {
                            $userB = addslashes($user);
                            //echo "RuleLid: " .$rule_lid. " User: " .$user. " User B: " .$userB. "\n";
                            $sec_rules_usr[] = "('$source', '$vsys','$rule_lid','$userB')";
                        }
                    }

                    //(source, vsys, rule_lid, table_name, member_lid)
                    if(isset($rule->application)) {
                        foreach ($rule->application as $app) {
                            $sec_rules_app[] = "('$source', '$vsys','$rule_lid','$app->location','$app->name')";
                        }
                    }

                    //(source, vsys, member_lid, rule_lid, table_name, member_lid)
                    if(isset($rule->tag)) {
                        foreach ($rule->tag as $tag) {
                            $sec_rules_tags[] = "('$source', '$vsys','$rule_lid','$tag->location','$tag->name')";
                        }
                    }

                    //Adding all the warning messages
                    if(isset($rule->logs)){
                        foreach($rule->logs as $log){
                            //Replace _RuleLid_ by its Rulelid
                            $log['message'] = str_replace('_RuleLid_', $rule_lid, $log['message']);
                            add_log2($log['logType'],$log['task'], $log['message'], $source, $log['action'],'rules', $rule_lid, 'security_rules');
                        }
                    }


                }
                else{
                    $rule_lid = $rule->globalPosition;
                    // (id, position, name, name_ext, description, action, disabled, vsys, source)
                    $sec_rules[] = "('$rule->globalPosition', '$rule->globalPosition', '$rule->name','$rule->name', '".normalizeComments($rule->comment)."','$rule->action', $rule->disabled, '$vsys', '$source')";

                    if (isset($rule->service)) {
                        foreach ($rule->service as $srv) {
                            if ($srv->location != 'any') {
                                //echo "Member lid service: " .$srv->name. "\n";
                                $sec_rules_srv[] = "('$source', '$vsys','$rule_lid','$srv->location','$srv->name')";
                            }
                        }
                    }

                    //( source, vsys, rule_lid, table_name, member_lid)
                    $src = $rule->source;
                    if($src->location != 'any'){
                        $sec_rules_src[] = "('$source', '$vsys','$rule_lid','$src->location','$src->name')";
                    }

                    //( source, vsys, rule_lid, table_name, member_lid)
                    $dst = $rule->destination;
                    if($dst->location != 'any'){
                        $sec_rules_dst[] = "('$source', '$vsys','$rule_lid','$dst->location','$dst->name')";
                    }

                    //(source, vsys, rule_lid, name)
                    if(isset($rule->zoneFrom)) {
                        foreach ($rule->zoneFrom as $from) {
                            $sec_rules_from[] = "('$source', '$vsys','$rule_lid','$from')";
                        }
                    }

                    //(source, vsys, rule_lid, name)
                    if(isset($rule->zoneTo)) {
                        foreach ($rule->zoneTo as $to) {
                            $sec_rules_to[] = "('$source', '$vsys','$rule_lid','$to')";
                        }
                    }

                    //(source, vsys, rule_lid, name)
                    if(isset($rule->user)) {
                        foreach ($rule->user as $user) {
                            $userB = addslashes($user);
                            //echo "RuleLid: " .$rule_lid. " User: " .$user. " User B: " .$userB. "\n";
                            $sec_rules_usr[] = "('$source', '$vsys','$rule_lid','$userB')";
                        }
                    }

                    //(source, vsys, rule_lid, table_name, member_lid)
                    if(isset($rule->application)) {
                        foreach ($rule->application as $app) {
                            $sec_rules_app[] = "('$source', '$vsys','$rule_lid','$app->location','$app->name')";
                        }
                    }

                    //(source, vsys, member_lid, rule_lid, table_name, member_lid)
                    if(isset($rule->tag)) {
                        foreach ($rule->tag as $tag) {
                            $sec_rules_tags[] = "('$source', '$vsys','$rule_lid','$tag->location','$tag->name')";
                        }
                    }

                    //Adding all the warning messages
                    if(isset($rule->logs)){
                        foreach($rule->logs as $log){
                            //Replace _RuleLid_ by its Rulelid
                            $log['message'] = str_replace('_RuleLid_', $rule_lid, $log['message']);
                            add_log2($log['logType'],$log['task'], $log['message'], $source, $log['action'],'rules', $rule_lid, 'security_rules');
                        }
                    }
                }

            }
        }
    }


    if(count($sec_rules)>0){
        $query = "INSERT INTO security_rules (id, position, name, name_ext, description, action, disabled, vsys, source) VALUES ".implode(",",$sec_rules).";";
        $projectdb->query($query);  unset($sec_rules);
    }

    if(count($sec_rules_srv)>0){
        $unique=array_unique($sec_rules_srv);
        $query = "INSERT INTO security_rules_srv (source, vsys, rule_lid, table_name, member_lid) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_srv); unset($unique);
    }

    if(count($sec_rules_src)>0){
        $unique=array_unique($sec_rules_src);
        $query = "INSERT INTO security_rules_src (source, vsys, rule_lid, table_name, member_lid) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_src); unset($unique);
    }

    if(count($sec_rules_dst)>0){
        $unique=array_unique($sec_rules_dst);
        $query = "INSERT INTO security_rules_dst (source, vsys, rule_lid, table_name, member_lid) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_dst); unset($unique);
    }

    if(count($sec_rules_from)>0){
        $unique=array_unique($sec_rules_from);
        $query = "INSERT INTO security_rules_from (source, vsys, rule_lid, name) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_from); unset($unique);
    }

    if(count($sec_rules_to)>0){
        $unique=array_unique($sec_rules_to);
        $query = "INSERT INTO security_rules_to (source, vsys, rule_lid, name) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_to); unset($unique);
    }

    if(count($sec_rules_usr)>0){
        $unique=array_unique($sec_rules_usr);
        $query = "INSERT INTO security_rules_usr (source, vsys, rule_lid, name) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_usr); unset($unique);
    }

    if(count($sec_rules_app)>0){
        $unique=array_unique($sec_rules_app);
        $query = "INSERT INTO security_rules_app (source, vsys, rule_lid, table_name, member_lid) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_app); unset($unique);
    }

    if(count($sec_rules_tags)>0){
        $unique=array_unique($sec_rules_tags);
        $query = "INSERT INTO security_rules_tag (source, vsys, rule_lid, table_name, member_lid) VALUES ".implode(",",$unique).";";
        $projectdb->query($query);  unset($sec_rules_tags); unset($unique);
    }

    if ($isFirePower==1){
        # Fix Rule 9998 Remove the services and add app teredo
        $get9998=$projectdb->query("SELECT id FROM security_rules WHERE description LIKE '%rule-id 9998%' AND source='$source' LIMIT 1;");
        if ($get9998->num_rows==1){
            $get9998data=$get9998->fetch_assoc();
            $get9998Id=$get9998data['id'];
            $projectdb->query("DELETE from security_rules_srv WHERE rule_lid='$get9998Id';");
            $getTeredo=$projectdb->query("SELECT id FROM default_applications WHERE name = 'teredo';");
            if ($getTeredo->num_rows==1){
                $getTeredoData=$getTeredo->fetch_assoc();
                $getTeredoId=$getTeredoData['id'];
                $projectdb->query("INSERT INTO security_rules_app (rule_lid,member_lid,table_name) VALUES ('$get9998Id','$getTeredoId','default_applications');");
            }
        }
    }

    return $AccessGroups;
}

function removeUnusedLabels(MySQLi $projectdb, STRING $source, STRING $vsys){
    $objects = array();
    $labelObjects = array();
    $query = "SELECT * FROM address WHERE source='$source' AND vsys='$vsys'";
    $results = $projectdb->query($query);
    if($results->num_rows>0) {
        while ($data = $results->fetch_assoc()) {
            $name = $data['name'];
            $objects[$name]['objects'][] = [
                'name'          => $data['name'],
                'id'            => $data['id'],
                'vtype'         => $data['vtype'],
                'ipaddress'     => $data['ipaddress'],
                'cidr'          => $data['cidr'],
            ];

            if($data['vtype'] == 'label'){
                $labelObjects[$name] = [
                    'name'  => $data['name'],
                    'id'    => $data['id'],
                    'cidr'  => $data['cidr'],
                ];
            }
        }
    }

    $deleteableLables = array();
    foreach($labelObjects as $labelName => $labelArray){
        $count = $objects[$labelName]['objects'];
        if($count>1){
            $deleteableLables[]=$labelArray['id'];
        }
    }

    $query = "DELETE FROM address WHERE id in (".implode(',',$deleteableLables).") AND description ='' AND cidr=0 ";
//    echo $query;
//    $projectdb->query($query);

}

function get_security_policies($cisco_config_file, $source, $vsys) {
    global $projectdb;
    global $global_config_filename;
    $AccessGroups = array();
    $comments = "";
    $x = 1;
    $thecolor = 1;
#First Round to get ACCESS-GROUPS ONLY ACCESS-LISTS ASSIGNED TO INTERFACE
    foreach ($cisco_config_file as $line => $names_line) {
        if (preg_match("/^access-group /i", $names_line)) {
            $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            array_push($AccessGroups, $netObj[1]);
            #Add Tag
            $color = "color" . $thecolor;
            $tagname = truncate_tags($netObj[1]);
            $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name ='$tagname'";
            //echo "$query\n";
            $result = $projectdb->query($query);
            if($result->num_rows == 0) {
                $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$tagname','$source','$vsys','$color');");
            }
            if ($thecolor == 16) {
                $thecolor = 1;
            } else {
                $thecolor++;
            }
        }
        if (preg_match("/crypto map /",$names_line)){
            $split=explode(" ",$names_line);
            if ( ($split[4]=="match") AND ($split[5]=="address") ){
                array_push($AccessGroups, trim($split[6]));
                #Add Tag
                $color = "color" . $thecolor;
                $tagname = truncate_tags(trim($split[6]));
                $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name ='$tagname'";
                //echo "$query\n";
                $result = $projectdb->query($query);
                if($result->num_rows == 0) {
                    $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$tagname','$source','$vsys','$color');");
                }
                if ($thecolor == 16) {
                    $thecolor = 1;
                } else {
                    $thecolor++;
                }
            }

        }

    }

    $manualServiceToApp = Array( 'ah' => 'ipsec-ah', 'icmp6' => 'ipv6-icmp', 'esp' => 'ipsec-esp', 'igrp' => 'igp',
        'ipinip' => 'ip-in-ip', 'nos' => 'ipip', 'pcp' => 'ipcomp'  );

    if (empty($AccessGroups)) {
        add_log('error', 'Reading Security Rules', 'No Access-groups found', $source, 'No Security Rules Added. Assign first the ACLs with access-groups.');
    } else {
        # Second Round to read the ACCESS-LISTS
        $comments = "";
        #Get Last lid from Profiles
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
        $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $position = intval($getLID1['max']) + 1;

        $rule_application = array();
        $rule_service = array();
        $rule = array();
        $rule_source = array();
        $rule_destination = array();
        $rule_from = array();
        $rule_to = array();
        $rule_tag = array();
        $oldtag = "";
        $rule_mapping = array();
        $comment = array();
        //$getApplicationdefault = $projectdb->query("SELECT id FROM shared_services WHERE name='application-default' AND source='$source';");
        $getApplicationdefault = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared';");
        if ($getApplicationdefault->num_rows == 1) {
            $getApplicationdefaultData = $getApplicationdefault->fetch_assoc();
            $application_default = $getApplicationdefaultData['id'];
        } else {
            add_default_services($source);
            //$getApplicationdefault = $projectdb->query("SELECT id FROM shared_services WHERE name='application-default' AND source='$source';");
            $getApplicationdefault = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared';");
//            if ($getApplicationdefault->num_rows == 1) {
                $getApplicationdefaultData = $getApplicationdefault->fetch_assoc();
                $application_default = $getApplicationdefaultData['id'];
//            }
        }

        $done_with_globalComments=true;
        foreach ($cisco_config_file as $line => $names_line) {
            $names_line = trim($names_line);
            if (preg_match("/^access-list /i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                if ((in_array($netObj[1], $AccessGroups)) OR ( $netObj[1] == "global")) {
                    #Clean Vars
                    $source_type = "";
                    $src = "";
                    $destination_type = "";
                    $dst = "";
                    $port_type = "";
                    $port = "";
                    $rule_disabled = "0";
                    $negate_source = 0;
                    $negate_destination = 0;
                    $action = "";
                    $isRule = 0;

                    $startRule = 2;
                    $isProtocol = false;
                    $CiscoProtocol = "none";
                    $isServiceObject = 0;
                    $protocol_tcp_udp = 0;

                    $accesslistName = $netObj[1];

                    if (preg_match("/\bline\b/", $names_line)) {
                        $startRule = $startRule + 2;
                    }
                    if (preg_match("/\bextended\b/", $names_line)) {
                        $startRule = $startRule + 1;
                    }

                    if (preg_match("/\bremark\b/i", $names_line, $dd)) {
                        if ($done_with_globalComments==true){
                            $done_with_globalComments=false;
                            $comment=array();
                        }

                        $dirty_comments = preg_split("/ remark /", $names_line);
                        $thisComment = addslashes(rtrim($dirty_comments[1]));
                        $thisComment = str_replace("\n", '', $thisComment); // remove new lines
                        $thisComment = str_replace("\r", '', $thisComment);
                        $comment[]=normalizeComments($thisComment);
                        continue;

                    }
                    else{
                        $done_with_globalComments=true;
                    }

                    if (preg_match("/\bwebtype\b/", $names_line)) {
                        #Dont work with webtype rules
                        continue;
                    }

                    #Check if is Disabled
                    $count = count($netObj);
                    $last = $count - 1;
                    if ($netObj[$last] == "inactive") {
                        $rule_disabled = "1";
                    } else {
                        $rule_disabled = "0";
                    }

                    #Check the protocol
                    $proto = $netObj[$startRule + 1];
                    $isProtocol = false;
                    if (is_numeric($proto)) {
                        $getApp = $projectdb->query("SELECT id,name FROM default_applications WHERE default_protocol='$proto';");
                        if ($getApp->num_rows == 1) {
                            $getAppData = $getApp->fetch_assoc();
                            $application_name = $getAppData['name'];
                            $application_id = $getAppData['id'];
                            add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using the Protocol number [' . $proto . '].', $source, 'App-id [' . $application_name . '] has been added to that Rule', 'rules', $lid, 'security_rules');
                            $rule_application[] = "('$source','$vsys','$lid','default_applications','$application_id')";
                            //$rule_service[] = "('$source','$vsys','$lid','shared_services','$application_default')";
                            $rule_service[] = "('$source','$vsys','$lid','services','$application_default')";
                            $isProtocol = true;
                        } else {
                            add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Unknown Protocol number [' . $proto . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $lid, 'security_rules');
                            $isProtocol = true;
                        }
                    }
                    else {
                        if (($proto == "object") OR ( $proto == "object-group")) {
                            # Do nothing here
                            $isProtocol = false;
                        }
                        elseif (($proto == "ip") OR ( $proto == "tcp") OR ( $proto == "udp")) {
                            #Do Nothing - Continue reading
                            $isProtocol = true;
                        }
                        else {
                            $getApp = $projectdb->query("SELECT id FROM default_applications WHERE name='$proto';");
                            if ($getApp->num_rows == 1) {
                                $getAppData = $getApp->fetch_assoc();
                                $application_id = $getAppData['id'];
                                add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using the Protocol Name [' . $proto . '].', $source, 'App-id [' . $proto . '] has been added to that Rule', 'rules', $lid, 'security_rules');
                                $rule_application[] = "('$source','$vsys','$lid','default_applications','$application_id')";
                                //$rule_service[] = "('$source','$vsys','$lid','shared_services','$application_default')";
                                $rule_service[] = "('$source','$vsys','$lid','services','$application_default')";
                                $isProtocol = true;
                            }
                            else {
                                if (isset($manualServiceToApp[$proto])) {
                                    $getApp = $projectdb->query("SELECT id FROM default_applications WHERE name='".$manualServiceToApp[$proto]."';");
                                    if ($getApp->num_rows == 1) {
                                        $getAppData = $getApp->fetch_assoc();
                                        $application_id = $getAppData['id'];
                                        add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using the Protocol Name [' . $proto . '].', $source, 'App-id [' . $manualServiceToApp[$proto] . '] has been added to that Rule', 'rules', $lid, 'security_rules');
                                        $rule_application[] = "('$source','$vsys','$lid','default_applications','$application_id')";
                                        //$rule_service[] = "('$source','$vsys','$lid','shared_services','$application_default')";
                                        $rule_service[] = "('$source','$vsys','$lid','services','$application_default')";
                                        $isProtocol = true;
                                    }
                                    else
                                        add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Unknown Protocol number [' . $proto . '] which triggered a SQL error, manual fix is required and report to developers welcome', $source, 'Check it manually', 'rules', $lid, 'security_rules');
                                }
                                else {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Unknown Protocol number [' . $proto . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $lid, 'security_rules');
                                    $isProtocol = true;
                                }
                            }
                        }
                    }

                    if ((   ($netObj[$startRule + 1] == "tcp") OR
                            ( $netObj[$startRule + 1] == "udp") OR
                            ( $isProtocol)
                        ) AND
                        (   ($netObj[$startRule] == "permit") OR
                            ( $netObj[$startRule] == "deny")
                        )
                    ) {
                        $isRule = 1;
                        $action = $netObj[$startRule];
                        if ($action == "permit") {
                            $action = "allow";
                        }
                        $ruleProtocol = $netObj[$startRule + 1];
                        if (($netObj[$startRule + 2] == "any") OR ( $netObj[$startRule + 2] == "any4") OR ( $netObj[$startRule + 2] == "any6")) {
                            $next = $startRule + 3;
                        }
                        elseif ($netObj[$startRule + 2] == "object-group") {
                            $SourceGroup = $netObj[$startRule + 3];
                            $getSourceGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$SourceGroup' AND vsys='$vsys';");
                            $next = $startRule + 4;
                            if ($getSourceGroup->num_rows > 0) {
                                $getSourceGroupData = $getSourceGroup->fetch_assoc();
                                $newlid = $getSourceGroupData['id'];
                                $rule_source[] = "('$source','$vsys','$lid','address_groups_id','$newlid')";
                            }
                            else {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Object-group [' . $SourceGroup . '] that is not defined in my Database. Fix it before to finish', $source, 'Check it manually', 'rules', $lid, 'security_rules');
                            }
                        }
                        elseif ($netObj[$startRule + 2] == "host") {
                            $SourceHost = $netObj[$startRule + 3];
                            $next = $startRule + 4;
                            $hostCidr = "32";
                            if (validateIpAddress($SourceHost, "v4")) {
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$SourceHost' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('H-$SourceHost','ip-netmask','H-$SourceHost','0','$source','0','$SourceHost','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            }
                            else {
                                # Is a name
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $SourceHost . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($SourceHost));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('$name_int','ip-netmask','$SourceHost','1','$source','0','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $hostCidr) {
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$ipaddress' AND cidr='$hostCidr' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$SourceHost-$hostCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,$ipversion,vsys, devicegroup) values('$name_int','ip-netmask','$myname','1','$source','1','$ipaddress','$hostCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                        }
                        elseif ($netObj[$startRule + 2] == "object") {
                            $SourceHost = $netObj[$startRule + 3];
                            $next = $startRule + 4;

                            # Is a name
                            $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='object';");
                            if ($getSource->num_rows == 0) {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $SourceHost . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                $name_int = truncate_names(normalizeNames($SourceHost));
                                $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,vtype, devicegroup) values('$name_int','ip-netmask','$SourceHost','1','$source','0','1.1.1.1','$hostCidr','1','$vsys','object','$global_config_filename');");
                                $newlid = $projectdb->insert_id;
                                $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                            } else {
                                $getSourceData = $getSource->fetch_assoc();
                                $newlid = $getSourceData['id'];
                                $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                            }
                        }
                        elseif ($netObj[$startRule + 2] == "interface") {
                            $next = $startRule + 4;
                        }
                        elseif (checkNetmask($netObj[$startRule + 3])) {
                            $next = $startRule + 4;
                            if (validateIpAddress($netObj[$startRule + 2], "v4")) {
                                $src = $netObj[$startRule + 2];
                                $SourceNetmask = $netObj[$startRule + 3];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                #Check if exists an object or create it
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$src' AND cidr='$SourceCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    if ($SourceCidr == 32) {
                                        $NameComplete = "H-$src";
                                    } else {
                                        $NameComplete = "N-$src-$SourceCidr";
                                    }
                                    $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$NameComplete' AND vsys='$vsys' AND vtype='';");
                                    if ($getDup->num_rows == 0) {
                                        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('$NameComplete','ip-netmask','$NameComplete','1','$source','0','$src','$SourceCidr','1','$vsys','$global_config_filename');");
                                        $newlid = $projectdb->insert_id;
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getSourceData = $getSource->fetch_assoc();
                                        $newlid = $getSourceData['id'];
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    }
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            }
                            else {
                                $src = $netObj[$startRule + 2];
                                $SourceNetmask = $netObj[$startRule + 3];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($src));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('$name_int','ip-netmask','$src','1','$source','1','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $SourceCidr) {
                                        $newlid = $getSourceData['id'];
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$src-$SourceCidr' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$src-$SourceCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('$name_int','ip-netmask','$myname','1','$source','0','$ipaddress','$SourceCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                        }
                    }
                    elseif ($netObj[$startRule] == "remark") {
                        #Nothing to do
                    }
                    elseif ($netObj[$startRule + 1] == "object") {
                        #access-list dmz extended permit object udp_8030 object metintsugpar0191_1 object-group F22SGS6001_F22SGS6002
                        #Really? services ??
                        $service = $netObj[$startRule + 2];
                        $queryService = "SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$service' ANd vsys='$vsys';";
                        $getSRV = $projectdb->query($queryService);
                        if ($getSRV->num_rows == 1) {
                            $myData = $getSRV->fetch_assoc();
                            $newlid = $myData['id'];
                            $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                        }
                        else {
                            add_log2('error', 'Reading Security Policies', 'Rule not covered: ' . $names_line, $source, 'Security RuleID [' . $lid . ']', 'rules', $lid, 'security_rules');
                        }

                        $isRule = 1;
                        $action = $netObj[$startRule];
                        if ($action == "permit") {
                            $action = "allow";
                        }
                        $ruleProtocol = $netObj[$startRule + 1];
                        if (($netObj[$startRule + 3] == "any") OR ( $netObj[$startRule + 3] == "any4") OR ( $netObj[$startRule + 3] == "any6")) {
                            $next = $startRule + 4;
                        }
                        elseif ($netObj[$startRule + 3] == "object-group") {
                            $SourceGroup = $netObj[$startRule + 4];
                            $getSourceGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$SourceGroup' AND vsys='$vsys';");
                            $next = $startRule + 5;
                            if ($getSourceGroup->num_rows > 0) {
                                $getSourceGroupData = $getSourceGroup->fetch_assoc();
                                $newlid = $getSourceGroupData['id'];
                                $rule_source[] = "('$source','$vsys','$lid','address_groups_id','$newlid')";
                            } else {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Object-group [' . $SourceGroup . '] that is not defined in my Database. Fix it before to finish', $source, 'Check it manually', 'rules', $lid, 'security_rules');
                            }
                        }
                        elseif ($netObj[$startRule + 3] == "host") {
                            $SourceHost = $netObj[$startRule + 4];
                            $next = $startRule + 5;
                            $hostCidr = "32";
                            if (validateIpAddress($SourceHost, "v4")) {
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$SourceHost' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('H-$SourceHost','ip-netmask','H-$SourceHost','1','$source','0','$SourceHost','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            } else {
                                # Is a name
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $SourceHost . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($SourceHost));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('$name_int','ip-netmask','$SourceHost','1','$source','0','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $hostCidr) {
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$ipaddress' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$SourceHost-$hostCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,$ipversion,vsys,devicegroup) values('$name_int','ip-netmask','$myname','1','$source','1','$ipaddress','$hostCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                        }
                        elseif ($netObj[$startRule + 3] == "object") {
                            $SourceHost = $netObj[$startRule + 4];
                            $next = $startRule + 5;

                            # Is a name
                            $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='object';");
                            if ($getSource->num_rows == 0) {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $SourceHost . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                $name_int = truncate_names(normalizeNames($SourceHost));
                                $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,vtype,devicegroup) values('$name_int','ip-netmask','$SourceHost','1','$source','0','1.1.1.1','$hostCidr','1','$vsys','object','$global_config_filename');");
                                $newlid = $projectdb->insert_id;
                                $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                            } else {
                                $getSourceData = $getSource->fetch_assoc();
                                $newlid = $getSourceData['id'];
                                $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                            }
                        } elseif ($netObj[$startRule + 3] == "interface") {
                            $next = $startRule + 5;
                        } elseif (checkNetmask($netObj[$startRule + 4])) {
                            $next = $startRule + 5;
                            if (validateIpAddress($netObj[$startRule + 3], "v4")) {
                                $src = $netObj[$startRule + 3];
                                $SourceNetmask = $netObj[$startRule + 4];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                #Check if exists an object or create it
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$src' AND cidr='$SourceCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    if ($SourceCidr == 32) {
                                        $NameComplete = "H-$src";
                                    } else {
                                        $NameComplete = "N-$src-$SourceCidr";
                                    }
                                    $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$NameComplete' AND vsys='$vsys' AND vtype='';");
                                    if ($getDup->num_rows == 0) {
                                        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('$NameComplete','ip-netmask','$NameComplete','1','$source','0','$src','$SourceCidr','1','$vsys','$global_config_filename');");
                                        $newlid = $projectdb->insert_id;
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getSourceData = $getSource->fetch_assoc();
                                        $newlid = $getSourceData['id'];
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    }
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            } else {
                                $src = $netObj[$startRule + 3];
                                $SourceNetmask = $netObj[$startRule + 4];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($src));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('$name_int','ip-netmask','$src','1','$source','1','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $SourceCidr) {
                                        $newlid = $getSourceData['id'];
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$src-$SourceCidr' AND vsys='$vsys' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$src-$SourceCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('$name_int','ip-netmask','$myname','1','$source','0','$ipaddress','$SourceCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                        }
                    }
                    elseif ($netObj[$startRule + 1] == "object-group") {
                        $isRule = 1;
                        $action = $netObj[$startRule];
                        if ($action == "permit") {
                            $action = "allow";
                        }
                        #Protocol Group or ServiceObjectGroup
                        $protocol_group = $netObj[$startRule + 2];
                        $getProtocol = $projectdb->query("SELECT member FROM cisco_protocol_groups WHERE source='$source' AND BINARY name='$protocol_group' AND vsys='$vsys';");
                        if ($getProtocol->num_rows > 0) {
                            # Check if its only tcp-udp
                            $istcpudp = $projectdb->query("SELECT member FROM cisco_protocol_groups WHERE source='$source' AND BINARY name='$protocol_group' AND member!='tcp' AND member!='udp';");
                            if ($istcpudp->num_rows == 0) {
                                $protocol_tcp_udp = 1;
                            } else {
                                $protocol_tcp_udp = 0;
                                while ($myProto = $istcpudp->fetch_assoc()) {
                                    $member = $myProto['member'];
                                    if (is_numeric($member)) {
                                        $getApp = $projectdb->query("SELECT id,name FROM default_applications WHERE default_protocol='$member';");
                                        if ($getApp->num_rows == 1) {
                                            $getAppData = $getApp->fetch_assoc();
                                            $application_name = $getAppData['name'];
                                            $application_id = $getAppData['id'];
                                            add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using the Protocol number [' . $member . '].', $source, 'App-id [' . $application_name . '] has been added to that Rule', 'rules', $lid, 'security_rules');
                                            $rule_application[] = "('$source','$vsys','$lid','default_applications','$application_id')";
                                            //$rule_service[] = "('$source','$vsys','$lid','shared_services','$application_default')";
                                            $rule_service[] = "('$source','$vsys','$lid','services','$application_default')";
                                        } else {
                                            add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Unknown Protocol number [' . $member . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $lid, 'security_rules');
                                        }
                                    } else {
                                        $getApp = $projectdb->query("SELECT id FROM default_applications WHERE name='$member';");
                                        if ($getApp->num_rows == 1) {
                                            $getAppData = $getApp->fetch_assoc();
                                            $application_id = $getAppData['id'];
                                            add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using the Protocol Name [' . $member . '].', $source, 'App-id [' . $member . '] has been added to that Rule', 'rules', $lid, 'security_rules');
                                            $rule_application[] = "('$source','$vsys','$lid','default_applications','$application_id')";
                                            //$rule_service[] = "('$source','$vsys','$lid','shared_services','$application_default')";
                                            $rule_service[] = "('$source','$vsys','$lid','services','$application_default')";
                                        } else {
                                            if (isset($manualServiceToApp[$member])) {
                                                $getApp = $projectdb->query("SELECT id FROM default_applications WHERE name='".$manualServiceToApp[$member]."';");
                                                if ($getApp->num_rows == 1) {
                                                    $getAppData = $getApp->fetch_assoc();
                                                    $application_id = $getAppData['id'];
                                                    add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using the Protocol Name [' . $member . '].', $source, 'App-id [' . $manualServiceToApp[$member] . '] has been added to that Rule', 'rules', $lid, 'security_rules');
                                                    $rule_application[] = "('$source','$vsys','$lid','default_applications','$application_id')";
                                                    $rule_service[] = "('$source','$vsys','$lid','shared_services','$application_default')";
                                                }
                                                else
                                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Unknown Protocol number [' . $member . '] which triggered a SQL error, manual fix is required and report to developpers welcome', $source,'Manual fix is required','rules', $lid, 'security_rules');
                                            }
                                            else {
                                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Unknown Protocol number [' . $member . ']. Fix it before to finish', $member, 'Check it manually', 'rules', $lid, 'security_rules');
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            #Will Check if its an Service-Object
                            $getServiceObject = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$protocol_group' AND vsys='$vsys'");
                            if ($getServiceObject->num_rows == 1) {
                                $getServiceObjectData = $getServiceObject->fetch_assoc();
                                $newlid = $getServiceObjectData['id'];
                                $rule_service[] = "('$source','$vsys','$lid','services_groups_id','$newlid')";
                            }
                            /*
                $getServiceObject=$projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND name='$protocol_group' AND vsys='$vsys'");
                if ($getServiceObject->num_rows==0){
                #FIX If found a object-group referencing a service-group add all the members to the srv
                $getSGid=$projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND name='$protocol_group' AND vsys='$vsys'");
                if (mysql_num_rows($getSGid)==1){
                $mySG=mysql_fetch_assoc($getSGid);
                $mylid=$mySG['id'];
                $getM=$projectdb->query("SELECT member_lid,table_name FROM services_groups WHERE source='$source' AND lid='$mylid';");
                while ($mynewData=mysql_fetch_assoc($getM)){
                $M_member_lid=$mynewData['member_lid'];
                $M_table_name=$mynewData['table_name'];
                $getDup=$projectdb->query("SELECT id FROM security_rules_srv WHERE source='$source' AND rule_lid='$lid' AND member_lid='$M_member_lid' AND table_name='$M_table_name';");
                if ($getDup->num_rows==0){
                $projectdb->query("INSERT INTO security_rules_srv (rule_lid,member_lid,table_name,project,vsys) values('$lid','$M_member_lid','$M_table_name','$projectname','vsys1');");
                }
                }
                }
                else {
                #Protocol GROUP doesnt exist in the database But it can be a service group id
                add_log('4','Phase 5: Reading Security Rules','Protocol-Group ['.$protocol_group.'] Is not in the Database. Rule ['.$lid.']',$projectname,'Please review the object-group protocol definition');
                }
                }
                else {
                #Is Service Object ADD Services and at the end add the apps
                $isServiceObject=1;
                $getServices=$projectdb->query("SELECT service_lid FROM cisco_service_objects WHERE source='$source' AND name='$protocol_group' and service_lid!='';");
                if (mysql_num_rows($getServices)>0){
                while ($data=mysql_fetch_assoc($getServices)){
                $service_lid=$data['service_lid'];
                $projectdb->query("INSERT INTO security_rules_srv (rule_lid,member_lid,table_name,project,vsys) values('$lid','$service_lid','services','$projectname','vsys1');");
                }
                }
                }
               */
                        }

                        #Delete 1 element and reorder to mantain the same index
                        unset($netObj[$startRule + 1]);
                        $myTMP = array_values($netObj);
                        $netObj = $myTMP;

                        if (($netObj[$startRule + 2] == "any") OR ( $netObj[$startRule + 2] == "any4") OR ( $netObj[$startRule + 2] == "any6")) {
                            $next = $startRule + 3;
                        } elseif ($netObj[$startRule + 2] == "object-group") {
                            $SourceGroup = $netObj[$startRule + 3];
                            $getSourceGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$SourceGroup' AND vsys='$vsys';");
                            $next = $startRule + 4;
                            if ($getSourceGroup->num_rows > 0) {
                                $getSourceGroupData = $getSourceGroup->fetch_assoc();
                                $newlid = $getSourceGroupData['id'];
                                $rule_source[] = "('$source','$vsys','$lid','address_groups_id','$newlid')";
                            } else {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Object-Group [' . $SourceGroup . '] that is not in my DB.', $source, 'Add manually and Assign to the Rule', 'rules', $lid, 'security_rules');
                            }
                        } elseif ($netObj[$startRule + 2] == "host") {
                            $SourceHost = $netObj[$startRule + 3];
                            $next = $startRule + 4;
                            $hostCidr = "32";
                            if (validateIpAddress($SourceHost, "v4")) {
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$SourceHost' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('H-$SourceHost','ip-netmask','H-$SourceHost','1','$source','0','$SourceHost','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            } else {
                                # Is a name
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $SourceHost . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($SourceHost));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, devicegroup) values('$name_int','ip-netmask','$SourceHost','1','$source','0','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $hostCidr) {
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$ipaddress' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$SourceHost-$hostCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,$ipversion,vsys,devicegroup) values('$name_int','ip-netmask','$myname','1','$source','1','$ipaddress','$hostCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                        } elseif ($netObj[$startRule + 2] == "interface") {
                            $next = $startRule + 4;
                        } elseif (checkNetmask($netObj[$startRule + 3])) {
                            $next = $startRule + 4;
                            if (validateIpAddress($netObj[$startRule + 2], "v4")) {
                                $src = $netObj[$startRule + 2];
                                $SourceNetmask = $netObj[$startRule + 3];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                #Check if exists an object or create it
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$src' AND cidr='$SourceCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    if ($SourceCidr == 32) {
                                        $NameComplete = "H-$src";
                                    } else {
                                        $NameComplete = "N-$src-$SourceCidr";
                                    }
                                    $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$NameComplete' AND vsys='$vsys' AND vtype='';");
                                    if ($getDup->num_rows == 0) {
                                        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('$NameComplete','ip-netmask','$NameComplete','1','$source','0','$src','$SourceCidr','1','$vsys','$global_config_filename');");
                                        $newlid = $projectdb->insert_id;
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getSourceData = $getSource->fetch_assoc();
                                        $newlid = $getSourceData['id'];
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    }
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            } else {
                                $src = $netObj[$startRule + 2];
                                $SourceNetmask = $netObj[$startRule + 3];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($src));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('$name_int','ip-netmask','$src','1','$source','1','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $SourceCidr) {
                                        $newlid = $getSourceData['id'];
                                        $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$src-$SourceCidr' AND vsys='$vsys' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$src-$SourceCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values ('$name_int','ip-netmask','$myname','1','$source','0','$ipaddress','$SourceCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                        } elseif ($netObj[$startRule + 2] == "object") {
                            $SourceHost = $netObj[$startRule + 3];
                            $next = $startRule + 4;
                            $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='object';");
                            if ($getAddress->num_rows == 1) {
                                $getData = $getAddress->fetch_assoc();
                                $newlid = $getData['id'];
                                $rule_source[] = "('$source','$vsys','$lid','address','$newlid')";
                            }
                        }
                    }

                    if ($next != "") {
                        if (($netObj[$next] == "lt") OR ( $netObj[$next] == "gt") OR ( $netObj[$next] == "eq") OR ( $netObj[$next] == "neq") OR ( $netObj[$next] == "range") OR ( $netObj[$next] == "object-group")) {
                            if ($netObj[$next] == "range") {
                                $next = $next + 3;
                            } elseif ($netObj[$next] == "object-group") {
                                $SourceGroup = $netObj[$next + 1];
                                $isSG = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$SourceGroup' AND vsys='$vsys';");
                                if ($isSG->num_rows == 0) {
                                    # Do nothing by now
                                } else {
                                    $next = $next + 2;
                                }
                            } else {
                                $next = $next + 2;
                            }
                        }
                        # Destination
                        $Destination = $netObj[$next];
                        if (($Destination == "any") OR ( $Destination == "any4") OR ( $Destination == "any6")) {
                            $next_service = $next + 1;
                        }
                        elseif ($Destination == "object-group") {
                            $SourceGroup = $netObj[$next + 1];
                            $getSourceGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$SourceGroup' AND vsys='$vsys';");
                            if ($getSourceGroup->num_rows > 0) {
                                $getSourceGroupData = $getSourceGroup->fetch_assoc();
                                $newlid = $getSourceGroupData['id'];
                                $rule_destination[] = "('$source','$vsys','$lid','address_groups_id','$newlid')";
                            } else {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Object-Group [' . $SourceGroup . '] that is not in my DB.', $source, 'Add manually and Assign to the Rule', 'rules', $lid, 'security_rules');
                            }
                            $next_service = $next + 2;
                        }
                        elseif ($Destination == "host") {
                            $SourceHost = $netObj[$next + 1];
                            $hostCidr = "32";
                            if (validateIpAddress($SourceHost, "v4")) {
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$SourceHost' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('H-$SourceHost','ip-netmask','H-$SourceHost','1','$source','0','$SourceHost','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            } else {
                                # Is a name
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $SourceHost . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($SourceHost));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('$name_int','ip-netmask','$SourceHost','1','$source','0','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $hostCidr) {
                                        $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$ipaddress' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$SourceHost-$hostCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,$ipversion,vsys,devicegroup) values('$name_int','ip-netmask','$myname','1','$source','1','$ipaddress','$hostCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                            $next_service = $next + 2;
                        }
                        elseif ($Destination == "interface") {
                            $next_service = $next + 2;
                        }
                        elseif ($Destination == "object") {
                            $SourceHost = $netObj[$next + 1];
                            $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$SourceHost' AND vsys='$vsys' AND vtype='object';");
                            if ($getAddress->num_rows == 1) {
                                $getData = $getAddress->fetch_assoc();
                                $newlid = $getData['id'];
                                $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                            }
                            $next_service = $next + 2;
                        }
                        elseif (checkNetmask($netObj[$next + 1])) {
                            if (validateIpAddress($netObj[$next], "v4")) {
                                $src = $netObj[$next];
                                $SourceNetmask = $netObj[$next + 1];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                #Check if exists an object or create it
                                $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$src' AND cidr='$SourceCidr' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    if ($SourceCidr == 32) {
                                        $NameComplete = "H-$src";
                                    } else {
                                        $NameComplete = "N-$src-$SourceCidr";
                                    }
                                    $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$NameComplete' AND vsys='$vsys' AND vtype='';");
                                    if ($getDup->num_rows == 0) {
                                        $name_int = truncate_names(normalizeNames($NameComplete));
                                        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values('$name_int','ip-netmask','$NameComplete','1','$source','0','$src','$SourceCidr','1','$vsys','$global_config_filename');");
                                        $newlid = $projectdb->insert_id;
                                        $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getSourceData = $getSource->fetch_assoc();
                                        $newlid = $getSourceData['id'];
                                        $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                    }
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $newlid = $getSourceData['id'];
                                    $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                }
                            } else {
                                $src = $netObj[$next];
                                $SourceNetmask = $netObj[$next + 1];
                                $SourceCidr = mask2cidrv4($SourceNetmask);
                                $getSource = $projectdb->query("SELECT id,cidr,ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND vtype='';");
                                if ($getSource->num_rows == 0) {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                                    $name_int = truncate_names(normalizeNames($src));
                                    $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values ('$name_int','ip-netmask','$src','1','$source','1','1.1.1.1','$hostCidr','1','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                } else {
                                    $getSourceData = $getSource->fetch_assoc();
                                    $cidr = $getSourceData['cidr'];
                                    $ipaddress = $getSourceData['ipaddress'];
                                    $ipversion = ip_version($ipaddress);
                                    if ($cidr == $SourceCidr) {
                                        $newlid = $getSourceData['id'];
                                        $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                    } else {
                                        $getCheck = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$src-$SourceCidr' AND vsys='$vsys' AND vtype='';");
                                        if ($getCheck->num_rows == 0) {
                                            $myname = "$src-$SourceCidr";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,ipaddress,cidr,v4,vsys,devicegroup) values ('ip-netmask','$myname','$name_int','1','$source','0','$ipaddress','$SourceCidr','1','$vsys','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                        } else {
                                            $data = $getCheck->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_destination[] = "('$source','$vsys','$lid','address','$newlid')";
                                        }
                                    }
                                }
                            }
                            $next_service = $next + 2;
                        }
                    }

                    #Add Services
                    if (isset($netObj[$next_service])) {
                        if ($netObj[$next_service] == "log") {

                        }
                        elseif ($netObj[$next_service] == "eq") {
                            $ServiceName = $netObj[$next_service + 1];
                            if (is_numeric($ServiceName)) {
                                #port number
                                if ($protocol_tcp_udp == 1) {
                                    $ruleProtocol = "tcp";
                                    $getSRV = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$ServiceName' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                    if ($getSRV->num_rows > 0) {
                                        $data = $getSRV->fetch_assoc();
                                        $newlid = $data['id'];
                                        $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                    } else {
                                        $myname = "$ruleProtocol-$ServiceName";
                                        $name_int = truncate_names(normalizeNames($myname));
                                        $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,dport,protocol,devicegroup) values('$name_int','$vsys','$ruleProtocol-$ServiceName','1','$source','1','$ServiceName','$ruleProtocol','$global_config_filename');");
                                        $newlid = $projectdb->insert_id;
                                        $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                    }
                                    $ruleProtocol = "udp";
                                    $getSRV = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$ServiceName' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                    if ($getSRV->num_rows > 0) {
                                        $data = $getSRV->fetch_assoc();
                                        $newlid = $data['id'];
                                        $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                    } else {
                                        $myname = "$ruleProtocol-$ServiceName";
                                        $name_int = truncate_names(normalizeNames($myname));
                                        $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,dport,protocol,devicegroup) values('$name_int','$vsys','$ruleProtocol-$ServiceName','1','$source','1','$ServiceName','$ruleProtocol','$global_config_filename');");
                                        $newlid = $projectdb->insert_id;
                                        $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                    }
                                } else {
                                    $getSRV = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$ServiceName' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                    if ($getSRV->num_rows > 0) {
                                        $data = $getSRV->fetch_assoc();
                                        $newlid = $data['id'];
                                        $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                    } else {
                                        $myname = "$ruleProtocol-$ServiceName";
                                        $name_int = truncate_names(normalizeNames($myname));
                                        $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,dport,protocol,devicegroup) values('$name_int','$vsys','$ruleProtocol-$ServiceName','1','$source','1','$ServiceName','$ruleProtocol','$global_config_filename');");
                                        $newlid = $projectdb->insert_id;
                                        $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                    }
                                }
                            } else {
                                #Port Name
                                if ($protocol_tcp_udp == 1) {
                                    $ruleProtocol = "tcp";
                                    $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$ServiceName' LIMIT 1;");
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_final = $cisconame['dport'];
                                    if ($port_final == "") {
                                        add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service Name [' . $ServiceName . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:65000].', 'rules', $lid, 'security_rules');
                                        $port_final = "65000";
                                    }
                                    else {
                                        $getSRV = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$port_final' AND protocol='$ruleProtocol';");
                                        if ($getSRV->num_rows > 0) {
                                            $data = $getSRV->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                        } else {
                                            #create it
                                            $myname = "$ruleProtocol-$port_final";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                        }
                                    }
                                    $ruleProtocol = "udp";
                                    $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$ServiceName' LIMIT 1;");
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_final = $cisconame['dport'];
                                    if ($port_final == "") {
                                        add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service Name [' . $ServiceName . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:65000].', 'rules', $lid, 'security_rules');
                                        $port_final = "65000";
                                    } else {
                                        $getSRV = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$port_final' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                        if ($getSRV->num_rows > 0) {
                                            $data = $getSRV->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                        } else {
                                            $myname = "$ruleProtocol-$port_final";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                        }
                                    }
                                } else {
                                    $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$ServiceName' LIMIT 1;");
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_final = $cisconame['dport'];
                                    if ($port_final == "") {
                                        add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service Name [' . $ServiceName . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:6500].', 'rules', $lid, 'security_rules');
                                        $port_final = "6500";
                                    } else {
                                        $getSRV = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$port_final' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                        if ($getSRV->num_rows > 0) {
                                            $data = $getSRV->fetch_assoc();
                                            $newlid = $data['id'];
                                            $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                        } else {
                                            $myname = "$ruleProtocol-$port_final";
                                            $name_int = truncate_names(normalizeNames($myname));
                                            $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                            $newlid = $projectdb->insert_id;
                                            $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                        }
                                    }
                                }
                            }
                        }
                        elseif ($netObj[$next_service] == "lt") {
                            $ServiceName = $netObj[$next_service + 1];
                            if (is_numeric($ServiceName)) {
                                $port_final = $ServiceName;
                                $srv_port_before = intval($port_final);
                                $port_final = "1-$srv_port_before";
                            } else {
                                $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$ServiceName' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                if ($port_final == "") {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service Name [' . $ServiceName . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:6500].', 'rules', $lid, 'security_rules');
                                    $port_final = "6500";
                                }
                                $srv_port_before = intval($port_final);
                                $port_final = "1-$srv_port_before";
                            }
                            if ($protocol_tcp_udp == 1) {
                                $ruleProtocol = "tcp";
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$port_final' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "LT-$ruleProtocol-$port_final";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','LT-$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                                $ruleProtocol = "udp";
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$port_final' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "LT-$ruleProtocol-$port_final";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$source','LT-$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                            } else {
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND protocol='$ruleProtocol' and dport='$port_final' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "LT-$ruleProtocol-$port_final";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','LT-$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                            }
                        }
                        elseif ($netObj[$next_service] == "gt") {
                            $ServiceName = $netObj[$next_service + 1];
                            if (is_numeric($ServiceName)) {
                                $port_final = $ServiceName;
                                $srv_port_before = intval($port_final);
                                $port_final = "$srv_port_before-65535";
                            }
                            else {
                                $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$ServiceName' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                if ($port_final == "") {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service port-name [' . $ServiceName . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:1025].', 'rules', $lid, 'security_rules');
                                    $port_final = "1025";
                                }
                                $srv_port_before = intval($port_final);
                                $port_final = "$srv_port_before-65535";
                            }
                            if ($protocol_tcp_udp == 1) {
                                $ruleProtocol = "tcp";
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$port_final' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "GT-$ruleProtocol-$port_final";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','GT-$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                                $ruleProtocol = "udp";
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND dport='$port_final' AND protocol='$ruleProtocol' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "GT-$ruleProtocol-$port_final";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','GT-$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                            } else {
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND protocol='$ruleProtocol' and dport='$port_final' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "GT-$ruleProtocol-$port_final";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','GT-$ruleProtocol-$port_final','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                            }
                        }
                        elseif ($netObj[$next_service] == "neq") {
                            $ServiceName = $netObj[$next_service + 1];
                            if (is_numeric($ServiceName)) {
                                $port_final = $ServiceName;
                                $srv_port_before = intval($port_final) - 1;
                                $srv_port_after = intval($port_final) + 1;
                                $port_final = "1-$srv_port_before,$srv_port_after-65535";
                                $port_final_name = "1-$srv_port_before_$srv_port_after-65535";
                            } else {
                                $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$ServiceName' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                if ($port_final == "") {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service Name [' . $ServiceName . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:6500].', 'rules', $lid, 'security_rules');
                                    $port_final = "6500";
                                }
                                $srv_port_before = intval($port_final) - 1;
                                $srv_port_after = intval($port_final) + 1;
                                $port_final = "1-$srv_port_before,$srv_port_after-65535";
                                $port_final_name = "1-$srv_port_before_$srv_port_after-65535";
                            }

                            if ($protocol_tcp_udp == 1) {
                                $ruleProtocol = "tcp";
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND protocol='$ruleProtocol' and dport='$port_final' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "NO-$ruleProtocol-$port_final_name";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','NO-$ruleProtocol-$port_final_name','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                                $ruleProtocol = "udp";
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND protocol='$ruleProtocol' and dport='$port_final' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "NO-$ruleProtocol-$port_final_name";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','NO-$ruleProtocol-$port_final_name','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                            } else {
                                $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND protocol='$ruleProtocol' and dport='$port_final' AND vsys='$vsys';");
                                if ($getPort->num_rows == 0) {
                                    $myname = "NO-$ruleProtocol-$port_final_name";
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,vsys,name_ext,checkit,source,used,protocol,dport,devicegroup) values('$name_int','$vsys','NO-$ruleProtocol-$port_final_name','1','$source','1','$ruleProtocol','$port_final','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                } else {
                                    $data = $getPort->fetch_assoc();
                                    $newlid = $data['id'];
                                    $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                }
                            }
                        }
                        elseif ($netObj[$next_service] == "range") {
                            $port_first = $netObj[$next_service + 1];
                            $port_last = rtrim($netObj[$next_service + 2]);

                            if (is_numeric($port_first)) {
                                $port_first_port = $port_first;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$port_first' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_first_port = $cisconame['dport'];

                                if ($port_first_port == "") {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Range port-name [' . $port_first . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:6500].', 'rules', $lid, 'security_rules');
                                    $port_first_port = "6500";
                                }
                            }
                            if (is_numeric($port_last)) {
                                $port_last_port = $port_last;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT id,dport FROM services WHERE source='$source' AND BINARY name_ext='$port_last' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_last_port = $cisconame['dport'];

                                if ($port_last_port == "") {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Range port-name [' . $port_first . '] and Protocol [' . $ruleProtocol . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:6500].', 'rules', $lid, 'security_rules');
                                    $port_last_port = "6500";
                                }
                            }

                            # Check first if they are EQUAL
                            if ($port_first_port == $port_last_port) {
                                $isRange = "";
                                $LastPort = "";
                                $vtype = "";
                                add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . ']. Moving Service-Range to Service [' . $names_line . '] ports are the same ', $source, 'No Action Required', 'rules', $lid, 'security_rules');
                            } else {
                                $isRange = "-range";
                                $LastPort = "-$port_last_port";
                                $vtype = "range";
                            }

                            if ($protocol_tcp_udp == 1) {
                                $myname = "tcp" . $isRange . "-$port_first_port" . $LastPort;
                                $name_int = truncate_names(normalizeNames($myname));
                                $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='tcp" . $isRange . "-$port_first_port" . $LastPort . "' ANd vsys='$vsys';");
                                if ($search->num_rows == 0) {
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys,devicegroup) values ('$name_int','tcp" . $isRange . "-$port_first_port" . $LastPort . "','tcp','$port_first_port" . $LastPort . "','1','$source','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                } else {
                                    $data = $search->fetch_assoc();
                                    $newlid = $data['id'];
                                }
                                $projectdb->query("INSERT INTO security_rules_srv (rule_lid,member_lid,table_name,source,vsys) VALUES ('$lid','$newlid','services','$source','vsys1');");
                                $newlid = $projectdb->insert_id;
                                $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                                $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='udp" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                                if ($search->num_rows == 0) {
                                    $myname = "udp" . $isRange . "-$port_first_port" . $LastPort;
                                    $name_int = truncate_names(normalizeNames($myname));
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys,devicegroup) values ('$name_int','udp" . $isRange . "-$port_first_port" . $LastPort . "','udp','$port_first_port" . $LastPort . "','1','$source','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                } else {
                                    $data = $search->fetch_assoc();
                                    $newlid = $data['id'];
                                }
                                $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                            } else {
                                $myname = "$ruleProtocol" . $isRange . "-$port_first_port" . $LastPort;
                                $name_int = truncate_names(normalizeNames($myname));
                                $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='$ruleProtocol" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                                if ($search->num_rows == 0) {
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys,devicegroup) values ('$name_int','$ruleProtocol" . $isRange . "-$port_first_port" . $LastPort . "','$ruleProtocol','$port_first_port" . $LastPort . "','1','$source','$vsys','$global_config_filename');");
                                    $newlid = $projectdb->insert_id;
                                } else {
                                    $data = $search->fetch_assoc();
                                    $newlid = $data['id'];
                                }
                                $rule_service[] = "('$source','$vsys','$lid','services','$newlid')";
                            }
                        }
                        elseif ($netObj[$next_service] == "object-group") {
                            $ServiceGroupName = $netObj[$next_service + 1];
                            $getSG = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$ServiceGroupName' AND vsys='$vsys' LIMIT 1;");
                            if ($getSG->num_rows == 1) {
                                $data = $getSG->fetch_assoc();
                                $newlid = $data['id'];
                                $rule_service[] = "('$source','$vsys','$lid','services_groups_id','$newlid')";
                            } else {
                                #Check if its a icmp_group
                                $getICMPGroup = $projectdb->query("SELECT id FROM cisco_icmp_groups WHERE source='$source' AND BINARY name='$ServiceGroupName' AND vsys='$vsys';");
                                if ($getICMPGroup->num_rows > 0) {
                                    $getICMP = $projectdb->query("SELECT id FROM default_applications WHERE name='icmp';");
                                    $getICMPData = $getICMP->fetch_assoc();
                                    $getICMPid = $getICMPData['id'];
                                    $rule_application[] = "('$source','$vsys','$lid','default_applications','$getICMPid')";
                                    //$rule_service[] = "('$source','$vsys','$lid','shared_services','$application_default')";
                                    $rule_service[] = "('$source','$vsys','$lid','services','$application_default')";
                                    add_log2('warning', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a ICMP-Protocol Group [' . $ServiceGroupName . '].', $source, 'Replacing by ICMP app-id', 'rules', $lid, 'security_rules');
                                } else {
                                    add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service Group [' . $ServiceGroupName . '] but is not defined in my DB', $source, 'Create it and add it to the Rule', 'rules', $lid, 'security_rules');
                                }
                            }
                        }
                    }


                    if ($isRule == 1) {
                        $next = "";
                        $next_service = "";
                        #Create the RULE
                        $accesslistNamePan = truncate_tags($accesslistName);
                        if ($accesslistNamePan != $oldtag) {
                            $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$accesslistNamePan' AND source='$source' AND vsys='$vsys';");
                            if ($getTag->num_rows == 1) {
                                $getTagData = $getTag->fetch_assoc();
                                $tag_id = $getTagData['id'];
                                $rule_tag[] = "('$source','$vsys','$lid','tag','$tag_id')";
                                $oldtag = $accesslistNamePan;
                            }
                        }
                        else {
                            $rule_tag[] = "('$source','$vsys','$lid','tag','$tag_id')";
                        }

                        $rule_name = "Rule $x";
                        $comments=implode(" ",$comment);
                        $rule[] = "('$lid','$position','$rule_name','$comments','$action','$rule_disabled','$vsys','$source','0','$accesslistName')";
                        $rule_mapping[] = "('$names_line','$rule_name','$lid')";
                        //$comment = array(); $comments="";

                        $lid++;
                        $position++;
                        $x++;
                    }
                }
            }
        }

        #Save the Data into the DB
        if (count($rule) > 0) {
            $projectdb->query("INSERT INTO security_rules (id,position,name,description,action,disabled,vsys,source,checkit,devicegroup) VALUES " . implode(",", $rule) . ";");
            unset($rule);

            if (count($rule_application) > 0) {
                $unique = array_unique($rule_application);
                $projectdb->query("INSERT INTO security_rules_app (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $unique) . ";");
                unset($rule_application);
                unset($unique);
            }
            if (count($rule_tag) > 0) {
                $unique = array_unique($rule_tag);
                $projectdb->query("INSERT INTO security_rules_tag (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $unique) . ";");
                unset($rule_tag);
                unset($unique);
            }
            if (count($rule_from) > 0) {
                $unique = array_unique($rule_from);
                $projectdb->query("INSERT INTO security_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $unique) . ";");
                unset($rule_from);
                unset($unique);
            }
            if (count($rule_to) > 0) {
                $unique = array_unique($rule_to);
                $projectdb->query("INSERT INTO security_rules_to (source,vsys,rule_lid,name) VALUES " . implode(",", $unique) . ";");
                unset($rule_to);
                unset($unique);
            }
            if (count($rule_source) > 0) {
                $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $rule_source) . ";");
                unset($rule_source);
            }
            if (count($rule_destination) > 0) {
                $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $rule_destination) . ";");
                unset($rule_destination);
            }
            if (count($rule_service) > 0) {
                $unique = array_unique($rule_service);
                $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $unique) . ";");
                unset($rule_service);
                unset($unique);
            }
            if (count($rule_mapping) > 0) {
                $projectdb->query("INSERT INTO cisco_policy_mapping (line,name,rule_lid) VALUES " . implode(",", $rule_mapping) . ";");
                unset($rule_mapping);
            }
        }
    }
}

function get_objectgroup_service($cisco_config_file, $source, $vsys) {
    global $projectdb;
    $isServiceGroup = 0;
    $addMember = array();
    $addMemberID = array();

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if (preg_match("/^object-group service/i", $names_line)) {
            $isServiceGroup = 1;
            $names = explode(" ", $names_line);
            $HostGroupName = rtrim($names[2]);
            $HostGroupNamePan = truncate_names(normalizeNames($HostGroupName));
            if (isset($names[3])) {
                $Protocol = rtrim($names[3]);
            } else {
                $Protocol = "";
            }
            $getDup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$HostGroupName' AND vsys='$vsys'");
            if ($getDup->num_rows == 0) {
                $projectdb->query("INSERT INTO services_groups_id (name,name_ext,source,vsys) values ('$HostGroupNamePan','$HostGroupName','$source','$vsys');");
                $lidgroup = $projectdb->insert_id;
            }
            else{
                $getDupData=$getDup->fetch_assoc();
                $lidgroup = $getDupData['id'];
            }

            continue;
        }

        if (( !preg_match("/port-object /",    $names_line)) AND
            ( !preg_match("/description /",    $names_line)) AND
            ( !preg_match("/group-object /",   $names_line)) AND
            ( !preg_match("/service-object /", $names_line))) {
            $isServiceGroup = 0;
        }

        if ($isServiceGroup == 1) {
            if (preg_match("/port-object /", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $operator = $netObj[1];
                if ($operator == "eq") {
                    $port = rtrim($netObj[2]);
                    if (is_numeric($port)) {
                        $port_final = $port;
                    } else {
                        # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                        $searchname = $projectdb->query("SELECT dport FROM services WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$port' LIMIT 1;");
                        $cisconame = $searchname->fetch_assoc();
                        $port_final = $cisconame['dport'];

                        if ($port_final == "") {
                            add_log('error', 'Reading Services Objects and Groups', 'Unknown Service port mapping for: ' . $port . ' in ServiceGroup [' . $HostGroupName . '] with Protocol [' . $Protocol . ']', $source, 'NOT Adding to the DB!!');
                            #$portpan=truncate_names(normalizeNames($port));
                            # Im not sure if is useful
                            #$projectdb->query("INSERT INTO services (name,type,name_ext,checkit,project,used) values('$portpan','$newlid','','$port','1','$projectname','0');");
                            #$projectdb->query("INSERT INTO services_groups (lid,member,project) values ('$lidgroup','$port','$projectname');");
                            $port_final = "mt-error";
                        }
                    }

                    if ($port_final == "mt-error") {

                    }
                    else {
                        if ($Protocol == "tcp-udp") {
                            # TCP AND UDP
                            $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='tcp-$port_final' AND vsys='$vsys';");
                            if ($search->num_rows == 0) {
                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('tcp-$port_final','tcp-$port_final','tcp','$port_final','0','$source','$vsys');");
                                $serviceID = $projectdb->insert_id;
                            }
                            else{
                                $data = $search->fetch_assoc();
                                $serviceID = $data['id'];
                            }
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                            $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='udp-$port_final' AND vsys='$vsys';");
                            if ($search->num_rows == 0) {
                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('udp-$port_final','udp-$port_final','udp','$port_final','0','$source','$vsys');");
                                $serviceID = $projectdb->insert_id;
                            }
                            else{
                                $data = $search->fetch_assoc();
                                $serviceID = $data['id'];
                            }
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                        else {
                            # TCP OR UDP
                            $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$Protocol-$port_final' AND vsys='$vsys';");
                            if ($search->num_rows == 0) {
                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                $serviceID = $projectdb->insert_id;
                            }
                            else{
                                $data = $search->fetch_assoc();
                                $serviceID = $data['id'];
                            }
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                    }
                }
                elseif ($operator == "range") {
                    $port_first = $netObj[2];
                    $port_last = rtrim($netObj[3]);

                    if (is_numeric($port_first)) {
                        $port_first_port = $port_first;
                    } else {
                        # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                        $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port_first' LIMIT 1;");
                        $cisconame = $searchname->fetch_assoc();
                        $port_first_port = $cisconame['dport'];

                        if ($port_first_port == "") {
                            add_log('error', 'Reading Services Objects and Groups', 'Unknown Service Range port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                            $port_first_port = "6500";
                        }
                    }
                    if (is_numeric($port_last)) {
                        $port_last_port = $port_last;
                    } else {
                        # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                        $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port_last' LIMIT 1;");
                        $cisconame = $searchname->fetch_assoc();
                        $port_last_port = $cisconame['dport'];

                        if ($port_last_port == "") {
                            add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range port-name mapping for: ' . $port_last, $source, 'Using 6500 port. Change it from the GUI');
                            $port_last_port = "6500";
                        }
                    }

                    # Check first if they are EQUAL
                    if ($port_first_port == $port_last_port) {
                        $isRange = "";
                        $LastPort = "";
                        $vtype = "";
                        add_log('warning', 'Reading Services Objects and Groups', 'Moving Service-Range to Service [' . $names_line . '] ports are the same', $source, 'No Action Required');
                    } else {
                        $isRange = "-range";
                        $LastPort = "-$port_last_port";
                        $vtype = "range";
                    }

                    if ($Protocol == "tcp-udp") {
                        $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='tcp" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                        if ($search->num_rows == 0) {
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('tcp" . $isRange . "-$port_first_port" . $LastPort . "','tcp" . $isRange . "-$port_first_port" . $LastPort . "','tcp','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                            $serviceID = $projectdb->insert_id;
                        }
                        else{
                            $data = $search->fetch_assoc();
                            $serviceID = $data['id'];
                        }
                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";

                        $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='udp" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                        if ($search->num_rows == 0) {
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('udp" . $isRange . "-$port_first_port" . $LastPort . "','udp" . $isRange . "-$port_first_port" . $LastPort . "','udp','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                            $serviceID = $projectdb->insert_id;
                        }
                        else{
                            $data = $search->fetch_assoc();
                            $serviceID = $data['id'];
                        }
                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                    }
                    else {
                        $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='$Protocol" . $isRange . "-$port_first_port" . $LastPort . "' ANd vsys='$vsys';");
                        if ($search->num_rows == 0) {
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                            $serviceID = $projectdb->insert_id;
                        }
                        else{
                            $data = $search->fetch_assoc();
                            $serviceID = $data['id'];
                        }
                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                    }
                }
            }
            elseif (preg_match("/group-object /i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $obj2 = rtrim($netObj[1]);
                $addMember[] = "('$lidgroup','$obj2','$source','$vsys')";
                /* $getServiceObject=$projectdb->query("SELECT application,service_lid,service_table_name FROM cisco_service_objects WHERE source='$source' AND name='$obj2';");
          if ($getServiceObject->num_rows==0){
          $addMember[]="('$lidgroup','$obj2','$source','$vsys')";
          }
          else {
          #Is Service Object Add the content of the group in this service object
          while ($data=mysql_fetch_assoc($getServiceObject)){
          $app=$data['application'];
          $service_lid=$data['service_lid'];
          $service_table_name=$data['service_table_name'];
          //$getDup=$projectdb->query("SELECT * FROM cisco_service_objects WHERE source='$source' AND name='$HostGroupName' AND application='$app' AND service_lid='$service_lid' AND service_table_name='$service_table_name';");
          //if ($getDup->num_rows==0){
          $projectdb->query("INSERT INTO cisco_service_objects (name,project,service_lid,service_table_name,application) VALUES ('$HostGroupName','$projectname','$service_lid','$service_table_name','$app')");
          //}
          }

          }
         */
            }
            elseif (preg_match("/service-object /i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $Protocol = $netObj[1];
                if (($Protocol == "tcp") or ( $Protocol == "udp")){
                    if(!isset($netObj[2])){
                        $getDup = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND dport='0-65535' AND protocol='$Protocol' AND vsys='$vsys' LIMIT 1;");
                        if ($getDup->num_rows == 0) {
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-All','$Protocol-All','$Protocol','0-65535','0','$source','$vsys');");
                            $serviceID = $projectdb->insert_id;
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                        else {
                            $data = $getDup->fetch_assoc();
                            $existingname = $data['name'];
                            $serviceID = $data['id'];
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                    }
                    else {
                        $port = $netObj[2];
                        $next = 3;

                        # New addition to cover
                        #

                        if ($port == "eq") {
                            $port = $netObj[$next]; // 3
                            if (is_numeric($port)) {
                                $port_final = $port;
                                $getService = $projectdb->query("SELECT name,id  FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                if ($getService->num_rows == 0) {
                                    # Create it
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                } else {
                                    $data = $getService->fetch_assoc();
                                    $existingname = $data['name'];
                                    $serviceID = $data['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            } else {
                                $searchname = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND protocol='$Protocol' AND vsys='$vsys';");
                                if ($searchname->num_rows == 0) {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_final = "6500";
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                                else{
                                    $data = $searchname->fetch_assoc();
                                    $serviceID = $data['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            }
                        }
                        elseif ($port == "gt") {
                            $port = $netObj[$next];
                            if (is_numeric($port)) {
                                $port = $port + 1;
                                $port_final = $port . "-65535";
                                $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                if ($getService->num_rows == 0) {
                                    # Create it
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                                else {
                                    $data = $getService->fetch_assoc();
                                    $existingname = $data['name'];
                                    $serviceID = $data['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            } else {
                                $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                if ($searchname->num_rows == 0) {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for GT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_final = "6500";
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                                else {
                                    $searchnameData = $searchname->fetch_assoc();
                                    $temp_dport = $searchnameData['dport'] + 1;
                                    $temp_protocol = $searchnameData['protocol'];
                                    $port_final = $temp_dport . "-65535";
                                    $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$port_final' AND protocol='$temp_protocol' LIMIT 1;");
                                    if ($check->num_rows == 1) {
                                        $checkData = $check->fetch_assoc();
                                        $tmp_name = $checkData['name_ext'];
                                        $serviceID = $checkData['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $tmp_name = $temp_protocol . "-" . $port_final;
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$tmp_name','$tmp_name','$temp_protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    // Todo: hay que leer el proto i el dport sumarle uno y poner 65535 y crearlo y añadir como member

//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                }
                            }
                        }
                        elseif ($port == "lt") {
                            $port = $netObj[$next];
                            if (is_numeric($port)) {
                                $port = $port - 1;
                                $port_final = "0-" . $port;
                                $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                if ($getService->num_rows == 0) {
                                    # Create it
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                                else {
                                    $data = $getService->fetch_assoc();
                                    $existingname = $data['name'];
                                    $serviceID = $data['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            }
                            else {
                                $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                if ($searchname->num_rows == 0) {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_final = "6500";
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                                else {
                                    $searchnameData = $searchname->fetch_assoc();
                                    $temp_dport = $searchnameData['dport'] - 1;
                                    $temp_protocol = $searchnameData['protocol'];
                                    $port_final = "0-" . $temp_dport;
                                    $check = $projectdb->query("SELECT name_ext,id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$port_final' AND protocol='$temp_protocol' LIMIT 1;");
                                    if ($check->num_rows == 1) {
                                        $checkData = $check->fetch_assoc();
                                        $tmp_name = $checkData['name_ext'];
                                        $serviceID = $checkData['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $tmp_name = $temp_protocol . "-" . $port_final;
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$tmp_name','$tmp_name','$temp_protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                }
                            }

                        }
                        elseif ($port == "range") {
                            $port_first = $netObj[$next]; //3
                            $port_last = rtrim($netObj[$next + 1]); //4

                            if (is_numeric($port_first)) {
                                $port_first_port = $port_first;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_first' AND vsys='$vsys';");
                                $cisconame = $searchname->fetch_assoc();
                                $port_first_port = $cisconame['dport'];

                                if ($port_first_port == "") {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_first_port = "6500";
                                }
                            }
                            if (is_numeric($port_last)) {
                                $port_last_port = $port_last;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_last' AND vsys='$vsys';");
                                $cisconame = $searchname->fetch_assoc();
                                $port_last_port = $cisconame['dport'];

                                if ($port_last_port == "") {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range  [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_last_port = "6500";
                                }
                            }

                            # Check first if they are EQUAL
                            if ($port_first_port == $port_last_port) {
                                $isRange = "";
                                $LastPort = "";
                                $vtype = "";
                                add_log('warning', 'Reading Services Objects and Groups', 'Moving Service-Range to Service [' . $names_line . '] ports are the same', $source, 'No Action Required');
                            } else {
                                $isRange = "-range";
                                $LastPort = "-$port_last_port";
                                $vtype = "range";
                            }

                            $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND BINARY name_ext='$Protocol" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                            if ($getService->num_rows == 0) {
                                # Create it
                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                                $serviceID = $projectdb->insert_id;
                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                            }
                            else {
                                #Assign to the service-object in service get table and lid
                                $getServiceData = $getService->fetch_assoc();
                                $service_name = $getServiceData['name'];
                                $serviceID = $getServiceData['id'];
                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                            }
                        }


                        #

                        if ($port == "source"){
                          $next = 4;
                          $port = $netObj[3];

                            if (!isset($port)) {
                                $getDup = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND sport='0-65535' AND dport='0-65535' AND protocol='$Protocol' AND vsys='$vsys' LIMIT 1;");
                                if ($getDup->num_rows == 0) {
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$Protocol-All','$Protocol-All','$Protocol','0-65535','0-65535','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                                else {
                                    $data = $getDup->fetch_assoc();
                                    $existingname = $data['name'];
                                    $serviceID = $data['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            }

                            if ($port == "eq") {
                                $port = $netObj[$next]; // 3
                                if (is_numeric($port)) {
                                    $port_final = $port;
                                    $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='0-65535' AND vsys='$vsys';");
                                    if ($getService->num_rows == 0) {
                                        # Create it
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport, checkit,source,vsys) values ('$Protocol-$port_final-source','$Protocol-$port_final-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $data = $getService->fetch_assoc();
                                        $existingname = $data['name'];
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                }
                                else {
                                    $searchname = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                    if ($searchname->num_rows == 0) {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_final = "6500";
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport,checkit,source,vsys) values ('$port-source','$port-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $data = $searchname->fetch_assoc();
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                }
                            }
                            elseif ($port == "gt") {
                                $port = $netObj[$next];
                                if (is_numeric($port)) {
                                    $port = $port + 1;
                                    $port_final = $port . "-65535";
                                    $getService = $projectdb->query("SELECT name,id FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='0-65535' AND vsys='$vsys';");
                                    if ($getService->num_rows == 0) {
                                        # Create it
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$Protocol-$port_final-source','$Protocol-$port_final-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $data = $getService->fetch_assoc();
                                        $existingname = $data['name'];
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                }
                                else {
                                    $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                    if ($searchname->num_rows == 0) {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for GT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_final = "6500";
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$port-source','$port-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $searchnameData = $searchname->fetch_assoc();
                                        $temp_dport = $searchnameData['dport'] + 1;
                                        $temp_protocol = $searchnameData['protocol'];
                                        $port_final = $temp_dport . "-65535";
                                        $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND sport='$port_final' AND dport='0-65535' AND protocol='$temp_protocol' LIMIT 1;");
                                        if ($check->num_rows == 1) {
                                            $checkData = $check->fetch_assoc();
                                            $tmp_name = $checkData['name_ext'];
                                            $serviceID = $checkData['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                        else {
                                            $tmp_name = $temp_protocol . "-" . $port_final;
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$tmp_name-source','$tmp_name-source','$temp_protocol','$port_final','0-65535','0','$source','$vsys');");
                                            $serviceID = $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                        // Todo: hay que leer el proto i el dport sumarle uno y poner 65535 y crearlo y añadir como member

//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                    }
                                }
                            }
                            elseif ($port == "lt") {
                                $port = $netObj[$next];
                                if (is_numeric($port)) {
                                    $port = $port - 1;
                                    $port_final = "0-" . $port;
                                    $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='0-65535' AND vsys='$vsys';");
                                    if ($getService->num_rows == 0) {
                                        # Create it
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport,checkit,source,vsys) values ('$Protocol-$port_final-source','$Protocol-$port_final-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $data = $getService->fetch_assoc();
                                        $existingname = $data['name'];
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                }
                                else {
                                    $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND dport='0-65535' AND vsys='$vsys';");
                                    if ($searchname->num_rows == 0) {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_final = "6500";
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$port-source','$port-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $searchnameData = $searchname->fetch_assoc();
                                        $temp_dport = $searchnameData['dport'] - 1;
                                        $temp_protocol = $searchnameData['protocol'];
                                        $port_final = "0-" . $temp_dport;
                                        $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND sport='$port_final' AND dport='0-65535' AND protocol='$temp_protocol' LIMIT 1;");
                                        if ($check->num_rows == 1) {
                                            $checkData = $check->fetch_assoc();
                                            $tmp_name = $checkData['name_ext'];
                                            $serviceID = $checkData['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                        else {
                                            $tmp_name = $temp_protocol . "-" . $port_final;
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$tmp_name-source','$tmp_name-source','$temp_protocol','$port_final','0-65535','0','$source','$vsys');");
                                            $serviceID = $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                    }
                                }

                            }
                            elseif ($port == "range") {
                                $port_first = $netObj[$next]; //3
                                $port_last = rtrim($netObj[$next + 1]); //4

                                if (is_numeric($port_first)) {
                                    $port_first_port = $port_first;
                                }
                                else {
                                    # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                    $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_first' AND vsys='$vsys';");
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_first_port = $cisconame['dport'];

                                    if ($port_first_port == "") {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_first_port = "6500";
                                    }
                                }
                                if (is_numeric($port_last)) {
                                    $port_last_port = $port_last;
                                }
                                else {
                                    # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                    $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_last' AND vsys='$vsys';");
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_last_port = $cisconame['dport'];

                                    if ($port_last_port == "") {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range  [' . $HostGroupName . '] source-port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_last_port = "6500";
                                    }
                                }

                                # Check first if they are EQUAL
                                if ($port_first_port == $port_last_port) {
                                    $isRange = "";
                                    $LastPort = "";
                                    $vtype = "";
                                    add_log('warning', 'Reading Services Objects and Groups', 'Moving Service-Range to Service [' . $names_line . '] ports are the same', $source, 'No Action Required');
                                }
                                else {
                                    $isRange = "-range";
                                    $LastPort = "-$port_last_port";
                                    $vtype = "range";
                                }

                                $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND BINARY name_ext='$Protocol" . $isRange . "-$port_first_port" . $LastPort . "-source' AND vsys='$vsys';");
                                if ($getService->num_rows == 0) {
                                    # Create it
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport,checkit,source,type,vsys) values ('$Protocol" . $isRange . "-$port_first_port" . $LastPort . "-source','$Protocol" . $isRange . "-$port_first_port" . $LastPort . "-source','$Protocol','$port_first_port" . $LastPort . "','0-65535','0','$source','$vtype','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                                else {
                                    #Assign to the service-object in service get table and lid
                                    $getServiceData = $getService->fetch_assoc();
                                    $service_name = $getServiceData['name'];
                                    $serviceID = $getServiceData['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            }
                        }

                        if ($port == "destination") {
                            $next = 4;
                            $port = $netObj[3];

                            if (!isset($port)) {
                                $getDup = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND dport='0-65535' AND protocol='$Protocol' AND vsys='$vsys' LIMIT 1;");
                                if ($getDup->num_rows == 0) {
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-All','$Protocol-All','$Protocol','0-65535','0','$source','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                } else {
                                    $data = $getDup->fetch_assoc();
                                    $existingname = $data['name'];
                                    $serviceID = $data['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            }

                            if ($port == "eq") {
                                $port = $netObj[$next]; // 3
                                if (is_numeric($port)) {
                                    $port_final = $port;
                                    $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                    if ($getService->num_rows == 0) {
                                        # Create it
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    } else {
                                        $data = $getService->fetch_assoc();
                                        $existingname = $data['name'];
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                } else {
                                    $que = "SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND protocol = '$Protocol' AND vsys='$vsys';";
                                    $searchname = $projectdb->query($que);
                                    if ($searchname->num_rows == 0) {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_final = "6500";
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    } else {
                                        $data = $searchname->fetch_assoc();
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                }
                            }
                            elseif ($port == "gt") {
                                $port = $netObj[$next];
                                if (is_numeric($port)) {
                                    $port = $port + 1;
                                    $port_final = $port . "-65535";
                                    $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                    if ($getService->num_rows == 0) {
                                        # Create it
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    } else {
                                        $data = $getService->fetch_assoc();
                                        $existingname = $data['name'];
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                } else {
                                    $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                    if ($searchname->num_rows == 0) {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for GT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_final = "6500";
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $searchnameData = $searchname->fetch_assoc();
                                        $temp_dport = $searchnameData['dport'] + 1;
                                        $temp_protocol = $searchnameData['protocol'];
                                        $port_final = $temp_dport . "-65535";
                                        $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$port_final' AND protocol='$temp_protocol' LIMIT 1;");
                                        if ($check->num_rows == 1) {
                                            $checkData = $check->fetch_assoc();
                                            $tmp_name = $checkData['name_ext'];
                                            $serviceID = $checkData['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                        else {
                                            $tmp_name = $temp_protocol . "-" . $port_final;
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$tmp_name','$tmp_name','$temp_protocol','$port_final','0','$source','$vsys');");
                                            $serviceID= $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                        // Todo: hay que leer el proto i el dport sumarle uno y poner 65535 y crearlo y añadir como member

//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                    }
                                }
                            }
                            elseif ($port == "lt") {
                                $port = $netObj[$next];
                                if (is_numeric($port)) {
                                    $port = $port - 1;
                                    $port_final = "0-" . $port;
                                    $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                    if ($getService->num_rows == 0) {
                                        # Create it
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    } else {
                                        $data = $getService->fetch_assoc();
                                        $existingname = $data['name'];
                                        $serviceID = $data['id'];
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                } else {
                                    $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                    if ($searchname->num_rows == 0) {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_final = "6500";
                                        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                        $serviceID = $projectdb->insert_id;
                                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                    }
                                    else {
                                        $searchnameData = $searchname->fetch_assoc();
                                        $temp_dport = $searchnameData['dport'] - 1;
                                        $temp_protocol = $searchnameData['protocol'];
                                        $port_final = "0-" . $temp_dport;
                                        $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$port_final' AND protocol='$temp_protocol' LIMIT 1;");
                                        if ($check->num_rows == 1) {
                                            $checkData = $check->fetch_assoc();
                                            $tmp_name = $checkData['name_ext'];
                                            $serviceID = $checkData['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                        else {
                                            $tmp_name = $temp_protocol . "-" . $port_final;
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$tmp_name','$tmp_name','$temp_protocol','$port_final','0','$source','$vsys');");
                                            $serviceID = $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                    }
                                }

                            }
                            elseif ($port == "range") {
                                $port_first = $netObj[$next]; //3
                                $port_last = rtrim($netObj[$next + 1]); //4

                                if (is_numeric($port_first)) {
                                    $port_first_port = $port_first;
                                } else {
                                    # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                    $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_first' AND vsys='$vsys';");
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_first_port = $cisconame['dport'];

                                    if ($port_first_port == "") {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_first_port = "6500";
                                    }
                                }
                                if (is_numeric($port_last)) {
                                    $port_last_port = $port_last;
                                } else {
                                    # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                    $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_last' AND vsys='$vsys';");
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_last_port = $cisconame['dport'];

                                    if ($port_last_port == "") {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range  [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_last_port = "6500";
                                    }
                                }

                                # Check first if they are EQUAL
                                if ($port_first_port == $port_last_port) {
                                    $isRange = "";
                                    $LastPort = "";
                                    $vtype = "";
                                    add_log('warning', 'Reading Services Objects and Groups', 'Moving Service-Range to Service [' . $names_line . '] ports are the same', $source, 'No Action Required');
                                } else {
                                    $isRange = "-range";
                                    $LastPort = "-$port_last_port";
                                    $vtype = "range";
                                }

                                $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND BINARY name_ext='$Protocol" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                                if ($getService->num_rows == 0) {
                                    # Create it
                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                                    $serviceID = $projectdb->insert_id;
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                } else {
                                    #Assign to the service-object in service get table and lid
                                    $getServiceData = $getService->fetch_assoc();
                                    $service_name = $getServiceData['name'];
                                    $serviceID = $getServiceData['id'];
                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                }
                            }
                        }


                    }
                }
                elseif ($Protocol == "tcp-udp") {
                    $port = $netObj[2];
                    $next = 3;
                    if ($port == "destination") {
                        $next = 4;
                        $port = $netObj[3];
                    }

                    if ($port == "eq") {
                        $port = $netObj[$next];
                        if (is_numeric($port)) {
                            $port_final = $port;
                        }
                        else {
                            $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                            $cisconame = $searchname->fetch_assoc();
                            $port_final = $cisconame['dport'];
                        }
                        if ($port_final == "") {
                            add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                            $port_final = "6500";
                        }
                        $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='tcp' AND dport='$port_final' AND vsys='$vsys';");
                        if ($getService->num_rows == 0) {
                            # Create it
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('tcp-$port_final','tcp-$port_final','tcp','$port_final','1','$source','$vsys');");
                            $serviceID = $projectdb->insert_id;
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        } else {
                            #Assign to the service-object in service get table and lid
                            $getServiceData = $getService->fetch_assoc();
                            $service_name = $getServiceData['name'];
                            $serviceID = $getServiceData['id'];
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                        $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='udp' AND dport='$port_final' AND vsys='$vsys';");
                        if ($getService->num_rows == 0) {
                            # Create it
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('udp-$port_final','udp-$port_final','udp','$port_final','0','$source','$vsys');");
                            $serviceID = $projectdb->insert_id;
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        } else {
                            #Assign to the service-object in service get table and lid
                            $getServiceData = $getService->fetch_assoc();
                            $service_name = $getServiceData['name'];
                            $serviceID = $getServiceData['id'];
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                    }
                    elseif ($port == "range") {
                        $port_first = $netObj[$next];
                        $port_last = rtrim($netObj[$next + 1]);

                        if (is_numeric($port_first)) {
                            $port_first_port = $port_first;
                        } else {
                            # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                            $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_first' AND vsys='$vsys';");
                            $cisconame = $searchname->fetch_assoc();
                            $port_first_port = $cisconame['dport'];

                            if ($port_first_port == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                $port_first_port = "6500";
                            }
                        }
                        if (is_numeric($port_last)) {
                            $port_last_port = $port_last;
                        } else {
                            # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                            $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_last' AND vsys='$vsys';");
                            $cisconame = $searchname->fetch_assoc();
                            $port_last_port = $cisconame['dport'];

                            if ($port_last_port == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range  [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                $port_last_port = "6500";
                            }
                        }

                        # Check first if they are EQUAL
                        if ($port_first_port == $port_last_port) {
                            $isRange = "";
                            $LastPort = "";
                            $vtype = "";
                            add_log('warning', 'Reading Services Objects and Groups', 'Moving Service-Range to Service [' . $names_line . '] ports are the same', $source, 'No Action Required');
                        } else {
                            $isRange = "-range";
                            $LastPort = "-$port_last_port";
                            $vtype = "range";
                        }

                        $getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='tcp" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                        if ($getService->num_rows == 0) {
                            # Create it
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('tcp" . $isRange . "-$port_first_port" . $LastPort . "','tcp" . $isRange . "-$port_first_port" . $LastPort . "','tcp','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                            $serviceID = $projectdb->insert_id;
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        } else {
                            $data = $getService->fetch_assoc();
                            $serviceID = $data['id'];
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                        $getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='udp" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                        if ($getService->num_rows == 0) {
                            # Create it
                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('udp" . $isRange . "-$port_first_port" . $LastPort . "','udp" . $isRange . "-$port_first_port" . $LastPort . "','udp','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                            $serviceID = $projectdb->insert_id;
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        } else {
                            #Assign to the service-object in service get table and lid
                            $data = $getService->fetch_assoc();
                            $serviceID = $data['id'];
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                    }
                }
                elseif ($Protocol == "object") {
                    $obj2 = $netObj[2];
                    $search = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$obj2' AND source='$source' AND vsys='$vsys';");
                    if ($search->num_rows == 1) {
                        $data = $search->fetch_assoc();
                        $serviceID = $data['id'];
                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                    } else {
                        #Not exists in DB Creating IT
                        add_log('error', 'Reading Service Objects and Groups', 'The ObjectName doesn\'t exist [' . $obj2 . ']', $source, 'Adding to the DB, please add the right Port and Protocol');
                        $obj2pan = truncate_names(normalizeNames($obj2));
                        $projectdb->query("INSERT INTO services (name,name_ext,checkit,source,vsys) values ('$obj2pan','$obj2','1','$source','$vsys');");
                        $serviceID = $projectdb->insert_id;
                        $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                    }
                }
                else {
                    if (($Protocol == "icmp") OR ( $Protocol == "icmp6")) {
                        if (isset($netObj[2])) {
                            $code = $netObj[2];
                            $servicename = "$Protocol-$code";
                        } else {
                            $code = "";
                            $servicename = $Protocol;
                        }
                        $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$Protocol' AND type='$code' LIMIT 1;");
                        if ($getService->num_rows == 0) {
                            $projectdb->query("INSERT INTO services (name,name_ext,checkit,source,vsys,protocol,icmp,type) values ('$servicename','$servicename','1','$source','$vsys','$Protocol',1,'$code');");
                            $serviceID = $projectdb->insert_id;
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        } else {
                            $getData = $getService->fetch_assoc();
                            $servicename = $getData['name'];
                            $serviceID = $getData['id'];
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                    }
                    elseif($Protocol == 'ip'){
                        if(isset($netObj[2])){
                            if ($netObj[2] == "source"){
                                $next = 4;
                                $port = $netObj[3];
                                $protocols = ['tcp', 'udp'];

                                foreach($protocols as $Protocol) {
                                    if (!isset($port)) {
                                        $getDup = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND sport='0-65535' AND dport='0-65535' AND protocol='$Protocol' AND vsys='$vsys' LIMIT 1;");
                                        if ($getDup->num_rows == 0) {
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$Protocol-All','$Protocol-All','$Protocol','0-65535','0-65535','0','$source','$vsys');");
                                            $serviceID = $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        } else {
                                            $data = $getDup->fetch_assoc();
                                            $existingname = $data['name'];
                                            $serviceID = $data['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                    }

                                    if ($port == "eq") {
                                        $port = $netObj[$next]; // 3
                                        if (is_numeric($port)) {
                                            $port_final = $port;
                                            $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='0-65535' AND vsys='$vsys';");
                                            if ($getService->num_rows == 0) {
                                                # Create it
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport, checkit,source,vsys) values ('$Protocol-$port_final-source','$Protocol-$port_final-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $getService->fetch_assoc();
                                                $existingname = $data['name'];
                                                $serviceID = $data['id'];
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            }
                                        } else {
                                            $searchname = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                            if ($searchname->num_rows == 0) {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_final = "6500";
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport,checkit,source,vsys) values ('$port-source','$port-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $searchname->fetch_assoc();
                                                $serviceID = $data['id'];
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            }
                                        }
                                    }
                                    elseif ($port == "gt") {
                                        $port = $netObj[$next];
                                        if (is_numeric($port)) {
                                            $port = $port + 1;
                                            $port_final = $port . "-65535";
                                            $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='0-65535' AND vsys='$vsys';");
                                            if ($getService->num_rows == 0) {
                                                # Create it
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$Protocol-$port_final-source','$Protocol-$port_final-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $getService->fetch_assoc();
                                                $existingname = $data['name'];
                                                $serviceID = $data['id'];
                                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                                            }
                                        } else {
                                            $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                            if ($searchname->num_rows == 0) {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for GT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_final = "6500";
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$port-source','$port-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $searchnameData = $searchname->fetch_assoc();
                                                $temp_dport = $searchnameData['dport'] + 1;
                                                $temp_protocol = $searchnameData['protocol'];
                                                $port_final = $temp_dport . "-65535";
                                                $check = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND sport='$port_final' AND dport='0-65535' AND protocol='$temp_protocol' LIMIT 1;");
                                                if ($check->num_rows == 1) {
                                                    $checkData = $check->fetch_assoc();
                                                    $tmp_name = $checkData['name_ext'];
                                                    $serviceID = $checkData['id'];
                                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                                } else {
                                                    $tmp_name = $temp_protocol . "-" . $port_final;
                                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$tmp_name-source','$tmp_name-source','$temp_protocol','$port_final','0-65535','0','$source','$vsys');");
                                                    $serviceID = $projectdb->insert_id;
                                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                                }
                                                // Todo: hay que leer el proto i el dport sumarle uno y poner 65535 y crearlo y añadir como member

//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                            }
                                        }
                                    }
                                    elseif ($port == "lt") {
                                        $port = $netObj[$next];
                                        if (is_numeric($port)) {
                                            $port = $port - 1;
                                            $port_final = "0-" . $port;
                                            $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND sport='$port_final' AND dport='0-65535' AND vsys='$vsys';");
                                            if ($getService->num_rows == 0) {
                                                # Create it
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport,checkit,source,vsys) values ('$Protocol-$port_final-source','$Protocol-$port_final-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $getService->fetch_assoc();
                                                $existingname = $data['name'];
                                                $serviceID =$data['id'];
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            }
                                        } else {
                                            $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND dport='0-65535' AND vsys='$vsys';");
                                            if ($searchname->num_rows == 0) {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_final = "6500";
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$port-source','$port-source','$Protocol','$port_final','0-65535','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            }
                                            else {
                                                $searchnameData = $searchname->fetch_assoc();
                                                $temp_dport = $searchnameData['dport'] - 1;
                                                $temp_protocol = $searchnameData['protocol'];
                                                $port_final = "0-" . $temp_dport;
                                                $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND sport='$port_final' AND dport='0-65535' AND protocol='$temp_protocol' LIMIT 1;");
                                                if ($check->num_rows == 1) {
                                                    $checkData = $check->fetch_assoc();
                                                    $tmp_name = $checkData['name_ext'];
                                                    $serviceID = $checkData['id'];
                                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                                } else {
                                                    $tmp_name = $temp_protocol . "-" . $port_final;
                                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport, dport,checkit,source,vsys) values ('$tmp_name-source','$tmp_name-source','$temp_protocol','$port_final','0-65535','0','$source','$vsys');");
                                                    $serviceID = $projectdb->insert_id;
                                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                                }
//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                            }
                                        }

                                    }
                                    elseif ($port == "range") {
                                        $port_first = $netObj[$next]; //3
                                        $port_last = rtrim($netObj[$next + 1]); //4

                                        if (is_numeric($port_first)) {
                                            $port_first_port = $port_first;
                                        } else {
                                            # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                            $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_first' AND vsys='$vsys';");
                                            $cisconame = $searchname->fetch_assoc();
                                            $port_first_port = $cisconame['dport'];

                                            if ($port_first_port == "") {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] source-port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_first_port = "6500";
                                            }
                                        }
                                        if (is_numeric($port_last)) {
                                            $port_last_port = $port_last;
                                        } else {
                                            # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                            $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_last' AND vsys='$vsys';");
                                            $cisconame = $searchname->fetch_assoc();
                                            $port_last_port = $cisconame['dport'];

                                            if ($port_last_port == "") {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range  [' . $HostGroupName . '] source-port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_last_port = "6500";
                                            }
                                        }

                                        # Check first if they are EQUAL
                                        if ($port_first_port == $port_last_port) {
                                            $isRange = "";
                                            $LastPort = "";
                                            $vtype = "";
                                            add_log('warning', 'Reading Services Objects and Groups', 'Moving Service-Range to Service [' . $names_line . '] ports are the same', $source, 'No Action Required');
                                        } else {
                                            $isRange = "-range";
                                            $LastPort = "-$port_last_port";
                                            $vtype = "range";
                                        }

                                        $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND BINARY name_ext='$Protocol" . $isRange . "-$port_first_port" . $LastPort . "-source' AND vsys='$vsys';");
                                        if ($getService->num_rows == 0) {
                                            # Create it
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport,checkit,source,type,vsys) values ('$Protocol" . $isRange . "-$port_first_port" . $LastPort . "-source','$Protocol" . $isRange . "-$port_first_port" . $LastPort . "-source','$Protocol','$port_first_port" . $LastPort . "','0-65535','0','$source','$vtype','$vsys');");
                                            $serviceID = $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        } else {
                                            #Assign to the service-object in service get table and lid
                                            $getServiceData = $getService->fetch_assoc();
                                            $service_name = $getServiceData['name'];
                                            $serviceID = $getServiceData['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                    }
                                }
                            }
                            elseif ($netObj[2] == "destination") {
                                $next = 4;
                                $port = $netObj[3];
                                $protocols = ['tcp', 'udp'];
                                foreach($protocols as $Protocol) {
                                    if (!isset($port)) {
                                        $getDup = $projectdb->query("SELECT name,id FROM services WHERE source='$source' AND dport='0-65535' AND protocol='$Protocol' AND vsys='$vsys' LIMIT 1;");
                                        if ($getDup->num_rows == 0) {
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-All','$Protocol-All','$Protocol','0-65535','0','$source','$vsys');");
                                            $serviceID = $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        } else {
                                            $data = $getDup->fetch_assoc();
                                            $existingname = $data['name'];
                                            $serviceID = $data['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                    }

                                    if ($port == "eq") {
                                        $port = $netObj[$next]; // 3
                                        if (is_numeric($port)) {
                                            $port_final = $port;
                                            $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                            if ($getService->num_rows == 0) {
                                                # Create it
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $getService->fetch_assoc();
                                                $existingname = $data['name'];
                                                $serviceID =$data['id'];
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            }
                                        } else {
                                            $searchname = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                            if ($searchname->num_rows == 0) {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_final = "6500";
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $searchname->fetch_assoc();
                                                $serviceID = $data['id'];
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            }
                                        }
                                    } elseif ($port == "gt") {
                                        $port = $netObj[$next];
                                        if (is_numeric($port)) {
                                            $port = $port + 1;
                                            $port_final = $port . "-65535";
                                            $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                            if ($getService->num_rows == 0) {
                                                # Create it
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $getService->fetch_assoc();
                                                $existingname = $data['name'];
                                                $serviceID = $data['id'];
                                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                                            }
                                        } else {
                                            $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                            if ($searchname->num_rows == 0) {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for GT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_final = "6500";
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $searchnameData = $searchname->fetch_assoc();
                                                $temp_dport = $searchnameData['dport'] + 1;
                                                $temp_protocol = $searchnameData['protocol'];
                                                $port_final = $temp_dport . "-65535";
                                                $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$port_final' AND protocol='$temp_protocol' LIMIT 1;");
                                                if ($check->num_rows == 1) {
                                                    $checkData = $check->fetch_assoc();
                                                    $tmp_name = $checkData['name_ext'];
                                                    $serviceID = $checkData['id'];
                                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                                } else {
                                                    $tmp_name = $temp_protocol . "-" . $port_final;
                                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$tmp_name','$tmp_name','$temp_protocol','$port_final','0','$source','$vsys');");
                                                    $serviceID = $projectdb->insert_id;
                                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                                }
                                                // Todo: hay que leer el proto i el dport sumarle uno y poner 65535 y crearlo y añadir como member

//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                            }
                                        }
                                    } elseif ($port == "lt") {
                                        $port = $netObj[$next];
                                        if (is_numeric($port)) {
                                            $port = $port - 1;
                                            $port_final = "0-" . $port;
                                            $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND protocol='$Protocol' AND dport='$port_final' AND vsys='$vsys';");
                                            if ($getService->num_rows == 0) {
                                                # Create it
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$Protocol-$port_final','$Protocol-$port_final','$Protocol','$port_final','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                                            } else {
                                                $data = $getService->fetch_assoc();
                                                $existingname = $data['name'];
                                                $serviceID = $data['id'];
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            }
                                        } else {
                                            $searchname = $projectdb->query("SELECT id,dport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$port' AND vsys='$vsys';");
                                            if ($searchname->num_rows == 0) {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for LT : ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_final = "6500";
                                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$port','$port','$Protocol','$port_final','0','$source','$vsys');");
                                                $serviceID = $projectdb->insert_id;
                                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                            } else {
                                                $searchnameData = $searchname->fetch_assoc();
                                                $temp_dport = $searchnameData['dport'] - 1;
                                                $temp_protocol = $searchnameData['protocol'];
                                                $port_final = "0-" . $temp_dport;
                                                $check = $projectdb->query("SELECT name_ext, id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$port_final' AND protocol='$temp_protocol' LIMIT 1;");
                                                if ($check->num_rows == 1) {
                                                    $checkData = $check->fetch_assoc();
                                                    $tmp_name = $checkData['name_ext'];
                                                    $serviceID = $checkData['id'];
                                                    $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                                } else {
                                                    $tmp_name = $temp_protocol . "-" . $port_final;
                                                    $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys) values ('$tmp_name','$tmp_name','$temp_protocol','$port_final','0','$source','$vsys');");
                                                    $serviceID = $projectdb->insert_id;
                                                    $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                                                }
//                                        $addMember[] = "('$lidgroup','$port','$source','$vsys')";
                                            }
                                        }

                                    } elseif ($port == "range") {
                                        $port_first = $netObj[$next]; //3
                                        $port_last = rtrim($netObj[$next + 1]); //4

                                        if (is_numeric($port_first)) {
                                            $port_first_port = $port_first;
                                        } else {
                                            # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                            $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_first' AND vsys='$vsys';");
                                            $cisconame = $searchname->fetch_assoc();
                                            $port_first_port = $cisconame['dport'];

                                            if ($port_first_port == "") {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_first_port = "6500";
                                            }
                                        }
                                        if (is_numeric($port_last)) {
                                            $port_last_port = $port_last;
                                        } else {
                                            # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                            $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND BINARY name_ext='$port_last' AND vsys='$vsys';");
                                            $cisconame = $searchname->fetch_assoc();
                                            $port_last_port = $cisconame['dport'];

                                            if ($port_last_port == "") {
                                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range  [' . $HostGroupName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                                $port_last_port = "6500";
                                            }
                                        }

                                        # Check first if they are EQUAL
                                        if ($port_first_port == $port_last_port) {
                                            $isRange = "";
                                            $LastPort = "";
                                            $vtype = "";
                                            add_log('warning', 'Reading Services Objects and Groups', 'Moving Service-Range to Service [' . $names_line . '] ports are the same', $source, 'No Action Required');
                                        } else {
                                            $isRange = "-range";
                                            $LastPort = "-$port_last_port";
                                            $vtype = "range";
                                        }

                                        $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND BINARY name_ext='$Protocol" . $isRange . "-$port_first_port" . $LastPort . "' AND vsys='$vsys';");
                                        if ($getService->num_rows == 0) {
                                            # Create it
                                            $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,type,vsys) values ('$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol" . $isRange . "-$port_first_port" . $LastPort . "','$Protocol','$port_first_port" . $LastPort . "','0','$source','$vtype','$vsys');");
                                            $serviceID = $projectdb->insert_id;
                                            $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                                        } else {
                                            #Assign to the service-object in service get table and lid
                                            $getServiceData = $getService->fetch_assoc();
                                            $service_name = $getServiceData['name'];
                                            $serviceID = $getServiceData['id'];
                                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                                        }
                                    }
                                }
                            }
                        }
                        else{
                            $getDup = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND dport='0-65535' AND protocol='tcp' AND vsys='$vsys' LIMIT 1;");
                            if ($getDup->num_rows == 0) {
                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys,type,description) values ('all_TCP_ports','all_TCP_ports','tcp','0-65535','0','$source','$vsys','range','All TCP ports');");
                                $serviceID = $projectdb->insert_id;
                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                            }
                            else {
                                $data = $getDup->fetch_assoc();
                                $existingname = $data['name'];
                                $serviceID = $data['id'];
                                $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                            }

                            $getDup = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND dport='0-65535' AND protocol='udp' AND vsys='$vsys' LIMIT 1;");
                            if ($getDup->num_rows == 0) {
                                $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,source,vsys,type,description) values ('all_UDP_ports','all_UDP_ports','udp','0-65535','0','$source','$vsys','range','All TCP ports');");
                                $serviceID = $projectdb->insert_id;
                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                            }
                            else {
                                $data = $getDup->fetch_assoc();
                                $existingname = $data['name'];
                                $serviceID = $data['id'];
                                $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                            }
                        }

                    }
                    else { //TODO: we should remove all the other ports for this security rule
                        $getService = $projectdb->query("SELECT name, id FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$Protocol' LIMIT 1;");
                        if ($getService->num_rows == 0) {
                            $projectdb->query("INSERT INTO services (name,name_ext,checkit,source,vsys,protocol) values ('$Protocol','$Protocol','1','$source','$vsys','$Protocol');");
                            $serviceID = $projectdb->insert_id;
                            $addMemberID[] = "('$lidgroup','services', $serviceID,'$source','$vsys')";
                        } else {
                            $getData = $getService->fetch_assoc();
                            $servicename = $getData['name'];
                            $serviceID = $getData['id'];
                            $addMemberID[] = "('$lidgroup','services',$serviceID,'$source','$vsys')";
                        }
                    }
                }
            }
        }
    }

    if (count($addMember) > 0) {
        $unique = array_unique($addMember);
        $query = "INSERT INTO services_groups (lid,member,source,vsys) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
        unset($addMember);
    }

    if (count($addMemberID) > 0) {
        $unique = array_unique($addMemberID);
        $query = "INSERT INTO services_groups (lid,table_name, member_lid, source,vsys) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
        unset($addMemberID);
    }
}

function add_cisco_services($source, $vsys) {
    global $projectdb;
    $exists = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND name_ext IN ('echo','gopher','pcanywhere-data');");
    if ($exists->num_rows == 0) {
        $add_srv = array();
        $add_srv[] = "('$source','$vsys','echo','echo','','7')";
        $add_srv[] = "('$source','$vsys','discard','discard','','9')";
        $add_srv[] = "('$source','$vsys','tacacs','tacacs','tcp','49')";  //changed tacacs-plus
        $add_srv[] = "('$source','$vsys','tacacs','tacacs','udp','49')";  //changed tacacs-plus
        $add_srv[] = "('$source','$vsys','domain','domain','tcp','53')";
        $add_srv[] = "('$source','$vsys','domain','domain','udp','53')";
        $add_srv[] = "('$source','$vsys','sunrpc','sunrpc','tcp','111')"; // changed portmapper
        $add_srv[] = "('$source','$vsys','sunrpc','sunrpc','udp','111')"; // changed portmapper
        $add_srv[] = "('$source','$vsys','pim-auto-rp','pim-auto-rp','tcp','496')";
        $add_srv[] = "('$source','$vsys','pim-auto-rp','pim-auto-rp','udp','496')";
        $add_srv[] = "('$source','$vsys','talk','talk','tcp','517')";
        $add_srv[] = "('$source','$vsys','talk','talk','udp','517')";
        $add_srv[] = "('$source','$vsys','kerberos','kerberos','tcp','750')";
        $add_srv[] = "('$source','$vsys','kerberos','kerberos','udp','750')";
        $add_srv[] = "('$source','$vsys','nfs','nfs','tcp','2049')";
        $add_srv[] = "('$source','$vsys','nfs','nfs','udp','2049')";
        $add_srv[] = "('$source','$vsys','sip','sip','tcp','5060')";
        $add_srv[] = "('$source','$vsys','sip','sip','udp','5060')";
//        $add_srv[] = "('$source','$vsys','112','vrrp','112','0')";
//        $add_srv[] = "('$source','$vsys','46','rsvp','46','0')";
//        $add_srv[] = "('$source','$vsys','57','skip','57','0')";
//        $add_srv[] = "('$source','$vsys','97','etherip','97','0')";
//        $add_srv[] = "('$source','$vsys','ah','ipsec-ah','ah','0')";
//        $add_srv[] = "('$source','$vsys','eigrp','eigrp','eigrp','0')";
//        $add_srv[] = "('$source','$vsys','esp','ipsec-esp','esp','0')";
//        $add_srv[] = "('$source','$vsys','gre','gre','gre','0')";
//        $add_srv[] = "('$source','$vsys','icmp','icmp','icmp','0')";
//        $add_srv[] = "('$source','$vsys','icmp6','ipv6-icmp','icmp6','0')";
//        $add_srv[] = "('$source','$vsys','igmp','igmp','igmp','0')";
//        $add_srv[] = "('$source','$vsys','ipinip','ip-in-ip','ipinip','0')";
//        $add_srv[] = "('$source','$vsys','ipsec','ipsec','ipsec','0')";
//        $add_srv[] = "('$source','$vsys','ospf','ospf','ospf','0')";
//        $add_srv[] = "('$source','$vsys','pim','pim','pim','0')";
        $add_srv[] = "('$source','$vsys','daytime','daytime','tcp','13')";
        $add_srv[] = "('$source','$vsys','chargen','chargen','tcp','19')";
        $add_srv[] = "('$source','$vsys','ftp-data','ftp-data','tcp','20')";
        $add_srv[] = "('$source','$vsys','ftp','ftp','tcp','21')";
        $add_srv[] = "('$source','$vsys','ssh','ssh','tcp','22')";
        $add_srv[] = "('$source','$vsys','telnet','telnet','tcp','23')";
        $add_srv[] = "('$source','$vsys','smtp','smtp','tcp','25')";
        $add_srv[] = "('$source','$vsys','whois','whois','tcp','43')";
        $add_srv[] = "('$source','$vsys','gopher','gopher','tcp','70')";
        $add_srv[] = "('$source','$vsys','finger','finger','tcp','79')";
        $add_srv[] = "('$source','$vsys','www','www','tcp','80')";
        $add_srv[] = "('$source','$vsys','www','www','udp','80')";
        $add_srv[] = "('$source','$vsys','hostname','hostname','tcp','101')";
        $add_srv[] = "('$source','$vsys','pop2','pop2','tcp','109')";
        $add_srv[] = "('$source','$vsys','pop3','pop3','tcp','110')";
        $add_srv[] = "('$source','$vsys','ident','ident','tcp','113')";
        $add_srv[] = "('$source','$vsys','nntp','nntp','tcp','119')";
        $add_srv[] = "('$source','$vsys','netbios-ssn','netbios-ssn','tcp','139')";  //changed netbios-ss_tcp
        $add_srv[] = "('$source','$vsys','imap4','imap4','tcp','143')";  //changed imap
        $add_srv[] = "('$source','$vsys','bgp','bgp','tcp','179')";
        $add_srv[] = "('$source','$vsys','irc','irc','tcp','194')";
        $add_srv[] = "('$source','$vsys','ldap','ldap','tcp','389')";
        $add_srv[] = "('$source','$vsys','https','https','tcp','443')";
        $add_srv[] = "('$source','$vsys','exec','exec','tcp','512')";  //changed r-exec
        $add_srv[] = "('$source','$vsys','login','login','tcp','513')";
        $add_srv[] = "('$source','$vsys','cmd','cmd','tcp','514')";
        $add_srv[] = "('$source','$vsys','rsh','rsh','tcp','514')";
        $add_srv[] = "('$source','$vsys','lpd','lpd','tcp','515')";
        $add_srv[] = "('$source','$vsys','uucp','uucp','tcp','540')";
        $add_srv[] = "('$source','$vsys','klogin','klogin','tcp','543')"; //changed eklogin
        $add_srv[] = "('$source','$vsys','kshell','kshell','tcp','544')";
        $add_srv[] = "('$source','$vsys','rtsp','rtsp','tcp','554')";
        $add_srv[] = "('$source','$vsys','ldaps','ldaps','tcp','636')";
        $add_srv[] = "('$source','$vsys','lotusnotes','lotusnotes','tcp','1352')";  //changed lotus-notes
        $add_srv[] = "('$source','$vsys','citrix-ica','citrix-ica','tcp','1494')";  //changed citrix
        $add_srv[] = "('$source','$vsys','sqlnet','sqlnet','tcp','1521')"; //changed oracle
        $add_srv[] = "('$source','$vsys','h323','h323','tcp','1720')"; //changed h.323
        $add_srv[] = "('$source','$vsys','pptp','pptp','tcp','1723')";
        $add_srv[] = "('$source','$vsys','ctiqbe','ctiqbe','tcp','2748')";
        $add_srv[] = "('$source','$vsys','cifs','cifs','tcp','3020')";
        $add_srv[] = "('$source','$vsys','aol','aol','tcp','5190')";  //changed aim
        $add_srv[] = "('$source','$vsys','pcanywhere-data','pcanywhere-data','tcp','5631')";
        $add_srv[] = "('$source','$vsys','time','time','udp','37')";
        $add_srv[] = "('$source','$vsys','nameserver','nameserver','udp','42')";
        $add_srv[] = "('$source','$vsys','bootps','bootps','udp','67')";
        $add_srv[] = "('$source','$vsys','bootpc','bootpc','udp','68')";
        $add_srv[] = "('$source','$vsys','tftp','tftp','udp','69')";
        $add_srv[] = "('$source','$vsys','ntp','ntp','udp','123')";
        $add_srv[] = "('$source','$vsys','netbios-ns','netbios-ns','udp','137')";
        $add_srv[] = "('$source','$vsys','netbios-dgm','netbios-dgm','udp','138')";  //changed netbios-dg
        $add_srv[] = "('$source','$vsys','netbios-ss','netbios-ss','udp','139')";  //changed netbios-ss_udp
        $add_srv[] = "('$source','$vsys','snmp','snmp','udp','161')";
        $add_srv[] = "('$source','$vsys','snmptrap','snmptrap','udp','162')";  //changed snmp-trap
        $add_srv[] = "('$source','$vsys','xdmcp','xdmcp','udp','177')";
        $add_srv[] = "('$source','$vsys','dnsix','dnsix','udp','195')";
        $add_srv[] = "('$source','$vsys','mobile-ip','mobile-ip','udp','434')";  //changed mobile
        $add_srv[] = "('$source','$vsys','isakmp','isakmp','udp','500')";
        $add_srv[] = "('$source','$vsys','biff','biff','udp','512')";
        $add_srv[] = "('$source','$vsys','who','who','udp','513')";
        $add_srv[] = "('$source','$vsys','syslog','syslog','udp','514')";
        $add_srv[] = "('$source','$vsys','rip','rip','udp','520')";
        $add_srv[] = "('$source','$vsys','radius','radius','udp','1645')";
        $add_srv[] = "('$source','$vsys','radius-acct','radius-acct','udp','1646')";
        $add_srv[] = "('$source','$vsys','secureid-udp','secureid-udp','udp','5510')";
        $add_srv[] = "('$source','$vsys','pcanywhere-status','pcanywhere-status','udp','5632')";

        $add_srv[] = "('$source','$vsys','snmptrap','snmptrap','udp','162')";
//        $add_srv[] = "('$source','$vsys','netbios-ssn','netbios-ssn','tcp','139')";
        $out = implode(",", $add_srv);
        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,protocol,dport) VALUES " . $out . ";");
        unset($add_srv);

//        $projectdb->query("INSERT INTO services_groups_id (source,vsys, name_ext,name,type) VALUES ('$source', '$vsys','tacacs','tacacs','static');");
//        $groupID = $projectdb->insert_id;
//        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,protocol,dport) VALUES ('$source','$vsys','tacacs-tcp','tacacs-tcp','tcp','49');");
//        $serviceID = $projectdb->insert_id;
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,table_name,member_lid) VALUES ('$source', '$vsys','$groupID','services','$serviceID');");
//        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,protocol,dport) VALUES ('$source','$vsys','tacacs-udp','tacacs-udp','udp','49');");
//        $serviceID = $projectdb->insert_id;
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,table_name,member_lid) VALUES ('$source', '$vsys','$groupID','services','$serviceID');");

    }
}

function get_object_service($cisco_config_file, $source, $vsys) {
    global $projectdb;
    $isObjectService = 0;
    $addService = array();

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if ($isObjectService == 1) {
            if (preg_match("/^service protocol/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $srv_protocol = $netObj[2];
                $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND protocol='$srv_protocol' AND vsys='$vsys';");
                //echo "1. SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND protocol='$srv_protocol' AND vsys='$vsys';\n";
                if ($search->num_rows == 0) {
                    $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','$srv_protocol','','','','','1','$source','$vsys')";
                    add_log('warning', 'Reading Services Objects and Groups', 'Service Protocol found [' . $ObjectServiceName . '] and Protocol [' . $srv_protocol . ']', $source, 'Replace it by the right app-id');
                }
            }
            elseif (preg_match("/^service icmp/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';");
                if ($search->num_rows == 0) {
                    $icmptype = $netObj[2];
                    $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','icmp','','',1,'$icmptype','1','$source','$vsys')";
                    add_log('warning', 'Phase 3: Reading Services Objects and Groups', 'ICMP Service found [' . $ObjectServiceName . ']', $source, 'Replace it by the ICMP app-id');
                }
            }
            elseif (preg_match("/^service icmp6/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';");
                if ($search->num_rows == 0) {
                    $icmptype = $netObj[2];
                    $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','icmp','','',1,'$icmptype','1','$source','$vsys')";
                    add_log('warning', 'Phase 3: Reading Services Objects and Groups', 'ICMP6 Service found [' . $ObjectServiceName . ']', $source, 'Replace it by the ICMP app-id');
                }
            }
            //elseif ((preg_match("/^service tcp /i", $names_line)) or ( preg_match("/^service udp /i", $names_line))) {
            elseif ((preg_match("/^service tcp/i", $names_line)) or ( preg_match("/^service udp/i", $names_line))) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                //print_r($netObj);
                $next = 2;
                $sport = "";
                $dport = "";
                $srv_protocol = $netObj[1];
                #Supported to find first destination  than source and vice versa

                if(isset($netObj[2])){
                    if (($netObj[2] == "source") or ( $netObj[2] == "destination")) {
                        if ($netObj[3] == "eq") {
                            $port = $netObj[4];
                            $next = 5;
                            if (is_numeric($port)) {
                                $port_final = $port;
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[3] == "neq") {
                            $port = $netObj[4];
                            $next = 5;
                            if (is_numeric($port)) {
                                $port_final = $port;
                                $srv_port_before = intval($port_final) - 1;
                                $srv_port_after = intval($port_final) + 1;
                                $port_final = "1-$srv_port_before,$srv_port_after-65535";
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                $srv_port_before = intval($port_final) - 1;
                                $srv_port_after = intval($port_final) + 1;
                                $port_final = "1-$srv_port_before,$srv_port_after-65535";
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[3] == "lt") {
                            $port = $netObj[4];
                            $next = 5;
                            if (is_numeric($port)) {
                                $port_final = $port;
                                $srv_port_before = intval($port_final);
                                $port_final = "1-$srv_port_before";
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                $srv_port_before = intval($port_final);
                                $port_final = "1-$srv_port_before";
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[3] == "gt") {
                            $port = $netObj[4];
                            $next = 5;
                            if (is_numeric($port)) {
                                $port_final = $port;
                                $srv_port_before = intval($port_final);
                                $port_final = "$srv_port_before-65535";
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                $srv_port_before = intval($port_final);
                                $port_final = "$srv_port_before-65535";
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[3] == "range") {
                            $port_first = $netObj[4];
                            $port_last = rtrim($netObj[5]);
                            $next = 6;
                            if (is_numeric($port_first)) {
                                $port_first_port = $port_first;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port_first' LIMIT 1;");
                                if ($searchname->num_rows==1){
                                    $cisconame = $searchname->fetch_assoc();
                                    $port_first_port = $cisconame['dport'];
                                }
                                else{
                                    if ($port_first_port == "") {
                                        add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range [' . $ObjectServiceName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                        $port_first_port = "6500";
                                    }
                                }
                            }
                            if (is_numeric($port_last)) {
                                $port_last_port = $port_last;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port_last' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_last_port = $cisconame['dport'];

                                if ($port_last_port == "") {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range [' . $ObjectServiceName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_last_port = "6500";
                                }
                            }

                            # Check first if they are EQUAL
                            if ($port_first_port == $port_last_port) {
                                $LastPort = "";
                            } else {
                                $LastPort = "-$port_last_port";
                            }

                            $port_final = $port_first_port . $LastPort;
                        }

                        if ($netObj[2] == "source") {
                            $sport = $port_final;
                        } else {
                            $dport = $port_final;
                        }
                    }
                }
                else{
                    // In case:
                    // object service MPI-MS-SQL-Monitor_Reply
                    // service udp
                    $dport = '0-65535';
                }

                if (isset($netObj[$next])) {
                    if (($netObj[$next] == "source") or ( $netObj[$next] == "destination")) {
                        if ($netObj[$next + 1] == "eq") {
                            $port = $netObj[$next + 2];
                            if (is_numeric($port)) {
                                $port_final = $port;
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[$next + 1] == "neq") {
                            $port = $netObj[$next + 2];
                            if (is_numeric($port)) {
                                $port_final = $port;
                                $srv_port_before = intval($port_final) - 1;
                                $srv_port_after = intval($port_final) + 1;
                                $port_final = "1-$srv_port_before,$srv_port_after-65535";
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                $srv_port_before = intval($port_final) - 1;
                                $srv_port_after = intval($port_final) + 1;
                                $port_final = "1-$srv_port_before,$srv_port_after-65535";
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[$next + 1] == "lt") {
                            $port = $netObj[$next + 2];
                            if (is_numeric($port)) {
                                $port_final = $port;
                                $srv_port_before = intval($port_final);
                                $port_final = "1-$srv_port_before";
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                $srv_port_before = intval($port_final);
                                $port_final = "1-$srv_port_before";
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[$next + 1] == "gt") {
                            $port = $netObj[$next + 2];
                            if (is_numeric($port)) {
                                $port_final = $port;
                                $srv_port_before = intval($port_final);
                                $port_final = "$srv_port_before-65535";
                            } else {
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_final = $cisconame['dport'];
                                $srv_port_before = intval($port_final);
                                $port_final = "$srv_port_before-65535";
                            }
                            if ($port_final == "") {
                                add_log('error', 'Reading Services Objects and Groups', 'Unknown Service [' . $ObjectServiceName . '] port-name mapping for: ' . $port, $source, 'Using 6500 port. Change it from the GUI');
                                $port_final = "6500";
                            }
                        }
                        elseif ($netObj[$next + 1] == "range") {
                            $port_first = $netObj[$next + 2];
                            $port_last = rtrim($netObj[$next + 3]);
                            if (is_numeric($port_first)) {
                                $port_first_port = $port_first;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port_first' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_first_port = $cisconame['dport'];

                                if ($port_first_port == "") {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range [' . $ObjectServiceName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_first_port = "6500";
                                }
                            }
                            if (is_numeric($port_last)) {
                                $port_last_port = $port_last;
                            } else {
                                # IS NAME TO SEARCH IN vendor_services_mapping TABLE
                                $searchname = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$port_last' LIMIT 1;");
                                $cisconame = $searchname->fetch_assoc();
                                $port_last_port = $cisconame['dport'];

                                if ($port_last_port == "") {
                                    add_log('error', 'Reading Services Objects and Groups', 'Unknown Service-Range [' . $ObjectServiceName . '] port-name mapping for: ' . $port_first, $source, 'Using 6500 port. Change it from the GUI');
                                    $port_last_port = "6500";
                                }
                            }

                            # Check first if they are EQUAL
                            if ($port_first_port == $port_last_port) {
                                $LastPort = "";
                            } else {
                                $LastPort = "-$port_last_port";
                            }

                            $port_final = $port_first_port . $LastPort;
                        }

                        if ($netObj[$next] == "source") {
                            $sport = $port_final;
                        } else {
                            $dport = $port_final;
                        }
                    }
                }
                $search = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';");
                //echo "FINAL: SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$ObjectServiceName' AND vsys='$vsys';\n";
                if ($search->num_rows == 0) {
                    if($sport != '' && $dport==''){
                        $dport='0-65535';
                    }
                    $addService[] = "('$ObjectServiceNamePan','$ObjectServiceName','$srv_protocol','$sport','$dport','0','',0,'$source','$vsys')";
                }
            }
        }

        if (preg_match("/^object service/i", $names_line)) {
            $isObjectService = 1;
            $names = explode(" ", $names_line);
            $ObjectServiceName = rtrim($names[2]);
            $ObjectServiceNamePan = truncate_names(normalizeNames($ObjectServiceName));
        }
    }

    if (count($addService) > 0) {
        $projectdb->query("INSERT INTO services (name,name_ext,protocol,sport,dport,icmp,type,checkit,source,vsys) values" . implode(",", $addService) . ";");
        unset($addService);
    }
}

/*function fix_destination_nat_old($config_path, $source, $vsys) {
    global $projectdb;
    $cisco_config_file = file($config_path);

    #First Calculate the Zones
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
    if ($getVR->num_rows == 1) {
        $VRData = $getVR->fetch_assoc();
        $vr = $VRData['id'];
        $from_or_to = "from";
        $rule_or_nat = "rule";

        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

        $projectdb->query("DELETE FROM security_rules_from WHERE source='$source' AND vsys='$vsys';");
        $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE source='$source' AND vsys='$vsys';");
        if ($getSRC->num_rows > 0) {
            while ($getSRCData = $getSRC->fetch_assoc()) {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                // Mirar si para esta regla es negated o no
                $getIsNegated = $projectdb->query("SELECT negate_source, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if ($getIsNegated->num_rows > 0) {
                    $getINData = $getIsNegated->fetch_assoc();
                    $negate_source = $getINData['negate_source'];
                    $devicegroup = $getINData['devicegroup'];
                }

                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_source';");
                if ($getZones->num_rows == 1){
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }
                else{
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                    $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                        . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_source','$vsys', '$source');");
                }
                foreach ($zones as $zone) {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid' AND vsys = '$vsys' AND source = '$source';");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }

        $from_or_to = "to";
        $rule_or_nat = "rule";
        $projectdb->query("DELETE FROM security_rules_to WHERE source='$source' AND vsys='$vsys';");
        $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE source='$source' AND vsys='$vsys';");
        if ($getSRC->num_rows > 0) {
            while ($getSRCData = $getSRC->fetch_assoc()) {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                // Mirar si para esta regla es negated o no
                $getIsNegated = $projectdb->query("SELECT negate_destination, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if ($getIsNegated->num_rows > 0) {
                    $getINData = $getIsNegated->fetch_assoc();
                    $negate_destination = $getINData['negate_destination'];
                    $devicegroup = $getINData['devicegroup'];
                }

                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_destination';");
                if ($getZones->num_rows == 1){
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }else{
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination);
                    $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                        . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_destination','$vsys', '$source');");
                }
                foreach ($zones as $zone) {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid' AND vsys = '$vsys' AND source = '$source';");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }
    }

    # Fix based in access-group direction

    foreach ($cisco_config_file as $line => $names_line) {
        if (preg_match("/^access-group /i", $names_line)) {
            $addfrom = array();
            $rules = array();
            $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $tagname = truncate_tags($netObj[1]);
            $zoneFrom = $netObj[4];
            $direction = $netObj[2];
            if ($direction == "in") {
                $table_direction = "security_rules_from";
                $whatzone = "FROM";
            } elseif ($direction == "out") {
                $table_direction = "security_rules_to";
                $whatzone = "TO";
            }
            $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='$tagname';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $member_lid = $getTagData['id'];
                $table_name = "tag";
                $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_tag WHERE source='$source' AND vsys='$vsys' AND member_lid='$member_lid' AND table_name='$table_name';");
                if ($getRules->num_rows > 0) {
                    while ($getRulesData = $getRules->fetch_assoc()) {
                        $rule_lid = $getRulesData['rule_lid'];
                        $addfrom[] = "('$source','$vsys','$zoneFrom','$rule_lid','default')";
                        $rules[] = $getRulesData['rule_lid'];
                    }
                }
                if (count($rules) > 0) {
                    $projectdb->query("DELETE FROM $table_direction WHERE rule_lid IN (" . implode(",", $rules) . ") AND source='$source' AND vsys='$vsys';");
                    unset($rules);
                }
                if (count($addfrom) > 0) {
                    $projectdb->query("INSERT INTO $table_direction (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $addfrom) . ";");
                    unset($addfrom);
                    add_log2('warning', 'Auto Zone Assign', 'Forcing Zone [' . $whatzone . '] to [' . $zoneFrom . '] on access-list [' . $tagname . '] based on access-group direction [' . $direction . ']', $source, 'No Action Required', '', '', '');
                }

                //Calculate the Zone
            }
        }
    }


    $getDNAT = $projectdb->query("SELECT id,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE is_dat=1 AND source='$source' AND vsys='$vsys' AND tp_dat_address_table!='';");
    if ($getDNAT->num_rows > 0) {

        while ($data = $getDNAT->fetch_assoc()) {
            $zoneFROM = "";
            $rule_lid = $data['id'];
            $tp_dat_address_lid = $data['tp_dat_address_lid'];
            $tp_dat_address_table = $data['tp_dat_address_table'];
            #get Address name
            $getname = $projectdb->query("SELECT name FROM $tp_dat_address_table WHERE id='$tp_dat_address_lid'");
            $getnameData = $getname->fetch_assoc();
            $datName = $getnameData['name'];
            #Get Source Zone from Nat Rule
            $getFROM = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$rule_lid' AND source='$source' AND vsys='$vsys';");
            if ($getFROM->num_rows == 1) {
                $dataFrom = $getFROM->fetch_assoc();
                $zoneFROM = $dataFrom['name'];
            }
            #Get Destination from OP
            $getDST = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$rule_lid' AND source='$source' AND vsys='$vsys';");
            if ($getDST->num_rows == 1) {
                $data2 = $getDST->fetch_assoc();
                $dst_member_lid = $data2['member_lid'];
                $dst_table_name = $data2['table_name'];
                #get Address name
                $getname = $projectdb->query("SELECT name FROM $dst_table_name WHERE id='$dst_member_lid'");
                $getnameData = $getname->fetch_assoc();
                $dstName = $getnameData['name'];
            }

            $getSecurityDST = $projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE source='$source' AND vsys='$vsys' AND "
                . "member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
            if ($getSecurityDST->num_rows > 0) {
                while ($data4 = $getSecurityDST->fetch_assoc()) {
                    $security_rule = $data4['rule_lid'];
                    #Check the ZONE, has to be the same from ZoneFROM
                    $getSecurityZone = $projectdb->query("SELECT name FROM security_rules_from WHERE source='$source' AND vsys='$vsys' AND rule_lid='$security_rule';");
                    if ($getSecurityZone->num_rows == 1) {
                        $data5 = $getSecurityZone->fetch_assoc();
                        $security_from = $data5['name'];
                        if ($security_from == $zoneFROM) {
                            $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                        }
                    } else {
                        #No source ZONE maybe is ANY :-)
                        $exist = $projectdb->query("SELECT id FROM security_rules_dst "
                            . "WHERE source='$source' AND vsys='$vsys' AND "
                            . "table_name='$tp_dat_address_table' ANd member_lid='$tp_dat_address_lid' AND rule_lid='$security_rule';");
                        if ($exist->num_rows == 1) {
                            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                        } else {
                            //Crec que aixo sobra
                            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            $projectdb->query("INSERT INTO security_rules_dst (rule_lid,member_lid,table_name,source,vsys) VALUES ('$security_rule','$dst_member_lid','$dst_table_name','$source','$vsys');");
                        }
                        add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                    }
                }
            }
        }
    }

    //Bidirectional
    // Cisco provides Security rules with post-NAT destination. Security policies need to be fixed to fit their pre-NAT destionations
    // for the comming back connection in the bidirectional NAT
    $query = "SELECT id, op_zone_to FROM nat_rules WHERE tp_sat_bidirectional=1 AND tp_sat_type='static-ip' AND source='$source' AND vsys='$vsys';";
    $getStaticBidirectNAT = $projectdb->query($query);
    if ($getStaticBidirectNAT->num_rows > 0) {
        while ($data = $getStaticBidirectNAT->fetch_assoc()) {
            $zoneB = $data['op_zone_to'];
            $rule_lid = $data['id'];
            //     Dir1 -  Original:  (ZoneA) A1 - (ZoneB) B1           Translate to:      (ZoneC) PostNatA1 - (ZoneB) B1
            //     Dir2 -  Original:  (ZoneB) B1 - (ZoneC) PostNatA1    Translate to:            (ZoneB)  B1 - (ZoneA) A1   (DNAT)

            //Get pre-NAT source. This will be the comming back post-NAT Destination
            $query = "SELECT member_lid, table_name FROM nat_rules_src WHERE source='$source' AND vsys='$vsys' AND rule_lid=$rule_lid;";
            $A1 = $projectdb->query($query);
            if ($A1->num_rows ==1){
                $data2 = $A1->fetch_assoc();
                $A1_member_lid = $data2['member_lid'];
                $A1_table_name = $data2['table_name'];
                #get Address name
                $getname = $projectdb->query("SELECT name_ext FROM $A1_table_name WHERE id='$A1_member_lid'");
                $getnameData = $getname->fetch_assoc();
                $A1_name = $getnameData['name_ext'];
            }

            $A1_list = array();
            if($A1_table_name=='address'){
                $query="SELECT a.id as id FROM address a "
                    . "INNER JOIN address b WHERE a.ipaddress=b.ipaddress and a.CIDR=b.cidr AND b.id='$A1_member_lid';";
                $getA1_list = $projectdb->query($query);
                if($getA1_list->num_rows > 0){
                    while($data_addr = $getA1_list->fetch_assoc()){
                        $A1_list[] = $data_addr['id'];
                    }
                }
            }

            //Get pre-NAT destination. This will be the comming back Source
            $query = "SELECT member_lid, table_name FROM nat_rules_dst WHERE source='$source' AND vsys='$vsys' AND rule_lid=$rule_lid;";
            $B1 = $projectdb->query($query);
            if ($B1->num_rows ==1){
                $data2 = $B1->fetch_assoc();
                $B1_member_lid = $data2['member_lid'];
                $B1_table_name = $data2['table_name'];
            }

            //Get post-NAT source. This will be the comming back pre-NAT Destination
            $query = "SELECT member_lid, table_name FROM nat_rules_translated_address WHERE source='$source' AND vsys='$vsys' AND rule_lid=$rule_lid;";
            $PostNatA1 = $projectdb->query($query);
            if ($PostNatA1->num_rows ==1){
                $data2 = $PostNatA1->fetch_assoc();
                $PostNatA1_member_lid = $data2['member_lid'];
                $PostNatA1_table_name = $data2['table_name'];
                #get Address name
                $getname = $projectdb->query("SELECT name_ext FROM $PostNatA1_table_name WHERE id='$PostNatA1_member_lid'");
                $getnameData = $getname->fetch_assoc();
                $PostNatA1_name = $getnameData['name_ext'];
            }

            if(count($A1_list)>0){
                $query = "SELECT rule_lid FROM security_rules_dst "
                    . "WHERE source='$source' AND vsys='$vsys' AND member_lid in ('".implode(",",$A1_list)."') AND table_name='address';";
                $getSecurityDST = $projectdb->query($query);
            }
            else{
                $getSecurityDST = $projectdb->query("SELECT rule_lid FROM security_rules_dst "
                    . "WHERE source='$source' AND vsys='$vsys' AND member_lid='$A1_member_lid' AND table_name='$A1_table_name';");
            }

            if ($getSecurityDST->num_rows > 0) {
                while ($data4 = $getSecurityDST->fetch_assoc()) {
                    $security_rule = $data4['rule_lid'];
                    #Check the ZONE, has to be the same from ZoneFROM
                    $getSecurityZone = $projectdb->query("SELECT name FROM security_rules_from WHERE source='$source' AND vsys='$vsys' AND rule_lid='$security_rule';");
                    if ($getSecurityZone->num_rows == 1) {
                        $data5 = $getSecurityZone->fetch_assoc();
                        $security_from = $data5['name'];
                        if ($security_from == $zoneB) {
                            $query = "UPDATE security_rules_dst SET table_name='$PostNatA1_table_name', member_lid='$PostNatA1_member_lid' "
                                . "WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND "
                                . "member_lid in ('".implode(",",$A1_list)."') AND table_name='$A1_table_name';";
                            $projectdb->query($query);
                            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            add_log2('warning', 'Fixing Destination Nats', 'Security RuleID ['.$security_rule.'] has been modified by Nat RuleID ['.$rule_lid.'], Replaced Destination Address old[' . $A1_name . '] by new[' . $PostNatA1_name . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                        }else{

                        }
                    } else {

                        #No source ZONE maybe is ANY :-)
                        $exist = $projectdb->query("SELECT id FROM security_rules_dst "
                            . "WHERE source='$source' AND vsys='$vsys' AND "
                            . "table_name='$A1_table_name' ANd member_lid='$A1_member_lid' AND rule_lid='$security_rule';");
                        if ($exist->num_rows == 1) {
                            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            $projectdb->query("UPDATE security_rules_dst SET table_name='$PostNatA1_table_name', member_lid='$PostNatA1_member_lid' "
                                . "WHERE rule_lid='$security_rule' AND source='$source' AND vsys='$vsys' AND "
                                . "member_lid in ('".implode(",",$A1_list)."') AND table_name='$A1_table_name';");
                        }
                        add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $A1_name . '] by new[' . $PostNatA1_name . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                    }
                }
            }
        }
    }

    # Change rules TO where static-ip nat has the TP -source equal as a security rule destination
    $getStatic=$projectdb->query("SELECT id FROM nat_rules WHERE tp_sat_type='static-ip' AND source='$source' AND vsys='$vsys';");
    if ($getStatic->num_rows>0){
        while ($getStaticData=$getStatic->fetch_assoc()){
            $nat_lid=$getStaticData['id'];
            #get FROM Zone
            $getZone=$projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$nat_lid' LIMIT 1;");
            if ($getZone->num_rows==1){
                $getZoneData=$getZone->fetch_assoc();
                $zoneFrom=$getZoneData['name'];
                $getTP=$projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$nat_lid' LIMIT 1;");
                if ($getTP->num_rows==1){
                    while ($getTPData=$getTP->fetch_assoc()){
                        $ori_member_lid=$getTPData['member_lid'];
                        $ori_table_name=$getTPData['table_name'];
                        #Exact object Match, future check if its inside
                        $getRulesDst=$projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE source='$source' AND vsys='$vsys' AND member_lid='$ori_member_lid' AND table_name='$ori_table_name';");
                        if ($getRulesDst->num_rows>0){
                            while ($getRulesDstData=$getRulesDst->fetch_assoc()){
                                $rule_lid=$getRulesDstData['rule_lid'];
                                $getZoneDst=$projectdb->query("SELECT id,name FROM security_rules_to WHERE rule_lid='$rule_lid' LIMIT 1;");
                                if ($getZoneDst->num_rows==1){
                                    $getZoneDstData=$getZoneDst->fetch_assoc();
                                    $zoneid=$getZoneDstData['id'];
                                    $zonename=$getZoneDstData['name'];
                                    if ($zoneFrom==$zonename){}
                                    else{
                                        $projectdb->query("UPDATE security_rules_to SET name='$zoneFrom' WHERE id='$zoneid';");
                                        $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$rule_lid';");
                                        add_log2('warning', 'Fixing Destination Zones', 'Security RuleID [' . $rule_lid . '] has been modified by Nat RuleID [' . $nat_lid . '], Replaced Destination Zone old[' . $zonename . '] by new[' . $zoneFrom . ']', $source, 'Check it manually', 'rules', $rule_lid, 'security_rules');
                                    }
                                }
                            }
                        }
                    }
                }
            }

        }
    }
}*/

function fix_destination_nat($config_path, $source, $vsys) {
    global $projectdb;
    global $global_config_filename;
    $cisco_config_file = file($config_path);

    echo "Name: $config_path\n";


    #First Calculate the Zones
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
    if ($getVR->num_rows == 1) {
        $VRData = $getVR->fetch_assoc();
        $vr = $VRData['id'];
        $from_or_to = "from";
        $rule_or_nat = "rule";

        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

        //$ids_rules = getSecurityIdsBySourceVsys($source, $vsys);
        $ids_rules = getIdsBySourceVsys("security_rules", $source, $vsys);

        $projectdb->query("DELETE FROM security_rules_from WHERE rule_lid IN (".implode(',', $ids_rules).");");

        $query = "SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE rule_lid IN (".implode(',', $ids_rules).");";
        $getSRC = $projectdb->query($query);
        if ($getSRC->num_rows > 0) {
            while ($getSRCData = $getSRC->fetch_assoc()) {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                // Mirar si para esta regla es negated o no
                $getIsNegated = $projectdb->query("SELECT negate_source, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if ($getIsNegated->num_rows > 0) {
                    $getINData = $getIsNegated->fetch_assoc();
                    $negate_source = $getINData['negate_source'];
                    $devicegroup = $getINData['devicegroup'];
                }

                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_source';");
                if ($getZones->num_rows == 1){
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }
                else{
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                    $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                        . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_source','$vsys', '$source');");
                }
                foreach ($zones as $zone) {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }

        $from_or_to = "to";
        $rule_or_nat = "rule";
        $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid IN (".implode(',', $ids_rules).");");
        $query = "SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE rule_lid IN (".implode(',', $ids_rules).");";
        //echo "$query\n";
        $getSRC = $projectdb->query($query);
        if ($getSRC->num_rows > 0) {
            while ($getSRCData = $getSRC->fetch_assoc()) {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                // Mirar si para esta regla es negated o no
                $getIsNegated = $projectdb->query("SELECT negate_destination, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if ($getIsNegated->num_rows > 0) {
                    $getINData = $getIsNegated->fetch_assoc();
                    $negate_destination = $getINData['negate_destination'];
                    $devicegroup = $getINData['devicegroup'];
                }

                //TODO: Transfer this information of the tmp_calc_zone into memory space
                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_destination';");
                if ($getZones->num_rows == 1){
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }
                else{
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination);
                    $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                        . " VALUES ('$member_lid', '$table_name', '".implode(",", $zones)."', '$negate_destination','$vsys', '$source');");
                }
                foreach ($zones as $zone) {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }
    }

    # Fix based in access-group direction


    foreach ($cisco_config_file as $line => $names_line) {
        if (preg_match("/^access-group /i", $names_line)) {
            $addfrom = array();
            $rules = array();
            $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $tagname = truncate_tags($netObj[1]);

            $direction = $netObj[2];
            if($direction == 'global'){
                continue;
            }

            $zoneFrom = $netObj[4];
            if ($direction == "in") {
                $table_direction = "security_rules_from";
                $whatzone = "FROM";
                $ZoneToCalculate = "To";
            }
            else //if ($direction == "out")
            {
                $table_direction = "security_rules_to";
                $whatzone = "TO";
                $ZoneToCalculate = "From";
            }


            //Get the Implicit zone that is defined in the Access_list
            $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='$tagname';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $member_lid = $getTagData['id'];
                $table_name = "tag";
                $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_tag WHERE member_lid='$member_lid' AND table_name='$table_name';");
                if ($getRules->num_rows > 0) {
                    while ($getRulesData = $getRules->fetch_assoc()) {
                        $rule_lid = $getRulesData['rule_lid'];
                        $addfrom[] = "('$source','$vsys','$zoneFrom','$rule_lid','$global_config_filename')";
                        $rules[] = $getRulesData['rule_lid'];
                    }
                }
                if (count($rules) > 0) {
                    $projectdb->query("DELETE FROM $table_direction WHERE rule_lid IN (" . implode(",", $rules) . ") ;");
                    unset($rules);
                }
                if (count($addfrom) > 0) {
                    $projectdb->query("INSERT INTO $table_direction (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $addfrom) . ";");
                    unset($addfrom);
                    add_log2('warning', 'Auto Zone Assign', 'Forcing Zone [' . $whatzone . '] to [' . $zoneFrom . '] on access-list [' . $tagname . '] based on access-group direction [' . $direction . ']', $source, 'No Action Required', '', '', '');
                }
            }

            //Calculate the Zone that is remaining

        }
    }
}

function get_twice_nats($cisco_config_file, $source, $vsys, $template,$isafter) {
    global $projectdb;
    global $global_config_filename;
    $nat_lid = "";
    $AddFrom=array();
    $AddSource=array();
    $AddTranslated=array();
    $AddDestination=array();

    $addNatRule = array();

    $ruleName = "";
    $op_zone_to = "";
    $op_service_lid = "";
    $op_service_table = "";
    $tp_dat_port = "";
    $tp_dat_address_lid = "";
    $tp_dat_address_table = "";
    $checkit = 0;
    $tp_sat_interface = "";
    $tp_dat_address_lid="";
    $tp_dat_address_table="";
    $op_service_table="";
    $op_service_lid="";
    $tp_sat_address_type="";
    $tp_sat_ipaddress="";
    $tp_sat_type="";
    $tp_dat_port="";
    $isdat="";
    $from="";

    #Nat Stuff Related
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $position = 1;
    }
    else {
        $ddata = $getPosition->fetch_assoc();
        $position = $ddata['t'] + 1;
    }
    if ($nat_lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $nat_lid = intval($getLID1['max']) + 1;
    }


    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = rtrim($names_line);

        if ( (preg_match("/^nat \(/", $names_line)) AND (
                (preg_match("/source static/",$names_line)) OR
                (preg_match("/source dynamic/",$names_line)) OR
                (preg_match("/destination static/",$names_line)) )){

            #nat (outside,inside) 1 source dynamic any PAT-ADDRESS-100 destination static SERVER-33.33.33.33 SERVER-192.168.100.200 service SMTP-SERVICE SMTP-SERVICE
            $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $zones = str_replace("(", '', $netObj[1]);
            $zones = str_replace(")", '', $zones);
            $zonesAll = explode(",", $zones);
            $from = $zonesAll[0];
            $op_zone_to = $zonesAll[1];
            $checkit = 0;

            if ($isafter=="after"){
                if ((preg_match("/ after-object \(/", $names_line)) OR (preg_match("/ after-auto \(/", $names_line)) OR (preg_match("/ after-auto source /", $names_line))){
                    echo "$names_line is After AUTO\n";
                }
                else{
                    echo "$names_line is ***NOT*** After AUTO\n";
                    continue;
                }
            }
            else{
                if ((preg_match("/ after-object \(/", $names_line)) OR (preg_match("/ after-auto \(/", $names_line)) OR (preg_match("/ after-auto source /", $names_line))){
                    continue;
                }
            }


            #nat (outside,inside) after-object 1 source dynamic any PAT-ADDRESS-100 destination static SERVER-33.33.33.33 SERVER-192.168.100.200 service SMTP-SERVICE SMTP-SERVICE
            if (isset($netObj[2]) && (($netObj[2]=="after-object") OR (is_numeric($netObj[2])) OR ($netObj[2]=="after-auto"))){unset($netObj[2]);$netObj = array_values($netObj);}
            if (is_numeric($netObj[2])){unset($netObj[2]);$netObj = array_values($netObj);}

            $ruleName = "Nat Twice $nat_lid";

            if (preg_match("/\binactive\b/", $names_line)) {
                $disabled = 1;
            } else {
                $disabled = 0;
            }
            #Description
            $isDescriptionin = array_search('description', $netObj);
            $descPos = $isDescriptionin + 1;
            if ($isDescriptionin != FALSE) {
                $description1 = array_slice($netObj, $descPos);
                $description=addslashes(implode(" ",$description1));
                $descPos = "";
                $description1="";
                $isDescriptionin = "";
            } else {
                $description = "";
            }
            $bidirectional=0;
            if (isset($netObj[2]) && ($netObj[2] == "source") AND ($netObj[3] == "dynamic")) {
                #get Real IP Address by name
                $ObjectNetworkName = $netObj[4];
                if ($ObjectNetworkName == "any") {}
                else {
                    $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                    if ($getRealIP->num_rows == 1) {
                        $getRealIPData = $getRealIP->fetch_assoc();
                        $RealIP = $getRealIPData['ipaddress'];
                        $RealIPCIDR = $getRealIPData['cidr'];
                        $member_lid = $getRealIPData['id'];
                        $table_name = "address";
                        $RealIPType = $getRealIPData['type'];
                        $AddSource[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    }
                    else {
                        $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $member_lid = $getRealIPData['id'];
                            $table_name = "address_groups_id";
                            $AddSource[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                    }
                    if (($from=="any") OR ($from=="")){
                        #Calculate the Zones based on Real IP
                        if ($table_name=="address_groups_id"){
                            $getMem=$projectdb->query("SELECT member_lid,table_name FROM address_groups WHERE lid='$member_lid' AND table_name !='address_groups_id' LIMIT 1;");
                            if ($getMem->num_rows==1){
                                $getMemData=$getMem->fetch_assoc();
                                $mem_member_lid=$getMemData['member_lid'];
                                $mem_table_name=$getMemData['table_name'];
                                $from = search_zone_address_one($mem_member_lid, $vsys, $source, $mem_table_name);
                            }
                        }
                        else{
                            $from = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                        }

                    }
                }

                $mappedIP = $netObj[5];
                if ($mappedIP==$ObjectNetworkName) {
                    # No Source NAT
                    $tp_sat_type="";
                }
                else {
                    # Source NAT
                    if ($mappedIP == "any") {}
                    elseif ($mappedIP == "interface") {
                        $getInterface=$projectdb->query("SELECT unitipaddress, unitname FROM interfaces WHERE source='$source' AND template='$template' AND zone='$op_zone_to' AND unitipaddress!='' LIMIT 1;");
                        if ($getInterface->num_rows==1){
                            $getInterfaceData=$getInterface->fetch_assoc();
                            $tp_sat_address_type="interface-address";
                            //$tp_sat_interface=$op_zone_to;
                            $tp_sat_interface = $getInterfaceData['unitname'];
                            $tp_sat_ipaddress=$getInterfaceData['unitipaddress'];
                            $tp_sat_type="dynamic-ip-and-port";
                        }
                        else{
                           echo "Problem 4186\n";
                        }
                    }
                    else {
                        if ($mappedIP=="pat-pool"){
                            $mappedIP=$netObj[6];
                            unset($netObj[6]);
                            $tp_sat_type="dynamic-ip-and-port";
                        }
                        else{
                            $tp_sat_type="dynamic-ip";
                        }
                        $getMappedIP = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_lid = $getMappedIPData['id'];
                            $dst_table = "address";
                            $tp_sat_address_type="translated-address";
                            $tp_sat_interface="";
                            $tp_sat_ipaddress="";
                            $AddTranslated[]="('$source','$vsys','$dst_lid','$dst_table','$nat_lid')";
                        }
                        else {
                            $getMappedIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getMappedIP->num_rows == 1) {
                                $getMappedIPData = $getMappedIP->fetch_assoc();
                                $dst_lid = $getMappedIPData['id'];
                                $dst_table = "address_groups_id";
                                $tp_sat_address_type="translated-address";
                                $tp_sat_interface="";
                                $tp_sat_ipaddress="";
                                $AddTranslated[]="('$source','$vsys','$dst_lid','$dst_table','$nat_lid')";
                            }
                            else{
                                echo "problem 4220\n";
                            }
                        }
                    }
                }
                unset($netObj[2]);unset($netObj[3]);unset($netObj[4]);unset($netObj[5]);$netObj = array_values($netObj);
            }

            if(isset($netObj[2]) && $netObj[2]== "flat"){
                add_log2('3', 'Reading NAT', 'Nat Rule ID [' . $nat_lid . '] containg unsuported "flat" option', $source, 'Review NAT rule','rules',$nat_lid,'nat_rules');
                unset($netObj[2]);
                $netObj = array_values($netObj);
            }

            if (isset($netObj[2]) && ($netObj[2] == "source") AND ( $netObj[3] == "static")) {
                #get Real IP Address by name
                $ObjectNetworkName = $netObj[4];
                if ($ObjectNetworkName == "any") {}
                else {
                    $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                    if ($getRealIP->num_rows == 1) {
                        $getRealIPData = $getRealIP->fetch_assoc();
                        $RealIP = $getRealIPData['ipaddress'];
                        $RealIPCIDR = $getRealIPData['cidr'];
                        $member_lid = $getRealIPData['id'];
                        $table_name = "address";
                        $RealIPType = $getRealIPData['type'];
                        $AddSource[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    }
                    else {
                        $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $member_lid = $getRealIPData['id'];
                            $table_name = "address_groups_id";
                            $AddSource[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                    }
                    if (($from=="any") OR ($from=="")){
                        #Calculate the Zones based on Real IP
                        if ($table_name=="address_groups_id"){
                            $getMem=$projectdb->query("SELECT member_lid,table_name FROM address_groups WHERE lid='$member_lid' AND table_name !='address_groups_id' LIMIT 1;");
                            if ($getMem->num_rows==1){
                                $getMemData=$getMem->fetch_assoc();
                                $mem_member_lid=$getMemData['member_lid'];
                                $mem_table_name=$getMemData['table_name'];
                                $from = search_zone_address_one($mem_member_lid, $vsys, $source, $mem_table_name);
                            }
                        }
                        else{
                            $from = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                        }

                    }
                }

                $mappedIP = $netObj[5];
                if ($mappedIP==$ObjectNetworkName) {
                    # No Source NAT
                    $tp_sat_type="";
                }
                else {
                    # Source NAT
                    $tp_sat_type="static-ip";
                    if (preg_match("/ unidirectional /",$names_line)){
                        $bidirectional=0;
                    }
                    else{
                        $bidirectional=1;
                    }
                    if ($mappedIP == "any") {}
                    elseif ($mappedIP == "interface") {
                        $getInterface=$projectdb->query("SELECT unitipaddress FROM interfaces WHERE source='$source' AND template='$template' AND zone='$op_zone_to' AND unitipaddress!='' LIMIT 1;");
                        if ($getInterface->num_rows==1){
                            $getInterfaceData=$getInterface->fetch_assoc();
                            //$tp_sat_address_type="interface-address";
                            //$tp_sat_interface=$op_zone_to;
                            $interface_ipaddress=explode("/",$getInterfaceData['unitipaddress']);
                            if ($interface_ipaddress[1]==""){$interface_ipaddress[1]=32;}
                            $getObj=$projectdb->query("SELECT id FROM address WHERE ipaddress='$interface_ipaddress[0]' AND cidr='$interface_ipaddress[1]' AND source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getObj->num_rows==1){
                                $getObjData=$getObj->fetch_assoc();
                                $int_member_lid=$getObjData['id'];
                                $int_table_name="address";
                                $AddTranslated[]="('$source','$vsys','$int_member_lid','$int_table_name','$nat_lid')";
                            }
                            else{
                                $name_int=$getInterfaceData['unitipaddress'];
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr,type,devicegroup) VALUES ('$source','$vsys','$name_int','$name_int','1','$interface_ipaddress[0]','$interface_ipaddress[1]','ip-netmask', '$global_config_filename')");
                                $int_member_lid=$projectdb->insert_id;
                                $int_table_name="address";
                                $AddTranslated[]="('$source','$vsys','$int_member_lid','$int_table_name','$nat_lid')";
                            }
                        }
                        else{
                            echo "problem 4309\n";
                        }
                    }
                    else {
                        # Pat pool should not be found here but. . .
                        if ($mappedIP=="pat-pool"){
                            $mappedIP=$netObj[6];
                            unset($netObj[6]);
                        }

                        $getMappedIP = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' AND vtype='object' LIMIT 1;");
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_lid = $getMappedIPData['id'];
                            $dst_table = "address";
                            $tp_sat_address_type="translated-address";
                            $tp_sat_interface="";
                            $tp_sat_ipaddress="";
                            $AddTranslated[]="('$source','$vsys','$dst_lid','$dst_table','$nat_lid')";
                        }
                        else {
                            $getMappedIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getMappedIP->num_rows == 1) {
                                $getMappedIPData = $getMappedIP->fetch_assoc();
                                $dst_lid = $getMappedIPData['id'];
                                $dst_table = "address_groups_id";
                                $tp_sat_address_type="translated-address";
                                $tp_sat_interface="";
                                $tp_sat_ipaddress="";
                                $AddTranslated[]="('$source','$vsys','$dst_lid','$dst_table','$nat_lid')";
                            }
                            else{
                                echo "problem 4340\n";
                            }
                        }
                    }
                }
                unset($netObj[2]);unset($netObj[3]);unset($netObj[4]);unset($netObj[5]);$netObj = array_values($netObj);
            }

            if (isset($netObj[2]) && $netObj[2]=="round-robin"){
                unset($netObj[2]);$netObj = array_values($netObj);
            }

            if (isset($netObj[2]) && ($netObj[2]=="destination") AND ($netObj[3]=="static")){
                #get Real IP Address by name
                $ObjectNetworkName = $netObj[4];
                if ($ObjectNetworkName == "any") {}
                else {
                    $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                    if ($getRealIP->num_rows == 1) {
                        $getRealIPData = $getRealIP->fetch_assoc();
                        $RealIP = $getRealIPData['ipaddress'];
                        $RealIPCIDR = $getRealIPData['cidr'];
                        $member_lid = $getRealIPData['id'];
                        $table_name = "address";
                        $RealIPType = $getRealIPData['type'];
                        $AddDestination[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    }
                    else {
                        $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $member_lid = $getRealIPData['id'];
                            $table_name = "address_groups_id";
                            $AddDestination[]="('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                    }
                    #Calculate the Zones based on Real IP

                    if ($table_name=="address_groups_id"){
                        $getMem=$projectdb->query("SELECT member_lid,table_name FROM address_groups WHERE lid='$member_lid' AND table_name !='address_groups_id' LIMIT 1;");
                        if ($getMem->num_rows==1){
                            $getMemData=$getMem->fetch_assoc();
                            $mem_member_lid=$getMemData['member_lid'];
                            $mem_table_name=$getMemData['table_name'];
                            $op_zone_to = search_zone_address_one($mem_member_lid, $vsys, $source, $mem_table_name);
                        }
                    }
                    else{
                        $op_zone_to = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                    }


                }

                $mappedIP = $netObj[5];
                if ($mappedIP==$ObjectNetworkName) {
                    # No Source NAT
                    $isdat=0;
                }
                else {
                    # Source NAT
                    $isdat=1;
                    if ($mappedIP == "any") {}
                    elseif ($mappedIP == "interface") {
                        $getInterface=$projectdb->query("SELECT unitipaddress FROM interfaces WHERE source='$source' AND template='$template' AND zone='$op_zone_to' AND unitipaddress!='' LIMIT 1;");
                        if ($getInterface->num_rows==1){
                            $getInterfaceData=$getInterface->fetch_assoc();
                            $datipaddress=explode("/",$getInterfaceData['unitipaddress']);
                            $ipaddress=$datipaddress[0];
                            $cidr=$datipaddress[1];
                            $ipandcidr=$getInterfaceData['unitipaddress'];
                            $getInt=$projectdb->query("SELECT id FROM address WHERE ipaddress='$ipaddress' AND cidr='$cidr' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getInt->num_rows==1){
                                $getIntData=$getInt->fetch_assoc();
                                $tp_dat_address_lid=$getIntData['id'];
                                $tp_dat_address_table="address";
                            }
                            else{
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,type,description,dummy,devicegroup) VALUES ('$source','$vsys','$ipandcidr','$ipandcidr','$ipaddress','$cidr','ip-netmask','Created by the MT3','1','$global_config_filename')");
                                $tp_dat_address_lid=$projectdb->insert_id;
                                $tp_dat_address_table="address";
                            }
                        }
                    }
                    else {
                        $getMappedIP = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $tp_dat_address_lid=$getMappedIPData['id'];
                            $tp_dat_address_table="address";
                        }

                    }
                }
                unset($netObj[2]);unset($netObj[3]);unset($netObj[4]);unset($netObj[5]);$netObj = array_values($netObj);
            }

            if (isset($netObj[2]) && $netObj[2] == "service") {
                #Destination Port Real
                $real_port = $netObj[3];
                $getdstPort = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$real_port' AND source='$source' AND vsys='$vsys';");
                if ($getdstPort->num_rows == 1) {
                    $getdstPortData = $getdstPort->fetch_assoc();
                    $op_service_lid = $getdstPortData['id'];
                    $op_service_table="services";

                } else {
                    if ($real_port=="any"){}
                    else{
                        add_log2('3', 'Reading TWICE NAT', 'Unknown Service [' . $real_port . '] on Nat Rule ID [' . $nat_lid . ']', $source, 'Using first service port. Change it from the GUI','rules',$nat_lid,'nat_rules');
                        $op_service_lid = 1;
                        $op_service_table = 'services';
                        $checkit = 1;
                    }


                }

                #Destination Port Mapped
                $dst_port = $netObj[4];
                if ($dst_port==$real_port){
                    # No translate Port
                    $tp_dat_port="";
                }
                else{
                    $getdstPort = $projectdb->query("SELECT id,dport FROM services WHERE BINARY name_ext='$dst_port' AND source='$source' AND vsys='$vsys';");
                    if ($getdstPort->num_rows == 1) {
                        $getdstPortData = $getdstPort->fetch_assoc();
                        $tp_dat_port_id = $getdstPortData['id'];
                        $dport = $getdstPortData['dport'];
                        if (is_numeric($dport)){
                            $tp_dat_port=$dport;
                        }
                        else {
                            add_log2('3', 'Reading TWICE NAT', 'Invalid Service [' . $dst_port . '] port ['.$dport.'] on Nat Rule ID [' . $nat_lid . ']', $source, 'Add the right Port from the GUI','rules',$nat_lid,'nat_rules');
                            $tp_dat_port="";
                        }
                    } else {
                        if ($dst_port=="any"){$tp_dat_port="";}
                        else{
                            add_log2('3', 'Reading TWICE NAT', 'Unknown Service [' . $dst_port . '] on Nat Rule ID [' . $nat_lid . ']', $source, 'Add the right Port from the GUI','rules',$nat_lid,'nat_rules');
                            $tp_dat_port="";
                        }

                    }

                }
            }

            if ($op_zone_to == "any") {
                $op_zone_to = "";
                $checkit = 1;
                add_log2('warning', 'Reading Objects Nat', 'Nat RuleID [' . $nat_lid . '] has destination Zone as ANY. Fix it before to finish', $source, 'Check it manually', 'rules', $nat_lid, 'nat_rules');
            }
            if (($from=="any") AND ($op_zone_to!="")){$from=$op_zone_to;$AddFrom[]="('$vsys','$source','$from','$nat_lid')";}
            else{$AddFrom[]="('$vsys','$source','$from','$nat_lid')";}

            $addNatRule[]="('$bidirectional','".normalizeComments($description)."','$source','$vsys','$nat_lid','$position','$disabled','$op_zone_to','$ruleName','$checkit','$tp_sat_address_type','$tp_sat_interface','$tp_sat_ipaddress','$tp_sat_type','$isdat','$tp_dat_address_lid','$tp_dat_address_table','$tp_dat_port','$op_service_lid','$op_service_table')";

            $nat_lid++;
            $position++;
            $ruleName = "";
            $op_zone_to = "";
            $op_service_lid = "";
            $op_service_table = "";
            $tp_dat_port = "";
            $tp_dat_address_lid = "";
            $tp_dat_address_table = "";
            $checkit = 0;
            $tp_sat_interface = "";
            $tp_dat_address_lid="";
            $tp_dat_address_table="";
            $op_service_table="";
            $op_service_lid="";
            $tp_sat_address_type="";
            $tp_sat_ipaddress="";
            $tp_sat_type="";
            $tp_dat_port="";
            $isdat="";
            $from="";

        }

    }
    if (count($addNatRule)>0){
        $projectdb->query("INSERT INTO nat_rules (tp_sat_bidirectional,description,source,vsys,id,position,disabled,op_zone_to,name,checkit,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_sat_type,is_dat,tp_dat_address_lid,tp_dat_address_table,tp_dat_port,op_service_lid,op_service_table) VALUES ".implode(",",$addNatRule).";");
        unset($addNatRule);

        if (count($AddFrom)>0){
            $projectdb->query("INSERT INTO nat_rules_from (vsys,source,name,rule_lid) VALUES ".implode(",",$AddFrom).";");
            unset($AddFrom);
        }

        if (count($AddSource)>0){
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES ".implode(",",$AddSource).";");
            unset($AddSource);
        }

        if (count($AddDestination)>0){
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES ".implode(",",$AddDestination).";");
            unset($AddDestination);
        }

        if (count($AddTranslated)>0){
            $query = "INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES ".implode(",",$AddTranslated).";";
            $projectdb->query($query);
            unset($AddTranslated);
        }


    }

}

function get_objects_nat($cisco_config_file, $source, $vsys) {
    global $projectdb;
    global $global_config_filename;
    $isObjectNetwork = 0;
    $nat_lid = "";
    $addRule = [];
    $addDestination = [];
    $addFROM = [];
    $addSNAT = [];
    $addNATFrom = [];
    $addNATTranslatedAddress = [];
    $addNatSrc = [];

    #Nat Stuff Related
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $position = 1;
    } else {
        $ddata = $getPosition->fetch_assoc();
        $position = $ddata['t'] + 1;
    }
    if ($nat_lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $nat_lid = intval($getLID1['max']) + 1;
    }

//    $my = fopen("/tmp/nat_cisco.txt","a");
    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if ($isObjectNetwork == 1) {
            if (preg_match("/^nat /i", $names_line)) {
                #nat (services,outside) static x.x.x.x service tcp smtp smtp (DNAT)
                #nat (services,outside) static y.y.y.y (SNAT static)
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $zones = str_replace("(", '', $netObj[1]);
                $zones = str_replace(")", '', $zones);
                $zonesAll = explode(",", $zones);
                $from = $zonesAll[0];
                $to = $zonesAll[1];
                $checkit = 0;
                if ($to == "any") {
                    $to = "";
                    $checkit = 1;
                    add_log2('warning', 'Reading Objects Nat', 'Nat RuleID [' . $nat_lid . '] has destination Zone as ANY. Fix it before to finish', $source, 'Check it manually', 'rules', $nat_lid, 'nat_rules');
                }

                #$ObjectNetworkName = $netObj[4];

                $ruleName = "AutoNat $ObjectNetworkName";
                $Status = 0; #Rule Enabled by default
                if ((isset($netObj[4])) AND ( isset($netObj[4]) AND $netObj[4] == "net-to-net")){

                }
//                if (isset($netObj[4]) AND ( $netObj[4] != "dns") AND ($netObj[4] != "route-lookup") AND $netObj[4] != "no-proxy-arp") {

                    if (($netObj[2] == "static") AND ( isset($netObj[4]) AND $netObj[4] == "service")) {
                        //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid is static * service\n"); fclose($my);
                        #get Real IP Address by name
                        $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $RealIP = $getRealIPData['ipaddress'];
                            $RealIPCIDR = $getRealIPData['cidr'];
                            $tp_dat_address_lid = $getRealIPData['id'];
                            $tp_dat_address_table = "address";
                        }

                        $protocol = $netObj[5];
                        $src_port = trim($netObj[7]);
                        $addFROM[] = "('$source','$vsys','$nat_lid','$to')";
                        if (is_numeric($src_port)) {
                            $getsrcPort = $projectdb->query("SELECT id FROM services WHERE dport='$src_port' AND protocol='$protocol' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getsrcPort->num_rows == 1) {
                                $getsrcPortData = $getsrcPort->fetch_assoc();
                                $op_service_lid = $getsrcPortData['id'];
                            } else {
                                $projectdb->query("INSERT INTO services (name_ext,name,dport,protocol,source,vsys) VALUES ('$protocol-$src_port','$protocol-$src_port','$src_port','$protocol','$source','$vsys');");
                                $op_service_lid = $projectdb->insert_id;
                            }
                        }
                        else {
                            $getsrcPort = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$src_port' AND protocol='$protocol' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getsrcPort->num_rows == 1) {
                                $getsrcPortData = $getsrcPort->fetch_assoc();
                                $op_service_lid = $getsrcPortData['id'];
                            } else {
                                $projectdb->query("INSERT INTO services (name_ext,name,dport,protocol,source,vsys) VALUES ('$src_port-$protocol','$src_port-$protocol','65000','$protocol','$source','$vsys');");
                                $op_service_lid = $projectdb->insert_id;
                                add_log('error', 'Reading Objects NAT', 'Unknown Service [' . $src_port . '] with Protocol ['.$protocol.'] on Nat Rule ID [' . $nat_lid . ']', $source, 'Using 6500 port. Change it from the GUI');

                            }
                        }

                        #Destination Port
                        $dst_port = $netObj[6];
                        if (!is_numeric($dst_port)) {
                            $getdstPort = $projectdb->query("SELECT dport FROM services WHERE ( (BINARY name_ext='$dst_port') OR (BINARY name_ext='$dst_port-$protocol')) AND protocol='$protocol' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getdstPort->num_rows == 1) {
                                $getdstPortData = $getdstPort->fetch_assoc();
                                $tp_dat_port = $getdstPortData['dport'];
                            } else {
                                add_log('error', 'Reading Objects NAT', 'Unknown Service [' . $dst_port . '] on Nat Rule ID [' . $nat_lid . ']', $source, 'Using 6500 port. Change it from the GUI');
                                $tp_dat_port = "65000";
                            }
                        }
                        else{
                            $tp_dat_port=$dst_port;
                        }

                        # Mapped IP check if its IP or Object
                        $mappedIP = $netObj[3];
                        if ($mappedIP == "interface") {
                            //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid is static interface service\n"); fclose($my);
                            $query ="SELECT unitipaddress, unitname FROM interfaces WHERE BINARY zone='$to' AND source='$source' LIMIT 1";
                            //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "     $query\n"); fclose($my);
                            $getInterface = $projectdb->query($query);
                            //$getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE source='$source' AND vsys='$vsys' AND BINARY name='$to';");
                            if ($getInterface->num_rows == 1) {
                                $getInterfaceData = $getInterface->fetch_assoc();
                                $getInterfaceIP = explode("/", $getInterfaceData['unitipaddress']);
                                //$unitIpAddress = $getInterfaceData['unitipaddress'];
                                //$unitName = $getInterfaceData['unitname'];
                                $getInterfaceNetwork = $getInterfaceIP[0];
                                $getInterfaceCidr = "32"; # Fixed?
                                $getObject = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$getInterfaceNetwork' AND cidr='$getInterfaceCidr';");
                                if ($getObject->num_rows == 1) {
                                    $getObjectData = $getObject->fetch_assoc();
                                    $dst_lid = $getObjectData['id'];
                                } else {
                                    if ($getInterfaceCidr == "32") {
                                        $type = "ip-netmask";
                                        $prefix = "H";
                                        $newname = "$prefix-$getInterfaceNetwork";
                                    } else {
                                        $type = "ip-netmask";
                                        $prefix = "N";
                                        $newname = "$prefix-$getInterfaceNetwork-$getInterfaceCidr";
                                    }
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr, devicegroup) VALUES ('$source','$vsys','$newname','$newname','$getInterfaceNetwork','ip-netmask','$getInterfaceCidr','$global_config_filename')");
                                    $dst_lid = $projectdb->insert_id;
                                }
                            }
                        }
                        elseif (ip_version($mappedIP) == "noip") {
                            //This is a label

                            // Let's check if this label has been provided with a CIDR
                            $mappedCIDR = $RealIPCIDR;  //By default, we consider the CIDR should be the one from the source

                            //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid is static <object> service\n"); fclose($my);
                            $getMappedIP = $projectdb->query("SELECT id, cidr FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' AND (vtype='label' OR vtype='object') LIMIT 1;");
                            if ($getMappedIP->num_rows == 1) {
                                $getMappedIPData = $getMappedIP->fetch_assoc();
                                $dst_lid = $getMappedIPData['id'];
                                $dst_cidr = $getMappedIPData['cidr'];
                                if($dst_cidr == 0 && $RealIPCIDR == 32){
                                    //Update the CIDR
                                    $query = "UPDATE address set cidr=32 WHERE id=$dst_lid";
    //                                    echo "NAT for $ObjectNetworkName. Label $mappedIP found with cidr 0. Let's update. $query\n";
                                    $projectdb->query($query);
                                }
                                elseif($dst_cidr == 32 && $mappedCIDR == 32){
                                    //We can use this label, that will become a valid object
    //                                    echo "NAT for $ObjectNetworkName. Label $mappedIP found with cidr 32. Nothing to do\n";
                                }
                                else{
                                    //We need to look for an object with the name-cidr and if it doesnt exist, clone the label and make it an object
    //                                    echo "NAT for $ObjectNetworkName. Label $mappedIP not found with cidr 32 or 0.";
                                    $newname = $mappedIP."-".$mappedCIDR;
                                    $query = "SELECT id,ipaddress,cidr,type,vtype FROM address WHERE BINARY name_ext='$newname' AND source='$source' AND vsys='$vsys' AND vtype='object' LIMIT 1;";
                                    $result = $projectdb->query($query);
                                    if ($getMappedIP->num_rows == 1){
    //                                        echo "But found an object with name $newname\n";
                                        $getMappedIPData = $getMappedIP->fetch_assoc();
                                        $dst_ip = $getMappedIPData['ipaddress'];
                                        $dst_lid = $getMappedIPData['id'];
                                        $dst_table = "address";
                                        $dst_cidr = $getMappedIPData['cidr'];
                                        $dst_type = $getMappedIPData['type'];
                                    }
                                    else {
    //                                        echo "We create $newname\n";
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr,vtype, devicegroup) VALUES ('$source','$vsys','$newname','$newname','$mappedIP','ip-netmask','$mappedCIDR','object','$global_config_filename')");
                                        $dst_lid = $projectdb->insert_id;
                                        $dst_table = "address";
                                        $dst_cidr = "32";
                                        $dst_type = 'ip-netmask';
                                    }

                                }
                            }
                            else{
                                //TODO: Report and error here
                                $dst_lid = -1;
                            }
                        }

                        else {
                            //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid is static <IP> service\n"); fclose($my);
                            $getMappedIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$mappedIP' AND cidr='$RealIPCIDR' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getMappedIP->num_rows == 1) {
                                $getMappedIPData = $getMappedIP->fetch_assoc();
                                $dst_lid = $getMappedIPData['id'];
                            } else {
                                if ($RealIPCIDR == "32") {
                                    $type = "ip-netmask";
                                    $prefix = "H";
                                    $newname = "$prefix-$mappedIP";
                                } else {
                                    $type = "ip-netmask";
                                    $prefix = "N";
                                    $newname = "$prefix-$mappedIP-$RealIPCIDR";
                                }
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr, devicegroup) VALUES ('$source','$vsys','$newname','$newname','$mappedIP','ip-netmask','$RealIPCIDR','$global_config_filename')");
                                $dst_lid = $projectdb->insert_id;
                            }
                        }
                        if (isset($dst_lid) && $dst_lid!=0) $addDestination[] = "('$source','$vsys','$nat_lid','$dst_lid','address')";
                        $addRule[] = "('','$nat_lid','$source','$vsys','$ruleName',1,'$position','$ruleName','$to','$op_service_lid','services','$tp_dat_port','$tp_dat_address_lid','$tp_dat_address_table')";
                    }
//                }
                elseif ($netObj[2] == "static") {
//                    fwrite($my, $names_line."\n");
                    #get Real IP Address by name
                    $dst_ip = "";
                    $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                    if ($getRealIP->num_rows == 1) {
                        $getRealIPData = $getRealIP->fetch_assoc();
                        $RealIP = $getRealIPData['ipaddress'];
                        $RealIPCIDR = $getRealIPData['cidr'];
                        $tp_dat_address_lid = $getRealIPData['id'];
                        $tp_dat_address_table = "address";
                        $RealIPType = $getRealIPData['type'];
                    }
                    else {
                        $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $tp_dat_address_lid = $getRealIPData['id'];
                            $tp_dat_address_table = "address_groups_id";
                        }
                        else{
                        }
                    }

                    $mappedIP = $netObj[3];
//                    fwrite($my, "  ".$mappedIP.": ".ip_version($mappedIP)."\n");
                    if (ip_version($mappedIP) == "noip") {
                        //This is a label or an object
//                        fwrite($my, "  $mappedIP is an label or an object\n");
                        // Let's check if this label has been provided with a CIDR
                        $mappedCIDR = $RealIPCIDR;  //By default, we consider the CIDR should be the one from the source
                        if(isset($netObj[4])){
                            if (cidr_match($netObj[4])){
                                $mappedCIDR =  mask2cidrv4($netObj[4]);
                            }
                        }

                        $getMappedIP = $projectdb->query("SELECT id,ipaddress,cidr,type,vtype FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' AND vtype='object' LIMIT 1;");
                        if ($getMappedIP->num_rows == 1) {
//                            fwrite($my, "  $mappedIP is found as an address object\n");
                            //                                    echo "But found an object with name $newname\n";
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_ip = $getMappedIPData['ipaddress'];
                            $dst_lid = $getMappedIPData['id'];
//                            fwrite($my, "  $mappedIP is address:" . $dst_lid . "\n");
                            $dst_table = "address";
                            $dst_cidr = $getMappedIPData['cidr'];
                            $dst_type = $getMappedIPData['type'];
                        }
                        else {
                            $getMappedIP = $projectdb->query("SELECT id,ipaddress,cidr,type,vtype FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' AND vtype='label' LIMIT 1;");
                            if ($getMappedIP->num_rows == 1) {
//                                fwrite($my, "  $mappedIP is found as an address label\n");
                                $getMappedIPData = $getMappedIP->fetch_assoc();
                                $dst_ip = $getMappedIPData['ipaddress'];
                                $dst_lid = $getMappedIPData['id'];
                                $dst_table = "address";
//                                fwrite($my, "  $mappedIP is address:" . $dst_lid . "\n");
                                $dst_cidr = $getMappedIPData['cidr'];
                                $dst_type = $getMappedIPData['type'];
                                if ($dst_cidr == 0 && $RealIPCIDR == 32) {
                                    //Update the CIDR
                                    $query = "UPDATE address set cidr=32 WHERE id=$dst_lid";
                                    //                                echo "NAT for $ObjectNetworkName. Label $mappedIP found with cidr 0. Let's update. $query\n";
                                    $projectdb->query($query);
                                } elseif ($dst_cidr == 32 && $mappedCIDR == 32) {
                                    //We can use this label, that will become a valid object
                                    //                                echo "NAT for $ObjectNetworkName. Label $mappedIP found with cidr 32. Nothing to do\n";
                                } else {
                                    //We need to look for an object with the name-cidr and if it doesnt exist, clone the label and make it an object
                                    //                                echo "NAT for $ObjectNetworkName. Label $mappedIP not found with cidr 32 or 0.";
                                    $newname = $mappedIP . "-" . $mappedCIDR;
                                    $query = "SELECT id,ipaddress,cidr,type,vtype FROM address WHERE BINARY name_ext='$newname' AND source='$source' AND vsys='$vsys' AND vtype='object' LIMIT 1;";
                                    $result = $projectdb->query($query);
//                                    fwrite($my, "$mappedIP is NOT CIDR=32\n");
                                    if ($getMappedIP->num_rows == 1) {
//                                        fwrite($my, "  $mappedIP is found\n");
                                        //                                    echo "But found an object with name $newname\n";
                                        $getMappedIPData = $getMappedIP->fetch_assoc();
                                        $dst_ip = $getMappedIPData['ipaddress'];
                                        $dst_lid = $getMappedIPData['id'];
//                                        fwrite($my, "  $mappedIP is address:" . $dst_lid . "\n");
                                        $dst_table = "address";
                                        $dst_cidr = $getMappedIPData['cidr'];
                                        $dst_type = $getMappedIPData['type'];
                                    } else {
                                        //                                    echo "We create $newname\n";
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr,vtype, devicegroup) VALUES ('$source','$vsys','$newname','$newname','$mappedIP','ip-netmask','$mappedCIDR','object','$global_config_filename')");
                                        $dst_lid = $projectdb->insert_id;
//                                        fwrite($my, "  $mappedIP is NOT found\n");
//                                        fwrite($my, "  $mappedIP is address:" . $dst_lid . "\n");
                                        $dst_table = "address";
                                        $dst_cidr = "32";
                                        $dst_type = 'ip-netmask';
                                    }

                                }
                                //                            echo "\n\n";
                            } else {
//                                fwrite($my, "  $mappedIP is NOT found as an address object\n");
                                $getMappedIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if ($getMappedIP->num_rows == 1) {
//                                    fwrite($my, "  $mappedIP is found as an address-group object\n");
                                    $getMappedIPData = $getMappedIP->fetch_assoc();
                                    $dst_lid = $getMappedIPData['id'];
//                                    fwrite($my, "  $mappedIP is address-group:" . $dst_lid . "\n");
                                    $dst_table = "address_groups_id";
                                }
                            }
                        }
                    }
                    else {
//                        fwrite($my, "  $mappedIP is an IP\n");
                        $getMappedIP = $projectdb->query("SELECT id,cidr,type FROM address WHERE ipaddress='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_lid = $getMappedIPData['id'];
                            $dst_table = "address";
                            $dst_cidr = $getMappedIPData['cidr'];
                            $dst_type = $getMappedIPData['type'];
                        }
                        else {
                            if (($RealIPCIDR == "32") OR ( $RealIPCIDR == "")) {
                                $type = "ip-netmask";
                                $prefix = "H";
                                $newname = "$prefix-$mappedIP";
                                $RealIPCIDR2 = "32";
                            } else {
                                $type = "ip-netmask";
                                $prefix = "N";
                                $newname = "$prefix-$mappedIP-$RealIPCIDR";
                                $RealIPCIDR2 = $RealIPCIDR;
                            }
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr, devicegroup) VALUES ('$source','$vsys','$newname','$newname','$mappedIP','ip-netmask','$RealIPCIDR2','$global_config_filename')");
                            $dst_lid = $projectdb->insert_id;
                            $dst_table = "address";
                            $dst_cidr = "32";
                            $dst_type = 'ip-netmask';
                        }
                    }

                    #Warning regarding DNS translation
                    if (isset($netObj[4]) == "dns") {
                        add_log2('warning', 'Reading Objects Nat', 'Nat RuleID [' . $nat_lid . '] has an unsupported feature. Object was [' . $ObjectNetworkName . ']. DNS translation', $source, 'Check it manually', 'rules', $nat_lid, 'nat_rules');
                    }

                    # Fix cidr=0 change by 32
                    if ($dst_cidr==0){$dst_cidr=32;}

                    if (($tp_dat_address_table == "address") AND ( $dst_table == "address")) {
                        if (($tp_dat_address_lid == $dst_lid) OR ( $RealIP == $dst_ip)) {
                            #Identity Nat
                            $ruleName = "IdentityNat $ObjectNetworkName";
                            $addNATFrom[] = "('$source','$vsys','$nat_lid','$from')";
                            $addNatSrc[] = "('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                            $addRule[] = "('','$nat_lid','$source','$vsys','$ruleName',0,'$position','No nat performed.','$to','$op_service_lid','','','','')";
                        } else {
                            if ($RealIPCIDR == $dst_cidr) {
                                $addNatSrc[] = "('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                                $addSNAT[] = "('$checkit','$source','$vsys','$nat_lid','$position','$ruleName','$Status','$to','',0,'','','static-ip','translated-address','','',1,'','None','','')";
                                $addNATFrom[] = "('$source','$vsys','$nat_lid','$from')";
                                $addNATTranslatedAddress[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                            } elseif ($dst_cidr == "32") {
                                $addNatSrc[] = "('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                                $addSNAT[] = "('$checkit','$source','$vsys','$nat_lid','$position','$ruleName','$Status','$to','',0,'','','dynamic-ip-and-port','translated-address','','',0,'','None','','')";
                                $addNATFrom[] = "('$source','$vsys','$nat_lid','$from')";
                                $addNATTranslatedAddress[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                            } else {
                                add_log2('error', 'Reading Objects Nat', 'Nat RuleID [' . $nat_lid . '] was not migrated. [' . $names_line . ']. '.$RealIPCIDR.' and '.$dst_cidr.'', $source, 'The original rule seems malformed and could not be migrated. Please review the use of original rule with the firewall administrator. Send an email with this line to fwmigrate@paloaltonetworks.com if this NAT should have been migrated.', 'rules', $nat_lid, 'nat_rules');
                            }
                        }
                    } else {
                        #Cant assing a group as a source OP with static-ip
                        add_log2('error', 'Reading Objects Nat', 'Nat RuleID [' . $nat_lid . '] is trying to apply a group to the translated packet. [' . $names_line . '].', $source, 'Rule not imported.', 'rules', $nat_lid, 'nat_rules');
                    }
                }
                elseif (($netObj[2] == "dynamic") AND ( $netObj[3] == "interface")) {
                    #nat (inside,outside) dynamic interface

                    //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid is dynamic interface\n"); fclose($my);
                    $query ="SELECT unitipaddress, unitname FROM interfaces WHERE BINARY zone='$to' AND source='$source' LIMIT 1";
                    //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "     $query\n"); fclose($my);
                    $getInterface = $projectdb->query($query);
                    if ($getInterface->num_rows == 1) {
                        $getInterfaceData = $getInterface->fetch_assoc();
                        $unitIpAddress = $getInterfaceData['unitipaddress'];
                        $unitName = $getInterfaceData['unitname'];
                    }

                    #get Real IP Address by name
                    $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                    if ($getRealIP->num_rows == 1) {
                        $getRealIPData = $getRealIP->fetch_assoc();
                        $RealIP = $getRealIPData['ipaddress'];
                        $RealIPCIDR = $getRealIPData['cidr'];
                        $tp_dat_address_lid = $getRealIPData['id'];
                        $tp_dat_address_table = "address";
                        $RealIPType = $getRealIPData['type'];
                    } else {
                        $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $tp_dat_address_lid = $getRealIPData['id'];
                            $tp_dat_address_table = "address_groups_id";
                        }
                    }

                    //AQUEST ES UN ERROR A PROPOSIT PERQUE TROBIS RAPID LA LINIA. SIMPLEMENT, BORRA AQUESTA LINIA
                    $addNatSrc[] = "('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                    //COMPTE AMB EL CAMP $unitName i $unitIpAddress, perque crec que no s'han declarar als static o dyanimc interface
                    //INSERT INTO nat_rules (checkit,source,vsys,id,position,name,disabled,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_ipaddress,description,tp_sat_bidirectional,tp_sat_interface,tp_fallback_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback) VALUES " . implode(",", $addSNAT) . ";");
                    //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "NAT: $nat_lid\n"); fclose($my);
                    //$my = fopen("ciscoNat.txt", "a"); fwrite($my, "('$checkit','$source','$vsys','$nat_lid','$position','$ruleName','$Status','$to','',0,'','','dynamic-ip-and-port','interface-address','$unitIpAddress','',0,'$unitName','None','','')\n");            fclose($my);
                    $addSNAT[] = "('$checkit','$source','$vsys','$nat_lid','$position','$ruleName','$Status','$to','any',0,'','','dynamic-ip-and-port','interface-address','$unitIpAddress','',0,'$unitName','None','','')";
                    //$addSNAT[] = "('$checkit','$source','$vsys','$nat_lid','$position','$ruleName','$Status','$to','',0,'','','dynamic-ip-and-port','interface-address','','',0,'$to','None','','')";
                    $addNATFrom[] = "('$source','$vsys','$nat_lid','$from')";
                    //$addNATTranslatedAddress[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                }
                elseif (($netObj[2] == "dynamic") AND ( $netObj[3] == "pat-pool")) {
                    #nat (inside,outside) dynamic pat-pool IPv4_POOL
                    #get Real IP Address by name
                    $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                    if ($getRealIP->num_rows == 1) {
                        $getRealIPData = $getRealIP->fetch_assoc();
                        $RealIP = $getRealIPData['ipaddress'];
                        $RealIPCIDR = $getRealIPData['cidr'];
                        $tp_dat_address_lid = $getRealIPData['id'];
                        $tp_dat_address_table = "address";
                        $RealIPType = $getRealIPData['type'];
                    } else {
                        $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $tp_dat_address_lid = $getRealIPData['id'];
                            $tp_dat_address_table = "address_groups_id";
                        }
                    }

                    $mappedIP = $netObj[3];
                    if (ip_version($mappedIP) == "noip") {
                        $getMappedIP = $projectdb->query("SELECT id,ipaddress,cidr,type FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_ip = $getMappedIPData['ipaddress'];
                            $dst_lid = $getMappedIPData['id'];
                            $dst_table = "address";
                            $dst_cidr = $getMappedIPData['cidr'];
                            $dst_type = $getMappedIPData['type'];
                        } else {
                            $getMappedIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getMappedIP->num_rows == 1) {
                                $getMappedIPData = $getMappedIP->fetch_assoc();
                                $dst_lid = $getMappedIPData['id'];
                                $dst_table = "address_groups_id";
                            }
                        }
                    } else {
                        $getMappedIP = $projectdb->query("SELECT id,cidr,type FROM address WHERE ipaddress='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_lid = $getMappedIPData['id'];
                            $dst_table = "address";
                            $dst_cidr = $getMappedIPData['cidr'];
                            $dst_type = $getMappedIPData['type'];
                        } else {
                            if (($RealIPCIDR == "32") OR ( $RealIPCIDR == "")) {
                                $type = "ip-netmask";
                                $prefix = "H";
                                $newname = "$prefix-$mappedIP";
                                $RealIPCIDR2 = "32";
                            } else {
                                $type = "ip-netmask";
                                $prefix = "N";
                                $newname = "$prefix-$mappedIP-$RealIPCIDR";
                                $RealIPCIDR2 = $RealIPCIDR;
                            }
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr, devicegroup) VALUES ('$source','$vsys','$newname','$newname','$mappedIP','ip-netmask','$RealIPCIDR2','$global_config_filename')");
                            $dst_lid = $projectdb->insert_id;
                            $dst_table = "address";
                            $dst_cidr = "32";
                            $dst_type = 'ip-netmask';
                        }
                    }
                    $addNatSrc[] = "('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                    $addSNAT[] = "('$checkit','$source','$vsys','$nat_lid','$position','$ruleName','$Status','$to','',0,'','','dynamic-ip-and-port','translated-address','','',0,'','None','','')";
                    $addNATFrom[] = "('$source','$vsys','$nat_lid','$from')";
                    $addNATTranslatedAddress[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                }
                elseif ($netObj[2] == "dynamic") {
                    #nat (inside,outside) dynamic 10.2.2.2
                    #get Real IP Address by name
                    $getRealIP = $projectdb->query("SELECT ipaddress,cidr,id,type FROM address WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys' AND vtype='object';");
                    if ($getRealIP->num_rows == 1) {
                        $getRealIPData = $getRealIP->fetch_assoc();
                        $RealIP = $getRealIPData['ipaddress'];
                        $RealIPCIDR = $getRealIPData['cidr'];
                        $tp_dat_address_lid = $getRealIPData['id'];
                        $tp_dat_address_table = "address";
                        $RealIPType = $getRealIPData['type'];
                    } else {
                        $getRealIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$ObjectNetworkName' AND source='$source' AND vsys='$vsys';");
                        if ($getRealIP->num_rows == 1) {
                            $getRealIPData = $getRealIP->fetch_assoc();
                            $tp_dat_address_lid = $getRealIPData['id'];
                            $tp_dat_address_table = "address_groups_id";
                        }
                    }

                    $mappedIP = $netObj[3];
                    if (ip_version($mappedIP) == "noip") {
                        $getMappedIP = $projectdb->query("SELECT id,ipaddress,cidr,type FROM address WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        $nat_type = "dynamic-ip";
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_ip = $getMappedIPData['ipaddress'];
                            $dst_lid = $getMappedIPData['id'];
                            $dst_table = "address";
                            $dst_cidr = $getMappedIPData['cidr'];
                            $dst_type = $getMappedIPData['type'];
                        } else {
                            $getMappedIP = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getMappedIP->num_rows == 1) {
                                $getMappedIPData = $getMappedIP->fetch_assoc();
                                $dst_lid = $getMappedIPData['id'];
                                $dst_table = "address_groups_id";
                            }
                        }
                    } else {
                        $getMappedIP = $projectdb->query("SELECT id,cidr,type FROM address WHERE ipaddress='$mappedIP' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        $nat_type = "dynamic-ip-and-port";
                        if ($getMappedIP->num_rows == 1) {
                            $getMappedIPData = $getMappedIP->fetch_assoc();
                            $dst_lid = $getMappedIPData['id'];
                            $dst_table = "address";
                            $dst_cidr = $getMappedIPData['cidr'];
                            $dst_type = $getMappedIPData['type'];
                        } else {
                            #if (($RealIPCIDR=="32") OR ($RealIPCIDR=="")){$type="ip-netmask";$prefix="H";$newname="$prefix-$mappedIP";$RealIPCIDR2="32";}else{$type="ip-netmask";$prefix="N";$newname="$prefix-$mappedIP-$RealIPCIDR";$RealIPCIDR2=$RealIPCIDR;}
                            $type = "ip-netmask";
                            $prefix = "H";
                            $newname = "$prefix-$mappedIP";
                            $RealIPCIDR2 = "32";
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,type,cidr, devicegroup) VALUES ('$source','$vsys','$newname','$newname','$mappedIP','ip-netmask','$RealIPCIDR2','$global_config_filename')");
                            $dst_lid = $projectdb->insert_id;
                            $dst_table = "address";
                            $dst_cidr = "32";
                            $dst_type = 'ip-netmask';
                        }
                    }

                    if (isset($netObj[4]) == "interface") {
                        #Fallback Activation
                        $tp_fallback_type = "interface-address";
                        $tp_sat_interface_fallback = $to;
                        $tp_sat_ipaddress_fallback = "";
                        add_log2('ok', 'Reading Objects Nat', 'Nat RuleID [' . $nat_lid . '] is using Interface Address for Fallback. [' . $names_line . '].', $source, 'No action Required.', 'rules', $nat_lid, 'nat_rules');
                    } else {
                        $tp_fallback_type = "None";
                        $tp_sat_interface_fallback = "";
                        $tp_sat_ipaddress_fallback = "";
                    }

                    $addNatSrc[] = "('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                    $addSNAT[] = "('$checkit','$source','$vsys','$nat_lid','$position','$ruleName','$Status','$to','',0,'','','$nat_type','translated-address','','',0,'','$tp_fallback_type','$tp_sat_interface_fallback','$tp_sat_ipaddress_fallback')";
                    $addNATFrom[] = "('$source','$vsys','$nat_lid','$from')";
                    $addNATTranslatedAddress[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                }




                $nat_lid++;
                $position++;
                $ruleName = "";
                $to = "";
                $op_service_lid = "";
                $op_service_table = "";
                $tp_dat_port = "";
                $tp_dat_address_lid = "";
                $tp_dat_address_table = "";
                $checkit = 0;
            }
        }

        if (preg_match("/^object network/i", $names_line)) {
            $isObjectNetwork = 1;
            $names = explode(" ", $names_line);
            $ObjectNetworkName = rtrim($names[2]);
            $ObjectNetworkNamePan = truncate_names(normalizeNames($ObjectNetworkName));
        }

        if (preg_match("/^access-list/", $names_line)) {
            $isObjectNetwork = 0;
        }
    }


    if (count($addRule) > 0) {
        $projectdb->query("INSERT INTO nat_rules (checkit,id,source,vsys,name,is_dat,position,description,op_zone_to,op_service_lid,op_service_table,tp_dat_port,tp_dat_address_lid,tp_dat_address_table) VALUES " . implode(",", $addRule) . ";");
        unset($addRule);
    }
    if (count($addDestination) > 0) {
        $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addDestination) . ";");
        unset($addDestination);
    }
    if (count($addFROM)> 0) {
        $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addFROM) . ";");
        unset($addFROM);
    }
    if (count($addSNAT) > 0) {
        $projectdb->query("INSERT INTO nat_rules (checkit,source,vsys,id,position,name,disabled,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_ipaddress,description,tp_sat_bidirectional,tp_sat_interface,tp_fallback_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback) VALUES " . implode(",", $addSNAT) . ";");
        if (count($addNATFrom) > 0) {
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addNATFrom) . ";");
            unset($addNATFrom);
        }
        if (count($addNATTranslatedAddress) > 0) {
            $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNATTranslatedAddress) . ";");
            unset($addNATTranslatedAddress);
        }
        if (count($addNatSrc) > 0) {
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNatSrc) . ";");
            unset($addNatSrc);
        }
        unset($addSNAT);
        #Block all the nat rules with Autonat in the name
        $projectdb->query("UPDATE nat_rules SET blocked=1 WHERE name LIKE 'Autonat %' AND source='$source' AND vsys='$vsys';");
    }
//    fclose($my);
}

//TODO: Change this function to use Arrays instead of so many SQL Queries
function get_object_network($cisco_config_file, $source, $vsys) {
    global $projectdb;
    global $global_config_filename;
    $addHost = array();
    $AddDescription = array();
    $isObjectNetwork = 0;
    $nat_lid = "";

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);

        if ($names_line == "!") {
            $isObjectNetwork = 0;
        }
        else{  //Other reasons that determine we are not entering a address object
            if (preg_match("/^crytpo /i", $names_line)){
                $isObjectNetwork = 0;
            }
            elseif(preg_match("/^route /i", $names_line)){
                $isObjectNetwork = 0;
            }
        }

        if ($isObjectNetwork == 1) {
            if (preg_match("/^host/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $ipaddress = $netObj[1];
                $search = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$ObjectNetworkName' AND ipaddress='$ipaddress' AND vsys='$vsys' AND vtype='object';");
                if ($search->num_rows == 0) {
                    $ipversion = ip_version($ipaddress);
                    if ($ipversion == "v4") {
                        $hostCidr = "32";
                        $addHost["ipv4"][] = "('$ObjectNetworkNamePan','ip-netmask','$ObjectNetworkName','0','$source','0','$ipaddress','$hostCidr','1','$vsys','object','$global_config_filename')";
                    } elseif ($ipversion == "v6") {
                        $hostCidr = "128";
                        $addHost["ipv6"][] = "('$ObjectNetworkNamePan','ip-netmask','$ObjectNetworkName','0','$source','0','$ipaddress','$hostCidr','1','$vsys','object','0','$global_config_filename')";
                    }

                }
            }
            elseif (preg_match("/^\bfqdn\b/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $fqdn = $netObj[1];
                if (($fqdn == "v4") OR ( $fqdn == "v6")) {
                    $fqdn = $netObj[2];
                }
                $search = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$ObjectNetworkName' AND fqdn='$fqdn' AND vsys='$vsys' AND vtype='object';");
                if ($search->num_rows == 0) {
                    $addHost["ipv4"][] = "('$ObjectNetworkNamePan','fqdn','$ObjectNetworkName','0','$source','0','$fqdn','','1','$vsys','object','$global_config_filename')";
                }
            }
            elseif (preg_match("/^\bsubnet\b/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $ipaddress = $netObj[1];
                $search = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$ObjectNetworkName' AND ipaddress='$ipaddress' AND vsys='$vsys' AND vtype='object';");
                if ($search->num_rows == 0) {
                    $ipversion = ip_version($ipaddress);
                    if ($ipversion == "v4") {
                        $hostCidr = mask2cidrv4(rtrim($netObj[2]));
                        $addHost["ipv4"][] = "('$ObjectNetworkNamePan','ip-netmask','$ObjectNetworkName','0','$source','0','$ipaddress','$hostCidr','1','$vsys','object','$global_config_filename')";
                    } elseif ($ipversion == "v6") {
                        $split=explode("/",$ipaddress);
                        $ipaddress=$split[0];
                        $hostCidr=$split[1];
                        $addHost["ipv6"][] = "('$ObjectNetworkNamePan','ip-netmask','$ObjectNetworkName','0','$source','0','$ipaddress','$hostCidr','1','$vsys','object','0','$global_config_filename')";
                    }

                }
            }
            elseif (preg_match("/^\brange\b/i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $first_ipaddress = $netObj[1];
                $last_ipaddress = $netObj[2];
                $search = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$ObjectNetworkName' AND ipaddress='$first_ipaddress-$last_ipaddress' AND type='ip-range' AND vtype='object';");
                if ($search->num_rows == 0) {
                    $ipversion = ip_version($first_ipaddress);
                    if ($ipversion == "v4") {
                        $addHost["ipv4"][] = "('$ObjectNetworkNamePan','ip-range','$ObjectNetworkName','0','$source','0','$first_ipaddress-$last_ipaddress','','1','$vsys','object','$global_config_filename')";
                    } elseif ($ipversion == "v6") {
                        $addHost["ipv6"][] = "('$ObjectNetworkNamePan','ip-range','$ObjectNetworkName','0','$source','0','$first_ipaddress-$last_ipaddress','','1','$vsys','object','0','$global_config_filename')";
                    }

                }
            }
            elseif (preg_match("/^\bdescription\b/i", $names_line)) {
                $netObj = preg_split('/description /', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $description = addslashes($netObj[0]);
                $description = str_replace("\n", '', $description); // remove new lines
                $description = str_replace("\r", '', $description);
                $description = utf8_encode($description);
                $AddDescription[] = "UPDATE address SET description='$description' WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$ObjectNetworkName' AND vtype='object'";
            }
        }

        if (preg_match("/^object network/i", $names_line)) {
            $isObjectNetwork = 1;
            $names = explode(" ", $names_line);
            $ObjectNetworkName = rtrim($names[2]);
            $ObjectNetworkNamePan = truncate_names(normalizeNames($ObjectNetworkName));
        }
    }

    if (isset($addHost["ipv4"]) && count($addHost["ipv4"]) > 0) {
        $unique = array_unique($addHost["ipv4"]);
        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys,vtype, devicegroup) values " . implode(",", $unique) . ";");
        unset($addHost["ipv4"]);
    }
    if (isset($addHost["ipv6"]) && count($addHost["ipv6"]) > 0) {
        $unique = array_unique($addHost["ipv6"]);
        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v6,vsys,vtype,v4, devicegroup) values " . implode(",", $unique) . ";");
        unset($addHost["ipv6"]);
    }
    if (count($AddDescription) > 0) {
        foreach ($AddDescription as $key => $value) {
            $projectdb->query($value . ";");
        }
        unset($AddDescription);
    }
}


//TODO: Change this method to use Array information
/*
function get_objectgroup_network($cisco_config_file, $source, $vsys) {
    global $projectdb;
    $isObjectGroup = 0;
    $addHost = array();
    $addMember = array();
    $addGroups = array();


    $getPosition = $projectdb->query("SELECT max(id) as t FROM address_groups_id WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $groupLid = 0;  //We set it to 0, because we increase by 1 as soon as we find a object-group network
    }
    else {
        $ddata = $getPosition->fetch_assoc();
        $groupLid = $ddata['t'];
    }

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);

        if (preg_match("/^object-group network/i", $names_line)) {
            $groupLid++;
            $isObjectGroup = 1;
            $names = explode(" ", $names_line);
            $HostGroupName = rtrim($names[2]);
            $HostGroupNamePan = truncate_names(normalizeNames($HostGroupName));
//            $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$HostGroupName' AND vsys='$vsys'");
//            if ($getDup->num_rows == 0) {
                $addGroups[] = "($groupLid,'$HostGroupNamePan','$HostGroupName','$source','$vsys')";
//                $projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,vsys) values ('$HostGroupNamePan','$HostGroupName','$source','$vsys');");
//                $groupLid = $projectdb->insert_id;
//            }
//            else{
//                $getDupData=$getDup->fetch_assoc();
//                $groupLid = $getDupData['id'];
//            }
        }
        else {
            if (($isObjectGroup == 1) AND
                (!preg_match("/\bnetwork-object\b/", $names_line)) AND
                (!preg_match("/\bdescription\b/", $names_line)) AND
                 (!preg_match("/\bgroup-object\b/", $names_line))) {
                $isObjectGroup = 0;
            }

            if ($isObjectGroup == 1) {
                if (preg_match("/network-object/i", $names_line)) {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $type = $netObj[1];
                    $obj2 = rtrim($netObj[2]);

                    if ($type == "host") {
                        $ipversion = ip_version($obj2);
                        if ($ipversion == "v4") {
                            $hostCidr = "32";
                        }
                        elseif ($ipversion == "v6") {
                            $hostCidr = "128";
                        }
                        else{
                            $hostCidr='';
                        }

                        if (($ipversion == "v4") or ($ipversion == "v6")) {
                            $getname = $projectdb->query("SELECT name_ext,cidr FROM address WHERE ipaddress='$obj2' AND cidr='$hostCidr' AND source='$source' AND vsys='$vsys';");
                            if ($getname->num_rows == 0) {
                                #Not Exists - Creating
                                $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='H-$obj2';");
                                if ($getDup->num_rows == 0) {
                                    $addHost[] = "('H-$obj2','ip-netmask','H-$obj2','0','$source','0','$obj2','$hostCidr','1','$vsys','object')";
                                    $addMember[] = "('$groupLid','H-$obj2','$source','$vsys')";
                                }
                                else {
                                    $addMember[] = "('$groupLid','H-$obj2','$source','$vsys')";
                                }
                            }
                            else {
                                $data = $getname->fetch_assoc();
                                $name = $data['name_ext'];
                                $addMember[] = "('$groupLid','$name','$source','$vsys')";
                            }
                        }
                        else {
                            #NAME
                            $getname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$obj2' AND cidr='0' AND vsys='$vsys' AND vtype!='object';");
                            if ($getname->num_rows == 1) {
                                $data = $getname->fetch_assoc();
                                $ipaddress = $data['ipaddress'];
                                $ipversion = ip_version($ipaddress);

                                $getCheck = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND ipaddress='$ipaddress' AND cidr='32' AND vsys='$vsys';");
                                if ($getCheck->num_rows == 0) {
                                    $name = "$obj2-32";
                                    $name_int = truncate_names(normalizeNames($name));
                                    $addHost[] = "('$name_int','ip-netmask','$name','0','$source','0','$ipaddress','32','1','$vsys','object')";
                                    $addMember[] = "('$groupLid','$obj2-32','$source','$vsys')";
                                }
                                else {
                                    $data = $getCheck->fetch_assoc();
                                    $name = $data['name_ext'];
                                    $addMember[] = "('$groupLid','$name','$source','$vsys')";
                                }
                            }
                            elseif ($getname->num_rows == 0) {
                                add_log('error', 'Reading Address Objects and Groups', 'ObjectName [' . $obj2 . '] is not in the Database.', $source, 'Adding to the DB with [ip:1.1.1.1], please modify it with the right IP Address');
                                $name_int = truncate_names(normalizeNames($obj2));
                                $addHost[] = "('$name_int','ip-netmask','$obj2','1','$source',0,'1.1.1.1','32','1','$vsys','object')";
                                $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
                            }
                        }
                    }
                    elseif ($type == "object") {
                        $search = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$obj2' AND source='$source'  AND vsys='$vsys' AND vtype='object';");
                        if ($search->num_rows == 1) {
                            $addMember[] = "('$groupLid','_mtobj_$obj2','$source','$vsys')";
                        }
                        else {
                            #Not exists in DB Creating IT
                            add_log('error', 'Reading Address Objects and Groups', 'ObjectName [' . $obj2 . '] is not in the Database.', $source, 'Adding to the DB with [ip:1.1.1.1], please modify it with the right IP Address');
                            $name_int = truncate_names(normalizeNames($obj2));
                            $addHost[] = "('$name_int','ip-netmask','$obj2','1','$source',0,'1.1.1.1','32','1','$vsys','object')";
                            $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
                        }
                    }
                    else {
                        $ipversion = ip_version($type);
                        $obj2 = $type;
                        if ($ipversion == "v4") {
                            $hostCidr = mask2cidrv4(rtrim($netObj[2]));
                            if ($hostCidr == "32") {
                                $NameComplete = "H-$obj2";
                            }
                            else {
                                $NameComplete = "N-$obj2-$hostCidr";
                            }
                            $getname = $projectdb->query("SELECT name_ext FROM address WHERE ipaddress='$obj2' AND cidr='$hostCidr' AND source='$source' AND vsys='$vsys';");
                            if ($getname->num_rows == 0) {
                                #Not Exists - Creating
                                $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name='$NameComplete' AND vsys='$vsys' AND vtype!='object';");
                                if ($getDup->num_rows == 0) {
                                    $name_int = truncate_names(normalizeNames($NameComplete));
                                    $addHost[] = "('$name_int','ip-netmask','$NameComplete','0','$source','1','$obj2','$hostCidr','1','$vsys','object')";
                                    $addMember[] = "('$groupLid','$NameComplete','$source','$vsys')";
                                } else {
                                    $addMember[] = "('$groupLid','$NameComplete','$source','$vsys')";
                                }
                            } else {
                                $data = $getname->fetch_assoc();
                                $objectname = $data['name_ext'];
                                $addMember[] = "('$groupLid','$objectname','$source','$vsys')";
                            }
                        }
                        elseif ($ipversion == "v6") {
                            //TODO
                            # TO BE IMPLEMENTED
                        }
                        else {
                            #NAME CHECKAR si name y cidr o name solo o si es name solo o name-cidr
                            $hostCidr = mask2cidrv4(rtrim($netObj[2]));
                            #NAME
                            $getname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$obj2' AND cidr='0' AND vsys='$vsys' AND vtype!='object';");
                            if ($getname->num_rows == 1) {
                                $data = $getname->fetch_assoc();
                                $ipaddress = $data['ipaddress'];
                                $ipversion = ip_version($ipaddress);

                                $getCheck = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND ipaddress='$ipaddress' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype!='object';");
                                if ($getCheck->num_rows == 0) {
                                    $name = "$obj2-$hostCidr";
                                    $name_int = truncate_names(normalizeNames($name));
                                    $addHost[] = "('$name_int','ip-netmask','$name','0','$source','0','$ipaddress','$hostCidr','1','$vsys','object')";
                                    $addMember[] = "('$groupLid','$obj2-$hostCidr','$source','$vsys')";
                                }
                                else {
                                    $data = $getCheck->fetch_assoc();
                                    $name = $data['name_ext'];
                                    $addMember[] = "('$groupLid','$name','$source','$vsys')";
                                }
                            }
                            elseif ($getname->num_rows == 0) {
                                add_log('error', 'Reading Address Objects and Groups', 'ObjectName [' . $obj2 . '] is not in the Database.', $source, 'Adding to the DB with [ip:1.1.1.1], please modify it with the right IP Address');
                                $name_int = truncate_names(normalizeNames($obj2));
                                $addHost[] = "('$name_int','ip-netmask','$obj2','1','$source',0,'1.1.1.1','32','1','$vsys','object')";
                                $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
                            }
                        }
                    }
                }
                elseif (preg_match("/group-object/i", $names_line)) {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $obj2 = rtrim($netObj[1]);
                    $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
                }
            }

        }
    }

    if (count($addGroups)>0){
        $unique = array_unique($addGroups);
        $query = "INSERT INTO address_groups_id (id, name,name_ext,source,vsys) values " . implode(",", $unique) . ";";
        $projectdb->query($query);
        unset($addGroups);
    }

    if (count($addHost) > 0) {
        $unique = array_unique($addHost);
        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, vtype) values " . implode(",", $unique) . ";");
        unset($addHost);
    }
    if (count($addMember) > 0) {
        $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys) values " . implode(",", $addMember) . ";");
        unset($addMember);
    }
}
*/

function get_objectgroup_network2($cisco_config_file, $source, $vsys, MemoryObjectsHandlerCisco $objectsInMemory, STRING $fileName) {
    global $projectdb;
    global $global_config_filename;
    $isObjectGroup = 0;
    $addHost = array();
    $addMember = array();
    $addMember2 = array();
    $addGroups = array();


    $getPosition = $projectdb->query("SELECT max(id) as t FROM address_groups_id");
    if ($getPosition->num_rows == 0) {
        $groupLid = 0;  //We set it to 0, because we increase by 1 as soon as we find a object-group network
    }
    else {
        $ddata = $getPosition->fetch_assoc();
        $groupLid = $ddata['t'];
    }

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);

        if (preg_match("/^object-group network/i", $names_line)) {
            $groupLid++;
            $isObjectGroup = 1;
            $names = explode(" ", $names_line);
            $HostGroupName = rtrim($names[2]);
            $HostGroupNamePan = truncate_names(normalizeNames($HostGroupName));
//            $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$HostGroupName' AND vsys='$vsys'");
//            if ($getDup->num_rows == 0) {
            $addGroups[$groupLid] = "($groupLid,'$HostGroupNamePan','$HostGroupName','$source','$vsys','static','$global_config_filename','')";
//                $projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,vsys) values ('$HostGroupNamePan','$HostGroupName','$source','$vsys');");
//                $groupLid = $projectdb->insert_id;
//            }
//            else{
//                $getDupData=$getDup->fetch_assoc();
//                $groupLid = $getDupData['id'];
//            }
            $addressGroupData = [
                'name'  => $HostGroupName,
                'type'  => 'static',
                'id'    => $groupLid,
                'source'=> $source,
                'vsys'  => $vsys,
                'devicegroup' => $global_config_filename,
                'description'   => $description
            ];
            $response = $objectsInMemory->addAddressGroup($addressGroupData);
            if(!$response['success']){
                echo "Group $HostGroupName with lid $groupLid not created\n";
            }
            else{
//                echo "Group $HostGroupName with lid $groupLid created\n";
            }
        }
        elseif (preg_match("/^object-group security/i", $names_line)) {
            $groupLid++;
            $names = explode(" ", $names_line);
            $HostGroupName = rtrim($names[2]);
            $HostGroupNamePan = truncate_names(normalizeNames($HostGroupName));
            $addGroups[] = "($groupLid,'$HostGroupNamePan','$HostGroupName','$source','$vsys','dynamic','$global_config_filename','')";
            $addressGroupData = [
                'name'  => $HostGroupName,
                'type'  => 'dynamic',
                'id'    => $groupLid,
                'source'=> $source,
                'vsys'  => $vsys,
                'devicegroup' => $global_config_filename
            ];
            $response = $objectsInMemory->addAddressGroup($addressGroupData);
            if(!$response['success']){
                echo "Group $HostGroupName with lid $groupLid not created\n";
            }
            else{
//                echo "Group $HostGroupName with lid $groupLid created\n";
            }

            add_log2('error', 'Reading Address Groups', 'Address group [' . $HostGroupName . '] is a name-based Group.', $source, 'Fix it manually, probably as a DAG', 'objects', $groupLid, 'address_groups_id');
        }
        else {
            if (($isObjectGroup == 1) AND
                (!preg_match("/\bnetwork-object\b/", $names_line)) AND
                (!preg_match("/\bdescription\b/", $names_line)) AND
                (!preg_match("/\bgroup-object\b/", $names_line))) {
                $isObjectGroup = 0;
            }

            if ($isObjectGroup == 1) {
                if (preg_match("/network-object/i", $names_line)) {
                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $type = $netObj[1];
                    $obj2 = isset($netObj[2])?rtrim($netObj[2]):'';

                    if ($type == "host") {
                        $ipversion = ip_version($obj2);
                        if ($ipversion == "v4") {
                            $hostCidr = 32;
                        }
                        elseif ($ipversion == "v6") {
                            $hostCidr = 128;
                        }
                        else{
                            $hostCidr=null;
                        }

                        if (($ipversion == "v4") or ($ipversion == "v6")) {
                            $ipWithCidr = $obj2."-".$hostCidr;
                            $addressObj = $objectsInMemory->getIPAddressReference($fileName, $source, $vsys,$obj2, $hostCidr);
                            // (lid,member,source,vsys,table_name, member_lid)
                            $addMember2[] = "('$groupLid','H-$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";

//                            $getname = $projectdb->query("SELECT name_ext,cidr FROM address WHERE ipaddress='$obj2' AND cidr='$hostCidr' AND source='$source' AND vsys='$vsys';");
//                            if ($getname->num_rows == 0) {
//                                #Not Exists - Creating
//                                $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='H-$obj2';");
//                                if ($getDup->num_rows == 0) {
//                                    //(name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, vtype)
//                                    $addHost[] = "('H-$obj2','ip-netmask','H-$obj2','0','$source','0','$obj2','$hostCidr','1','$vsys','object')";
//                                    $addMember[] = "('$groupLid','H-$obj2','$source','$vsys')";
//                                }
//                                else {
//                                    $addMember[] = "('$groupLid','H-$obj2','$source','$vsys')";
//                                }
//                            }
//                            else {
//                                $data = $getname->fetch_assoc();
//                                $name = $data['name_ext'];
//                                $addMember[] = "('$groupLid','$name','$source','$vsys')";
//                            }
                        }
                        else {
                            #NAME
                            $addressObj = $objectsInMemory->getAddressReference($fileName, $source, $vsys,$obj2, $hostCidr);
                            $addMember2[] = "('$groupLid','H-$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";

//                            $getname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$obj2' AND cidr='0' AND vsys='$vsys' AND vtype!='object';");
//                            if ($getname->num_rows == 1) {
//                                $data = $getname->fetch_assoc();
//                                $ipaddress = $data['ipaddress'];
//                                $ipversion = ip_version($ipaddress);
//
//                                $getCheck = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND ipaddress='$ipaddress' AND cidr='32' AND vsys='$vsys';");
//                                if ($getCheck->num_rows == 0) {
//                                    $name = "$obj2-32";
//                                    $name_int = truncate_names(normalizeNames($name));
//                                    $addHost[] = "('$name_int','ip-netmask','$name','0','$source','0','$ipaddress','32','1','$vsys','object')";
//                                    $addMember[] = "('$groupLid','$obj2-32','$source','$vsys')";
//                                }
//                                else {
//                                    $data = $getCheck->fetch_assoc();
//                                    $name = $data['name_ext'];
//                                    $addMember[] = "('$groupLid','$name','$source','$vsys')";
//                                }
//                            }
//                            elseif ($getname->num_rows == 0) {
//                                add_log('error', 'Reading Address Objects and Groups', 'ObjectName [' . $obj2 . '] is not in the Database.', $source, 'Adding to the DB with [ip:1.1.1.1], please modify it with the right IP Address');
//                                $name_int = truncate_names(normalizeNames($obj2));
//                                $addHost[] = "('$name_int','ip-netmask','$obj2','1','$source',0,'1.1.1.1','32','1','$vsys','object')";
//                                $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
//                            }
                        }
                    }
                    elseif ($type == "object") {
                        $addressObj = $objectsInMemory->getAddressReference($fileName, $source, $vsys,$obj2);
                        $addMember2[] = "('$groupLid','H-$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";

//                        $search = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$obj2' AND source='$source'  AND vsys='$vsys' AND vtype='object';");
//                        if ($search->num_rows == 1) {
//                            $addMember[] = "('$groupLid','_mtobj_$obj2','$source','$vsys')";
//                        }
//                        else {
//                            #Not exists in DB Creating IT
//                            add_log('error', 'Reading Address Objects and Groups', 'ObjectName [' . $obj2 . '] is not in the Database.', $source, 'Adding to the DB with [ip:1.1.1.1], please modify it with the right IP Address');
//                            $name_int = truncate_names(normalizeNames($obj2));
//                            $addHost[] = "('$name_int','ip-netmask','$obj2','1','$source',0,'1.1.1.1','32','1','$vsys','object')";
//                            $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
//                        }
                    }
                    else {
                        $ipversion = ip_version($type);
                        $obj2 = $type;
                        if ($ipversion == "v4") {
                            $hostCidr = mask2cidrv4(rtrim($netObj[2]));
                            if ($hostCidr == "32") {
                                $NameComplete = "H-$obj2";
                            }
                            else {
                                $NameComplete = "N-$obj2-$hostCidr";
                            }

//                            $addressObj = $objectsInMemory->getIPAddressReference($fileName, $source, $vsys, $obj2, $hostCidr);
                            $addressObj = $objectsInMemory->getAddressReference($fileName, $source, $vsys, $obj2, $hostCidr);
                            // (lid,member,source,vsys,table_name, member_lid)
                            $addMember2[] = "('$groupLid','$NameComplete','$source','$vsys','$addressObj->location','$addressObj->name')";

//                            $getname = $projectdb->query("SELECT name_ext FROM address WHERE ipaddress='$obj2' AND cidr='$hostCidr' AND source='$source' AND vsys='$vsys';");
//                            if ($getname->num_rows == 0) {
//                                #Not Exists - Creating
//                                $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name='$NameComplete' AND vsys='$vsys' AND vtype!='object';");
//                                if ($getDup->num_rows == 0) {
//                                    $name_int = truncate_names(normalizeNames($NameComplete));
//                                    $addHost[] = "('$name_int','ip-netmask','$NameComplete','0','$source','1','$obj2','$hostCidr','1','$vsys','object')";
//                                    $addMember[] = "('$groupLid','$NameComplete','$source','$vsys')";
//                                } else {
//                                    $addMember[] = "('$groupLid','$NameComplete','$source','$vsys')";
//                                }
//                            } else {
//                                $data = $getname->fetch_assoc();
//                                $objectname = $data['name_ext'];
//                                $addMember[] = "('$groupLid','$objectname','$source','$vsys')";
//                            }
                        }
                        elseif ($ipversion == "v6") {
                            $ipv6Parts = explode("/", $netObj[1]);
                            if(isset($ipv6Parts[1])){
                                $hostCidr = $ipv6Parts[1];
                            }
                            else{
                                $hostCidr = 128;
                            }
                            if($hostCidr == 128) {
                                $NameComplete = "H-".$ipv6Parts[0]."-128";
                            }
                            else {
                                $NameComplete = "N-".$ipv6Parts[0]."-".$hostCidr;
                            }
                            $addressObj = $objectsInMemory->getAddressReference($fileName, $source, $vsys, $obj2, $hostCidr);
                            $addMember2[] = "('$groupLid','$NameComplete','$source','$vsys','$addressObj->location','$addressObj->name')";
                        }
                        else {
                            //Verify it is not an IPv6 with CIDR
                            $ipv6Parts = explode("/", $netObj[1]);
                            if(isset($ipv6Parts[1])){
                                $hostCidr = $ipv6Parts[1];
                                if($hostCidr == 128) {
                                    $NameComplete = "H-".$ipv6Parts[0]."-128";
                                }
                                else {
                                    $NameComplete = "N-".$ipv6Parts[0]."-".$hostCidr;
                                }
                                $addressObj = $objectsInMemory->getAddressReference($fileName, $source, $vsys, $ipv6Parts[0], $hostCidr);
                                $addMember2[] = "('$groupLid','$NameComplete','$source','$vsys','$addressObj->location','$addressObj->name')";
                            }
                            else {
                                #NAME CHECKAR si name y cidr o name solo o si es name solo o name-cidr
                                $hostCidr = mask2cidrv4(rtrim($netObj[2]));

                                $addressObj = $objectsInMemory->getAddressReference($fileName, $source, $vsys, $obj2, $hostCidr);
                                $addMember2[] = "('$groupLid','H-$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";
                            }

//                            #NAME
//                            $getname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND BINARY name_ext='$obj2' AND cidr='0' AND vsys='$vsys' AND vtype!='object';");
//                            if ($getname->num_rows == 1) {
//                                $data = $getname->fetch_assoc();
//                                $ipaddress = $data['ipaddress'];
//                                $ipversion = ip_version($ipaddress);
//
//                                $getCheck = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND ipaddress='$ipaddress' AND cidr='$hostCidr' AND vsys='$vsys' AND vtype!='object';");
//                                if ($getCheck->num_rows == 0) {
//                                    $name = "$obj2-$hostCidr";
//                                    $name_int = truncate_names(normalizeNames($name));
//                                    $addHost[] = "('$name_int','ip-netmask','$name','0','$source','0','$ipaddress','$hostCidr','1','$vsys','object')";
//                                    $addMember[] = "('$groupLid','$obj2-$hostCidr','$source','$vsys')";
//                                }
//                                else {
//                                    $data = $getCheck->fetch_assoc();
//                                    $name = $data['name_ext'];
//                                    $addMember[] = "('$groupLid','$name','$source','$vsys')";
//                                }
//                            }
//                            elseif ($getname->num_rows == 0) {
//                                add_log('error', 'Reading Address Objects and Groups', 'ObjectName [' . $obj2 . '] is not in the Database.', $source, 'Adding to the DB with [ip:1.1.1.1], please modify it with the right IP Address');
//                                $name_int = truncate_names(normalizeNames($obj2));
//                                $addHost[] = "('$name_int','ip-netmask','$obj2','1','$source',0,'1.1.1.1','32','1','$vsys','object')";
//                                $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
//                            }
                        }
                    }
                }
                elseif (preg_match("/group-object/i", $names_line)) {

                    $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $obj2 = rtrim($netObj[1]);
                    $addressObj = $objectsInMemory->getAddressGroupReference($fileName, $source, $vsys,$obj2);
                    $addMember2[] = "('$groupLid','$obj2','$source','$vsys','$addressObj->location','$addressObj->name')";
//                    $addMember[] = "('$groupLid','$obj2','$source','$vsys')";
                }
                elseif (preg_match("/\bdescription\b/", $names_line)){
                    $words = explode(" ", $names_line);
                    array_shift($words);
                    $description = implode(" ", $words);

                    list($field1, $field2,$field3,$field4,$field5, $field6,$field7,$field8) = getFields($addGroups[$groupLid], 8);
                    $addGroups[$groupLid] = "($field1,'$field2','$field3','$field4','$field5','$field6','$field7','".addslashes($description)."')";
                }
            }

        }
    }

    if (count($addGroups)>0){
        $unique = array_unique($addGroups);
        $query = "INSERT INTO address_groups_id (id, name,name_ext,source,vsys, type, devicegroup, description) values " . implode(",", $unique) . ";";
        $projectdb->query($query);
        unset($addGroups);
    }

//    if (count($addHost) > 0) {
//        $unique = array_unique($addHost);
//        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys, vtype) values " . implode(",", $unique) . ";");
//        unset($addHost);
//    }
//    if (count($addMember) > 0) {
//        $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys) values " . implode(",", $addMember) . ";");
//        unset($addMember);
//    }
    if (count($addMember2) > 0) {
        $query = "INSERT INTO address_groups (lid,member,source,vsys, table_name, member_lid) values " . implode(",", $addMember2) . ";";
        $projectdb->query($query);
        unset($addMember2);
    }

    $objectsInMemory->insertNewAddresses($projectdb);
}

function getFields(STRING $entry, INT $number){
    preg_match('/\((?<cadena>.*)\)/', $entry, $output_array);
    $substring = $output_array['cadena'];
    $dirtyFields = explode(",", $substring);

    if(count($dirtyFields) == $number){
        $fields = array();
        foreach($dirtyFields as $dirtyField){
            $fields[] = trim(trim($dirtyField),"'");
        }
        return $fields;
    }
    else{
        return [];
    }
}

function get_static_routes($cisco_config_file, $source, $vsys, $template) {
    global $projectdb;
    global $vrid;
    $addRoutes = array();
    $vr = "vr_" . $vsys;
    $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr';");
    if ($isDup->num_rows == 0) {
        $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
        $vrid = $projectdb->insert_id;
    } else {
        $get = $isDup->fetch_assoc();
        $vrid = $get['id'];
    }

    $interfaceMapping=array();
    $getInterface=$projectdb->query("SELECT unitname,zone FROM interfaces WHERE template='$template' AND zone!='' AND link_state != 'down';");
    if ($getInterface->num_rows>0){
        while($getInterfaceData=$getInterface->fetch_assoc()){
            $interfaceMapping[$getInterfaceData['zone']]=$getInterfaceData['unitname'];
        }
    }

    $x = 1;
    $count=0;
    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if (preg_match("/^route /i", $names_line)) {
            $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $zoneName = $netObj[1];
            $ip_network = $netObj[2];
            $ip_netmask = rtrim($netObj[3]);
            $ip_gateway = rtrim($netObj[4]);
            $metric = $netObj[5];
            $route_network = "";
            $cidr = "";

            if (($metric == "") OR ( $metric == "0") Or ( $metric == "1")) {
                $metric = "10";
            }

            $ip_version = ip_version($ip_network);
            if ($ip_version == "noip") {
                # name
                $getHostname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name_ext='$ip_network'");
                if ($getHostname->num_rows == 1) {
                    $getName = $getHostname->fetch_assoc();
                    $ip_network = $getName['ipaddress'];
                    $ip_version=ip_version($ip_network);
                }
            }

            $gateway_ip_version = ip_version($ip_gateway);
            if ($gateway_ip_version == "noip") {
                # name
                $getHostname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name_ext='$ip_gateway'");
                if ($getHostname->num_rows == 1) {
                    $getName = $getHostname->fetch_assoc();
                    $ip_gateway = $getName['ipaddress'];
                }
            }

            $routename = "";

            if (($ip_network == "0.0.0.0") AND ( $ip_netmask == "0.0.0.0")) {
                if ($count==0){
                    $routename = "default";
                    $count++;
                }
                else{
                    $routename = "default ".$count;
                    $count++;
                }

                $route_network = "0.0.0.0/0";
            }
            else {
                $routename = "Route " . $x;
                $x++;
                $cidr = mask2cidrv4($ip_netmask);
                $route_network = "$ip_network/$cidr";
            }

            if ($zoneName!=""){
                $interfaceto=isset($interfaceMapping[$zoneName])?$interfaceMapping[$zoneName]:'';
            }
            else{
                $interfaceto="";
            }

            $addRoutes[] = "('$zoneName','$source','$vrid','$template','$ip_version','$routename','$route_network','$interfaceto','ip-address','$ip_gateway','$metric','$vsys','10')";
        }
    }
    if (count($addRoutes) > 0) {
        $unique = array_unique($addRoutes);
        $projectdb->query("INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys,admin_dist) VALUES " . implode(",", $unique) . ";");
        unset($addRoutes);
    }
}

function save_names($cisco_config_file, $source, $vsys, $filename) {
    global $projectdb;
    global $global_config_filename;
    $addName = array();

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if (preg_match("/^name /i", $names_line)) {
            $ipaddress = "";
            $name = "";
            $descriptiontrimmed = "";
            $description = "";

            $names = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $count = count($names);

            $ipaddress = $names[1];
            $ipversion = ip_version($ipaddress);

            if ($ipversion == "v4") {
                $hostCidr = "32";
            } elseif ($ipversion == "v6") {
                $hostCidr = "128";
            } else {
                $ipversion = "v4";
                $hostCidr = "32";
            }

            $name = rtrim($names[2]);
            $name_int = truncate_names(normalizeNames($name));

            if (($count > 3) AND ( $names[3] == "description")) {
                $descriptiontrimmed = $names[4];
                for ($i = 5; $i <= $count; $i++) {
                    if (isset($names[$i])) {
                        $descriptiontrimmed.=" " . $names[$i];
                    }
                }
            }

            $description = addslashes(normalizeComments($descriptiontrimmed));
            $description = str_replace("\n", '', $description); // remove new lines
            $description = str_replace("\r", '', $description);

            $getDup = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$name' AND source='$source';");
            if ($getDup->num_rows == 0) {
                if ($ipversion == "v6") {
                    $addName[] = "('$name_int','ip-netmask','$ipaddress','$hostCidr','$name','0','$description','$source','0','1','label','$global_config_filename')";
                } else {
                    $addName[] = "('$name_int','ip-netmask','$ipaddress','$hostCidr','$name','0','$description','$source','1','0','label','$global_config_filename')";
                }
            }
        }
    }

    if (count($addName) > 0) {
        $projectdb->query("INSERT INTO address (name,type,ipaddress,cidr,name_ext,checkit,description,source,v4,v6,vtype, devicegroup) values" . implode(",", $addName) . ";");
        unset($addName);
    }
}

function get_interfaces($cisco_config_file, $source, $vsys, $template) {
    global $projectdb;
    global $vrid;
    $zoneName="";
    $unitipaddress="";
    $addZones = array();
    $addInterface = array();
    $isFirst=TRUE;
    $isInterface = FALSE;
    $link_state = "auto";
    $media = "ethernet";
    $comment = '';
    #Check if THE VR is already created for this VSYS
    $vr = "vr_" . $vsys;
    $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr';");
    if ($isDup->num_rows == 0) {
        $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
        $vrid = $projectdb->insert_id;
    } else {
        $get = $isDup->fetch_assoc();
        $vrid = $get['id'];
    }

    foreach ($cisco_config_file as $line => $names_line) {

        if (preg_match("/^interface /i", $names_line)) {
            $isInterface = TRUE;
            $dataI = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $interfaceName=$dataI[1];
            if (preg_match("/ethernet/i", $names_line)) {
                $media = "ethernet";
            }
        }


        if ($isInterface === TRUE) {
            if (preg_match("/description /i", $names_line)) {
                $tmpExplode = explode(' ', trim($names_line), 2);
                if (count($tmpExplode) > 1)
                    $comment = normalizeComments($tmpExplode[1]);
            }
            elseif (preg_match("/nameif /i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $zoneName = $netObj[1];
            }
            elseif (preg_match("/shutdown/i", $names_line)){
                $link_state = "down";
            }
            elseif (preg_match("/ip address /i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $ip_network = $netObj[2];
                $ip_netmask = rtrim($netObj[3]);
                $ip_version = ip_version($ip_network);

                if ($ip_version == "v4") {
                    $cidr = mask2cidrv4($ip_netmask);
                    $unitipaddress = ($unitipaddress == "")?$ip_network."/".$cidr : $unitipaddress.",".$ip_network."/".$cidr;
                } elseif ($ip_version == "v6") {
                    # TO BE IMPLEMENTED
                } else {
                    $getHostname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name_ext='$ip_network'");
                    if ($getHostname->num_rows == 1) {
                        $getName = $getHostname->fetch_assoc();
                        $ip_network = $getName['ipaddress'];
                        $ip_version = ip_version($ip_network);
                        if ($ip_version == "v4") {
                            $cidr = mask2cidrv4($ip_netmask);
                            $unitipaddress = ($unitipaddress == "")?$ip_network."/".$cidr : $unitipaddress.",".$ip_network."/".$cidr;

                        } elseif ($ip_version == "v6") {
                            # TO BE IMPLEMENTED
                        }
                    }
                }
            }
            elseif (preg_match("/ipv6 address /i", $names_line)) {
                $netObj = preg_split('/\s/', $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $ip_network1 = $netObj[2];
                $ip_networkArr = explode("/", $ip_network1);
                $ip_network = $ip_networkArr[0];
                $ip_netmask = isset($ip_networkArr[1])?$ip_networkArr[1]:"128";

                $ip_version = ip_version($ip_network);

                if ($ip_version == "v6") {
                    $unitipaddress = ($unitipaddress == "")?$ip_network."/".$ip_netmask : $unitipaddress.",".$ip_network."/".$ip_netmask;
                } else {
                    $getHostname = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name_ext='$ip_network'");
                    if ($getHostname->num_rows == 1) {
                        $getName = $getHostname->fetch_assoc();
                        $ip_network = $getName['ipaddress'];
                        $ip_version = ip_version($ip_network);
                        if ($ip_version == "v6") {
                            $unitipaddress = ($unitipaddress == "")?$ip_network."/".$ip_netmask : $unitipaddress.",".$ip_network."/".$ip_netmask;
                        }
                    }
                }
            }
            elseif (preg_match("/ vlan /", $names_line)) {
                $data = explode(" ",$names_line);
                $unittag = $data[2];
            }
            elseif (preg_match("/^!/i", $names_line)){
                $isInterface = FALSE;
                #ADD INFO INTO DB
                if (!isset($unittag) || $unittag == "") {
                    $unittag = 0;
                    $unitname = (isset($zoneName))? $zoneName : '';
                }
                else {
                    $unitname = $zoneName . "." . $unittag;
                }
                if ($unitname != "") {

                    if ($interfaceName!=""){
                        $intsplit=explode(".",$interfaceName);
                        $name=$intsplit[0];
                        if (isset($intsplit[1])){
                            if (($unittag=="0") OR ($unittag=="")){
                                $unittag=$intsplit[1];
                                $unitname=$interfaceName;
                            }
                            else{
                                $unitname=$interfaceName;
                            }

                        }
                        else {
                            $unittag=0;
                            $unitname=$interfaceName;
                        }

                        if (preg_match("/Vlan/",$name)){
                            $vlansplit=explode("Vlan",$name);
                            $unittag=intval($vlansplit[1]);
                            $name="Vlan";
                            $unitname="Vlan.".$unittag;
                            if ($isFirst===TRUE){
                                $isFirst=false;
                                $addInterface[] = "('$vrid','$source','$vsys','$template','0','Vlan','Vlan','','','$media','$comment','$link_state')";
                            }
                        }

                        $addInterface[] = "('$vrid','$source','$vsys','$template','$unittag','$unitname','$name','$unitipaddress','$zoneName','$media','$comment','$link_state')";
                    }
                    else{
                        $addInterface[] = "('$vrid','$source','$vsys','$template','$unittag','$unitname','$zoneName','$unitipaddress','$zoneName','$media','$comment','$link_state')";
                    }


                    #Insert Zone
                    $addZones[] = "('$source','$template','$vsys','$zoneName','layer3')";
                }
                $unittag = "";
                $unitipaddress = "";
                $zoneName = "";
                $vr = "";
                $unitname = "";
                $comment = "";
                $link_state = "auto";
            }
        }
    }

    if (count($addZones) > 0) {
        $unique = array_unique($addZones);
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type) VALUES " . implode(",", $unique) . ";");
        unset($addZones);
    }
    if (count($addInterface) > 0) {
        $unique = array_unique($addInterface);
        $projectdb->query("INSERT INTO interfaces (vr_id,source,vsys,template,unittag,unitname,name,unitipaddress,zone,media,comment,link_state) VALUES " . implode(",", $unique) . ";");
        unset($addInterface);
    }

#Add Interfaces to the VR
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    while ($data = $getVR->fetch_assoc()) {
        $int = array();
        $vr_id = $data['id'];
        $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id' AND link_state!='down'");
        while ($data2 = $getInt->fetch_assoc()) {
            $int[] = $data2['unitname'];
        }
        if (count($int)>0){
            $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
        }
    }

#Add Interfaces to the Zones
    $getVR = $projectdb->query("SELECT name FROM zones WHERE template='$template';");
    while ($data = $getVR->fetch_assoc()) {
        $int = array();
        $zone = $data['name'];
        $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND zone='$zone'");
        while ($data2 = $getInt->fetch_assoc()) {
            $int[] = $data2['unitname'];
        }
        if (count($int)>0){
            $projectdb->query("UPDATE zones SET interfaces='" . implode(",", $int) . "' WHERE name='$zone' AND source='$source';");
        }
    }

    # Check Interfaces without unittag=0
    $getInterfaces=$projectdb->query("SELECT name,type FROM interfaces WHERE template='$template' AND media='ethernet' AND unittag!=0 GROUP BY name ORDER BY name");
    if ($getInterfaces->num_rows>0){
        while($data=$getInterfaces->fetch_assoc()){
            $name=$data['name'];
            $type=$data['type'];
            $unitname=$name;
            $projectdb->query("INSERT INTO interfaces (vr_id,source,vsys,template,unittag,unitname,name,media,type) VALUES ('$vr','$source','$vsys','$template','0','$unitname','$name','ethernet','$type');");
        }
    }
}

function optimize_names2($cisco_config_file, $source, $vsys){
    global $projectdb;

    $get32s = $projectdb->query("SELECT id,name,ipaddress,cidr FROM address WHERE source='$source' AND vsys='$vsys' AND type='ip-netmask' AND name like '%-32';");
    if($get32s->num_rows > 0){

    }

}


//No se utiliza
/*function optimize_names($cisco_config_file, $source, $vsys) {
    global $projectdb;

    $getAll = $projectdb->query("SELECT id,name,ipaddress,cidr FROM address WHERE source='$source' AND vsys='$vsys' AND type='ip-netmask' AND cidr='0';");
    if ($getAll->num_rows > 0) {
        while ($data = $getAll->fetch_assoc()) {
            $original_name_int = $data['name'];
            $original_ipaddress = $data['ipaddress'];
            $original_id = $data['id'];
            $getNew = $projectdb->query("SELECT id,name_ext,name FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$original_ipaddress' AND cidr!='0';");
            if ($getNew->num_rows == 1) {
                $data2 = $getNew->fetch_assoc();
                $newid = $data2['id'];
                $newname2 = $data2['name_ext'];
                $newname = $data2['name'];
                if (preg_match("/$original_name_int\-/", $newname)) {
                    $projectdb->query("UPDATE address SET name_ext='$original_name_int', name='$original_name_int' WHERE id='$newid';");
                    $projectdb->query("UPDATE address_groups SET member='$original_name_int' WHERE member='$newname2' AND source='$source' AND vsys='$vsys';");
                    $projectdb->query("DELETE FROM address where id='$original_id';");
                    #Update all tables
                    $projectdb->query("UPDATE address_groups SET member_lid='$newid' WHERE member_lid='$original_id' AND table_name='address';");
                    $projectdb->query("UPDATE security_rules_src SET member_lid='$newid' WHERE member_lid='$original_id' AND table_name='address' ;");
                    $projectdb->query("UPDATE security_rules_dst SET member_lid='$newid' WHERE member_lid='$original_id' AND table_name='address' ;");
                    $projectdb->query("UPDATE nat_rules_src SET member_lid='$newid' WHERE member_lid='$original_id' AND table_name='address' ;");
                    $projectdb->query("UPDATE nat_rules_dst SET member_lid='$newid' WHERE member_lid='$original_id' AND table_name='address' ;");
                    $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid='$newid' WHERE tp_dat_address_lid='$original_id' AND tp_dat_address_table='address' ;");
                    $projectdb->query("UPDATE nat_rules_translated_address SET member_lid='$newid' WHERE member_lid='$original_id' AND table_name='address' ;");
                    $projectdb->query("UPDATE nat_rules_translated_address_fallback SET member_lid='$newid' WHERE member_lid='$original_id' AND table_name='address' ;");
                }
            }
        }
    }
#Change the Netmask from 0 to 32 to all the others
    $projectdb->query("UPDATE address SET cidr='32' WHERE cidr='0' AND type='ip-netmask' AND source='$source';");
}*/

function clean_zone_any($source, $vsys){

    global $projectdb;

    $getZoneAny = $projectdb->query("SELECT id FROM zones WHERE source = '$source' AND vsys = '$vsys' AND name = 'any';");
    if ($getZoneAny->num_rows > 0) {
        $dataZ = $getZoneAny->fetch_assoc();
        $id_zone_any = $dataZ['id'];
        $projectdb->query("UPDATE zones SET name = 'any1' WHERE id = '$id_zone_any';");
        $projectdb->query("UPDATE nat_rules_from SET name = 'any1' WHERE source = '$source' AND vsys = '$vsys' AND name = 'any';");
        $projectdb->query("UPDATE nat_rules SET op_zone_to = 'any1' WHERE source = '$source' AND vsys = '$vsys' AND op_zone_to = 'any';");
    }
    else{
        // Clean any's
        $projectdb->query("DELETE FROM nat_rules_from WHERE source = '$source' AND vsys = '$vsys' AND name = 'any';");
        $projectdb->query("UPDATE nat_rules SET op_zone_to = '' WHERE source = '$source' AND vsys = '$vsys' AND op_zone_to = 'any';");
    }

}

# NATS
function natpre83($source, $vsys, $cisco_config_file, $template) {
    global $projectdb;
    global $global_config_filename;
    $projectdb->query("TRUNCATE TABLE cisco_nat_global;");
    $nat_lid = "";
    $position = "";
    $AddFrom = [];
    $AddSource = [];
    $AddTranslated = [];
    $AddDestination = [];
    $NAT = array();
    $NONAT = array();
    $NAT_static = array();
    $NAT_static_accesslist = array();
    $NAT_accesslist = array();

    #Nat Stuff Related
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $position = 1;
    }
    else {
        $ddata = $getPosition->fetch_assoc();
        $position = $ddata['t'] + 1;
    }
    if ($nat_lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        if ($getlastlid->num_rows == 1) {
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = intval($getLID1['max']) + 1;
        } else {
            $nat_lid = 1;
        }
    }

    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = rtrim($names_line);

        #Regular Static NAT
        #static (inside,outside) 192.168.100.100 10.1.1.6 netmask 255.255.255.255
        if (preg_match_all("/^static \((.*),(.*)\)\s(tcp|udp)\s(.*)\s(.*)\saccess-list\s(.*)/", $names_line, $out)) {
            #static (dmz,outside) tcp NAT-SortidaSenseProxyPerSimetrica https access-list dmz_nat_static
            $from = $out[1][0];
            $to = $out[2][0];
            $NatID = "";
            $NAT_static_tmp = read_access_list($vsys, $source, $out[6][0], $cisco_config_file, $NAT_static_accesslist, $NatID, $from, $to, $nat_lid, $position, "pat", $out[4][0], $out[5][0]);
            $NAT_static_accesslist = $NAT_static_tmp[0];
            $nat_lid = $NAT_static_tmp[1];
            $position = $NAT_static_tmp[2];
        }
        elseif (preg_match_all("/^static \((.*),(.*)\)\s(tcp|udp)\s(.*)\s(.*)\s(.*)\s(.*)\snetmask\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", $names_line, $out)) {
            $from = $out[1][0];
            $to = $out[2][0];
            $NatID = "";
            $netmask = $out[8][0];
            $static_cidr = mask2cidrv4($netmask);
            $destination = $out[4][0];
            $destination_port = $out[5][0];
            $translated_address = $out[6][0];
            $translated_port = $out[7][0];
            $netmask = $out[8][0];
            $static_cidr = mask2cidrv4($netmask);
            $protocol = $out[3][0];
            if ($static_cidr != "32") {
                $destination = whatipaddress($out[4][0], $source, $vsys) . "/" . $static_cidr;
                $translated_address = whatipaddress($out[6][0], $source, $vsys) . "/" . $static_cidr;
            }

            if (is_numeric($destination_port)) {
                $getDport = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$destination_port' AND protocol='$protocol' LIMIT 1;");
                if ($getDport->num_rows == 1) {
                    $getDportData = $getDport->fetch_assoc();
                    $destination_port = $getDportData['name_ext'];
                } else {
                    #
                    $name_int = $protocol . "_" . $destination_port;
                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name_int','$name_int','$destination_port','$protocol')");
                    $destination_port = $name_int;
                }
            }

            if (!is_numeric($translated_port)) {
                $getDport = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$translated_port' LIMIT 1;");
                if ($getDport->num_rows == 1) {
                    $getDportData = $getDport->fetch_assoc();
                    $translated_port = $getDportData['dport'];
                } else {
                    #
                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using an Service [' . $translated_port . ' / ' . $protocol . '] that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                }
            }

            if ($translated_address == $destination) {
                #NO NAT
                add_log2('error', 'Reading Nat Policies', 'Nat rule will not be migrated becasue the source and translated address are the same. [' . $names_line . '].', $source, 'fix it manually.', '', '', '');
            } else {
                $NAT1["destination"] = $destination;
                $NAT1["nat_lid"] = $nat_lid;
                $NAT1["access-list"] = $names_line;
                $NAT1["tp_sat_type"] = "";
                $NAT1["name"] = "Rule " . $nat_lid;
                $NAT1["from"] = $to;
                $NAT1["is_dat"] = 1;
                $NAT1["op_zone_to"] = $to;
                $NAT1["position"] = $position;
                $NAT1["nat_rules_translated_address"] = $translated_address;
                $NAT1["service"] = $destination_port;
                $NAT1["tp_dat_port"] = $translated_port;
                $NAT1["tp_sat_address_type"] = "";
                $NAT_static[] = $NAT1;
                $NAT1 = [];
                $nat_lid++;
                $position++;
            }

            //print $names_line."->";
            //print "FROM:$to SRC=ANY TO:$to DST=$destination port:$destination_port TP[ SRC=ANY DST=$translated_address Port:$translated_port ] MASK:$static_cidr\n";
        }
        elseif (preg_match_all("/^static \((.*),(.*)\)\s(.*)\s(.*)\snetmask\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", $names_line, $out)) {
            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "NAT: ".$out[0][0]."\n"); fclose($my);
            $from = $out[1][0];
            $to = $out[2][0];
            $NatID = "";
            $netmask = $out[5][0];
            $static_cidr = mask2cidrv4($netmask);
            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   1-".$out[1][0].", 2-".$out[2][0].",3-".$out[3][0].", 4-".$out[4][0]." ,5-".$out[5][0]." and $static_cidr\n"); fclose($my);

            if ($static_cidr != "32") {
                $translated_src = whatipaddress($out[3][0], $source, $vsys) . "/" . $static_cidr;
                $src = whatipaddress($out[4][0], $source, $vsys) . "/" . $static_cidr;
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    NATting a network: $src -> $translated_src\n"); fclose($my);
            } else {
                $translated_src = whatipaddress($out[3][0], $source, $vsys);
                $src = whatipaddress($out[4][0], $source, $vsys);
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    NATting a host:    $src -> $translated_src\n"); fclose($my);
            }

            if ($translated_src == $src) {
                #NO NAT
                $NAT1["source"] = $src;
                $NAT1["nat_lid"] = $nat_lid;
                $NAT1["access-list"] = $names_line;
                $NAT1["tp_sat_type"] = "";
                $NAT1["name"] = "Rule " . $nat_lid . " NoNat";
                $NAT1["from"] = $from;
                $NAT1["op_zone_to"] = $to;
                $NAT1["position"] = $position;
                $NAT_static[] = $NAT1;
                $NAT1 = [];
                $nat_lid++;
                $position++;
            }
            else {

                $NAT1["source"] = $src;
                $NAT1["nat_lid"] = $nat_lid;
                $NAT1["access-list"] = $names_line;
                $NAT1["tp_sat_type"] = "static-ip";
                $NAT1["name"] = "Rule " . $nat_lid;
                $NAT1["from"] = $from;
                $NAT1["op_zone_to"] = $to;
                $NAT1["position"] = $position;
                $NAT1["nat_rules_translated_address"] = $translated_src;
                $NAT1["tp_sat_bidirectional"] = 1;
                $NAT_static[] = $NAT1;
                $NAT1 = [];
                $nat_lid++;
                $position++;
            }
        }
        elseif (preg_match_all("/^static \((.*),(.*)\)\s(.*)\saccess-list\s(.*)/", $names_line, $out)) {
            #static (outside,inside) 10.99.248.98  access-list a_policy_nat_xxx
            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Access-list:  ".$out[0][0]."\n"); fclose($my);
            $from = $out[1][0];
            $to = $out[2][0];
            $NatID = "";
            $out[3][0] = trim($out[3][0]);
            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$out[4][0].", ".$out[3][0]."-\n"); fclose($my);
            $NAT_static_tmp = read_access_list($vsys, $source, $out[4][0], $cisco_config_file, $NAT_static_accesslist, $NatID, $from, $to, $nat_lid, $position, "static", $out[3][0], "");
            $NAT_static_accesslist = $NAT_static_tmp[0];
            $nat_lid = $NAT_static_tmp[1];
            $position = $NAT_static_tmp[2];
        }
        elseif (preg_match_all("/^global \((.*)\)\s(\d+)\s(.*)/", $names_line, $out)) {
            # Dynamic
            # global (DMZ) 4 N_FAD_GENERICA netmask 255.255.0.0
            # global (WAN) 1 interface
            # nat (pweb_dmz) 0 access-list pweb_dmz_nat0_outbound
            $out2 = explode(" ", $out[3][0]);
            $global_zone = $out[1][0];
            $global_natid = $out[2][0];

            if ($out[3][0] == "interface") {
                $global[$out[2][0]][$out[1][0]][] = array("type" => "interface");
                $type = "interface";
                $getIntIP = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE template='$template' AND source='$source' AND zone='$global_zone' LIMIT 1;");
                if ($getIntIP->num_rows == 1) {
                    $getIntIPData = $getIntIP->fetch_assoc();
                    $getIntIPaddress = $getIntIPData['unitipaddress'];
                    if ($getIntIPaddress != "") {
                        $split_ipandcidr = explode("/", $getIntIPaddress);
                        $interface_ipaddress = $split_ipandcidr[0];
                        $interface_cidr = $split_ipandcidr[1];
                    }
                }
                $already = $projectdb->query("SELECT id FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND zone='$global_zone' AND natid='$global_natid' AND type='$type';");
                if ($already->num_rows == 0) {
                    $projectdb->query("INSERT INTO cisco_nat_global (natid,zone,type,address,cidr,source,vsys) VALUES ('$global_natid','$global_zone','$type','$interface_ipaddress','$interface_cidr','$source','$vsys');");
                }
            }
            else {
                $member_lid = "";
                $table_name = "";
                $hostname = "";
                $hostname_ip = $out2[0];
                if ((ip_version($hostname_ip) == "v4") OR ( ip_version($hostname_ip) == "v6")) {
                    $type = "address";
                }
                elseif(preg_match("/-/",$hostname_ip)){
                    $type = "range";
                }
                else {
                    $type = "hostname";
                    $hostname = $out2[0];
                    $getMember = $projectdb->query("SELECT id,ipaddress FROM address WHERE BINARY name_ext='$hostname_ip' AND vsys='$vsys' AND source='$source' LIMIT 1;");
                    if ($getMember->num_rows == 1) {
                        $getMemberData = $getMember->fetch_assoc();
                        $member_lid = $getMemberData['id'];
                        $table_name = "address";
                        $hostname_ip = $getMemberData['ipaddress'];
                    }
                }
                if (!isset($out2[2]) || $out2[2]=="" ){$out2[2]="32";}
                $global[$out[2][0]][$out[1][0]][] = array("type" => $type, "address" => $out2[0], "netmask" => $out2[2]);
                $already = $projectdb->query("SELECT id FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND zone='$global_zone' AND natid='$global_natid' AND type='$type' AND address='$hostname_ip' AND netmask='$out2[2]';");
                if ($already->num_rows == 0) {
                    $getcidr = mask2cidrv4($out2[2]);
                    if ($getcidr==0){$getcidr=32;}
                    $projectdb->query("INSERT INTO cisco_nat_global (natid,zone,type,address,netmask,cidr,source,vsys,member_lid,table_name,hostname) VALUES ('$global_natid','$global_zone','$type','$hostname_ip','$out2[2]','$getcidr','$source','$vsys','$member_lid','$table_name','$hostname');");
                }
            }
        }
        elseif ((preg_match_all("/^nat \((.*)\)\s(\d+)\s(.*)\s(.*)\s(.*)/",$names_line,$out)) OR (preg_match_all("/^nat \((.*)\)\s(\d+)\s(.*)\s(.*)/",$names_line,$out))){
            # nat (LAN) 0 access-list LAN_nat0_outbound
            # nat (LAN) 1 172.50.0.0 255.255.255.0
            # nat (LAN) 1 REDILO 255.255.255.0
            # nat (DMZ) 4 192.168.1.0 255.255.255.0

            $nat_interface = FALSE;
            $OPFrom = $out[1][0];
            $NatID = $out[2][0];
            $src_addr = "";
            $allNatEntry = $out[0][0];
            if ($out[3][0] == "access-list") {
                if ($NatID == 0) {
                    # NONAT
                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "is it here\n"); fclose($my);
                    $NONAT_tmp = read_access_list($vsys, $source, $out[4][0], $cisco_config_file, $NONAT, $NatID, $OPFrom, "", $nat_lid, $position, "nonat", "", "");
                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "was it here\n"); fclose($my);
                    $NONAT = $NONAT_tmp[0];
                    $nat_lid = $NONAT_tmp[1];
                    $position = $NONAT_tmp[2];
                }
                else {
                    # Read Access-lists and pass the ip to nat the source or destination
                    $static_tmp = read_access_list2($vsys, $source, $out[4][0], $cisco_config_file, $NAT_accesslist, $NatID, $OPFrom, "", $nat_lid, $position, "dynamic", "", "");
                    $NAT_accesslist = $static_tmp[0];
                    $nat_lid = $static_tmp[1];
                    $position = $static_tmp[2];
                }
            }
            else {
                $src_mask = $out[4][0];
                if ($src_mask == "255.255.255.255") {
                    $src_addr = $out[3][0];
                }
                else {
                    $src_addr = $out[3][0];
                    if (ip_version($src_addr) == "noip") {
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "HostRangeName\n"); fclose($my);
                        if ($out[4][0] != "") {
                            $addr_cidr = mask2cidrv4($src_mask);
                            $src_addr = $src_addr . "/" . $addr_cidr;
                        }
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    $src_addr\n"); fclose($my);
                    }
                    elseif (ip_version($src_addr) == "v4") {
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "HostRangeIP\n"); fclose($my);
                        $addr_cidr = mask2cidrv4($src_mask);
                        $src_addr = $src_addr . "/" . $addr_cidr;
                        if ($src_addr == "0.0.0.0/0") {
                            $src_addr = "";
                        }
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    $src_addr\n"); fclose($my);
                    }
                    elseif (ip_version($src_addr) == "v6") {
                        if (($src_addr == "::/0") OR ( $src_addr == "0:0:0:0:0:0:0:0/0")) {
                            $src_addr = "";
                        }
                    }
                }
                if ($NatID !== 0) {
                    $exists = false;
                    $getGlobals = $projectdb->query("SELECT * FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND natid='$NatID';");
                    $total_globals = $getGlobals->num_rows;
                    if ($total_globals > 0) {
                        while ($getGlobalsData = $getGlobals->fetch_assoc()) {
                            $zone = $getGlobalsData["zone"];
                            if ($getGlobalsData["type"] == "address") {
                                if (($getGlobalsData["cidr"] != "") AND ($getGlobalsData["cidr"] != "0") AND ($getGlobalsData["cidr"] != "32")){
                                    $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                                }
                                else {
                                    $element_ipaddress[] = $getGlobalsData["address"];
                                }
                            }
                            elseif ($getGlobalsData["type"] == "range") {
                                $element_ipaddress[] = $getGlobalsData["address"];
                            }
                            elseif ($getGlobalsData["type"] == "hostname") {
                                $hostname = $getGlobalsData["hostname"];
                                $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                            }
                            elseif ($getGlobalsData["type"] == "interface") {
                                $hostname = "";
                                $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                            }

                            if (count($NAT) == 0) {
                                if ($src_addr != "") {
                                    $NAT1["source"] = $src_addr;
                                }
                                $NAT1["natid"] = $NatID;
                                $NAT1["nat_lid"] = $nat_lid;
                                $NAT1["access-list"] = $names_line;
                                $NAT1["tp_sat_type"] = "dynamic-ip-and-port";
                                $NAT1["name"] = "Rule " . $nat_lid . " Nat-ID " . $NatID;
                                $NAT1["from"] = $OPFrom;
                                $NAT1["op_zone_to"] = $zone;
                                $NAT1["position"] = $position;
                                $NAT1["nat_rules_translated_address"] = implode(",", $element_ipaddress);
                                $NAT[] = $NAT1;
                                $NAT1 = [];
                                $nat_lid++;
                                $position++;
                            }
                            else {
                                foreach ($NAT as $mykey => $myobjects) {
                                    if (($myobjects["natid"] == $NatID) AND ( $myobjects["op_zone_to"] == $zone) AND ( $myobjects["from"] == $OPFrom)) {
                                        $exists = true;
                                        break;
                                    }
                                }
                                if ($exists == TRUE) {
                                    $exists = false;
                                    $src_addr_last = $NAT[$mykey]["source"] . "," . $src_addr;
                                    $NAT[$mykey]["source"] = $src_addr_last;
                                }
                                else {
                                    if ($src_addr != "") {
                                        $NAT1["source"] = $src_addr;
                                    }
                                    $NAT1["natid"] = $NatID;
                                    $NAT1["nat_lid"] = $nat_lid;
                                    $NAT1["access-list"] = $names_line;
                                    $NAT1["tp_sat_type"] = "dynamic-ip-and-port";
                                    $NAT1["name"] = "Rule " . $nat_lid . " Nat-ID " . $NatID;
                                    $NAT1["from"] = $OPFrom;
                                    $NAT1["op_zone_to"] = $zone;
                                    $NAT1["position"] = $position;
                                    $NAT1["nat_rules_translated_address"] = implode(",", $element_ipaddress);
                                    $NAT[] = $NAT1;
                                    $NAT1 = [];
                                    $nat_lid++;
                                    $position++;
                                }
                            }
                            $element_ipaddress = [];
                        }
                    }
                }
                else {
                    # Identity NAT or NONAT
                    $exists = false;
                    #Calc zone TO
                    //$getTO=$projectdb->query("SELECT ");

                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "$src_addr\n"); fclose($my);
                    if (count($NONAT) == 0) {
                        if ($src_addr != "") {
                            $NONAT1["source"] = $src_addr;
                        }
                        $NONAT1["natid"] = $NatID;
                        $NONAT1["nat_lid"] = $nat_lid;
                        $NONAT1["access-list"] = $names_line;

                        $NONAT1["name"] = "Rule " . $nat_lid . " Identity Nat";
                        $NONAT1["from"] = $OPFrom;
                        $NONAT1["op_zone_to"] = $zone;
                        $NONAT1["position"] = $position;
                        $NONAT[] = $NONAT1;
                        $NONAT1 = [];
                        $nat_lid++;
                        $position++;
                    }
                    else {
                        foreach ($NONAT as $mykey => $myobjects) {
                            if (($myobjects["natid"] == $NatID) AND ( $myobjects["op_zone_to"] == $zone) AND ( $myobjects["from"] == $OPFrom)) {
                                $exists = true;
                                break;
                            }
                        }
                        if ($exists == TRUE) {
                            $exists = false;
                            $src_addr_last = $NONAT[$mykey]["source"] . "," . $src_addr;
                            $NONAT[$mykey]["source"] = $src_addr_last;
                        }
                        else {
                            if ($src_addr != "") {
                                $NONAT1["source"] = $src_addr;
                            }
                            $NONAT1["natid"] = $NatID;
                            $NONAT1["nat_lid"] = $nat_lid;
                            $NONAT1["access-list"] = $names_line;
                            $NONAT1["name"] = "Rule " . $nat_lid . " Identity Nat ";
                            $NONAT1["from"] = $OPFrom;
                            $NONAT1["op_zone_to"] = $zone;
                            $NONAT1["position"] = $position;
                            $NONAT[] = $NONAT1;
                            $NONAT1 = [];
                            $nat_lid++;
                            $position++;
                        }
                    }
                }
            }
        }
    }

    if (count($NAT) > 0) {
        $sorted = array_orderby($NAT, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
        foreach ($sorted as $key => $value) {
            $nat_lid = $value['nat_lid'];
            $nat_description = $value['access-list'];
            $tp_sat_type = $value['tp_sat_type'];
            $nat_position = $value['position'];
            $op_zone_to = $value['op_zone_to'];
            $nat_from = $value['from'];
            $nat_rulename = $value['name'];
            $translated_address = $value['nat_rules_translated_address'];

            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   $nat_lid, $nat_description, $nat_from, $translated_address \n"); fclose($my);


            if (preg_match("/\//", $translated_address)) {
                $split = explode("/", $translated_address);
            }
            else {
                $split[0] = $translated_address;
                $split[1] = "32";
            }

            //$translated_address_parts = explode("/",$translated_address);
            if (ip_version($split[0])==="noip"){
                //Look for objects with this name.
                $getTrans = get_member_and_lid($split[0], $source, $vsys, "address");
                $member_lid = $getTrans['member_lid'];
                $table_name = $getTrans['table_name'];
                $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   $split[0] in $table_name:$member_lid\n"); fclose($my);
            }
            else{
                //Look for objects with this IP address
                $getTrans = get_member_and_lid("$split[0]/$split[1]", $source, $vsys, "ipaddress");

                if ($getTrans != ""){
                    //There is an object with such IP and CIDR
                    $member_lid = $getTrans['member_lid'];
                    $table_name = $getTrans['table_name'];
                    //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   Found as $table_name:$member_lid\n"); fclose($my);
                }
                else{
                    //Look for an existing Label
                    $getTrans = get_member_and_lid("$split[0]/0", $source, $vsys, "ipaddress");
                    if($getTrans != ""){
                        //We found a label with such IP. Let's create an object with the name
                        $label_lid = $getTrans['member_lid'];
                        $query = "SELECT name_ext, name FROM address WHERE id='$label_lid';";
                        $getLabel = $projectdb->query($query);
                        $label=$getLabel->fetch_assoc();
                        $name = $label['name_ext'];
                        $name_int = $label['name'];

                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) "
                            . "VALUES ('$source','$vsys','$name-$split[1]','$name_int-$split[1]','$split[0]','$split[1]',0, '$global_config_filename');");
                        $member_lid = $projectdb->insert_id;
                    }
                    else{
                        //There is not even a Label that we could use
                        $translated_address = str_replace("/", "-", $translated_address);
                        $translated_address = truncate_names(normalizeNames($translated_address));
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'$global_config_filename');");
                        $member_lid = $projectdb->insert_id;
                    }
                }
                $table_name = "address";
                $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
            }

            /*
            if ($getTrans == "") {
                $split = [];
                if (preg_match("/\//", $translated_address)) {
                    $split = explode("/", $translated_address);
                }
                else {
                    $split[0] = $translated_address;
                    $split[1] = "32";
                }
                if (ip_version($split[0]) == "noip") {
                    if (preg_match("/-/",$split[0])){
                        $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$split[0]' AND type='ip-range';");
                        if ($getDup->num_rows==1){
                            $getDupData=$getDup->fetch_assoc();
                            $member_lid=$getDupData['id'];
                        }
                        else {
                            $translated_address = str_replace("/", "-", $translated_address);
                            $translated_address = truncate_names(normalizeNames($translated_address));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy,type) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'ip-range');");
                            $member_lid = $projectdb->insert_id;
                        }

                    }
                    else{
                        $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$split[0]' AND cidr='$split[1]';");
                        if ($getDup->num_rows==1){
                            $getDupData=$getDup->fetch_assoc();
                            $member_lid=$getDupData['id'];
                        }
                        else{
                            $translated_address = str_replace("/", "-", $translated_address);
                            $translated_address = truncate_names(normalizeNames($translated_address));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                            $member_lid = $projectdb->insert_id;
                        }

                    }

                }
                else {
                    $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                    if ($getObj->num_rows == 1) {
                        $getObjData = $getObj->fetch_assoc();
                        $member_lid = $getObjData['id'];
                    } else {
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                        $member_lid = $projectdb->insert_id;
                    }
                }
                $table_name = "address";
                $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
            }
            else {
                $member_lid = $getTrans['member_lid'];
                $table_name = $getTrans['table_name'];
                $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                $my = fopen("ciscoNats.txt","a"); fwrite($my, "   $translated_address_parts[0] in $table_name:$member_lid\n"); fclose($my);
            }
             */

            $sources = isset($value['source'])?explode(",", $value['source']):array();
            foreach ($sources as $key => $val) {
                $realip = explode("/", $val);
                if ($realip[1] == "") {
                    $realip[1] = 32;
                }
                if ($value['source'] == "") {

                } elseif (ip_version($realip[0]) == "noip") {
                    $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                    if ($retrieve->num_rows == 1) {
                        $retrieveData = $retrieve->fetch_assoc();
                        $search_ip = $retrieveData['ipaddress'];
                        $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                        if ($searchIP->num_rows == 1) {
                            $searchIPData = $searchIP->fetch_assoc();
                            $member_lid1 = $searchIPData['id'];
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            $name_int = truncate_names(normalizeNames($realip[0]));
                            $name_int == str_replace("/", "-", $name_int);
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    } else {
                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($getGRP->num_rows == 1) {
                            $getGRPData = $getGRP->fetch_assoc();
                            $member_lid1 = $getGRPData['id'];

                            if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                add_log2('ok', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Replaced object [$realip[0]] by his members.', $source, 'No Action required.', 'rules', $nat_lid, 'nat_rules');
                                $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                if ($getMembers->num_rows > 0) {
                                    while ($getMembersData = $getMembers->fetch_assoc()) {
                                        $table_name1 = $getMembersData['table_name'];
                                        $member_lid1 = $getMembersData['member_lid'];
                                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                }
                            } else {
                                $table_name1 = "address_groups_id";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        } else {
                            add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                        }
                    }
                } else {
                    $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                    if ($retrieve->num_rows == 1) {
                        $retrieveData = $retrieve->fetch_assoc();
                        $member_lid1 = $retrieveData['id'];
                        $table_name1 = "address";
                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                    } else {
                        //$val = str_replace("-", "/", $val);
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1,'$global_config_filename');");
                        $member_lid1 = $projectdb->insert_id;
                        $table_name1 = "address";
                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                    }
                }
            }

            $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address', '$global_config_filename')";
            $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
        }

        $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type, devicegroup) VALUES " . implode(",", $add_nat_dyn) . ";");
        $unique_add_nat_from=array_unique($add_nat_from);
        $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $unique_add_nat_from) . ";");
        $unique_add_translated_address=array_unique($add_translated_address);
        $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $unique_add_translated_address) . ";");
        $add_nat_source_unique=array_unique($add_nat_source);
        $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source_unique) . ";");
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
    }
    if (count($NONAT) > 0) {
        $sorted = array_orderby($NONAT, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_nat_source = [];
        $add_nat_destination = [];
        foreach ($sorted as $key => $value) {
            $nat_lid = $value['nat_lid'];
            $nat_description = $value['access-list'];
            $nat_position = $value['position'];
            $op_zone_to = $value['op_zone_to'];
            $nat_from = $value['from'];
            $nat_rulename = $value['name'];
            $src = $value['source'];
            $dst = $value['destination'];
            $srv = $value['service'];

            if ($src != "") {
                //TODO HERE: src podria ser un grupo, o un host, o . . .!!!

                $realip = explode("/", $src);
                if ($realip[1] == "") {
                    $realip[1] = 32;
                }


                if (ip_version($realip[0]) == "noip") {
                    $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                    if ($retrieve->num_rows == 1) {
                        $retrieveData = $retrieve->fetch_assoc();
                        $search_ip = $retrieveData['ipaddress'];
                        $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                        if ($searchIP->num_rows == 1) {
                            $searchIPData = $searchIP->fetch_assoc();
                            $member_lid1 = $searchIPData['id'];
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            $name_int = truncate_names(normalizeNames($realip[0]));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                    else {
                        $query = "SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;";
                        $getGRP = $projectdb->query($query);
                        //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     $query\n");                fclose($my);
                        //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     ".$realip[0]." found here?\n");                fclose($my);
                        if ($getGRP->num_rows == 1) {
                            //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     yes\n");                fclose($my);
                            $getGRPData = $getGRP->fetch_assoc();
                            $member_lid1 = $getGRPData['id'];
                            if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                $query = "SELECT member, member_lid, table_name FROM address_groups WHERE lid='$member_lid1';";
                                $getMembers = $projectdb->query($query);
                                //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "     $query\n");                fclose($my);
                                if ($getMembers->num_rows > 0) {
                                    /*
                                     while ($getMembersData = $getMembers->fetch_assoc() ) {
                                        $subtable_name1 = $getMembersData['table_name'];
                                        $submember_lid1 = $getMembersData['member_lid'];
                                        $submember_name = $getMembersData['member'];
                                        $my = fopen("ciscoNats.txt", "a");                fwrite($my, "     $submember_name -> ('$source','$vsys','$submember_lid1','$subtable_name1','$nat_lid')\n");                fclose($my);
                                        if($submember_lid1!=0){
                                            $add_nat_source[] = "('$source','$vsys','$submember_lid1','$subtable_name1','$nat_lid')";
                                        }
                                    }
                                    */
                                    $table_name1 = "address_groups_id";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }

                            }
                            else {
                                $table_name1 = "address_groups_id";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        } else {
                            add_log2('error', 'Reading [NO]Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                        }
                    }
                } else {
                    $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                    if ($retrieve->num_rows == 1) {
                        $retrieveData = $retrieve->fetch_assoc();
                        $member_lid1 = $retrieveData['id'];
                        $table_name1 = "address";
                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                    } else {
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$src','$src','$realip[0]','$realip[1]',1,'$global_config_filename');");
                        $member_lid1 = $projectdb->insert_id;
                        $table_name1 = "address";
                        $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                    }
                }
            }

            # Destination
            if ($dst != "") {
                $realip = explode("/", $dst);
                if (!isset($realip[1]) || $realip[1] == "") {
                    $realip[1] = 32;
                }

                if (ip_version($realip[0]) == "noip") {
                    $retrieve = $projectdb->query("SELECT id,ipaddress,cidr FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                    if ($retrieve->num_rows == 1) {
                        $retrieveData = $retrieve->fetch_assoc();
                        $search_ip = $retrieveData['ipaddress'];
                        $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($searchIP->num_rows == 1) {
                            $searchIPData = $searchIP->fetch_assoc();
                            $member_lid1 = $searchIPData['id'];
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            $name_int = truncate_names(normalizeNames($realip[0]));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    } else {
                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($getGRP->num_rows == 1) {
                            $getGRPData = $getGRP->fetch_assoc();
                            $member_lid1 = $getGRPData['id'];
                            if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                $getMembers = $projectdb->query("SELECT id,member,member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                if ($getMembers->num_rows > 0) {
                                    while ($getMembersData = $getMembers->fetch_assoc()) {
                                        $membername=$getMembersData['member'];

                                        $getTrans = get_member_and_lid($membername, $source, $vsys, "address");
                                        $member_lid1 = $getTrans['member_lid'];
                                        $table_name1 = $getTrans['table_name'];
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                }
                            } else {
                                $table_name1 = "address_groups_id";
                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        } else {
                            add_log2('error', 'Reading [NO]Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                        }
                    }
                } else {
                    $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$dst' AND dummy=1 LIMIT 1;");
                    if ($retrieve->num_rows == 1) {
                        $retrieveData = $retrieve->fetch_assoc();
                        $member_lid1 = $retrieveData['id'];
                        $table_name1 = "address";
                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                    } else {
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$dst','$dst','$realip[0]','$realip[1]',1,'$global_config_filename');");
                        $member_lid1 = $projectdb->insert_id;
                        $table_name1 = "address";
                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                    }
                }
                if ($op_zone_to == "") {
                    $op_zone_to = search_zone_address_one($member_lid1, $vsys, $source, $table_name1);
                }
            }

            if ($srv != "") {
                $srv_table_name = "";
                $srv_member_lid = "";
                $retrieve = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$srv';");
                if ($retrieve->num_rows == 1) {
                    $retrieveData = $retrieve->fetch_assoc();
                    $srv_member_lid = $retrieveData['id'];
                    $srv_table_name = "services";
                } else {
                    # Is GROUP
                    $retrieveGrp = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$srv';");
                    if ($retrieveGrp->num_rows == 1) {
                        $retrieveGrpdata = $retrieveGrp->fetch_assoc();
                        $srv_member_lid = $retrieveData['id'];
                        $srv_table_name = "services_groups_id";
                    } else {
                        add_log2('error', 'Reading [NO]Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $srv . '] in service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                    }
                }
            }
            else{
                $srv_table_name = "";
                $srv_member_lid = "";
            }

            $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','','$nat_description','$op_zone_to','$nat_rulename','','$srv_member_lid','$srv_table_name','$global_config_filename')";
            $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
        }
        $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,op_service_lid,op_service_table, devicegroup) VALUES " . implode(",", $add_nat_dyn) . ";");
        $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
        $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
        $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_nat_source = [];
        $add_nat_destination = [];
    }
    if (count($NAT_static) > 0) {
        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Processing Static Nats\n"); fclose($my);
        $sorted = array_orderby($NAT_static, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
        $add_nat_destination = [];

        foreach ($sorted as $key => $value) {
            $tp_dat_port = "";
            $is_dat = 0;
            $tp_dat_address_table = "";
            $tp_dat_address_lid = "";
            $op_service_lid = "";
            $op_service_table = "";
            $tp_sat_bidirectional = 0;
            $nat_lid = $value['nat_lid'];
            $nat_description = $value['access-list'];
            $tp_sat_type = $value['tp_sat_type'];
            $nat_position = $value['position'];
            $op_zone_to = $value['op_zone_to'];
            $nat_from = $value['from'];
            $nat_rulename = $value['name'];
            $translated_address = isset($value['nat_rules_translated_address'])?$value['nat_rules_translated_address']:null;
            $tp_dat_port = isset($value['tp_dat_port'])?$value['tp_dat_port']:null;
            $is_dat = isset($value['is_dat'])?$value['is_dat']:null;
            $service = isset($value['service'])?$value['service']:null;
            $tp_sat_bidirectional = isset($value['tp_sat_bidirectional'])?$value['tp_sat_bidirectional']:null;

            if ($is_dat == 1) {
                $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                if ($getTrans == "") {
                    $split = [];
                    if (preg_match("/\//", $translated_address)) {
                        $split = explode("/", $translated_address);
                    } else {
                        $split[0] = $translated_address;
                        $split[1] = "32";
                    }
                    if (ip_version($split[0]) == "noip") {
                        $translated_address = str_replace("/", "-", $translated_address);
                        $translated_address = truncate_names(normalizeNames($translated_address));
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'$global_config_filename');");
                        $tp_dat_address_lid = $projectdb->insert_id;
                    } else {
                        $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getObj->num_rows == 1) {
                            $getObjData = $getObj->fetch_assoc();
                            $tp_dat_address_lid = $getObjData['id'];
                        } else {
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1,'$global_config_filename');");
                            $tp_dat_address_lid = $projectdb->insert_id;
                        }
                    }
                    $tp_dat_address_table = "address";
                } else {
                    $tp_dat_address_lid = $getTrans['member_lid'];
                    $tp_dat_address_table = $getTrans['table_name'];
                }
            }
            else {
                if ($translated_address == "") {

                }
                else{
                    if (preg_match("/\//", $translated_address)) {
                        $split = explode("/", $translated_address);
                    }
                    else {
                        $split[0] = $translated_address;
                        $split[1] = "32";
                    }

                    if (ip_version($split[0])==="noip"){
                        //Look for objects with this name.
                        $getTrans = get_member_and_lid($split[0], $source, $vsys, "address");
                        $member_lid = $getTrans['member_lid'];
                        $table_name = $getTrans['table_name'];
                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   $split[0] in $table_name:$member_lid\n"); fclose($my);
                    }
                    else{
                        //Look for objects with this IP address
                        $getTrans = get_member_and_lid("$split[0]/$split[1]", $source, $vsys, "ipaddress");

                        if ($getTrans != ""){
                            //There is an object with such IP and CIDR
                            $member_lid = $getTrans['member_lid'];
                            $table_name = $getTrans['table_name'];
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "   Found as $table_name:$member_lid\n"); fclose($my);
                        }
                        else{
                            //Look for an existing Label
                            $getTrans = get_member_and_lid("$split[0]/0", $source, $vsys, "ipaddress");
                            if($getTrans != ""){
                                //We found a label with such IP. Let's create an object with the name
                                $label_lid = $getTrans['member_lid'];
                                $query = "SELECT name_ext, name FROM address WHERE id='$label_lid';";
                                $getLabel = $projectdb->query($query);
                                $label=$getLabel->fetch_assoc();
                                $name = $label['name_ext'];
                                $name_int = $label['name'];

                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) "
                                    . "VALUES ('$source','$vsys','$name-$split[1]','$name_int-$split[1]','$split[0]','$split[1]',0,'$global_config_filename');");
                                $member_lid = $projectdb->insert_id;
                            }
                            else{
                                //There is not even a Label that we could use
                                $translated_address = str_replace("/", "-", $translated_address);
                                $translated_address = truncate_names(normalizeNames($translated_address));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) "
                                    . "VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'$global_config_filename');");
                                $member_lid = $projectdb->insert_id;
                            }
                        }
                        $table_name = "address";
                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    }
                }

                /*
                else {
                    if (ip_version($translated_address == "v4")){
                        $split = [];
                        //Looking for an object that matches the IP and CIDR
                        if (preg_match("/\//", $translated_address)) {
                            $split = explode("/", $translated_address);
                        } else {
                            $split[0] = $translated_address;
                            $split[1] = "32";
                        }
                        $getTrans = get_member_and_lid($split[0]."/".$split[1], $source, $vsys, "ipaddress");


                        //Looking for an object that it is a label, so it does not have CIDR
//                        if ($getTrans == "") {
//                            $split[1] = "0";
//                            $getTrans = get_member_and_lid($split[0]."/".$split[1], $source, $vsys, "ipaddress");
//                        }


                        if ($getTrans == "") {
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Translated Address $translated_address not found\n"); fclose($my);
//
//                            $split = [];
//                            if (preg_match("/\//", $translated_address)) {
//                                $split = explode("/", $translated_address);
//                            } else {
//                                $split[0] = $translated_address;
//                                $split[1] = "32";
//                            }

                            if (ip_version($split[0]) == "noip") {
                                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    NOIP $translated_address\n"); fclose($my);
                                $translated_address = str_replace("/", "-", $translated_address);
                                $translated_address = truncate_names(normalizeNames($translated_address));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                                $member_lid = $projectdb->insert_id;
                            } else {
                                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    YESIP $translated_address\n"); fclose($my);
                                $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if ($getObj->num_rows == 1) {
                                    $getObjData = $getObj->fetch_assoc();
                                    $member_lid = $getObjData['id'];
                                } else {
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                                    $member_lid = $projectdb->insert_id;
                                }
                            }
                            $table_name = "address";
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                        else {
                            $member_lid = $getTrans['member_lid'];
                            $table_name = $getTrans['table_name'];
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                    }
                    else{
                        $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                        if ($getTrans == "") {
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Translated Address $translated_address not found\n"); fclose($my);
                            $split = [];
                            if (preg_match("/\//", $translated_address)) {
                                $split = explode("/", $translated_address);
                            } else {
                                $split[0] = $translated_address;
                                $split[1] = "32";
                            }
                            if (ip_version($split[0]) == "noip") {
                                $translated_address = str_replace("/", "-", $translated_address);
                                $translated_address = truncate_names(normalizeNames($translated_address));
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0);");
                                $member_lid = $projectdb->insert_id;
                            } else {
                                $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if ($getObj->num_rows == 1) {
                                    $getObjData = $getObj->fetch_assoc();
                                    $member_lid = $getObjData['id'];
                                } else {
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1);");
                                    $member_lid = $projectdb->insert_id;
                                }
                            }
                            $table_name = "address";
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                        else {
                            $member_lid = $getTrans['member_lid'];
                            $table_name = $getTrans['table_name'];
                            $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                        }
                    }

                }
                 */
            }

            if (isset($value['source'])) {
                $sources = explode(",", $value['source']);
                foreach ($sources as $key => $val) {
                    $realip = explode("/", $val);
                    if (!isset($realip[1]) || $realip[1] == "") {
                        $realip[1] = 32;
                    }
                    if ($value['source'] == "") {

                    }
                    elseif (ip_version($realip[0]) == "noip") {
                        $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $search_ip = $retrieveData['ipaddress'];
                            $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                            if ($searchIP->num_rows == 1) {
                                $searchIPData = $searchIP->fetch_assoc();
                                $member_lid1 = $searchIPData['id'];
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                $name_int = truncate_names(normalizeNames($realip[0]));
                                $name_int == str_replace("/", "-", $name_int);
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        } else {
                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($getGRP->num_rows == 1) {
                                $getGRPData = $getGRP->fetch_assoc();
                                $member_lid1 = $getGRPData['id'];

                                if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                    if ($getMembers->num_rows > 0) {
                                        while ($getMembersData = $getMembers->fetch_assoc()) {
                                            $table_name1 = $getMembersData['table_name'];
                                            $member_lid1 = $getMembersData['member_lid'];
                                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    }
                                } else {
                                    $table_name1 = "address_groups_id";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            }
                            else {
                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                            }
                        }
                    }
                    else {
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    Source Address $realip[0] - $realip[1]"); fclose($my);
                        $query = "SELECT ipaddress, cidr FROM address WHERE id=185;";
                        $test = $projectdb->query($query);
                        $data = $test->fetch_assoc();
                        //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$data['ipaddress']." - ".$data['cidr']."\n"); fclose($my);
                        //$query = "SELECT id, ipaddress, cidr FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;";
                        $query = "SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;";
                        $retrieve = $projectdb->query($query);

                        if ($retrieve->num_rows == 1){
                            //The Host or Range already exists
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$realip[0]."-".$realip[1]." Found with ID $member_lid1\n"); fclose($my);
                        }
                        else{
                            //The Host or Range does not exist
                            $query = "SELECT * FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='0' LIMIT 1;;";
                            $retrieve = $projectdb->query($query);

                            if ($retrieve->num_rows > 0){
                                //There exist a label with the same name
                                $label = $retrieve->fetch_assoc();
                                $name = $label['name']."-".$realip[1];
                                $name_int = $label['name']."-".$realip[1];
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$name','$name_int','$realip[0]','$realip[1]',0,'$global_config_filename');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$realip[0]."-".$realip[1]." Not found, but yes to label $name_int\n"); fclose($my);
                            }
                            else{
                                //There is nothing that brings us information about this new Host or Range. We need to create a new object.
                                $val = str_replace("/", "-", $val);
                                //This object has been corrected in its name. It has a - instead of a /, therefore it is not a dummy object anymore.
                                //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1);");
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',0,'$global_config_filename');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                //$my = fopen("ciscoNats.txt","a"); fwrite($my, "    ".$realip[0]."-".$realip[1]." Not found. Not even a label\n"); fclose($my);
                            }

                        }
                    }
                }
            }

            if (isset($value['destination'])) {
                $sources = explode(",", $value['destination']);
                foreach ($sources as $key => $val) {
                    $realip = explode("/", $val);
                    if ($realip[1] == "") {
                        $realip[1] = 32;
                    }

                    if ($value['destination'] == "") {

                    } elseif (ip_version($realip[0]) == "noip") {
                        if ($realip[0] == "interface") {
                            $getInt = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE zone='$op_zone_to' AND source='$source' LIMIT 1");
                            if ($getInt->num_rows == 1) {
                                $getIndData = $getInt->fetch_assoc();
                                $interface = explode("/", $getIndData['unitipaddress']);
                                $interface_ipaddress = $interface[0];
                                $interface_cidr = $interface[1];
                                $getIntObj = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$interface_ipaddress' AND cidr='$interface_cidr';");
                                if ($getIntObj->num_rows == 1) {
                                    $getIntObjData = $getIntObj->fetch_assoc();
                                    $member_lid1 = $getIntObjData['id'];
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','services','$nat_lid')";
                                } else {
                                    $interface = str_replace("/", "/", $getIndData['unitipaddress']);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$interface','$interface','$interface_ipaddress','$interface_cidr',1,'$global_config_filename');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Unable to retrieve IP address based on Zone [' . $op_zone_to . '].', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                            }
                        } else {
                            $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $search_ip = $retrieveData['ipaddress'];
                                $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                if ($searchIP->num_rows == 1) {
                                    $searchIPData = $searchIP->fetch_assoc();
                                    $member_lid1 = $searchIPData['id'];
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                } else {
                                    $name_int = truncate_names(normalizeNames($realip[0]));
                                    $name_int == str_replace("/", "-", $name_int);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                if ($getGRP->num_rows == 1) {
                                    $getGRPData = $getGRP->fetch_assoc();
                                    $member_lid1 = $getGRPData['id'];

                                    if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                        if ($getMembers->num_rows > 0) {
                                            while ($getMembersData = $getMembers->fetch_assoc()) {
                                                $table_name1 = $getMembersData['table_name'];
                                                $member_lid1 = $getMembersData['member_lid'];
                                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                            }
                                        }
                                    } else {
                                        $table_name1 = "address_groups_id";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                }
                            }
                        }
                    } else {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            //$val = str_replace("-", "/", $val);
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1,'$global_config_filename');");
                            //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$realip[0]/$realip[1]','$realip[0]/$realip[1]','$realip[0]','$realip[1]',1);");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                }
            }

            if (isset($value['service'])) {
                if ($value['service'] == "") {

                } else {
                    $getSRV = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$service' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                    if ($getSRV->num_rows == 1) {
                        $getSRVData = $getSRV->fetch_assoc();
                        $op_service_lid = $getSRVData['id'];
                        $op_service_table = "services";
                    } else {
                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $service . '] in Service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                    }
                }
            }

            $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address','$tp_dat_port','$is_dat','$tp_dat_address_lid','$tp_dat_address_table','$op_service_lid','$op_service_table','$tp_sat_bidirectional','$global_config_filename')";
            $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
        }

        $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,tp_dat_port,is_dat,tp_dat_address_lid,tp_dat_address_table,op_service_lid,op_service_table,tp_sat_bidirectional,devicegroup) VALUES " . implode(",", $add_nat_dyn) . ";");
        $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
        $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_translated_address) . ";");
        $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
        $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
        $add_nat_destination = [];
    }
    if (count($NAT_static_accesslist) > 0) {
        $sorted = array_orderby($NAT_static_accesslist, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
        $add_nat_destination = [];

        foreach ($sorted as $key => $value) {
            $tp_dat_port = "";
            $is_dat = 0;
            $tp_dat_address_table = "";
            $tp_dat_address_lid = "";
            $op_service_lid = "";
            $op_service_table = "";
            $tp_sat_bidirectional = 0;
            $nat_lid = $value['nat_lid'];
            $nat_description = $value['access-list'];
            $tp_sat_type = $value['tp_sat_type'];
            $nat_position = $value['position'];
            $op_zone_to = $value['op_zone_to'];
            $nat_from = $value['from'];
            $nat_rulename = $value['name'];
            $translated_address = $value['nat_rules_translated_address'];
            $tp_dat_port = $value['tp_dat_port'];
            $is_dat = $value['is_dat'];
            $service = $value['service'];
            $tp_sat_bidirectional = $value['tp_sat_bidirectional'];

            if ($is_dat == 1) {
                $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                if ($getTrans == "") {
                    $split = [];
                    if (preg_match("/\//", $translated_address)) {
                        $split = explode("/", $translated_address);
                    } else {
                        $split[0] = $translated_address;
                        $split[1] = "32";
                    }
                    if (ip_version($split[0]) == "noip") {
                        $translated_address = str_replace("/", "-", $translated_address);
                        $translated_address = truncate_names(normalizeNames($translated_address));
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'$global_config_filename');");
                        $tp_dat_address_lid = $projectdb->insert_id;
                    } else {
                        $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getObj->num_rows == 1) {
                            $getObjData = $getObj->fetch_assoc();
                            $tp_dat_address_lid = $getObjData['id'];
                        } else {
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1, '$global_config_filename');");
                            $tp_dat_address_lid = $projectdb->insert_id;
                        }
                    }
                    $tp_dat_address_table = "address";
                } else {
                    $tp_dat_address_lid = $getTrans['member_lid'];
                    $tp_dat_address_table = $getTrans['table_name'];
                }
            } else {
                if ($translated_address == "") {

                } else {
                    $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                    if ($getTrans == "") {
                        $split = [];
                        if (preg_match("/\//", $translated_address)) {
                            $split = explode("/", $translated_address);
                        } else {
                            $split[0] = $translated_address;
                            $split[1] = "32";
                        }
                        if (ip_version($split[0]) == "noip") {
                            $translated_address = str_replace("/", "-", $translated_address);
                            $translated_address = truncate_names(normalizeNames($translated_address));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'$global_config_filename');");
                            $member_lid = $projectdb->insert_id;
                        } else {
                            $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getObj->num_rows == 1) {
                                $getObjData = $getObj->fetch_assoc();
                                $member_lid = $getObjData['id'];
                            } else {
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1,'$global_config_filename');");
                                $member_lid = $projectdb->insert_id;
                            }
                        }
                        $table_name = "address";
                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    } else {
                        $member_lid = $getTrans['member_lid'];
                        $table_name = $getTrans['table_name'];
                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    }
                }
            }

            if (isset($value['source'])) {
                $sources = explode(",", $value['source']);
                foreach ($sources as $key => $val) {
                    $realip = explode("/", $val);
                    if ($realip[1] == "") {
                        $realip[1] = 32;
                    }
                    if ($value['source'] == "") {

                    } elseif (ip_version($realip[0]) == "noip") {
                        $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $search_ip = $retrieveData['ipaddress'];
                            $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                            if ($searchIP->num_rows == 1) {
                                $searchIPData = $searchIP->fetch_assoc();
                                $member_lid1 = $searchIPData['id'];
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                $name_int = truncate_names(normalizeNames($realip[0]));
                                //$name_int = str_replace("-", "/", $name_int);
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        } else {
                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($getGRP->num_rows == 1) {
                                $getGRPData = $getGRP->fetch_assoc();
                                $member_lid1 = $getGRPData['id'];

                                if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                    if ($getMembers->num_rows > 0) {
                                        while ($getMembersData = $getMembers->fetch_assoc()) {
                                            $table_name1 = $getMembersData['table_name'];
                                            $member_lid1 = $getMembersData['member_lid'];
                                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    }
                                } else {
                                    $table_name1 = "address_groups_id";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                            }
                        }
                    } else {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            $val = str_replace("-", "/", $val);
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1,'$global_config_filename');");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                }
            }

            if (isset($value['destination'])) {
                $sources = explode(",", $value['destination']);
                foreach ($sources as $key => $val) {
                    $realip = explode("/", $val);
                    if ($realip[1] == "") {
                        $realip[1] = 32;
                    }
                    if ($value['destination'] == "") {

                    } elseif (ip_version($realip[0]) == "noip") {
                        if ($realip[0] == "interface") {
                            $getInt = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE zone='$op_zone_to' AND source='$source' LIMIT 1");
                            if ($getInt->num_rows == 1) {
                                $getIndData = $getInt->fetch_assoc();
                                $interface = explode("/", $getIndData['unitipaddress']);
                                $interface_ipaddress = $interface[0];
                                $interface_cidr = $interface[1];
                                $getIntObj = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$interface_ipaddress' AND cidr='$interface_cidr';");
                                if ($getIntObj->num_rows == 1) {
                                    $getIntObjData = $getIntObj->fetch_assoc();
                                    $member_lid1 = $getIntObjData['id'];
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','services','$nat_lid')";
                                } else {
                                    $interface = str_replace("/", "/", $getIndData['unitipaddress']);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$interface','$interface','$interface_ipaddress','$interface_cidr',1,'$global_config_filename');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Unable to retrieve IP address based on Zone [' . $op_zone_to . '].', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                            }
                        } else {
                            $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $search_ip = $retrieveData['ipaddress'];
                                $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                if ($searchIP->num_rows == 1) {
                                    $searchIPData = $searchIP->fetch_assoc();
                                    $member_lid1 = $searchIPData['id'];
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                } else {
                                    $name_int = truncate_names(normalizeNames($realip[0]));
                                    $name_int == str_replace("/", "-", $name_int);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                if ($getGRP->num_rows == 1) {
                                    $getGRPData = $getGRP->fetch_assoc();
                                    $member_lid1 = $getGRPData['id'];

                                    if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                        if ($getMembers->num_rows > 0) {
                                            while ($getMembersData = $getMembers->fetch_assoc()) {
                                                $table_name1 = $getMembersData['table_name'];
                                                $member_lid1 = $getMembersData['member_lid'];
                                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                            }
                                        }
                                    } else {
                                        $table_name1 = "address_groups_id";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                }
                            }
                        }
                    } else {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            //$val = str_replace("-", "/", $val);
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1,'$global_config_filename');");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                }
            }

            if (isset($value['service'])) {
                if ($service == "") {

                } else {
                    $getSRV = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$service' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                    if ($getSRV->num_rows == 1) {
                        $getSRVData = $getSRV->fetch_assoc();
                        $op_service_lid = $getSRVData['id'];
                        $op_service_table = "services";
                    } else {
                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $service . '] in Service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                    }
                }
            }

            $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address','$tp_dat_port','$is_dat','$tp_dat_address_lid','$tp_dat_address_table','$op_service_lid','$op_service_table','$tp_sat_bidirectional', '$global_config_filename')";
            $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
        }

        $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,tp_dat_port,is_dat,tp_dat_address_lid,tp_dat_address_table,op_service_lid,op_service_table,tp_sat_bidirectional, devicegroup) VALUES " . implode(",", $add_nat_dyn) . ";");
        $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
        $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_translated_address) . ";");
        $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
        $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
        $add_nat_destination = [];
    }
    if (count($NAT_accesslist) > 0) {
        $sorted = array_orderby($NAT_accesslist, 'nat_lid', SORT_ASC, 'position', SORT_ASC);
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
        $add_nat_destination = [];

        foreach ($sorted as $key => $value) {
            $tp_dat_address_table = "";
            $tp_dat_address_lid = "";
            $op_service_lid = "";
            $op_service_table = "";
            $nat_lid = $value['nat_lid'];
            $nat_description = $value['access-list'];
            $tp_sat_type = $value['tp_sat_type'];
            $nat_position = $value['position'];
            $op_zone_to = $value['op_zone_to'];
            $nat_from = $value['from'];
            $nat_rulename = $value['name'];
            $translated_address = $value['nat_rules_translated_address'];
            $tp_dat_port = isset($value['tp_dat_port'])?$value['tp_dat_port']:'';
            $is_dat = isset($value['is_dat'])?$value['is_dat']:0;
            $service = $value['service'];
            $tp_sat_bidirectional = isset($value['tp_sat_bidirectional'])?$value['tp_sat_bidirectional']:0;

            if ($is_dat == 1) {
                $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                if ($getTrans == "") {
                    $split = [];
                    if (preg_match("/\//", $translated_address)) {
                        $split = explode("/", $translated_address);
                    } else {
                        $split[0] = $translated_address;
                        $split[1] = "32";
                    }
                    if (ip_version($split[0]) == "noip") {
                        $translated_address = str_replace("/", "-", $translated_address);
                        $translated_address = truncate_names(normalizeNames($translated_address));
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'$global_config_filename');");
                        $tp_dat_address_lid = $projectdb->insert_id;
                    } else {
                        $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getObj->num_rows == 1) {
                            $getObjData = $getObj->fetch_assoc();
                            $tp_dat_address_lid = $getObjData['id'];
                        } else {
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1, '$global_config_filename');");
                            $tp_dat_address_lid = $projectdb->insert_id;
                        }
                    }
                    $tp_dat_address_table = "address";
                } else {
                    $tp_dat_address_lid = $getTrans['member_lid'];
                    $tp_dat_address_table = $getTrans['table_name'];
                }
            } else {
                if ($translated_address == "") {

                } else {
                    $getTrans = get_member_and_lid($translated_address, $source, $vsys, "address");
                    if ($getTrans == "") {
                        $split = [];
                        if (preg_match("/\//", $translated_address)) {
                            $split = explode("/", $translated_address);
                        } else {
                            $split[0] = $translated_address;
                            $split[1] = "32";
                        }
                        if (($split[1] == 0) OR ( $split[1] == "")) {
                            $split[1] = "32";
                            $translated_address = $split[0];
                        }
                        if (ip_version($split[0]) == "noip") {
                            $translated_address = str_replace("/", "-", $translated_address);
                            $translated_address = truncate_names(normalizeNames($translated_address));
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',0,'$global_config_filename');");
                            $member_lid = $projectdb->insert_id;
                        } else {
                            $getObj = $projectdb->query("SELECT id FROM address WHERE ipaddress='$split[0]' AND cidr='32' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getObj->num_rows == 1) {
                                $getObjData = $getObj->fetch_assoc();
                                $member_lid = $getObjData['id'];
                            } else {
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$translated_address','$translated_address','$split[0]','$split[1]',1, '$global_config_filename');");
                                $member_lid = $projectdb->insert_id;
                            }
                        }
                        $table_name = "address";
                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    } else {
                        $member_lid = $getTrans['member_lid'];
                        $table_name = $getTrans['table_name'];
                        $add_translated_address[] = "('$source','$vsys','$member_lid','$table_name','$nat_lid')";
                    }
                }
            }

            if (isset($value['source'])) {
                $sources = explode(",", $value['source']);
                foreach ($sources as $key => $val) {
                    $realip = explode("/", $val);
                    if ($realip[1] == "") {
                        $realip[1] = 32;
                    }
                    if ($value['source'] == "") {

                    } elseif (ip_version($realip[0]) == "noip") {
                        $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $search_ip = $retrieveData['ipaddress'];
                            $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                            if ($searchIP->num_rows == 1) {
                                $searchIPData = $searchIP->fetch_assoc();
                                $member_lid1 = $searchIPData['id'];
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            } else {
                                $name_int = truncate_names(normalizeNames($realip[0]));
                                $name_int == str_replace("/", "-", $name_int);
                                $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                                $member_lid1 = $projectdb->insert_id;
                                $table_name1 = "address";
                                $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                            }
                        } else {
                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($getGRP->num_rows == 1) {
                                $getGRPData = $getGRP->fetch_assoc();
                                $member_lid1 = $getGRPData['id'];

                                if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                    if ($getMembers->num_rows > 0) {
                                        while ($getMembersData = $getMembers->fetch_assoc()) {
                                            $table_name1 = $getMembersData['table_name'];
                                            $member_lid1 = $getMembersData['member_lid'];
                                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                        }
                                    }
                                } else {
                                    $table_name1 = "address_groups_id";
                                    $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Source that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                            }
                        }
                    } else {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            //$val = str_replace("-", "/", $val);
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1,'$global_config_filename');");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_source[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                }
            }

            if (isset($value['destination'])) {
                $sources = explode(",", $value['destination']);
                foreach ($sources as $key => $val) {
                    $realip = explode("/", $val);
                    if ($realip[1] == "") {
                        $realip[1] = 32;
                    }
                    if ($value['destination'] == "") {

                    } elseif (ip_version($realip[0]) == "noip") {
                        if ($realip[0] == "interface") {
                            $getInt = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE zone='$op_zone_to' AND source='$source' LIMIT 1");
                            if ($getInt->num_rows == 1) {
                                $getIndData = $getInt->fetch_assoc();
                                $interface = explode("/", $getIndData['unitipaddress']);
                                $interface_ipaddress = $interface[0];
                                $interface_cidr = $interface[1];
                                $getIntObj = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$interface_ipaddress' AND cidr='$interface_cidr';");
                                if ($getIntObj->num_rows == 1) {
                                    $getIntObjData = $getIntObj->fetch_assoc();
                                    $member_lid1 = $getIntObjData['id'];
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','services','$nat_lid')";
                                } else {
                                    $interface = str_replace("/", "/", $getIndData['unitipaddress']);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$interface','$interface','$interface_ipaddress','$interface_cidr',1,'$global_config_filename');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] Unable to retrieve IP address based on Zone [' . $op_zone_to . '].', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                            }
                        } else {
                            $retrieve = $projectdb->query("SELECT id,ipaddress FROM address WHERE vsys='$vsys' AND source='$source' AND BINARY name_ext='$realip[0]' LIMIT 1;");
                            if ($retrieve->num_rows == 1) {
                                $retrieveData = $retrieve->fetch_assoc();
                                $search_ip = $retrieveData['ipaddress'];
                                $searchIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$search_ip' AND cidr='$realip[1]' AND source='$source' AND vsys='$vsys';");
                                if ($searchIP->num_rows == 1) {
                                    $searchIPData = $searchIP->fetch_assoc();
                                    $member_lid1 = $searchIPData['id'];
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                } else {
                                    $name_int = truncate_names(normalizeNames($realip[0]));
                                    $name_int == str_replace("/", "-", $name_int);
                                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr, devicegroup) VALUES ('$source','$vsys','$realip[0]-$realip[1]','$name_int-$realip[1]','$search_ip','$realip[1]','$global_config_filename');");
                                    $member_lid1 = $projectdb->insert_id;
                                    $table_name1 = "address";
                                    $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                }
                            } else {
                                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE vsys='$vsys' AND source='$source' ANd BINARY name_ext='$realip[0]' LIMIT 1;");
                                if ($getGRP->num_rows == 1) {
                                    $getGRPData = $getGRP->fetch_assoc();
                                    $member_lid1 = $getGRPData['id'];

                                    if (preg_match("/^DM_INLINE_NETWORK/", $realip[0])) {
                                        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid='$member_lid1';");
                                        if ($getMembers->num_rows > 0) {
                                            while ($getMembersData = $getMembers->fetch_assoc()) {
                                                $table_name1 = $getMembersData['table_name'];
                                                $member_lid1 = $getMembersData['member_lid'];
                                                $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                            }
                                        }
                                    } else {
                                        $table_name1 = "address_groups_id";
                                        $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                                    }
                                } else {
                                    add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $realip[0] . '] in Destination that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                                }
                            }
                        }
                    } else {
                        $retrieve = $projectdb->query("SELECT id FROM address WHERE vsys='$vsys' AND source='$source' AND ipaddress='$realip[0]' AND cidr='$realip[1]' LIMIT 1;");
                        if ($retrieve->num_rows == 1) {
                            $retrieveData = $retrieve->fetch_assoc();
                            $member_lid1 = $retrieveData['id'];
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        } else {
                            //$val = str_replace("-", "/", $val);
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy, devicegroup) VALUES ('$source','$vsys','$val','$val','$realip[0]','$realip[1]',1,'$global_config_filename');");
                            $member_lid1 = $projectdb->insert_id;
                            $table_name1 = "address";
                            $add_nat_destination[] = "('$source','$vsys','$member_lid1','$table_name1','$nat_lid')";
                        }
                    }
                }
            }

            if (isset($value['service'])) {
                if ($service == "") {

                } else {
                    $getSRV = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$service' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                    if ($getSRV->num_rows == 1) {
                        $getSRVData = $getSRV->fetch_assoc();
                        $op_service_lid = $getSRVData['id'];
                        $op_service_table = "services";
                    } else {
                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $service . '] in Service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                    }
                }
            }

            $add_nat_dyn[] = "('$source','$vsys','$nat_position','$nat_lid','$tp_sat_type','$nat_description','$op_zone_to','$nat_rulename','translated-address','$tp_dat_port','$is_dat','$tp_dat_address_lid','$tp_dat_address_table','$op_service_lid','$op_service_table','$tp_sat_bidirectional','$global_config_filename')";
            $add_nat_from[] = "('$source','$vsys','$nat_lid','$nat_from')";
        }

        $projectdb->query("INSERT INTO nat_rules (source,vsys,position,id,tp_sat_type,description,op_zone_to,name,tp_sat_address_type,tp_dat_port,is_dat,tp_dat_address_lid,tp_dat_address_table,op_service_lid,op_service_table,tp_sat_bidirectional,devicegroup) VALUES " . implode(",", $add_nat_dyn) . ";");
        $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $add_nat_from) . ";");
        $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_translated_address) . ";");
        $projectdb->query("INSERT INTO nat_rules_src (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_source) . ";");
        $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $add_nat_destination) . ";");
        $add_nat_dyn = [];
        $add_nat_from = [];
        $add_translated_address = [];
        $add_nat_source = [];
        $add_nat_destination = [];
    }
}

function array_orderby() {
    $args = func_get_args();
    $data = array_shift($args);
    foreach ($args as $n => $field) {
        if (is_string($field)) {
            $tmp = array();
            foreach ($data as $key => $row)
                $tmp[$key] = $row[$field];
            $args[$n] = $tmp;
        }
    }
    $args[] = &$data;
    call_user_func_array('array_multisort', $args);
    return array_pop($args);
}

function whatipaddress($ipaddress, $source, $vsys) {
    global $projectdb;
    if (ip_version($ipaddress) == "noip") {
        $getIP = $projectdb->query("SELECT ipaddress FROM address WHERE BINARY name_ext='$ipaddress' AND source='$source' AND vsys='$vsys' LIMIT 1;");
        if ($getIP->num_rows == 1) {
            $getIPData = $getIP->fetch_assoc();
            return $getIPData['ipaddress'];
        }
    } else {
        return $ipaddress;
    }
}

function read_access_list($vsys, $source, $accesslist, $cisco_config_file, $ARRAY, $NatID, $OPFrom, $op_zone_to, $nat_lid, $position, $type, $translated_address, $translated_port) {
    global $projectdb;
    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = rtrim($names_line);
        if ((preg_match("/^access-list $accesslist /", $names_line)) AND ( preg_match("/ permit /", $names_line))) {
            $isSourcePort = false;
            $split = explode(" ", $names_line);
            # Cleaning
            $remove = array("access-list", $accesslist, "extended", "permit");
            foreach ($remove as $kremove => $del_val) {
                if (($key = array_search($del_val, $split)) !== false) {
                    unset($split[$key]);
                }
            }
            # Init vars
            $protocol = "";
            $split = array_values($split);

            $start = 0;
            if (($split[$start] == "ip") OR ( $split[$start] == "tcp") OR ( $split[$start] == "udp")) {
                $protocol = $split[$start];
                unset($split[$start]);
            }
            else {
                add_log2('error', 'Reading Nat Policies', 'Access-list [' . $accesslist . '] with protocol other than TCP or UDP Or IP [' . $split[$start] . '].', $source, 'fix it manually.', '', '', '');
                continue;
            }
            $split = array_values($split);

            # GET SOURCES
            if ($split[$start] == "host") {
                //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "host\n");                fclose($my);
                $src = $split[$start + 1];
                $start = $start + 2;
            }
            elseif ($split[$start] == "object-group") {
                //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "object-group\n");                fclose($my);
                $src = $split[$start + 1];
                $start = $start + 2;
            }
            elseif ($split[$start] == "object") {
                //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "object\n");                fclose($my);
                $src = $split[$start + 1];
                $start = $start + 2;
            }
            elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "any\n");                fclose($my);
                $start++;
            }
            else {
                //$my = fopen("ciscoNats.txt", "a");                fwrite($my, "noip\n");                fclose($my);
                # NAME or IP ADDRESS
                if (ip_version($split[$start]) == "noip") {
                    # NAME
                    $src = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                } else {
                    # IP ADDRESS
                    $src = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                }
            }

            # GET DESTINATIONS
            if ($split[$start] == "host") {
                $dst = $split[$start + 1];
                $start = $start + 2;
            }
            elseif ($split[$start] == "object-group") {
                $dst = $split[$start + 1];
                $start = $start + 2;
            }
            elseif ($split[$start] == "object") {
                $dst = $split[$start + 1];
                $start = $start + 2;
            }
            elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                $start++;
            }
            elseif (($split[$start] == "eq") OR ( $split[$start] == "lt") OR ( $split[$start] == "gt") OR ( $split[$start] == "neq") OR ( $split[$start] == "range")) {
                print "IS SOURCE SERVICE:" . $split[$start + 1] . "\n";
                $isSourcePort = true;
                if ($split[$start] == "range") {
                    $start = $start + 3;
                } else {
                    $start = $start + 2;
                }
            }
            else {
                # NAME or IP ADDRESS
                if (ip_version($split[$start]) == "noip") {
                    # NAME
                    $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                } else {
                    # IP ADDRESS
                    $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                }
            }

            # If was source port then has to come the destination
            if ($isSourcePort == TRUE) {
                # Get Destination
                if ($split[$start] == "host") {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                } elseif ($split[$start] == "object-group") {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                } elseif ($split[$start] == "object") {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                } elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                    $start++;
                } else {
                    # NAME or IP ADDRESS
                    if (ip_version($split[$start]) == "noip") {
                        # NAME
                        $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    } else {
                        # IP ADDRESS
                        $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                }
                $dst = "";
            }

            # Get SERVICES
            if(isset($split[$start])) {
                if (($split[$start] == "eq") OR ($split[$start] == "lt") OR ($split[$start] == "gt") OR ($split[$start] == "neq") OR ($split[$start] == "range")) {
                    $srv = $split[$start + 1];
                    if (is_numeric($srv)) {
                        if ($split[$start] == "eq") {
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "lt") {
                            $srv = "0-" . $srv;
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "gt") {
                            $srv = $srv . "-65535";
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "neq") {
                            $srv1 = intval($srv) - 1;
                            $srv2 = intval($srv) + 1;
                            $srv = "0-" . $srv1 . "," . $srv2 . "-65535";
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "range") {
                            $first = $split[$start + 1];
                            $second = $split[$start + 2];
                            if (!is_numeric($second)) {
                                $getSecond = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name='$second' LIMIT 1;");
                                if ($getSecond->num_rows == 1) {
                                    $getSecondData = $getSecond->fetch_assoc();
                                    $second = $getSecondData['dport'];
                                }
                            }
                            $srv = $first . "-" . $second;
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        }
                    } else {

                    }
                }
                elseif ($split[$start] == "object-group") {
                    $srv = $split[$start + 1];
                }
            }
            $NONAT1["natid"] = $NatID;
            $NONAT1["nat_lid"] = $nat_lid;
            $NONAT1["access-list"] = $names_line;
            if ($NatID == "") {
                $NONAT1["name"] = "Rule " . $nat_lid;
            }
            elseif ($NatID > 0) {
                $NONAT1["name"] = "Rule " . $nat_lid . " Nat ID " . $NatID;
            }
            else {
                $NONAT1["name"] = "Rule " . $nat_lid . " Identity Nat";
            }

            $NONAT1["from"] = $OPFrom;
            $NONAT1["op_zone_to"] = $op_zone_to;
            $NONAT1["position"] = $position;
            //$my = fopen("ciscoNats.txt","a"); fwrite($my, "IdentityNat $NatID: $src\n"); fclose($my);
            $NONAT1["source"] = isset($src)?$src:'';
            $NONAT1["destination"] = $dst;
            $NONAT1["service"] = isset($srv)?$srv:'';

            if ($type == "static") {
                $NONAT1["tp_sat_type"] = "static-ip";
                $NONAT1["nat_rules_translated_address"] = trim($translated_address);
                //$NONAT1["tp_sat_address_type"]="translated-addres";
            }
            elseif ($type == "pat") {
                if ($srv == "") {
                    $NONAT1["tp_sat_type"] = "static-ip";
                    $NONAT1["tp_sat_bidirectional"] = 1;
                } else {
                    $NONAT1["is_dat"] = "1";

                    if (!is_numeric($translated_port)) {
                        $getDport = $projectdb->query("SELECT dport FROM services WHERE BINARY name_ext='$translated_port' AND vsys='$vsys' AND source='$source' LIMIT 1;");
                        if ($getDport->num_rows == 1) {
                            $getDportData = $getDport->fetch_assoc();
                            $translated_port = $getDportData['dport'];
                        } else {
                            add_log2('error', 'Reading [NO]Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using object [' . $translated_port . '] in service that is not defined in my Database.', $source, 'fix it manually.', 'rules', $nat_lid, 'nat_rules');
                        }
                    }
                    $NONAT1["tp_dat_port"] = $translated_port;
                }

                $NONAT1["nat_rules_translated_address"] = trim($translated_address);
            }

            $ARRAY[] = $NONAT1;
            $NONAT1 = [];
            $nat_lid++;
            $position++;
            $src = "";
            $dst = "";
            $srv = "";
            $isSourcePort = false;
        }
    }
    return array($ARRAY, $nat_lid, $position);
}

function read_access_list2($vsys, $source, $accesslist, $cisco_config_file, $ARRAY, $NatID, $OPFrom, $op_zone_to, $nat_lid, $position, $type, $translated_address, $translated_port) {
    global $projectdb;
    foreach ($cisco_config_file as $line => $names_line) {
        $names_line = rtrim($names_line);
        if ((preg_match("/^access-list $accesslist /", $names_line)) AND ( preg_match("/ permit /", $names_line))) {
            $isSourcePort = false;
            $split = explode(" ", $names_line);
            # Cleaning
            $remove = array("access-list", $accesslist, "extended", "permit");
            foreach ($remove as $kremove => $del_val) {
                if (($key = array_search($del_val, $split)) !== false) {
                    unset($split[$key]);
                }
            }
            # Init vars
            $protocol = "";
            $split = array_values($split);

            $start = 0;
            if (($split[$start] == "ip") OR ( $split[$start] == "tcp") OR ( $split[$start] == "udp")) {
                $protocol = $split[$start];
                unset($split[$start]);
            } else {
                add_log2('error', 'Reading Nat Policies', 'Access-list [' . $accesslist . '] with protocol other than TCP or UDP Or IP [' . $split[$start] . '].', $source, 'fix it manually.', '', '', '');
                continue;
            }
            $split = array_values($split);

            # GET SOURCES
            if ($split[$start] == "host") {
                $src = $split[$start + 1];
                $start = $start + 2;
            } elseif ($split[$start] == "object-group") {
                $src = $split[$start + 1];
                $start = $start + 2;
            } elseif ($split[$start] == "object") {
                $src = $split[$start + 1];
                $start = $start + 2;
            } elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                $start++;
            } else {
                # NAME or IP ADDRESS
                if (ip_version($split[$start]) == "noip") {
                    # NAME
                    $src = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                } else {
                    # IP ADDRESS
                    $src = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                }
            }

            # GET DESTINATIONS
            if ($split[$start] == "host") {
                $dst = $split[$start + 1];
                $start = $start + 2;
            } elseif ($split[$start] == "object-group") {
                $dst = $split[$start + 1];
                $start = $start + 2;
            } elseif ($split[$start] == "object") {
                $dst = $split[$start + 1];
                $start = $start + 2;
            } elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                $start++;
            } elseif (($split[$start] == "eq") OR ( $split[$start] == "lt") OR ( $split[$start] == "gt") OR ( $split[$start] == "neq") OR ( $split[$start] == "range")) {
                print "IS SOURCE SERVICE:" . $split[$start + 1] . "\n";
                $isSourcePort = true;
                if ($split[$start] == "range") {
                    $start = $start + 3;
                } else {
                    $start = $start + 2;
                }
            } else {
                # NAME or IP ADDRESS
                if (ip_version($split[$start]) == "noip") {
                    # NAME
                    $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                } else {
                    # IP ADDRESS
                    $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                    $start = $start + 2;
                }
            }

            $dst = "";

            # If was source port then has to come the destination
            if ($isSourcePort == TRUE) {
                # Get Destination

                if ($split[$start] == "host") {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                } elseif ($split[$start] == "object-group") {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                } elseif ($split[$start] == "object") {
                    $dst = $split[$start + 1];
                    $start = $start + 2;
                } elseif (($split[$start] == "any") OR ( $split[$start] == "0.0.0.0") OR ( $split[$start] == "0")) {
                    $start++;
                } else {
                    # NAME or IP ADDRESS
                    if (ip_version($split[$start]) == "noip") {
                        # NAME
                        $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    } else {
                        # IP ADDRESS
                        $dst = $split[$start] . "/" . mask2cidrv4($split[$start + 1]);
                        $start = $start + 2;
                    }
                }
                //$dst = "";
            }

            # Get SERVICES
            if(isset($split[$start])) {
                if (($split[$start] == "eq") OR ($split[$start] == "lt") OR ($split[$start] == "gt") OR ($split[$start] == "neq") OR ($split[$start] == "range")) {
                    $srv = $split[$start + 1];
                    if (is_numeric($srv)) {
                        if ($split[$start] == "eq") {
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "lt") {
                            $srv = "0-" . $srv;
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "gt") {
                            $srv = $srv . "-65535";
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "neq") {
                            $srv1 = intval($srv) - 1;
                            $srv2 = intval($srv) + 1;
                            $srv = "0-" . $srv1 . "," . $srv2 . "-65535";
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        } elseif ($split[$start] == "range") {
                            $first = $split[$start + 1];
                            $second = $split[$start + 2];
                            if (!is_numeric($second)) {
                                $getSecond = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$second' LIMIT 1;");
                                if ($getSecond->num_rows == 1) {
                                    $getSecondData = $getSecond->fetch_assoc();
                                    $second = $getSecondData['dport'];
                                }
                            }
                            $srv = $first . "-" . $second;
                            $getSRV = $projectdb->query("SELECT name_ext FROM services WHERE source='$source' AND vsys='$vsys' AND protocol='$protocol' AND dport='$srv' LIMIT 1;");
                            if ($getSRV->num_rows == 1) {
                                $getSRVData = $getSRV->fetch_assoc();
                                $srv = $getSRVData['name_ext'];
                            } else {
                                $name = $protocol . "_" . $srv;
                                $name_int = truncate_names(normalizeNames($name));
                                $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','$name','$name_int','$srv','$protocol');");
                                $srv = $name;
                            }
                        }
                    } else {

                    }
                } elseif ($split[$start] == "object-group") {
                    $srv = $split[$start + 1];
                }
            }

            # To be iterated by the elemets on globals
            if ($NatID !== 0) {
                $getGlobals = $projectdb->query("SELECT * FROM cisco_nat_global WHERE source='$source' AND vsys='$vsys' AND natid='$NatID';");
                $total_globals = $getGlobals->num_rows;
                if ($total_globals > 0) {
                    while ($getGlobalsData = $getGlobals->fetch_assoc()) {
                        $zone = $getGlobalsData["zone"];
                        if ($getGlobalsData["type"] == "address") {
                            if ($getGlobalsData["cidr"] != "") {
                                $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                            } else {
                                $element_ipaddress[] = $getGlobalsData["address"];
                            }
                        } elseif ($getGlobalsData["type"] == "range") {
                            $element_ipaddress[] = $getGlobalsData["address"];
                        } elseif ($getGlobalsData["type"] == "hostname") {
                            $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                        } elseif ($getGlobalsData["type"] == "interface") {
                            $element_ipaddress[] = $getGlobalsData["address"] . "/" . $getGlobalsData["cidr"];
                        }


                        if ($src != "") {
                            $NAT1["source"] = $src;
                        }
                        $NAT1["natid"] = $NatID;
                        $NAT1["nat_lid"] = $nat_lid;
                        $NAT1["access-list"] = $names_line;
                        $NAT1["tp_sat_type"] = "dynamic-ip-and-port";
                        $NAT1["name"] = "Rule " . $nat_lid . " Nat-ID " . $NatID;
                        $NAT1["from"] = $OPFrom;
                        $NAT1["op_zone_to"] = $zone;
                        $NAT1["position"] = $position;
                        $NAT1["destination"] = $dst;
                        $NAT1["service"] = isset($srv)?$srv:'';
                        $NAT1["tp_sat_address_type"] = "translated-addres";
                        $NAT1["nat_rules_translated_address"] = implode(",", $element_ipaddress);
                        $ARRAY[] = $NAT1;
                        $NAT1 = [];
                        $nat_lid++;
                        $position++;
                        $element_ipaddress = [];
                    }
                }
            }

            $src = "";
            $dst = "";
            $srv = "";
            $isSourcePort = false;

            /*
              #  END
              $NONAT1["natid"]=$NatID;
              $NONAT1["nat_lid"]=$nat_lid;
              $NONAT1["access-list"]=$names_line;
              $NONAT1["name"]="Rule ".$nat_lid." Nat ID ".$NatID;
              $NONAT1["from"]=$OPFrom;
              $NONAT1["op_zone_to"]=$op_zone_to;
              $NONAT1["position"]=$position;
              $NONAT1["source"]=$src;
              $NONAT1["destination"]=$dst;
              $NONAT1["service"]=$srv;

              if ($type=="dynamic"){
              $NONAT1["tp_sat_type"]="dynamic-ip-and-port";
              $NONAT1["nat_rules_translated_address"]=$translated_address;
              $NONAT1["tp_sat_address_type"]="translated-addres";

              }
              $ARRAY[]=$NONAT1;
              $NONAT1=[];
              $nat_lid++;
              $position++;
             */
        }
    }
    return array($ARRAY, $nat_lid, $position);
}

# Library Functions
function convertLifeTime($input, $entero, &$output_unit, &$output_value){
    $output_value = $input;
    $output_unit = 1;
    //Seconds
    if ($output_value > 65535){
        $output_value = $output_value / 60;
        $output_unit++;
    }
    //Minutes
    if ($output_value > 65535){
        $output_value = $output_value / 60;
        $output_unit++;
    }
    //Hours
    if ($output_value > 65535){
        $output_value = $output_value / 24;
        $output_unit++;
    }
    //Days

    switch ($output_unit){
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

    if($entero){
        $output_value = round($output_value);
    }
}

function convertLifeSize($input, $entero, &$output_unit, &$output_value){
    $output_value = $input;
    $output_unit = 1;
    while($output_value > 65535){
        $output_value = $output_value / 1024;
        $output_unit++;
    }

    switch ($output_unit){
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

    if($entero){
        $output_value = round($output_value);
    }
}

function getApplicationSnippet(MySQLi $projectdb, STRING $name, $source, STRING $vsys):MemberObject{
    require_once INC_ROOT.'/libs/projectdb.php';
    $pandb = selectDatabase('pandb');

    $getDup = $projectdb->query("SELECT id FROM applications WHERE name='$name' AND vsys='$vsys' AND source='$source';");
    if ($getDup->num_rows == 1) {
        $data = $getDup->fetch_assoc();
        $member = new MemberObject($data['id'],'applications');
    }
    else {
        $getSnippet = $pandb->query("SELECT name, type, data, panos FROM snippets WHERE name='$name' and type ='appid';");
        if ($getSnippet->num_rows == 1) {
            $getSnippetData = $getSnippet->fetch_assoc();
            $data = $getSnippetData['data'];
            $version = $getSnippetData['panos'];

            $sql = array();
            $profilesArray = simplexml_load_string($data);
            if ($profilesArray != FALSE) {
                $name = $profilesArray->attributes()->name;
                $subcategory = $profilesArray->subcategory;
                $category = $profilesArray->category;
                $technology = $profilesArray->technology;
                $risk = $profilesArray->risk;
                $evasive_behavior = $profilesArray->{'evasive-behavior'};
                $consume_big_bandwidth = $profilesArray->{'consume-big-bandwidth'};
                $used_by_malware = $profilesArray->{'used-by-malware'};
                $able_to_transfer_file = $profilesArray->{'able-to-transfer-file'};
                $has_known_vulnerability = $profilesArray->{'has-known-vulnerability'};
                $tunnel_other_application = $profilesArray->{'tunnel-other-application'};
                $tunnel_applications = $profilesArray->{'tunnel-applications'};
                $prone_to_misuse = $profilesArray->{'prone-to-misuse'};
                $pervasive_use = $profilesArray->{'pervasive-use'};
                $file_type_ident = $profilesArray->{'file-type-ident'};
                $virus_ident = $profilesArray->{'virus-ident'};
                $spyware_ident = $profilesArray->{'spyware-ident'};
                $data_ident = $profilesArray->{'data-ident'};
                $parent_app = $profilesArray->{'parent-app'};
                $timeout = $profilesArray->timeout;
                $timeout_tcp = $profilesArray->{'tcp-timeout'};
                $timeout_udp = $profilesArray->{'udp-timeout'};
                $tcp_half_closed_timeout = $profilesArray->{'tcp-half-closed-timeout'};
                $tcp_time_wait_timeout = $profilesArray->{'tcp-time-wait-timeout'};
                $icmp_code = "";

                if (isset($profilesArray->default->port)) {
                    $default_type = "port";
                    $default_value_array = array();
                    foreach ($profilesArray->default->port->member as $vvvalue) {
                        $default_value_array[] = $vvvalue;
                    }
                    //$default_value = implode(",", $default_value_array);
                }
                elseif (isset($profilesArray->default->{'ident-by-ip-protocol'})) {
                    $default_type = "ident-by-ip-protocol";
                    $default_value = $profilesArray->default->{'ident-by-ip-protocol'};
                }
                elseif (isset($profilesArray->default->{'ident-by-icmp-type'})) {
                    $default_type = "ident-by-icmp-type";
                    $default_value = $profilesArray->default->{'ident-by-icmp-type'};
                    $icmp_type = $profilesArray->default->{'ident-by-icmp-type'};

                    if (isset($profilesArray->default->{'ident-by-icmp-type'}->type)) {
                        $icmp_type = $profilesArray->default->{'ident-by-icmp-type'}->type;
                        $icmp_code = $profilesArray->default->{'ident-by-icmp-type'}->code;
                    }

                }
                elseif (isset($profilesArray->default->{'ident-by-icmp6-type'})) {
                    $default_type = "ident-by-icmp6-type";
                    $icmp_type = $profilesArray->default->{'ident-by-icmp6-type'}->type;
                    $icmp_code = $profilesArray->default->{'ident-by-icmp6-type'}->code;
                    $default_value = "";
                }
                elseif (!isset($profilesArray->default)) {
                    $default_type = "None";
                    $default_value = "";
                }

                $query = "INSERT INTO applications (default_type,value,type,code,parent_app,source,name,vsys,devicegroup,subcategory,category,technology,risk,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,spyware_ident,data_ident,timeout,tcp_timeout,udp_timeout,tcp_half_closed_timeout, tcp_time_wait_timeout) "
                    . "VALUES ('$default_type','$default_value','$icmp_type','$icmp_code','$parent_app','$source','$name','$vsys','','$subcategory','$category','$technology','$risk','$evasive_behavior','$consume_big_bandwidth','$used_by_malware','$able_to_transfer_file','$has_known_vulnerability','$tunnel_other_application','$tunnel_applications','$prone_to_misuse','$pervasive_use','$file_type_ident','$virus_ident','$spyware_ident','$data_ident','$timeout','$timeout_tcp','$timeout_udp','$tcp_half_closed_timeout', '$tcp_time_wait_timeout');";
                $projectdb->query($query);
                $appid = $projectdb->insert_id;
                if (isset($profilesArray->signature)) {
                    foreach ($profilesArray->signature->entry as $signature) {
                        $signatureXML = $signature->asXML();
                        $projectdb->query("INSERT INTO applications_signatures (member_lid,table_name,signature,vsys,devicegroup,source) VALUES ('$appid','applications','$signatureXML','$vsys','',$source);");
                    }
                }

                if($default_type == "port"){
                    if (count($default_value_array) > 0) {
                        foreach ($default_value_array as $port) {
                            $projectdb->query("INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$appid','applications','$port','$vsys','','$source');");
                            //echo "INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$appid','applications','$port','$vsys','$devicegroup','$source');\n";
                        }
                    }
                }

                $member = new MemberObject($projectdb->insert_id, 'applications');
            }
            else{
                $member = new MemberObject();
            }
        }
        else{
            $member = new MemberObject();
        }
    }

    return $member;
}

function getTimeOutClass($vsys, $source, $cisco_config_file):array{
    $aclsWithTimeout = array();

    $aclClassName = '';
    global $projectdb;
    foreach ($cisco_config_file as $line => $input_line) {
        $input_line = rtrim($input_line);
        preg_match('/.*class-map (?<aclClassName>.*)/', $input_line, $output_array);
        if(isset($output_array['aclClassName'])){
            $aclClassName = $output_array['aclClassName'];
            $aclsWithTimeout[$aclClassName]['name'] = $aclClassName;
        }
        else{
            preg_match('/.*class (?<aclClassName>.*)/', $input_line, $output_array);
            if(isset($output_array['aclClassName'])){
                $aclClassName = $output_array['aclClassName'];
            }
            else {
                preg_match('/.*match access-list (?<aclName>.*)/', $input_line, $output_array);
                if (isset($output_array['aclName'])) {
                    $aclsWithTimeout[$aclClassName]['aclName'] = $output_array['aclName'];
                } else {
                    //set connection timeout idle 4:00:00
                    preg_match('/.*set connection timeout (?<timeout>.*)/', $input_line, $output_array);
                    if (isset($output_array['timeout'])) {
                        switch ($output_array['timeout']) {
                            case 'dcd':
                                $timeout = 86400;
                                break;
                            default:
                                preg_match('/.*set connection timeout .* (?<hours>\d*):(?<minutes>\d*):(?<seconds>\d*).*/', $input_line, $output_array);
                                if(count($output_array)>0){
                                    $timeout = $output_array['hours']*60*60 + $output_array['minutes']*60 + $output_array['seconds'];
                                }
                                else{
                                    $timeout = 86400;
                                }
                                break;
                        }
                        $aclsWithTimeout[$aclClassName]['timeout'] = $timeout;
                    }
                }
            }
        }
    }

    $acls = array();
    $generalServices = array();
    foreach ($aclsWithTimeout as $acl_entry){
        if(isset($acl_entry['timeout']) && isset($acl_entry['aclName'])) {
            $acls[$acl_entry['aclName']]['timeout'] =$acl_entry['timeout'];
        }
        elseif(isset($acl_entry['timeout']) && isset($acl_entry['service'])){
            $generalServices[$acl_entry['service']]['timeout'] =$acl_entry['timeout'];
        }
    }

    return [
        'acls'=>$acls,
        'services'=>$generalServices
    ];
}

function fixServiceTimeouts($devicegroup, $cisco_config_file, $source, STRING $vsys, MemoryObjectsHandlerCisco $objectsInMemory, $aclsWithTimeouts=array(), $servicesWithTimouts=array()){
    global $projectdb;

    foreach ($aclsWithTimeouts as $aclGroup=> $acl){
        $timeout = $acl['timeout'];
        //echo "$aclGroup has timeout of $timeout\n";

        $secIds = [];
        $services = [];
        $serviceGroups = [];
        $wrongServices = [];

        //Collect the rules that should have timeouts for this ACL group
        $query = "SELECT * FROM security_rules WHERE source=$source AND vsys = '$vsys' AND name like '".$aclGroup."_%'";
        // echo $query."\n";
        $results = $projectdb->query($query);
        if ($projectdb->affected_rows > 0){
            //echo "   This one looks good\n";

            while ($sec_rule = $results->fetch_assoc()){
                $secIds[] = $sec_rule['id'];
            }

            //Collect the services that are used on those rules
            $query = "SELECT table_name, member_lid, id FROM security_rules_srv WHERE rule_lid in (".implode(", ",$secIds).") ;";
            // echo "Services: $query\n";
            $servicesDataSet = $projectdb->query($query);
            if($projectdb->affected_rows > 0){
                $cases = array();
                while($service = $servicesDataSet->fetch_assoc()){
                    if($service['table_name']=='services'){
                        $services[$service['member_lid']]['usedIn'][] = $service['id'];
                    }
                    else{
                        $serviceGroups[$service['member_lid']]['usedIn'][] = $service['id'];
                    }
                }

                //Get information about the services
                foreach($services as $serviceID => &$service){
                    //echo "Service $serviceID\n";
                    $rules = $service['usedIn'];
                    $serviceObject = $objectsInMemory->getServiceByID($source, $vsys, $serviceID);
                    if($serviceObject['timeout'] != $timeout){
                        //Using the wrong service. Lets check if the service with timeout exists
                        $serviceNameWithTimeout = $serviceObject['name'];
                        //We need to clone the service and replace its usage
                        $serviceObject = $objectsInMemory->getServiceWithTimeout($devicegroup, $source, $vsys, $serviceNameWithTimeout, $timeout);
                        $cases[] = " WHEN rule_lid in (".implode(",", $rules).") AND table_name='services' AND member_lid=$serviceID THEN ".$serviceObject->name. " ";
                    }
                }

                //If there were any new services identified, insert them
                $objectsInMemory->insertNewServices($projectdb);

                $query = "UPDATE security_rules_srv SET member_lid = CASE ".implode(" ", $cases)." ELSE member_lid END";
                $projectdb->query($query);
                //echo $query;

            }
        }
    }
}

function generateAuthRules($devicegroup, $cisco_config_file, $source, $vsys, $objectsInMemory){
    global $projectdb;

    $aclsGroupsWithAAA = array();

    //Look for all the ACL-Groups that should have Authentication AAA
    $aclGroupName = '';
    global $projectdb;
    foreach ($cisco_config_file as $line => $input_line) {
        $input_line = rtrim($input_line);
        preg_match('/.*aaa authentication match (?<aclGroup>.*)/', $input_line, $output_array);
        if(isset($output_array['aclGroup'])){
            $aclGroupName = $output_array['aclClassName'];
            $aclsGroupsWithAAA[$aclGroupName]['name'] = $aclGroupName;
        }
    }

    //Create Authentication rules for the ACLs that have authentication
    if(count($aclsGroupsWithAAA)>0){

    }

}

function replaceServicesWithTimeout(STRING $source, STRING $vsys, STRING $clone_to_vsys, ARRAY $ids, INT $timeout, MemoryObjectsHandlerCisco $objectsInMemory){

    global $projectdb;
    $clone_member_lid = 0;

    foreach ($ids as $member_lid) {

        $getMember = $projectdb->query("SELECT id,name_ext,name,vsys,devicegroup,description,sport,dport,protocol,icmp,source,tag "
            . "FROM services WHERE id='$member_lid' AND dummy = 0;");

        if ($getMember->num_rows > 0){
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

            if($vsys == $clone_to_vsys){
                $name = "Cl-$name";
            }

            $getExist = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext = '$name_ext' AND BINARY name = '$name' "
                . "AND devicegroup = '$devicegroup' AND description = '$description' AND protocol = '$protocol' AND dport = '$dport' "
                . "AND sport = '$sport' AND icmp = '$icmp' AND tag = '$tag' AND source = '$source' AND vsys = '$clone_to_vsys';");
            if ($getExist->num_rows > 0){
                $getEData = $getExist->fetch_assoc();
                $clone_member_lid = $getEData['id'];
            }
            elseif($getExist->num_rows == 0){
                $projectdb->query("INSERT INTO services (name_ext,name,devicegroup,vsys,protocol,sport,description,dport,icmp,source,tag)  "
                    . "VALUES ('$name_ext','$name','$devicegroup','$clone_to_vsys','$protocol','$sport','$description','$dport','$icmp','$source','$tag');");
                $clone_member_lid = $projectdb->insert_id;

                $getTagRelations = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$member_lid' AND table_name = 'services';");
                if($getTagRelations->num_rows > 0){
                    while($dataTR = $getTagRelations->fetch_assoc()){
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
//function explodeGroups2Members($members,$projectdb, $source, $vsys, $level){
//    $tmp_members=array();
//    foreach($members as $member){
//
//        //Not a group. Let's add it directly
//        if(strcmp($member->location, 'address')==0){
//            if(!isset($member->value) || !isset($member->cidr)){
//                $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
//                $getMember = $projectdb->query($query);
//                if($getMember->num_rows == 1){
//                    $row=$getMember->fetch_assoc();
//                    $member->cidr=$row['cidr'];
//                    $member->value=$row['ipaddress'];
//                }
//            }
//            $tmp_members[]=$member;
//        }
//
//        //This is a group. Let's expand it
//        else{
//            $query = "SELECT member_lid, table_name ".
//                "FROM address_groups adg ".
//                "WHERE adg.source='$source' AND adg.vsys='$vsys' AND ".
//                " BINARY adg.lid='$member->name' ";
//            $getMember = $projectdb->query($query);
//            while($row = $getMember->fetch_assoc()) {
//                $member_id= $row['member_lid'];
//                $member_location = $row['table_name'];
//                $member2[] = new MemberObject($member_id, $member_location);
//            }
//            $tmp_members = array_merge($tmp_members, explodeGroups2Members($member2, $projectdb, $source, $vsys, $level+1));
//        }
//    }
//
//    return $tmp_members;
//}

?>
