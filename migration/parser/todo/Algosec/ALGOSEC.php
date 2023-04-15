<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';

//User management control
require_once INC_ROOT . '/userManager/start.php';
include INC_ROOT . '/bin/authentication/sessionControl.php';

//Dependencies
require_once INC_ROOT . '/libs/shared.php';

//Capture request paramenters
switch ($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action = (string)(isset($_GET['action']) ? $_GET['action'] : '');
        $type = (string)(isset($_GET['type']) ? $_GET['type'] : ''); // zip / xml / device
        $project = (string)(isset($_GET['project']) ? $_GET['project'] : '');
        $start = (integer)(isset($_GET['start']) ? $_GET['start'] : '');
        $limit = (integer)(isset($_GET['limit']) ? $_GET['limit'] : '');
        break;
    case 'POST':
        $action = (string)(isset($_POST['action']) ? $_POST['action'] : '');
        $type = (string)(isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
        $project = (string)(isset($_POST['project']) ? $_POST['project'] : '');
        $start = (integer)(isset($_POST['start']) ? $_POST['start'] : '');
        $limit = (integer)(isset($_POST['limit']) ? $_POST['limit'] : '');
        break;

    default:
        $action = (string)(isset($_POST['action']) ? $_POST['action'] : '');
        $type = (string)(isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
        $project = (string)(isset($_POST['project']) ? $_POST['project'] : '');
        $start = (integer)(isset($_POST['start']) ? $_POST['start'] : '');
        $limit = (integer)(isset($_POST['limit']) ? $_POST['limit'] : '');
        break;
}
//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);

require_once INC_ROOT . '/libs/projectdb.php';
global $projectdb;
$projectdb = selectDatabase($project);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


if( $action == "get" )
{
    if( $type == "devices" )
    {
        $afa_hostname = (string)(isset($_POST['afa_hostname']) ? $_POST['afa_hostname'] : $_GET['afa_hostname']);
        $username = (string)(isset($_POST['username']) ? $_POST['username'] : $_GET['username']);
        $password = (string)(isset($_POST['password']) ? $_POST['password'] : $_GET['password']);

        $projectdb->query("TRUNCATE TABLE algosec_devices;");

        ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
        $sHost = $afa_hostname; // AFA host
        $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
        //$client = new SoapClient($sWSDLlocavion);
        $client = new SoapClient($sWSDLlocavion,
            array(

                "stream_context" => stream_context_create(
                    array(
                        'ssl' => array(
                            'verify_peer' => FALSE,
                            'verify_peer_name' => FALSE,
                        )
                    )
                )
            )
        );
        try
        {
            $client->__setLocation($sWSDLlocavion);
            $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));

            if( isset($return->SessionID) )
            {
                $sSessionID = $return->SessionID;
                //Retrieve Device list
                $QueryResult = $client->get_devices_list(array('SessionID' => $sSessionID));
                $QueryHTMLlink = $QueryResult->Device;
                //print_r(json_encode($QueryHTMLlink));

                foreach( $QueryHTMLlink as $key => $value )
                {
                    $projectdb->query("INSERT INTO algosec_devices (Brand,ID,Name,IP) VALUES ('$value->Brand','$value->ID','$value->Name','$value->IP');");
                }

                $return = $client->disconnect(array('SessionID' => $sSessionID));

                $getTags = $projectdb->query("SELECT * FROM algosec_devices;");
                if( $getTags->num_rows > 0 )
                {
                    while( $data = $getTags->fetch_object() )
                    {
                        $myData[] = $data;
                    }
                    if( $getTags->num_rows == 0 )
                    {
                        $myData = "";
                    }
                    echo json_encode($myData);
                }
                else
                {
                    echo '[{}]';
                }


            }
        } catch(Exception $objException)
        {
            echo 'Error: ' . $objException->getMessage();
            echo 'Error: ' . $objException->faultstring;
            echo '<xmp>';
            print_r($objException);
            echo '</xmp>';
        }


    }
    elseif( $type == "tags" )
    {
        $getTags = $projectdb->query("SELECT id,name FROM algosec_tags;");
        if( $getTags->num_rows > 0 )
        {
            while( $data = $getTags->fetch_object() )
            {
                $myData[] = $data;
            }
            if( $getTags->num_rows == 0 )
            {
                $myData = "";
            }
            echo '{"total":"' . $getTags->num_rows . '","rows":' . json_encode($myData) . '}';
        }
        else
        {
            echo '{"total":"' . $getTags->num_rows . '","rows":[{"id":1,"name":"Documentation"}]}';
        }

    }
}
elseif( $action == "add" )
{
    if( $type == "tags" )
    {
        global $projectdb;
        $data = (string)(isset($_POST['data']) ? $_POST['data'] : $_GET['data']);
        if( $data == "" )
        {
        }
        else
        {
            $data_new = explode(",", $data);
            $newtags = array();
            $existing = array();
            $getAll = $projectdb->query("SELECT name FROM algosec_tags;");
            while( $all = $getAll->fetch_assoc() )
            {
                $existing[] = "('" . $all['name'] . "')";
            }
            foreach( $data_new as $key => $value )
            {
                $newtags[] = "('" . $value . "')";
            }
            $toadd = array_diff($newtags, $existing);
            $query = implode(",", $toadd);
            if( $query != "" )
            {
                $projectdb->query("INSERT INTO algosec_tags (name) VALUES " . $query . ";");
            }
        }
        echo json_encode(array("success" => TRUE));
    }
}
elseif( $action == "remove" )
{
    if( $type == "tags" )
    {
        global $projectdb;
        take_snapshot_last($project);
        $data = (string)(isset($_POST['data']) ? $_POST['data'] : $_GET['data']);
        $data_new = explode(",", $data);
        $projectdb->query("DELETE FROM algosec_tags WHERE id IN(" . $data . ")");
        echo json_encode(array("success" => TRUE));
    }
}
elseif( $action == "import" )
{
    $afa_hostname = (string)(isset($_POST['afa_hostname']) ? $_POST['afa_hostname'] : $_GET['afa_hostname']);
    $username = (string)(isset($_POST['username']) ? $_POST['username'] : $_GET['username']);
    $password = (string)(isset($_POST['password']) ? $_POST['password'] : $_GET['password']);
    $signatureid = (string)(isset($_POST['signatureid']) ? $_POST['signatureid'] : $_GET['signatureid']); // ID from Algosec Devices

    take_snapshot_last($project);
    $devices_id = explode(",", $signatureid);
    update_progress($project, '0.00', 'Reading config files', $jobid);
    foreach( $devices_id as $key => $value )
    {
        $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$value';");
        if( $isUploaded->num_rows == 0 )
        {
            #$projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$value','',0,1,'$project','$value','$value','0','Algosec')");
            #$source=$projectdb->insert_id;
            $source = 0;
            $vsys = $value;
            #import_address($source,$vsys,$username,$password,$afa_hostname);
            import_policies($source, $vsys, $username, $password, $afa_hostname);
        }


    }


    update_progress($project, '1.00', 'Done.');
    //sleep(4);
    //update_progress($project,'0','Ready');
}
elseif( $action == "import_tags" )
{
    if( $type == "selection" )
    {
        $afa_hostname = (string)(isset($_POST['afa_hostname']) ? $_POST['afa_hostname'] : $_GET['afa_hostname']);
        $username = (string)(isset($_POST['username']) ? $_POST['username'] : $_GET['username']);
        $password = (string)(isset($_POST['password']) ? $_POST['password'] : $_GET['password']);
        $data = (string)(isset($_POST['data']) ? $_POST['data'] : $_GET['data']);
        $source = (string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $vsys = (string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $DeviceID = (string)(isset($_POST['deviceid']) ? $_POST['deviceid'] : $_GET['deviceid']);
        ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
        $sHost = $afa_hostname; // AFA host
        $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
        //$client = new SoapClient($sWSDLlocavion);
        $client = new SoapClient($sWSDLlocavion,
            array(

                "stream_context" => stream_context_create(
                    array(
                        'ssl' => array(
                            'verify_peer' => FALSE,
                            'verify_peer_name' => FALSE,
                        )
                    )
                )
            )
        );
        $QueryHTMLlink = array();

        if( ($data != "") and ($username != "") and ($password != "") and ($afa_hostname != "") )
        {

            add_progress($project, '0.00', 'Retrieving Reports');

            /*$getDeviceID=$projectdb->query("SELECT device FROM device_mapping WHERE id='$source';");
            if ($getDeviceID->num_rows==1){
                $getDeviceIDData=$getDeviceID->fetch_assoc();
                $DeviceID=$getDeviceIDData['device'];
            }
            */


            $x = 0;
            $rulesnames = explode(",", $data);
            $allrules = count($rulesnames);

            try
            {
                $client->__setLocation($sWSDLlocavion);
                $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));
                if( isset($return->SessionID) )
                {
                    $sSessionID = $return->SessionID;
                    foreach( $rulesnames as $key => $value )
                    {
                        $x++;
                        $rules_split = explode(";", $value);
                        $rule_lid = $rules_split[0];
                        $rule_name = $rules_split[1];
                        if( $rule_name != "" )
                        {
                            $projectdb->query("DELETE FROM algosec_tags_values WHERE tag_mapping='$rule_lid';");

                            import_tags($source, $vsys, $sSessionID, $rule_name, $DeviceID, $rule_lid, $client);
                        }
                        $progress = $x / $allrules;
                        if( $progress == 1 )
                        {
                            update_progress($project, '1.00', 'Finished.');
                            sleep(4);
                            update_progress($project, '0.00', 'Ready.');
                        }
                        else
                        {
                            update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                        }
                    }
                }
                $return = $client->disconnect(array('SessionID' => $sSessionID));
            } catch(Exception $objException)
            {
                echo 'Error: ' . $objException->getMessage();
                echo 'Error: ' . $objException->faultstring;
                echo '<xmp>';
                print_r($objException);
                echo '</xmp>';
            }
        }
    }
    elseif( $type == "bulk" )
    {
        $afa_hostname = (string)(isset($_POST['afa_hostname']) ? $_POST['afa_hostname'] : $_GET['afa_hostname']);
        $username = (string)(isset($_POST['username']) ? $_POST['username'] : $_GET['username']);
        $password = (string)(isset($_POST['password']) ? $_POST['password'] : $_GET['password']);
        $source = (string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $vsys = (string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);

        ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
        $sHost = $afa_hostname; // AFA host
        $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
        //$client = new SoapClient($sWSDLlocavion);
        $client = new SoapClient($sWSDLlocavion,
            array(
                "stream_context" => stream_context_create(
                    array(
                        'ssl' => array(
                            'verify_peer' => FALSE,
                            'verify_peer_name' => FALSE,
                        )
                    )
                )
            )
        );
        $QueryHTMLlink = array();

        add_progress($project, '0.00', 'Retrieving Reports');

        #$getDeviceID=$projectdb->query("SELECT device FROM device_mapping WHERE id='$source';");
        #if ($getDeviceID->num_rows==1){
        #	$getDeviceIDData=$getDeviceID->fetch_assoc();
        #	$DeviceID=$getDeviceIDData['device'];
        #}

        $getDeviceID = $projectdb->query("SELECT DeviceID FROM algosec_policy_mapping GROUP BY DeviceID;");
        if( $getDeviceID->num_rows > 0 )
        {
            while( $data = $getDeviceID->fetch_assoc() )
            {
                $DeviceID = $data['DeviceID'];
                try
                {
                    $client->__setLocation($sWSDLlocavion);
                    $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));
                    if( isset($return->SessionID) )
                    {
                        $sSessionID = $return->SessionID;
                        $getRules = $projectdb->query("SELECT id,name FROM security_rules WHERE devicegroup='$DeviceID';");
                        $allrules = $getRules->num_rows;
                        $x = 0;
                        if( $allrules > 0 )
                        {
                            while( $value = $getRules->fetch_assoc() )
                            {
                                $x++;
                                $rule_lid = $value['id'];
                                $rule_name = $value['name'];
                                if( $rule_name != "" )
                                {
                                    $projectdb->query("DELETE FROM algosec_tags_values WHERE tag_mapping='$rule_lid';");
                                    import_tags($source, $vsys, $sSessionID, $rule_name, $DeviceID, $rule_lid, $client);
                                }
                                $progress = $x / $allrules;
                                if( $progress == 1 )
                                {

                                }
                                else
                                {
                                    update_progress($project, $progress, 'DeviceID[' . $DeviceID . '] Retrieved Report ' . $x . ' from ' . $allrules);
                                }
                            }
                        }
                    }
                    $return = $client->disconnect(array('SessionID' => $sSessionID));
                } catch(Exception $objException)
                {
                    echo 'Error: ' . $objException->getMessage();
                    echo 'Error: ' . $objException->faultstring;
                    echo '<xmp>';
                    print_r($objException);
                    echo '</xmp>';
                }
            }
            update_progress($project, '1.00', 'Finished.');
            sleep(4);
            update_progress($project, '0.00', 'Ready.');
        }
    }
}
elseif( $action == "export" )
{
    if( $type == "tags_selected" )
    {
        $afa_hostname = (string)(isset($_POST['afa_hostname']) ? $_POST['afa_hostname'] : $_GET['afa_hostname']);
        $username = (string)(isset($_POST['username']) ? $_POST['username'] : $_GET['username']);
        $password = (string)(isset($_POST['password']) ? $_POST['password'] : $_GET['password']);
        $data = (string)(isset($_POST['data']) ? $_POST['data'] : $_GET['data']);
        $source = (string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $vsys = (string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $DeviceID = (string)(isset($_POST['DeviceID']) ? $_POST['DeviceID'] : $_GET['DeviceID']);

        if( ($data != "") and ($DeviceID != "") )
        {
            add_progress($project, '0.00', 'Retrieving Reports');
            $x = 0;
            $rulesnames = explode(",", $data);
            $allrules = count($rulesnames);
            ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
            $sHost = $afa_hostname; // AFA host
            $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
            //$client = new SoapClient($sWSDLlocavion);
            $client = new SoapClient($sWSDLlocavion,
                array(

                    "stream_context" => stream_context_create(
                        array(
                            'ssl' => array(
                                'verify_peer' => FALSE,
                                'verify_peer_name' => FALSE,
                            )
                        )
                    )
                )
            );
            try
            {
                $client->__setLocation($sWSDLlocavion);
                $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));

                if( isset($return->SessionID) )
                {
                    $sSessionID = $return->SessionID;
                    foreach( $rulesnames as $key => $value )
                    {
                        $x++;
                        $rules_split = explode(";", $value);
                        $rule_lid = $rules_split[0];
                        $rule_name = $rules_split[1];
                        if( ($rule_name != "") and ($rule_lid != "") )
                        {
                            $getTags = $projectdb->query("SELECT tag_value,tag_id FROM algosec_tags_values WHERE tag_mapping='$rule_lid';");
                            if( $getTags->num_rows > 0 )
                            {
                                while( $getTagsData = $getTags->fetch_assoc() )
                                {
                                    $tag_value = $getTagsData['tag_value'];
                                    $tag_id = $getTagsData['tag_id'];
                                    $getTagName = $projectdb->query("SELECT name FROM algosec_tags WHERE id='$tag_id';");
                                    $getTagNameData = $getTagName->fetch_assoc();
                                    $tag = $getTagNameData['name'];
                                    export_tags($source, $vsys, $sSessionID, $rule_name, $DeviceID, $rule_lid, $client, $tag, $tag_value);
                                }
                            }

                        }
                        $progress = $x / $allrules;
                        if( $progress == 1 )
                        {
                            update_progress($project, '1.00', 'Finished.');
                            sleep(4);
                            update_progress($project, '0.00', 'Ready.');
                        }
                        else
                        {
                            update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                        }
                    }
                    $return = $client->disconnect(array('SessionID' => $sSessionID));
                }
            } catch(Exception $objException)
            {
                echo 'Error: ' . $objException->getMessage();
                echo 'Error: ' . $objException->faultstring;
                echo '<xmp>';
                print_r($objException);
                echo '</xmp>';
            }
        }
    }
    if( $type == "tags_all" )
    {
        $afa_hostname = (string)(isset($_POST['afa_hostname']) ? $_POST['afa_hostname'] : $_GET['afa_hostname']);
        $username = (string)(isset($_POST['username']) ? $_POST['username'] : $_GET['username']);
        $password = (string)(isset($_POST['password']) ? $_POST['password'] : $_GET['password']);
        $source = (string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $vsys = (string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $DeviceID = (string)(isset($_POST['DeviceID']) ? $_POST['DeviceID'] : $_GET['DeviceID']);

        if( $DeviceID != "" )
        {
            add_progress($project, '0.00', 'Retrieving Reports');
            $x = 0;
            ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
            $sHost = $afa_hostname; // AFA host
            $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
            //$client = new SoapClient($sWSDLlocavion);
            $client = new SoapClient($sWSDLlocavion,
                array(

                    "stream_context" => stream_context_create(
                        array(
                            'ssl' => array(
                                'verify_peer' => FALSE,
                                'verify_peer_name' => FALSE,
                            )
                        )
                    )
                )
            );
            try
            {
                $client->__setLocation($sWSDLlocavion);
                $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));

                if( isset($return->SessionID) )
                {
                    $sSessionID = $return->SessionID;

                    $getTags = $projectdb->query("SELECT tag_value,tag_id,tag_mapping FROM algosec_tags_values WHERE tag_mapping!='';");
                    $allrules = $getTags->num_rows;
                    if( $getTags->num_rows > 0 )
                    {
                        while( $getTagsData = $getTags->fetch_assoc() )
                        {
                            $x++;
                            $tag_value = $getTagsData['tag_value'];
                            $tag_id = $getTagsData['tag_id'];
                            $rule_lid = $getTagsData['tag_mapping'];
                            $getTagName = $projectdb->query("SELECT name FROM algosec_tags WHERE id='$tag_id';");
                            $getTagNameData = $getTagName->fetch_assoc();
                            $tag = $getTagNameData['name'];
                            $getRules = $projectdb->query("SELECT name FROM security_rules WHERE id='$rule_lid';");
                            if( $getRules->num_rows == 1 )
                            {
                                $getRulesData = $getRules->fetch_assoc();
                                $rule_name = $getRulesData['name'];
                                export_tags($source, $vsys, $sSessionID, $rule_name, $DeviceID, $rule_lid, $client, $tag, $tag_value);
                            }
                            $progress = $x / $allrules;
                            if( $progress == 1 )
                            {
                                update_progress($project, '1.00', 'Finished.');
                                sleep(4);
                                update_progress($project, '0.00', 'Ready.');
                            }
                            else
                            {
                                update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                            }
                        }
                    }
                    $return = $client->disconnect(array('SessionID' => $sSessionID));
                }
            } catch(Exception $objException)
            {
                echo 'Error: ' . $objException->getMessage();
                echo 'Error: ' . $objException->faultstring;
                echo '<xmp>';
                print_r($objException);
                echo '</xmp>';
            }
        }
        else
        {
            update_progress($project, '1.00', 'Finished.');
            sleep(4);
            update_progress($project, '0.00', 'Ready.');
        }
    }
}

function export_tags($source, $vsys, $sSessionID, $RuleUid, $DeviceID, $tag_mapping, $client, $tag, $tag_value)
{
    $QueryResult = $client->edit_rule_documentation(array('SessionID' => $sSessionID, 'DeviceID' => $DeviceID, 'RuleUid' => $RuleUid, 'DocumentationColumn' => $tag, 'DocumentationData' => $tag_value));
}

function import_tags($source, $vsys, $sSessionID, $RuleUid, $DeviceID, $tag_mapping, $client)
{
    global $projectdb;

#Documentation FIELDS
    $getTags = $projectdb->query("SELECT id,name FROM algosec_tags;");
    if( $getTags->num_rows > 0 )
    {
        $QueryHTMLlink = array();
        while( $data = $getTags->fetch_assoc() )
        {
            $tag = $data['name'];
            $tag_id = $data['id'];
            $QueryResult = $client->get_rule_documentation(array('SessionID' => $sSessionID, 'DeviceID' => $DeviceID, 'RuleUid' => $RuleUid, 'DocumentationColumn' => $tag));
            if( $QueryResult != "" )
            {
                $QueryHTMLlink[] = "('$tag_id','$QueryResult','$tag_mapping')";
            }
        }
    }

    if( count($QueryHTMLlink) > 0 )
    {
        $projectdb->query("INSERT INTO algosec_tags_values (tag_id,tag_value,tag_mapping) VALUES " . implode(",", $QueryHTMLlink) . ";");
        unset($QueryHTMLlink);
    }
}

function import_address($source, $vsys, $username, $password, $afa_hostname)
{
    global $projectdb;
    $addHost = array();
    $addGroup = array();
    ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
    $sHost = $afa_hostname; // AFA host
    $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
    //$client = new SoapClient($sWSDLlocavion);
    $client = new SoapClient($sWSDLlocavion,
        array(

            "stream_context" => stream_context_create(
                array(
                    'ssl' => array(
                        'verify_peer' => FALSE,
                        'verify_peer_name' => FALSE,
                    )
                )
            )
        )
    );
    try
    {
        $client->__setLocation($sWSDLlocavion);
        $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));

        if( isset($return->SessionID) )
        {
            $sSessionID = $return->SessionID;
            //Retrieve Device list
            $QueryResult = $client->get_hostgroups_by_device(array('SessionID' => $sSessionID, 'EntityID' => $vsys));
            $QueryHTMLlink = $QueryResult->HostGroup;

            #Get last ID FROM ADDRESS
            $getlastlid = $projectdb->query("SELECT max(id) as max FROM address;");
            $getLID1 = $getlastlid->fetch_assoc();
            $address_lid = intval($getLID1['max']) + 1;

            foreach( $QueryHTMLlink as $key => $value )
            {
                $count_ip = count($value->IP);
                $name_ext = $value->CanonizedName;
                $name_int = truncate_names(normalizeNames($name_ext));
                if( $count_ip > 1 )
                {
                    #Group
                    $projectdb->query("INSERT INTO address_groups_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$name_ext','$name_int')");
                    $gid = $projectdb->insert_id;
                }
                foreach( $value->IP as $kkey => $vvalue )
                {
                    $theIP = preg_replace('/\s+/', '', $vvalue);
                    if( preg_match("/-/", $theIP) )
                    {
                        $type = "ip-range";
                        $cidr = "";
                    }
                    else
                    {
                        $type = "ip-netmask";
                        $cidr = "32";
                    }
                    if( $count_ip == 1 )
                    {
                        $exits = $projectdb->query("SELECT id FROM address WHERE ipaddress='$theIP' AND vsys='$vsys' AND source='$source';");
                        if( $exits->num_rows == 0 )
                        {
                            $addHost[] = "('$address_lid','$source','$vsys','$name_ext','$name_int','$theIP','$cidr','$type')";
                            $address_lid++;
                        }
                    }
                    elseif( $count_ip == 0 )
                    {
                    }
                    else
                    {
                        $exits = $projectdb->query("SELECT id FROM address WHERE ipaddress='$theIP' AND vsys='$vsys' AND source='$source';");
                        if( $exits->num_rows == 0 )
                        {
                            $addHost[] = "('$address_lid','$source','$vsys','$theIP','$theIP','$theIP','$cidr','$type')";
                            $address_lid++;
                        }
                        else
                        {
                            $data = $exits->fetch_assoc();
                            $address_lid = $data['id'];
                        }
                        $addGroup[] = "('$source','$vsys','$gid','$address_lid','address')";
                    }
                }
                $gid = "";
                if( count($addHost) > 0 )
                {
                    $unique = array_unique($addHost);
                    $projectdb->query("INSERT INTO address (id,source,vsys,name_ext,name,ipaddress,cidr,type) VALUES " . implode(",", $unique) . ";");
                }
                if( count($addGroup) > 0 )
                {
                    $unique = array_unique($addGroup);
                    $projectdb->query("INSERT INTO address_groups (source,vsys,lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                }
                $addGroup = [];
                $addHost = [];
            }

            $return = $client->disconnect(array('SessionID' => $sSessionID));

        }
    } catch(Exception $objException)
    {
        echo 'Error: ' . $objException->getMessage();
        echo 'Error: ' . $objException->faultstring;
        echo '<xmp>';
        print_r($objException);
        echo '</xmp>';
    }


}

function import_services($source, $vsys, $username, $password, $afa_hostname)
{
    global $projectdb;
    $addHost = array();
    $addgroup = array();
    ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
    $sHost = $afa_hostname; // AFA host
    $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
    //$client = new SoapClient($sWSDLlocavion);
    $client = new SoapClient($sWSDLlocavion,
        array(

            "stream_context" => stream_context_create(
                array(
                    'ssl' => array(
                        'verify_peer' => FALSE,
                        'verify_peer_name' => FALSE,
                    )
                )
            )
        )
    );
    try
    {
        $client->__setLocation($sWSDLlocavion);
        $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));

        if( isset($return->SessionID) )
        {
            $sSessionID = $return->SessionID;
            //Retrieve Device list
            $QueryResult = $client->get_services_by_device(array('SessionID' => $sSessionID, 'DeviceID' => $vsys));
            $QueryHTMLlink = $QueryResult->Service;

            #Get last ID FROM Services
            $getlastlid = $projectdb->query("SELECT max(id) as max FROM services;");
            $getLID1 = $getlastlid->fetch_assoc();
            $address_lid = intval($getLID1['max']) + 1;

            foreach( $QueryHTMLlink as $key => $value )
            {
                $count_ip = count($value->IP);
                $name_ext = $value->CanonizedName;
                $name_int = truncate_names(normalizeNames($name_ext));
                if( $count_ip > 1 )
                {
                    #Group
                    $projectdb->query("INSERT INTO address_groups_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$name_ext','$name_int')");
                    $gid = $projectdb->insert_id;
                }
                foreach( $value->IP as $kkey => $vvalue )
                {
                    $theIP = preg_replace('/\s+/', '', $vvalue);
                    if( preg_match("/-/", $theIP) )
                    {
                        $type = "ip-range";
                        $cidr = "";
                    }
                    else
                    {
                        $type = "ip-netmask";
                        $cidr = "32";
                    }
                    if( $count_ip == 1 )
                    {
                        $exits = $projectdb->query("SELECT id FROM address WHERE ipaddress='$theIP' AND vsys='$vsys' AND source='$source';");
                        if( $exits->num_rows == 0 )
                        {
                            $addHost[] = "('$address_lid','$source','$vsys','$name_ext','$name_int','$theIP','$cidr','$type')";
                            $address_lid++;
                        }
                    }
                    elseif( $count_ip == 0 )
                    {
                    }
                    else
                    {
                        $exits = $projectdb->query("SELECT id FROM address WHERE ipaddress='$theIP' AND vsys='$vsys' AND source='$source';");
                        if( $exits->num_rows == 0 )
                        {
                            $addHost[] = "('$address_lid','$source','$vsys','$theIP','$theIP','$theIP','$cidr','$type')";
                            $address_lid++;
                        }
                        else
                        {
                            $data = $exits->fetch_assoc();
                            $address_lid = $data['id'];
                        }
                        $addGroup[] = "('$source','$vsys','$gid','$address_lid','address')";
                    }
                }
                $gid = "";
                if( count($addHost) > 0 )
                {
                    $unique = array_unique($addHost);
                    $projectdb->query("INSERT INTO address (id,source,vsys,name_ext,name,ipaddress,cidr,type) VALUES " . implode(",", $unique) . ";");
                }
                if( count($addGroup) > 0 )
                {
                    $unique = array_unique($addGroup);
                    $projectdb->query("INSERT INTO address_groups (source,vsys,lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                }
                $addGroup = [];
                $addHost = [];
            }

            $return = $client->disconnect(array('SessionID' => $sSessionID));

        }
    } catch(Exception $objException)
    {
        echo 'Error: ' . $objException->getMessage();
        echo 'Error: ' . $objException->faultstring;
        echo '<xmp>';
        print_r($objException);
        echo '</xmp>';
    }


}

function import_policies($source, $vsys, $username, $password, $afa_hostname)
{
    global $projectdb;
    global $project;
    take_snapshot_last($project);
    $projectdb->query("TRUNCATE algosec_tags_mapping;");
    $projectdb->query("TRUNCATE algosec_tags_values;");
    #$x=0;
    #$addHost=array();
    #$addgroup=array();
    #$addTags=array();
    $addRule = array();
    ini_set("soap.wsdl_cache_enabled", "0"); // disabling WSDL cache for development
    $sHost = $afa_hostname; // AFA host
    $sWSDLlocavion = 'https://' . $sHost . '/AFA/php/ws.php?wsdl';
    //$client = new SoapClient($sWSDLlocavion);
    $client = new SoapClient($sWSDLlocavion,
        array(

            "stream_context" => stream_context_create(
                array(
                    'ssl' => array(
                        'verify_peer' => FALSE,
                        'verify_peer_name' => FALSE,
                    )
                )
            )
        )
    );
    $projectdb->query("DELETE FROM algosec_policy_mapping WHERE vsys='$vsys';");
    try
    {
        $client->__setLocation($sWSDLlocavion);
        $return = $client->connect(array('UserName' => $username, 'Password' => $password, 'Domain' => ''));

        if( isset($return->SessionID) )
        {
            $sSessionID = $return->SessionID;
            //Retrieve Device list
            $QueryResult = $client->get_rules_by_device(array('SessionID' => $sSessionID, 'DeviceID' => $vsys));
            $QueryHTMLlink = $QueryResult->Rules;

            #Get last ID FROM Security
            #$getlastlid=$projectdb->query("SELECT max(id) as max FROM security_rules;");
            #$getLID1=$getlastlid->fetch_assoc();
            #$lid=intval($getLID1['max'])+1;

            #Get last Position FROM Security
            #$getlastlid=$projectdb->query("SELECT max(position) as max FROM security_rules;");
            #$getLID1=$getlastlid->fetch_assoc();
            #$position=intval($getLID1['max'])+1;

            foreach( $QueryHTMLlink as $key1 => $value1 )
            {
                foreach( $value1 as $key => $value )
                {
                    $deviceID = $value->DeviceID;
                    #$ruleName=$value->UID;
                    #$line=$value->Line;
                    #$sources=split(",",$value->Source);
                    /*foreach ($sources as $kkey=>$vvalue){
                        if ($vvalue=="any"){}
                        else{
                            if (ip_version($vvalue)=="noip"){
                                $exists=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name='$vvalue';");
                                if ($exists->num_rows==0){
                                    #Create it

                                }
                                else {
                                    $data=$exists->fetch_assoc();
                                    $member_lid=$data['id'];
                                    $table_name="address";
                                }
                            }
                            else{
                                $exists=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$vvalue';");
                                if ($exists->num_rows==0){
                                    #Create it

                                }
                                else {
                                    $data=$exists->fetch_assoc();
                                    $member_lid=$data['id'];
                                    $table_name="address";
                                }
                            }

                        }
                    }
                    */
                    #$addTags[]="('$source','$vsys','$value->Line','$value->UID','$lid','$value->DeviceID','$x')";
                    #import_tags($source,$vsys,$username,$password,$afa_hostname,$value->UID,$value->DeviceID,$x);
                    #if ($value->Action=="permit"){$action="allow";}else{$action="deny";}
                    $addRule[] = "('$value->Line','$value->UID','$value->DeviceID')";
                    #$position++;$lid++;$x++;
                    #$action="";
                }
            }
            if( count($addRule) > 0 )
            {
                $projectdb->query("INSERT INTO algosec_policy_mapping (Line,RuleUid,DeviceID) VALUES " . implode(",", $addRule) . ";");
                unset($addRule);
            }
            #if (count($addTags)>0){
            #	$projectdb->query("INSERT INTO algosec_tags_mapping (source,vsys,Line,RuleUid,rule_lid,DeviceID,id) VALUES ".implode(",",$addTags).";");
            #}
            $return = $client->disconnect(array('SessionID' => $sSessionID));

            #Rename Rules
            $get = $projectdb->query("SELECT Line,RuleUid FROM algosec_policy_mapping WHERE DeviceID='$deviceID';");
            if( $get->num_rows > 0 )
            {
                while( $data = $get->fetch_assoc() )
                {
                    $Line = $data['Line'];
                    $RuleUid = $data['RuleUid'];
                    $get2 = $projectdb->query("SELECT rule_lid FROM cisco_policy_mapping WHERE line='$Line';");
                    if( $get2->num_rows == 1 )
                    {
                        $data2 = $get2->fetch_assoc();
                        $rule_lid = $data2['rule_lid'];
                        $projectdb->query("UPDATE security_rules SET name='$RuleUid',devicegroup='$deviceID' WHERE id='$rule_lid';");
                    }
                }
            }
        }
    } catch(Exception $objException)
    {
        echo 'Error: ' . $objException->getMessage();
        echo 'Error: ' . $objException->faultstring;
        echo '<xmp>';
        print_r($objException);
        echo '</xmp>';
    }
}

?>
