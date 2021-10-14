<?php
//Todo: swaschkut 20210624
// - change UTIL script so it can be used here:
//   - address-merger/addressgroup-merger/service-merger/servicegroup-merge/tag-merger/rule-merger
//   - interface/routing/vwire/ike
// -
// - user authentication OAuth2 - access to only specific projects
// - create project related to user => response project ID
// - upload config to project folder by using project ID
// - use git module to do all manipulation against one file within a project folder


require_once dirname(__FILE__)."/../../../../lib/pan_php_framework.php";
require_once ( dirname(__FILE__)."/../../../lib/UTIL.php");


set_exception_handler(function ($e) {
    $code = $e->getCode() ?: 400;
    header("Content-Type: application/json", NULL, $code);
    print json_encode(["error" => $e->getMessage()]);
    exit;
});

$projects_folder = "/project/";

$file_tmp_name = "";
$upload_dir = "";
if( !isset( $_GET['in'] ) && isset($_FILES['configInput']) )
{
    #header('Content-Type: application/json; charset=utf-8');
    #header("Access-Control-Allow-Origin: *");
    #header("Access-Control-Allow-Methods: PUT, GET, POST");

    $response = array();
    $upload_dir = '';
    //$server_url = 'http://localhost:8082/utils/develop/api/v1';

    $file_name = $_FILES['configInput']["name"];
    $file_tmp_name = $_FILES['configInput']["tmp_name"];
    $error = $_FILES['configInput']["error"];

    if($error > 0)
    {
        $message = "Error uploading the file!";
        throw new Exception($message, 404);
    }
    else
    {
        $random = rand(1000,1000000);
        $random_name = $random."-".$file_name;
        $upload_name = $upload_dir.strtolower($random_name);
        $upload_name = preg_replace('/\s+/', '-', $upload_name);

        /*
        if( move_uploaded_file( $file_tmp_name , $upload_name  ) )
        {
            $response = array(
                "status" => "success",
                "error" => false,
                "message" => "File uploaded successfully",
                "url" => $server_url."/".$upload_name,
                "filename" => $upload_name
            );
        }
        else
        {
            $message = "Error uploading the file!";
            throw new Exception($message, 404);
        }
        */
    }
}


// assume JSON, handle requests by verb and path
$verb = $_SERVER['REQUEST_METHOD'];
if( isset( $_SERVER['PATH_INFO'] ) )
    $url_pieces = explode('/', $_SERVER['PATH_INFO']);
else
    $url_pieces = array();


$supportedRoute = array(
    "stats",
    "address", "service", "tag", "schedule", "application", "threat",
    "rule",
    "device", "securityprofile", "securityprofilegroup",
    "zone",  "interface", "virtualwire", "routing",
    "key-manager",
    "address-merger", "addressgroup-merger",
    "service-merger", "servicegroup-merger",
    "tag-merger",
    "rule-merger",
    "override-finder",
    "diff",
    "upload",
    "xml-issue",
    "appid-enabler",
    "config-size",
    "download-predefined"
    );
sort($supportedRoute );

// catch this here, we don't support many routes yet
if( empty( $url_pieces) || ( isset($url_pieces[1]) && !in_array( $url_pieces[1], $supportedRoute ) ) )
{
    $example = "http://localhost:8082/utils/develop/api/v1/tool.php/address?shadow-json";
    $message = 'Unknown endpoint. supported: '.implode( ", ", $supportedRoute ).' Example: '.$example;

    throw new Exception($message, 404);
}


$argv = array();
$argv[0] = "Standard input code";

if( !isset($_GET['in']) && isset( $_FILES['configInput'] ) ){
    $argv[] = "in=".$file_tmp_name;
    #$argv[] = "out=".$upload_dir.$random."-new.xml";
    $argv[] = "out=true";
}
elseif( isset($_GET['in']) )
{
    if( !isset($_GET['out']) )
        $argv[] = "out=true";
}
elseif( isset($_GET['help']) || isset($_GET['listfilters']) || isset($_GET['listactions']) || $url_pieces[1] == "key-manager" )
{
}
else{
    #$argv[] = "in=".dirname(__FILE__)."/../../../../tests/input/panorama-10.0-merger.xml";
    $message = 'No File available with argument in=';
    throw new Exception($message, 404);
}






switch($verb) {
    case 'GET':
        UTILcaller( $url_pieces, $argv );

        break;
    // two cases so similar we'll just share code
    case 'POST':
        //introduce uploading XML config file for manipulation
        #print_r($_POST);
        #print_r($HTTP_POST_FILES);
        #print_r($HTTP_POST_VARS);


    case 'PUT':
        // read the JSON
        /*
        $params = json_decode(file_get_contents("php://input"), true);
        if(!$params) {
            throw new Exception("Data missing or invalid");
        }
        if($verb == 'PUT') {
            #$id = $url_pieces[2];
            #$item = $storage->update($id, $params);
            $status = 204;
        } else {
            #$item = $storage->create($params);
            $status = 201;
        }
        */
        #$storage->save();

        // send header, avoid output handler
        #header("Location: " . $item['url'], null,$status);
        #exit;
        #break;

        #throw new Exception("PUT");


        UTILcaller( $url_pieces, $argv );


        break;
    case 'DELETE':
        $id = $url_pieces[2];
        #$storage->remove($id);
        #$storage->save();
        header("Location: http://localhost:8080/items", null, 204);
        exit;
        break;
    case 'OPTIONS':
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: POST, GET, DELETE, PUT, PATCH, OPTIONS');
        header('Access-Control-Allow-Headers: token, Content-Type');
        header('Content-Length: 0');
        #header('Content-Type: text/plain');
        header('Content-Type: application/xml; charset=utf-8');
        header("HTTP/1.1", null, 204);
        exit;
        break;
    default:
        throw new Exception('Method Not Supported', 405);
}

#header("Content-Type: application/json");
#print json_encode($data);

function UTILcaller( $url_pieces, $argv )
{
    global $projects_folder;

    if(isset($url_pieces[2]))
    {
        try
        {
            #$data = $storage->getOne($url_pieces[2]);
        } catch (UnexpectedValueException $e) {
            throw new Exception("Resource does not exist", 404);
        }
    }
    else
    {
        if (isset($_GET['help']))
        {
            $argv = array();
            $argv[0] = "Standard input code";
            $argv[] = "shadow-json";
            foreach( $_GET as $key => $get )
            {
                $argv[] = $key;
            }
        }
        elseif (isset($_GET['listactions']))
        {
            $argv = array();
            $argv[0] = "Standard input code";
            $argv[] = "shadow-json";
            $argv[] = "listactions";
        }
        elseif (isset($_GET['listfilters']))
        {
            $argv = array();
            $argv[0] = "Standard input code";
            $argv[] = "shadow-json";
            $argv[] = "listfilters";
        }
        else
        {
            foreach( $_GET as $key => $get )
            {
                if( $key == "in" )
                {
                    unset( $argv[1] );
                    if( strpos( $get, "api" ) === false )
                        $get = dirname(__FILE__).$projects_folder.$get;
                    else
                    {
                        #throw new Exception( "PAN-OS XML API mode is NOT yet supported.", 404);
                    }

                }
                elseif( $key == "out" )
                {
                    $get = dirname(__FILE__).$projects_folder.$get;
                }

                if( !empty($get) )
                    $value = $key."=".$get;
                else
                    $value = $key;
                $argv[] = $value;
            }
        }

        header("Content-Type: application/json");
        if( $url_pieces[1] == 'rule' )
            $util = new RULEUTIL( $url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == 'stats' )
            $util = new STATSUTIL( $url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == 'securityprofile' )
            $util = new SECURITYPROFILEUTIL( $url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == 'zone'
            || $url_pieces[1] == 'interface'
            || $url_pieces[1] == 'routing'
            || $url_pieces[1] == 'virtualwire'
        )
            $util = new NETWORKUTIL( $url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == 'device' )
            $util = new DEVICEUTIL( $url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == "key-manager" )
            $util = new KEYMANGER($url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == "address-merger"
            || $url_pieces[1] == "addressgroup-merger"
            || $url_pieces[1] == "service-merger"
            || $url_pieces[1] == "servicegroup-merger"
            || $url_pieces[1] == "tag-merger"
        )
            $util = new MERGER($url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == "rule-merger" )
            $util = new RULEMERGER($url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == "override-finder" )
            $util = new OVERRIDEFINDER($url_pieces[1], $argv, __FILE__);
        elseif( $url_pieces[1] == "diff" )
            $util = new DIFF($url_pieces[1], $argv, __FILE__);
        elseif( $url_pieces[1] == "upload" )
            $util = new UPLOAD($url_pieces[1], $argv, __FILE__);
        elseif( $url_pieces[1] == "xml-issue" )
            $util = new XMLISSUE($url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == "appid-enabler" )
            $util = new APPIDENABLER($url_pieces[1], $argv, __FILE__);
        elseif( $url_pieces[1] == "config-size" )
            $util = new CONFIGSIZE($url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == "download-predefined" )
            $util = new PREDEFINED($url_pieces[1], $argv, __FILE__);

        elseif( $url_pieces[1] == 'address'
            || $url_pieces[1] == 'service'
            || $url_pieces[1] == 'tag'
            || $url_pieces[1] == 'schedule'
            || $url_pieces[1] == 'securityprofilegroup'
            || $url_pieces[1] == 'application'
            || $url_pieces[1] == 'threat'
        )
            $util = new UTIL( $url_pieces[1], $argv, __FILE__);

    }
}