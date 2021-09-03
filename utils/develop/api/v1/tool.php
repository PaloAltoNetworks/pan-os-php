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

// assume JSON, handle requests by verb and path
$verb = $_SERVER['REQUEST_METHOD'];
if( isset( $_SERVER['PATH_INFO'] ) )
    $url_pieces = explode('/', $_SERVER['PATH_INFO']);
else
    $url_pieces = array();


$argv = array();
$argv[0] = "Standard input code";
$argv[1] = "in=".dirname(__FILE__)."/../../../../tests/input/panorama-10.0-merger.xml";
#$argv[2] = "shadow-json";

$supportedRoute = array('stats', 'address', 'service', 'tag', 'rule', 'device', 'securityprofile', 'securityprofilegroup', 'zone', 'schedule', 'interface', 'virtualwire', 'routing', 'application');
sort($supportedRoute );

// catch this here, we don't support many routes yet
if( empty( $url_pieces) || ( isset($url_pieces[1]) && !in_array( $url_pieces[1], $supportedRoute ) ) )
{
    $message = 'Unknown endpoint. supported: '.implode( ", ", $supportedRoute );
    throw new Exception($message, 404);
}

switch($verb) {
    case 'GET':
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
                foreach( $_GET as $key => $get )
                {
                    $argv[] = $key;
                }
            }
            elseif (isset($_GET['listactions']))
            {
                $argv = array();
                $argv[0] = "Standard input code";
                $argv[1] = "listactions";
            }
            elseif (isset($_GET['listfilters']))
            {
                $argv = array();
                $argv[0] = "Standard input code";
                $argv[1] = "listfilters";
            }
            else
            {
                foreach( $_GET as $key => $get )
                {
                    if( $key == "in" )
                    {
                        unset( $argv[1] );
                        if( strpos( $get, "api" ) === false )
                            $get = dirname(__FILE__)."/../../../../projects/".$get;
                        else
                            throw new Exception( "PAN-OS XML API mode is NOT yet supported.", 404);
                    }
                    elseif( $key == "out" )
                    {
                        $get = dirname(__FILE__)."/../../../../projects/".$get;
                    }

                    if( !empty($get) )
                        $value = $key."=".$get;
                    else
                        $value = $key;
                    $argv[] = $value;
                }
            }

            header("Content-Type: application/json");
            if( $url_pieces[1] == 'stats' )
                $util = new STATSUTIL( "stats", $argv, __FILE__);

            elseif( $url_pieces[1] == 'address' )
                $util = new UTIL( "address", $argv, __FILE__);
            elseif( $url_pieces[1] == 'service' )
                $util = new UTIL( "service", $argv, __FILE__);
            elseif( $url_pieces[1] == 'tag' )
                $util = new UTIL( "tag", $argv, __FILE__);
            elseif( $url_pieces[1] == 'schedule' )
                $util = new UTIL( "schedule", $argv, __FILE__);
            elseif( $url_pieces[1] == 'securityprofilegroup' )
                $util = new UTIL( "securityprofilegroup", $argv, __FILE__);
            elseif( $url_pieces[1] == 'application' )
                $util = new UTIL( "application", $argv, __FILE__);

            elseif( $url_pieces[1] == 'rule' )
                $util = new RULEUTIL( "rule", $argv, __FILE__);

            elseif( $url_pieces[1] == 'device' )
                $util = new DEVICEUTIL( "device", $argv, __FILE__);

            elseif( $url_pieces[1] == 'zone' )
                $util = new NETWORKUTIL( "zone", $argv, __FILE__);
            elseif( $url_pieces[1] == 'interface' )
                $util = new NETWORKUTIL( "interface", $argv, __FILE__);
            elseif( $url_pieces[1] == 'routing' )
                $util = new NETWORKUTIL( "routing", $argv, __FILE__);
            elseif( $url_pieces[1] == 'virtualwire' )
                $util = new NETWORKUTIL( "virtualwire", $argv, __FILE__);

            elseif( $url_pieces[1] == 'securityprofile' )
                $util = new SECURITYPROFILEUTIL( "securityprofile", $argv, __FILE__);

        }
        break;
    // two cases so similar we'll just share code
    case 'POST':
        //introduce uploading XML config file for manipulation
        #print_r($_POST);
        #print_r($HTTP_POST_FILES);
        #print_r($HTTP_POST_VARS);
    case 'PUT':
        // read the JSON
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
        #$storage->save();

        // send header, avoid output handler
        #header("Location: " . $item['url'], null,$status);
        exit;
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