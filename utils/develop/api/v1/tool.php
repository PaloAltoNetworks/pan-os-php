<?php

require_once dirname(__FILE__)."/../../../../lib/pan_php_framework.php";
require_once ( dirname(__FILE__)."/../../../lib/UTIL.php");


set_exception_handler(function ($e) {
    $code = $e->getCode() ?: 400;
    header("Content-Type: application/json", NULL, $code);
    echo json_encode(["error" => $e->getMessage()]);
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

$supportedRoute = array('stats', 'address', 'service', 'tag', 'rule');


// catch this here, we don't support many routes yet
if( !isset( $url_pieces) || ( isset($url_pieces[1]) && !in_array( $url_pieces[1], $supportedRoute ) ) )
{
    throw new Exception('Unknown endpoint', 404);
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
            elseif( $url_pieces[1] == 'rule' )
                $util = new RULEUTIL( "rule", $argv, __FILE__);
        }
        break;
    // two cases so similar we'll just share code
    case 'POST':
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
    default:
        throw new Exception('Method Not Supported', 405);
}

#header("Content-Type: application/json");
#echo json_encode($data);