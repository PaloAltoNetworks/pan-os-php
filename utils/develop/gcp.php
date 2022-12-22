<?php

/**
 * ISC License
 *
 * Copyright (c) 2019, Palo Alto Networks Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

########################################################################################################################
//"docker pull google/cloud-sdk:latest"

//"docker run -ti  google/cloud-sdk:latest gcloud version"

//"docker run -ti --name gcloud-config google/cloud-sdk gcloud auth login"
//"docker run --rm -ti --volumes-from gcloud-config google/cloud-sdk gcloud compute instances list --project ".$project
//"docker run --rm -ti --volumes-from gcloud-config google/cloud-sdk gcloud container clusters get-credentials ".$cluster." --region ".$region." --project ".$project
//"docker run --rm -ti --volumes-from gcloud-config google/cloud-sdk kubectl --insecure-skip-tls-verify=true exec -it ".$tenantID." -c ".substr($tenantID, 0, -2)." -- bash"

########################################################################################################################
PH::processCliArgs();


$tenantID = null;
$http_auth_IP = "10.181.137.2";
#$http_auth_IP = "10.181.244.2";
#$http_auth_IP = "10.181.244.66";
$inputconfig = null;
$outputfilename = null;
$displayOutput = true;
$configPath = "/opt/pancfg/mgmt/saved-configs/";
#$configPath = "/opt/pancfg/mgmt/factory/";
#$configPath = "/tmp/";

$insecureValue = "--insecure-skip-tls-verify=true";


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input filename', 'argDesc' => '[filename]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output filename ie: out=[PATH]/save-config.xml', 'argDesc' => '[filename]');
#$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['cluster'] = Array('niceName' => 'Cluster', 'shortHelp' => 'specify the cluster you like to connect | default: cluster=paas-fw1', 'argDesc' => '=paas-f1');
$supportedArguments['region'] = Array('niceName' => 'Region', 'shortHelp' => 'specify the region | default: region=us-central1', 'argDesc' => '=us-central1');
$supportedArguments['project'] = Array('niceName' => 'Project', 'shortHelp' => 'specify the project | default: project=ngfw-dev', 'argDesc' => '=ngfw-dev');
$supportedArguments['tenantid'] = Array('niceName' => 'TenantID', 'shortHelp' => 'TenantID you like to use. also possible to bring in a part script will do grep', 'argDesc' => '=123456789');
$supportedArguments['actions'] = Array('niceName' => 'actions', 'shortHelp' => 'specify the action the script should trigger', 'argDesc' => 'actions=grep');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." cluster=paas-f1 actions=grep tenantid=expedition";

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );

if( isset(PH::$args['help']) )
    $util->help(PH::$args);

if( isset(PH::$args['cluster']) )
    $cluster = PH::$args['cluster'];
else
    $cluster = "paas-f1";
if( isset(PH::$args['region']) )
    $region = PH::$args['region'];
else
    $region = "us-central1";
if( isset(PH::$args['project']) )
    $project = PH::$args['project'];
else
    $project = "ngfw-dev";


if( isset(PH::$args['tenantid']) )
    $tenantID = PH::$args['tenantid'];
else
    derr( "argument tenantid=[ID] is missing", null, false );

if( isset(PH::$args['in']) )
    $inputconfig = PH::$args['in'];

if( isset(PH::$args['out']) )
    $outputfilename = PH::$args['out'];

if( isset(PH::$args['actions']) )
{
    $action = PH::$args['actions'];

    $actionArray = array();
    $actionArray[] = "grep";
    $actionArray[] = "expedition-log";
    $actionArray[] = "upload";
    $actionArray[] = "download";
    if( strposARRAY( strtolower($action), $actionArray  ) == FALSE )
        derr( "not supported ACTION - ".implode(",", $actionArray) );
}
else
{
    PH::print_stdout();
    PH::print_stdout( " - possible actions=XYZ");
    PH::print_stdout( "   - actions=grep tenantid=XYZ");
    PH::print_stdout( "   - actions=expedition-log tenantid=090");
    PH::print_stdout( "   - actions=upload tenantid=FULL");
    PH::print_stdout( "   - actions=download tenantid=FULL");
    PH::print_stdout();
    derr( "argument actions= is missing", null, false );
}


########################################################################################################################

$http_auth = "https://".$http_auth_IP."/";

$get_auth = "gcloud container clusters get-credentials ".$cluster." --region ".$region." --project ".$project;
$get_all_pods = "kubectl ".$insecureValue." get pods";

$cliArray = array();
$cliArray2 = array();

########################################################################################################################

MFAAuthenticationCheck();


if( $displayOutput )
    PH::print_stdout();

//Authentication on cluster
execCLIWithOutput( $get_auth );
//get correct tenantid
if( isset(PH::$args['tenantid']) )
{
    $tenantIDString = $tenantID;
    $tenantID = grepAllPods( $tenantID );
    if( count( $tenantID ) == 1 )
        $tenantID = $tenantID[0];
    else
        $tenantID = $tenantIDString;
}



if( $action == "grep" )
{
    $kubectlArray = createKubectl( $tenantID );

    if( $kubectlArray !== null )
        foreach( $kubectlArray as $kubectlString )
        {
            PH::print_stdout( $kubectlString );
            PH::print_stdout();
        }

    #if( count( $kubectlArray ) == 1 )
    #    execCLI( $kubectlArray[0], $output, $retValue);
}
elseif( $action == "expedition-log" )
{
    $tmpArray = createKubectl( "expedition", "-- cat /var/log/expedition.log" );
    $cliArray2[] = $tmpArray[0];


    foreach( $cliArray2 as $cli )
    {
        $grepStringExpedition = "Done with executing the expedition convertor ";
        $grepStringExpedition2 = $tenantID;

        execCLI($cli, $output, $retValue);

        $checkCAT = FALSE;
        if( strpos($cli, "-- cat") !== FALSE )
            $checkCAT = TRUE;

        foreach( $output as $line )
        {
            if( !$checkCAT || ($checkCAT && strpos($line, $grepStringExpedition) !== FALSE) )
            {
                $string = '   ##  ';
                $string .= $line;

                PH::print_stdout($string);
                PH::print_stdout();

                $test = explode($grepStringExpedition, $line);
                $test = explode($grepStringExpedition2, $test[1]);
                if( isset($test[1]) )
                {
                    $test = explode(":", $test[1]);
                    $test = explode('"', $test[1]);

                    $tmpTenantid = trim($test[0]);

                    PH::print_stdout( $tmpTenantid );

                    $tenant_exec_array = createKubectl( $tmpTenantid );
                    if( $tenant_exec_array === null )
                    {
                        PH::print_stdout( "Tenant: '".$tmpTenantid."' not FOUND as a pod on cluster: ".$cluster );
                        PH::print_stdout();
                    }
                    else
                    {
                        foreach($tenant_exec_array as $tenant_exec)
                        {
                            PH::print_stdout();
                            PH::print_stdout( $tenant_exec );
                            PH::print_stdout();
                        }
                    }
                }
                else
                    PH::print_stdout( "Tenant: '".$tenantID."' not FOUND for successful migration" );
            }
        }
    }
}
elseif( $action == "upload" )
{
    if( $inputconfig === null )
        derr( "argument 'in=/PATH/FILENAME' is not specified" );
    if( $outputfilename === null )
    {
        #derr( "argument 'out=FILENAME' is not specified" );
        $tmpArray = explode( "/", $inputconfig );
        if( count( $tmpArray ) == 1 )
            $outputfilename = $inputconfig;
        elseif( count( $tmpArray ) > 1 )
            $outputfilename = end($tmpArray);
    }
    $tmpArray = explode( "/", $outputfilename );
    if( count( $tmpArray ) > 1 )
        derr( "argument 'out=FILENAME' is only with FILENAME not a PATH allowed" );
    $container = substr($tenantID, 0, -2);

    $cli = "kubectl ".$insecureValue." cp ".$inputconfig." -c ".$container." ".$tenantID.":".$configPath.$outputfilename;
    execCLIWithOutput( $cli );
}
elseif( $action == "download" )
{
    if( $outputfilename === null )
        derr( "argument 'out=FILENAME' is not specified" );
    if( $inputconfig === null )
        $inputconfig = "running-config.xml";
    $tmpArray = explode( "/", $inputconfig );
    if( count( $tmpArray ) > 1 )
        derr( "argument 'in=FILENAME' is only with FILENAME not a PATH allowed" );


    $cli = "kubectl ".$insecureValue." exec ".$tenantID." -c ".substr($tenantID, 0, -2)." -- cat ".$configPath.$inputconfig." > ".$outputfilename;
    execCLIWithOutput( $cli );
}

########################################################################################################################
########################################################################################################################
########################################################################################################################

function execCLI( $cli, &$output, &$retValue )
{
    PH::print_stdout();
    PH::print_stdout( "execute: '".$cli."'");
    exec($cli, $output, $retValue);
}

function execCLIWithOutput( $cli )
{
    global $displayOutput;

    execCLI($cli, $output, $retValue);
    foreach( $output as $line )
    {
        $string = '   ##  ';
        $string .= $line;
        if( $displayOutput )
        {
            PH::print_stdout($string);
            PH::print_stdout();
        }
    }
}

function strposARRAY(string $haystack, array $needles, int $offset = 0): bool
{
    foreach($needles as $needle) {
        if(strpos($haystack, $needle, $offset) !== false) {
            return true; // stop on first true result
        }
    }

    return false;
}

function extractTenentID( $line, $command = "-- bash" )
{
    $tmpArray = explode(" ", $line);
    $tmpTenantID = $tmpArray[0];
    PH::print_stdout("'" . $tmpTenantID . "'");
    PH::print_stdout();


    return $tmpTenantID;
}


function createKubectl( $tenantID, $command = "-- bash" )
{
    global $insecureValue;

    $return = array();
    //get correct onprem tenant
    $tenantIDarray = grepAllPods( $tenantID );

    if( !empty($tenantIDarray) )
    {
        foreach( $tenantIDarray as $tenantID )
        {
            if( strpos( $tenantID, "expedition" ) !== FALSE )
                $tenant_exec = "kubectl ".$insecureValue." exec -it " . $tenantID . " -c expedition";
            else
                $tenant_exec = "kubectl ".$insecureValue." exec -it " . $tenantID . " -c ".substr($tenantID, 0, -2);

            $return[] = $tenant_exec." ".$command;
        }
        return $return;
    }

    return null;
}

function grepAllPods( $tenantID )
{
    global $get_all_pods;
    global $displayOutput;

    $returnArray = array();
    $cli = $get_all_pods." | grep ".$tenantID;

    execCLI($cli, $output, $retValue);
    foreach( $output as $line )
    {
        $string = '   ##  ';
        $string .= $line;
        if( $displayOutput )
        {
            PH::print_stdout($string);
        }
        $returnArray[] = extractTenentID( $line );
    }

    return $returnArray;
}

function MFAAuthenticationCheck()
{
    global $http_auth;
    global $http_auth_IP;

    $expectedResponse = '{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {
    
  },
  "code": 403
}';


    $curl = curl_init($http_auth);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_HTTPHEADER,
        array('User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12')
    );
    $response = curl_exec($curl);
    curl_close($curl);

    if( $expectedResponse !== $response )
    {
        //execute:
        #$exec = "Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome https://".$http_auth_IP;
        #exec( $exec );
        #sleep(20);

        $message = "please open: ".$http_auth." in WebBrowser for MFA authentication. Then rerun this script";
        derr( $message, null, FALSE );
        #mwarning( $message, null, FALSE );
    }
    else
    {
        PH::print_stdout( "##############################");
        PH::print_stdout( "MFA authentication checked with: ".$http_auth );
        PH::print_stdout( "##############################");
    }
}
