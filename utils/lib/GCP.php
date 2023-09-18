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

class GCP extends UTIL
{
    private $tenantID = null;
    private $http_auth_IP = "10.181.137.2";
    private $http_auth = "";
    #$http_auth_IP = "10.181.244.2";
    #$http_auth_IP = "10.181.244.66";

    private $get_all_pods = "";

    private $inputconfig = null;
    private $outputfilename = null;
    private $displayOutput = true;
    private $configPath = "/opt/pancfg/mgmt/saved-configs/";
    private $configPath_factory = "/opt/pancfg/mgmt/factory/";
    #private $configPath = "/opt/pancfg/mgmt/factory/";
    private $configPath_tmp = "/tmp/";

    private $insecureValue = "--insecure-skip-tls-verify=true";


    private $project_json = null;
    private $validation_command = null;


    public function utilStart()
    {
        PH::processCliArgs();

        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input filename', 'argDesc' => '[filename]');
        $this->supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output filename ie: out=[PATH]/save-config.xml', 'argDesc' => '[filename]');
        #$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['cluster'] = Array('niceName' => 'Cluster', 'shortHelp' => 'specify the cluster you like to connect | default: cluster=paas-fw1', 'argDesc' => '=paas-f1');
        $this->supportedArguments['region'] = Array('niceName' => 'Region', 'shortHelp' => 'specify the region | default: region=us-central1 | region=europe-west3', 'argDesc' => '=us-central1');
        $this->supportedArguments['project'] = Array('niceName' => 'Project', 'shortHelp' => 'specify the project | default: project=ngfw-dev', 'argDesc' => '=ngfw-dev');
        $this->supportedArguments['tenantid'] = Array('niceName' => 'TenantID', 'shortHelp' => 'TenantID you like to use. also possible to bring in a part script will do grep', 'argDesc' => '=123456789');
        $this->supportedArguments['actions'] = Array('niceName' => 'actions', 'shortHelp' => 'specify the action the script should trigger', 'argDesc' => 'actions=grep');


        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." cluster=paas-f1 actions=grep tenantid=expedition";


        $this->prepareSupportedArgumentsArray();


        #$this->utilInit();


        $this->main();


    }

    public function main()
    {
        if( isset(PH::$args['help']) )
            $this->help(PH::$args);

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
        elseif( isset(PH::$args['in']) )
            $outputfilename = $inputconfig;
        elseif( isset(PH::$args['project-json']) )
            $project_json = PH::$args['project-json'];
        elseif( isset(PH::$args['validation-command']) )
            $validation_command = PH::$args['validation-command'];

        if( isset(PH::$args['actions']) )
        {
            $action = PH::$args['actions'];

            $actionArray = array();
            $actionArray[] = "grep";
            $actionArray[] = "expedition-log";
            $actionArray[] = "upload";
            $actionArray[] = "download";
            $actionArray[] = "validation";
            $actionArray[] = "onboard";
            $actionArray[] = "offboard";
            $actionArray[] = "mysql-validation";
            if( $this->strposARRAY( strtolower($action), $actionArray  ) == FALSE )
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
            PH::print_stdout( "   - actions=validation tenantid=XYZ validation-command='XYZ'");
            PH::print_stdout( "   - actions=onboard tenantid=XYZ");
            PH::print_stdout( "   - actions=offboard tenantid=XYZ");
            PH::print_stdout( "   - actions=mysql-validation tenantid=XYZ");
            PH::print_stdout();
            derr( "argument actions= is missing", null, false );
        }


########################################################################################################################

        $this->http_auth = "https://".$this->http_auth_IP."/";

        $get_auth = "gcloud container clusters get-credentials ".$cluster." --region ".$region." --project ".$project;
        $this->get_all_pods = "kubectl ".$this->insecureValue." get pods";

        $cliArray = array();
        $cliArray2 = array();

########################################################################################################################
        print $get_auth."\n";
        $this->MFAAuthenticationCheck();


        if( $this->displayOutput )
            PH::print_stdout();

//Authentication on cluster

        $this->execCLIWithOutput( $get_auth );
//get correct tenantid
        if( isset(PH::$args['tenantid']) && $action != "mysql-validation" )
        {
            $tenantIDString = $tenantID;
            $tenantID = $this->grepAllPods( $tenantID );
            if( count( $tenantID ) == 1 )
                $tenantID = $tenantID[0];
            else
                $tenantID = $tenantIDString;
        }



        if( $action == "grep" )
        {
            $kubectlArray = $this->createKubectl( $tenantID );

            if( $kubectlArray !== null )
                foreach( $kubectlArray as $kubectlString )
                {
                    PH::print_stdout( $kubectlString );
                    PH::print_stdout();
                }

            #if( count( $kubectlArray ) == 1 )
            #    $this->execCLI( $kubectlArray[0], $output, $retValue);
        }
        elseif( $action == "expedition-log" )
        {
            $tmpArray = $this->createKubectl( "expedition", "-- cat /var/log/expedition.log" );
            $cliArray2[] = $tmpArray[0];


            foreach( $cliArray2 as $cli )
            {
                $grepStringExpedition = "Done with executing the expedition convertor ";
                $grepStringExpedition2 = $tenantID;

                $this->execCLI($cli, $output, $retValue);

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

                            $tenant_exec_array = $this->createKubectl( $tmpTenantid );
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
            if( strpos( $tenantID, "expedition" ) !== False )
            {
                $container = "expedition";
                $this->configPath = "/tmp/";
            }
            else
                $container = substr($tenantID, 0, -2);

            $cli = "kubectl ".$this->insecureValue." cp ".$inputconfig." -c ".$container." ".$tenantID.":".$this->configPath.$outputfilename;
            $this->execCLIWithOutput( $cli );
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

            if( strpos( $tenantID, "expedition" ) !== False )
            {
                $container = "expedition";
                $this->configPath = "/tmp/";
            }
            else
                $container = substr($tenantID, 0, -2);

            $cli = "kubectl ".$this->insecureValue." exec ".$tenantID." -c ".$container." -- cat ".$this->configPath.$inputconfig." > ".$outputfilename;
            $this->execCLIWithOutput( $cli );
        }
        elseif( $action == "validation" )
        {

            if( $validation_command === null )
                derr( "argument 'validation-command=COMMAND' is not specified" );


            if( strpos( $tenantID, "expedition" ) !== False )
            {
                $container = "expedition";
                $this->configPath = "/tmp/";
            }
            else
                $container = substr($tenantID, 0, -2);

            $cli = "kubectl ".$this->insecureValue." exec ".$tenantID." -c ".$container." -- ".$validation_command;

            $this->execCLI($cli, $output, $retValue);

            foreach( $output as $line )
            {
                $string = '   ##  ';
                $string .= $line;

                PH::print_stdout($string);
            }
        }
        elseif( $action == "onboard" )
        {
            //gcloud container clusters get-credentials admin --region us-central1 --project ngfw-dev
            #$region = "us-central1";
            #$project = "ngfw-dev";
            $get_auth = "gcloud container clusters get-credentials admin --region ".$region." --project ".$project;
            //kubectl get pods --insecure-skip-tls-verify=true
            //grep mgmtsvc


            $this->execCLIWithOutput( $get_auth );
            $mgmtsvc_tenantID = $this->grepAllPods( "mgmtsvc" );
            PH::print_stdout( "mgmtsvc tenantID: '".$mgmtsvc_tenantID[0]."'");


            $mgmtsvc = "kubectl exec -it ".$mgmtsvc_tenantID[0]." -c mgmtsvc --insecure-skip-tls-verify=true -- ";

            #$tenant = "swaschkut-2";
            #$cluster = "paas-f4";
            $region_location = "americas";
            $onbard_string = 'curl -X POST http://127.0.0.1:8085/api/v1/src/mgmtsvc/customer/onboard -d \'{"id":"'.$tenantID.'","aid":"'.$tenantID.'","c":"'.$cluster.'", "b":"{\"tenant_id\":\"'.$tenantID.'\",\"associations\":[{\"app_id\":\"Logging Service\",\"tenant_id\":\"'.$tenantID.'\",\"region\":\"'.$region_location.'\"}]}"}\'';
            $this->execCLIWithOutput( $mgmtsvc.$onbard_string );
        }
        elseif( $action == "offboard" )
        {
            $get_auth = "gcloud container clusters get-credentials admin --region ".$region." --project ".$project;
            $this->execCLIWithOutput( $get_auth );

            $mgmtsvc_tenantID = $this->grepAllPods( "mgmtsvc" );
            $mgmtsvc = "kubectl exec -it ".$mgmtsvc_tenantID[0]." -c mgmtsvc --insecure-skip-tls-verify=true -- ";

            $offboard_string = 'curl --header "Content-Type: application/json; charset=UTF-8" --request POST --data \'{"id":"'.$tenantID.'", "r":"false", "mig":"false"}\' http://127.0.0.1:8085/api/v1/src/mgmtsvc/customer/offboard';
            $this->execCLIWithOutput( $mgmtsvc.$offboard_string );

            /*
            Clean up database for that tenant
            //mysqladmin -h[hostname/localhost] -u[username] -p[password] drop [database]
            adi@mgmtsvc-5ddbbc7fbd-t7r4s:~$ mysql --host 127.0.0.1 --port  3310 -u USER -p PASSWORD

            mysql> drop database `DATABASE`;
             */
            $username = "paloalto";
            //check if available via .panconfigkeystore
            $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'gcp-mysql-password' );
            $mysqlPassword = $connector->apikey;

            #$database = substr($tenantID, 0, -2);
            $database = $tenantID;
            if( !is_numeric($tenantID) )
                derr( "tenantID: '".$tenantID."' - is not numeric" );

            $drop_database_string = 'mysql -h 127.0.0.1 -P 3310 -u '.$username.' -p'.$mysqlPassword.' drop `'.$database.'`';
            $this->execCLIWithOutput( $mgmtsvc.$drop_database_string );
        }
        elseif( $action == "mysql-validation" )
        {
            $get_auth = "gcloud container clusters get-credentials admin --region ".$region." --project ".$project;
            $this->execCLIWithOutput( $get_auth );

            $mgmtsvc_tenantID = $this->grepAllPods( "mgmtsvc" );
            $mgmtsvc = "kubectl exec -it ".$mgmtsvc_tenantID[0]." -c mgmtsvc --insecure-skip-tls-verify=true -- ";


            $username = "paloalto";

            //check if available via .panconfigkeystore
            $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'gcp-mysql-password' );
            $mysqlPassword = $connector->apikey;


            if( !is_numeric($tenantID) )
                derr( "tenantID: '".$tenantID."' - is not numeric" );

            $cmdArray = array();
            $cmdArray[] = array("cmd" => "select * from adi_adm_customer_info where tenant_id='".$tenantID."_onprem'\G" );
            $cmdArray[] = array("cmd" => "select * from adi_migration where onprem_tenant_id='".$tenantID."_onprem'\G" );
            /*
             Use $tenantID;
              Select * from jobs\G
             */
            $cmdArray[] = array("cmd" => "select * from jobs\G", "db" => $tenantID);

            $cmdArray[] = array("cmd" => "select * from spiffy_license_info where cdl_tenant_id='".$tenantID."'\G" );

            $cmdArray[] = array("cmd" => "select * from adi_adm_customer_info where customer_blob like '%".$tenantID."%'\G" );


            $cmdArray[] = array("cmd" => "select info_status_message from adi_ext_prisma_access_sync_status where tenant_id='".$tenantID."'\G" );

            foreach( $cmdArray as $cmd )
            {
                if( isset( $cmd['db'] ) )
                    $DB = $cmd['db'];
                else
                    $DB = "admin";
                $drop_database_string = 'mysql -h 127.0.0.1 -P 3310 -u '.$username.' -U '.$DB.' -p'.$mysqlPassword.' -e "'.$cmd['cmd'].'"';
                $this->execCLIWithOutput( $mgmtsvc.$drop_database_string );
            }
        }
    }


    private function execCLI( $cli, &$output, &$retValue )
    {
        PH::print_stdout();
        $cliString = $cli;
        if( strpos( $cliString, "mysql" ) !== FALSE )
        {
            $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'gcp-mysql-password' );
            $mysqlPassword = $connector->apikey;
            $cliString = str_replace($mysqlPassword, "**********", $cliString);
        }

        PH::print_stdout( "execute: '".$cliString."'");
        exec($cli, $output, $retValue);
    }

    private function execCLIWithOutput( $cli )
    {
        $this->execCLI($cli, $output, $retValue);

        if( strpos( $cli, "get-credentials" ) != False && $retValue == 1 )
            derr( "permission denied on resource: ".$cli, null, False );

        foreach( $output as $line )
        {
            $string = '   ##  ';
            $string .= $line;



            if( $this->displayOutput )
            {
                PH::print_stdout($string);
                PH::print_stdout();
            }
        }
    }

    private function strposARRAY(string $haystack, array $needles, int $offset = 0): bool
    {
        foreach($needles as $needle) {
            if(strpos($haystack, $needle, $offset) !== false) {
                return true; // stop on first true result
            }
        }

        return false;
    }

    private function extractTenentID( $line, $command = "-- bash" )
    {
        $tmpArray = explode(" ", $line);
        $tmpTenantID = $tmpArray[0];
        PH::print_stdout("'" . $tmpTenantID . "'");
        PH::print_stdout();


        return $tmpTenantID;
    }


    private function createKubectl( $tenantID, $command = "-- bash" )
    {
        $return = array();
        //get correct onprem tenant
        $tenantIDarray = $this->grepAllPods( $tenantID );

        if( !empty($tenantIDarray) )
        {
            foreach( $tenantIDarray as $tenantID )
            {
                if( strpos( $tenantID, "expedition" ) !== FALSE )
                    $tenant_exec = "kubectl ".$this->insecureValue." exec -it " . $tenantID . " -c expedition";
                elseif( strpos( $tenantID, "mgmtsvc" ) !== FALSE )
                    $tenant_exec = "kubectl ".$this->insecureValue." exec -it " . $tenantID . " -c mgmtsvc";
                else
                    $tenant_exec = "kubectl ".$this->insecureValue." exec -it " . $tenantID . " -c ".substr($tenantID, 0, -2);

                $return[] = $tenant_exec." ".$command;
            }
            return $return;
        }

        return null;
    }

    private function grepAllPods( $tenantID )
    {
        $returnArray = array();
        $cli = $this->get_all_pods." | grep ".$tenantID;

        $this->execCLI($cli, $output, $retValue);
        foreach( $output as $line )
        {
            $string = '   ##  ';
            $string .= $line;
            if( $this->displayOutput )
            {
                PH::print_stdout($string);
            }
            $returnArray[] = $this->extractTenentID( $line );
        }

        return $returnArray;
    }

    private function MFAAuthenticationCheck()
    {
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

        $expectedResponse = '{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {},
  "code": 403
}';

        $curl = curl_init($this->http_auth);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_HTTPHEADER,
            array('User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12')
        );
        $response = curl_exec($curl);
        curl_close($curl);

        if( $expectedResponse !== $response )
        {
            $counter = 0;
            do
            {
                PH::print_stdout( "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                PH::print_stdout( "AUTHENTICATION NEEDED - please check new CHROME window");
                PH::print_stdout( "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                //execute:
                $exec = 'open -a "Google Chrome" '.$this->http_auth;
                exec( $exec );
                sleep(20);

                $response = curl_exec($curl);
                curl_close($curl);

                $counter++;
            }
            while( $expectedResponse !== $response && $counter < 2 );
        }

        if( $expectedResponse === $response )
        {
            PH::print_stdout( "##############################");
            PH::print_stdout( "MFA authentication checked with: ".$this->http_auth );
            PH::print_stdout( "##############################");
        }
        else
        {
            $message = "please open: ".$this->http_auth." in WebBrowser for MFA authentication. Then rerun this script";
            derr( $message, null, FALSE );
        }
    }

}