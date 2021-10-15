<?php


class USERIDMGR extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE EXAMPLES: ') . "\n - php " . basename(__FILE__) . " in=api://1.2.3.4 action=register location=vsys1 records=10.0.0.1,domain\\user2/10.2.3.4,domain\\user3"
            . "\n - php " . basename(__FILE__) . " in=api://1.2.3.4 action=register location=vsys1 recordFile=users.txt";
        
        $this->prepareSupportedArgumentsArray();
        
        
        $this->utilInit();


        $this->main();


        $this->endOfScript();
    }

    public function main()
    {

        PH::print_stdout( " - Connected to API at {$this->pan->connector->apihost} / {$this->pan->connector->info_hostname}");
        PH::print_stdout( " - PANOS version: {$this->pan->connector->info_PANOS_version}");
        PH::print_stdout( " - PANOS model: {$this->pan->connector->info_model}");
        PH::print_stdout( "");


        if( !isset(PH::$args['actions']) )
            $this->display_error_usage_exit("no 'action' was defined");


        $action = strtolower(PH::$args['actions']);

        if( $action == 'display' || $action == 'unregister-all' )
        {
            PH::print_stdout(" - action is '$action'");
            PH::print_stdout("");

            $unregister_array = array();

            $this->pan->load_from_domxml($this->xmlDoc);

            if( $this->configType == 'panos' )
                $virtualsystems = $this->pan->getVirtualSystems();
            elseif( $this->configType == 'panorama' )
                $virtualsystems = $this->pan->getDeviceGroups();


            $all = array();
            foreach( $virtualsystems as $sub )
            {
                $unregister_array[$sub->name()] = array();

                PH::print_stdout("##################################");
                PH::print_stdout(PH::boldText(" - " . $sub->name()));

                $register_ip_array = $this->pan->connector->userid_getIp($sub->name());
                PH::print_stdout("     - user-ip-mappings: [" . count($register_ip_array) . "]");

                foreach( $register_ip_array as $ip => $reg )
                {
                    #$first_value = reset($reg); // First Element's Value
                    #$first_key = key($reg); // First Element's Key

                    PH::print_stdout("          " . $ip . " - " . $reg['user'] );#. " - " . $reg['type']);
                    $unregister_array[$sub->name()]['ip'][] = $ip;
                    $unregister_array[$sub->name()]['user'][] = $reg['user'];
                }
            }

            if( $action == 'unregister-all' )
            {

                foreach( $unregister_array as $vsysName => $vsys )
                {
                    $response = $this->pan->connector->userIDLogout($vsys['ip'], $vsys['user'], $vsysName)  ;
                }

            }
        }
        elseif( $action == 'register' || $action == 'unregister' )
        {
            PH::print_stdout( " - action is '$action'");
            $records = array();

            if( isset(PH::$args['records']) )
            {
                PH::print_stdout( " - a list of 'records' was provided on CLI, now parsing it...");
                $explode = explode('/', PH::$args['records']);
                foreach( $explode as $record )
                {
                    $lrecord = explode(',', $record);
                    if( count($lrecord) != 2 )
                        $this->display_error_usage_exit("the following record does not have the right syntax: '{$record}'");
                    $username = trim($lrecord[1]);
                    $ipaddress = trim($lrecord[0]);

                    if( strlen($username) < 1 )
                        $this->display_error_usage_exit("blank username in record '{$record}'");

                    if( strlen($ipaddress) < 1 )
                        $this->display_error_usage_exit("blank IP in record '{$record}'");

                    if( isset($records[$ipaddress]) && $records[$ipaddress] != $username )
                        $this->display_error_usage_exit("record '{$ipaddress}\\{$username}' conflicts with '{$ipaddress}\\{$records[$ipaddress]}'");

                    if( !filter_var($ipaddress, FILTER_VALIDATE_IP) )
                        $this->display_error_usage_exit("IP address '{$ipaddress}' is not valid in record '{$record}'");

                    $records[$ipaddress] = $username;
                }


            }
            elseif( isset(PH::$args['recordfile']) )
            {
                PH::print_stdout( " - record file was provided, now parsing it...");

                $explode = file_get_contents(PH::$args['recordfile']);
                $explode = explode("\n", $explode);

                foreach( $explode as $record )
                {
                    if( strlen(trim($record)) < 1 )
                        continue; // this is an empty line

                    $lrecord = explode(',', $record);
                    if( count($lrecord) != 2 )
                        $this->display_error_usage_exit("the following record does not have the right syntax: '{$record}'");
                    $username = trim($lrecord[1]);
                    $ipaddress = trim($lrecord[0]);

                    if( strlen($username) < 1 )
                        $this->display_error_usage_exit("blank username in record '{$record}'");

                    if( strlen($ipaddress) < 1 )
                        $this->display_error_usage_exit("blank IP in record '{$record}'");

                    if( isset($records[$ipaddress]) && $records[$ipaddress] != $username )
                        $this->display_error_usage_exit("record '{$ipaddress}\\{$username}' conflicts with '{$ipaddress}\\{$records[$ipaddress]}'");

                    if( !filter_var($ipaddress, FILTER_VALIDATE_IP) )
                        $this->display_error_usage_exit("IP address '{$ipaddress}' is not valid in record '{$record}'");

                    $records[$ipaddress] = $username;
                }


            }
            else
                derr("you need to provide 'records' or 'recordfile' argument");

            $count = count($records);
            PH::print_stdout( " - found {$count} records:");
            foreach( $records as $ip => $user )
            {
                PH::print_stdout( "   - " . str_pad($ip, 16) . " / {$user}");
            }

            PH::print_stdout( " - now sending records to API ... ");
            if( $action == 'register' )
                $this->pan->connector->userIDLogin(array_keys($records), $records, $this->location);
            else
                $this->pan->connector->userIDLogout(array_keys($records), $records, $this->location);



        }
        elseif( $action == 'fakeregister' )
        {
            $numberOfIPs = 500;
            $numberOfIPs = 10;
            $userPrefix = 'acme\\Bob_';
            $startingIP = ip2long('10.0.0.0');

            $records = array();


            PH::print_stdout( "  - Generating {$numberOfIPs} fake records starting at IP " . long2ip($startingIP) . "... ");
            for( $i = 1; $i <= $numberOfIPs; $i++ )
            {
                $records[long2ip($startingIP + $i)] = $userPrefix . $i;
            }



            PH::print_stdout( " - now sending records to API ... ");
            $this->pan->connector->userIDLogin(array_keys($records), $records, $this->location);


        }
        else
            derr("action '{$action}' is not supported");
    }

    public function supportedArguments()
    {
        $this->supportedArguments[] = array('niceName' => 'Actions', 'shortHelp' => 'type of action you want to perform against API', 'argDesc' => 'display|register|unregister|fakeregister|unregister-all');
        $this->supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'the target PANOS device ie: in=api://1.2.3.4', 'argDesc' => 'api://[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'defines the VSYS target of the UserID request', 'argDesc' => 'vsys1[,vsys2,...]');
        $this->supportedArguments[] = array('niceName' => 'records', 'shortHelp' => 'list of userid records to register/unregister in API', 'argDesc' => '10.0.0.1,domain\user2/10.2.3.4,domain\user3');
        $this->supportedArguments[] = array('niceName' => 'recordFile', 'shortHelp' => 'use a text file rather than CLI to input UserID records', 'argDesc' => 'users.txt');
        $this->supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
    }

}