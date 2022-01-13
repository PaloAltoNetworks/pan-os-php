<?php


class SYSTEMLOG extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'vsys1|shared|dg1');
        $this->supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters logs based on a query. ie: 'filter=( (subtype eq auth) and ( receive_time geq !TIME! ) )'", 'argDesc' => '(field operator value)');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['stats'] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
        $this->supportedArguments['hours'] = Array('niceName' => 'Hours', 'shortHelp' => 'display log for the last few hours');
        $this->supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');

        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api://192.168.55.100 location=shared [Actions=display] ['Filter=(subtype eq pppoe)'] ...";


        $this->prepareSupportedArgumentsArray();


        $this->utilInit();


        $this->main();


        $this->endOfScript();
    }

    public function main()
    {

        if( !$this->pan->isFirewall() )
            derr( "only PAN-OS FW is supported" );

#if( !$util->apiMode && !$offline_config_test )
        if( !$this->apiMode )
            derr( "only PAN-OS API connection is supported" );

        $inputConnector = $this->pan->connector;

########################################################################################################################

        if( isset(PH::$args['hours']) )
            $hours = PH::$args['hours'];
        else
            $hours = 0.25;
        PH::print_stdout( " - argument 'hours' set to '{$hours}'" );

        date_default_timezone_set("Europe/Berlin");
        $time = time() - ($hours * 3600);
        $time = date('Y/m/d H:i:s', $time);


        if( isset(PH::$args['filter']) )
        {
            $query = "(".PH::$args['filter'].")";
            $query = str_replace( "!TIME!", "'".$time."'", $query );
        }
        else
        {
            $query = '';
        }


########################################################################################################################

        $inputConnector->refreshSystemInfos();
        $inputConnector->setShowApiCalls( $this->debugAPI );


        $apiArgs = Array();
        $apiArgs['type'] = 'log';
        $apiArgs['log-type'] = 'system';
        $apiArgs['query'] = $query;


        $output = $inputConnector->getLog($apiArgs);


        PH::print_stdout( "" );
        PH::print_stdout( "##########################################" );
        PH::print_stdout( "system log filter: '".$query."'" );
        PH::print_stdout( "" );

        if( !empty($output) )
        {
            /*
            PH::print_stdout( "PPPoE was successfully established during the last ".$hours."h:" );
            PH::print_stdout( "" );
            */

            foreach( $output as $log )
            {
                /*
                $opaque = explode(',', $log['opaque']);
                $ipaddress = explode(':', $opaque[3]);

                PH::print_stdout( "time: " . $log['receive_time'] . " - ipaddress: " . $ipaddress[1] );
                */
                #print_r( $log );
                PH::print_stdout(  " - ".http_build_query($log,'',' | ') );
                PH::print_stdout( "" );
                PH::$JSON_OUT['system-log'][] = $log;
            }
        }
        else
        {
            PH::print_stdout( "nothing found" );
            PH::print_stdout( "" );
            PH::$JSON_OUT['system-log'] = array();
        }

        PH::print_stdout( "##########################################" );
        PH::print_stdout( "" );
    }

}