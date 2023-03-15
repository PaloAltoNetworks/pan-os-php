<?php


class CUSTOMREPORT extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {

        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['report-file'] = Array('niceName' => 'report-file', 'shortHelp' => 'file which containers custom report information');
        $this->supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');

        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api://192.168.55.100 location=shared [Actions=display] ['Filter=(subtype eq pppoe)'] ...";


        $this->prepareSupportedArgumentsArray();


        $this->utilInit();


        $this->main();


        
    }

    public function main()
    {

        #$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
        #$util->utilInit();
#$util->load_config();

        #if( !$this->pan->isFirewall() )
        #    derr( "only PAN-OS FW is supported" );

#if( !$util->apiMode && !$offline_config_test )
        if( !$this->apiMode )
            derr( "only PAN-OS API connection is supported" );

        $inputConnector = $this->pan->connector;

########################################################################################################################

        if( isset(PH::$args['report-file'])  )
            $file = PH::$args['report-file'];
        else
            derr( "argument file not set" );

        $req = file_get_contents( $file );

########################################################################################################################

        $inputConnector->refreshSystemInfos();
        $inputConnector->setShowApiCalls( $this->debugAPI );

        //&type=report&reporttype=dynamic&reportname=custom-dynamic-report&async=yes

        $apiArgs = Array();
        $apiArgs['type'] = 'report';
        $apiArgs['reporttype'] = 'dynamic';
        $apiArgs['reportname'] = 'custom-dynamic-report';
        $apiArgs['async'] = 'yes';
        $apiArgs['cmd'] = $req;

        $output = $inputConnector->getReport( $apiArgs );



        if( !empty($output) )
        {
            foreach( $output as $log )
            {
                PH::print_stdout(  " - ".http_build_query($log,'',' | ') );
                PH::print_stdout();

                PH::$JSON_OUT['traffic-log'][] = $log;
            }
        }
        else
        {
            PH::print_stdout( "nothing found" );
            PH::print_stdout();

            PH::$JSON_OUT['traffic-log'] = array();
        }

        PH::print_stdout( "##########################################" );
        PH::print_stdout();
    }

}