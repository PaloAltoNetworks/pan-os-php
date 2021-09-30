<?php

class STATSUTIL extends RULEUTIL
{
    function __construct($utilType, $argv, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "")
    {
        $_usageMsg =  PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] [location=vsys2]";;
        parent::__construct($utilType, $argv, $PHP_FILE, $_supportedArguments, $_usageMsg);
    }

    public function utilStart()
    {

        $this->utilInit();
        //unique for RULEUTIL
        $this->ruleTypes();

        //no need to do actions on every single rule
        $this->doActions = array();

        $this->createRQuery();
        $this->load_config();
        $this->location_filter();


        $this->location_filter_object();
        $this->time_to_process_objects();




        PH::$args['stats'] = "stats";
        $this->stats();

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }

    /*
    public function supportedArguments()
    {
        parent::supportedArguments();
    }
    */
}