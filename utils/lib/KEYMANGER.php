<?php


class KEYMANGER extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " [delete=hostOrIP] [add=hostOrIP] [test=hostOrIP] [hiddenPW]";

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();

        $this->arg_validation();


        $this->mainKEY();


        $this->endOfScript();
    }

    public function mainKEY()
    {

        $noArgProvided = TRUE;

        if( isset(PH::$args['nohiddenpw']) )
            $hiddenPW = FALSE;
        else
            $hiddenPW = TRUE;

        if( isset(PH::$args['debugapi']) )
            $debugAPI = TRUE;
        else
            $debugAPI = FALSE;

        if( isset(PH::$args['user']) )
            $cliUSER = PH::$args['user'];
        else
            $cliUSER = null;

        if( isset(PH::$args['pw']) )
            $cliPW = PH::$args['pw'];
        else
            $cliPW = null;


        PH::print_stdout( " - loading keystore from file in user home directory... ");
        PanAPIConnector::loadConnectorsFromUserHome( $debugAPI);


        PH::print_stdout("");


        if( isset(PH::$args['delete']) )
        {
            $noArgProvided = FALSE;
            $deleteHost = PH::$args['delete'];
            PH::print_stdout( " - requested to delete Host/IP '{$deleteHost}'");
            if( !is_string($deleteHost) )
                derr("argument of 'delete' must be a string , wrong input provided");

            $foundConnector = FALSE;
            foreach( PanAPIConnector::$savedConnectors as $cIndex => $connector )
            {
                if( $connector->apihost == $deleteHost )
                {
                    $foundConnector = TRUE;
                    PH::print_stdout( " - found and deleted" );
                    unset(PanAPIConnector::$savedConnectors[$cIndex]);
                    PanAPIConnector::saveConnectorsToUserHome();
                }
            }
            if( !$foundConnector )
                PH::print_stdout( "\n\n **WARNING** no host or IP named '{$deleteHost}' was found so it could not be deleted" );
        }

        if( isset(PH::$args['add']) )
        {
            $noArgProvided = FALSE;
            $addHost = PH::$args['add'];
            PH::print_stdout( " - requested to add Host/IP '{$addHost}'");

            if( !isset(PH::$args['apikey']) )
                $connector = PanAPIConnector::findOrCreateConnectorFromHost($addHost, null, TRUE, TRUE, $hiddenPW, $debugAPI, $cliUSER, $cliPW);
            else
                $connector = PanAPIConnector::findOrCreateConnectorFromHost($addHost, PH::$args['apikey']);
        }

        if( isset(PH::$args['test']) )
        {
            $noArgProvided = FALSE;
            $checkHost = PH::$args['test'];

            if( $checkHost == 'any' || $checkHost == 'all' )
            {
                foreach( PanAPIConnector::$savedConnectors as $connector )
                {
                    $checkHost = $connector->apihost;
                    PH::print_stdout( " - requested to test Host/IP '{$checkHost}'");

                    PH::enableExceptionSupport();
                    try
                    {
                        if( !isset(PH::$args['apikey']) )
                            $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, null, TRUE, TRUE, $hiddenPW, $debugAPI , $cliUSER, $cliPW);
                        else
                            $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, PH::$args['apikey'], TRUE, TRUE, TRUE, $debugAPI);

                        if( $debugAPI )
                            $connector->showApiCalls = true;

                        $connector->testConnectivity();
                    } catch(Exception $e)
                    {
                        PH::disableExceptionSupport();
                        PH::print_stdout( "   ***** API Error occured : " . $e->getMessage() );
                    }

                    PH::disableExceptionSupport();
                    PH::print_stdout("");
                }
            }
            else
            {
                PH::print_stdout( " - requested to test Host/IP '{$checkHost}'");
                if( !isset(PH::$args['apikey']) )
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, null, TRUE, TRUE, $hiddenPW, $debugAPI, $cliUSER, $cliPW);
                else
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, PH::$args['apikey'], TRUE, TRUE, TRUE, $debugAPI);

                if( $debugAPI )
                    $connector->showApiCalls = true;

                $connector->testConnectivity();

                PH::print_stdout("");
            }
        }

        $keyCount = count(PanAPIConnector::$savedConnectors);
        PH::print_stdout( "Listing available keys:");

        $connectorList = array();
        foreach( PanAPIConnector::$savedConnectors as $connector )
        {
            $connectorList[$connector->apihost] = $connector;
        }
        ksort($connectorList);

        foreach( $connectorList as $connector )
        {
            $key = $connector->apikey;
            if( strlen($key) > 24 )
                $key = substr($key, 0, 12) . '...' . substr($key, strlen($key) - 12);
            $host = str_pad($connector->apihost, 15, ' ', STR_PAD_RIGHT);

            PH::print_stdout( " - Host {$host}: key={$key}");
        }

        if( $noArgProvided )
        {
            PH::print_stdout("");
            $this->display_usage_and_exit();
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments[] = array('niceName' => 'delete', 'shortHelp' => 'Clears API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'add', 'shortHelp' => 'Adds API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'test', 'shortHelp' => 'Tests API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'apikey', 'shortHelp' => 'can be used in combination with add argument to use specific API key provided as an argument.', 'argDesc' => '[API Key]');
        $this->supportedArguments[] = array('niceName' => 'nohiddenpw', 'shortHelp' => 'Use this if the entered password should be displayed.');
        $this->supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments[] = array('niceName' => 'user', 'shortHelp' => 'can be used in combination with "add" argument to use specific Username provided as an argument.', 'argDesc' => '[USERNAME]');
        $this->supportedArguments[] = array('niceName' => 'pw', 'shortHelp' => 'can be used in combination with "add" argument to use specific Password provided as an argument.', 'argDesc' => '[PASSWORD]');
        $this->supportedArguments[] = array('niceName' => 'shadow-apikeynohidden', 'shortHelp' => 'send API-KEY in clear text via URL. this is needed for all PAN-OS version <9.0 if API mode is used. ');
    }

}