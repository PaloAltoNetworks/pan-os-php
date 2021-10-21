<?php


class RUNSSH
{
    function __construct( $ip, $user, $password, $commands, &$output_string )
    {
        PH::print_stdout("");

        $ssh = new Net_SSH2($ip);

        PH::enableExceptionSupport();
        PH::print_stdout( " - connect to " . $ip . "...");
        try
        {
            if( !$ssh->login($user, $password) )
            {
                PH::print_stdout( "Login Failed");
                #PH::print_stdout( $ssh->getLog() );
                exit('END');
            }
        } catch(Exception $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
            return;
        }
        PH::disableExceptionSupport();

        $ssh->read();

        ############################################

        end($commands);
        //fetch key of the last element of the array.
        $lastElementKey = key($commands);

        foreach( $commands as $k => $command )
        {
            PH::print_stdout(  strtoupper($command) . ":");
            $ssh->write($command . "\n");

            $tmp_string = $ssh->read();
            PH::print_stdout( $tmp_string );


            $output_string .= $tmp_string;
        }


        if( isset(PH::$args['debugapi']) )
        {
            PH::print_stdout( "LOG:" );
            PH::print_stdout( $ssh->getLog() );
        }


        PH::print_stdout("");
    }
}