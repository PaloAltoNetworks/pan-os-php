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

class RUNSSH
{
    function __construct( $ip, $user, $password, $commands, &$output_string, $timeout = 10, $port = 22, $setcommandMaxLine = 20  )
    {
        PH::print_stdout("");

        $ssh = new Net_SSH2($ip, $port, $timeout);

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

        $configureFound = false;
        $combinedCommands = "";
        $write = false;
        foreach( $commands as $k => $command )
        {
            PH::print_stdout(  strtoupper($command) . ":");


            if( strpos( $command, "configure" ) !== FALSE )
            {
                $configureFound = true;
                $ssh->write($command . "\n");
                $configureCounter = 0;
            }


            if( $configureFound && $configureCounter != 0 )
            {
                $combinedCommands .= $command."\n";
                $configureCounter++;
                if( $configureCounter == $setcommandMaxLine )
                {
                    $configureCounter = 1;

                    $ssh->write( $combinedCommands );
                    $write = true;
                    $combinedCommands = "";
                }
            }
            elseif( $configureFound && $configureCounter == 0 )
            {
                $configureCounter++;
            }
            else
            {
                $ssh->write($command . "\n");
                $write = true;
            }


            //$ssh->write($command . "\n");

            if( $write )
            {
                sleep(1);
                $tmp_string = $ssh->read();
                PH::print_stdout( $tmp_string );

                $checkArray = array( 'Invalid syntax.' );
                foreach ($checkArray as $issue)
                {
                    if (strpos($tmp_string, $issue) !== FALSE)
                    {
                        $string = "this command was not correctly send: '".$command."'";
                        PH::print_stdout( $string );
                        derr( $string, null, false );
                    }
                }

                $warningArray = array( "Object doesn't exist" );
                foreach ($warningArray as $issue)
                {
                    if (strpos($tmp_string, $issue) !== FALSE)
                    {
                        $string = "this command was not correctly send: '".$command."'";
                        PH::print_stdout( $string );
                        mwarning( $string, null, false );
                    }
                }


                $output_string .= $tmp_string;
                $write = false;
            }

        }


        if( isset(PH::$args['debugapi']) )
        {
            PH::print_stdout( "LOG:" );
            PH::print_stdout( $ssh->getLog() );
        }


        PH::print_stdout("");
    }
}