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

class PROTOCOLL_NUMBERS__
{
    function __construct( )
    {
        self::main();
    }

    public function main()
    {
        $download_successfull = false;

        $arrContextOptions=array(
            "ssl"=>array(
                "verify_peer"=>false,
                "verify_peer_name"=>false,
            ),
            "http" => array(
                "header" => "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
            ),
        );

        // Initialize a file URL to the variable
        $url = "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv";

        $predefined_path = __DIR__ . '/../../lib/resources/ip_protocol/';

        // Use basename() function to return the base name of file
        $file_name = $predefined_path.basename($url);

        try
        {
            //cert check fail if SSL interception is done
            if( file_put_contents( $file_name,file_get_contents($url, false, stream_context_create($arrContextOptions))) )
            {
                print "File downloaded successfully\n";
                $download_successfull = true;
            }
            else
            {
                print "File downloading failed.\n";
            }
        }
        catch(Exception $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout(" ***** an error occured : " . $e->getMessage());
        }

        if( $download_successfull )
        {
            //read CSV file
            //create JSON file
        }



        $url = "https://gist.githubusercontent.com/SamSamskies/ff6571bf1d72c310d98b83ca3d3c502e/raw/d6e66ba112269af01db21c762a4509ba7eda97fa/ip-protocol-numbers.json";

        // Use basename() function to return the base name of file
        $file_name = $predefined_path.basename($url);


        if( file_put_contents( $file_name,file_get_contents($url, false, stream_context_create($arrContextOptions))) )
        {
            print "File downloaded successfully\n";
            $download_successfull = true;
        }
        else
        {
            print "File downloading failed.\n";
        }
    }

    function endOfScript()
    {
    }

}