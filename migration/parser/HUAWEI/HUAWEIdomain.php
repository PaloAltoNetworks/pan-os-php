<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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


trait HUAWEIdomain
{
    #print_r( $address );
    #print_r( $services );

    function add_domain( $domain)
    {
        global $debug;
        global $print;

        $padding = "   ";
        $padding_name = substr($padding, 0, -1);

        $domain_lines = explode( "\n", $domain );

        #print_r( $domain_lines );



        #print_r( $address );
        //working

        $tmp_custome_url_profile = null;
        foreach( $domain_lines as $key => $line )
        {
            $line = trim( $line );
            $line_array = explode( " ", $line);


            if( $line_array[0] == "domain-set" )
            {
                $name = $line_array[2];
                if( strpos( $name, '"' ) !== false )
                {
                    $i = 3;
                    do
                    {
                        if( isset($line_array[$i]) )
                        {
                            $name .= " ".$line_array[$i]." ";
                        }
                        $i++;
                    } while( $i < count($line_array) + 1 );
                    $name = str_replace( '"', '', $name );
                }
                $name = trim( $name );

                if( $print )
                    print $padding." * create custom URL profile: ".$name."\n";

                $tmp_custome_url_profile = $this->sub->customURLProfileStore->newCustomSecurityProfileURL( $name );


            }
            elseif( $line_array[0] == "add" && $line_array[1] == "domain" )
            {
                if( $print )
                    print $padding."     add custom URL: |".$line_array[2]."|\n";

                $chars = array("[", "]");
                $custom_url = str_replace( $chars, "", $line_array[2] );

                if( $tmp_custome_url_profile != null )
                    $tmp_custome_url_profile->addMember( $line_array[2] );
            }

        }
    }
}

