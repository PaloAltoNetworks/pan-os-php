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

$JSON_filename = dirname(__FILE__)."/service_predefined.json";
$JSON_string = file_get_contents($JSON_filename);

$someArray = json_decode($JSON_string, TRUE);

$vendor_array = array( 'cisco', 'fortinet', 'huawei', 'screenos', 'junos', 'stonesoft' );
foreach( $vendor_array as $vendor )
{
    print "\n\n".$vendor."\n";
    $tmp_services = $someArray['service_predefined'][$vendor];



    $name_array = array();
    foreach( $tmp_services as $service )
    {
        if( !isset( $name_array[ $service['name'] ] ) )
            $name_array[ $service['name'] ] = $service;
        else
        {
            if( !isset( $name_array[ $service['name'] ][0] ) )
            {
                $tmp = $name_array[ $service['name'] ];
                $name_array[ $service['name'] ] = array();
                $name_array[ $service['name'] ][] = $tmp;
            }

            $name_array[ $service['name'] ][] = $service;

            print_r( $name_array[ $service['name'] ] );
        }
    }
}




