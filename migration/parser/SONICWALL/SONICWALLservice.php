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

trait SONICWALLservice
{

#print_r( $address );
#print_r( $services );

    function add_service( $service)
    {
        global $debug;
        global $print;

        $padding = "   ";
        $padding_name = substr($padding, 0, -1);

        foreach( $service as $key => $service_entry )
        {


            $service_entry = $this->strip_hidden_chars($service_entry);
            $orig_service_entry = $service_entry;

            $service_entry = preg_replace('#^"#m', "", $service_entry);

            $service_entry = explode('"', $service_entry);
            if( count($service_entry) == 1 )
            {
                $service_entry = explode(' ', $service_entry[0]);
                $name = $service_entry[0];
            }
            else
            {
                $name = $service_entry[0];
                $service_entry2 = explode(' ', trim($service_entry[1]));
                unset($service_entry[1]);
                foreach( $service_entry2 as $service2 )
                {
                    $service_entry[] = $service2;
                }
                $service_entry = array_values($service_entry);
            }


            $name = $this->truncate_names($this->normalizeNames($name));
            $tmp_service = $this->sub->serviceStore->find($name);
            if( $tmp_service == null )
            {
                $protocol = strtolower($service_entry[1]);
                if( $protocol == "tcp" || $protocol == "udp" )
                {
                    if( $service_entry[2] == $service_entry[3] )
                        $port = $service_entry[2];
                    else
                        $port = $service_entry[2] . "-" . $service_entry[3];

                    if( $print )
                        print $padding_name . "* name: '" . $name . "' protocol: '" . $protocol . "' port: '" . $port . "'\n";
                    $tmp_service = $this->sub->serviceStore->newService($name, $protocol, $port);
                }
                else
                    if( $debug )
                    {
                        print $padding_name . "X check service: " . $orig_service_entry . " | service created: TMP_" . $name . "\n";
                        $tmp_service = $this->sub->serviceStore->newService("TMP_" . $name, "tcp", "65000");
                        $tmp_service->set_node_attribute('error', $orig_service_entry);
                        #print_r( $service_entry );
                    }

            }
        }
    }

}
