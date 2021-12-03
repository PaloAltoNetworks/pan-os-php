<?php
/**
 * ISC License
 *
  * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

InterfaceCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( InterfaceCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        //Todo: optimization needed, same process as for other utiles

        $text = "       - " . $object->type . " - ";

        if( $object->type == "layer3" || $object->type == "virtual-wire" || $object->type == "layer2" )
        {
            if( $object->isSubInterface() )
            {
                $text .= "subinterface - ";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterface'] = "yes";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterfacecount'] = "0";
            }

            else
            {
                $text .= "count subinterface: " . $object->countSubInterfaces() . " - ";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterface'] = "false";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterfacecount'] = $object->countSubInterfaces();
            }

        }
        elseif( $object->type == "aggregate-group" )
        {
            $text .= "".$object->ae()." - ";
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ae'] = $object->ae();
        }


        if( $object->type == "layer3" )
        {
            $text .= "ip-addresse(s): ";
            foreach( $object->getLayer3IPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }

                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout( $ip_address." ({$object->value()}) ,");
                }
            }
        }
        elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
        {
            $text .= ", ip-addresse(s): ";
            foreach( $object->getIPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }

                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout($text); $ip_address." ({$object->value()}) ,");
                }
            }
        }
        elseif( $object->type == "auto-key" )
        {
            $text .= " - IPsec config";
            $text .= " - IKE gateway: " . $object->gateway;
            $text .= " - interface: " . $object->interface;
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ike']['gw'] = $object->gateway;
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ike']['interface'] = $object->interface;
        }

        PH::print_stdout( $text );

    },
);
