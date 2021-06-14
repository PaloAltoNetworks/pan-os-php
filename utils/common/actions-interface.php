<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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
        print "     * ".get_class($object)." '{$object->name()}'  \n";

        //Todo: optimization needed, same process as for other utiles

        print "       - " . $object->type . " - ";
        if( $object->type == "layer3" || $object->type == "virtual-wire" || $object->type == "layer2" )
        {
            if( $object->isSubInterface() )
                print "subinterface - ";
            else
                print "count subinterface: " . $object->countSubInterfaces() . " - ";
        }
        elseif( $object->type == "aggregate-group" )
        {
            print "".$object->ae()." - ";
        }


        if( $object->type == "layer3" )
        {
            print "ip-addresse(s): ";
            foreach( $object->getLayer3IPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                    print $ip_address . ",";
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #print $ip_address." ({$object->value()}) ,";
                }
            }
        }
        elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
        {
            print ", ip-addresse(s): ";
            foreach( $object->getIPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                    print $ip_address . ",";
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #print $ip_address." ({$object->value()}) ,";
                }
            }
        }
        elseif( $object->type == "auto-key" )
        {
            print " - IPsec config";
            print " - IKE gateway: " . $object->gateway;
            print " - interface: " . $object->interface;
        }

        print "\n";

    },
);
