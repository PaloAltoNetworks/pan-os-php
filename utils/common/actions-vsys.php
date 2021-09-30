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

VsysCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (VsysCallContext $context) {
        $context->interface_wo_vsys = array();
    },
    'MainFunction' => function (VsysCallContext $context) {
        $object = $context->object;
        $text = "     * " . get_class($object) . " '{$object->name()}'";
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        foreach( $object->importedInterfaces as $interfacecontainer )
        {
            if( is_a($interfacecontainer, 'NetworkPropertiesContainer') )
            {
                foreach( $interfacecontainer->getAllInterfaces() as $interface )
                {
                    $tmp_vsys = $interfacecontainer->findVsysInterfaceOwner($interface->name());
                    if( $tmp_vsys != null )
                    {
                        if( $tmp_vsys->name() == $object->name() )
                        {
                            $text .= "       - " . $interface->type . " - ";
                            if( $interface->type == "layer3" )
                            {
                                if( $interface->isSubInterface() )
                                    $text .= "subinterface - ";
                                else
                                    $text .= "count subinterface: " . $interface->countSubInterfaces() . " - ";
                            }
                            elseif( $interface->type == "aggregate-group" )
                            {
                                #$interface->
                            }

                            $text .= $interface->name() . ", ip-addresse(s): ";
                            if( $interface->type == "layer3" )
                            {
                                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                                    $text .= $ip_address . ",";
                            }
                            elseif( $interface->type == "tunnel" )
                            {
                                foreach( $interface->getIPv4Addresses() as $ip_address )
                                    $text .= $ip_address . ",";
                            }
                        }
                    }
                    else
                        $context->interface_wo_vsys[$interface->name()] = $interface;
                }
            }
        }

        PH::print_stdout( $text );
        PH::print_stdout( "" );
    },
    'GlobalFinishFunction' => function (VsysCallContext $context) {
        PH::print_stdout( PH::boldText("\n\nall interfaces NOT attached to an vsys:") );

        foreach( $context->interface_wo_vsys as $interface )
        {
            $text = "  - " . $interface->type . " - ";
            if( $interface->type == "layer3" )
            {
                if( $interface->isSubInterface() )
                    $text .= "subinterface - ";
                else
                    $text .= "count subinterface: " . $interface->countSubInterfaces() . " - ";
            }
            elseif( $interface->type == "aggregate-group" )
            {
                #$interface->
            }

            $text .= $interface->name() . ", ip-address(es): ";
            if( $interface->type == "layer3" )
            {
                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                    $text .= $ip_address . ",";
            }
            elseif( $interface->type == "tunnel" )
            {
                foreach( $interface->getIPv4Addresses() as $ip_address )
                    $text .= $ip_address . ",";
            }

            PH::print_stdout( $text );
            PH::print_stdout( "" );
        }
    },
);