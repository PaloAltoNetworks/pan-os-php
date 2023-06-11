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



DHCPCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( DHCPCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        PH::print_stdout("       RESERVATION:" );

        foreach( $object->server_leases as $lease )
        {
            #PH::print_stdout("       - "."IP: ".$lease['ip']." | mac: ".$lease['mac']);
            PH::print_stdout("       - "."".$lease['ip']." | ".$lease['mac']);
            PH::$JSON_TMP['sub']['object'][$object->name()]['server']['reserved'][] = $lease;
        }
    },

    //Todo: display routes to zone / Interface IP
);

DHCPCallContext::$supportedActions['dhcp-server-reservation-create'] = Array(
    'name' => 'dhcp-server-reservation',
    'MainFunction' => function ( DHCPCallContext $context )
    {
        $object = $context->object;

        $xpath = $object->getXPath()."/server/reserved";

        $tmp_ip = $context->arguments['ip'];
        $tmp_mac = $context->arguments['mac'];
        $tmp_mac = str_replace("$$", ":", $tmp_mac);

        $tmp_array = array();
        $tmp_array[] = array("ip"=> $tmp_ip, "mac"=> $tmp_mac);

        $element = "";
        foreach( $tmp_array as $entry)
        {
            $ip = $entry['ip'];
            $mac = $entry['mac'];


            if( $context->isAPI )
            {
                $element .= "<entry name='".$ip."'><mac>".$mac."</mac></entry>";
            }
            else
            {
                $tmp_server_xml = DH::findFirstElementOrCreate( 'server', $object->xmlroot );
                $tmp_reserved_xml = DH::findFirstElementOrCreate( 'reserved', $tmp_server_xml );
                $tmp_entry_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $ip, $tmp_reserved_xml, $object->xmlroot->ownerDocument);
                $tmp_mac_xml = DH::createElement( $tmp_entry_xml, "mac" );
                $tmp_mac_xml->textContent = $mac;
            }
        }

        if( $context->isAPI )
        {
            $con = findConnectorOrDie($object);
            $con->sendSetRequest($xpath, $element);
        }
    },
    'args' => array(
        'ip' => array('type' => 'string', 'default' => 'false'),
        'mac' => array('type' => 'string', 'default' => 'false'),
    ),
);
