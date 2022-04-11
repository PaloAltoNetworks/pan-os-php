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



RoutingCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( RoutingCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        $text = "";
        foreach( $object->staticRoutes() as $staticRoute )
        {
            $text .= "       - NAME: " . str_pad($staticRoute->name(), 20);
            PH::$JSON_TMP['sub']['object'][$object->name()]['staticroute'][$staticRoute->name()]['name'] = $staticRoute->name();

            $text .= " - DEST: " . str_pad($staticRoute->destination(), 20);
            PH::$JSON_TMP['sub']['object'][$object->name()]['staticroute'][$staticRoute->name()]['destination'] = $staticRoute->destination();

            if( $staticRoute->nexthopIP() !== null )
            {
                $text .= " - NEXTHOP: " . str_pad($staticRoute->nexthopIP(), 20);
                PH::$JSON_TMP['sub']['object'][$object->name()]['staticroute'][$staticRoute->name()]['nexthop'] = $staticRoute->nexthopIP();
            }

            if( $staticRoute->nexthopInterface() != null )
            {
                $text .= "\n           - NEXT INTERFACE: " . str_pad($staticRoute->nexthopInterface()->toString(), 20);
                PH::$JSON_TMP['sub']['object'][$object->name()]['staticroute'][$staticRoute->name()]['nexthopinterface'] = $staticRoute->nexthopInterface()->name();
            }

            PH::print_stdout( $text );
        }

        PH::print_stdout();
        PH::print_stdout( "- - - - - - - - - - - - - - - -" );
        PH::print_stdout();
        PH::print_stdout();
    },

    //Todo: display routes to zone / Interface IP
);

