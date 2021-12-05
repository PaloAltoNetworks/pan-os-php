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

VirtualWireCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( VirtualWireCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );

        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
        PH::$JSON_TMP['sub']['object'][$object->name()]['interface1'] = $object->attachedInterface1;
        PH::$JSON_TMP['sub']['object'][$object->name()]['interface2'] = $object->attachedInterface2;

        $text = "       - ";
        $text .= "interface1: ".$object->attachedInterface1." - ";
        $text .= "interface2: ".$object->attachedInterface2;
        PH::print_stdout( $text );

        PH::print_stdout( "" );
    },

);