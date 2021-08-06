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


ThreatCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ThreatCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);



ThreatCallContext::$supportedActions[] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (ThreatCallContext $context) {
        $context->counter_spyware = 0;
        $context->counter_vulnerability = 0;

    },
    'MainFunction' => function (ThreatCallContext $context) {
        $threat = $context->object;

        PH::print_stdout( $context->padding . "* " . get_class($threat) . " '{$threat->name()}' " );

        PH::print_stdout( "          - Threatname: '{$threat->threatname()}'  category: '{$threat->category()}' severity: '{$threat->severity()}'  default-action: '{$threat->defaultAction()}'" );

        if( $threat->type() == "vulnerability" )
            $context->counter_vulnerability++;
        elseif( $threat->type() == "spyware" )
            $context->counter_spyware++;

    },
    'GlobalFinishFunction' => function (ThreatCallContext $context) {
        print "spyware: ".$context->counter_spyware."\n";
        print "vulnerability: ".$context->counter_vulnerability."\n";
    }
);
