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

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../utils/lib/UTIL.php";



$util = new UTIL("custom", $argv, $argc, __FILE__);


$array = array( 'address', 'service', 'tag', 'rule', 'zone', 'securityprofile', 'schedule','virtualwire','routing','interface','device', 'securityprofilegroup', 'application', 'threat');



foreach( $array as $entry )
{
    $util->utilType = $entry;
    $tmp_array[ $entry ]['action'] = $util ->supportedActions();

    $filter_array = RQuery::$defaultFilters[$util->utilType];
    ksort( $filter_array );
    $tmp_array[ $entry ]['filter'] = $filter_array;
}


$JSON_pretty =  json_encode( $tmp_array, JSON_PRETTY_PRINT );

print $JSON_pretty;

file_put_contents(__DIR__ . "/lib/"."util_action_filter.json", $JSON_pretty);