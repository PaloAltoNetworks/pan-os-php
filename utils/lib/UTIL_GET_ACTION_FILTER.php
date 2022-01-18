<?php
/**
 * ISC License
 *
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

class UTIL_GET_ACTION_FILTER
{
    function __construct( $argv, $argc )
    {
        $util = new UTIL("custom", $argv, $argc, __FILE__);


        //$array = array( 'address', 'service', 'tag', 'rule', 'zone', 'securityprofile', 'schedule','virtualwire','routing','interface','device', 'securityprofilegroup', 'application', 'threat');
        $array = PH::$supportedUTILTypes;


        foreach( $array as $entry )
        {
            $tmp_array[ $entry ]['name'] = $entry;

            $util->utilType = $entry;
            $tmp_array[ $entry ]['action'] = $util->supportedActions();

            if( isset(RQuery::$defaultFilters[$util->utilType]) )
            {
                $filter_array = RQuery::$defaultFilters[$util->utilType];
                ksort( $filter_array );
                $tmp_array[ $entry ]['filter'] = $filter_array;
            }
            else
                $tmp_array[ $entry ]['filter'] = array();

        }


        $JSON_pretty =  json_encode( $tmp_array, JSON_PRETTY_PRINT );

        print $JSON_pretty;

        $this->createJSONarrayFILE( $JSON_pretty);

        file_put_contents(__DIR__ . "/util_action_filter.json", $JSON_pretty);
    }

    function createJSONarrayFILE( $JSON_pretty )
    {
        $startString = "var subjectObject =
";
        $string = "

var additionalArguments = {
    \"location\": {
        \"arg\": {},
        \"help\": {}
    },
    \"stats\": {
        \"help\": {}
    },
    \"shadow-reduceXML\": {
        \"help\": {}
    },
    \"shadow-json\": {
        \"help\": {}
    },
    \"shadow-ignoreinvalidaddressobjects\": {
        \"help\": {}
    },
    \"shadow-enablexmlduplicatedeletion\": {
        \"help\": {}
    },
}

var migrationVendors = {
    \"ciscoasa\": {
        \"help\": {}
    },
    \"ciscoswitch\": {
        \"help\": {}
    },
    \"ciscoisr\": {
        \"help\": {}
    },
    \"netscreen\": {
        \"help\": {}
    },
    \"srx\": {
        \"help\": {}
    },
    \"stonesoft\": {
        \"help\": {}
    },
    \"cp\": {
        \"help\": {}
    },
    \"cp-r80\": {
        \"help\": {}
    },
    \"fortinet\": {
        \"help\": {}
    },
    \"huawei\": {
        \"help\": {}
    },
    \"sidewinder\": {
        \"help\": {}
    },
    \"sonicwall\": {
        \"help\": {}
    },
    \"sophos\": {
        \"help\": {}
    }
}";

        $finalString = $startString.$JSON_pretty.$string;
        file_put_contents(__DIR__ . "/../develop/ui/json_array.js", $finalString);
    }

    function endOfScript()
    {
    }
}