<?php


class UTIL_GET_ACTION_FILTER
{
    function __construct( $argv, $argc )
    {
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

        file_put_contents(__DIR__ . "/util_action_filter.json", $JSON_pretty);
    }
}