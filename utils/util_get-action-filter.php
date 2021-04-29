<?php

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");



$util = new UTIL("custom", $argv, __FILE__);


$array = array( 'address', 'service', 'tag', 'rule', 'zone', 'securityprofile');

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