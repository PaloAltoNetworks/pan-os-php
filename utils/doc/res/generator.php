<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

echo "\n***********************************************\n";
echo "************ DOC GENERATOR  **************\n\n";

require_once("../../../lib/pan_php_framework.php");
require_once("../../common/actions.php");

$dataFile = __DIR__ . '/data.js';

function &generateActionJSON(&$actions)
{

    $result = array();
    foreach( $actions as $action )
    {
        $record = array('name' => $action['name'], 'help' => null, 'args' => FALSE);

        if( isset($action['help']) )
            $record['help'] = str_replace(array("\n", ' '),
                array("<br>", '&nbsp'),
                $action['help']);

        if( isset($action['args']) && $action['args'] !== FALSE )
        {
            $record['args'] = array();
            foreach( $action['args'] as $argName => $arg )
            {
                $tmpArr = $arg;
                if( isset($arg['help']) )
                    $arg['help'] = str_replace(array("\n", ' '),
                        array("<br>", '&nbsp'),
                        $arg['help']);
                $tmpArr['name'] = $argName;
                $record['args'][] = $tmpArr;
            }
        }

        $result[] = $record;
    }

    return $result;
}

$actionsData = array();
$actionsData['rule'] = generateActionJSON(RuleCallContext::$supportedActions);
$actionsData['address'] = generateActionJSON(AddressCallContext::$supportedActions);
$actionsData['service'] = generateActionJSON(ServiceCallContext::$supportedActions);
$actionsData['tag'] = generateActionJSON(TagCallContext::$supportedActions);

function &generateFilterJSON($filters)
{
    $result = array();

    ksort($filters);

    foreach( $filters as $name => $filter )
    {
        $record = array('name' => $name, 'help' => null, 'operators' => array());
        ksort($filter['operators']);

        foreach( $filter['operators'] as $opName => $opDetails )
        {
            $opRecord = array('name' => $opName, 'help' => null, 'argument' => null);

            if( isset($opDetails['arg']) && $opDetails['arg'] === TRUE )
                $opRecord['argument'] = '*required*';

            if( isset($opDetails['help']) )
                $opRecord['help'] = $opDetails['help'];

            $record['operators'][] = $opRecord;
        }

        $result[] = $record;
    }

    return $result;
}

$filtersData = array();
$filtersData['rule'] = generateFilterJSON(RQuery::$defaultFilters['rule']);
$filtersData['address'] = generateFilterJSON(RQuery::$defaultFilters['address']);
$filtersData['service'] = generateFilterJSON(RQuery::$defaultFilters['service']);
$filtersData['tag'] = generateFilterJSON(RQuery::$defaultFilters['tag']);


$data = array('actions' => &$actionsData, 'filters' => &$filtersData);

$data = 'var data = ' . json_encode($data, JSON_PRETTY_PRINT) . ';';

file_put_contents($dataFile, $data);

echo "\nDOC GENERATED !!!\n\n";