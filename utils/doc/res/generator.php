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


require_once("../../../lib/pan_php_framework.php");
require_once("../../common/actions.php");

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

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
$actionsData['zone'] = generateActionJSON(ZoneCallContext::$supportedActions);
$actionsData['securityprofile'] = generateActionJSON(SecurityProfileCallContext::$supportedActions);
$actionsData['securityprofilegroup'] = generateActionJSON(SecurityProfileGroupCallContext::$supportedActions);
$actionsData['device'] = generateActionJSON(DeviceCallContext::$supportedActions);
$actionsData['interface'] = generateActionJSON(InterfaceCallContext::$supportedActions);
$actionsData['routing'] = generateActionJSON(RoutingCallContext::$supportedActions);
$actionsData['virtualwire'] = generateActionJSON(VirtualWireCallContext::$supportedActions);
$actionsData['schedule'] = generateActionJSON(ScheduleCallContext::$supportedActions);


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
$filtersData['zone'] = generateFilterJSON(RQuery::$defaultFilters['zone']);
$filtersData['securityprofile'] = generateFilterJSON(RQuery::$defaultFilters['securityprofile']);
$filtersData['securityprofilegroup'] = generateFilterJSON(RQuery::$defaultFilters['securityprofilegroup']);
$filtersData['device'] = generateFilterJSON(RQuery::$defaultFilters['device']);
$filtersData['interface'] = generateFilterJSON(RQuery::$defaultFilters['interface']);
$filtersData['routing'] = generateFilterJSON(RQuery::$defaultFilters['routing']);
$filtersData['virtualwire'] = generateFilterJSON(RQuery::$defaultFilters['virtualwire']);
$filtersData['schedule'] = generateFilterJSON(RQuery::$defaultFilters['schedule']);


$data = array('actions' => &$actionsData, 'filters' => &$filtersData);

$data = 'var data = ' . json_encode($data, JSON_PRETTY_PRINT) . ';';

file_put_contents($dataFile, $data);

PH::print_stdout( "DOC GENERATED !!!" );