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

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");


$supportedArguments = array();
$supportedArguments[] = array('niceName' => 'delete', 'shortHelp' => 'Clears API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = array('niceName' => 'add', 'shortHelp' => 'Adds API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = array('niceName' => 'test', 'shortHelp' => 'Tests API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = array('niceName' => 'apikey', 'shortHelp' => 'can be used in combination with add argument to use specific API key provided as an argument.', 'argDesc' => '[API Key]');
$supportedArguments[] = array('niceName' => 'nohiddenpw', 'shortHelp' => 'Use this if the entered password should be displayed.');
$supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments[] = array('niceName' => 'user', 'shortHelp' => 'can be used in combination with "add" argument to use specific Username provided as an argument.', 'argDesc' => '[USERNAME]');
$supportedArguments[] = array('niceName' => 'pw', 'shortHelp' => 'can be used in combination with "add" argument to use specific Password provided as an argument.', 'argDesc' => '[PASSWORD]');
$supportedArguments['shadow-apikeynohidden'] = array('niceName' => 'shadow-apikeynohidden', 'shortHelp' => 'send API-KEY in clear text via URL. this is needed for all PAN-OS version <9.0 if API mode is used. ');

$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " [delete=hostOrIP] [add=hostOrIP] [test=hostOrIP] [hiddenPW]";

$util = new KEYMANGER( "key-manager", $argv, __FILE__, $supportedArguments, $usageMsg);

PH::print_stdout("");
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout("");

