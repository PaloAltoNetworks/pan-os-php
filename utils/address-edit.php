<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

#require_once("lib/autoloader.php");
#spl_autoload_register('myAutoloader');

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

require_once dirname(__FILE__)."/../utils/lib/UTIL.php";

if( !PH::$shadow_json )
{
    echo "\n***********************************************\n";
    echo "*********** ADDRESS-EDIT UTILITY **************\n\n";
}

$util = new UTIL("address", $argv, __FILE__);

if( !PH::$shadow_json )
{
    echo "\n\n********** END OF ADDRESS-EDIT UTILITY ***********\n";
    echo "**************************************************\n";
    echo "\n\n";
}
