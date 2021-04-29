<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

print "\n***********************************************\n";
print   "*********** SERVICE-EDIT UTILITY **************\n\n";


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

require_once dirname(__FILE__)."/../utils/lib/UTIL.php";


print "\n";

$util = new UTIL("service", $argv, __FILE__);


print "\n\n*********** END OF SERVICE-EDIT UTILITY **********\n";
print     "**************************************************\n";
print "\n\n";
