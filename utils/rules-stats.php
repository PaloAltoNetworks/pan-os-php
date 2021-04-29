<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

//------------------------------------------------------------------------------------------------------

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

//------------------------------------------------------------------------------------------------------

if( !PH::$shadow_json )
{
    print "\n\n";
    print "************************************************\n";
    print "************ RULE-STATS UTILITY ****************\n";
    print "\n\n";
}

$util = new STATSUTIL( "stats", $argv, __FILE__);

//------------------------------------------------------------------------------------------------------

if( !PH::$shadow_json )
{
    print "\n";
    print "************ END OF RULE-STATS UTILITY ************\n";
    print "***************************************************\n";
    print "\n\n";
}




