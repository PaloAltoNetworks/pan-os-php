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

echo "\n***********************************************\n";
echo "*********** " . basename(__FILE__) . " UTILITY **************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

require_once dirname(__FILE__)."/../utils/lib/UTIL.php";
require_once("utils/lib/MERGER.php");


$supportedArguments = array();
$supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => 'sub1[,sub2]');
$supportedArguments[] = array('niceName' => 'DupAlgorithm',
    'shortHelp' => "Specifies how to detect duplicates:\n" .
        "  - SameDstSrcPorts: objects with same Dst and Src ports will be replaced by the one picked (default)\n" .
        "  - SamePorts: objects with same Dst ports will be replaced by the one picked\n" .
        "  - WhereUsed: objects used exactly in the same location will be merged into 1 single object and all ports covered by these objects will be aggregated\n",
    'argDesc' => 'SameDstSrcPorts|SamePorts|WhereUsed');
$supportedArguments[] = array('niceName' => 'mergeCountLimit', 'shortHelp' => 'stop operations after X objects have been merged', 'argDesc' => '100');
$supportedArguments[] = array('niceName' => 'pickFilter',
    'shortHelp' => "specify a filter a pick which object will be kept while others will be replaced by this one.\n" .
        "   ie: 2 services are found to be mergeable: 'H-1.1.1.1' and 'Server-ABC'. Then by using pickFilter=(name regex /^H-/) you would ensure that object H-1.1.1.1 would remain and Server-ABC be replaced by it.",
    'argDesc' => '(name regex /^g/)');
$supportedArguments[] = array('niceName' => 'excludeFilter', 'shortHelp' => 'specify a filter to exclude objects from merging process entirely', 'argDesc' => '(name regex /^g/)');
$supportedArguments[] = array('niceName' => 'allowMergingWithUpperLevel', 'shortHelp' => 'when this argument is specified, it instructs the script to also look for duplicates in upper level');
$supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');

$usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml [out=outputfile.xml] location=shared [dupAlgorithm=XYZ] [MergeCountLimit=100] ['pickFilter=(name regex /^H-/)']...";


$PHP_FILE = __FILE__;
$utilType = "service-merger";


$merger = new MERGER($utilType, $argv, $PHP_FILE, $supportedArguments, $usageMsg);


if( isset(PH::$args['mergecountlimit']) )
    $merger->mergeCountLimit = PH::$args['mergecountlimit'];





if( isset(PH::$args['dupalgorithm']) )
{
    $merger->dupAlg = strtolower(PH::$args['dupalgorithm']);
    if( $merger->dupAlg != 'sameports' && $merger->dupAlg != 'whereused' && $merger->dupAlg != 'samedstsrcports' )
        $merger->display_error_usage_exit('unsupported value for dupAlgorithm: ' . PH::$args['dupalgorithm']);
}
else
    $merger->dupAlg = 'samedstsrcports';


$merger->service_merging();


$merger->save_our_work( true );

echo "\n************* END OF SCRIPT " . basename(__FILE__) . " ************\n\n";

