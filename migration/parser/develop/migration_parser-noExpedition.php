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

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());

$additionalPath = "/../..";

require_once dirname(__FILE__).$additionalPath."/pan-os-php/lib/pan_php_framework.php";

require_once dirname(__FILE__).$additionalPath."/parser/lib/CONVERTER.php";
require_once dirname(__FILE__).$additionalPath."/parser/lib/PARSER.php";
require_once dirname(__FILE__).$additionalPath."/parser/lib/SHAREDNEW.php";

PH::processCliArgs();
if( isset(PH::$args['vendor']) )
    $vendor = strtolower(PH::$args['vendor']);
PH::$argv = array();

$converter = vendornewClass( $vendor, $additionalPath );

$converter->initial();

$converter->global_start();

//combined run:
$converter->vendor_main();



if( PH::$shadow_reducexml )
    $converter->global_end(FALSE, -1, 0);
else
    $converter->global_end();


########### FUNCTIONS ###########

function vendornewClass( $vendor, $additionalPath )
{
    //DEFINE VENDOR specific RECUIRE
    if( $vendor == "ciscoasa" )
    {
        require_once dirname(__FILE__).$additionalPath."/parser/CISCO/CISCOASA.php";
        $converter = new CISCOASA();
    }
    elseif( $vendor == "ciscoisr" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/CISCOISR/CISCOISR.php");
        $converter = new CISCOISR();
    }
    elseif( $vendor == "ciscoswitch" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/CISCOSWITCH/CISCOSWITCH.php");
        $converter = new CISCOSWITCH();
    }
    elseif( $vendor == "netscreen" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/SCREENOS/SCREENOS.php");
        $converter = new SCREENOS();
    }
    elseif( $vendor == "fortinet" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/FORTINET/FORTINET.php");
        $converter = new FORTINET();
    }

    elseif( $vendor == "pfsense" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/PFSENSE/PFSENSE.php");
        $converter = new PFSENSE();
    }
    elseif( $vendor == "sonicwall" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/SONICWALL/SONICWALL.php");
        $converter = new SONICWALL();
    }
    elseif( $vendor == "sophos" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/SOPHOS/SOPHOS.php");
        $converter = new SOPHOS();
    }
    elseif( $vendor == "srx" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/SRX/SRX.php");
        $converter = new SRX();
    }
    elseif( $vendor == "cp-r80" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/CP_R80/CP_R80.php");
        $converter = new CP_R80();
    }
    elseif( $vendor == "cp" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/CP/CP.php");
        $converter = new CP();
    }
    elseif( $vendor == "cp-beta" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/CP/develop/CPnew.php");
        $converter = new CPnew();
    }
    elseif( $vendor == "huawei" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/HUAWEI/HUAWEI.php");
        $converter = new HUAWEI();
    }
    elseif( $vendor == "stonesoft" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/STONESOFT/STONESOFT.php");
        $converter = new STONESOFT();
    }
    elseif( $vendor == "sidewinder" )
    {
        require_once(dirname(__FILE__).$additionalPath."/parser/SIDEWINDER/SIDEWINDER.php");
        $converter = new SIDEWINDER();
    }
    else
        derr("VENDOR: " . $vendor . " is not supported yet");

    return $converter;
}