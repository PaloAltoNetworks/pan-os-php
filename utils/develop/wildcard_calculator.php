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

print "\n***********************************************\n";
print "************ IP WILDCARD MASK UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");
PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    //display_usage_and_exit(true);
}

function array_cartesian_product($arrays)
{
    $result = array();
    $arrays = array_values($arrays);
    $sizeIn = sizeof($arrays);
    $size = $sizeIn > 0 ? 1 : 0;
    foreach ($arrays as $array)
        $size = $size * sizeof($array);
    for ($i = 0; $i < $size; $i ++)
    {
        $result[$i] = array();
        for ($j = 0; $j < $sizeIn; $j ++)
            array_push($result[$i], current($arrays[$j]));
        for ($j = ($sizeIn -1); $j >= 0; $j --)
        {
            if (next($arrays[$j]))
                break;
            elseif (isset ($arrays[$j]))
                reset($arrays[$j]);
        }
    }
    return $result;
}

$supportedArguments = Array();
$supportedArguments['ip'] = Array('niceName' => 'in', 'shortHelp' => 'IP Address', 'argDesc' => 'ip=10.182.0.1');
$supportedArguments['wildcardmask'] = Array('niceName' => 'out', 'shortHelp' => 'Wildcard Mask', 'argDesc' => 'wildcardmask=0.127.248.0');
$supportedArguments['actions'] = Array('niceName' => 'actions', 'shortHelp' => '', 'argDesc' => 'actions=display / displayip');
$supportedArguments['vendor'] = Array('niceName' => 'vendor', 'shortHelp' => '', 'argDesc' => 'vendor=cisco');

PH::processCliArgs();

foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['ip']) )
{
    $ip_address = PH::$args['ip'];
}
else
{
    derr( "argument IP= missing" );
}

if( isset(PH::$args['wildcardmask']) )
{
    $wildcard_netmask = PH::$args['wildcardmask'];
}
else
{
    derr( "argument WILDCARDMASK= missing" );
}

if( isset(PH::$args['actions']) )
{
    $actions = PH::$args['actions'];
}
else
{
    $actions = "display";
}


if( isset(PH::$args['vendor']) )
{
    if(strtolower(PH::$args['vendor']) == "cisco")
    {
        $cidr_array = explode( ".", $wildcard_netmask );
        $tmp_hostCidr = "";
        foreach( $cidr_array as $key => &$entry )
        {
            $final_entry = 255 - (int)$entry;
            if( $key == 0 )
                $tmp_hostCidr .= $final_entry;
            else
                $tmp_hostCidr .= ".".$final_entry;
        }
        $wildcard_netmask = $tmp_hostCidr;
    }
    else
        derr( "only 'vendor=cisco' is supported", null, false );

}

#$ip_address = "10.128.0.1";
#$wildcard_netmaks = "0.127.248.0";


print "\n\n";

print "IP-ADDRESS: ".$ip_address."\n";
print "WILDCARD-MASK: ".$wildcard_netmask."\n";

print "\n\n";



$ip_explode = explode( ".", $ip_address );
$netmask_explode = explode( ".", $wildcard_netmask );



#print_r( $ip_explode );

#print_r( $netmask_explode );



$netmask_array = array(255, 254, 252, 248, 240, 224, 192, 128 );

$final_array = array();
foreach( $netmask_explode as $key => $position )
{
    if( $position == 0 )
    {
        $final_array[$key] = $ip_explode[$key];
        continue;
    }

    if( $position < 127  )
        $position = 255 - $position;


    if( !in_array( $position, $netmask_array ) )
    {
        if( in_array( $position+1, $netmask_array ) )
        {
            $position = $position+1;
            #print "mask is now: |".$position."|\n";
        }
        else
            derr( "wildcard mask: ".$position." WRONG");
    }



    if( $position != 255 )
    {
        $start = ( intval($position)  &  intval($ip_explode[$key]) );
        $end = ( $start + ( 255 - $position ) );
    }
    else
    {
        $start = 0;
        $end = $position;
    }



    $final_array[$key] = "[ ".$start." - ".$end." ]";

################################

    print "\n############\n";


    print "IP octet:|".$ip_explode[$key]."|wildcard_netmask:|".$position."|\n";
    if( $position != 255 )
        $max_ip = (255 - $position);
    else
        $max_ip = 255;

    print "max nummer of IP-Addresses---". $max_ip ."\n";
    print "wildcard_netmask as binary: ".str_pad(  decbin($position), 8, '0', STR_PAD_LEFT)."\n";

    print "start: ".  $start ."\n";
    print "end: ". $end."\n";

    print "from: ".$start." to: ".$end."\n";


    print "\n############\n";

################################
}



print "\n";
foreach( $final_array as $key => $octet )
{
    print $octet;
    if( $key <3 )
        print " . ";

}
print "\n\n\n";



$dummy_array = array();
foreach( $final_array as $key => $octet )
{
    if( $netmask_explode[$key] == 0 )
    {
        $dummy_array[$key][] = $octet;
    }
    else
    {
        $octet = str_replace( "[", "", $octet );
        $octet = str_replace( "]", "",$octet );
        $octet = str_replace( " ", "",$octet );
        $octet = explode( "-", $octet );
        for( $i = $octet[0]; $i <= $octet[1]; $i++ )
        {
            $dummy_array[$key][] = $i;
        }
    }
}

#print_r($dummy_array);
#print_r( array_cartesian_product($dummy_array) );

if( $actions == "displayip" )
{
    foreach( array_cartesian_product($dummy_array) as $key => $address )
    {
        print str_pad($key, 6) . " - " . $address[0] . "." . $address[1] . "." . $address[2] . "." . $address[3] . "\n";

    }
}

print "\n\n";

print "IP-ADDRESS: ".$ip_address."\n";
print "WILDCARD-MASK: ".$wildcard_netmask."\n";

print "\n\n";


print "\n";
foreach( $final_array as $key => $octet )
{
    print $octet;
    if( $key <3 )
        print " . ";

}

print "\n";

print "\n\n************ END OF IP WILDCARD MASK UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";


