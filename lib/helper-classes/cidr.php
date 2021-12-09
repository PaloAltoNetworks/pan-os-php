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

class cidr
{
    // convert cidr to netmask
    // e.g. 21 = 255.255.248.0
    static public function cidr2netmask($cidr)
    {
        if(filter_var($cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            $netmask = self::ipv6_cidr2netmask( $cidr );

        elseif(filter_var($cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
            $netmask = self::ipv4_cidr2netmask( $cidr );

        return $netmask;
    }

    static public function ipv4_cidr2netmask($cidr)
    {
        $bin = '';

        for( $i = 1; $i <= 32; $i++ )
            $bin .= $cidr >= $i ? '1' : '0';

        $netmask = long2ip(bindec($bin));

        if( $netmask == "0.0.0.0" )
            return FALSE;

        return $netmask;
    }

    static public function ipv6_cidr2netmask($cidr)
    {

    }
    // get network address from cidr subnet
    // e.g. 10.0.2.56/21 = 10.0.0.0
    static public function cidr2network($ip, $cidr)
    {
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
        {
            $network = self::ipv6_cidr2network( $ip, $cidr );
        }
        elseif(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
        {
            $network = self::ipv4_cidr2network( $ip, $cidr );
        }

        return $network;
    }

    static public function ipv4_cidr2network($ip, $cidr)
    {
        $network = long2ip((ip2long($ip)) & ((-1 << (32 - (int)$cidr))));

        return $network;
    }

    static public function ipv6_cidr2network($ip, $cidr)
    {
        // Split in address and prefix length
        #list($addr_given_str, $prefixlen) = explode('/', $prefix);

        // Parse the address into a binary string
        $addr_given_bin = inet_pton($ip);

        // Convert the binary string to a string with hexadecimal characters
        $addr_given_hex = bin2hex($addr_given_bin);

        // Overwriting first address string to make sure notation is optimal
        $ip = inet_ntop($addr_given_bin);

        // Calculate the number of 'flexible' bits
        $flexbits = 128 - $cidr;

        // Build the hexadecimal strings of the first and last addresses
        $addr_hex_first = $addr_given_hex;
        $addr_hex_last = $addr_given_hex;

        // We start at the end of the string (which is always 32 characters long)
        $pos = 31;
        while ($flexbits > 0) {
            // Get the characters at this position
            $orig_first = substr($addr_hex_first, $pos, 1);
            $orig_last = substr($addr_hex_last, $pos, 1);

            // Convert them to an integer
            $origval_first = hexdec($orig_first);
            $origval_last = hexdec($orig_last);

            // First address: calculate the subnet mask. min() prevents the comparison from being negative
            $mask = 0xf << (min(4, $flexbits));

            // AND the original against its mask
            $new_val_first = $origval_first & $mask;

            // Last address: OR it with (2^flexbits)-1, with flexbits limited to 4 at a time
            $new_val_last = $origval_last | (pow(2, min(4, $flexbits)) - 1);

            // Convert them back to hexadecimal characters
            $new_first = dechex($new_val_first);
            $new_last = dechex($new_val_last);

            // And put those character back in their strings
            $addr_hex_first = substr_replace($addr_hex_first, $new_first, $pos, 1);
            $addr_hex_last = substr_replace($addr_hex_last, $new_last, $pos, 1);

            // We processed one nibble, move to previous position
            $flexbits -= 4;
            $pos -= 1;
        }

        // Convert the hexadecimal strings to a binary string
        $addr_bin_first = hex2bin($addr_hex_first);
        $addr_bin_last = hex2bin($addr_hex_last);

        // And create an IPv6 address from the binary string
        $addr_str_first = inet_ntop($addr_bin_first);
        $addr_str_last = inet_ntop($addr_bin_last);

        return $addr_str_first;
    }


    // convert netmask to cidr
    // e.g. 255.255.255.128 = 25
    static public function netmask2cidr($netmask)
    {
        $bits = 0;
        if(filter_var($netmask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
        {
            $bits = self::ipv6_netmask2cidr( $netmask );
        }
        elseif(filter_var($netmask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
        {
            $bits = self::ipv4_netmask2cidr( $netmask );
        }

        return $bits;
    }

    static public function ipv4_netmask2cidr($netmask)
    {
        $bits = 0;
        $netmask = explode(".", $netmask);

        foreach( $netmask as $octect )
            $bits += strlen(str_replace("0", "", decbin($octect)));

        return $bits;
    }

    static public function ipv6_netmask2cidr($netmask) {
        $s = '';
        if (substr($netmask, -1) == ':') $netmask .= '0';
        if (substr($netmask, 0, 1) == ':') $netmask = '0' . $netmask;
        if (strpos($netmask, '::') !== false)
            $mask = str_replace('::', str_repeat(':0', 8 - substr_count($netmask, ':')).':', $netmask);

        foreach(explode(':',$netmask) as $oct) {
            // The following two lines, perhaps, superfluous.
            // I left them because of the paranoia :)
            $oct = trim($oct);
            if ($oct == '') $s .= '0000000000000000';
            else $s .= str_pad(base_convert($oct, 16, 2), 16, '0',  STR_PAD_LEFT);
        }
        #return strlen($s) - strlen(rtrim($s, '0'));
        return strlen(rtrim($s, '0'));
    }

    private static $_int2pow = null;
    private static $_cidr2maskInt = null;

    /**
     * @param int $start
     * @param int $end
     * @return bool|int[] FALSE if start/end do not match a network/mask. Otherwise : Array( 'network' => '10.0.0.0', 'mask' => 8, 'string' => '10.0.0.0/8')
     */
    static public function range2network($start, $end)
    {
        if( is_string($start) )
            derr("'start' cannot be a string");
        if( is_string($end) )
            derr("'end' cannot be a string");

        $diff = $end - $start + 1;

        if( self::$_int2pow === null )
        {
            self::$_int2pow = array();
            for( $i = 0; $i < 32; $i++ )
                self::$_int2pow[pow(2, $i)] = $i;
        }
        if( self::$_cidr2maskInt === null )
        {
            self::$_cidr2maskInt = array();
            self::$_cidr2maskInt[0] = 0;
            self::$_cidr2maskInt[32] = 4294967295;
            for( $i = 1; $i <= 31; $i++ )
                self::$_cidr2maskInt[$i] = self::$_cidr2maskInt[$i - 1] + pow(2, 32 - $i);
        }

        if( !isset(self::$_int2pow[$diff]) )
            return FALSE;

        $netmask = 32 - self::$_int2pow[$diff];
        $calculatedNetworkStart = $start & self::$_cidr2maskInt[$netmask];

        if( $start != $calculatedNetworkStart )
            return FALSE;

        return array('network' => $start, 'mask' => $netmask, 'string' => long2ip($start) . '/' . $netmask);
    }


    // is ip in subnet
    // e.g. is 10.5.21.30 in 10.5.16.0/20 == true
    //      is 192.168.50.2 in 192.168.30.0/23 == false
    /**
     * @param string $ip
     * @param string $network
     * @param int $cidr
     * @return bool
     */
    static public function cidr_match($ip, $network, $cidr)
    {
        if( (ip2long($ip) & ~((1 << (32 - $cidr)) - 1)) == ip2long($network) )
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     * return 0 if not match, 1 if $sub is included in $ref, 2 if $sub is partially matched by $ref.
     * @param string|int[] $sub ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @param string|int[] $ref
     * @return int
     */
    static public function netMatch($sub, $ref)
    {
        if( is_array($sub) )
        {
            $subNetwork = $sub['start'];
            $subBroadcast = $sub['end'];
        }
        else
        {
            $res = cidr::stringToStartEnd($sub);
            $subNetwork = $res['start'];
            $subBroadcast = $res['end'];
        }

        if( is_array($ref) )
        {
            $refNetwork = $ref['start'];
            $refBroadcast = $ref['end'];
        }
        else
        {
            $res = cidr::stringToStartEnd($ref);
            $refNetwork = $res['start'];
            $refBroadcast = $res['end'];
        }

        if( $subNetwork >= $refNetwork && $subBroadcast <= $refBroadcast )
        {
            //print "sub $sub is included in $ref\n";
            return 1;
        }
        if( $subNetwork >= $refNetwork && $subNetwork <= $refBroadcast ||
            $subBroadcast >= $refNetwork && $subBroadcast <= $refBroadcast ||
            $subNetwork <= $refNetwork && $subBroadcast >= $refBroadcast )
        {
            //print "sub $sub is included in $ref\n";
            return 2;
        }

        return 0;
    }

    static public function &stringToStartEnd($value)
    {
        $result = array();
        $result['network'] = $value;

        $ex = explode('-', $value);
        if( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE )
            $version = "ipv4";
        elseif( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE )
            $version = "ipv6";

        if( count($ex) == 2 )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE )
                derr("'{$ex[0]}' is not a valid IP");

            if( filter_var($ex[1], FILTER_VALIDATE_IP) === FALSE )
                derr("'{$ex[1]}' is not a valid IP");

            if( $version == "ipv4" )
            {
                $result['start'] = ip2long($ex[0]);
                $result['end'] = ip2long($ex[1]);
            }
            elseif( $version == "ipv6" )
            {
                $result['start'] = cidr::inet_ptoi($ex[0]);
                $result['end'] = cidr::inet_ptoi($ex[1]);
            }

            return $result;
        }


        $ex = explode('/', $value);
        if( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE )
        {
            $version = "ipv4";
            $maskvalue = 32;
        }

        elseif( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE )
        {
            $version = "ipv6";
            $maskvalue = 128;
        }

        if( count($ex) > 1 && (($version == "ipv4" && $ex[1] != $maskvalue) || ($version == "ipv6" && $ex[1] != $maskvalue) ))
        {
            if( $ex[1] < 0 || $ex[1] > $maskvalue )
                derr("invalid netmask in value {$value}");


            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE )
                derr("'{$ex[0]}' is not a valid IP");

            $bmask = 0;
            for( $i = 1; $i <= ($maskvalue - $ex[1]); $i++ )
                $bmask += pow(2, $i - 1);


            if( $version == "ipv4" )
            {
                $subNetwork = ip2long($ex[0]) & ((-1 << (32 - (int)$ex[1])));
                $subBroadcast = ip2long($ex[0]) | $bmask;
            }
            elseif( $version = "ipv6" )
            {
                $return = cidr::IPv6network2StartEnd( $ex[0]."/".$ex[1]);
                $subNetwork = cidr::inet_ptoi( $return['start']);
                $subBroadcast = cidr::inet_ptoi( $return['end']);
            }
        }
        elseif( count($ex) > 1 && (($version == "ipv4" && $ex[1] == $maskvalue) || ($version == "ipv6" && $ex[1] == $maskvalue) ) )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE )
                derr("'{$ex[0]}' is not a valid IP");

            if( $version == "ipv4" )
            {
                $subNetwork = ip2long($ex[0]);
                $subBroadcast = $subNetwork;
            }
            elseif( $version == "ipv6" )
            {
                $subNetwork = cidr::inet_ptoi($ex[0]);
                $subBroadcast = $subNetwork;
            }
        }
        else
        {
            if( filter_var($value, FILTER_VALIDATE_IP) === FALSE )
                derr("'{$value}' is not a valid IP");

            if( $version == "ipv4" )
            {
                $subNetwork = ip2long($ex[0]);
                $subBroadcast = $subNetwork;
            }
            elseif( $version == "ipv6" )
            {
                $subNetwork = cidr::inet_ptoi($ex[0]);
                $subBroadcast = $subNetwork;
            }
        }


        $result['start'] = $subNetwork;
        $result['end'] = $subBroadcast;

        return $result;
    }


    static public function &IPv6network2StartEnd($ip)
    {
        #print "IP: ".$ip."\n";

        // Split in address and prefix length
        list($addr_given_str, $prefixlen) = explode('/', $ip);

        $ip = $addr_given_str;
        $cidr = $prefixlen;

        // Parse the address into a binary string
        $addr_given_bin = inet_pton($ip);

        // Convert the binary string to a string with hexadecimal characters
        $addr_given_hex = bin2hex($addr_given_bin);

        // Overwriting first address string to make sure notation is optimal
        $ip = inet_ntop($addr_given_bin);

        // Calculate the number of 'flexible' bits
        $flexbits = 128 - $cidr;

        // Build the hexadecimal strings of the first and last addresses
        $addr_hex_first = $addr_given_hex;
        $addr_hex_last = $addr_given_hex;

        // We start at the end of the string (which is always 32 characters long)
        $pos = 31;
        while ($flexbits > 0) {
            // Get the characters at this position
            $orig_first = substr($addr_hex_first, $pos, 1);
            $orig_last = substr($addr_hex_last, $pos, 1);

            // Convert them to an integer
            $origval_first = hexdec($orig_first);
            $origval_last = hexdec($orig_last);

            // First address: calculate the subnet mask. min() prevents the comparison from being negative
            $mask = 0xf << (min(4, $flexbits));

            // AND the original against its mask
            $new_val_first = $origval_first & $mask;

            // Last address: OR it with (2^flexbits)-1, with flexbits limited to 4 at a time
            $new_val_last = $origval_last | (pow(2, min(4, $flexbits)) - 1);

            // Convert them back to hexadecimal characters
            $new_first = dechex($new_val_first);
            $new_last = dechex($new_val_last);

            // And put those character back in their strings
            $addr_hex_first = substr_replace($addr_hex_first, $new_first, $pos, 1);
            $addr_hex_last = substr_replace($addr_hex_last, $new_last, $pos, 1);

            // We processed one nibble, move to previous position
            $flexbits -= 4;
            $pos -= 1;
        }

        // Convert the hexadecimal strings to a binary string
        $addr_bin_first = hex2bin($addr_hex_first);
        $addr_bin_last = hex2bin($addr_hex_last);

        // And create an IPv6 address from the binary string
        $addr_str_first = inet_ntop($addr_bin_first);
        $addr_str_last = inet_ntop($addr_bin_last);


        #print "START: ".$addr_bin_first."\n";
        #print "ENd: ".$addr_bin_last."\n";

        $result['start'] = $addr_str_first;
        $result['end'] = $addr_str_last;

        return $result;
    }

    /**
     * Converts human readable representation to a 128 bit int
     * which can be stored in MySQL using DECIMAL(39,0).
     *
     * Requires PHP to be compiled with IPv6 support.
     * This could be made to work without IPv6 support but
     * I don't think there would be much use for it if PHP
     * doesn't support IPv6.
     *
     * @param string $ip IPv4 or IPv6 address to convert
     * @return string 128 bit string that can be used with DECIMNAL(39,0) or false
     */
    static public function inet_ptoi($ip)
    {
        // make sure it is an ip
        if (filter_var($ip, FILTER_VALIDATE_IP) === false)
            return false;

        $parts = unpack('N*', inet_pton($ip));

        // fix IPv4
        if (strpos($ip, '.') !== false)
            $parts = array(1=>0, 2=>0, 3=>0, 4=>$parts[1]);

        foreach ($parts as &$part)
        {
            // convert any unsigned ints to signed from unpack.
            // this should be OK as it will be a PHP float not an int
            if ($part < 0)
                $part += 4294967296;
        }

        // Use BCMath if available
        if (function_exists('bcadd'))
        {
            $decimal = $parts[4];
            $decimal = bcadd($decimal, bcmul($parts[3], '4294967296'));
            $decimal = bcadd($decimal, bcmul($parts[2], '18446744073709551616'));
            $decimal = bcadd($decimal, bcmul($parts[1], '79228162514264337593543950336'));
        }
        // Otherwise use the pure PHP BigInteger class
        else
        {
            $decimal = new Math_BigInteger($parts[4]);
            $part3   = new Math_BigInteger($parts[3]);
            $part2   = new Math_BigInteger($parts[2]);
            $part1   = new Math_BigInteger($parts[1]);

            $decimal = $decimal->add($part3->multiply(new Math_BigInteger('4294967296')));
            $decimal = $decimal->add($part2->multiply(new Math_BigInteger('18446744073709551616')));
            $decimal = $decimal->add($part1->multiply(new Math_BigInteger('79228162514264337593543950336')));

            $decimal = $decimal->toString();
        }

        return $decimal;
    }


    /**
     * Converts a 128 bit int to a human readable representation.
     *
     * Requires PHP to be compiled with IPv6 support.
     * This could be made to work without IPv6 support but
     * I don't think there would be much use for it if PHP
     * doesn't support IPv6.
     *
     * @param string $decimal 128 bit int
     * @return string IPv4 or IPv6
     *
     *
     * PROBLEM BY USING IT WITH IPV4 0.X.X.X MAYBE AS NETMASK/WILDCARD AS IT RETURN IPV6
     *
     */

    static public function inet_itop($decimal)
    {
        $parts = array();

        // Use BCMath if available
        if (function_exists('bcadd'))
        {
            $parts[1] = bcdiv($decimal, '79228162514264337593543950336', 0);
            $decimal  = bcsub($decimal, bcmul($parts[1], '79228162514264337593543950336'));
            $parts[2] = bcdiv($decimal, '18446744073709551616', 0);
            $decimal  = bcsub($decimal, bcmul($parts[2], '18446744073709551616'));
            $parts[3] = bcdiv($decimal, '4294967296', 0);
            $decimal  = bcsub($decimal, bcmul($parts[3], '4294967296'));
            $parts[4] = $decimal;
        }
        // Otherwise use the pure PHP BigInteger class
        else
        {
            $decimal = new Math_BigInteger($decimal);
            list($parts[1],) = $decimal->divide(new Math_BigInteger('79228162514264337593543950336'));
            $decimal = $decimal->subtract($parts[1]->multiply(new Math_BigInteger('79228162514264337593543950336')));
            list($parts[2],) = $decimal->divide(new Math_BigInteger('18446744073709551616'));
            $decimal = $decimal->subtract($parts[2]->multiply(new Math_BigInteger('18446744073709551616')));
            list($parts[3],) = $decimal->divide(new Math_BigInteger('4294967296'));
            $decimal = $decimal->subtract($parts[3]->multiply(new Math_BigInteger('4294967296')));
            $parts[4] = $decimal;

            $parts[1] = $parts[1]->toString();
            $parts[2] = $parts[2]->toString();
            $parts[3] = $parts[3]->toString();
            $parts[4] = $parts[4]->toString();
        }

        foreach ($parts as &$part)
        {
            // convert any signed ints to unsigned for pack
            // this should be fine as it will be treated as a float
            if ($part > 2147483647)
                $part -= 4294967296;
        }

        $ip = inet_ntop(pack('N4', $parts[1], $parts[2], $parts[3], $parts[4]));


        // fix IPv4 by removing :: from the beginning
        if (strpos($ip, '.') !== false)
            return substr($ip, 2);

        return $ip;
    }
}

