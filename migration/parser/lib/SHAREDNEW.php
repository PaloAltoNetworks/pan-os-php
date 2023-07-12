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


trait SHAREDNEW
{
    //SVEN

    public $toolname = "PAN-PHP-FRAMEWORK";

    public function strip_hidden_chars($str)
    {
        $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

        $str = str_replace($chars, "", $str);

        #return preg_replace('/\s+/',' ',$str);
        return $str;
    }

    public function find_string_between($line, $needle1, $needle2 = "--END--")
    {
        $needle_length = strlen($needle1);
        $pos1 = strpos($line, $needle1);

        if( $needle2 !== "--END--" )
            $pos2 = strpos($line, $needle2);
        else
            $pos2 = strlen($line);

        $finding = substr($line, $pos1 + $needle_length, $pos2 - ($pos1 + $needle_length));

        return $finding;
    }

    public function IKE_IPSEC_name_validation($IKE_name, $string = "")
    {
        if( preg_match('[^\d]', $IKE_name) )
        {
            //NO digit allowed at the beginning of a name
            $IKE_name = "X_" . $IKE_name;
            #derr( 'no digit allowed at the beginning of a IKE gateway name' );
        }

        if( preg_match('/[^0-9a-zA-Z_\-]/', $IKE_name) )
        {
            //NO blank allowed in gateway name
            //NO other characters are allowed as seen here
            $IKE_name = preg_replace('/[^0-9a-zA-Z_\-]/', "", $IKE_name);
            if( $string !== "" )
            {
                #print " *** new IKE / IPSEC name: ".$IKE_name." in ".$string." config \n";
                #mwarning( 'Name will be replaced with: '.$name."\n", null, false );

            }
        }

        return $IKE_name;
    }


    public function strpos_arr($haystack, $needle)
    {
        if( !is_array($needle) ) $needle = array($needle);
        foreach( $needle as $what )
        {
            if( ($pos = strpos($haystack, $what)) !== FALSE ) return $pos;
        }
        return FALSE;
    }

////////////////


    public function truncate_names($longString)
    {
        global $source;
        $variable = strlen($longString);

        if( $variable < 63 )
        {
            return $longString;
        }
        else
        {
            $separator = '';
            $separatorlength = strlen($separator);
            $maxlength = 63 - $separatorlength;
            $start = $maxlength;
            $trunc = strlen($longString) - $maxlength;
            $salida = substr_replace($longString, $separator, $start, $trunc);

            if( $salida != $longString )
            {
                //Todo: swaschkut - xml attribute adding needed
                #add_log('warning', 'Names Normalization', 'Object Name exceeded >63 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
            }
            return $salida;
        }
    }

    public function normalizeNames($nameToNormalize)
    {
        $nameToNormalize = trim($nameToNormalize);
        //$nameToNormalize = preg_replace('/(.*) (&#x2013;) (.*)/i', '$0 --> $1 - $3', $nameToNormalize);
        //$nameToNormalize = preg_replace("/&#x2013;/", "-", $nameToNormalize);
        $nameToNormalize = preg_replace("/[\/]+/", "_", $nameToNormalize);
        $nameToNormalize = preg_replace("/[,]+/", "_", $nameToNormalize);
        $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_. *]+/", "", $nameToNormalize);
        $nameToNormalize = preg_replace("/[\s]+/", " ", $nameToNormalize);

        $nameToNormalize = preg_replace("/^[-]+/", "", $nameToNormalize);
        $nameToNormalize = preg_replace("/^[_]+/", "", $nameToNormalize);

        $nameToNormalize = preg_replace('/\(|\)/', '', $nameToNormalize);
        $nameToNormalize = preg_replace("/[\*]+/", "", $nameToNormalize);

        $nameToNormalize = trim( $nameToNormalize );

        return $nameToNormalize;
    }

    public function normalizeComments($nameToNormalize)
    {
        $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_.:\,\s]+/", "", $nameToNormalize);
        return $nameToNormalize;
    }

    public function ip_version($ip)
    {

        $ip = explode("/", $ip);
        $ip = $ip[0];

        if( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) )
        {
            return "v4";
        }
        elseif( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
        {
            return "v6";
        }
        else
        {
            return "noip";
        }
    }

    public function mask2cidrv4($mask)
    {
        $long = ip2long($mask);
        $base = ip2long('255.255.255.255');
        return 32 - log(($long ^ $base) + 1, 2);
    }

    public function truncate_tags($longString)
    {
        global $source;
        $variable = strlen($longString);

        if( $variable < 127 )
        {
            return $longString;
        }
        else
        {
            $separator = '';
            $separatorlength = strlen($separator);
            $maxlength = 127 - $separatorlength;
            $start = $maxlength;
            $trunc = strlen($longString) - $maxlength;
            $salida = substr_replace($longString, $separator, $start, $trunc);

            if( $salida != $longString )
            {
                #add_log('warning', 'Names Normalization', 'Object Name exceeded >127 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required', '', '', '');
            }
            return $salida;
        }
    }

    public function truncate_rulenames($longString)
    {

        global $source;

        $variable = strlen($longString);

        $max = getMaxLengthRuleName($source);

        /*$version = calcVersion($source);

        if($version < 8.1){
            $max = 31;
        }elseif($version >= 8.1){
            $max = 63;
        }*/

        if( $variable < $max )
        {
            return $longString;
        }
        else
        {
            $separator = '';
            $separatorlength = strlen($separator);
            $maxlength = $max - $separatorlength;
            $start = $maxlength;
            $trunc = strlen($longString) - $maxlength;
            $salida = substr_replace($longString, $separator, $start, $trunc);

            if( $salida != $longString )
            {
                add_log('warning', 'Names Normalization', 'Object Name exceeded > ' . $max . ' chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
            }
            return $salida;
        }
    }

    public function truncate_zone_names_cisco($longString, $version = "6")
    {
        global $projectname;
        global $source;
        global $projectdb;
        $projectdb = selectDatabase($projectname);

        $variable = strlen($longString);

        if( $variable < 14 )
        {
            //return $longString;
        }
        else
        {
            $maxChars = 15;
            $salida = substr_replace($longString, '', $maxChars / 2, $variable - $maxChars);
            if( $salida != $longString )
            {
                add_log('warning', 'Names Normalization', 'Zone Name exceeded >15 chars Original:[' . $longString . '] NewName:[' . $salida . ']', $source, 'No Action Required');
                $projectdb->query("UPDATE security_rules_from SET name='$salida' WHERE name='$longString';");
                $projectdb->query("UPDATE security_rules_to SET name='$salida' WHERE name='$longString';");
                $projectdb->query("UPDATE nat_rules_from SET name='$salida' WHERE name='$longString';");
                $projectdb->query("UPDATE nat_rules SET op_zone_to='$salida' WHERE source='$source' AND op_zone_to='$longString';");
                $projectdb->query("UPDATE routes_static SET zone='$salida' WHERE source='$source' AND zone='$longString';");
            }
            //return $salida;
        }
    }

    public static function default_regions()
    {
        $tmp_regions = array();

        $JSON_filename = dirname(__FILE__)."/../region.json";
        $JSON_string = file_get_contents($JSON_filename);

        $someArray = json_decode($JSON_string, TRUE);
        $tmp_regions = $someArray['region'];

        return $tmp_regions;
    }

    public function convertWildcards(STRING $wildcard, STRING $type)
    {
        # @type cidr or netmask

        $netmask_explode = explode(".", $wildcard);
        if( isset($netmask_explode[3]) && $netmask_explode[3] > "200" )
        {
            $netmask_array = array(255, 254, 252, 248, 240, 224, 192, 128);

            $final_array = array();
            foreach( $netmask_explode as $key => $position )
            {
                if( $position == 255 )
                {
                    $position = 0;
                }
                else
                {
                    if( $position < 127 )
                        $position = 255 - $position;

                    if( !in_array($position, $netmask_array) )
                    {
                        if( in_array($position + 1, $netmask_array) )
                        {
                            $position = $position + 1;
                            #print "mask is now: |".$position."|\n";
                        }
                        else
                            derr("wildcard mask: " . $position . " WRONG");
                    }
                }

                $final_array[$key] = $position;
            }

            $comma_separated = implode(".", $final_array);

            switch ($type)
            {
                case "netmask":
                    return $comma_separated;
                    break;
                case "cidr":
                    return CIDR::netmask2cidr($comma_separated);
                    break;
            }
        }

        switch ($wildcard)
        {

            case "0.255.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.0.0.0";
                        break;
                    case "cidr":
                        return "8";
                        break;
                }
                break;
            case "0.127.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.128.0.0";
                        break;
                    case "cidr":
                        return "9";
                        break;
                }
                break;
            case "0.63.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.192.0.0";
                        break;
                    case "cidr":
                        return "10";
                        break;
                }
                break;
            case "0.31.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.224.0.0";
                        break;
                    case "cidr":
                        return "11";
                        break;
                }
                break;
            case "0.15.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.240.0.0";
                        break;
                    case "cidr":
                        return "12";
                        break;
                }
                break;
            case "0.7.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.248.0.0";
                        break;
                    case "cidr":
                        return "13";
                        break;
                }
                break;
            case "0.3.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.252.0.0";
                        break;
                    case "cidr":
                        return "14";
                        break;
                }
                break;
            case "0.1.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.254.0.0";
                        break;
                    case "cidr":
                        return "15";
                        break;
                }
                break;
            case "0.0.255.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.0.0";
                        break;
                    case "cidr":
                        return "16";
                        break;
                }
                break;
            case "0.0.127.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.128.0";
                        break;
                    case "cidr":
                        return "17";
                        break;
                }
                break;
            case "0.0.63.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.192.0";
                        break;
                    case "cidr":
                        return "18";
                        break;
                }
                break;
            case "0.0.31.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.224.0";
                        break;
                    case "cidr":
                        return "19";
                        break;
                }
                break;
            case "0.0.15.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.240.0";
                        break;
                    case "cidr":
                        return "20";
                        break;
                }
                break;
            case "0.0.7.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.248.0";
                        break;
                    case "cidr":
                        return "21";
                        break;
                }
                break;
            case "0.0.3.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.252.0";
                        break;
                    case "cidr":
                        return "22";
                        break;
                }
                break;
            case "0.0.1.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.254.0";
                        break;
                    case "cidr":
                        return "23";
                        break;
                }
                break;
            case "0.0.0.255":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.0";
                        break;
                    case "cidr":
                        return "24";
                        break;
                }
                break;
            case "0.0.0.127":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.128";
                        break;
                    case "cidr":
                        return "25";
                        break;
                }
                break;
            case "0.0.0.63":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.192";
                        break;
                    case "cidr":
                        return "26";
                        break;
                }
                break;
            case "0.0.0.31":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.224";
                        break;
                    case "cidr":
                        return "27";
                        break;
                }
                break;
            case "0.0.0.15":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.240";
                        break;
                    case "cidr":
                        return "28";
                        break;
                }
                break;
            case "0.0.0.7":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.248";
                        break;
                    case "cidr":
                        return "29";
                        break;
                }
                break;
            case "0.0.0.3":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.252";
                        break;
                    case "cidr":
                        return "30";
                        break;
                }
                break;
            case "0.0.0.1":
                switch ($type)
                {
                    case "netmask":
                        return "255.255.255.254";
                        break;
                    case "cidr":
                        return "31";
                        break;
                }
                break;
            default:
                return FALSE;

        }


    }

    public function checkNetmask($ip)
    {
        if( !ip2long($ip) )
        {
            return FALSE;
        }
        elseif( strlen(decbin(ip2long($ip))) != 32 && ip2long($ip) != 0 )
        {
            return FALSE;
        }
        elseif( preg_match('/01/', decbin(ip2long($ip))) || !preg_match('/0/', decbin(ip2long($ip))) )
        {
            return FALSE;
        }
        else
        {
            return TRUE;
        }
    }


# Match IPv4  cidr_match("1.2.3.4", "0.0.0.0/0"): true
    public function cidr_match($ip, $cidr)
    {
        $list = explode('/', $cidr);
        $subnet = $list[0];
        $mask = $list[1];
        if( (ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet) )
        {
            return TRUE;
        }

        return FALSE;
    }

    function netMatchObjects2Ways($sub, $ref, &$way)
    {
        if( isset($sub->cidr) && !strcmp($sub->cidr, '') == 0 )
        {
            $sub_local = "$sub->value/$sub->cidr";
        }
        else
        {
            $sub_local = "$sub->value";
        }
        if( isset($ref->cidr) && !strcmp($ref->cidr, '') == 0 )
        {
            $ref_local = "$ref->value/$ref->cidr";
        }
        else
        {
            $ref_local = "$ref->value";
        }

        $result = netMatch2Ways($sub_local, $ref_local, $way);
        if( $way == AisinB ) return $sub;
        elseif( $way == BisinA ) return $ref;
        else
        {
            $start = $result['start'];
            $end = $result['end'];
            $member = new MemberObject('', '', "$start-$end", '32');
            return null;
        }
    }

    //copied from Expedition lib-objects.php
    function isAinB_Zones(array $groupA, array $groupB, array &$foundZones = null)
    {
        //$groupA/B are arrays of zoneObjects -> name is needed
        //Todo: deep validation of $groupA/B info is needed

        foreach( $groupA as $key => $item )
        {
            $groupA[$key] = $item->name();
        }

        foreach( $groupB as $key => $item )
        {
            $groupB[$key] = $item->name();
        }

        #$isFromCovered = $this->isAinB_Zones($security_rule->from->getAll(), $getNatData->from->getAll(), $zonesFrom);
        //Todo: why is $zonesFrom needed?
        #$isFromCovered = $getNatData->from->includesContainer( $security_rule->from );


        if( in_array("any", $groupB) || in_array("Any", $groupB) )
        {
            if( in_array("any", $groupA) || in_array("Any", $groupA) )
            {
                $foundZones = $groupA;
                return 1;
            }
            else
            {
                $foundZones = $groupA;
                return 2;
            }
        }
        elseif( in_array("any", $groupA) || in_array("Any", $groupA) )
        {
            $foundZones = $groupB;
            return 2;
        }
        else
        {
            $foundZones = array_intersect($groupA, $groupB);
        }

        if( count($foundZones) == 0 )
        {
            return 0;
        }
        if( count($foundZones) == count($groupA) )
        {
            return 1;
        }
        return 2;
    }

    /**
     * This method checks whether the members in groupA are in the groupB.
     * @param array(MemberObject) $groupA
     * @param array(MemberObject) $groupB
     * @param String $debugText
     * @return int
     */
    function isAinB($groupA, $groupB, &$foundMembers = null, $debugText = null)
    {
        //Todo: same from above isAinBZone -> get array membmer names


        if( isset($debugText) )
        {
            echo "$debugText\n";
        }
        $foundMembers = array();

        $allChildrenFound = TRUE;
        $someChildrenFound = FALSE;

        foreach( $groupA as $childMember )
        {
//        echo "Child:";  print_r($childMember);
            if( is_array($childMember) )
            {
                print_r(debug_backtrace());
            }
            if( $this->ip_version($childMember->value()) != 'v4' )
            {
                $allChildrenFound = FALSE;
            }
            else
            {
                foreach( $groupB as $parentMember )
                {
                    $result = -1;

                    if( $this->ip_version($parentMember->value()) != 'v4' )
                    {
                        $newMatch = -1;
                    }
                    else
                    {
//                    echo "Parent:";  print_r($parentMember);
                        $newMatch = $this->netMatchObjects2Ways($childMember, $parentMember, $result);
//            echo "Result: $result\n\n";
                    }

                    if( $result == 1 )
                    { //if one of the members in the groupA is not in groupB, then A is not in B
//                $isChildPartiallyFound = 1;
                        $someChildrenFound = TRUE;
                        $foundMembers[] = $childMember;
                        break;
                    }
                    elseif( $result == 2 )
                    {
                        $allChildrenFound = FALSE;
                        $someChildrenFound = TRUE;
                        $foundMembers[] = $newMatch;
                    }
                    else
                    {
                        $allChildrenFound = FALSE;
                    }
                }
            }
        }

        if( $allChildrenFound )
        {
//        echo "Final result 1\n";
            return 1;
        }
        if( $someChildrenFound )
        {
//        echo "Final result 2\n";
            return 2;
        }
//    echo "Final result 0\n";
        return 0;
    }

    function isAinB_service($groupA, $groupB, &$foundServices = null, $debugText = null)
    {
        #$isSrvCovered = $this->isAinB_service($security_rule->services->getAll(), $getNatData->service, $servicesMatched);

        if( isset($debugText) )
        {
            echo "$debugText\n";
        }
        foreach( $groupA as $childMember )
        {
            $isChildFound = 0;
            $isChildPartiallyFound = 0;
            foreach( $groupB as $parentMember )
            {
                $result = -1;
                $newMatch = serviceMatchObjects2Ways($childMember, $parentMember, $result);
                if( $result == 1 )
                { //if one of the members in the groupA is not in groupB, then A is not in B
                    $isChildFound = 1;
                    $foundServices[] = $newMatch;
                    break;
                }
                elseif( $result == 2 )
                {
                    $isChildPartiallyFound = 1;
                    $foundServices[] = $newMatch;
                }
            }
            if( $isChildFound == 0 && $isChildPartiallyFound == 0 )
            {
//            echo "Service Not Matched\n";
                return 0;
            }
            elseif( $isChildFound == 0 && $isChildPartiallyFound == 1 )
            {
//            echo "Service Partial GroupA Match\n";
                return 2;
            }
        }
//    echo "Service Full GroupA Match\n";
        return 1;
    }


    public function MainAddHost($name, $IPvalue, $type = "ip-netmask", $description = null)
    {
        global $print;

        if( $IPvalue == "" )
            return null;

        //remove leading 0 on IP address
        //20230621 - swaschkut - why was this line added, just commented out
        //$IPvalue = ltrim($IPvalue, "0");

        $value_array = explode( "/", $IPvalue );
        if( isset( $value_array[1] ) )
        {
            if( strpos($value_array[1], ".") !== FALSE )
            {
                $type= "ip-wildcard";
            }
        }

        $location = $this->sub;

        $name = $this->truncate_names($this->normalizeNames($name));
        $value = $IPvalue;
        $value = str_replace('"', "", $value);

        $tmp_address = $location->addressStore->find($name);
        if( $tmp_address == null )
        {
            #if( $this->print )
            if( $print )
                print " * create address object: " . $name . " | type: " . $type . " | value: " . $value . "\n";
            $tmp_address = $location->addressStore->newAddress($name, $type, $value);
        }
        else
        {
            if( $tmp_address->isAddress() )
            {
                $value = $tmp_address->value();
            }
            else
                $value = "GROUP";
            mwarning("address object: " . $name . " already available; with value: " . $value . "\n", null, false);
        }

        if( $description !== null )
        {
            $description = $this->normalizeNames($description);
            $tmp_address->setDescription($description);
        }


        return $tmp_address;
    }

    public function MainAddAddressGroup($name, $members, $description, &$missingMembers = array())
    {
        global $print;

        $location = $this->sub;

        $name = $this->truncate_names($this->normalizeNames($name));

        $tmp_addressgroup = $location->addressStore->find($name);
        if( $tmp_addressgroup === null )
        {
            #if( $this->print )
            if( $print )
                print "\n * create addressgroup: " . $name . "\n";
            $tmp_addressgroup = $location->addressStore->newAddressGroup($name);

            if( $description !== null )
                $tmp_addressgroup->setDescription($description);
        }

        foreach( $members as $member )
        {
            $member = $this->truncate_names($this->normalizeNames($member));
            $tmp_address = $location->addressStore->find($member);

            if( $tmp_address !== null )
            {
                /*
                if( !$tmp_addressgroup->hasObjectRecursive($tmp_address) && $tmp_addressgroup != $tmp_address )
                {
                    #if( $this->print )
                    if( $print )
                        print "    * add address object: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";

                    $tmp_addressgroup->addMember($tmp_address);
                }
                else
                {*/
                #if( $this->print )
                if( $print )
                    print "    * address object: " . $tmp_address->name() . " already a member or submember of addressgroup: " . $tmp_addressgroup->name() . "\n";

                #if( $this->print )
                if( $print )
                    print "    * add address object: " . $tmp_address->name() . " also as it is added already\n";
                $tmp_addressgroup->addMember($tmp_address);
                #}
            }
            else
            {
                if( $print )
                    print "    X address object: " . $member . " not found - can not be added to addressgroup: " . $tmp_addressgroup->name() . "\n";

                $missingMembers[$tmp_addressgroup->name()][] = $member;
                #mwarning( "address object: ".$member." not found" );
            }
        }

        return $tmp_addressgroup;
    }

    public function MainAddService($name, $protocol, $dport, $description = '', $sport = null)
    {
        global $print;

        $location = $this->sub;

        $name = $this->truncate_names($this->normalizeNames($name));

        $tmp_service = $location->serviceStore->find($name);

        #if( $description !== null )
            #$description = $this->normalizeNames($description);

        if( $tmp_service == null )
        {
            #if( $this->print )
            if( $print )
                print " * create service: " . $name . " | protocol: " . $protocol . " | port: " . $dport . "\n";
            $tmp_service = $location->serviceStore->newService($name, $protocol, $dport, $description, $sport);
        }
        else
        {
            mwarning($protocol . " service: " . $name . " already available\n", null, false);
        }

        return $tmp_service;
    }

    public function MainAddServiceGroup($name, $members, $description, &$missingMembers, $find_tmp = FALSE)
    {
        global $print;

        $location = $this->sub;

        $name = $this->truncate_names($this->normalizeNames($name));

        /** @var ServiceGroup $tmp_servicegroup*/
        $tmp_servicegroup = $location->serviceStore->find($name);
        if( $tmp_servicegroup === null )
        {
            #if( $this->print )
            if( $print )
                print "\n * create servicegroup: " . $name . "\n";
            $tmp_servicegroup = $location->serviceStore->newServiceGroup($name);

            if( $description !== null )
            {
                #$tmp_servicegroup->setDescription($description);
                #mwarning( "PAN-OS servicegroup do not support description" );
            }

        }
        else
        {
            if( !$tmp_servicegroup->isGroup() )
            {
                mwarning( "service can not be added as member to a sevice object\n" );
                return null;
            }

        }

        foreach( $members as $member )
        {
            $member = $this->truncate_names($this->normalizeNames($member));
            $tmp_service = $location->serviceStore->find($member);

            if( $tmp_service !== null )
            {

                if( $print )
                    print "    * add service object: " . $tmp_service->name() . " to servicegroup: " . $tmp_servicegroup->name() . "\n";

                $tmp_servicegroup->addMember($tmp_service);


                /*
                print "first: checkgroup: '".$tmp_servicegroup->name()."'\n";
                if( !$tmp_servicegroup->hasObjectRecursive($tmp_service) && $tmp_servicegroup != $tmp_service ){
                    #if( $this->print )
                    if( $print )
                        print "    * add service object: " . $tmp_service->name() . " to servicegroup: " . $tmp_servicegroup->name() . "\n";

                    $tmp_servicegroup->addMember($tmp_service);
                }


                else
                {
                    #if( $this->print )
                    if( $print )
                        print "    * service object: " . $tmp_service->name() . " already a member or submember of servicegroup: " . $tmp_servicegroup->name() . "\n";

                    #if( $this->print )
                    if( $print )
                        print "    * add service object: " . $tmp_service->name() . " also as it is added already\n";
                    $tmp_servicegroup->addMember($tmp_service);
                }
                */


            }
            else
            {
                if( $find_tmp )
                {
                    $tmp_service = $location->serviceStore->find("tmp-" . $member);

                    if( $tmp_service !== null )
                    {
                        ///*
                        if( $print )
                            print "    * add service object: " . $tmp_service->name() . " to servicegroup: " . $tmp_servicegroup->name() . "\n";

                        $tmp_servicegroup->addMember($tmp_service);
                    }
                }

                if( $tmp_service === null )
                {
                    if( $print )
                    {
                        if( $find_tmp )
                            $member_name = "tmp-" . $member;
                        else
                            $member_name = $member;

                        print "    X service object: " . $member_name . " not found - can not be added to servicegroup: " . $tmp_servicegroup->name() . "\n";
                    }


                    $missingMembers[$tmp_servicegroup->name()][] = $member;
                    #mwarning( "service object: ".$member." not found", null,false );
                }

            }
        }

        return $tmp_servicegroup;
    }

    public function json_validate($string)
    {
        if( is_string($string) )
        {
            @json_decode($string);
            return (json_last_error() === JSON_ERROR_NONE);
        }
        return FALSE;
    }

    public function addServicePredefined( $vendor )
    {
        global $add_srv;

        $JSON_filename = dirname(__FILE__)."/../service_predefined.json";
        $JSON_string = file_get_contents( $JSON_filename );
        $someArray = json_decode($JSON_string, TRUE);

        $add_srv = array();
        if( isset( $someArray['service_predefined'][$vendor] ) )
            $add_srv = $someArray['service_predefined'][$vendor];

        //https://www.cisco.com/c/en/us/td/docs/security/asa/asa915/asdm715/general/asdm-715-general-config/ref-ports.pdf
        //https://help.fortinet.com/fos40hlp/43/wwhelp/wwhimpl/common/html/wwhelp.htm?context=fgt&file=fw_components.12.23.html

        foreach( $add_srv as $srv )
        {
            $name = $srv['name'];
            $protocol = $srv['protocol'];
            $dport = $srv['dport'];
            if( isset( $srv['memberOfGroup'] ) )
                $group = $srv['memberOfGroup'];
            else
                $group = null;

            $tmptag = $this->sub->tagStore->findOrCreate( "predefined-EC" );

            if( $group != null )
            {
                $group = $this->truncate_names( $this->normalizeNames( $group ) );
                $tmpservicegroup = $this->sub->serviceStore->find($group);
                if( $tmpservicegroup == null )
                {
                    print "\n - create servicegroup object: " . $group . "\n";
                    $tmpservicegroup = $this->sub->serviceStore->newServiceGroup($group);
                    $tmpservicegroup->tags->addTag( $tmptag );
                }
            }

            if( $protocol != 'tcp' && $protocol !=  "udp")
            {
                $name = "tmp-".$name;
                $protocol = "tcp";
                $dport = "65535";
            }

            $name = $this->truncate_names( $this->normalizeNames($name));

            $tmpservice = $this->sub->serviceStore->find($name);
            if( $tmpservice == null )
            {
                print "\n - create service object: " . $name . "\n";
                $tmpservice = $this->sub->serviceStore->newService($name, $protocol, $dport, $description = null);
                $tmpservice->tags->addTag( $tmptag );
            }
            if( $group != null )
                $tmpservicegroup->addMember( $tmpservice );
        }
    }

    public function load_custom_application()
    {
        $custom_appids = array();

        //Todo: max. customapp-id name is 31 characters
        $someJSON = file_get_contents(dirname(__FILE__)."/../custom_appid_icmp.json");
        $someArray = json_decode($someJSON, TRUE);
        $custom_appids = $someArray['custom_appid_icmp'];


        //Todo: check if icmp customer app with code is already available
        //if not, add it
        //Todo: for this first each custom app must be load separatly
        //- then it could also be checked if another one is already available

        $app_string = "<application>\n";
        foreach( $custom_appids as $key => $icmp_type )
        {
            $icmpType = $icmp_type['icmpType'];
            if( isset( $icmp_type['icmpCode'] ) )
                $icmpCode = $icmp_type['icmpCode'];
            else
                $icmpCode = null;

            if( $icmpCode != null )
                $icmp_code = "<code>" . $icmpCode . "</code>";
            else
                $icmp_code = "";


            if( strpos($key, "ipv6") !== FALSE )
            {
                $ident_by = 'ident-by-icmp6-type';

                $tmp_icmp_app = $this->sub->appStore->get_app_by_icmptype( "ipv6", $icmpType, $icmpCode );
            }
            else
            {
                $ident_by = 'ident-by-icmp-type';

                $tmp_icmp_app = $this->sub->appStore->get_app_by_icmptype( "ipv6", $icmpType, $icmpCode );
            }



            $tmp_string = "    <entry name=\"" . $key . "\">
      <subcategory>ip-protocol</subcategory>
      <category>networking</category>
      <technology>network-protocol</technology>
      <risk>1</risk>
      <default>
        <" . $ident_by . ">
          <type>" . $icmpType . "</type>
          " . $icmp_code . "
        </" . $ident_by . ">
      </default>
    </entry>";
            $app_string .= $tmp_string . "\n";

        }
        $app_string .= "</application>";



        $doc = new DOMDocument();
        $doc->loadXML($app_string);
        $tmp = DH::findFirstElement('application', $doc);
        print "load appid\n";
        $this->sub->appStore->load_application_custom_from_domxml($tmp);

        //this load all the create custom app-id into XML config file
        $sub_application_xmlroot = DH::findFirstElementorCreate( 'application', $this->sub->xmlroot);

        if( get_class( $this->sub ) == "PanoramaConf" )
            $doc = $this->sub->xmldoc;
        else
            $doc = $this->sub->owner->xmldoc;

        foreach( $tmp->childNodes as $node_xml )
        {
            /** @var DOMElement $childNode */
            if( $node_xml->nodeType != XML_ELEMENT_NODE )
                continue;

            $node = $doc->importNode($node_xml, TRUE);
            $sub_application_xmlroot->appendChild($node);
        }

        #$this->sub->appStore->rewriteXML();
    }

    // convert netmask to cidr
// e.g. 255.255.255.128 = 25
    function netmask2wildcardnetmask($netmask)
    {
        $wildcardnetmask = self::wildcardnetmask2netmask($netmask);

        return $wildcardnetmask;
    }

// convert netmask to cidr
    // e.g. 255.255.255.128 = 25
    function wildcardnetmask2netmask($wildcardnetmask)
    {
        $netmask_array = array();
        $wildcardnetmask = explode(".", $wildcardnetmask);

        foreach( $wildcardnetmask as $key => $octect )
            $netmask_array[] = 255 - intval($octect);

        $netmask = "";
        foreach( $netmask_array as $key => $octet )
        {
            if( $key == 0 )
                $netmask .= $octet;
            else
                $netmask .= "." . $octet;
        }

        return $netmask;
    }
}

