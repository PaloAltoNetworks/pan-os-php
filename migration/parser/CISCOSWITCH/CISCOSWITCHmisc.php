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

trait CISCOSWITCHmisc
{

    function find_net($host, $mask, $reverse = FALSE)
    {
        if( $reverse )
        {

        }

        $broadcast = "";
        ### Function to determine network characteristics
        ### $host = IP address or hostname of target host (string)
        ### $mask = Subnet mask of host in dotted decimal (string)
        ### returns array with
        ###   "cidr"      => host and mask in CIDR notation
        ###   "network"   => network address
        ###   "broadcast" => broadcast address
        ###
        ### Example: find_net("192.168.37.215","255.255.255.224")
        ### returns:
        ###    "cidr"      => 192.168.37.215/27
        ###    "network"   => 192.168.37.192
        ###    "broadcast" => 192.168.37.223
        ###

        //Todo: swaschkut 20210421 reuse existing methods from framework -

        $bits = strpos(decbin(ip2long($mask)), "0");
        $net["cidr"] = gethostbyname($host) . "/" . $bits;

        $net["network"] = long2ip(bindec(decbin(ip2long(gethostbyname($host))) & decbin(ip2long($mask))));

        $binhost = str_pad(decbin(ip2long(gethostbyname($host))), 32, "0", STR_PAD_LEFT);
        $binmask = str_pad(decbin(ip2long($mask)), 32, "0", STR_PAD_LEFT);
        for( $i = 0; $i < 32; $i++ )
        {
            if( substr($binhost, $i, 1) == "1" || substr($binmask, $i, 1) == "0" )
            {
                $broadcast .= "1";
            }
            else
            {
                $broadcast .= "0";
            }
        }
        $net["broadcast"] = long2ip(bindec($broadcast));

        return $net;
    }

    function & addOrGetIPMaskEntry($ip, $mask)
    {
        global $IpMaskTable;

        if( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
        {
            $sanitizedName = str_replace(':', '-', $ip);
            if( $mask == 128 || $mask === null )
                $objName = "H-$sanitizedName";
            else
                $objName = "N-$sanitizedName-$mask";
        }
        else
        {
            if( $mask == 32 || $mask === null )
                $objName = "H-$ip";
            else
                $objName = "N-$ip-$mask";
        }

        if( $mask !== null )
            $value = $ip . '/' . $mask;
        else
            $value = $ip;

        if( !isset($IpMaskTable[$objName]) )
            $IpMaskTable[$objName] = array('type' => 'ip-net', 'name' => $objName, 'value' => "{$value}");

        return $IpMaskTable[$objName];
    }


    function wildcard_reading($object, $rule_array, $ii, $srcdst)
    {
        if( isset($object[$ii]) && isset($object[$ii + 1]) )
        {
            $this->wildcard = TRUE;

            if( $object[$ii + 1] == 'log' || $object[$ii + 1] == 'eq' )
            {
                $tmp_array = explode("/", $object[$ii]);
                $net['cidr'] = $object[$ii];
            }
            else
            {
                $second_value = $object[$ii + 1];
                $net = $this->find_net($object[$ii], $second_value);
                $net = $this->find_net($object[$ii], $net['broadcast']);
            }


            if( substr($net['cidr'], -1) == "/" )
            {
                #print "Wildcard2: ".$object[$ii]."|".$object[$ii+1]."-".$net['cidr']."\n";
                mwarning("network and netmask calcaluation wrong: check network|" . $object[$ii] . "|" . $object[$ii + 1] . "-" . $net['cidr'], null, FALSE);
                $rule_array[$srcdst] = $net['cidr'];
            }
            else
            {
                $rule_array[$srcdst] = $net['cidr'];
            }

            #continue;
            #derr( 'not supported: '.$object[$ii] );

            $ii++;
            $ii++;

            return array($rule_array, $ii);
        }
    }

    function service_reading($object, $rule_array, $ii, $src_dst_port = 'srv')
    {


        if( isset($object[0]) )
            $keyToCheckforsrv = 1;
        else
            $keyToCheckforsrv = 2;


        if( $object[$keyToCheckforsrv] == "tcp" || $object[$keyToCheckforsrv] == 'udp' )
            $protocol = $object[$keyToCheckforsrv] . "|";

        if( isset($object[$ii]) && ($object[$ii] == "eq" || $object[$ii] == "neq") )
        {
            if( $object[$ii] == "neq" )
            {
                if( $src_dst_port == 'srv' )
                {
                    $rule_array['service-negate'] = TRUE;
                    derr("service operator NEQ - not possible with pan-os | change to deny rule and add and allow rule below\n");
                    $this->print_rule_array = TRUE;
                }
                else
                {
                    $this->print_rule_array = TRUE;
                    derr("negate for source service port not implemented.");
                }


            }

            $ii++;
            if( is_numeric($object[$ii]) )
            {
                $rule_array[$src_dst_port] = $protocol . $object[$ii];
            }
            else
            {
                if( isset($this->svcReplaceByOther[$object[$ii]][0]) )
                    $rule_array[$src_dst_port] = $protocol . $this->svcReplaceByOther[$object[$ii]][0];
                else
                {
                    mwarning('add service-port for: |' . $object[$ii] . "|");
                }

            }

            $ii++;
        }
        elseif( isset($object[$ii]) && $object[$ii] == "range" )
        {
            $ii++;
            if( is_numeric($object[$ii]) )
            {
                if( is_numeric($object[$ii + 1]) )
                    $rule_array[$src_dst_port] = $protocol . $object[$ii] . "-" . $object[$ii + 1];
                else
                {
                    if( isset($this->svcReplaceByOther[$object[$ii + 1]][0]) )
                        $rule_array[$src_dst_port] = $protocol . $object[$ii] . "-" . $this->svcReplaceByOther[$object[$ii + 1]][0];
                    else
                    {
                        mwarning('add service-port for: |' . $object[$ii + 1] . "|");
                    }
                }
            }
            else
            {
                if( isset($this->svcReplaceByOther[$object[$ii]][0]) )
                {
                    if( is_numeric($object[$ii + 1]) )
                        $rule_array[$src_dst_port] = $protocol . $this->svcReplaceByOther[$object[$ii]][0] . "-" . $object[$ii + 1];
                    else
                    {
                        if( isset($this->svcReplaceByOther[$object[$ii + 1]][0]) )
                            $rule_array[$src_dst_port] = $protocol . $this->svcReplaceByOther[$object[$ii]][0] . "-" . $this->svcReplaceByOther[$object[$ii + 1]][0];
                        else
                        {
                            derr('add service-port for: |' . $object[$ii + 1] . "|");
                        }
                    }
                }
                else
                {
                    derr('add service-port for: |' . $object[$ii] . "|");
                }

            }


            $ii++;
            $ii++;
        }
        elseif( isset($object[$ii]) && $object[$ii] == "gt" )
        {
            $ii++;
            if( is_numeric($object[$ii]) )
            {
                $rule_array[$src_dst_port] = $protocol . (intval($object[$ii]) + 1) . "-65535";
            }
            else
            {
                if( isset($this->svcReplaceByOther[$object[$ii]][0]) )
                    $rule_array[$src_dst_port] = $protocol . (intval($this->svcReplaceByOther[$object[$ii]][0]) + 1) . "-65535";
                else
                {
                    derr('add service-port for: |' . $object[$ii] . "|");
                }

            }
            $ii++;

            #$this->print_rule_array = true;
        }
        elseif( isset($object[$ii]) && $object[$ii] == "lt" )
        {
            $ii++;
            if( is_numeric($object[$ii]) )
            {
                $rule_array[$src_dst_port] = $protocol . "1-" . (intval($object[$ii]) - 1);
            }
            else
            {
                if( isset($this->svcReplaceByOther[$object[$ii]][0]) )
                    $rule_array[$src_dst_port] = $protocol . "1-" . (intval($this->svcReplaceByOther[$object[$ii]][0]) - 1);
                else
                {
                    derr('add service-port for: |' . $object[$ii] . "|");
                }

            }
            $ii++;

            #$this->print_rule_array = true;
        }
        else
        {
            $tmp_array = $this->wildcard_reading($object, $rule_array, $ii, 'dst');

            $rule_array = $tmp_array[0];
            $ii = $tmp_array[1];
        }

        return array($rule_array, $ii);
    }

    function dst_reading($object, $rule_array, $ii)
    {

        if( isset($object[$ii]) && $object[$ii] == "any" )
        {
            //any => DST: any
            //[3]
            $rule_array['dst'] = $object[$ii];
            $ii++;//4
        }
        elseif( isset($object[$ii]) && $object[$ii] == "host" )
        {
            //host ip => [5]
            $ii++;
            $rule_array['dst'] = $object[$ii];
            $ii++;//7
        }
        elseif( isset($object[$ii]) && ($object[$ii] == "eq" || $object[$ii] == "gt" || $object[$ii] == "lt" || $object[$ii] == "range") || $object[$ii] == "neq" )
        {
            $tmp_array = service_reading($object, $rule_array, $ii);
            $rule_array = $tmp_array[0];
            $ii = $tmp_array[1];
        }
        else
        {
            $tmp_array = $this->wildcard_reading($object, $rule_array, $ii, 'dst');

            $rule_array = $tmp_array[0];
            $ii = $tmp_array[1];

            /*
            #print_r($object);
            #print "ii:|".$ii."|\n";
            if( $ii == "" )
                mwarning( "NOT SET" , null, false);
            $rule_array['dst'] = $object[$ii];
            $ii++;//4
            */
        }

        return array($rule_array, $ii);
    }


}