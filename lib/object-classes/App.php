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


class App
{

    use ReferenceableObject;
    use PathableName;

    public $type = 'tmp';

    public $tcp = null;
    public $udp = null;
    public $icmp = null;
    public $icmp6 = null;

    public $tcp_secure = null;
    public $udp_secure = null;
    public $icmp_secure = null;
    public $icmp6_secure = null;

    public $icmpsub = null;
    public $icmp6sub = null;
    public $icmpcode = null;
    public $icmp6code = null;
    public $proto = null;

    public $timeout = null;
    public $tcp_timeout = null;
    public $udp_timeout = null;
    public $tcp_half_closed_timeout = null;
    public $tcp_time_wait_timeout = null;

    /** @var null|array */
    public $app_filter_details = null;

    /** @var null|string */
    public $category = null;
    /** @var null|string */
    public $subCategory = null;
    /** @var null|string */
    public $technology = null;
    /** @var null|string */
    public $risk = null;

    /** @var bool */
    public $virusident = FALSE;
    /** @var bool */
    public $filetypeident = FALSE;
    /** @var bool */
    public $fileforward = FALSE;

    /** @var bool */
    public $custom_signature = FALSE;

    /** @var string[] */
    public $_characteristics = array();

    static public $_supportedCharacteristics = array(
        'evasive' => 'evasive',
        'excessive-bandwidth' => 'excessive-bandwidth',
        'prone-to-misuse' => 'prone-to-misuse',
        'saas' => 'saas',
        'transfers-files' => 'transfers-files',
        'tunnels-other-apps' => 'tunnels-other-apps',
        'used-by-malware' => 'used-by-malware',
        'vulnerabilities' => 'vulnerabilities',
        'widely-used' => 'widely-used'
    );

    //public $type = 'notfound';

    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;

        foreach( self::$_supportedCharacteristics as $characteristicName )
            $this->_characteristics[$characteristicName] = FALSE;
    }

    public function isUsingSpecialProto()
    {

        if( $this->isContainer() )
        {
            foreach( $this->subapps as $app )
            {
                if( $app->isUsingSpecialProto() )
                    return TRUE;
            }
            return FALSE;
        }

        if( $this->proto === null && $this->icmp === null && $this->icmpsub === null )
            return FALSE;

        return TRUE;
    }

    public function isContainer()
    {
        if( isset($this->subapps) )
            return TRUE;

        return FALSE;
    }

    public function containerApps()
    {
        if( !$this->isContainer() )
            derr('cannot be be called on a non container app');

        return $this->subapps;
    }

    /**
     * returns true if application is using dynamic ports
     * @return bool
     */
    public function useDynamicPorts()
    {

        if( $this->isContainer() )
        {
            foreach( $this->subapps as $app )
            {
                if( $app->useDynamicPorts() )
                    return TRUE;
            }
            return FALSE;
        }

        if( $this->tcp !== null )
        {
            foreach( $this->tcp as &$port )
            {
                if( $port[0] == 'dynamic' )
                    return TRUE;
            }
        }

        if( $this->udp !== null )
        {
            foreach( $this->udp as &$port )
            {
                if( $port[0] == 'dynamic' )
                    return TRUE;
            }
        }

        return FALSE;
    }

    public function matchPort($proto, $port)
    {

        if( $this->isContainer() )
        {
            foreach( $this->subapps as $app )
            {
                if( $app->matchPort($proto, $port) )
                    return TRUE;
            }
            return FALSE;
        }

        if( $proto === null || $port === null )
            derr('cannot be called with null arguments');

        if( $proto != 'tcp' && $proto != 'udp' )
            derr('unsupported procotol : ' . $proto);

        if( $this->$proto !== null )
        {
            foreach( $this->$proto as &$lport )
            {
                if( $lport[0] == 'single' && $lport[1] == $port )
                    return TRUE;
                if( $lport[0] == 'range' && $port >= $lport[1] && $port <= $lport[2] )
                    return TRUE;
            }
        }

        return FALSE;
    }

    /**
     * will return a list of dependencies and remove the 'implicit' ones
     * @return App[]
     */
    public function &calculateDependencies()
    {
        $ret = array();

        if( isset($this->explicitUse) )
            $plus = $this->explicitUse;
        else
            $plus = array();

        if( !isset($this->implicitUse) )
            return $plus;

        foreach( $plus as $plusApp )
        {
            $found = FALSE;
            foreach( $this->implicitUse as $implApp )
            {
                if( $implApp === $plusApp )
                {
                    $found = TRUE;
                    break;
                }
            }
            if( !$found )
                $ret[] = $plusApp;
        }

        return $ret;
    }

    public function isApplicationCustom()
    {
        if( $this->type == 'application-custom' )
            return TRUE;

        return FALSE;
    }

    public function isApplicationGroup()
    {
        if( $this->type == 'application-group' )
            return TRUE;

        return FALSE;
    }

    public function isApplicationFilter()
    {
        if( $this->type == 'application-filter' )
            return TRUE;

        return FALSE;
    }

    public function isTmp()
    {
        if( $this->type == 'tmp' )
            return TRUE;

        return FALSE;
    }

    public function isPredefined()
    {
        if( $this->type == 'predefined' )
            return TRUE;

        return FALSE;
    }

    public function type()
    {
        return $this->type;
    }

    public function CustomHasSignature()
    {
        if( $this->isApplicationCustom() )
            if( $this->custom_signature )
                return TRUE;

        return FALSE;
    }

    function print_appdetails( $padding_above, $printName = true, &$subarray = array()  )
    {
        global $print_explicit;
        global $print_implicit;

        $padding = 30;
        $padding_10 = "          ";

        $text = "";
        if( $printName )
        {
            PH::print_stdout("");
            $text .= $padding_above . " - " . str_pad(PH::boldText($this->name()), $padding) . " - ";
        }
        $subarray[$this->name()]['name'] = $this->name();


        if( isset($this->obsolete) )
        {
            $text .= $padding_above . "  - (obsolete) ";
            $subarray[$this->name()]['obsolete'] = "true";
        }


        if( isset($this->category) )
        {
            $text .= $padding_above . "  - category|" . str_pad($this->category, $padding) . " - ";
            $subarray[$this->name()]['category'] = $this->category;
        }


        if( isset($this->subCategory) )
        {
            $text .= "subcategory|" . str_pad($this->subCategory, $padding) . " - ";
            $subarray[$this->name()]['subcategory'] = $this->subCategory;
        }


        if( isset($this->technology) )
        {
            $text .= "technology|" . str_pad($this->technology, $padding) . " - ";
            $subarray[$this->name()]['technology'] = $this->technology;
        }

        if( isset($this->risk) )
        {
            $text .= "risk|" . $this->risk . " - ";
            $subarray[$this->name()]['risk'] = $this->risk;
        }


        PH::print_stdout($text);

        $text_tcp = "";
        if( isset($this->tcp) )
        {
            $text_tcp = $padding_10 . "tcp/";
            foreach( $this->tcp as $tcp )
            {
                if( $tcp[0] == "single" )
                    $text_tcp .= $tcp[1] . ",";
                elseif( $tcp[0] == "dynamic" )
                    $text_tcp .= "dynamic";
                elseif( $tcp[0] == "range" )
                    $text_tcp .= $tcp[1] . "-" . $tcp[2] . ",";
                else
                    $text_tcp .= "implode:" . implode("','", $tcp) . "";
            }
            $subarray[$this->name()]['tcp'] = $text_tcp;
        }
        $text_udp = "";
        if( isset($this->udp) )
        {
            $text_udp = $padding_10 . "udp/";
            foreach( $this->udp as $udp )
            {
                if( $udp[0] == "single" )
                    $text_udp .= $udp[1] . ",";
                elseif( $udp[0] == "dynamic" )
                    $text_udp .= "dynamic";
                elseif( $udp[0] == "range" )
                    $text_udp .= $udp[1] . "-" . $udp[2] . ",";
                else
                    $text_udp .= "implode:" . implode("','", $udp) . "";
            }
            $subarray[$this->name()]['udp'] = $text_udp;
        }
        PH::print_stdout($text_tcp . $text_udp);

        //secure ports:
        $text_tcp = "";
        if( isset($this->tcp_secure) )
        {
            $text_tcp .= $padding_10 . "secure - tcp/";
            foreach( $this->tcp_secure as $tcp )
            {
                if( $tcp[0] == "single" )
                    $text_tcp .= $tcp[1] . ",";
                elseif( $tcp[0] == "dynamic" )
                    $text_tcp .= "dynamic";
                elseif( $tcp[0] == "range" )
                    $text_tcp .= $tcp[1] . "-" . $tcp[2] . ",";
                else
                    $text_tcp .= "implode:" . implode("','", $tcp) . "";
            }
            $subarray[$this->name()]['tcpsecure'] = $text_tcp;
        }
        $text_udp = "";
        if( isset($this->udp_secure) )
        {
            $text_udp .= $padding_10 . "secure - udp/";
            foreach( $this->udp_secure as $udp )
            {
                if( $udp[0] == "single" )
                    $text_udp .= $udp[1] . ",";
                elseif( $udp[0] == "dynamic" )
                    $text_udp .= "dynamic";
                elseif( $udp[0] == "range" )
                    $text_udp .= $udp[1] . "-" . $udp[2] . ",";
                else
                    $text_udp .= "implode:" . implode("','", $udp) . "";
            }
            $subarray[$this->name()]['udpsecure'] = $text_udp;
        }
        PH::print_stdout($text_tcp . $text_udp);

        if( $this->proto != "" )
        {
            PH::print_stdout($padding_10 . "IP-Protocol: '" . $this->proto . "'");
            $subarray[$this->name()]['ipprotocol'] = $this->proto;
        }


        $text = "";
        if( isset($this->timeout) )
        {
            $text .= $padding_10 . "timeout|" . $this->timeout . " - ";
            $subarray[$this->name()]['timeout'] = $this->timeout;
        }

        if( isset($this->tcp_timeout) )
        {
            $text .= $padding_10 . "tcp-timeout|" . $this->tcp_timeout . " - ";
            $subarray[$this->name()]['tcp-timeout'] = $this->tcp_timeout;
        }
        if( isset($this->tcp_half_closed_timeout) )
        {
            $text .= $padding_10 . "tcp-half-closed-timeout|" . $this->tcp_half_closed_timeout . " - ";
            $subarray[$this->name()]['tcp-half-closed-timeout'] = $this->tcp_half_closed_timeout;
        }
        if( isset( $this->tcp_time_wait_timeout ) )
        {
            $text .= $padding_10."tcp-time-wait-timeout|".$this->tcp_time_wait_timeout . " - ";
            $subarray[$this->name()]['tcp-time-wait-timeout'] = $this->tcp_time_wait_timeout;
        }
        if( isset( $this->udp_timeout ) )
        {
            $text .= $padding_10."udp-timeout|".$this->udp_timeout . " - ";
            $subarray[$this->name()]['udp-timeout'] = $this->udp_timeout;
        }
            
        PH::print_stdout($text);

        if( isset( $this->explicitUse ) && $print_explicit )
        {
            foreach( $this->explicitUse as $app1 )
            {
                PH::print_stdout( "           explicit->" . $app1->type . " | " );

                $tmparray = array();
                $app1->print_appdetails( $padding_above, true, $tmparray );
                $subarray['implicit'][] = $tmparray;
            }
        }

        if( isset( $this->implicitUse ) && $print_implicit )
        {
            foreach( $this->implicitUse as $app2 )
            {
                PH::print_stdout( "           implicit->" . $app2->type . " | " );

                $tmparray = array();
                $app2->print_appdetails( $padding_above, true, $tmparray );
                $subarray['implicit'][] = $tmparray;
            }
        }

        if( isset( $this->icmpsub )  )
        {
            PH::print_stdout( "               icmp type: ". $this->icmpsub );
            $subarray[$this->name()]['icmp'] = $this->icmpsub;
        }
        if( isset( $this->icmp6sub )  )
        {
            PH::print_stdout( "               icmpv6 type: ". $this->icmp6sub );
            $subarray[$this->name()]['icmpv6'] = $this->icmp6sub;
        }
        if( isset( $this->icmpcode )  )
        {
            PH::print_stdout( "               icmp code: ". $this->icmpcode );
            $subarray[$this->name()]['icmpcode'] = $this->icmpcode;
        }
        if( isset( $this->icmp6code )  )
        {
            PH::print_stdout( "               icmpv6 code: ". $this->icmp6code );
            $subarray[$this->name()]['icmpv6code'] = $this->icmp6code;
        }
        /*
            if( isset($app->_characteristics) )
            {
                #PH::print_stdout(  PH::list_to_string($app->_characteristics) );
                print_r( $app->_characteristics );
            }
        */

        if( isset($this->tmp_details) )
        {
            PH::print_stdout( "TMP details: -" );
            print_r( $this->tmp_details );
            derr('check');
        }



        if( $this->type == 'application-group' )
        {
            if( isset( $this->groupapps ) )
            {
                foreach( $this->groupapps as $tmpapp)
                {
                    $tmparray = array();
                    $tmpapp->print_appdetails( $padding_above, true, $tmparray );
                    $subarray['application-group'][] = $tmparray;
                }

            }
        }
    }
}


