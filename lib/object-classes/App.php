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

    public function isCustom()
    {
        if( $this->type == 'application-custom' )
            return TRUE;

        return FALSE;
    }

    public function CustomHasSignature()
    {
        if( $this->isCustom() )
            if( $this->custom_signature )
                return TRUE;

        return FALSE;
    }
}


