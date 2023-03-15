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

/**
 * Class IPsecTunnelStore
 * @property $o IPsecTunnel[]
 * @property PANConf $owner
 */
class IPsecTunnelStore extends ObjStore
{
    public $owner;

    protected $_tunnels = array();

    public static $childn = 'IPsecTunnel';

    protected $fastMemToIndex = null;
    protected $fastNameToIndex = null;

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return IPsecTunnel[]
     */
    public function tunnels()
    {
        return $this->o;
    }


    /**
     * @return IPsecTunnel[]
     */
    public function getInterfaces()
    {
        return $this->o;
    }

    /**
     * Creates a new IPsecTunnel in this store. It will be placed at the end of the list.
     * @param string $name name of the new IPsecTunnel
     * @return IPsecTunnel
     */
    public function newIPsecTunnel($name)
    {
        $tunnel = new IPsecTunnel($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, IPsecTunnel::$templatexml);

        $tunnel->load_from_domxml($xmlElement);

        $this->_tunnels[] = $tunnel;

        $tunnel->owner = null;
        $tunnel->setName($name);

        $this->addIPsecTunnel($tunnel);

        return $tunnel;
    }


    /**
     * @param IKEGateway $gateway
     * @return bool
     */
    public function addIPsecTunnel($tunnel)
    {
        if( !is_object($tunnel) )
            derr('this function only accepts IPsecTunnel class objects');

        if( $tunnel->owner !== null )
            derr('Trying to add a tunnel that has a owner already !');


        $ser = spl_object_hash($tunnel);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $tunnel->owner = $this;

            $this->_tunnels[] = $tunnel;
            $index = lastIndex($this->_tunnels);
            $this->fastMemToIndex[$ser] = $index;
            $this->fastNameToIndex[$tunnel->name()] = $index;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($tunnel->xmlroot);

            $ret = $this->add($tunnel);

            return TRUE;
        }
        else
            derr('You cannot add a Tunnel that is already here :)');

        return FALSE;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            //TODO: 20180331 why I need to create full path? why it is not set before???
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);
            $xml = DH::findFirstElementOrCreate('tunnel', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('ipsec', $xml);
        }
    }

    /**
     * @param $IPSecTunnelName string
     * @return null|IPsecTunnel
     */
    public function findIpsecTunnel($IPSecTunnelName)
    {
        return $this->findByName($IPSecTunnelName);
    }

} 