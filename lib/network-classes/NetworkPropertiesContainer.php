<?php


class NetworkPropertiesContainer
{
    use PathableName;

    /** @var PANConf|PanoramaConf */
    public $owner;

    /** @var EthernetIfStore */
    public $ethernetIfStore;

    /** @var AggregateEthernetIfStore */
    public $aggregateEthernetIfStore;

    /** @var IPsecTunnelStore */
    public $ipsecTunnelStore;

    /** @var LoopbackIfStore */
    public $loopbackIfStore;

    /** @var TmpInterfaceStore */
    public $tmpInterfaceStore;

    /** @var VirtualRouterStore */
    public $virtualRouterStore;

    /** @var IkeCryptoProfileStore */
    public $ikeCryptoProfileStore;

    /** @var IPSecCryptoProfileStore */
    public $ipsecCryptoProfileStore;

    /** @var ikeGatewayStore */
    public $ikeGatewayStore;

    /** @var vlanIfStore */
    public $vlanIfStore;

    /** @var tunnelIfStore */
    public $tunnelIfStore;

    /** @var virtualWireStore */
    public $virtualWireStore;

    /** @var DOMElement|null */
    public $xmlroot = null;


    /**
     * NetworkPropertiesContainer constructor.
     * @param PANConf|PanoramaConf $owner
     */
    function __construct($owner)
    {
        $this->owner = $owner;
        $this->ethernetIfStore = new EthernetIfStore('EthernetIfaces', $owner);
        $this->aggregateEthernetIfStore = new AggregateEthernetIfStore('AggregateEthernetIfaces', $owner);
        $this->loopbackIfStore = new LoopbackIfStore('LoopbackIfaces', $owner);
        $this->ipsecTunnelStore = new IPsecTunnelStore('IPsecTunnels', $owner);
        $this->greTunnelStore = new GreTunnelStore('GreTunnels', $owner);
        $this->tmpInterfaceStore = new TmpInterfaceStore('TmpIfaces', $owner);
        $this->virtualRouterStore = new VirtualRouterStore('', $owner);
        $this->ikeCryptoProfileStore = new IkeCryptoProfileStore('IkeCryptoProfiles', $owner);
        $this->ipsecCryptoProfileStore = new IPSecCryptoProfileStore('IPSecCryptoProfiles', $owner);
        $this->ikeGatewayStore = new IKEGatewayStore('IkeGateways', $owner);
        $this->vlanIfStore = new VlanIfStore('VlanIfaces', $owner);
        $this->tunnelIfStore = new TunnelIfStore('TunnelIfaces', $owner);
        $this->virtualWireStore = new VirtualWireStore('', $owner);
        $this->dhcpStore = new DHCPStore('DHCP', $owner);
    }

    function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;


        $xmlInterface = DH::findFirstElementOrCreate('interface', $this->xmlroot);
        $tmp = DH::findFirstElement('ethernet', $xmlInterface);
        if( $tmp !== FALSE )
            $this->ethernetIfStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElement('aggregate-ethernet', $xmlInterface);
        if( $tmp !== FALSE )
            $this->aggregateEthernetIfStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElement('loopback', $xmlInterface);
        if( $tmp !== FALSE )
        {
            $tmp = DH::findFirstElement('units', $tmp);
            if( $tmp !== FALSE )
                $this->loopbackIfStore->load_from_domxml($tmp);
        }

        $tmp = DH::findFirstElement('vlan', $xmlInterface);
        if( $tmp !== FALSE )
        {
            $tmp = DH::findFirstElement('units', $tmp);
            if( $tmp !== FALSE )
                $this->vlanIfStore->load_from_domxml($tmp);
        }

        $tmp = DH::findFirstElement('tunnel', $xmlInterface);
        if( $tmp !== FALSE )
        {
            $tmp = DH::findFirstElement('units', $tmp);
            if( $tmp !== FALSE )
                $this->tunnelIfStore->load_from_domxml($tmp);
        }


        $tmp = DH::findFirstElement('virtual-router', $this->xmlroot);
        if( $tmp !== FALSE )
            $this->virtualRouterStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElement('virtual-wire', $this->xmlroot);
        if( $tmp !== FALSE )
            $this->virtualWireStore->load_from_domxml($tmp);

        $tmp = DH::findFirstElement('dhcp', $this->xmlroot);
        if( $tmp !== FALSE )
        {
            $tmp = DH::findFirstElement('interface', $tmp);
            if( $tmp !== FALSE )
                $this->dhcpStore->load_from_domxml($tmp);
        }


    }

    function load_from_domxml_2(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $tmp = DH::findFirstElement('ike', $this->xmlroot);
        if( $tmp !== FALSE )
        {
            $tmp_crypto = DH::findFirstElementOrCreate('crypto-profiles', $tmp);
            if( $tmp_crypto !== FALSE )
            {
                $tmp_ike = DH::findFirstElement('ike-crypto-profiles', $tmp_crypto);
                if( $tmp_ike !== FALSE )
                {
                    $this->ikeCryptoProfileStore->load_from_domxml($tmp_ike);
                }

                $tmp_ipsec = DH::findFirstElement('ipsec-crypto-profiles', $tmp_crypto);
                if( $tmp_ipsec !== FALSE )
                {
                    $this->ipsecCryptoProfileStore->load_from_domxml($tmp_ipsec);
                }
            }

            $tmp2 = DH::findFirstElementOrCreate('gateway', $tmp);
            if( $tmp2 !== FALSE )
            {
                $this->ikeGatewayStore->load_from_domxml($tmp2);
            }
        }
        $tmp = DH::findFirstElement('tunnel', $this->xmlroot);
        if( $tmp !== FALSE )
        {
            $tmp1 = DH::findFirstElement('ipsec', $tmp);
            if( $tmp1 !== FALSE )
                $this->ipsecTunnelStore->load_from_domxml($tmp1);

            $tmp1 = DH::findFirstElement('gre', $tmp);
            if( $tmp1 !== FALSE )
                $this->greTunnelStore->load_from_domxml($tmp1);
        }
    }


    /**
     * @return EthernetInterface[]|IPsecTunnel[]|LoopbackInterface[]|AggregateEthernetInterface[]|TmpInterface[]|VlanInterface[]
     */
    function getAllInterfaces()
    {
        $ifs = array();

        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->loopbackIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->ipsecTunnelStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->greTunnelStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->vlanIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->tunnelIfStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        foreach( $this->tmpInterfaceStore->getInterfaces() as $if )
            $ifs[$if->name()] = $if;

        return $ifs;
    }

    public function count()
    {
        $tmpcount = $this->getAllInterfaces();
        return count($tmpcount);
    }
    /**
     * @param string $interfaceName
     * @return EthernetInterface|IPsecTunnel|TmpInterface|VlanInterface|TunnelInterface|LoopbackInterface|GreTunnel|null
     */
    function findInterface($interfaceName)
    {
        foreach( $this->ethernetIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->loopbackIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->ipsecTunnelStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->vlanIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->tunnelIfStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        foreach( $this->tmpInterfaceStore->getInterfaces() as $if )
            if( $if->name() == $interfaceName )
                return $if;

        return null;
    }

    /**
     * Convenient alias to findInterface
     * @param string $interfaceName
     * @return EthernetInterface|IPsecTunnel|TmpInterface|VlanInterface|null
     */
    public function find($interfaceName)
    {
        return $this->findInterface($interfaceName);
    }


    /**
     * @param string $interfaceName
     * @return null|VirtualSystem
     */
    function findVsysInterfaceOwner($interfaceName)
    {
        foreach( $this->owner->virtualSystems as $vsys )
        {
            if( $vsys->importedInterfaces->hasInterfaceNamed($interfaceName) )
                return $vsys;
        }

        return null;
    }

    /**
     * @param string $interfaceName
     * @return EthernetInterface|IPsecTunnel|TmpInterface|ReferenceableObject
     */
    function findInterfaceOrCreateTmp($interfaceName)
    {
        $resolved = $this->findInterface($interfaceName);

        if( $resolved !== null )
            return $resolved;

        $tmp_interface = $this->tmpInterfaceStore->createTmp($interfaceName);

        return $tmp_interface;
    }

    /**
     * @param string $ip
     * @return EthernetInterface[]|IPsecTunnel[]|LoopbackInterface[]|AggregateEthernetInterface[]
     */
    function findInterfacesNetworkMatchingIP($ip)
    {
        $ifs = array();

        foreach( $this->ethernetIfStore->getInterfaces() as $if )
        {
            if( $if->type() == 'layer3' )
            {
                $ipAddresses = $if->getLayer3IPv4Addresses();
                foreach( $ipAddresses as $ipAddress )
                {
                    if( cidr::netMatch($ip, $ipAddress) > 0 )
                    {
                        $ifs[] = $if;
                        break;
                    }
                }
            }
        }

        foreach( $this->aggregateEthernetIfStore->getInterfaces() as $if )
        {
            if( $if->type() == 'layer3' )
            {
                $ipAddresses = $if->getLayer3IPv4Addresses();
                foreach( $ipAddresses as $ipAddress )
                {
                    if( cidr::netMatch($ip, $ipAddress) > 0 )
                    {
                        $ifs[] = $if;
                        break;
                    }
                }
            }
        }

        foreach( $this->loopbackIfStore->getInterfaces() as $if )
        {
            $ipAddresses = $if->getIPv4Addresses();
            foreach( $ipAddresses as $ipAddress )
            {
                if( cidr::netMatch($ip, $ipAddress) > 0 )
                {
                    $ifs[] = $if;
                    break;
                }
            }
        }


        foreach( $this->vlanIfStore->getInterfaces() as $if )
        {
            $ipAddresses = $if->getIPv4Addresses();
            foreach( $ipAddresses as $ipAddress )
            {
                if( cidr::netMatch($ip, $ipAddress) > 0 )
                {
                    $ifs[] = $if;
                    break;
                }
            }
        }

        foreach( $this->tunnelIfStore->getInterfaces() as $if )
        {
            $ipAddresses = $if->getIPv4Addresses();
            foreach( $ipAddresses as $ipAddress )
            {
                if( cidr::netMatch($ip, $ipAddress) > 0 )
                {
                    $ifs[] = $if;
                    break;
                }
            }
        }


        return $ifs;
    }

}

