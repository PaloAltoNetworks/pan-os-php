<?php

trait InterfaceType
{
    public function isEthernetType()
    {
        return FALSE;
    }

    public function isIPsecTunnelType()
    {
        return FALSE;
    }

    public function isAggregateType()
    {
        return FALSE;
    }

    public function isTmpType()
    {
        return FALSE;
    }

    public function isLoopbackType()
    {
        return FALSE;
    }

    public function isTunnelType()
    {
        return FALSE;
    }

    public function isVlanType()
    {
        return FALSE;
    }

    public $importedByVSYS = null;


    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return bool
     */
    public function addIPv4Address($ip)
    {
        foreach( $this->getIPv4Addresses() as $IPv4Address )
        {
            if( $IPv4Address == $ip )
                return TRUE;
        }

        if( strpos($ip, "/") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());

            if( is_object($tmp_vsys) )
                $object = $tmp_vsys->addressStore->find($ip);
            else
                return FALSE;

            if( is_object($object) )
                $object->addReference($this);
            else
                derr("objectname: " . $ip . " not found. Can not be added to interface.\n", $this);
        }


        $this->_ipv4Addresses[] = $ip;

        $tmp_xmlroot = $this->xmlroot;

        $ipNode = DH::findFirstElementOrCreate('ip', $tmp_xmlroot);

        $tmp_ipaddress = DH::createElement($ipNode, 'entry', "");
        $tmp_ipaddress->setAttribute('name', $ip);

        $ipNode->appendChild($tmp_ipaddress);

        return TRUE;
    }

    /**
     * Add a ip to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_addIPv4Address($ip)
    {
        $ret = $this->addIPv4Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            $xpath .= '/ip';

            $con->sendSetRequest($xpath, "<entry name='{$ip}'/>");
        }

        return $ret;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return bool
     */
    public function removeIPv4Address($ip)
    {
        $tmp_IPv4 = array();
        foreach( $this->getIPv4Addresses() as $key => $IPv4Address )
        {
            $tmp_IPv4[$IPv4Address] = $IPv4Address;
            if( $IPv4Address == $ip )
                unset($this->_ipv4Addresses[$key]);
        }

        if( !array_key_exists($ip, $tmp_IPv4) )
        {
            PH::print_stdout(  " ** skipped ** IP Address: " . $ip . " is not set on interface: " . $this->name() );
            return FALSE;
        }

        if( strpos($ip, "/") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());

            if( is_object($tmp_vsys) )
                $object = $tmp_vsys->addressStore->find($ip);
            else
                return FALSE;

            if( is_object($object) )
                $object->removeReference($this);
            else
                mwarning("objectname: " . $ip . " not found. Can not be removed from interface.\n", $this);
        }

        $tmp_xmlroot = $this->xmlroot;

        $ipNode = DH::findFirstElementOrCreate('ip', $tmp_xmlroot);

        $tmp_ipaddress = DH::findFirstElementByNameAttrOrDie('entry', $ip, $ipNode);
        $ipNode->removeChild($tmp_ipaddress);

        return TRUE;
    }

    /**
     * remove a ip address to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_removeIPv4Address($ip)
    {
        $ret = $this->removeIPv4Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            $xpath .= '/ip';

            $con->sendDeleteRequest($xpath . "/entry[@name='{$ip}']");
        }

        return $ret;
    }
}