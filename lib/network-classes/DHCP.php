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

class DHCP
{
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    /** @var DHCPStore */
    public $owner;
    public $server_leases = array();
    public $server_ip_pool = array();
    public $relay_ipv4 = array();
    public $relay_ipv6 = array();
    public $relay_ipv4_status = false;
    public $relay_ipv6_status = false;

    /**
     * @param $name string
     * @param $owner DHCPStore
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("DHCP name not found\n");

        #$interface = $this->owner->owner->network->findInterface( $this->name );
        $interface = $this->owner->owner->network->findInterfaceOrCreateTmp( $this->name );
        if( $interface !==  null )
            $interface->addReference( $this );
        else
            mwarning( "interface with name: ".$this->name." can not be found for DHCP: ".$this->name." | ".$this->owner->owner->_PANC_shortName(), null, FALSE );

        ///todo: update interface list - to correctly show all interfaces

        $tmp_server = DH::findFirstElement("server", $xml);
        if( $tmp_server !== false )
        {
            $tmp_reserved = DH::findFirstElement("reserved", $tmp_server);
            if( $tmp_reserved !== false )
            {
                foreach( $tmp_reserved->childNodes as $entry )
                {
                    if( $entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_IP = DH::findAttribute('name', $entry);
                    $tmp_mac_xml = DH::findFirstElement("mac", $entry);
                    if( $tmp_mac_xml !== False )
                    {
                        $tmp_mac = $tmp_mac_xml->textContent;

                        $this->server_leases[] = array( 'ip' => $tmp_IP, 'mac' => $tmp_mac );
                    }
                }
            }

            $tmp_ip_pool = DH::findFirstElement("ip-pool", $tmp_server);
            if( $tmp_ip_pool !== false )
            {
                foreach( $tmp_ip_pool->childNodes as $entry )
                {
                    if( $entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->server_ip_pool[] = $entry->textContent;
                }
            }
                /*
              <option>
               <lease>
                <unlimited/>
               </lease>
              </option>
              <mode>auto</mode>
             */
        }
        $tmp_relay = DH::findFirstElement("relay", $xml);
        if( $tmp_relay !== false )
        {
            $tmp_relay_ipv4 = DH::findFirstElement("ip", $tmp_relay);
            if( $tmp_relay_ipv4 !== false )
            {
                $tmp_enabled = DH::findFirstElement("enabled", $tmp_relay_ipv4);
                if( $tmp_enabled->textContent == "yes" )
                    $this->relay_ipv4_status = true;

                $tmp_server = DH::findFirstElement("server", $tmp_relay_ipv4);
                if( $tmp_server !== false )
                {
                    foreach( $tmp_server->childNodes as $entry )
                    {
                        if( $entry->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $this->relay_ipv4[] = $entry->textContent;
                    }
                }
            }
            $tmp_relay_ipv6 = DH::findFirstElement("ipv6", $tmp_relay);
            if( $tmp_relay_ipv6 !== false )
            {
                $tmp_enabled = DH::findFirstElement("enabled", $tmp_relay_ipv6);
                if( $tmp_enabled->textContent == "yes" )
                    $this->relay_ipv6_status = true;

                $tmp_server = DH::findFirstElement("server", $tmp_relay_ipv6);
                if( $tmp_server !== false )
                {
                    foreach( $tmp_server->childNodes as $entry )
                    {
                        if( $entry->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $this->relay_ipv6[] = $entry->textContent;
                    }
                }
            }
        }
    }

    /**
     * return true if change was successful false if not
     * @param string $name new name for the VirtualRouter
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( $this->name != "**temporarynamechangeme**" )
            $this->setRefName($name);

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return TRUE;
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getDHCPStoreXPath() . "/entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner !== null && get_class( $this->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }


        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"><relay></relay></entry>';

}