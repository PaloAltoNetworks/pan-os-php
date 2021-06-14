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


/**
 * Class InterfaceContainer
 * @property VirtualSystem|Zone|VirtualRouter|PbfRule|DosRule $owner
 * @property EthernetInterface[]|AggregateEthernetInterface[]|LoopbackInterface[]|IPsecTunnel[]|TunnelInterface[]|VlanInterface[] $o
 */
class InterfaceContainer extends ObjRuleContainer
{
    /** @var  NetworkPropertiesContainer */
    public $parentCentralStore;

    /**
     * @param VirtualSystem|DeviceCloud|Zone|VirtualRouter|PbfRule|DoSRule $owner
     * @param NetworkPropertiesContainer $centralStore
     */
    public function __construct($owner, $centralStore)
    {
        $this->owner = $owner;
        $this->parentCentralStore = $centralStore;

        $this->o = array();
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $interfaceString = $node->textContent;

            $interface = $this->parentCentralStore->findInterfaceOrCreateTmp($interfaceString);

            $this->add($interface);
        }
    }

    public function rewriteXML()
    {
        DH::clearDomNodeChilds($this->xmlroot);

        foreach( $this->o as $entry )
        {
            $tmp = DH::createElement($this->xmlroot, "member", $entry->name());
        }


    }

    /**
     * @return EthernetInterface[]|AggregateEthernetInterface[]|LoopbackInterface[]||IPsecTunnel[]|TunnelInterface[]|VlanInterface[]
     */
    public function interfaces()
    {
        return $this->o;
    }

    /**
     * @param EthernetInterface[]|AggregateEthernetInterface[]|LoopbackInterface[]|IPsecTunnel[]|TunnelInterface[]|VlanInterface[] $if
     * @param bool $caseSensitive
     * @return bool
     */
    public function hasInterface($if)
    {
        return $this->has($if);
    }

    /**
     * @param string $ifName
     * @param bool $caseSensitive
     * @return bool
     */
    public function hasInterfaceNamed($ifName, $caseSensitive = TRUE)
    {
        return $this->has($ifName, $caseSensitive);
    }

    /**
     * @param EthernetInterface|AggregateEthernetInterface|LoopbackInterface|IPsecTunnel|TunnelInterface|VlanInterface $if
     * @return bool
     */
    public function addInterface($if)
    {
        if( $if->type() == 'aggregate-group' )
        {
            mwarning("Interface of type: aggregate-group can not be added to a vsys.\n");
            return FALSE;
        }


        if( $this->has($if) )
            return FALSE;

        $this->o[] = $if;
        $if->addReference($this);

        DH::createElement($this->xmlroot, 'member', $if->name());

        return TRUE;
    }


    /**
     * @param EthernetInterface|AggregateEthernetInterface|LoopbackInterface|IPsecTunnel|TunnelInterface|VlanInterface $if
     * @return bool
     */
    public function API_addInterface($if)
    {
        //Todo: is this working for zone ??????????
        if( $this->addInterface($if) )
        {
            $con = findConnectorOrDie($this);

            $xpath = $this->owner->getXPath() . '/import/network/interface';
            $importRoot = DH::findFirstElementOrDie('import', $this->owner->xmlroot);
            $networkRoot = DH::findFirstElementOrDie('network', $importRoot);
            $importIfRoot = DH::findFirstElementOrDie('interface', $networkRoot);

            $con->sendSetRequest($xpath, "<member>{$if->name()}</member>");
        }

        return TRUE;
    }

    public function removeInterface($if)
    {
        if( $if->type() == 'aggregate-group' )
        {
            mwarning("Interface of type: aggregate-group can not be added to a vsys.\n");
            return FALSE;
        }


        if( $this->has($if) )
        {
            $tmp_key = array_search($if, $this->o);
            if( $tmp_key !== FALSE )
            {
                unset($this->o[$tmp_key]);
            }

            $if->removeReference($this);

            //DH::createElement( $this->xmlroot, 'member', $if->name() );

            $this->rewriteXML();

            return TRUE;
        }

        return FALSE;
    }


}