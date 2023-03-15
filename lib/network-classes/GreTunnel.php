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
 * Class GreTunnel
 * @property GreTunnelStore $owner
 */
class GreTunnel
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    public $owner;

    public $localInterface;
    public $tunnelInterface;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;
    /** @var null|string[]|DOMElement */
    public $proxyIdRoot = null;

    /** @var null|string[]|DOMElement */
    public $proxyIdRootv6 = null;

    public $type = 'notfound';

    /** @var null|string[]|DOMElement */
    public $gateway = 'notfound';

    /** @var null|string[]|DOMElement */
    public $protocol = 'notfound';
    /** @var null|string[]|DOMElement */
    public $protocol_local = 'notfound';
    /** @var null|string[]|DOMElement */
    public $protocol_remote = 'notfound';

    public $proxys = array();

    public $proposal = null;
    public $interface = null;
    public $localIP = null;
    public $remoteIP = null;

    public $disabled = "no";

    /**
     * GreTunnel constructor.
     * @param string $name
     * @param GreTunnelStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;

        $this->localInterface = new InterfaceContainer($this, $owner->owner->network);
        $this->tunnelInterface = new InterfaceContainer($this, $owner->owner->network);
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tunnel name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'local-address' )
            {
                $tmp = DH::findFirstElement('interface', $node);

                $tmpInterface = $this->owner->owner->network->findInterface( $tmp->textContent );
                $tmpInterface->addReference( $this->localInterface );

                $this->localInterface->addInterface( $tmpInterface );
            }

            if( $node->nodeName == 'tunnel-interface' )
            {
                $tmpInterface = $this->owner->owner->network->findInterface( $node->textContent );
                $tmpInterface->addReference( $this->tunnelInterface );

                $this->tunnelInterface->addInterface( $tmpInterface );
            }

            if( $node->nodeName == 'disabled' )
            {
                $this->disabled = $node->textContent;
            }
        }
    }


    /**
     * return true if change was successful false if not (duplicate GreTunnel name?)
     * @param string $name new name for the GreTunnel
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( preg_match('/[^0-9a-zA-Z_\-\s]/', $name) )
        {
            $name = preg_replace('/[^0-9a-zA-Z_\-\s]/', "", $name);
            PH::print_stdout( " *** new name: " . $name );
            #mwarning( 'Name will be replaced with: '.$name."\n" );
        }


        /* TODO: 20180331 finalize needed
        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this,$oldname);
            }
            else
                return false;
        }
*/
        if( $this->name != "**temporarynamechangeme**" )
            $this->setRefName($name);

        $this->name = $name;
        $this->xmlroot->setAttribute('name', $name);

        return TRUE;
    }


    public function setInterface($interface)
    {
        if( $this->interface == $interface )
            return TRUE;

        $this->interface = $interface;

        $tmp_ipsec_entry = DH::findFirstElementOrCreate('tunnel-interface', $this->xmlroot);
        DH::setDomNodeText($tmp_ipsec_entry, $interface);

        $tmp_interface = $this->owner->owner->network->findInterface($interface);
        $tmp_interface->addReference($this);

        return TRUE;
    }

    public function referencedObjectRenamed($h)
    {
        if( $this->interface !== $h->name() )
        {
            //why set it again????
            $this->interface = $h->name();

            $this->rewriteInterface_XML();

            return;
        }

        mwarning("object is not part of this object : {$h->toString()}");
    }

    public function rewriteInterface_XML()
    {
        $tmp_ipsec_entry = DH::findFirstElementOrCreate('tunnel-interface', $this->xmlroot);
        DH::setDomNodeText($tmp_ipsec_entry, $this->interface);
        #DH::createOrResetElement( $this->xmlroot, 'interface', $this->_interface->name());
    }
    public function getInterface()
    {
        return $this->interface;
    }

    public function setDisabled($bool)
    {
        if( $bool )
            $disabled = "yes";
        else
            $disabled = "no";

        if( $this->disabled == $disabled )
            return TRUE;

        $this->disabled = $disabled;

        $tmp_disable_entry = DH::findFirstElementOrCreate('disabled', $this->xmlroot);
        DH::setDomNodeText($tmp_disable_entry, $disabled);

        return TRUE;
    }

    public function getDisabled()
    {
        return $this->disabled;
    }

    public function isGreTunnelType()
    {
        return TRUE;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
              <local-address></local-address>
              <peer-address></peer-address>
              <keep-alive></keep-alive>
              <tunnel-interface></tunnel-interface>
    </entry>';

}