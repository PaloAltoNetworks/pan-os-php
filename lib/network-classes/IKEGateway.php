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
 * Class IKEGateway
 * @property IKEGatewayStore $owner
 */
class IKEGateway
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    public $preSharedKey = '';

    public $proposal = '';

    public $version = '';

    public $natTraversal = '';
    public $fragmentation = '';

    public $localAddress = FALSE;
    public $localInterface = FALSE;
    public $peerAddress = FALSE;

    public $localID = FALSE;
    public $peerID = FALSE;

    public $localIDtype = FALSE;
    public $peerIDtype = FALSE;

    public $disabled = "no";

    public $exchangemode = "auto";

    /**
     * IKEGateway constructor.
     * @param string $name
     * @param IKEGatewayStore $owner
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
            derr("IKE gateway name not found\n");

        #print "imported gateway with name: ". $this->name."\n";

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'authentication' )
            {
                $tmp_psk = DH::findFirstElement('pre-shared-key', $node);
                if( $tmp_psk != null )
                    $this->preSharedKey = DH::findFirstElementOrCreate('key', $tmp_psk)->textContent;
            }

            if( $node->nodeName == 'local-address' )
            {
                $tmp_gw_interface = DH::findFirstElement('interface', $node)->textContent;

                if( $tmp_gw_interface != null )
                {
                    $this->localInterface = $tmp_gw_interface;

                    $tmp_interface = $this->owner->owner->network->findInterfaceOrCreateTmp($this->localInterface);
                    $tmp_interface->addReference($this);
                }

            }

            if( $node->nodeName == 'peer-address' )
            {
                $peerAddressNode = DH::findFirstElement('ip', $node);
                if( $peerAddressNode != null )
                    $this->peerAddress = $peerAddressNode->textContent;
            }


            if( $node->nodeName == 'protocol' )
            {
                $this->version = DH::findFirstElement('version', $node);
                if( $this->version != null )
                    $this->version = $this->version->textContent;

                $tmp_ikevX = $this->proposal = DH::findFirstElement($this->version, $node);
                if( $tmp_ikevX != null )
                {
                    $proposalNode = DH::findFirstElement('ike-crypto-profile', $tmp_ikevX);
                    if( $proposalNode != null )
                        $this->proposal = $proposalNode->textContent;

                    $exchangemodeNode = DH::findFirstElement('exchange-mode', $tmp_ikevX);
                    if( $exchangemodeNode != null )
                        $this->exchangemode = $exchangemodeNode->textContent;
                    //<exchange-mode>main</exchange-mode>

                    $tmpDPD = DH::findFirstElement('dpd', $tmp_ikevX);
                    if( $tmpDPD != null )
                    {
                        $dpd_enabled = DH::findFirstElement('enable', $tmpDPD);
                        if( $dpd_enabled != null )
                            $dpd_enabled = $dpd_enabled->textContent;

                        $dpd_interval = DH::findFirstElement('interval', $tmpDPD);
                        if( $dpd_interval != null )
                            $dpd_interval = $dpd_interval->textContent;

                        $dpd_retry = DH::findFirstElement('retry', $tmpDPD);
                        if( $dpd_retry != null )
                            $dpd_retry = $dpd_retry->textContent;
                    }


                    //todo: dpd
                    /*
                      <protocol>
                        <ikev1>
                          <dpd>
                            <enable>yes</enable>
                            <interval>15</interval>
                            <retry>15</retry>
                          </dpd>
                        </ikev1>
                        <ikev2>
                          <dpd>
                            <enable>yes</enable>
                          </dpd>
                        </ikev2>
                      </protocol>
                     */
                }


                if( $this->proposal == null )
                    $this->proposal = "default";
                if( $this->exchangemode == null )
                    $this->exchangemode = "auto";
            }

            if( $node->nodeName == 'protocol-common' )
            {
                $tmp_natT = DH::findFirstElementOrCreate('nat-traversal', $node);
                if( $tmp_natT != null )
                    $this->natTraversal = DH::findFirstElementOrCreate('enable', $tmp_natT)->textContent;

                $tmp_frag = DH::findFirstElementOrCreate('fragmentation', $node);
                if( $tmp_frag != null )
                    $this->fragmentation = DH::findFirstElementOrCreate('enable', $tmp_frag)->textContent;
            }

            if( $node->nodeName == 'local-id' )
            {
                $this->localID = DH::findFirstElementOrCreate('id', $node)->textContent;
                $this->localIDtype = DH::findFirstElementOrCreate('type', $node)->textContent;
            }

            if( $node->nodeName == 'peer-id' )
            {
                $this->peerID = DH::findFirstElementOrCreate('id', $node)->textContent;
                $this->peerIDtype = DH::findFirstElementOrCreate('type', $node)->textContent;
            }


            if( $node->nodeName == 'disabled' )
                $this->disabled = $node->textContent;
        }
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( preg_match('[^\d]', $name) )
        {
            //NO digit allowed at the beginning of a name
            derr('no digit allowed at the beginning of a IKE gateway name');
        }

        if( preg_match('/[^0-9a-zA-Z_\-]/', $name) )
        {
            //NO blank allowed in gateway name
            //NO other characters are allowed as seen here
            $name = preg_replace('/[^0-9a-zA-Z_\-]/', "", $name);
            #print " *** new gateway name: ".$name." \n";
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

    public function setproposal($proposal)
    {
        if( $this->proposal == $proposal )
            return TRUE;

        $this->proposal = $proposal;

        $tmp_gateway = DH::findFirstElementOrCreate('protocol', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate($this->version, $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate('ike-crypto-profile', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $proposal);

        return TRUE;
    }

    //Todo: swaschkut 20201001 update this
    public function setExchangeMode($mode)
    {
        if( $this->proposal == $proposal )
            return TRUE;

        $this->proposal = $proposal;

        $tmp_gateway = DH::findFirstElementOrCreate('protocol', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate($this->version, $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate('ike-crypto-profile', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $proposal);

        return TRUE;
    }

    public function setinterface($interface, $type = "ethernet")
    {
        if( $this->localInterface == $interface )
            return TRUE;

        $this->localInterface = $interface;

        $tmp_gateway = DH::findFirstElementOrCreate('local-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('interface', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $interface);


        $tmp_interface = $this->owner->owner->network->findInterface($interface);
        if( !is_object($tmp_interface) )
        {
            if( $type == "ethernet" )
            {
                if( strpos($interface, ".") === FALSE )
                {
                    $tmp_interface = $this->owner->owner->network->ethernetIfStore->newEthernetIf($interface, 'layer3');

                    #$this->owner->owner->importedInterfaces->addInterface( $tmp_interface );
                }
                else
                {
                    //subinterface
                    $tmp_subinterface = explode(".", $interface);

                    $int_name = $tmp_subinterface[0];
                    $vlan_name = $tmp_subinterface[1];

                    $tmp_int_main = $this->owner->owner->network->findInterface($int_name);
                    if( !is_object($tmp_int_main) )
                    {
                        PH::print_stdout(  " - create interface: " . $int_name );
                        $tmp_int_main = $this->owner->owner->network->ethernetIfStore->newEthernetIf($int_name, 'layer3');
                        #$v->importedInterfaces->addInterface( $tmp_int_main );
                    }

                    $tmp_interface = $this->owner->owner->network->findInterface($interface);
                    if( !is_object($tmp_interface) )
                    {
                        #print "   - add subinterface: " . $int[5] . "\n";
                        $tmp_interface = $tmp_int_main->addSubInterface($vlan_name, $interface);
                        #$v->importedInterfaces->addInterface($tmp_sub);
                    }
                }
            }
            elseif( $type == "loopback" )
            {
                $tmp_interface = $this->owner->owner->network->loopbackIfStore->newLoopbackIf( $interface );
            }

        }
        $tmp_interface->addReference($this);

        #if( $interface == "loopback.21" )
            #derr( "STOP" );
        return TRUE;
    }

    public function setpeerAddress($peeraddress)
    {
        if( $this->peerAddress == $peeraddress )
            return TRUE;

        $this->peerAddress = $peeraddress;

        $tmp_gateway = DH::findFirstElementOrCreate('peer-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('ip', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $peeraddress);

        return TRUE;
    }

    public function setPreSharedKey($presharedkey)
    {
        if( $this->preSharedKey == $presharedkey )
            return TRUE;

        $this->preSharedKey = $presharedkey;

        $tmp_gateway = DH::findFirstElementOrCreate('authentication', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('pre-shared-key', $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate('key', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $presharedkey);

        return TRUE;
    }

    /**
     * @param $newType string
     * @return bool true if successful
     */
    public function API_setPreSharedKey($presharedkey)
    {
        if( !$this->setPreSharedKey($presharedkey) )
            return FALSE;

        $c = findConnectorOrDie($this);

        #$xpath = $this->getXPath();
        $tmp_gateway = DH::findFirstElementOrCreate('authentication', $this->xmlroot);
        $xpath = DH::findFirstElementOrCreate('pre-shared-key', $tmp_gateway);
        $xpath = $xpath->getNodePath();

        $element = "<key>" . $presharedkey . "</key>";

        $c->sendSetRequest($xpath, $element);

        $this->setPreSharedKey($presharedkey);

        return TRUE;
    }
    //TODO: create set functions for:
    //set nat-traversal
    //set dpd


    public function isIKEGatewayType()
    {
        return TRUE;
    }

    public function referencedObjectRenamed($h)
    {
        if( $this->localInterface !== $h->name() )
        {
            //why set it again????
            $this->localInterface = $h->name();

            $this->rewriteInterface_XML();

            return;
        }

        mwarning("object is not part of this object : {$h->toString()}");
    }

    public function rewriteInterface_XML()
    {
        $tmp_gateway = DH::findFirstElementOrCreate('local-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('interface', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $this->localInterface);
        #DH::createOrResetElement( $this->xmlroot, 'interface', $this->_interface->name());
    }

    //"-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==" => "DEMO"
    //"-AQ==2WmDHripnP+MAuaB9DKJ5dPWlmQ=wgoOihqVrKK2NmxerTkFKg==" => 'temp'
    static public $templatexml = '<entry name="**temporarynamechangeme**">
    <authentication>
        <pre-shared-key>
            <key>-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==</key>
        </pre-shared-key>
    </authentication>
    <protocol>
        <ikev1><dpd><enable>yes</enable><interval>5</interval><retry>5</retry></dpd><ike-crypto-profile>default</ike-crypto-profile><exchange-mode>auto</exchange-mode></ikev1>
        <ikev2><dpd><enable>yes</enable><interval>5</interval></dpd><ike-crypto-profile>default</ike-crypto-profile></ikev2>
        <version>ikev1</version>
      </protocol>
    <protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>
    <local-address><interface></interface></local-address>
    <peer-address><ip></ip></peer-address>
    <disabled>no</disabled>
</entry>';

    static public $templatexml_ikev2 = '<entry name="**temporarynamechangeme**">
    <authentication>
        <pre-shared-key>
            <key>-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==</key>
        </pre-shared-key>
    </authentication>
    <protocol>
        <ikev1><dpd><enable>yes</enable><interval>5</interval><retry>5</retry></dpd><ike-crypto-profile>default</ike-crypto-profile><exchange-mode>auto</exchange-mode></ikev1>
        <ikev2><dpd><enable>yes</enable><interval>5</interval></dpd><ike-crypto-profile>default</ike-crypto-profile></ikev2>
        <version>ikev2</version>
      </protocol>
    <protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>
    <local-address><interface></interface></local-address>
    <peer-address><ip></ip></peer-address>
    <disabled>no</disabled>
</entry>';

}