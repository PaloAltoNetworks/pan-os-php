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
 * Class EthernetIfStore
 * @property EthernetInterface[] $o
 */
class EthernetIfStore extends ObjStore
{

    /** @var PANConf */
    public $owner;

    protected $fastMemToIndex = null;
    protected $fastNameToIndex = null;

    public static $childn = 'EthernetInterface';

    /**
     * @param PANConf $owner
     */
    function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->classn = &self::$childn;
    }


    function countSubInterfaces()
    {
        $count = 0;

        foreach( $this->o as $interface )
        {
            $count += $interface->countSubInterfaces();
        }

        return $count;
    }


    /**
     * @return EthernetInterface[]
     */
    function getInterfaces()
    {
        return $this->o;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        parent::load_from_domxml($xml);
        foreach( $this->o as $o )
        {
            foreach( $o->subInterfaces() as $sub )
            {
                $this->add($sub);
            }
        }
    }

    /**
     * Creates a new EthernetInterface in this store. It will be placed at the end of the list.
     * @param string $name name of the new EthernetInterface
     * @return EthernetInterface
     */
    public function newEthernetIf($name, $ethtype = 'layer3', $ae = null)
    {
        if( array_search($ethtype, EthernetInterface::$supportedTypes) === FALSE )
            derr("ethernet interface of type: " . $ethtype . " not supported.\n");

        foreach( $this->getInterfaces() as $interface )
        {
            if( $interface->name() == $name )
                derr("Interface: " . $name . " already available\n");
        }

        $ethernetIf = new EthernetInterface($name, $this);
        if( $ethtype == "layer3" )
            $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, EthernetInterface::$templatexml);
        elseif( $ethtype == "layer2" )
            $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, EthernetInterface::$templatexmll2);
        elseif( $ethtype == "aggregate-group" )
            $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, EthernetInterface::$templatexmlae);
        elseif( $ethtype == "virtual-wire" )
            $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, EthernetInterface::$templatexmlvw);
        else
            derr("ethernet interface of type: " . $ethtype . " not yet supported.\n");
        //todo: add ethernet type 'tap', 'ha', 'log-card', 'decrypt-mirror'

        $ethernetIf->load_from_domxml($xmlElement);

        $ethernetIf->owner = null;
        $ethernetIf->setName($name);

        if( $ae !== null )
            $ethernetIf->setAE($ae);

        //20190507 - which add method is best, is addEthernetIf needed??
        $this->addEthernetIf($ethernetIf);
        $this->add($ethernetIf);

        return $ethernetIf;
    }


    /**
     * Creates a new EthernetInterface in this store. It will be placed at the end of the list.
     * @param string $name name of the new EthernetInterface
     * @return EthernetInterface
     */
    public function API_newEthernetIf($name, $ethtype = 'layer3', $ae = null)
    {
        $newif = $this->newEthernetIf($name, $ethtype, $ae);

        $con = findConnectorOrDie($this);
        $xpath = $newif->getXPath();
        $con->sendSetRequest($xpath, $newif, TRUE);

        return $newif;
    }

    /**
     * @param EthernetInterface $ethernetIf
     * @return bool
     */
    public function addEthernetIf($ethernetIf)
    {
        if( !is_object($ethernetIf) )
            derr('this function only accepts EthernetInterface class objects');

        if( $ethernetIf->owner !== null )
            derr('Trying to add a EthernetInterface that has a owner already !');


        $ser = spl_object_hash($ethernetIf);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $ethernetIf->owner = $this;

            $this->fastMemToIndex[$ser] = $ethernetIf;
            $this->fastNameToIndex[$ethernetIf->name()] = $ethernetIf;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($ethernetIf->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a EthernetInterface that is already here :)');

        return FALSE;
    }

    /**
     * @param EthernetInterface $s
     * @return bool
     */
    public function API_addEthernetIf($s)
    {
        $ret = $this->addEthernetIf($s);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $xpath = $s->getXPath();
            #PH::print_stdout( 'XPATH: '.$xpath->textContent );
            $con->sendSetRequest($xpath, DH::domlist_to_xml($s->xmlroot->childNodes, -1, FALSE));
        }

        return $ret;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            //TODO: 20180331 why I need to create full path? why it is not set before???
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);
            $xml = DH::findFirstElementOrCreate('interface', $xml);
            $this->xmlroot = DH::findFirstElementOrCreate('ethernet', $xml);
        }
    }

    public function &getXPath()
    {
        $str = $this->getBaseXPath();

        if( get_class($this) == "EthernetIfStore" )
            $str = $str . '/ethernet';
        elseif( get_class($this) == "AggregateEthernetIfStore" )
            $str = $str . '/aggregate-ethernet';

        return $str;
    }


    public function &getBaseXPath()
    {

        $str = "";
        /*
                if( $this->owner->owner->isTemplate() )
                    $str .= $this->owner->owner->getXPath();
                elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
                    $str = '/config/shared';
                else
                    derr('unsupported');
        */

        //TODO: intermediate solution
        $str .= '/config/devices/entry/network/interface';

        return $str;
    }

    public function &getEthernetIfStoreXPath()
    {
        if( get_class($this) == "EthernetIfStore" )
            $path = $this->getBaseXPath() . '/ethernet';
        elseif( get_class($this) == "AggregateEthernetIfStore" )
            $path = $this->getBaseXPath() . '/aggregate-ethernet';

        return $path;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
            {
                $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
                $xml = DH::findFirstElementOrCreate('entry', $xml);
                $xml = DH::findFirstElementOrCreate('network', $xml);
                $xml = DH::findFirstElementOrCreate('interface', $xml);

                if( get_class($this) == "EthernetIfStore" )
                    $xml = DH::findFirstElementOrCreate('ethernet', $xml);
                elseif( get_class($this) == "AggregateEthernetIfStore" )
                    $xml = DH::findFirstElementOrCreate('aggregate-ethernet', $xml);

                DH::findFirstElementOrCreate('units', $xml);
                #DH::findFirstElementOrCreate('tag', $this->owner->xmlroot);
            }

        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            if( !$o->isTmp() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
    }

    public function addSubinterfaceToStore($subinterface)
    {
        $this->add($subinterface);
    }
}