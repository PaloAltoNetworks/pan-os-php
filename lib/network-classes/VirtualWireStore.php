<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

/**
 * Class VirtualWireStore
 * @property $o VirutalWire[]
 */
class VirtualWireStore extends ObjStore
{

    /** @var null|PANConf */
    public $owner;

    protected $fastMemToIndex = null;
    protected $fastNameToIndex = null;

    public static $childn = 'VirtualWire';

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return VirtualWire[]
     */
    public function virtualWires()
    {
        return $this->o;
    }

    /**
     * @param $vwName string
     * @return null|VirtualWire
     */
    public function findVirtualWire($vwName)
    {
        return $this->findByName($vwName);
    }


    /**
     * Creates a new VirtualWire in this store. It will be placed at the end of the list.
     * @param string $name name of the new VirtualWire
     * @return VirtualWire
     */
    public function newVirtualWire($name)
    {
        foreach( $this->virtualWires() as $vw )
        {
            if( $vw->name() == $name )
                derr("VirtualWire: " . $name . " already available\n");
        }

        $virtualWire = new VirtualWire($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, VirtualWire::$templatexml);

        $virtualWire->load_from_domxml($xmlElement);

        $virtualWire->owner = null;
        $virtualWire->setName($name);

        //20190507 - which add method is best, is addVirtualWire needed??
        $this->addVirtualWire($virtualWire);
        $this->add($virtualWire);

        return $virtualWire;
    }

    public function API_newVirtualWire($name)
    {
        $newvw = $this->newVirtualWire($name);

        $con = findConnectorOrDie($this);
        //$xpath = $newvw->getXPath();
        $xpath = $this->getEthernetIfStoreXPath();
        $con->sendSetRequest($xpath, "<entry name='{$newvw->name()}'/>", TRUE);

        return $newvw;
    }


    /**
     * @param VirtualWire $virtualWire
     * @return bool
     */
    public function addVirtualWire($virtualWire)
    {
        if( !is_object($virtualWire) )
            derr('this function only accepts VirtualWire class objects');

        if( $virtualWire->owner !== null )
            derr('Trying to add a VirtualWire that has a owner already !');


        $ser = spl_object_hash($virtualWire);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $virtualWire->owner = $this;

            $this->fastMemToIndex[$ser] = $virtualWire;
            $this->fastNameToIndex[$virtualWire->name()] = $virtualWire;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($virtualWire->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a VirtualWire that is already here :)');

        return FALSE;
    }

    /**
     * @param EthernetInterface $s
     * @return bool
     */
    public function API_addVirtualWire($s)
    {
        $ret = $this->addVirtualWire($s);

        if( $ret )
        {
            $con = findConnectorOrDie($this);

            $xpath = $this->getEthernetIfStoreXPath();

            $con->sendSetRequest($xpath, "<entry name='{$s->name()}'/>");
        }

        return $ret;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('virtual-wire', $xml);
        }
    }

    private function &getBaseXPath()
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
        $str .= '/config/devices/entry/network';

        return $str;
    }

    public function &getEthernetIfStoreXPath()
    {
        $path = $this->getBaseXPath() . '/virtual-wire';
        return $path;
    }

}