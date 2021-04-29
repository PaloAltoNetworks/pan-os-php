<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

/**
 * Class ManagedDeviceStore
 * @property ManagedDevice[] $o
 * @property PanoramaConf|FawkesConf $owner
 * @method ManagedDevice[] getAll()
 */
class ManagedDeviceStore extends ObjStore
{
    /** @var  PanoramaConf|FawkesConf */
    public $owner;

    /** @var null|TagStore */
    protected $parentCentralStore = null;

    public static $childn = 'ManagedDevice';


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->owner->managedFirewallsSerials = $this->get_serial_from_xml($xml, TRUE);

    }

    public function get_serial_from_xml(DOMElement $xml, $add_firewall = FALSE)
    {
        $tmp_managedFirewallsSerials = array();

        $tmp = DH::findFirstElementOrCreate('devices', $xml);

        foreach( $tmp->childNodes as $serial )
        {
            if( $serial->nodeType != 1 )
                continue;
            $s = DH::findAttribute('name', $serial);
            if( $s === FALSE )
                derr('no serial found');

            if( $add_firewall )
            {
                $tmp_obj = new ManagedDevice($s, $this);
                $this->add($tmp_obj);
            }


            $tmp_managedFirewallsSerials[$s] = $s;
        }
        return $tmp_managedFirewallsSerials;
    }

    /**
     * @param $serial
     * @param null $ref
     * @param bool $nested
     * @return null|ManagedDevice
     */
    public function find($serial, $ref = null, $nested = TRUE)
    {
        $f = $this->findByName($serial, $ref);

        if( $f !== null )
            return $f;

        return null;
    }
}