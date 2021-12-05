<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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


class LogCollectorGroup
{

    use PathableName;
    use PanSubHelperTrait;

    /** String */
    protected $name;

    /** @var PanoramaConf */
    public $owner = null;

    /** @var DOMElement */
    public $xmlroot;

    /** @var DOMElement */
    public $devicesRoot;

    /** @var Array */
    private $devices = array();

    public static $templatexml = '<entry name="**Need a Name**"><monitor-setting></monitor-setting><logfwd-setting></logfwd-setting><general-setting></general-setting>
									</entry>';

    public function __construct($owner)
    {
        $this->owner = $owner;

        $this->device = array();
    }

    public function load_from_templateXml()
    {
        if( $this->owner === null )
            derr('cannot be used if owner === null');

        $fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

        if( !$fragment->appendXML(self::$templatexml) )
            derr('error occured while loading device group template xml');

        $element = $this->owner->devicegrouproot->appendChild($fragment);

        $this->load_from_domxml($element);
    }

    /**
     * !! Should not be used outside of a PanoramaConf constructor. !!
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        // this VirtualSystem has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("LogCollectorGroup name not found\n");


        // Devices extraction
        $this->logfwdRoot = DH::findFirstElementOrCreate('logfwd-setting', $xml);
        $this->devicesRoot = DH::findFirstElementOrCreate('devices', $this->logfwdRoot);

        foreach( $this->devicesRoot->childNodes as $device )
        {
            if( $device->nodeType != 1 ) continue;
            $devname = DH::findAttribute('name', $device);

            $collectorlist = array();

            $collectorChild = DH::firstChildElement($device);

            if( $collectorChild !== FALSE )
            {
                foreach( $collectorChild->childNodes as $collectorentry )
                {
                    if( $collectorentry->nodeType != 1 ) continue;
                    $vname = DH::findAttribute('name', $collectorentry);
                    $collectorlist[$vname] = $vname;
                }
            }
            else
            {
                //print "No collector for device '$devname'\n";
                #$collectorlist[$vname] = $vname;
            }

            $this->devices[$devname] = array('serial' => $devname, 'collectorlist' => $collectorlist);
            foreach( $this->devices as $serial => $array )
            {
                $managedFirewall = $this->owner->managedFirewallsStore->find($serial);
                if( $managedFirewall !== null )
                    $managedFirewall->addReference( $this );
            }
        }
    }
}