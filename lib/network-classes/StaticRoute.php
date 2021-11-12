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


class StaticRoute
{
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    //Todo:
    //set interface
    //set metric
    //set nexthop


    /** @var string */
    protected $_destination;

    protected $_nexthopType = 'none';

    protected $_nexthopIP = null;

    /** @var null|string */
    protected $_nexthopVR = null;

    /** @var VirtualRouter */
    public $owner;

    /** @var null|EthernetInterface|AggregateEthernetInterface|TmpInterface */
    protected $_interface = null;


    /**
     * StaticRoute constructor.
     * @param string $name
     * @param VirtualRouter $owner
     */
    function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param $xml DOMElement
     */
    function load_from_xml($xml)
    {
        $this->xmlroot = $xml;

        //<entry name="Route 161">
            //<nexthop><ip-address>10.34.111.1</ip-address></nexthop>
            //<metric>10</metric>
            //<interface>Port-channel22.511</interface>
            //<destination>192.168.220.70/32</destination>
        //</entry>

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("static-route name not found\n");

        #print "NAME: ".$this->name."\n";

        #$dstNode = DH::findFirstElementOrDie('destination', $xml);
        $dstNode = DH::findFirstElement('destination', $xml);

        if( $dstNode !== FALSE )
        {
            #print "DST: ".$dstNode->textContent."\n";
            #var_dump( $dstNode );

            if( strpos( $dstNode->textContent, "/" ) !== false )
            {
                $this->_destination = $dstNode->textContent;
            }
            else
            {
                //Todo: swaschkut 20201216 - _destination can be also an address object;
                //how to find correct addressStore if Panorama? because
                $array_vsys = $this->owner->findConcernedVsys();

                if( isset($array_vsys[0]) )
                    $this->_destination = $array_vsys[0];
            }
        }


        $ifNode = DH::findFirstElement('interface', $xml);
        if( $ifNode !== FALSE )
        {
            #print "INTERFACE: ".$ifNode->textContent."\n";
            #var_dump( $ifNode );
            $tmp_interface = $this->owner->owner->owner->network->findInterfaceOrCreateTmp($ifNode->textContent);
            $this->_interface = $tmp_interface;
            $tmp_interface->addReference($this);
        }

        $fhNode = DH::findFirstElement('nexthop', $xml);
        if( $fhNode !== FALSE )
        {
            $fhTypeNode = DH::findFirstElement('ip-address', $fhNode);
            if( $fhTypeNode !== FALSE )
            {
                $this->_nexthopType = 'ip-address';
                $this->_nexthopIP = $fhTypeNode->textContent;
                return;
            }
            $fhTypeNode = DH::findFirstElement('ipv6-address', $fhNode);
            if( $fhTypeNode !== FALSE )
            {
                $this->_nexthopType = 'ipv6-address';
                $this->_nexthopIP = $fhTypeNode->textContent;
                return;
            }
            $fhTypeNode = DH::findFirstElement('next-vr', $fhNode);
            if( $fhTypeNode !== FALSE )
            {
                $this->_nexthopType = 'next-vr';
                $this->_nexthopVR = $fhTypeNode->textContent;
                return;
            }

        }
    }

    function create_staticroute_from_xml($xmlString)
    {
        #print $xmlString."\n";
        $xmlElement = DH::importXmlStringOrDie($this->owner->owner->xmlroot->ownerDocument, $xmlString);
        $this->load_from_xml($xmlElement);

        return $this;
    }

    function create_staticroute_from_variables( $routename, $destination, $nexthop, $metric, $interface)
    {
        $xml_interface = "";
        if( $interface !== "" )
            $xml_interface = "<interface>" . $interface . "</interface>";

        //Todo: nexthop would be also good, but it could be that nexthop is "" than $interface ip-address must be used for IP check
        $checkIP = explode( "/", $destination);

        if(filter_var($checkIP[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
            $ipType = "ip-address";
        elseif(filter_var($checkIP[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            $ipType = "ipv6-address";

        $xmlString = "<entry name=\"" . $routename . "\"><nexthop><".$ipType.">" . $nexthop . "</".$ipType."></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $destination . "</destination></entry>";

        $tmpRoute = $this->create_staticroute_from_xml($xmlString);

        return $tmpRoute;
    }

    /**
     * @return string
     */
    public function destination()
    {
        return $this->_destination;
    }

    /**
     * @return bool|string
     */
    public function destinationIP4Mapping()
    {
        self::destinationIPMapping();
    }

    /**
     * @return bool|string
     */
    public function destinationIPMapping()
    {
        return cidr::stringToStartEnd($this->_destination);
    }

    public function nexthopIP()
    {
        return $this->_nexthopIP;
    }

    /**
     * @return null|string
     */
    public function nexthopVR()
    {
        return $this->_nexthopVR;
    }

    public function nexthopInterface()
    {
        return $this->_interface;
    }


    /**
     * @return string   'none','ip-address'
     */
    public function nexthopType()
    {
        return $this->_nexthopType;
    }

    public function referencedObjectRenamed($h)
    {
        if( $this->_interface === $h )
        {
            $this->_interface = $h;
            $this->rewriteInterface_XML();

            return;
        }

        mwarning("object is not part of this static route : {$h->toString()}");
    }

    public function rewriteInterface_XML()
    {
        DH::createOrResetElement($this->xmlroot, 'interface', $this->_interface->name());
    }

}