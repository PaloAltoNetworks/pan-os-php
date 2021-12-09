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


class Service
{
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;
    use ServiceCommon;

    protected $_protocol = 'tcp';
    protected $_dport = '';
    protected $_sport = '';
    protected $_timeout = '';
    protected $_halfclose_timeout;
    protected $_timewait_timeout;

    /** @var null|DOMElement */
    public $protocolRoot = null;

    /** @var null|DOMElement */
    protected $tcpOrUdpRoot = null;

    /** @var null|DOMElement */
    public $dportroot = null;

    public $type = '';

    /** @var ServiceStore */
    public $owner = null;

    /** @var TagRuleContainer */
    public $tags;


    /**
     * @param $name
     * @param ServiceStore $owner
     * @param bool $fromTemplateXml
     */
    function __construct($name, $owner = null, $fromTemplateXml = FALSE)
    {
        $this->owner = $owner;

        if( $fromTemplateXml )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $this->owner->serviceRoot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);
            $this->owner = null;

            $this->setName($name);
        }
        else
            $this->name = $name;

        $this->tags = new TagRuleContainer($this);
    }


    /**
     * @param DOMElement $xml
     * @throws Exception
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("service name not found\n");

        $this->_load_description_from_domxml();

        //
        // seeking <protocol>
        //
        $this->protocolRoot = DH::findFirstElementOrDie('protocol', $xml);

        $this->tcpOrUdpRoot = DH::findFirstElement('tcp', $this->protocolRoot);

        if( $this->tcpOrUdpRoot === FALSE )
        {
            $this->_protocol = 'udp';
            $this->tcpOrUdpRoot = DH::findFirstElement('udp', $this->protocolRoot);
        }
        if( $this->tcpOrUdpRoot === FALSE )
            derr("Error: <tcp> or <udp> not found for service" . $this->name . "\n");

        $this->dportroot = DH::findFirstElementOrDie('port', $this->tcpOrUdpRoot);

        $this->_dport = $this->dportroot->textContent;

        $sportroot = DH::findFirstElement('source-port', $this->tcpOrUdpRoot);
        if( $sportroot !== FALSE )
        {
            $this->_sport = $sportroot->textContent;
        }

        if( $this->owner->owner->version >= 60 )
        {
            $tagRoot = DH::findFirstElement('tag', $xml);
            if( $tagRoot !== FALSE )
                $this->tags->load_from_domxml($tagRoot);
        }

        #if( $this->owner->owner->version >= 81 )
        #{
        $this->overrideroot = DH::findFirstElement('override', $this->tcpOrUdpRoot);
        if( $this->overrideroot !== FALSE )
        {
            $override_noyes = DH::findFirstElement('yes', $this->overrideroot);
            if( $override_noyes !== FALSE )
            {
                $timeoutroot = DH::findFirstElement('timeout', $override_noyes);
                if( $timeoutroot != FALSE )
                    $this->_timeout = $timeoutroot->textContent;

                $halfclose_timeoutroot = DH::findFirstElement('halfclose-timeout', $override_noyes);
                if( $halfclose_timeoutroot != FALSE )
                    $this->_halfclose_timeout = $halfclose_timeoutroot->textContent;

                $timewait_timeoutroot = DH::findFirstElement('timewait-timeout', $override_noyes);
                if( $timewait_timeoutroot != FALSE )
                    $this->_timewait_timeout = $timewait_timeoutroot->textContent;
            }
        }
        #}
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function setDestPort($newPorts)
    {
        if( strlen($newPorts) == 0 )
            derr("invalid blank value for newPorts");

        if( strlen($newPorts) > 1023 )
            derr("invalid value for destinationPort. string length >1023");

        if( $newPorts == $this->_dport )
            return FALSE;

        $this->_dport = $newPorts;
        $tmp = DH::findFirstElementOrCreate('port', $this->tcpOrUdpRoot, $this->_dport);
        DH::setDomNodeText($tmp, $newPorts);
        return TRUE;
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_setDestPort($newPorts)
    {
        $ret = $this->setDestPort($newPorts);
        $connector = findConnectorOrDie($this);

        $this->API_sync();

        return $ret;
    }


    public function setSourcePort($newPorts)
    {
        if( $newPorts === null || strlen($newPorts) == 0 )
        {
            if( strlen($this->_sport) == 0 )
                return FALSE;

            $this->_sport = $newPorts;
            $sportroot = DH::findFirstElement('source-port', $this->tcpOrUdpRoot);
            if( $sportroot !== FALSE )
                $this->tcpOrUdpRoot->removeChild($sportroot);

            return TRUE;
        }
        if( $this->_sport == $newPorts )
            return FALSE;

        if( strlen($this->_sport) == 0 )
        {
            DH::findFirstElementOrCreate('source-port', $this->tcpOrUdpRoot, $newPorts);
            return TRUE;
        }
        $sportroot = DH::findFirstElementOrCreate('source-port', $this->tcpOrUdpRoot);
        DH::setDomNodeText($sportroot, $newPorts);
        return TRUE;
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_setSourcePort($newPorts)
    {
        $ret = $this->setSourcePort($newPorts);
        $connector = findConnectorOrDie($this);

        $this->API_sync();

        return $ret;
    }

    public function isTcp()
    {
        if( $this->_protocol == 'tcp' )
            return TRUE;

        return FALSE;
    }

    public function isUdp()
    {
        if( $this->_protocol == 'udp' )
            return TRUE;

        return FALSE;
    }

    /**
     * @param string $newProtocol
     */
    public function setProtocol($newProtocol)
    {
        if( $newProtocol != 'tcp' && $newProtocol != 'udp' )
            derr("unsupported protocol '{$newProtocol}'");

        if( $newProtocol == $this->_protocol )
            return;

        $this->_protocol = $newProtocol;

        DH::clearDomNodeChilds($this->protocolRoot);

        $this->tcpOrUdpRoot = DH::createElement($this->protocolRoot, $this->_protocol);

        DH::createElement($this->tcpOrUdpRoot, 'port', $this->_dport);

        if( strlen($this->_sport) > 0 )
            DH::createElement($this->tcpOrUdpRoot, 'source-port', $this->_dport);
    }


    /**
     * @param string $newPorts
     * @return bool
     */
    public function setTimeout($newTimeout)
    {
        if( strlen($newTimeout) == 0 )
            derr("invalid blank value for newTimeouts");

        if( $newTimeout == $this->_timeout )
            return FALSE;

        if( $newTimeout == 3600 )
            return FALSE;

        $this->_timeout = $newTimeout;
        $tmp = DH::findFirstElementOrCreate('override', $this->tcpOrUdpRoot);
        $tmpno = DH::findFirstElement('no', $tmp);
        if( $tmpno !== false )
            $tmp->removeChild( $tmpno );
        $tmp = DH::findFirstElementOrCreate('yes', $tmp);
        $tmp = DH::findFirstElementOrCreate('timeout', $tmp, $this->_timeout);
        DH::setDomNodeText($tmp, $newTimeout);
        return TRUE;
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_setTimeout($newTimeout)
    {
        $ret = $this->setTimeout($newTimeout);
        $connector = findConnectorOrDie($this);

        $this->API_sync();

        return $ret;
    }

    /**
     * @return string
     */
    public function protocol()
    {
        if( $this->isTmpSrv() )
            return 'tmp';

        else
            return $this->_protocol;
    }

    /**
     * @return string
     */
    public function getDestPort()
    {
        if( $this->isTmpSrv() )
        {
            if( $this->name() == 'service-http' )
                return '80';
            if( $this->name() == 'service-https' )
                return '443';
        }

        return $this->_dport;
    }

    /**
     * @return string
     */
    public function getSourcePort()
    {
        return $this->_sport;
    }

    /**
     * @return string
     */
    public function getTimeout()
    {
        return $this->_timeout;
    }

    /**
     * @return string
     */
    public function getHalfcloseTimeout()
    {
        return $this->_halfclose_timeout;
    }

    /**
     * @return string
     */
    public function getTimewaitTimeout()
    {
        return $this->_timewait_timeout;
    }

    /**
     * @return string
     */
    public function getOverride()
    {
        if( $this->_timeout == "" && $this->_halfclose_timeout == "" && $this->_timewait_timeout == "" )
            return "";
        else
            return $this->_timeout . "," . $this->_halfclose_timeout . "," . $this->_timewait_timeout;
    }

    /**
     * @param string $newName
     */
    public function setName($newName)
    {
        $this->setRefName($newName);

        if( $this->xmlroot !== null )
            $this->xmlroot->setAttribute('name', $newName);
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();
        $c->sendRenameRequest($xpath, $newName);
        $this->setName($newName);
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getServiceStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    public function isService()
    {
        return TRUE;
    }


    public function isTmpSrv()
    {
        if( $this->type == 'tmp' )
            return TRUE;

        return FALSE;
    }


    /**
     * @param $otherObject Service|ServiceStore
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isService() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(Service $otherObject)
    {
        if( $this->isTmpSrv() && !$otherObject->isTmpSrv() )
            return FALSE;

        if( $otherObject->isTmpSrv() && !$this->isTmpSrv() )
            return FALSE;

        if( $otherObject->_protocol !== $this->_protocol )
            return FALSE;

        if( $otherObject->_dport !== $this->_dport )
            return FALSE;

        if( $otherObject->_sport !== $this->_sport )
            return FALSE;

        return TRUE;
    }

    /**
     * @return ServiceDstPortMapping
     * @throws Exception
     */
    public function dstPortMapping()
    {
        if( $this->isTmpSrv() )
        {
            if( $this->name() == 'service-http' )
                return ServiceDstPortMapping::mappingFromText('80', TRUE);
            if( $this->name() == 'service-https' )
                return ServiceDstPortMapping::mappingFromText('443', TRUE);

            return new ServiceDstPortMapping();
        }


        if( $this->_protocol == 'tcp' )
            $tcp = TRUE;
        else
            $tcp = FALSE;

        return ServiceDstPortMapping::mappingFromText($this->_dport, $tcp);
    }

    /**
     * @return ServiceSrcPortMapping
     * @throws Exception
     */
    public function srcPortMapping()
    {
        if( $this->isTmpSrv() )
            return new ServiceSrcPortMapping();

        if( $this->_protocol == 'tcp' )
            $tcp = TRUE;
        else
            $tcp = FALSE;

        return ServiceSrcPortMapping::mappingFromText($this->_sport, $tcp);
    }

    public function API_delete()
    {
        if( $this->isTmpSrv() )
            derr('cannot be called on a Tmp service object');

        return $this->owner->API_remove($this);
    }

    public function removeReference($object)
    {
        $this->super_removeReference($object);

        if( $this->isTmpSrv() && $this->countReferences() == 0 && $this->owner !== null )
        {
            $this->owner->remove($this);
        }

    }

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><protocol><tcp><port>0</port></tcp></protocol></entry>';
    static protected $templatexmlroot = null;

}
