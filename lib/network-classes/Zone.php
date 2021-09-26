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

class Zone
{

    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var null|ZoneStore */
    public $owner = null;

    private $isTmp = TRUE;

    public $externalVsys = array();

    public $_type = 'tmp';


    /** @var InterfaceContainer */
    public $attachedInterfaces;

    public $zoneProtectionProfile = null;
    public $packetBufferProtection = FALSE;
    public $logsetting = null;


    const TypeTmp = 0;
    const TypeLayer3 = 1;
    const TypeExternal = 2;
    const TypeVirtualWire = 3;
    const TypeTap = 4;
    const TypeLayer2 = 5;
    const TypeTunnel = 6;

    static private $ZoneTypes = array(
        self::TypeTmp => 'tmp',
        self::TypeLayer3 => 'layer3',
        self::TypeExternal => 'external',
        self::TypeVirtualWire => 'virtual-wire',
        self::TypeTap => 'tap',
        self::TypeLayer2 => 'layer2',
        self::TypeTunnel => 'tunnel',
    );


    /**
     * @param string $name
     * @param ZoneStore $owner
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE, $type = 'layer3')
    {
        if( !is_string($name) )
            derr('name must be a string');

        $this->owner = $owner;

        if( $this->owner->owner->isVirtualSystem() )
        {
            $this->attachedInterfaces = new InterfaceContainer($this, $this->owner->owner->owner->network);
        }
        else
            $this->attachedInterfaces = new InterfaceContainer($this, null);


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();

            if( $type == "virtual-wire" )
                $doc->loadXML(self::$templatexmlvw, XML_PARSE_BIG_LINES);
            elseif( $type == "layer2" )
                $doc->loadXML(self::$templatexmll2, XML_PARSE_BIG_LINES);
            else
                $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $this->owner->xmlroot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);

            #$this->owner = null;
            $this->setName($name);
            $this->owner = $owner;

            $this->load_from_domxml($this->xmlroot);


        }

        $this->name = $name;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }


    public function isTmp()
    {
        return $this->isTmp;
    }

    public function type()
    {
        return $this->_type;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->isTmp = FALSE;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("zone name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("Zone name '" . $this->name . "' is not valid", $xml);

        $networkNode = DH::findFirstElement('network', $xml);

        if( $networkNode === FALSE )
            return;

        foreach( $networkNode->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->tagName == 'layer3' || $node->tagName == 'virtual-wire' )
            {
                $this->_type = $node->tagName;

                $this->attachedInterfaces->load_from_domxml($node);
            }
            else if( $node->tagName == 'external' )
            {
                $this->_type = 'external';
                foreach( $node->childNodes as $memberNode )
                {
                    if( $memberNode->nodeType != XML_ELEMENT_NODE )
                        continue;
                    $this->externalVsys[$memberNode->textContent] = $memberNode->textContent;
                }

                $this->attachedInterfaces->load_from_domxml($node);
            }
            elseif( $node->tagName == 'tap' )
            {
                $this->_type = $node->tagName;
            }
            elseif( $node->tagName == 'tunnel' )
            {
                $this->_type = $node->tagName;
            }
            elseif( $node->tagName == 'layer2' )
            {
                $this->_type = $node->tagName;
            }


            elseif( $node->tagName == 'zone-protection-profile' )
            {
                $this->zoneProtectionProfile = $node->textContent;
            }
            elseif( $node->tagName == 'log-setting' )
            {
                $this->logsetting = $node->textContent;
            }
            elseif( $node->tagName == 'enable-packet-buffer-protection' )
            {

            }
            else
                mwarning("zone type: " . $node->tagName . " is not yet supported.");

        }
    }

    /**
     * @param $objectToAdd Zone
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = FALSE, $outputPadding = '', $skipIfConflict = FALSE)
    {
        foreach( $this->refrules as $ref )
        {
            $refClass = get_class($ref);
            if( $refClass == 'ZoneRuleContainer' )
            {
                /** @var ZoneRuleContainer $ref */
                $ownerClass = get_class($ref->owner);

                if( $ownerClass == 'SecurityRule' )
                {
                    $ref->addZone($objectToAdd);
                }
                else
                {
                    derr("unsupported owner class '{$ownerClass}'");
                }
            }
            else
                derr("unsupported class '{$refClass}");
        }
    }


    public function API_setName($newname)
    {
        if( !$this->isTmp() )
        {
            $c = findConnectorOrDie($this);
            $path = $this->getXPath();

            $c->sendRenameRequest($path, $newname);
        }
        else
        {
            mwarning('this is a temporary object, cannot be renamed from API');
        }

        $this->setName($newname);
    }

    /**
     * @param string $newZPP
     * @return bool
     */
    public function setZPP($newZPP)
    {
        if( $newZPP == "none" )
            $this->zoneProtectionProfile = null;
        else
            $this->zoneProtectionProfile = $newZPP;


        $valueRoot = DH::findFirstElement('network', $this->xmlroot);
        $zppRoot = DH::findFirstElementOrCreate('zone-protection-profile', $valueRoot);


        if( $newZPP != "none" )
            DH::setDomNodeText($zppRoot, $this->zoneProtectionProfile);
        else
            $valueRoot->removeChild($zppRoot);

        return TRUE;
    }

    /**
     * @param string $newZPP
     * @return bool
     */
    public function API_setZPP($newZPP)
    {
        if( !$this->setZPP($newZPP) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $newZPP != 'none' )
        {
            $valueRoot = DH::findFirstElement('network', $this->xmlroot);
            $zppRoot = DH::findFirstElementOrCreate('zone-protection-profile', $valueRoot);
            $c->sendSetRequest($xpath . "/network", DH::dom_to_xml($zppRoot, -1, FALSE));
        }
        else
            $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }

    /**
     * @param bool
     * @return bool
     */
    public function setPaketBufferProtection($bool)
    {
        if( $bool )
            $this->packetBufferProtection = TRUE;
        else
            $this->packetBufferProtection = FALSE;


        $valueRoot = DH::findFirstElement('network', $this->xmlroot);
        $zppRoot = DH::findFirstElementOrCreate('enable-packet-buffer-protection', $valueRoot);


        if( $this->packetBufferProtection )
            DH::setDomNodeText($zppRoot, "yes");
        else
            $valueRoot->removeChild($zppRoot);

        return TRUE;
    }

    /**
     * @param bool
     * @return bool
     */
    public function API_setPaketBufferProtection($bool)
    {
        if( !$this->setPaketBufferProtection($bool) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $bool )
        {
            $valueRoot = DH::findFirstElement('network', $this->xmlroot);
            $zppRoot = DH::findFirstElementOrCreate('enable-packet-buffer-protection', $valueRoot);
            $c->sendSetRequest($xpath . "/network", DH::dom_to_xml($zppRoot, -1, FALSE));
        }
        else
            $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }
    //                <enable-packet-buffer-protection>yes</enable-packet-buffer-protection>

    /**
     * @param string $newLogSetting
     * @return bool
     */
    public function setLogSetting($newLogSetting)
    {
        if( $newLogSetting == "none" )
            $this->logsetting = null;
        else
            $this->logsetting = $newLogSetting;


        $valueRoot = DH::findFirstElement('network', $this->xmlroot);
        $logsettingRoot = DH::findFirstElementOrCreate('log-setting', $valueRoot);


        if( $newLogSetting != "none" )
            DH::setDomNodeText($logsettingRoot, $this->logsetting);
        else
            $valueRoot->removeChild($logsettingRoot);

        return TRUE;
    }

    /**
     * @param string $newLogSetting
     * @return bool
     */
    public function API_setLogSetting($newLogSetting)
    {
        if( !$this->setLogSetting($newLogSetting) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $newLogSetting != 'none' )
        {
            $valueRoot = DH::findFirstElement('network', $this->xmlroot);
            $logsettingRoot = DH::findFirstElementOrCreate('log-setting', $valueRoot);
            $c->sendSetRequest($xpath . "/network", DH::dom_to_xml($logsettingRoot, -1, FALSE));
        }
        else
            $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }


    public function &getXPath()
    {
        if( $this->isTmp() )
            derr('no xpath on temporary objects');

        $str = $this->owner->getXPath() . "entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner->owner  !== null && get_class( $this->owner->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }

        return $str;
    }


    static protected $templatexml = '<entry name="**temporarynamechangemeL3**"><network><layer3></layer3></network></entry>';
    static protected $templatexmlvw = '<entry name="**temporarynamechangemeVW**"><network><virtual-wire></virtual-wire></network></entry>';
    static protected $templatexmll2 = '<entry name="**temporarynamechangemeL2**"><network><layer2></layer2></network></entry>';

}



