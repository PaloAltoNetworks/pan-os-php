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
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class Address
{
    use AddressCommon;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /** @var string|null */
    protected $value;

    /** @var AddressStore|null */
    public $owner;

    /** @var TagRuleContainer */
    public $tags;

    const TypeTmp = 0;
    const TypeIpNetmask = 1;
    const TypeIpRange = 2;
    const TypeFQDN = 3;
    const TypeDynamic = 4;
    const TypeIpWildcard = 5;


    static public $AddressTypes = array(
        self::TypeTmp => 'tmp',
        self::TypeIpNetmask => 'ip-netmask',
        self::TypeIpRange => 'ip-range',
        self::TypeFQDN => 'fqdn',
        self::TypeDynamic => 'dynamic',
        self::TypeIpWildcard => 'ip-wildcard'
    );

    protected $type = self::TypeTmp;

    public $_ip4Map = null;

    /**
     * you should not need this one for normal use
     * @param string $name
     * @param AddressStore $owner
     * @param bool $fromXmlTemplate
     */
    function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            if( $this->owner->addressRoot !== null )
                $rootDoc = $this->owner->addressRoot->ownerDocument;
            else
            {
                $tmpXML = DH::findFirstElementOrCreate( "address", $this->owner->owner->xmlroot );
                $this->owner->load_addresses_from_domxml( $tmpXML );
                $rootDoc = $this->owner->owner->xmlroot->ownerDocument;
            }

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            //
            $this->owner = null;

            $this->setName( $name );
        }
        //
        else
            $this->name = $name;

        $this->tags = new TagRuleContainer($this);

    }


    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("address name not found\n");

        $this->_load_description_from_domxml();

        //PH::print_stdout( "object named '".$this->name."' found" );


        $typeFound = FALSE;

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */

            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $lsearch = array_search($node->nodeName, self::$AddressTypes);
            if( $lsearch !== FALSE )
            {
                $typeFound = TRUE;
                $this->type = $lsearch;
                $this->value = $node->textContent;
            }
        }

        if( !$typeFound )
        {
            if( !PH::$ignoreInvalidAddressObjects )
                derr('Object type not found or not supported for address object ' . $this->name . '. Please check your configuration file and fix it or invoke with argument "shadow-ignoreInvalidAddressObjects"', $xml);

            mwarning('Object type not found or not supported for address object ' . $this->name . ' but you manually did bypass this error', $xml, FALSE);
            return FALSE;
        }

        if( $this->owner->owner->version >= 60 )
        {
            $tagRoot = DH::findFirstElement('tag', $xml);
            if( $tagRoot !== FALSE )
                $this->tags->load_from_domxml($tagRoot);
        }


        return TRUE;
    }

    /**
     * @return null|string
     */
    public function value()
    {
        if( $this->isTmpAddr() )
        {
            if( $this->nameIsValidRuleIPEntry() )
                return $this->name();
        }

        return $this->value;
    }


    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function setValue($newValue, $rewriteXml = TRUE)
    {
        if( isset($this->_ip4Map) )
            unset($this->_ip4Map);

        if( !is_string($newValue) )
            derr('value can be text only');

        if( $newValue == $this->value )
            return FALSE;

        if( $this->isTmpAddr() )
            return FALSE;

        $this->value = $newValue;

        if( $rewriteXml )
        {

            $valueRoot = DH::findFirstElementOrDie(self::$AddressTypes[$this->type], $this->xmlroot);
            DH::setDomNodeText($valueRoot, $this->value);
        }

        return TRUE;
    }

    /**
     * @param $newType string
     * @param bool $rewritexml
     * @return bool true if successful
     */
    public function setType($newType, $rewritexml = TRUE)
    {
        if( isset($this->_ip4Map) )
            unset($this->_ip4Map);

        $tmp = array_search($newType, self::$AddressTypes);
        if( $tmp === FALSE )
            derr('this type is not supported : ' . $newType);

        if( $newType === $tmp )
            return FALSE;

        $this->type = $tmp;

        if( $rewritexml )
            $this->rewriteXML();

        return TRUE;
    }

    /**
     * @param $newType string
     * @return bool true if successful
     */
    public function API_setType($newType)
    {
        if( !$this->setType($newType) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        $this->setType($newType);

        return TRUE;
    }

    /**
     * @param string $newValue
     * @return bool
     */
    public function API_setValue($newValue)
    {
        if( !$this->setValue($newValue) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        $this->setValue($newValue);

        return TRUE;
    }

    /**
     * @param string $newValue
     * @return bool
     */
    public function API_editValue($newValue)
    {
        if( !$this->setValue($newValue) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        $this->setValue($newValue);

        return TRUE;
    }


    public function rewriteXML()
    {
        if( $this->isTmpAddr() )
            return;

        DH::clearDomNodeChilds($this->xmlroot);

        $tmp = DH::createElement($this->xmlroot, self::$AddressTypes[$this->type], $this->value);

        if( $this->_description !== null && strlen($this->_description) > 0 )
        {
            DH::createElement($this->xmlroot, 'description', $this->_description);
        }

        if( $this->tags->count() > 0 )
        {
            $this->tags->xmlroot = DH::createElement($this->xmlroot, 'tag');
            $this->tags->rewriteXML();
        }

    }

    /**
     * change the name of this object
     * @param string $newName
     *
     */
    public function setName($newName)
    {
        $this->setRefName($newName);
        $this->xmlroot->setAttribute('name', $newName);

        if( $this->isTmpAddr() )
            unset($this->_ip4Map);
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        if( $this->isTmpAddr() )
        {
            mwarning('renaming of TMP object in API is not possible, it was ignored');
            return;
        }
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
        $str = $this->owner->getAddressStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    /**
     * @return string ie: 'ip-netmask' 'ip-range'
     */
    public function type()
    {
        return self::$AddressTypes[$this->type];
    }

    public function isAddress()
    {
        return TRUE;
    }

    public function isTmpAddr()
    {
        if( $this->type == self::TypeTmp )
            return TRUE;

        return FALSE;
    }

    public function isType_ipNetmask()
    {
        return $this->type == self::TypeIpNetmask;
    }

    public function isType_ipRange()
    {
        return $this->type == self::TypeIpRange;
    }

    public function isType_FQDN()
    {
        return $this->type == self::TypeFQDN;
    }

    public function isType_TMP()
    {
        return $this->type == self::TypeTmp;
    }

    public function isType_ipWildcard()
    {
        return $this->type == self::TypeIpWildcard;
    }

    /**
     * @param $otherObject Address|AddressGroup
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isAddress() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(Address $otherObject)
    {
        if( $this->isTmpAddr() && !$otherObject->isTmpAddr() )
            return FALSE;

        if( $otherObject->isTmpAddr() && !$this->isTmpAddr() )
            return FALSE;

        if( $otherObject->type !== $this->type )
            return FALSE;

        if( $otherObject->value !== $this->value )
            return FALSE;

        return TRUE;
    }


    /**
     * Return an array['start']= startip and ['end']= endip
     * @return IP4Map
     */
    public function getIP4Mapping()
    {
        if( isset($this->_ip4Map) )
        {
            return $this->_ip4Map;
        }

        if( $this->isTmpAddr() )
        {
            if( !$this->nameIsValidRuleIPEntry() )
            {
                // if this object is temporary/unsupported, we send an empty mapping
                $this->_ip4Map = new IP4Map();
                $this->_ip4Map->unresolved[$this->name] = $this;
            }
            else
                $this->_ip4Map = IP4Map::mapFromText($this->name);
        }
        elseif( $this->type != self::TypeIpRange && $this->type != self::TypeIpNetmask )
        {
            $this->_ip4Map = new IP4Map();
            $this->_ip4Map->unresolved[$this->name] = $this;
        }
        elseif( $this->type == self::TypeIpNetmask || $this->type == self::TypeIpRange )
        {
            $this->_ip4Map = IP4Map::mapFromText($this->value);
            if( $this->_ip4Map->count() == 0 )
                $this->_ip4Map->unresolved[$this->name] = $this;
        }
        else
        {
            derr("unexpected type");
        }

        return $this->_ip4Map;
    }


    /**
     * return 0 if not match, 1 if this object is fully included in $network, 2 if this object is partially matched by $ref.
     * @param $network string|IP4Map ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function includedInIP4Network($network)
    {
        if( $this->type != self::TypeIpNetmask && $this->type != self::TypeIpRange && !$this->isTmpAddr() )
            return 0;

        if( is_object($network) )
        {
            $networkMap = $network;
        }
        else
            $networkMap = IP4Map::mapFromText($network);

        $localEntry = $networkMap->getFirstMapEntry();
        if( $localEntry === null )
            return 0;

        $networkEntry = $this->getIP4Mapping()->getFirstMapEntry();
        if( $networkEntry === null )
            return 0;

        return cidr::netMatch($localEntry, $networkEntry);
    }

    /**
     * return 0 if not match, 1 if $network is fully included in this object, 2 if $network is partially matched by this object.
     * @param $network string|IP4Map ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function includesIP4Network($network)
    {
        if( $this->type != self::TypeIpNetmask && $this->type != self::TypeIpRange && !$this->isTmpAddr() )
            return 0;

        if( is_object($network) )
        {
            $networkMap = $network;
        }
        else
            $networkMap = IP4Map::mapFromText($network);

        $localEntry = $networkMap->getFirstMapEntry();
        if( $localEntry === null )
            return 0;

        $networkEntry = $this->getIP4Mapping()->getFirstMapEntry();
        if( $networkEntry === null )
            return 0;


        return cidr::netMatch($networkEntry, $localEntry);
    }


    public function removeReference($object)
    {
        $this->super_removeReference($object);

        // adding extra cleaning
        if( $this->isTmpAddr() && $this->countReferences() == 0 && $this->owner !== null )
        {
            $this->owner->remove($this);
        }

    }

    public function getNetworkMask()
    {
        if( $this->type !== self::TypeIpNetmask )
            return FALSE;

        $explode = explode('/', $this->value);

        if( count($explode) < 2 )
        {
            if(filter_var($this->value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
                return 128;
            else
                return 32;
        }


        else
            return intval($explode[1]);
    }

    /**
     * @return bool|string
     */
    public function getNetworkValue()
    {
        if( $this->type !== self::TypeIpNetmask )
            return FALSE;

        $explode = explode('/', $this->value);

        if( count($explode) < 2 )
            return $this->value;

        else
            return $explode[0];
    }

    public function nameIsValidRuleIPEntry()
    {
        if( filter_var($this->name, FILTER_VALIDATE_IP) !== FALSE )
            return TRUE;

        $ex = explode('-', $this->name);

        if( count($ex) == 2 )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE || filter_var($ex[1], FILTER_VALIDATE_IP) === FALSE )
            {
                return FALSE;
            }
            return TRUE;
        }

        $ex = explode('/', $this->name);

        if( count($ex) != 2 )
            return FALSE;

        $mask = &$ex[1];
        if( !is_numeric($mask) )
            return FALSE;

        if( (int)$mask > 32 || (int)$mask < 0 )
            return FALSE;

        if( filter_var($ex[0], FILTER_VALIDATE_IP) !== FALSE )
            return TRUE;

        return FALSE;

    }

    public function merge_tag_description_to( $pickedObject, $apiMode = false )
    {
        foreach( $this->tags->getAll() as $tag )
        {
            PH::print_stdout( "     - merge TAG: '{$tag->name()}' before deleting...");
            /** @var  Tag $tag*/
            if( !$pickedObject->tags->hasTag( $tag ) )
            {
                $newTag = $pickedObject->owner->owner->tagStore->find( $tag->name() );
                if( $newTag === null )
                {
                    $newTag = $pickedObject->owner->owner->tagStore->createTag( $tag->name() );
                    $newTag->setColor( $tag->getColor() );
                    $newTag->addComments( $tag->getComments() );

                    if( $apiMode )
                        $newTag->API_sync();
                }
                
                if( $apiMode )
                {
                    $pickedObject->tags->API_addTag( $newTag );
                    if( $tag !== $newTag)
                    {
                        $tag->replaceMeGlobally($newTag);
                        $tag->owner->API_removeTag($tag);
                    }
                }
                else
                {
                    $pickedObject->tags->addTag( $newTag );
                    if( $tag !== $newTag)
                    {
                        $tag->replaceMeGlobally($newTag);
                        if( $tag->owner !== null )
                            $tag->owner->removeTag($tag);
                    }
                }
            }
        }

        $pickedObject->description_merge( $this );
    }

    public function getIPcount()
    {
        $value = $this->value();

        if( $this->isType_ipNetmask() )
        {
            $startEndArray = CIDR::stringToStartEnd( $value );
            $start = $startEndArray['start'];
            $end = $startEndArray['end'];

            $int = $end - $start + 1;
        }
        elseif( $this->isType_FQDN() )
            return false;
        elseif( $this->isType_ipWildcard() )
        {
            //count IP addresses
            return false;
        }
        elseif( $this->isType_ipRange() )
        {
            $startEndArray = CIDR::stringToStartEnd( $value );
            $start = $startEndArray['start'];
            $end = $startEndArray['end'];

            $int = $end - $start + 1;
        }
        elseif( $this->isType_TMP() )
            $int = 1;


        return $int;
    }

    public function replaceIPbyObject( $context, $prefix = array() )
    {
        if(filter_var($this->value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            $maxmaskvalue = 128;
        else
            $maxmaskvalue = 32;

        if( empty( $prefix ) )
        {
            $prefix['host'] = "H-";

            $prefix['network'] = "N-";
            $prefix['networkmask'] = "-";

            $prefix['range'] = "R-";
            $prefix['rangeseparator'] = "-";
        }
        $rangeDetected = FALSE;


        $objectRefs = $this->getReferences();
        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            {
                $clearForAction = FALSE;
                $string = "because its used in unsupported class $class";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
        }

        $pan = PH::findRootObjectOrDie($this->owner);

        if( strpos($this->name(), '-') === FALSE )
        {
            $explode = explode('/', $this->name());

            if( count($explode) > 1 )
            {
                $name = $explode[0];
                $mask = $explode[1];
            }
            else
            {
                $name = $this->name();
                $mask = $maxmaskvalue;
            }

            if( $mask > $maxmaskvalue || $mask < 0 )
            {
                $string = "because of invalid mask detected : '$mask'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            if( filter_var($name, FILTER_VALIDATE_IP) === FALSE )
            {
                $string = "because of invalid IP detected : '$name'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            if( $mask == $maxmaskvalue )
            {
                $newName = $prefix['host'] . $name;
            }
            else
            {
                $newName = $prefix['network'] . $name . $prefix['networkmask'] . $mask;
            }
        }
        else
        {
            $rangeDetected = TRUE;
            $explode = explode('-', $this->name());
            $newName = $prefix['range'] . $explode[0] . $prefix['rangeseparator'] . $explode[1];
        }

        $string = "new object name will be $newName";
        PH::ACTIONlog( $context, $string );

        $objToReplace = $this->owner->find($newName);
        if( $objToReplace === null || $objToReplace->isType_TMP() )
        {
            if( $context->isAPI )
            {
                if( $rangeDetected )
                    $objToReplace = $this->owner->API_newAddress($newName, 'ip-range', $explode[0] . '-' . $explode[1]);
                else
                    $objToReplace = $this->owner->API_newAddress($newName, 'ip-netmask', $name . '/' . $mask);
            }
            else
            {
                if( $rangeDetected )
                    $objToReplace = $this->owner->newAddress($newName, 'ip-range', $explode[0] . '-' . $explode[1]);
                else
                    $objToReplace = $this->owner->newAddress($newName, 'ip-netmask', $name . '/' . $mask);
            }
        }
        else
        {
            $objMap = IP4Map::mapFromText($name . '/' . $mask);
            if( !$objMap->equals($objToReplace->getIP4Mapping()) )
            {
                $string = "because an object with same name exists but has different value";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
        }


        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);

                if( $class == 'AddressRuleContainer' )
                {
                    /** @var AddressRuleContainer $objectRef */
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    if( $objectRef->owner->isNatRule()
                        && $objectRef->name == 'snathosts'
                        && $objectRef->owner->sourceNatTypeIs_DIPP()
                        && $objectRef->owner->snatinterface !== null )
                    {
                        $string = "because it's a SNAT with Interface IP address";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        continue;
                    }

                    $oldName = $this->name();
                    $newName = $objToReplace->name();

                    if( $context->isAPI )
                        $objectRef->API_add($objToReplace);
                    else
                        $objectRef->addObject($objToReplace);

                    if( $oldName !== $newName )
                    {
                        if( $context->isAPI )
                            $objectRef->API_remove($this);
                        else
                            $objectRef->remove($this);
                    }

                }
                elseif( $class == 'NatRule' )
                {
                    /** @var NatRule $objectRef */
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    if( $context->isAPI )
                        $objectRef->API_setDNAT($objToReplace, $objectRef->dnatports);
                    else
                        $objectRef->replaceReferencedObject($this, $objToReplace);
                }
                else
                {
                    derr("unsupported class '$class'");
                }
            }
        }
    }


    static protected $templatexml = '<entry name="**temporarynamechangeme**"><ip-netmask>tempvaluechangeme</ip-netmask></entry>';

}


