<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


/**
 * Class VirutalRouterContainer
 * @property VirtualSystem $owner
 * @property VirtualRouter[] $o
 */
class VirtualRouterContainer extends ObjRuleContainer
{
    /** @var  NetworkPropertiesContainer */
    public $parentCentralStore;

    /**
     * @param VirtualSystem|DeviceCloud $owner
     * @param NetworkPropertiesContainer $centralStore
     */
    public function __construct($owner, $centralStore)
    {
        $this->owner = $owner;
        $this->parentCentralStore = $centralStore;

        $this->o = array();
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $interfaceString = $node->textContent;

            $interface = $this->parentCentralStore->findInterfaceOrCreateTmp($interfaceString);

            $this->add($interface);
        }
    }

    public function rewriteXML()
    {
        DH::clearDomNodeChilds($this->xmlroot);

        foreach( $this->o as $entry )
        {
            $tmp = DH::createElement($this->xmlroot, "member", $entry->name());
        }


    }

    /**
     * @return VirtualRouter[]
     */
    public function virtualrouters()
    {
        return $this->o;
    }

    /**
     * @param VirtualRouter[] $if
     * @param bool $caseSensitive
     * @return bool
     */
    public function hasVirtualRouter($if)
    {
        return $this->has($if);
    }

    /**
     * @param string $ifName
     * @param bool $caseSensitive
     * @return bool
     */
    public function hasVirtualRouterNamed($ifName, $caseSensitive = TRUE)
    {
        return $this->has($ifName, $caseSensitive);
    }

    /**
     * @param VirtualRouter $if
     * @return bool
     */
    public function addVirtualRouter($if)
    {
        if( $this->has($if) )
            return FALSE;

        $this->o[] = $if;
        $if->addReference($this);

        DH::createElement($this->xmlroot, 'member', $if->name());

        return TRUE;
    }


    /**
     * @param VirtualRouter $if
     * @return bool
     */
    public function API_addVirtualRouter($if)
    {
        //Todo: is this working for zone ??????????
        if( $this->addVirtualRouter($if) )
        {
            $con = findConnectorOrDie($this);

            $xpath = $this->owner->getXPath() . '/import/network/virtual-router';
            $importRoot = DH::findFirstElementOrDie('import', $this->owner->xmlroot);
            $networkRoot = DH::findFirstElementOrDie('network', $importRoot);
            $importIfRoot = DH::findFirstElementOrDie('virtual-router', $networkRoot);

            $con->sendSetRequest($xpath, "<member>{$if->name()}</member>");
        }

        return TRUE;
    }

    public function removeVirtualRouter($if)
    {
        if( $this->has($if) )
        {
            $tmp_key = array_search($if, $this->o);
            if( $tmp_key !== FALSE )
            {
                unset($this->o[$tmp_key]);
            }

            $if->removeReference($this);

            //DH::createElement( $this->xmlroot, 'member', $if->name() );

            $this->rewriteXML();

            return TRUE;
        }

        return FALSE;
    }


}