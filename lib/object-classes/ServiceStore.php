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

class ServiceStore
{
    use PathableName;
    use XmlConvertible;

    /** @var PanoramaConf|PANConf|VirtualSystem|DeviceGroup */
    public $owner;

    public $name;

    /** @var null|ServiceStore */
    public $parentCentralStore = null;

    protected $appdef = FALSE;

    /** @var Service[]|ServiceGroup[] */
    protected $_all = array();

    /** @var Service[] */
    protected $_serviceObjects = array();

    /** @var ServiceGroup[] */
    protected $_serviceGroups = array();
    /** @var Service[] */
    protected $_tmpServices = array();

    /**
     * @var DOMElement
     */
    public $serviceRoot;
    /**
     * @var DOMElement
     */
    public $serviceGroupRoot;


    public function __construct($owner)
    {
        $this->owner = $owner;

        $this->setParentCentralStore( 'serviceStore' );
    }


    /**
     * @param DOMElement $xml
     */
    public function load_services_from_domxml($xml)
    {
        $this->serviceRoot = $xml;

        $duplicatesRemoval = array();

        foreach( $this->serviceRoot->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $ns = new Service('', $this);
            $ns->load_from_domxml($node);
            if( isset($this->_all[$ns->name()]) )
            {
                mwarning("service named '{$ns->name()}' already exists and was ignored, check your XML configuration", $node, false);
                if( PH::$enableXmlDuplicatesDeletion )
                    $duplicatesRemoval[] = $node;

                continue;
            }

            if( $ns->name() == "application-default")
            {
                mwarning("service named '{$ns->name()}' is created, PAN-OS Security Rule default behaviour is affected", $node, false);
            }

            $this->_serviceObjects[$ns->name()] = $ns;
            $this->_all[$ns->name()] = $ns;
        }

        foreach( $duplicatesRemoval as $node )
        {
            $node->parentNode->removeChild($node);
        }
    }


    /**
     * Returns an Array with all Service , ServiceGroups, TmpService objects in this store
     * @param $withFilter string|null
     * @param bool $sortByDependencies
     * @return Service[]|ServiceGroup[]
     */
    public function all($withFilter = null, $sortByDependencies = FALSE)
    {
        $query = null;

        if( $withFilter !== null && $withFilter != '' )
        {
            $errMesg = '';
            $query = new RQuery('service');
            if( $query->parseFromString($withFilter, $errMsg) === FALSE )
                derr("error while parsing query: {$errMesg}");

            $res = array();
            foreach( $this->_all as $obj )
            {
                if( $query->matchSingleObject($obj) )
                    $res[] = $obj;
            }
            return $res;
        }

        if( !$sortByDependencies )
            return $this->_all;

        $result = array();

        foreach( $this->_tmpServices as $object )
            $result[] = $object;

        foreach( $this->_serviceObjects as $object )
            $result[] = $object;

        foreach( $this->serviceGroups(TRUE) as $object )
            $result[] = $object;

        return $result;
    }

    /**
     * @return Service[]
     */
    public function serviceObjects()
    {
        return $this->_serviceObjects;
    }

    /**
     * @return ServiceGroup[]
     * @var bool $sortByDependencies
     */
    public function serviceGroups($sortByDependencies = FALSE)
    {
        if( !$sortByDependencies )
            return $this->_serviceGroups;

        $result = array();

        $sortingArray = array();

        foreach( $this->_serviceGroups as $group )
        {
            $sortingArray[$group->name()] = array();

            $subGroups = $group->expand(TRUE);

            foreach( $subGroups as $subGroup )
            {
                if( !$subGroup->isGroup() )
                    continue;
                if( $subGroup->owner !== $this )
                    continue;

                $sortingArray[$group->name()][$subGroup->name()] = TRUE;
            }
        }

        $loopCount = 0;
        $listed_loop_group = array();
        while( count($sortingArray) > 0 )
        {
            foreach( $sortingArray as $groupName => &$groupDependencies )
            {
                if( count($groupDependencies) == 0 )
                {
                    $result[] = $this->_serviceGroups[$groupName];
                    unset($sortingArray[$groupName]);

                    foreach( $sortingArray as &$tmpGroupDeps )
                    {
                        if( isset($tmpGroupDeps[$groupName]) )
                            unset($tmpGroupDeps[$groupName]);
                    }
                }
                elseif( count($groupDependencies) == 1 )
                {
                    unset($sortingArray[$groupName]);

                    foreach( $sortingArray as &$tmpGroupDeps )
                    {
                        if(!isset($listed_loop_group[$groupName]))
                        {
                            $listed_loop_group[$groupName] = $groupName;
                            mwarning( "servicegroup: ".$groupName." is maybe not listed as it is involved in a loop usage", null, false );
                        }

                        if( isset($tmpGroupDeps[$groupName]) )
                            unset($tmpGroupDeps[$groupName]);
                    }
                }
            }

            $loopCount++;
            if( $loopCount > 40 )
            {
                PH::print_stdout("ServiceGroup LOOP detected | please manual manipulate your configuration file, check the output above!!");
                derr("cannot determine groups dependencies after 40 loops iterations: is there too many nested groups?", null, False);
            }

        }

        return $result;
    }

    /**
     * @return Service[]
     */
    public function serviceTmpObjects()
    {
        return $this->_tmpServices;
    }


    /**
     * @param $xml DOMElement
     */
    public function load_servicegroups_from_domxml($xml)
    {
        $this->serviceGroupRoot = $xml;

        $duplicatesRemoval = array();

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $name = $node->getAttribute('name');
            if( strlen($name) == 0 )
                derr("unsupported empty group name", $node);

            $ns = new ServiceGroup($name, $this);

            if( isset($this->_tmpServices[$name]) )
            {
                $tmpObj = $this->_tmpServices[$name];
                $tmpObj->replaceMeGlobally($ns);
                $this->remove($tmpObj);
            }

            if( isset($this->_all[$name]) )
            {
                if( PH::$enableXmlDuplicatesDeletion )
                    $duplicatesRemoval[] = $node;
                else
                    mwarning("an object with name '{$name}' already exists in this store, please investigate your xml file", $node, false);
                continue;
            }

            $this->_serviceGroups[$name] = $ns;
            $this->_all[$name] = $ns;
        }

        foreach( $duplicatesRemoval as $node )
        {
            $node->parentNode->removeChild($node);
        }

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != 1 ) continue;

            $name = $node->getAttribute('name');
            if( isset( $this->_serviceGroups[$name] ) )
            {
                $ns = $this->_serviceGroups[$name];
                $ns->load_from_domxml($node);
            }
            else
                mwarning( "earlier warning available that: an object with name '{$name}' already exists in this store, please investigate your xml file as this will be ignored and could eventually be lost.",$node, false);
        }
    }


    public function count()
    {
        return count($this->_all);
    }


    /**
     * returns the count of ServiceGroups in this store
     *
     */
    public function countServiceGroups()
    {

        return count($this->_serviceGroups);
    }

    /**
     * returns the count of Services (ie not groups) in this store
     *
     */
    public function countServices()
    {
        return count($this->_serviceObjects);
    }


    public function countTmpServices()
    {
        return count($this->_tmpServices);
    }


    /**
     *
     * @ignore
     */
    protected function findParentCentralStore( $storeType )
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $curo = $this;
            while( isset($curo->owner) && $curo->owner !== null )
            {
                if( isset($curo->owner->$storeType) && $curo->owner->$storeType !== null )
                {
                    $this->parentCentralStore = $curo->owner->$storeType;
                    return;
                }
                $curo = $curo->owner;
            }
        }
    }

    /**
     *
     * @ignore
     */
    protected function setParentCentralStore( $storeType )
    {
        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->$storeType;

        elseif( isset($owner->parentContainer) && $owner->parentContainer !== null )
            $this->parentCentralStore = $owner->parentContainer->$storeType;

        else
            $this->findParentCentralStore( $storeType );
    }

    /**
     * @param string $objectName
     * @param null $ref
     * @param bool $nested
     * @return null|Service|ServiceGroup
     */
    public function find($objectName, $ref = null, $nested = TRUE)
    {
        $f = null;

        if( isset($this->_all[$objectName]) )
        {
            $foundObject = $this->_all[$objectName];
            $foundObject->addReference($ref);
            return $foundObject;
        }


        if( $nested && isset($this->panoramaShared) )
        {
            $f = $this->panoramaShared->find($objectName, $ref, FALSE);

            if( $f !== null )
                return $f;
        }
        else if( $nested && isset($this->panoramaDG) )
        {
            $f = $this->panoramaDG->find($objectName, $ref, FALSE);
            if( $f !== null )
                return $f;
        }


        if( $nested && $this->parentCentralStore !== null )
        {
            $f = $this->parentCentralStore->find($objectName, $ref, $nested);
        }

        return $f;
    }

    /**
     * @param $fn
     * @param null $ref
     * @param bool|true $nested
     * @return null|Service|ServiceGroup
     */
    public function findOrCreate($fn, $ref = null, $nested = TRUE)
    {
        $f = $this->find($fn, $ref, $nested);
        if( $f )
            return $f;

        $f = $this->createTmp($fn, $ref);

        return $f;
    }

    /**
     * @param $name
     * @return null|Service
     */
    public function findTmpService($name)
    {
        if( isset($this->_tmpServices[$name]) )
            return $this->_tmpServices[$name];
        return null;
    }


    /**
     * @param Service|ServiceGroup $s
     * @param bool $cleanInMemory
     * @return bool
     */
    public function remove($s, $cleanInMemory = FALSE)
    {
        $class = get_class($s);

        $objectName = $s->name();


        if( !isset($this->_all[$objectName]) )
        {
            mdeb('Tried to remove an object that is not part of this store');
            return FALSE;
        }

        unset($this->_all[$objectName]);


        if( $class == 'Service' )
        {
            if( $s->isTmpSrv() )
            {
                unset($this->_tmpServices[$objectName]);
            }
            else
            {
                unset($this->_serviceObjects[$objectName]);
            }
        }
        else if( $class == 'ServiceGroup' )
        {
            unset($this->_serviceGroups[$objectName]);
            if( $cleanInMemory )
                $s->removeAll(FALSE);
        }
        else
            derr('invalid class found');

        $s->owner = null;


        if( !$s->isTmpSrv() )
        {
            if( $class == "Service" )
            {
                if( count($this->_serviceObjects) > 0 )
                    $this->serviceRoot->removeChild($s->xmlroot);
                else
                    DH::clearDomNodeChilds($this->serviceRoot);

            }
            else if( $class == "ServiceGroup" )
            {
                if( count($this->_serviceGroups) > 0 )
                    $this->serviceGroupRoot->removeChild($s->xmlroot);
                else
                    DH::clearDomNodeChilds($this->serviceGroupRoot);
            }
            else
                derr('unsupported');
        }

        if( $cleanInMemory )
            $s->xmlroot = null;

        return TRUE;
    }

    /**
     * @param Service|ServiceGroup $s
     * @param bool $cleanInMemory
     * @return bool
     */
    public function API_remove($s, $cleanInMemory = FALSE)
    {
        $xpath = null;

        if( !$s->isTmpSrv() )
            $xpath = $s->getXPath();

        $ret = $this->remove($s, $cleanInMemory);

        if( $ret && !$s->isTmpSrv() )
        {
            $con = findConnectorOrDie($this);
            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }


    public function rewriteServiceStoreXML()
    {
        DH::clearDomNodeChilds($this->serviceRoot);
        foreach( $this->_serviceObjects as $s )
        {
            $this->serviceRoot->appendChild($s->xmlroot);
        }
    }

    public function rewriteServiceGroupStoreXML()
    {
        DH::clearDomNodeChilds($this->serviceGroupRoot);
        foreach( $this->_serviceGroups as $s )
        {
            $this->serviceGroupRoot->appendChild($s->xmlroot);
        }
    }

    /**
     * @param Service|ServiceGroup $s
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function add($s, $rewriteXml = TRUE)
    {
        $objectName = $s->name();

        // there is already an object named like that
        if( isset($this->_all[$objectName]) && $this->_all[$objectName] !== $s )
        {
            derr('You cannot add object with same name in a store');
        }

        $class = get_class($s);

        if( $class == 'Service' )
        {
            if( $s->isTmpSrv() )
            {
                $this->_tmpServices[$objectName] = $s;
            }
            else
            {
                $this->_serviceObjects[$objectName] = $s;
                if( $rewriteXml )
                {
                    if( $this->serviceRoot == null )
                        $this->serviceRoot = DH::findFirstElementOrCreate( 'service', $this->owner->xmlroot );
                    $this->serviceRoot->appendChild($s->xmlroot);
                }

            }

            $this->_all[$objectName] = $s;
        }
        elseif( $class == 'ServiceGroup' )
        {
            $this->_serviceGroups[$objectName] = $s;
            $this->_all[$objectName] = $s;

            if( $rewriteXml )
            {
                if( $this->serviceGroupRoot == null )
                    $this->serviceGroupRoot = DH::findFirstElementOrCreate( 'service-group', $this->owner->xmlroot );
                $this->serviceGroupRoot->appendChild($s->xmlroot);
            }

        }
        else
            derr('invalid class found');

        $s->owner = $this;


        return TRUE;
    }

    private function &getBaseXPath()
    {
        $class = get_class($this->owner);

        if( $class == 'PanoramaConf' || $class == 'PANConf' )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();

        return $str;
    }

    public function &getServiceStoreXPath()
    {
        $path = $this->getBaseXPath() . '/service';
        return $path;
    }

    public function &getServiceGroupStoreXPath()
    {
        $path = $this->getBaseXPath() . '/service-group';
        return $path;
    }

    /**
     * @param $name string
     * @param $protocol string
     * @param $destinationPorts string
     * @param $description string
     * @return Service
     * @throws Exception
     */
    public function newService($name, $protocol, $destinationPorts, $description = '', $sourcePorts = null)
    {

        if( isset($this->_all[$name]) )
            derr("A Service named '$name' already exists");

        $s = new Service($name, $this, TRUE);
        $s->setProtocol($protocol);
        $s->setDestPort($destinationPorts);
        $s->setDescription($description);
        if( $sourcePorts !== null )
            $s->setSourcePort($sourcePorts);
        $this->add($s);
        return $s;

    }

    /**
     * @param $name string
     * @param $protocol string
     * @param $destinationPorts string
     * @param $description string
     * @return Service
     * @throws Exception
     */
    public function API_newService($name, $protocol, $destinationPorts, $description = '', $sourcePorts = null)
    {
        $newObject = $this->newService($name, $protocol, $destinationPorts, $description, $sourcePorts);

        $con = findConnectorOrDie($this);
        $xpath = $newObject->getXPath();
        $con->sendSetRequest($xpath, $newObject, TRUE);

        return $newObject;
    }

    /**
     * Creates a new Service Group named '$name' . Will exit with error if a group with that
     * name already exists
     * @param string $name
     * @return ServiceGroup
     **/
    public function newServiceGroup($name)
    {
        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create ServiceGroup named '" . $name . "' as this name is already in use");

        $newGroup = new ServiceGroup($name, $this, TRUE);
        $newGroup->setName($name);
        $this->add($newGroup);

        return $newGroup;

    }

    /**
     * Creates a new Service Group named '$name' . Will exit with error if a group with that
     * name already exists
     * @param $name string
     * @return ServiceGroup
     **/
    public function API_newServiceGroup($name)
    {
        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create ServiceGroup named '" . $name . "' as this name is already in use");

        $newObject = $this->newServiceGroup($name);

        $con = findConnectorOrDie($this);
        $xpath = $newObject->getXPath();
        $con->sendSetRequest($xpath, $newObject, TRUE);

        return $newObject;
    }

    function createTmp($name, $ref = null)
    {
        $f = new Service($name, $this);
        $this->_tmpServices[$name] = $f;
        $this->_all[$name] = $f;
        $f->type = 'tmp';
        $f->addReference($ref);

        return $f;
    }

    /**
     * @return Service[]|ServiceGroup[]
     */
    public function nestedPointOfView()
    {
        $current = $this;

        $objects = array();

        while( TRUE )
        {
            foreach( $current->_serviceObjects as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
            }
            foreach( $current->_serviceGroups as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
            }

            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->serviceStore;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->serviceStore;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->serviceStore;
            else
                break;
        }

        return $objects;
    }

    /**
     * @return Service[]|ServiceGroup[]
     */
    public function nestedPointOfView_sven()
    {
        $current = $this;

        $objects = array();

        while( TRUE )
        {
            if( get_class( $current->owner ) == "PanoramaConf" )
                $location = "shared";
            else
                $location = $current->owner->name();

            foreach( $current->_serviceObjects as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    if( $tmp_ref_count == 0 )
                    {
                        //Todo: check if object value is same; if same to not add ref
                        if( $location != "shared" )
                            foreach( $o->refrules as $ref )
                                $tmp_o->addReference( $ref );
                    }
                }
            }
            foreach( $current->_serviceGroups as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    if( $tmp_ref_count == 0 )
                    {
                        //Todo: check if object value is same; if same to not add ref
                        if( $location != "shared" )
                            foreach( $o->refrules as $ref )
                                $tmp_o->addReference( $ref );
                    }
                }
            }

            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->serviceStore;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->serviceStore;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null )
                $current = $current->owner->owner->serviceStore;
            else
                break;
        }

        return $objects;
    }

    /**
     * @param Service|ServiceGroup $h
     * @param $oldName
     * @return bool
     */
    public function referencedObjectRenamed($h, $oldName)
    {
        if( $this->_all[$oldName] !== $h )
        {
            mwarning("Unexpected : object is not part of this library");
            return FALSE;
        }

        $newName = $h->name();

        unset($this->_all[$oldName]);
        $this->_all[$newName] = $h;

        $class = get_class($h);

        if( $class == 'Service' )
        {
            if( $h->isTmpSrv() )
            {
                unset($this->_tmpServices[$oldName]);
                $this->_tmpServices[$newName] = $h;
            }
            else
            {
                unset($this->_serviceObjects[$oldName]);
                $this->_serviceObjects[$newName] = $h;
            }
        }
        elseif( $class == 'ServiceGroup' )
        {
            unset($this->_serviceGroups[$oldName]);
            $this->_serviceGroups[$newName] = $h;
        }
        else
            derr('unsupported class');

        return TRUE;
    }

    /**
     * @param Service|ServiceGroup $object
     * @return bool
     */
    public function inStore($object)
    {
        if( $object === null )
            derr('a NULL object, really ?');

        if( isset($this->_all[$object->name()]) )
            if( $this->_all[$object->name()] === $object )
                return TRUE;

        return FALSE;

    }


    public function countUnused()
    {
        $count = 0;
        foreach( $this->_all as $o )
        {
            if( $o->countReferences() == 0 )
                $count++;
        }

        return $count;
    }

    public function countUnusedServices()
    {
        $count = 0;
        foreach( $this->_serviceObjects as $o )
        {
            if( $o->countReferences() == 0 )
                $count++;
        }

        return $count;
    }

    public function countUnusedServiceGroups()
    {
        $count = 0;
        foreach( $this->_serviceGroups as $o )
        {
            if( $o->countReferences() == 0 )
                $count++;
        }

        return $count;
    }


    /**
     * @param string $base
     * * @param bool $nested
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
     */
    public function findAvailableName($base, $nested = TRUE, $suffix = '', $startCount = '')
    {
        $maxl = 31;
        $basel = strlen($base);
        $suffixl = strlen($suffix);
        $inc = $startCount;
        $basePlusSuffixL = $basel + $suffixl;

        while( TRUE )
        {

            $incl = strlen(strval($inc));

            if( $basePlusSuffixL + $incl > $maxl )
            {
                $newname = substr($base, 0, $basel - $suffixl - $incl) . $suffix . $inc;
            }
            else
                $newname = $base . $suffix . $inc;

            if( $this->find($newname, null, $nested) === null )
                return $newname;

            if( $startCount == '' )
                $startCount = 0;

            $inc++;
        }
    }

    public function findByProtocolDstSrcPort($protocol, $destinationPort, $sourcePort = "")
    {
        foreach( $this->_serviceObjects as $service )
        {
            if( $service->protocol() == $protocol )
            {
                if( $service->getDestPort() == $destinationPort )
                {
                    if( $service->getSourcePort() == $sourcePort )
                        return $service;
                }
            }
        }

        return null;
    }

    function replaceServiceWith($object, $newObjectName, $padding, $isAPI)
    {
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($newObjectName);

        if( $foundObject === null )
            derr("cannot find an object named '{$newObjectName}'");

        /** @var ServiceGroup|ServiceRuleContainer $objectRef */

        foreach( $objectRefs as $objectRef )
        {
            PH::print_stdout( $padding . " * replacing in {$objectRef->toString()}" );
            if( $objectRef === $foundObject || $objectRef->name() == $foundObject->name() )
            {
                PH::print_stdout( $padding . "   - SKIPPED : cannot replace an object by itself" );
                continue;
            }
            if( $isAPI )
                $objectRef->API_replaceReferencedObject($object, $foundObject);
            else
                $objectRef->replaceReferencedObject($object, $foundObject);
        }
    }

    public function storeName()
    {
        return "serviceStore";
    }

    /**
     * Returns an Array with all Service|ServiceGroup inside this store
     * @return Service[]|ServiceGroup[]
     */
    public function &resultingObjectSet()
    {

        $res = array();

        if( isset($this->owner->parentDeviceGroup) )
        {
            $varName = $this->storeName();
            /** @var ServiceStore $var */
            $var = $this->owner->parentDeviceGroup->$varName;
            #$var = $this->owner->parentDeviceGroup->serviceStore;
            $res = $var->resultingObjectSet();
        }
        elseif( $this->owner->isPanorama() )
        {
            $varName = $this->storeName();
            /** @var ServiceStore $var */
            $var = $this->owner->$varName;
            #$var = $this->owner->serviceStore;
            $res = $var->all();
        }

        if( !$this->owner->isPanorama() )
            $res = array_merge($res, $this->all());

        return $res;
    }
}
