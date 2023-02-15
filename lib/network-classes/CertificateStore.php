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
 * Class CertificateStore
 *
 * @property CertificateStore $parentCentralStore
 * @property Zone[] $o
 *
 */
class CertificateStore extends ObjStore
{
    /** @var DeviceGroup|PanoramaConf|VirtualSystem */
    public $owner;

    public $parentCentralStore = null;

    public static $childn = 'Certificate';

    /**
     * @param VirtualSystem|DeviceCloud|DeviceGroup|PanoramaConf|Container|FawkesConf|Template $owner
     */
    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;

        $this->findParentCentralStore( 'certificateStore' );
    }


    /**
     * looks for a certificate named $name ,return that Certificate object, null if not found
     * @param string $name
     * @return Certificate
     */
    public function find($name, $ref = null, $nested = false)
    {
        return $this->findByName($name, $ref, $nested);
    }


    /**
     * add a Zone to this store. Use at your own risk.
     * @param Zone
     * @param bool
     * @return bool
     */
    public function addCertificate(Certificate $certificate, $rewriteXML = TRUE)
    {
        $fasthashcomp = null;

        $ret = $this->add($certificate);

        if( $ret && $rewriteXML && !$certificate->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->appendChild($certificate->xmlroot);
        }
        return $ret;
    }


    /**
     * remove a Zone a Zone to this store.
     * @param Certificate
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeZone(Zone $certificate)
    {
        $ret = $this->remove($certificate);

        if( $ret && !$certificate->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($certificate->xmlroot);
        }

        return $ret;
    }

    /**
     * @param Zone|string $certificateName can be Zone object or certificate name (string). this is case sensitive
     * @return bool
     */
    public function hasCertificateNamed($certificateName, $caseSensitive = TRUE)
    {
        return $this->has($certificateName, $caseSensitive);
    }


    /**
     * @param string $ifName
     * @return null|Zone
     */
    public function findZoneMatchingInterfaceName($ifName)
    {
        foreach( $this->o as $certificate )
        {
            if( $certificate->isTmp() )
                continue;

            if( $certificate->attachedInterfaces->hasInterfaceNamed($ifName) )
                return $certificate;
        }

        return null;
    }

    /**
     * @param $vsys string|VirtualSystem
     * @return null|Zone
     */
    public function findZoneWithExternalVsys($vsys)
    {
        if( is_string($vsys) )
        {
            foreach( $this->o as $certificate )
            {
                if( $certificate->type() == 'external' )
                    if( isset($certificate->externalVsys[$vsys]) )
                        return $certificate;
            }
            return null;
        }

        foreach( $this->o as $certificate )
        {
            if( $certificate->type() == 'external' )
            {
                if( isset($certificate->externalVsys[$vsys->name()]) )
                    return $certificate;
            }
        }
        return null;
    }


    /**
     * return an array with all Zones in this store
     * @return Zone[]
     */
    public function certificates()
    {
        return $this->o;
    }


    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $certificate )
            {
                if( !$certificate->isTmp() )
                    $this->xmlroot->appendChild($certificate->xmlroot);
            }
        }

    }


    public function &getXPath()
    {
        if( $this->xmlroot === null )
            derr('unsupported on virtual Stores');

        $xpath = $this->owner->getXPath() . "/certificate/";

        return $xpath;

    }


    public function newZone($name, $type)
    {
        foreach( $this->certificates() as $certificate )
        {
            if( $certificate->name() == $name )
                derr("Zone: " . $name . " already available\n");
        }

        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create Zone named '" . $name . "' as this name is already in use ");

        $ns = new Certificate($name, $this, TRUE, $type);

        $this->addCertificate($ns);

        return $ns;

    }


}



