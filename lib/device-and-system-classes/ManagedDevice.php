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

class ManagedDevice
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use PanSubHelperTrait;

    /** @var  ManagedDeviceStore */
    public $owner;

    public $devicegroup;
    public $template;
    public $template_stack;

    public $deviceContainer;
    public $vsysContainer;


    public $isConnected = false;
    public $mgmtIP;
    public $version;
    public $model;
    public $hostname;

    function __construct($name, $owner )
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        if( $this->owner->owner->isFawkes() )
        {
            #DH::DEBUGprintDOMDocument( $xml );

            $tmp = DH::findFirstElement('device-container', $xml);
            if( $tmp != false )
                $this->deviceContainer = $tmp->textContent;

            $deviceOnPrem = $this->owner->owner->findDeviceOnPrem( $this->deviceContainer );
            if( $deviceOnPrem !== null )
            {
                $deviceOnPrem->devices[$this->name()] = $this;
                $this->addReference( $deviceOnPrem );
            }

            $tmp = DH::findFirstElement('vsys', $xml);
            if( $tmp != false )
            {
                $vsysEntry = DH::findFirstElement('entry', $tmp);
                $this->vsysContainer = DH::findAttribute('name', $vsysEntry);

                $tmp = DH::findFirstElement('vsys-container', $vsysEntry);
                if( $tmp != false )
                {
                    if( $tmp->textContent !== $this->deviceContainer )
                        mwarning( "manageddevice: ".$this->name()." has device-container: ".$this->deviceContainer." but vsys-container: ".$tmp->textContent );
                }
            }
        }
    }

    public function addDeviceGroup($devicegroup)
    {
        $this->devicegroup = $devicegroup;
    }

    public function addTemplate($template)
    {
        $this->template = $template;
    }

    public function addTemplateStack($template_stack)
    {
        $this->template_stack = $template_stack;
    }

    public function getDeviceGroup()
    {
        return $this->devicegroup;
    }

    public function getTemplate()
    {
        return $this->template;
    }

    public function getTemplateStack()
    {
        return $this->template_stack;
    }

    public function getDeviceContainer()
    {
        return $this->deviceContainer;
    }

    public function getDeviceVsysContainer()
    {
        return $this->vsysContainer;
    }

    public function isManagedDevice()
    {
        return TRUE;
    }
}