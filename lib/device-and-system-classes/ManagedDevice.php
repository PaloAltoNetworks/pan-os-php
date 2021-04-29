<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class ManagedDevice
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var  ManagedDeviceStore */
    public $owner;

    public $devicegroup;
    public $template;
    public $template_stack;


    function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
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
}