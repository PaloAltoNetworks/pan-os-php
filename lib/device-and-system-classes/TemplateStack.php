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

class TemplateStack
{
    use ReferenceableObject;
    use PathableName;
    use PanSubHelperTrait;

    /** @var PanoramaConf */
    public $owner;

    /** @var  array */
    public $templates = array();

    protected $templateRoot = null;

    public $xmlroot = null;

    public $FirewallsSerials = array();

    /** @var CertificateStore */
    public $certificateStore = null;

    /** @var  PANConf */
    public $deviceConfiguration;

    /**
     * Template constructor.
     * @param string $name
     * @param PanoramaConf $owner
     */
    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->deviceConfiguration = new PANConf(null, null, $this);

        $this->certificateStore = new CertificateStore($this);
        $this->certificateStore->setName('certificateStore');
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("templatestack name not found\n", $xml);

        #print "template-stack: ".$this->name."\n";
        $this->templateRoot = DH::findFirstElement('templates', $xml);

        if( $this->templateRoot !== FALSE )
        {
            foreach( $this->templateRoot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;

                $ldv = $node->textContent;

                $template = $this->owner->findTemplate( $ldv );
                $this->templates[] = $template;

                $template->addReference( $this );
            }
        }

        $tmp = DH::findFirstElement('devices', $xml);
        if( $tmp !== false )
        {
            $this->FirewallsSerials = $this->owner->managedFirewallsStore->get_serial_from_xml($tmp, TRUE);
            #$this->FirewallsSerials = $this->owner->managedFirewallsStore->get_serial_from_xml($tmp);
            foreach( $this->FirewallsSerials as $serial => $managedFirewall )
            {
                if( $managedFirewall !== null )
                {
                    $managedFirewall->addTemplateStack($this->name);
                    $managedFirewall->addReference( $this );
                }
            }
        }

        //Todo: how common it is to have device config inside templateStack???
        $tmp = DH::findFirstElement('config', $xml);

        if( $tmp !== false )
        {
            $this->deviceConfiguration->load_from_domxml($tmp);

            $shared = DH::findFirstElement('shared', $tmp);
            if( $shared !== false )
            {
                //
                // Extract Certificate objects
                //
                $tmp = DH::findFirstElement('certificate', $shared);
                if( $tmp !== FALSE )
                {
                    $this->certificateStore->load_from_domxml($tmp);
                }
                // End of Certificate objects extraction
            }
        }


    }

    public function name()
    {
        return $this->name;
    }

    public function setName($newName)
    {
        $this->xmlroot->setAttribute('name', $newName);

        $this->name = $newName;
    }

    public function isTemplateStack()
    {
        return TRUE;
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param Template $newObject Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function addTemplate($newObject, $position, $rewriteXml = TRUE)
    {
        if( !is_object($newObject) )
            derr("Only objects can be passed to this function");

        if( get_class( $newObject ) !== "Template" )
        {
            mwarning("only objects of class Template can be added to a Template-Stack!");
            return FALSE;
        }

        if( $position !== 'bottom' )
        {
            mwarning("Template position only bottom is supported right now!");
            return null;
        }


        if( !in_array($newObject, $this->templates, TRUE) )
        {
            $this->templates[] = $newObject;
            $newObject->addReference($this);
            if( $rewriteXml && $this->owner !== null )
            {
                DH::createElement($this->templateRoot, 'member', $newObject->name());
            }

            return TRUE;
        }

        return FALSE;
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param Template $newObject Object to be added
     * @return bool
     */
    public function API_addTemplate($newObject, $position)
    {
        $ret = $this->addTemplate($newObject, $position);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();
            if( $con->isAPI() )
                $con->sendSetRequest($xpath."/templates", "<member>{$newObject->name()}</member>");
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='" . $this->name . "']";

        return $str;
    }

}

