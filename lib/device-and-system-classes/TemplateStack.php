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

class TemplateStack
{
    use ReferenceableObject;
    use PathableName;
    use PanSubHelperTrait;

    /** @var PanoramaConf */
    public $owner;

    /** @var  array */
    public $templates = array();

    protected $FirewallsSerials = array();

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
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("templatestack name not found\n", $xml);


        //Todo: how common it is to have device config inside templateStack???

        #print "template-stack: ".$this->name."\n";
        $tmp = DH::findFirstElement('templates', $xml);

        if( $tmp !== FALSE )
        {
            foreach( $tmp->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;

                $ldv = $node->textContent;

                $template = $this->owner->findTemplate( $ldv );
                $this->templates[] = $template;

            }
        }

        $this->FirewallsSerials = $this->owner->managedFirewallsStore->get_serial_from_xml($xml);
        foreach( $this->FirewallsSerials as $serial )
        {
            $managedFirewall = $this->owner->managedFirewallsStore->find($serial);
            if( $managedFirewall !== null )
                $managedFirewall->addTemplateStack($this->name);
        }

        $tmp = DH::findFirstElement('config', $xml);

        if( $tmp !== false )
        {
            $this->deviceConfiguration->load_from_domxml($tmp);
        }

    }

    public function name()
    {
        return $this->name;
    }

    public function isTemplateStack()
    {
        return TRUE;
    }

}

