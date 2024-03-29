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

class Sub
{
    public $rulebaseroot;
    public $defaultSecurityRules;

    private  $defaultSecurityRules_xml = "<default-security-rules>
                    <rules>
                      <entry name=\"intrazone-default\">
                        <action>allow</action>
                        <log-start>no</log-start>
                        <log-end>no</log-end>
                      </entry>
                      <entry name=\"interzone-default\">
                        <action>deny</action>
                        <log-start>no</log-start>
                        <log-end>no</log-end>
                      </entry>
                    </rules>
                  </default-security-rules>";

    function load_defaultSecurityRule( )
    {
        $finalroot = FALSE;
        $tmproot = DH::findFirstElement('default-security-rules', $this->rulebaseroot);
        if( $tmproot !== FALSE )
        {
            $finalroot = DH::findFirstElement('rules', $tmproot);
            if( $finalroot !== FALSE )
            {
                $finalroot = $this->createPartialDefaultSecurityRule( $finalroot );
            }
        }

        if( $tmproot === FALSE )
        {
            //Pan
            $finalroot = $this->createDefaultSecurityRule( );
        }


        return $finalroot;
    }

    function createDefaultSecurityRule( )
    {
        $ownerDocument = $this->rulebaseroot->ownerDocument;

        $newdoc = new DOMDocument;
        $newdoc->loadXML( $this->defaultSecurityRules_xml, XML_PARSE_BIG_LINES);
        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
        $node = $ownerDocument->importNode($node, TRUE);

        $node = $this->rulebaseroot->appendChild($node);

        $ruleNode = DH::findFirstElement('rules', $node);

        return $ruleNode;
    }

    function createPartialDefaultSecurityRule( $originalRuleNode )
    {
        $ownerDocument = $this->rulebaseroot->ownerDocument;

        $newdoc = new DOMDocument;
        $newdoc->loadXML( $this->defaultSecurityRules_xml, XML_PARSE_BIG_LINES);
        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
        $ruleNode = DH::findFirstElement('rules', $node);

        foreach( $ruleNode->childNodes as $defaultRule )
        {
            /** @var DOMElement $defaultRule */
            if( $defaultRule->nodeType != XML_ELEMENT_NODE )
                continue;

            $newName = DH::findAttribute( 'name', $defaultRule);
            $origName = DH::findFirstElementByNameAttr( "entry", $newName, $originalRuleNode);
            if( $origName === FALSE || $origName === null )
            {
                $node = $ownerDocument->importNode($defaultRule, TRUE);
                $originalRuleNode->appendChild($node);
            }
        }
        return $originalRuleNode;
    }
}

