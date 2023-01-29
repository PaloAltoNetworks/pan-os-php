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

    function load_defaultSecurityRule( )
    {
        $tmproot = DH::findFirstElement('default-security-rules', $this->rulebaseroot);
        if( $tmproot !== FALSE )
        {
            $tmprulesroot = DH::findFirstElement('rules', $tmproot);
            if( $tmprulesroot !== FALSE )
            {
                if( DH::hasChild($tmprulesroot) )
                    $this->defaultSecurityRules->load_from_domxml($tmprulesroot);
                else
                {
                    $defaultSecurityRules_xml = "<default-security-rules>
                    <rules>
                      <entry name=\"intrazone-default\">
                        <log-end>no</log-end>
                      </entry>
                      <entry name=\"interzone-default\">
                        <log-end>no</log-end>
                        <action>deny</action>
                      </entry>
                    </rules>
                  </default-security-rules>";

                    $ownerDocument = $this->rulebaseroot->ownerDocument;

                    $newdoc = new DOMDocument;
                    $newdoc->loadXML( $defaultSecurityRules_xml );
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = $ownerDocument->importNode($node, TRUE);


                    $tmprulesroot = DH::findFirstElement('rules', $node);
                    if( $tmprulesroot !== FALSE )
                        $this->defaultSecurityRules->load_from_domxml($tmprulesroot);
                }
            }
        }
        else
        {
            $defaultSecurityRules_xml = "<default-security-rules>
                    <rules>
                      <entry name=\"intrazone-default\">
                        <log-end>no</log-end>
                      </entry>
                      <entry name=\"interzone-default\">
                        <log-end>no</log-end>
                        <action>deny</action>
                      </entry>
                    </rules>
                  </default-security-rules>";

            $ownerDocument = $this->rulebaseroot->ownerDocument;

            $newdoc = new DOMDocument;
            $newdoc->loadXML( $defaultSecurityRules_xml );
            $node = $newdoc->importNode($newdoc->firstChild, TRUE);
            $node = $ownerDocument->importNode($node, TRUE);


            $tmprulesroot = DH::findFirstElement('rules', $node);
            if( $tmprulesroot !== FALSE )
                $this->defaultSecurityRules->load_from_domxml($tmprulesroot);
        }
    }
}