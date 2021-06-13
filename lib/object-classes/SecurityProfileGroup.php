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

class SecurityProfileGroup
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var SecurityProfileGroupStore|null */
    public $owner = null;

    /*
     * FAWKES
     *    <dns-security>    <spyware>   <vulnerability> <url-filtering> <file-blocking> <saas-security> <virus-and-wildfire-analysis>
     */
    private $secprof_array = array('virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering');
    private $secprof_fawkes_array = array('virus-and-wildfire-analysis-analysis', 'spyware', 'vulnerability', 'file-blocking', 'dns-security', 'url-filtering');

    /*
     * FAWKES
     * define new ProfileStore:
     * ->VirusWildfireProfileStore; DnsSecurityProfileStore; SaasSecurityProfileStore
     */
    private $secprof_store = array( 'AntiVirusProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'WildfireProfileStore', 'URLProfileStore' );
    private $secprof_fawkes_store = array( 'VirusAndWildfireProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'DNSSecurityProfileStore', 'URLProfileStore' );


    public $secprofiles = array();

    /** @var string|null */
    public $comments;

    public $hash = null;

    /**
     * @param string $name
     * @param SecurityProfileGroupStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElement('entry', $doc);

            if( $owner->xmlroot === null )
                $owner->createXmlRoot();

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot, $owner);

            $this->setName($name);
        }

        //Panorama
        if( get_class( $owner->owner ) == "Container" || get_class( $owner->owner ) == "DeviceCloud" || get_class( $owner->owner ) == "FawkesConf" )
            $used_secprof_array = $this->secprof_fawkes_array;
        else
            $used_secprof_array = $this->secprof_array;

        foreach( $used_secprof_array as $secprof )
        {
            $this->secprofiles[$secprof] = null;
        }

        $this->owner = $owner;

    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
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
        $str = $this->owner->getSecurityProfileGroupStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }



    public function load_from_domxml(DOMElement $xml, $owner)
    {
        $this->xmlroot = $xml;
        $this->owner = $owner;

        $str = '';

        if( get_class( $owner->owner ) == "Container" || get_class( $owner->owner ) == "DeviceCloud" || get_class( $owner->owner ) == "FawkesConf" )
            $used_secprof_array = $this->secprof_fawkes_array;
        else
            $used_secprof_array = $this->secprof_array;


        $counter = count( $used_secprof_array );
        $i = 1;
        foreach( $used_secprof_array as $key => $secprof_type )
        {
            $tmp_type = DH::findFirstElement($secprof_type, $xml);
            if( $tmp_type != FALSE )
            {
                $tmp_type = DH::findFirstElement('member', $tmp_type);
                if( $tmp_type != null )
                {
                    //Panorama
                    if( get_class( $owner->owner ) == "Container" || get_class( $owner->owner ) == "DeviceCloud" || get_class( $owner->owner ) == "FawkesConf" )
                        $used_secprof_store = $this->secprof_fawkes_store;
                    else
                        $used_secprof_store = $this->secprof_store;

                    $tmp_store_name = $used_secprof_store[$key];
                    $profile = $this->owner->owner->$tmp_store_name->find( $tmp_type->nodeValue );
                    if( $profile != false )
                        $this->secprofiles[ $secprof_type ] = $profile;
                    else
                    {
                        //Todo: not a profile - default profile
                        #print "PROFILE: ".$tmp_type->nodeValue." not found\n";
                        $this->secprofiles[ $secprof_type ] = $tmp_type->nodeValue;
                    }

                    $str .= $secprof_type.':'.$tmp_type->nodeValue;
                    if( $i < $counter )
                    {
                        $str .= ',';
                        $i++;
                    }
                }
            }
        }

        $this->hash = md5( $str );

    }


    /**
     * @return string
     */
    public function getComments()
    {
        $ret = $this->comments;

        return $ret;
    }

    /**
     * * @param string $newComment
     * * @param bool $rewriteXml
     * @return bool
     */
    public function addComments($newComment, $rewriteXml = TRUE)
    {
        $oldComment = $this->comments;
        $newComment = $oldComment . $newComment;


        if( $this->xmlroot === null )
            return FALSE;

        if( $rewriteXml )
        {
            $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
            if( $commentsRoot === FALSE )
            {
                $child = new DOMElement('comments');
                $this->xmlroot->appendChild($child);
                $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
            }

            DH::setDomNodeText($commentsRoot, $newComment);
        }


        return TRUE;
    }

    /**
     * @param string $newComment
     * @return bool
     */
    public function API_addComments($newComment)
    {
        if( !$this->addComments($newComment) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
        $c->sendEditRequest($xpath . "/comments", DH::dom_to_xml($commentsRoot, -1, FALSE));
        $this->addComments($newComment);

        return TRUE;
    }

    /**
     * @return bool
     */
    public function deleteComments()
    {
        if( $this->xmlroot === null )
            return FALSE;

        $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
        $valueRoot = DH::findFirstElement('color', $this->xmlroot);
        if( $commentsRoot !== FALSE )
            $this->xmlroot->removeChild($commentsRoot);

        if( $valueRoot === FALSE )
            $this->xmlroot->nodeValue = "";

        return TRUE;
    }

    /**
     * @return bool
     */
    public function API_deleteComments()
    {
        if( !$this->deleteComments() )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }

    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
            DH::clearDomNodeChilds($this->xmlroot);

        foreach( $this->secprofiles as $key => $secprof)
        {
            if( $secprof != null )
            {
                $tmp = $this->owner->xmlroot->ownerDocument->createElement($key);
                $tmp1 = $this->xmlroot->appendChild( $tmp );

                $tmp = $this->owner->xmlroot->ownerDocument->createElement('member');
                $tmp1 = $tmp1->appendChild( $tmp );

                if( is_object( $secprof ) )
                {
                    $tmp = $this->owner->xmlroot->ownerDocument->createTextNode( $secprof->name() );
                }
                else
                {
                    $tmp = $this->owner->xmlroot->ownerDocument->createTextNode( $secprof );
                }

                $tmp1->appendChild( $tmp );
            }

        }

        /*
        $newdoc = new DOMDocument;
        $node = $newdoc->importNode($this->xmlroot, true);
        $newdoc->appendChild($node);
        print "secProfGroup\n";
        print $newdoc->saveXML();
        */
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

