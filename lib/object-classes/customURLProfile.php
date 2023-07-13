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

class customURLProfile
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /** @var SecurityProfileStore|null */
    public $owner = null;

    /** @var array $members */
    private $members = array();

    /** @var DOMElement */
    private $membersRoot = null;

    public $secprof_type;

    public $ancestor;

    /**
     * @param SecurityProfileStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        #$this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            if( $this->owner->owner->version < 90 )
                $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);
            else
                $doc->loadXML(self::$templatexml_v9, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElement('entry', $doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
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
        $this->setName($newName);

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param string $newMember Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function addMember($newMember, $rewriteXml = TRUE)
    {

        if( !in_array($newMember, $this->members, TRUE) )
        {
            $this->members[] = $newMember;
            if( $rewriteXml && $this->owner !== null )
            {
                if( $this->membersRoot == null )
                    $this->membersRoot = DH::findFirstElementOrCreate('list', $this->xmlroot);
                DH::createElement($this->membersRoot, 'member', $newMember);
            }

            return TRUE;
        }

        return FALSE;
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param string $newMember Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function deleteMember($newMember, $rewriteXml = TRUE)
    {

        if( in_array($newMember, $this->members, TRUE) )
        {
            $key = array_search($newMember, $this->members);
            unset($this->members[$key]);

            if( $rewriteXml && $this->owner !== null )
            {
                if( $this->membersRoot == null )
                    $this->membersRoot = DH::findFirstElementOrCreate('list', $this->xmlroot);

                foreach( $this->membersRoot->childNodes as $membernode )
                {
                    /** @var DOMElement $membernode */
                    if( $membernode->nodeType != 1 ) continue;

                    if( $membernode->textContent == $newMember )
                        $this->membersRoot->removeChild( $membernode );
                }
            }

            return TRUE;
        }

        return FALSE;
    }
    /**
     * @return array
     */
    public function getmembers()
    {
        return $this->members;
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getSecurityProfileStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function isTmp()
    {
        if( $this->xmlroot === null )
            return TRUE;
        return FALSE;
    }

    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->secprof_type = "customURL";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("CustomProfileURL name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("CustomProfileURL name '" . $this->name . "' is not valid.", $xml);

        $this->membersRoot = DH::findFirstElement('list', $xml);
        if( $this->membersRoot !== FALSE )
        {
            foreach( $this->membersRoot->childNodes as $node )
            {
                if( $node->nodeType != 1 ) continue;

                $memberName = $node->textContent;

                if( strlen($memberName) < 1 )
                    derr('found a member with empty name !', $node);

                #$f = $this->owner->findOrCreate($memberName, $this, true);
                $this->members[] = $memberName;

            }
        }

        return TRUE;
    }

    public function display()
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    ");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);
        /*
        //Todo: continue for PH::print_stdout( ); out
        foreach( $this->tmp_url_prof_array as $url_type )
        {
            PH::print_stdout(  "       ".PH::boldText( strtoupper( $url_type ) ) );
            foreach( $this->$url_type as $member )
            {
                PH::print_stdout(  "         - ".$member );
            }
        }*/

        PH::print_stdout(  "" );

        foreach( $this->members as $member )
        {
            PH::print_stdout(  "        - " . $member );
            PH::$JSON_TMP['sub']['object'][$this->name()]['members'][] = $member;
        }

        PH::print_stdout(  "" );
    }

    public function count()
    {
        return count( $this->members );
    }

    /**
     * Return true if other object is also a group and has same object name
     *  ( value in not taken in account, only object name !! )
     * @param AddressGroup $otherObject
     * @return bool
     */
    public function sameValue(customURLProfile $otherObject)
    {
        #if( $this->isTmpAddr() && !$otherObject->isTmpAddr() )
        #    return FALSE;

        #if( $otherObject->isTmpAddr() && !$this->isTmpAddr() )
        #    return FALSE;

        if( $otherObject->count() != $this->count() )
            return FALSE;

        $diff = $this->getValueDiff($otherObject);

        if( count($diff['plus']) + count($diff['minus']) != 0 )
            return FALSE;

        return TRUE;
    }


    public function &getValueDiff(customURLProfile $otherObject)
    {
        $result = array('minus' => array(), 'plus' => array());

        $localObjects = $this->members;
        $otherObjects = $otherObject->members;

        usort($localObjects, '__CmpObjName');
        usort($otherObjects, '__CmpObjName');

        $diff = array_udiff($otherObjects, $localObjects, '__CmpObjName');
        if( count($diff) != 0 )
            foreach( $diff as $d )
            {
                $result['minus'][] = $d;
            }

        $diff = array_udiff($localObjects, $otherObjects, '__CmpObjName');
        if( count($diff) != 0 )
            foreach( $diff as $d )
            {
                $result['plus'][] = $d;
            }

        return $result;
    }

    public function displayValueDiff(customURLProfile $otherObject, $indent = 0, $toString = FALSE)
    {
        $retString = '';

        $indent = str_pad(' ', $indent);


        $retString .= $indent . "Diff for between " . $this->toString() . " vs " . $otherObject->toString() . "\n";
        $retString .= $indent . "  ' - ' means missing member \n";
        $retString .= $indent . "  ' + ' means additional member \n";
        $retString .= $indent . "       in ".$this->_PANC_shortName()."\n";

        $diff = $this->getValueDiff($otherObject);

        if( count($diff['minus']) != 0 )
            foreach( $diff['minus'] as $d )
            {
                /** @var string $d */
                $retString .= $indent . " - {$d}\n";
            }

        if( count($diff['plus']) != 0 )
            foreach( $diff['plus'] as $d )
            {
                $retString .= $indent . " + {$d}\n";
            }

        if( $toString )
            return $retString;

        PH::print_stdout( $retString );
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';
    static public $templatexml_v9 = '<entry name="**temporarynamechangeme**"><type>URL List</type></entry>';

    public function isCustomURL()
    {
        return TRUE;
    }

    /**
     * @param $otherObject Tag
     * @return bool
     */

    public function equals( $otherObject )
    {
        #if( ! $otherObject->isTag() )
        if( get_class($otherObject) !== "customURLProfile" )
            return false;

        if( $otherObject->name != $this->name )
            return false;

        return $this->sameValue( $otherObject);
    }


}

