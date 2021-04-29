<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


class RuleWithUserID extends Rule
{
    const __UserIDType_Any = 0;
    const __UserIDType_Unknown = 1;
    const __UserIDType_Known = 2;
    const __UserIDType_PreLogon = 3;
    const __UserIDType_Custom = 4;

    static private $__UserIDTypes = array(
        self::__UserIDType_Any => 'any',
        self::__UserIDType_Unknown => 'unknown',
        self::__UserIDType_Known => 'known',
        self::__UserIDType_PreLogon => 'pre-logon',
        self::__UserIDType_Custom => 'custom'
    );

    protected $_userIDType = self::__UserIDType_Any;

    /** @var string[] */
    protected $_users = array();

    function userID_IsAny()
    {
        return ($this->_userIDType == self::__UserIDType_Any);
    }

    function userID_IsUnknown()
    {
        return $this->_userIDType == self::__UserIDType_Unknown;
    }

    function userID_IsKnown()
    {
        return $this->_userIDType == self::__UserIDType_Known;
    }

    function userID_IsPreLogon()
    {
        return $this->_userIDType == self::__UserIDType_PreLogon;
    }

    function userID_IsCustom()
    {
        return $this->_userIDType == self::__UserIDType_Custom;
    }

    /**
     * @return string
     */
    function userID_type()
    {
        return self::$__UserIDTypes[$this->_userIDType];
    }

    function userID_getUsers()
    {
        return $this->_users;
    }

    /**
     * For developers only
     */
    function userID_loadUsersFromXml()
    {
        $xml = DH::findFirstElement('source-user', $this->xmlroot);
        if( $xml === FALSE )
            return;

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $content = $node->textContent;
            if( strlen($content) == 0 )
                derr('empty username in rule', $node);

            if( $content == 'any' )
                return;
            if( $content == 'unknown' )
            {
                $this->_userIDType = self::__UserIDType_Unknown;
                return;
            }
            if( $content == 'known' )
            {
                $this->_userIDType = self::__UserIDType_Known;
                return;
            }
            if( $content == 'pre-logon' )
            {
                $this->_userIDType = self::__UserIDType_PreLogon;
                return;
            }

            $this->_users[] = $content;
        }

        $this->_userIDType = self::__UserIDType_Custom;
    }


    function userID_setUsers($newUser)
    {
        $tmpRoot = DH::findFirstElementOrCreate('source-user', $this->xmlroot);

        $newUser = utf8_encode($newUser);
        if( in_array($newUser, $this->_users, TRUE) )
            return FALSE;

        $this->_users[] = $newUser;

        DH::Hosts_to_xmlDom($tmpRoot, $this->_users, 'member', FALSE, 'any', FALSE);
    }

}
