<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

/**
 * @property TmpInterface[] $o
 * @property PANConf $owner
 */
class TmpInterfaceStore extends ObjStore
{
    public static $childn = 'EthernetInterface';

    /**
     * @param PANConf $owner
     */
    function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->classn = &self::$childn;
    }

    /**
     * @return TmpInterface[]
     */
    function getInterfaces()
    {
        return $this->o;
    }


}