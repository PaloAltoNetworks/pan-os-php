<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class TmpInterface
{
    use ReferenceableObject;
    use PathableName;
    use InterfaceType;

    /** @property $owner TmpInterfaceStore */

    /**
     * @param $name string
     * @param TmpInterfaceStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    public function isTmpType()
    {
        return TRUE;
    }


}

