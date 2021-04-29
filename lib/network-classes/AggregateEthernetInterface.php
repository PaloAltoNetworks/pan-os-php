<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class AggregateEthernetInterface extends EthernetInterface
{

    /** @var string */
    public $type = 'aggregate';

    public function isEthernetType()
    {
        return FALSE;
    }

    public function isAggregateType()
    {
        return TRUE;
    }


    static public $templatexml = '<entry name="**temporarynamechangeme**">
  <layer3>
    <ipv6>
      <neighbor-discovery>
        <router-advertisement>
          <enable>no</enable>
        </router-advertisement>
      </neighbor-discovery>
    </ipv6>
    <ndp-proxy>
      <enabled>no</enabled>
    </ndp-proxy>
    <lldp>
      <enable>no</enable>
    </lldp>
    <ip></ip>
  </layer3>
</entry>';

}