<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

/**
 * Class AggregateEthernetIfStore
 * @property AggregateEthernetInterface[] $o
 */
class AggregateEthernetIfStore extends EthernetIfStore
{
    public static $childn = 'AggregateEthernetInterface';


    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            //TODO: 20180331 why I need to create full path? why it is not set before???
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);
            $xml = DH::findFirstElementOrCreate('interface', $xml);
            #$xml = DH::findFirstElementOrCreate('aggregate-ethernet', $xml);

            #$this->xmlroot = DH::findFirstElementOrCreate('units', $xml);
            $this->xmlroot = DH::findFirstElementOrCreate('aggregate-ethernet', $xml);
        }
    }

}