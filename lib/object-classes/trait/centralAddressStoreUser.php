<?php

/**
 * Class centralAddressStoreUser
 * @property VirtualSystem|DeviceGroup|PANConf|PanoramaConf $owner
 */
trait centralAddressStoreUser
{
    /**
     * @var AddressStore|null
     */
    protected $parentAddressStore = null;

    public function findParentAddressStore()
    {
        $this->parentAddressStore = null;

        if( $this->owner )
        {
            $currentOwner = $this;
            while( isset($currentOwner->owner) && $currentOwner->owner !== null )
            {

                if( isset($currentOwner->owner->addressStore) &&
                    $currentOwner->owner->addressStore !== null )
                {
                    $this->parentAddressStore = $currentOwner->owner->addressStore;
                    //print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
                    return;
                }
                $currentOwner = $currentOwner->owner;
            }
        }
        //die($this->toString()." : not found parent central store: \n");

    }


}