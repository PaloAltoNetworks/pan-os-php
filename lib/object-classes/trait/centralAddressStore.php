<?php


trait centralAddressStore
{
    /**
     * @var AddressStore|null
     */
    public $addressStore = null;

    public function addressStore()
    {
        return $this->addressStore;
    }
}