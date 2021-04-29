<?php


trait centralServiceStore
{
    /**
     * @var ServiceStore
     */
    public $serviceStore = null;

    public function serviceStore()
    {
        return $this->serviceStore;
    }
}

