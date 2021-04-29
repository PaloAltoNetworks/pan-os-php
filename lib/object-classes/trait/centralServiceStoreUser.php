<?php

trait centralServiceStoreUser
{
    protected $parentServiceStore = null;

    public function findParentServiceStore()
    {
        $this->parentServiceStore = null;

        if( $this->owner )
        {
            $curo = $this;
            while( isset($curo->owner) && $curo->owner !== null )
            {

                if( isset($curo->owner->serviceStore) &&
                    $curo->owner->serviceStore !== null )
                {
                    $this->parentServiceStore = $curo->owner->serviceStore;
                    return;
                }
                $curo = $curo->owner;
            }
        }
    }
}
