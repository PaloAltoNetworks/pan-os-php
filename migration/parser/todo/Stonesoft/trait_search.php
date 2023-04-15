<?php


trait trait_search
{
    /**
     *
     * @param string $object_name name of the object being searched
     * @param int $lid ID of the found object
     * @param string $table table wher ethe object has been found
     * @param string $vsys Virtual system used
     * @param int $source Source used
     * @global mysqli $projectdb
     */
    function searchAddress($valueNorm, $vsys, $source, &$lid = '', &$table = '', &$objectsInMemory)
    {
        global $projectdb;

        if( isset($objectsInMemory['address'][$vsys][$valueNorm]) )
        {
            $lid = $objectsInMemory['address'][$vsys][$valueNorm]['id'];
            $table = 'address';
            return TRUE;
        }
        elseif( isset($objectsInMemory['address_groups_id'][$vsys][$valueNorm]) )
        {
            $lid = $objectsInMemory['address_groups_id'][$vsys][$valueNorm]['id'];
            $table = 'address_groups_id';
            return TRUE;
        }
        else
        {
            return FALSE;
        }

        /* $getAddress = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';");
        if ($getAddress->num_rows > 0){
            $myData = $getAddress->fetch_assoc();
            $lid = $myData['id'];
            $table = 'address';
            return true;
        }

        else{
            $getAddress = $projectdb->query( "SELECT id FROM address_groups_id WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';");
            if ($getAddress->num_rows > 0){
                $myData = $getAddress->fetch_assoc();
                $lid = $myData['id'];
                $table = 'address_groups_id';
                return true;
            }
        }
        return false;*/
    }

    function searchAddressIPandCIDR($valueNorm, $vsys, $source, &$member, &$objectsInMemory)
    {
        global $projectdb;

        if( isset($objectsInMemory['address'][$vsys][$valueNorm]) )
        {
            $member = new MemberObject($valueNorm, 'address', $objectsInMemory['address'][$vsys][$valueNorm]['ipaddress'], $objectsInMemory['address'][$vsys][$valueNorm]['cidr']);
            return 1;
        }

        /*$query = "SELECT id, ipaddress, cidr FROM address WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';";
        $getAddress = $projectdb->query($query);
        if ($getAddress->num_rows > 0){
            $myData = $getAddress->fetch_assoc();
            $member = new MemberObject($object_name, 'address', $myData['ipaddress'], $myData['cidr']);
            return 1;
        }*/
//
//    else{
//        $getAddress = $projectdb->query( "SELECT id FROM address_groups_id WHERE BINARY name='$object_name' AND source='$source' AND vsys='$vsys';");
//        if ($getAddress->num_rows > 0){
//            $myData = $getAddress->fetch_assoc();
//            $lid = $myData['id'];
//            $table = 'address_groups_id';
//            return true;
//        }
//    }
        return 0;
    }

    /**
     *
     * @param string $object_name
     * @param string $vsys
     * @param int $source
     * @param int $lid
     * @param string $table
     * @global mysqli $projectdb
     */
    function searchService($valueNorm, $vsys, $source, &$lid = '', &$table = '', &$objectsInMemory)
    {
        global $projectdb;

        if( isset($objectsInMemory['services'][$vsys][$valueNorm]) )
        {
            $lid = $objectsInMemory['services'][$vsys][$valueNorm]['id'];
            $table = 'services';
            return TRUE;
        }
        elseif( isset($objectsInMemory['services_groups_id'][$vsys][$valueNorm]) )
        {
            $lid = $objectsInMemory['services_groups_id'][$vsys][$valueNorm]['id'];
            $table = 'services_groups_id';
            return TRUE;
        }
        else
        {
            return FALSE;
        }

        /*$getAddress = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';");
        if ($getAddress->num_rows > 0){
            $myData = $getAddress->fetch_assoc();
            $lid = $myData['id'];
            $table = 'services';
            return true;
        }

        else{
            $getAddress = $projectdb->query( "SELECT id FROM services_groups_id WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';");
            if ($getAddress->num_rows > 0){
                $myData = $getAddress->fetch_assoc();
                $lid = $myData['id'];
                $table = 'services_groups_id';
                return true;
            }
        }
        return false;*/
    }
}
