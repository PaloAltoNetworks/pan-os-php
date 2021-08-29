<?php

function merger_location_array($utilType, $objectsLocation, $pan)
{
    #global $pan;
    if( $objectsLocation == 'any' || $objectsLocation == 'all' )
    {
        if( $pan->isPanorama() )
            $alldevicegroup = $pan->deviceGroups;
        else
            $alldevicegroup = $pan->virtualSystems;
        foreach( $alldevicegroup as $key => $tmp_location )
        {
            $objectsLocation = $tmp_location->name();
            $findLocation = $pan->findSubSystemByName($objectsLocation);
            if( $findLocation === null )
                derr("cannot find DeviceGroup/VSYS named '{$objectsLocation}', check case or syntax");
            if( $utilType == "address-merger" )
            {
                $store = $findLocation->addressStore;
                $parentStore = $findLocation->owner->addressStore;
            }
            elseif( $utilType == "service-merger" )
            {
                $store = $findLocation->serviceStore;
                $parentStore = $findLocation->owner->serviceStore;
            }
            $location_array[$key]['findLocation'] = $findLocation;
            $location_array[$key]['store'] = $store;
            $location_array[$key]['parentStore'] = $parentStore;
            if( $pan->isPanorama() )
            {
                $childDeviceGroups = $findLocation->childDeviceGroups(TRUE);
                $location_array[$key]['childDeviceGroups'] = $childDeviceGroups;
            }
            else
                $location_array[$key]['childDeviceGroups'] = array();
        }
        $location_array = array_reverse($location_array);
        $location_array[$key + 1]['findLocation'] = 'shared';
        if( $utilType == "address-merger" )
            $location_array[$key + 1]['store'] = $pan->addressStore;
        elseif( $utilType == "service-merger" )
            $location_array[$key + 1]['store'] = $pan->serviceStore;
        $location_array[$key + 1]['parentStore'] = null;
        $location_array[$key + 1]['childDeviceGroups'] = $alldevicegroup;
    }
    else
    {
        if( $objectsLocation == 'shared' )
        {
            if( $utilType == "address-merger" )
                $store = $pan->addressStore;
            elseif( $utilType == "service-merger" )
                $store = $pan->serviceStore;
            elseif( $utilType == "tag-merger" )
                $store = $pan->tagStore;
            $parentStore = null;
            $location_array[0]['findLocation'] = $objectsLocation;
            $location_array[0]['store'] = $store;
            $location_array[0]['parentStore'] = $parentStore;
        }
        else
        {
            $findLocation = $pan->findSubSystemByName($objectsLocation);
            if( $findLocation === null )
                derr("cannot find DeviceGroup/VSYS named '{$objectsLocation}', check case or syntax");
            if( $utilType == "address-merger" )
            {
                $store = $findLocation->addressStore;
                $parentStore = $findLocation->owner->addressStore;
            }
            elseif( $utilType == "service-merger" )
            {
                $store = $findLocation->serviceStore;
                $parentStore = $findLocation->owner->serviceStore;
            }
            elseif( $utilType == "tag-merger" )
            {
                $store = $findLocation->tagStore;
                $parentStore = $findLocation->owner->tagStore;
            }
            $location_array[0]['findLocation'] = $findLocation;
            $location_array[0]['store'] = $store;
            $location_array[0]['parentStore'] = $parentStore;
        }
        if( $pan->isPanorama() )
        {
            if( $objectsLocation == 'shared' )
                $childDeviceGroups = $pan->deviceGroups;
            else
                $childDeviceGroups = $findLocation->childDeviceGroups(TRUE);
            $location_array[0]['childDeviceGroups'] = $childDeviceGroups;
        }
        else
            $location_array[0]['childDeviceGroups'] = array();
    }
    return $location_array;
}

function filterArgument(&$pickFilter = null, &$excludeFilter = null, &$upperLevelSearch = FALSE)
{
    $pickFilter = null;
    if( isset(PH::$args['pickfilter']) )
    {
        $pickFilter = new RQuery('service');
        $errMsg = '';
        if( $pickFilter->parseFromString(PH::$args['pickfilter'], $errMsg) === FALSE )
            derr("invalid pickFilter was input: " . $errMsg);
        echo " - pickFilter was input: ";
        $pickFilter->display();
        echo "\n";
    }
    $excludeFilter = null;
    if( isset(PH::$args['excludefilter']) )
    {
        $excludeFilter = new RQuery('service');
        $errMsg = '';
        if( $excludeFilter->parseFromString(PH::$args['excludefilter'], $errMsg) === FALSE )
            derr("invalid pickFilter was input: " . $errMsg);
        echo " - excludeFilter was input: ";
        $excludeFilter->display();
        echo "\n";
    }
    $upperLevelSearch = FALSE;
    if( isset(PH::$args['allowmergingwithupperlevel']) )
        $upperLevelSearch = TRUE;
}

function prepareSupportedArgumentsArray(&$supportedArguments)
{
    $tmpArgs = array();
    foreach( $supportedArguments as &$arg )
    {
        $tmpArgs[strtolower($arg['niceName'])] = $arg;
    }
    $supportedArguments = $tmpArgs;
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(TRUE);
}

function display_usage_and_exit($shortMessage = FALSE)
{
    global $usageMsg;
    global $supportedArguments;
    PH::print_stdout( $usageMsg );
    PH::print_stdout( "" );

    if( !$shortMessage )
    {
        PH::print_stdout( "" );
        PH::print_stdout( PH::boldText("Listing available arguments") );
        PH::print_stdout( "" );

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            $text = " - " . PH::boldText($arg['niceName']);
            if( isset($arg['argDesc']) )
                $text .= '=' . $arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']) )
            {
                PH::print_stdout( "" );
                PH::print_stdout("     " . $arg['shortHelp'] );
            }
            PH::print_stdout( "" );
        }

        PH::print_stdout( "" );
        PH::print_stdout( "" );
    }

    exit(1);
}