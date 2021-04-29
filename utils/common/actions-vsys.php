<?php


VsysCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (VsysCallContext $context) {
        $context->interface_wo_vsys = array();
    },
    'MainFunction' => function (VsysCallContext $context) {
        $object = $context->object;
        print "     * " . get_class($object) . " '{$object->name()}'  ";


        foreach( $object->importedInterfaces as $interfacecontainer )
        {
            if( is_a($interfacecontainer, 'NetworkPropertiesContainer') )
            {
                foreach( $interfacecontainer->getAllInterfaces() as $interface )
                {
                    $tmp_vsys = $interfacecontainer->findVsysInterfaceOwner($interface->name());
                    if( $tmp_vsys != null )
                    {
                        if( $tmp_vsys->name() == $object->name() )
                        {
                            print "\n       - " . $interface->type . " - ";
                            if( $interface->type == "layer3" )
                            {
                                if( $interface->isSubInterface() )
                                    print "subinterface - ";
                                else
                                    print "count subinterface: " . $interface->countSubInterfaces() . " - ";
                            }
                            elseif( $interface->type == "aggregate-group" )
                            {
                                #$interface->
                            }

                            print $interface->name() . ", ip-addresse(s): ";
                            if( $interface->type == "layer3" )
                            {
                                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                                    print $ip_address . ",";
                            }
                            elseif( $interface->type == "tunnel" )
                            {
                                foreach( $interface->getIPv4Addresses() as $ip_address )
                                    print $ip_address . ",";
                            }
                        }
                    }
                    else
                        $context->interface_wo_vsys[$interface->name()] = $interface;
                }
            }
        }

        print "\n\n";
    },
    'GlobalFinishFunction' => function (VsysCallContext $context) {
        print PH::boldText("\n\nall interfaces NOT attached to an vsys:\n");
        foreach( $context->interface_wo_vsys as $interface )
        {
            print "\n  - " . $interface->type . " - ";
            if( $interface->type == "layer3" )
            {
                if( $interface->isSubInterface() )
                    print "subinterface - ";
                else
                    print "count subinterface: " . $interface->countSubInterfaces() . " - ";
            }
            elseif( $interface->type == "aggregate-group" )
            {
                #$interface->
            }

            print $interface->name() . ", ip-address(es): ";
            if( $interface->type == "layer3" )
            {
                foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                    print $ip_address . ",";
            }
            elseif( $interface->type == "tunnel" )
            {
                foreach( $interface->getIPv4Addresses() as $ip_address )
                    print $ip_address . ",";
            }

            print "\n\n\n";
        }
    },
);