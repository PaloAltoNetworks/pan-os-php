<?php


InterfaceCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( InterfaceCallContext $context )
    {
        $object = $context->object;
        print "     * ".get_class($object)." '{$object->name()}'  \n";

        //Todo: optimization needed, same process as for other utiles

        print "       - " . $object->type . " - ";
        if( $object->type == "layer3" || $object->type == "virtual-wire" || $object->type == "layer2" )
        {
            if( $object->isSubInterface() )
                print "subinterface - ";
            else
                print "count subinterface: " . $object->countSubInterfaces() . " - ";
        }
        elseif( $object->type == "aggregate-group" )
        {
            print "".$object->ae()." - ";
        }


        if( $object->type == "layer3" )
        {
            print "ip-addresse(s): ";
            foreach( $object->getLayer3IPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                    print $ip_address . ",";
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #print $ip_address." ({$object->value()}) ,";
                }
            }
        }
        elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
        {
            print ", ip-addresse(s): ";
            foreach( $object->getIPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                    print $ip_address . ",";
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #print $ip_address." ({$object->value()}) ,";
                }
            }
        }
        elseif( $object->type == "auto-key" )
        {
            print " - IPsec config";
            print " - IKE gateway: " . $object->gateway;
            print " - interface: " . $object->interface;
        }

        print "\n";

    },
);
