<?php




RoutingCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( RoutingCallContext $context )
    {
        $object = $context->object;
        print "     * ".get_class($object)." '{$object->name()}'  \n";


        foreach( $object->staticRoutes() as $staticRoute )
        {
            print "       - NAME: " . str_pad($staticRoute->name(), 20);
            print " - DEST: " . str_pad($staticRoute->destination(), 20);
            print " - NEXTHOP: " . str_pad($staticRoute->nexthopIP(), 20);
            if( $staticRoute->nexthopInterface() != null )
                print " - NEXT INTERFACE: " . str_pad($staticRoute->nexthopInterface()->toString(), 20);

            print "\n";
        }

        print "\n- - - - - - - - - - - - - - - - \n\n";


        print "\n";

    },

    //Todo: display routes to zone / Interface IP
);

