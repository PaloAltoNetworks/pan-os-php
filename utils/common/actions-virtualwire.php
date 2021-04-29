<?php

VirtualWireCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( VirtualWireCallContext $context )
    {
        $object = $context->object;
        print "     * ".get_class($object)." '{$object->name()}'  \n";

        print "       - ";
        print "interface1: ".$object->attachedInterface1." - ";
        print "interface2: ".$object->attachedInterface2."\n";



        print "\n";

    },

);