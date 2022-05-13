<?php

/**
 * Class ServiceRQueryContext
 * @property Service|ServiceGroup $object
 * @ignore
 */
class ServiceRQueryContext extends RQueryContext
{
    public function ServiceCount( $object, $type = "both" )
    {
        $objects[] = $object;
        $dst_port_mapping = new ServiceDstPortMapping();
        $dst_port_mapping->mergeWithArrayOfServiceObjects( $objects );

        $dst_port_mapping->countPortmapping();
        if( $type === "both" )
            $calculatedCounter = $dst_port_mapping->PortCounter;
        elseif( $type === "tcp" )
            $calculatedCounter = $dst_port_mapping->tcpPortCounter;
        elseif( $type === "udp" )
            $calculatedCounter = $dst_port_mapping->udpPortCounter;

        return $calculatedCounter;
    }
}