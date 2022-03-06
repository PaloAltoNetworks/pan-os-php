<?php

/**
 * Class RuleRQueryContext
 * @property Rule|SecurityRule|NatRule|PbfRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|QoSRule $object
 * @ignore
 */
class RuleRQueryContext extends RQueryContext
{
    public function ServiceCount( $rule, $type = "both" )
    {
        $objects = $rule->services->o;

        if( count($objects  ) > 0 )
        {
            $dst_port_mapping = new ServiceDstPortMapping();
            $dst_port_mapping->mergeWithArrayOfServiceObjects( $objects);

            $dst_port_mapping->countPortmapping();
            if( $type === "both" )
                $calculatedCounter = $dst_port_mapping->PortCounter;
            elseif( $type === "tcp" )
                $calculatedCounter = $dst_port_mapping->tcpPortCounter;
            elseif( $type === "udp" )
                $calculatedCounter = $dst_port_mapping->udpPortCounter;
        }
        else
        {
            $maxPortcount = 65536;
            if( $type === "both" )
                $calculatedCounter = ($maxPortcount * 2);
            elseif( $type === "tcp" || $type === "udp" )
                $calculatedCounter = $maxPortcount;
        }

        return $calculatedCounter;
    }
}