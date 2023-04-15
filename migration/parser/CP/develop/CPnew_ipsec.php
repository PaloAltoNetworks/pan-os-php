<?php


trait CPnew_ipsec
{
    public function addIPsec($end_array)
    {
        $addconfig = TRUE;

        #print_r( array_keys( $end_array[0]['communities'] ) );
        //todo: print out
        #print_r( $end_array[0]['communities'] );


        $tmp_array = $end_array[0]['communities'];
        #derr("END VPN");


        #print_r( $tmp_array );

        foreach( $tmp_array as $objKey => $netobj )
        {
            if( is_numeric( $objKey ) )
            {
                if( $netobj[0][0] == "MyIntranet" || $netobj[0][0] == "RemoteAccess" )
                {
                    unset( $tmp_array[$objKey] );
                }
                else
                {
                    #print_r( $netobj );
                    print "NAME: ".$netobj[0][0]."\n";

                    if( isset($netobj['participant_gateways']) )
                    {
                        print 'participant_gateways'."\n";
                        print_r($netobj['participant_gateways']);
                    }


                    if( isset($netobj['satellite_gateways']) )
                    {
                        print 'satellite_gateways'."\n";
                        print_r($netobj['satellite_gateways']);
                    }

                    if( isset($netobj['ike_p1']) )
                    {
                        print 'ike_p1'."\n";
                        print_r($netobj['ike_p1']);
                    }

                    if( isset($netobj['ike_p2']) )
                    {
                        print 'ike_p2'."\n";
                        print_r($netobj['ike_p2']);
                    }
                }
            }
        }
    }
}