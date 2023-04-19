<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

trait HUAWEIservice
{
    function add_service( $service)
    {
        global $debug;
        global $print;

        $print = true;

        $padding = "   ";
        $padding_name = substr($padding, 0, -1);


        foreach( $service as $key => $service_entry )
        {
            #print_r( $service_entry );
            $srv_array = array();
            $srv_array1 = array();
            $tmp_servicegroup = null;
            $tmp_service = null;

            $lines = explode( "\n", $service_entry );

            $counter = count( $lines );
            #print "COUNTER: ".$counter."\n";

            foreach( $lines as $key => $line )
            {
                $line = $this->strip_hidden_chars( $line );

                $line_arr = explode( " ", $line );

                if( $key == 0 )
                {
                    //get name
                    $name = $line_arr[0];
                    $groupname = $name;
                }
                elseif( (strpos( $line, " description" ) !== false) && (strpos( $line, " description" ) == 0) )
                {
                    print "DESCRIPTION: ".$line."\n";
                }
                else
                {

                    $sport = "";
                    $dport = "";


                    //todo: create service objct

                    #print_r( $line_arr );
                    /*
                     *     [0] =>
[1] => service
[2] => 0
[3] => protocol
[4] => udp
[5] => source-port
[6] => 0
[7] => to
[8] => 65535
[9] => destination-port
[10] => 53
[11] => 68
[12] => 161
[13] => 427
[14] => 547
[15] => 6999
[16] => 8100
[17] => 8200
[18] => 8300
[19] => to
[20] => 8302
[21] => 9084
[22] => 12345
[23] => 23451
                     */
                    $service_set = FALSE;

                    if( $line_arr[3] != "service-set" && $line_arr[4] != "service-set" )
                    {
                        if( isset($line_arr[4]) && $line_arr[3] == "protocol" )
                        {
                            $protocol = $line_arr[4];
                            #if( $protocol == "icmp" )
                            #    continue;
                            if( isset($line_arr[6]) && $line_arr[5] == "icmp-type" )
                            {
                                $protocol = $line_arr[6];
                            }
                        }


                        if( isset($line_arr[5]) && $line_arr[5] == "source-port" )
                        {
                            if( $line_arr[6] == '0' && $line_arr[7] == 'to' && $line_arr[8] == '65535' )
                            {
                                //no sport set needed;
                            }
                            else
                            {
                                $sport = "";
                                print "SPORT\n";
                            }

                            //find dport
                            if( $line_arr[9] == "destination-port" )
                            {
                                $dport = $this->findDport( $line_arr, $dport, 10 );
                                /*
                                $i = 10;
                                do
                                {
                                    if( isset($line_arr[$i]) )
                                    {
                                        if( $line_arr[$i] != "to" )
                                        {
                                            $dport .= $line_arr[$i];
                                            if( ($i < count($line_arr) - 1) && $line_arr[$i + 1] != "to" )
                                                $dport .= ",";
                                        }
                                        else
                                            $dport .= "-";
                                    }
                                    $i++;
                                } while( $i < count($line_arr) + 1 );
                                */
                            }
                        }
                        else
                        {
                            //find dport
                            if( isset($line_arr[5]) && $line_arr[5] == "destination-port" )
                            {
                                $dport = $this->findDport( $line_arr, $dport, 6 );
                                /*
                                $i = 6;
                                do
                                {
                                    if( isset($line_arr[$i]) )
                                    {
                                        if( $line_arr[$i] != "to" )
                                        {
                                            $dport .= $line_arr[$i];
                                            if( ($i < count($line_arr) - 1) && $line_arr[$i + 1] != "to" )
                                                $dport .= ",";
                                        }
                                        else
                                            $dport .= "-";
                                    }
                                    $i++;
                                } while( $i < count($line_arr) + 1 );
                                */
                            }
                        }
                    }
                    else
                    {
                        #print "print search servic_group: " . $line_arr[4] . "\n";
                        $service_set = TRUE;
                    }


                    if( !$service_set )
                    {
                        if( $counter != 2 )
                        {
                            if( $protocol == "tcp" || $protocol == "udp" )
                                $name = $protocol . "_";
                            else
                                $name = $protocol;

                            if( $sport != "" )
                                $name .= $sport . "_";
                            $name .= str_replace( ",", "_", $dport);
                        }

                        /*
                        print "NAME: " . $name . "\n";

                        print "PROTOCOL: " . $protocol . "\n";
                        print "SPORT: " . $sport . "\n";
                        print "DPORT: " . $dport . "\n";
                        */

                        $srv_array1['name'] = $name;
                        $srv_array1['protocol'] = $protocol;
                        $srv_array1['sport'] = $sport;
                        $srv_array1['dport'] = $dport;
                    }
                    else{
                        $srv_array1['name'] = $line_arr[4];
                        $srv_array1['service-set'] = 'service-set';
                    }


                    $srv_array[] = $srv_array1;
                }



            }


            #if( count( $srv_array ) > 1 || (count( $srv_array ) == 1 && ( isset( $srv_array[0]['service-set']) || ( ( $protocol != "tcp" ) && ($protocol != "udp") )   ) ) )
            if( count( $srv_array ) > 1 || (count( $srv_array ) == 1 && ( isset( $srv_array[0]['service-set'])  ) ) )
            {
                #$name = $srv_array[0]['name'];

                    $name = $groupname;

                $name = $this->truncate_names($this->normalizeNames($name));
                $tmp_servicegroup = $this->sub->serviceStore->find($name);
                if( $tmp_servicegroup == null )
                {
                    if( $print )
                        print $padding_name . "* name: " . $name . "\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($name);
                }
            }

            #print_r( $srv_array );

            foreach( $srv_array as $service )
            {

                if( !isset( $service['service-set']) )
                {
                    //create service object
                    $name = $this->truncate_names($this->normalizeNames($service['name']));
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service == null )
                    {

                        $protocol = strtolower($service['protocol']);
                        if( $protocol == "tcp" || $protocol == "udp" )
                        {
                            $dport = $service['dport'];
                            if( $print )
                                print $padding_name . "* name: '" . $name . "' protocol: '" . $protocol . "' port: '" . $dport . "'\n";
                            $tmp_service = $this->sub->serviceStore->newService($name, $protocol, $dport);
                        }
                        else
                        {
                            print $padding_name . "X check service: " . $name . " | service created: TMP_" . $name . "\n";

                            if( $protocol != $name )
                            {
                                //create addr_group
                                //search for object if not there, create
                                // add to group

                                $name = $this->truncate_names($this->normalizeNames($name));
                                $tmp_servicegroup = $this->sub->serviceStore->find($name);
                                if( $tmp_servicegroup == null )
                                {
                                    if( $print )
                                        print $padding_name . "* name: " . $name . "\n";
                                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($name);
                                }

                                $name = $this->truncate_names($this->normalizeNames( "TMP_".$protocol ) );
                                $tmp_service = $this->sub->serviceStore->find($name);
                                if( $tmp_service == null )
                                {
                                    $tmp_service = $this->sub->serviceStore->newService( $name, "tcp", "65000");
                                }

                                $tmp_servicegroup->addMember( $tmp_service );
                            }
                            else
                            {
                                $name = $this->truncate_names($this->normalizeNames( "TMP_".$name ) );
                                $tmp_service = $this->sub->serviceStore->find($name);
                                if( $tmp_service == null )
                                {
                                    $tmp_service = $this->sub->serviceStore->newService( $name, "tcp", "65000");
                                }

                                $tmp_service->set_node_attribute('error', $name);
                                #print_r( $service_entry );
                            }

                        }

                    }

                    if( $counter > 2 )
                    {
                        if( $tmp_servicegroup != null && $tmp_servicegroup->isGroup() )
                        {
                            if( $print )
                                print $padding_name.$padding_name."add service: ".$tmp_service->name()." \n";
                            $tmp_servicegroup->addMember( $tmp_service );
                        }

                    }
                }
                else
                {
                    #print_r( $service );

                    //Todo; create addressgroup, and search for addressgroup and add it
                    $name = $this->truncate_names($this->normalizeNames($service['name']));
                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service != null )
                    {
                        if( $tmp_servicegroup != null && $tmp_servicegroup->isGroup() )
                        {
                            if( $print )
                                print $padding_name.$padding_name . "add service: ".$tmp_service->name()." \n";
                            $tmp_servicegroup->addMember( $tmp_service );
                        }
                        else
                        {
                            if ( $tmp_servicegroup == null )
                                print "is null\n";
                            elseif( !$tmp_servicegroup->isGroup() )
                                print "no group\n";


                            mwarning( "found ".$service['name']." but to which group to add" );
                        }
                    }
                }
            }


            print "---------\n";


        }
    }

    function findDport( $line_arr, $dport, $i )
    {
        do
        {
            if( isset($line_arr[$i]) )
            {
                if( $line_arr[$i] != "to" )
                {
                    $dport .= $line_arr[$i];
                    if( ($i < count($line_arr) - 1) && $line_arr[$i + 1] != "to" )
                        $dport .= ",";
                }
                else
                    $dport .= "-";
            }
            $i++;
        } while( $i < count($line_arr) + 1 );

        return $dport;
    }
}
