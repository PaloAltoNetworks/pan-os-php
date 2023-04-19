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

trait FORTINETipsec
{
    #function get_interfaces($fortinet_config_file, $vsys, $source, $template, $ismultiornot) {
    function get_ipsec( $ismultiornot)
    {
        global $projectdb;

        global $debug;
        global $print;

        $isP1Config = FALSE;
        $isP2Config = FALSE;

        $isP1IntConfig = FALSE;
        $isP2IntConfig = FALSE;

        $P1_string = "";
        $P2_string = "";
        $P1Int_string = "";
        $P2Int_string = "";
        $string = "";

        foreach( $this->data as $line => $names_line )
        {
            if( preg_match("/^config vpn ipsec phase1-interface/i", $names_line) )
            {
                $isP1IntConfig = TRUE;
                $string = "";
                #print "found P1Int\n";
            }
            elseif( preg_match("/^config vpn ipsec phase2-interface/i", $names_line) )
            {
                $isP2IntConfig = TRUE;
                $string = "";
                #print "found P2Int\n";
            }
            elseif( preg_match("/^config vpn ipsec phase1/i", $names_line) )
            {
                $isP1Config = TRUE;
                $string = "";
                #print "found P1\n";
            }
            elseif( preg_match("/^config vpn ipsec phase2/i", $names_line) )
            {
                $isP2Config = TRUE;
                $string = "";
                #print "found P2\n";
            }

            elseif( ( $isP1Config or $isP2Config or $isP1IntConfig or $isP2IntConfig )  )
            {
                if( preg_match("/^end/i", $names_line) )
                {
                    #print "found END\n";
                    if( $isP1Config )
                    {
                        $isP1Config = FALSE;
                        $P1_string = $string;
                    }
                    elseif( $isP2Config )
                    {
                        $isP2Config = FALSE;
                        $P2_string = $string;
                    }
                    elseif( $isP1IntConfig )
                    {
                        $isP1IntConfig = FALSE;
                        $P1Int_string = $string;
                    }
                    elseif( $isP2IntConfig )
                    {
                        $isP2IntConfig = FALSE;
                        $P2Int_string = $string;
                    }
                }
                else
                {
                    #print $names_line."\n";
                    $string .= $names_line."\n";
                }
            }
        }


        if( $P1_string != "" )
        {
            print "\n\n";
            print "P1:\n";
            print $P1_string;
        }


        if( $P2_string != "" )
        {
            print "\n\n";
            print "P2:\n";
            print $P2_string;
        }


        if( $P1Int_string != "" )
        {
            print "\n\n";
            print "P1Int:\n";
            #print $P1Int_string;
            $IKEgateways = $this->splitConfig( $P1Int_string );
            print_r( $IKEgateways );

            foreach( $IKEgateways as $key => $gw )
            {
                $isIKE2 = false;
                if( isset( $gw['ike-version'] ) && $gw['ike-version'] == 2 )
                    $isIKE2 = true;

                if( !isset( $gw['name'] ) )
                    $gw['name'] = "no-name".$key;

                $tmp_newIKEGateway[$gw['name']] = $this->template->network->ikeGatewayStore->findIKEGateway($gw['name']);
                if( $tmp_newIKEGateway[$gw['name']] == null )
                {
                    $tmp_newIKEGateway[$gw['name']] = $this->template->network->ikeGatewayStore->newIKEGateway($gw['name'], $isIKE2);
                }


                if( isset( $gw['remote-gw'] ) )
                    $tmp_newIKEGateway[$gw['name']]->setpeerAddress($gw['remote-gw']);

                if( isset( $gw['proposal'] ) && isset( $gw['dhgrp'] ) )
                {
                    //todo: create IKE proposal based on:

                    //$gw['proposal']
                    $proposal = $gw['proposal'];
                    $dh = $gw['dhgrp'];



                    if( isset( $gw['keylife'] ) )
                        $keylife = $gw['keylife'];

                    $proposal_array = explode( " ", $proposal );

                    $tmp_name = "";
                    foreach( $proposal_array as $key => $proposal )
                    {
                        if( $proposal == "" )
                            continue;

                        $proposal = explode( "-", $proposal );

                        #if( !isset( $proposal[0] ) or !isset( $proposal[1] ) )
                        #    continue;

                        $tmp_name .= $proposal[1]."_".$proposal[0];
                        if( $key != 0 )
                            $tmp_name .= "-";
                    }

                    $proposal_name = "g".$dh."_".$tmp_name;

                    $tmp_P1_config_proposals[$proposal_name] = $this->template->network->ikeCryptoProfileStore->findIKECryptoProfil($proposal_name);
                    if( $tmp_P1_config_proposals[$proposal_name] == null )
                    {
                        $tmp_P1_config_proposals[$proposal_name] = $this->template->network->ikeCryptoProfileStore->newIKECryptoProfil($proposal_name);
                        if( $print )
                            print "create IKE crypto proposal: " . $proposal_name . "\n";
                    }

                    $tmp_P1_config_proposals[$proposal_name]->setDHgroup( "group".$dh);

                    foreach( $proposal_array as $key => $proposal )
                    {
                        if( $proposal == "" )
                            continue;
                        
                        $proposal = explode("-", $proposal);

                        if( strpos($proposal[1], 'sha') !== FALSE )
                            $proposal[1] = 'sha1';
                        $tmp_P1_config_proposals[$proposal_name]->sethash($proposal[1]);

                        $tmp_P1_config_proposals[$proposal_name]->setencryption($proposal[0]);

                    }

                    if( isset( $gw['keylife'] ) )
                        $tmp_P1_config_proposals[$proposal_name]->setlifetime( "seconds", $keylife);


                    $tmp_newIKEGateway[ $gw['name'] ]->setproposal( $proposal_name );
                }


                if( isset( $gw['interface'] ) )
                    $tmp_newIKEGateway[ $gw['name'] ]->setinterface($gw['interface']);


                #print_r( $gw );
            }
        }


        if( $P2Int_string != "" )
        {
            print "\n\n";
            print "P2Int:\n";
            #print $P2Int_string;
            $IPsecTunnel = $this->splitConfig( $P2Int_string );
            #print_r( $IPsecTunnel );

            foreach( $IPsecTunnel as $key => $tunnel )
            {
                if( !isset( $tunnel['name'] ) )
                    $tunnel['name'] = "no-name".$key;

                $VPN_name = $this->IKE_IPSEC_name_validation($tunnel['name'], "");

                $tmp_newIPsecTunnel[$VPN_name] = $this->template->network->ipsecTunnelStore->findIPsecTunnel($VPN_name);
                if( $tmp_newIPsecTunnel[$VPN_name] == null )
                {
                    $tmp_newIPsecTunnel[$VPN_name] = $this->template->network->ipsecTunnelStore->newIPsecTunnel($VPN_name);
                }


                if( isset( $tunnel['phase1name'] ) )
                {
                    $gateway = $this->IKE_IPSEC_name_validation($tunnel['phase1name'], "");
                    $tmp_newIPsecTunnel[$VPN_name]->setIKEGateway($gateway);
                }

                if( isset( $tunnel['proposal'] ) && isset( $tunnel['dhgrp'] ))
                {
                    $proposal = $tunnel['proposal'];
                    $dh = $tunnel['dhgrp'];


                    $proposal_array = explode( " ", $proposal );

                    $tmp_name = "";
                    foreach( $proposal_array as $key => $proposal )
                    {
                        if( empty( $proposal)  )
                            continue;
                        #print "'".$proposal."'\n";
                        $proposal = explode( "-", $proposal );

                        if( count( $proposal) ==2 )
                            $tmp_name .= $proposal[1]."_".$proposal[0];
                        else
                            $tmp_name .= $proposal[0];
                        if( $key != 0 )
                            $tmp_name .= "-";

                    }

                    $proposal_name = "g".$dh."_".$tmp_name;

                    $tmp_P2_config_proposals[$proposal_name] = $this->template->network->ipsecCryptoProfileStore->findIpsecCryptoProfil($proposal_name);
                    if( $tmp_P2_config_proposals[$proposal_name] == null )
                    {
                        $tmp_P2_config_proposals[$proposal_name] = $this->template->network->ipsecCryptoProfileStore->newIPsecCryptoProfil($proposal_name);

                        if( $print )
                            print "create IPSEC crypto proposal: " . $proposal_name . "\n";
                    }




                    $tmp_P2_config_proposals[$proposal_name]->setDHgroup( "group".$dh );

                    foreach( $proposal_array as $key => $proposal )
                    {
                        if( empty( $proposal)  )
                            continue;
                        print "'".$proposal."\n";
                        $proposal = explode( "-", $proposal );

                        #if( strpos($proposal[1], 'sha') !== FALSE )
                        #$proposal[1] = 'sha1';
                        if( isset($proposal[1]) )
                            $tmp_P2_config_proposals[$proposal_name]->setauthentication($proposal[1], 'esp');

                        if( strpos($proposal[0], 'aes128') !== FALSE )
                            $proposal[0] = 'aes-128-cbc';
                        if( strpos($proposal[0], 'aes256') !== FALSE )
                            $proposal[0] = 'aes-256-cbc';
                        $tmp_P2_config_proposals[$proposal_name]->setencryption($proposal[0]);
                    }


                    if( isset( $tunnel['keylife-type'] ) )
                    {
                        $keylife = $tunnel['keylife'.$tunnel['keylife-type']];
                        $tmp_P2_config_proposals[$proposal_name]->setlifetime( $tunnel['keylife-type'], $keylife);
                    }

                    $tmp_newIPsecTunnel[$VPN_name]->setProposal( $proposal_name);
                }

                //Todo: create tunnel interface
                //$tunnelInt = newtunnel aso.
                //$tmp_newIPsecTunnel[$VPN_name]->setInterface($tunnelInt );
                $tunnelINTP2 = $this->tunnelinterface[ $tunnel['phase1name'] ];

                print "set interface: ".$tunnelINTP2->name()."\n";
                $tmp_newIPsecTunnel[$VPN_name]->setInterface($tunnelINTP2->name() );

                //Todo: add proxyID
                if( isset( $tunnel['dst-subnet'] ) && isset( $tunnel['src-subnet'] ) )
                {
                    $srcSubnet = $tunnel['src-subnet'];
                    $dstSubnet = $tunnel['dst-subnet'];

                    $srcSubnet = explode( " ", $srcSubnet );
                    $dstSubnet = explode( " ", $dstSubnet );

                    $srcSubnet[1] = CIDR::netmask2cidr($srcSubnet[1] );
                    $dstSubnet[1] = CIDR::netmask2cidr($dstSubnet[1] );

                    if( $srcSubnet[0] == "0.0.0.0" && $dstSubnet[0] == "0.0.0.0" )
                    {

                    }
                    else
                        $tmp_newIPsecTunnel[$VPN_name]->addProxyId( $srcSubnet[0]."/".$srcSubnet[1], $dstSubnet[0]."/".$dstSubnet[1]);
                }

                print_r( $tunnel );
            }

        }
    }

    function splitConfig( $string )
    {
        $array1 = explode( "\n", $string);

        $start = false;
        $name = "";

        foreach( $array1 as $line )
        {

            if( preg_match("/    edit/i", $line) )
            {
                $start = true;
                $name = trim( $line );
                $name = explode( " ", $name);
                $name = $name[ 1 ];
                $name = str_replace( '"', "", $name );
                $array[ $name ]['name'] = $name;
            }
            elseif( preg_match("/    next/i", $line) )
            {
                $start = false;
            }
            else
            {
                $set = trim( $line );
                $set = explode( " ", $set);

                if( isset( $set[1] ) && isset( $set[2] ) )
                {
                    $text = "";
                    if( count( $set ) > 3 )
                    {
                        $i = 2;
                        while( count( $set ) > $i )
                        {
                            $text .= $set[$i]." ";
                            $i++;
                        }
                    }
                    else
                        $text = $set[2];
                    $text = str_replace( '"', "", $text );
                    $array[ $name ][ $set[1] ] = $text;
                }

            }

        }


        return $array;
    }
}