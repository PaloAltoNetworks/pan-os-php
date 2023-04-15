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


trait SCREENOSipsec
{
    function netscreen_ipsec($file_content)
    {
        global $debug;
        global $print;
        ########################################################################
########################################################################


        $IKE_array = array();
        $VPN_array = array();
        $tmp_newIKEGateway = array();
        $tmp_newIPsecTunnel = array();

        $P1_proposals = array();
        $P2_proposals = array();

        $P1_config_proposals = array();
        $P2_config_proposals = array();
        $tmp_P1_config_proposals = array();
        $tmp_P2_config_proposals = array();

#$needle = 'set ike gateway "';
#$needle = "";

        $newIKEGateway = array();


        $policy_based_vpn = array();
        $policy_based_start = FALSE;
        $policy_based_counter = 0;

        foreach( $file_content as $line )
        {
            $line = $this->strip_hidden_chars($line);

            //print "\n#######################################################################################################################\n";

            $needle = 'set ike p1-proposal "';
            if( strpos($line, 'set ike p1-proposal "') !== FALSE )
            {
                $proposal_name = $this->find_string_between($line, 'set ike p1-proposal "', '" preshare');
                $P1_config_proposals[$proposal_name] = $line;

                $proposal_rest = $this->find_string_between($line, '" ');
                $proposal_argument = explode(" ", $proposal_rest);

                #print_r( $proposal_argument );

                $tmp_P1_config_proposals[$proposal_name] = $this->template->network->ikeCryptoProfileStore->newIKECryptoProfil($proposal_name);
                if( $print )
                    print "create IKE crypto proposal: " . $proposal_name . "\n";

                $tmp_P1_config_proposals[$proposal_name]->setDHgroup($proposal_argument[1]);


                if( strpos($proposal_argument[4], 'sha') !== FALSE )
                    $proposal_argument[4] = 'sha1';
                $tmp_P1_config_proposals[$proposal_name]->sethash($proposal_argument[4]);


                if( strpos($proposal_argument[3], 'aes128') !== FALSE )
                    $proposal_argument[3] = 'aes-128-cbc';
                if( strpos($proposal_argument[3], 'aes256') !== FALSE )
                    $proposal_argument[3] = 'aes-256-cbc';
                $tmp_P1_config_proposals[$proposal_name]->setencryption($proposal_argument[3]);

                //86400 as seconds not available within PAN-OS ; 86400 is 24h
                if( isset($proposal_argument[6]) && intval($proposal_argument[6]) == 86400 )
                {
                    $proposal_argument[5] = 'day';
                    $proposal_argument[6] = '1';
                }
                elseif( isset($proposal_argument[6]) && intval($proposal_argument[6]) > 65535 )
                {
                    //derr( "lifetime is greater then 65535 - validation needed" );
                    if( $debug )
                        mwarning("lifetime is greater then 65535 - validation needed", null, FALSE);
                }

                if( isset($proposal_argument[5]) && isset($proposal_argument[6]) )
                    $tmp_P1_config_proposals[$proposal_name]->setlifetime($proposal_argument[5] . "s", $proposal_argument[6]);
            }

            //print "\n#######################################################################################################################\n";

            $needle = 'set ike p2-proposal "';
            if( strpos($line, $needle) !== FALSE )
            {
                $proposal_name = $this->find_string_between($line, $needle, '" ');
                $P2_config_proposals[$proposal_name] = $line;

                $proposal_rest = $this->find_string_between($line, '" ');
                $proposal_argument = explode(" ", $proposal_rest);
                #print "p2-proposal\n";
                #print_r( $proposal_argument );

                $tmp_P2_config_proposals[$proposal_name] = $this->template->network->ipsecCryptoProfileStore->newIPsecCryptoProfil($proposal_name);
                if( $print )
                    print "create IPSEC crypto proposal: " . $proposal_name . "\n";

                $tmp_P2_config_proposals[$proposal_name]->setDHgroup($proposal_argument[0]);

                if( strpos($proposal_argument[3], 'sha') !== FALSE )
                    $proposal_argument[3] = 'sha1';
                $tmp_P2_config_proposals[$proposal_name]->setauthentication($proposal_argument[3], $proposal_argument[1]);


                if( $proposal_argument[1] == 'esp' || $proposal_argument[1] == 'ah' )
                {
                    if( $proposal_argument[1] == 'esp' )
                    {
                        if( strpos($proposal_argument[2], 'aes128') !== FALSE )
                            $proposal_argument[2] = 'aes-128-cbc';
                        if( strpos($proposal_argument[2], 'aes256') !== FALSE )
                            $proposal_argument[2] = 'aes-256-cbc';
                        $tmp_P2_config_proposals[$proposal_name]->setencryption($proposal_argument[2]);
                    }
                    elseif( $proposal_argument[1] == 'ah' )
                    {
                        $tmp_P2_config_proposals[$proposal_name]->setencryption('notfound');
                    }

                    //86400 as seconds not available within PAN-OS ; 86400 is 24h
                    if( intval($proposal_argument[4]) == 86400 )
                    {
                        $proposal_argument[3] = 'day';
                        $proposal_argument[4] = '1';
                    }
                    elseif( intval($proposal_argument[4]) > 65535 )
                    {
                        #derr( "lifetime is greater then 65535 - validation needed" );
                        if( $debug )
                            mwarning("lifetime is greater then 65535 - validation needed", null, FALSE);
                    }

                    $tmp_P2_config_proposals[$proposal_name]->setlifetime($proposal_argument[3] . "s", $proposal_argument[4]);
                }
            }

            //print "\n#######################################################################################################################\n";

            $needle = 'set ike gateway "';
            $needle2 = 'set ike gateway ikev2 "';
            if( (strpos($line, $needle) !== FALSE) or (strpos($line, $needle2) !== FALSE) )
            {

                //TODO: 20180326 what is this config for
                #dpd-liveness
                if( strpos($line, 'dpd-liveness') !== FALSE )
                {
                    /*
                     *  set ike gateway "IKE:CAdmin" dpd-liveness interval 120
                        set ike gateway "IKE:CAdmin" dpd-liveness retry 3
                     */
                    $IKE_dpd = $this->find_string_between($line, 'dpd-liveness ');
                    $IKE_dpd_argument = explode(" ", $IKE_dpd);
                    if( $debug )
                    {
                        print "$IKE_dpd:\n";
                        print_r($IKE_dpd_argument);
                    }


                    #print $line."\n";
                    #continue;
                }

                #nat-traversal
                if( strpos($line, 'nat-traversal ') !== FALSE )
                {
                    /*
                     *  set ike gateway "doh-sts-esf1" nat-traversal udp-checksum
                        set ike gateway "doh-sts-esf1" nat-traversal keepalive-frequency 5
                     */
                    $IKE_nat_t = $this->find_string_between($line, 'nat-traversal ');
                    $IKE_nat_t_argument = explode(" ", $IKE_nat_t);

                    if( $debug )
                    {
                        print "IKE_nat_t:\n";
                        print_r($IKE_nat_t_argument);
                    }


                    #print $line."\n";
                    #continue;
                }

                if( strpos($line, '" address') !== FALSE || strpos($line, '" dialup') !== FALSE )
                {
                    if( strpos($line, $needle2) !== FALSE )
                    {
                        $IKE_name = $this->find_string_between($line, $needle2, '" address');
                    }
                    elseif( strpos($line, '" address') !== FALSE )
                        $IKE_name = $this->find_string_between($line, $needle, '" address');
                    elseif( strpos($line, '" dialup') !== FALSE )
                        $IKE_name = $this->find_string_between($line, $needle, '" dialup');
                    #$IKE_array[ $IKE_name ]['line'] = $line;


                    if( $print )
                        print "create IKE gateway: " . $IKE_name . "\n";
                    $IKE_name = $this->IKE_IPSEC_name_validation($IKE_name, "IKE");

                    if( strpos($line, $needle2) !== FALSE )
                    {
                        $tmp_newIKEGateway[$IKE_name] = $this->template->network->ikeGatewayStore->newIKEGateway($IKE_name, TRUE);
                    }
                    else
                        $tmp_newIKEGateway[$IKE_name] = $this->template->network->ikeGatewayStore->newIKEGateway($IKE_name);

                    //"-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==" => "DEMO"
                    $tmp_newIKEGateway[$IKE_name]->setPreSharedKey('-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==');
                }
                else
                {
                    #derr( "can not find IKE name: no address or dialup found - " );
                }

                if( strpos($line, ' Main outgoing-interface') !== FALSE )
                {
                    $IKE_address = $this->find_string_between($line, '" address ', ' Main outgoing-interface');
                    $IKE_array[$IKE_name]['address'] = $IKE_address;

                    $tmp_newIKEGateway[$IKE_name]->setpeerAddress($IKE_address);
                }

                if( strpos($line, 'outgoing-interface "') !== FALSE )
                {
                    $IKE_interface = $this->find_string_between($line, 'outgoing-interface "', '" preshare "');
                    $IKE_array[$IKE_name]['interface'] = $IKE_interface;

                    if( strpos($IKE_interface, ":1") !== FALSE )
                        $IKE_interface = str_replace(":1", "", $IKE_interface);
                    if( strpos($IKE_interface, ":2") !== FALSE )
                        $IKE_interface = str_replace(":2", "", $IKE_interface);

                    if( strpos( $IKE_interface, "loopback" ) !== false )
                        $tmp_newIKEGateway[$IKE_name]->setinterface($IKE_interface, "loopback");
                    else
                        $tmp_newIKEGateway[$IKE_name]->setinterface($IKE_interface);
                }

                if( strpos($line, '" proposal "') !== FALSE )
                {
                    $proposal = $this->find_string_between($line, '" proposal "');
                    $proposal = substr($proposal, 0, strpos($proposal, '"'));
                    $IKE_array[$IKE_name]['proposal'] = $proposal;
                    $P1_proposals[$proposal] = $proposal;

                    $tmp_newIKEGateway[$IKE_name]->setproposal($proposal);
                }
            }

            //print "\n#######################################################################################################################\n";

            $needle = 'set vpn "';
            if( strpos($line, $needle) !== FALSE )
            {
                $VPN_name = $this->find_string_between($line, $needle, '" ');
                $VPN_name = $this->IKE_IPSEC_name_validation($VPN_name);
                #$VPN_array[ $VPN_name ]['line'][] = $line;

                $needle = '" gateway "';
                if( strpos($line, $needle) !== FALSE )
                {
                    $gateway = $this->find_string_between($line, $needle, 'replay tunnel');
                    $gateway = str_replace('" no-', "", $gateway);
                    $gateway = str_replace('" ', "", $gateway);

                    if( $print )
                        print "create IPsecTunnel: " . $VPN_name . "\n";
                    $VPN_name = $this->IKE_IPSEC_name_validation($VPN_name, "IPSEC");
                    $tmp_newIPsecTunnel[$VPN_name] = $this->template->network->ipsecTunnelStore->newIPsecTunnel($VPN_name);

                    $gateway = $this->IKE_IPSEC_name_validation($gateway, "IPSEC related IKE");
                    $VPN_array[$VPN_name]['gateway'] = $gateway;

                    $tmp_newIPsecTunnel[$VPN_name]->setIKEGateway($gateway);
                }


                $needle = ' proposal "';
                if( strpos($line, $needle) !== FALSE )
                {
                    $proposal = $this->find_string_between($line, $needle);
                    $proposal = substr($proposal, 0, strpos($proposal, '"'));

                    $VPN_array[$VPN_name]['proposal'] = $proposal;
                    $P2_proposals[$proposal] = $proposal;

                    #print "create P2 proposal:\n";
                    $tmp_newIPsecTunnel[$VPN_name]->setProposal($proposal);
                }


                $needle = 'bind interface ';
                if( strpos($line, $needle) !== FALSE )
                {
                    $interface = $this->find_string_between($line, $needle);


                    if( strpos($interface, ":1") !== FALSE )
                        $interface = str_replace(":1", "", $interface);
                    if( strpos($interface, ":2") !== FALSE )
                        $interface = str_replace(":2", "", $interface);
                    #print "create interface:\n";
                    $interface = trim($interface);
                    $VPN_array[$VPN_name]['interface'] = $interface;
                    print "set interface: ".$interface." - for ipsectunnel: ".$tmp_newIPsecTunnel[$VPN_name]->name()."\n";
                    $tmp_newIPsecTunnel[$VPN_name]->setInterface($interface);
                }


                $needle = ' remote-ip ';
                if( strpos($line, $needle) !== FALSE )
                {
                    $remote_ip = $this->find_string_between($line, $needle);
                    $protocol = $remote_ip;
                    $remote_ip = substr($remote_ip, 0, strpos($remote_ip, ' "'));

                    $local_ip = $this->find_string_between($line, ' proxy-id local-ip ', $needle);
                    $VPN_array[$VPN_name]['proxy-id'][$remote_ip] = $local_ip;

                    $protocol = substr($protocol, strpos($protocol, ' "') + 2);
                    $protocol = substr($protocol, 0, strpos($protocol, '"'));
                    if( strtolower($protocol) !== "any" )
                    {
                        if( $debug )
                        {
                            print $line . "\n";
                            mwarning("protocol is NOT any - not implemented yet", null, FALSE);
                            //$warning++;
                            #derr( "protocol is NOT any - not implemented yet - change to warning and change manually" );
                        }
                    }

                    $tmp_newIPsecTunnel[$VPN_name]->addProxyId($local_ip, $remote_ip);
                }
            }

            $needle = 'set policy id';
            if( strpos($line, $needle) !== FALSE )
            {
                $VPN_name = $this->find_string_between($line, $needle, '" ');

                $needle2 = 'tunnel vpn';
                if( strpos($line, $needle2) !== FALSE )
                {
                    $policy_based_vpn[$policy_based_counter] = $line;
                    $policy_based_counter++;
                }
                else
                {
                    if( strpos($line, "permit") == FALSE )
                    {
                        $policy_based_start = TRUE;
                    }
                }

            }

            if( $policy_based_start )
            {
                if( strpos($line, "exit") !== FALSE )
                {
                    $policy_based_counter++;
                    $policy_based_start = FALSE;
                }

                else
                {
                    $needle2 = 'tunnel vpn';
                    if( strpos($line, $needle2) !== FALSE )
                    {
                        $policy_based_vpn[$policy_based_counter][] = $line;
                    }
                }
            }
        }

        if( count($policy_based_vpn) > 0 )
        {
            //print_r( $policy_based_vpn );
//Todo: SVEn 20190514 investigate
// find next free tunnel interface number and create it and bind it to IPsec
// create Security Rule for outgoing / incoming proxy-id traffic
//PROBLEMS:
//add route - problem how to define what is local and what is remote ??????
// create proxy-id for IPsec definition - problem: what is remote what is local???????

            //mwarning( 'Policy based VPN found - not supported yet! ', null, false );
        }


#######################################################################################################################


        if( $print )
        {
            print "\n#######################################################################################################################\n";

            print_r($IKE_array);
            print_r($VPN_array);
        }
//check if for each VPN (phase2) there is also an IKE (phase1) available
        foreach( $VPN_array as $tunnel_name => $phase2 )
        {
            if( !isset($IKE_array[$phase2['gateway']]) )
            {
                print "NO IKE gateway (" . $phase2['gateway'] . ") found for VPN: " . $tunnel_name . "\n";
            }
        }

#######################################################################################################################

//https://kb.juniper.net/InfoCenter/index?page=content&id=KB6719&cat=FIREWALL_IPSEC_VPN&actp=LIST
//https://www.juniper.net/documentation/software/screenos/screenos6.3.0/630_ce_VPN.pdf


//lifetime:
        /*
         * The default lifetime for Phase 1 is 28800 seconds

            The default lifetime for Phase 2 is 3600 seconds
            https://forums.juniper.net/t5/SRX-Services-Gateway/VPN-standard-proposal-set-default-value/td-p/109084
         */

        if( $print )
        {
            print "\n\n";

            print_r($P1_proposals);
            print "P1 proposals of config file:\n";
            print_r($P1_config_proposals);


            print "\n#######################################################################################################################\n";

            print "Check each P1 proposal, if there is also an configuration proposal available\n";
        }

        foreach( $P1_proposals as $proposal_name => $phase2 )
        {
            if( !isset($P1_config_proposals[$proposal_name]) )
            {
                if( $print )
                    print "NO P1_proposal found for VPN: " . $proposal_name . "\n";
                #print_r( $proposal_argument );

                $proposal_argument = explode("-", $proposal_name);

                $tmp_P1_config_proposals[$proposal_name] = $this->template->network->ikeCryptoProfileStore->newIKECryptoProfil($proposal_name);

                if( $print )
                    print "create IKE crypto profile: " . $proposal_name . "\n";

                $tmp_P1_config_proposals[$proposal_name]->setDHgroup($proposal_argument[1]);

                if( strpos($proposal_argument[3], 'sha') !== FALSE )
                    $proposal_argument[3] = 'sha1';
                $tmp_P1_config_proposals[$proposal_name]->sethash($proposal_argument[3]);


                if( strpos($proposal_argument[2], 'aes128') !== FALSE )
                    $proposal_argument[2] = 'aes-128-cbc';
                if( strpos($proposal_argument[2], 'aes256') !== FALSE )
                    $proposal_argument[2] = 'aes-256-cbc';
                $tmp_P1_config_proposals[$proposal_name]->setencryption($proposal_argument[2]);
                $tmp_P1_config_proposals[$proposal_name]->setlifetime("seconds", "28800");
            }

        }

        if( $print )
        {
            print "\n#######################################################################################################################\n";

            print "\n\n";
            print "Check each VPN (phase2) proposal if there is also an P2 configuration proposal available\n";
        }

        foreach( $P2_proposals as $proposal_name => $phase2 )
        {
            if( !isset($P2_config_proposals[$proposal_name]) )
            {
                if( $print )
                    print "NO P2_proposal found for VPN: " . $proposal_name . "\n";
                #print_r( $proposal_argument );


                $proposal_argument = explode("-", $proposal_name);

                $tmp_P2_config_proposals[$proposal_name] = $this->template->network->ipsecCryptoProfileStore->newIPsecCryptoProfil($proposal_name);
                if( $print )
                    print "create IPSEC crypto profile: " . $proposal_name . "\n";

                if( $proposal_argument[1] != 'nopfs' )
                    $tmp_P2_config_proposals[$proposal_name]->setDHgroup($proposal_argument[0]);

                if( strpos($proposal_argument[3], 'sha') !== FALSE )
                    $proposal_argument[3] = 'sha1';
                $tmp_P2_config_proposals[$proposal_name]->setauthentication($proposal_argument[3], $proposal_argument[1]);

                if( $proposal_argument[1] == 'esp' )
                {
                    if( strpos($proposal_argument[2], 'aes128') !== FALSE )
                        $proposal_argument[2] = 'aes-128-cbc';
                    if( strpos($proposal_argument[2], 'aes256') !== FALSE )
                        $proposal_argument[2] = 'aes-256-cbc';
                    $tmp_P2_config_proposals[$proposal_name]->setencryption($proposal_argument[2]);
                }


                $tmp_P2_config_proposals[$proposal_name]->setlifetime("seconds", "3600");
            }


        }
        if( $print )
        {
            print_r($P2_proposals);
            print "P2 proposals of config file:\n";
            print_r($P2_config_proposals);
        }
    }

}


