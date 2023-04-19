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


trait CISCOvpn
{
    function tmp_cloneIPsecProfile( $ipsecTunnels, $cryptoMapName, $cisco_prof_name, $tmp_array)
    {
        global $debug;
        global $print;

        $tmp_ipsecCryptoProfiles = $this->template->network->ipsecCryptoProfileStore->findIpsecCryptoProfil($cisco_prof_name);

        if( $tmp_ipsecCryptoProfiles != null )
        {
            #$tmp_ipsecCryptoProfileName = $tmp_ipsecCryptoProfiles->name() . "-" . $cryptoMapName;
            $tmp_ipsecCryptoProfileName = "clonded-" . $cryptoMapName;
            $tmp2_ipsecCryptoProfiles = $tmp_ipsecCryptoProfiles->cloneIPsecCryptoProfile( $tmp_ipsecCryptoProfileName );

            $ipsecTunnels[$cryptoMapName]->setProposal($tmp2_ipsecCryptoProfiles->name());
            if( $print )
            {
                print " * clone " . $tmp_ipsecCryptoProfiles->name() . " and set new name: " . $tmp_ipsecCryptoProfiles->name() . "-" . $cryptoMapName . "\n";
                print " * add IPsecCryptoProfile: " . $tmp_ipsecCryptoProfiles->name() . "-" . $cryptoMapName . " to IPsecTunnel: " . $cryptoMapName . "\n";
            }

            if( !empty($tmp_array) )
            {
                if( isset($tmp_array['lifetime']) )
                {
                    if( $print )
                        print " * set lifetime: " . $tmp_array['lifetime']['value'] . " with time: " . $tmp_array['lifetime']['time'] . "\n";
                    $tmp2_ipsecCryptoProfiles->setlifetime($tmp_array['lifetime']['value'], $tmp_array['lifetime']['time']);
                }
                elseif( isset($tmp_array['lifesize']) )
                {
                    if( $print )
                        print " * set lifesize: " . $tmp_array['lifesize']['value'] . " with size: " . $tmp_array['lifesize']['size'] . "\n";
                    $tmp2_ipsecCryptoProfiles->setlifesize($tmp_array['lifesize']['value'], $tmp_array['lifesize']['size']);
                }
                elseif( isset($tmp_array['pfs']) )
                {
                    if( $print )
                        print " * set pfs: " . $tmp_array['pfs'] . "\n";
                    $tmp2_ipsecCryptoProfiles->setDHgroup($tmp_array['pfs']);
                }

                $tmp_array = array();
            }
        }
        else
        {
            mwarning("can not finde ipsec crypto profil: " . $cisco_prof_name . "|\n", null, FALSE);
            $tmp2_ipsecCryptoProfiles = null;
        }


        return array($tmp2_ipsecCryptoProfiles, $tmp_array);
    }

    /**
     * @param array $this->data
     * @param PANConf $pan
     */

#function get_ipsec_vpn_sven($config_path, $source, $vsys,$template,$jobid,$project){
    function get_ipsec_vpn2()
    {
        global $projectdb;

        global $debug;
        global $print;

        $cryptoProfiles = [];
        $ipsecTunnels = [];
        $checking_psk = FALSE;
        $tunnelInterfaces = [];
        $isIkev1Profile = FALSE;
        $IkeCryptoProfiles = [];
        $ikeGateways = array();
        $ipsecCryptoProfiles = array();
        $tmp2_ipsecCryptoProfiles = null;

//    update_progress($project, '0.90', 'Importing IPSEC VPNs');
        # Get Base Config VERSION
        /*
        $getVersion = $projectdb->query("SELECT version FROM device_mapping WHERE active=1 AND baseconfig=1 GROUP BY filename;");
        if ($getVersion->num_rows == 1) {
            $getVersionData = $getVersion->fetch_assoc();
            $panos_version = $getVersionData['version'];
            if (preg_match("/^6\.0/", $panos_version)) {
                $version = 6;
            } elseif (preg_match("/^6\.1/", $panos_version)) {
                $version = 6.1;
            } elseif (preg_match("/^5\./", $panos_version)) {
                $version = 5;
            } elseif (preg_match("/^7\./", $panos_version)) {
                $version = 7;
            }
        }
        else {
            $version = 7;
        }
        */
        //Todo: check out verion, static set for now
        $version = 7;


        # Check Tunnel Interfaces
        #$getTunnel = $projectdb->query("SELECT unitname FROM interfaces WHERE media='tunnel' AND template='$template';");
        $getTunnel = $this->template->network->tunnelIfStore->getInterfaces();
        if( count($getTunnel) > 0 )
        {
            $old = 0;
            foreach( $getTunnel as $tunnel )
            {
                $tunnel_name = $tunnel->name();
                $split = explode(".", $tunnel_name);
                $new = intval($split[1]);
                if( $new > $old )
                {
                    $old = $new;
                }
            }
            /*
            while ($getTunnelData = $getTunnel->fetch_assoc()) {
                $split = explode(".", $getTunnelData['unitname']);
                $new = intval($split[1]);
                if ($new > $old) {
                    $old = $new;
                }
            }*/
            $tunnelID = $old + 1;
        }
        else
        {
            $tunnelID = 1;
        }

        //Todo: Sven Waschkut - why choosing only the first VR found in config???
        # Read VR
        /*
        $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND source='$source';");
        if ($getVR->num_rows == 1) {
            $getVRData = $getVR->fetch_assoc();
            $vr_id = $getVRData['id'];
        }
        */



        #$this->data = file($config_path);

        $vsys = $this->template_vsys->name();
        #Check if THE VR is already created for this VSYS
        $vr = "vr_" . $vsys;

        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr === null )
        {
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
        }

        $tmp_array = array();
        $cryptoMapName = "";
        $cryptoMapPriority = "";
        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);

            if( $names_line == "!" )
            {
                $isIkev1Profile = FALSE;
            }

            if( (preg_match("/crypto isakmp enable/", $names_line)) or (preg_match("/crypto ikev1 enable/", $names_line)) )
            {
                $split = $names_line;
                $ikeInterface = $split[3];
            }

            if( preg_match("/crypto ipsec ikev2 ipsec-proposal/", $names_line) )
            {
                $split = explode(" ", $names_line);
                $ikev2ProposalName = $split[4];
                #$cryptoProfiles["$ikev2ProposalName"] = new IpsecCryptoProfile;
                #$cryptoProfiles["$ikev2ProposalName"]->name = $ikev2ProposalName;


                #$tmp_ikecryptoProfile = $this->template->network->ikeCryptoProfileStore->newIkeCryptoProfil( $ikev2ProposalName );
                #$ikecryptoProfiles[ $ikev2ProposalName ] = $tmp_ikecryptoProfile;
                $tmp_ipsecCryptoProfiles = $this->template->network->ipsecCryptoProfileStore->findIpsecCryptoProfil($ikev2ProposalName);
                if( $tmp_ipsecCryptoProfiles === null )
                {
                    if( $print )
                    {
                        #print " * create IKE crypto Profile: ".$ikev2ProposalName."\n";
                        print " * create IPSEC crypto Profile: " . $ikev2ProposalName . "\n";
                    }
                    $tmp_ipsecCryptoProfiles = $this->template->network->ipsecCryptoProfileStore->newIPsecCryptoProfil($ikev2ProposalName);
                }


                $ipsecCryptoProfiles[$ikev2ProposalName] = $tmp_ipsecCryptoProfiles;
            }

            if( preg_match("/protocol esp encryption /", $names_line) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                unset($split[1]);
                unset($split[2]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $splitelement )
                {
                    switch ($splitelement)
                    {
                        case "des":
                            #$addlog = 'Encryption DES is not supported on Profile [' . $ikev2ProposalName . ' - Automatically changed to 3des. Please update with your peer';
                            #$cryptoProfiles["$ikev2ProposalName"]->addEncryption("3des");
                            //Todo: SVEN - with PAN-OS 7.1 'DES' is supported
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setencryption('des');
                            #$ipsecCryptoProfiles[$ikev2ProposalName]->set_node_attribute( 'warning', $addlog );
                            break;
                        case "3des":
                            #$cryptoProfiles["$ikev2ProposalName"]->addEncryption("3des");
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setencryption('3des');
                            break;
                        case "aes":
                            $addlog = 'Encryption AES128 changed to [aes-128-cbc] on Profile [' . $ikev2ProposalName . '] - Please update with your peer';
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setencryption('aes-128-cbc');
                            $ipsecCryptoProfiles[$ikev2ProposalName]->set_node_attribute('warning', $addlog);
                            /*
                            if ($version < 7) {
                                $ikecryptoProfiles["$ikev2ProposalName"]->addEncryption("aes128");
                            } else {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-128-cbc");
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                            */
                            break;
                        case "aes-192":
                            $addlog = 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $ikev2ProposalName . '] - Please update with your peer';
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setencryption('aes-192-cbc');
                            $ipsecCryptoProfiles[$ikev2ProposalName]->set_node_attribute('warning', $addlog);
                            /*
                            if ($version < 7) {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes192");
                            } else {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-192-cbc");
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                            */
                            break;
                        case "aes-256":
                            $addlog = 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $ikev2ProposalName . '] - Please update with your peer';
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setencryption('aes-256-cbc');
                            $ipsecCryptoProfiles[$ikev2ProposalName]->set_node_attribute('warning', $addlog);
                            /*
                            if ($version < 7) {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes256");
                            } else {
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-256-cbc");
                            }
                            */
                            break;
                    }
                }
            }

            if( preg_match("/protocol esp integrity /", $names_line) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                unset($split[1]);
                unset($split[2]);
                $split_tmp = array_values($split);
                $split = $split_tmp;

                //Todo: search for ipsec-protocoll
                $ipsecProtocol = 'esp';

                foreach( $split as $splitelement )
                {
                    switch ($splitelement)
                    {
                        case "md5":
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setauthentication('md5', $ipsecProtocol);
                            #$cryptoProfiles["$ikev2ProposalName"]->addAuthentication("md5");
                            break;
                        case "sha-1":
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setauthentication('sha1', $ipsecProtocol);
                            #$cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha1");
                            break;
                        case "sha256":
                        case "sha-256":
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setauthentication('sha256', $ipsecProtocol);
                            #$cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha256");
                            break;
                        case "sha384":
                        case "sha-384":
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setauthentication('sha384', $ipsecProtocol);
                            #$cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha384");
                            break;
                        case "sha512":
                        case "sha-512":
                            $ipsecCryptoProfiles[$ikev2ProposalName]->setauthentication('sha512', $ipsecProtocol);
                            #$cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha512");
                            break;
                    }
                }
            }

            if( (preg_match("/crypto ipsec transform-set/i", $names_line)) or (preg_match("/crypto ipsec ikev1 transform-set/i", $names_line)) )
            {
                # Read the IPSEC CRYPTO PROFILE
                //$my = fopen("vpn.txt","a"); fwrite($my, " $names_line \n"); fclose($my);
                $split = explode(" ", $names_line);
                if( preg_match("/crypto ipsec ikev1 transform-set/i", $names_line) )
                {
                    unset($split[2]);
                    $split_tmp = array_values($split);
                    $split = $split_tmp;
                }

                #$cryptoProfiles["$split[3]"] = new IpsecCryptoProfile;

                $ipsecCryptoProfileName = $split[3];
                $tmp_ipsecCryptoProfiles = $this->template->network->ipsecCryptoProfileStore->findIpsecCryptoProfil($split[3]);
                if( $tmp_ipsecCryptoProfiles === null )
                {

                    if( $print )
                        print " * create IPSEC crypto Profile: " . $ipsecCryptoProfileName . "\n";
                    $tmp_ipsecCryptoProfiles = $this->template->network->ipsecCryptoProfileStore->newIPsecCryptoProfil($ipsecCryptoProfileName);
                }


                $ipsecCryptoProfiles[ $ipsecCryptoProfileName ] = $tmp_ipsecCryptoProfiles;
                # Attach Data to the Object
                #$cryptoProfiles["$split[3]"]->name = $split[3];
                $next = 5;
                switch ($split[4])
                {
                    case "esp-null":
                        #$ipseccryptoProfiles["$split[3]"]->addEncryption("null");
                        $ipsecCryptoProfiles[ $ipsecCryptoProfileName ]->set_node_attribute('warning', "esp-null | no encryption set");
                        break;
                    case "esp-des":
                        #$addlog = 'Encryption DES is not supported on Profile [' . $split[3] . '] - Automatically changed to 3des. Please update with your peer';
                        #$ipseccryptoProfiles["$split[3]"]->addEncryption("3des");
                        $ipsecCryptoProfiles[ $ipsecCryptoProfileName ]->setencryption("des");
                        #$ipsecCryptoProfiles[ $split[3] ]->set_node_attribute( 'error', $addlog );
                        break;
                    case "esp-3des":
                        #$cryptoProfiles["$split[3]"]->addEncryption("3des");
                        $ipsecCryptoProfiles[ $ipsecCryptoProfileName ]->setencryption("3des");
                        break;
                    case "esp-aes":
                        if( !preg_match("/-/", $split[5]) )
                        {
                            $next = 6;
                            /*
                            if ($version < 7) {
                                $tmp = "aes" . $split[5];
                            } else {
                                $tmp = "aes-" . $split[5] . "-cbc";
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [' . $tmp . '] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                            $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                            */
                            $addlog = 'Encryption AES changed to [' . "aes-" . $split[5] . "-cbc" . '] on Profile [' .  $ipsecCryptoProfileName  . '] - Please update with your peer';
                            $ipsecCryptoProfiles[ $ipsecCryptoProfileName ]->setencryption("aes-" . $split[5] . "-cbc");
                            $ipsecCryptoProfiles[ $ipsecCryptoProfileName ]->set_node_attribute('error', $addlog);
                        }
                        else
                        {
                            /*if ($version < 7) {
                                $cryptoProfiles["$split[3]"]->addEncryption("aes128");
                            } else {
                                $cryptoProfiles["$split[3]"]->addEncryption("aes-128-cbc");
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }*/
                            $addlog = 'Encryption AES changed to [ aes-128-cbc ] on Profile [' .  $ipsecCryptoProfileName  . '] - Please update with your peer';
                            $ipsecCryptoProfiles[ $ipsecCryptoProfileName ]->setencryption("aes-128-cbc");
                            $ipsecCryptoProfiles[ $ipsecCryptoProfileName ]->set_node_attribute('error', $addlog);
                        }
                        break;
                    case "esp-aes-192":
                        /*
                        if ($version < 7) {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes192");
                        } else {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes-192-cbc");
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                        }*/
                        $addlog = 'Encryption AES changed to [ aes-192-cbc ] on Profile [' . $split[3] . '] - Please update with your peer';
                        $ipsecCryptoProfiles[$split[3]]->setencryption("aes-192-cbc");
                        $ipsecCryptoProfiles[$split[3]]->set_node_attribute('error', $addlog);
                        break;
                    case "esp-aes-256":
                        /*if ($version < 7) {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes256");
                        } else {
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            $cryptoProfiles["$split[3]"]->addEncryption("aes-256-cbc");
                        }*/
                        $addlog = 'Encryption AES changed to [ aes-256-cbc ] on Profile [' . $split[3] . '] - Please update with your peer';
                        $ipsecCryptoProfiles[$split[3]]->setencryption("aes-256-cbc");
                        $ipsecCryptoProfiles[$split[3]]->set_node_attribute('error', $addlog);
                        break;
                    case "esp-aes":
                        if( is_int($split[5]) )
                        {
                            /*if ($version < 7) {
                                $tmp = "aes" . $split[5];
                                $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                            } else {
                                $tmp = "aes-" . $split[5] . "-cbc";
                                $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES' . $split[5] . ' changed to [' . $tmp . '] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }*/
                            $addlog = 'Encryption AES changed to [' . "aes-" . $split[5] . "-cbc" . '] on Profile [' . $split[3] . '] - Please update with your peer';
                            $ipsecCryptoProfiles[$split[3]]->setencryption("aes-" . $split[5] . "-cbc");
                            $ipsecCryptoProfiles[$split[3]]->set_node_attribute('error', $addlog);
                        }
                        break;
                    case "mode":
                        break;
                    default:
                        $addlog = 'Reading IPSEC Crypto Profiles' . $split[4] . ' Encryption not supported on MT yet - Please send an email with the Encryption to fwmigrate at paloaltonetworks.com';
                        $ipsecCryptoProfiles[$split[3]]->set_node_attribute('error', $addlog);
                }

                //Todo: search for ipsec-protocoll
                $ipsecProtocol = 'esp';

                switch ($split[$next])
                {
                    case "esp-md5-hmac":
                        #$cryptoProfiles["$split[3]"]->addAuthentication("md5");
                        $ipsecCryptoProfiles[$split[3]]->setauthentication('md5', $ipsecProtocol);
                        break;
                    case "esp-sha-hmac":
                        #$cryptoProfiles["$split[3]"]->addAuthentication("sha1");
                        $ipsecCryptoProfiles[$split[3]]->setauthentication('sha1', $ipsecProtocol);
                        break;
                    case "esp-sha256-hmac":
                        #$cryptoProfiles["$split[3]"]->addAuthentication("sha256");
                        $ipsecCryptoProfiles[$split[3]]->setauthentication('sha256', $ipsecProtocol);
                        break;
                    case "esp-sha384-hmac":
                        #$cryptoProfiles["$split[3]"]->addAuthentication("sha384");
                        $ipsecCryptoProfiles[$split[3]]->setauthentication('sha384', $ipsecProtocol);
                        break;
                    case "esp-sha512-hmac":
                        #$cryptoProfiles["$split[3]"]->addAuthentication("sha512");
                        $ipsecCryptoProfiles[$split[3]]->setauthentication('sha512', $ipsecProtocol);
                        break;
                    case "esp-none":
                        #$cryptoProfiles["$split[3]"]->addAuthentication("none");
                        break;
                }
            }


            if( preg_match("/crypto ipsec security-association lifetime seconds /", $names_line) )
            {
                $split = explode(" ", $names_line);
                $this->convertLifeTime($split[5], 1, $time_value, $time);
                foreach( $ipsecCryptoProfiles as $key => $cryptoProfilesObj )
                {
                    #$cryptoProfilesObj->addLifeTime($time, $time_value);
                    $cryptoProfilesObj->setlifetime($time_value, $time);
                }
            }


            if( preg_match("/crypto ipsec security-association lifetime kilobytes /", $names_line) )
            {
                $split = explode(" ", $names_line);
                $this->convertLifeSize($split[5], 1, $size_value, $size);
                foreach( $cryptoProfiles as $key => $cryptoProfilesObj )
                {
                    #$cryptoProfilesObj->addLifeSize($size, $size_value);
                    $cryptoProfilesObj->setlifesize($size_value, $size);
                }
            }


            if( preg_match("/crypto map /", $names_line) )
            {
                //$cryptoMapPriority = $split[3];
                //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "$names_line\n"); fclose($my);

                $split = explode(" ", $names_line);


                if( ($split[4] == "match") and ($split[5] == "address") )
                {
                    $cryptoMapPriority = $split[3];
                    //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "   $cryptoMapPriority\n"); fclose($my);
                    $cryptoMapName = $split[2] . "-" . $cryptoMapPriority;

                    $accesslist = $split[6];
                    $tunnelName = "tunnel." . $tunnelID;
                    $tunnelInterfaces[] = $tunnelName;

                    #$projectdb->query("INSERT INTO interfaces (name,template,source,vsys,unitname,zone,media,vr_id) VALUES ('tunnel','$template','$source','$vsys','$tunnelName','$cryptoMapName','tunnel','$vr_id');");
                    #$projectdb->query("INSERT INTO zones (source,template,vsys,name,interfaces,type) VALUES ('$source','$template','$vsys','$cryptoMapName','$tunnelName','layer3');");


                    $tmp_int_main = $this->template->network->findInterface($tunnelName);
                    if( !is_object($tmp_int_main) )
                    {
                        $tmp_int_main = $this->template->network->tunnelIfStore->newTunnelIf($tunnelName);
                        $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);


                        $tmp_zone = $this->template_vsys->zoneStore->find($cryptoMapName);
                        if( $tmp_zone == null )
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($cryptoMapName, 'layer3');

                        $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);

                        $tmp_vr->attachedInterfaces->addInterface($tmp_int_main);

                    }


                    # UPDATE VR_ID with Interface
                    #$my = fopen("ciscoipsec.txt","a"); fwrite($my, "ipsecTunnels inserting $cryptoMapPriority\n"); fclose($my);
                    print "ipsecTunnels inserting " . $cryptoMapName . " - accesslist: " . $accesslist . "\n";

                    //$ipsecTunnels["$cryptoMapName-$cryptoMapPriority"] = new IpsecTunnel($cryptoMapName, $cryptoMapPriority, $accesslist, $tunnelName);
                    print "create ipsec tunnel: " . $cryptoMapName . "\n";
                    $tmp_ipsectunnel = $this->template->network->ipsecTunnelStore->newIPsecTunnel($cryptoMapName);
                    $ipsecTunnels[$cryptoMapName] = $tmp_ipsectunnel;
                    $ipsecTunnels[$cryptoMapName]->setInterface($tmp_int_main->name());
                    //Todo; create ipsec tunnel and add relevant information to ipsectunnel

                    //Todo: add proxyid right now here based on $accesslist search;
                    //SVEN 20200508
                    $tmp_tag_vpn = $this->sub->tagStore->findOrCreate("VPN-l2l");

                    self::getProxyIDinformation( $tmp_ipsectunnel, $accesslist, $tmp_tag_vpn, $tmp_vr);

                    $tunnelID++;

                    //cleanup
                    $tmp2_ipsecCryptoProfiles = null;
                    $tmp_array = array();
                }
                elseif( isset($ipsecTunnels[$cryptoMapName]) )
                {
                    if( ($split[4] == "set") and ($split[5] == "peer") )
                    {
                        if( $this->ip_version($split[6]) == "noip" )
                        {
                            $tmp_address = $this->sub->addressStore->find($split[6]);
                            if( $tmp_address != null )
                            {
                                $split[6] = $tmp_address->getNetworkValue();
                            }
                            else
                            {
                                mwarning("Ipsec: address object not found: " . $split[6], null, FALSE);
                            }
                            /*
                            $getIP = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext ='$split[6]' LIMIT 1;");
                            if ($getIP->num_rows == 1) {
                                $getIPData = $getIP->fetch_assoc();
                                $split[6] = $getIPData['ipaddress'];
                            }
                            */
                        }
                        //$cryptoMapPriority = $split[3];
                        //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "   $cryptoMapPriority\n"); fclose($my);
                        #$ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->addPeer($split[6]);
                        #$ikeGateways["$cryptoMapPriority"] = new IkeGateway($cryptoMapName, $split[6]);

                        print "create IKE gateway: " . $cryptoMapName . "\n";
                        $tmp_ikegateway = $this->template->network->ikeGatewayStore->newIKEGateway($cryptoMapName);
                        $ikeGateways[$cryptoMapName] = $tmp_ikegateway;
                        $ikeGateways[$cryptoMapName]->setpeerAddress($split[6]);

                        $ipsecTunnels[$cryptoMapName]->setIKEGateway($ikeGateways[$cryptoMapName]->name());

                    }
                    elseif( ($split[4] == "set") and ($split[5] == "transform-set") )
                    {
                        /*$transformSet = clone $cryptoProfiles["$split[6]"];
                        $transformSet->name = $transformSet->name . "-" . $cryptoMapPriority;
                        $ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->addTransformSet($transformSet);*/

                        print "line: |" . $names_line . "\n";

                        $tmp_array2 = $this->tmp_cloneIPsecProfile( $ipsecTunnels, $cryptoMapName, $split[6], $tmp_array);
                        $tmp2_ipsecCryptoProfiles = $tmp_array2[0];
                        //$tmp2_ipsecCryptoProfiles->setlifetime( "hour", "1");
                        $tmp_array = $tmp_array2[1];
                        /*
                        $tmp_ipsecCryptoProfiles = $this->template->network->ipsecCryptoProfileStore->findIpsecCryptoProfil( $split[6] );

                        $tmp2_ipsecCryptoProfiles = $tmp_ipsecCryptoProfiles->cloneIPsecCryptoProfile( $tmp_ipsecCryptoProfiles->name()."-".$cryptoMapName );

                        $ipsecTunnels[ $cryptoMapName ]->setProposal( $tmp2_ipsecCryptoProfiles->name() );
                        */

                    }
                    elseif( ($split[4] == "set") and (isset($split[6]) && $split[6] == "transform-set") )
                    {
                        /*$transformSet = clone $cryptoProfiles["$split[7]"];
                        $transformSet->name = $transformSet->name . "-" . $cryptoMapPriority;
                        $ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->addTransformSet($transformSet);*/


                        $tmp_array2 = $this->tmp_cloneIPsecProfile( $ipsecTunnels, $cryptoMapName, $split[7], $tmp_array);
                        $tmp2_ipsecCryptoProfiles = $tmp_array2[0];
                        //$tmp2_ipsecCryptoProfiles->setlifetime( "hour", "1");
                        $tmp_array = $tmp_array2[1];
                    }
                    /*
                    elseif (($split[4] == "set") AND (($split[5] == "ikev2")) AND (($split[6] == "ipsec-proposal"))){
                        if ($ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->transformSet) {
                            add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found but ikev1 was seen before: ' . $names_line, $source, 'The tool is not attaching the ikev2 proposal to the Tunnel ' . $ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->name, '', '', '');
                        } else {
                            $transformSet = clone $cryptoProfiles["$split[7]"];
                            $transformSet->name = $transformSet->name . "-" . $cryptoMapPriority;
                            $ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->addTransformSet($transformSet);
                            add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found with more than one:' . $names_line, $source, 'Just Attaching the First One. You can create a new Profile combining all the options from all the Proposals', '', '', '');
                        }
                        add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found with more than one:'.$names_line, $source, 'Just Attaching the First One. You can create a new Profile combining all the options from all the Proposals', '', '', '');
                    }
                    */
                    elseif( ($split[4] == "set") and ($split[5] == "security-association") and ($split[6] == "lifetime") and ($split[7] == "seconds") )
                    {
                        /*$ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->addLifetimeSeconds($split[8]);
                        $this->convertLifeTime($split[8], 1, $time_value, $time);
                        if (isset($transformSet)) {
                            $transformSet->addLifeTime($time, $time_value);
                        }
                        */
                        $this->convertLifeTime($split[8], 1, $time_value, $time);
                        if( $tmp2_ipsecCryptoProfiles != null )
                        {
                            print "set cryptoprofile time: " . $tmp2_ipsecCryptoProfiles->name() . "\n";
                            $tmp2_ipsecCryptoProfiles->setlifetime($time_value, $time);
                        }
                        else
                        {
                            $tmp_array['setlifetime']['value'] = $time_value;
                            $tmp_array['setlifetime']['time'] = $time;
                        }


                    }

                    elseif( ($split[4] == "set") and ($split[5] == "security-association") and ($split[6] == "lifetime") and ($split[7] == "kilobytes") )
                    {
                        if( $split[8] != "unlimited" )
                        {
                            /*$ipsecTunnels["$cryptoMapName."-".$cryptoMapPriority"]->addLifetime_kilobytes($split[8]);
                            $this->convertLifeSize($split[8], 1, $size_value, $size);
                            if (isset($transformSet)) {
                                $transformSet->addLifeSize($size, $size_value);
                            }
                            */
                            if( $tmp2_ipsecCryptoProfiles != null )
                            {
                                $this->convertLifeSize($split[8], 1, $size_value, $size);
                                $tmp2_ipsecCryptoProfiles->setlifesize($size_value, $size);
                            }
                            else
                            {
                                $tmp_array['setlifesize']['value'] = $size_value;
                                $tmp_array['setlifesize']['size'] = $size;
                            }
                        }
                        else
                        {
                            /*if (isset($transformSet)) {
                                $transformSet->addLifeSize('65535', 'tb');
                            }*/
                            if( $tmp2_ipsecCryptoProfiles != null )
                                $tmp2_ipsecCryptoProfiles->setlifesize('tb', '65535');
                            else
                            {
                                $tmp_array['setlifesize']['value'] = 'tb';
                                $tmp_array['setlifesize']['size'] = '65535';
                            }
                        }
                    }

                    elseif( ($split[4] == "set") and ($split[5] == "pfs") )
                    {
                        if( isset($split[6]) )
                        {
                            $pfs = $split[6];
                        }
                        else
                        {
                            $pfs = "group2";
                        }
                        print "PFS: " . $pfs . "\n";
                        if( ($pfs != "group21") and ($pfs != "group24") )
                        {
                            if( $tmp2_ipsecCryptoProfiles != null )
                            {
                                if( $print )
                                    print " * " . $tmp2_ipsecCryptoProfiles->name() . " set DHgroup: " . $pfs . "\n";
                                $tmp2_ipsecCryptoProfiles->setDHgroup($pfs);
                            }
                            else
                            {
                                $tmp_array['pfs'] = $pfs;
                            }
                            /*if (isset($transformSet)) {
                                $transformSet->addDHgroup($pfs);
                            }*/
                        }
                        else
                        {
                            $pfs = "group20";
                            if( $tmp2_ipsecCryptoProfiles != null )
                            {
                                $addlog = 'The PFS group ' . $pfs . ' is not supported yet. Group20 has been assigned instead on Profile[' . $tmp2_ipsecCryptoProfiles->name();

                                if( $print )
                                    print " * " . $tmp2_ipsecCryptoProfiles->name() . " set DHgroup: " . $pfs . "\n";
                                $tmp2_ipsecCryptoProfiles->setDHgroup($pfs);
                            }
                            else
                            {
                                $tmp_array['pfs'] = $pfs;
                            }

                            /*if (isset($transformSet)) {
                                $transformSet->addDHgroup($pfs);
                            }*/
                        }
                    }

                    elseif( $split[3] == "interface" )
                    {
                        $cryptoMapName_int = $split[2];
                        $interface_tmp = $split[4];

                        $tmp_zone = $this->template_vsys->zoneStore->find($interface_tmp);
                        if( $tmp_zone != null )
                        {
                            $tmp_zone_int = $tmp_zone->attachedInterfaces->getAll();
                            if( count($tmp_zone_int) == 1 )
                            {
                                foreach( $ikeGateways as $key => $ikeGWObj )
                                {
                                    if( strpos($ikeGWObj->name(), $cryptoMapName_int) !== FALSE )
                                    {
                                        //Todo: what happen if multiple IP-addresses are attached to one interface??
                                        $ikeGWObj->setinterface($tmp_zone_int[0]->name());
                                    }
                                }
                            }
                            else
                            {
                                //Todo: what happen if multiple interface are attached to this zone?
                                mwarning("found multiple interfaces for zone: " . $interface_tmp, null, FALSE);
                            }
                        }


                        /*
                        $getINT = $projectdb->query("SELECT unitname,unitipaddress FROM interfaces WHERE zone='$interface_tmp' AND template='$template' LIMIT 1;");
                        if ($getINT->num_rows == 1) {
                            $getINTData = $getINT->fetch_assoc();
                            //Todo: it is not correct to change ALL ikeGateways, everytime you found an interface

                            #foreach ($ikeGateways as $key => $ikeGWObj) {
                            3    $ikeGWObj->addInterface($getINTData['unitname']);
                            3    $ikeGWObj->addInterfaceIP($getINTData['unitipaddress']);
                            #}
                            //old correct settings
                            $ikeGateways[ $cryptoMapName ]->addInterface($getINTData['unitname']);
                            $ikeGateways[ $cryptoMapName ]->addInterfaceIP($getINTData['unitipaddress']);
                        }*/
                    }
                    //Todo: not implemented yet
                    /*
                    elseif (($split[4] == "set") AND ( $split[5] == "phase1-mode") AND ( $split[6] == "aggressive")) {
                        $ikeGateways["$cryptoMapPriority"]->exchange_mode_ikev1 = "aggressive";
                    }

                    elseif (($split[4] == "set") AND ( $split[5] == "phase1-mode") AND ( $split[6] == "main")) {
                        $ikeGateways["$cryptoMapPriority"]->exchange_mode_ikev1 = "main";
                    }

                    elseif (($split[4] == "set") AND ( $split[5] == "nat-t-disable")) {
                        $ikeGateways["$cryptoMapPriority"]->nat_traversal = "no";
                    }
                    */

                }
                else
                {
                    mwarning("search for: " . $cryptoMapName . "\n", null, FALSE);
                }
            }

//Todo: continue implementation here 2019/07/23 - nat-t, main/aggressive, PSK
            /*
                    if (preg_match("/no crypto isakmp nat-traversal/", $names_line)) {
                        #Disable globally the nat-t
                        foreach ($ikeGateways as $element) {
                            $element->nat_traversal = "no";
                        }
                    }
                    elseif (preg_match("/crypto isakmp nat-traversal/", $names_line)) {
                        #Disable globally the nat-t
                        foreach ($ikeGateways as $element) {
                            $element->nat_traversal = "yes";
                        }
                    }


                    if ((preg_match("/no crypto ikev1 am-disable/", $names_line)) OR ( preg_match("/no crypto isakmp am-disable/", $names_line))) {
                        foreach ($ikeGateways as $element) {
                            $element->exchange_mode_ikev1 = "aggressive";
                        }
                    }
                    elseif ((preg_match("/crypto ikev1 am-disable/", $names_line)) OR ( preg_match("/crypto isakmp am-disable/", $names_line))) {
                        foreach ($ikeGateways as $element) {
                            $element->exchange_mode_ikev1 = "main";
                        }
                    }

                    # Capture PSK
                    if (preg_match("/tunnel-group /", $names_line)) {
                        $split = explode(" ", $names_line);
                        if ((($this->ip_version($split[1]) == "v4") OR ( $this->ip_version($split[1]) == "v6")) AND ( $split[2] == "ipsec-attributes")) {
                            $last_peer_seen = $split[1];
                            $checking_psk = TRUE;
                        }
                    }

                    # Read Pre-Shared-Key for ikev1
                    if (($checking_psk === TRUE) AND ( preg_match("/ikev1 pre-shared-key/", $names_line))) {
                        $split = explode(" ", $names_line);
                        $psk = $split[2];
                        foreach ($ikeGateways as $key => $ikeGWObj) {
                            if ($ikeGWObj->peer_ip_address == $last_peer_seen) {
                                if ($psk != "*****") {
                                    $ikeGWObj->pre_shared_key = $psk;
                                } else {
                                    $ikeGWObj->pre_shared_key = "";
                                }
                            }
                        }
                        $checking_psk = FALSE;
                    }
                    elseif (($checking_psk === TRUE) AND ( preg_match("/pre-shared-key/", $names_line))) {
                        $split = explode(" ", $names_line);
                        $psk = $split[1];
                        foreach ($ikeGateways as $key => $ikeGWObj) {
                            if ($ikeGWObj->peer_ip_address == $last_peer_seen) {
                                if ($psk != "*****") {
                                    $ikeGWObj->pre_shared_key = $psk;
                                } else {
                                    $ikeGWObj->pre_shared_key = "";
                                }
                            }
                        }
                        $checking_psk = FALSE;
                    }
            */


            # Import the ikev1 Crypto Profiles
            if( (preg_match("/crypto isakmp policy/", $names_line)) or (preg_match("/crypto ikev1 policy/", $names_line)) or (preg_match("/crypto ikev2 policy/", $names_line)) )
            {
                $split = explode(" ", trim($names_line));
                $ikeCryptoProfileName = $split[1] . "-" . $split[3];
                $isIkev1Profile = TRUE;
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/authentication /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                if( preg_match("/pre-share/", $names_line) )
                {
                    $IkeCryptoProfiles[$ikeCryptoProfileName] = $this->template->network->ikeCryptoProfileStore->newIkeCryptoProfil($ikeCryptoProfileName);
                    #$IkeCryptoProfiles[$ikeCryptoProfileName] = new IkeCryptoProfile($ikeCryptoProfileName);
                }
                else
                {
                    $isIkev1Profile = FALSE;
                    $IkeCryptoProfiles[$ikeCryptoProfileName] = $this->template->network->ikeCryptoProfileStore->newIkeCryptoProfil($ikeCryptoProfileName);
                    $addlog = 'Only Pre-Shared key Profiles are supported, Ignoring ' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name();
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->set_node_attribute('error', $addlog);
                }
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/encryption /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                if( !isset($IkeCryptoProfiles[$ikeCryptoProfileName]) )
                {
                    #$IkeCryptoProfiles[$ikeCryptoProfileName] = new IkeCryptoProfile($ikeCryptoProfileName);
                    $IkeCryptoProfiles[$ikeCryptoProfileName] = $this->template->network->ikeCryptoProfileStore->newIkeCryptoProfil($ikeCryptoProfileName);
                }
                switch ($split[1])
                {
                    case "des":
                        $addlog = 'Encryption DES is not supported on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name() . '] - Automatically changed to 3des. Please update with your peer';
                        #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("3des");
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("des");
                        break;
                    case "3des":
                        #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("3des");
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("3des");
                        break;
                    case "aes":
                        if( $version < 7 )
                        {
                            #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes128");
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("aes-128-cbc");
                        }
                        else
                        {
                            #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-128-cbc");
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("aes-128-cbc");
                            $addlog = 'Encryption AES changed to [aes-128-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name() . '] - Please update with your peer';
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->set_node_attribute('error', $addlog);
                        }
                        break;
                    case "aes-192":
                        if( $version < 7 )
                        {
                            #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes192");
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("aes-192-cbc");
                        }
                        else
                        {
                            #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-192-cbc");
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("aes-192-cbc");
                            $addlog = 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name() . '] - Please update with your peer';
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->set_node_attribute('error', $addlog);
                        }
                        break;
                    case "aes-256":
                        if( $version < 7 )
                        {
                            #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes256");
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("aes-256-cbc");
                        }
                        else
                        {
                            $addlog = 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name() . '] - Please update with your peer';
                            #$IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-256-cbc");
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->setencryption("aes-256-cbc");
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->set_node_attribute('error', $addlog);
                        }

                        break;
                    default:
                        #$addlog =  $split[4] . ' Encryption not supported on MT yet - Please send an email with the Encryption to fwmigrate at paloaltonetworks.com';
                        $addlog = $names_line . ' Encryption not supported on MT yet - Please send an email with the Encryption to fwmigrate at paloaltonetworks.com';
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->set_node_attribute('error', $addlog);
                }
            }


            if( ($isIkev1Profile === TRUE) and (preg_match("/hash /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $kkey => $vvalue )
                {
                    //Todo: how to set more hash not only one
                    if( ($vvalue != "") and ($vvalue != null) && $kkey == 0 )
                    {
                        #$IkeCryptoProfiles[$ikeCryptoProfileName]->addHash($vvalue);
                        if( $vvalue == 'sha' )
                            $vvalue = 'sha1';
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->sethash($vvalue);
                    }
                }
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/integrity /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $kkey => $vvalue )
                {
                    //Todo: how to set more hash not only one
                    if( ($vvalue != "") and ($vvalue != null) && $kkey == 0 )
                    {
                        #$IkeCryptoProfiles[$ikeCryptoProfileName]->addHash($vvalue);
                        if( $vvalue == 'sha' )
                            $vvalue = 'sha1';
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->sethash($vvalue);
                    }
                }
            }


            if( ($isIkev1Profile === TRUE) and (preg_match("/group /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $kkey => $vvalue )
                {
                    //Todo: how to set more dhgroup not only one implemented
                    if( ($vvalue != "") and ($vvalue != null) && $kkey == 0 )
                    {
                        $groupname = "group" . $vvalue;
                        #$IkeCryptoProfiles[$ikeCryptoProfileName]->addDHgroup($groupname);
                        if( $print )
                            print " * " . $ikeCryptoProfileName . " * set dhgroup: " . $groupname . "\n";
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->setDHgroup($groupname);
                    }
                }
            }


            if( ($isIkev1Profile === TRUE) and (preg_match("/lifetime /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                if( is_numeric($split[1]) )
                {
                    $this->convertLifeTime($split[1], 1, $time_value, $time);
                    #$IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeType = $time_value;
                    #$IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeValue = $time;
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->setlifetime($time_value, $time);
                }
                else
                {
                    if( $split[1] == "seconds" )
                    {
                        $this->convertLifeTime($split[1], 1, $time_value, $time);
                        #$IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeType = $time_value;
                        #$IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeValue = $time;
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->setlifetime($time_value, $time);
                    }
                }
                $isIkev1Profile = FALSE;
            }
        }

//not needed
        /*
        # OUTPUT
        # IKE Crypto Profile
        if (count($IkeCryptoProfiles) > 0) {
            $allsql = [];
            foreach ($IkeCryptoProfiles as $key => $object) {
                $sql_tmp = $object->getSQL($source, $template, $vsys);
                $allsql[] = $sql_tmp;
            }
            if (count($allsql) > 0) {
                $projectdb->query("INSERT INTO ike_crypto_profiles (name,vsys,source,template,encryption,hash,dh_group,seconds,minutes,hours,days) VALUES " . implode(",", $allsql) . ";");
            }
        }


        # Attach Tunnel Interfaces to the VR
        if (($vr_id != "") AND ( count($tunnelInterfaces) > 0)) {
            $getInt = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$vr_id';");
            if ($getInt->num_rows == 1) {
                $getIntData = $getInt->fetch_assoc();
                $vr_interfaces = $getIntData['interfaces'] . "," . implode(",", $tunnelInterfaces);
                $projectdb->query("UPDATE virtual_routers SET interfaces='$vr_interfaces' WHERE id='$vr_id';");
            }
        }

        #IKE GWS
        if (count($ikeGateways) > 0) {
            $allsql = [];
            foreach ($ikeGateways as $key => $object) {
                $sql_tmp = $object->getSQL($source, $template, $vsys);
                $allsql[] = $sql_tmp;
            }

            if (count($allsql) > 0) {
                $projectdb->query("INSERT INTO ike_gateways_profiles (address_type,name,vsys,source,template,version,dpd_ikev1,ike_interval_ikev1,retry_ikev1,ike_crypto_profile_ikev1,exchange_mode_ikev1,dpd_ikev2,ike_interval_ikev2,ike_crypto_profile_ikev2,require_cookie_ikev2,local_address_ip,interface,type_authentication,pre_shared_key,allow_id_payload_mismatch,strict_validation_revocation,nat_traversal,passive_mode,fragmentation,peer_ip_type,peer_ip_address) VALUES " . implode(",", $allsql) . ";");
            }
            add_log2('info', 'Reading IKE Gateways', 'Please attach the proper IKEv1 / IKEv2 Profiles to your IKE Gateways', $source, 'You can use the Attach buttons from IKE Gateways View', '', '', '');
        }
    */


        #IPSEC tunnel
        if( count($ipsecTunnels) > 0 )
        {
            # Check for VPN-l2l TAG. Create it and add it to all the Rules related to VPNs

            $tmp_tag_vpn = $this->sub->tagStore->findOrCreate("VPN-l2l");
            /*
            $getTAG = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='VPN-l2l' LIMIT 1;");
            if ($getTAG->num_rows == 1) {
                $getTAGData = $getTAG->fetch_assoc();
                $tag_id = $getTAGData['id'];
                $tag_table = "tag";
            }
            else {
                $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('VPN-l2l','$source','$vsys','color1');");
                $tag_id = $projectdb->insert_id;
                $tag_table = "tag";
            }
            */

            $allsql = [];
            //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "Number of ipsecTunnels: ".count($ipsecTunnels)."\n"); fclose($my);

            foreach( $ipsecTunnels as $key => $object )
            {
                //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "    $key, $object->name\n"); fclose($my);
                #$sql_tmp = $object->getSQL($source, $template, $vsys);
                #$allsql[] = $sql_tmp;
                //$this->proposal
                if( isset($object->proposal) )
                {
                    $test[] = $object->proposal;
                }
                else
                {
                    print "The transform set has not been found. Please create a new IPSEC Crypto Profile and attach to " . $object->proposal . "\n";

                }
            }
        }

        //Todo: Sven Waschkut
        return null;

        //Todo: 20200120 continue here:

        //Todo: find way to validate the name of all objects
        /*
        // Check if name start with Num in IPSec Tunnels, IPSec Crypto, IKE Crypto and IKE Gateways
        // IKE Crypto Profiles
        $getIKECryptoProfiles = $projectdb->query("SELECT id, name, template, source FROM ike_crypto_profiles;");
        if($getIKECryptoProfiles->num_rows > 0){
            while($this->dataICP = $getIKECryptoProfiles->fetch_assoc()){
                $id_ike_c_p = $this->dataICP['id'];
                $name_ike_c_p = $this->dataICP['name'];
                $template_ike_c_p = $this->dataICP['template'];
                $source_ike_c_p = $this->dataICP['source'];

                if (checkNamesStartNum($name_ike_c_p) == TRUE) {
                    $name_ike_c_p_new = addPrefixSuffix("on", "p", "", "", $name_ike_c_p, 31);
                    $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev1 = '$name_ike_c_p_new' WHERE source = '$source_ike_c_p' AND template = '$template_ike_c_p' AND ike_crypto_profile_ikev1 = '$name_ike_c_p' ;");
                    $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev2 = '$name_ike_c_p_new' WHERE source = '$source_ike_c_p' AND template = '$template_ike_c_p' AND ike_crypto_profile_ikev2 = '$name_ike_c_p' ;");
                    $projectdb->query("UPDATE ike_crypto_profiles SET name = '$name_ike_c_p_new' WHERE id = '$id_ike_c_p';");
                }
            }
        }

        // IPSec Crypto Profiles
        $getIPSecCryptoProfiles = $projectdb->query("SELECT id, name, template, source FROM ipsec_crypto_profiles;");
        if($getIPSecCryptoProfiles->num_rows > 0){
            while($this->dataICP = $getIPSecCryptoProfiles->fetch_assoc()){
                $id_ipsec_c_p = $this->dataICP['id'];
                $name_ipsec_c_p = $this->dataICP['name'];
                $template_ipsec_c_p = $this->dataICP['template'];
                $source_ipsec_c_p = $this->dataICP['source'];

                if (checkNamesStartNum($name_ipsec_c_p) == TRUE) {
                    $name_ipsec_c_p_new = addPrefixSuffix("on", "p", "", "", $name_ipsec_c_p, 31);
                    $projectdb->query("UPDATE ipsec_tunnel SET ipsec_crypto_profile = '$name_ipsec_c_p_new' WHERE source = '$source_ipsec_c_p' AND template = '$template_ipsec_c_p' AND ipsec_crypto_profile = '$name_ipsec_c_p' ;");
                    $projectdb->query("UPDATE ipsec_crypto_profiles SET name = '$name_ipsec_c_p_new' WHERE id = '$id_ipsec_c_p';");
                }
            }
        }

        // IKE Gateways Profiles
        $getIKEGatewaysProfiles = $projectdb->query("SELECT id, name, template, source FROM ike_gateways_profiles;");
        if($getIKEGatewaysProfiles->num_rows > 0){
            while($this->dataIGP = $getIKEGatewaysProfiles->fetch_assoc()){
                $id_ike_g_p = $this->dataIGP['id'];
                $name_ike_g_p = $this->dataIGP['name'];
                $template_ike_g_p = $this->dataIGP['template'];
                $source_ike_g_p = $this->dataIGP['source'];

                if (checkNamesStartNum($name_ike_g_p) == TRUE) {
                    $name_ike_g_p_new = addPrefixSuffix("on", "p", "", "", $name_ike_g_p, 31);
                    $projectdb->query("UPDATE ipsec_tunnel SET ike_gateway = '$name_ike_g_p_new' WHERE source = '$source_ike_g_p' AND template = '$template_ike_g_p' AND ike_gateway = '$name_ike_g_p' ;");
                    $projectdb->query("UPDATE ike_gateways_profiles SET name = '$name_ike_g_p_new' WHERE id = '$id_ike_g_p';");
                }
            }
        }

        // IPSec Tunnels
        $getIPSecTunnels = $projectdb->query("SELECT id, name, template, source FROM ipsec_tunnel;");
        if($getIPSecTunnels->num_rows > 0){
            while($this->dataIT = $getIPSecTunnels->fetch_assoc()){
                $id_ipsec_t = $this->dataIT['id'];
                $name_ipsec_t = $this->dataIT['name'];
                $template_ipsec_t = $this->dataIT['template'];
                $source_ipsec_t = $this->dataIT['source'];

                if (checkNamesStartNum($name_ipsec_t) == TRUE) {
                    $name_ipsec_t_new = addPrefixSuffix("on", "p", "", "", $name_ipsec_t, 31);
                    $projectdb->query("UPDATE ipsec_tunnel SET name = '$name_ipsec_t_new' WHERE id = '$id_ipsec_t';");
                }
            }
        }
        */
    }

    function getProxyIDinformation( $ipsectunnel, $accesslist, $tmp_tag_vpn, $tmp_vr, $yy = 1)
    {
        global $print;
        global $debug;

        $tunnelInterface = $ipsectunnel->getInterface();
        $ipsecTunnelName = $ipsectunnel->name();


        # Search The Rules by TAG = access-list
        print "search for accesslist: '" . $accesslist . "'\n";

        $tmptag = $this->sub->tagStore->find($accesslist);
        if( $tmptag == null )
        {
            $tmptag = $this->sub->tagStore->findOrCreate($accesslist);
        }


        $tmp_rules = $this->sub->securityRules->rules('tag has ' . $tmptag->name());

        if( count($tmp_rules) > 0 )
        {

            $xx = 1;

            foreach( $tmp_rules as $rule )
            {
                print "tunnel: " . $ipsectunnel->name() . "check rule: " . $rule->name() . "with tag: " . $tmp_tag_vpn->name() . "\n";


                if( $print )
                    print "Rule: " . $rule->name() . " - add TAG: " . $tmp_tag_vpn->name() . "\n";
                $rule->tags->addTag($tmp_tag_vpn);

                $getToZone = $rule->to->getAll();
                $tmp_zone = $this->template_vsys->zoneStore->findOrCreate($ipsecTunnelName);
                if( count($getToZone) == 1 )
                {
                    $rule->to->addZone($tmp_zone);
                    //Todo: 20210715 why is remove no longer working?
                    #$rule->to->removeZone(array_values($getToZone)[0]);
                }
                elseif( count($getToZone) == 0 )
                {

                    $rule->to->addZone($tmp_zone);
                }


                $srcbyrule = $rule->source->getAll();
                $dstbyrule = $rule->destination->getAll();


                //Todo: SVEN
                //go through all objects and check if address group, if group then get only objects

                $getAllSRC = array();
                foreach( $srcbyrule as $key => $addr )
                {
                    if( !$addr->isAddress() )
                    {
                        $tmp_object = $addr->expand();
                        foreach( $tmp_object as $obj2 )
                        {
                            if( $obj2->isType_ipNetmask() )
                            {
                                $getAllSRC[$obj2->name()] = $obj2;
                            }
                            elseif( $obj2->isType_ipRange() )
                            {
                                mwarning( "SRC - RANGE found not implemented yet: ".$obj2->name() );
                            }
                            else
                                mwarning( "ADDR Object found type not implemented yet" );

                        }
                    }
                    else
                    {
                        /** @var Address $addr */
                        if( $addr->isType_ipNetmask() )
                        {
                            $getAllSRC[$addr->name()] = $addr;
                            print "SRC OBJ: " . $addr->name() . " and value: " . $addr->value() . "\n";
                        }
                        elseif( $addr->isType_ipRange() )
                        {
                            mwarning( "SRC - RANGE found not implemented yet: ".$addr->name() );
                        }

                    }

                }

                $getAllDST = array();
                foreach( $dstbyrule as $key => $addr )
                {
                    if( !$addr->isAddress() )
                    {
                        $tmp_object = $addr->expand();
                        foreach( $tmp_object as $obj2 )
                        {
                            if( $obj2->isType_ipNetmask() )
                            {
                                $getAllDST[$obj2->name()] = $obj2;
                            }
                            elseif( $obj2->isType_ipRange() )
                            {
                                $tmp_array = explode( "-", $obj2->value() );
                                $start = $tmp_array[0];
                                $end = $tmp_array[1];
                                $return = CIDR::range2network( ip2long( $start), ip2long( $end ) );

                                if( $return == false )
                                    print "FALSE\n";
                                else
                                    print_r( $return );

                                mwarning( "DST - RANGE found not implemented yet: ".$obj2->name() );
                            }
                            else
                                mwarning( "ADDR Object found type not implemented yet" );
                        }
                    }
                    else
                    {
                        if( $addr->isType_ipNetmask() )
                        {
                            $getAllDST[$addr->name()] = $addr;
                            print "DST OBJ: " . $addr->name() . " and value: " . $addr->value() . "\n";
                        }
                        elseif( $addr->isType_ipRange() )
                        {
                            mwarning( "DST - RANGE found not implemented yet: ".$addr->name() );
                        }
                    }

                }


                foreach( $getAllSRC as $mySrcObj )
                {
                    /*
                    $mySrc = $mySrcObj->value . "/" . $mySrcObj->cidr;
                    $type = $this->ip_version($mySrcObj->value);
                    if ($type == "noip") {
                        $type = "v4";
                    }
                    */
                    $mySrc = $mySrcObj->value();
                    $type = $this->ip_version($mySrcObj->getNetworkValue());
                    if( $type == "noip" )
                    {
                        $type = "v4";
                    }
                    $protocol = "Any";


                    foreach( $getAllDST as $myDstObj )
                    {
                        $myDst = $myDstObj->value();
                        #$myDst = $myDstObj->value . "/" . $myDstObj->cidr;
                        $proxyIDName = "ProxyID" . $xx;
                        $xx++;

                        $ipsectunnel->addProxyId($mySrc, $myDst, $proxyIDName);
                        #$projectdb->query("INSERT INTO proxy_id_ipsec_tunnel (name,vsys,source,template,ipsec_tunnel_id,protocol,local,remote,type) VALUES ('$proxyIDName','$vsys','$source','$template','$ipsecTunnelID','$protocol','$mySrc','$myDst','$type');");


                        # Check the Static Routes

                        $tmp_routes = $tmp_vr->staticRoutes();
                        $found_route = array();
                        foreach( $tmp_routes as $staticRoute )
                        {
                            if( $staticRoute->destination() == $myDst )
                            {
                                $found_route[] = $staticRoute;
                            }
                        }


                        //Todo: fix static routing
                        if( count($found_route) == 0 )
                        {
                            $routeName = $ipsecTunnelName . $yy;
                            $yy++;

                            $route_type = "ip-address";
                            #$nexthop_value = $ip_gateway;

                            $metric = '10';

                            #if( $ip_version == "v4" )
                            $xmlString = "<entry name=\"" . $routeName . "\"><metric>" . $metric . "</metric><interface>" . $tunnelInterface . "</interface><destination>" . $myDst . "</destination></entry>";
                            #elseif( $ip_version == "v6" )
                            #    $xmlString = "<entry name=\"".$routeName."\"><nexthop><ipv6-address>".$ip_gateway."</ipv6-address></nexthop><metric>".$metric."</metric>".$xml_interface."<destination>".$route_network."</destination></entry>";

                            $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                            $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

                            if( $print )
                                print " * add static route: " . $tmpRoute->name() . " with Destination: " . $myDst . " -  Interface: " . $tunnelInterface . "\n";

                            #if( $ip_version == "v4" )
                            $tmp_vr->addstaticRoute($tmpRoute);
                            #elseif( $ip_version == "v6" )
                            #    $tmp_vr->addstaticRoute( $tmpRoute, 'ipv6' );
                        }
                        elseif( count($found_route) == 1 )
                        {
                            #$routeNH = $getRouteData['nexthop_value'];
                            #$projectdb->query("UPDATE routes_static SET nexthop_value='None', nexthop='None', tointerface='$tunnelInterface' WHERE id='$routeID';");

                            $routeName = $found_route[0]->name();
                            $metric = 10;
                            $xmlString = "<entry name=\"" . $routeName . "\"><metric>" . $metric . "</metric><interface>" . $tunnelInterface . "</interface><destination>" . $myDst . "</destination></entry>";

                            $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                            $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

                            if( $print )
                                print " * add static route: " . $tmpRoute->name() . " with Destination: " . $myDst . " -  Interface: " . $tunnelInterface . "\n";

                            $tmp_vr->removeStaticRoute($found_route[0]);

                            $tmp_vr->addstaticRoute($tmpRoute);
                        }
                        else
                        {
                            mwarning('Reading IPSEC Tunnel ProxyIDs - Too many static routes for the destination [' . $myDst . '] - Fix the routes to point to interface [' . $tunnelInterface . ']');
                        }
                    }
                }
            }
        }
        else
        {
            mwarning('Reading IPSEC Tunnel ProxyIDs - No Rules found by TAG [' . $accesslist . '] related to IPSEC Tunnel [' . $ipsecTunnelName . '] - Add PROXYIDs by hand');
        }

    }

    //old - not needed anymore ???
    function get_ipsec_vpn($config_path, $source, $vsys, $template, $jobid, $project)
    {
        global $projectdb;
        $cryptoProfiles = [];
        $ipsecTunnels = [];
        $checking_psk = FALSE;
        $tunnelInterfaces = [];
        $isIkev1Profile = FALSE;
        $IkeCryptoProfiles = [];
        $ikeGateways = array();

//    update_progress($project, '0.90', 'Importing IPSEC VPNs');
        # Get Base Config VERSION
        $getVersion = $projectdb->query("SELECT version FROM device_mapping WHERE active=1 AND baseconfig=1 GROUP BY filename;");
        if( $getVersion->num_rows == 1 )
        {
            $getVersionData = $getVersion->fetch_assoc();
            $panos_version = $getVersionData['version'];
            if( preg_match("/^6\.0/", $panos_version) )
            {
                $version = 6;
            }
            elseif( preg_match("/^6\.1/", $panos_version) )
            {
                $version = 6.1;
            }
            elseif( preg_match("/^5\./", $panos_version) )
            {
                $version = 5;
            }
            elseif( preg_match("/^7\./", $panos_version) )
            {
                $version = 7;
            }
        }
        else
        {
            $version = 7;
        }

        # Check Tunnel Interfaces
        $getTunnel = $projectdb->query("SELECT unitname FROM interfaces WHERE media='tunnel' AND template='$template';");
        if( $getTunnel->num_rows > 0 )
        {
            $old = 0;
            while( $getTunnelData = $getTunnel->fetch_assoc() )
            {
                $split = explode(".", $getTunnelData['unitname']);
                $new = intval($split[1]);
                if( $new > $old )
                {
                    $old = $new;
                }
            }
            $tunnelID = $old + 1;
        }
        else
        {
            $tunnelID = 1;
        }

        # Read VR
        $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND source='$source';");
        if( $getVR->num_rows == 1 )
        {
            $getVRData = $getVR->fetch_assoc();
            $vr_id = $getVRData['id'];
        }

        $this->data = file($config_path);

        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);
            if( (preg_match("/crypto isakmp enable/", $names_line)) or (preg_match("/crypto ikev1 enable/", $names_line)) )
            {
                $split = $names_line;
                $ikeInterface = $split[3];
            }

            if( preg_match("/crypto ipsec ikev2 ipsec-proposal/", $names_line) )
            {
                $split = explode(" ", $names_line);
                $ikev2ProposalName = $split[4];
                $cryptoProfiles["$ikev2ProposalName"] = new IpsecCryptoProfile;
                $cryptoProfiles["$ikev2ProposalName"]->name = $ikev2ProposalName;
            }

            if( preg_match("/protocol esp encryption /", $names_line) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                unset($split[1]);
                unset($split[2]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $splitelement )
                {
                    switch ($splitelement)
                    {
                        case "des":
                            add_log2('error', 'Reading IPSEC Crypto Profiles', 'Encryption DES is not supported on Profile [' . $ikev2ProposalName . ']', $source, 'Automatically changed to 3des. Please update with your peer', '', '', '');
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("3des");
                            break;
                        case "3des":
                            $cryptoProfiles["$ikev2ProposalName"]->addEncryption("3des");
                            break;
                        case "aes":
                            if( $version < 7 )
                            {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes128");
                            }
                            else
                            {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-128-cbc");
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                            break;
                        case "aes-192":
                            if( $version < 7 )
                            {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes192");
                            }
                            else
                            {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-192-cbc");
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                            break;
                        case "aes-256":
                            if( $version < 7 )
                            {
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes256");
                            }
                            else
                            {
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $cryptoProfiles["$ikev2ProposalName"]->name . ']', $source, 'Please update with your peer', '', '', '');
                                $cryptoProfiles["$ikev2ProposalName"]->addEncryption("aes-256-cbc");
                            }
                            break;
                    }
                }
            }

            if( preg_match("/protocol esp integrity /", $names_line) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                unset($split[1]);
                unset($split[2]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $splitelement )
                {
                    switch ($splitelement)
                    {
                        case "md5":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("md5");
                            break;
                        case "sha-1":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha1");
                            break;
                        case "sha256":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha256");
                            break;
                        case "sha384":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha384");
                            break;
                        case "sha512":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha512");
                            break;
                        case "sha-256":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha256");
                            break;
                        case "sha-384":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha384");
                            break;
                        case "sha-512":
                            $cryptoProfiles["$ikev2ProposalName"]->addAuthentication("sha512");
                            break;
                    }
                }
            }

            if( (preg_match("/crypto ipsec transform-set/i", $names_line)) or (preg_match("/crypto ipsec ikev1 transform-set/i", $names_line)) )
            {
                # Read the IPSEC CRYPTO PROFILE
                //$my = fopen("vpn.txt","a"); fwrite($my, " $names_line \n"); fclose($my);
                $split = explode(" ", $names_line);
                if( preg_match("/crypto ipsec ikev1 transform-set/i", $names_line) )
                {
                    unset($split[2]);
                    $split_tmp = array_values($split);
                    $split = $split_tmp;
                }

                $cryptoProfiles["$split[3]"] = new IpsecCryptoProfile;
                # Attach Data to the Object
                $cryptoProfiles["$split[3]"]->name = $split[3];
                $next = 5;
                switch ($split[4])
                {
                    case "esp-null":
                        $cryptoProfiles["$split[3]"]->addEncryption("null");
                        break;
                    case "esp-des":
                        add_log2('error', 'Reading IPSEC Crypto Profiles', 'Encryption DES is not supported on Profile [' . $split[3] . ']', $source, 'Automatically changed to 3des. Please update with your peer', '', '', '');
                        $cryptoProfiles["$split[3]"]->addEncryption("3des");
                        break;
                    case "esp-3des":
                        $cryptoProfiles["$split[3]"]->addEncryption("3des");
                        break;
                    case "esp-aes":
                        if( !preg_match("/-/", $split[5]) )
                        {
                            $next = 6;
                            if( $version < 7 )
                            {
                                $tmp = "aes" . $split[5];
                            }
                            else
                            {
                                $tmp = "aes-" . $split[5] . "-cbc";
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [' . $tmp . '] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                            $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                        }
                        else
                        {
                            if( $version < 7 )
                            {
                                $cryptoProfiles["$split[3]"]->addEncryption("aes128");
                            }
                            else
                            {
                                $cryptoProfiles["$split[3]"]->addEncryption("aes-128-cbc");
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                        }
                        break;
                    case "esp-aes-192":
                        if( $version < 7 )
                        {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes192");
                        }
                        else
                        {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes-192-cbc");
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                        }
                        break;
                    case "esp-aes-256":
                        if( $version < 7 )
                        {
                            $cryptoProfiles["$split[3]"]->addEncryption("aes256");
                        }
                        else
                        {
                            add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            $cryptoProfiles["$split[3]"]->addEncryption("aes-256-cbc");
                        }

                        break;
                    case "esp-aes":
                        if( is_int($split[5]) )
                        {
                            if( $version < 7 )
                            {
                                $tmp = "aes" . $split[5];
                                $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                            }
                            else
                            {
                                $tmp = "aes-" . $split[5] . "-cbc";
                                $cryptoProfiles["$split[3]"]->addEncryption($tmp);
                                add_log2('warning', 'Reading IPSEC Crypto Profiles', 'Encryption AES' . $split[5] . ' changed to [' . $tmp . '] on Profile [' . $cryptoProfiles["$split[3]"]->name . ']', $source, 'Please update with your peer', '', '', '');
                            }
                        }
                        break;
                    case "mode":
                        break;
                    default:
                        add_log2('error', 'Reading IPSEC Crypto Profiles', $split[4] . ' Encryption not supported on MT yet', $source, 'Please send an email with the Encryption to fwmigrate at paloaltonetworks.com', '', '', '');
                }

                switch ($split[$next])
                {
                    case "esp-md5-hmac":
                        $cryptoProfiles["$split[3]"]->addAuthentication("md5");
                        break;
                    case "esp-sha-hmac":
                        $cryptoProfiles["$split[3]"]->addAuthentication("sha1");
                        break;
                    case "esp-sha256-hmac":
                        $cryptoProfiles["$split[3]"]->addAuthentication("sha256");
                        break;
                    case "esp-sha384-hmac":
                        $cryptoProfiles["$split[3]"]->addAuthentication("sha384");
                        break;
                    case "esp-sha512-hmac":
                        $cryptoProfiles["$split[3]"]->addAuthentication("sha512");
                        break;
                    case "esp-none":
                        $cryptoProfiles["$split[3]"]->addAuthentication("none");
                        break;
                }
            }

            if( preg_match("/crypto ipsec security-association lifetime seconds /", $names_line) )
            {
                $split = explode(" ", $names_line);
                $this->convertLifeTime($split[5], 1, $time_value, $time);
                foreach( $cryptoProfiles as $key => $cryptoProfilesObj )
                {
                    $cryptoProfilesObj->addLifeTime($time, $time_value);
                }
            }

            if( preg_match("/crypto ipsec security-association lifetime kilobytes /", $names_line) )
            {
                $split = explode(" ", $names_line);
                $this->convertLifeSize($split[5], 1, $size_value, $size);
                foreach( $cryptoProfiles as $key => $cryptoProfilesObj )
                {
                    $cryptoProfilesObj->addLifeSize($size, $size_value);
                }
            }

            if( preg_match("/crypto map /", $names_line) )
            {
                //$cryptoMapPriority = $split[3];
                //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "$names_line\n"); fclose($my);

                $split = explode(" ", $names_line);

                if( ($split[4] == "match") and ($split[5] == "address") )
                {
                    $cryptoMapPriority = $split[3];
                    //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "   $cryptoMapPriority\n"); fclose($my);
                    $cryptoMapName = $split[2] . "-" . $cryptoMapPriority;
                    $accesslist = $split[6];
                    $tunnelName = "tunnel." . $tunnelID;
                    $tunnelInterfaces[] = $tunnelName;
                    $projectdb->query("INSERT INTO interfaces (name,template,source,vsys,unitname,zone,media,vr_id) VALUES ('tunnel','$template','$source','$vsys','$tunnelName','$cryptoMapName','tunnel','$vr_id');");
                    $projectdb->query("INSERT INTO zones (source,template,vsys,name,interfaces,type) VALUES ('$source','$template','$vsys','$cryptoMapName','$tunnelName','layer3');");

                    # UPDATE VR_ID with Interface
                    //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "ipsecTunnels inserting $cryptoMapPriority\n"); fclose($my);
                    $ipsecTunnels["$cryptoMapPriority"] = new IpsecTunnel($cryptoMapName, $cryptoMapPriority, $accesslist, $tunnelName);
                    $tunnelID++;
                }
                elseif( isset($ipsecTunnels["$cryptoMapPriority"]) )
                {
                    if( ($split[4] == "set") and ($split[5] == "peer") )
                    {
                        if( $this->ip_version($split[6]) == "noip" )
                        {
                            $getIP = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext ='$split[6]' LIMIT 1;");
                            if( $getIP->num_rows == 1 )
                            {
                                $getIPData = $getIP->fetch_assoc();
                                $split[6] = $getIPData['ipaddress'];
                            }
                        }
                        //$cryptoMapPriority = $split[3];
                        //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "   $cryptoMapPriority\n"); fclose($my);
                        //Todo: SVEN Waschkut - cryptMapPriority is not uniq
                        $ipsecTunnels["$cryptoMapPriority"]->addPeer($split[6]);
                        $ikeGateways["$cryptoMapPriority"] = new IkeGateway($cryptoMapName, $split[6]);
                    }
                    elseif( ($split[4] == "set") and ($split[5] == "transform-set") )
                    {
                        $transformSet = clone $cryptoProfiles["$split[6]"];
                        #$transformSet->name = $transformSet->name . "-" . $cryptoMapPriority;
                        $transformSet->name = "cloned-" . $cryptoMapPriority;
                        $ipsecTunnels["$cryptoMapPriority"]->addTransformSet($transformSet);
                    }
                    elseif( ($split[4] == "set") and (isset($split[6]) && $split[6] == "transform-set") )
                    {
                        $transformSet = clone $cryptoProfiles["$split[7]"];
                        #$transformSet->name = $transformSet->name . "-" . $cryptoMapPriority;
                        $transformSet->name = "cloned-" . $cryptoMapPriority;
                        $ipsecTunnels["$cryptoMapPriority"]->addTransformSet($transformSet);
                    }
                    elseif( ($split[4] == "set") and (($split[5] == "ikev2")) and (($split[6] == "ipsec-proposal")) )
                    {
                        if( $ipsecTunnels["$cryptoMapPriority"]->transformSet )
                        {
                            add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found but ikev1 was seen before: ' . $names_line, $source, 'The tool is not attaching the ikev2 proposal to the Tunnel ' . $ipsecTunnels["$cryptoMapPriority"]->name, '', '', '');
                        }
                        else
                        {
                            $transformSet = clone $cryptoProfiles["$split[7]"];
                            #$transformSet->name = $transformSet->name . "-" . $cryptoMapPriority;
                            $transformSet->name = "cloned-" . $cryptoMapPriority;
                            $ipsecTunnels["$cryptoMapPriority"]->addTransformSet($transformSet);
                            add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found with more than one:' . $names_line, $source, 'Just Attaching the First One. You can create a new Profile combining all the options from all the Proposals', '', '', '');
                        }
                        add_log2('error', 'Reading IPSEC-Tunnel', 'Ikev2 Proposal found with more than one:' . $names_line, $source, 'Just Attaching the First One. You can create a new Profile combining all the options from all the Proposals', '', '', '');
                    }
                    elseif( ($split[4] == "set") and ($split[5] == "security-association") and ($split[6] == "lifetime") and ($split[7] == "seconds") )
                    {
                        $ipsecTunnels["$cryptoMapPriority"]->addLifetimeSeconds($split[8]);
                        $this->convertLifeTime($split[8], 1, $time_value, $time);
                        if( isset($transformSet) )
                        {
                            $transformSet->addLifeTime($time, $time_value);
                        }
                    }
                    elseif( ($split[4] == "set") and ($split[5] == "security-association") and ($split[6] == "lifetime") and ($split[7] == "kilobytes") )
                    {
                        if( $split[8] != "unlimited" )
                        {
                            $ipsecTunnels["$cryptoMapPriority"]->addLifetime_kilobytes($split[8]);
                            $this->convertLifeSize($split[8], 1, $size_value, $size);
                            if( isset($transformSet) )
                            {
                                $transformSet->addLifeSize($size, $size_value);
                            }
                        }
                        else
                        {
                            if( isset($transformSet) )
                            {
                                $transformSet->addLifeSize('65535', 'tb');
                            }
                        }
                    }
                    elseif( ($split[4] == "set") and ($split[5] == "pfs") )
                    {
                        if( isset($split[6]) )
                        {
                            $pfs = $split[6];
                        }
                        else
                        {
                            $pfs = "group2";
                        }
                        if( ($pfs != "group21") and ($pfs != "group24") )
                        {
                            if( isset($transformSet) )
                            {
                                $transformSet->addDHgroup($pfs);
                            }
                        }
                        else
                        {
                            add_log2('error', 'Reading IKE-Crypto Profiles', 'The PFS group ' . $pfs . ' is not supported yet.', $source, 'Group20 has been assigned instead on Profile[' . $transformSet->name . ']', '', '', '');
                            $pfs = "group20";
                            if( isset($transformSet) )
                            {
                                $transformSet->addDHgroup($pfs);
                            }
                        }
                    }
                    elseif( $split[3] == "interface" )
                    {
                        $interface_tmp = $split[4];
                        $getINT = $projectdb->query("SELECT unitname,unitipaddress FROM interfaces WHERE zone='$interface_tmp' AND template='$template' LIMIT 1;");
                        if( $getINT->num_rows == 1 )
                        {
                            $getINTData = $getINT->fetch_assoc();
                            foreach( $ikeGateways as $key => $ikeGWObj )
                            {
                                $ikeGWObj->addInterface($getINTData['unitname']);
                                $ikeGWObj->addInterfaceIP($getINTData['unitipaddress']);
                            }
                        }
                    }
                    elseif( ($split[4] == "set") and ($split[5] == "phase1-mode") and ($split[6] == "aggressive") )
                    {
                        $ikeGateways["$cryptoMapPriority"]->exchange_mode_ikev1 = "aggressive";
                    }
                    elseif( ($split[4] == "set") and ($split[5] == "phase1-mode") and ($split[6] == "main") )
                    {
                        $ikeGateways["$cryptoMapPriority"]->exchange_mode_ikev1 = "main";
                    }
                    elseif( ($split[4] == "set") and ($split[5] == "nat-t-disable") )
                    {
                        $ikeGateways["$cryptoMapPriority"]->nat_traversal = "no";
                    }
                }
            }

            if( preg_match("/no crypto isakmp nat-traversal/", $names_line) )
            {
                #Disable globally the nat-t
                foreach( $ikeGateways as $element )
                {
                    $element->nat_traversal = "no";
                }
            }
            elseif( preg_match("/crypto isakmp nat-traversal/", $names_line) )
            {
                #Disable globally the nat-t
                foreach( $ikeGateways as $element )
                {
                    $element->nat_traversal = "yes";
                }
            }


            if( (preg_match("/no crypto ikev1 am-disable/", $names_line)) or (preg_match("/no crypto isakmp am-disable/", $names_line)) )
            {
                foreach( $ikeGateways as $element )
                {
                    $element->exchange_mode_ikev1 = "aggressive";
                }
            }
            elseif( (preg_match("/crypto ikev1 am-disable/", $names_line)) or (preg_match("/crypto isakmp am-disable/", $names_line)) )
            {
                foreach( $ikeGateways as $element )
                {
                    $element->exchange_mode_ikev1 = "main";
                }
            }

            # Capture PSK
            if( preg_match("/tunnel-group /", $names_line) )
            {
                $split = explode(" ", $names_line);
                if( (($this->ip_version($split[1]) == "v4") or ($this->ip_version($split[1]) == "v6")) and ($split[2] == "ipsec-attributes") )
                {
                    $last_peer_seen = $split[1];
                    $checking_psk = TRUE;
                }
            }

            # Read Pre-Shared-Key for ikev1
            if( ($checking_psk === TRUE) and (preg_match("/ikev1 pre-shared-key/", $names_line)) )
            {
                $split = explode(" ", $names_line);
                $psk = $split[2];
                foreach( $ikeGateways as $key => $ikeGWObj )
                {
                    if( $ikeGWObj->peer_ip_address == $last_peer_seen )
                    {
                        if( $psk != "*****" )
                        {
                            $ikeGWObj->pre_shared_key = $psk;
                        }
                        else
                        {
                            $ikeGWObj->pre_shared_key = "";
                        }
                    }
                }
                $checking_psk = FALSE;
            }
            elseif( ($checking_psk === TRUE) and (preg_match("/pre-shared-key/", $names_line)) )
            {
                $split = explode(" ", $names_line);
                $psk = $split[1];
                foreach( $ikeGateways as $key => $ikeGWObj )
                {
                    if( $ikeGWObj->peer_ip_address == $last_peer_seen )
                    {
                        if( $psk != "*****" )
                        {
                            $ikeGWObj->pre_shared_key = $psk;
                        }
                        else
                        {
                            $ikeGWObj->pre_shared_key = "";
                        }
                    }
                }
                $checking_psk = FALSE;
            }

            # Import the ikev1 Crypto Profiles
            if( (preg_match("/crypto isakmp policy/", $names_line)) or (preg_match("/crypto ikev1 policy/", $names_line)) or (preg_match("/crypto ikev2 policy/", $names_line)) )
            {
                $split = explode(" ", trim($names_line));
                $ikeCryptoProfileName = $split[1] . "-" . $split[3];
                $isIkev1Profile = TRUE;
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/authentication /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                if( preg_match("/pre-share/", $names_line) )
                {
                    $IkeCryptoProfiles[$ikeCryptoProfileName] = new IkeCryptoProfile($ikeCryptoProfileName);
                }
                else
                {
                    $isIkev1Profile = FALSE;
                    add_log2('error', 'Reading IKE-Crypto Profiles', 'Only Pre-Shared key Profiles are supported', $source, 'Ignoring ' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name, '', '', '');
                }
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/encryption /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                if( !isset($IkeCryptoProfiles[$ikeCryptoProfileName]) )
                {
                    $IkeCryptoProfiles[$ikeCryptoProfileName] = new IkeCryptoProfile($ikeCryptoProfileName);
                }
                switch ($split[1])
                {
                    case "des":
                        add_log2('error', 'Reading IKE Crypto Profiles', 'Encryption DES is not supported on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Automatically changed to 3des. Please update with your peer', '', '', '');
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("3des");
                        break;
                    case "3des":
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("3des");
                        break;
                    case "aes":
                        if( $version < 7 )
                        {
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes128");
                        }
                        else
                        {
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-128-cbc");
                            add_log2('warning', 'Reading IKE Crypto Profiles', 'Encryption AES changed to [aes-128-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Please update with your peer', '', '', '');
                        }
                        break;
                    case "aes-192":
                        if( $version < 7 )
                        {
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes192");
                        }
                        else
                        {
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-192-cbc");
                            add_log2('warning', 'Reading IKE Crypto Profiles', 'Encryption AES192 changed to [aes-192-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Please update with your peer', '', '', '');
                        }
                        break;
                    case "aes-256":
                        if( $version < 7 )
                        {
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes256");
                        }
                        else
                        {
                            add_log2('warning', 'Reading IKE Crypto Profiles', 'Encryption AES256 changed to [aes-256-cbc] on Profile [' . $IkeCryptoProfiles[$ikeCryptoProfileName]->name . ']', $source, 'Please update with your peer', '', '', '');
                            $IkeCryptoProfiles[$ikeCryptoProfileName]->addEncryption("aes-256-cbc");
                        }

                        break;
                    default:
                        add_log2('error', 'Reading IKE Crypto Profiles', $split[4] . ' Encryption not supported on MT yet', $source, 'Please send an email with the Encryption to fwmigrate at paloaltonetworks.com', '', '', '');
                }
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/hash /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $kkey => $vvalue )
                {
                    if( ($vvalue != "") and ($vvalue != null) )
                    {
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addHash($vvalue);
                    }
                }
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/integrity /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $kkey => $vvalue )
                {
                    if( $vvalue != "" )
                    {
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addHash($vvalue);
                    }
                }
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/group /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                unset($split[0]);
                $split_tmp = array_values($split);
                $split = $split_tmp;
                foreach( $split as $kkey => $vvalue )
                {
                    if( $vvalue != "" )
                    {
                        $groupname = "group" . $vvalue;
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->addDHgroup($groupname);
                    }
                }
            }

            if( ($isIkev1Profile === TRUE) and (preg_match("/lifetime /", $names_line)) )
            {
                $split = explode(" ", $names_line);
                if( is_int($split[1]) )
                {
                    $this->convertLifeTime($split[1], 1, $time_value, $time);
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeType = $time_value;
                    $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeValue = $time;
                }
                else
                {
                    if( $split[1] == "seconds" )
                    {
                        $this->convertLifeTime($split[1], 1, $time_value, $time);
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeType = $time_value;
                        $IkeCryptoProfiles[$ikeCryptoProfileName]->keyLifeTimeValue = $time;
                    }
                }
                $isIkev1Profile = FALSE;
            }
        }

        # OUTPUT
        # IKE Crypto Profile
        if( count($IkeCryptoProfiles) > 0 )
        {
            $allsql = [];
            foreach( $IkeCryptoProfiles as $key => $object )
            {
                $sql_tmp = $object->getSQL($source, $template, $vsys);
                $allsql[] = $sql_tmp;
            }
            if( count($allsql) > 0 )
            {
                $projectdb->query("INSERT INTO ike_crypto_profiles (name,vsys,source,template,encryption,hash,dh_group,seconds,minutes,hours,days) VALUES " . implode(",", $allsql) . ";");
            }
        }

        # Attach Tunnel Interfaces to the VR
        if( ($vr_id != "") and (count($tunnelInterfaces) > 0) )
        {
            $getInt = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$vr_id';");
            if( $getInt->num_rows == 1 )
            {
                $getIntData = $getInt->fetch_assoc();
                $vr_interfaces = $getIntData['interfaces'] . "," . implode(",", $tunnelInterfaces);
                $projectdb->query("UPDATE virtual_routers SET interfaces='$vr_interfaces' WHERE id='$vr_id';");
            }
        }

        #IKE GWS
        if( count($ikeGateways) > 0 )
        {
            $allsql = [];
            foreach( $ikeGateways as $key => $object )
            {
                $sql_tmp = $object->getSQL($source, $template, $vsys);
                $allsql[] = $sql_tmp;
            }

            if( count($allsql) > 0 )
            {
                $projectdb->query("INSERT INTO ike_gateways_profiles (address_type,name,vsys,source,template,version,dpd_ikev1,ike_interval_ikev1,retry_ikev1,ike_crypto_profile_ikev1,exchange_mode_ikev1,dpd_ikev2,ike_interval_ikev2,ike_crypto_profile_ikev2,require_cookie_ikev2,local_address_ip,interface,type_authentication,pre_shared_key,allow_id_payload_mismatch,strict_validation_revocation,nat_traversal,passive_mode,fragmentation,peer_ip_type,peer_ip_address) VALUES " . implode(",", $allsql) . ";");
            }
            add_log2('info', 'Reading IKE Gateways', 'Please attach the proper IKEv1 / IKEv2 Profiles to your IKE Gateways', $source, 'You can use the Attach buttons from IKE Gateways View', '', '', '');
        }

        #IPSEC tunnel
        if( count($ipsecTunnels) > 0 )
        {
            # Check for VPN-l2l TAG. Create it and add it to all the Rules related to VPNs
            $getTAG = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='VPN-l2l' LIMIT 1;");
            if( $getTAG->num_rows == 1 )
            {
                $getTAGData = $getTAG->fetch_assoc();
                $tag_id = $getTAGData['id'];
                $tag_table = "tag";
            }
            else
            {
                $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('VPN-l2l','$source','$vsys','color1');");
                $tag_id = $projectdb->insert_id;
                $tag_table = "tag";
            }
            $allsql = [];
            //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "Number of ipsecTunnels: ".count($ipsecTunnels)."\n"); fclose($my);
            foreach( $ipsecTunnels as $key => $object )
            {
                //$my = fopen("ciscoipsec.txt","a"); fwrite($my, "    $key, $object->name\n"); fclose($my);
                $sql_tmp = $object->getSQL($source, $template, $vsys);
                $allsql[] = $sql_tmp;
                if( isset($object->transformSet) )
                {
                    $test[] = $object->transformSet->getHash();
                }
                else
                {
                    add_log2('warning', 'IPSEC Tunnel', 'The transform set has not been found', $source, 'Please create a new IPSEC Crypto Profile and attach to ' . $object->name, '', '', '');

                }

            }
            # Write the IPSEC Tunnels to the DB
            if( count($allsql) > 0 )
            {
                $projectdb->query("INSERT INTO ipsec_tunnel (name,vsys,source,template,tunnel_interface,address_type,type_tunnel,ike_gateway,ipsec_crypto_profile) VALUES " . implode(",", $allsql) . ";");
            }

            # Reduce Crypto Ipsec Profiles
            $unique = array_unique($test);
            foreach( $unique as $key => $value )
            {
                $x = 0;
                foreach( $ipsecTunnels as $kkey => $object )
                {
                    if( (isset($object->transformSet)) and ($object->transformSet->getHash() == $value) )
                    {
                        $x++;
                        if( $x == 1 )
                        {
                            # Get Name
                            $replace = $object->transformSet->name;
                            # Store the CRypto Ipsec Profile
                            $encryption = implode(",", $object->transformSet->encryption);
                            $authentication = implode(",", $object->transformSet->authentication);
                            $dhgroup = $object->transformSet->dhgroup;
                            $protocol = strtoupper($object->transformSet->ipsecProtocol);
                            $keyLifeTimeValue = $object->transformSet->keyLifeTimeValue;
                            $keyLifeTimeType = $object->transformSet->keyLifeTimeType;
                            $lifeSizeValue = $object->transformSet->lifeSizeValue;
                            $lifeSizeType = $object->transformSet->lifeSizeType;

                            if( $keyLifeTimeValue == "" )
                            {
                                $keyLifeTimeValue = "seconds";
                            }
                            if( $lifeSizeValue == "" )
                            {
                                $lifeSizeValue = "kb";
                            }

                            $sql = "('$replace','$vsys','$source','$template','$encryption','$authentication','$dhgroup','$protocol','$keyLifeTimeType','$lifeSizeType')";
                            $projectdb->query("INSERT INTO ipsec_crypto_profiles (name,vsys,source,template,encryption,hash,dh_group,protocol,$keyLifeTimeValue,$lifeSizeValue) VALUES " . $sql . ";");

                        }
                        else
                        {
                            $original = $object->transformSet->name;
                            $projectdb->query("UPDATE ipsec_tunnel SET ipsec_crypto_profile='$replace' WHERE template='$template' AND source='$source' AND BINARY ipsec_crypto_profile='$original';");
                        }
                    }
                    else
                    {
                        add_log2('warning', 'IPSEC Tunnel', 'The transform set has not been found', $source, 'Please create a new IPSEC Crypto Profile and attach to ' . $object->name, '', '', '');

                    }
                }
            }

            # Create the ProxyIDs to the IPSEC Tunnel.
            foreach( $ipsecTunnels as $key => $object )
            {
                # Accesslist
                $yy = 1;
                $accesslist = $object->accesslist;
                if( $accesslist != "" )
                {
                    $tunnelInterface = $object->tunnelInterface;
                    $ipsecTunnelName = $object->name;
                    # Calculate Tunnel ID
                    $getTunnelID = $projectdb->query("SELECT id FROM ipsec_tunnel WHERE source='$source' AND template='$template' AND BINARY name='$ipsecTunnelName';");
                    if( $getTunnelID->num_rows == 1 )
                    {
                        $getTunnelDataData = $getTunnelID->fetch_assoc();
                        $ipsecTunnelID = $getTunnelDataData['id'];

                        # Search The Rules by TAG = access-list
                        $getTAG = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='$accesslist';");
                        if( $getTAG->num_rows == 1 )
                        {
                            $getTAGData = $getTAG->fetch_assoc();
                            $tmp_id = $getTAGData['id'];
                            # Read Rules by TAG
                            $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_tag WHERE member_lid='$tmp_id' AND table_name='tag' ;");
                            if( $getRules->num_rows > 0 )
                            {
                                $rulesByAccesslist = [];
                                while( $getRulesData = $getRules->fetch_assoc() )
                                {
                                    $tmp_rule_lid = $getRulesData['rule_lid'];
                                    $rulesByAccesslist[] = $tmp_rule_lid;
                                    $projectdb->query("INSERT INTO security_rules_tag (source,vsys,member_lid,table_name,rule_lid) VALUES ('$source','$vsys','$tag_id','$tag_table','$tmp_rule_lid');");
                                }
                                if( count($rulesByAccesslist) > 0 )
                                {
                                    $xx = 1;

                                    foreach( $rulesByAccesslist as $rule_lid )
                                    {
                                        $srcbyrule = [];
                                        $dstbyrule = [];
                                        $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE rule_lid='$rule_lid' ;");
                                        if( $getZone->num_rows == 1 )
                                        {
                                            $getZoneData = $getZone->fetch_assoc();
                                            $getZoneID = $getZoneData['id'];
                                            $projectdb->query("UPDATE security_rules_to SET name='$ipsecTunnelName' WHERE id='$getZoneID';");
                                        }
                                        elseif( $getZone->num_rows == 0 )
                                        {
                                            $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES ('$source','$vsys','$ipsecTunnelName','$rule_lid');");
                                        }
                                        $getSRC = $projectdb->query("SELECT member_lid,table_name FROM security_rules_src WHERE rule_lid='$rule_lid';");
                                        if( $getSRC->num_rows > 0 )
                                        {
                                            while( $getSRCData = $getSRC->fetch_assoc() )
                                            {
                                                $srcbyrule[] = array($getSRCData['member_lid'], $getSRCData['table_name']);
                                            }
                                        }
                                        $getDST = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$rule_lid';");
                                        if( $getDST->num_rows > 0 )
                                        {
                                            while( $getDSTData = $getDST->fetch_assoc() )
                                            {
                                                $dstbyrule[] = array($getDSTData['member_lid'], $getDSTData['table_name']);
                                            }
                                        }
                                        #convert to memberObj
                                        $getAllSRCObj = [];
                                        $srcbyrule = array_map("unserialize", array_unique(array_map("serialize", $srcbyrule)));
                                        foreach( $srcbyrule as $key => $srcs )
                                        {
                                            $getAllSRCObj[] = new MemberObject($srcs[0], $srcs[1]);
                                        }

                                        $getAllSRC = explodeGroups2Members($getAllSRCObj, $projectdb, $source, $vsys, 0);
                                        #$dstbyrule = array_unique($dstbyrule);
                                        #convert to memberObj
                                        $getAllDSTObj = [];
                                        $dstbyrule = array_map("unserialize", array_unique(array_map("serialize", $dstbyrule)));
                                        foreach( $dstbyrule as $key => $dsts )
                                        {
                                            $getAllDSTObj[] = new MemberObject($dsts[0], $dsts[1]);
                                        }

                                        $getAllDST = explodeGroups2Members($getAllDSTObj, $projectdb, $source, $vsys, 0);


                                        foreach( $getAllSRC as $mySrcObj )
                                        {
                                            $mySrc = $mySrcObj->value . "/" . $mySrcObj->cidr;
                                            $type = $this->ip_version($mySrcObj->value);
                                            if( $type == "noip" )
                                            {
                                                $type = "v4";
                                            }
                                            $protocol = "Any";
                                            foreach( $getAllDST as $myDstObj )
                                            {
                                                $myDst = $myDstObj->value . "/" . $myDstObj->cidr;
                                                $proxyIDName = "ProxyID" . $xx;
                                                $xx++;
                                                $projectdb->query("INSERT INTO proxy_id_ipsec_tunnel (name,vsys,source,template,ipsec_tunnel_id,protocol,local,remote,type) VALUES ('$proxyIDName','$vsys','$source','$template','$ipsecTunnelID','$protocol','$mySrc','$myDst','$type');");
                                                # Check the Static Routes
                                                $getRoute = $projectdb->query("SELECT id,nexthop_value,nexthop,tointerface FROM routes_static WHERE vr_id='$vr_id' AND template='$template' AND source='$source' AND destination='$myDst';");
                                                if( $getRoute->num_rows == 0 )
                                                {
                                                    $routeName = $ipsecTunnelName . $yy;
                                                    $yy++;
                                                    $projectdb->query("INSERT INTO routes_static (vr_id,$this->ip_version,source,template,name,destination,tointerface,nexthop) VALUES ('$vr_id','$type','$source','$template','$routeName','$myDst','$tunnelInterface','None');");
                                                }
                                                elseif( $getRoute->num_rows == 1 )
                                                {
                                                    $getRouteData = $getRoute->fetch_assoc();
                                                    $routeID = $getRouteData['id'];
                                                    $routeNH = $getRouteData['nexthop_value'];
                                                    $projectdb->query("UPDATE routes_static SET nexthop_value='None', nexthop='None', tointerface='$tunnelInterface' WHERE id='$routeID';");
                                                }
                                                else
                                                {
                                                    add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'Too many static routes for the destination [' . $myDst . ']', $source, 'Fix the routes to point to interface [' . $tunnelInterface . ']', '', '', '');
                                                }
                                            }
                                        }

                                    }

                                }
                                else
                                {
                                    add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No Rules found by TAG [' . $accesslist . '] related to IPSEC Tunnel [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                                }
                            }
                            else
                            {
                                add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No Rules found by TAG [' . $accesslist . '] related to IPSEC Tunnel [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                            }
                        }
                        else
                        {
                            add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No Rules found by TAG [' . $accesslist . '] related to IPSEC Tunnel [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                        }
                    }
                    else
                    {
                        add_log2('error', 'Reading IPSEC Tunnel ProxyIDs', 'No tunnel id found in the DB for Tunnel name [' . $ipsecTunnelName . ']', $source, 'Add PROXYIDs by hand', '', '', '');
                    }
                }
            }
        }

        // Check if name start with Num in IPSec Tunnels, IPSec Crypto, IKE Crypto and IKE Gateways
        // IKE Crypto Profiles
        $getIKECryptoProfiles = $projectdb->query("SELECT id, name, template, source FROM ike_crypto_profiles;");
        if( $getIKECryptoProfiles->num_rows > 0 )
        {
            while( $this->dataICP = $getIKECryptoProfiles->fetch_assoc() )
            {
                $id_ike_c_p = $this->dataICP['id'];
                $name_ike_c_p = $this->dataICP['name'];
                $template_ike_c_p = $this->dataICP['template'];
                $source_ike_c_p = $this->dataICP['source'];

                if( checkNamesStartNum($name_ike_c_p) == TRUE )
                {
                    $name_ike_c_p_new = addPrefixSuffix("on", "p", "", "", $name_ike_c_p, 31);
                    $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev1 = '$name_ike_c_p_new' WHERE source = '$source_ike_c_p' AND template = '$template_ike_c_p' AND ike_crypto_profile_ikev1 = '$name_ike_c_p' ;");
                    $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev2 = '$name_ike_c_p_new' WHERE source = '$source_ike_c_p' AND template = '$template_ike_c_p' AND ike_crypto_profile_ikev2 = '$name_ike_c_p' ;");
                    $projectdb->query("UPDATE ike_crypto_profiles SET name = '$name_ike_c_p_new' WHERE id = '$id_ike_c_p';");
                }
            }
        }

        // IPSec Crypto Profiles
        $getIPSecCryptoProfiles = $projectdb->query("SELECT id, name, template, source FROM ipsec_crypto_profiles;");
        if( $getIPSecCryptoProfiles->num_rows > 0 )
        {
            while( $this->dataICP = $getIPSecCryptoProfiles->fetch_assoc() )
            {
                $id_ipsec_c_p = $this->dataICP['id'];
                $name_ipsec_c_p = $this->dataICP['name'];
                $template_ipsec_c_p = $this->dataICP['template'];
                $source_ipsec_c_p = $this->dataICP['source'];

                if( checkNamesStartNum($name_ipsec_c_p) == TRUE )
                {
                    $name_ipsec_c_p_new = addPrefixSuffix("on", "p", "", "", $name_ipsec_c_p, 31);
                    $projectdb->query("UPDATE ipsec_tunnel SET ipsec_crypto_profile = '$name_ipsec_c_p_new' WHERE source = '$source_ipsec_c_p' AND template = '$template_ipsec_c_p' AND ipsec_crypto_profile = '$name_ipsec_c_p' ;");
                    $projectdb->query("UPDATE ipsec_crypto_profiles SET name = '$name_ipsec_c_p_new' WHERE id = '$id_ipsec_c_p';");
                }
            }
        }

        // IKE Gateways Profiles
        $getIKEGatewaysProfiles = $projectdb->query("SELECT id, name, template, source FROM ike_gateways_profiles;");
        if( $getIKEGatewaysProfiles->num_rows > 0 )
        {
            while( $this->dataIGP = $getIKEGatewaysProfiles->fetch_assoc() )
            {
                $id_ike_g_p = $this->dataIGP['id'];
                $name_ike_g_p = $this->dataIGP['name'];
                $template_ike_g_p = $this->dataIGP['template'];
                $source_ike_g_p = $this->dataIGP['source'];

                if( checkNamesStartNum($name_ike_g_p) == TRUE )
                {
                    $name_ike_g_p_new = addPrefixSuffix("on", "p", "", "", $name_ike_g_p, 31);
                    $projectdb->query("UPDATE ipsec_tunnel SET ike_gateway = '$name_ike_g_p_new' WHERE source = '$source_ike_g_p' AND template = '$template_ike_g_p' AND ike_gateway = '$name_ike_g_p' ;");
                    $projectdb->query("UPDATE ike_gateways_profiles SET name = '$name_ike_g_p_new' WHERE id = '$id_ike_g_p';");
                }
            }
        }

        // IPSec Tunnels
        $getIPSecTunnels = $projectdb->query("SELECT id, name, template, source FROM ipsec_tunnel;");
        if( $getIPSecTunnels->num_rows > 0 )
        {
            while( $this->dataIT = $getIPSecTunnels->fetch_assoc() )
            {
                $id_ipsec_t = $this->dataIT['id'];
                $name_ipsec_t = $this->dataIT['name'];
                $template_ipsec_t = $this->dataIT['template'];
                $source_ipsec_t = $this->dataIT['source'];

                if( checkNamesStartNum($name_ipsec_t) == TRUE )
                {
                    $name_ipsec_t_new = addPrefixSuffix("on", "p", "", "", $name_ipsec_t, 31);
                    $projectdb->query("UPDATE ipsec_tunnel SET name = '$name_ipsec_t_new' WHERE id = '$id_ipsec_t';");
                }
            }
        }

    }
}

