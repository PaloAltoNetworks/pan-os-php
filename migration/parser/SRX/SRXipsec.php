<?php


trait SRXipsec
{
    public $tmp_P2_config_proposals = array();
    public $tmp_P2_policy = array();

    function get_XML_IPSEC($configRoot, $shared)
    {
        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            #print $nodeName."\n";

            if( $nodeName == "proposal" )
            {
                $this->get_IPSEC_proposal($childNode, $shared);
            }
            elseif( $nodeName == "policy" )
            {
                $this->get_IPSEC_policy($childNode, $shared);
            }
            elseif( $nodeName == "vpn" )
            {
                $this->get_IPSEC_vpn($childNode, $shared);
            }
            else
            {
                mwarning("IKE child nodeName: " . $nodeName . " not supported");
            }


        }
    }

    function get_IPSEC_proposal($configRoot, $shared)
    {
        global $print;
        global $debug;
        global $tmp_P2_config_proposals;


        #print "\nPROPOSAL\n";
        #$this->printXML( $configRoot );

        $tmp_array = array();

        /*
        proposal proposal-name {
            authentication-algorithm (hmac-md5-96 | hmac-sha-256-128 | hmac-sha-256-96 | hmac-sha-384 | hmac-sha-512 | hmac-sha1-96);
            description description;
            encryption-algorithm (3des-cbc | aes-128-cbc | aes-128-gcm | aes-192-cbc | aes-192-gcm | aes-256-cbc | aes-256-gcm | des-cbc);
            extended-sequence-number;
            lifetime-kilobytes kilobytes;
            lifetime-seconds seconds;
            protocol (ah | esp);
        }
         */
        $proposal_name = "";
        $protocol = 'esp';
        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;

            if( $nodeName == 'name' )
            {
                $proposal_name = $nodeValue;
                $tmp_P2_config_proposals[$proposal_name] = $this->template->network->ipsecCryptoProfileStore->newIPsecCryptoProfil($nodeValue);
                if( $print )
                    print "create IPSEC crypto proposal: " . $proposal_name . "\n";
            }
            elseif( $nodeName == 'protocol' )
            {
                $protocol = $nodeValue;
            }
            elseif( $nodeName == 'authentication-algorithm' )
            {
                #$tmp_P2_config_proposals[$proposal_name]->setDHgroup($nodeValue);

                if( strpos($nodeValue, 'sha1-') !== FALSE )
                    $nodeValue = 'sha1';
                elseif( strpos($nodeValue, 'sha-256') !== FALSE )
                    $nodeValue = 'sha256';
                elseif( strpos($nodeValue, 'sha-384') !== FALSE )
                    $nodeValue = 'sha384';
                elseif( strpos($nodeValue, 'sha-512') !== FALSE )
                    $nodeValue = 'sha512';
                elseif( strpos($nodeValue, 'md5') !== FALSE )
                    $nodeValue = 'md5';
                $tmp_P2_config_proposals[$proposal_name]->setauthentication($nodeValue, $protocol);
            }
            elseif( $nodeName == "encryption-algorithm" )
            {
                /*
                if( strpos( $nodeValue, 'aes128') !== FALSE )
                    $nodeValue = 'aes-128-cbc';
                elseif( strpos( $nodeValue, 'aes256') !== FALSE )
                    $nodeValue = 'aes-256-cbc';
                else
                    */
                if( strpos($nodeValue, '3des') !== FALSE )
                    $nodeValue = '3des';
                elseif( strpos($nodeValue, 'des') !== FALSE )
                    $nodeValue = 'des';
                elseif( strpos($nodeValue, 'aes-192-gcm') !== FALSE )
                    $nodeValue = 'aes-256-gcm';

                $tmp_P2_config_proposals[$proposal_name]->setencryption($nodeValue);
            }
            elseif( $nodeName == 'lifetime-seconds' )
            {
                //86400 as seconds not available within PAN-OS ; 86400 is 24h
                if( intval($nodeValue) == 86400 )
                {
                    $lifetimetype = 'days';
                    $nodeValue = '1';
                }
                elseif( intval($nodeValue) > 65535 )
                {
                    #derr( "lifetime is greater then 65535 - validation needed" );
                    if( $debug )
                        mwarning("lifetime is greater then 65535 - validation needed", null, FALSE);
                    $lifetimetype = "seconds";
                }
                else
                    $lifetimetype = "seconds";
                $tmp_P2_config_proposals[$proposal_name]->setlifetime($lifetimetype, $nodeValue);
            }
            elseif( $nodeName == 'lifetime-kilobytes' )
            {
                $lifetimetype = "kb";

                $tmp_P2_config_proposals[$proposal_name]->setlifesize($lifetimetype, $nodeValue);
            }
            elseif( $nodeName == 'description' )
            {

            }
            else
            {
                mwarning("IPSEC nodeName " . $nodeName . " not supported");
            }

        }


        /*
name - STXNEXT-IKEv2-PROPOSAL
description - STXNEXT TO HOGARTH IPSEC PROPOSAL
protocol - esp
authentication-algorithm - hmac-sha-256-128
encryption-algorithm - aes-256-cbc
lifetime-seconds - 14400
         */

    }

    function get_IPSEC_policy($configRoot, $shared)
    {
        global $tmp_P2_policy;

        /*
        <policy>
            <name>Hogarth-Standard</name>
            <perfect-forward-secrecy>
                <keys>group2</keys>
            </perfect-forward-secrecy>
            <proposals>Hogarth-Standard-Phase-2</proposals>
        </policy>
         */
        #print "\nPOLICY\n";
        #$this->printXML( $configRoot );



        #print "\nPROPOSAL\n";
        #$this->printXML( $configRoot );

        $tmp_P2_policy_name = "";
        $tmp_P2_keys = array();

        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;

            if( $nodeName == 'name' )
            {
                $tmp_P2_policy_name = $nodeValue;
            }
            elseif( $nodeName == 'perfect-forward-secrecy' )
            {
                foreach( $node->childNodes as $nodeKEY )
                {
                    $nodeName2 = $nodeKEY->nodeName;
                    $nodeValue2 = $nodeKEY->nodeValue;

                    if( $nodeName2 == "keys" )
                        $tmp_P2_keys[$nodeValue2] = $nodeValue2;
                }
            }
            elseif( $nodeName == 'proposals' )
            {
                $tmp_P2_policy[$tmp_P2_policy_name] = $nodeValue;
                $proposal = $this->template->network->ipsecCryptoProfileStore->findIpsecCryptoProfil($nodeValue);

                foreach( $tmp_P2_keys as $keys )
                    $proposal->setDHgroup($keys);
            }
        }

        $tmp_P2_vpn_name = null;
        $tmp_P2_keys = null;
    }

    function get_IPSEC_vpn($configRoot, $shared)
    {
        global $tmp_P2_policy;

        #print "\nVPN\n";
        #$this->printXML( $configRoot );

        /*
        <vpn>
            <name>IBM-IDAM-VPN</name>
            <bind-interface>st0.75</bind-interface>
            <ike>
                <gateway>IBM-IDAM-GATEWAY</gateway>
                <ipsec-policy>IBM-IDAM-POLICY-PHASE-2</ipsec-policy>
            </ike>
            <traffic-selector>
                <name>t1</name>
                <local-ip>10.252.32.0/24</local-ip>
                <remote-ip>159.8.143.78/32</remote-ip>
            </traffic-selector>
            <traffic-selector>
                <name>t2</name>
                <local-ip>10.252.32.0/24</local-ip>
                <remote-ip>159.8.143.87/32</remote-ip>
            </traffic-selector>
            <traffic-selector>
                <name>t3</name>
                <local-ip>10.252.32.0/24</local-ip>
                <remote-ip>159.8.175.56/32</remote-ip>
            </traffic-selector>
            <traffic-selector>
                <name>t4</name>
                <local-ip>10.252.32.0/24</local-ip>
                <remote-ip>159.8.175.59/32</remote-ip>
            </traffic-selector>
        </vpn>
         */



        #print "\nPROPOSAL\n";
        #$this->printXML( $configRoot );

        $tmp_P2_vpn_name = "";
        $tmp_P2_keys = array();
        $tmp_newIPsecTunnel = array();

        $inactive = DH::findAttribute('inactive', $configRoot);

        //<vpn inactive="inactive">

        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;

            if( $nodeName == 'name' )
            {
                $tmp_P2_vpn_name = $nodeValue;
                print "\ncreate P2 tunnel config: " . $tmp_P2_vpn_name . "\n";

                #$VPN_name = $this->IKE_IPSEC_name_validation($VPN_name, "IPSEC");
                $tmp_newIPsecTunnel[$tmp_P2_vpn_name] = $this->template->network->ipsecTunnelStore->newIPsecTunnel($tmp_P2_vpn_name);


                if( $inactive != null && $inactive == "inactive" )
                {
                    print "set to INACTIVE\n";
                    $tmp_newIPsecTunnel[$tmp_P2_vpn_name]->setDisabled(TRUE);
                }

            }
            elseif( $nodeName == 'bind-interface' )
            {
                print "bind to tunnel interface: ".$nodeValue."\n";
                $tmp_sub = $this->template->network->findInterface($nodeValue);
                $tmp_newIPsecTunnel[$tmp_P2_vpn_name]->setInterface($nodeValue);
                #exit;
            }
            //df-bit
            elseif( $nodeName == 'df-bit' )
            {
                #print "DFBIT: ".$nodeValue."\n";
                mwarning("PAN-OS do not support df-bit setting on IPsec tunnel level.", null, FALSE);
            }
            elseif( $nodeName == 'ike' )
            {
                $nodeGW = DH::findFirstElement('gateway', $node);
                if( $nodeGW !== FALSE )
                {
                    #print "combine with gateway: ".$nodeGW->nodeValue."\n";
                    #$gateway = $this->IKE_IPSEC_name_validation($gateway, "IPSEC related IKE");
                    $VPN_array[$tmp_P2_vpn_name]['gateway'] = $nodeGW->nodeValue;

                    $tmp_newIPsecTunnel[$tmp_P2_vpn_name]->setIKEGateway($nodeGW->nodeValue);
                }


                $nodePOLICY = DH::findFirstElement('ipsec-policy', $node);
                if( $nodePOLICY !== FALSE )
                {
                    #print "add policy: ".$nodePOLICY->nodeValue." with proposal: ". $tmp_P2_policy[ $nodePOLICY->nodeValue ] ."\n";

                    if( isset( $tmp_P2_policy[$nodePOLICY->nodeValue] ) )
                    {
                        $proposal = $this->template->network->ipsecCryptoProfileStore->findIpsecCryptoProfil($tmp_P2_policy[$nodePOLICY->nodeValue]);
                        $tmp_newIPsecTunnel[$tmp_P2_vpn_name]->setProposal($proposal->name());
                    }
                    else
                        $tmp_newIPsecTunnel[$tmp_P2_vpn_name]->setProposal( "default" );


                }

            }
            elseif( $nodeName == 'traffic-selector' )
            {
                #$this->printXML( $node );
                /*
                name - t2
                local-ip - 10.157.0.0/20
                remote-ip - 172.25.96.0/24
                 */

                $nodeTrafficName = DH::findFirstElement('name', $node);
                if( $nodeTrafficName !== FALSE )
                    print "trafficName: " . $nodeTrafficName->nodeValue . "\n";

                $nodeLOCAL = DH::findFirstElement('local-ip', $node);


                $nodeREMOTE = DH::findFirstElement('remote-ip', $node);
                if( $nodeLOCAL !== FALSE && $nodeREMOTE !== FALSE )
                {
                    $local_ip = $nodeLOCAL->nodeValue;
                    $remote_ip = $nodeREMOTE->nodeValue;

                    print "LOCAL: " . $local_ip . "\n";
                    print "REMOTE: " . $remote_ip . "\n";

                    #mwarning( "implementation needed for traffic-selector / proxy-IDs" );

                    $tmp_newIPsecTunnel[$tmp_P2_vpn_name]->addProxyId($local_ip, $remote_ip);
                }


            }
        }
    }


}