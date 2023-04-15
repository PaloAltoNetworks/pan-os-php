<?php



//Todo: SRX PSK
//https://www.juniper.net/documentation/en_US/junos/topics/reference/command-summary/request-security-decryp-password.html


trait SRXike
{
    public $IKE_policy = array();

    function get_XML_IKE($configRoot, $shared )
    {
        global $IKE_policy;

        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            #print $nodeName."\n";

            if( $nodeName == "proposal" )
            {
                $this->get_IKE_proposal($childNode, $shared);
            }
            elseif( $nodeName == "policy" )
            {
                $this->get_IKE_policy($childNode);

            }
            elseif( $nodeName == "gateway" )
            {
                #print_r( $IKE_policy );
                #todo: implemented please validate again
                $this->get_IKE_gateway($childNode, $shared);
            }
            else
            {
                mwarning("IKE child nodeName: " . $nodeName . " not supported");
            }


        }
    }

    function get_IKE_proposal($configRoot, $shared)
    {
        global $print;
        global $debug;
        global $tmp_P1_config_proposals;


        #print "\nPROPOSAL\n";
        #$this->printXML( $configRoot );

        $proposal_name = "";
        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;

            if( $nodeName == 'name' )
            {
                $proposal_name = $nodeValue;
                $tmp_P1_config_proposals[$proposal_name] = $this->template->network->ikeCryptoProfileStore->newIKECryptoProfil($nodeValue);
                if( $print )
                    print "create IKE crypto proposal: " . $nodeValue . "\n";
            }
            elseif( $nodeName == 'dh-group' )
            {
                $tmp_P1_config_proposals[$proposal_name]->setDHgroup($nodeValue);
            }
            elseif( $nodeName == 'authentication-algorithm' )
            {
                if( strpos($nodeValue, 'sha-128') !== FALSE )
                    $nodeValue = 'sha128';
                elseif( strpos($nodeValue, 'sha-256') !== FALSE )
                    $nodeValue = 'sha256';

                $tmp_P1_config_proposals[$proposal_name]->sethash($nodeValue);
            }
            elseif( $nodeName == 'encryption-algorithm' )
            {
                if( strpos($nodeValue, 'aes128') !== FALSE )
                    $nodeValue = 'aes-128-cbc';
                elseif( strpos($nodeValue, 'aes256') !== FALSE )
                    $nodeValue = 'aes-256-cbc';
                elseif( strpos($nodeValue, '3des') !== FALSE )
                    $nodeValue = '3des';

                $tmp_P1_config_proposals[$proposal_name]->setencryption($nodeValue);
            }
            elseif( $nodeName == 'lifetime-seconds' )
            {
                if( $nodeValue == 86400 )
                {
                    $lifetimetype = 'days';
                    $nodeValue = '1';
                }
                elseif( $nodeValue > 65535 )
                {
                    //derr( "lifetime is greater then 65535 - validation needed" );
                    if( $debug )
                        mwarning("lifetime is greater then 65535 - validation needed", null, FALSE);
                    $lifetimetype = "seconds";
                }
                else
                    $lifetimetype = "seconds";


                $tmp_P1_config_proposals[$proposal_name]->setlifetime($lifetimetype, $nodeValue);
            }
        }

        /*
         * name - AGG-IKE-PROP
description - Produban VPN proposal
authentication-method - pre-shared-keys
dh-group - group5
authentication-algorithm - sha-256
encryption-algorithm - aes-256-cbc
lifetime-seconds - 28800
         */

    }

    function get_IKE_policy($configRoot)
    {
        global $IKE_policy;
        #print "\nPOLICY\n";
        #$this->printXML( $configRoot );
        $policy_name = null;

        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;
            #print $nodeName . " - " . $nodeValue . "\n";

            if( $nodeName == 'name' )
            {
                $policy_name = $nodeValue;
                $IKE_policy[$policy_name]['name'] = $nodeValue;
            }
            elseif( $nodeName == 'mode' )
            {
                $IKE_policy[$policy_name]['mode'] = $nodeValue;
            }
            elseif( $nodeName == 'proposals' )
            {
                $IKE_policy[$policy_name]['proposals'] = $nodeValue;
            }
            elseif( $nodeName == 'proposal-set' )
            {
                $IKE_policy[$policy_name]['proposals'] = $nodeValue;
            }
            elseif( $nodeName == 'pre-shared-key' )
            {
                $nodePSK = DH::findFirstElement('ascii-text', $node);
                if( $nodePSK !== FALSE )
                    $IKE_policy[$policy_name]['pre-shared-key'] = $nodePSK->nodeValue;
                else
                    mwarning("pre-shared-key ascii-text not found");
            }
        }
        /*
        <name>ZONZA-PROD-EU-WEST-2-POLICY-A</name>
        <mode>main</mode>
        <proposals>ZONZA-PROD-EU-WEST-2-PROPOSAL-A</proposals>
        <pre-shared-key>
            <ascii-text>$9$HqQnApBRSefT/A0Ohc24oZiqz3/9t09ANVw2ZGHk.5Q36/tuBEDiORSeXxJZUD.5CAu0IEjHfz6AOBs24oZDHqfQ36tu</ascii-text>
        </pre-shared-key>
         */
    }

    function get_IKE_gateway($configRoot, $shared)
    {
        global $print;
        global $debug;
        global $tmp_newIKEGateway;
        global $IKE_policy;



        print "\nGATEWAY\n";
        #$this->printXML( $configRoot );

        $IKE_name = null;

        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;
            #print $nodeName." - ".$nodeValue."\n";

            if( $nodeName == 'name' )
            {
                $IKE_name = $nodeValue;
                /*
                if( strpos($line, $needle2) !== FALSE )
                {
                    $tmp_newIKEGateway[$IKE_name] = $this->template->network->ikeGatewayStore->newIKEGateway($IKE_name, TRUE);
                }
                else
                    */
                $tmp_newIKEGateway[$IKE_name] = $this->template->network->ikeGatewayStore->newIKEGateway($nodeValue);
                if( $print )
                    print "create IKE gateway: " . $nodeValue . "\n";

            }
            elseif( $nodeName == 'ike-policy' )
            {
                //can be handled with an array,
                #print_r( $IKE_policy[$nodeValue] );
                if( isset($IKE_policy[$nodeValue]) )
                {
                    /*
                    [mode] => aggressive
                    [proposals] => AGG-IKE-PROP
                    [pre-shared-key] => $9$GEUiq5Q3At0ZU5Fn90ONdbsgaHqmQzniH5zn/OBxNdbs4ji.m5FZUA0BRSygoJGqP
                     */

                    if( isset( $IKE_policy[$nodeValue]['proposals'] ) and $IKE_policy[$nodeValue]['proposals'] == "standard" )
                        $IKE_policy[$nodeValue]['proposals'] = "default";

                    if( isset( $IKE_policy[$nodeValue]['proposals'] ) )
                        $tmp_newIKEGateway[$IKE_name]->setproposal($IKE_policy[$nodeValue]['proposals']);
                    else
                        //Todo: swaschkut 20200921
                        mwarning( "Proposal not found: ".$IKE_name. " Policy nodeValue: ". $nodeValue );

                    //Todo check mode : main or aggressive
                    if( isset($IKE_policy[$nodeValue]['mode']) && $IKE_policy[$nodeValue]['mode'] == "aggressive" )
                    {
                        mwarning("not implemented yet - change to aggressive");
                    }
                }
                else
                {
                    mwarning("IKE policy: " . $nodeValue . " not found.");
                }
            }
            elseif( $nodeName == 'address' )
            {
                $tmp_newIKEGateway[$IKE_name]->setpeerAddress($nodeValue);
            }
            elseif( $nodeName == 'dynamic' )
            {
                $nodeDYNAMIC = DH::findFirstElement('hostname', $node);
                if( is_object( $nodeDYNAMIC ) )
                    print "DYNAMIC: " . $nodeDYNAMIC->nodeValue . "\n";
            }
            elseif( $nodeName == 'dead-peer-detection' )
            {
                $nodeINTERVAL = DH::findFirstElement('interval', $node);
                if( $nodeINTERVAL !== FALSE )
                    print "DEAD-PEER-DETECTION: INTERVALL: " . $nodeINTERVAL->nodeValue . "\n";

                $nodeTHRESHOLD = DH::findFirstElement('threshold', $node);
                if( $nodeTHRESHOLD !== FALSE )
                    print "DEAD-PEER-DETECTION: THRESHOLD: " . $nodeTHRESHOLD->nodeValue . "\n";
            }
            elseif( $nodeName == 'no-nat-traversal' )
            {
                if( $nodeValue != "" )
                {
                    print "NO-NAT-TRAVERSAL: " . $nodeValue . "\n";
                    mwarning("implementation needed of no-nat-traversal");
                }
            }
            elseif( $nodeName == 'local-identity' )
            {
                $nodeINET = DH::findFirstElement('inet', $node);
                $nodeHOSTNAME = DH::findFirstElement('hostname', $node);

                if( $nodeINET !== FALSE )
                {
                    $nodeIPV = DH::findFirstElement('identity-ipv4', $nodeINET);
                    print "LOCAL-IDENTITY: " . $nodeIPV->nodeValue . "\n";
                    //Todo: set local identity
                    mwarning("implemenetation of local-identicy-ipv4 needed");
                }
                elseif( $nodeHOSTNAME !== FALSE )
                {
                    $nodeHOST = DH::findFirstElement('identity-hostname', $nodeHOSTNAME);
                    print "LOCAL-IDENTITY: " . $nodeHOST->nodeValue . "\n";
                    //Todo: set local identity
                    mwarning("implementation of identity-hostname needed");
                }
            }
            elseif( $nodeName == 'external-interface' )
            {
                $tmp_newIKEGateway[$IKE_name]->setinterface($nodeValue);
            }
            elseif( $nodeName == 'version' )
            {
                //Todo: how to fix config if IKE is set but IKEv2 must be used?
                print "VERSION: " . $nodeValue . "\n";
                mwarning("implementation needed for version");
            }
            else
                mwarning("IKE gateway nodeName: " . $nodeName . " not supported");
        }
        /*
        <gateway inactive="inactive">
            <name>ANOTHER-AWS-VPN-DR-GW-2</name>
            <ike-policy>ANOTHER-AWS-VPN-DR-POL-2</ike-policy>
            <address>18.130.94.69</address>
            <dead-peer-detection>
                <interval>10</interval>
                <threshold>3</threshold>
            </dead-peer-detection>
            <no-nat-traversal/>
            <external-interface>reth2.247</external-interface>
        </gateway>
        <gateway>
            <name>POST-OFFICE-AGG-VPN-GW</name>
            <ike-policy>AGG-IKE-POLICY</ike-policy>
            <dynamic>
                <hostname>POFLJUFW01</hostname>
            </dynamic>
            <no-nat-traversal/>
            <local-identity>
                <hostname>
                    <identity-hostname>ixlljufw01</identity-hostname>
                </hostname>
            </local-identity>
            <external-interface>reth2.247</external-interface>
        </gateway>
         */
    }

    function printXML($childNode)
    {
        $interfaceName = "";
        $comment = "";
        $create_subinterface = FALSE;
        $tmp_int_main = null;

        foreach( $childNode->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;
            print $nodeName . " - " . $nodeValue . "\n";
        }
    }
}