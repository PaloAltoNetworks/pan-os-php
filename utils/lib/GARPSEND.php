<?php
/**
 * ISC License
 *
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

class GARPSEND extends UTIL
{
    public $utilType = null;

    public $commands = array();
    public $interfaceIP = array();
    public $ipRangeInt = array();

    public $offline_config_test = false;
    public $user = "";
    public $password = "";


    public function utilStart()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['test'] = array('niceName' => 'test', 'shortHelp' => 'command to test against offline config file');
        $this->supportedArguments['user'] = array('niceName' => 'user', 'shortHelp' => 'must be set to trigger sendGARP via SSH', 'argDesc' => '[USERNAME]');
        $this->supportedArguments['pw'] = array('niceName' => 'pw', 'shortHelp' => 'must be set to trigger sendGARP via SSH', 'argDesc' => '[PASSWORD]');

        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] [test] [user=SSHuser] [pw=SSHpw]" .
            "
             - for Firewalls where Interfaces or other config is from Panorama Device-Group / Template please use in=api://FW-MGMT-ip/merged-config";


        $this->prepareSupportedArgumentsArray();


        $this->utilInit();


        $this->main();


        
    }

    public function main()
    {
        /*
        set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
        require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
        require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

        require_once dirname(__FILE__)."/../../phpseclib/Net/SSH2.php";
        require_once dirname(__FILE__)."/../../phpseclib/Crypt/RSA.php";
        */

        ###################################################################################
        ###################################################################################


        $this->offline_config_test = false;
        $this->user = "";
        $this->password = "";




        #PH::processCliArgs();

        if( !isset(PH::$args['help']) )
        {
            if( isset(PH::$args['test']) )
                $this->offline_config_test = TRUE;

            if( isset(PH::$args['in']) )
            {
                $configInput = PH::$args['in'];

                if( strpos($configInput, "api://") === FALSE && !$this->offline_config_test )
                    derr("only PAN-OS API connection is supported", null, false);

                $configInput = str_replace("api://", "", $configInput);
            }

        else
            derr("argument 'in' is needed", null, false);


        if( isset(PH::$args['user']) )
            $this->user = PH::$args['user'];
        else
        {
            if( !$this->offline_config_test )
                derr("argument 'user' is needed", null, false);
        }

        if( isset(PH::$args['pw']) )
            $this->password = PH::$args['pw'];
        else
        {
            if( !$this->offline_config_test )
                derr("argument 'pw' is needed", null, false);
        }

        //this is storing the username / pw in .panconfigkeystore
        $argv2 = array();
        PH::$args = array();
        PH::$argv = array();
        $argv2[] = "key-manager";
        $argv2[] = "add=" . $configInput;
        $argv2[] = "user=" . $this->user;
        $argv2[] = "pw=" . $this->password;
        $argc2 = count($argv2);

        if( !$this->offline_config_test )
            $util = new KEYMANGER("key-manager", $argv2, $argc2, __FILE__);
        }

        PH::$args = array();
        PH::$argv = array();

        $util = new UTIL("custom", $this->argv, $this->argc, __FILE__, $this->supportedArguments, $this->usageMsg);
        $util->utilInit();
        $util->load_config();

        if( !$util->pan->isFirewall() )
            derr("only PAN-OS FW is supported");

        if( !$util->apiMode && !$this->offline_config_test )
            derr("only PAN-OS API connection is supported");

        $inputConnector = $util->pan->connector;


        $interfaces = $util->pan->network->getAllInterfaces();


        foreach( $interfaces as $int )
        {
            /** @var EthernetInterface $int */
            $name = $int->name();

            #print "CLASS: ".get_class( $int )."\n";
            if( get_class($int) !== "EthernetInterface" )
                continue;

            if( $int->type() === "layer3" )
                $ips = $int->getLayer3IPAddresses();
            else
                $ips = array();

            foreach( $ips as $key => $ip )
            {
                $intIP = explode("/", $ip);

                $intIP = $intIP[0];
                if( !isset($intIP[1]) )
                {
                    //more validation if object is used
                    /** @var VirtualSystem $vsys */
                    $object = $vsys->addressStore->find($key);

                    if( $object->isType_FQDN() || $object->isType_ipWildcard() )
                        continue;

                    $intIP = $object->getNetworkValue();
                }

                if( filter_var($intIP, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
                    continue;

                if( $key == 0 )
                {
                    $this->interfaceIP[$name] = $intIP;
                }
                $this->ipRangeInt[$ip] = $name;

                $this->commands[$intIP . $name] = "test arp gratuitous ip " . $intIP . " interface " . $name;
            }
        }


        //get all vsys
        $vsyss = $util->pan->getVirtualSystems();

        foreach( $vsyss as $vsys )
        {
            $natDNATrules = $vsys->natRules->rules('(dnat is.set)');
            foreach( $natDNATrules as $rule )
            {
                #print "NAME: ".$rule->name()."\n";
                $dstObjects = $rule->destination->getAll();
                foreach( $dstObjects as $object )
                    self::getTestCommands($vsys, $object);
            }

            $natSNATrules = $vsys->natRules->rules('(snat is.set)');
            foreach( $natSNATrules as $rule )
            {
                /** @var NatRule $rule */
                if( $rule->snatinterface !== null )
                    continue;

                #print "NAME: ".$rule->name()."\n";
                $snatObjects = $rule->snathosts->getAll();

                foreach( $snatObjects as $object )
                    $this->getTestCommands($vsys, $object);
            }

            //bidirNAT are already involved in the SNAT calculation above
        }


        if( !$this->offline_config_test || $util->apiMode )
        {
            $cmd = "<show><arp><entry name = 'all'/></arp></show>";
            $response = $inputConnector->sendOpRequest($cmd);
        #$xmlDoc = new DOMDocument();
        #$xmlDoc->loadXML($response);
        #echo $response->saveXML();

            $result = DH::findFirstElement("result", $response);
            $entries = DH::findFirstElement("entries", $result);
            foreach( $entries->childNodes as $entry )
            {
                if( $entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $ip = DH::findFirstElement("ip", $entry);
                $interface = DH::findFirstElement("interface", $entry);

                $intIP = $this->interfaceIP[$interface->textContent];
                $intIP = explode("/", $intIP);
                $intIP = $intIP[0];

                $this->commands[] = "ping source " . $intIP . " count 2 host " . $ip->textContent;
            }
        }
        else
        {
            PH::print_stdout("");
            PH::print_stdout("ping commands can not be prepared in offline");
            PH::print_stdout("");
        }


        PH::print_stdout("");
        PH::print_stdout("Display the commands you like to send to the FW:");
        PH::print_stdout("");

        foreach( $this->commands as $command )
            PH::print_stdout($command);


        ##############################################
        ##############################################
        PH::print_stdout("");
        $output_string = "";
        if( !$this->offline_config_test )
        {
            $configInputExplode = explode('/', $configInput);
            if( count($configInputExplode) > 1 )
                $configInput = $configInputExplode[0];
            $ssh = new RUNSSH($configInput, $this->user, $this->password, $this->commands, $output_string);
        }


        print $output_string;
        ##############################################
        ##############################################



    }

    function getTestCommands($vsys, $object)
    {
        /** @var Address $object */
        #print "DST: ".$object->name()."\n";
        #print "IP: ".$object->value()."\n";

        if( $object->isType_FQDN() || $object->isType_ipWildcard() )
            return;

        $dstIP = $object->value();
        $dstIP = str_replace("/32", "", $dstIP);

        $this->IParray = array();
        if( strpos($dstIP, "/") === FALSE and strpos($dstIP, "-") === FALSE )
        {
            $this->IParray[$dstIP] = $dstIP;
        }
        else
        {
            $startEndarray = CIDR::stringToStartEnd($dstIP);
            $this->IParray = CIDR::StartEndToIParray($startEndarray);
        }


        foreach( $this->IParray as $dstIP )
        {
            if( filter_var($dstIP, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
                continue;

            //this is from above to get all interfaces
            foreach( $this->ipRangeInt as $key => $intName )
            {
                $IP_network = explode("/", $key);
                $value = $IP_network[0];
                if( !isset($IP_network[1]) )
                {
                    //more validation if object is used
                    /** @var VirtualSystem $vsys */
                    $object = $vsys->addressStore->find($key);

                    if( $object->isType_FQDN() || $object->isType_ipWildcard() )
                        continue;

                    $value = $object->getNetworkValue();
                    $netmask = $object->getNetworkMask();
                }
                else
                {
                    $netmask = $IP_network[1];
                }
                $network = cidr::cidr2network($value, $netmask);

                if( cidr::cidr_match($dstIP, $network, $netmask) )
                    $this->commands[$dstIP . $intName] = "test arp gratuitous ip " . $dstIP . " interface " . $intName;
            }
        }
    }
}