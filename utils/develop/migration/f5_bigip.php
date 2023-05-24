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


###################################################################################
###################################################################################
//Todo: possible to bring this in via argument
//CUSTOM variables for the script

//BOTH PROFILES MUST BE available if API
$log_profile = "Logging to Panorama";
$secprofgroup_name = "SecDev_Security Profile";



###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ F5 UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = Array('niceName' => 'CSV', 'shortHelp' => 'VMware VNIX in CSV format');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] file=[csv_text file] [out=]";

function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars,"",$str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}


$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

if( isset(PH::$args['file'])  )
    $file = PH::$args['file'];
else
    derr( "argument file not set" );





$util->load_config();
$util->location_filter();

$pan = $util->pan;


if( $util->configType == 'panos' )
{
    // Did we find VSYS1 ?
    $v = $pan->findVirtualSystem( $util->objectsLocation[0] );
    if( $v === null )
        derr( $util->objectsLocation[0]." was not found ? Exit\n");
}
elseif( $util->configType == 'panorama' )
{
    $v = $pan->findDeviceGroup( $util->objectsLocation[0] );
    if( $v == null )
        $v = $pan->createDeviceGroup( $util->objectsLocation[0] );
}
elseif( $util->configType == 'fawkes' )
{
    $v = $pan->findContainer( $util->objectsLocation[0] );
    if( $v == null )
        $v = $pan->createContainer( $util->objectsLocation[0] );
}


##########################################

$file_content = file( $file ) or die("Unable to open file!");



$objectRoot = false;
$objectAddresses=false;
$objectAddressList=false;

$serviceRoot = false;
$objectService=false;
$objectServiceList=false;

$globalRules=false;
$isGlobalPolicy=false;
$isPolicy=false;
$globalPolicies=false;


$isRule = false;
$rules=false;
$isRuleDestinationAddress=false;
$isRuleDestinationAddressList=false;
$isRuleDestinationZone=false;
$isRuleDestinationPortList=false;
$isRuleDestinationPort=false;

$isRuleSource=false;
$isRuleSourceAddress=false;
$isRuleSourceAddressList=false;
$isRuleSourceZone=false;
$isRuleSourcePortList=false;
$isRuleSourcePort=false;

$testSERVICEprotocol="";

$fixAddressGroup = array();

$color = 1;

// Parse the Configuration
foreach ($file_content as $line => $names_line) {
    $names_line_original=$names_line;
    $names_line = trim($names_line);
    // AddressGroups
    if (preg_match('/security firewall address-list/',$names_line)){
        $parts=explode(" ",$names_line);
        if ($parts[4]=="{"){
            $addressGroupName=$parts[3];
            $addressGroupName = truncate_names(normalizeNames($addressGroupName));

            $tmp_addressgroup = $v->addressStore->find( $addressGroupName );
            if( $tmp_addressgroup == null )
            {
                print "   - create addressgroup: " . $addressGroupName . "\n";
                $tmp_addressgroup = $v->addressStore->newAddressGroup($addressGroupName);
            }

            $currentObject = $tmp_addressgroup;

            $objectRoot=true;
            $objectAddresses=false;
            $objectAddressList=false;
        }
    }
    if ($objectRoot){
        if ($names_line=="}"){
            if (($objectAddresses==false) AND ($objectAddressList==false) ){
                $objectRoot=false;
            }
            if ($objectAddressList){
                $objectAddressList=false;
            }
            if ($objectAddresses){
                $objectAddresses=false;
            }
        }
        if (preg_match('/description /',$names_line)) {
            if (preg_match('/\"/',$names_line)){
                $desc=explode('"',$names_line);
                $description=$desc[1];
            }
            else{
                $desc=explode(' ',$names_line);
                $description=$desc[1];
            }

            $tmp_addressgroup->setDescription( $description );

            continue(1);
        }
        if ($objectAddresses){
            $ips=explode(" ",$names_line);

            $addressName = $ips[0];
            $addressName = truncate_names(normalizeNames($addressName));

            $tmp_address = $v->addressStore->find( $addressName );
            if( $tmp_address == null )
            {
                print "   - create address object: ".$addressName." | value: ".$addressName."\n";
                $tmp_address = $v->addressStore->newAddress( $addressName, 'ip-netmask', $addressName );
            }
            $tmp_addressgroup->addMember( $tmp_address );
        }
        if ($objectAddressList){
            $ips=explode(" ",$names_line);

            $addressName = truncate_names(normalizeNames($ips[0]));

            $tmp_address = $v->addressStore->find( $addressName );
            if( $tmp_address != null )
                $tmp_addressgroup->addMember( $tmp_address );
            else
            {
                $fixAddressGroup[ $tmp_addressgroup->name() ][] = $addressName;
                print "addressgroup member: ".$addressName. " not found - fix at the end\n";
            }

        }
        if (preg_match('/addresses /',$names_line)) {
            // IP address
            $objectAddresses=true;
            $objectAddressList=false;
            continue(1);
        }

        if (preg_match('/address-lists /',$names_line)) {
            // IP LIsts
            $objectAddressList=true;
            $objectAddresses=false;
            continue(1);
        }
    }
    // ServicesGroups
    if (preg_match('/security firewall port-list/',$names_line)){
        $parts=explode(" ",$names_line);
        if ($parts[4]=="{"){
            $serviceGroupName=$parts[3];
            $serviceGroupName = truncate_names(normalizeNames($serviceGroupName));

            $tmp_servicegroup = $v->serviceStore->find( $serviceGroupName );
            if( $tmp_servicegroup == null )
            {
                if( strpos( $serviceGroupName, "tcp" ) !== false || strpos( $serviceGroupName, "TCP" ) !== false )
                    $testSERVICEprotocol = 'tcp';
                elseif( strpos( $serviceGroupName, "udp" ) !== false || strpos( $serviceGroupName, "UDP" ) !== false )
                    $testSERVICEprotocol = 'udp';
                else
                    $testSERVICEprotocol = 'tcp';

                print "   - create servicegroup: " . $serviceGroupName . "\n";
                $tmp_servicegroup = $v->serviceStore->newServiceGroup($serviceGroupName);
            }

            $currentObject=$tmp_servicegroup;

            $serviceRoot=true;
            $objectService=false;
            $objectServiceList=false;
        }
    }

    if ($serviceRoot){
        if ($names_line=="}"){
            if (($objectService==false) AND ($objectServiceList==false) ){
                $serviceRoot=false;

                //Todo: swaschkut 20201103 what is this??? add to shared level????
                //$SGDB->addSG($currentObject);

                $tmp_servicegroup = $v->serviceStore->find("SGDB");
                if( $tmp_servicegroup == null )
                    $tmp_servicegroup = $v->serviceStore->newServiceGroup("SGDB");
                $tmp_servicegroup->addMember( $currentObject );

            }
            if ($objectServiceList){
                $objectServiceList=false;
            }
            if ($objectService){
                $objectService=false;
            }
        }
        if (preg_match('/description /',$names_line)) {
            if (preg_match('/\"/',$names_line)){
                $desc=explode('"',$names_line);
                $description=$desc[1];
            }
            else{
                $desc=explode(' ',$names_line);
                $description=$desc[1];
            }

            if( $tmp_servicegroup->isGroup() )
            {
                mwarning("PANOS does not support description on ServiceGroup!!!");
            }
            else
                $tmp_servicegroup->setDescription( $description );
            continue(1);
        }
        if ($objectService){
            $ips=explode(" ",$names_line);

            $serviceName = $testSERVICEprotocol."-".$ips[0];
            $serviceValue = $ips[0];
            $serviceName = truncate_names(normalizeNames($serviceName));

            #if( !is_numeric( $serviceValue ) )
                #derr( $names_line. " service port not numeric" );

            $tmp_service = $v->serviceStore->find( $serviceName );
            if( $tmp_service == null )
            {
                print "   - create service object: ".$serviceName." | value: ".$serviceValue."\n";
                $tmp_service = $v->serviceStore->newService( $serviceName, $testSERVICEprotocol, $serviceValue );
            }
            $tmp_servicegroup->addMember( $tmp_service );
        }
        if ($objectServiceList){
            $ips=explode(" ",$names_line);

            // Could be the object is not read yet but referenced
            $serviceGroupName = $ips[0];
            $serviceGroupName = truncate_names(normalizeNames($serviceGroupName));

            $tmp_servicegroup = $v->serviceStore->find( $serviceGroupName );
            if( $tmp_servicegroup == null )
            {
                print "   - create servicegroup: " . $serviceGroupName . "\n";
                $tmp_servicegroup = $v->serviceStore->newServiceGroup($serviceGroupName);
            }

            $tmp_servicegroup->addMember( $tmp_service );
        }
        if (preg_match('/ports /',$names_line)) {
            // IP address
            $objectService=true;
            $objectServiceList=false;
            continue(1);
        }

        if (preg_match('/port-lists /',$names_line)) {
            // IP LIsts
            $objectServiceList=true;
            $objectService=false;
            continue(1);
        }
    }
    // Global Rules
    if (preg_match('/security firewall global-rules/',$names_line)){
        $globalRules=true;
        $last="";
        continue(1);
    }
    if ($globalRules){
        if ($names_line=="}"){
            if ($globalRules){
                $globalRules=false;
            }
        }
        if (preg_match('/enforced-policy/',$names_line)){
            $parts=explode(" ",$names_line);
            $globalPolicies[$parts[1]]=$parts[1];

            //Todo: create security policy
            //$myGlobalPolicy[$parts[1]]=new Policies($parts[1]);
            mwarning( "global policy found - not implemented yet" );
        }
    }
    // Policies based on Global Rules
    if (preg_match('/security firewall policy /',$names_line)){
        $parts0=explode(" ",$names_line);
        if (!isset($globalPolicies[$parts0[3]])){

            //Todo: create security policy
            //$globalPolicies[$parts0[3]]=new Policies($parts0[3]);
            print  "global policy found - not implemented yet -'".$parts0[3]."'\n" ;
        }
        if ( isset($globalPolicies[$parts0[3]]) && $parts0[3]==$globalPolicies[$parts0[3]]){
            $isGlobalPolicy=true;
            continue(1);

        }
    }
    if ($isGlobalPolicy){
        if ($names_line=="rules {"){
            continue(1);
        }
        if ($last==$names_line){
            $isGlobalPolicy=false;
        }
        if (preg_match('/ {/',$names_line)){
            $split=explode(" ",$names_line);
            $myPolicy=$split[0];
            $globalPolicies[$parts0[3]]=$split[0];
            if (!isset($tags[$split[0]])){

                //Todo: create TAGS
                //$tags[$split[0]]= new Tag($split[0],$color++);
                $tmp_tag = $v->tagStore->find( $split[0] );
                if( $tmp_tag == null )
                {
                    $tmp_tag = $v->tagStore->createTag($split[0]);
                }
                //todo: how to set different color based on numbers, not implemented yet in framework;

                if ($color==11){
                    $color=1;
                }
            }
        }

        if ( preg_match('/rule-list /',$names_line)){
            $parts1=explode(" ",$names_line);
            $myRule=$parts1[1];

            //Todo: what to do here?
            //$myGlobalPolicy[$parts[1]]->setPolicy($myPolicy,$myRule);
            mwarning( "global policy found - not implemented yet" );
        }
        $last=$names_line;
    }
    // Rules inside a Policy
    if (preg_match('/security firewall rule-list /',$names_line)){
        $split=explode(" ",$names_line);
        $currentPolicy=$split[3];
        $isPolicy=true;
        // echo "Entering Rule-List $currentPolicy".PHP_EOL;
        continue(1);
    }

    if ($isPolicy){
        if ($names_line_original=="}"){
            $isPolicy=false;
            // echo "END of Rule-List $currentPolicy".PHP_EOL;
            continue(1);
        }
        if ($names_line=="rules {"){
            $readRules=true;
            $ruleName="";
            $ruleProtocol="";
            // echo "Entering in Rule-List Rules".PHP_EOL;
            continue(1);
        }

        if ($readRules){
            if (preg_match('/^    }/',$names_line_original)){
                $readRules=false;
                $ruleProtocol="";
                $ruleName="";
                // echo "Exiting Rule-List Rules".PHP_EOL;
                continue(1);

            }

            if ((preg_match('/{/',$names_line)) AND ($isRule==false)){
                $split=explode(" ",$names_line);
                $ruleName=$split[0];
                //echo "RUlE: ".$ruleName.PHP_EOL;


                $ruleName = truncate_names(normalizeNames($ruleName));

                //Todo: find if rulename is free;
                //if( $v->securityRules-> )
                $tmp_rule = $v->securityRules->newSecurityRule( $ruleName);
                print "\n * create SecurityRule: " . $ruleName . "\n";

                $currentPolicy = truncate_names(normalizeNames($currentPolicy));
                $tmp_tag = $v->tagStore->find( $currentPolicy );
                if( $tmp_tag == null )
                {
                    $tmp_tag = $v->tagStore->createTag($currentPolicy);
                }
                print "   - add Tag: " . $currentPolicy . "\n";
                $tmp_rule->tags->addTag( $tmp_tag );

                $isRule=true;
                continue(1);
            }

            if ($isRule){
                if (preg_match('/^        }/',$names_line_original)){
                    $isRule=false;
                    // echo "Exiting Rule $ruleName".PHP_EOL;
                    continue(1);
                }

                if (preg_match('/action /',$names_line)){
                    $split=explode(" ",$names_line);

                    if( $split[1] == "accept" )
                        $action = "allow";


                    print "   - set Action to ".$action."\n";
                    $tmp_rule->setAction( $action );
                    continue(1);
                }

                if (preg_match('/log /',$names_line)){
                    $split=explode(" ",$names_line);


                    #mwarning( "log set not yet implemented - '".$split[1]."'" );
                    //Todo set log
                    //$rules[$currentPolicy][$ruleName]->setLog($split[1]);

                    // for logprof
                    #print " * add log forwarding profile: ".$log_profile."\n";
                    #$tmp_rule->setLogSetting( $log_profile );
                    continue(1);
                }
                if (preg_match('/ip-protocol /',$names_line)){
                    $split=explode(" ",$names_line);
                    $ruleProtocol=$split[1];
                    // if (($ruleProtocol!="tcp") AND ($ruleProtocol!="udp")){
                    //     print "PROTOCOL NOT TCP/UDP:".$ruleProtocol.PHP_EOL;
                    // }


                    if (($ruleProtocol!="tcp") AND ($ruleProtocol!="udp"))
                    {
                        $tmp_service = $v->serviceStore->find( "tmp-".$ruleProtocol );
                        if( $tmp_service == null )
                        {
                            $tmp_service = $v->serviceStore->newService( "tmp-".$ruleProtocol, "tcp", '0' );
                        }
                        print "   - add TMP service object: " . $tmp_service->name() . "\n";
                        $tmp_rule->services->add($tmp_service);
                    }

                    continue(1);
                }
                if (preg_match('/description /',$names_line)){
                    if (preg_match('/\"/',$names_line)){
                        $split=explode("\"",$names_line);

                        print "   - add Description: " . $split[1] . "\n";
                        $tmp_rule->setDescription( $split[1] );
                    }
                    else{
                        $split=explode("description ",$names_line);

                        print "   - add Description: " . $split[1] . "\n";
                        $tmp_rule->setDescription( $split[1] );
                    }
                    continue(1);
                }
                if (preg_match('/destination {/',$names_line)){
                    $isRuleDestination=true;
                    // echo "$ruleName Here is Rule Destination".PHP_EOL;
                    continue(1);
                }
                if ($isRuleDestination){
                    if (preg_match('/^            }/',$names_line_original)){
                        $isRuleDestination=false;
                        // echo "$ruleName Exiting Rule Destination".PHP_EOL;
                        continue(1);
                    }
                    if (preg_match('/addresses {/',$names_line)){
                        $isRuleDestinationAddress=true;
                        $isRuleDestinationAddressList=false;
                        // echo "Entering Rule Destination Addresses".PHP_EOL;
                        continue(1);
                    }

                    if ($isRuleDestinationAddress)
                    {
                        if( preg_match('/^                }/', $names_line_original) )
                        {
                            $isRuleDestinationAddress = FALSE;
                            // echo "Exiting Rule Destination Addresses".PHP_EOL;
                            continue(1);
                        }
                        // echo "should be Destination Addresses".$names_line.PHP_EOL;
                        $split = explode(" ", $names_line);


                        $addressName = $split[0];
                        $addressName = truncate_names(normalizeNames($addressName));

                        if( $addressName != "" )
                        {
                            $tmp_address = $v->addressStore->find($addressName);
                            if( $tmp_address == null )
                            {
                                print "   - create address object: " . $addressName . " | value: " . $addressName . "\n";
                                $tmp_address = $v->addressStore->newAddress($addressName, 'ip-netmask', $addressName);
                            }

                            print "   - add source object: " . $tmp_address->name() . "\n";
                            $tmp_rule->destination->addObject($tmp_address);
                        }

                        continue(1);
                    }
                    if (preg_match('/address-lists {/',$names_line)){
                        $isRuleDestinationAddressList=true;
                        $isRuleDestinationAddress=false;
                        // echo "$ruleName Entering Rule Destination Address-List".PHP_EOL;
                        continue(1);
                    }

                    if ($isRuleDestinationAddressList){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleDestinationAddressList=false;
                            // echo "$ruleName Exiting Rule Destination Address-List".PHP_EOL;
                            continue(1);
                        }
                        $split=explode(" ",$names_line);

                        $addressName = $split[0];
                        $addressName = truncate_names(normalizeNames($addressName));
                        $tmp_address = $v->addressStore->find( $addressName );
                        if( $tmp_address == null )
                        {
                            echo "PROBLEM. RULE: $ruleName Found a Destination Address list which was not defined:".$split[0].PHP_EOL;
                        }

                        print "   - add source object: ".$tmp_address->name()."\n" ;
                        $tmp_rule->destination->addObject( $tmp_address );
                    }
                    //
                    if (preg_match('/vlans {/',$names_line)){
                        $isRuleDestinationZone=true;
                        //echo "$ruleName Entering Rule Destination Zone".PHP_EOL;
                        continue(1);
                    }
                    if ($isRuleDestinationZone){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleDestinationZone=false;
                            continue(1);
                        }

                        //echo "DESTINATION VLAN - ZONE".$names_line.PHP_EOL;


                        $tmp_to_zone = $v->zoneStore->find( $names_line );
                        if( $tmp_to_zone == null )
                        {
                            $tmp_to_zone = $v->zoneStore->findorCreate( $names_line );
                        }
                        print " * add to Zone: ".$names_line."\n";
                        $tmp_rule->to->addZone( $tmp_to_zone);
                   }
                    //
                    if (preg_match('/ports {/',$names_line)){
                        $isRuleDestinationPort=true;
                        continue(1);
                    }

                    if ($isRuleDestinationPort){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleDestinationPort=false;
                            continue(1);
                        }
                        $split=explode(" ",$names_line);
                        if (($ruleProtocol=="tcp") OR ($ruleProtocol=="udp"))
                        {
                            if( $split[0] != "" )
                            {
                                $serviceName = $ruleProtocol."-".$split[0];
                                $serviceValue = $split[0];
                                $serviceName = truncate_names(normalizeNames($serviceName));

                                $tmp_service = $v->serviceStore->find( $serviceName );
                                if( $tmp_service == null )
                                {
                                    print "   - create service object: ".$serviceName." value: ".$serviceValue."\n";
                                    //$tmp_service = $v->serviceStore->newService( $name, $protocol, $dport, $description);
                                    //Todo: validation needed, regarding protocol
                                    $tmp_service = $v->serviceStore->newService( $serviceName, $ruleProtocol, $serviceValue );
                                }
                                print "   - add service object: " . $tmp_service->name() . "\n";
                                $tmp_rule->services->add($tmp_service);
                            }
                        }
                        else
                        {
                            echo "INVALID PROTOCOL : ".$ruleProtocol. " ON RULENAME $ruleName" .PHP_EOL;
                        }
                    }

                    if (preg_match('/port-lists {/',$names_line)){
                        $isRuleDestinationPortList=true;
                        continue(1);
                    }

                    if ($isRuleDestinationPortList){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleDestinationPortList=false;
                            continue(1);
                        }


                        $serviceName = truncate_names(normalizeNames($names_line));
                        $tmp_service = $v->serviceStore->find( $serviceName );
                        if( $tmp_service == null )
                            echo "PROBLEM. RULE: $ruleName Found a Destination Port-List list which was not defined:".$names_line.PHP_EOL;


                        if (($ruleProtocol=="tcp") OR ($ruleProtocol=="udp"))
                        {
                            //todo: what to do here?
                            //swaschkut
                            /*
                            $objectSG=$SGDB->getByOriginal($names_line);
                            if ($objectSG!=NULL){
                                $ServiceGroupNameToCheck=$objectSG->getName()."-".$ruleProtocol;
                                if ($SGDB->getByOriginal($ServiceGroupNameToCheck)!=NULL){
                                    $rules[$currentPolicy][$ruleName]->addService($ServiceGroupNameToCheck);
                                }
                                else{
                                    $objTransformed=transformByProtocol($serviceGroup,$objectSG,$ruleProtocol,$services,$SGDB,$ServiceGroupNameToCheck);
                                    if ($objTransformed!=NULL){
                                        $rules[$currentPolicy][$ruleName]->addService($objTransformed);
                                    }
                                    else{
                                        // ServiceGroup Doesnt Exist...
                                        echo "ServiceGroup ".$names_line." Does not Exists".PHP_EOL;
                                    }
                                }

                            }

*/

                        }
                        else{
                            echo "INVALID PROTOCOL : ".$ruleProtocol. " ON RULENAME $ruleName" .PHP_EOL;
                        }
                        //$rules[$currentPolicy][$ruleName]->addService($serviceGroup[$names_line]->getName());
                    }


                }
                if (preg_match('/source {/',$names_line)){
                    $isRuleSource=true;
                    continue(1);
                }
                if ($isRuleSource){
                    if (preg_match('/^            }/',$names_line_original)){
                        $isRuleSource=false;
                        continue(1);
                    }
                    if (preg_match('/addresses {/',$names_line)){
                        $isRuleSourceAddress=true;
                        continue(1);
                    }

                    if ($isRuleSourceAddress){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleSourceAddress=false;
                            continue(1);
                        }
                        $split=explode(" ",$names_line);

                        $addressName = $split[0];
                        $addressName = truncate_names(normalizeNames($addressName));

                        if( $addressName != "" )
                        {
                            $tmp_address = $v->addressStore->find( $addressName );
                            if( $tmp_address == null )
                            {
                                print "   - create address object: ".$addressName." | value: ".$addressName."\n";
                                $tmp_address = $v->addressStore->newAddress( $addressName, 'ip-netmask', $addressName );
                            }

                            print "   - add source object: ".$tmp_address->name()."\n" ;
                            $tmp_rule->source->addObject( $tmp_address );
                        }

                    }

                    if (preg_match('/address-lists {/',$names_line)){
                        $isRuleSourceAddressList=true;
                        continue(1);
                    }

                    if ($isRuleSourceAddressList){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleSourceAddressList=false;
                            continue(1);
                        }
                        $split=explode(" ",$names_line);

                        $addressName = $split[0];
                        $addressName = truncate_names(normalizeNames($addressName));
                        $tmp_address = $v->addressStore->find( $addressName );
                        if( $tmp_address == null )
                        {
                            echo "PROBLEM. RULE: $ruleName Found a Source Address list which was not defined:".$split[0].PHP_EOL;
                        }

                        print "   - add source object: ".$tmp_address->name()."\n" ;
                        $tmp_rule->source->addObject( $tmp_address );
                    }
                    //
                    if (preg_match('/vlans {/',$names_line)){
                        $isRuleSourceZone=true;
                        //echo "$ruleName Entering Rule Source Zone".PHP_EOL;
                        continue(1);
                    }
                    if ($isRuleSourceZone){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleSourceZone=false;
                            continue(1);
                        }

                        $tmp_from_zone = $v->zoneStore->find( $names_line );
                        if( $tmp_from_zone == null )
                        {
                            $tmp_from_zone = $v->zoneStore->findorCreate( $names_line );
                        }
                        print " * add from Zone: ".$names_line."\n";
                        $tmp_rule->from->addZone( $tmp_from_zone);

                    }
                    //
                    if (preg_match('/ports {/',$names_line)){
                        $isRuleSourcePort=true;
                        continue(1);
                    }

                    if ($isRuleSourcePort){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleSourcePort=false;
                            continue(1);
                        }
                    }

                    if (preg_match('/port-lists {/',$names_line)){
                        $isRuleSourcePortList=true;
                        continue(1);
                    }

                    if ($isRuleSourcePortList){
                        if (preg_match('/^                }/',$names_line_original)){
                            $isRuleSourcePortList=false;
                            continue(1);
                        }
                    }
                }
            }
        }
    }
}


print "\n\n FIX ADDRESSGROUPS\n";

foreach( $fixAddressGroup as $addressgroupname => $groupmembers )
{
    $tmp_addressgroup = $v->addressStore->find( $addressgroupname );
    print "  - fix addressgroup: ".$addressgroupname."\n";
    foreach( $groupmembers as $member )
    {
        $tmp_address = $v->addressStore->find( $member );
        if( $tmp_address !== null )
        {
            print "    - add member: ".$member."\n";
            $tmp_addressgroup->addMember( $tmp_address );
        }


    }
}


function truncate_names($longString) {
    global $source;
    $variable = strlen($longString);

    if ($variable < 63) {
        return $longString;
    } else {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = 63 - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if ($salida != $longString) {
            //Todo: swaschkut - xml attribute adding needed
            #add_log('warning', 'Names Normalization', 'Object Name exceeded >63 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
        }
        return $salida;
    }
}

function normalizeNames($nameToNormalize) {
    $nameToNormalize = trim($nameToNormalize);
    //$nameToNormalize = preg_replace('/(.*) (&#x2013;) (.*)/i', '$0 --> $1 - $3', $nameToNormalize);
    //$nameToNormalize = preg_replace("/&#x2013;/", "-", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\/]+/", "_", $nameToNormalize);
    $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_. ]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\s]+/", " ", $nameToNormalize);

    $nameToNormalize = preg_replace("/^[-]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/^[_]+/", "", $nameToNormalize);

    $nameToNormalize = preg_replace('/\(|\)/','',$nameToNormalize);

    return $nameToNormalize;
}
##################################################################




/*
foreach( $addressObjectArray as $storagename => $object )
{
    print "Storagename: ".$storagename. " - Name: ".$object->name()."\n";
}
*/

print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF F5 UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";