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
$secprofgroup_name = "SecDev_Security Profile_NAWAH";



###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ TMG UTILITY ****************\n\n";


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

//Todo: read XML file:
$xml = new DOMDocument;
$xml->load( $file );



$addressObjectArray = array();
$addressMissingObjects = array();

$serviceObjectArray = array();
$serviceMissingObjects = array();

$userObjectArray = array();
$userMissingObjects = array();

$policyGroupObjectArray = array();
$policyGroupMissingObjects = array();

$missingURL = array();


#######################################################
//FIND OBJECTS


/*Todo: are these objects also needed?
*
 * $xml = DH::findFirstElementOrCreate('fpc4:Root', $xml );
$xml = DH::findFirstElementOrCreate('fpc4:fpc4:Enterprise', $xml );
 */

$xml = DH::findFirstElementOrCreate('fpc4:Root', $xml );
$xml = DH::findFirstElementOrCreate('fpc4:Arrays', $xml );
$xml = DH::findFirstElementOrCreate('fpc4:Array', $xml );

foreach( $xml->childNodes as $appx )
{
    if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

    $appName = $appx->nodeName;

    #print "|1:|".$appName."\n";

    /*
    |1:|fpc4:AdminMajorVersion
    |1:|fpc4:AdminMinorVersion
    |1:|fpc4:CompatibilityVersion
    |1:|fpc4:Components
    |1:|fpc4:DNSName
    |1:|fpc4:IsJoinedToEnterprise
    |1:|fpc4:Name
    |1:|fpc4:Version
    |1:|fpc4:ChangeTracking

    |1:|fpc4:Servers
    |1:|fpc4:Extensions
    |1:|fpc4:UpdateCenter

        |1:|fpc4:RuleElements
    |1:|fpc4:NetConfig

    |1:|fpc4:Alerts
    |1:|fpc4:ConnectivityVerifiers
    |1:|fpc4:Cache
    |1:|fpc4:ArrayPolicy
    |1:|fpc4:ClientConfigSettings
    |1:|fpc4:Logs
    |1:|fpc4:Reports
    |1:|fpc4:Ref
    |1:|fpc4:PolicyAssignment
    |1:|fpc4:ConfigurationStorageServerConnection
    |1:|fpc4:MalwareInspectionSettings
    |1:|fpc4:NetworkInspectionSystem
    |1:|fpc4:StaticRoutes
    |1:|fpc4:SmtpProtectionConfiguration
    |1:|fpc4:SecurityAssessmentSharing
    |1:|fpc4:Credentials
     */


/*
|2:|fpc4:ProxyScheduleTemplates
        |2:|fpc4:Computers
        |2:|fpc4:AddressRanges
        |2:|fpc4:Subnets
        |2:|fpc4:ComputerSets
|2:|fpc4:URLSets
|2:|fpc4:DomainNameSets
        |2:|fpc4:Protocols
-|2:|fpc4:EventDefinitions
-|2:|fpc4:RadiusServers
|2:|fpc4:WebListeners
|2:|fpc4:AuthenticationSchemes
    |2:|fpc4:ContentTypeSets
    |2:|fpc4:UserSets
-|2:|fpc4:VendorParametersSets
-|2:|fpc4:ServerFarms
|2:|fpc4:UserAgentMappings
|2:|fpc4:UrlCategorySets
|2:|fpc4:PolicyGroups
 */
    if( $appName == "fpc4:RuleElements" )
    {
        foreach( $appx->childNodes as $appx2 )
        {
            if( $appx2->nodeType != XML_ELEMENT_NODE ) continue;

            $appName2 = $appx2->nodeName;
            print "|12:|" . $appName2 . "\n";

            if( $appName2 == "fpc4:Computers" || $appName2 == "fpc4:AddressRanges" || $appName2 == "fpc4:Subnets" )
            {
                addressObjects( $appx2, $appName2 );
            }
            elseif( $appName2 == "fpc4:ComputerSets" )
            {
                foreach( $appx2->childNodes as $appx3 )
                {
                    if( $appx3->nodeType != XML_ELEMENT_NODE ) continue;

                    print_xml_info( $appx3 );

                    $storagename = DH::findAttribute('StorageName', $appx3);
                    $name = DH::findFirstElement('fpc4:Name', $appx3 );
                    $description = DH::findFirstElement('fpc4:Description', $appx3 );

                    if( $name !== FALSE )
                    {
                        #print "NAME: |".$name->textContent."|\n";
                        $name = $name->textContent;
                    }

                    if( $description !== FALSE )
                    {
                        #print "Description: |".$description->textContent."|\n";
                        $description = $description->textContent;
                        $description = strip_hidden_chars( $description );
                    }
                    else
                        $description = "";


                    if( $storagename !== FALSE )
                    {
                        $find = array("{","}");
                        $storagename = str_replace($find, "", $storagename);
                        #print "STORAGE: |".$storagename."|\n";
                    }


                    $name = truncate_names(normalizeNames($name));

                    $tmp_addressgroup = $v->addressStore->find( "g-".$name );
                    if( $tmp_addressgroup == null )
                    {
                        print "   - create addressgroup: g-".$name."\n";
                        $tmp_addressgroup = $v->addressStore->newAddressGroup( "g-".$name );
                        $tmp_addressgroup->setDescription( $description );

                        $addressObjectArray[ $storagename ] = $tmp_addressgroup;

                    }
                    else
                    {
                        mwarning( "Object: ".$tmp_addressgroup->name(). " already available\n" );
                    }


                    foreach( $appx3->childNodes as $appx4 )
                    {
                        if( $appx4->nodeType != XML_ELEMENT_NODE ) continue;

                        $appName4 = $appx4->nodeName;

                        #print "|4:|" . $appName4 . "\n";

                        if( $appName4 == "fpc4:Computers" || $appName4 == "fpc4:AddressRanges" || $appName4 == "fpc4:Subnets" )
                            addressObjects($appx4, $appName4, $tmp_addressgroup);
                    }
                }
            }

            elseif( $appName2 == "fpc4:Protocols" )
            {
                foreach( $appx2->childNodes as $appx3 )
                {
                    if( $appx3->nodeType != XML_ELEMENT_NODE ) continue;

                    print_xml_info( $appx3 );



                    print "\n\n";

                    $storagename = DH::findAttribute('StorageName', $appx3);
                    $description = DH::findFirstElement('fpc4:Description', $appx3 );
                    $name = DH::findFirstElement('fpc4:Name', $appx3 );

                    if( $name !== FALSE )
                    {
                        print "NAME: |".$name->textContent."|\n";
                        $name = $name->textContent;
                    }

                    if( $description !== FALSE )
                    {
                        print "Description: |".$description->textContent."|\n";
                        $description = $description->textContent;
                        $description = strip_hidden_chars( $description );
                    }
                    else
                        $description = "";


                    if( $storagename !== FALSE )
                    {
                        $find = array("{","}");
                        $storagename = str_replace($find, "", $storagename);
                        print "STORAGE: |".$storagename."|\n";
                    }

                    $protocolConnections = DH::findFirstElement('fpc4:ProtocolConnections', $appx3 );

                    if( $protocolConnections != null )
                    {
                        $storagename2 = DH::findAttribute('StorageName', $protocolConnections);
                        if( $storagename2 != "PrimaryConnections" )
                            $protocolConnections = DH::findLastElement('fpc4:ProtocolConnections', $appx3 );

                        $dport = "";
                        $protocol = "tcp";

                        foreach( $protocolConnections->childNodes as $connection )
                        {
                            if( $connection->nodeType != XML_ELEMENT_NODE ) continue;

                            $appName3 = $connection->nodeName;

                            $portHigh = DH::findFirstElement('fpc4:PortHigh', $connection);
                            $portLow = DH::findFirstElement('fpc4:PortLow', $connection);
                            $ConnectionType = DH::findFirstElement('fpc4:ConnectionType', $connection);

                            if( $portHigh !== FALSE )
                            {
                                print "PortHigh: |" . $portHigh->textContent . "|\n";
                                $portHigh = $portHigh->textContent;
                            }

                            if( $portLow !== FALSE )
                            {
                                print "PortLow: |" . $portLow->textContent . "|\n";
                                $portLow = $portLow->textContent;
                            }

                            if( $dport == "" )
                            {
                                if( ($portHigh == $portLow) && ($portHigh != FALSE && $portLow != FALSE) )
                                    $dport = $portHigh;
                                elseif( $portHigh != FALSE && $portLow != FALSE )
                                {
                                    $dport = $portLow . "-" . $portHigh;
                                }
                            }
                            elseif( $dport == "6500" )
                            {
                                if( ($portHigh == $portLow) && ($portHigh != FALSE && $portLow != FALSE) )
                                    $dport = $portHigh;
                                elseif( $portHigh != FALSE && $portLow != FALSE )
                                {
                                    $dport = $portLow . "-" . $portHigh;
                                }
                            }
                            else
                            {
                                $dport .= ",";
                                if( ($portHigh == $portLow) && ($portHigh != FALSE && $portLow != FALSE) )
                                    $dport .= $portHigh;
                                elseif( $portHigh != FALSE && $portLow != FALSE )
                                {
                                    $dport .= $portLow . "-" . $portHigh;
                                }
                            }

                            if( $ConnectionType !== FALSE )
                            {
                                print "CONNECTIONType: |" . $ConnectionType->textContent . " [UDP]|\n";
                                $ConnectionType = $ConnectionType->textContent;

                                $protocol = "udp";
                            }
                            else
                                $protocol = "tcp";
                        }

                        if( $dport == "" )
                        {
                            $dport = "6500";
                            $name = "tmp-".$name;
                        }

                        $name = truncate_names(normalizeNames($name));

                        $tmp_service = $v->serviceStore->find( $name );
                        if( $tmp_service == null )
                        {
                            print "- create service: ".$name." proto: ".$protocol." port:".$dport." \n";
                            $tmp_service = $v->serviceStore->newService( $name, $protocol, $dport, $description);

                            $serviceObjectArray[$storagename] = $tmp_service;
                        }
                        else
                        {
                            $value = $tmp_service->getDestPort();

                            if( strpos( $dport, $value ) === FALSE )
                            {
                                //do we need to add additional ports????
                                print "    - set dport: ".$value.",".$dport."\n";
                                $tmp_service->setDestPort( $value.",".$dport );
                            }
                        }
                    }
                    else
                    {
                        print "XXXX service object: ".$name." need to be calculated / created\n";

                        $dport = "6500";
                        $name = "tmp-".$name;
                        $protocol = "tcp";

                        $name = truncate_names(normalizeNames($name));

                        $tmp_service = $v->serviceStore->find( $name );
                        if( $tmp_service == null )
                        {
                            print "- create TMP service: ".$name." proto: ".$protocol." port:".$dport." \n";
                            $tmp_service = $v->serviceStore->newService( $name, $protocol, $dport, $description);

                            $serviceObjectArray[$storagename] = $tmp_service;
                        }
                    }
                }
            }
            elseif( $appName2 == "fpc4:UserSets" )
            {
                foreach( $appx2->childNodes as $appx3 )
                {
                    if( $appx3->nodeType != XML_ELEMENT_NODE ) continue;

                    $appName3 = $appx3->nodeName;
                    #print "|33:|" . $appName3 . "\n";

                    print_xml_info($appx3 );

                    /*
|<fpc4:UserSet xmlns:fpc4="http://schemas.microsoft.com/isa/config-4" xmlns:dt="urn:schemas-microsoft-com:datatypes" StorageName="{B6DF26BA-0278-481C-8844-BCB85AAD73E3}" StorageType="1">
						<fpc4:Name dt:dt="string">Admins</fpc4:Name>
						<fpc4:Accounts StorageName="Access" StorageType="1">
							<fpc4:Account StorageName="MINAZ-Domain Admins" StorageType="1">
								<fpc4:AccountSid dt:dt="string">S-1-5-21-728778889-3922516257-2670499643-512</fpc4:AccountSid>
								<fpc4:AccountType dt:dt="int">1</fpc4:AccountType>
							</fpc4:Account>
						</fpc4:Accounts>
					</fpc4:UserSet>
                     */

                    $storagename = DH::findAttribute('StorageName', $appx3);
                    $name = DH::findFirstElement('fpc4:Name', $appx3 );
                    $description = DH::findFirstElement('fpc4:Description', $appx3 );

                    if( $name !== FALSE )
                    {
                        #print "NAME: |".$name->textContent."|\n";
                        $name = $name->textContent;
                    }

                    if( $description !== FALSE )
                    {
                        #print "Description: |".$description->textContent."|\n";
                        $description = $description->textContent;
                        $description = strip_hidden_chars( $description );
                    }
                    else
                        $description = "";


                    if( $storagename !== FALSE )
                    {
                        $find = array("{","}");
                        $storagename = str_replace($find, "", $storagename);
                        #print "STORAGE: |".$storagename."|\n";
                    }


                    $userObjectArray[ $storagename ] = $name;
                }
            }
            elseif( $appName2 == "fpc4:PolicyGroups" )
            {
                print_xml_info( $appx2 );
                /*
					<fpc4:PolicyGroup StorageName="{559D7DDD-628D-45B3-AA67-00CF9D2D9A25}" StorageType="1">
						<fpc4:Name dt:dt="string">E-Factuur</fpc4:Name>
						<fpc4:Type dt:dt="int">100</fpc4:Type>
					</fpc4:PolicyGroup>
                 */

                foreach( $appx2->childNodes as $appx3 )
                {
                    if( $appx3->nodeType != XML_ELEMENT_NODE ) continue;

                    $appName3 = $appx3->nodeName;
                    #print "|33:|" . $appName3 . "\n";

                    print_xml_info($appx3 );


                    $storagename = DH::findAttribute('StorageName', $appx3);
                    $name = DH::findFirstElement('fpc4:Name', $appx3 );


                    if( $name !== FALSE )
                    {
                        #print "NAME: |".$name->textContent."|\n";
                        $name = $name->textContent;
                    }

                    if( $storagename !== FALSE )
                    {
                        $find = array("{","}");
                        $storagename = str_replace($find, "", $storagename);
                        #print "STORAGE: |".$storagename."|\n";
                    }

                    $tmp_tag = $v->tagStore->find( $name );
                    if( $tmp_tag == null )
                    {
                        $tmp_tag = $v->tagStore->createTag($name);

                        $policyGroupObjectArray[$storagename] = $tmp_tag;
                    }
                }
            }
            elseif( $appName2 == "fpc4:URLSets" || $appName2 == "fpc4:DomainNameSets" )
            {

                foreach( $appx2->childNodes as $appx3 )
                {
                    if( $appx3->nodeType != XML_ELEMENT_NODE ) continue;

                    $appName3 = $appx3->nodeName;
                    #print "|33:|" . $appName3 . "\n";

                    print_xml_info($appx3 );

                    /*
                 * //create object
                <fpc4:URLSet StorageName="{3F27106C-5AA3-4CCE-A35C-E728D53F153F}" StorageType="1">
                    <fpc4:Description dt:dt="string">URL voor het bereiken van het portal voor beveiligers bij de 2e Kamer.</fpc4:Description>
                    <fpc4:Name dt:dt="string">mijn.tweedekamer.nl</fpc4:Name>
                    <fpc4:Predefined dt:dt="boolean">0</fpc4:Predefined>
                    <fpc4:URLStrings>
                        <fpc4:Str dt:dt="string">http://mijn.tweedekamer.nl</fpc4:Str>
                    </fpc4:URLStrings>
                </fpc4:URLSet>
                 */

                    $storagename = DH::findAttribute('StorageName', $appx3);
                    $name = DH::findFirstElement('fpc4:Name', $appx3 );
                    $description = DH::findFirstElement('fpc4:Description', $appx3 );

                    if( $name !== FALSE )
                    {
                        #print "NAME: |".$name->textContent."|\n";
                        $name = $name->textContent;
                    }

                    if( $description !== FALSE )
                    {
                        #print "Description: |".$description->textContent."|\n";
                        $description = $description->textContent;
                        $description = strip_hidden_chars( $description );
                    }
                    else
                        $description = "";


                    if( $storagename !== FALSE )
                    {
                        $find = array("{","}");
                        $storagename = str_replace($find, "", $storagename);
                        #print "STORAGE: |".$storagename."|\n";
                    }


                    $name = truncate_names(normalizeNames($name));


                    $name_prefix = str_replace( "fpc4:", "", $appName2);


                    $tmp_addressgroup = $v->addressStore->find( "g-".$name_prefix."-".$name );
                    if( $tmp_addressgroup == null )
                    {
                        print "   - create addressgroup: g-".$name_prefix."-".$name."\n";
                        $tmp_addressgroup = $v->addressStore->newAddressGroup( "g-".$name_prefix."-".$name );
                        $tmp_addressgroup->setDescription( $description );

                        $addressObjectArray[ $storagename ] = $tmp_addressgroup;
                    }
                    else
                    {
                        mwarning( "Object: ".$tmp_addressgroup->name(). " already available\n" );
                    }


                    //fpc4:URLStrings
                    /*
<fpc4:URLStrings>
							<fpc4:Str dt:dt="string">http://untalk.pl</fpc4:Str>
							<fpc4:Str dt:dt="string">http://dobar.pl</fpc4:Str>
							<fpc4:Str dt:dt="string">http://dudebox.pl</fpc4:Str>
							<fpc4:Str dt:dt="string">http://dyndin.ru</fpc4:Str>
							<fpc4:Str dt:dt="string">http://headart.pl</fpc4:Str>
							<fpc4:Str dt:dt="string">http://iprice.pl</fpc4:Str>
							<fpc4:Str dt:dt="string">http://linebench.ru</fpc4:Str>
							<fpc4:Str dt:dt="string">http://gagalis.net</fpc4:Str>
							<fpc4:Str dt:dt="string">http://postnl-track.net</fpc4:Str>
							<fpc4:Str dt:dt="string">http://postnl-tracking.net</fpc4:Str>
							<fpc4:Str dt:dt="string">http://postnl-tracktrace.net</fpc4:Str>
							<fpc4:Str dt:dt="string">http://foley.go2lightuniversity.com</fpc4:Str>
							<fpc4:Str dt:dt="string">http://banking.techpool.org</fpc4:Str>
							<fpc4:Str dt:dt="string">http://soaring.betsystemreviews.com</fpc4:Str>
							<fpc4:Str dt:dt="string">http://alfiantoys.com</fpc4:Str>
							<fpc4:Str dt:dt="string">http://supervision.sactown.us</fpc4:Str>
						</fpc4:URLStrings>
                     */
                    if( $appName2 == "fpc4:URLSets" )
                        $URLStrings = DH::findFirstElement('fpc4:URLStrings', $appx3 );
                    elseif( $appName2 == "fpc4:DomainNameSets" )
                        $URLStrings = DH::findFirstElement('fpc4:DomainNameStrings', $appx3 );

                    if( $URLStrings != null )
                    {
                        foreach( $URLStrings->childNodes as $appx4 )
                        {
                            if( $appx4->nodeType != XML_ELEMENT_NODE ) continue;

                            $appName4 = $appx4->nodeName;

                            #print "|4:|" . $appName4 . "\n";

                            $string = $appx4->textContent;


                            $string = str_replace( "http://", "", $string);
                            $string = str_replace( "https://", "", $string);

                            if( strpos( $string, "*" ) !== FALSE or (strpos( $string, "/" ) !== FALSE) )
                            {
                                #print "1|".$string."|\n";
                                //do not create // add
                                #print "|".strpos( $string, "*" )."|\n";
                                $missingURL[ $storagename ]['missing'][] = $string;

                            }
                            else
                            {

                                #print "2|".$string."|\n";

                                $name = $string;
                                $value = $string;
                                $type = "fqdn";


                                $name = truncate_names(normalizeNames($name));

                                $name_prefix = str_replace( "fpc4:", "", $appName2);

                                $tmp_address = $v->addressStore->find( $name_prefix."-".$name );
                                if( $tmp_address == null )
                                {
                                    print "   - create address object: ".$name_prefix."-"." value: ".$value."\n";
                                    $tmp_address = $v->addressStore->newAddress( $name_prefix."-".$name, $type, $value );

                                    #$addressObjectArray[ $storagename ] = $tmp_address;
                                }

                                if( $tmp_addressgroup != null && $tmp_address != null )
                                {
                                    print "     - add address: ".$tmp_address->name()." to addressgroup: ".$tmp_addressgroup->name()."\n";
                                    $tmp_addressgroup->addMember( $tmp_address );

                                    #$missingURL[ $storagename ]['added'][] = $string;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                print_xml_info( $appx2 );
            }
        }
    }
    elseif( $appName == "fpc4:NetConfig" )
    {
        $networks = DH::findFirstElement('fpc4:Networks', $appx);
        getNetConfig( $networks );

        $networks = DH::findFirstElement('fpc4:NetworkSets', $appx);
        getNetConfig( $networks );

        $nats = DH::findFirstElement('fpc4:NetworkRules', $appx);
        getNetworkRules( $nats );
    }

    elseif( $appName == "fpc4:ArrayPolicy" )
    {
        foreach( $appx->childNodes as $appx2 )
        {
            if( $appx2->nodeType != XML_ELEMENT_NODE ) continue;

            $appName2 = $appx2->nodeName;

            print_xml_info( $appx2 );


            if( $appName2 == "fpc4:PolicyRules" )
            {
                foreach( $appx2->childNodes as $appx3 )
                {
                    if( $appx3->nodeType != XML_ELEMENT_NODE ) continue;


                    print_xml_info( $appx3 );

                    //SKIP system policy
                    $system = DH::findFirstElement('fpc4:System', $appx3);
                    if( $system != null )
                    {
                        $system = $system->textContent;
                        if( $system == "1" )
                            continue;
                    }

                    //						<fpc4:Action dt:dt="int">1</fpc4:Action>
                    $action = DH::findFirstElement('fpc4:Action', $appx3);
                    $enabled = DH::findFirstElement('fpc4:Enabled', $appx3);
                    $rulename = DH::findFirstElement('fpc4:Name', $appx3);
                    $order = DH::findFirstElement('fpc4:Order', $appx3);
                    $ref = DH::findFirstElement('fpc4:Ref', $appx3);
                    $nat = DH::findFirstElement('fpc4:ServerPublishingProperties', $appx3);

                    $name = truncate_names(normalizeNames($rulename->textContent));

                    $tmp_rule = $v->securityRules->newSecurityRule( $name);
                    print "\n * create SecurityRule: " . $name . "\n";

                    if( $action != null )
                    {
                        $action = $action->textContent;
                        if( $action == "1" )
                        {
                            print "   - set Action to DENY\n";
                            $tmp_rule->setAction( "deny" );
                        }
                    }

                    //GroupPolicy
                    if( $ref != null )
                    {
                        $refname = DH::findFirstElement('fpc4:Name', $ref);
                        if( $refname != null )
                        {
                            $find = array("{", "}");
                            $refstoragename = str_replace($find, "", $refname->textContent);

                            if( isset($policyGroupObjectArray[$refstoragename]) )
                            {

                                if( $policyGroupObjectArray[$refstoragename] != "All Users" )
                                {
                                    print "  - add tag object: " . $policyGroupObjectArray[$refstoragename]->name() . "\n";
                                    $tmp_rule->tags->addTag( $policyGroupObjectArray[$refstoragename] );
                                }
                            }
                            else
                            {
                                $policyGroupMissingObjects[$refstoragename] = $refstoragename;
                            }
                        }
                    }




                    //SOURCE
                    $sourceRoot = DH::findFirstElement('fpc4:SelectionIPs', $appx3);
                    if( $sourceRoot != null )
                        getIPaddresses( $sourceRoot, $tmp_rule, "source" );

                    //ServerPublishingProperties
                    if( $nat != null )
                    {
                        //Todo: NAT rule name must be optimized
                        #$tmp_natrule = $v->natRules->newNatRule($rulename->textContent);
                        #print "\n * create NATRule: " . $rulename->textContent . "\n";
                        /*
						<fpc4:ServerPublishingProperties StorageName="ServerPublishingProperties" StorageType="1">
							<fpc4:PublishedServerIP dt:dt="string">172.21.1.182</fpc4:PublishedServerIP>
							<fpc4:Ref StorageName="PublishedProtocol" StorageType="1">
								<fpc4:Name dt:dt="string">{63C3384D-DBC9-4495-8A86-B692FB60C87A}</fpc4:Name>
								<fpc4:RefClass dt:dt="string">msFPCProtocol</fpc4:RefClass>
							</fpc4:Ref>
							<fpc4:IPsOnNetworks StorageName="IPsOnNetworks" StorageType="1">
								<fpc4:IPOnNetwork StorageName="{9AF68181-F3D4-4DF1-B6BA-53081090A82A}" StorageType="1">
									<fpc4:IPSelectionMethod dt:dt="int">2</fpc4:IPSelectionMethod>
									<fpc4:Ref StorageName="Network" StorageType="1">
										<fpc4:Name dt:dt="string">{6C6D4FE8-DF73-4E0C-AFF4-1D15154B8CD9}</fpc4:Name>
										<fpc4:RefClass dt:dt="string">msFPCNetwork</fpc4:RefClass>
									</fpc4:Ref>
									<fpc4:IPAddresses StorageName="IPAddresses" StorageType="1">
										<fpc4:IPAddressesStrings>
											<fpc4:Str dt:dt="string">145.21.148.133</fpc4:Str>
										</fpc4:IPAddressesStrings>
									</fpc4:IPAddresses>
								</fpc4:IPOnNetwork>
							</fpc4:IPsOnNetworks>
							<fpc4:Refs StorageName="IPsOnNetworkSets" StorageType="1"/>
						</fpc4:ServerPublishingProperties>
                     */
                    }


                    //AccessProperties
                    $AccessProperties = DH::findFirstElement('fpc4:AccessProperties', $appx3);
                    if( $AccessProperties != null )
                    {
                        foreach( $AccessProperties->childNodes as $node )
                        {
                            if( $node->nodeType != XML_ELEMENT_NODE ) continue;
                            $appName3 = $node->nodeName;


                            if( $appName3 == "fpc4:SelectionIPs" )
                            {
                                //DESTINATION
                                getIPaddresses( $node, $tmp_rule, "destination" );
                            }
                            elseif( $appName3 == "fpc4:Refs" )
                            {
                                //StorageName="ProtocolsUsed"
                                $storagename = DH::findAttribute('StorageName', $node);
                                if( $storagename == "ProtocolsUsed" )
                                {
                                    //find services and add
                                    print_xml_info( $node );

                                    foreach( $node->childNodes as $node2 )
                                    {
                                        if( $node2->nodeType != XML_ELEMENT_NODE ) continue;
                                        $appName4 = $node2->nodeName;

                                        $serviceName = DH::findFirstElement('fpc4:Name', $node2);

                                        $find = array("{", "}");
                                        $storagename = str_replace($find, "", $serviceName->textContent);


                                        if( isset($serviceObjectArray[$storagename]) )
                                        {

                                            print "  - add service object: " . $serviceObjectArray[$storagename]->name() . "\n";
                                            $tmp_rule->services->add($serviceObjectArray[$storagename]);
                                        }
                                        else
                                        {
                                            $serviceMissingObjects[$storagename] = $storagename;
                                        }
                                    }
                                }
                                elseif( $storagename == "UserSets" )
                                {
                                    print_xml_info( $node );

                                    foreach( $node->childNodes as $node2 )
                                    {
                                        if( $node2->nodeType != XML_ELEMENT_NODE ) continue;
                                        $appName4 = $node2->nodeName;

                                        $serviceName = DH::findFirstElement('fpc4:Name', $node2);

                                        $find = array("{", "}");
                                        $storagename = str_replace($find, "", $serviceName->textContent);

                                        if( isset($userObjectArray[$storagename]) )
                                        {

                                            if( $userObjectArray[$storagename] != "All Users" )
                                            {
                                                print "  - add user object: " . $userObjectArray[$storagename] . "\n";
                                                #$tmp_rule->services->add($userObjectArray[$storagename]);
                                                $tmp_rule->userID_setUsers( $userObjectArray[$storagename] );
                                            }

                                        }
                                        else
                                        {
                                            $userMissingObjects[$storagename] = $storagename;
                                        }
                                    }
                                }
                                elseif( $storagename == "URLSet" || $storagename == "URLSets" )
                                {
                                    //Todo:

                                    //found from RULE:
                                    /*
                                    <fpc4:Refs StorageName="URLSet" StorageType="1">
                                        <fpc4:Ref StorageName="{8573C1D4-0453-4C06-8AA2-2B32BA3A1D3A}" StorageType="1">
                                            <fpc4:Name dt:dt="string">{3F27106C-5AA3-4CCE-A35C-E728D53F153F}</fpc4:Name>
                                            <fpc4:RefClass dt:dt="string">msFPCURLSet</fpc4:RefClass>
                                        </fpc4:Ref>
                                    </fpc4:Refs>


                                    <fpc4:Refs StorageName="URLSet" StorageType="1">
                                        <fpc4:Ref StorageName="{8462C043-42A8-4B93-A813-80DECFF58DC4}" StorageType="1">
                                            <fpc4:Name dt:dt="string">{E4419EEC-5C6D-4ED3-8265-58D97F870BD6}</fpc4:Name>
                                            <fpc4:RefClass dt:dt="string">msFPCURLSet</fpc4:RefClass>
                                        </fpc4:Ref>
                                    </fpc4:Refs>
                                    <fpc4:Refs StorageName="UserSets" StorageType="1">
                                        <fpc4:Ref StorageName="{97A79AFC-F07B-4614-A78C-B899F6BEBDF4}" StorageType="1">
                                            <fpc4:Name dt:dt="string">{DFFB7833-9365-4184-AABC-7CAFB018A7FA}</fpc4:Name>
                                            <fpc4:RefClass dt:dt="string">msFPCUserSet</fpc4:RefClass>
                                            <fpc4:Scope dt:dt="int">1</fpc4:Scope>
                                        </fpc4:Ref>
                                    </fpc4:Refs>
                                     */


                                    foreach( $node->childNodes as $node2 )
                                    {
                                        if( $node2->nodeType != XML_ELEMENT_NODE ) continue;
                                        $appName4 = $node2->nodeName;

                                        #print "SVEN2\n";
                                        print_xml_info( $node2 );

                                        $serviceName = DH::findFirstElement('fpc4:Name', $node2);

                                        $find = array("{", "}");
                                        $storagename = str_replace($find, "", $serviceName->textContent);

                                        #print "search for:|".$storagename."|\n";

                                        if( isset($addressObjectArray[$storagename]) )
                                        {

                                            print "  - add destination object: " . $addressObjectArray[$storagename]->name() . "\n";
                                            $tmp_rule->destination->addObject($addressObjectArray[$storagename]);

                                            if( isset( $missingURL[ $storagename ] ) )
                                            {
                                                print "  * clone Security Rule, remove all DST IP, add custom URL category with all URL:\n";
                                                print_r( $missingURL[ $storagename ] );
                                                //set profiles custom-url-category test list sven.waschkut.de

                                                $cloned_rule = $tmp_rule->owner->cloneRule( $tmp_rule );
                                                $cloned_rule->destination->setAny();

                                                $tmp_custome_url_profile = $v->customURLProfileStore->newCustomSecurityProfileURL( $addressObjectArray[$storagename]->name() );


                                                foreach( $missingURL[$storagename]['missing'] as $custom )
                                                {
                                                    print "set profiles custome-url-category ".$addressObjectArray[$storagename]->name()." list ".$custom."\n";
                                                    $tmp_custome_url_profile->addMember( $custom );
                                                }

                                                print "set rulebase security rules ".$cloned_rule->name()." category ".$addressObjectArray[$storagename]->name()."\n";

                                            }

                                        }
                                        else
                                        {
                                            $addressMissingObjects['destination'][$storagename] = $storagename;
                                        }
                                    }
                                }
                                elseif( $storagename == "URLSets" )
                                {

                                }
                                elseif( $storagename == "UrlCategory" )
                                {

                                    /*
                                <fpc4:UrlCategories StorageName="UrlCategories" StorageType="0">
                                    <fpc4:UrlCategory StorageName="{013899fa-1734-428f-b7dd-8609efd7ccb8}" StorageType="2">
                                        <fpc4:CategoryId dt:dt="int">32</fpc4:CategoryId>
                                        <fpc4:Description dt:dt="string">Malicious Web sites covertly install applications onto targeted systems with the intent of causing harm to people or property through use of unauthorized computer activity.</fpc4:Description>
                                        <fpc4:Name dt:dt="string">Malicious</fpc4:Name>
                                    </fpc4:UrlCategory>
                                     */
                                    //found from RULE
                                    /*
                                    <fpc4:Refs StorageName="UrlCategory" StorageType="1">
                                        <fpc4:Ref StorageName="{8EE17585-EC13-4932-A5C4-C7094CFCDB98}" StorageType="1">
                                            <fpc4:Name dt:dt="string">{013899fa-1734-428f-b7dd-8609efd7ccb8}</fpc4:Name>
                                            <fpc4:RefClass dt:dt="string">msFPCUrlCategory</fpc4:RefClass>
                                            <fpc4:Scope dt:dt="int">1</fpc4:Scope>
                                        </fpc4:Ref>
                                        <fpc4:Ref StorageName="{22F14637-F6FB-4A1A-A12A-AA800B3F477E}" StorageType="1">
                                            <fpc4:Name dt:dt="string">{e1079988-6b06-4e8c-bf8c-5288af8918a9}</fpc4:Name>
                                            <fpc4:RefClass dt:dt="string">msFPCUrlCategory</fpc4:RefClass>
                                            <fpc4:Scope dt:dt="int">1</fpc4:Scope>
                                        </fpc4:Ref>
                                        <fpc4:Ref StorageName="{B95F1B16-3489-4A88-80DC-A4CC6713D73C}" StorageType="1">
                                            <fpc4:Name dt:dt="string">{e8dfdee6-5d60-4753-b3e7-ea0e17852f99}</fpc4:Name>
                                            <fpc4:RefClass dt:dt="string">msFPCUrlCategory</fpc4:RefClass>
                                            <fpc4:Scope dt:dt="int">1</fpc4:Scope>
                                        </fpc4:Ref>
                                    </fpc4:Refs>
                                    */
                                }
                                elseif( $storagename == "UrlCategorySet" )
                                {

                                }
                                elseif( $storagename == "DestinationDomainNameSets" )
                                {
                                    /*
                                    <fpc4:DomainNameSet StorageName="{2A205761-B3D0-4F7F-959E-335B72E8AB8F}" StorageType="1">
                                        <fpc4:Description dt:dt="string">Toevoegingen i.v.m. GOVCERT AO/MvS/9050</fpc4:Description>
                                        <fpc4:DomainNameStrings>
                                            <fpc4:Str dt:dt="string">*.2228.org</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.3322.org</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.8800.org</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.athersite.com</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.fw.nu</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.pass.as</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.redirect.hm</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.rr.nu</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.thegloriousdead.com</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.taggingapp.com</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.from-gunergs.ru</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.oak-tureght.ru</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.nationwidedownload.com</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.postnl-tracktrace.net</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.postnl-tracking.net</fpc4:Str>
                                            <fpc4:Str dt:dt="string">*.postnl-track.net</fpc4:Str>
                                        </fpc4:DomainNameStrings>
                                        <fpc4:Name dt:dt="string">GOVCERT AO/MvS/9050</fpc4:Name>
                                    </fpc4:DomainNameSet>
                                     */

                                    //found from RULE
                                    /*
                                     <fpc4:Refs StorageName="DestinationDomainNameSets" StorageType="1">
                                        <fpc4:Ref StorageName="{18437F06-9E8B-4A4C-8104-9285D7B44D6E}" StorageType="1">
                                            <fpc4:Name dt:dt="string">{2A205761-B3D0-4F7F-959E-335B72E8AB8F}</fpc4:Name>
                                            <fpc4:RefClass dt:dt="string">msFPCDomainNameSet</fpc4:RefClass>
                                        </fpc4:Ref>
                                    </fpc4:Refs>
                                     */

                                    print_xml_info( $node );

                                    foreach( $node->childNodes as $node2 )
                                    {
                                        if( $node2->nodeType != XML_ELEMENT_NODE ) continue;
                                        $appName4 = $node2->nodeName;

                                        $serviceName = DH::findFirstElement('fpc4:Name', $node2);

                                        $find = array("{", "}");
                                        $storagename = str_replace($find, "", $serviceName->textContent);

                                        if( isset($addressObjectArray[$storagename]) )
                                        {

                                            print "  - add destination object: " . $addressObjectArray[$storagename]->name() . "\n";
                                            $tmp_rule->destination->addObject($addressObjectArray[$storagename]);

                                            if( isset( $missingURL[ $storagename ] ) )
                                            {
                                                print "  * clone Security Rule, remove all DST IP, add custom URL category with all URL:\n";
                                                print_r( $missingURL[ $storagename ] );
                                                //set profiles custom-url-category test list sven.waschkut.de

                                                $cloned_rule = $tmp_rule->owner->cloneRule( $tmp_rule );
                                                $cloned_rule->destination->setAny();

                                                foreach( $missingURL[$storagename]['missing'] as $custom )
                                                {
                                                    print "set profiles custome-url-category ".$addressObjectArray[$storagename]->name()." list ".$custom."\n";
                                                }

                                                print "set rulebase security rules ".$cloned_rule->name()." category ".$addressObjectArray[$storagename]->name()."\n";

                                            }
                                        }
                                        else
                                        {
                                            $addressMissingObjects['destination'][$storagename] = $storagename;
                                        }
                                    }
                                }
                                else
                                {
                                    #print "SVEN1\n";
                                    print_xml_info( $node );
                                }

                            }
                            else
                            {
                                #print_xml_info( $node, true );
                                //<fpc4:ProtocolSelectionMethod xmlns:fpc4="http://schemas.microsoft.com/isa/config-4" xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">1</fpc4:ProtocolSelectionMethod>
                            }
                        }

                        /*
                        //DESTINATION
                        $destinationRoot = DH::findFirstElement('fpc4:SelectionIPs', $AccessProperties);
                        if( $destinationRoot != null )
                            getIPaddresses( $destinationRoot, $tmp_rule, "destination" );
                        */

                    }

                }
            }
            else
            {
                print_xml_info( $appx2 );
            }
        }
    }
}

function getIPaddresses( $xml, $tmp_rule, $srcdst )
{
    global $addressObjectArray;
    global $addressMissingObjects;

        foreach( $xml->childNodes as $refs )
        {
            if( $refs->nodeType != XML_ELEMENT_NODE ) continue;

            print_xml_info( $refs );

            foreach( $refs->childNodes as $refs3 )
            {
                if( $refs3->nodeType != XML_ELEMENT_NODE ) continue;

                print_xml_info( $refs3 );


                $name = DH::findFirstElement('fpc4:Name', $refs3);
                $refClass = DH::findFirstElement('fpc4:RefClass', $refs3);


                $find = array("{","}");
                $storagename = str_replace($find, "", $name->textContent);

                #print "search for object: ".$storagename."\n";

                if( isset( $addressObjectArray[ $storagename ] ) )
                {

                    if( $srcdst == "source" )
                    {
                        print "  - add source object: ".$addressObjectArray[ $storagename ]->name()."\n" ;
                        $tmp_rule->source->addObject( $addressObjectArray[ $storagename ] );
                    }

                    elseif( $srcdst == "destination" )
                    {
                        print "  - add destination object: ".$addressObjectArray[ $storagename ]->name()."\n" ;
                        $tmp_rule->destination->addObject( $addressObjectArray[ $storagename ] );
                    }

                }
                else
                {
                    $addressMissingObjects[$srcdst][ $storagename ] = $storagename;
                }
            }
        }
    #}

}

print "\n\n\n";
print "MISSING addressObjects:\n";
print_r( $addressMissingObjects );

print "MISSING serviceObjects:\n";
print_r( $serviceMissingObjects );

print "MISSING usrObjects:\n";
print_r( $userMissingObjects );

print "MISSING policyGroup Objects:\n";
print_r( $policyGroupMissingObjects );

function addressObjects( $appx2, $appName2 = null, $addressgroup = null )
{
    global $v;
    global $addressObjectArray;

    foreach( $appx2->childNodes as $appx3 )
    {
        if( $appx3->nodeType != XML_ELEMENT_NODE ) continue;

        $storagename = DH::findAttribute('StorageName', $appx3);
        $description = DH::findFirstElement('fpc4:Description', $appx3 );
        $name = DH::findFirstElement('fpc4:Name', $appx3 );

        if( $name !== FALSE )
        {
            #print "NAME: |".$name->textContent."|\n";
            $name = $name->textContent;
        }

        if( $description !== FALSE )
        {
            #print "Description: |".$description->textContent."|\n";
            $description = $description->textContent;
            $description = strip_hidden_chars( $description );
        }
        else
            $description = "";


        if( $storagename !== FALSE )
        {
            $find = array("{","}");
            $storagename = str_replace($find, "", $storagename);
            #print "STORAGE: |".$storagename."|\n";
        }



        if( $appName2 == "fpc4:Computers" )
        {
            $ipAddress = DH::findFirstElement('fpc4:IPAddress', $appx3);
            if( $ipAddress !== FALSE )
            {
                #print "IP: |" . $ipAddress->textContent . "|\n";
                $value = $ipAddress->textContent;
                $type = "ip-netmask";
            }

        }
        elseif( $appName2 == "fpc4:AddressRanges" )
        {
            $ipFrom = DH::findFirstElement('fpc4:IPFrom', $appx3 );
            $ipTo = DH::findFirstElement('fpc4:IPTo', $appx3 );

            if( $ipFrom !== FALSE && $ipTo !== FALSE )
                $value = $ipFrom->textContent."-".$ipTo->textContent;

            $type = "ip-range";
        }
        elseif( $appName2 == "fpc4:Subnets" )
        {
            $ipAddress = DH::findFirstElement('fpc4:IPAddress', $appx3 );
            $ipMask = DH::findFirstElement('fpc4:IPMask', $appx3 );

            if( $ipMask !== FALSE )
            {
                #print "IPMask: |".$ipMask->textContent."|\n";
                $ipMask = $ipMask->textContent;
                $ipMask = CIDR::netmask2cidr( $ipMask );
            }

            $value = $ipAddress->textContent."/".$ipMask;
            $type = "ip-netmask";
        }

        $name = truncate_names(normalizeNames($name));

        $name_prefix = str_replace( "fpc4:", "", $appName2);

        $tmp_address = $v->addressStore->find( $name_prefix."-".$name );
        if( $tmp_address == null )
        {
            print "   - create address object: ".$name_prefix."-".$name." value: ".$value."\n";
            $tmp_address = $v->addressStore->newAddress( $name_prefix."-".$name, $type, $value );
            $tmp_address->setDescription( $description );

            $addressObjectArray[ $storagename ] = $tmp_address;

        }
        else
        {
            if( get_class( $tmp_address ) !== "AddressGroup" )
            {
                //object available, compare value
                if( $tmp_address->value() != $value )
                {
                    print "   - create address object: ".$name_prefix."-".$name."-".$value." value: ".$value."\n";
                    $tmp_address = $v->addressStore->newAddress( $name_prefix."-".$name."-".$value, $type, $value );
                    $tmp_address->setDescription( $description );

                    $addressObjectArray[ $storagename ] = $tmp_address;
                    mwarning( "Object: ".$tmp_address->name(). " with different value: ".$tmp_address->value()." compare to ".$value."\n" );
                }
            }
        }

        if( $addressgroup != null && $tmp_address != null )
        {
            print "     - add address: ".$tmp_address->name()." to addressgroup: ".$addressgroup->name()."\n";
            $addressgroup->addMember( $tmp_address );
        }
    }
}

function getNetConfig( $networks )
{
    global $v;
    global $addressObjectArray;

    foreach( $networks->childNodes as $node )
    {
        if( $node->nodeType != XML_ELEMENT_NODE ) continue;

        print_xml_info( $node );

        $name = DH::findFirstElement('fpc4:Name', $node);
        $storagename = DH::findAttribute('StorageName', $node);
        $description = DH::findFirstElement('fpc4:Description', $node );

        if( $name !== FALSE )
        {
            #print "NAME: |".$name->textContent."|\n";
            $name = $name->textContent;
        }

        if( $description !== FALSE )
        {
            #print "Description: |".$description->textContent."|\n";
            $description = $description->textContent;
            $description = strip_hidden_chars( $description );
        }
        else
            $description = "";

        if( $storagename !== FALSE )
        {
            $find = array("{","}");
            $storagename = str_replace($find, "", $storagename);
            #print "STORAGE: |".$storagename."|\n";
        }

        $name = truncate_names(normalizeNames($name));

        $tmp_addressgroup = $v->addressStore->find( "g-".$name );
        if( $tmp_addressgroup == null )
        {
            print "   - create addressgroup: g-".$name."\n";
            $tmp_addressgroup = $v->addressStore->newAddressGroup( "g-".$name );
            $tmp_addressgroup->setDescription( $description );

            $addressObjectArray[ $storagename ] = $tmp_addressgroup;
        }



        $ipRangeSet = DH::findFirstElement('fpc4:IpRangeSet', $node);

        if( $ipRangeSet != null )
        {
            foreach( $ipRangeSet->childNodes as $ipRange )
            {
                if( $ipRange->nodeType != XML_ELEMENT_NODE ) continue;

                print_xml_info( $ipRange );

                $ipFrom = DH::findFirstElement('fpc4:IPFrom', $ipRange );
                $ipTo = DH::findFirstElement('fpc4:IPTo', $ipRange );

                if( $ipFrom !== FALSE && $ipTo !== FALSE )
                    $value = $ipFrom->textContent."-".$ipTo->textContent;

                $type = "ip-range";

                $name = truncate_names(normalizeNames($value));

                $name_prefix = str_replace( "fpc4:", "", "fpc4:IpRangeSet" );

                $tmp_address = $v->addressStore->find( $name_prefix."-".$name );
                if( $tmp_address == null )
                {
                    print "    - create address object: ".$name_prefix."-".$name."\n";
                    $tmp_address = $v->addressStore->newAddress( $name_prefix."-".$name, $type, $value );
                }

                if( $tmp_address != null )
                {
                    print "   - add to addressgroup: ".$tmp_addressgroup->name()."\n";
                    $tmp_addressgroup->addMember( $tmp_address );
                }

            }
        }

    }
}


function getNetworkRules( $nat )
{

    global $v;
    global $addressObjectArray;

    foreach( $nat->childNodes as $node )
    {
        if( $node->nodeType != XML_ELEMENT_NODE ) continue;

        print_xml_info($node );

        $name = DH::findFirstElement('fpc4:Name', $node);
        $storagename = DH::findAttribute('StorageName', $node);
        $description = DH::findFirstElement('fpc4:Description', $node);
        $enabled = DH::findFirstElement('fpc4:Enabled', $node);

        if( $name !== FALSE )
        {
            #print "NAME: |".$name->textContent."|\n";
            $name = $name->textContent;

            //Todo: NAT rule name must be optimized
            $name = truncate_names(normalizeNames( $name ));

            $tmp_natrule = $v->natRules->newNatRule($name);
            print "\n * create NATRule: " . $name . "\n";
        }


        if( $storagename !== FALSE )
        {
            $find = array("{", "}");
            $storagename = str_replace($find, "", $storagename);
            #print "STORAGE: |".$storagename."|\n";
        }
        /*
        <fpc4:NetworkRule StorageName="{3D7F8D7E-23B3-42ba-83D0-2E6FC5420FFE}" StorageType="1">
            <fpc4:Enabled dt:dt="boolean">1</fpc4:Enabled>
            <fpc4:Name dt:dt="string">Local Host Access</fpc4:Name>
            <fpc4:Order dt:dt="bin.hex">0000000000000000</fpc4:Order>
            <fpc4:Predefined dt:dt="boolean">1</fpc4:Predefined>
            <fpc4:RoutingType dt:dt="int">0</fpc4:RoutingType>



            <fpc4:SelectionIPs StorageName="SourceSelectionIPs" StorageType="1">
                <fpc4:Refs StorageName="Networks" StorageType="1">
                    <fpc4:Ref StorageName="{98E31493-37BB-44F9-9745-5B11C0DA3F30}" StorageType="1">
                        <fpc4:Name dt:dt="string">{5ED77DCE-8110-4821-B445-008B7E6B7F6D}</fpc4:Name>
                        <fpc4:RefClass dt:dt="string">msFPCNetwork</fpc4:RefClass>
                    </fpc4:Ref>
                </fpc4:Refs>
            </fpc4:SelectionIPs>



            <fpc4:SelectionIPs StorageName="DestinationSelectionIPs" StorageType="1">
                <fpc4:Refs StorageName="NetworkSets" StorageType="1">
                    <fpc4:Ref StorageName="{11C28BB6-2773-47B6-ABE3-AFF2EBBF09C8}" StorageType="1">
                        <fpc4:Name dt:dt="string">{18d0438b-5144-4362-b79e-742712513729}</fpc4:Name>
                        <fpc4:RefClass dt:dt="string">msFPCNetworkSet</fpc4:RefClass>
                    </fpc4:Ref>
                </fpc4:Refs>
            </fpc4:SelectionIPs>


            <fpc4:IPAddresses StorageName="HidingAddresses" StorageType="1">
                <fpc4:IPAddressesStrings>
                    <fpc4:Str dt:dt="string">145.21.148.129</fpc4:Str>
                </fpc4:IPAddressesStrings>
            </fpc4:IPAddresses>


        </fpc4:NetworkRule>
         */
        foreach( $node->childNodes as $node1 )
        {
            if( $node1->nodeType != XML_ELEMENT_NODE ) continue;
            $appName3 = $node1->nodeName;

            if( $appName3 == "fpc4:SelectionIPs" )
            {
                $storagename = DH::findAttribute('StorageName', $node1);

                if( $storagename == "SourceSelectionIPs" )
                {
                    print_xml_info( $node1 );

                    $refs = DH::findFirstElement('fpc4:Refs', $node1);

                    foreach( $refs->childNodes as $node2 )
                    {
                        if( $node2->nodeType != XML_ELEMENT_NODE ) continue;
                        $appName4 = $node2->nodeName;

                        $name = DH::findFirstElement('fpc4:Name', $node2);

                        $find = array("{", "}");
                        $storagename = str_replace($find, "", $name->textContent);

                        print_xml_info( $node2 );

                        #print "search for object: ".$storagename."\n";

                        if( isset($addressObjectArray[$storagename]) )
                        {
                            print "  - add source object: " . $addressObjectArray[$storagename]->name() . "\n";
                            $tmp_natrule->source->addObject($addressObjectArray[$storagename]);
                        }
                        else
                        {
                            $addressMissingObjects['source'][$storagename] = $storagename;
                        }
                    }
                }
                elseif( $storagename == "DestinationSelectionIPs" )
                {
                    //check if Source or destination
                    print_xml_info( $node1 );

                    $refs = DH::findFirstElement('fpc4:Refs', $node1);

                    foreach( $refs->childNodes as $node2 )
                    {
                        if( $node2->nodeType != XML_ELEMENT_NODE ) continue;
                        $appName4 = $node2->nodeName;

                        $name = DH::findFirstElement('fpc4:Name', $node2);

                        $find = array("{", "}");
                        $storagename = str_replace($find, "", $name->textContent);

                        print_xml_info( $node2 );

                        #print "search for object: ".$storagename."\n";

                        if( isset($addressObjectArray[$storagename]) )
                        {
                            print "  - add destination object: " . $addressObjectArray[$storagename]->name() . "\n";
                            $tmp_natrule->destination->addObject($addressObjectArray[$storagename]);
                        }
                        else
                        {
                            $addressMissingObjects['source'][$storagename] = $storagename;
                        }
                    }
                }
            }
            elseif( $appName3 == "fpc4:IPAddresses" )
            {
                $IPAddressesStrings = DH::findFirstElement('fpc4:IPAddressesStrings', $node1);
                $Str = DH::findFirstElement('fpc4:Str', $IPAddressesStrings);

                if( $Str != False )
                {
                    $nat_string = $Str->textContent;
                    $name = truncate_names(normalizeNames($nat_string));

                    $tmp_address1 = $v->addressStore->all( 'value string.regex /'.$nat_string.'/' );
                    if( $tmp_address1 == null )
                    {
                        $name_prefix = str_replace( "fpc4:", "", $appName3);

                        $tmp_address1 = $v->addressStore->find( $name_prefix."-".$name );
                        if( $tmp_address1 == null )
                        {
                            $tmp_address1 = $v->addressStore->newAddress( $name_prefix."-".$name, 'ip-netmask', $nat_string);
                        }
                    }

                    $tmp_natrule->snathosts->addObject($tmp_address1);
                    $tmp_natrule->changeSourceNAT('dynamic-ip-and-port');
                }
            }
        }
    }
}

function print_xml_info( $appx3, $print = false )
{
    $appName3 = $appx3->nodeName;

    if( $print )
        print "|13:|" . $appName3 . "\n";

    $newdoc = new DOMDocument;
    $node = $newdoc->importNode($appx3, TRUE);
    $newdoc->appendChild($node);
    $html = $newdoc->saveHTML();

    if( $print )
        print "|" . $html . "|\n";
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

print "\n\n************ END OF TMG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
