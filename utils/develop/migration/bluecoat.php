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


$print = false;

###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ BlueCoat UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");


$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = Array('niceName' => 'FILE', 'shortHelp' => 'BlueCoat config file, export via CLI: ""');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['loadxmlfromfile'] = Array('niceName' => 'loadxmlfromfile', 'shortHelp' => 'do not load from memory, load from newly generated XML file during execution');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=[PAN-OS base config file] file=[PULSE xml config file] [out=]";


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
#$util->location_filter();
#$location = $util->objectsLocation[0];


$location = $util->objectsLocation;

$pan = $util->pan;


print "location: ".$location."\n";

if( $util->configType == 'panos' )
{
    // Did we find VSYS1 ?
    $v = $pan->findVirtualSystem( $location );
    if( $v === null )
        derr( $util->$location." was not found ? Exit\n");
}
elseif( $util->configType == 'panorama' )
{
    $v = $pan->findDeviceGroup( $location );
    if( $v == null )
        $v = $pan->createDeviceGroup( $location );
}
elseif( $util->configType == 'fawkes' )
{
    $v = $pan->findContainer( $location );
    if( $v == null )
        $v = $pan->createContainer( $location );
}


##########################################

//read file to string
#$file_content = file( $file ) or die("Unable to open file!");
$content = file_get_contents( $file );




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
//FIND OBJECTS - Bluecoat

$policy = array();


#$content = strip_hidden_chars( $content );
#$content = test_input($content);
#print "|".$content."|\n";

/*
if( preg_match_all('/^!- BEGIN policy(.*?)^!- END policy(.*?)$/ms', $content, $output_array) )
{
    #print_r( $output_array );
    $policy = $output_array;
}

if( !isset( $policy[0] ) )
    derr( "nothing found" );
*/

function strpos_all($haystack, $needle) {
    $offset = 0;
    $allpos = array();
    while (($pos = strpos($haystack, $needle, $offset)) !== FALSE) {
        $offset   = $pos + 1;
        $allpos[] = $pos;
    }
    return $allpos;
}

#$pos_begin = strpos_all($content, "!- BEGIN policy") ;
$pos_begin = strpos_all($content, "<vpmapp>") ;

$pos_end = strpos_all($content, "</vpmapp>");

$xml = substr( $content, $pos_begin[0], $pos_end[0]+9-$pos_begin[0] );
$xml = utf8_encode( $xml );
$xml = preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $xml);
file_put_contents($file."_BCorig1.xml", $xml);


#print "|".$xml."|\n";

/*
#foreach( $policy[0] as $subPolicy ){
    if( preg_match_all('#^define (.*?)^end#ms', $string, $output_array) )
    {
        $define = $output_array;
        #print_r( $define[1] );
    }


    if( preg_match_all('#^<vpmapp>(.*?)^</vpmapp>#ms', $string, $output_array) )
    {
        print_r( $output_array[1][0] );
        $xml = "<vpmapp>" . $output_array[1][0] . "</vpmapp>";

    }
*/

    if( empty( $xml ) )
        exit();

    $xmlDoc = new DOMDocument;
    $xmlDoc->preserveWhiteSpace = FALSE;
    $xmlDoc->formatOutput = TRUE;


    if( isset(PH::$args['loadxmlfromfile'])  )
        $xmlDoc->load( $file."_BCorig1.xml" );
    else
        $xmlDoc->loadXML($xml);

    $xmlString = $xmlDoc->saveXML();
    file_put_contents($file."_BCorig2.xml", $xmlString);
    //store bluecoat



    $xmlRoot = $xmlDoc->documentElement;
#$xmlRoot = DH::findFirstElement('vpmapp', $xmlDoc->documentElement);


#print_xml_info($xmlRoot, true);

    foreach( $xmlRoot->childNodes as $childNode )
    {
        #print "NODE: ".$childNode->nodeName."\n";
    }
    /*
    NODE: vpmxml-info
    NODE: enforcement-point
    NODE: conditionObjects
    NODE: layers -> policy
     */

    ///////////////////////////////////////////////////////////////////////////////////////
    $conditionObjects = DH::findFirstElement('conditionObjects', $xmlRoot);

    $nameArray = array();
    foreach( $conditionObjects->childNodes as $childNode )
    {
        if( $childNode->nodeType != XML_ELEMENT_NODE )
            continue;

        #print "NODE: ".$childNode->nodeName."\n";
        $nameArray[$childNode->nodeName] = $childNode->nodeName;
    }
    print_r( $nameArray );

    //exit();

    //a-url
    $aUrlLists = $conditionObjects->getElementsByTagName('a-url');
    //<a-url d="go.microsoft.com" name="RequestURL21" typ="r"></a-url>
    //<a-url name="RequestURL77" r="jetblue\-[a-zA-Z0-9]*\.sharepoint\.com" typ="r"></a-url>
    //<a-url h="timaticweb2.com" h-t="domain" name="http_timaticweb2" p-t="exact-phrase" s="http" typ="r"></a-url>
    //<a-url name="BLOCK_BINEXE" p="bin.exe" p-t="at-end" typ="r"></a-url>
/*
<a-url
h="servicebus.windows.net"
h-t="domain"
name="Citrix_ServiceBus"
p-t="exact-phrase"
typ="r">
</a-url>
*/
    foreach( $aUrlLists as $member )
    {

        $name = $member->getAttribute('name');
        $name = normalizeNames($name);


        //TYPE1
        $dURL = $member->getAttribute('d');
        //this could be also created as address object -> fqdn

        //TYPE2
        $rURL = $member->getAttribute('r');

        //TYPE3
        $hURL = $member->getAttribute('h');
        //$hURL = $member->getAttribute('h-t');
        //$hURL = $member->getAttribute('p-t');
        //$hURL = $member->getAttribute('s');

        //TYPE4
        $pURL = $member->getAttribute('p');
        //$hURL = $member->getAttribute('p-t');



        if( (!empty($dURL) && strpos( $dURL, "*" ) === false ) || ( !empty($hURL) && strpos( $hURL, "*" ) === false ) )
        {
            if( !empty($dURL) )
                $url = $dURL;
            elseif( !empty($hURL) )
                $url = $hURL;

            $tmp_address = $v->addressStore->find($name);
            if( $tmp_address == null )
            {
                #print "create NAME: ".$name." - url: ".$url."\n";
                if( $print )
                    print "- create address: ".$name." -type: fqdn -value: ".$url."\n";
                $tmp_address = $v->addressStore->newAddress($name, 'fqdn', $url);
            }

        }
        elseif( !empty($dURL) || !empty($rURL)  || !empty($pURL) || !empty($hURL) )
        {
            if( !empty($dURL) )
                $url = $dURL;
            elseif( !empty($rURL) )
                $url = $rURL;
            elseif( !empty($hURL) )
                $url = $hURL;
            elseif( !empty($pURL) )
                $url = $pURL;

            $tmp_custome_url_profile = $v->customURLProfileStore->newCustomSecurityProfileURL($name);
            $tmp_custome_url_profile->addMember($url);
        }
        else
            print_xml_info($member, TRUE);
    }

    //ipobject
    $ipobjectLists = $conditionObjects->getElementsByTagName('ipobject');
    //<ipobject name="__Client IP Address/Subnet208" single="true" type="1" value="10.20.128.64">
    //</ipobject>
    foreach( $ipobjectLists as $member )
    {
        $name = $member->getAttribute('name');
        $name = normalizeNames($name);
        $value = $member->getAttribute('value');

        $tmp_address = $v->addressStore->find($name);
        if( $tmp_address == null )
        {
            if( strpos( $value, "-" ) !== false )
                $type = "ip-range";
            else
                $type = "ip-netmask";

            if( $print )
                print "- create address: ".$name." -type: ".$type." -value: ".$value."\n";
            $tmp_address = $v->addressStore->newAddress($name, $type, $value);
        }


        #print_xml_info($member, true);
    }

    //conditionObjects><vpm-cat>
    $vpm_cat = DH::findFirstElement('vpm-cat', $conditionObjects);
    $ipobjectLists = $vpm_cat->getElementsByTagName('node');
    foreach( $ipobjectLists as $member )
    {
        $name = $member->getAttribute('n');
        $name = normalizeNames($name);
        $value = $member->getAttribute('u-l');

        $tmp_array = explode("\n", $value);
        #$valueArray = explode( "&#10;", $value );
        //n="OKTA_IPs" u-l="3.12.225.63/32

        //Todo: continue integration/migrating this
        #print "NAME: ".$name."\n";
        #print_r( $tmp_array );

        $tmp_addressgroup = $v->addressStore->find($name);
        if( $tmp_addressgroup == null )
        {
            if( $print )
                print "- create addressgroup: ".$name."\n";
            $tmp_addressgroup = $v->addressStore->newAddressGroup($name);
        }

        foreach( $tmp_array as $memberOBJ )
        {
            if( empty($memberOBJ) )
                continue;

            $memberOBJArray = explode( ";", $memberOBJ );
            $memberOBJ = $memberOBJArray[0];
            $memberOBJ = str_replace( " ", "", $memberOBJ);

            $ip = explode( "/", $memberOBJ );

            if(filter_var($ip[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || filter_var($ip[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
            {
                $tmpName = str_replace( "/", "m", $memberOBJ);
                $tmp_address = $v->addressStore->find( $tmpName);
                if( $tmp_address === null )
                {
                    if( $print )
                        print "- create address: ".$tmpName." -type: ip-netmask -value: ".$memberOBJ."\n";
                    $tmp_address = $v->addressStore->newAddress($tmpName, 'ip-netmask', $memberOBJ);
                    if( isset( $memberOBJArray[1] ) )
                        $tmp_address->setDescription( str_replace( " ", "",$memberOBJArray[1]) );
                }

                if( $print )
                    print "- add to addressgroup: ".$name." - ".$tmpName."\n";
                $tmp_addressgroup->addMember( $tmp_address );
            }
            elseif( strpos( $memberOBJ, "*" ) === false )
            {
                $tmp_address = $v->addressStore->find( $memberOBJ);
                if( $tmp_address === null )
                {
                    if( $print )
                        print "- create address: ".$memberOBJ." -type: fqdn -value: ".$memberOBJ."\n";
                    $tmp_address = $v->addressStore->newAddress($memberOBJ, 'fqdn', $memberOBJ);
                    if( isset( $memberOBJArray[1] ) )
                        $tmp_address->setDescription( str_replace( " ", "",$memberOBJArray[1]) );
                }

                if( $print )
                    print "- add to addressgroup: ".$name." - ".$memberOBJ."\n";
                $tmp_addressgroup->addMember( $tmp_address );
            }
            else
            {
                /** @var PanConf $v */
                $tmp_custome_url_profile = $v->customURLProfileStore->find( $name );
                if( $tmp_custome_url_profile === null )
                {
                    if( $print )
                        print "- create customURL: ".$name."\n";
                    $tmp_custome_url_profile = $v->customURLProfileStore->newCustomSecurityProfileURL( $name );
                }

                if( $print )
                    print "- add to customURL: ".$name." - ".$memberOBJ."\n";
                $tmp_custome_url_profile->addMember( $memberOBJ );
            }
        }

        #print_xml_info($member, true);

    }
#exit();

    //[comb-obj] => comb-obj => using ipobject and a-url
    $ipobjectLists = $conditionObjects->getElementsByTagName('comb-obj');
    foreach( $ipobjectLists as $member )
    {
        //<comb-obj d="" n-1="false" n-2="false" name="MicrosoftUpdate" t="2">
        $name = $member->getAttribute('name');
        $name = normalizeNames($name);



        $tmp_addressgroup = $v->addressStore->find($name);
        if( $tmp_addressgroup == null )
        {
            if( $print )
                print "- create addressgroup: ".$name."\n";
            $tmp_addressgroup = $v->addressStore->newAddressGroup($name);
        }

        if( $tmp_addressgroup->isAddress() )
        {
            print "NAME is Adress but group needed: ".$tmp_addressgroup->name()."\n";
            continue;
        }


        $memberlist = $member->getElementsByTagName('c-l-1');
        foreach( $memberlist as $member2 )
        {
            $member_name = $member2->getAttribute('n');
            $member_name = normalizeNames($member_name);


            $tmp_address = $v->addressStore->find($member_name);
            if( $tmp_address != null )
            {
                if( $print )
                    print "   - add member: ".$member_name."\n";
                $tmp_addressgroup->addMember( $tmp_address );
            }

            else
            {
                #if( $print )
                    print "   X addressgroup: ".$name." - member: ".$member_name." not found\n";
                    #print_xml_info($member2, true);
            }

            #print_xml_info($member2, true);
        }

    }

    //[proxy] => comb-obj => using ipobject and a-url
    #<proxy ip-address="172.15.214.103" name="__Proxy_172_22_114_103_P1080" port="1080"></proxy>
    $ipobjectLists = $conditionObjects->getElementsByTagName('proxy');
    foreach( $ipobjectLists as $member )
    {
        #print_xml_info($member, true);
        #exit();


        $name = $member->getAttribute('name');
        $name = normalizeNames($name);
        $value = $member->getAttribute('ip-address');

        $port = $member->getAttribute('port');

        $tmp_address = $v->addressStore->find($name);
        if( $tmp_address == null && !empty( $value ) )
        {
            if( strpos( $value, "-" ) !== false )
                $type = "ip-range";
            else
                $type = "ip-netmask";

            if( $print )
                print "- create address: ".$name." -type: ".$type." -value: ".$value."\n";
            $tmp_address = $v->addressStore->newAddress($name, $type, $value);
        }

        $tmp_service = $v->serviceStore->find($name);
        if( $tmp_service == null )
        {
            $tmp_address = $v->serviceStore->newService( $name, "tcp", $port );
        }

    }

    /*
    [comb-obj] => comb-obj => using ipobject and a-url
    [app-url] => app-url    => appid??????
    [categorylist4] => categorylist4

    [ret-redir] => ret-redir // redirection on url? supported? I do not think so
                <ret-redir
                name="ReturnRedirectTimaticweb2"
                r="301"
                v="https://timaticweb2.com">
                </ret-redir>


    [group] => group    // authentication
                    <group
                delimiters="\!!"
                group-base="JB_TCS_Access-SG"
                group-location="jetblue"
                group-prefix="jetblue"
                group-suffix=""
                name="__GROUP3"
                realm-name="JetBlue"
                realm-type="13"
                restrict="false"
                suffix="false"
                user="false">
                </group>

    [htm-ntfy] => htm-ntfy      //html notification => not supported
    [svr-cert] => svr-cert

    [h-o] => h-o
    [af-host] => af-host
    [trace-obj] => trace-obj

    [attribute] => attribute
    [auth-obj] => auth-obj
    [host-port] => host-port
    [proxy] => proxy
    [acc-log-fac] => acc-log-fac
    [dny-exc] => dny-exc
    [svr-cert-valdn] => svr-cert-valdn
    [hdr-obj] => hdr-obj
    [time] => time
    [ssl-fwd-prxy522] => ssl-fwd-prxy522
    [ssl-fwd-prxy] => ssl-fwd-prxy
    [file-download] => file-download
    [appar-data-type] => appar-data-type
    [adm-auth-obj] => adm-auth-obj
    */


    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    $layers = DH::findFirstElement('layers', $xmlRoot);

    //layer
    $layerLists = $layers->getElementsByTagName('layer');
    /*
     <layer layertype="com.bluecoat.sgos.vpm.WebAccessPolicyTable">
        <name>Logging to LEC</name>
        <numRows>1</numRows>
        <rowItem enabled="true" num="0">
            <colItem col="0" id="no" value="1"></colItem>
            <colItem col="1" id="so" name="Any" type="String"></colItem>
            <colItem col="2" id="de" name="Any" type="String"></colItem>
            <colItem col="3" id="se" name="Any" type="String"></colItem>
            <colItem col="5" id="ti" name="Any" type="String"></colItem>
            <colItem col="4" id="ac" name="CombinedAction1" negate="false" type="Condition"></colItem>
            <colItem col="7" id="tr" name="None" type="String"></colItem>
            <colItem col="7" id="ep" name="Appliance" negate="false" type="Condition"></colItem>
            <colItem col="6" id="co" name="" type="String"></colItem>
        </rowItem>
    </layer>
     */


    //Todo: swaschkut 20212021 - continue migrating rules


    foreach( $layerLists as $member )
    {
        $layertype = $member->getAttribute('layertype');

        foreach( $member->childNodes as $child )
        {
            if( $child->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $child->nodeName;

            if( $nodeName === "name" )
            {
                $rulename = strip_hidden_chars($child->textContent );
                $rulename = normalizeNames($rulename);
                print "\n - NAME: ".$rulename." - type: ".$layertype;

            }
            elseif( $nodeName === "numRows" )
            {
                print " - count rows: ".strip_hidden_chars( $child->textContent )."\n";
                if( $layertype === "com.bluecoat.sgos.vpm.WebAccessPolicyTable" )
                    print "|No|Source|Destination|Service|Time|Action|Track|XYZ?|Comment\n";

                elseif( $layertype === "com.bluecoat.sgos.vpm.UserAuthenticationPolicyTable")
                    print "|No|Source|Destination|Action|Track|XYZ?|Comment\n";

                elseif ( $layertype === "com.bluecoat.sgos.vpm.SSLAccessPolicyTable")
                    print "|No|Source|Destination|Service|Action|Track|XYZ?|Comment\n";

                elseif ( $layertype === "com.bluecoat.sgos.vpm.SSLInterceptPolicyTable")
                    print "|No|Source|Destination|Action|Track|XYZ?|Comment\n";
            }
            elseif( $nodeName === "guard" )
            {
                //see below
            }
            elseif( $nodeName === "rowItem" )
            {
                //see below
            }

            #print_xml_info($member, true);
        }

        $guardLists = $member->getElementsByTagName('guard');
        foreach( $guardLists as $key => $rowItem )
        {
            $colItemLists = $rowItem->getElementsByTagName('colItem');
            $rule = "";
            foreach( $colItemLists as $key2 => $colItem )
            {
                //col="5" id="ti" name="Any" type="String">
                $col = $colItem->getAttribute('col');
                $id = $colItem->getAttribute('id');
                $name = $colItem->getAttribute('name');
                $type = $colItem->getAttribute('type');

                $rule .= "|".$name;
            }
            print "GUARD: ".$rule."\n";
        }

        $rowItemLists = $member->getElementsByTagName('rowItem');
        $disabled = false;
        foreach( $rowItemLists as $key => $rowItem )
        {
            $enabled = $rowItem->getAttribute('enabled');
            if( $enabled === "false" )
            {
                #print "DISABLED\n";
                $disabled = true;
            }


            $colItemLists = $rowItem->getElementsByTagName('colItem');
            $rule = "";
            $tmp_rule2 = null;

            foreach( $colItemLists as $key2 => $colItem )
            {
                //col="5" id="ti" name="Any" type="String">
                $col = $colItem->getAttribute('col');
                $id = $colItem->getAttribute('id');
                $name = $colItem->getAttribute('name');
                $name = normalizeNames($name);

                $type = $colItem->getAttribute('type');



                if( $layertype === "com.bluecoat.sgos.vpm.WebAccessPolicyTable" )
                {
                    if( $key2 == 0 )
                    {
                        print "create Rule: ".$rulename."-".$key."\n";
                        $tmp_rule = $v->securityRules->newSecurityRule( $rulename."-".$key);

                        if( $disabled )
                        {
                            print " - Rule: ".$rulename."-".$key." disabled\n";
                            $tmp_rule->setDisabled( true );
                        }

                    }
                    if( $id === 'so' and $name !== "Any" )
                    {
                        $name = normalizeNames($name);

                        $tmp_source = $v->addressStore->find( $name );
                        if( $tmp_source !== null )
                            $tmp_rule->source->addObject( $tmp_source );
                        else
                        {
                            print "rule ".$tmp_rule->name()." source: ".$name." not found\n";
                        }
                    }
                    if( $id === 'de' and $name !== "Any" )
                    {
                        $name = normalizeNames($name);

                        $tmp_source = $v->addressStore->find( $name );
                        if( $tmp_source !== null )
                        {
                            $tmp_rule->destination->addObject( $tmp_source );

                            $tmp_custome_url_profile = $v->customURLProfileStore->find( $name );
                            if( $tmp_custome_url_profile !== null )
                            {

                                $tmp_rule2 = $v->securityRules->cloneRule($tmp_rule, $tmp_rule->name()."URLlist");
                                $tmp_rule2->destination->setAny();
                                $tmp_rule2->setUrlCategories( $tmp_custome_url_profile->name() );
                            }
                        }

                        else
                        {
                            print "rule ".$tmp_rule->name()." destination: ".$name." not found\n";
                        }
                    }

                    if( $id === 'ac' )
                    {
                        print "ACTION: ".$name."\n";
                        $name = normalizeNames($name);
                        print "ACTION2: ".$name."\n";
                        if( $name === "Deny" )
                        {
                            print "   - set Action to DENY\n";
                            $tmp_rule->setAction( "deny" );

                            if( $tmp_rule2 !== null )
                            {
                                $tmp_rule->setAction( "deny" );
                            }
                        }
                    }

                }
                elseif( $layertype === "com.bluecoat.sgos.vpm.WebAccessPolicyTable"
                    || $layertype === "com.bluecoat.sgos.vpm.UserAuthenticationPolicyTable"
                    || $layertype === "com.bluecoat.sgos.vpm.SSLAccessPolicyTable"
                    || $layertype === "com.bluecoat.sgos.vpm.SSLInterceptPolicyTable"
                )
                {
                    if( $name == "")
                        $name = "---";

                    if( $key2 == 0 )
                        $name = $key;


                    $rule .= "|".$name;
                }
                else
                    print "col: ".$col." - id: ".$id." - name: ".$name." - type: ".$type."\n";
                #print_xml_info($colItem, true);
            }
            if( $layertype === "com.bluecoat.sgos.vpm.WebAccessPolicyTable"
                || $layertype === "com.bluecoat.sgos.vpm.UserAuthenticationPolicyTable"
                || $layertype === "com.bluecoat.sgos.vpm.SSLAccessPolicyTable"
                || $layertype === "com.bluecoat.sgos.vpm.SSLInterceptPolicyTable"
            )
                print $rule."\n";

            print "-------------------------------------------\n";
        }

    }




#}
#######################################################


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

function find_string_between($line, $needle1, $needle2 = "--END--")
{
    $needle_length = strlen($needle1);
    $pos1 = strpos($line, $needle1);

    if( $needle2 !== "--END--" )
        $pos2 = strpos($line, $needle2);
    else
        $pos2 = strlen($line);

    $finding = substr($line, $pos1 + $needle_length, $pos2 - ($pos1 + $needle_length));

    return $finding;
}

##################################################################

/*

$configInput = array();
$configInput['type'] = 'file';
$configInput['filename'] = $util->configInput;

CONVERTER::rule_merging( $v, $configInput, true, false, false, "tag", array( "1", "3" ) );
*/

print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF TMG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";


//Todo: bluecoat appid
/*
ABC
Adobe Creative Cloud
Alibaba
Amazon
Amazon Drive
Amazon Prime Video
Ameba
AOL Mail
Apple Update
Ask
Baidu Search
BBC
Bing Search
Blogger
BOL Mail
Box
Break
CBS
Cisco OpenDNS DNS over HTTPS (DoH)
Cisco WebEx
Citrix GoToMeeting
Citrix ShareFile
Classmates
Cloudflare DNS over HTTPS (DoH)
CNN
Craigslist
Cyworld Blog
Dailymotion
Daum Blog
Daum Mail
Digg
Disqus
Dropbox
eBaums World
eBay
ESPN
Etrade
Evernote
Facebook
Facebook Plugins
FC2 Blog
FIFA World Cup
FilesAnywhere
Flickr
Flipkart
Fox Sports
Gamer.com.tw
Gmail
GMX FreeMail
Go.com
Google Cloud Print
Google Drive
Google Hangouts
Google Photos
Google Play Music
Google Public DNS over HTTPS (DoH)
Google Search
GooglePlus
GooglePlus Widgets
Groupon
hi5
Hightail
Hulu
iCloud Mail
Ifeng
Imgur
Indiatimes
Instagram
iTunes Store
Kaixin
Last.fm
LinkedIn
LinkedIn SlideShare
LiveJournal
LiveLeak
LogMeIn
Lycos Search
Mail.com
Mail.ru Mail
MediaFire
MEGA
meinVZ
Metacafe
Microsoft Update
mixi
MLB
Mobile01
Myspace
Nate Mail
Nate Search
Naver Blog
NAVER Cloud
Naver Mail
NBA
NBC
NCAA Mens Basketball Tournament
Netflix
NFL
Niconico
Ning
Office 365 Exchange Online
Office 365 General
Office 365 OneDrive
Office 365 SharePoint
Office 365 Skype for Business
Office 365 Sway
Office 365 Yammer
OK
OpenDrive
Outlook.com
Pandora
Pastebin
PayPal
PChome
Pengyou
Pinterest
Plurk
QQ Mail
QQ Space
Quad9 DNS over HTTPS (DoH)
Rakuten
Rambler.ru Mail
Rambler.ru Search
Reddit
Renren
Scribd
Sina
Sina Weibo
Snapchat
Sogou Search
studiVZ
Stupid Videos
SugarSync
Symantec Live Update
Taobao
Telly
Tencent Weibo
tmall
Tudou
Tumblr
Twitch
Twitter
Twitter Widgets
Typepad
UCloud
Ustream
Veoh
Vimeo
Vine
VK
WEB.DE FreeMail
WEB.DE Online Storage
Webhard
WeTransfer
Wikipedia
WordPress
XFINITY Connect Email
XING
Yahoo Mail
Yahoo Search
Yahoo Web Messenger
Yandex Mail
Yandex Search
Youku
YouTube
Zoom
 */