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

require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

#PH::print_stdout();
#PH::print_stdout("***********************************************");
#PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
#PH::print_stdout();

#PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$displayAttributeName = false;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file1'] = Array('niceName' => 'file1', 'shortHelp' => 'orig file');
$supportedArguments['file2'] = Array('niceName' => 'file1', 'shortHelp' => 'new file');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );

PH::processCliArgs();

##########################################
##########################################

########################################################################################################################

//file1
if( !isset(PH::$args['file1']) )
    $util->display_error_usage_exit('"file1" is missing from arguments');
$file1 = PH::$args['file1'];
if( !file_exists($file1) )
    derr( "FILE: ". $file1. " not available", null, false);
if( !is_string($file1) || strlen($file1) < 1 )
    $util->display_error_usage_exit('"file1" argument is not a valid string');

#PH::print_stdout( "Opening ORIGINAL '{$file1}' XML file... ");
$doc1 = new DOMDocument();
if( $doc1->load($file1) === FALSE )
    derr('Error while parsing xml:' . libxml_get_last_error()->message , null, false);


//file2
if( !isset(PH::$args['file2']) )
    $util->display_error_usage_exit('"file2" is missing from arguments');
$file2 = PH::$args['file2'];
if( !file_exists($file2) )
    derr( "FILE: ". $file2. " not available", null, false);
if( !is_string($file2) || strlen($file2) < 1 )
    $util->display_error_usage_exit('"file1" argument is not a valid string');

#PH::print_stdout( "Opening COMPARE '{$file2}' XML file... ");
$doc2 = new DOMDocument();
if( $doc2->load($file2) === FALSE )
    derr('Error while parsing xml:' . libxml_get_last_error()->message, null, false);

########################################################################################################################

//preparation

//Todo: this must be done for file1 and file2

//load empty FW config file
$argv = array();
$argc = array();
PH::$args = array();
PH::$argv = array();

$argv[] = basename(__FILE__);
#$argv[] = "in=".dirname(__FILE__)."/panos_baseconfig.xml";
$argv[] = "in=".dirname(__FILE__)."/panorama_baseconfig.xml";

$util = new UTIL( "custom", $argv, $argc, __FILE__);

$util->utilInit();

##########################################
##########################################

$util->load_config();
#$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;

if( $util->configType == 'panos' )
    $sub = $pan->findVirtualSystem('vsys1');
elseif( $util->configType == 'panorama' )
    $sub = $pan->createDeviceGroup( "diff");

$candidateConfig = $util->pan->xmldoc;
########################################################################################################################

PH::print_stdout();
#$sub->display_statistics();

########################################################################################################################

if( $util->configType == 'panorama' )
{
    PH::print_stdout( "###################################################");
    PH::print_stdout( "unused objects from FILE1");
    $sub = $pan->createDeviceGroup( "diff1");
    display_unused( $doc1, $sub );

    PH::print_stdout( "###################################################");

    PH::print_stdout( "unused objects from FILE2");
    $sub = $pan->createDeviceGroup( "diff2");
    display_unused( $doc2, $sub );

    PH::print_stdout( "###################################################");
}







//load xpath:
// - /policy/panorama/address
// - /policy/panorama/address-group
// - /policy/panorama/pre-rulebase
// - /policy/panorama/post-rulebase

// get information about unused address objects

########################################################################################################################
PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################

function debugDisplayXML( $element)
{
    $doc2 = new DOMDocument();
    $node = $doc2->importNode($element, true);
    $doc2->appendChild($node);
    PH::print_stdout( $doc2->saveXML( $doc2->documentElement) );
    PH::print_stdout( "");
}

function saveXML( $element, $filename)
{
    $doc2 = new DOMDocument();
    $node = $doc2->importNode($element, true);
    $doc2->appendChild($node);

    $doc2->save( $filename );
    #PH::print_stdout( $doc2->saveXML( $doc2->documentElement) );
}

function display_unused( $doc1, $sub )
{
    /** @var DeviceGroup $sub */

    //find xpath: /policy/panorama
    $doc1policy = DH::findFirstElement( "policy", $doc1);
    if( $doc1policy !== FALSE )
    {
        #debugDisplayXML( $doc1policy );
        $doc1panorama = DH::findFirstElement( "panorama", $doc1policy);

        if( $doc1panorama !== FALSE )
        {
            $doc1address = DH::findFirstElement( "address", $doc1panorama);
            if( $doc1address !== FALSE )
            {
                #debugDisplayXML( $doc1address );
                $sub->addressStore->load_addresses_from_domxml( $doc1address );
            }
            $doc1address = DH::findFirstElement( "address-group", $doc1panorama);
            if( $doc1address !== FALSE )
            {
                #debugDisplayXML( $doc1address );
                $sub->addressStore->load_addressgroups_from_domxml($doc1address);
            }

            /*
            $doc1rulebase = DH::findFirstElement( "pre-rulebase", $doc1panorama);
            if( $doc1rulebase !== FALSE )
            {
                $doc1rulebaseSecurity = DH::findFirstElement( "security", $doc1rulebase);
                if( $doc1rulebaseSecurity !== FALSE )
                    $sub->securityRules->load_from_domxml( $doc1rulebaseSecurity);
            }
            $doc1rulebase = DH::findFirstElement( "post-rulebase", $doc1panorama);
            if( $doc1rulebase !== FALSE )
            {
                $doc1rulebaseSecurity = DH::findFirstElement( "security", $doc1rulebase);
                if( $doc1rulebaseSecurity !== FALSE )
                    $sub->securityRules->load_from_domxml( $doc1rulebaseSecurity);
            }
            */


            //
            // Extracting policies
            //
            $prerulebase = DH::findFirstElement('pre-rulebase', $doc1panorama);
            $postrulebase = DH::findFirstElement('post-rulebase', $doc1panorama);

            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('security', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('security', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->securityRules->load_from_domxml($tmp, $tmpPost);

            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('nat', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('nat', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->natRules->load_from_domxml($tmp, $tmpPost);


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('decryption', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('decryption', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->decryptionRules->load_from_domxml($tmp, $tmpPost);


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('application-override', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('application-override', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->appOverrideRules->load_from_domxml($tmp, $tmpPost);


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('captive-portal', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('captive-portal', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->captivePortalRules->load_from_domxml($tmp, $tmpPost);


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('authentication', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('authentication', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->authenticationRules->load_from_domxml($tmp, $tmpPost);


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('pbf', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('pbf', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->pbfRules->load_from_domxml($tmp, $tmpPost);


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('qos', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('qos', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->qosRules->load_from_domxml($tmp, $tmpPost);


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('dos', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('dos', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->dosRules->load_from_domxml($tmp, $tmpPost);//


            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement('tunnel-inspect', $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('tunnel-inspect', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->tunnelInspectionRules->load_from_domxml($tmp, $tmpPost);//


            //default-security-Rules are only available on POST
            if( $prerulebase === FALSE )
                $tmp = null;
            else
                $tmp = null;
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement('default-security-rules', $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->defaultSecurityRules->load_from_domxml($tmp, $tmpPost);

            //network-packet-broker
            $xmlTagName = "network-packet-broker";
            $var = "networkPacketBrokerRules";
            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement($xmlTagName, $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement($xmlTagName, $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->$var->load_from_domxml($tmp, $tmpPost);

            //network-packet-broker
            $xmlTagName = "sdwan";
            $var = "sdWanRules";
            if( $prerulebase === FALSE )
                $tmp = null;
            else
            {
                $tmp = DH::findFirstElement($xmlTagName, $prerulebase);
                if( $tmp !== FALSE )
                    $tmp = DH::findFirstElement('rules', $tmp);

                if( $tmp === FALSE )
                    $tmp = null;
            }
            if( $postrulebase === FALSE )
                $tmpPost = null;
            else
            {
                $tmpPost = DH::findFirstElement($xmlTagName, $postrulebase);
                if( $tmpPost !== FALSE )
                    $tmpPost = DH::findFirstElement('rules', $tmpPost);

                if( $tmpPost === FALSE )
                    $tmpPost = null;
            }
            $sub->$var->load_from_domxml($tmp, $tmpPost);
            //
            // end of policies extraction
            //
        }

        #$sub->display_statistics();

        foreach( $sub->addressStore->all() as $o )
        {
            if( $o->countReferences() == 0 )
            {
                $object = $o;
                if( $object->isGroup() )
                {
                    if( $object->isDynamic() )
                    {
                        $tag_string = "";
                        if( count($object->tags->tags()) > 0 )
                        {
                            $toStringInline = $object->tags->toString_inline();
                            TAG::revertreplaceNamewith( $toStringInline );
                            $tag_string = "tag: '".$toStringInline."'";
                        }


                        $tmpFilter = $object->filter;
                        TAG::revertreplaceNamewith( $tmpFilter );
                        PH::print_stdout( "* " . get_class($object) . " '{$object->name()}' (DYNAMIC)  ({$object->count()} members)  desc: '{$object->description()}' $tag_string filter: '{$tmpFilter}" );
                    }
                    else
                    {
                        PH::print_stdout( "* " . get_class($object) . " '{$object->name()}' ({$object->count()} members)   desc: '{$object->description()}'" );
                    }

                    foreach( $object->members() as $member )
                    {
                        if( $member->isAddress() )
                        {
                            PH::print_stdout( "          - {$member->name()}  value: '{$member->value()}'" );
                        }
                        else
                            PH::print_stdout( "          - {$member->name()}" );
                    }
                }
                elseif( $object->isAddress() )
                {
                    $tag_string = "";
                    if( count($object->tags->tags()) > 0 )
                    {
                        $toStringInline = $object->tags->toString_inline();
                        TAG::revertreplaceNamewith( $toStringInline );
                        $tag_string = "tag: '".$toStringInline."'";
                    }
                    PH::print_stdout( "* " . get_class($object) . " '{$object->name()}'  type: '{$object->type()}'  value: '{$object->value()}'  desc: '{$object->description()}' IPcount: '{$object->getIPcount()}' $tag_string" );
                }
                elseif( $object->isRegion() )
                {
                    PH::print_stdout( "* " . get_class($object) . " '{$object->name()}'  " );
                }
            }

        }

    }
}