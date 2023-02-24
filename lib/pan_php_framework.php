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

if( PHP_MAJOR_VERSION <= 5 && PHP_MINOR_VERSION <= 4 )
    die("\n*** ERROR **** PAN-OS-PHP requires PHP version >= 5.5\n");
#elseif( PHP_MAJOR_VERSION == 8 && PHP_MINOR_VERSION > 1 )
    #die("\n*** ERROR **** PAN-OS-PHP requires PHP version <= 8.1\n");

set_time_limit(0);
ini_set("memory_limit", "14512M");
error_reporting(E_ALL);
gc_enable();

// For Web apps, STDIN/ERR are not prepopulated
if( !defined('STDIN') )
{
    define('STDIN', fopen('php://stdin', 'r'));
}
if( !defined('STDOUT') )
{
    define('STDOUT', fopen('php://stdout', 'w'));
}
if( !defined('STDERR') )
{
    define('STDERR', fopen('php://stderr', 'w'));
}


if( !defined('XML_PARSE_BIG_LINES') )
{
    define('XML_PARSE_BIG_LINES', 4194304);
}

//check if Device timezone is correctly used after loading the config
date_default_timezone_set('UTC');

if( !extension_loaded('curl') )
{
    if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
    {
        dl('php_curl.dll');
    }
    else
    {
        dl('curl.so');
    }
}
if( !extension_loaded('xml') )
{
    if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
    {
        dl('php_xml.dll');
    }
    else
    {
        dl('xml.so');
    }
}
if( !extension_loaded('dom') )
{
    if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
    {
        dl('php_dom.dll');
    }
    else
    {
        dl('dom.so');
    }
}


/**
 *
 * @ignore
 */
function show_backtrace($str)
{
    PH::print_stdout("\nBacktrace\n: $str" );
    var_dump(debug_backtrace());
}

/**
 *
 * @ignore
 */
function memory_and_gc($str)
{
    $before = memory_get_usage(TRUE);
    gc_enable();
    $gcs = gc_collect_cycles();
    $after = memory_get_usage(TRUE);

    PH::print_stdout( "Memory usage at the $str : " . convert($before) . ". After GC: " . convert($after) . " and freed $gcs variables" );
}

function myErrorHandler($errno, $errstr, $errfile, $errline)
{
    if( $errno == E_USER_NOTICE || $errno == E_USER_WARNING || $errno == E_WARNING || $errno == E_NOTICE )
    {
        derr("Died on user notice or warning!! Error: {$errstr} on {$errfile}:{$errline}\n");
    }
    return FALSE; //Will trigger PHP's default handler if reaches this point.
}


set_error_handler('myErrorHandler');

register_shutdown_function('my_shutdown');


function my_shutdown()
{
    PH::$ignoreDestructors = TRUE;
    gc_disable();
}

$basedir = dirname(__FILE__);

require_once $basedir . '/../phpseclib/Math/BigInteger.php';

require_once $basedir . '/ErrorReporter.php';
require_once $basedir . '/classes/taskManagement/TaskReporter.php';
require_once $basedir . '/classes/taskManagement/ExpeditionTaskReporter.php';
require_once $basedir . '/classes/taskManagement/FileTaskReporter.php';

require_once $basedir . '/../git-php/src/IRunner.php';
require_once $basedir . '/../git-php/src/Runners/CliRunner.php';
require_once $basedir . '/../git-php/src/Runners/MemoryRunner.php';
require_once $basedir . '/../git-php/src/CommandProcessor.php';
require_once $basedir . '/../git-php/src/Commit.php';
require_once $basedir . '/../git-php/src/CommitId.php';
require_once $basedir . '/../git-php/src/Helpers.php';
require_once $basedir . '/../git-php/src/exceptions.php';
require_once $basedir . '/../git-php/src/RunnerResult.php';
require_once $basedir . '/../git-php/src/GitRepository.php';
require_once $basedir . '/../git-php/src/Git.php';


require_once $basedir . '/misc-classes/trait/ReferenceableObject.php';
require_once $basedir . '/misc-classes/trait/XmlConvertible.php';
require_once $basedir . '/misc-classes/trait/ObjectWithDescription.php';
require_once $basedir . '/misc-classes/trait/PathableName.php';
require_once $basedir . '/misc-classes/DH.php';
require_once $basedir . '/misc-classes/PH.php';

require_once $basedir . '/misc-classes/RQuery.php';
require_once $basedir . '/misc-classes/RQueryContext.php';
require_once $basedir . '/misc-classes/AddressRQueryContext.php';
require_once $basedir . '/misc-classes/ApplicationRQueryContext.php';
require_once $basedir . '/misc-classes/RuleRQueryContext.php';
require_once $basedir . '/misc-classes/ServiceRQueryContext.php';
require_once $basedir . '/misc-classes/TagRQueryContext.php';
require_once $basedir . '/misc-classes/ZoneRQueryContext.php';
require_once $basedir . '/misc-classes/ScheduleRQueryContext.php';

require_once $basedir . '/misc-classes/ThreatRQueryContext.php';

require_once $basedir . '/misc-classes/InterfaceRQueryContext.php';
require_once $basedir . '/misc-classes/RoutingRQueryContext.php';
require_once $basedir . '/misc-classes/VirtualWireRQueryContext.php';

require_once $basedir . '/misc-classes/SecurityProfileRQueryContext.php';
require_once $basedir . '/misc-classes/SecurityProfileGroupRQueryContext.php';

require_once $basedir . '/misc-classes/DeviceRQueryContext.php';

require_once $basedir . '/misc-classes/DHCPRQueryContext.php';
require_once $basedir . '/misc-classes/CertificateRQueryContext.php';


require_once $basedir . '/misc-classes/CsvParser.php';
require_once $basedir . '/misc-classes/trait/PanSubHelperTrait.php';
require_once $basedir . '/misc-classes/PanAPIConnector.php';


require_once $basedir . '/helper-classes/IP4Map.php';
require_once $basedir . '/helper-classes/ServiceDstPortMapping.php';
require_once $basedir . '/helper-classes/ServiceSrcPortMapping.php';
require_once $basedir . '/helper-classes/cidr.php';

require_once $basedir . '/container-classes/ObjRuleContainer.php';
require_once $basedir . '/container-classes/ZoneRuleContainer.php';
require_once $basedir . '/container-classes/TagRuleContainer.php';
require_once $basedir . '/container-classes/AppRuleContainer.php';
require_once $basedir . '/container-classes/AddressRuleContainer.php';
require_once $basedir . '/container-classes/ServiceRuleContainer.php';
require_once $basedir . '/container-classes/UrlCategoryRuleContainer.php';

require_once $basedir . '/object-classes/ObjStore.php';
require_once $basedir . '/object-classes/TagStore.php';
require_once $basedir . '/object-classes/AppStore.php';
require_once $basedir . '/object-classes/AddressStore.php';
require_once $basedir . '/object-classes/ServiceStore.php';
require_once $basedir . '/object-classes/Tag.php';
require_once $basedir . '/object-classes/App.php';
require_once $basedir . '/object-classes/AppCustom.php';
require_once $basedir . '/object-classes/AppFilter.php';
require_once $basedir . '/object-classes/AppGroup.php';
require_once $basedir . '/object-classes/trait/AddressCommon.php';
require_once $basedir . '/object-classes/trait/centralAddressStore.php';
require_once $basedir . '/object-classes/trait/centralAddressStoreUser.php';
require_once $basedir . '/object-classes/Address.php';
require_once $basedir . '/object-classes/AddressGroup.php';
require_once $basedir . '/object-classes/Region.php';
require_once $basedir . '/object-classes/trait/ServiceCommon.php';
require_once $basedir . '/object-classes/trait/centralServiceStore.php';
require_once $basedir . '/object-classes/trait/centralServiceStoreUser.php';
require_once $basedir . '/object-classes/trait/ServiceCommon.php';
require_once $basedir . '/object-classes/Service.php';
require_once $basedir . '/object-classes/ServiceGroup.php';

require_once $basedir . '/object-classes/ThreatStore.php';
require_once $basedir . '/object-classes/Threat.php';
require_once $basedir . '/object-classes/ThreatVulnerability.php';
require_once $basedir . '/object-classes/ThreatSpyware.php';

require_once $basedir . '/object-classes/ScheduleStore.php';
require_once $basedir . '/object-classes/Schedule.php';

require_once $basedir . '/object-classes/SecurityProfileStore.php';
require_once $basedir . '/object-classes/SecurityProfileGroupStore.php';
require_once $basedir . '/object-classes/SecurityProfileGroup.php';
require_once $basedir . '/object-classes/SecurityProfile.php';
require_once $basedir . '/object-classes/URLProfile.php';
require_once $basedir . '/object-classes/AntiVirusProfile.php';
require_once $basedir . '/object-classes/VulnerabilityProfile.php';
require_once $basedir . '/object-classes/AntiSpywareProfile.php';
require_once $basedir . '/object-classes/FileBlockingProfile.php';
require_once $basedir . '/object-classes/DataFilteringProfile.php';
require_once $basedir . '/object-classes/WildfireProfile.php';
require_once $basedir . '/object-classes/customURLProfile.php';
require_once $basedir . '/object-classes/PredefinedSecurityProfileURL.php';

require_once $basedir . '/object-classes/VirusAndWildfireProfile.php';
require_once $basedir . '/object-classes/DNSSecurityProfile.php';
require_once $basedir . '/object-classes/SaasSecurityProfile.php';

require_once $basedir . '/object-classes/DecryptionProfile.php';

require_once $basedir . '/object-classes/Profile.php';
require_once $basedir . '/object-classes/HipObjectsProfile.php';
require_once $basedir . '/object-classes/HipProfilesProfile.php';

require_once $basedir . '/object-classes/GTPProfile.php';
require_once $basedir . '/object-classes/SCEPProfile.php';
require_once $basedir . '/object-classes/PacketBrokerProfile.php';
require_once $basedir . '/object-classes/SDWanErrorCorrectionProfile.php';
require_once $basedir . '/object-classes/SDWanPathQualityProfile.php';
require_once $basedir . '/object-classes/SDWanSaasQualityProfile.php';
require_once $basedir . '/object-classes/SDWanTrafficDistributionProfile.php';
require_once $basedir . '/object-classes/DataObjectsProfile.php';

require_once $basedir . '/device-and-system-classes/VirtualSystem.php';
require_once $basedir . '/device-and-system-classes/PANConf.php';
require_once $basedir . '/device-and-system-classes/PanoramaConf.php';
require_once $basedir . '/device-and-system-classes/DeviceGroup.php';
require_once $basedir . '/device-and-system-classes/Template.php';
require_once $basedir . '/device-and-system-classes/TemplateStack.php';
require_once $basedir . '/device-and-system-classes/ManagedDevice.php';
require_once $basedir . '/device-and-system-classes/ManagedDeviceStore.php';
require_once $basedir . '/device-and-system-classes/LogCollectorGroup.php';

require_once $basedir . '/device-and-system-classes/FawkesConf.php';
require_once $basedir . '/device-and-system-classes/Container.php';
require_once $basedir . '/device-and-system-classes/DeviceCloud.php';
require_once $basedir . '/device-and-system-classes/DeviceOnPrem.php';

require_once $basedir . '/device-and-system-classes/BuckbeakConf.php';
require_once $basedir . '/device-and-system-classes/Snippet.php';

require_once $basedir . '/device-and-system-classes/Sub.php';

require_once $basedir . '/network-classes/trait/InterfaceType.php';
require_once $basedir . '/network-classes/Zone.php';
require_once $basedir . '/network-classes/ZoneStore.php';
require_once $basedir . '/network-classes/InterfaceContainer.php';
require_once $basedir . '/network-classes/VirtualRouterContainer.php';
require_once $basedir . '/network-classes/StaticRoute.php';
require_once $basedir . '/network-classes/VirtualRouter.php';
require_once $basedir . '/network-classes/VirtualRouterStore.php';
require_once $basedir . '/network-classes/DHCP.php';
require_once $basedir . '/network-classes/DHCPStore.php';
require_once $basedir . '/network-classes/NetworkPropertiesContainer.php';
require_once $basedir . '/network-classes/IPsecTunnelStore.php';
require_once $basedir . '/network-classes/IPsecTunnel.php';
require_once $basedir . '/network-classes/GreTunnelStore.php';
require_once $basedir . '/network-classes/GreTunnel.php';
require_once $basedir . '/network-classes/LoopbackIfStore.php';
require_once $basedir . '/network-classes/LoopbackInterface.php';
require_once $basedir . '/network-classes/EthernetInterface.php';
require_once $basedir . '/network-classes/EthernetIfStore.php';
require_once $basedir . '/network-classes/TmpInterface.php';
require_once $basedir . '/network-classes/TmpInterfaceStore.php';
require_once $basedir . '/network-classes/AggregateEthernetInterface.php';
require_once $basedir . '/network-classes/AggregateEthernetIfStore.php';
require_once $basedir . '/network-classes/IkeCryptoProfileStore.php';
require_once $basedir . '/network-classes/IkeCryptoProfil.php';
require_once $basedir . '/network-classes/IPSecCryptoProfileStore.php';
require_once $basedir . '/network-classes/IPSecCryptoProfil.php';
require_once $basedir . '/network-classes/IKEGatewayStore.php';
require_once $basedir . '/network-classes/IKEGateway.php';
require_once $basedir . '/network-classes/VlanIfStore.php';
require_once $basedir . '/network-classes/VlanInterface.php';
require_once $basedir . '/network-classes/TunnelIfStore.php';
require_once $basedir . '/network-classes/TunnelInterface.php';
require_once $basedir . '/network-classes/VirtualWire.php';
require_once $basedir . '/network-classes/VirtualWireStore.php';

require_once $basedir . '/network-classes/Certificate.php';
require_once $basedir . '/network-classes/CertificateStore.php';


require_once $basedir . '/rule-classes/RuleStore.php';
require_once $basedir . '/rule-classes/Rule.php';
require_once $basedir . '/rule-classes/trait/NegatableRule.php';
require_once $basedir . '/rule-classes/trait/RulewithLogging.php';
require_once $basedir . '/rule-classes/RuleWithUserID.php';
require_once $basedir . '/rule-classes/RuleWithSchedule.php';
require_once $basedir . '/rule-classes/SecurityRule.php';
require_once $basedir . '/rule-classes/NatRule.php';
require_once $basedir . '/rule-classes/DecryptionRule.php';
require_once $basedir . '/rule-classes/AppOverrideRule.php';
require_once $basedir . '/rule-classes/CaptivePortalRule.php';
require_once $basedir . '/rule-classes/AuthenticationRule.php';
require_once $basedir . '/rule-classes/PbfRule.php';
require_once $basedir . '/rule-classes/QoSRule.php';
require_once $basedir . '/rule-classes/DoSRule.php';
require_once $basedir . '/rule-classes/TunnelInspectionRule.php';
require_once $basedir . '/rule-classes/DefaultSecurityRule.php';
require_once $basedir . '/rule-classes/NetworkPacketBrokerRule.php';
require_once $basedir . '/rule-classes/SDWanRule.php';

if( isset( $_SERVER['REQUEST_METHOD'] ) )
{
    $argv = array();
    $argc = 0;
}
$tmp_ph = new PH($argv, $argc);
PH::$basedir = $basedir;

unset($basedir);


function &array_diff_no_cast(&$ar1, &$ar2)
{
    $diff = array();
    foreach( $ar1 as $key => $val1 )
    {
        if( array_search($val1, $ar2, TRUE) === FALSE )
        {
            $diff[$key] = $val1;
        }
    }
    return $diff;
}


function &array_unique_no_cast(&$ar1)
{
    $unique = array();
    foreach( $ar1 as $val1 )
    {
        if( array_search($val1, $unique, TRUE) === FALSE )
            $unique[] = $val1;
    }

    return $unique;
}

/**
 *
 * @ignore
 */
function &searchForName($fname, $id, &$array)
{
    // $fname : is field name
    // $id : the value you are looking for
    $null = null;

    if( $array === null )
        derr('Array cannot be null');

    $c = count($array);
    $k = array_keys($array);


    for( $i = 0; $i < $c; $i++ )
    {
        if( isset($array[$k[$i]][$fname]) && $array[$k[$i]][$fname] === $id )
        {
            return $array[$i];
        }
    }
    return $null;

}


/**
 *
 * @ignore
 */
function clearA(&$a)
{
    if( !is_array($a) )
    {
        derr("This is not an array\n");
    }
    $c = count($a);
    $k = array_keys($a);

    for( $i = 0; $i < $c; $i++ )
    {
        unset($a[$k[$i]]);
    }
}


function removeElement(&$o, &$arr)
{
    $pos = array_search($o, $arr, TRUE);

    if( $pos === FALSE )
        return;

    unset($arr[$pos]);
}


/**
 * to be used only on array of objects
 *
 */
function &insertAfter(&$arradd, &$refo, &$arr)
{
    $new = array();

    $cadd = count($arradd);
    $kadd = array_keys($arradd);

    $c = count($arr);
    $k = array_keys($arr);

    for( $i = 0; $i < $c; $i++ )
    {
        $new[] = &$arr[$k[$i]];

        if( $arr[$k[$i]] === $refo )
        {
            for( $iadd = 0; $iadd < $cadd; $iadd++ )
            {
                $new[] = $arradd[$kadd[$iadd]];
            }
        }
    }

    return $new;
}

/**
 *
 * @param ReferenceableObject[] $arr
 *
 * @ignore
 */
function reLinkObjs(&$arr, &$ref)
{
    foreach( $arr as $object )
    {
        $object->addReference($ref);
    }
}


function convert($size, &$array = array())
{
    if( $size == 0 )
        return '0';
    elseif( $size < 0 )
    {
        $returnValue = '0 b';
        $array = explode( " ", $returnValue );
        return $returnValue;
    }

    $unit = array('b', 'kb', 'mb', 'gb', 'tb', 'pb');

    $var = 1024;
    $var = 1000;
    $returnValue = @round($size / pow($var, ($i = floor(log($size, $var)))), 2) . ' ' . $unit[$i];
    $array = explode( " ", $returnValue );
    return $returnValue;
}


function &cloneArray(&$old)
{
    $new = array();

    $c = count($old);
    $k = array_keys($old);

    for( $i = 0; $i < $c; $i++ )
    {
        if( is_array($old[$k[$i]]) )
        {
            if( isset($old[$k[$i]]['name']) && $old[$k[$i]]['name'] == 'ignme' )
                continue;
            $new[$k[$i]] = cloneArray($old[$k[$i]]);
        }
        else
            $new[$k[$i]] = $old[$k[$i]];
    }

    return $new;
}

function __CmpObjName($objA, $objB)
{
    return strcmp($objA->name(), $objB->name());
}

function __CmpObjMemID($objA, $objB)
{
    return strcmp(spl_object_hash($objA), spl_object_hash($objB));
}


/*function __RemoveObjectsFromArray( &$arrToRemove, &$originalArray)
{
	$indexes = Array();
	
	foreach( $originalArray as $i:$o )
	{
		//$indexes[spl_object_hash($o)] = $i;
	}
	
	
	unset($indexes);
}*/


function printn($msg)
{
    PH::print_stdout( $msg );
}


function lastIndex(&$ar)
{
    end($ar);


    return key($ar);
}

/**
 * Stops script with an error message and a backtrace
 * @param string $msg error message to display
 * @param DOMNode $object
 * @throws Exception
 */
function derr($msg, $object = null, $print_backtrace = TRUE)
{
    if( $object !== null )
    {
        $class = get_class($object);
        if( $class == 'DOMNode' || $class == 'DOMElement' || is_subclass_of($object, 'DOMNode') )
        {
            $msg .= "\nXML line #" . $object->getLineNo() . ", XPATH: " . DH::elementToPanXPath($object) . "\n" . DH::dom_to_xml($object, 0, TRUE, 3);
        }
    }

    if( PH::$useExceptions )
    {
        $ex = new Exception($msg);
        throw $ex;
    }

    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
        fwrite(STDERR, PH::boldText("\n* ** ERROR ** * ") . $msg . "\n\n");



    if( $print_backtrace )
    {
        backtrace_print();
    }

    if( PH::$shadow_json )
    {
        PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
        print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );

    }


    exit(1);
}


function derr_print( $string )
{
    PH::$JSON_OUTlog .= $string;
    if( !PH::$shadow_json )
        fwrite(STDERR, $string);
}

function backtrace_print()
{
    $d = debug_backtrace();

    $skip = 0;

    $string = " *** Backtrace ***\n";
    derr_print( $string );

    $count = 0;

    foreach( $d as $l )
    {
        if( $skip >= 0 )
        {
            $string = "$count ****\n";
            derr_print( $string );

            if( isset($l['object']) && method_exists($l['object'], 'toString') )
            {
                $string = '   ' . $l['object']->toString() . "\n";
                derr_print( $string );
            }

            $file = '';
            if( isset($l['file']) )
                $file = $l['file'];
            $line = '';
            if( isset($l['line']) )
                $line = $l['line'];

            if( isset($l['object']) )
            {
                $string = '       ' . PH::boldText($l['class'] . '::' . $l['function'] . "()") . " @\n           {$file} line {$line}\n";
                derr_print( $string );
            }
            else
            {
                $string = "       " . PH::boldText($l['function']) . "()\n       ::{$file} line {$line}\n";
                derr_print( $string );
            }
        }
        $skip++;
        $count++;
    }
}

/**
 * Prints a debug message along with a backtrace, program can continue normally.
 *
 */
function mdeb($msg)
{
    global $PANC_DEBUG;

    if( !isset($PANC_DEBUG) || $PANC_DEBUG != 1 )
        return;

    fwrite(STDERR, "\n*DEBUG*" . $msg . "\n");

    //debug_print_backtrace();

    $d = debug_backtrace();

    $skip = 0;

    fwrite(STDERR, " *** Backtrace ***\n");

    foreach( $d as $l )
    {
        if( $skip >= 0 )
        {
            if( $skip == 0 && isset($l['object']) )
            {
                fwrite(STDERR, $l['object']->toString() . "\n");
            }

            $file = '';
            if( isset($l['file']) )
                $file = $l['file'];
            $line = '';
            if( isset($l['line']) )
                $line = $l['line'];

            if( isset($l['object']) )
                fwrite(STDERR, '       ' . PH::boldText($l['class'] . '::' . $l['function'] . "()") . " @\n           {$file} line {$line}\n");
            else
                fwrite(STDERR, "       " . PH::boldText($l['function']) . "()\n       ::{$file} line {$line}\n");
        }
        $skip++;
    }

    fwrite(STDERR, "\n\n");
}

/**
 * @param string $msg
 * @param null|DOMNode|DOMElement $object
 * @throws Exception
 */
function mwarning($msg, $object = null, $print_backtrace = TRUE, $print_object = TRUE)
{
    if( !PH::$PANC_WARN )
        return;

    if( $object !== null )
    {
        $class = get_class($object);
        if( $class == 'DOMNode' || $class == 'DOMElement' || is_subclass_of($object, 'DOMNode') )
        {
            $msg .= "\n"."XML line #" . $object->getLineNo() . ", XPATH: " . DH::elementToPanXPath($object);
            if( $print_object )
                $msg .= "\n". DH::dom_to_xml($object, 0, TRUE, 3);
        }
    }

    if( PH::$useExceptions )
    {
        $ex = new Exception($msg);
        throw $ex;
    }

    if( PH::$shadow_json )
    {
        if( isset(PH::$JSON_OUT['warning']) )
        {
            PH::$JSON_OUT['warning'][] = $msg;
        }
        else
            PH::$JSON_OUT['warning'][0] = $msg;
    }

    else
        fwrite(STDERR, PH::boldText("* ** WARNING ** * ") . $msg . "\n\n");


    if( $print_backtrace )
    {
        backtrace_print();

        $string = "\n";
        derr_print( $string );
    }

}


/**
 *
 * @ignore
 */
function boolYesNo($bool)
{
    if( $bool )
        return 'yes';

    return 'no';
}

function yesNoBool($yes)
{
    $yes = strtolower($yes);
    if( $yes == 'yes' )
        return TRUE;
    if( $yes == 'no' )
        return FALSE;

    derr("unsupported value '$yes' given");
}

/**
 * @param $object
 * @return PanAPIConnector|null
 */
function findConnector($object)
{
    if( isset($object->connector) )
        return $object->connector;

    if( !isset($object->owner) )
        return null;

    if( $object->owner === null )
        return null;

    return findConnector($object->owner);
}

/**
 * @param $object
 * @return PanAPIConnector|null
 */
function findConnectorOrDie($object)
{
    if( isset($object->connector) )
        return $object->connector;

    if( !isset($object->owner) )
        derr("cannot find API connector");

    if( $object->owner === null )
        derr("cannot find API connector");

    return findConnectorOrDie($object->owner);
}


function &array_to_devicequery(&$devices)
{
    $dvq = '';

    $first = TRUE;

    foreach( $devices as &$device )
    {

        if( !$first )
            $dvq .= ' or ';

        $vsysl = '';

        $nfirst = TRUE;
        foreach( $device['vsyslist'] as &$vsys )
        {
            if( !$nfirst )
                $vsysl .= ' or ';

            $vsysl .= "(vsys eq $vsys)";

            $nfirst = FALSE;
        }

        $dvq .= " ((serial eq " . $device['serial'] . ") and ($vsysl)) ";

        $first = FALSE;
    }

    return $dvq;
}


function &sortArrayByStartValue(&$arrayToSort)
{
    //
    // Sort incl objects IP mappings by Start IP
    //
    //PH::print_stdout(  "\n   * Sorting incl obj by StartIP" );
    $returnMap = array();
    $tmp = array();
    foreach( $arrayToSort as &$incl )
    {
        $tmp[$incl['start']][] = $incl;
    }
    unset($incl);
    ksort($tmp, SORT_NUMERIC);
    foreach( $tmp as $start => &$ends )
    {
        foreach( $ends as &$end )
        {
            $returnMap[] = $end;
        }
    }

    return $returnMap;
}



