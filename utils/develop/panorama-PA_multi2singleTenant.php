<?php

/*
 USAGE;
php multiTenant_2singleTenant.php in=caixabank-running-config.xml tenant=Corporatiu out=singleTenant.xml
 */

require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$displayAttributeName = false;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['tenant'] = Array('niceName' => 'tenant', 'shortHelp' => 'specify the tenant you like to keep');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "\"tenant=TENANTname\n".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

$util->load_config();
#$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


########################################################################################################################


if( !isset( PH::$args['tenant'] ) )
{
    //missing part get all available multi tenant and display them
    $availableTenants = array();
    $tenants = findMultiTenant( $util, $availableTenants );

    PH::print_stdout();
    PH::print_stdout( PH::boldText( "available Tenants:" ) );
    foreach( $availableTenants as $tenant )
        PH::print_stdout( " - ".$tenant );

    $util->display_error_usage_exit('"tenant" argument is not set: example "tenant=TENANTname');
}
else
    $tenantToFind = PH::$args['tenant'];

########################################################################################################################

//VARIABLE declaration
$plugins = null;
$cloud_service_node = null;
$cloud_service_version = null;


//get available TENANT name
$availableTenants = array();

$tenants = findMultiTenant( $util, $availableTenants );


foreach( $tenants->childNodes as $entry )
{
    /** @var DOMElement $entry */
    if( $entry->nodeType != XML_ELEMENT_NODE )
        continue;

    $tenantName = DH::findAttribute( "name", $entry );
    $tmp_node = $entry->cloneNode( true);
    $availableTenants[ $tenantName ] = $tenantName;


    if( $tenantName === $tenantToFind )
    {
        renameTemplateDeviceGroup( $pan, $entry );

        $newdoc = new DOMDocument;
        $element = $newdoc->createElement('cloud_services');
        $element->setAttribute("version", $cloud_service_version);
        $newdoc->appendChild($element);

        foreach( $entry->childNodes as $childNode )
        {
            $node = $newdoc->importNode($childNode, true);
            $element->appendChild($node);
        }
    }
    else
    {
        deleteTemplateDeviceGroup( $pan, $entry );
    }

}

if( !isset( $availableTenants[$tenantToFind] ) )
{
    print_r(array_keys($availableTenants));
    derr( "TENANT: ".$tenantToFind." not found in this configuration file!" );
}

//Todo: remove all DG and template which are from the removed other tenantes
// - rename DG and template to the supported once in the migration script

$plugins->removeChild( $cloud_service_node );

$node = $util->xmlDoc->importNode($element, true);
$plugins->appendChild( $node );


//use class
#PH::print_stdout(PH::$JSON_TMP, false, "serials");
PH::$JSON_TMP = array();

$util->save_our_work(TRUE);

$util->endOfScript();

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
function deleteTemplateDeviceGroup( &$pan, $entry )
{
    /** @var PanoramaConf $pan */

    $array = array( 'service-connection', 'mobile-users', 'remote-networks' );
    foreach( $array as $type )
    {
        $xmlNode = DH::findFirstElement( $type, $entry );
        if( $xmlNode !== FALSE )
        {
            $templateStack = DH::findFirstElement( "template-stack", $xmlNode );
            if( $templateStack !== FALSE )
            {
                $stack = $pan->findTemplateStack( $templateStack->textContent );
                if( $stack !== null )
                {
                    PH::print_stdout( "remove TemplateStack: |".$templateStack->textContent."|\n" );
                    $pan->removeTemplateStack( $stack );
                }
                else
                {
                    PH::print_stdout( "TemplateStack: |".$templateStack->textContent."| not found\n" );
                }
            }

            $deviceGroup = DH::findFirstElement( "device-group", $xmlNode );
            if( $deviceGroup !== FALSE )
            {
                $dg = $pan->findDeviceGroup( $deviceGroup->textContent );
                if( $dg !== null )
                {
                    PH::print_stdout( "remove DeviceGroup: |".$deviceGroup->textContent."|\n" );
                    $pan->removeDeviceGroup( $dg );
                }
                else
                {
                    PH::print_stdout( "DeviceGroup: |".$deviceGroup->textContent."| not found\n" );
                }

            }

        }
    }
}
function renameTemplateDeviceGroup( &$pan, $entry )
{
    /** @var PanoramaConf $pan */

    $array = array( 'service-connection', 'mobile-users', 'remote-networks' );
    foreach( $array as $type )
    {
        $xmlNode = DH::findFirstElement( $type, $entry );
        if( $xmlNode !== FALSE )
        {
            $templateStack = DH::findFirstElement( "template-stack", $xmlNode );
            if( $templateStack !== FALSE )
            {
                $name = $templateStack->textContent;
                $stack = $pan->findTemplateStack( $name );
                if( $stack !== null )
                {
                    if( $type == "service-connection" )
                        $newName = "Service_Conn_Template_Stack";
                    elseif( $type == "mobile-users" )
                        $newName = "Mobile_User_Template_Stack";
                    elseif( $type == "remote-networks" )
                        $newName = "Remote_Network_Template_Stack";
                    elseif( $type == "mobile-users-explicit-proxy" )
                        $newName = "Explicit_Proxy_Template_Stack";

                    /*
                     *  if(  $templateStack->name() != "Mobile_User_Template_Stack" &&
                    $templateStack->name() != "Remote_Network_Template_Stack" &&
                    $templateStack->name() != "Service_Conn_Template_Stack" &&
                    $templateStack->name() != "Explicit_Proxy_Template_Stack" )
                     */
                    if( $name !== $newName )
                    {
                        PH::print_stdout("rename TemplateStack: |" . $name . "| to new name: " . $newName . "\n");
                        $stack->setName($newName);
                        $templateStack->textContent = $newName;

                        $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/template-stack', $pan->xmlroot);
                        $DGmetaData = DH::findFirstElementByNameAttrOrDie('entry', $name, $dgMetaDataNode);
                        $DGmetaData->setAttribute("name", $newName);
                    }
                }
                else
                {
                    PH::print_stdout( "TemplateStack: |".$name."| not found\n" );
                }
            }

            $deviceGroup = DH::findFirstElement( "device-group", $xmlNode );
            if( $deviceGroup !== FALSE )
            {
                $name = $deviceGroup->textContent;
                $dg = $pan->findDeviceGroup( $name );
                if( $dg !== null )
                {
                    /*
                     * Remote_Network_Device_Group" || $DG === "Service_Conn_Device_Group
                     */
                    if( $type == "service-connection" )
                        $newName = "Service_Conn_Device_Group";
                    elseif( $type == "mobile-users" )
                        $newName = "Mobile_User_Device_Group";
                    elseif( $type == "remote-networks" )
                        $newName = "Remote_Network_Device_Group";
                    elseif( $type == "mobile-users-explicit-proxy" )
                        $newName = "Explicit_Proxy_Device_Group";

                    if( $name !== $newName )
                    {
                        PH::print_stdout( "rename DeviceGroup: |".$name."| to new name: ".$newName."\n" );
                        $dg->setName( $newName );
                        $deviceGroup->textContent = $newName;

                        $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device-group', $pan->xmlroot);
                        $DGmetaData = DH::findFirstElementByNameAttrOrDie('entry', $name, $dgMetaDataNode);
                        $DGmetaData->setAttribute("name", $newName);
                    }

                }
                else
                {
                    PH::print_stdout( "DeviceGroup: |".$name."| not found\n" );
                }

            }

        }
    }
}

function findMultiTenant( $util, &$availableTenants )
{
    global $plugins;
    global $cloud_service_node;
    global $cloud_service_version;

    $plugin_query = "/config/devices/entry/plugins";

    $panorama_dom = new DOMXPath($util->xmlDoc);

    $entries = $panorama_dom->query($plugin_query);
    $plugins = $entries->item(0);


    if( $plugins == null )
        derr("PLUGin section not found - stop migration!");


    $cloud_service_node = DH::findFirstElement("cloud_services", $plugins);
    if( $cloud_service_node === FALSE )
    {
        derr("cloud_service XML node not found!");
    }


    $cloud_service_version = DH::findAttribute("version", $cloud_service_node);


    $multi_tenant_enable = DH::findFirstElement("multi-tenant-enable", $cloud_service_node);

    if( $multi_tenant_enable === FALSE )
        derr( "this is not a multi-tenant Plugin Panorama configuration file" );
    else
    {
        #DH::DEBUGprintDOMDocument( $cloud_service_node );
    }


    $multi_tenant = DH::findFirstElement("multi-tenant", $cloud_service_node);
    $tenants = DH::findFirstElement("tenants", $multi_tenant);

    foreach( $tenants->childNodes as $entry )
    {
        /** @var DOMElement $entry */
        if( $entry->nodeType != XML_ELEMENT_NODE )
            continue;

        $tenantName = DH::findAttribute("name", $entry);
        $tmp_node = $entry->cloneNode(TRUE);
        $availableTenants[$tenantName] = $tenantName;
    }

    return $tenants;
}