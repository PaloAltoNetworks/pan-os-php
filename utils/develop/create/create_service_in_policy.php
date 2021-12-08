<?php
/**
 * Created by PhpStorm.
 * User: swaschkut
 * Date: 4/19/16
 * Time: 9:12 AM
 */


print "\n***********************************************\n";
print "************ CREATE-services in SecurityPolicy UTILITY ****************\n\n";


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";


    if( !$shortMessage )
    {
        print PH::boldText("\nListing available arguments\n\n");

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            print " - ".PH::boldText($arg['niceName']);
            if( isset( $arg['argDesc']))
                print '='.$arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']))
                print "\n     ".$arg['shortHelp'];
            print "\n\n";
        }

        print "\n\n";
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit(true);
}


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
    "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n" .
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


///////////////////////////////////////////////////////

$sub = $pan->findVirtualSystem($util->objectsLocation);

$zone_array = array();

$rule = $sub->securityRules->find( 'autogen-0' );

#LIMIT 10000 for vsys / another 100000 for shared level
for( $i = 1; $i<130; $i++ )
{
    $name = "service.".$i;
    print "create service ".$name."\n";


    //VSYS
    $tmp_tag = $sub->serviceStore->find( $name );
    if( $tmp_tag === null )
    {
        if( $util->configInput['type'] == 'api' )
        {
            $tmp_tag = $sub->serviceStore->API_newService( $name, "tcp", $i );
        }

        else
            $tmp_tag = $sub->serviceStore->newService( $name, "tcp", $i );
    }



    if( $util->configInput['type'] == 'api' )
        $rule->services->API_add( $tmp_tag );
    else
        $rule->services->add( $tmp_tag );

}


##############################################

print "\n\n\n";

// save our work !!!
$util->save_our_work();



print "\n\n************ END OF CREATE-TAG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
