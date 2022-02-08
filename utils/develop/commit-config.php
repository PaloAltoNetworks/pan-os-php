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


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";

PH::print_stdout("");
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout("");

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );


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



print "\n";

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = false;
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


PH::processCliArgs();

foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');



if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

if( isset(PH::$args['folder'])  )
{
    $offline_folder = PH::$args['folder'];
}


################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, true);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if( $configInput['type'] == 'file' )
{
    derr( "offline file not supported\n" );
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( ! $xmlDoc1->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{

    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    print " - Downloading config from API... ";

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        print " - 'loadPanoramaPushedConfig' was requested, downloading it through API...";
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    $hostname = $configInput['connector']->info_hostname;

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );

    print "OK!\n";

}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult1 = DH::findXPath('/config/devices/entry/vsys', $xmlDoc1);
if( $xpathResult1 === FALSE )
    derr('XPath error happened');
if( $xpathResult1->length <1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length <1 )
        $configType = 'panorama';
    else
        $configType = 'pushed_panorama';
}
else
    $configType = 'panos';
unset($xpathResult1);

print " - Detected platform type is '{$configType}'\n";

############## actual not used

if( $configType == 'panos' )
    $pan = new PANConf();
elseif( $configType == 'panorama' )
    $pan = new PanoramaConf();



if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];





// </editor-fold>

################


//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $objectslocation = PH::$args['location'];
    if( !is_string($objectslocation) || strlen($objectslocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'panorama' )
    {
        print " - No 'location' provided so using default ='shared'\n";
        $objectslocation = 'shared';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
}



##########################################
##########################################


#/api/?type=op&cmd=<validate><full></full></validate>
/*
$apiArgs = Array();
$apiArgs['type'] = 'op';
$apiArgs['cmd'] = '<validate><full></full></validate>';

if( $configInput['type'] == 'api' )
    $ret= $pan->connector->sendRequest($apiArgs);

print DH::dom_to_xml($ret, 0, true, 5);



$cursor = DH::findFirstElement('job', $ret);

if( $cursor === FALSE )
    derr("unsupported API answer, no JOB ID found");

$jobid = $cursor->textContent;

    $ret = $pan->connector->getJobResult($jobid);

print DH::dom_to_xml($ret, 0, true, 5);
*/


$apiArgs = Array();
$apiArgs['type'] = 'commit';
$apiArgs['cmd'] = '<commit></commit>';



//Todo: support partial

#$apiArgs['cmd'] = '<commit><partial><admin><member>admin2</member></admin></partial></commit>';


#working for PA-200
#$apiArgs['cmd'] = '<commit><partial><device-and-network>exclude</device-and-network><shared-object>excluded</shared-object></partial></commit>';


#commit partial vsys vsys1 device-and-network excluded
#$apiArgs['cmd'] = '<commit><partial><vsys><vsys1><device-and-network>excluded</device-and-network></vsys1></vsys></partial></commit>';



if( $configInput['type'] == 'api' )
{
    $ret= $pan->connector->sendRequest($apiArgs);
}



/*
function &getCommit($req)
{
    $ret = $this->sendRequest($req);
*/
//print DH::dom_to_xml($ret, 0, true, 4);

$cursor = DH::findXPathSingleEntryOrDie('/response', $ret);
$cursor = DH::findFirstElement('result', $cursor);

if( $cursor === FALSE )
{
    $cursor = DH::findFirstElement('report', DH::findXPathSingleEntryOrDie('/response', $ret));
    #print DH::dom_to_xml($ret, 0, true, 5);
    if( $cursor === FALSE )
    {
        $cursor = DH::findFirstElement('msg', DH::findXPathSingleEntryOrDie('/response', $ret));
        if( $cursor === FALSE )
            derr("unsupported API answer");
    }


    $report = DH::findFirstElement('result', $cursor);
    if( $report === FALSE )
    {
        $report = $cursor;
        if( $report === FALSE )
            derr("unsupported API answer");
    }


}

if( !isset($report) )
{

    $cursor = DH::findFirstElement('job', $cursor);

    if( $cursor === FALSE )
        derr("unsupported API answer, no JOB ID found");

    $jobid = $cursor->textContent;

    while( TRUE )
    {
        sleep(1);
        $query = '&type=op&cmd=<show><jobs><id>' . $jobid . '</id></jobs></show>';
        $ret= $pan->connector->sendRequest($query);
        #print DH::dom_to_xml($ret, 0, true, 5);

        $cursor = DH::findFirstElement('result', DH::findXPathSingleEntryOrDie('/response', $ret));

        if( $cursor === FALSE )
            derr("unsupported API answer", $ret);

        $jobcur = DH::findFirstElement('job', $cursor);

        if( $jobcur === FALSE )
            derr("unsupported API answer", $ret);

        $percent = DH::findFirstElement('progress', $jobcur);

        if( $percent == FALSE )
            derr("unsupported API answer", $cursor);

        if( $percent->textContent != '100' )
        {
            print $percent->textContent."% - ";
            sleep(9);
            continue;
        }

        $cursor = DH::findFirstElement('result', $jobcur);

        if( $cursor === FALSE )
            derr("unsupported API answer", $ret);

        $report = $cursor;

        break;

    }
}
//print_r($ret);

#    return $report;
#}

#print $report->textContent;


if( $report->textContent == "FAIL" )
{
    echo "\n*********************************************************\n";
    echo "*                                                       *\n";
    echo "*                FIREWALL " . $hostname . " COMMIT               *\n";
    echo "*                                                       *\n";
    echo "*                         FAILED                        *\n";
    echo "*                                                       *\n";
    echo "*********************************************************\n";
    derr( "The configuration COMMIT to ".$hostname." firewall failed.\n" );
}
elseif( $report->textContent == 'There are no changes to commit.' )
{
    echo "\n*********************************************************\n";
    echo "*                                                       *\n";
    echo "*                FIREWALL " . $hostname . " COMMIT               *\n";
    echo "*                                                       *\n";
    echo "*             THERE ARE NO CHANGES TO COMMIT.           *\n";
    echo "*                                                       *\n";
    echo "*********************************************************\n";
}
else
{
    echo "\n*********************************************************\n";
    echo "*                                                       *\n";
    echo "*                FIREWALL " . $hostname . " COMMIT               *\n";
    echo "*                                                       *\n";
    echo "*                      SUCCESSFULL                      *\n";
    echo "*                                                       *\n";
    echo "*********************************************************\n";
}

##############################################



print "\n\n************ END OF COMMIT-CONFIG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
