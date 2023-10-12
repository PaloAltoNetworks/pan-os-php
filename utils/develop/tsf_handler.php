<?php

require_once( "lib/pan_php_framework.php" );


##########################################
##########################################


PH::processCliArgs();


if( isset(PH::$args['in']) )
    $TSFfile = PH::$args['in'];
else
    derr( "in= argument not found" );

//read

$techSupportFileString = file_get_contents($TSFfile);


///////////////////////////////////////
///////////////////////////////////////

$systeminfoArray = get_systemInfo_from_TSF($techSupportFileString);
print_r($systeminfoArray);

///////////////////////////////////////

$licenseinfoArray = get_license_from_TSF($techSupportFileString);
print_r( $licenseinfoArray );

///////////////////////////////////////
///////////////////////////////////////
function get_systemInfo_from_TSF($techSupportFileString)
{
    $needle1 = "> show system info";
    $needle2 = "> show system files";
    $systeminfo = PH::find_string_between($techSupportFileString, $needle1, $needle2);

    $tmpArray = explode(PHP_EOL, $systeminfo);

    $systeminfoArray = array();
    foreach( $tmpArray as $entry )
    {
        if( empty($entry) )
            continue;

        $exploded = explode( ": ", $entry );
        $systeminfoArray[$exploded[0]] = $exploded[1];
    }

    return $systeminfoArray;
}

function get_license_from_TSF( $techSupportFileString)
{
    $needle1 = "> request license info";
    $needle2 = "> show system setting logging";
    $licenseinfo = PH::find_string_between($techSupportFileString, $needle1, $needle2);
    #print $licenseinfo."\n";
    $tmpArray = explode(PHP_EOL, $licenseinfo);
    #print_r($tmpArray);

    $licenseinfoArray = array();
    $licenseinfoArray['time'] = "";
    $licenseinfoArray['license'] = array();
    foreach( $tmpArray as $entry ) {
        if (empty($entry))
            continue;

        if (strpos($entry, "Current ") !== FALSE)
            $licenseinfoArray['time'] = $entry;
        elseif (strpos($entry, "License entry:") !== FALSE)
        {
            $licArray = array();
            $endFound = false;
        }
        else
        {
            $exploded = explode( ": ", $entry );
            $licArray[$exploded[0]] = $exploded[1];

            if (strpos($entry, "Expired?:") !== FALSE)
                $licenseinfoArray['license'][] = $licArray;
        }
    }

    return $licenseinfoArray;
}