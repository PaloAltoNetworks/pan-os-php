<?php

require_once "lib/pan_php_framework.php";

//Maxmind
//database
//https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz

//CSV
//https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip

if( !isset(PH::$args['maxmind-licensekey']) )
{
    //check if available via .panconfigkeystore
    $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'maxmind-licensekey' );
    $licensekey = $connector->apikey;
    #derr( "argument 'maxmind-licensekey' missing." );
}
else
{
    $licensekey = PH::$args['maxmind-licensekey'];

    //store key in .panconfkeystore
    $connector = PanAPIConnector::findOrCreateConnectorFromHost( 'maxmind-licensekey', $licensekey );
    //add it to panconfkeystore
}


$folderExpression = "GeoLite2-Country-CSV";

$url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=".$licensekey."&suffix=zip";
$file_name = $folderExpression.".zip";
$folder = $folderExpression;


//DOWNLOAD ZIP
//cert check fail if SSL interception is done
if(file_put_contents( $file_name,file_get_contents($url)))
    echo "File: ".$file_name." downloaded successfully\n";
else
    echo "File: ".$file_name." downloading failed.\n";


//zip always contains a folder
#$data = system('unzip -d '.$folder.' '.$file_name);
$data = system('unzip -o '.$file_name);


//delete downloaded file
// Use unlink() function to delete a file
if (!unlink($file_name)) {
    print ("$file_name cannot be deleted due to an error\n");
}
else {
    print ("$file_name has been deleted\n");
}


##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################




$folder = "notExist/";
$dirs = array_filter(glob( '*'), 'is_dir');
foreach( $dirs as $foldername )
{
    if( strpos( $foldername, $folderExpression ) !== false )
        $folder = $foldername;
}

function delete_folder($folder) {
    $glob = glob($folder);
    foreach ($glob as $g) {
        if (!is_dir($g)) {
            unlink($g);
        } else {
            delete_folder("$g/*");
            rmdir($g);
        }
    }
}

function getdataRegion($csvFile){
    $file_handle = fopen($csvFile, 'r');
    $first = true;
    $line_of_text = array();
    while (!feof($file_handle) )
    {
        $array = fgetcsv($file_handle, 1024);
        if( !$first && !empty($array) )
        {
            if( !empty( $array[4] ) )
                $line_of_text[ $array[0] ] = $array[4];
            else
                $line_of_text[ $array[0] ] = $array[2];
        }

        $first = false;
    }
    fclose($file_handle);
    return $line_of_text;
}



function getdataSven($csvFile)
{
    global $countryNumbers;

    $file_handle = fopen($csvFile, 'r');
    $first = true;
    $countryArray = array();

    while (!feof($file_handle) )
    {
        $array = fgetcsv($file_handle, 1024);
        if( !$first && !empty($array) )
        {
            $value = $array[0];

            $valueArray = cidr::stringToStartEnd($value);
            $ipStart = cidr::inet_itop($valueArray['start']);
            $ipEnd = cidr::inet_itop($valueArray['end']);

            $value = $ipStart."-".$ipEnd;

            #print "check: ".$array[1]." value: ".$value."\n";

            if( !empty($array[1]) )
                $countryArray[ $countryNumbers[ $array[1] ] ][] =  $value;
            else
                $countryArray[ $countryNumbers[ $array[2] ] ][] =  $value;
        }

        $first = false;
    }
    fclose($file_handle);
    return $countryArray;
}

// Set path to CSV file
$csvFile = $folder.'/GeoLite2-Country-Locations-en.csv';
$countryNumbers = getdataRegion($csvFile);
#print_r( $countryNumbers );


$ipTypearray = array( 'ipv4', 'ipv6' );

foreach( $ipTypearray as $type )
{
    if( $type == 'ipv4' )
        $name = 'IPv4';
    elseif( $type == 'ipv6' )
        $name = 'IPv6';

    // Set path to CSV file
    $csvFile = $folder.'/GeoLite2-Country-Blocks-'.$name.'.csv';

    $csv = getdataSven($csvFile);
    #print_r($csv);

    $filename = "RegionCC".$type.".json";
    print "create file: ".$filename."\n";

    $JSONstring = json_encode( $csv, JSON_PRETTY_PRINT );
    file_put_contents( "data/".$filename, $JSONstring);
}


//delete previously extracted folder
// Use unlink() function to delete a file
system('rm -fr '.$folder);
print ("$folder has been deleted\n");