<?php


/*
// this script is to prepare test XML file with log information,
// the information is normally generated in production with script report-generator.php against PAN-OS XML API
 */

$timezone_name = "GMT";
date_default_timezone_set( $timezone_name );

$unix_timestamp = time();
$date =  date('d-F-Y H:i');

$stats_filename = "0123456789-vsys1-stats_blank.xml";

$stats_file = file_get_contents($stats_filename);

$stats_file1 = str_replace( "{unix-timestamp}", $unix_timestamp, $stats_file );
$stats_file2 = str_replace( "{date}", $date, $stats_file1 );



$filename = "../0123456789-vsys1-stats.xml";
file_put_contents($filename, $stats_file2);