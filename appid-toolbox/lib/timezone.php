<?php


if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
{
    $system_timezone = exec('tzutil /g');

    $temp = explode(' ', $system_timezone);
    $result = '';
    foreach($temp as $t)
        $result .= $t[0];

    $system_timezone = strtoupper($result);

    print "WINDOWS\n";
}
else
{
    $system_timezone = exec('date +%Z');
    print "UNIX\n";
}

print "\n\n-------------------------------------------------\n\n";
print "|".$system_timezone."|";
print "\n\n-------------------------------------------------\n\n";

$timezone_name = timezone_name_from_abbr( $system_timezone );

print "\n\n-------------------------------------------------\n\n";
print "|".$timezone_name."|";
print "\n\n-------------------------------------------------\n\n";