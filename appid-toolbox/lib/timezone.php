<?php


if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
{
    $system_timezone = exec('tzutil /g');

    $temp = explode(' ', $system_timezone);
    $result = '';
    foreach($temp as $t)
        $result .= $t[0];

    $system_timezone = strtoupper($result);

    PH::print_stdout( "WINDOWS" );
}
else
{
    $system_timezone = exec('date +%Z');
    PH::print_stdout( "UNIX" );
}

PH::print_stdout( "" );
PH::print_stdout( "" );
PH::print_stdout("-------------------------------------------------" );
PH::print_stdout( "" );
PH::print_stdout("|".$system_timezone."|" );
PH::print_stdout( "" );
PH::print_stdout("-------------------------------------------------" );
PH::print_stdout( "" );
$timezone_name = timezone_name_from_abbr( $system_timezone );

PH::print_stdout( "" );
PH::print_stdout( "" );
PH::print_stdout("-------------------------------------------------" );
PH::print_stdout( "" );
PH::print_stdout("|".$timezone_name."|" );
PH::print_stdout( "" );
PH::print_stdout("-------------------------------------------------" );
PH::print_stdout( "" );