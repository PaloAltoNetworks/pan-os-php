<?php


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../pan-os-php/lib/pan_php_framework.php";


require_once dirname(__FILE__)."/../parser/lib/CONVERTER.php";
require_once dirname(__FILE__)."/../parser/lib/PARSER.php";
require_once dirname(__FILE__)."/../parser/lib/SHAREDNEW.php";




PH::processCliArgs();



if( isset(PH::$args['folder'])  )
    $folder = PH::$args['folder'];
else
    derr( "argument 'folder' not set" );

if( isset(PH::$args['vendor'])  )
    $vendor = PH::$args['vendor'];
else
    derr( "argument 'vendor' not set" );

if( isset(PH::$args['in'])  )
    $input = PH::$args['in'];
else
    derr( "argument 'in' not set" );

if( isset(PH::$args['out'])  )
    $final_out = PH::$args['out'];
else
    derr( "argument 'folder' not set" );



$files = PH::getFilesInFolder( $folder );

$ii = 1;
foreach( $files as $file )
{
    PH::print_stdout( "FILE: '".$file."'" );

    //created folder migrate
    $migrationFolder = $folder."/migrate";
    if (!is_dir($migrationFolder)) {
        mkdir($migrationFolder, 0777, true);
    }


    $arguments = array();
    $arguments[0] = "migration_batch.php";
    if( $ii == 1 )
        $arguments[] = "in=".$input."";
    else
        $arguments[] = "in=".$out."";
    $arguments[] = "vendor=".$vendor."";
    $arguments[] = "file=".$folder."/".$file."";

    $out = $migrationFolder."/".$file.".xml";
    $arguments[] = "out=".$out;


    PH::resetCliArgs( $arguments);

    $converter = new CONVERTER();

    $ii++;
}


PH::print_stdout( "copy last file to: ".$final_out );
copy($out, $final_out);



