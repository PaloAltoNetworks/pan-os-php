<?php

// load 'PAN Configurator' library
require_once("../lib/pan_php_framework.php");

/***************************************************************

 

****************************************************************/


// input and ouput xml files
$inputfile = 'sample-configs/panorama-example.xml';
$outputfile = 'output.xml';


// Create a new PanoramaConf object
$p = new PanoramaConf();
// and load it from a XML file
$p->load_from_file($inputfile);

PH::print_stdout("***********************************************");
PH::print_stdout("" );




// display some statiscs for debug and exit program!
PH::print_stdout("***********************************************");
PH::print_stdout("" );
$p->display_statistics();


