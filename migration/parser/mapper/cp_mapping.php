<?php


function cp_getLineWithString($fileName, $str)
{
    $lines = $fileName;
    $record = array();
    foreach( $lines as $lineNumber => $line )
    {
        if( strpos($line, $str) !== FALSE )
        {
            $myline = (string)$line;
            $explde = explode("##", $myline);
            $remove = explode("\"", $explde[1]);
            $record[]['name'] = $remove[0];
        }
    }
    if( count($record) == 0 )
    {
        return -1;
    }
    else
    {
        return $record;
    }

}

function cp_getPolicyName($fileName, $str, $project)
{
    $lines = $fileName;
    $record = array();
    $print = FALSE;
    $tabs = "";
    $policyFile = USERSPACE_PATH . "/projects/" . $project . "/" . $str;
    $myfile = fopen($policyFile, "w");
    foreach( $lines as $lineNumber => $line )
    {
        if( (strpos($line, "##" . $str) !== FALSE) or ($print) )
        {
            if( $print === FALSE )
            {
                $tabs = strspn($line, "\t");
                $print = TRUE;

            }
            else
            {
                $tabs2 = strspn($line, "\t");
                if( $tabs == $tabs2 )
                {
                    $print = FALSE;
                }
            }
            fwrite($myfile, $line);
        }
    }
    fclose($myfile);
}




function cp_filecheck( $config_filename, &$someArray )
{
    global $expedition;
    global $mainfolder;

    $policyName = null;

    $rulebases = "";

    $newfolder = $mainfolder . "/".uniqid();

    if( !$expedition )
        print "folder: " . $newfolder . "\n";

    if( file_exists($newfolder) )
        delete_directory($newfolder);

    if( !file_exists($newfolder) )
        mkdir($newfolder, 0700, TRUE);

    $configFolder = $config_filename;



    $files1 = scandir($configFolder);
#print_r( $files1 );


//Todo: 20200604 other possible way: argument "file=[objects]/[policy]/[rulebase]"
//what about advanced options??? add more arguments ????

    foreach( $files1 as $item )
    {
        if( strpos($item, "rulebases") !== FALSE )
        {
            $tmp_check = explode(".", $item);
            if( $tmp_check[0] == "rulebases_5_0" && $tmp_check[1] == "fws" )
                $rulebases = $configFolder . "/" . $item;
        }
        elseif( strpos($item, "PolicyName") !== FALSE )
        {
            $tmp_check = explode(".", $item);
            if( $tmp_check[0] == "PolicyName" && $tmp_check[1] == "W" )
                $policyName = $configFolder . "/" . $item;
        }
        elseif( strpos($item, "object") !== FALSE )
        {
            $tmp_check = explode(".", $item);
            if( $tmp_check[0] == "objects_5_0" && $tmp_check[1] == "C" )
                $objectName = $configFolder . "/" . $item;
        }
        elseif( strpos($item, ".W") !== FALSE )
        {
            $tmp_check = explode(".", $item);
            if( $tmp_check[1] == "W" )
                $policyName = $configFolder . "/" . $item;
        }
        else
            continue;

    }


    if( $policyName == null )
        $policyName = $rulebases;

    if( !$expedition )
    {
        print "POLICY: " . $policyName . "\n";
#$policyName = $configFolder."/PolicyName.W";
#print "POLICY2: ".$policyName."\n";


        print "RULEBASE: " . $rulebases . "\n";
#$rulebases = $configFolder."/rulebases_5_0.fws";
#print "RULEBASE2: ".$rulebases."\n";


        print "OBJECT: " . $objectName . "\n";
#$objectName = $configFolder."/objects_5_0.C";
#print "OBJECT2: ".$objectName."\n";

        print "-------------------------------------------\n";
    }


    if( file_exists($rulebases) )
        $migratecomments = "--merge_AI=" . $rulebases;
    else
        $migratecomments = "";

#$policyName = str_replace(' ', '_', $policyName);



//todo: open file $policyName;
//search for ":rule-base"


    $rulebaseNames = file($policyName);

    $result = cp_getLineWithString($rulebaseNames, ":rule-base");



    if( $result != -1 )
    {
        #print_r($result);
        $someArray = $result;
    }
    else
    {
        #print "\nONLY one rulebase found! \n";
        $someArray = array();
    }

    if( file_exists($newfolder) )
        delete_directory($newfolder);
}