<?php
/**
 * Created by PhpStorm.
 * User: aestevez
 * Date: 01/03/2017
 * Time: 15:59
 */
function getLineWithString($fileName, $str) {
    $lines = $fileName;
    $record=array();
    foreach ($lines as $lineNumber => $line) {
        if (strpos($line, $str) !== false) {
            $myline = (string)$line;
            $explde=explode("##",$myline);
            $remove=explode("\"",$explde[1]);
            $record[]=$remove[0];
        }
    }
    if (count($record)==0){return -1;}
    else{
        return $record;
    }

}

function getPolicyName($fileName, $str){
    $lines = $fileName;
    $record=array();
    $print=false;
    $tabs="";
    $policyFile="/home/userSpace/projects/point/".$str;
    $myfile=fopen($policyFile,"w");
    foreach ($lines as $lineNumber => $line) {
        if ((strpos($line, "##".$str) !== false) OR ($print)) {
            if ($print===false){
                $tabs=strspn($line, "\t");
                $print=true;

            }
            else{
                $tabs2=strspn($line, "\t");
                if ($tabs==$tabs2){
                    $print=false;
                }
            }
            $string=preg_replace("/^\t/","",$line);
            fwrite($myfile,$string);
        }
    }
    fclose($myfile);
}

ini_set('memory_limit', '-1');

# Check if the Policy file contains more than one rule-base
$fileName="/home/userSpace/projects/point/PolicyName.W";
$rulebase=file($fileName);
$result=getLineWithString($rulebase, ":rule-base");

if ($result!=-1){
    # Split Policy in several files.
    foreach($result as $policyName){
        getPolicyName($rulebase, $policyName);
    }
    $rulebase="";

}
else{
    # Just Once
}