<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT . '/libs/database.php';
require_once INC_ROOT . '/libs/shared.php';
require_once INC_ROOT . '/libs/projectdb.php';
require_once INC_ROOT . '/libs/objects/SecurityRulePANObject.php';


require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
global $app;
include INC_ROOT . '/bin/configurations/parsers/readVars.php';
global $projectdb;
$projectdb = selectDatabase($project);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

$sourceAdded = array();
global $source;

if( $noDNAT == "1" )
{
    $skipDNAT = TRUE;
}
else
{
    $skipDNAT = FALSE;
}

if( $action == "import" )
{
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", '-1');
    $convertObjectsShared = FALSE;

    update_progress($project, '0.00', 'Reading config files', $jobid);

    # Check if the Policy file contains more than one rule-base
    $fileName = USERSPACE_PATH . "/projects/$project/PolicyName.W";
    $rulebase = file($fileName);
    $result = getLineWithString($rulebase, ":rule-base");
    if( $result != -1 )
    {
        # Split Policy in several files.
        update_progress($project, '0.00', 'VSX Multiple Rulebases found. Splitting them...', $jobid);
        foreach( $result as $policyName )
        {
            getPolicyName($rulebase, str_replace(' ', '_', $policyName), $project);
        }
        $rulebase = "";

    }
    else
    {
        # Just Once
        $result = array();
        $result[] = "PolicyName.W";
    }

    if( count($result) > 1 )
    {
        $convertObjectsShared = TRUE;
    }
    $source = "";
    $alreadyLoaded = FALSE;
    foreach( $result as $policyName )
    {

        $rulebases = USERSPACE_PATH . "/projects/$project/rulebases_5_0.fws";
        if( file_exists($rulebases) )
        {
            $migratecomments = "--merge_AI=" . USERSPACE_PATH . "/projects/$project/rulebases_5_0.fws";
        }
        else
        {
            $migratecomments = "";
        }
        $policyName = str_replace(' ', '_', $policyName);
        $checkJsonParser = FALSE;
        $fwdoc = USERSPACE_PATH . "/projects/$project/conf.fwdoc";
        $ParserPath = INC_ROOT . "/bin/configurations/parsers/Checkpoint/checkpoint-parser.pl";
        $Parse = "/usr/bin/perl $ParserPath --rules=" . USERSPACE_PATH . "/projects/$project/$policyName --objects=" . USERSPACE_PATH . "/projects/$project/objects_5_0.C $migratecomments> $fwdoc";
        shell_exec($Parse);

        if( (file_exists($fwdoc)) and (filesize($fwdoc) != 0) )
        {
            update_progress($project, '0.10', 'Rulebase ' . $policyName . ' Phase 1 of 10', $jobid);

            #Gotcha , si falla esto que se ejecute el jsonparser
            if( !file_exists(USERSPACE_PATH . "/projects/$project/rules.txt") )
            {
                $file = USERSPACE_PATH . "/projects/$project/conf.fwdoc";
                if( file_exists($file) )
                {
                    $Rules = "false";
                    $Objects = "false";
                    $enterObject = "false";
                    $ObjectName = "";
                    $ObjectType = "";
                    $ObjectIP = "";
                    $ObjectComment = "";
                    $ObjectGatewayBrand = "";
                    $ObjectGRoupMembersBase = "";
                    $ObjectGroupMembersException = "";
                    $ObjectLayer7Filter = "";
                    $ObjectDestinationPort = "";
                    $ObjectSourcePort = "";
                    $ObjectProtocol = "";
                    $members = "";
                    $members2 = "";
                    $isGroup = "false";
                    $Services = "false";
                    $RuleNumber = "";
                    $RuleHeader = "";
                    $RuleEnabled = "";
                    $RuleFrom = "";
                    $RuleFrom2 = "";
                    $RuleFromInverted = "no";
                    $RuleTo = "";
                    $RuleTo2 = "";
                    $RuleToInverted = "no";
                    $RuleServices = "";
                    $RuleServices2 = "";
                    $RuleServicesInverted = "no";
                    $RuleAction = "";
                    $RuleLog = "yes";
                    $RuleComment = "";
                    $enterRule = "false";
                    $isFrom = "false";
                    $isTo = "false";
                    $isService = "false";
                    $comments = "";
                    $rulesline = "";
                    $objectline = "";
                    $servicesline = "";
                    $location = "";
                    $isInterface = FALSE;
                    $NatNumber = "";
                    $NatEnabled = "";
                    $RuleInstall = "";
                    $RuleInstall2 = "";
                    $NatOrigFrom = "";
                    $NatOrigTo = "";
                    $NatOrigService = "";
                    $NatType = "";
                    $NatFrom = "";
                    $NatTo = "";
                    $NatService = "";
                    $NatComment = "";
                    $NatHeader = "";
                    $NatRules = "false";
                    $enterNatRule = "false";
                    $isInstall = FALSE;
                    $isShared = "0";
                    $Objects_File = USERSPACE_PATH . '/projects/' . $project . '/objects.txt';
                    $Services_File = USERSPACE_PATH . '/projects/' . $project . '/services.txt';
                    $Rules_File = USERSPACE_PATH . '/projects/' . $project . '/rules.txt';
                    $Nat_File = USERSPACE_PATH . '/projects/' . $project . '/natrules.txt';
                    $natrulesline = "";

                    $string = file($file);

                    foreach( $string as $line => $record )
                    {

                        if( preg_match("/^  \"accessrules\": \[/i", $record) )
                        {
                            $Rules = "true";
                            continue;
                        }

                        if( preg_match("/^  \"services\": \{/i", $record) )
                        {
                            $Services = "true";
                            continue;
                        }

                        if( preg_match("/^  \"objects\": \{/i", $record) )
                        {
                            $Objects = "true";
                            continue;
                        }

                        if( preg_match("/^  \"natrules\": \[/i", $record) )
                        {
                            $NatRules = "true";
                            continue;
                        }

                        if( $NatRules == "true" )
                        {

                            if( preg_match("/^  \],/i", $record) )
                            {
                                $NatRules = "false";
                            }
                            else
                            {
                                # print $record;
                                if( preg_match("/^  \"natrules\": \[/i", $record) )
                                {
                                }
                                else
                                {
                                    #All the objects without the objects definition
                                    $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                    if( (preg_match("/^    {/i", $record)) or (preg_match("/^    ,{/i", $record)) )
                                    {
                                        $enterNatRule = "true";
                                    }

                                    if( $enterNatRule = "true" )
                                    {

                                        if( preg_match("/^    }/i", $record) )
                                        {
                                            $enterNatRule = "false";
                                            #print $RuleNumber ."-". $RuleServices ."-". $RuleServices2 ."\n";
                                            #Salimos del objeto y lo printamos

                                            $comments = addslashes($NatComment);

                                            if( $NatNumber == "" )
                                            {
                                                $NatNumber = "(implicit)";
                                            }

                                            if( $NatHeader == "\"\"" )
                                            {
                                                $NatHeader = "";
                                            }

                                            $natrulesline .= "$NatNumber;$NatEnabled;$NatOrigFrom;$NatOrigTo;$NatOrigService;$NatType;$NatFrom;$NatTo;$NatService;$RuleInstall2;$comments;$NatHeader\n";

                                            #list($rule_id,$rule_enabled,$negate_source,$source,$negate_destination,$destination,$negate_service,$service,$action,$log,$time,$firewall,$rulename)

                                            #print "$ObjectName - $ObjectType - $ObjectIP - $ObjectComment - $ObjectGatewayBrand - $ObjectGRoupMembersBase - $ObjectGroupMembersException - $ObjectLayer7Filter - $ObjectDestinationPort - $ObjectSourcePort - $ObjectProtocol\n";

                                            #limpiamos variables
                                            $NatNumber = "";
                                            $NatEnabled = "";
                                            $NatOrigFrom = "";
                                            $NatOrigTo = "";
                                            $NatOrigService = "";
                                            $NatType = "";
                                            $NatFrom = "";
                                            $NatTo = "";
                                            $NatService = "";
                                            $NatComment = "";
                                            $RuleInstall2 = "";
                                            $RuleInstall = "";
                                            $NatHeader = "";

                                        }
                                        else
                                        {

                                            if( preg_match("/\"install_on\": \[/i", $record) )
                                            {
                                                $isInstall = "true";
                                            }
                                            if( isset($data[0]) )
                                            {
                                                if( $data[0] == "number" )
                                                {
                                                    $NatNumber = $data[2];
                                                }

                                                if( $data[0] == "enabled" )
                                                {
                                                    $NatEnabled = $data[2];
                                                }

                                                if( $data[0] == "orig_from" )
                                                {
                                                    $NatOrigFrom = $data[3];
                                                }

                                                if( $data[0] == "orig_to" )
                                                {
                                                    $NatOrigTo = $data[3];
                                                }

                                                if( $data[0] == "orig_service" )
                                                {
                                                    $NatOrigService = $data[3];
                                                }

                                                if( $data[0] == "nat_type" )
                                                {
                                                    $NatType = $data[2];
                                                }

                                                if( $data[0] == "nat_from" )
                                                {
                                                    $NatFrom = $data[2];
                                                }

                                                if( $data[0] == "nat_to" )
                                                {
                                                    $NatTo = $data[2];
                                                }

                                                if( $data[0] == "nat_service" )
                                                {
                                                    $NatService = $data[2];
                                                }

                                                if( $data[0] == "comment" )
                                                {
                                                    $NatComment = trim($data[2]);
                                                }

                                                if( $data[0] == "header" )
                                                {
                                                    $NatHeader = trim($data[2]);
                                                }
                                            }


                                            if( $isInstall == "true" )
                                            {
                                                if( preg_match("/^        \],/i", $record) )
                                                {
                                                    $isInstall = "false";
                                                    #printar el resultado de todos miembros
                                                    $RuleInstall2 = substr($RuleInstall, 1);
                                                    #echo "members: $members2\n";

                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                                    if( isset($data2[0]) )
                                                    {
                                                        if( $data2[0] == "firewall" )
                                                        {
                                                            //print "0:$data2[0] 1:$data2[1] 2:$data2[2] 3:$data2[3]\n";
                                                            $RuleInstall .= "," . $data2[2];
                                                        }
                                                        else
                                                        {

                                                        }
                                                    }
                                                    else
                                                    {
                                                        print $record;
                                                    }
                                                }
                                            }


                                            #groupmembers


                                        }
                                    }
                                    #print $record;
                                    #print $data[0]." ".$data[1]."\n";
                                }
                                #End
                            }

                        }

                        if( $Rules == "true" )
                        {
                            if( preg_match("/^  \],/i", $record) )
                            {
                                $Rules = "false";
                            }
                            else
                            {
                                # print $record;
                                if( preg_match("/^  \"accessrules\": \[/i", $record) )
                                {
                                }
                                else
                                {
                                    #All the objects without the objects definition
                                    $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                    if( (preg_match("/^    {/i", $record)) or (preg_match("/^    ,{/i", $record)) )
                                    {
                                        $enterRule = "true";
                                    }

                                    if( $enterRule = "true" )
                                    {

                                        if( preg_match("/^    }/i", $record) )
                                        {
                                            $enterRule = "false";
                                            #print $RuleNumber ."-". $RuleServices ."-". $RuleServices2 ."\n";
                                            #Salimos del objeto y lo printamos
                                            if( ($RuleServices2 == "") or ($RuleServices == "") )
                                            {
                                                $RuleServices2 = "Any";
                                                #mysql_query("Insert into errors (level,source,message) values ('warning','rules','Review Rule $RuleNumber, cannot locate service, changing by Any');");
                                            }

                                            $comments = addslashes($RuleComment);

                                            if( $headertext == "\"\"" )
                                            {
                                                $headertext = "";
                                            }

                                            $rulesline .= "$RuleNumber;$RuleEnabled;$RuleFromInverted;$RuleFrom2;$RuleToInverted;$RuleTo2;$RuleServicesInverted;$RuleServices2;$RuleAction;$RuleLog;;$RuleInstall2;$comments;$headertext;$location\n";

                                            #list($rule_id,$rule_enabled,$negate_source,$source,$negate_destination,$destination,$negate_service,$service,$action,$log,$time,$firewall,$rulename)

                                            #print "$ObjectName - $ObjectType - $ObjectIP - $ObjectComment - $ObjectGatewayBrand - $ObjectGRoupMembersBase - $ObjectGroupMembersException - $ObjectLayer7Filter - $ObjectDestinationPort - $ObjectSourcePort - $ObjectProtocol\n";

                                            #limpiamos variables
                                            $RuleNumber = "";
                                            $RuleHeader = "";
                                            $RuleEnabled = "";
                                            $RuleFrom = "";
                                            $RuleFrom2 = "";
                                            $RuleFromInverted = "no";
                                            $RuleTo = "";
                                            $RuleTo2 = "";
                                            $RuleToInverted = "no";
                                            $RuleServices = "";
                                            $RuleServices2 = "";
                                            $RuleServicesInverted = "no";
                                            $RuleAction = "";
                                            $RuleLog = "yes";
                                            $RuleInstall2 = "";
                                            $RuleInstall = "";
                                            $RuleComment = "";
                                            $comments = "";
                                            $headertext = "";
                                            $location = "";

                                        }
                                        else
                                        {

                                            if( preg_match("/\"from\": \[/i", $record) )
                                            {
                                                $isFrom = "true";
                                            }
                                            if( preg_match("/\"install_on\": \[/i", $record) )
                                            {
                                                $isInstall = "true";
                                            }
                                            if( preg_match("/\"to\": \[/i", $record) )
                                            {
                                                $isTo = "true";
                                            }
                                            if( preg_match("/\"services\": \[/i", $record) )
                                            {
                                                $isService = "true";
                                            }

                                            if( $isFrom == "true" )
                                            {
                                                if( preg_match("/^        \],/i", $record) )
                                                {
                                                    $isFrom = "false";
                                                    #printar el resultado de todos miembros
                                                    $RuleFrom2 = substr($RuleFrom, 1);
                                                    #echo "members: $members2\n";

                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                                                    if( $data2[0] == "from" )
                                                    {
                                                    }
                                                    else
                                                    {
                                                        if( $data2[4] == "user" )
                                                        {
                                                            $RuleFrom .= "," . $data2[6] . "@" . $data2[3];
                                                        }
                                                        else
                                                        {
                                                            $RuleFrom .= "," . $data2[3];
                                                        }
                                                    }
                                                    #print "AQUI ".$data2[0];
                                                }
                                            }

                                            if( $isInstall == "true" )
                                            {
                                                if( preg_match("/^        \],/i", $record) )
                                                {
                                                    $isInstall = "false";
                                                    #printar el resultado de todos miembros
                                                    $RuleInstall2 = substr($RuleInstall, 1);
                                                    #echo "members: $members2\n";

                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                                                    if( $data2[0] == "firewall" )
                                                    {
                                                        //print "0:$data2[0] 1:$data2[1] 2:$data2[2] 3:$data2[3]\n";
                                                        $RuleInstall .= "," . $data2[2];
                                                    }
                                                    else
                                                    {

                                                    }

                                                }
                                            }

                                            if( $isTo == "true" )
                                            {
                                                if( preg_match("/^        \],/i", $record) )
                                                {
                                                    $isTo = "false";
                                                    #printar el resultado de todos miembros
                                                    $RuleTo2 = substr($RuleTo, 1);
                                                    #echo "members: $members2\n";
                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                                    if( $data2[0] == "to" )
                                                    {
                                                    }
                                                    else
                                                    {
                                                        $RuleTo .= "," . $data2[0];
                                                    }
                                                }
                                            }

                                            if( $isService == "true" )
                                            {
                                                if( preg_match("/^        \],/i", $record) )
                                                {
                                                    $isService = "false";
                                                    #printar el resultado de todos miembros
                                                    $RuleServices2 = substr($RuleServices, 1);
                                                    #echo "members: $members2\n";
                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                                    if( $data2[0] == "services" )
                                                    {
                                                    }
                                                    else
                                                    {
                                                        $RuleServices .= "," . $data2[3];
                                                    }
                                                    #print "AQUI ".$data2[0];
                                                }
                                            }
                                            if( isset($data[0]) )
                                            {
                                                if( $data[0] == "number" )
                                                {
                                                    $RuleNumber = $data[2];
                                                }

                                                if( $data[0] == "enabled" )
                                                {
                                                    $RuleEnabled = $data[2];
                                                }

                                                if( $data[0] == "from_inverted" )
                                                {
                                                    $RuleFromInverted = $data[2];
                                                }

                                                if( $data[0] == "to_inverted" )
                                                {
                                                    $RuleToInverted = $data[2];
                                                }

                                                if( $data[0] == "services_inverted" )
                                                {
                                                    $RuleServicesInverted = $data[2];
                                                }

                                                if( $data[0] == "action" )
                                                {
                                                    $RuleAction = $data[2];
                                                }

                                                if( $data[0] == "header" )
                                                {
                                                    $headertext = $data[2];
                                                }

                                                if( $data[0] == "location" )
                                                {
                                                    $location = $data[2];
                                                }

                                                if( $data[0] == "comment" )
                                                {
                                                    $RuleComment = $data[2];
                                                }
                                            }
                                        }
                                        #groupmembers
                                    }
                                }
                            }
                            #End
                        }

                        if( $Objects == "true" )
                        {

                            if( preg_match("/^  }/i", $record) )
                            {
                                $Objects = "false";
                            }
                            else
                            {
                                #print $record; #Debug
                                #Here all the objects are obtained
                                if( preg_match("/^  \"objects\": \{/i", $record) )
                                {
                                }
                                else
                                {
                                    #All the objects without the objects definition
                                    $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                                    if( preg_match("/: {/", $record) )
                                    {
                                        $enterObject = "true";
                                        continue;
                                    }

                                    if( $enterObject = "true" )
                                    {

                                        if( preg_match("/\}/", $record) )
                                        {
                                            $enterObject = "false";

                                            #Salimos del objeto y lo printamos
                                            if( $ObjectType == "cluster_member" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "dynamic_net_obj" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;;;;$ObjectComment;;$isShared\n";
                                            }
                                            elseif( $ObjectType == "domain" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType\n";
                                            }
                                            elseif( $ObjectType == "gateway_cluster" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;$members2;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "gateway_fw" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "gateways" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "host" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "gateway" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "machines_range" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;;$ObjectComment;;$isShared\n";
                                            }
                                            elseif( $ObjectType == "network" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "router" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "sofaware_gateway" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;$ObjectIP;;;$ObjectComment;$interfaces2;$isShared\n";
                                            }
                                            elseif( $ObjectType == "group_with_exclusion" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;;;$ObjectGRoupMembersBase,$ObjectGroupMembersException;$ObjectComment;;$isShared\n";
                                            }
                                            elseif( $ObjectType == "group" )
                                            {
                                                $objectline .= "$ObjectName;$ObjectType;;;;;$members2;$ObjectComment;;$isShared\n";
                                            }
                                            else
                                            {
                                                #mysql_query("Insert into logs (level,task,message) values ('4','Reading Objects','Unsupported Object, please send an email to fwmigrate@paloaltonetworks.com : $record');");
                                            }


                                            #print "$ObjectName - $ObjectType - $ObjectIP - $ObjectComment - $ObjectGatewayBrand - $ObjectGRoupMembersBase - $ObjectGroupMembersException - $ObjectLayer7Filter - $ObjectDestinationPort - $ObjectSourcePort - $ObjectProtocol\n";

                                            #limpiamos variables
                                            $ObjectName = "";
                                            $ObjectType = "";
                                            $ObjectIP = "";
                                            $ObjectComment = "";
                                            $ObjectGatewayBrand = "";
                                            $ObjectGRoupMembersBase = "";
                                            $ObjectGroupMembersException = "";
                                            $ObjectLayer7Filter = "";
                                            $ObjectDestinationPort = "";
                                            $ObjectSourcePort = "";
                                            $ObjectProtocol = "";
                                            $members = "";
                                            $members2 = "";
                                            $interfaces = "";
                                            $interfaces2 = "";
                                            $isShared = "0";
                                        }
                                        else
                                        {

                                            #Interfaces
                                            if( preg_match("/,\"interfaces\": \[/i", $record) )
                                            {
                                                $isInterface = "true";
                                                continue;
                                            }
                                            //else{
                                            //    $isInterface="false";
                                            //}

                                            if( $isInterface == "true" )
                                            {
                                                if( preg_match("/]/", $record) )
                                                {
                                                    $isInterface = "false";
                                                    #printar el resultado de todos miembros
                                                    $interfaces2 = substr($interfaces, 1);

                                                    #echo "members: $members2\n";

                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                                                    if( $data2[0] == "interfaces" )
                                                    {
                                                    }
                                                    else
                                                    {

                                                        $interfaces .= "," . $data2[0];
                                                    }
                                                    #print "AQUI ".$data2[0];
                                                }
                                            }

                                            if( preg_match("/,\"groupmembers\": \[/i", $record) )
                                            {
                                                $isGroup = "true";
                                                continue;
                                            }
                                            //else{
                                            //   $isGroup="false";
                                            //}

                                            if( $isGroup == "true" )
                                            {
                                                if( preg_match("/]/", $record) )
                                                {
                                                    $isGroup = "false";
                                                    #printar el resultado de todos miembros
                                                    $members2 = substr($members, 1);
                                                    #echo "members: $members2\n";

                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                                    $members .= "," . $data2[0];
                                                    #print "AQUI ".$data2[0];
                                                }
                                            }

                                            if( isset($data[0]) )
                                            {
                                                if( $data[0] == "name" )
                                                {
                                                    $ObjectName = $data[2];
                                                }

                                                if( $data[0] == "type" )
                                                {
                                                    $ObjectType = $data[2];
                                                }

                                                if( $data[0] == "ipaddr" )
                                                {
                                                    $ObjectIP = $data[2];
                                                }

                                                if( $data[0] == "comment" )
                                                {
                                                    $ObjectComment = $data[2];
                                                }

                                                if( $data[0] == "shared" )
                                                {
                                                    $isShared = $data[2];
                                                }

                                                if( $data[0] == "gateway_brand" )
                                                {
                                                    $ObjectGatewayBrand = $data[2];
                                                }

                                                if( $data[0] == "groupmembers_base" )
                                                {
                                                    $ObjectGRoupMembersBase = $data[3];
                                                }

                                                if( $data[0] == "groupmembers_exception" )
                                                {
                                                    $ObjectGroupMembersException = $data[3];
                                                }

                                                if( $data[0] == "layer7filter" )
                                                {
                                                    $ObjectLayer7Filter = $data[2];
                                                }

                                                if( $data[0] == "destinationport" )
                                                {
                                                    $ObjectDestinationPort = $data[2];
                                                }
                                                if( $data[0] == "sourceport" )
                                                {
                                                    $ObjectSourcePort = $data[2];
                                                }
                                                if( $data[0] == "protocol" )
                                                {
                                                    $ObjectProtocol = $data[2];
                                                }
                                            }
                                            #groupmembers
                                        }
                                    }
                                    #print $record;
                                    #print $data[0]." ".$data[1]."\n";
                                }

                            }

                        }

                        if( $Services == "true" )
                        {
                            if( preg_match("/^  }/i", $record) )
                            {
                                $Services = "false";
                            }
                            else
                            {
                                # print $record;
                                if( preg_match("/^  \"services\": \{/i", $record) )
                                {
                                }
                                else
                                {
                                    #All the objects without the objects definition
                                    $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                    if( preg_match("/: {/", $record) )
                                    {
                                        $enterObject = "true";
                                    }

                                    if( $enterObject = "true" )
                                    {

                                        if( preg_match("/}/", $record) )
                                        {
                                            $enterObject = "false";

                                            #Salimos del objeto y lo printamos
                                            $servicesline .= "$ObjectName;$ObjectType;$ObjectSourcePort;$ObjectDestinationPort;;$members2;$ObjectComment;$isShared\n";


                                            #print "$ObjectName - $ObjectType - $ObjectIP - $ObjectComment - $ObjectGatewayBrand - $ObjectGRoupMembersBase - $ObjectGroupMembersException - $ObjectLayer7Filter - $ObjectDestinationPort - $ObjectSourcePort - $ObjectProtocol\n";

                                            #limpiamos variables
                                            $ObjectName = "";
                                            $ObjectType = "";
                                            $ObjectIP = "";
                                            $ObjectComment = "";
                                            $ObjectGatewayBrand = "";
                                            $ObjectGRoupMembersBase = "";
                                            $ObjectGroupMembersException = "";
                                            $ObjectLayer7Filter = "";
                                            $ObjectDestinationPort = "";
                                            $ObjectSourcePort = "";
                                            $ObjectProtocol = "";
                                            $members = "";
                                            $members2 = "";
                                            $isShared = "0";
                                        }
                                        else
                                        {

                                            if( preg_match("/,\"groupmembers\": \[/i", $record) )
                                            {
                                                $isGroup = "true";
                                            }

                                            if( $isGroup == "true" )
                                            {
                                                if( preg_match("/]/", $record) )
                                                {
                                                    $isGroup = "false";
                                                    #printar el resultado de todos miembros
                                                    $members2 = substr($members, 1);
                                                    #echo "members: $members2\n";

                                                }
                                                else
                                                {
                                                    $data2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $record, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                                                    if( $data2[0] == "groupmembers" )
                                                    {
                                                    }
                                                    else
                                                    {

                                                        $members .= "," . $data2[0];
                                                    }
                                                    #print "AQUI ".$data2[0];
                                                }
                                            }
                                            if( isset($data[0]) )
                                            {
                                                if( $data[0] == "name" )
                                                {
                                                    if( $data[2] != "" )
                                                    {
                                                        $ObjectName = $data[2];
                                                    }
                                                }

                                                if( $data[0] == "type" )
                                                {
                                                    $ObjectType = $data[2];
                                                }

                                                if( $data[0] == "ipaddr" )
                                                {
                                                    $ObjectIP = $data[2];
                                                }

                                                if( $data[0] == "shared" )
                                                {
                                                    $isShared = $data[2];
                                                }

                                                if( $data[0] == "comment" )
                                                {
                                                    $ObjectComment = $data[2];
                                                }

                                                if( $data[0] == "gateway_brand" )
                                                {
                                                    $ObjectGatewayBrand = $data[2];
                                                }

                                                if( $data[0] == "groupmembers_base" )
                                                {
                                                    $ObjectGRoupMembersBase = $data[2];
                                                }

                                                if( $data[0] == "groupmembers_exception" )
                                                {
                                                    $ObjectGroupMembersException = $data[2];
                                                }

                                                if( $data[0] == "layer7filter" )
                                                {
                                                    $ObjectLayer7Filter = $data[2];
                                                }

                                                if( $data[0] == "destinationport" )
                                                {
                                                    $ObjectDestinationPort = $data[2];
                                                }
                                                if( $data[0] == "sourceport" )
                                                {
                                                    $ObjectSourcePort = $data[2];
                                                }
                                                if( $data[0] == "protocol" )
                                                {
                                                    $ObjectProtocol = $data[2];
                                                }
                                            }
                                            #groupmembers
                                        }
                                    }
                                    #print $record;
                                    #print $data[0]." ".$data[1]."\n";
                                }

                                #End
                            }

                        }

                    }

                    #Guardar Ficheros
                    if( !$handle = fopen($Objects_File, 'w') )
                    {
                        echo "Cannot open ($Objects_File)";
                        exit;
                    }
                    if( fwrite($handle, $objectline) === FALSE )
                    {
                        echo "Cannot write to ($Objects_File)";
                        exit;
                    }
                    fclose($handle);

                    #Guardar Services
                    if( !$handle = fopen($Services_File, 'w') )
                    {
                        echo "Cannot open ($Services_File)";
                        exit;
                    }
                    if( fwrite($handle, $servicesline) === FALSE )
                    {
                        echo "Cannot write to ($Services_File)";
                        exit;
                    }
                    fclose($handle);

                    #Guardar Rules
                    if( !$handle = fopen($Rules_File, 'w') )
                    {
                        echo "Cannot open ($Rules_File)";
                        exit;
                    }
                    if( fwrite($handle, $rulesline) === FALSE )
                    {
                        echo "Cannot write to ($Rules_File)";
                        exit;
                    }
                    fclose($handle);

                    #Guardar NatRules
                    if( !$handle = fopen($Nat_File, 'w') )
                    {
                        echo "Cannot open ($Nat_File)";
                        exit;
                    }
                    if( fwrite($handle, $natrulesline) === FALSE )
                    {
                        echo "Cannot write to ($Nat_File)";
                        exit;
                    }
                    fclose($handle);
                }
                $checkJsonParser = TRUE;
            }
            else
            {
                #Debug
                #If the rules.txt has been created but the debug contain an error we will stop the process
                if( (file_exists(USERSPACE_PATH . '/projects/' . $project . '/debug.txt')) and (filesize(USERSPACE_PATH . '/projects/' . $project . '/debug.txt') != 0) )
                {
                    $get_debug = file(USERSPACE_PATH . '/projects/' . $project . '/debug.txt');
                    foreach( $get_debug as $line => $debug_line )
                    {
                        if( preg_match('/KeyError/i', $debug_line) )
                        {
                            #list($kk,$errores)=split('\'',$debug_line);
                            update_progress($project, '-1.00', 'We cannot continue. Failed!', $jobid);
                            exit;
                        }
                    }
                }
            }

            //Check Again for if the jsonparser has worked
            if( $checkJsonParser == TRUE )
            {
                if( !file_exists(USERSPACE_PATH . "/projects/$project/objects.txt") )
                {
                    $get_debug = file(USERSPACE_PATH . '/projects/' . $project . '/debug.txt');
                    foreach( $get_debug as $line => $debug_line )
                    {
                        if( preg_match('/KeyError/i', $debug_line) )
                        {
                            #list($kk,$errores)=split('\'',$debug_line);
                            ##add_log('4','Phase 1: Start Parsing Files','Impossible to migrate this configuration. Object '.$errores.' is not in your Objects file',$project,'Check if the files were correctly assigned');
                        }
                    }
                    update_progress($project, '-1.00', 'We cannot continue. Failed!', $jobid);
                    exit;
                }
                else
                {
                    ##add_log('1','Phase 1: Start Parsing Files','All the minimum files has been parsed',$project,'No Action required');
                    update_progress($project, '0.10', 'Phase 1 of 10', $jobid);
                }
            }

            #Check if is the first vsys
            if( $checkpointName == "" )
            {
                $filename = unique_id(10);
            }
            else
            {
                $filename = $checkpointName;
            }

            $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
            if( $getVsys->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','shared','Checkpoint')");
                $source = $projectdb->insert_id;

                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','vsys1','Checkpoint')");
                $vsys = "vsys1";
                if( $source == "" )
                {
                    $source = $projectdb->insert_id;
                }
                $sourceAdded[] = $source;
            }
            else
            {
                $getnewVsys = $projectdb->query("SELECT max(id) as maxid FROM device_mapping WHERE vsys!='shared' AND filename='$filename';");
                if( $getnewVsys->num_rows == 1 )
                {
                    $getmaxid = $getnewVsys->fetch_assoc();
                    $maxid = $getmaxid['maxid'];
                    $getnewVsys = $projectdb->query("SELECT vsys FROM device_mapping WHERE id='$maxid';");
                    if( $getnewVsys->num_rows == 1 )
                    {
                        $getnewVsysData = $getnewVsys->fetch_assoc();
                        $tmp_vsys = $getnewVsysData['vsys'];
                        $tmp_vsys0 = explode("vsys", $tmp_vsys);
                        $vsysID = intval($tmp_vsys0[1]);
                        $vsysID++;
                        $vsys = "vsys" . $vsysID;
                        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','$vsys','Checkpoint')");
                    }
                }
            }

            #Config Template
            $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
            $template_name = $filename . "_template";
            $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
            $template = $projectdb->insert_id;

            if( $convertObjectsShared )
            {
                if( $alreadyLoaded === FALSE )
                {
                    add_default_services($source);
                    update_progress($project, '0.20', 'Rulebase ' . $policyName . ' Phase 2 of 10 Loading Address to Shared', $jobid);
                    get_objects($project, $source, "shared");
                    update_progress($project, '0.30', 'Rulebase ' . $policyName . ' Phase 3 of 10 Loading Services to Shared', $jobid);
                    get_services($project, $source, "shared");
                    $alreadyLoaded = TRUE;
                }
            }
            else
            {
                add_default_services($source);
                update_progress($project, '0.20', 'Rulebase ' . $policyName . ' Phase 2 of 10 Loading Address into ' . $vsys, $jobid);
                get_objects($project, $source, $vsys);
                update_progress($project, '0.30', 'Rulebase ' . $policyName . ' Phase 3 of 10 Loading Services into ' . $vsys, $jobid);
                get_services($project, $source, $vsys);
            }

            update_progress($project, '0.40', 'Rulebase ' . $policyName . ' Phase 4 of 10 Loading Network information', $jobid);
            get_routes($project, $source, $template, $vsys);
            update_progress($project, '0.50', 'Rulebase ' . $policyName . ' Phase 5 of 10 Loading Security Rules into ' . $vsys, $jobid);
            get_security_policies($project, $source, $vsys, $convertObjectsShared);
            update_progress($project, '0.60', 'Rulebase ' . $policyName . ' Phase 6 of 10 Loading NAT Rules into ' . $vsys, $jobid);
            get_nat_policies($project, $source, $vsys, $convertObjectsShared);


            //update_progress($project,'0.70','Rulebase '.$policyName.' Phase 7 of 10',$jobid);
            //GroupMember2IdAddress($filename);

            //update_progress($project,'0.80','Rulebase '.$policyName.' Phase 8 of 10',$jobid);


            //update_progress($project,'0.85','Rulebase '.$policyName.' Phase 9 of 10',$jobid);

            //update_progress($project,'0.90','Calculating Used Objects',$jobid);
            //update_progress($project,'0.95','Rulebase '.$policyName.' Phase 9 of 10',$jobid);
            //update_progress($project,'0.98','Rulebase '.$policyName.' Phase 9 of 10',$jobid);


            clean_partial_files($project, $policyName);


            // Call function to generate initial consumptions
            deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);

        }
        else
        {
            #add_log('4','Phase 1: Start Parsing Files','Impossible to migrate this configuration',$project,'Check if the files were the right ones and were correctly assigned to the right upload field');
            update_progress($project, '-1.00', 'We cannot start. Failed!', $jobid);
        }

    }


    //generate_viewer($project);
    update_progress($project, '0.7', 'Calculating Group  Phase 7 of 10', $jobid);
    GroupMember2IdAddress_improved($filename);
    GroupMember2IdServices($filename);
    calculateExclusionGroups();
    update_progress($project, '0.8', 'Calculating Used/Unused Objects Phase 8 of 10', $jobid);
    check_used_objects_new($sourceAdded);
    #Removing all the Unused Objects
    update_progress($project, '0.9', 'Optimizing Phase 9 of 10', $jobid);
    $getAllvsys = $projectdb->query("SELECT vsys FROM device_mapping WHERE filename='$filename';");
    if( $getAllvsys->num_rows > 0 )
    {
        while( $getAllvsysData = $getAllvsys->fetch_assoc() )
        {
            $vsys = $getAllvsysData['vsys'];
            ##delete_unused($source,$vsys);
            fix_destination_nat($source, $vsys, $skipDNAT);
            get_normalized_names($source, $vsys);
            auto_rule_name($vsys, "rules", $project, $source);
            optimization($source, $vsys, $template);
        }
    }

    #Calculate Layer4-7
    $queryRuleIds = "SELECT id from security_rules WHERE source = $source;";
    $resultRuleIds = $projectdb->query($queryRuleIds);
    if( $resultRuleIds->num_rows > 0 )
    {
        $rules = array();
        while( $dataRuleIds = $resultRuleIds->fetch_assoc() )
        {
            $rules[] = $dataRuleIds['id'];
        }
        $rulesString = implode(",", $rules);
        $securityRulesMan = new \SecurityRulePANObject();
        $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
    }

    clean_files($project);
    update_progress($project, '1.0', 'Done', $jobid);


}

#Functions for Checkpoint Only
function getLineWithString($fileName, $str)
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
            $record[] = $remove[0];
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

function getPolicyName($fileName, $str, $project)
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

function clean_partial_files($project, $policyName)
{
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/rules.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/rules.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/routes.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/routes.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/routes.out") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/routes.out");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/conf.fwdoc") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/conf.fwdoc");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/natrules.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/natrules.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/objects.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/objects.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/" . $policyName) )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/" . $policyName);
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/" . $policyName . "_FWS") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/" . $policyName . "_FWS");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/services.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/services.txt");
    }
}

function clean_files($project)
{
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/rules.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/rules.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/routes.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/routes.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/routes.out") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/routes.out");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/conf.fwdoc") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/conf.fwdoc");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/natrules.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/natrules.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/objects_5_0.C") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/objects_5_0.C");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/objects.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/objects.txt");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/PolicyName.W") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/PolicyName.W");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/PolicyName.W_FWS") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/PolicyName.W_FWS");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/rulebases_5_0.fws") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/rulebases_5_0.fws");
    }
    if( file_exists(USERSPACE_PATH . "/projects/" . $project . "/services.txt") )
    {
        unlink(USERSPACE_PATH . "/projects/" . $project . "/services.txt");
    }
}

function get_objects($project, $source, $vsys)
{
    global $projectdb;
    $original_vsys = $vsys;
    $objectsfile = USERSPACE_PATH . "/projects/$project/objects.txt";
    $lines = file($objectsfile);
    $linesNumber = count(($lines));

    #add_log('1','Phase 2: Reading Address Objects and Groups','Saving Objects in the DataBase',$project,$linesNumber.' objects found.');
    $getMax = $projectdb->query("SELECT max(id) as max FROM address_groups_id;");
    if( $getMax->num_rows == 1 )
    {
        $getMaxData = $getMax->fetch_assoc();
        $lid = $getMaxData["max"] + 1;
    }
    else
    {
        $lid = 1;
    }

    #If we found objects type edge we will create an IP address like 10.10.10.X LIMITATION 254 Objects from 1 to 254
    $ipaddress_host_edge = 1;

    $address = array();
    $addmembers = array();
    $addressgroups = array();
    foreach( $lines as $line_num => $line )
    {
        #Clean VARS
        $name = "";
        $type = "";
        $ip = "";
        $mask = "";
        $firstip = "";
        $lastip = "";
        $members = "";
        $member = "";
        $member_var = "";
        $x = "";
        $isGlobal = "0";

        $data = explode(";", $line);

        $name = $data[0];
        $type = rtrim($data[1]);
        $ipaddress = trim($data[4]);
        $members = $data[6];
        $descriptiontrimmed = rtrim($data[7]);
        $description = normalizeComments($descriptiontrimmed);
        if( isset($data[8]) )
        {
            $obj_interfaces = trim($data[8]);
        }
        else
        {
            $obj_interfaces = "";
        }

        if( isset($data[9]) )
        {
            $isGlobal = $data[9];
            if( $isGlobal == 1 )
            {
                $vsys = "shared";
            }
            else
            {
                $vsys = $original_vsys;
            }
        }
        else
        {
            $vsys = $original_vsys;
        }

        #Get IP Version Default v4
        $ipversion = ip_version($ipaddress);

        #Types of Objects
        if( $type == "machines_range" )
        {
            $ranges = preg_split('/ - /', $ipaddress, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $firstip = trim($ranges[0]);
            $lastip = trim($ranges[1]);
            #Get IP Version Default v4
            $ipversion = ip_version($firstip);
        }

        if( preg_match("/\//i", $ipaddress) )
        {
            $newvar = explode("/", $ipaddress);
            $ip = trim($newvar[0]);
            $mask = $newvar[1];
        }
        else
        {
            $ip = trim($ipaddress);
        }

        if( $ipversion == "v4" )
        {
            $hostCidr = "32";
        }
        if( $ipversion == "v6" )
        {
            $hostCidr = "128";
        }
        else
        {
            $ipversion = "v4";
        }

        if( $type == "cluster_member" )
        {
            $address[$ipversion][] = "('ip-netmask','$type','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";
        }
        elseif( $type == "dynamic_net_obj" )
        {
            $address[$ipversion][] = "('ip-netmask','$type','$ip','$mask','$name','$name','1','1','$description','$source','$vsys')";
        }
        elseif( $type == "domain" )
        {
            #All the resolutions will be V4 by now cidr 32
            $x = gethostbyname($name);
            $address[$ipversion][] = "('fqdn','$type','$x','32','$name','$name','1','1','$description','$source','$vsys')";
            #$projectdb->query("Insert into errors (level,source,message) values ('warning','resolve_domain','Domain object, please do a nslookup, resolve the domain name and check the Ip address field : $line');");
        }
        elseif( $type == "gateway_cluster" )
        {
            if( $obj_interfaces == "" )
            {
                $address[$ipversion][] = "('ip-netmask','ip-netmask','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";
            }
            else
            {
                #Convert to Group
                $newMembers = array();
                $myInt = explode(",", $obj_interfaces);
                $execute_group = FALSE;
                if( count($myInt) == 1 )
                {
                    $get_parts = explode("/", $obj_interfaces);
                    if( $ip == $get_parts[0] )
                    {
                        #as Host
                        $address[$ipversion][] = "('ip-netmask','ip-netmask','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";
                        $execute_group = FALSE;
                    }
                    else
                    {
                        #group
                        $execute_group = TRUE;
                    }
                }
                elseif( count($myInt) > 1 )
                {
                    $execute_group = TRUE;
                }

                if( $execute_group === TRUE )
                {
                    if( ($ip != "") and ($ip != "0.0.0.0") )
                    {
                        $address[$ipversion][] = "('ip-netmask','ip-netmask','$ip','$hostCidr','INT-$ip-$hostCidr','INT-$ip-$hostCidr','0','1','$description','$source','$vsys')";
                        $newMembers[] = "INT-$ip-$hostCidr";
                        foreach( $myInt as $key => $value )
                        {
                            $network_and_cidr = explode("/", $value);
                            $ipversion2 = ip_version($network_and_cidr[0]);
                            if( $ipversion2 == "v4" )
                            {
                                $hostCidr2 = "32";
                            }
                            if( $ipversion2 == "v6" )
                            {
                                $hostCidr2 = "128";
                            }
                            else
                            {
                                $ipversion2 = "v4";
                            }
                            $nameInt = "INT-" . $network_and_cidr[0] . "-" . $hostCidr2;
                            if( ($nameInt != "INT--") and ($nameInt != "INT-0.0.0.0-0") )
                            {
                                $newMembers[] = $nameInt;
                                $address[$ipversion][] = "('ip-netmask','ip-netmask','$network_and_cidr[0]','$hostCidr2','$nameInt','$nameInt','0','1','$description','$source','$vsys')";
                            }
                        }
                        //$projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,type,checkit) VALUES ('$name','$name','$source','static','0')");
                        //$lid=$projectdb->insert_id;
                        $addressgroups[] = "('$lid','$name','$name','$source','static','0','$vsys','$description')";
                        foreach( $newMembers as $key2 => $member_var )
                        {
                            $addmembers[] = "('$lid','$member_var','$source','$vsys')";
                            #$projectdb->query("INSERT INTO address_groups (lid,member,source) values('$lid','$member_var','$source');");
                        }
                        $lid++;
                        add_log2('warning', 'Transformation', 'Host called [' . $name . '] has many Interfaces [' . $obj_interfaces . '] Converting to Address Group', $source, 'No action required', 'objects', $lid, 'address_groups_id');
                    }
                    $execute_group = FALSE;
                }


            }
            #$address[$ipversion][]="('ip-netmask','$type','$ipaddress','$hostCidr','$name','1','1','$description','$source')";
        }
        elseif( $type == "gateway_fw" )
        {
            $address[$ipversion][] = "('ip-netmask','$type','$ip','$mask','$name','$name','1','1','$description','$source','$vsys')";
        }
        elseif( $type == "gateways" )
        {
            $address[$ipversion][] = "('ip-netmask','$type','$ip','$mask','$name','$name','1','1','$description','$source','$vsys')";
        }
        elseif( $type == "host" )
        {
            if( $obj_interfaces == "" )
            {
                $address[$ipversion][] = "('ip-netmask','ip-netmask','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";
            }
            else
            {
                #Convert to Group
                $newMembers = array();
                $myInt = explode(",", $obj_interfaces);
                $execute_group = FALSE;
                if( count($myInt) == 1 )
                {
                    $get_parts = explode("/", $obj_interfaces);
                    if( $ip == $get_parts[0] )
                    {
                        #as Host
                        $address[$ipversion][] = "('ip-netmask','ip-netmask','$ip','$hostCidr','$name','$name','0','1','$description','$source','$vsys')";
                        $execute_group = FALSE;
                    }
                    else
                    {
                        #group
                        $execute_group = TRUE;
                    }
                }
                elseif( count($myInt) > 1 )
                {
                    $execute_group = TRUE;
                }

                if( $execute_group === TRUE )
                {
                    if( ($ip != "") and ($ip != "0.0.0.0") )
                    {
                        $address[$ipversion][] = "('ip-netmask','ip-netmask','$ip','$hostCidr','INT-$ip-$hostCidr','INT-$ip-$hostCidr','0','1','$description','$source','$vsys')";
                        $newMembers[] = "INT-$ip-$hostCidr";
                        foreach( $myInt as $key => $value )
                        {
                            $network_and_cidr = explode("/", $value);
                            $ipversion2 = ip_version($network_and_cidr[0]);
                            if( $ipversion2 == "v4" )
                            {
                                $hostCidr2 = "32";
                            }
                            if( $ipversion2 == "v6" )
                            {
                                $hostCidr2 = "128";
                            }
                            else
                            {
                                $ipversion2 = "v4";
                            }
                            $nameInt = "INT-" . $network_and_cidr[0] . "-" . $hostCidr2;
                            if( ($nameInt != "INT--") and ($nameInt != "INT-0.0.0.0-0") )
                            {
                                $newMembers[] = $nameInt;
                                $address[$ipversion][] = "('ip-netmask','ip-netmask','$network_and_cidr[0]','$hostCidr2','$nameInt','$nameInt','0','1','$description','$source','$vsys')";
                            }
                        }
                        $addressgroups[] = "('$lid','$name','$name','$source','static','0','$vsys','$description')";
                        //$projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,type,checkit,vsys) VALUES ('$name','$name','$source','static','0','$vsys')");
                        //$lid=$projectdb->insert_id;
                        foreach( $newMembers as $key2 => $member_var )
                        {
                            $addmembers[] = "('$lid','$member_var','$source','$vsys')";
                            #$projectdb->query("INSERT INTO address_groups (lid,member,source) values('$lid','$member_var','$source');");
                        }
                        $lid++;
                        add_log2('warning', 'Transformation', 'Host called [' . $name . '] has many Interfaces [' . $obj_interfaces . '] Converting to Address Group', $source, 'No action required', 'objects', $lid, 'address_groups_id');
                    }
                    $execute_group = FALSE;
                }


            }

        }
        elseif( $type == "gateway" )
        {
            $address[$ipversion][] = "('ip-netmask','$type','$ip','$hostCidr','$name','$name','1','1','$description','$source','$vsys')";
        }
        elseif( $type == "machines_range" )
        {
            $address[$ipversion][] = "('ip-range','ip-range','$firstip-$lastip','','$name','$name','0','1','$description','$source','$vsys')";
        }
        elseif( $type == "network" )
        {
            $address[$ipversion][] = "('ip-netmask','ip-netmask','$ip','$mask','$name','$name','0','1','$description','$source','$vsys')";
        }
        elseif( $type == "router" )
        {
            $address[$ipversion][] = "('ip-netmask','$type','$ip','$mask','$name','$name','1','1','$description','$source','$vsys')";
        }
        elseif( $type == "security_zone_obj" )
        {

        }
        elseif( $type == "community" )
        {
            #What to do with the communities VPN?? nothing by now
            #add_log('2','Phase 2: Reading Address Objects and Groups','VPN Community found',$project,'Omiting Object '.$name);
        }
        elseif( ($type == "sofaware_gateway") or ($type == "voip_gk") or ($type == "voip_gw") )
        {
            $ipaddress_host_edge = $ipaddress_host_edge + 1;
            $ipaddress_host_edge_ip = "10.10.10." . $ipaddress_host_edge;
            $address[$ipversion][] = "('ip-netmask','$type','$ipaddress_host_edge_ip','32','$name','$name','1','1','$description','$source','$vsys')";
            add_log('warning', 'Phase 2: Reading Address Objects and Groups', 'Sofaware/voIP gateway found, creating group with 2 members', $source, 'Added ' . $name . ' with ip ' . $ipaddress_host_edge_ip);
        }
        elseif( $type == "group_with_exclusion" )
        {
            $member = explode(",", $members);
            //$projectdb->query("INSERT INTO address_groups_id (name,source,type,checkit) VALUES ('$name','$source','static','1')");
            //$projectdb->query("INSERT INTO address_groups_id (name_ext,name,source,type,checkit,vsys) VALUES ('$name','$name','$source','group_with_exclusion','1','$vsys')");

            $addressgroups[] = "('$lid','$name','$name','$source','group_with_exclusion','1','$vsys','$description')";
            foreach( $member as $member_var )
            {
                $addmembers[] = "('$lid','$member_var','$source','$vsys')";
            }
            $lid++;
            // Exclusions Groups
            //calculateExclusionGroups($lid);

            //add_log('warning','Phase 2: Reading Address Objects and Groups','Group with Exclusion found, creating group with 2 members',$source,'Group '.$name.': The first member is the Global, second the excluded.');
        }
        elseif( $type == "group" )
        {
            $member = explode(",", $members);
            //$projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,type,checkit,vsys) VALUES ('$name','$name','$source','static','0','$vsys')");
            //$lid=$projectdb->insert_id;
            $addressgroups[] = "('$lid','$name','$name','$source','static','0','$vsys','$description')";
            foreach( $member as $member_var )
            {
                $addmembers[] = "('$lid','$member_var','$source','$vsys')";
            }
            $lid++;
        }
        else
        {
            add_log('error', 'Phase 2: Reading Address Objects and Groups', 'Unexpected Object found', $source, 'Please send an email to fwmigrate@paloaltonetworks.com :' . $line);
        }


    }
    if( (isset($address['v4'])) and (count($address['v4']) > 0) )
    {
        $unique = array_unique($address['v4']);
        $projectdb->query("INSERT INTO address (type,vtype,ipaddress,cidr,name,name_ext, checkit,v4,description,source,vsys) VALUES " . implode(",", $unique) . ";");
    }
    if( (isset($address['v6'])) and (count($address['v6']) > 0) )
    {
        $unique = array_unique($address['v6']);
        $projectdb->query("INSERT INTO address (type,vtype,ipaddress,cidr,name,checkit,v6,description,source,vsys) VALUES " . implode(",", $unique) . ";");
    }
    unset($address);
    if( (isset($addressgroups)) and (count($addressgroups) > 0) )
    {
        $projectdb->query("INSERT INTO address_groups_id (id,name,name_ext,source,type,checkit,vsys,description) VALUES " . implode(",", $addressgroups) . ";");
        unset($addressgroups);
        if( (isset($addmembers)) and (count($addmembers) > 0) )
        {
            $unique = array_unique($addmembers);
            $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys) VALUES " . implode(",", $unique) . ";");
            unset($unique);
        }
        unset($addmembers);
    }

    #Clean Vars
    $lines = "";
}

function get_services($project, $source, $vsys)
{
    global $projectdb;
    $servicesfile = USERSPACE_PATH . "/projects/$project/services.txt";
    $lines = file($servicesfile);
    $linesNumber = count(($lines));
    #add_log('1','Phase 3: Reading Services Objects and Groups','Saving Services in the DataBase',$project,$linesNumber.' services found.');
    $getMax = $projectdb->query("SELECT max(id) as max FROM services_groups_id;");
    if( $getMax->num_rows == 1 )
    {
        $getMaxData = $getMax->fetch_assoc();
        $lid = $getMaxData["max"] + 1;
    }
    $services = array();
    $servicesMembers = array();
    $servicegroups = array();
    $original_vsys = $vsys;
    foreach( $lines as $line_num => $line )
    {
        $servicename = "";
        $servicerange = "";
        $serviceprotocol = "";
        $serviceport = "";
        $servicemembers = "";
        $servicemember = "";
        $servicemember_var = "";
        $firstport = "";
        $lastport = "";
        $isGlobal = "0";

        $data = explode(";", $line);

        $name = $data[0];
        $serviceprotocol = $data[1];
        $srcport = $data[2];
        $serviceport = $data[3];
        $dcerpc = $data[4];
        $servicemembers = $data[5];
        $descriptiontrimmed = rtrim($data[6]);
        $description = addslashes(normalizeComments($descriptiontrimmed));

        if( isset($data[7]) )
        {
            $isGlobal = $data[7];
            if( $isGlobal == 1 )
            {
                $vsys = "shared";
            }
            else
            {
                $vsys = $original_vsys;
            }
        }
        else
        {
            $vsys = $original_vsys;
        }

        if( ($serviceprotocol == "tcp") or ($serviceprotocol == "udp") )
        {

            if( preg_match("/:/i", $serviceport) )
            {
                $newvar = explode(":", $serviceport);
                $firstport = $newvar[0];
                $lastport = $newvar[1];
                $serviceport = "$firstport-$lastport";
            }
            elseif( preg_match("/>/i", $serviceport) )
            {
                $newvar = explode(">", $serviceport);
                $firstport = intval($newvar[1]) + 1;
                $serviceport = "$firstport-65535";
            }
            elseif( preg_match("/</i", $serviceport) )
            {
                $newvar = explode("<", $serviceport);
                $firstport = intval($newvar[1]) - 1;
                $serviceport = "0-$firstport";
            }

            # Src_PORT
            if( preg_match("/:/i", $srcport) )
            {
                $newvar = explode(":", $srcport);
                $firstport = $newvar[0];
                $lastport = $newvar[1];
                $srcport = "$firstport-$lastport";
            }
            elseif( preg_match("/>/i", $srcport) )
            {
                $newvar = explode(">", $srcport);
                $firstport = intval($newvar[1]) + 1;
                $srcport = "$firstport-65535";
            }
            elseif( preg_match("/</i", $srcport) )
            {
                $newvar = explode("<", $srcport);
                $firstport = intval($newvar[1]) - 1;
                $srcport = "0-$firstport";
            }

            $services[] = "('$name','$name','$serviceprotocol','$serviceport','0','$description','$source','0','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "group" )
        {
            $servicemember = explode(",", $servicemembers);
            $servicegroups[] = "('$lid','$name','$source','0','$vsys','$description')";
            foreach( $servicemember as $servicemember_var )
            {
                $servicesMembers[] = "('$lid','$servicemember_var','$source','$vsys')";
            }
            $lid++;
        }
        elseif( $serviceprotocol == "gtp" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','0','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "gtp_mm_v0" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','0','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "gtp_mm_v1" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','0','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "gtp_v1" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','0','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "icmp" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','1','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "icmpv6" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','1','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "other" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','0','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "tcp_citrix" )
        {
            $services[] = "('$name','$name','tcp','$serviceport','1','$description','$source','0','$vsys','$srcport')";
        }
        elseif( $serviceprotocol == "tcp_subservice" )
        {
            $services[] = "('$name','$name','$serviceprotocol','$serviceport','1','$description','$source','0','$vsys','$srcport')";
        }
        else
        {
            if( $serviceprotocol != "" )
            {
                add_log('error', 'Phase 3: Reading Services Objects and Groups', 'Reading Contents', $source, 'Unknown Service Protocol, please send a mail to fwmigrate@paloaltonetworks.com : ' . $serviceline);
            }
        }
    }

    if( count($services) > 0 )
    {
        $unique = array_unique($services);
        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,checkit,description,source,icmp,vsys,sport) VALUES " . implode(",", $unique) . ";");
        unset($services);
        unset($unique);
    }
    if( count($servicegroups) > 0 )
    {
        $projectdb->query("INSERT INTO services_groups_id (id,name,source,checkit,vsys,description) VALUES " . implode(",", $servicegroups) . ";");
        unset($servicegroups);
        if( count($servicesMembers) > 0 )
        {
            $projectdb->query("INSERT INTO services_groups (lid,member,source,vsys) VALUES " . implode(",", $servicesMembers) . ";");
            unset($servicesMembers);
        }
    }

}

function generate_viewer()
{
    global $project;
    if( file_exists(USERSPACE_PATH . "/projects/$project/rulebases_5_0.fws") )
    {
        $cmd = "/usr/bin/perl /var/www/html/tools/cpoint_viewer/fw1rules.pl --output_html=" . USERSPACE_PATH . "/projects/$project/CPviewer.html --rules=" . USERSPACE_PATH . "/projects/$project/PolicyName.W --merge_AI=" . USERSPACE_PATH . "/projects/$project/rulebases_5_0.fws  --objects=" . USERSPACE_PATH . "/projects/$project/objects_5_0.C --with_ip --show_members --icon_path=/tools/cpoint_viewer/icons";
    }
    else
    {
        $cmd = "/usr/bin/perl /var/www/html/tools/cpoint_viewer/fw1rules.pl --output_html=" . USERSPACE_PATH . "/projects/$project/CPviewer.html --rules=" . USERSPACE_PATH . "/projects/$project/PolicyName.W --objects=" . USERSPACE_PATH . "/projects/$project/objects_5_0.C --with_ip --show_members --icon_path=/tools/cpoint_viewer/icons";
    }
    shell_exec($cmd);
}

function get_nat_policies($project, $source, $vsys, $convertObjectsShared)
{
    global $projectdb;
    $rulesfile = USERSPACE_PATH . "/projects/$project/natrules.txt";
    $lines = file($rulesfile);
    #$linesNumber = count(($lines));
    $headerB = "";
    $thecolor = 1;
    if( $vsys == "" )
    {
        $vsys = "vsys1";
    }
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if( $getPosition->num_rows == 0 )
    {
        $position = 1;
    }
    else
    {
        $ddata = $getPosition->fetch_assoc();
        $position = $ddata['t'];
    }

    $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']);

    $header = "";
    foreach( $lines as $line_num => $line )
    {
        $data = explode(";", $line);
        $rule_enabled = $data[1];
        $implicit = "0";
        $src = $data[2];
        $destination = $data[3];
        $service = $data[4];
        $nat_type = $data[5];
        $translated_source = $data[6];
        $translated_destination = $data[7];
        $translated_port = $data[8];
        $firewall = $data[9];
        $description = rtrim($data[10]);

        $nat_service_id = "";
        $nat_service_table = "";
        $isImplicit = FALSE;

        #Check if the Rule is implicit or not
        if( $data[0] == "(implicit)" )
        {
            $implicit = "1";
        }

        if( ($implicit == "1") and ($data[6] == "0.0.0.0") )
        {
            $isImplicit = TRUE;
            add_log('3', 'Phase 5: Reading NAT Rules', 'Ignoring Implicit Nat: ' . $line, $source, 'You can add manually later.');
        }
        elseif( $src == "]" )
        {
            $isImplicit = TRUE;
            $header = $data[11];
            #add_log('3','Phase 5: Reading NAT Rules','Ignoring Header TEXT: '.$line,$source,'No Action Required.');
        }
        else
        {
            $lid++;
            $position++;
            $name = "Rule $lid";
            #Get the Description and apply the truncate and normalization
            if( $description == '\"\"' )
            {
                $comment = "";
            }
            else
            {
                $comment = addslashes($description);
            }

            if( $rule_enabled == "yes" )
            {
                $rule_enabled = "0";
            }
            else
            {
                $rule_enabled = "1";
            }
            if( $firewall == "" )
            {
                $firewall = "Any";
            }

            if( $nat_type == "static-ip" )
            {
                $isImplicit = TRUE;
                $getback = $projectdb->query("SELECT MAX(id) AS max_id FROM nat_rules WHERE source='$source';");
                $getbackData = $getback->fetch_assoc();
                $newID = $getbackData['max_id'];
                $projectdb->query("UPDATE nat_rules SET tp_sat_bidirectional='1' WHERE id='$newID';");
            }
            else
            {
                $projectdb->query("INSERT INTO nat_rules (id,position,name,implicit,disabled,target,source,vsys,description) VALUES ('$lid','$position','$name','$implicit','$rule_enabled','$firewall','$source','$vsys','$comment')");

            }


            if( $header != "" )
            {
                $headerFinal = normalizeNames(truncate_tags($header));

                if( $convertObjectsShared )
                {
                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$headerFinal' AND source='$source' AND vsys='shared';");
                    if( $getTag->num_rows == 1 )
                    {
                        $getTagData = $getTag->fetch_assoc();
                        $tag_lid = $getTagData['id'];
                        $add_tag[] = "('$lid','$source','$tag_lid','tag','shared')";
                    }
                    else
                    {
                        #Add Tag
                        $color = "color" . $thecolor;
                        $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$headerFinal','$source','shared','$color');");
                        $tag_lid = $projectdb->insert_id;
                        if( $thecolor == 16 )
                        {
                            $thecolor = 1;
                        }
                        else
                        {
                            $thecolor++;
                        }
                        $add_tag[] = "('$lid','$source','$tag_lid','tag','shared')";
                    }
                }
                else
                {
                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$headerFinal' AND source='$source' AND vsys='$vsys';");
                    if( $getTag->num_rows == 1 )
                    {
                        $getTagData = $getTag->fetch_assoc();
                        $tag_lid = $getTagData['id'];
                        $add_tag[] = "('$lid','$source','$tag_lid','tag','$vsys')";
                    }
                    else
                    {
                        $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$headerFinal' AND source='$source' AND vsys='shared';");
                        if( $getTag->num_rows == 1 )
                        {
                            $getTagData = $getTag->fetch_assoc();
                            $tag_lid = $getTagData['id'];
                            $add_tag[] = "('$lid','$source','$tag_lid','tag','shared')";
                        }
                        else
                        {
                            #Add Tag
                            $color = "color" . $thecolor;
                            $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$headerFinal','$source','$vsys','$color');");
                            $tag_lid = $projectdb->insert_id;
                            if( $thecolor == 16 )
                            {
                                $thecolor = 1;
                            }
                            else
                            {
                                $thecolor++;
                            }
                            $add_tag[] = "('$lid','$source','$tag_lid','tag','$vsys')";
                        }

                    }
                }

            }

        }

        if( $isImplicit == FALSE )
        {
            #Add target
            $members = explode(",", $firewall);

            /*foreach ($members as $member_var){
                if ($member_var=="Gateways"){$member_var="Any";}
                $isdup=$projectdb->query("SELECT id from checkpoint_targets where source='$source' and target='$member_var'");
                if (mysql_num_rows($isdup)==0){
                    if ($member_var!=""){
                        $projectdb->query("INSERT INTO checkpoint_targets (project,target,enabled,vsys) values ('$project','$member_var','1','vsys1');");
                    }
                }
            }*/

            #Add Sources
            if( ($src == "Any") or ($src == "any") or ($src == "ANY") )
            {
            }
            else
            {
                $isGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE name = '$src' AND source='$source' LIMIT 1;");
                if( $isGroup->num_rows == '0' )
                {
                    $search_member_id = $projectdb->query("SELECT id FROM address WHERE name='$src' AND source='$source' LIMIT 1;");
                    $countHost = $search_member_id->num_rows;
                    if( $countHost > 0 )
                    {
                        $search_member_id_assoc = $search_member_id->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $projectdb->query("INSERT INTO nat_rules_src (rule_lid,member_lid,table_name,source,vsys) values ('$lid','$member_id','address','$source','$vsys');");
                    }
                    else
                    {
                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $lid . '] is using an Address [' . $src . '] as Source that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'nat_rules');
                        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys) values ('$src','ip-netmask','$src','1','$source','0','1.1.1.1','32','1','$vsys');");
                        $flid = $projectdb->insert_id;
                        $projectdb->query("INSERT INTO nat_rules_src (rule_lid,member_lid,table_name,source,vsys) values ('$lid','$flid','address','$source','$vsys');");
                    }
                }
                else
                {
                    $search_member_id_assoc = $isGroup->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $projectdb->query("INSERT INTO nat_rules_src (rule_lid,member_lid,table_name,source,vsys) values ('$lid','$member_id','address_groups_id','$source','$vsys');");
                }
            }

            #Add Destinations
            if( ($destination == "Any") or ($destination == "any") or ($destination == "ANY") )
            {
            }
            else
            {
                $isGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE name = '$destination' AND source='$source' LIMIT 1;");
                if( $isGroup->num_rows == '0' )
                {
                    $search_member_id = $projectdb->query("SELECT id FROM address WHERE name='$destination' AND source='$source' LIMIT 1;");
                    $countHost = $search_member_id->num_rows;
                    if( $countHost > 0 )
                    {
                        $search_member_id_assoc = $search_member_id->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,member_lid,table_name,source,vsys) values ('$lid','$member_id','address','$source','$vsys');");
                    }
                    else
                    {
                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $lid . '] is using an Address [' . $destination . '] as Destination that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'nat_rules');
                        $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys) values ('$destination','ip-netmask','$destination','1','$source','0','1.1.1.1','32','1','$vsys');");
                        $flid = $projectdb->insert_id;
                        $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,member_lid,table_name,source,vsys) values ('$lid','$flid','address','$source','$vsys');");
                    }
                }
                else
                {
                    $search_member_id_assoc = $isGroup->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,member_lid,table_name,source,vsys) values ('$lid','$member_id','address_groups_id','$source','$vsys');");
                }
            }

            #Add Service Get the nat_service_id and nat_service_table to be added to nat_rules
            if( ($service == "Any") or ($service == "any") or ($service == "ANY") )
            {
            }
            else
            {
                $isGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE name = '$service' AND source='$source' LIMIT 1;");
                $rows = $isGroup->num_rows;
                if( $rows == '0' )
                {
                    $search_member_id = $projectdb->query("SELECT id FROM services WHERE name='$service' AND source='$source' LIMIT 1;");
                    $countHost = $search_member_id->num_rows;
                    if( $countHost > 0 )
                    {
                        $search_member_id_assoc = $search_member_id->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $nat_service_id = $member_id;
                        $nat_service_table = "services";
                        $projectdb->query("UPDATE nat_rules SET op_service_lid='$nat_service_id', op_service_table='$nat_service_table' WHERE id='$lid';");
                    }
                    else
                    {
                        add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $lid . '] is using a Service [' . $service . ']  that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB. Assign a port and protocol', 'rules', $lid, 'nat_rules');
                        $projectdb->query("INSERT INTO services (type,name,checkit,source,used,vsys) values('','$service','1','$source','1','$vsys');");
                        $flid = $projectdb->insert_id;
                        $projectdb->query("UPDATE nat_rules SET op_service_lid='$flid', op_service_table='services' WHERE id='$lid';");
                    }
                }
                else
                {
                    $search_member_id_assoc = $isGroup->fetch_assoc();
                    $member_id = $search_member_id_assoc['id'];
                    $nat_service_id = $member_id;
                    $nat_service_table = "services_groups_id";
                    $projectdb->query("UPDATE nat_rules SET op_service_lid='$nat_service_id', op_service_table='$nat_service_table' WHERE id='$lid';");
                    //add_log2('error','Reading Nat Policies','Nat RuleID ['.$lid.'] is using a Service Group as a Destination ['.$service.']  that is not supported by Palo Alto Networks. It has to be a Service instead. Fix it before to finish',$source,'Adding Alert','rules',$lid,'nat_rules');
                }
            }

            #Source Translation
            if( $translated_source == "ORIGINAL" )
            {
                $nat_type = "None";
            }
            else
            {
                $checkIPversion = ip_version($translated_source);

                if( $checkIPversion == "noip" )
                {
                    $isGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE name = '$translated_source' AND source='$source' limit 1;");
                    if( $isGroup->num_rows == '0' )
                    {
                        $search_member_id = $projectdb->query("SELECT id FROM address WHERE name='$translated_source' AND source='$source' limit 1;");
                        $countHost = $search_member_id->num_rows;
                        if( $countHost > 0 )
                        {
                            $search_member_id_assoc = $search_member_id->fetch_assoc();
                            $member_id = $search_member_id_assoc['id'];
                            $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys) VALUES ('$lid','$member_id','address','$source','$vsys');");
                        }
                        else
                        {
                            add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $lid . '] is using an Address [' . $translated_source . '] as Translated address that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'nat_rules');
                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys) values ('$translated_source','ip-netmask','$translated_source','1','$source','0','1.1.1.1','32','1','$vsys');");
                            $flid = $projectdb->insert_id;
                            $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys) VALUES ('$lid','$flid','address','$source','$vsys');");
                        }
                    }
                    else
                    {
                        $search_member_id_assoc = $isGroup->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys) VALUES ('$lid','$member_id','address_groups_id','$source','$vsys');");

                    }
                }
                else
                {
                    #is IP or v4 or v6 - Check if exists an object or create it.
                    $getIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='$translated_source' AND source='$source';");
                    if( $getIP->num_rows == 0 )
                    {
                        #Create it
                        $name = "H-$translated_source";
                        if( $checkIPversion == "v4" )
                        {
                            $hostCidr = "32";
                        }
                        if( $checkIPversion == "v6" )
                        {
                            $hostCidr = "128";
                        }
                        $projectdb->query("INSERT into address (type,name,checkit,source,used,ipaddress,cidr,$checkIPversion,vtype,vsys) values('ip-netmask','$name','1','$source','1','$translated_source','$hostCidr','1','ip-netmask','$vsys');");
                        $flid = $projectdb->insert_id;
                        $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys) values('$lid','$flid','address','$source','$vsys');");
                    }
                    else
                    {
                        $getData = $getIP->fetch_assoc();
                        $id = $getData['id'];
                        $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys) values ('$lid','$id','address','$source','$vsys');");
                    }
                }
            }

            #Add the TYPE
            if( ($nat_type == "static") or ($nat_type == "static-ip") )
            {
                $nat_type = "static-ip";
                $projectdb->query("UPDATE nat_rules set tp_sat_type = '$nat_type', tp_sat_address_type='' WHERE id='$lid';");
            }
            elseif( ($nat_type == "masq") or ($nat_type == "masq-ip") )
            {
                $nat_type = "dynamic-ip-and-port";
                $projectdb->query("UPDATE nat_rules set tp_sat_type = '$nat_type', tp_sat_address_type='translated-address' WHERE id='$lid';");
            }
            else
            {
                $nat_type = "None";
                $projectdb->query("UPDATE nat_rules set tp_sat_type = '$nat_type', tp_sat_address_type='' WHERE id='$lid';");
            }
            $projectdb->query("UPDATE nat_rules set tp_sat_type = '$nat_type', tp_sat_address_type='translated-address' WHERE id='$lid';");


            #Destination Translate
            if( $translated_destination == "ORIGINAL" )
            {
            }
            else
            {
                $getHost = $projectdb->query("SELECT id FROM address WHERE source='$source' AND name='$translated_destination';");
                if( $getHost->num_rows == 1 )
                {
                    $host = $getHost->fetch_assoc();
                    $hostlid = $host['id'];
                    $projectdb->query("UPDATE nat_rules set is_dat='1', tp_dat_address_lid='$hostlid', tp_dat_address_table='address' WHERE id='$lid';");
                }
            }


            #Get the translated port
            if( $translated_port == "ORIGINAL" )
            {
            }
            else
            {
                $getPort = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND name='$translated_port';");
                if( $getPort->num_rows == 1 )
                {
                    $getPortData = $getPort->fetch_assoc();
                    $port = $getPortData['dport'];
                    $projectdb->query("UPDATE nat_rules SET tp_dat_port='$port' WHERE id='$lid';");
                }
            }


        }

    }

    if( count($add_tag) > 0 )
    {
        $projectdb->query("INSERT INTO nat_rules_tag (rule_lid,source,member_lid,table_name,vsys) VALUES " . implode(",", $add_tag) . ";");
        unset($add_tag);
    }

}

function get_security_policies($project, $source, $vsys, $convertObjectsShared)
{
    global $projectdb;
    $file_source = $source;
    if( $vsys == "" )
    {
        $vsys = "vsys1";
    }
    $lid = 0;
    $rulesfile = USERSPACE_PATH . "/projects/$project/rules.txt";
    $lines = file($rulesfile);
    $linesNumber = count(($lines));
    $headerB = "";

    #add_log('1','Phase 4: Reading Security Rules','Saving Rules in the DataBase',$project,$linesNumber.' rules found.');


    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    $add_tag = array();
    $add_rule = array();
    $add_service = array();
    $rule_source = array();
    $rule_user = array();
    $rule_destination = array();
    $thecolor = 1;

    foreach( $lines as $line_num => $line )
    {
        $data = explode(";", $line);
        $rule_id = $data[0];
        $rule_enabled = $data[1];
        $negate_source = $data[2];
        $source = $data[3];
        $negate_destination = $data[4];
        $destination = $data[5];
        $negate_service = $data[6];
        $service = $data[7];
        $action = $data[8];
        $log = $data[9];
        $time = $data[10];
        $firewall = $data[11];
        $rulenameK = trim($data[12]);
        $headerA = trim($data[13]);
        $isHeader = 0;
        $location = trim($data[14]);
        $checkit = 0;
        if( $headerA == "" )
        {
            $header = $headerB;
        }
        else
        {
            $header = $headerA;
            $headerB = $headerA;
        }
        #Increment the lid
        #$lid++;

        #Handle the Comments and the Rule Name
        if( preg_match("/Name:,/i", $rulenameK) )
        {
            $rulename2 = "";
            $rulenameK = str_replace("Name:,", "", $rulenameK);
            $rulenameK = str_replace("Comment:", "", $rulenameK);
            $comment = trim(addslashes($rulenameK));
        }
        elseif( preg_match("/Name:/i", $rulenameK) )
        {
            $NameAndComments = explode(",", $rulenameK);
            $RuleName = $NameAndComments[0];
            unset($NameAndComments[0]);
            $RuleComment = implode(",", $NameAndComments);
            $RuleName = str_replace("Name:", "", $RuleName);
            $rulename2 = trim(normalizeComments($RuleName));
            $rulenameK = str_replace("Comment:", "", $RuleComment);
            $comment = trim(addslashes($rulenameK));
        }
        else
        {
            $rulename2 = "";
            $comment = trim(normalizeComments($rulenameK));
        }

        if( $comment == "" )
        {
            $comment = $rulename2;
        }
        if( $comment == "Name: Comment:" )
        {
            $comment = "";
        }
        if( $rulename2 == "Name: Comment:" )
        {
            $rulename2 = "";
        }

        #Change the Action
        if( $action == "accept" )
        {
            $action = "allow";
        }
        elseif( $action == "clientauth" )
        {
            $action = "allow";
            add_log2('warning', 'Reading Security Rules', 'Action is client Auth in RuleID [' . $lid . ']', $file_source, 'Changing Action to Allow', 'rules', $lid, 'security_rules');
        }
        elseif( $action == "reject" )
        {
            $action = "drop";
        }
        else
        {
            $action = "deny";
        }
        if( $rule_enabled == "yes" )
        {
            $rule_enabled = "0";
        }
        else
        {
            $rule_enabled = "1";
        }
        if( $negate_source == "no" )
        {
            $negate_source = "0";
        }
        else
        {
            $negate_source = "1";
            #add_log2('warning','Reading Security Rules','Negated Source found in RuleID ['.$lid.']',$file_source,'Review the Zones probably will not correctly calculated','rules',$lid,'security_rules');
        }
        if( $negate_destination == "no" )
        {
            $negate_destination = "0";
        }
        else
        {
            $negate_destination = "1";
            #add_log2('warning','Reading Security Rules','Negated Destination found in RuleID ['.$lid.']',$file_source,'Review the Zones probably will not correctly calculated','rules',$lid,'security_rules');
        }

        #We dont want to add the last rule is its only a header without any source and any destination
        if( ($source == "") and ($destination == "") )
        {
            #add_log('3','Phase 4: Reading Security Rules','This Rule:'.$lid.' is only a header',$project,'Rule has not been added. Omiting.');
            $isHeader = 1;
        }

        if( $isHeader == 0 )
        {

            #Add Tags from headers
            if( $header != "" )
            {
                $headerFinal = normalizeNames(truncate_tags($header));

                if( $convertObjectsShared )
                {
                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$headerFinal' AND source='$file_source' AND vsys='shared';");
                    if( $getTag->num_rows == 1 )
                    {
                        $getTagData = $getTag->fetch_assoc();
                        $tag_lid = $getTagData['id'];
                        $add_tag[] = "('$lid','$file_source','$tag_lid','tag','shared')";
                    }
                    else
                    {
                        #Add Tag
                        $color = "color" . $thecolor;
                        $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$headerFinal','$file_source','shared','$color');");
                        $tag_lid = $projectdb->insert_id;
                        if( $thecolor == 16 )
                        {
                            $thecolor = 1;
                        }
                        else
                        {
                            $thecolor++;
                        }
                        $add_tag[] = "('$lid','$file_source','$tag_lid','tag','shared')";
                    }
                }
                else
                {
                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$headerFinal' AND source='$file_source' AND vsys='$vsys';");
                    if( $getTag->num_rows == 1 )
                    {
                        $getTagData = $getTag->fetch_assoc();
                        $tag_lid = $getTagData['id'];
                        $add_tag[] = "('$lid','$file_source','$tag_lid','tag','$vsys')";
                    }
                    else
                    {
                        $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$headerFinal' AND source='$file_source' AND vsys='shared';");
                        if( $getTag->num_rows == 1 )
                        {
                            $getTagData = $getTag->fetch_assoc();
                            $tag_lid = $getTagData['id'];
                            $add_tag[] = "('$lid','$file_source','$tag_lid','tag','shared')";
                        }
                        else
                        {
                            #Add Tag
                            $color = "color" . $thecolor;
                            $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$headerFinal','$file_source','$vsys','$color');");
                            $tag_lid = $projectdb->insert_id;
                            if( $thecolor == 16 )
                            {
                                $thecolor = 1;
                            }
                            else
                            {
                                $thecolor++;
                            }
                            $add_tag[] = "('$lid','$file_source','$tag_lid','tag','$vsys')";
                        }

                    }
                }

            }
            # Move to Pre or Post Rules based on the Location
            if( $location != "" )
            {
                if( $location == "before" )
                {
                    $preorpost = 0;
                    $location = "pre-rule";
                }
                elseif( $location == "after" )
                {
                    $preorpost = 1;
                    $location = "post-rule";
                }
                else
                {
                    $preorpost = 0;
                }
                if( $location != "middle" )
                {
                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$location' AND source='$file_source' AND vsys='$vsys';");
                    if( $getTag->num_rows == 1 )
                    {
                        $getTagData = $getTag->fetch_assoc();
                        $tag_lid = $getTagData['id'];
                        $add_tag[] = "('$lid','$file_source','$tag_lid','tag','$vsys')";
                    }
                    else
                    {
                        #Add Tag
                        $color = "color" . $thecolor;
                        $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$location','$file_source','$vsys','$color');");
                        $tag_lid = $projectdb->insert_id;
                        if( $thecolor == 16 )
                        {
                            $thecolor = 1;
                        }
                        else
                        {
                            $thecolor++;
                        }
                        $add_tag[] = "('$lid','$file_source','$tag_lid','tag','$vsys')";
                    }
                }
            }
            else
            {
                $preorpost = 0;
            }

            #Add target
            /*$members=split(",",$firewall);
            foreach ($members as $member_var){
                $isdup=$projectdb->query("SELECT id from checkpoint_targets where source='$source' and target='$member_var'");
                if (mysql_num_rows($isdup)==0){
                    if ($member_var!=""){
                        $projectdb->query("INSERT INTO checkpoint_targets (project,target,enabled,vsys) values ('$project','$member_var','1','vsys1');");
                    }
                }
            }*/
            #Add Sources
            $members = explode(",", $source);
            $unique = array_unique($members);
            $members = $unique;
            foreach( $members as $member_var )
            {
                $isuser = $member_var;
                if( preg_match("/@/i", $isuser) )
                {
                    $newvar = explode("@", $isuser);
                    $sourcea = $newvar[1];
                    if( $sourcea == "Any" )
                    {
                        $rule_user[] = "('$newvar[0]','$lid')";
                    }
                    else
                    {
                        $rule_user[] = "('$isuser','$lid')";
                    }
                    $member_var = ltrim($sourcea);
                    $checkit = 1;

                    add_log2('warning', 'Reading Security Rules', 'Users found (' . $isuser . ') in RuleID [' . $lid . ']', $file_source, 'Assigning the User as a Source', 'rules', $lid, 'security_rules');
                }

                if( ($member_var == "Any") or ($member_var == "any") or ($member_var == "ANY") )
                {
                }
                else
                {
                    $isGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name = '$member_var' AND source='$file_source' LIMIT 1;");
                    if( $isGroup->num_rows == 0 )
                    {
                        $search_member_id = $projectdb->query("SELECT id FROM address WHERE BINARY name='$member_var' AND source='$file_source' LIMIT 1;");
                        if( $search_member_id->num_rows == 0 )
                        {
                            add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $member_var . '] as Source that is not defined in my Database. Fix it before to finish', $file_source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                            #add_log('4','Phase 4: Reading Security Rules','Source Object ('.$member_var.') not found in DB in Rule:'.$lid,$project,'Generating the Object, add the IP.');
                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys) values('$member_var','ip-netmask','$member_var','1','$file_source','0','1.1.1.1','32','1','$vsys');");
                            $newlid = $projectdb->insert_id;
                            $rule_source[] = "('$file_source','$vsys','$lid','address','$newlid')";
                        }
                        else
                        {
                            $search_member_id_assoc = $search_member_id->fetch_assoc();
                            $member_id = $search_member_id_assoc['id'];
                            $rule_source[] = "('$file_source','$vsys','$lid','address','$member_id')";
                            #$projectdb->query("INSERT INTO security_rules_src (rule_lid,member_lid,table_name,project,vsys) VALUES ('$lid','$member_id','address','$project','vsys1');");
                        }
                    }
                    else
                    {
                        //$search_member_id=$projectdb->query("SELECT lid from address_groups where name='$member_var' and source='$source' limit 1;");
                        $search_member_id_assoc = $isGroup->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $rule_source[] = "('$file_source','$vsys','$lid','address_groups_id','$member_id')";
                        #$projectdb->query("INSERT INTO security_rules_src (rule_lid,member_lid,table_name,project,vsys) VALUES ('$lid','$member_id','address_groups_id','$project','vsys1');");
                    }
                }
            }

            #Add Destinations
            $members = explode(",", $destination);
            $unique = array_unique($members);
            $members = $unique;
            foreach( $members as $member_var )
            {
                if( ($member_var == "Any") or ($member_var == "any") or ($member_var == "ANY") )
                {
                }
                else
                {
                    $isGroup = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name = '$member_var' AND source='$file_source' LIMIT 1;");
                    if( $isGroup->num_rows == 0 )
                    {
                        $search_member_id = $projectdb->query("SELECT id FROM address WHERE BINARY name='$member_var' AND source='$file_source' LIMIT 1;");
                        if( $search_member_id->num_rows == 0 )
                        {
                            add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $member_var . '] as Destination that is not defined in my Database. Fix it before to finish', $file_source, 'Adding to the DB [ip:1.1.1.1]. Add IP Address', 'rules', $lid, 'security_rules');
                            #add_log('4','Phase 4: Reading Security Rules','Source Object ('.$member_var.') not found in DB in Rule:'.$lid,$project,'Generating the Object, add the IP.');
                            $projectdb->query("INSERT INTO address (name,type,name_ext,checkit,source,used,ipaddress,cidr,v4,vsys) values('$member_var','ip-netmask','$member_var','1','$file_source','0','1.1.1.1','32','1','$vsys');");
                            $newlid = $projectdb->insert_id;
                            $rule_destination[] = "('$file_source','$vsys','$lid','address','$newlid')";
                        }
                        else
                        {
                            $search_member_id_assoc = $search_member_id->fetch_assoc();
                            $member_id = $search_member_id_assoc['id'];
                            $rule_destination[] = "('$file_source','$vsys','$lid','address','$member_id')";
                            #$projectdb->query("INSERT INTO security_rules_src (rule_lid,member_lid,table_name,project,vsys) VALUES ('$lid','$member_id','address','$project','vsys1');");
                        }
                    }
                    else
                    {
                        //$search_member_id=$projectdb->query("SELECT lid from address_groups where name='$member_var' and source='$source' limit 1;");
                        $search_member_id_assoc = $isGroup->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $rule_destination[] = "('$file_source','$vsys','$lid','address_groups_id','$member_id')";
                        #$projectdb->query("INSERT INTO security_rules_src (rule_lid,member_lid,table_name,project,vsys) VALUES ('$lid','$member_id','address_groups_id','$project','vsys1');");
                    }
                }
            }

            #Add Services
            $members = explode(",", $service);
            $unique = array_unique($members);
            $members = $unique;
            foreach( $members as $member_var )
            {
                if( preg_match("/->/i", $member_var) )
                {
                    $srvs = explode(" ", $member_var);
                    $member_var = $srvs[0];
                    add_log2('warning', 'Reading Security Rules', 'Service with resource found in RuleID [' . $lid . ']', $file_source, 'Saving only the service ' . $srvs[0], 'rules', $lid, 'security_rules');
                    $checkit = 1;
                    #$projectdb->query("UPDATE security_rules SET checkit='1' WHERE source='$source' and lid='$lid';");
                }

                if( ($member_var == "Any") or ($member_var == "any") or ($member_var == "ANY") )
                {
                }
                else
                {
                    $isGroup = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name = '$member_var' AND source='$file_source' LIMIT 1;");
                    if( $isGroup->num_rows == '0' )
                    {
                        $search_member_id = $projectdb->query("SELECT id FROM services WHERE BINARY name='$member_var' AND source='$file_source' LIMIT 1;");
                        $search_member_id_assoc = $search_member_id->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $rule_service[] = "('$file_source','$vsys','$lid','services','$member_id')";
                        #$projectdb->query("INSERT INTO security_rules_srv (rule_lid,member_lid,table_name,project,vsys) VALUES ('$lid','$member_id','services','$project','vsys1');");
                    }
                    else
                    {
                        //$search_member_id=$projectdb->query("SELECT lid from services_groups where name='$member_var' and source='$source' limit 1;");
                        $search_member_id_assoc = $isGroup->fetch_assoc();
                        $member_id = $search_member_id_assoc['id'];
                        $rule_service[] = "('$file_source','$vsys','$lid','services_groups_id','$member_id')";
                        #$projectdb->query("INSERT INTO security_rules_srv (rule_lid,member_lid,table_name,project,vsys) VALUES ('$lid','$member_id','services_groups_id','$project','vsys1');");
                    }
                }
            }

            #Alert when Negate Service is Found AND Fix it.
            if( $negate_service == "yes" )
            {
                #Add the Rule with the Services and negate the Action, duplicate the rule with service any and negating again the action
                #if ($action == "allow") {$action="deny";} else {$action="allow";}
                //$projectdb->query("INSERT INTO security_rules (lid,disabled,negate_source,negate_destination,action,target,name,description,checkit,project,vsys) values ('$lid','$rule_enabled','$negate_source','$negate_destination','$action','$firewall','$rulename2','$comment','1','$project','vsys1');");
                #$projectdb->query("UPDATE security_rules SET action='$action' WHERE lid='$lid' AND source='$source';");
                add_log2('error', 'Reading Security Rules', 'Negated Service found in RuleID [' . $lid . ']', $file_source, 'Check Rule:' . $lid . ' to fix by hand.', 'rules', $lid, 'security_rules');
                #$position=$lid;
                #$lid++;
                #clone_security_rule($position,$lid,'vsys1',$project,$addVsys,$position);
                #if ($action == "allow") {$action="deny";} else {$action="allow";}
                #$projectdb->query("UPDATE security_rules SET action='$action' WHERE lid='$lid' AND source='$source';");
                #$projectdb->query("DELETE FROM security_rules_srv WHERE source='$source' AND rule_lid='$lid';");
            }

            $rulename2 = normalizeNames($rulename2);
            $add_rule[] = "('$lid','$rule_enabled','$negate_source','$negate_destination','$action','$firewall','$rulename2','$comment','$file_source','$vsys','$position','$preorpost','$checkit')";
            $lid++;
            $position++;

        }

    }

    if( count($add_rule) > 0 )
    {
        $projectdb->query("INSERT INTO security_rules (id,disabled,negate_source,negate_destination,action,target,name,description,source,vsys,position,preorpost,checkit) VALUES " . implode(",", $add_rule) . ";");
        unset($add_rule);
        if( count($add_tag) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_tag (rule_lid,source,member_lid,table_name,vsys) VALUES " . implode(",", $add_tag) . ";");
            unset($add_tag);
        }
        if( count($rule_source) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $rule_source) . ";");
            unset($rule_source);
        }
        if( count($rule_destination) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $rule_destination) . ";");
            unset($rule_destination);
        }
        if( count($rule_service) > 0 )
        {
            $unique = array_unique($rule_service);
            $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $unique) . ";");
            unset($rule_service);
            unset($unique);
        }
        if( count($rule_user) > 0 )
        {
            $unique = array_unique($rule_user);
            $projectdb->query("INSERT INTO security_rules_usr (name,rule_lid) VALUES " . implode(",", $unique) . ";");
            unset($rule_user);
            unset($unique);
        }
    }

}

function fix_destination_nat($source, $vsys, $skipDAT)
{
    global $projectdb;

    #First Calculate the Zones
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE source='$source' AND vsys='$vsys';");
    if( $getVR->num_rows == 1 )
    {
        $VRData = $getVR->fetch_assoc();
        $vr = $VRData['id'];
        $from_or_to = "from";
        $rule_or_nat = "rule";

        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

        $projectdb->query("DELETE FROM security_rules_from WHERE source = '$source' AND vsys = '$vsys' ;");
        $getSRC = $projectdb->query("SELECT rule_lid, member_lid, table_name FROM security_rules_src WHERE source = '$source' AND vsys = '$vsys';");
        if( $getSRC->num_rows > 0 )
        {
            while( $getSRCData = $getSRC->fetch_assoc() )
            {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                // Mirar si para esta regla es negated o no
                $getIsNegated = $projectdb->query("SELECT negate_source, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if( $getIsNegated->num_rows > 0 )
                {
                    $getINData = $getIsNegated->fetch_assoc();
                    $negate_source = $getINData['negate_source'];
                    $devicegroup = $getINData['devicegroup'];
                }

                // Comprobar si ya existe la zona en la tabla tmp_calc_zone
                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_source';");
                if( $getZones->num_rows == 1 )
                {
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }
                else
                {
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                    if( count($zones) != 0 )
                    {
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '" . implode(",", $zones) . "', '$negate_source','$vsys', '$source');");
                    }
                }

                foreach( $zones as $zone )
                {
                    if( $zone != "" )
                    {
                        $getZone = $projectdb->query("SELECT id FROM security_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid' AND vsys = '$vsys' AND source = '$source';");
                        if( $getZone->num_rows == 0 )
                        {
                            $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) "
                                . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                        }
                    }

                }
                /*if ( ($table_name=="address") or ($table_name=="shared_address") ){
                        search_zone_address($rule_lid,$member_lid,$vsys,$source,$vr,$table_name,$from_or_to,$rule_or_nat);
                } else {
                        search_zone_group($rule_lid,$member_lid,$vsys,$source,$vr,$table_name,$from_or_to,$rule_or_nat);
                }*/
            }
        }

        $from_or_to = "to";
        $rule_or_nat = "rule";
        $projectdb->query("DELETE FROM security_rules_to WHERE source='$source' AND vsys='$vsys';");
        $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE source = '$source' AND vsys = '$vsys';");
        if( $getSRC->num_rows > 0 )
        {
            while( $getSRCData = $getSRC->fetch_assoc() )
            {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                // Mirar si para esta regla es negated o no
                $getIsNegated = $projectdb->query("SELECT negate_destination, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if( $getIsNegated->num_rows > 0 )
                {
                    $getINData = $getIsNegated->fetch_assoc();
                    $negate_destination = $getINData['negate_destination'];
                    $devicegroup = $getINData['devicegroup'];
                }

                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '$negate_destination';");
                if( $getZones->num_rows == 1 )
                {
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }
                else
                {
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination);
                    if( count($zones) != 0 )
                    {
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '" . implode(",", $zones) . "', '$negate_destination','$vsys', '$source');");
                    }
                }
                foreach( $zones as $zone )
                {
                    if( $zone != "" )
                    {
                        $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid' AND vsys = '$vsys' AND source = '$source';");
                        if( $getZone->num_rows == 0 )
                        {
                            $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                                . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                        }
                    }

                }
                /*if ( ($table_name=="address") or ($table_name=="shared_address") ){
                        search_zone_address($rule_lid,$member_lid,$vsys,$source,$vr,$table_name,$from_or_to,$rule_or_nat);
                } else {
                        search_zone_group($rule_lid,$member_lid,$vsys,$source,$vr,$table_name,$from_or_to,$rule_or_nat);
                }*/
            }
        }

        // Calculate Zone FROM to NAT
        $projectdb->query("DELETE FROM nat_rules_from WHERE source = '$source' AND vsys = '$vsys' ;");
        $getSRC = $projectdb->query("SELECT rule_lid, member_lid, table_name FROM nat_rules_src WHERE source = '$source' AND vsys = '$vsys';");
        if( $getSRC->num_rows > 0 )
        {
            while( $getSRCData = $getSRC->fetch_assoc() )
            {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];
                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '0';");
                if( $getZones->num_rows == 1 )
                {
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }
                else
                {
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                    if( count($zones) != 0 )
                    {
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '" . implode(",", $zones) . "', '0', '$vsys', '$source');");
                    }

                }
                foreach( $zones as $zone )
                {
                    if( $zone != "" )
                    {
                        $getZone = $projectdb->query("SELECT id FROM nat_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid' AND vsys = '$vsys' AND source = '$source';");
                        if( $getZone->num_rows == 0 )
                        {
                            $projectdb->query("INSERT INTO nat_rules_from (rule_lid, name, source, vsys, devicegroup) "
                                . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                        }
                    }
                }
            }
        }

        // Calculate Zone TO to NAT
        $projectdb->query("UPDATE nat_rules SET op_zone_to='' WHERE source='$source' AND vsys='$vsys' ");
        $getSRC = $projectdb->query("SELECT rule_lid, member_lid, table_name FROM nat_rules_dst WHERE source = '$source' AND vsys = '$vsys';");
        if( $getSRC->num_rows > 0 )
        {
            while( $getSRCData = $getSRC->fetch_assoc() )
            {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];
                $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '0';");
                if( $getZones->num_rows == 1 )
                {
                    $getZonesData = $getZones->fetch_assoc();
                    $zones_sql = $getZonesData['zone'];
                    $zones = explode(",", $zones_sql);
                }
                else
                {
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                    if( count($zones) != 0 )
                    {
                        $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                            . " VALUES ('$member_lid', '$table_name', '" . implode(",", $zones) . "', '0', '$vsys', '$source');");
                    }
                }
                $zona = current($zones);
                $projectdb->query("UPDATE nat_rules SET op_zone_to = '$zona' WHERE id = '$rule_lid' ;");
            }
        }
        $allruleid = array();
        $noany = array();
        // Mirar las que tienen el destination a any y si tienen el [TP] Source, mirar la zona de ésta
        $getAllNatRules = $projectdb->query("SELECT id FROM nat_rules WHERE source = '$source' AND vsys = '$vsys' ");
        if( $getAllNatRules->num_rows > 0 )
        {
            while( $getAllRulesData = $getAllNatRules->fetch_assoc() )
            {
                $allruleid[] = $getAllRulesData['id'];
            }
        }
        $getNoAny = $projectdb->query("SELECT rule_lid FROM nat_rules_dst WHERE source = '$source' AND vsys = '$vsys' ");
        if( $getNoAny->num_rows == 0 )
        {
            $array_dif = $allruleid;
        }
        elseif( $getNoAny->num_rows > 0 )
        {
            while( $getNoAnyData = $getNoAny->fetch_assoc() )
            {
                $noany[] = $getNoAnyData['rule_lid'];
            }
            $array_dif = array_diff($allruleid, $noany);
        }
        foreach( $array_dif as $key => $rule_id )
        {
            $getType = $projectdb->query("SELECT tp_sat_address_type, tp_sat_interface FROM nat_rules WHERE id = '$rule_id';");
            if( $getType->num_rows > 0 )
            {
                $getTypeData = $getType->fetch_assoc();
                $type_sat_address = $getTypeData['tp_sat_address_type'];
                $tp_sat_interface = $getTypeData['tp_sat_interface'];
            }
            if( $type_sat_address == "translated-address" )
            {
                $getSRC = $projectdb->query("SELECT rule_lid, member_lid, table_name FROM nat_rules_translated_address WHERE source = '$source' AND vsys = '$vsys' AND rule_lid = '$rule_id' UNION SELECT rule_lid, member_lid, table_name FROM nat_rules_translated_address_fallback WHERE source = '$source' AND vsys = '$vsys' AND rule_lid = '$rule_id';");
                if( $getSRC->num_rows > 0 )
                {
                    while( $getSRCData = $getSRC->fetch_assoc() )
                    {
                        $member = "";
                        $member_lid = $getSRCData['member_lid'];
                        $table_name = $getSRCData['table_name'];
                        $rule_lid = $getSRCData['rule_lid'];
                        $getZones = $projectdb->query("SELECT zone FROM tmp_calc_zone WHERE source = '$source' AND vsys = '$vsys' AND member_lid = '$member_lid' AND table_name = '$table_name' AND is_negated = '0';");
                        if( $getZones->num_rows == 1 )
                        {
                            $getZonesData = $getZones->fetch_assoc();
                            $zones_sql = $getZonesData['zone'];
                            $zones = explode(",", $zones_sql);
                        }
                        else
                        {
                            $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                            if( count($zones) != 0 )
                            {
                                $projectdb->query("INSERT INTO tmp_calc_zone (member_lid, table_name, zone, is_negated, vsys, source )"
                                    . " VALUES ('$member_lid', '$table_name', '" . implode(",", $zones) . "', '0', '$vsys', '$source');");
                            }
                        }
                        $total_zones = count($zones);
                        if( $total_zones > 1 )
                        {
                            add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_lid . '] is usign more than one Zone as a Destination [' . implode(",", $zones) . ']', $source, 'Only one Destination Zone is allowed', 'rules', $rule_lid, 'nat_rules');
                        }
                        $zona = current($zones);
                        $projectdb->query("UPDATE nat_rules SET op_zone_to = '$zona' WHERE id = '$rule_lid' ;");
                        // Añadir en el log que hemos cogido la zona del [TP] Source
                        add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_lid . '] capturing zone from the Translated Address', $source, '', 'rules', $rule_lid, 'nat_rules');
                    }
                }
            }
            elseif( $type_sat_address == "interface-address" )
            {
                $getZoneToInterface = $projectdb->query("SELECT zone FROM interfaces WHERE source = '$source' AND vsys = '$vsys' AND name = '$tp_sat_interface' LIMIT 1;");
                if( $getZoneToInterface->num_rows > 0 )
                {
                    $getZTIData = $getZoneToInterface->fetch_assoc();
                    $zona_interface = $getZTIData['zone'];
                    $projectdb->query("UPDATE nat_rules SET op_zone_to = '$zona_interface' WHERE id = '$rule_id' ;");
                    add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_id . '] capturing zone from the Translated Interfaces', $source, '', 'rules', $rule_lid, 'nat_rules');
                }
            }
        }//fin foreach
    }

    // Se queda igual
    $getDNAT = $projectdb->query("SELECT id,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE is_dat=1 AND source='$source' AND vsys='$vsys';");
    if( $getDNAT->num_rows > 0 )
    {

        while( $data = $getDNAT->fetch_assoc() )
        {
            $zoneFROM = "";
            $rule_lid = $data['id'];
            $tp_dat_address_lid = $data['tp_dat_address_lid'];
            $tp_dat_address_table = $data['tp_dat_address_table'];
            #get Address name
            $getname = $projectdb->query("SELECT name FROM $tp_dat_address_table WHERE id='$tp_dat_address_lid'");
            $getnameData = $getname->fetch_assoc();
            $datName = $getnameData['name'];
            #Get Source Zone from Nat Rule
            $getFROM = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$rule_lid' ;");
            if( $getFROM->num_rows == 1 )
            {
                $dataFrom = $getFROM->fetch_assoc();
                $zoneFROM = $dataFrom['name'];
            }
            #Get Destination from OP
            $getDST = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$rule_lid' ;");
            if( $getDST->num_rows == 1 )
            {
                $data2 = $getDST->fetch_assoc();
                $dst_member_lid = $data2['member_lid'];
                $dst_table_name = $data2['table_name'];
                #get Address name
                $getname = $projectdb->query("SELECT name FROM $dst_table_name WHERE id='$dst_member_lid'");
                $getnameData = $getname->fetch_assoc();
                $dstName = $getnameData['name'];
            }

            if( !$skipDAT )
            {
                $getSecurityDST = $projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                if( $getSecurityDST->num_rows > 0 )
                {
                    while( $data4 = $getSecurityDST->fetch_assoc() )
                    {
                        $security_rule = $data4['rule_lid'];
                        #Check the ZONE, has to be the same from ZoneFROM
                        $getSecurityZone = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$security_rule';");
                        if( $getSecurityZone->num_rows == 1 )
                        {
                            $data5 = $getSecurityZone->fetch_assoc();
                            $security_from = $data5['name'];
                            if( $security_from == $zoneFROM )
                            {
                                $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                            }
                        }
                        else
                        {
                            #No source ZONE maybe is ANY :-)
                            $exist = $projectdb->query("SELECT id FROM security_rules_dst WHERE table_name='$tp_dat_address_table' ANd member_lid='$tp_dat_address_lid' AND rule_lid='$security_rule';");
                            if( $exist->num_rows == 1 )
                            {
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                            }
                            else
                            {
                                $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                                $projectdb->query("INSERT INTO security_rules_dst (rule_lid,member_lid,table_name,source,vsys) VALUES ('$security_rule','$dst_member_lid','$dst_table_name','$source','$vsys');");
                            }
                            add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                        }
                    }
                }
            }
        }
    }
    #Clean Posible Duplicated destinations on Rules
    $dup = $projectdb->query("SELECT max(id) as m,count(*) as t FROM security_rules_dst GROUP BY rule_lid,member_lid,table_name HAVING t>1;");
    if( $dup->num_rows > 0 )
    {
        while( $data = $dup->fetch_assoc() )
        {
            $theID = $data['m'];
            $projectdb->query("DELETE FROM security_rules_dst WHERE id='$theID';");
        }
    }
}

function get_routes($project, $source, $template, $vsys)
{
#Support for ipv4 by now
    global $projectdb;
    $count = 0;
    $routes_file = USERSPACE_PATH . "/projects/$project/routes.txt";
    $routes_out = USERSPACE_PATH . "/projects/$project/routes.out";
    if( file_exists($routes_file) )
    {
        #Trick to clean the file and align
        $command = "cat $routes_file | awk '{print $1, $2, $3, $4, $5, $6, $7, $8}' > $routes_out";
        shell_exec($command);
        #clean the ctrl+M
        $command = "tr -d \'\r\' < $routes_out > $routes_file";
        shell_exec($command);
        #Open the fixed file
        $routes = file($routes_file);
        #Log


        $whichtable = "";
        $fields = array();

        #Create a VR
        $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
        if( $getVR->num_rows == 0 )
        {
            $projectdb->query("INSERT INTO virtual_routers (name,source,template,vsys) VALUES ('chkpt-vr','$source','$template','$vsys');");
            $vr_id = $projectdb->insert_id;
        }
        else
        {
            $getVRData = $getVR->fetch_assoc();
            $vr_id = $getVRData['id'];
        }


        foreach( $routes as $line => $routes_line1 )
        {
            $routes_line = rtrim($routes_line1);
            $fields = explode(' ', $routes_line);
            if( ($fields[0] == "Destination") and ($fields[1] == "Gateway") and ($fields[2] == "Genmask") )
            {
                $whichtable = "linux";
                break;
            }
            elseif( preg_match("/^255./i", $fields[1]) )
            {
                $whichtable = "other";
                break;
            }
            elseif( ($fields[0] == "Destination") and ($fields[1] == "Type") and ($fields[2] == "Ref") and ($fields[3] == "NextHop") )
            {
                $whichtable = "gaia";
                break;
            }
            elseif( ($fields[0] == "Destination") and ($fields[1] == "Gateway") and ($fields[2] == "Flags") and ($fields[3] == "Refs") )
            {
                $whichtable = "ipso";
                break;
            }
            elseif( ($fields[0] == "Destination") and ($fields[1] == "Type") and ($fields[3] == "NextHop") )
            {
                $whichtable = "ipso2";
                break;
            }
            elseif( preg_match("/255./i", $fields[2]) )
            {
                $whichtable = "splat";
                break;
            }
            else
            {
                $whichtable = "idontknow";
            }
        }

        $addRoutes = array();
        $i = 0;
        $x = 0;
        $y = 0;
        foreach( $routes as $line => $routes_line )
        {
            $network = "";
            $gateway = "";
            $netmask = "";
            $flags = "";
            $metric = "";
            $ref = "";
            $use = "";
            $interface = "";
            $zone = "";

            if( $whichtable == 'linux' )
            {
                list($network, $gateway, $netmask, $flags, $metric, $ref, $use, $interface) = explode(" ", $routes_line);
            }
            elseif( $whichtable == 'splat' )
            {
                list($network, $gateway, $netmask, $flags, $metric, $ref, $use, $interface) = explode(" ", $routes_line);
            }
            elseif( $whichtable == 'other' )
            {
                list($network, $netmask, $gateway, $flags, $metric, $ref, $use, $interface) = explode(" ", $routes_line);
            }
            elseif( $whichtable == 'ipso' )
            {
                list($network_and_mask, $gateway, $flags, $ref, $use, $interface) = explode(" ", $routes_line);
                if( ($network_and_mask == "default") and ($gateway != "RCSU") )
                {
                    $network = "default";
                }
                elseif( ($flags == "lCGSU") or ($flags == "lCSU") or ($flags == "iCGSU") or ($flags == "lGC") or ($flags == "gCDSU") )
                {
                    $network = "ignore";
                }
                elseif( $gateway == "RCSU" )
                {
                    $network = "ignore";
                }
                elseif( ($gateway == "rCGSU") or ($gateway == "CGUX") )
                {
                    #Interfaces
                    list($net, $mask) = explode("/", $network_and_mask);
                    list($a, $b, $c, $d) = explode(".", $net);
                    if( $b == "" )
                    {
                        $b = 0;
                    }
                    if( $c == "" )
                    {
                        $c = 0;
                    }
                    if( $d == "" )
                    {
                        $d = 0;
                    }
                    $network = $a . "." . $b . "." . $c . "." . $d;
                    $netmask = convertNetmaskv4($mask);
                    $gateway = "0.0.0.0";
                    $metric = 1;
                }
                elseif( ($flags == "iCSU") or ($flags == "iSUW") or ($flags == "CU") )
                {
                    if( validateIpAddress($network_and_mask, "v4") )
                    {
                        $network = $network_and_mask;
                        $netmask = "255.255.255.255";
                        $metric = 1;
                    }
                    elseif( preg_match("/\//i", $network_and_mask) )
                    {
                        list($net, $mask) = explode("/", $network_and_mask);
                        list($a, $b, $c, $d) = explode(".", $net);
                        if( $b == "" )
                        {
                            $b = 0;
                        }
                        if( $c == "" )
                        {
                            $c = 0;
                        }
                        if( $d == "" )
                        {
                            $d = 0;
                        }
                        $network = $a . "." . $b . "." . $c . "." . $d;
                        $netmask = convertNetmaskv4($mask);
                        $metric = 1;
                    }
                }
            }
            elseif( $whichtable == 'ipso2' )
            {
                list($network_and_mask, $kk, $kk1, $gateway, $flags, $ref, $use, $interface) = explode(" ", $routes_line);
                if( ($network_and_mask == "default") and ($gateway != "RCSU") )
                {
                    $network = "default";
                }
                elseif( $kk == "clon" )
                {
                    $network = "ignore";
                }
                elseif( ($gateway == "rCGSU") or ($gateway == "CGUX") )
                {
                    #Interfaces
                    list($net, $mask) = explode("/", $network_and_mask);
                    list($a, $b, $c, $d) = explode(".", $net);
                    if( $b == "" )
                    {
                        $b = 0;
                    }
                    if( $c == "" )
                    {
                        $c = 0;
                    }
                    if( $d == "" )
                    {
                        $d = 0;
                    }
                    $network = $a . "." . $b . "." . $c . "." . $d;
                    $netmask = convertNetmaskv4($mask);
                    $gateway = "0.0.0.0";
                    $metric = 1;
                }
                elseif( ($flags == "iCSU") or ($flags == "iSUW") or ($flags == "CU") )
                {
                    if( validateIpAddress($network_and_mask, "v4") )
                    {
                        $network = $network_and_mask;
                        $netmask = "255.255.255.255";
                        $metric = 1;
                    }
                    elseif( preg_match("/\//i", $network_and_mask) )
                    {
                        list($net, $mask) = explode("/", $network_and_mask);
                        list($a, $b, $c, $d) = explode(".", $net);
                        if( $b == "" )
                        {
                            $b = 0;
                        }
                        if( $c == "" )
                        {
                            $c = 0;
                        }
                        if( $d == "" )
                        {
                            $d = 0;
                        }
                        $network = $a . "." . $b . "." . $c . "." . $d;
                        $netmask = convertNetmaskv4($mask);
                        $metric = 1;
                    }
                }
            }
            elseif( $whichtable == 'gaia' )
            {
                list($network_and_mask, $type, $ref, $gateway, $type2, $ref, $interface, $interface2) = explode(" ", $routes_line);
                if( ($network_and_mask == "default") and ($gateway != "RCSU") )
                {
                    $network = "default";
                }
                elseif( $type == "clon" )
                {
                    $network = "ignore";
                }
                elseif( ($type == "dest") and ($gateway == "rslv") )
                {
                    #Interfaces
                    list($net, $mask) = explode("/", $network_and_mask);
                    list($a, $b, $c, $d) = explode(".", $net);
                    if( $b == "" )
                    {
                        $b = 0;
                    }
                    if( $c == "" )
                    {
                        $c = 0;
                    }
                    if( $d == "" )
                    {
                        $d = 0;
                    }
                    $network = $a . "." . $b . "." . $c . "." . $d;
                    $netmask = convertNetmaskv4($mask);
                    $gateway = "0.0.0.0";
                    $metric = 1;
                }
                elseif( ($type == "user") and ($type2 == "dest") )
                {
                    if( validateIpAddress($network_and_mask, "v4") )
                    {
                        $network = $network_and_mask;
                        $netmask = "255.255.255.255";
                        $metric = 1;
                    }
                    elseif( preg_match("/\//i", $network_and_mask) )
                    {
                        list($net, $mask) = explode("/", $network_and_mask);
                        list($a, $b, $c, $d) = explode(".", $net);
                        if( $b == "" )
                        {
                            $b = 0;
                        }
                        if( $c == "" )
                        {
                            $c = 0;
                        }
                        if( $d == "" )
                        {
                            $d = 0;
                        }
                        $network = $a . "." . $b . "." . $c . "." . $d;
                        $netmask = convertNetmaskv4($mask);
                        $metric = 1;
                    }
                }
            }
            elseif( $whichtable == "idontknow" )
            {
                if( preg_match("/ via /i", $routes_line) )
                {
                    $keywords = preg_split("/[\s,]+/", $routes_line);
                    $key = array_search('via', $keywords);
                    if( $keywords[$key - 1] == "0.0.0.0/0" )
                    {
                        if( validateIpAddress($keywords[$key + 1], "v4") )
                        {
                            $gateway = $keywords[$key + 1];
                            $network = "0.0.0.0";
                            $netmask = "0.0.0.0";
                        }
                    }
                    else
                    {
                        #check the IP address v4 or v6 and is not the default ? FIX THIS
                        $keywords = preg_split("/[\s,]+/", $routes_line);
                        $key = array_search('via', $keywords);
                        if( validateIpAddress($keywords[$key + 1], "v4") )
                        {
                            $gateway = $keywords[$key + 1];
                            $network_and_mask = $keywords[$key - 1];
                            if( preg_match("/\//i", $network_and_mask) )
                            {
                                list($net, $mask) = explode("/", $network_and_mask);
                                list($a, $b, $c, $d) = explode(".", $net);
                                if( $b == "" )
                                {
                                    $b = 0;
                                }
                                if( $c == "" )
                                {
                                    $c = 0;
                                }
                                if( $d == "" )
                                {
                                    $d = 0;
                                }
                                $network = $a . "." . $b . "." . $c . "." . $d;
                                $netmask = convertNetmaskv4($mask);
                                $metric = 1;
                            }
                        }
                    }

                }
                elseif( preg_match("/ is directly connected, /", $routes_line) )
                {
                    $keywords = preg_split("/[\s,]+/", $routes_line);
                    $key = array_search('is', $keywords);
                    $network_and_mask = explode("/", $keywords[$key - 1]);
                    $network = $network_and_mask[0];
                    if( validateIpAddress($network, "v4") )
                    {
                        $netmask = convertNetmaskv4($network_and_mask[1]);
                        $gateway = "0.0.0.0";
                        $zone = $keywords[$key + 3];
                    }
                    else
                    {
                        list($a, $b, $c, $d) = explode(".", $network);
                        if( $b == "" )
                        {
                            $b = 0;
                        }
                        if( $c == "" )
                        {
                            $c = 0;
                        }
                        if( $d == "" )
                        {
                            $d = 0;
                        }
                        $network = $a . "." . $b . "." . $c . "." . $d;
                        $netmask = convertNetmaskv4($network_and_mask[1]);
                        $gateway = "0.0.0.0";
                        $zone = $keywords[$key + 3];
                    }
                }
            }

            $int_tmp = trim($interface);
            $interface = $int_tmp;
            $unitname = $interface;

            if( $metric == "0" )
            {
                $metric = "1";
            }
            if( $metric == "" )
            {
                $metric = "1";
            }
            if( $network == "Destination" )
            {
            }
            elseif( $network == "" )
            {
            }
            elseif( $network == "255.255.255.255" )
            {
            }
            elseif( ($flags == "CGU") or ($flags == "UW") )
            {
            }
            elseif( $network == "ignore" )
            {
            }
            elseif( preg_match("/\#/", $network) )
            {
            }
            elseif( ($gateway == "*") and ($netmask == "255.255.255.255") and ($network == "localhost") )
            {
            }
            elseif( ($gateway == "gCDSU") or ($gateway == "BCSU") or ($gateway == "RCGSU") or ($gateway == "lCSU") or ($gateway == "RCU") or ($gateway == "CDU") or ($gateway == "BCU") or ($gateway == "RGCU") or ($gateway == "CG") or ($gateway == "CU") or ($gateway == "CGU") )
            {
            }
            elseif( $network == "Kernel" )
            {
            }
            elseif( ($network == "127.0.0.0") or ($network == "127.0.0.1") )
            {
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Ignoring loopback interface '.$network);
            }
            elseif( $network == "224.0.0.2" )
            {
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Ignoring Multicast interface '.$network);
            }
            elseif( ($network == "0.0.0.0") and ($netmask == "0.0.0.0") )
            {
                $ip_version = "v4";
                if( validateIpAddress($gateway, $ip_version) )
                {
                    if( $count == 0 )
                    {
                        $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }
                    else
                    {
                        $newRouteName = "default " . $count;
                        $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','$newRouteName','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }

                }
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('$network','$gateway','$netmask','$metric','default','','$project');");
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / '.$netmask.' - '.$gateway);
            }
            elseif( ($network == "0.0.0.0") and ($netmask == "255.255.255.255") )
            {
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('$network','$gateway','0.0.0.0','$metric','default','','$project');");
                $ip_version = "v4";
                if( validateIpAddress($gateway, $ip_version) )
                {
                    $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                }
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / 0.0.0.0 - '.$gateway);
            }
            elseif( $network == "default" )
            {
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('0.0.0.0','$gateway','0.0.0.0','$metric','default','','$project');");
                #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / 0.0.0.0 - '.$gateway);
                $ip_version = "v4";
                if( validateIpAddress($gateway, $ip_version) )
                {
                    if( $count == 0 )
                    {
                        $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }
                    else
                    {
                        $newRouteName = "default " . $count;
                        $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','$newRouteName','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                        $count++;
                    }

                }
            }
            elseif( ($gateway == "*") and ($flags == "U") )
            {
                $x++;
                $zoneName = "Zone" . $x;
                $cidr = mask2cidrv4($netmask);
                $media = "ethernet";
                $unittag = 0;
                if( $interface == "" )
                {
                    $y++;
                    $interface = "ethernet1/" . $y;
                    $unitname = $interface;
                }
                elseif( preg_match("/bond/", $interface) )
                {
                    $int_tmp = str_replace("bond", "", $interface);
                    $int_tmp2 = explode(".", $int_tmp);
                    if( count($int_tmp2) == 1 )
                    {
                        $unittag = 0;
                    }
                    else
                    {
                        $unittag = intval($int_tmp2[1]);
                    }
                    if( $int_tmp2[0] == 0 )
                    {
                        $unitname_tmp = "1";
                    }
                    else
                    {
                        $unitname_tmp = $int_tmp2[0] + 1;
                    }
                    $unitname = "ae" . $unitname_tmp . "." . $unittag;
                    $interface = "ae" . $unitname_tmp;
                    $media = "aggregate-ethernet";
                }
                else
                {
                    $interface = trim($interface);
                    $int_tmp2 = explode(".", $interface);
                    if( count($int_tmp2) == 1 )
                    {
                        $unittag = "";
                    }
                    else
                    {
                        $unittag = intval($int_tmp2[1]);
                    }
                    $interface = $int_tmp2[0];
                    if( ($unittag == "") or ($unittag == 0) )
                    {
                        $unitname = $interface;
                    }
                    else
                    {
                        $unitname = $interface . "." . $unittag;
                        if( preg_match("/.0$/", $interface) )
                        {
                            $int_tmp2 = explode(".", $interface);
                            $interface = $int_tmp2[0];
                        }
                    }

                }
                $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','$network/$cidr','$unitname','$zoneName','$unittag');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','layer3','$unitname');");
                $interface = "";
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project) values ('$network','0.0.0.0','$netmask','$metric','$project');");
            }
            elseif( ($gateway == "0.0.0.0") and (($flags == "rCGSU") or ($network != "0.0.0.0")) )
            {
                $x++;
                $zoneName = "Zone" . $x;
                $cidr = mask2cidrv4($netmask);
                $media = "ethernet";
                $unittag = 0;
                if( $interface == "" )
                {
                    $y++;
                    $interface = "ethernet1/" . $y;
                    $unitname = $interface;
                }
                elseif( preg_match("/bond/", $interface) )
                {
                    $int_tmp = str_replace("bond", "", $interface);
                    $int_tmp2 = explode(".", $int_tmp);
                    if( $int_tmp2[0] == 0 )
                    {
                        $unitname_tmp = "1";
                    }
                    else
                    {
                        $unitname_tmp = $int_tmp2[0] + 1;
                    }
                    if( count($int_tmp2) == 1 )
                    {
                        $unittag = 0;
                    }
                    else
                    {
                        $unittag = intval($int_tmp2[1]);
                    }
                    $unitname = "ae" . $unitname_tmp . "." . $unittag;
                    $interface = "ae" . $unitname_tmp;
                    $media = "aggregate-ethernet";
                }
                else
                {
                    $interface = trim($interface);
                    $int_tmp2 = explode(".", $interface);
                    if( count($int_tmp2) == 1 )
                    {
                        $unittag = "";
                    }
                    else
                    {
                        $unittag = intval($int_tmp2[1]);
                    }
                    $interface = $int_tmp2[0];
                    if( ($unittag == "") or ($unittag == 0) )
                    {
                        $unitname = $interface;
                    }
                    else
                    {
                        $unitname = $interface . "." . $unittag;
                        if( preg_match("/.0$/", $interface) )
                        {
                            $int_tmp2 = explode(".", $interface);
                            $interface = $int_tmp2[0];
                        }
                    }

                }


                $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','$network/$cidr','$unitname','$zoneName','$unittag');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','layer3','$unitname');");
                $interface = "";
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project) values ('$network','0.0.0.0','$netmask','$metric','$project');");
            }
            else
            {
                $i++;
                $name = "Route " . $i;
                $ip_version = "v4";
                $cidr = mask2cidrv4($netmask);
                #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project,zone) values ('$network','$gateway','$netmask','$metric','$project','$zone');");
                #$addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','$name','$network/$cidr','','ip-address','$gateway','$metric','$vsys')";
            }
        }

        if( count($addRoutes) > 0 )
        {
            $unique = array_unique($addRoutes);
            $projectdb->query("INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES " . implode(",", $unique) . ";");
            unset($addRoutes);
        }
        #Clean the vars

        $routes = "";

        # Get Interfaces to VR
        $getInterface = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id' AND source='$source';");
        if( $getInterface->num_rows > 0 )
        {
            $myInterfaces = array();
            while( $data = $getInterface->fetch_assoc() )
            {
                $myInterfaces[] = $data['unitname'];
            }
            $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $myInterfaces) . "' WHERE id='$vr_id';");
        }
    }

}

function optimization($source, $vsys, $template)
{
    global $projectdb;

    #FIX clean address_groups with 0 members or member_lid=0
    # Need to add the rules affected
    $getEmpty = $projectdb->query("SELECT lid,member FROM address_groups WHERE source='$source' AND member_lid=0 AND vsys='$vsys';");
    if( $getEmpty->num_rows > 0 )
    {
        while( $empty = $getEmpty->fetch_assoc() )
        {
            $lid = $empty['lid'];
            $member = $empty['member'];
            $getG = $projectdb->query("SELECT name,used FROM address_groups_id WHERE id='$lid' LIMIT 1;");
            $data = $getG->fetch_assoc();
            $used = $data['used'];
            $name = $data['name'];
            $projectdb->query("DELETE FROM address_groups WHERE source='$source' AND member_lid=0 AND lid='$lid' AND member='$member';");
            add_log2('warning', 'Optimization', 'Found member [' . $member . '] in AddressGroup [' . $name . '] without reference', $source, 'Removing member from the Group.', 'objects', $lid, 'address_groups_id');
        }
    }

    $getEmpty = $projectdb->query("SELECT id,name,used FROM address_groups_id WHERE source='$source' AND vsys='$vsys';");
    if( $getEmpty->num_rows > 0 )
    {
        while( $data = $getEmpty->fetch_assoc() )
        {
            $lid = $data['id'];
            $name_int = $data['name'];
            $used = $data['used'];
            $getEmpty2 = $projectdb->query("SELECT id FROM address_groups WHERE lid='$lid';");
            if( $getEmpty2->num_rows == 0 )
            {
                $table_name = "address_groups_id";
                $member_lid = $lid;

                if( $used == '0' )
                {
                    add_log('2', 'Optimization', 'Found AddressGroup [' . $name_int . '] without Members', $source, 'Removing Unused Address Group.');
                    $projectdb->query("DELETE FROM address_groups_id WHERE source='$source' AND id='$lid';");
                }
                #Search in Groups
                $projectdb->query("DELETE FROM address_groups WHERE member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("DELETE FROM security_rules_src WHERE member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("DELETE FROM security_rules_dst WHERE member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("DELETE FROM nat_rules_src WHERE member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("DELETE FROM nat_rules_dst WHERE member_lid='$member_lid' AND table_name='$table_name';");

                $projectdb->query("DELETE FROM nat_rules_translated_address WHERE member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("DELETE FROM nat_rules_translated_address_fallback WHERE member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid='', tp_dat_address_table='' WHERE tp_dat_address_lid='$member_lid' AND tp_dat_address_table='$table_name';");
                add_log('3', 'Optimization', 'Found AddressGroup [' . $name_int . '] without Members', $source, 'Removing Used Address Group.');
                $projectdb->query("DELETE FROM address_groups_id WHERE id='$lid';");
            }
        }
    }

    $getEmpty = $projectdb->query("SELECT lid,member FROM services_groups WHERE source='$source' AND member_lid=0  AND vsys='$vsys';");
    if( $getEmpty->num_rows > 0 )
    {
        while( $empty = $getEmpty->fetch_assoc() )
        {
            $lid = $empty['lid'];
            $member = $empty['member'];
            $getG = $projectdb->query("SELECT name,used FROM services_groups_id WHERE id='$lid' LIMIT 1;");
            $data = $getG->fetch_assoc();
            $used = $data['used'];
            $name_int = $data['name'];
            $projectdb->query("DELETE FROM services_groups WHERE source='$source' AND member_lid=0 AND lid='$lid' AND member='$member';");
            add_log('3', 'Optimization', 'Found member [' . $member . '] in ServiceGroup [' . $name_int . '] without reference', $source, 'Removing member from the Group.');
        }
    }

    $getEmpty = $projectdb->query("SELECT id,name,used FROM services_groups_id WHERE source='$source' AND vsys='$vsys';");
    if( $getEmpty->num_rows > 0 )
    {
        while( $data = $getEmpty->fetch_assoc() )
        {
            $lid = $data['id'];
            $name_int = $data['name'];
            $used = $data['used'];
            $getEmpty2 = $projectdb->query("SELECT id FROM services_groups WHERE lid='$lid';");
            if( $getEmpty2->num_rows == 0 )
            {
                $table_name = "services_groups_id";
                $member_lid = $lid;

                if( $used == '0' )
                {
                    add_log('3', 'Optimization', 'Found ServiceGroup [' . $name_int . '] without Members', $source, 'Removing Unused Service Group.');
                    $projectdb->query("DELETE FROM services_groups_id WHERE id='$lid';");
                }
                #Search in Groups
                $projectdb->query("DELETE FROM services_groups WHERE source='$source' AND member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("DELETE FROM security_rules_srv WHERE source='$source' AND member_lid='$member_lid' AND table_name='$table_name';");
                $projectdb->query("UPDATE nat_rules SET op_service_lid='', op_service_table='' WHERE source='$source' AND op_service_lid='$member_lid' AND op_service_table='$table_name';");
                add_log('3', 'Optimization', 'Found ServiceGroup [' . $name_int . '] without Members', $source, 'Removing Used Service Group.');
            }
        }
    }

    #check objects start by
    $getDomains = $projectdb->query("SELECT id,name,ipaddress,name FROM address WHERE vtype='domain' AND source='$source' AND vsys='$vsys';");
    if( $getDomains->num_rows > 0 )
    {
        while( $data = $getDomains->fetch_assoc() )
        {
            $name = $data['name'];
            $ipaddress = $data['ipaddress'];
            $ipaddress2 = preg_replace("/^./", "", $ipaddress);
            $id = $data['id'];
            $name2 = preg_replace("/^./", "", $name);
            if( $name != $name2 )
            {
                $projectdb->query("UPDATE address SET name='$name2',ipaddress='$ipaddress2' WHERE id='$id'");
                add_log2('warning', 'Optimization', 'FQDN Object starts by "." [' . $name . '] changing to [' . $name2 . ']', $source, 'No action required', 'objects', $id, 'address');
            }
        }
    }

    # Add Interfaces with unittag0
    $getInterfaces = $projectdb->query("SELECT name,type,media,vsys,template,vr_id,unitname FROM interfaces WHERE source='$source' AND template='$template' GROUP BY name;");
    if( $getInterfaces->num_rows > 0 )
    {
        while( $getInterfacesData = $getInterfaces->fetch_assoc() )
        {
            $interfaceName = $getInterfacesData['name'];
            $interfaceType = $getInterfacesData['type'];
            $interfaceMedia = $getInterfacesData['media'];
            $interfaceVrid = $getInterfacesData['vr_id'];
            $interfaceVsys = $getInterfacesData['vsys'];
            $unitname = $interfaceName;
            $unittag = "";
            $getUnit0 = $projectdb->query("SELECT name,type,media,vsys,template,vr_id,unitname FROM interfaces WHERE source='$source' AND template='$template' AND name='$interfaceName' AND unittag='0';");
            if( $getUnit0->num_rows == 0 )
            {
                $projectdb->query("INSERT INTO interfaces (unittag,source,template,vsys,name,unitname,media,type) VALUES ('$unittag','$source','$template','$interfaceVsys','$interfaceName','$unitname','$interfaceMedia','$interfaceType')");
            }
        }
        # Update Virtual Router
        /* $getInterface = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$interfaceVrid' AND source='$source';");
          if ($getInterface->num_rows > 0) {
          while ($data = $getInterface->fetch_assoc()) {
          $myInterfaces[] = $data['unitname'];
          }
          $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $myInterfaces) . "' WHERE id='$interfaceVrid';");
          } */
    }

    #Map Ip address with INT address
    $getInterfaces = $projectdb->query("SELECT id,unitipaddress FROM interfaces WHERE unitipaddress!='' AND template='$template' AND source='$source';");
    if( $getInterfaces->num_rows > 0 )
    {
        while( $data = $getInterfaces->fetch_assoc() )
        {
            $id = $data['id'];
            $unitipaddress = $data['unitipaddress'];
            $split = explode("/", $unitipaddress);
            $network = $split[0];
            $cidr = $split[1];
            $getMap = $projectdb->query("SELECT ipaddress FROM address WHERE source='$source' AND name like 'INT-%';");
            if( $getMap->num_rows > 0 )
            {
                while( $data2 = $getMap->fetch_assoc() )
                {
                    $ip = $data2['ipaddress'];
                    if( netMatchV4($unitipaddress, $ip) )
                    {
                        $new_network = $ip . "/" . $cidr;
                        $projectdb->query("UPDATE interfaces SET unitipaddress='$new_network' WHERE id='$id';");
                    }
                }
            }
        }
    }
}

function calculateExclusionGroups()
{

    global $projectdb;

    $getLid = $projectdb->query("SELECT id, vsys, source, devicegroup FROM address_groups_id WHERE type = 'group_with_exclusion';");

    if( $getLid->num_rows > 0 )
    {
        while( $dataLid = $getLid->fetch_assoc() )
        {
            $lid = $dataLid['id'];
            $vsys = $dataLid['vsys'];
            $source = $dataLid['source'];
            $devicegroup = $dataLid['devicegroup'];

            $incGroupExpanded = array();
            $exclGroupExpanded = array();
            $res = array();

            $incGroupExpanded_p = expandMembersGroups($lid, "1");
            $exclGroupExpanded_p = expandMembersGroups($lid, "2");
            /*if(($lid == "416") || ($lid == "234")){
                echo "START: incGroupExpanded_p:\n";
                print_r($incGroupExpanded_p);
                echo "exclGroupExpanded_p:\n";
                print_r($exclGroupExpanded_p);
            }*/

            // create IP mappings for all objects
            foreach( $incGroupExpanded_p as $index => $object )
            {

                if( $object['table_name'] == "address_groups_id" )
                {

                    $incGroupExpanded = expandMembersGroups($object['member_lid'], "3");

                    foreach( $incGroupExpanded as $index => $object2 )
                    {

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        $incGroupExpanded[$index] = array('object' => $object2['member'], 'member_lid' => $object2['member_lid'], 'table_name' => $object2['table_name'], 'start' => $res['start'],
                            'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']), 'status' => 0);

                    }

                }
                else
                {

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    $incGroupExpanded[$index] = array('object' => $object['member'], 'member_lid' => $object['member_lid'], 'table_name' => $object['table_name'], 'start' => $res['start'],
                        'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']), 'status' => 0);
                }
            }

            foreach( $exclGroupExpanded_p as $index => $object )
            {

                if( $object['table_name'] == "address_groups_id" )
                {

                    $exclGroupExpanded = expandMembersGroups($object['member_lid'], "3");

                    foreach( $exclGroupExpanded as $index => $object2 )
                    {

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        $exclGroupExpanded[$index] = array('object' => $object2['member'], 'member_lid' => $object2['member_lid'], 'table_name' => $object2['table_name'], 'start' => $res['start'],
                            'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']));

                    }

                }
                else
                {

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    $exclGroupExpanded[$index] = array('object' => $object['member'], 'member_lid' => $object['member_lid'], 'table_name' => $object['table_name'], 'start' => $res['start'],
                        'end' => $res['end'], 'startip' => long2ip($res['start']), 'endip' => long2ip($res['end']));
                }
            }

            /*if(($lid == "416") || ($lid == "234")){
                echo "-------------------> END FOREACH: " .$lid. "\n";
                echo "incGroupExpanded: \n";
                print_r($incGroupExpanded);
                echo "exclGroupExpanded: \n";
                print_r($exclGroupExpanded);
            }*/

            //  Now we need to match all excl vs inc objects
            foreach( $exclGroupExpanded as $index => &$excl )
            {
                foreach( $incGroupExpanded as &$incl )
                {
                    // this object was already fully matched so we skip
                    if( $incl['status'] == 2 ) continue;
                    if( $incl['start'] >= $excl['start'] && $incl['end'] <= $excl['end'] )
                    {
                        $incl['status'] = 2;
                    }
                    elseif( $incl['start'] >= $excl['start'] && $incl['start'] <= $excl['end'] || $incl['end'] >= $excl['start'] && $incl['end'] <= $excl['end']
                        || $incl['start'] <= $excl['start'] && $incl['end'] >= $excl['end'] )
                    {
                        $incl['status'] = 1;
                    }
                }
            }//fin foreach

            // First filter is done, now we make a list of Incl objects :
            // - Partial matches, these ones will require special treatment
            // - FULL matches, these ones will not be included in final group
            // - NO matches, these ones will be included in final group
            $inclPartial = array();
            $inclNo = array();


            foreach( $incGroupExpanded as &$incl )
            {

                /*if( $incl['status'] == 1 ){
                    $inclPartial[] = &$incl;
                }elseif( $incl['status'] == 2 ){
                    $inclNo[] = &$incl;
                }*/

                if( ($incl['status'] == 1) || ($incl['status'] == 2) )
                {
                    $inclPartial[] = &$incl;
                }
                elseif( $incl['status'] == 0 )
                {
                    $inclNo[] = &$incl;
                }
            }

            // Sort incl objects IP mappings by Start IP
            $inclMapping = array();
            $tmp = array();
            foreach( $inclPartial as &$incl )
            {
                $tmp[] = $incl['start'];
            }
            unset($incl);
            sort($tmp, SORT_NUMERIC);
            foreach( $tmp as $value )
            {
                foreach( $inclPartial as &$incl )
                {
                    if( $value == $incl['start'] )
                    {
                        $inclMapping[] = $incl;
                    }
                }
            }
            unset($incl);

            // Sort excl objects IP mappings by Start IP
            $exclMapping = array();
            $tmp = array();
            foreach( $exclGroupExpanded as &$excl )
            {
                $tmp[] = $excl['start'];
            }
            unset($excl);
            sort($tmp, SORT_REGULAR);
            foreach( $tmp as $value )
            {
                foreach( $exclGroupExpanded as &$excl )
                {
                    if( $value == $excl['start'] )
                    {
                        $exclMapping[] = $excl;
                    }
                }
            }
            unset($excl);

            // Merge overlapping or Incl joint entries
            $mapKeys = array_keys($inclMapping);
            $mapCount = count($inclMapping);
            for( $i = 0; $i < $mapCount; $i++ )
            {
                $current = &$inclMapping[$mapKeys[$i]];
                for( $j = $i + 1; $j < $mapCount; $j++ )
                {
                    $compare = &$inclMapping[$mapKeys[$j]];

                    if( $compare['start'] > $current['end'] + 1 )
                        break;

                    $current['end'] = $compare['end'];
                    $current['endip'] = $compare['endip'];
                    unset($inclMapping[$mapKeys[$j]]);
                    $i++;
                }
            }

            // Merge overlapping or joint Excl entries
            $mapKeys = array_keys($exclMapping);
            $mapCount = count($exclMapping);
            for( $i = 0; $i < $mapCount; $i++ )
            {
                $current = &$exclMapping[$mapKeys[$i]];
                for( $j = $i + 1; $j < $mapCount; $j++ )
                {
                    $compare = &$exclMapping[$mapKeys[$j]];

                    if( $compare['start'] > $current['end'] + 1 )
                        break;

                    $current['end'] = $compare['end'];
                    $current['endip'] = $compare['endip'];
                    unset($exclMapping[$mapKeys[$j]]);
                    $i++;
                }
            }

            // Calculate IP RANGE HOLES !!!
            foreach( $inclMapping as $index => &$incl )
            {
                $current = &$incl;

                foreach( $exclMapping as &$excl )
                {
                    if( $excl['start'] > $current['end'] )
                        continue;
                    if( $excl['start'] < $current['start'] && $excl['end'] < $current['start'] )
                        continue;
                    // if this excl object is including ALL
                    if( $excl['start'] <= $current['start'] && $excl['end'] >= $current['end'] )
                    {
                        unset($inclMapping[$index]);
                        break;
                    }
                    elseif( $excl['start'] <= $current['start'] && $excl['end'] <= $current['end'] )
                    {
                        $current['start'] = $excl['end'];
                        $current['startip'] = $excl['endip'];
                    }
                    elseif( $excl['start'] > $current['start'] && $excl['end'] >= $current['end'] )
                    {
                        $current['end'] = $excl['start'] - 1;
                        $current['endip'] = long2ip($current['end']);
                        break;
                    }
                    elseif( $excl['start'] > $current['start'] && $excl['end'] < $current['end'] )
                    {
                        $oldEnd = $current['end'];
                        $oldEndIP = $current['endip'];
                        $current['end'] = $excl['start'] - 1;
                        $current['endip'] = long2ip($current['end']);
                        unset($current);

                        $current = array();
                        $inclMapping[] = &$current;
                        $current['start'] = $excl['end'] + 1;
                        $current['startip'] = long2ip($current['start']);
                        $current['end'] = $oldEnd;
                        $current['endip'] = $oldEndIP;
                    }
                }
            }

            // Sort incl objects IP mappings by Start IP
            $finalInclMapping = array();
            $tmp = array();
            foreach( $inclMapping as &$incl3 )
            {
                $tmp[] = $incl3['start'];
            }
            unset($incl3);

            sort($tmp, SORT_NUMERIC);
            $is_first = 0;
            $members_news = array();
            foreach( $tmp as $value )
            {
                foreach( $inclMapping as &$incl )
                {
                    if( $value == $incl['start'] )
                    {
                        $oValue = $incl['startip'] . "-" . $incl['endip'];

                        $oName = 'R-' . $incl['startip'] . "-" . $incl['endip'];
                        $finalInclMapping[] = $incl;

                        $members_news[] = $oName;

                        $getExistAddress = $projectdb->query("SELECT id FROM address WHERE name = '$oName' AND type = 'ip-range' AND ipaddress = '$oValue' AND vsys = '$vsys' AND source = '$source' ");
                        if( $getExistAddress->num_rows == 1 )
                        {
                            while( $data = $getExistAddress->fetch_assoc() )
                            {
                                $member_lid = $data['id'];
                            }
                        }
                        else
                        {
                            $projectdb->query("INSERT INTO address (id, name_ext, name, used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified) "
                                . "VALUES (NULL, '$oName', '$oName', '', '', '$devicegroup', '$vsys', 'ip-range','$oValue','', '', '', '', '', 'ip-range', '$source', '', '', '', '');");

                            $member_lid = $projectdb->insert_id;
                        }

                        if( $is_first == 0 )
                        {

                            $name_int_old = array();

                            $getNameGroup = $projectdb->query("SELECT name FROM address_groups_id WHERE id = '$lid' ");
                            if( $getNameGroup->num_rows == 1 )
                            {
                                $dataNG = $getNameGroup->fetch_assoc();
                                $group_name = $dataNG['name'];
                            }

                            $getMembersGroups = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid = '$lid' ");
                            if( $getMembersGroups->num_rows >= 1 )
                            {
                                while( $dataM = $getMembersGroups->fetch_assoc() )
                                {
                                    $member_lid_g = $dataM['member_lid'];
                                    $table_name_g = $dataM['table_name'];

                                    $getMembersGroupsN = $projectdb->query("SELECT name FROM $table_name_g WHERE id = '$member_lid_g' ");
                                    if( $getMembersGroupsN->num_rows == 1 )
                                    {
                                        $dataN = $getMembersGroupsN->fetch_assoc();
                                        $name_int_old[] = $dataN['name'];
                                    }
                                }
                            }

                            $projectdb->query("DELETE FROM address_groups WHERE lid = '$lid' ");
                            $is_first = 1;
                        }

                        $projectdb->query("INSERT INTO address_groups (id, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source) "
                            . "VALUES (NULL, '', '', '$devicegroup', '$vsys', '$oValue', '$member_lid', 'address', '$lid', '$source');");

                    }
                }
            }

            // Añadir el resto de miembros
            foreach( $inclNo as &$incl2 )
            {

                $name_int_no = $incl2['object'];
                $member_lid_no = $incl2['member_lid'];
                $table_name_no = $incl2['table_name'];
                $getExistMember = $projectdb->query("SELECT id FROM address_groups WHERE member_lid = '$member_lid_no' AND table_name = '$table_name_no' AND lid = '$lid' AND vsys = '$vsys' AND source = '$source' ");

                if( $getExistMember->num_rows == 0 )
                {

                    $projectdb->query("INSERT INTO address_groups (id, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source) "
                        . "VALUES (NULL, '', '', '$devicegroup', '$vsys', '$name_int_no', '$member_lid_no', '$table_name_no', '$lid', '$source')");

                }
            }

            unset($incl);
            unset($incl2);
            unset($inclNo);

            if( count($members_news) > 0 )
            {
                add_log('ok', 'Phase 2: Reading Address Objects and Groups', 'Group with exclusion ' . $group_name . ': The members {' . implode(",", $name_int_old) . '} were replaced by {' . implode(",", $members_news) . '}.', $source, '');
            }
            $projectdb->query("UPDATE address_groups_id SET type = 'static' WHERE id = '$lid'");
        }
    }// fin if lid
}

function expandMembersGroups($lid, $position)
{

    global $projectdb;

    $myMembers = array();

    if( $position == "1" )
    {
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id ASC LIMIT 1 ;");
        if( $getFirstGroup->num_rows > 0 )
        {
            while( $data = $getFirstGroup->fetch_assoc() )
            {
                $myMembers[] = $data;
            }
        }
    }
    elseif( $position == "2" )
    {
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id DESC LIMIT 1 ;");
        if( $getFirstGroup->num_rows > 0 )
        {
            while( $data = $getFirstGroup->fetch_assoc() )
            {
                $myMembers[] = $data;
            }
        }
    }
    elseif( $position == "3" )
    {
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid';");
        if( $getFirstGroup->num_rows > 0 )
        {
            while( $data = $getFirstGroup->fetch_assoc() )
            {
                $myMembers[] = $data;
            }
        }
    }

    return $myMembers;

}
