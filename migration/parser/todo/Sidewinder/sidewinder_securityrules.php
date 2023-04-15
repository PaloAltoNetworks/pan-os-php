<?php


function get_security_policy($source, $vsys, $template, $config_path)
{
    global $projectdb;

    $mcafee_config_file = file($config_path);

    $addRule = array();
    $addZoneFrom = array();
    $addZoneTo = array();
    $addSRV = array();
    $addTag = array();
    $addSRC = array();
    $addDST = array();
    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;
    $thecolor = 1;
    foreach( $mcafee_config_file as $line2 => $names_line2 )
    {
        if( preg_match("/^policy add table=rulegroup/", $names_line2) )
        {
            #Convert into Tags
            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);
            if( count($matches) > 1 )
            {
                $counter = 0;
                $rule = array();
                foreach( $matches[1] as $option )
                {
                    $counter++;
                    $option = str_replace("'", "", $option);
                    $tmp = explode('=', $option);
                    $name = $tmp[0];
                    $value = '';
                    if( count($tmp) > 1 )
                    {
                        if( !empty($tmp[1]) )
                        {
                            $value = $tmp[1];
                            if( substr($value, 0, 1) == "'" and substr($value, -1, 1) == "'" )
                            {
                                $value = substr($value, 1, -1);
                            }
                            //print $tmp[0] .":". $value."\n";
                            $rule[$tmp[0]] = $value;
                        }
                        else
                        {
                            $value = '';
                        }
                    }
                }
                if( isset($rule["name"]) )
                {
                    $color = "color" . $thecolor;
                    $tagname = truncate_tags($rule["name"]);
                    $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$tagname','$source','$vsys','$color');");
                    if( $thecolor == 16 )
                    {
                        $thecolor = 1;
                    }
                    else
                    {
                        $thecolor++;
                    }
                }
            }
        }
        if( preg_match("/^policy add table=rule /i", $names_line2) )
        {
            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);
            if( count($matches) > 1 )
            {
                $counter = 0;
                foreach( $matches[1] as $option )
                {
                    $option = str_replace("'", "", $option);
                    $counter++;
                    $tmp = explode('=', $option);
                    $name = $tmp[0];
                    $value = '';
                    if( count($tmp) > 1 )
                    {
                        if( !empty($tmp[1]) )
                        {
                            $value = $tmp[1];
                            if( substr($value, 0, 1) == "'" and substr($value, -1, 1) == "'" )
                            {
                                $value = substr($value, 1, -1);
                            }
                            //print $tmp[0] .":". $value."\n";
                            $rule[$tmp[0]] = $value;
                        }
                        else
                        {
                            $value = '';
                        }
                    }
                }

                if( isset($rule["disable"]) )
                {
                    if( $rule["disable"] == "yes" )
                    {
                        $RuleDisable = "1";
                    }
                    if( $rule["disable"] == "no" )
                    {
                        $RuleDisable = "0";
                    }
                }
                else
                {
                    $RuleDisable = "0";
                }

                if( isset($rule["name"]) )
                {
                    $RuleName = truncate_names(normalizeNames($rule["name"]));
                }
                else
                {
                    $RuleName = "Rule " . $lid;
                }

                if( isset($rule["description"]) )
                {
                    $RuleDescription = normalizeComments($rule["description"]);
                }
                else
                {
                    $RuleDescription = "";
                }

                if( isset($rule["action"]) )
                {
                    if( ($rule["action"] == "allow") or ($rule["action"] == "deny") )
                    {
                        $RuleAction = $rule["action"];
                    }
                }
                else
                {
                    $RuleAction = "allow";
                    add_log2('1', 'Phase 5: Reading Security Rules', 'Action other than Allow or Deny [' . $rule["action"] . '] found in RuleID [' . $lid . ']', $source, 'No Action Required.', 'rules', $lid, 'security_rules');
                }

                if( isset($rule["rulegroup"]) )
                {
                    $Tag = truncate_tags($rule["rulegroup"]);
                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$Tag' AND source='$source' AND vsys='$vsys' LIMIT 1");
                    if( $getTag->num_rows == 1 )
                    {
                        $getTagData = $getTag->fetch_assoc();
                        $TagId = $getTagData['id'];
                        $addTag[] = "('$source','$vsys','$TagId','tag','$lid')";
                    }
                }

                if( isset($rule["source_burbs"]) )
                {

                    if( $rule["source_burbs"] == "*" )
                    {
                        $RuleZoneSrc = "";
                    }
                    elseif( preg_match('/,/i', $rule["source_burbs"]) )
                    {
                        $matches2 = explode(',', $rule["source_burbs"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["source_burbs"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    }
                    unset($rule["source_burbs"]);
                }

                if( isset($rule["source_zones"]) )
                {

                    if( $rule["source_zones"] == "*" )
                    {
                        $RuleZoneSrc = "";
                    }
                    elseif( preg_match('/,/i', $rule["source_zones"]) )
                    {
                        $matches2 = explode(',', $rule["source_zones"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["source_zones"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    }
                    unset($rule["source_zones"]);
                }

                if( isset($rule["dest_zones"]) )
                {

                    if( $rule["dest_zones"] == "*" )
                    {
                        $RuleZoneDst = "";
                    }
                    elseif( preg_match('/,/i', $rule["dest_zones"]) )
                    {
                        $matches2 = explode(',', $rule["dest_zones"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["dest_zones"]);
                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    }
                    unset($rule["dest_zones"]);
                }

                if( isset($rule["dest_burbs"]) )
                {

                    if( $rule["dest_burbs"] == "*" )
                    {
                        $RuleZoneDst = "";
                    }
                    elseif( preg_match('/,/i', $rule["dest_burbs"]) )
                    {
                        $matches2 = explode(',', $rule["dest_burbs"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["dest_burbs"]);
                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if( $combo != "" )
                            {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    }
                    unset($rule["dest_burbs"]);
                }

                if( isset($rule["service"]) )
                {

                    if( $rule["service"] == "*" )
                    {
                        $RuleService = "";
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["service"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $tableService = $members[0];
                            $searchService = $members[1];

                            if( $tableService == "service" )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys';");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addSRV[] = "('$source','$vsys','$lid','$member_id','services')";
                                    }
                                }
                                else
                                {
                                    #Error or 0 or more than 1 found OR i migrated to GROUP by TCP and UDP object
                                    $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                    if( $SearchS->num_rows == 1 )
                                    {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if( $combo != "" )
                                        {
                                            $addSRV[] = "('$source','$vsys','$lid','$member_id','services_groups_id')";
                                        }
                                    }
                                    else
                                    {
                                        #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                        #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                    }
                                }
                            }
                            elseif( $tableService == "servicegroup" )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addSRV[] = "('$source','$vsys','$lid','$member_id','services_groups_id')";
                                    }
                                }
                                else
                                {
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                    #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                }
                            }
                            else
                            {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Service Object in Rule $RuleID: Name: $searchService');");
                            }
                        }
                    }
                }

                if( isset($rule["application"]) )
                {
                    //print "App: ".$rule["application"]."\n";
                    if( ($rule["application"] == "*") or ($rule["application"] == "application:all") )
                    {
                        $RuleService = "";
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["application"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $tableService = $members[0];
                            $searchService = $members[1];
                            //print "splitApp: ".$tableService.":".$searchService."\n";
                            if( ($tableService == "custom") or ($tableService == "application") )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys';");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addSRV[] = "('$source','$vsys','$lid','$member_id','services')";
                                    }
                                }
                                else
                                {
                                    #Error or 0 or more than 1 found OR i migrated to GROUP by TCP and UDP object
                                    $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                    if( $SearchS->num_rows == 1 )
                                    {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if( $combo != "" )
                                        {
                                            $addSRV[] = "('$source','$vsys','$lid','$member_id','services_groups_id')";
                                        }
                                    }
                                    else
                                    {
                                        #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                        #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                    }
                                }
                            }
                            elseif( $tableService == "appgroup" )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addSRV[] = "('$source','$vsys','$lid','$member_id','services_groups_id')";
                                    }
                                }
                                else
                                {
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                    #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                }
                            }
                            else
                            {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Service Object in Rule $RuleID: Name: $searchService');");
                            }
                        }
                    }
                    unset($rule["application"]);
                }

                if( isset($rule["source"]) )
                {

                    if( ($rule["source"] == "*") or ($rule["source"] == "all:v4") or ($rule["source"] == "all:v6") or ($rule["source"] == "All") )
                    {
                        $RuleSource = "";
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["source"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $tableSource = $members[0];
                            $searchSource = $members[1];

                            if( ($tableSource == "host") or ($tableSource == "subnet") or ($tableSource == "iprange") )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                }
                                else
                                {

                                    #Error or 0 or more than 1 found
                                    # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                }
                            }
                            elseif( $tableSource == "ipaddr" )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE ipaddress='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                }
                                else
                                {
                                    $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name='$searchSource' AND source='$source' AND vsys='$vsys'");
                                    if( $SearchS->num_rows == 1 )
                                    {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if( $combo != "" )
                                        {
                                            $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                        }
                                    }
                                    else
                                    {
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,type) VALUES ('$source','$vsys','H-$searchSource','H-$searchSource','$searchSource','32','host')");
                                        $member_id = $projectdb->insert_id;
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                    #Error or 0 or more than 1 found
                                    # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                }
                            }
                            elseif( $tableSource == "netgroup" )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address_groups_id')";
                                    }
                                }
                                else
                                {
                                    #Error or 0 or more than 1 found
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','HostGroup used in Rule $RuleID but not seen in HostGroup Database: Name: $searchSource');");
                                }
                            }
                            elseif( $tableSource == "domain" )
                            {
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Domain used in Rule $RuleID (source) but is an unsupported Object for Palo Alto Networks, Name: $searchSource');");
                            }
                            else
                            {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Source Address Object in Rule $RuleID: Name: $searchSource');");
                            }
                        }
                    }

                    unset($rule["source"]);
                }

                if( isset($rule["dest"]) )
                {

                    if( ($rule["dest"] == "*") or ($rule["dest"] == "all:v4") or ($rule["dest"] == "all:v6") or ($rule["dest"] == "All") )
                    {
                        $RuleSource = "";
                    }
                    else
                    {
                        $matches2 = explode(',', $rule["dest"]);

                        foreach( $matches2 as $num => $combo )
                        {
                            $members = explode(":", $combo);
                            $tableSource = $members[0];
                            $searchSource = $members[1];

                            if( ($tableSource == "host") or ($tableSource == "subnet") or ($tableSource == "iprange") )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                    else
                                    {
                                        #Error or 0 or more than 1 found
                                        # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                    }
                                }
                            }
                            elseif( $tableSource == "ipaddr" )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE ipaddress='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                }
                                else
                                {
                                    $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name='$searchSource' AND source='$source' AND vsys='$vsys'");
                                    if( $SearchS->num_rows == 1 )
                                    {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if( $combo != "" )
                                        {
                                            $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                        }
                                    }
                                    else
                                    {
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,type) VALUES ('$source','$vsys','H-$searchSource','H-$searchSource','$searchSource','32','host')");
                                        $member_id = $projectdb->insert_id;
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                        #Error or 0 or more than 1 found
                                        # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                    }
                                }
                            }
                            elseif( $tableSource == "netgroup" )
                            {
                                $SearchS = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if( $SearchS->num_rows == 1 )
                                {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if( $combo != "" )
                                    {
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address_groups_id')";
                                    }
                                }
                                else
                                {
                                    #Error or 0 or more than 1 found
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','HostGroup used in Rule $RuleID but not seen in HostGroup Database: Name: $searchSource');");
                                }
                            }
                            elseif( $tableSource == "domain" )
                            {
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Domain used in Rule $RuleID (source) but is an unsupported Object for Palo Alto Networks, Name: $searchSource');");
                            }
                            else
                            {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Source Address Object in Rule $RuleID: Name: $searchSource');");
                            }
                        }
                    }

                    unset($rule["dest"]);
                }


                $addRule[] = "('$source','$vsys','$lid','$position','$RuleName','$RuleDescription','$RuleAction','$RuleDisable')";
                $lid++;
                $position++;
            }
        }
    }
    if( count($addRule) > 0 )
    {
        $projectdb->query("INSERT INTO security_rules (source,vsys,id,position,name,description,action,disabled) VALUES " . implode(",", $addRule));
        unset($addRule);

        if( count($addTag) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_tag (source,vsys,member_lid,table_name,rule_lid) VALUES " . implode(",", $addTag));
            unset($addTag);
        }
        if( count($addZoneFrom) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid) VALUES " . implode(",", $addZoneFrom));
            unset($addZoneFrom);
        }
        if( count($addZoneTo) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES " . implode(",", $addZoneTo));
            unset($addZoneTo);
        }
        if( count($addSRV) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addSRV));
            unset($addSRV);
        }
        if( count($addSRC) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addSRC));
            unset($addSRC);
        }
        if( count($addDST) > 0 )
        {
            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addDST));
            unset($addDST);
        }

        # Update objects where ipaddress is equal to the Name as Dummy
        $projectdb->query("UPDATE address SET dummy=1 WHERE name_ext=ipaddress AND (cidr=32 OR cidr=128) AND source='$source' AND vsys='$vsys';");
    }
}
