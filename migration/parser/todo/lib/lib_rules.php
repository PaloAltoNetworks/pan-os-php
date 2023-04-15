<?php

/*
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';

require_once 'definitions.php';

require_once INC_ROOT . '/libs/common/lib-objects.php';
require_once INC_ROOT . '/libs/common/RuleObject.php';
require_once INC_ROOT . '/libs/common/CompleteSecRuleObject.php';

require_once INC_ROOT . '/libs/common/MemberObject.php'; //class: MemberObject

use PaloaltoNetworks\Policy\Objects\MemberObject;
use PaloaltoNetworks\Policy\Objects\RuleObject;
use PaloaltoNetworks\Policy\Objects\CompleteSecRuleObject;

define('EQUAL', 0);
define('DIFFERENT', -1);

/** This method declares all the posible fields that a Rule may have in an Array Structure
 * @return array
 */
function initSecRule()
{
    $rule = array();
    $rule['position'] = $rule['name'] = $rule['negate_source'] = $rule['negate_destination'] = $rule['description'] =
    $rule['action'] = $rule['schedule'] = $rule['disabled'] = $rule['log_start'] = $rule['log_end'] =
    $rule['log_forwarding'] = $rule['vsys'] = $rule['lid'] = $rule['source'] = $rule['dsri'] =
    $rule['target'] = $rule['checkit'] = $rule['migrate'] = $rule['counter'] = $rule['qos'] =
    $rule['profile_type'] = $rule['profile_group'] = $rule['qos_value'] = $rule['tag'] = $rule['preorpost'] =
    $rule['devicegroup'] = $rule['blocked'] = $rule['rule_type'] = $rule['invalid'] =
    $rule['icmp_unreachable'] = "";
    $rule['modified'] = 0;

    return $rule;
}

function initNatRule()
{
    $natRule = array();
    $natRule['position'] = $natRule['name'] = $natRule['description'] = $natRule['target'] = $natRule['target_negate'] =
    $natRule['disabled'] = $natRule['vsys'] = $natRule['lid'] = $natRule['source'] = $natRule['checkit'] =
    $natRule['migrate'] = $natRule['counter'] = $natRule['tp_sat_bidirectional'] = $natRule['op_zone_to'] = $natRule['op_to_interface'] =
    $natRule['is_dat'] = $natRule['op_service_lid'] = $natRule['op_service_table'] = $natRule['tp_sat_type'] = $natRule['tp_sat_address_type'] =
    $natRule['tp_sat_interface'] = $natRule['tp_sat_ipaddress'] = $natRule['tp_dat_port'] = $natRule['tp_dat_address_lid'] = $natRule['tp_dat_address_table'] =
    $natRule['implicit'] = $natRule['preorpost'] = $natRule['devicegroup'] = $natRule['tag'] = $natRule['active_active_device_binding'] =
    $natRule['nat_type'] = $natRule['tp_sat_interface_fallback'] = $natRule['tp_sat_ipaddress_fallback'] = $natRule['tp_fallback_type'] = $natRule['blocked'] =
    $natRule['invalid'] = $natRule['modified'] = "";

    return $natRule;
}

function getSecRuleId(mysqli $projectdb, STRING $source, STRING $devicegroup, STRING $vsys, STRING $ruleName)
{
//function getSecRuleId($projectdb, STRING $vsys, STRING $ruleName){
    global $projectdb;

    $query = "SELECT id, position FROM security_rules WHERE name = '$ruleName';";
    $matchingAddress = $projectdb->query($query);
    if( $matchingAddress->num_rows != 0 )
    {
        $get = (array)$matchingAddress->fetch_assoc();
        $id = $get['id'];
        $location = "security_rules";
        $position = $get['position'];
        $name = $ruleName;
    }
    else
    {
//        echo "The $ruleName security rule does not exist!\n";
        return null;
    }

    $member = new RuleObject($id, $location, $name, $position);

    return $member;
}

function pushSecRules(mysqli $projectdb, STRING $source, STRING $devicegroup, STRING $vsys, &$initial, $positions)
{
    //Check if there is anything to push
    $query = "SELECT id FROM security_rules WHERE source='$source' AND vsys='$vsys' AND devicegroup='$devicegroup' AND position='$initial';";
//    echo "$query\n";
    $matchingAddress = $projectdb->query($query);

    if( $matchingAddress->num_rows != 0 )
    {
        $query = "UPDATE security_rules SET position = position+$positions WHERE position >= $initial AND source='$source' AND vsys='$vsys' AND devicegroup='$devicegroup';";
//        echo "$query\n";
        $projectdb->query($query);
        return 1;
    }
    else
    {
        return 0;
    }
}

function pushNatRules(mysqli $projectdb, STRING $source, STRING $devicegroup, STRING $vsys, $initial, $positions)
{
    $query = "SELECT id FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND devicegroup='$devicegroup' AND position='$initial';";
//    echo "$query\n";
    $matchingAddress = $projectdb->query($query);

    if( $matchingAddress->num_rows != 0 )
    {
        $query = "UPDATE nat_rules SET position = position+$positions WHERE position >= $initial AND source='$source' AND vsys='$vsys' AND devicegroup='$devicegroup';";
        $projectdb->query($query);
        return 1;
    }
    else
    {
        return 0;
    }
}


function insertNatRule(mysqli $projectdb, array $natRule, STRING $table, &$position)
{
    $pushed = pushNatRules($projectdb, $natRule['source'], $natRule['devicegroup'], $natRule['vsys'], $natRule['position'], 1);
    if( $pushed == 1 )
    {
        $position++;
    }
    $query = "INSERT INTO $table (" .
        "position, name, description, target, target_negate, " .
        "disabled, vsys, lid, source, checkit, " .
        "migrate, counter, tp_sat_bidirectional, op_zone_to, op_to_interface, " .
        "is_dat, op_service_lid, op_service_table, tp_sat_type, tp_sat_address_type, " .
        "tp_sat_interface, tp_sat_ipaddress, tp_dat_port, tp_dat_address_lid, tp_dat_address_table, " .
        "implicit, preorpost, devicegroup, tag, active_active_device_binding, " .
        "nat_type, tp_sat_interface_fallback, tp_sat_ipaddress_fallback, tp_fallback_type, blocked, " .
        "invalid, modified) " .
        "VALUES " .
        "('" . $natRule['position'] . "', '" . $natRule['name'] . "', '" . $natRule['description'] . "', '" . $natRule['target'] . "', '" . $natRule['target_negate'] . "', " .
        " '" . $natRule['disabled'] . "', '" . $natRule['vsys'] . "', '" . $natRule['lid'] . "', '" . $natRule['source'] . "', '" . $natRule['checkit'] . "', " .
        " '" . $natRule['migrate'] . "', '" . $natRule['counter'] . "', '" . $natRule['tp_sat_bidirectional'] . "', '" . $natRule['op_zone_to'] . "', '" . $natRule['op_to_interface'] . "', " .
        " '" . $natRule['is_dat'] . "', '" . $natRule['op_service_lid'] . "', '" . $natRule['op_service_table'] . "', '" . $natRule['tp_sat_type'] . "', '" . $natRule['tp_sat_address_type'] . "', " .
        " '" . $natRule['tp_sat_interface'] . "', '" . $natRule['tp_sat_ipaddress'] . "', '" . $natRule['tp_dat_port'] . "', '" . $natRule['tp_dat_address_lid'] . "', '" . $natRule['tp_dat_address_table'] . "', " .
        " '" . $natRule['implicit'] . "', '" . $natRule['preorpost'] . "', '" . $natRule['devicegroup'] . "', '" . $natRule['tag'] . "', '" . $natRule['active_active_device_binding'] . "', " .
        " '" . $natRule['nat_type'] . "', '" . $natRule['tp_sat_interface_fallback'] . "', '" . $natRule['tp_sat_ipaddress_fallback'] . "', '" . $natRule['tp_fallback_type'] . "', '" . $natRule['blocked'] . "', " .
        " '" . $natRule['invalid'] . "', '" . $natRule['modified'] . "')";
    $projectdb->query($query);
    return $projectdb->insert_id;
}

function insertSecRule(mysqli $projectdb, array $rule, STRING $table, INT &$position)
{
    $pushed = pushSecRules($projectdb, $rule['source'], $rule['devicegroup'], $rule['vsys'], $rule['position'], 1);
    if( $pushed == 1 )
    {
        $position++;
    }

    $query = "INSERT INTO $table (" .
        "position, name, negate_source, negate_destination,description, " .
        "action, schedule, disabled, log_start, log_end, " .
        "log_forwarding, vsys, lid, source, dsri, " .
        "target, checkit, migrate, counter, qos, " .
        "profile_type, profile_group, qos_value, tag, preorpost, " .
        "devicegroup, blocked, rule_type, invalid, modified, " .
        "icmp_unreachable) " .
        "VALUES " .
        "('" . $rule['position'] . "', '" . $rule['name'] . "', '" . $rule['negate_source'] . "', '" . $rule['negate_destination'] . "', '" . addslashes($rule['description']) . "'," .
        " '" . $rule['action'] . "', '" . $rule['schedule'] . "', '" . $rule['disabled'] . "', '" . $rule['log_start'] . "','" . $rule['log_end'] . "'," .
        " '" . $rule['log_forwarding'] . "', '" . $rule['vsys'] . "', '" . $rule['lid'] . "', '" . $rule['source'] . "', '" . $rule['dsri'] . "'," .
        " '" . $rule['target'] . "', '" . $rule['checkit'] . "', '" . $rule['migrate'] . "', '" . $rule['counter'] . "', '" . $rule['qos'] . "'," .
        " '" . $rule['profile_type'] . "', '" . $rule['profile_group'] . "', '" . $rule['qos_value'] . "', '" . $rule['tag'] . "', '" . $rule['preorpost'] . "'," .
        " '" . $rule['devicegroup'] . "', '" . $rule['blocked'] . "', '" . $rule['rule_type'] . "', '" . $rule['invalid'] . "', '" . $rule['modified'] . "'," .
        " '" . $rule['icmp_unreachable'] . "')";
//    echo "$query\n";
    $projectdb->query($query);
    return $projectdb->insert_id;
}

function insertSecRuleComplete(mysqli $projectdb, CompleteSecRuleObject $rule, STRING $table, INT &$security_rule_position)
{
    $pushed = pushSecRules($projectdb, $rule->getSource(), $rule->getDevicegroup(), $rule->getVsys(), $security_rule_position, 1);
    if( $pushed == 1 )
    {
        $security_rule_position++;
    }

    $query = "INSERT INTO $table (" .
        "position, name, negate_source, negate_destination,description, " .
        "action, schedule, disabled, log_start, log_end, " .
        "log_forwarding, vsys, lid, source, dsri, " .
        "target, checkit, migrate, counter, qos, " .
        "profile_type, profile_group, qos_value, tag, preorpost, " .
        "devicegroup, blocked, rule_type, invalid, modified, " .
        "icmp_unreachable) " .
        "VALUES " .
        "('" . $rule->getPosition() . "', '" . $rule->getName() . "', '" . $rule->getNegateSource() . "', '" . $rule->getNegateDestination() . "', '" . addslashes($rule->getDescription()) . "'," .
        " '" . $rule->getAction() . "', '" . $rule->getSchedule() . "', '" . $rule->getDisabled() . "', '" . $rule->getLogStart() . "','" . $rule->getLogEnd() . "'," .
        " '" . $rule->getLogForwarding() . "', '" . $rule->getVsys() . "', '" . $rule->getLid() . "', '" . $rule->getSource() . "', '" . $rule->getDsri() . "'," .
        " '" . $rule->getTarget() . "', '" . $rule->getCheckit() . "', '" . $rule->getMigrate() . "', '" . $rule->getCounter() . "', '" . $rule->getQos() . "'," .
        " '" . $rule->getProfileType() . "', '" . $rule->getProfileGroup() . "', '" . $rule->getQosValue() . "', '', '" . $rule->getPreorpost() . "'," .
        " '" . $rule->getDevicegroup() . "', '" . $rule->getBlocked() . "', '" . $rule->getRuleType() . "', '" . $rule->getInvalid() . "', '0'," .
        " '" . $rule->getIcmpUnreachable() . "')";
//    echo "$query\n";
    $projectdb->query($query);
    $newRuleLid = $projectdb->insert_id;

    insertSecRuleComplete_app($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_categories($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_dst($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_from($projectdb, $rule, $newRuleLid);
//TODO    insertSecRuleComplete_hip($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_profiles($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_src($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_srv($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_tag($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_to($projectdb, $rule, $newRuleLid);
    insertSecRuleComplete_usr($projectdb, $rule, $newRuleLid);

    return $newRuleLid;
}

function insertSecRuleComplete_app(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $apps = array();
    foreach( $rule->getApplications() as $application_member )
    {
        $apps[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$application_member->location','$application_member->name','$ruleLid')";
    }
    if( count($apps) > 0 )
    {
        $unique = array_unique($apps);
        $query = "INSERT INTO security_rules_app (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_categories(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
//  source, name, rule_lid, vsys, devicegroup
    $categories = array();
    foreach( $rule->getCategories() as $categoryMember )
    {
        $categories[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$categoryMember->name','$ruleLid')";
    }

    if( count($categories) > 0 )
    {
        $unique = array_unique($categories);
        $query = "INSERT INTO security_rules_categories (source,vsys,name, rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_dst(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $destinations = array();
    foreach( $rule->getDestinationMembers() as $destination_member )
    {
//        echo "$destination_member->name@$destination_member->location $destination_member->value.$destination_member->id, ";
        $destinations[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$destination_member->location','$destination_member->name','$ruleLid')";
    }
//    echo "\n";
    if( count($destinations) > 0 )
    {
        $unique = array_unique($destinations);
        $query = "INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_from(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $froms = array();
    foreach( $rule->getFrom() as $from_member )
    {
        $froms[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$from_member->name','$ruleLid')";
    }
    if( count($froms) > 0 )
    {
        $unique = array_unique($froms);
        $query = "INSERT INTO security_rules_from (source,vsys,name,rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_hip(mysqli $projectdb, CompleteSecRuleObject $rule, INT $newRuleLid)
{

}

function insertSecRuleComplete_profiles(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $profiles = array();
    foreach( $rule->getProfileParameters() as $profileMember )
    {
//        echo "$destination_member->name@$destination_member->location $destination_member->value.$destination_member->id, ";
        //TODO The field type needs to be filled in!!
        $profiles[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$profileMember->location','$profileMember->name','$profileMember->value','$ruleLid')";
    }

    if( count($profiles) > 0 )
    {
        $unique = array_unique($profiles);
        $query = "INSERT INTO security_rules_profiles (source,vsys,table_name,member_lid, type, rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_src(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $sources = array();
    foreach( $rule->getSourceMembers() as $source_member )
    {
        $sources[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$source_member->location','$source_member->name','$ruleLid')";
    }

    if( count($sources) > 0 )
    {
        $unique = array_unique($sources);
        $query = "INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_srv(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $services = array();
    foreach( $rule->getServices() as $serviceMember )
    {
        $services[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$serviceMember->location','$serviceMember->name','$ruleLid')";
    }

    if( count($services) > 0 )
    {
        $unique = array_unique($services);
        $query = "INSERT INTO security_rules_srv (source,vsys,table_name,member_lid, rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_tag(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $tags = array();
    foreach( $rule->getTags() as $tag_member )
    {
        $tags[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$tag_member->location','$tag_member->name','$ruleLid')";
    }
    if( count($tags) > 0 )
    {
        $unique = array_unique($tags);
        $query = "INSERT INTO security_rules_tag (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_to(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $tos = array();
    foreach( $rule->getTo() as $from_member )
    {
        $tos[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$from_member->name','$ruleLid')";
    }
    if( count($tos) > 0 )
    {
        $unique = array_unique($tos);
        $query = "INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function insertSecRuleComplete_usr(mysqli $projectdb, CompleteSecRuleObject $rule, INT $ruleLid)
{
    $users = array();
    foreach( $rule->getSourceUsers() as $userMember )
    {
        $users[] = "('" . $rule->getSource() . "','" . $rule->getVsys() . "','$userMember->name','$ruleLid')";
    }

    if( count($users) > 0 )
    {
        $unique = array_unique($users);
        $query = "INSERT INTO security_rules_usr (source,vsys,name, rule_lid) VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
    }
}

function compareSecRules(mysqli $projectdb, $source, STRING $devicegroup, STRING $vsys, RuleObject $ruleObjectOriginal, CompleteSecRuleObject $newRule)
{
    $differences = array();

    $query = "SELECT * FROM " . $ruleObjectOriginal->location . " WHERE id='" . $ruleObjectOriginal->id . "';";
//    echo "$query\n";
    $matchingRule = $projectdb->query($query);
    if( $matchingRule->num_rows != 0 )
    {
        $get = (array)$matchingRule->fetch_assoc();
    }
    else
    {
        return DIFFERENT;
    }

    if( $get['modified'] == 1 )
    {
        return DIFFERENT;
    } //Compare modified
    //Compare from

    //Compare to

    //Compare sourceMembers security_rules_src

    //Compare destination

    //Compare source_user

    //Compare application

    //Compare service

    //Compare category

    //Compare position


    if( $get['negate_source'] != $newRule->getNegateSource() )
    {
        return DIFFERENT;
    } //Compare negate_source
    if( $get['negate_destination'] != $newRule->getNegateDestination() )
    {
        return DIFFERENT;
    } //Compare negate_destination
    if( $get['action'] != $newRule->getAction() )
    {
        return DIFFERENT;
    } //Compare action
    if( $get['disabled'] != $newRule->getDisabled() )
    {
        return DIFFERENT;
    } //Compare disabled
    if( $get['log_start'] != $newRule->getLogStart() )
    {
        return DIFFERENT;
    } //Compare log_start
    if( $get['log_end'] != $newRule->getLogEnd() )
    {
        return DIFFERENT;
    } //Compare log_end

    //Compare description
    if( $get['description'] != $newRule->getDescription() )
    {
        $differences[] = "description";
    } //Compare log_end

    //Compare schedule


    //Compare log_forwarding

    //Compare vsys
    //Compare devicegroup
    //Compare invalid


    //Compare dsri

    if( $get['target'] != $newRule->getTarget() )
    {
        return DIFFERENT;
    } //Compare target

    //Compare checkit

    //Compare migrate

    //Compare counter

    if( $get['qos'] != $newRule->getQos() )
    {
        return DIFFERENT;
    }//Compare qos
    if( $get['profile_type'] != $newRule->getProfileType() )
    {
        return DIFFERENT;
    }//Compare profile_type
    if( $get['profile_group'] != $newRule->getProfileGroup() )
    {
        return DIFFERENT;
    }//Compare profile_group
    if( $get['qos_value'] != $newRule->getQosValue() )
    {
        return DIFFERENT;
    }//Compare qos_value

    //Compare tag

    if( $get['preorpost'] != $newRule->getPreorpost() )
    {
        return DIFFERENT;
    } //Compare preorpost
    if( $get['blocked'] != $newRule->getBlocked() )
    {
        return DIFFERENT;
    } //Compare blocked
    if( $get['rule_type'] != $newRule->getRuleType() )
    {
        return DIFFERENT;
    } //Compare rule_type
    if( $get['icmp_unreachable'] != $newRule->getIcmpUnreachable() )
    {
        return DIFFERENT;
    }//Compare icmp_unreachable


    //Compare virus

    //Compare file_blocking

    //Compare spyware

    //Compare vulnerability

    //Compare wildfire_analysis

    return EQUAL;
}

function insertSecRuleAttribute(mysqli $projectdb, STRING $source, STRING $devicegroup, STRING $vsys, $attribute, $attribute_type, $ruleObject_1)
{
    //Reminder: If you update a Rule, set the modified=2 so that the Modified paramter does not get set as 1.
    switch ($attribute_type)
    {
        case "source":
            $query = "INSERT INTO security_rules_src (source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES " .
                " ('$source', '$ruleObject_1->id', '$attribute->name', '$attribute->location', '$vsys', '', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "destination":
            $query = "INSERT INTO security_rules_dst (source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES " .
                " ('$source', '$ruleObject_1->id', '$attribute->name', '$attribute->location', '$vsys', '', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "source-user":
            $query = "INSERT INTO security_rules_usr (source, vsys, name, rule_lid, devicegroup) VALUES " .
                " ('$source', '$vsys', '$attribute->name', '$ruleObject_1->id', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "service":
            $query = "INSERT INTO security_rules_srv (source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES " .
                " ('$source', '$ruleObject_1->id', '$attribute->name', '$attribute->location', '$vsys', '', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "action":
            $query = "UPDATE security_rules SET action='$attribute->name', modified=2 " .
                "WHERE source='$source' AND id='$ruleObject_1->id' AND vsys='$vsys' AND devicegroup='$devicegroup';";
//            echo "ACTION $query\n";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "tag":
            $query = "INSERT INTO security_rules_tag (source, member_lid, table_name, rule_lid, vsys, devicegroup) VALUES " .
                " ('$source', '$attribute->name', '$attribute->location', '$ruleObject_1->id', '$vsys', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "to":
            $query = "INSERT INTO security_rules_to (source, vsys, name, rule_lid, devicegroup) VALUES " .
                " ('$source', '$vsys', '$attribute->name', '$ruleObject_1->id', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "from":
            $query = "INSERT INTO security_rules_from (source, vsys, name, rule_lid, devicegroup) VALUES " .
                " ('$source', '$vsys', '$attribute->name', '$ruleObject_1->id', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "category":
            $query = "INSERT INTO security_rules_categories (source, vsys, name, rule_lid, devicegroup) VALUES " .
                " ('$source', '$vsys', '$attribute->name', '$ruleObject_1->id', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "application":
            $query = "INSERT INTO security_rules_app (source, vsys, member_lid, table_name, rule_lid, devicegroup) VALUES " .
                " ('$source', '$vsys', '$attribute->name', '$attribute->location' , '$ruleObject_1->id', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "profile_type":
            $query = "UPDATE security_rules SET profile_type='$attribute',modified=2 WHERE id = '$ruleObject_1->id';";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        case "url-filtering":
        case "virus":
        case "file-blocking":
        case "spyware":
        case "vulnerability":
        case "wildfire-analysis":
            $query = "INSERT INTO security_rules_profiles (source, vsys, member_lid, table_name, type, rule_lid, devicegroup) VALUES " .
                " ('$source', '$vsys', '$attribute->name', '$attribute->location' , '$attribute_type', '$ruleObject_1->id', '$devicegroup')";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        default:
            echo "$attribute_type option not implemented yet in insertSecRuleAttribute()\n";
            return -1;
            break;
    }
}

function updateSecRuleAttribute(mysqli $projectdb, STRING $source, STRING $devicegroup, STRING $vsys, $attribute, $attribute_type, $ruleObject_1)
{
    switch ($attribute_type)
    {
        case "action":
            return insertSecRuleAttribute($projectdb, $source, $devicegroup, $vsys, $attribute, $attribute_type, $ruleObject_1);
            break;

        default:
            echo "echo \"$attribute_type option not implemented yet in updateRuleAttribute()\n";
            return -1;
            break;
    }

}

function deleteSecRuleAttribute(mysqli $projectdb, STRING $source, STRING $devicegroup, STRING $vsys, $member, $attribute_type, $ruleObject_1)
{
    switch ($attribute_type)
    {
        case "destination":
//            $query = "INSERT INTO security_rules_dst (source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) VALUES ".
//                " ('$source', '$ruleObject_1->id', '$member->name', '$member->location', '$vsys', '', '$devicegroup')";
////            echo "$query\n";
//            $projectdb->query($query);
//            return $projectdb->insert_id;
            echo "$attribute_type option not implemented yet in deleteRuleAttribute()\n";
            return -1;
            break;

        case "service":
            $query = "DELETE FROM security_rules_srv WHERE source='$source' AND rule_lid='$ruleObject_1->id' AND member_lid='$member->name' AND table_name='$member->location' AND vsys='$vsys' AND devicegroup='$devicegroup';";
            $projectdb->query($query);
            return $projectdb->insert_id;
            break;

        default:
            echo "$attribute_type option not implemented yet in deleteRuleAttribute()\n";
            return -1;
            break;
    }

}

/***
 * METHODS TO PRE-PROCESS SECURITY POLICIES
 */


/***
 * METHODS TO PROCESS SECURITY POLICIES
 */


/***
 * METHODS TO POST-PROCESS SECURITY POLICIES
 * fix_Zones_Policies($source, $vsys, $vr);
 */

/** Looks for policy rules that match a DNAT rule. Those rules need to get out via the correct "Zone To"
 *
 * @param type $source
 * @param type $vsys
 * @param type $vr
 * @global type $projectdb
 */
function fix_Zones_Policies(STRING $projectName, STRING $source, STRING $vsys, $vr, &$ipMapping = null)
{
    global $projectdb;

    $explodedMembersMap = array(); //Cache of Exploded Address Objects
    $zonesMap = array(); //Cache of Zones for each address Object
    $nat_rules = array();
    $updatableNatFrom = array();
    $nat_rules_from = array();
    $op_zone_to = array();

    $projectdb = selectDatabase($projectName);

//    $my = fopen("DNAT.txt","a");
//    printMemory($my, "Start");
    if( is_null($ipMapping) || count($ipMapping) == 0 )
    {
        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    }

    $natted_rules = null;   //IDs of the modified rules
    $security_rules = array();
    $ids = array();

    /***
     * COLLECT ALL THE POLICY RULES AS OBJECTS
     */
//    printMemory($my, "Initialized");
    //Initialize a 2Dim associative array for the security rules with the size of the rules we have.
    $number_of_rules = $projectdb->query("SELECT id FROM security_rules WHERE source='$source' AND vsys='$vsys';");
    if( $number_of_rules->num_rows > 0 )
    {
        while( $getINData = $number_of_rules->fetch_assoc() )
        {
            $id = $getINData['id'];
            $ids[] = $getINData['id'];
            $security_rules[$id]['src'] = array();    //List of Members that are sources
            $security_rules[$id]['dst'] = array();    //List of Members that are destinations
            $security_rules[$id]['modified'] = FALSE; //Flag to mark if this rule has been corrected or not
        }
    }
//    printMemory($my, "   Policy Structures created");

    if( count($ids) > 0 )
    {
        //Get all the Security_Rules Sources and Destinations and group them by Rule_lid
        $getRulesSrc = $projectdb->query("SELECT member_lid, table_name, rule_lid FROM security_rules_src WHERE rule_lid IN (" . implode(',', $ids) . ");");
        if( $getRulesSrc->num_rows > 0 )
        {
            while( $getINData = $getRulesSrc->fetch_assoc() )
            {
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];
                $rule_lid = $getINData['rule_lid'];
                $member = new MemberObject($member_lid, $table_name);
                $security_rules[$rule_lid]['src'][] = $member;
            }
        }
//    printMemory($my, "   Sources loaded");
        $getRulesDst = $projectdb->query("SELECT member_lid, table_name, rule_lid FROM security_rules_dst WHERE rule_lid IN (" . implode(',', $ids) . ");");
        if( $getRulesDst->num_rows > 0 )
        {
            while( $getINData = $getRulesDst->fetch_assoc() )
            {
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];
                $rule_lid = $getINData['rule_lid'];
                $member = new MemberObject($member_lid, $table_name);
                $security_rules[$rule_lid]['dst'][] = $member;
            }
        }
//    printMemory($my, "   Destinations loaded");

        //Expand the Members that we have founds for each rule
        foreach( $security_rules as $key => &$security_rule )
        {
//        printMemory($my, "   Exploding Sources and Destinations for rule $key\n");
            $members_src = $security_rule['src'];
//        if(is_null($members_src)){
//            $members_src = array();
//        }
            $members_dst = $security_rule['dst'];
//        if(is_null($members_dst)){
//            $members_dst = array();
//        }
            $code = sha1(json_encode($members_src));
            if( !isset($explodedMembersMap[$code]) )
            {
                $explodedMembersMap[$code] = explodeGroups2Members($members_src, $projectdb, $source, $vsys);
                $nat_rule['src'] = $explodedMembersMap[$code];
            }
            else
            {
                $nat_rule['src'] = $explodedMembersMap[$code];
            }

            $code = sha1(json_encode($members_dst));
            if( !isset($explodedMembersMap[$code]) )
            {
                $explodedMembersMap[$code] = explodeGroups2Members($members_dst, $projectdb, $source, $vsys);
                $nat_rule['dst'] = $explodedMembersMap[$code];
            }
            else
            {
                $nat_rule['dst'] = $explodedMembersMap[$code];
            }
//        $security_rule['src'] = explodeGroups2Members($members_src,$projectdb, $source, $vsys);
//        $security_rule['dst'] = explodeGroups2Members($members_dst,$projectdb, $source, $vsys);
        }
//    printMemory($my, "   Exploded Sources and Destinations");

        //Some rules did not get any specific source or destination. Those were ANY. Let's fill it with the ANY member
        $member = new MemberObject('', '', '0.0.0.0', '0');
        foreach( $security_rules as &$security_rule )
        {
            if( count($security_rule['src']) == 0 )
            {
                $security_rule['src'][] = $member;
            }
            if( count($security_rule['dst']) == 0 )
            {
                $security_rule['dst'][] = $member;
            }
        }
//    printMemory($my, "   Substituted ANY objects");
    }


//    printMemory($my, "Matching");
    //Select the NAT rules that are Not disabled
//    fwrite($my, "SELECT id, tp_dat_address_lid, tp_dat_address_table, devicegroup, is_dat, op_zone_to FROM nat_rules WHERE disabled='0' AND source='$source' AND vsys='$vsys';");
    $getDAT = $projectdb->query("SELECT id, tp_dat_address_lid, tp_dat_address_table, devicegroup, is_dat, op_zone_to FROM nat_rules WHERE disabled='0' AND source='$source' AND vsys='$vsys';");

    while( $getSRCData = $getDAT->fetch_assoc() )
    {
        //For each NAT rule that makes DAT, we will check the Security Rules that are affected, and update its TO_ZONE
        $member_lid_dat = $getSRCData['tp_dat_address_lid'];
        $table_name_dat = $getSRCData['tp_dat_address_table'];
        $nat_rule_lid = $getSRCData['id'];
        $devicegroup = $getSRCData['devicegroup'];
        $is_dat = $getSRCData['is_dat'];
        $negate_source = 0;  //In Stonesoft, we do not negate rules due to the JUMP approach they use. Insead, in case a Negate is applied in Stonesoft, we calculate all the opposite addresses
//        printMemory($my, "   Loading NAT-$nat_rule_lid");

        //Initialize Sources and Destinations for mapping
        $nat_src_members = array();
        $exploded_nat_src_Members = array();

        $nat_dst_members = array();
        $exploded_nat_dst_Members = array();


        //Get the source before applying NAT
        $getSrc = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid='$nat_rule_lid';");
        if( $getSrc->num_rows > 0 )
        {
            while( $getINData = $getSrc->fetch_assoc() )
            {
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];

                $member = new MemberObject($member_lid, $table_name);
                $nat_src_members[] = $member;
            }
            $code = sha1(json_encode($nat_src_members));
            if( !isset($explodedMembersMap[$code]) )
            {
                $explodedMembersMap[$code] = explodeGroups2Members($nat_src_members, $projectdb, $source, $vsys);
                $exploded_nat_src_Members = $explodedMembersMap[$code];
            }
            else
            {
                $exploded_nat_src_Members = $explodedMembersMap[$code];
            }
        }
        else
        {
            $exploded_nat_src_Members[] = new MemberObject('', '', '0.0.0.0', '0');
        }
        //$exploded_nat_src_Members = get_all_members(nat_rules_src, $source, $vsys, $nat_rule_lid);

        //Get the destination before applying NAT
        $getDst = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid='$nat_rule_lid';");
        if( $getDst->num_rows > 0 )
        {
            while( $getINData = $getDst->fetch_assoc() )
            {
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];

                $member = new MemberObject($member_lid, $table_name);
                $nat_dst_members[] = $member;
            }
            $code = sha1(json_encode($nat_dst_members));
            if( !isset($explodedMembersMap[$code]) )
            {
                $explodedMembersMap[$code] = explodeGroups2Members($nat_dst_members, $projectdb, $source, $vsys);
                $exploded_nat_dst_Members = $explodedMembersMap[$code];
            }
            else
            {
                $exploded_nat_dst_Members = $explodedMembersMap[$code];
            }
//            $exploded_nat_dst_Members = explodeGroups2Members($nat_dst_members,$projectdb, $source, $vsys);
        }
        else
        {
            $exploded_nat_dst_Members[] = new MemberObject('', '', '0.0.0.0', '0');
        }
        //$exploded_nat_dst_Members = get_all_members(nat_rules_dst, $source, $vsys, $nat_rule_lid);


        /* Now we have For this NAT rule:
         *  1- the NAT origins (in $exploded_nat_src_Members)
         *  2- the NAT destinations (in $exploded_nat_dst_Members)
         *  3- all the sources for all the security rules (in $security_rule[ruleID]['src'])
         *  4- all the destina for all the security rules (in $security_rule[ruleID]['dst'])
         *
         * Ready for doing the matching
         */

//        printMemory($my, "   Loaded NAT-$nat_rule_lid");

        //Find the Security rules that are affected by this NAT
        //DNAT Logic applies here
        if( $is_dat == 1 )
        {
//            printMemory($my, "       This rules is DAT");
            $natted_rules = array();
            foreach( $security_rules as $sec_rule_lid => $security_rule )
            {
                $isDSTCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members);
                if( !$isDSTCovered )
                {
                    //No need to check if the Source matches
                    break;
                }
                $isSRCCovered = isAinB($security_rule['src'], $exploded_nat_src_Members);

                if( $isSRCCovered )
                {
//                    printMemory($my, "       Sec RUle $sec_rule_lid Matches");
                    //Calculate destination Zone after NAT
                    $correct_zones_to = getAutoZone($ipMapping['ipv4'], $member_lid_dat, $table_name_dat, $negate_source);  //This will provide all the zones that this NAT has as destination AFTER NAT

                    $natted_rules[] = $sec_rule_lid;  //Add this rule in the list of modified rules, so we do not need to process it again.
                    $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$sec_rule_lid';");
                    $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                        . "VALUES ('$sec_rule_lid', '" . implode(',', $correct_zones_to) . "', '$source', '$vsys', '$devicegroup');");
                    add_log2('warning', 'Auto Zone Assign', 'Rule [' . $sec_rule_lid . ']. Forcing TO Zone as [' . implode(',', $correct_zones_to) . '] based on DAT defined in NAT rule [' . $nat_rule_lid . ']', $source, 'No Action Required', 'rules', $sec_rule_lid, 'security_rules');
                }
            }
//            printMemory($my, "        Matches done");
            if( count($natted_rules) > 0 )
            {
                $unique = array_unique($natted_rules);
                $out = implode(",", $unique);
                $query = "UPDATE security_rules SET blocked=1 WHERE id in (" . $out . ");";
                $projectdb->query($query);
//                fwrite($my, "$nat_rule_lid matches $out\n");
                //Remove those Security Rules from the Associative array, as they have already found a NAT match
                removeKeysFromArray($security_rules, $natted_rules);
            }
        }
        //NAT Logic applies here
        else
        {
//            printMemory($my, "       This is a Static Nat Rule");
            $natted_rules = array();
            //Find the Security rules that are affected by this NAT
            foreach( $security_rules as $sec_rule_lid => $security_rule )
            {

                $isDSTCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members);
                if( !$isDSTCovered )
                {
                    break;
                }
                $isSRCCovered = isAinB($security_rule['src'], $exploded_nat_src_Members);

                if( $isSRCCovered )
                {
                    //TODO: Use this part to update source Zones, for example
                    $natted_rules[] = $sec_rule_lid;
                }
            }
//            printMemory($my, "        Matches done");
            if( count($natted_rules) > 0 )
            {
//                printMemory($my, "       Sec Rule $sec_rule_lid Matches");
                $unique = array_unique($natted_rules);
//                $out = implode(",", $unique);
//                fwrite($my, "$nat_rule_lid matches $out\n");
                //Remove those Security Rules from the Associative array, as they have already found a NAT match
                removeKeysFromArray($security_rules, $unique);
            }

        }

        //Free Memory
        $exploded_nat_src_Members = null;
        $exploded_nat_dst_Members = null;

        //Checking if this NAT actually affects any Security Rule or
        //  (a) it is shadowed by prior NATS
        //  (b) it is too restrictive
        if( count($natted_rules) == 0 )
        {
//            fwrite($my, "   Reporting NoMatch\n");
            add_log2('info', 'NAT Analysis', 'NAT Rule [' . $nat_rule_lid . '] does not affect any of the existing security rules. Or affects only ranges inside a security rule.', $source, 'No Action Required. Suggestion to review and/or remove. If partial matching, you may consider split the security rule.', 'rules', $nat_rule_lid, 'nat_rules');
        }
    }

//    print_r($explodedMembersMap);
//    die;
//    fwrite($my, "DONE");
//    fclose($my);
}


function fix_Nat_Policy($jobid, STRING $projectName, STRING $source, STRING $vsys, $vr,
                        array &$ipMapping, array $ruleIds,
                        bool $doFrom = TRUE, bool $doTo = TRUE)
{
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $explodedMembersMap = array();
    $zonesMap = array(); //Cache of Zones for each address Object
    $nat_rules = array();
    $updatableNatFrom = array();
    $nat_rules_from = array();
    $op_zone_to = array();
    $ids = array();

    if( count($ipMapping) == 0 )
    {
        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    }

    if( count($ruleIds) > 0 )
    {
        $conditionIds = " AND id IN (" . implode(',', $ruleIds) . ")";
    }
    else
    {
        $conditionIds = '';
    }


    $query = "SELECT id, devicegroup FROM nat_rules WHERE source='$source' $conditionIds ORDER BY position;";
    $number_of_rules = $projectdb->query($query);
    if( $number_of_rules->num_rows > 0 )
    {
        while( $getINData = $number_of_rules->fetch_assoc() )
        {
            $id = $getINData['id'];
            $ids[] = $getINData['id'];
            $nat_rules[$id]['src'] = array();    //List of Members that are sources
            $nat_rules[$id]['dst'] = array();    //List of Members that are destinations
            $nat_rules[$id]['modified'] = FALSE; //Flag to mark if this rule has been corrected or not
            $nat_rules[$id]['devicegroup'] = $getINData['devicegroup'];
        }
    }

    //Get all the Security_Rules Sources and Destinations and group them by Rule_lid
    $query = "SELECT member_lid, table_name, rule_lid FROM nat_rules_src WHERE rule_lid IN (" . implode(',', $ids) . ");";
    $getRulesSrc = $projectdb->query($query);
    if( $getRulesSrc->num_rows > 0 )
    {
        while( $getINData = $getRulesSrc->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $nat_rules[$rule_lid]['src'][] = $member;
        }
    }

    $getRulesDst = $projectdb->query("SELECT member_lid, table_name, rule_lid FROM nat_rules_dst WHERE rule_lid IN (" . implode(',', $ids) . ");");
    if( $getRulesDst->num_rows > 0 )
    {
        while( $getINData = $getRulesDst->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $nat_rules[$rule_lid]['dst'][] = $member;
        }
    }

    //Expand the Members that we have founds for each rule
    foreach( $nat_rules as $key => &$nat_rule )
    {
        $members_src = $nat_rule['src'];
        $members_dst = $nat_rule['dst'];
        $code = sha1(json_encode($members_src));
        if( !isset($explodedMembersMap[$code]) )
        {
            $explodedMembersMap[$code] = explodeGroups2Members($members_src, $projectdb, $source, $vsys);
            $nat_rule['src'] = $explodedMembersMap[$code];
        }
        else
        {
            $nat_rule['src'] = $explodedMembersMap[$code];
        }

        $code = sha1(json_encode($members_dst));
        if( !isset($explodedMembersMap[$code]) )
        {
            $explodedMembersMap[$code] = explodeGroups2Members($members_dst, $projectdb, $source, $vsys);
            $nat_rule['dst'] = $explodedMembersMap[$code];
        }
        else
        {
            $nat_rule['dst'] = $explodedMembersMap[$code];
        }
    }


    //Some rules did not get any specific source or destination. Those were ANY. Let's fill it with the ANY member
    $anyMember = new MemberObject('any', '', '0.0.0.0', '0');
    foreach( $nat_rules as &$nat_rule )
    {
        if( count($nat_rule['src']) == 0 )
        {
            $nat_rule['src'][] = $anyMember;
        }
        if( count($nat_rule['dst']) == 0 )
        {
            $nat_rule['dst'][] = $anyMember;
        }
    }


    //Calculate the ZONES TO to the all the security rules in the selection
    if( $doFrom )
    {
        $count = 0;
        foreach( $nat_rules as $rule_lid => $nat_rule )
        {
            $negate_source = 0;
            $zones = array();

            foreach( $nat_rule['src'] as $nat_source )
            {
                $member_lid = $nat_source->name;
                $table_name = $nat_source->location;
                if( $member_lid == 'any' )
                {
                    $zones = array();
                    break;
                }
                else
                {
                    if( !isset($zonesMap[$table_name . "." . $member_lid . "." . $negate_source]) )
                    {
                        $foundZones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                        $zones = array_merge($zones, $foundZones);
                        $zonesMap[$table_name . "." . $member_lid . "." . $negate_source] = $foundZones;
                    }
                    else
                    {
                        $zones = array_merge($zones, $zonesMap[$table_name . "." . $member_lid . "." . $negate_source]);
                    }
                }
            }


            if( count($zones) != 0 )
            {
                $updatableNatFrom[] = $rule_lid;
                foreach( $zones as $zone )
                {
                    $nat_rules_from[] = "('$rule_lid', '$zone', '$source', '$vsys')";
                }
            }
            $count++;
        }
    }

    $nat_rules_from = array_unique($nat_rules_from);
    if( count($updatableNatFrom) > 0 )
    {
        $projectdb->query("DELETE FROM nat_rules_from WHERE rule_lid in (" . implode(',', $updatableNatFrom) . ")");
    }
    if( count($nat_rules_from) > 0 )
    {
        $query = "INSERT INTO nat_rules_from (rule_lid, name, source, vsys) VALUES " . implode(',', $nat_rules_from);
//        fwrite($my, $query."\n");
        $projectdb->query($query);
    }


    if( $doTo )
    {
        foreach( $nat_rules as $rule_lid => $nat_rule )
        {
            $negate_source = 0;
            $zones = array();

            foreach( $nat_rule['dst'] as $nat_dest )
            {
                $member_lid = $nat_dest->name;
                $table_name = $nat_dest->location;
                if( $member_lid == 'any' )
                {
                    $zones = array();
                    //If this is a Static Source NAT, then we can know that the destination Zone is the zone of the translated Source
                    $query = "select member_lid, table_name from nat_rules_translated_address where rule_lid=$rule_lid";
                    $result = $projectdb->query($query);
                    if( $result->num_rows > 0 )
                    {
                        //If there is more than 1, we have an issue here, but we get the Zone of the first translated Addreess anyway
                        add_log2('info',
                            'NAT AutoZone',
                            'NAT Rule [' . $rule_lid . '] has an ANY as a destination. Zone TO has been calculated based on Translated Source.',
                            $source,
                            'No Action Required. Suggestion to review and/or correct the TO Zone.',
                            'rules',
                            $rule_lid,
                            'nat_rules');
                        $data = $result->fetch_assoc();
                        $source_member_lid = $data['member_lid'];
                        $source_table_name = $data['table_name'];
                        $thisZones = getAutoZone($ipMapping['ipv4'], $source_member_lid, $source_table_name, $negate_source);
                        $zones = $thisZones;
                    }

                    break;
                }
                else
                {
                    if( !isset($zonesMap[$table_name . "." . $member_lid . "." . $negate_source]) )
                    {
                        $thisZones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                        $zones = array_merge($zones, $thisZones);
                        $zonesMap[$table_name . "." . $member_lid . "." . $negate_source] = $zones;
                    }
                    else
                    {
                        $zones = array_merge($zones, $zonesMap[$table_name . "." . $member_lid . "." . $negate_source]);
                    }
                }
            }
            $zones = array_unique($zones);
            if( count($zones) != 0 )
            {

                if( count($zones) == 1 )
                {
                    $query = "UPDATE nat_rules SET op_zone_to = '" . implode(',', $zones) . "' WHERE id=$rule_lid";
                    $projectdb->query($query);
                }
                else
                {
                    $zone1 = array_pop($zones);
                    foreach( $zones as $zone )
                    {
                        $newNatLid = clone_nat_rule("", "", $vsys, $source, $rule_lid, "Cl-Rule $rule_lid $zone", $projectName);
                        //echo "CLONE NAT RULE: " .$newNatLid. "\n";
                        add_log2('info',
                            'NAT AutoZone',
                            'NAT Rule [' . $rule_lid . '] had (originally) more than one Zone To (maybe due to incorrect Destination addresses). It has been split into 2 or more Nat Rules. This rule [' . $newNatLid . '] is a resulting one.',
                            $source,
                            'Suggestion to review and/or correct the TO Zone and or remove this NAT rule if not needed.',
                            'rules',
                            $newNatLid,
                            'nat_rules');
                        $query = "UPDATE nat_rules SET op_zone_to = '$zone' WHERE id=$newNatLid";
                        $projectdb->query($query);
                    }
                    $query = "UPDATE nat_rules SET op_zone_to = '$zone1' WHERE id=$rule_lid";
                    $projectdb->query($query);
                }
            }
        }
    }

}

/***
 *
 * Recommendation, in case multiple calls to this method will be performed, declare $ipMapping before by getIPtoZoneRouteMapping($vsys, $source, $vr) and avoid innecessary repetitions
 *
 * @param STRING $projectName
 * @param STRING $source
 * @param STRING $vsys
 * @param $vr
 * @param array $ipMapping
 * @param STRING $ruleId
 * @param bool $applyNat
 * @param array|null $tags
 * @param bool $doFrom
 * @param bool $doTo
 */
// No se utiliza
function fix_Zones_Policy($jobid, STRING $projectName, STRING $source, STRING $vsys, $vr,
//                          ARRAY &$ipMapping, ARRAY $ruleIds, ARRAY $tags = null,
                          array $ruleIds, array $tags = null,
                          bool $applyNat = TRUE, bool $doFrom = TRUE, bool $doTo = TRUE)
{

    //Set max execution times
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    global $projectdb;
    $projectdb = selectDatabase($projectName);


//    if(count($ipMapping)==0) {
    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
//    }

    //Check we have routing information to be able to calculate Zones
    if( count($ipMapping['ipv4']) == 0 )
    {
        update_progress($projectName, '-1.00', 'Routing information is missing. Not possible to calculate policy Zones', $jobid);
        return;
    }

    $natted_rules = null;   //IDs of the modified rules
    $security_rules = array();
    $ids = array();

    if( count($ruleIds) > 0 )
    {
        $conditionIds = " AND id IN (" . implode(',', $ruleIds) . ")";
    }
    else
    {
        $conditionIds = '';
    }

    if( count($tags) > 0 )
    {
        $conditionTags = " AND tag LIKE %$tags%";
    }
    else
    {
        $conditionTags = '';
    }

    if( $vsys == 'all' )
    {
        $conditionVsys = '';
    }
    else
    {
        $conditionVsys = " AND vsys='$vsys' ";
    }

    /***
     * COLLECT ALL THE POLICY RULES AS OBJECTS
     */

    //Initialize a 2Dim associative array for the security rules with the size of the rules we have.
    $query = "SELECT id, devicegroup, negate_source, negate_destination FROM security_rules WHERE source='$source' $conditionVsys $conditionIds $conditionTags ORDER BY position;";
    $rules = $projectdb->query($query);
    $number_of_rules = $rules->num_rows;
    if( $number_of_rules > 0 )
    {
        while( $getINData = $rules->fetch_assoc() )
        {
            $id = $getINData['id'];
            $ids[] = $getINData['id'];
            $security_rules[$id]['src'] = array();    //List of Members that are sources
            $security_rules[$id]['Nsrc'] = $getINData['negate_source'];
            $security_rules[$id]['dst'] = array();    //List of Members that are destinations
            $security_rules[$id]['Ndst'] = $getINData['negate_destination'];
            $security_rules[$id]['srv'] = array();    //List of Members that are services
            $security_rules[$id]['modified'] = FALSE; //Flag to mark if this rule has been corrected or not
            $security_rules[$id]['devicegroup'] = $getINData['devicegroup'];;
        }
    }

    //Get all the Security_Rules Sources and Destinations and group them by Rule_lid
    $query = "SELECT member_lid, table_name, rule_lid FROM security_rules_src WHERE rule_lid IN (" . implode(',', $ids) . ");";
    $getRulesSrc = $projectdb->query($query);
    if( $getRulesSrc->num_rows > 0 )
    {
        while( $getINData = $getRulesSrc->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $security_rules[$rule_lid]['src'][] = $member;
        }
    }

    $getRulesDst = $projectdb->query("SELECT member_lid, table_name, rule_lid FROM security_rules_dst WHERE rule_lid IN (" . implode(',', $ids) . ");");
    if( $getRulesDst->num_rows > 0 )
    {
        while( $getINData = $getRulesDst->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $security_rules[$rule_lid]['dst'][] = $member;
        }
    }

    $getRulesDst = $projectdb->query("SELECT member_lid, table_name, rule_lid FROM security_rules_srv WHERE rule_lid IN (" . implode(',', $ids) . ");");
    if( $getRulesDst->num_rows > 0 )
    {
        while( $getINData = $getRulesDst->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $security_rules[$rule_lid]['srv'][] = $member;
        }
    }
//    print_r($security_rules);

    update_progress($projectName, '0.05', 'Security Rules Loaded.', $jobid);

    //Expand the Members that we have founds for each rule
    foreach( $security_rules as $key => &$security_rule )
    {
        $members_src = $security_rule['src'];
        $members_dst = $security_rule['dst'];
        $members_srv = $security_rule['srv'];
        $security_rule['src'] = explodeGroups2Members($members_src, $projectdb, $source, $vsys);
        $security_rule['dst'] = explodeGroups2Members($members_dst, $projectdb, $source, $vsys);
        $security_rule['srv'] = explodeGroups2Services($members_srv, $projectdb, $source, $vsys);
    }

//    print_r($security_rules);

    //Some rules did not get any specific source or destination. Those were ANY. Let's fill it with the ANY member
    $anyMember = new MemberObject('', '', '0.0.0.0', '0');
    $anyMemberSrv = new MemberObject('any', '', '0', '');
    foreach( $security_rules as &$security_rule )
    {
        if( count($security_rule['src']) == 0 )
        {
            $security_rule['src'][] = $anyMember;
        }
        if( count($security_rule['dst']) == 0 )
        {
            $security_rule['dst'][] = $anyMember;
        }
        if( count($security_rule['srv']) == 0 )
        {
            $security_rule['srv'][] = $anyMemberSrv;
        }
    }

    update_progress($projectName, '0.10', 'Security Rules Expanded.', $jobid);

//    print_r($security_rules);

    //Calculate the ZONES TO to the all the security rules in the selection

    if( $doFrom )
    {
        foreach( $security_rules as $rule_lid => $sec_rule )
        {
            $negate_source = 0;
            $zones = array();

            foreach( $sec_rule['src'] as $sec_source )
            {
                $member_lid = $sec_source->name;
                $table_name = $sec_source->location;
                if( $member_lid == 'any' )
                {
                    $zones = array();
                    break;
                }
                else
                {
                    $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                }
            }

            $projectdb->query("DELETE FROM security_rules_from WHERE rule_lid='$rule_lid';");
            $values = array();
            foreach( $zones as $zone )
            {
                $values[] = "('$rule_lid', '$zone')";
            }
            $listValues = implode(',', $values);
            $query = "INSERT INTO security_rules_from (rule_lid, name) VALUES $listValues;";
            $projectdb->query($query);
        }
    }

    update_progress($projectName, '0.15', 'Zone TO calculated.', $jobid);

    if( $doTo )
    {
        if( $applyNat )
        {
            //Select the NAT rules that are Not disabled

            $query = "SELECT id, tp_dat_address_lid, tp_dat_address_table, devicegroup, is_dat, op_zone_to, position 
                                     FROM nat_rules WHERE disabled='0' AND source='$source' $conditionVsys ORDER BY position;";
            $getDAT = $projectdb->query($query);
            $number_of_nats = $getDAT->num_rows;
            $processed_nat = 1;
            while( $getSRCData = $getDAT->fetch_assoc() )
            {
                $percentage = 0.2 + round(0.8 * $processed_nat / $number_of_nats, 2);
                update_progress($projectName, $percentage, "Checking NAT Rule ($processed_nat of $number_of_nats).", $jobid);

//                $natted_rules = array();

                //For each NAT rule that makes DAT, we will check the Security Rules that are affected, and update its TO_ZONE
                $member_lid_dat = $getSRCData['tp_dat_address_lid'];
                $table_name_dat = $getSRCData['tp_dat_address_table'];
                $nat_rule_lid = $getSRCData['id'];
                $devicegroup = $getSRCData['devicegroup'];
                $is_dat = $getSRCData['is_dat'];
                $negate_source = 0;  //In Stonesoft, we do not negate rules due to the JUMP approach they use. Insead, in case a Negate is applied in Stonesoft, we calculate all the opposite addresses

                //Initialize Sources and Destinations for mapping
                $nat_src_members = array();
                $exploded_nat_src_Members = array();

                $nat_dst_members = array();
                $exploded_nat_dst_Members = array();

                $nat_srv_members = array();
                $exploded_nat_srv_Members = array();


                //Get the source before applying NAT
                $getSrc = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid='$nat_rule_lid';");
                if( $getSrc->num_rows > 0 )
                {
                    while( $getINData = $getSrc->fetch_assoc() )
                    {
                        $member_lid = $getINData['member_lid'];
                        $table_name = $getINData['table_name'];

                        $member = new MemberObject($member_lid, $table_name);
                        $nat_src_members[] = $member;
                    }
                    $exploded_nat_src_Members = explodeGroups2Members($nat_src_members, $projectdb, $source, $vsys);
                }
                else
                {
                    $exploded_nat_src_Members[] = new MemberObject('', '', '0.0.0.0', '0');
                }
                //$exploded_nat_src_Members = get_all_members(nat_rules_src, $source, $vsys, $nat_rule_lid);

                //Get the destination before applying NAT
                $getDst = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid='$nat_rule_lid';");
                if( $getDst->num_rows > 0 )
                {
                    while( $getINData = $getDst->fetch_assoc() )
                    {
                        $member_lid = $getINData['member_lid'];
                        $table_name = $getINData['table_name'];

                        $member = new MemberObject($member_lid, $table_name);
                        $nat_dst_members[] = $member;
                    }
                    $exploded_nat_dst_Members = explodeGroups2Members($nat_dst_members, $projectdb, $source, $vsys);
                }
                else
                {
                    $exploded_nat_dst_Members[] = new MemberObject('', '', '0.0.0.0', '0');
                }
                //$exploded_nat_dst_Members = get_all_members(nat_rules_dst, $source, $vsys, $nat_rule_lid);

                //Get the services defined in the NAT
                $getDst = $projectdb->query("SELECT op_service_lid, op_service_table FROM nat_rules WHERE id='$nat_rule_lid';");
                if( $getDst->num_rows > 0 )
                {
                    while( $getINData = $getDst->fetch_assoc() )
                    {
                        $member_lid = $getINData['op_service_lid'];
                        $table_name = $getINData['op_service_table'];
                        if( $member_lid > 0 && $table_name != '' )
                        {
                            $member = new MemberObject($member_lid, $table_name);
                        }
                        else
                        {
                            $member = new MemberObject('any', '', '0', '');
                        }
                        $nat_srv_members[] = $member;
                    }
                    $exploded_nat_srv_Members = explodeGroups2Services($nat_srv_members, $projectdb, $source, $vsys);
                }
                else
                {
                    $exploded_nat_srv_Members[] = new MemberObject('any', '', '0', '');
                }

                /* Now we have For this NAT rule:
                 *  1- the NAT origins (in $exploded_nat_src_Members)
                 *  2- the NAT destinations (in $exploded_nat_dst_Members)
                 *  3- the NAT services (in $exploded_nat_srv_Members)
                 *  4- all the sources for all the security rules (in $security_rule[ruleID]['src'])
                 *  5- all the destina for all the security rules (in $security_rule[ruleID]['dst'])
                 *  6- all the service for all the security rules (in $security_rule[ruleID]['srv'])
                 *
                 * Ready for doing the matching
                 */

                update_progress($projectName, $percentage, "Checking NAT Rule ($processed_nat of $number_of_nats). Rule Expanded", $jobid);

                //Find the Security rules that are affected by this NAT
                //DNAT Logic applies here
                if( $is_dat == 1 )
                {
                    $natted_rules = array();

                    $unprocesses_sec_rules = count($security_rules);
                    $xx = 1;
                    foreach( $security_rules as $sec_rule_lid => $sec_rule )
                    {
                        $percentage = 0.2 + round(0.8 * $processed_nat / $number_of_nats, 2);
                        update_progress($projectName, $percentage, "Checking NAT Rule ($processed_nat of $number_of_nats). Matching Security Rules ($xx of $unprocesses_sec_rules)", $jobid);
                        $xx++;
//                    echo "Checking (Sec:$sec_rule_lid, Nat:$nat_rule_lid):\n";
//                    print_r($sec_rule);
                        $isDSTCovered = isAinB($sec_rule['dst'], $exploded_nat_dst_Members);
                        if( !$isDSTCovered )
                        {
                            //No need to further check if the NAT matches
                        }
//                    echo "Destinations match (Sec:$sec_rule_lid, Nat:$nat_rule_lid): $isDSTCovered\n";

                        $isSRCCovered = isAinB($sec_rule['src'], $exploded_nat_src_Members);
                        if( !$isSRCCovered )
                        {
                            //No need to further check if the NAT matches
                        }
//                    echo "Sources match (Sec:$sec_rule_lid, Nat:$nat_rule_lid): $isSRCCovered\n";

                        $isSRVCovered = isAinB_service($sec_rule['srv'], $exploded_nat_srv_Members);
//                    echo "Service match: match (Sec:$sec_rule_lid, Nat:$nat_rule_lid): $isSRVCovered\n";

                        if( ($isDSTCovered == 1) && ($isSRCCovered == 1) && ($isSRVCovered == 1) )
                        {
                            //Calculate destination Zone after NAT
//                        echo "getAutoZone(".$ipMapping['ipv4'].", $member_lid_dat, $table_name_dat, $negate_source);";
                            $correct_zones_to = getAutoZone($ipMapping['ipv4'], $member_lid_dat, $table_name_dat, $negate_source);  //This will provide all the zones that this NAT has as destination AFTER NAT

                            $natted_rules[] = $sec_rule_lid;  //Add this rule in the list of modified rules, so we do not need to process it again.
                            $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$sec_rule_lid';");
                            //TODO: those should be individual entries
                            foreach( $correct_zones_to as $zone )
                            {
                                $values[] = "('$sec_rule_lid', '$zone')";
                            }
                            $listValues = implode(',', $values);
                            $listValuesUnique = array_unique($listValues);
                            $query = "INSERT INTO security_rules_to (rule_lid, name) VALUES $listValuesUnique;";
//                            echo "$query based on $nat_rule_lid\n";
                            $projectdb->query($query);
                            add_log2('ok', 'Auto Zone Assign', 'Rule [' . $sec_rule_lid . ']. Updating "TO Zones" as [' . implode(',', $correct_zones_to) . '] based on DAT defined in NAT rule [' . $nat_rule_lid . ']', $source, 'No Action Required', 'rules', $sec_rule_lid, 'security_rules');
                        }
                        else
                        {
                            if( ($isDSTCovered + $isSRCCovered + $isSRVCovered) > 3 &&
                                ($isDSTCovered != 0) && ($isSRCCovered != 0) && ($isSRVCovered != 0)
                            )
                            {
                                $correct_zones_to = getAutoZone($ipMapping['ipv4'], $member_lid_dat, $table_name_dat, $negate_source);
                                foreach( $correct_zones_to as $zone )
                                {
                                    $values[] = "('$sec_rule_lid', '$zone')";
                                }
                                $listValues = implode(',', $values);
                                $listValuesUnique = array_unique($listValues);
                                $query = "INSERT INTO security_rules_to (rule_lid, name) VALUES $listValuesUnique;";
                                $projectdb->query($query);
//                              echo "+-+-+-+-+-This was a partial match!\n";
                                add_log2('warning', 'Auto Zone Assign', 'Rule [' . $sec_rule_lid . ']. This security Rule is partially covered by NAT rule [' . $nat_rule_lid . ']. Added the following "TO Zones": [' . implode(',', $correct_zones_to) . ']. Suggestion to split the rule and assign the following "TO Zones": [' . implode(',', $correct_zones_to) . ']', $source, 'No Action Required', 'rules', $sec_rule_lid, 'security_rules');
                            }
                            else
                            {

                            }
                        }
                    }

                    if( count($natted_rules) > 0 )
                    {
//                    $unique = array_unique($natted_rules);
//                    $out = implode(",", $unique);
//                    $query = "UPDATE security_rules SET blocked=1 WHERE id in (" . $out . ");";
//                    $projectdb->query($query);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $natted_rules);
                    }
                } //NAT Logic applies here
                else
                {
//                echo "----This is not DAT\n";
                    $natted_rules = array();
                    //Find the Security rules that are affected by this NAT
                    $unprocesses_sec_rules = count($security_rules);
                    $xx = 1;
                    foreach( $security_rules as $sec_rule_lid => $sec_rule )
                    {
                        $percentage = 0.2 + round(0.8 * $processed_nat / $number_of_nats, 2);
                        update_progress($projectName, $percentage, "Checking NAT Rule ($processed_nat of $number_of_nats). Matching Security Rules ($xx of $unprocesses_sec_rules)", $jobid);
                        $xx++;
                        $isDSTCovered = isAinB($sec_rule['dst'], $exploded_nat_dst_Members);
                        if( !$isDSTCovered )
                        {
                            break;
                        }
                        $isSRCCovered = isAinB($sec_rule['src'], $exploded_nat_src_Members);

                        if( $isSRCCovered )
                        {
                            //TODO: Use this part to update source Zones, for example
                            $natted_rules[] = $sec_rule_lid;
                        }
                    }
                    if( count($natted_rules) > 0 )
                    {
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($sec_rules, $natted_rules);
                    }
                }

                //Free Memory
                $exploded_nat_src_Members = null;
                $exploded_nat_dst_Members = null;

                //Checking if this NAT actually affects any Security Rule or
                //  (a) it is shadowed by prior NATS
                //  (b) it is too restrictive
                if( count($natted_rules) == 0 )
                {
                    add_log2('info', 'NAT Analysis', 'NAT Rule [' . $nat_rule_lid . '] does not affect any of the existing security rules. Or affects only ranges inside a security rule.', $source, 'No Action Required. Suggestion to review and/or remove. If partial matching, you may consider split the security rule.', 'rules', $nat_rule_lid, 'nat_rules');
                }

                $processed_nat++;
            }

            //Calculate the ZONES TO to the remaining the security rules in the selection
            foreach( $security_rules as $sec_rule )
            {
                $negate_source = 0;
                $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                $devicegroup = $sec_rule['devicegroup'];

                foreach( $zones as $zone )
                {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                    if( $getZone->num_rows == 0 )
                    {
                        $query = "INSERT INTO security_rules_to (rule_lid, name) "
                            . " VALUES ('$rule_lid', '$zone');";
//                    echo "$query\n";
                        $projectdb->query($query);
                    }
                }
            }
        }
        else
        {
            //Calculate the ZONES TO to the all the security rules in the selection without NATs considered
            $processed_rule = 1;
            $number_of_rules = count($security_rules);
            foreach( $security_rules as $rule_lid => $sec_rule )
            {
                $negate_source = 0;
                $percentage = 0.2 + round(0.8 * $processed_rule / $number_of_rules, 2);
                $processed_rule++;

                update_progress($projectName, $percentage, "Checking NAT Rule ($processed_rule of $number_of_rules).", $jobid);

                foreach( $sec_rule['dst'] as $sec_source )
                {
                    $member_lid = $sec_source->name;
                    $table_name = $sec_source->location;
                    if( $member_lid == 'any' )
                    {
                        $zones = array();
                        break;
                    }
                    else
                    {
                        $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                    }
                }
                $devicegroup = $sec_rule['devicegroup'];

                $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$rule_lid';");
                foreach( $zones as $zone )
                {
                    $query = "SELECT id FROM security_rules_to WHERE name='$zone' AND rule_lid='$rule_lid';";
                    $getZone = $projectdb->query($query);
                    if( $getZone->num_rows == 0 )
                    {
                        $query = "INSERT INTO security_rules_to (rule_lid, name) "
                            . " VALUES ('$rule_lid', '$zone');";
                        $projectdb->query($query);
                    }
                }
            }
        }
    }

    update_progress($projectName, '1.00', "Finished", $jobid);
}

function set_Zones_Nat($projectName, $source, $vsys, $vr)
{
    global $projectdb;

    $projectdb = selectDatabase($projectName);

    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

    //Zones FROM
    //$getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_src WHERE source='$source' AND vsys='$vsys';");
    $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_src;");

    if( $getSRC->num_rows > 0 )
    {
        while( $getSRCData = $getSRC->fetch_assoc() )
        {
            $member_lid = $getSRCData['member_lid'];
            $table_name = $getSRCData['table_name'];
            $rule_lid = $getSRCData['rule_lid'];

            $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM nat_rules WHERE id = '$rule_lid';");
            if( $getDeviceGroup->num_rows > 0 )
            {
                $getINData = $getDeviceGroup->fetch_assoc();
                $devicegroup = $getINData['devicegroup'];
            }

            $negate_source = 0;
            $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);

            foreach( $zones as $zone )
            {
                $getZone = $projectdb->query("SELECT id FROM nat_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid' ;");
                if( $getZone->num_rows == 0 )
                {
                    $projectdb->query("INSERT INTO nat_rules_from (rule_lid, name, source, vsys, devicegroup) "
                        . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                }
            }
        }
    }

    //Zones TO
    $to_zones = array();
    //$getDST = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_dst WHERE source='$source' AND vsys='$vsys';");
    $getDST = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_dst;");
    if( $getDST->num_rows > 0 )
    {
        while( $getDSTData = $getDST->fetch_assoc() )
        {
            $member_lid = $getDSTData['member_lid'];
            $table_name = $getDSTData['table_name'];
            $rule_lid = $getDSTData['rule_lid'];

            $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM nat_rules WHERE id = '$rule_lid';");
            if( $getDeviceGroup->num_rows > 0 )
            {
                $getINData = $getDeviceGroup->fetch_assoc();
                $devicegroup = $getINData['devicegroup'];
            }

            $negate_source = 0;

            $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
            foreach( $zones as $zone )
            {
                $to_zones[$rule_lid][] = $zone;
            }
        }

        if( count($to_zones) > 0 )
        {
            foreach( $to_zones as $key => $zones )
            {
                $unique = array_unique($zones);
                $all_zones = implode(",", $unique);
                $query = "UPDATE nat_rules SET op_zone_to = '$all_zones' WHERE id ='$key';";
                $projectdb->query($query);
            }
        }
    }
}

function removeKeysFromArray(&$array, $keys)
{
    foreach( $keys as $key )
    {
        unset($array[$key]);
        //$array[$key] = null;
    }
}

function printMemory($file, STRING $string)
{
    $memory = memory_get_usage();
    $mem_usage = round($memory / 1048576, 2);
    fwrite($file, "$string - Memory: matches $mem_usage MB\n");
}

function loadObjectsInMemory(mysqli $connection, STRING $source, STRING $vsys)
{
    $inMemory = array();

    $rules = array();
    $query = "SELECT id, 'security' as ruleType FROM security_rules WHERE source='$source' AND vsys='$vsys' UNION 
              SELECT id, 'nat'      as ruleType FROM nat_rules      WHERE source='$source' AND vsys='$vsys' ";
    $result = $connection->query($query);
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $type = $data['ruleType'];
            $lid = $data['id'];
            $rules[$type][] = $lid;
        }
    }

    //Step 2. Get the ids ob the objects that will be requested
    $listAddresses = array();
    $listAddressGroups = array();
    $listServices = array();
    $listServiceGroups = array();
    $listZones = array();
    $query = "SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid in (" . implode(',', $rules['security']) . ") GROUP BY member_lid, table_name UNION 
              SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid in (" . implode(',', $rules['security']) . ") GROUP BY member_lid, table_name UNION
              SELECT member_lid, table_name FROM nat_rules_src      WHERE rule_lid in (" . implode(',', $rules['nat']) . ")      GROUP BY member_lid, table_name UNION
              SELECT member_lid, table_name FROM nat_rules_dst      WHERE rule_lid in (" . implode(',', $rules['nat']) . ")      GROUP BY member_lid, table_name";
    $result = $connection->query($query);
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $table = $data['table_name'];
            switch ($table)
            {
                case "address":
                    $listAddresses[] = $data['member_lid'];
                    break;
                case "address_groups_id":
                    $listAddressGroups[] = $data['member_lid'];
                    break;
                default:
                    break;
            }
        }
    }

    $query = "SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid in (" . implode(',', $rules['security']) . ") GROUP BY member_lid, table_name";
    $result = $connection->query($query);
    if( $result->num_rows > 0 )
    {

        while( $data = $result->fetch_assoc() )
        {
            $table = $data['table_name'];
            switch ($table)
            {
                case "services":
                    $listServices[] = $data['member_lid'];
                    break;
                case "services_groups_id":
                    $listServiceGroups[] = $data['member_lid'];
                    break;
                default:
                    break;
            }
        }
    }

    /** Zones */
    $query = "SELECT name FROM security_rules_from WHERE rule_lid in (" . implode(',', $rules['security']) . ") GROUP BY name UNION 
              SELECT name FROM security_rules_to   WHERE rule_lid in (" . implode(',', $rules['security']) . ") GROUP BY name UNION
              SELECT name FROM nat_rules_from      WHERE rule_lid in (" . implode(',', $rules['nat']) . ") GROUP BY name ";
    $result = $connection->query($query);
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $listZones[] = "'" . $data['name'] . "'";
        }
    }

    $query = "SELECT tp_dat_address_lid, tp_dat_address_table, op_service_lid, op_service_table, op_zone_to FROM nat_rules WHERE id in (" . implode(',', $rules['nat']) . ")";
    $result = $connection->query($query);
    if( $result->num_rows > 0 )
    {
        while( $data = $result->fetch_assoc() )
        {
            $table_address = $data['tp_dat_address_table'];
            switch ($table_address)
            {
                case "address":
                    $listAddresses[] = $data['tp_dat_address_lid'];
                    break;
                case "address_groups_id":
                    $listAddressGroups[] = $data['tp_dat_address_lid'];
                    break;
                default:
                    break;
            }
            $table_service = $data['op_service_table'];
            switch ($table_service)
            {
                case "services":
                    $listServices[] = $data['op_service_lid'];
                    break;
                case "services_groups_id":
                    $listServiceGroups[] = $data['op_service_lid'];
                    break;
                default:
                    break;
            }
            $listZones[] = "'" . $data['op_zone_to'] . "'";
        }
    }

    $listAddresses = array_unique($listAddresses);
    $listAddressGroups = array_unique($listAddressGroups);
    $listServices = array_unique($listServices);
    $listServiceGroups = array_unique($listServiceGroups);
    $listZones = array_unique($listZones);

    //Address
    if( count($listAddresses) > 0 )
    {
        $query = "SELECT * FROM address WHERE id in (" . implode(',', $listAddresses) . ")";
        $result = $connection->query($query);
        while( $row = $result->fetch_assoc() )
        {
            $inMemory['address'][$row['id']] = $row;
        }
    }
    //AddGroups
    if( count($listAddressGroups) > 0 )
    {
        $query = "SELECT * FROM address_groups_id WHERE id in (" . implode(',', $listAddressGroups) . ")";
        $result = $connection->query($query);
        while( $row = $result->fetch_assoc() )
        {
            $inMemory['address_groups_id'][$row['id']] = $row;
        }
    }
    //Services
    if( count($listServices) > 0 )
    {
        $query = "SELECT * FROM services WHERE id in (" . implode(',', $listServices) . ")";
        $result = $connection->query($query);
        while( $row = $result->fetch_assoc() )
        {
            $inMemory['services'][$row['id']] = $row;
        }
    }
    //Service Groups
    if( count($listServiceGroups) > 0 )
    {
        $query = "SELECT * FROM services_groups_id WHERE id in (" . implode(',', $listServiceGroups) . ")";
        $result = $connection->query($query);
        while( $row = $result->fetch_assoc() )
        {
            $inMemory['services_groups_id'][$row['id']] = $row;
        }
    }
    //Zones
    if( count($listZones) > 0 )
    {
        $query = "SELECT * FROM zones WHERE name in (" . implode(',', $listZones) . ")";
        $result = $connection->query($query);
        while( $row = $result->fetch_assoc() )
        {
            $inMemory['zones'][$row['id']] = $row;
        }
    }

    return $inMemory;
}

function recalculate_Dst_basedOn_NAT(mysqli $connection, STRING $source, STRING $vsys, STRING $vr, STRING $project, STRING $vendor = null)
{
    require_once INC_ROOT . '/libs/shared.php';
    global $projectdb;

    $add_logs = array();
    $projectdb = $connection;

    if( !isset($vendor) )
    {
        $vendor = 'Paloalto';
    }

    switch (strtolower($vendor))
    {
        case "paloalto":
            $vendor_type = 0;
            break;
        case "stonesoft":
            $vendor_type = 1;
            break;
        case "cisco":
            $vendor_type = 2;
            break;
        case "checkpoint":
            $vendor_type = 3;
            break;
        case "checkpointr80":
            $vendor_type = 4;
            break;
        default:
            $vendor_type = 5;
            break;
    }

    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    $natted_rules = array();   //IDs of the modified rules
    $security_rules = array();

//    $objectsInMemory = loadObjectsInMemory($connection, $source, $vsys);
    /***
     * COLLECT ALL THE POLICY RULES AS OBJECTS
     */
    //Initialize a 2Dim associative array for the security rules with the size of the rules we have.

    $security_rules = loadInMemorySecRules($connection, $source, $vsys);

    $memberAnyAddress = new MemberObject('', '', '0.0.0.0', '0');
    $memberAnyService = new MemberObject('', '', '0-65535', 'any');

    $newRulesDNAT = $newRulesSNAT = $newRulesNONAT = $rulesNONAT = array(); //This array will contain information to generate new Rules that come from splitting security rules based on NATs

    //Select the NAT rules that are Not disabled
    $getDAT = $connection->query("SELECT id, tp_dat_address_lid, tp_dat_address_table, devicegroup, is_dat, op_zone_to, op_service_lid, op_service_table, tp_sat_type, tp_sat_bidirectional 
FROM nat_rules WHERE disabled='0' AND source='$source' AND vsys='$vsys' ORDER BY position;");
    while( $getNatData = $getDAT->fetch_assoc() )
    {

        $nat_rule_lid = $getNatData['id'];
        $devicegroup = $getNatData['devicegroup'];
        $is_dat = $getNatData['is_dat'];
        $tp_sat_type = $getNatData['tp_sat_type'];
        $tp_sat_bidirectional = $getNatData['tp_sat_bidirectional'];
        $nat_to_zones = array($getNatData['op_zone_to']);

        //Get the destionation afterNAT
        $member_lid_dat = $getNatData['tp_dat_address_lid'];
        $table_name_dat = $getNatData['tp_dat_address_table'];
        if( $table_name_dat != '' && $member_lid_dat != '' )
        {
            $member = new MemberObject($member_lid_dat, $table_name_dat);
            $exploded_nat_Tdst_Members = explodeGroups2Members(array($member), $connection, $source, $vsys);
        }
        else
        {
            $exploded_nat_Tdst_Members = array(new MemberObject('', '', '0.0.0.0', '0'));
        }

        //Get the zones TO
        $nat_Tto_zones = array();
        foreach( $exploded_nat_Tdst_Members as $sec_source )
        {
            $member_lid = $sec_source->name;
            $table_name = $sec_source->location;
            if( $member_lid == 'any' )
            {
                $nat_Tto_zones = array('any');
                break;
            }
            else
            {
                $nat_Tto_zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
            }
        }


        //Get the service in NAT
        $member_lid_opSrv = $getNatData['op_service_lid'];
        $table_name_opSrv = $getNatData['op_service_table'];
        if( $member_lid_opSrv != '' && $table_name_opSrv != '' )
        {
            $exploded_nat_srv_Members = explodeGroups2Services(array(new MemberObject($member_lid_opSrv, $table_name_opSrv)), $connection, $source, $vsys);

        }
        else
        {
            $exploded_nat_srv_Members = array($memberAnyService);
        }
        if( count($exploded_nat_srv_Members) == 0 )
        {
            $exploded_nat_srv_Members = array($memberAnyService);
        }

        $negate_source = 0;  //Note: In Stonesoft, we do not negate rules due to the JUMP approach they use. Insead, in case a Negate is applied in Stonesoft, we calculate all the opposite addresses

        //Initialize Sources and Destinations for mapping
        $nat_src_members = array();
        $exploded_nat_src_Members = array();

        $nat_dst_members = array();
        $exploded_nat_dst_Members = array();

        $nat_Tsrc_members = array();
        $exploded_nat_Tsrc_Members = array();

        //Get the From beforeNAT
        $getFrom = $connection->query("SELECT name FROM nat_rules_from WHERE rule_lid='$nat_rule_lid';");
        if( $getFrom->num_rows > 0 )
        {
            $nat_from_zones = array();
            while( $getFromData = $getFrom->fetch_assoc() )
            {
                $nat_from_zones[] = $getFromData['name'];;
            }
        }
        else
        {
            $nat_from_zones = array("any");
        }

        //Get the source beforeNAT
        $getSrc = $connection->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid='$nat_rule_lid';");
        if( $getSrc->num_rows > 0 )
        {
            while( $getINData = $getSrc->fetch_assoc() )
            {
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];

                $member = new MemberObject($member_lid, $table_name);
                $nat_src_members[] = $member;
            }
            $exploded_nat_src_Members = explodeGroups2Members($nat_src_members, $connection, $source, $vsys);
        }
        else
        {
            $exploded_nat_src_Members[] = new MemberObject('', '', '0.0.0.0', '0');
        }

        //Get the destination beforeNAT
        $getDst = $connection->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid='$nat_rule_lid';");
        if( $getDst->num_rows > 0 )
        {
            while( $getINData = $getDst->fetch_assoc() )
            {
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];

                $member = new MemberObject($member_lid, $table_name);
                $nat_dst_members[] = $member;
            }
            $exploded_nat_dst_Members = explodeGroups2Members($nat_dst_members, $connection, $source, $vsys);
        }
        else
        {
            $exploded_nat_dst_Members[] = new MemberObject('', '', '0.0.0.0', '0');
        }

        //Get the sources afterNAT
        $getTSrc = $connection->query("SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid='$nat_rule_lid';");
        if( $getTSrc->num_rows > 0 )
        {
            while( $getDSrcData = $getTSrc->fetch_assoc() )
            {
                $member_lid = $getDSrcData['member_lid'];
                $table_name = $getDSrcData['table_name'];

                $member = new MemberObject($member_lid, $table_name);
                $nat_Tsrc_members[] = $member;
            }
            $exploded_nat_Tsrc_Members = explodeGroups2Members($nat_Tsrc_members, $connection, $source, $vsys);
        }
        else
        {
            $exploded_nat_Tsrc_Members[] = new MemberObject('', '', '0.0.0.0', '0');
        }


        /* Now we have For this NAT rule:
         *  1.1- the NAT origins (in $exploded_nat_src_Members)
         *  1.2- the NAT destinations (in $exploded_nat_dst_Members)
         *  1.3- the NAT Srv (in $exploded_nat_srv_Members)
         *  1.4- the NAT Tdest (in $exploded_nat_Tdst_Members)
         *  1.5- the NAT Tsour (in $exploded_nat_Tsrc_Members)
         *  1.6- the NAT From Zone (in $nat_from_zones)
         *  1.7- the NAT To after NAT (in $nat_to_zones)
         *
         *  2.1- all the sources for all the security rules (in $security_rule[ruleID]['src'])
         *  2.2- all the destina for all the security rules (in $security_rule[ruleID]['dst'])
         *  2.3- all the service for all the security rules (in $security_rule[ruleID]['srv'])
         *  2.4- all the zoneFro for all the security rules (in $security_rule[ruleID]['form'])
         *  2.5- all the ZoneTo  for all the security rules (in $security_rule[ruleID]['to'])
         *
         * Ready for doing the matching
         */


        //Find the Security rules that are affected by this NAT

        //NO NAT Rule
        if( count($exploded_nat_Tdst_Members) == 1 && $exploded_nat_Tdst_Members[0] == $memberAnyAddress &&
            count($exploded_nat_Tsrc_Members) == 1 && $exploded_nat_Tsrc_Members[0] == $memberAnyAddress &&
            ($tp_sat_type == '' || $tp_sat_type == 'none') )
        {
            if( $vendor == 0 || $vendor == 1 || $vendor == 2 || $vendor == 3 )
            {
                $natted_rules = array();
                foreach( $security_rules as $security_rule_lid => $security_rule )
                {
                    $zonesFrom = array();
                    $isFromCovered = isAinB_Zones($security_rule['from'], $nat_from_zones, $zonesFrom);
                    if( !$isFromCovered )
                    {
                        continue 1;
                    }
                    $zonesTo = array();
                    $isToCovered = isAinB_Zones($security_rule['to'], $nat_to_zones, $zonesTo);
                    if( !$isToCovered )
                    {
                        continue 1;
                    }

                    $sourcesMatched = array();
//                $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $sourcesMatched, true);
                    $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $sourcesMatched);
                    if( !$isSrcCovered )
                    {
                        continue 1;
                    }
                    $destinationsMatched = array();
                    $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members, $destinationsMatched);
                    if( !$isDstCovered )
                    {
                        continue 1;
                    }
                    $servicesMatched = array();
                    $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                    if( !$isSrvCovered )
                    {
                        continue 1;
                    }
                    //Recover the DST ip before the Static NAT
                    if( $isFromCovered * $isToCovered * $isSrcCovered * $isDstCovered * $isSrvCovered == 1 )
                    { //Fully covered
                        $natted_rules[] = $security_rule_lid;
                    }
                    elseif( $isSrvCovered && $isDstCovered && $isSrvCovered )
                    {//Partially Covered
                        if( count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress) )
                        {
                            // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                            //Clone the rule and add a subset with the new Destinations before Nat
                            $count = isset($newRulesNONAT[$security_rule_lid]['cloned']) ? $newRulesNONAT[$security_rule_lid]['cloned'] + 1 : 0;
                            if( !isset($newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid']) )
                            {
                                $newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                            }
                            $newRulesNONAT[$security_rule_lid]['cloned'] = $count;

                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['from'] = $zonesFrom;
                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['to'] = $zonesTo;
                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['sources'] = $sourcesMatched;
                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['destinations'] = $destinationsMatched;
                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['services'] = $servicesMatched;
                        }
                    }
                }
                if( count($natted_rules) > 0 )
                {
                    $unique = array_unique($natted_rules);
                    //Remove those Security Rules from the Associative array, as they have already found a NAT match
                    removeKeysFromArray($security_rules, $unique);
                }
            }
            elseif( $vendor == 4 )
            {
                $natted_rules = array();
                foreach( $security_rules as $security_rule_lid => $security_rule )
                {
//                    $zonesFrom = array();
//                    $isFromCovered = isAinB_Zones($security_rule['from'], $nat_from_zones, $zonesFrom);
//                    if (!$isFromCovered) {
//                        continue 1;
//                    }
//                    $zonesTo = array();
//                    $isToCovered = isAinB_Zones($security_rule['to'], $nat_to_zones, $zonesTo);
//                    if (!$isToCovered) {
//                        continue 1;
//                    }
                    $sourcesMatched = array();
//                $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $sourcesMatched, true);
                    $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $sourcesMatched);
                    if( !$isSrcCovered )
                    {
                        continue 1;
                    }
                    $destinationsMatched = array();
                    $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members, $destinationsMatched);
                    if( !$isDstCovered )
                    {
                        continue 1;
                    }
                    $servicesMatched = array();
                    $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                    if( !$isSrvCovered )
                    {
                        continue 1;
                    }
                    //Recover the DST ip before the Static NAT
                    if( $isSrcCovered * $isDstCovered * $isSrvCovered == 1 )
                    { //Fully covered
                        $natted_rules[] = $security_rule_lid;
                        $rulesNONAT[$security_rule_lid]['from'] = $nat_from_zones;
                        $rulesNONAT[$security_rule_lid]['to'] = $nat_to_zones;
                    }
                    elseif( $isSrvCovered && $isDstCovered && $isSrvCovered )
                    {//Partially Covered
                        if( count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress) )
                        {
                            // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                            //Clone the rule and add a subset with the new Destinations before Nat
                            $count = isset($newRulesNONAT[$security_rule_lid]['cloned']) ? $newRulesNONAT[$security_rule_lid]['cloned'] + 1 : 0;
                            if( !isset($newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid']) )
                            {
                                $newRulesNONAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                            }
                            $newRulesNONAT[$security_rule_lid]['cloned'] = $count;
                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['from'] = $nat_from_zones;
                            $newRulesNONAT[$security_rule_lid]['clones'][$count]['to'] = $nat_to_zones;
                        }
                    }
                }
                if( count($natted_rules) > 0 )
                {
                    $unique = array_unique($natted_rules);
                    //Remove those Security Rules from the Associative array, as they have already found a NAT match
                    removeKeysFromArray($security_rules, $unique);
                }
            }
        }

        //DNAT Logic applies here
        elseif( $is_dat == 1 )
        {
            if( $vendor_type == 0 )
            {
            }
            elseif( $vendor_type == 1 )
            { //TODO: Review the code for Stonesoft based on the function fix_Zones_Policies
                $natted_rules = array();
                foreach( $security_rules as $sec_rule_lid => $security_rule )
                {
                    $isDSTCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members);
                    if( !$isDSTCovered )
                    {
                        //No need to check if the Source matches
                        continue;
                    }
                    $isSRCCovered = isAinB($security_rule['src'], $exploded_nat_src_Members);

                    if( $isSRCCovered )
                    {
                        //Calculate destination Zone after NAT
                        $correct_zones_to = getAutoZone($ipMapping['ipv4'], $member_lid_dat, $table_name_dat, $negate_source);  //This will provide all the zones that this NAT has as destination AFTER NAT

                        $natted_rules[] = $sec_rule_lid;  //Add this rule in the list of modified rules, so we do not need to process it again.
                        $connection->query("DELETE FROM security_rules_to WHERE rule_lid='$sec_rule_lid';");
                        $connection->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                            . "VALUES ('$sec_rule_lid', '" . implode(',', $correct_zones_to) . "', '$source', '$vsys', '$devicegroup');");
                        $add_logs[] = "('NOW()','2', 'Auto Zone Assign', 'Rule [$sec_rule_lid]. Forcing TO Zone as [" . implode(',', $correct_zones_to) . "] based on DAT defined in NAT rule [$nat_rule_lid]', '$source', 'No Action Required', 'rules', '$sec_rule_lid', 'security_rules')";
                    }
                }
                if( count($natted_rules) > 0 )
                {
                    $unique = array_unique($natted_rules);
                    $out = implode(",", $unique);
                    $query = "UPDATE security_rules SET blocked=1 WHERE id in (" . $out . ");";
                    $connection->query($query);
                    //Remove those Security Rules from the Associative array, as they have already found a NAT match
                    removeKeysFromArray($security_rules, $natted_rules);
                }
            }
            elseif( $vendor_type == 2 )
            {
                $natted_rules = array();
                foreach( $security_rules as $security_rule_lid => $security_rule )
                {
                    $zonesFrom = array();
                    $isFromCovered = isAinB_Zones($security_rule['from'], $nat_from_zones, $zonesFrom);
                    if( !$isFromCovered )
                    {
                        continue 1;
                    }

                    $zonesTo = array();
                    $isToCovered = isAinB_Zones($security_rule['to'], $nat_Tto_zones, $zonesTo);
                    if( !$isToCovered )
                    {
                        continue 1;
                    }

                    $TDstMembers = array();
                    $isTDstCovered = isAinB($security_rule['dst'], $exploded_nat_Tdst_Members, $TDstMembers);
                    if( !$isTDstCovered )
                    {
                        continue 1;
                    }

                    $SrcMembers = array();
                    $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $SrcMembers);
                    if( !$isSrcCovered )
                    {
                        continue 1;
                    }

                    $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members);
                    if( !$isSrvCovered )
                    {
                        continue 1;
                    }

                    //Recover the IP before NAT
                    if( $isFromCovered * $isToCovered * $isSrcCovered * $isTDstCovered * $isSrvCovered == 1 )
                    { //Fully covered
                        $natted_rules[] = $security_rule_lid;
                        // "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                        //Modify the rule and replace the destination with before NAT
                        $query = "DELETE FROM security_rules_dst WHERE rule_lid='$security_rule_lid'";
                        $connection->query($query);
                        $destinations = array();
                        foreach( $exploded_nat_dst_Members as $dst_Member )
                        {
                            $destinations[] = "('$security_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                        }
                        if( count($destinations) > 0 )
                        {
                            $unique = array_unique($destinations);
                            $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                            $connection->query($query);
                            $add_logs[] = "('NOW()','1', 'Correcting Destination based on DNAT', 'Destination address corrected to value before DNAT, based on NAT Rule[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$security_rule_lid', 'security_rules')";
                        }
                    }
                    elseif( $isTDstCovered && $isSrcCovered && $isSrvCovered )
                    {
                        if( count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress) )
                        {
                            // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                            //Clone the rule and add a subset with the new Destinations before Nat
                            $count = isset($newRulesDNAT[$security_rule_lid]['cloned']) ? $newRulesDNAT[$security_rule_lid]['cloned'] + 1 : 0;
                            if( !isset($newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid']) )
                            {
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                            }
                            $newRulesDNAT[$security_rule_lid]['cloned'] = $count;

                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['from'] = $zonesFrom;
                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['to'] = $zonesTo;
                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['destinations'] = $exploded_nat_dst_Members;
                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['services'] = $exploded_nat_srv_Members;
                        }
                    }
                }

                if( count($natted_rules) > 0 )
                {
                    $unique = array_unique($natted_rules);
                    $out = implode(",", $unique);
                    $query = "UPDATE security_rules SET blocked=1 WHERE id in (" . $out . ");";
                    $connection->query($query);
                    //Remove those Security Rules from the Associative array, as they have already found a NAT match
                    removeKeysFromArray($security_rules, $natted_rules);
                }
            }
            elseif( $vendor_type == 3 )
            {
            }
            elseif( $vendor_type == 4 )
            {
                $natted_rules = array();
                foreach( $security_rules as $security_rule_lid => $security_rule )
                {
//                    $zonesFrom = array();
//                    $isFromCovered = isAinB_Zones($security_rule['from'], $nat_from_zones, $zonesFrom);
//                    if(!$isFromCovered){
//                        continue 1;
//                    }
//
//                    $zonesTo = array();
//                    $isToCovered = isAinB_Zones($security_rule['to'], $nat_Tto_zones, $zonesTo);
//                    if(!$isToCovered){
//                        continue 1;
//                    }

                    $DstMembers = array();
                    $isTDstCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members, $DstMembers);
                    if( !$isTDstCovered )
                    {
                        continue 1;
                    }

//                    echo "Sec Rule[$security_rule_lid] and Nat[$nat_rule_lid] matches: DST, ";

                    $SrcMembers = array();
                    $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_src_Members, $SrcMembers);
                    if( !$isSrcCovered )
                    {
//                        echo "\n";
                        continue 1;

                    }
//                    echo "SRC-";

                    $SrvMembers = array();
                    $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $SrvMembers);
                    if( !$isSrvCovered )
                    {
//                        echo "\n";
//                        echo "Sec:";
//                        print_r($security_rule['srv']);
//                        echo "Nat:";
//                        print_r($exploded_nat_srv_Members);
//                        echo "Result: $isSrvCovered Cross:";
//                        print_r($SrvMembers);
//                        die;
                        continue 1;
                    }
//                    echo "SRV\n";
//                    die;

                    //Recover the IP before NAT
                    if( $isSrcCovered * $isTDstCovered * $isSrvCovered == 1 )
                    { //Fully covered
                        $natted_rules[] = $security_rule_lid;
                        // "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                        //Modify the rule and replace the destination with before NAT
                        //TODO: convert into one single INSERT
                        foreach( $nat_from_zones as $zone )
                        {
                            if( $zone != "any" )
                            {
                                $tempZonesFrom[] = "($security_rule_lid, '$zone', '$vsys', '$source')";

                            }
                        }
                        if( count($tempZonesFrom) > 0 )
                        {
                            $unique = array_unique($tempZonesFrom);
                            $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(",", $unique) . ";";
                            $connection->query($query);
                        }

                        foreach( $nat_Tto_zones as $zone )
                        {
                            if( $zone != "any" )
                            {
                                $tempZonesTo[] = "($security_rule_lid, '$zone', '$vsys', '$source')";
                            }
                        }
                        if( count($tempZonesTo) > 0 )
                        {
                            $unique = array_unique($tempZonesTo);
                            $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(",", $unique) . ";";
                            $connection->query($query);
                        }
                    }
                    elseif( $isTDstCovered && $isSrcCovered && $isSrvCovered )
                    {
                        if( count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress) )
                        {
                            // "Rule $security_rule_lid is partially covered by NAT $nat_rule_lid\n";
                            //Clone the rule and add a subset with the new Destinations before Nat
                            $count = isset($newRulesDNAT[$security_rule_lid]['cloned']) ? $newRulesDNAT[$security_rule_lid]['cloned'] + 1 : 0;
                            if( !isset($newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid']) )
                            {
                                $newRulesDNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                            }
                            $newRulesDNAT[$security_rule_lid]['cloned'] = $count;
                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['from'] = $nat_from_zones;
                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['to'] = $nat_Tto_zones;
                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['destinations'] = $DstMembers;
                            $newRulesDNAT[$security_rule_lid]['clones'][$count]['services'] = $SrvMembers;
                        }
                    }
                }

                if( count($natted_rules) > 0 )
                {
                    $unique = array_unique($natted_rules);
                    //Remove those Security Rules from the Associative array, as they have already found a NAT match
                    removeKeysFromArray($security_rules, $unique);
                }
            }
        }
        //NAT Logic applies here
        else
        {
            if( $vendor_type == 0 )
            {
            }
            elseif( $vendor_type == 1 )
            {
                $natted_rules = array();
                //Find the Security rules that are affected by this NAT
                foreach( $security_rules as $sec_rule_lid => $security_rule )
                {
//                    $counter++;

                    $isDSTCovered = isAinB($security_rule['dst'], $exploded_nat_dst_Members);
                    if( !$isDSTCovered )
                    {
                        break;
                    }
                    $isSRCCovered = isAinB($security_rule['src'], $exploded_nat_src_Members);

                    if( $isSRCCovered )
                    {
                        //TODO: Use this part to update source Zones, for example
                        $natted_rules[] = $sec_rule_lid;
                    }
                }
//                printMemory($my, "        Matches done");
                if( count($natted_rules) > 0 )
                {
                    $unique = array_unique($natted_rules);
//                    $out = implode(",", $unique);
//                    fwrite($my, "$nat_rule_lid matches $out\n");
                    //Remove those Security Rules from the Associative array, as they have already found a NAT match
                    removeKeysFromArray($security_rules, $unique);
                }
            }
            elseif( $vendor_type == 2 )
            {
                if( $tp_sat_type == 'static-ip' && $tp_sat_bidirectional == '1' )
                {
                    $natted_rules = array();
                    foreach( $security_rules as $security_rule_lid => $security_rule )
                    {
                        $zonesFrom = array();
                        $isFromCovered = isAinB_Zones($security_rule['from'], $nat_to_zones, $zonesFrom);
                        if( !$isFromCovered )
                        {
                            continue 1;
                        }
                        $zonesTo = array();
                        $isToCovered = isAinB_Zones($security_rule['to'], $nat_from_zones, $zonesTo);
                        if( !$isToCovered )
                        {
                            continue 1;
                        }

                        $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_dst_Members);
                        if( !$isSrcCovered )
                        {
                            continue 1;
                        }
                        $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_src_Members);
                        if( !$isDstCovered )
                        {
                            continue 1;
                        }
                        $servicesMatched = array();
                        $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                        if( !$isSrvCovered )
                        {
                            continue 1;
                        }

                        if( $isFromCovered * $isToCovered * $isSrvCovered * $isDstCovered * $isSrvCovered == 1 )
                        { //Fully covered
                            $natted_rules[] = $security_rule_lid;
                            //   "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                            //Modify the rule and replace the destination with before NAT
                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$security_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach( $exploded_nat_Tsrc_Members as $dst_Member )
                            {
                                $destinations[] = "('$security_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                            }
                            if( count($destinations) > 0 )
                            {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                                $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$security_rule_lid] and NAT Rule[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$security_rule_lid', 'security_rules')";
                            }
                        }
                        //Recover the DST ip before the Static NAT
                        elseif( $isSrvCovered && $isDstCovered && $isSrvCovered )
                        { //Partially Covered
                            if( count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress) )
                            {
                                // "Rule $security_rule_lid is partially covered by Static NAT $nat_rule_lid\n";
                                //Clone the rule and add a subset with the new Destinations before Nat
                                $count = isset($newRulesSNAT[$security_rule_lid]['cloned']) ? $newRulesSNAT[$security_rule_lid]['cloned'] + 1 : 0;
                                if( !isset($newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid']) )
                                {
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                }
                                $newRulesSNAT[$security_rule_lid]['cloned'] = $count;

                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['from'] = $zonesFrom;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['to'] = $zonesTo;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['destinations'] = $exploded_nat_Tsrc_Members;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['services'] = $servicesMatched;
                            }
                        }
                    }


                    if( count($natted_rules) > 0 )
                    {
                        $unique = array_unique($natted_rules);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $unique);
                    }
                }
            }
            elseif( $vendor_type == 3 )
            {
                if( $tp_sat_type == 'static-ip' && $tp_sat_bidirectional == '1' )
                {
                    $natted_rules = array();
                    foreach( $security_rules as $security_rule_lid => $security_rule )
                    {
                        $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_dst_Members);
                        if( !$isSrcCovered )
                        {
                            continue 1;
                        }
                        $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_src_Members);
                        if( !$isDstCovered )
                        {
                            continue 1;
                        }
                        $servicesMatched = array();
                        $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                        if( !$isSrvCovered )
                        {
                            continue 1;
                        }

                        if( $isSrvCovered * $isDstCovered * $isSrvCovered == 1 )
                        { //Fully covered
                            $natted_rules[] = $security_rule_lid;
                            //   "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                            //Modify the rule and replace the destination with before NAT
                            $query = "DELETE FROM security_rules_dst WHERE rule_lid='$security_rule_lid'";
                            $connection->query($query);
                            $destinations = array();
                            foreach( $exploded_nat_Tsrc_Members as $dst_Member )
                            {
                                $destinations[] = "('$security_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                            }
                            if( count($destinations) > 0 )
                            {
                                $unique = array_unique($destinations);
                                $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                                $connection->query($query);
                                $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$security_rule_lid] and NAT Rule[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$security_rule_lid', 'security_rules')";
                            }
                        }
                        //Recover the DST ip before the Static NAT
                        elseif( $isSrvCovered && $isDstCovered && $isSrvCovered )
                        { //Partially Covered
                            if( count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress) )
                            {
                                // "Rule $security_rule_lid is partially covered by Static NAT $nat_rule_lid\n";
                                //Clone the rule and add a subset with the new Destinations before Nat
                                $count = isset($newRulesSNAT[$security_rule_lid]['cloned']) ? $newRulesSNAT[$security_rule_lid]['cloned'] + 1 : 0;
                                if( !isset($newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid']) )
                                {
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                }
                                $newRulesSNAT[$security_rule_lid]['cloned'] = $count;

                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['destinations'] = $exploded_nat_Tsrc_Members;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['services'] = $servicesMatched;
                            }
                        }
                    }


                    if( count($natted_rules) > 0 )
                    {
                        $unique = array_unique($natted_rules);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $unique);
                    }
                }
            }
            elseif( $vendor_type == 4 )
            {
                if( $tp_sat_type == 'static-ip' && $tp_sat_bidirectional == '1' )
                {
                    $natted_rules = array();
                    foreach( $security_rules as $security_rule_lid => $security_rule )
                    {
//                        $zonesFrom = array();
//                        $isFromCovered = isAinB_Zones($security_rule['from'], $nat_to_zones, $zonesFrom);
//                        if(!$isFromCovered){
//                            continue 1;
//                        }
//                        $zonesTo = array();
//                        $isToCovered = isAinB_Zones($security_rule['to'], $nat_from_zones, $zonesTo);
//                        if(!$isToCovered){
//                            continue 1;
//                        }

                        $SrcMembers = array();
                        $isSrcCovered = isAinB($security_rule['src'], $exploded_nat_dst_Members, $SrcMembers);
                        if( !$isSrcCovered )
                        {
                            continue 1;
                        }
                        $DstMembers = array();
                        $isDstCovered = isAinB($security_rule['dst'], $exploded_nat_src_Members, $DstMembers);
                        if( !$isDstCovered )
                        {
                            continue 1;
                        }
                        $servicesMatched = array();
                        $isSrvCovered = isAinB_service($security_rule['srv'], $exploded_nat_srv_Members, $servicesMatched);
                        if( !$isSrvCovered )
                        {
                            continue 1;
                        }

                        if( $isSrvCovered * $isDstCovered * $isSrvCovered == 1 )
                        { //Fully covered
                            $natted_rules[] = $security_rule_lid;
                            //   "Rule $security_rule_lid is Fully covered by NAT $nat_rule_lid\n";
                            //Modify the rule and replace the destination with before NAT
                            $tempZonesFrom = array();
                            $tempZonesTo = array();
                            foreach( $nat_Tto_zones as $zone )
                            {
                                if( $zone != "any" )
                                {
                                    $tempZonesFrom[] = "($security_rule_lid, '$zone', '$vsys', '$source')";

                                }
                            }

                            if( count($tempZonesFrom) > 0 )
                            {
                                $unique = array_unique($tempZonesFrom);
                                $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(",", $unique) . ";";
                                $connection->query($query);
                            }

                            foreach( $nat_Tto_zones as $zone )
                            {
                                if( $zone != "any" )
                                {
                                    $tempZonesTo[] = "($security_rule_lid, '$zone', '$vsys', '$source')";

                                }
                            }
                            if( count($tempZonesTo) > 0 )
                            {
                                $unique = array_unique($tempZonesTo);
                                $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(",", $unique) . ";";
                                $connection->query($query);
                            }
                        }
                        //Recover the DST ip before the Static NAT
                        elseif( $isSrvCovered && $isDstCovered && $isSrvCovered )
                        { //Partially Covered
                            if( count($security_rule['dst']) != 1 || (count($security_rule['dst']) == 1 && $security_rule['dst'][0] != $memberAnyAddress) )
                            {
                                // "Rule $security_rule_lid is partially covered by Static NAT $nat_rule_lid\n";
                                //Clone the rule and add a subset with the new Destinations before Nat
                                $count = isset($newRulesSNAT[$security_rule_lid]['cloned']) ? $newRulesSNAT[$security_rule_lid]['cloned'] + 1 : 0;
                                if( !isset($newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid']) )
                                {
                                    $newRulesSNAT[$security_rule_lid]['clones'][$count]['nat_lid'] = $nat_rule_lid;
                                }
                                $newRulesSNAT[$security_rule_lid]['cloned'] = $count;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['from'] = $nat_from_zones;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['to'] = $nat_to_zones;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['destinations'] = $DstMembers;
                                $newRulesSNAT[$security_rule_lid]['clones'][$count]['services'] = $servicesMatched;
                            }
                        }
                    }


                    if( count($natted_rules) > 0 )
                    {
                        $unique = array_unique($natted_rules);
                        //Remove those Security Rules from the Associative array, as they have already found a NAT match
                        removeKeysFromArray($security_rules, $unique);
                    }
                }
            }
        }

        //Free Memory
        $exploded_nat_src_Members = null;
        $exploded_nat_dst_Members = null;

        //Checking if this NAT actually affects any Security Rule or
        //  (a) it is shadowed by prior NATS
        //  (b) it is too restrictive
        if( count($natted_rules) == 0 )
        {
            $add_logs[] = "('NOW()','0', 'NAT Analysis', 'NAT Rule [$nat_rule_lid] does not affect any of the existing security rules. Or affects only ranges inside a security rule.', '$source', 'No Action Required. Suggestion to review and/or remove. If partial matching, you may consider split the security rule.', 'rules', '$nat_rule_lid', 'nat_rules')";
        }
    } //Done analysing all the NAT rules and checking the Security Rules that Match

    //Time to Insert the new Partial NATed Security Rules
    if( $vendor_type == 2 )
    {

        //Reload the new Security Rules, in case they have been modified by a NAT doing full Match
        // So we can check which ones of the Partial Matches are already covered by the original Sec Rule
        $security_rules = loadInMemorySecRules($connection, $source, $vsys);

        //***** DNATS
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='DNAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','DNAT','color1')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanDNAT = array();
        foreach( $newRulesDNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isFromCovered = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                $isToCovered = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
//                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                if( $isFromCovered * $isToCovered * $isDstCovered * $isSrvCovered > 0 )
                {
                    $add_logs[] = "('NOW()', '1', 'Correcting Destination based on DNAT', 'Security Rule[$sec_rule_lid] covers the DNAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesDNAT = $newRulesCleanDNAT;

        //Compact Rules by: From-Tp-Source-Destination
        $newRulesCleanDNAT = array();
        $removedRules = array();
        foreach( $newRulesDNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                        md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesDNAT = $newRulesCleanDNAT;

        foreach( $newRulesDNAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];

                //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'DNAT', $project);

                //Tag the cloned Rule with the DNAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_from WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $zonesFrom = array();
                if( isset($clone['from']) )
                {
                    foreach( $clone['from'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesFrom) > 0 )
                    {
                        $unique = array_unique($zonesFrom);
                        $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $query = "DELETE FROM security_rules_to WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $zonesTo = array();
                if( isset($clone['to']) )
                {
                    foreach( $clone['to'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesTo) > 0 )
                    {
                        $unique = array_unique($zonesTo);
                        $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                foreach( $clone['services'] as $srv_Member )
                {
                    if( $srv_Member != $memberAnyService )
                    {
                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                    }
                }
                if( count($services) > 0 )
                {
                    $unique = array_unique($services);
                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }
                $add_logs[] = "('NOW()','1', 'Correcting Destination based on DNAT', 'Destination address corrected to value before DNAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        //***** Static NATS
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='Static-NAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','Static-NAT','color6')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanSNAT = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isFromCovered = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                $isToCovered = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
//                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                if( $isFromCovered * $isToCovered * $isDstCovered * $isSrvCovered > 0 )
                {
                    $add_logs[] = "('NOW()', '1', 'Correcting Destination based on Static NAT', 'Security Rule[$sec_rule_lid] covers the Static NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        //Compact Rules by: From-Tp-Source-Destination
        $newRulesCleanSNAT = array();
        $removedRules = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                        md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        //Compact Rules by: From-Tp-Service
        $newRulesCleanSNAT = array();
        $removedRules = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                        md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                        md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) )
                    {
                        $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        foreach( $newRulesSNAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];

                //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'SNAT', $project);

                //Tag the cloned Rule with the SNAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_from WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $zonesFrom = array();
                if( isset($clone['from']) )
                {
                    foreach( $clone['from'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesFrom) > 0 )
                    {
                        $unique = array_unique($zonesFrom);
                        $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $query = "DELETE FROM security_rules_to WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $zonesTo = array();
                if( isset($clone['to']) )
                {
                    foreach( $clone['to'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesTo) > 0 )
                    {
                        $unique = array_unique($zonesTo);
                        $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                if( isset($clone['services']) )
                {
                    foreach( $clone['services'] as $srv_Member )
                    {
                        if( $srv_Member != $memberAnyService )
                        {
                            $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                        }
                    }
                    if( count($services) > 0 )
                    {
                        $unique = array_unique($services);
                        $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }
                $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        //***** NO-NATS
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='NO-NAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','NO-NAT','color3')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Filter out those NONAT clones that won't match
        $newRulesCleanNONAT = array();
        foreach( $newRulesNONAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];

                //Check if the TO zone contains the DST addresses
                $zones = array();
                foreach( $clone['sources'] as $sec_source )
                {
                    $member_lid = $sec_source->name;
                    $table_name = $sec_source->location;
                    if( $member_lid == 'any' )
                    {
                        $zones = array('any');
                        break;
                    }
                    else
                    {
                        $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                    }
                }
                $foundZones = array();
                if( isAinB_Zones($clone['from'], $zones, $foundZones) != 1 )
                {
                    //The sources are not in the FROM zones
                    continue;
                }

                //Check if the FROM zone contains the SRC addresses
                $zones = array();
                foreach( $clone['destinations'] as $sec_source )
                {
                    $member_lid = $sec_source->name;
                    $table_name = $sec_source->location;
                    if( $member_lid == 'any' )
                    {
                        break;
                    }
                    else
                    {
                        $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, 0);
                    }
                }
                $foundZones = array();
                if( isAinB_Zones($clone['to'], $zones, $foundZones) != 1 )
                {
                    //The destinations are not in the TO zones
                    continue;
                }

                $newRulesCleanNONAT[$sec_rule_lid] = $clones;
            }
        }

        $newRulesNONAT = $newRulesCleanNONAT;

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanNONAT = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isFromCovered = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                $isToCovered = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                $isSrcCovered = isAinB($clone['sources'], $security_rules[$sec_rule_lid]['src']);
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
//                if($isFromCovered*$isToCovered*$isSrcCovered*$isDstCovered*$isSrvCovered == 1){
                if( $isFromCovered * $isToCovered * $isSrcCovered * $isDstCovered * $isSrvCovered > 0 )
                {
                    $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NO-NAT', 'Security Rule[$sec_rule_lid] covers the NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-Tp-Service-Destination
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                        md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                        md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['sources'] = array_merge($clone['sources'], $clone2['sources']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-Tp-Source-Destination
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                        md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                        md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-To-Source-Service
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['from'])) == md5(serialize($clone2['from'])) &&
                        md5(serialize($clone['to'])) == md5(serialize($clone2['to'])) &&
                        md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                        md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) )
                    {
                        $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        foreach( $newRulesNONAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];
                $new_rule_lid = clone_security_rule("", "-1", $vsys, $source, $sec_rule_lid, 'NO-NAT', $project);

                //Tag the cloned Rule with the NO-NAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_src WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $sources = array();
                foreach( $clone['sources'] as $src_Member )
                {
                    if( $src_Member != $memberAnyAddress )
                    {
                        $sources[] = "('$new_rule_lid','$src_Member->name','$src_Member->location','$vsys','$source')";
                    }
                }
                if( count($sources) > 0 )
                {
                    $unique = array_unique($sources);
                    $query = "INSERT INTO security_rules_src (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_from WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $zonesFrom = array();
                if( isset($clone['from']) )
                {
                    foreach( $clone['from'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesFrom) > 0 )
                    {
                        $unique = array_unique($zonesFrom);
                        $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $query = "DELETE FROM security_rules_to WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $zonesTo = array();
                if( isset($clone['to']) )
                {
                    foreach( $clone['to'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesTo) > 0 )
                    {
                        $unique = array_unique($zonesTo);
                        $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                if( isset($clone['services']) )
                {
                    foreach( $clone['services'] as $srv_Member )
                    {
                        if( $srv_Member != $memberAnyService )
                        {
                            $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                        }
                    }
                    if( count($services) > 0 )
                    {
                        $unique = array_unique($services);
                        $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }
                $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NAT', 'Security Rule[$sec_rule_lid] cloned to consider NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        if( count($add_logs) > 0 )
        {
            add_log_bulk($connection, $add_logs);
        }

        updateRuleNames($projectdb, $source, $vsys, "fix_duplicates", "", "security_rules");
    }
    if( $vendor_type == 3 )
    {

        //Reload the new Security Rules, in case they have been modified by a NAT doing full Match
        // So we can check which ones of the Partial Matches are already covered by the original Sec Rule
        $security_rules = loadInMemorySecRules($connection, $source, $vsys);

        //***** DNATS
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='DNAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','DNAT','color1')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanDNAT = array();
        foreach( $newRulesDNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
//                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                if( $isFromCovered * $isToCovered * $isDstCovered * $isSrvCovered > 0 )
                {
                    $add_logs[] = "('NOW()', '1', 'Correcting Destination based on DNAT', 'Security Rule[$sec_rule_lid] covers the DNAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesDNAT = $newRulesCleanDNAT;

        //Compact Rules by: From-To-Source-Destination
        $newRulesCleanDNAT = array();
        $removedRules = array();
        foreach( $newRulesDNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesDNAT = $newRulesCleanDNAT;

        foreach( $newRulesDNAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];

                //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'DNAT', $project);

                //Tag the cloned Rule with the DNAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                foreach( $clone['services'] as $srv_Member )
                {
                    if( $srv_Member != $memberAnyService )
                    {
                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                    }
                }
                if( count($services) > 0 )
                {
                    $unique = array_unique($services);
                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }
                $add_logs[] = "('NOW()','1', 'Correcting Destination based on DNAT', 'Destination address corrected to value before DNAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        //***** Static NATS
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='Static-NAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','Static-NAT','color6')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanSNAT = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
//                if($isFromCovered*$isToCovered*$isDstCovered*$isSrvCovered == 1){
                if( $isDstCovered * $isSrvCovered > 0 )
                {
                    $add_logs[] = "('NOW()', '1', 'Correcting Destination based on Static NAT', 'Security Rule[$sec_rule_lid] covers the Static NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        //Compact Rules by: From-Tp-Source-Destination
        $newRulesCleanSNAT = array();
        $removedRules = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        //Compact Rules by: From-Tp-Service
        $newRulesCleanSNAT = array();
        $removedRules = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) )
                    {
                        $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        foreach( $newRulesSNAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];

                //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'SNAT', $project);

                //Tag the cloned Rule with the SNAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                if( isset($clone['services']) )
                {
                    foreach( $clone['services'] as $srv_Member )
                    {
                        if( $srv_Member != $memberAnyService )
                        {
                            $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                        }
                    }
                    if( count($services) > 0 )
                    {
                        $unique = array_unique($services);
                        $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }
                $add_logs[] = "('NOW()','1', 'Correcting Destination based on Static NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        //***** NO-NATS
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='NO-NAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','NO-NAT','color3')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanNONAT = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isSrcCovered = isAinB($clone['sources'], $security_rules[$sec_rule_lid]['src']);
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
//                if($isFromCovered*$isToCovered*$isSrcCovered*$isDstCovered*$isSrvCovered == 1){
                if( $isSrcCovered * $isDstCovered * $isSrvCovered > 0 )
                {
                    $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NO-NAT', 'Security Rule[$sec_rule_lid] covers the NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-Tp-Service-Destination
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['sources'] = array_merge($clone['sources'], $clone2['sources']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-Tp-Source-Destination
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-To-Source-Service
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                        md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) )
                    {
                        $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        foreach( $newRulesNONAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];
                $new_rule_lid = clone_security_rule("", "-1", $vsys, $source, $sec_rule_lid, 'NO-NAT', $project);

                //Tag the cloned Rule with the NO-NAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_src WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $sources = array();
                foreach( $clone['sources'] as $src_Member )
                {
                    if( $src_Member != $memberAnyAddress )
                    {
                        $sources[] = "('$new_rule_lid','$src_Member->name','$src_Member->location','$vsys','$source')";
                    }
                }
                if( count($sources) > 0 )
                {
                    $unique = array_unique($sources);
                    $query = "INSERT INTO security_rules_src (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                if( isset($clone['services']) )
                {
                    foreach( $clone['services'] as $srv_Member )
                    {
                        if( $srv_Member != $memberAnyService )
                        {
                            $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                        }
                    }
                    if( count($services) > 0 )
                    {
                        $unique = array_unique($services);
                        $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }
                $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NAT', 'Security Rule[$sec_rule_lid] cloned to consider NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        if( count($add_logs) > 0 )
        {
            add_log_bulk($connection, $add_logs);
        }

        updateRuleNames($projectdb, $source, $vsys, "fix_duplicates", "", "security_rules");
    }
    if( $vendor_type == 4 )
    {
        //Fixing zones of Security Rules that did not match any Nat Rule
        echo "Calculating the zone for those rules that did not make any match\n";
        $rules = array();
        foreach( $security_rules as $key => $value )
        {
            $rules[] = $key;
        }
        set_Zones_Security_Rules_noNat($rules, $source, $vsys, $vr, $ipMapping);
        //Done Calculating zones of Security Rules that did not match any Nat Rule

        echo "Going to insert the new partial matches\n";
        //Reload the new Security Rules, in case they have been modified by a NAT doing full Match
        // So we can check which ones of the Partial Matches are already covered by the original Sec Rule
        $security_rules = loadInMemorySecRules($connection, $source, $vsys);

        //***** DNATS
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='DNAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','DNAT','color1')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        echo "Inserting DNAT affected Rules\n";
        $newRulesCleanDNAT = array();
        foreach( $newRulesDNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isFromCovered = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                $isToCovered = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
                if( $isFromCovered * $isToCovered * $isDstCovered * $isSrvCovered == 1 )
                {
//                if($isDstCovered*$isSrvCovered > 0){
                    $add_logs[] = "('NOW()', '1', 'Correcting Destination based on DNAT', 'Security Rule[$sec_rule_lid] covers the DNAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesDNAT = $newRulesCleanDNAT;

        //Compact Rules by: Source-Service
        $newRulesCleanDNAT = array();
        $removedRules = array();
        foreach( $newRulesDNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) )
                    {
                        $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanDNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesDNAT = $newRulesCleanDNAT;

        foreach( $newRulesDNAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];

                //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'DNAT', $project);

                //TODO: Make those Delete and Insert as unique queries
                //Tag the cloned Rule with the DNAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                foreach( $clone['services'] as $srv_Member )
                {
                    if( $srv_Member != $memberAnyService )
                    {
                        $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                    }
                }
                if( count($services) > 0 )
                {
                    $unique = array_unique($services);
                    $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }


                //Adding the From Zone
                $zonesFrom = array();
                if( isset($clone['from']) )
                {
                    foreach( $clone['from'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesFrom) > 0 )
                    {
                        $unique = array_unique($zonesFrom);
                        $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                //Adding the To Zone
                $zonesTo = array();
                if( isset($clone['to']) )
                {
                    foreach( $clone['to'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesTo) > 0 )
                    {
                        $unique = array_unique($zonesTo);
                        $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $add_logs[] = "('NOW()','1', 'Correcting Destination, Zone From and Zone To based on DNAT', 'Destination address corrected to value before DNAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        //***** Static NATS
        echo "Inserting Static-NAT affected Rules\n";
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='Static-NAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','Static-NAT','color6')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanSNAT = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isFromCovered = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                $isToCovered = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
                if( $isFromCovered * $isToCovered * $isDstCovered * $isSrvCovered == 1 )
                {
//                if($isDstCovered*$isSrvCovered > 0){
                    $add_logs[] = "('NOW()', '1', 'Correcting Destination based on Static NAT', 'Security Rule[$sec_rule_lid] covers the Static NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue;
                }
                else
                {
                    $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        //Compact Rules by: From-Tp-Source-Destination
        $newRulesCleanSNAT = array();
        $removedRules = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        //Compact Rules by: From-Tp-Service
        $newRulesCleanSNAT = array();
        $removedRules = array();
        foreach( $newRulesSNAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) )
                    {
                        $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanSNAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesSNAT = $newRulesCleanSNAT;

        foreach( $newRulesSNAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];

                //DO NOT Check if the FROM zone contains the SRC addresses. The Zone is AfterNAT!!

                $new_rule_lid = clone_security_rule("", "", $vsys, $source, $sec_rule_lid, 'SNAT', $project);

                //Tag the cloned Rule with the SNAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                if( isset($clone['services']) )
                {
                    foreach( $clone['services'] as $srv_Member )
                    {
                        if( $srv_Member != $memberAnyService )
                        {
                            $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                        }
                    }
                    if( count($services) > 0 )
                    {
                        $unique = array_unique($services);
                        $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                //Adding the From Zone
                $zonesFrom = array();
                if( isset($clone['from']) )
                {
                    foreach( $clone['from'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesFrom) > 0 )
                    {
                        $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $zonesFrom) . ";";
                        $connection->query($query);
                    }
                }

                //Adding the To Zone
                $zonesTo = array();
                if( isset($clone['to']) )
                {
                    foreach( $clone['to'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesTo) > 0 )
                    {
                        $unique = array_unique($zonesTo);
                        $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $add_logs[] = "('NOW()','1', 'Correcting Destination, Zone From and Zone To based on Static Bidirectional NAT', 'Destination address corrected to value before Static NAT, based on Sec. Rule[$sec_rule_lid] and NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        //***** NO-NATS
        echo "Inserting No-NAT affected Rules\n";
        $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='NO-NAT'";
        $result = $connection->query($query);
        if( $result->num_rows == 0 )
        {
            $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','NO-NAT','color3')";
            $connection->query($query);
            $tag_id = $connection->insert_id;
        }
        else
        {
            $data = $result->fetch_assoc();
            $tag_id = $data['id'];
        }

        //Check which rules are already covered by the original Security Rule
        $newRulesCleanNONAT = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                $isFromCovered = isAinB_Zones($clone['from'], $security_rules[$sec_rule_lid]['from']);
                $isToCovered = isAinB_Zones($clone['to'], $security_rules[$sec_rule_lid]['to']);
                $isSrcCovered = isAinB($clone['sources'], $security_rules[$sec_rule_lid]['src']);
                $isDstCovered = isAinB($clone['destinations'], $security_rules[$sec_rule_lid]['dst']);
                $isSrvCovered = isAinB_service($clone['services'], $security_rules[$sec_rule_lid]['srv']);
                $nat_rule_lid = $clone['nat_lid'];
                if( $isFromCovered * $isToCovered * $isSrcCovered * $isDstCovered * $isSrvCovered == 1 )
                {
//                if($isSrcCovered*$isDstCovered*$isSrvCovered > 0){
                    $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses based on NO-NAT', 'Security Rule[$sec_rule_lid] covers the NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$sec_rule_lid', 'security_rules')";
                    continue 1;
                }
                else
                {
                    $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
                }
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-Tp-Service-Destination
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['sources'] = array_merge($clone['sources'], $clone2['sources']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-Tp-Source-Destination
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                        md5(serialize($clone['destinations'])) == md5(serialize($clone2['destinations'])) )
                    {
                        $clone['services'] = array_merge($clone['services'], $clone2['services']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        //Compact Rules by: From-To-Source-Service
        $newRulesCleanNONAT = array();
        $removedRules = array();
        foreach( $newRulesNONAT as $sec_rule_lid => &$clones )
        {
            foreach( $clones['clones'] as $id => &$clone )
            {
                if( isset($removedRules[$sec_rule_lid]) && in_array($id, $removedRules[$sec_rule_lid]) )
                {
                    continue;
                }
                foreach( $clones['clones'] as $id2 => &$clone2 )
                {
                    if( $id == $id2 || (isset($removedRules[$sec_rule_lid]) && in_array($id2, $removedRules[$sec_rule_lid])) )
                    {
                        continue;
                    }
                    if( md5(serialize($clone['sources'])) == md5(serialize($clone2['sources'])) &&
                        md5(serialize($clone['services'])) == md5(serialize($clone2['services'])) )
                    {
                        $clone['destinations'] = array_merge($clone['destinations'], $clone2['destinations']);
                        $clone['nat_lid'] .= "," . $clone2['nat_lid'];
                        $removedRules[$sec_rule_lid][] = $id2;
                    }
                }
                $newRulesCleanNONAT[$sec_rule_lid]['clones'][$id] = $clone;
            }
        }
        $newRulesNONAT = $newRulesCleanNONAT;

        foreach( $newRulesNONAT as $sec_rule_lid => $clones )
        {
            foreach( $clones['clones'] as $clone )
            {
                $nat_rule_lid = $clone['nat_lid'];
                $new_rule_lid = clone_security_rule("", "-1", $vsys, $source, $sec_rule_lid, 'NO-NAT', $project);

                //TODO:
                //Tag the cloned Rule with the NO-NAT tag
                $query = "INSERT INTO security_rules_tag (source, vsys, member_lid, table_name, rule_lid) VALUES ('$source', '$vsys','$tag_id', 'tag', '$new_rule_lid')";
                $connection->query($query);

                $query = "DELETE FROM security_rules_src WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $sources = array();
                foreach( $clone['sources'] as $src_Member )
                {
                    if( $src_Member != $memberAnyAddress )
                    {
                        $sources[] = "('$new_rule_lid','$src_Member->name','$src_Member->location','$vsys','$source')";
                    }
                }
                if( count($sources) > 0 )
                {
                    $unique = array_unique($sources);
                    $query = "INSERT INTO security_rules_src (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_dst WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $destinations = array();
                foreach( $clone['destinations'] as $dst_Member )
                {
                    if( $dst_Member != $memberAnyAddress )
                    {
                        $destinations[] = "('$new_rule_lid','$dst_Member->name','$dst_Member->location','$vsys','$source')";
                    }
                }
                if( count($destinations) > 0 )
                {
                    $unique = array_unique($destinations);
                    $query = "INSERT INTO security_rules_dst (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                    $connection->query($query);
                }

                $query = "DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid'";
                $connection->query($query);
                $services = array();
                if( isset($clone['services']) )
                {
                    foreach( $clone['services'] as $srv_Member )
                    {
                        if( $srv_Member != $memberAnyService )
                        {
                            $services[] = "('$new_rule_lid','$srv_Member->name','$srv_Member->location','$vsys','$source')";
                        }
                    }
                    if( count($services) > 0 )
                    {
                        $unique = array_unique($services);
                        $query = "INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                //Adding the From Zone
                $zonesFrom = array();
                if( isset($clone['from']) )
                {
                    foreach( $clone['from'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesFrom[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesFrom) > 0 )
                    {
                        $query = "INSERT INTO security_rules_from (rule_lid, name, vsys, source) VALUES " . implode(',', $zonesFrom) . ";";
                        $connection->query($query);
                    }
                }

                //Adding the To Zone
                $zonesTo = array();
                if( isset($clone['to']) )
                {
                    foreach( $clone['to'] as $zone )
                    {
                        if( $zone != "any" )
                        {
                            $zonesTo[] = "('$new_rule_lid','$zone','$vsys','$source')";
                        }
                    }
                    if( count($zonesTo) > 0 )
                    {
                        $unique = array_unique($zonesTo);
                        $query = "INSERT INTO security_rules_to (rule_lid, name, vsys, source) VALUES " . implode(',', $unique) . ";";
                        $connection->query($query);
                    }
                }

                $add_logs[] = "('NOW()', '1', 'Correcting Security Addresses and Zones based on NO-NAT', 'Security Rule[$sec_rule_lid] cloned to consider NO-NAT Rule(s)[$nat_rule_lid].', '$source', 'No Action required', 'rules', '$new_rule_lid', 'security_rules')";
            }
        }

        if( count($add_logs) > 0 )
        {
            add_log_bulk($connection, $add_logs);
        }

        updateRuleNames($projectdb, $source, $vsys, "fix_duplicates", "", "security_rules");
    }
}

function set_Zones_Security_Rules_noNat(array $rules = null, $source, $vsys, $vr, &$ipMapping)
{
    global $projectdb;
    $devicegroup = '';

    $security_rules_from = array();
    $security_rules_to = array();

    if( count($ipMapping) == 0 )
    {
        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    }

    if( is_null($rules) || count($rules) == 0 )
    {
        //$querySRC = "SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE source='$source' AND vsys='$vsys';";
        //$queryDST = "SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE source='$source' AND vsys='$vsys';";
        $querySRC = "SELECT rule_lid,member_lid,table_name FROM security_rules_src;";
        $queryDST = "SELECT rule_lid,member_lid,table_name FROM security_rules_dst;";
    }
    else
    {
        $querySRC = "SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE rule_lid IN (" . implode(',', $rules) . ");";
        $queryDST = "SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE rule_lid IN (" . implode(',', $rules) . ");";
    }

    //Zones FROM
    $getSRC = $projectdb->query($querySRC);
    if( $getSRC->num_rows > 0 )
    {
        while( $getSRCData = $getSRC->fetch_assoc() )
        {
            $member_lid = $getSRCData['member_lid'];
            $table_name = $getSRCData['table_name'];
            $rule_lid = $getSRCData['rule_lid'];

            $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM security_rules WHERE id = '$rule_lid';");
            if( $getDeviceGroup->num_rows > 0 )
            {
                $getINData = $getDeviceGroup->fetch_assoc();
                $devicegroup = $getINData['devicegroup'];
            }

            $negate_source = 0;

            $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);

            foreach( $zones as $zone )
            {
                $security_rules_from[] = "('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup')";
            }
        }
    }

    //Zones TO
    $getDST = $projectdb->query($queryDST);
    if( $getDST->num_rows > 0 )
    {
        while( $getDSTData = $getDST->fetch_assoc() )
        {
            $member_lid = $getDSTData['member_lid'];
            $table_name = $getDSTData['table_name'];
            $rule_lid = $getDSTData['rule_lid'];

            $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM security_rules WHERE id = '$rule_lid';");
            if( $getDeviceGroup->num_rows > 0 )
            {
                $getINData = $getDeviceGroup->fetch_assoc();
                $devicegroup = $getINData['devicegroup'];
            }

            $negate_source = 0;

            $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
            //$zones = getAutoZoneToVR($vr, $member_lid, $table_name, $vsys, $source);
            foreach( $zones as $zone )
            {
                $security_rules_to[] = "('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup')";
            }
        }
    }

    $security_rules_to = array_unique($security_rules_to);
    $security_rules_from = array_unique($security_rules_from);
    if( count($security_rules_to) > 0 )
    {
        $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) VALUES " . implode(',', $security_rules_to));
    }
    if( count($security_rules_from) > 0 )
    {
        $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) VALUES " . implode(',', $security_rules_from));
    }
}


function updateRuleNames(mysqli $project, STRING $source, STRING $vsys, STRING $type, $ids, $table_name)
{

    $message = null;

    $vsys_sql = '';
    $ids_sql = '';
    if( $vsys != "all" )
    {
        $vsys_sql = " AND vsys = '$vsys' ";
    }

    if( $ids != "" )
    {
        $ids_sql = " AND id IN ($ids) ";
    }

    switch ($type)
    {

        case "clean_all":

            $project->query("UPDATE $table_name SET name='' WHERE source='$source' $vsys_sql $ids_sql;");
            $message = [
                "code" => TRUE
            ];
            break;

        case "auto_name":

            $x = 1;
            $getRules = $project->query("SELECT id FROM $table_name WHERE source='$source' $vsys_sql $ids_sql AND name='' ORDER BY position ASC;");
            if( $getRules->num_rows > 0 )
            {
                while( $getRulesData = $getRules->fetch_assoc() )
                {
                    $rule_lid = $getRulesData['id'];
                    $rulename = "Rule " . $x;
                    $project->query("UPDATE $table_name SET name='$rulename' WHERE id='$rule_lid';");
                    $x++;
                }
            }
            $message = [
                "code" => TRUE
            ];
            break;

        case "fix_duplicates":

            $getRulesDup = $project->query("SELECT name,count(id) as t FROM $table_name WHERE source='$source' $vsys_sql $ids_sql GROUP BY name HAVING t>1;");
            if( $getRulesDup->num_rows > 0 )
            {
                $c = 'a';

                $max_length_rule_name = getMaxLengthRuleName($source);
                $max_length_rule_name_more_number = $max_length_rule_name - 2;

                while( $data = $getRulesDup->fetch_assoc() )
                {
                    $originalName = $data['name'];
                    $getRules = $project->query("SELECT id FROM $table_name WHERE source='$source' $vsys_sql $ids_sql AND name='$originalName';");
                    $amount = $getRules->num_rows;
                    $lengthNumber = ceil(log10($amount));
                    //if((strlen($originalName)+$lengthNumber)>29){
                    if( (strlen($originalName) + $lengthNumber) > $max_length_rule_name_more_number )
                    {
                        //$originalName = mb_strimwidth($originalName, 0,31-$lengthNumber-2);
                        $originalName = mb_strimwidth($originalName, 0, $max_length_rule_name - $lengthNumber - 2);
                    }
                    //if ($getRules->num_rows>0){
                    $x = 0;
                    while( $getRulesData = $getRules->fetch_assoc() )
                    {
                        $theid = $getRulesData['id'];
                        if( $x == 0 )
                        {
                        }
                        else
                        {
                            $x = sprintf("%0" . $lengthNumber . "d", $x);
                            $newName = $originalName . "_" . $c . $x;
                            $project->query("UPDATE $table_name SET name='$newName' WHERE id='$theid';");
                        }
                        $x++;
                    }
                    //}
                    $c++;
                }
            }
            $message = [
                "code" => TRUE
            ];
            break;

        default:
            $message = [
                "code" => FALSE,
                "msg" => "Option $type not recognized"
            ];
            break;
    }

    return $message;
}


function loadInMemorySecRules(mysqli $connection, STRING $source, STRING $vsys)
{
    $security_rules = array();

    $number_of_rules = $connection->query("SELECT id, negate_source, negate_destination FROM security_rules WHERE source='$source' AND vsys='$vsys';");
    if( $number_of_rules->num_rows > 0 )
    {
        while( $getINData = $number_of_rules->fetch_assoc() )
        {
            $id = $getINData['id'];
            $ids[] = $getINData['id'];
            $security_rules[$id]['negate_src'] = $getINData['negate_source'];
            $security_rules[$id]['negate_dst'] = $getINData['negate_destination'];
            $security_rules[$id]['src'] = array();    //List of Members that are sources
            $security_rules[$id]['dst'] = array();    //List of Members that are destinations
            $security_rules[$id]['from'] = array();
            $security_rules[$id]['to'] = array();
            $security_rules[$id]['srv'] = array();
            $security_rules[$id]['modified'] = FALSE; //Flag to mark if this rule has been corrected or not
        }
    }

    //Get all the Security_Rules Sources and Destinations and group them by Rule_lid
    //$getRulesSrc = $connection->query("SELECT member_lid, table_name, rule_lid FROM security_rules_src WHERE source='$source' AND vsys='$vsys';");
    $getRulesSrc = $connection->query("SELECT member_lid, table_name, rule_lid FROM security_rules_src WHERE rule_lid IN (" . implode(",", $ids) . ");");
    if( $getRulesSrc->num_rows > 0 )
    {
        while( $getINData = $getRulesSrc->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $security_rules[$rule_lid]['src'][] = $member;
        }
    }

    $getRulesDst = $connection->query("SELECT member_lid, table_name, rule_lid FROM security_rules_dst WHERE rule_lid IN (" . implode(",", $ids) . ");");
    if( $getRulesDst->num_rows > 0 )
    {
        while( $getINData = $getRulesDst->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $security_rules[$rule_lid]['dst'][] = $member;
        }
    }

    $getRulesDst = $connection->query("SELECT member_lid, table_name, rule_lid FROM security_rules_srv WHERE rule_lid IN (" . implode(",", $ids) . ");");
    if( $getRulesDst->num_rows > 0 )
    {
        while( $getINData = $getRulesDst->fetch_assoc() )
        {
            $member_lid = $getINData['member_lid'];
            $table_name = $getINData['table_name'];
            $rule_lid = $getINData['rule_lid'];
            $member = new MemberObject($member_lid, $table_name);
            $security_rules[$rule_lid]['srv'][] = $member;
        }
    }

    $getRulesDst = $connection->query("SELECT name, rule_lid FROM security_rules_from WHERE rule_lid IN (" . implode(",", $ids) . ");");
    if( $getRulesDst->num_rows > 0 )
    {
        while( $getINData = $getRulesDst->fetch_assoc() )
        {
            $zoneName = $getINData['name'];
            $rule_lid = $getINData['rule_lid'];
            $security_rules[$rule_lid]['from'][] = $zoneName;
        }
    }

    $getRulesDst = $connection->query("SELECT name, rule_lid FROM security_rules_to WHERE rule_lid IN (" . implode(",", $ids) . ");");
    if( $getRulesDst->num_rows > 0 )
    {
        while( $getINData = $getRulesDst->fetch_assoc() )
        {
            $zoneName = $getINData['name'];
            $rule_lid = $getINData['rule_lid'];
            $security_rules[$rule_lid]['to'][] = $zoneName;
        }
    }


    //Expand the Members that we have founds for each rule
    foreach( $security_rules as $key => &$security_rule )
    {
        if( $security_rule['negate_src'] == '1' )
        {
            $explodedSrc = explodeGroups2Members($security_rule['src'], $connection, $source, $vsys);
            $security_rule['src'] = negateAddress($connection, $explodedSrc);
        }
        else
        {
            $security_rule['src'] = explodeGroups2Members($security_rule['src'], $connection, $source, $vsys);
        }

        if( $security_rule['negate_dst'] == '1' )
        {
            $explodedDst = explodeGroups2Members($security_rule['dst'], $connection, $source, $vsys);
            $security_rule['dst'] = negateAddress($connection, $explodedDst);
        }
        else
        {
            $security_rule['dst'] = explodeGroups2Members($security_rule['dst'], $connection, $source, $vsys);
        }

        $security_rule['srv'] = explodeGroups2Services($security_rule['srv'], $connection, $source, $vsys);
    }

    //Some rules did not get any specific source or destination. Those were ANY. Let's fill it with the ANY member
    $memberAnyAddress = new MemberObject('', '', '0.0.0.0', '0');
    $memberAnyService = new MemberObject('', '', '0-65535', 'any');
    foreach( $security_rules as &$security_rule )
    {
        if( count($security_rule['src']) == 0 )
        {
            $security_rule['src'][] = $memberAnyAddress;
        }
        if( count($security_rule['dst']) == 0 )
        {
            $security_rule['dst'][] = $memberAnyAddress;
        }
        if( count($security_rule['srv']) == 0 )
        {
            $security_rule['srv'][] = $memberAnyService;
        }
        if( count($security_rule['from']) == 0 )
        {
            $security_rule['from'][] = "any";
        }
        if( count($security_rule['to']) == 0 )
        {
            $security_rule['to'][] = "any";
        }
    }

    return $security_rules;
}


function clean_duplicated_members_on_rules($table)
{
    global $projectdb;
    $getDup = $projectdb->query("SELECT id,count(id) as t FROM $table GROUP BY rule_lid, member_lid, table_name HAVING t>1;");
    if( $getDup->num_rows > 0 )
    {
        $id = array();
        while( $data = $getDup->fetch_assoc() )
        {
            $id[] = $data['id'];
        }
        $projectdb->query("DELETE FROM $table WHERE id IN (" . implode(",", $id) . ")");
    }
}


function replace_addressgroups_by_members($vsys, $source, $rule_lid, $rules, $table_name)
{

    global $projectdb;

    if( $rules == "security" )
    {

        $getSRV = $projectdb->query("SELECT id, member_lid, table_name, devicegroup FROM $table_name 
                                     WHERE rule_lid = '$rule_lid' AND table_name = 'address_groups_id';");
        if( $getSRV->num_rows > 0 )
        {
            while( $getSRVData = $getSRV->fetch_object() )
            {
                $originID = $getSRVData->id;
                $member_lid = $getSRVData->member_lid;
                $devicegroup = $getSRVData->devicegroup;

                $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid = '$member_lid';");
                if( $getMembers->num_rows > 0 )
                {
                    while( $getMembersData = $getMembers->fetch_object() )
                    {
                        $projectdb->query("INSERT INTO $table_name (rule_lid, member_lid, table_name, source, vsys, devicegroup) 
                              VALUES ('$rule_lid', '$getMembersData->member_lid', '$getMembersData->table_name', '$source', '$vsys', '$devicegroup');");
                    }
                }
                $projectdb->query("DELETE FROM $table_name WHERE id = '$originID';");
                clean_duplicated_members_on_rules($table_name);
            }
        }
    }
}


function replace_servicegroups_by_members($vsys, $source, $rule_lid, $rules)
{

    global $projectdb;

    if( $rules == "security" )
    {

        $getSRV = $projectdb->query("SELECT id, member_lid, table_name, devicegroup FROM security_rules_srv 
                                     WHERE rule_lid = '$rule_lid' AND table_name = 'services_groups_id';");
        if( $getSRV->num_rows > 0 )
        {
            while( $getSRVData = $getSRV->fetch_object() )
            {
                $originID = $getSRVData->id;
                $member_lid = $getSRVData->member_lid;
                $devicegroup = $getSRVData->devicegroup;

                $getMembers = $projectdb->query("SELECT member_lid, table_name FROM services_groups WHERE lid = '$member_lid';");
                if( $getMembers->num_rows > 0 )
                {
                    while( $getMembersData = $getMembers->fetch_object() )
                    {
                        $projectdb->query("INSERT INTO security_rules_srv (rule_lid, member_lid, table_name, source, vsys, devicegroup) 
                              VALUES ('$rule_lid', '$getMembersData->member_lid', '$getMembersData->table_name', '$source', '$vsys', '$devicegroup');");
                    }
                }
                $projectdb->query("DELETE FROM security_rules_srv WHERE id = '$originID';");
                clean_duplicated_members_on_rules("security_rules_srv");
            }
        }
    }
}

/*function getSecurityIdsBySourceVsys($source, $vsys){

    global $projectdb;

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

    $sec_query = "SELECT id FROM security_rules WHERE source = '$source' $sql_vsys;";
    $result = $projectdb->query($sec_query);
    //echo $sec_query;
    $ids = array();
    if($result->num_rows >0){
        while($data = $result->fetch_assoc()){
            $ids[] = $data['id'];
        }
    }

    return $ids;
}


function getNatIdsBySourceVsys($source, $vsys){

    global $projectdb;

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

    $sec_query = "SELECT id FROM nat_rules WHERE source = '$source' $sql_vsys;";
    $result = $projectdb->query($sec_query);
    //echo $sec_query;
    $ids = array();
    if($result->num_rows >0){
        while($data = $result->fetch_assoc()){
            $ids[] = $data['id'];
        }
    }

    return $ids;
}*/