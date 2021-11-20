<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
 * Copyright (c) 2019, Palo Alto Networks Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

class RuleCallContext extends CallContext
{

    public static $commonActionFunctions = array();
    public static $supportedActions = array();

    static public function prepareSupportedActions()
    {
        $tmpArgs = array();
        foreach( self::$supportedActions as &$arg )
        {
            $tmpArgs[strtolower($arg['name'])] = $arg;
        }
        ksort($tmpArgs);
        self::$supportedActions = $tmpArgs;
    }

    public function addRuleToMergedApiChange($setValue)
    {
        $rule = $this->object;

        if( !isset($this->mergeArray) )
            $this->mergeArray = array();

        $mergeArray = &$this->mergeArray;
        $panoramaMode = $this->baseObject->isPanorama();
        $subSystem = $this->subSystem;


        $classToType = array('SecurityRule' => 'security', 'NatRule' => 'nat',);
        $type = $classToType[get_class($rule)];

        if( !$panoramaMode )
        {
            $mergeArray[$subSystem->name()][$type][$rule->name()] = $setValue;
            return;
        }

        $ruleLocation = 'pre-rulebase';
        if( $rule->isPostRule() )
            $ruleLocation = 'post-rulebase';

        if( $rule->owner->owner->isPanorama() )
            $mergeArray['shared'][$ruleLocation][$type][$rule->name()] = $setValue;
        else
            $mergeArray[$subSystem->name()][$ruleLocation][$type][$rule->name()] = $setValue;
    }


    public function generateRuleMergedApiChangeString($forSharedRules = FALSE)
    {

        if( !isset($this->mergeArray) )
            return null;

        $mergeArray = &$this->mergeArray;

        if( count($mergeArray) < 1 )
            return null;

        if( $this->baseObject->isPanorama() )
        {
            $strPointer = '';

            if( $forSharedRules && !isset($mergeArray['shared']) )
                return null;

            foreach( $mergeArray as $subSystemName => &$locations )
            {
                if( $subSystemName == 'shared' )
                {
                    if( !$forSharedRules )
                        continue;
                }
                else
                {
                    if( $forSharedRules )
                        continue;
                }

                if( !$forSharedRules )
                    $strPointer .= "<entry name=\"{$subSystemName}\">";

                foreach( $locations as $locationName => &$types )
                {
                    $strPointer .= "<{$locationName}>";

                    foreach( $types as $typeName => &$rules )
                    {
                        $strPointer .= "<{$typeName}><rules>\n";

                        foreach( $rules as $ruleName => $xmlValue )
                        {
                            $strPointer .= "<entry name=\"{$ruleName}\">{$xmlValue}</entry>\n";
                        }

                        $strPointer .= "</rules></{$typeName}>\n";
                    }

                    $strPointer .= "</{$locationName}>";
                }

                if( !$forSharedRules )
                    $strPointer .= "</entry>";
            }

            if( $forSharedRules )
                return $strPointer;

            if( strlen($strPointer) < 1 )
                return null;

            return '<device-group>' . $strPointer . '</device-group>';
        }
        elseif( !$forSharedRules )
        {
            if( count($mergeArray) < 1 )
                return null;

            $xml = '<vsys>';
            foreach( $mergeArray as $subSystemName => &$types )
            {
                $xml .= "<entry name=\"{$subSystemName}\"><rulebase>";

                foreach( $types as $typeName => &$rules )
                {
                    $xml .= "<{$typeName}><rules>\n";

                    foreach( $rules as $ruleName => $xmlValue )
                    {
                        $xml .= "<entry name=\"{$ruleName}\">{$xmlValue}</entry>\n";
                    }

                    $xml .= "</rules></{$typeName}>\n";
                }

                $xml .= "</rulebase></entry>";
            }
            $xml .= '</vsys>';

            return $xml;
        }
        return null;
    }

    public function doBundled_API_Call()
    {
        $setString = $this->generateRuleMergedApiChangeString(TRUE);
        if( $setString !== null )
        {
            $text = $this->padding . ' - sending API call for SHARED... ';
            $this->connector->sendSetRequest('/config/shared', $setString);

            PH::print_stdout( $text );
        }
        $setString = $this->generateRuleMergedApiChangeString(FALSE);
        if( $setString !== null )
        {
            $text = $this->padding . ' - sending API call for Device-Groups/VSYS... ';
            $this->connector->sendSetRequest("/config/devices/entry[@name='localhost.localdomain']", $setString);

            PH::print_stdout( $text );
        }
    }

    public function clearPolicyAppUsageDATA_doBundled_API_Call($uuid_array)
    {
        if( $this->connector->info_PANOS_version_int >= 90 )
        {
            $cmd = '<clear><policy-app-usage-data>';
            foreach( $uuid_array as $uuid )
            {
                $cmd .= '<ruleuuid>' . $uuid . '</ruleuuid>';
            }
            $cmd .= '</policy-app-usage-data></clear>';
            $res = $this->connector->sendOpRequest($cmd, TRUE);
            ///api/?type=op&cmd=<clear><policy-app-usage-data><ruleuuid></ruleuuid></policy-app-usage-data></clear>
        }
        else
        {
            PH::print_stdout("  PAN-OS version must be 9.0 or higher" );
        }
    }

    private function enclose($value, $nowrap = TRUE)
    {
        $output = '';

        if( is_string($value) )
            $output = htmlspecialchars($value);
        elseif( is_array($value) )
        {
            $output = '';
            $first = TRUE;
            foreach( $value as $subValue )
            {
                if( !$first )
                {
                    $output .= '<br />';
                }
                else
                    $first = FALSE;

                if( is_string($subValue) )
                    $output .= htmlspecialchars($subValue);
                else
                    $output .= htmlspecialchars($subValue->name());
            }
        }
        else
            derr('unsupported');

        if( $nowrap )
            return '<td style="white-space: nowrap">' . $output . '</td>';

        return "<td>{$output}</td>";
    }

    /**
     * @param Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
     * @param $fieldName
     * @return string
     */
    public function ruleFieldHtmlExport($rule, $fieldName, $wrap = TRUE)
    {
        if( $fieldName == 'location' )
        {
            if( $rule->owner->owner->isPanorama() || $rule->owner->owner->isFirewall() )
                return self::enclose('shared');
            return self::enclose($rule->owner->owner->name(), $wrap);
        }

        if( $fieldName == 'name' )
            return self::enclose($rule->name(), $wrap);

        if( $fieldName == 'description' )
            return self::enclose($rule->description(), $wrap);

        if( $fieldName == 'schedule' )
        {
            if( !$rule->isSecurityRule() )
                return self::enclose('');
            $schedule = $rule->schedule();
            if( $schedule == null )
                return self::enclose('');

            if( strlen($schedule->name()) > 0 )
                return self::enclose($schedule->name(), $wrap);
            else
                return self::enclose('');
        }

        if( $fieldName == 'schedule_resolved_sum' )
        {
            $port_mapping_text = $this->ScheduleResolveSummary( $rule, true );
            return self::enclose($port_mapping_text);
        }


        if( $fieldName == 'tags' )
            return self::enclose($rule->tags->getAll(), $wrap);

        if( $fieldName == 'type' )
            return self::enclose($rule->ruleNature(), $wrap);

        if( $fieldName == 'from' )
        {
            if( $rule->from->isAny() )
                return self::enclose('any');
            return self::enclose($rule->from->getAll(), $wrap);
        }

        if( $fieldName == 'to' )
        {
            if( $rule->isPbfRule() && $rule->isInterfaceBased() )
                return self::enclose($rule->to->getAll(), $wrap);

            if( $rule->isPbfRule() )
                return self::enclose('---');

            if( $rule->to->isAny() )
                return self::enclose('any');

            return self::enclose($rule->to->getAll(), $wrap);
        }

        if( $fieldName == 'source_negated' )
        {
            if( !method_exists($rule, 'sourceIsNegated') || !$rule->sourceIsNegated() )
                return self::enclose('no');

            return self::enclose('yes');
        }

        if( $fieldName == 'destination_negated' )
        {
            if( !method_exists($rule, 'destinationIsNegated') || !$rule->destinationIsNegated() )
                return self::enclose('no');

            return self::enclose('yes');
        }

        if( $fieldName == 'source' )
        {
            if( $rule->source->isAny() )
                return self::enclose('any');
            return self::enclose($rule->source->getAll(), $wrap);
        }

        if( $fieldName == 'destination' )
        {
            if( $rule->destination->isAny() )
                return self::enclose('any');
            return self::enclose($rule->destination->getAll(), $wrap);
        }

        if( $fieldName == 'service' )
        {
            if( $rule->isDecryptionRule() )
                return self::enclose('');
            if( $rule->isAppOverrideRule() )
                return self::enclose($rule->ports());
            if( $rule->isNatRule() )
            {
                if( $rule->service !== null )
                    return self::enclose(array($rule->service));
                return self::enclose('any');
            }
            if( $rule->services->isAny() )
                return self::enclose('any');
            if( $rule->services->isApplicationDefault() )
                return self::enclose('application-default');
            return self::enclose($rule->services->getAll(), $wrap);
        }

        if( $fieldName == 'service_resolved_sum' )
        {
            $port_mapping_text = $this->ServiceResolveSummary( $rule );
            return self::enclose($port_mapping_text);
        }

        if( $fieldName == 'application' )
        {
            if( !$rule->isSecurityRule() )
                return self::enclose('');

            if( $rule->apps->isAny() )
                return self::enclose('any');

            return self::enclose($rule->apps->getAll(), $wrap);
        }

        if( $fieldName == 'application_resolved_sum' )
        {
            $port_mapping_text = $this->ApplicationResolveSummary( $rule, true );
            return self::enclose($port_mapping_text);
        }

        if( $fieldName == 'security-profile' )
        {
            if( !$rule->isSecurityRule() )
                return self::enclose('');

            if( $rule->securityProfileType() == 'none' )
                return self::enclose('');

            if( $rule->securityProfileType() == 'group' )
                return self::enclose('group:' . $rule->securityProfileGroup(), $wrap);

            $profiles = array();

            foreach( $rule->securityProfiles() as $profType => $profName )
                $profiles[] = $profType . ':' . $profName;

            return self::enclose($profiles, $wrap);
        }

        if( $fieldName == 'action' )
        {
            if( !$rule->isSecurityRule() && !$rule->isCaptivePortalRule() )
                return self::enclose('');

            return self::enclose(array($rule->action()));
        }

        if( $fieldName == 'src-user' )
        {
            if( $rule->isSecurityRule() || $rule->isPbfRule() || $rule->isDecryptionRule() )
            {
                if( $rule->userID_IsCustom() )
                    return self::enclose($rule->userID_getUsers(), $wrap);

                return self::enclose($rule->userID_type(), $wrap);
            }

            return self::enclose('');
        }

        if( $fieldName == 'log_start' )
        {
            if( !$rule->isSecurityRule() )
                return self::enclose('');
            return self::enclose(boolYesNo($rule->logStart()), $wrap);
        }
        if( $fieldName == 'log_end' )
        {
            if( !$rule->isSecurityRule() )
                return self::enclose('');
            return self::enclose(boolYesNo($rule->logEnd()), $wrap);
        }

        if( $fieldName == 'log_profile' )
        {
            if( !$rule->isSecurityRule() )
                return self::enclose('');

            return self::enclose(boolYesNo($rule->logSetting()), $wrap);
        }

        if( $fieldName == 'log_profile_name' )
        {
            if( !$rule->isSecurityRule() )
                return self::enclose('');

            if( $rule->logSetting() === FALSE )
                return self::enclose( '');

            return self::enclose($rule->logSetting());
        }

        if( $fieldName == 'snat_type' )
        {
            if( !$rule->isNatRule() )
                return self::enclose('');
            return self::enclose($rule->SourceNat_Type(), $wrap);
        }
        if( $fieldName == 'snat_address' )
        {
            if( !$rule->isNatRule() )
                return self::enclose('');
            return self::enclose($rule->snathosts->getAll(), $wrap);
        }
        if( $fieldName == 'dnat_host' )
        {
            if( !$rule->isNatRule() )
                return self::enclose('');
            if( $rule->dnathost === null )
                return self::enclose('');
            return self::enclose(array($rule->dnathost), $wrap);
        }

        if( $fieldName == 'disabled' )
        {
            return self::enclose(boolYesNo($rule->isDisabled()));
        }

        if( $fieldName == 'src_resolved_sum' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveSummary( $rule, "source", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }

        if( $fieldName == 'dst_resolved_sum' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveSummary( $rule, "destination", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }

        if( $fieldName == 'dnat_host_resolved_sum' )
        {
            $unresolvedArray = array();
            $strMapping = $this->NatAddressResolveSummary( $rule, "dnathost", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }

        if( $fieldName == 'snat_address_resolved_sum' )
        {
            $unresolvedArray = array();
            $strMapping = $this->NatAddressResolveSummary( $rule, "snathosts", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }

        if( $fieldName == 'target' )
        {
            if( $rule->target_isAny() )
                return self::enclose('');

            $strMapping = $rule->targets_toString();

            return self::enclose($strMapping);
        }

        return self::enclose('unsupported');

    }

    public function AddressResolveSummary( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        if( $rule->$typeSrcDst->isAny() )
            return array( '0.0.0.0-255.255.255.255', '::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        $mapping = $rule->$typeSrcDst->getIP4Mapping();
        $strMapping = explode(',', $mapping->dumpToString());

        foreach( array_keys($mapping->unresolved) as $unresolved )
        {
            #$strMapping[] = $unresolved;
            $unresolvedArray[] = $unresolved;
        }

        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }

    public function NatAddressResolveSummary( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        if( !$rule->isNatRule() )
            return array();

        if( $rule->$typeSrcDst === null )
            return array();

        $mapping = $rule->$typeSrcDst->getIP4Mapping();
        $strMapping = explode(',', $mapping->dumpToString());

        foreach( array_keys($mapping->unresolved) as $unresolved )
        {
            #$strMapping[] = $unresolved;
            $unresolvedArray[] = $unresolved;
        }

        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }

    public function ServiceResolveSummary( $rule )
    {
        $port_mapping_text = array();

        if( $rule->isDecryptionRule() )
            return array();
        if( $rule->isAppOverrideRule() )
            return $rule->ports();


        if( $rule->isNatRule() )
        {
            if( $rule->service !== null )
                return array($rule->service);
            return array( 'any' );
        }

        if( $rule->services->isAny() )
            return array( 'any' );
        if( $rule->services->isApplicationDefault() )
        {
            //if application is any
            if( $rule->apps->isAny() )
                return array( 'application-default' );
            else
            {
                $applications = $rule->apps->getAll();

                //get all apps
                $app_array = array();
                foreach( $applications as $app )
                {
                    /** @var App $app */
                    $app_array = array_merge( $app_array, $app->getAppsRecursive() );
                }


                foreach( $app_array as $app )
                {
                    #$name = " ".$app->name();
                    $name = "";

                    if( isset($app->tcp) )
                    {
                        $protocol = "tcp/";
                        foreach( $app->tcp as $tcp )
                        {
                            if( $tcp[0] == "single" )
                                $port_mapping_text[$protocol . $tcp[1]] = $protocol . $tcp[1].$name;
                            elseif( $tcp[0] == "dynamic" )
                            {
                                #$port_mapping_text[$protocol . "dynamic"] = $protocol . "dynamic";
                                $port_mapping_text[$protocol . "1024-65535"] = $protocol . "1024-65535". $name;
                            }
                            elseif( $tcp[0] == "range" )
                                $port_mapping_text[$protocol . $tcp[1] . "-" . $tcp[2]] = $protocol . $tcp[1] . "-" . $tcp[2]. $name;
                            else
                                foreach( $tcp as $port )
                                    $port_mapping_text[$protocol . $port] = $protocol . $port. $name;
                        }
                    }

                    if( isset($app->udp) )
                    {
                        $protocol = "udp/";
                        foreach( $app->udp as $udp )
                        {
                            if( $udp[0] == "single" )
                                $port_mapping_text[$protocol . $udp[1]] = $protocol . $udp[1]. $name;
                            elseif( $udp[0] == "dynamic" )
                            {
                                #$port_mapping_text[$protocol . "dynamic"] = $protocol . "dynamic";
                                $port_mapping_text[$protocol . "1024-65535"] = $protocol . "1024-65535". $name;
                            }
                            elseif( $udp[0] == "range" )
                                $port_mapping_text[$protocol . $udp[1] . "-" . $udp[2]] = $protocol . $udp[1] . "-" . $udp[2]. $name;
                            else
                                foreach( $udp as $port )
                                    $port_mapping_text[$protocol . $port] = $protocol . $port.$name;
                        }
                    }
                }

                return $port_mapping_text;
            }
        }


        $objects = $rule->services->getAll();

        $array = array();
        foreach( $objects as $object )
        {
            $port_mapping = $object->dstPortMapping();
            $mapping_texts = $port_mapping->mappingToText();

            //TODO: handle predefined service objects in a different way
            if( $object->name() == 'service-http' )
                $mapping_texts = 'tcp/80';
            if( $object->name() == 'service-https' )
                $mapping_texts = 'tcp/443';


            if( strpos($mapping_texts, " ") !== FALSE )
                $mapping_text_array = explode(" ", $mapping_texts);
            else
                $mapping_text_array[] = $mapping_texts;


            $protocol = "tmp";
            foreach( $mapping_text_array as $mapping_text )
            {
                if( strpos($mapping_text, "tcp/") !== FALSE )
                    $protocol = "tcp/";
                elseif( strpos($mapping_text, "udp/") !== FALSE )
                    $protocol = "udp/";

                $mapping_text = str_replace($protocol, "", $mapping_text);
                $mapping_text = explode(",", $mapping_text);

                foreach( $mapping_text as $mapping )
                {

                    if( !in_array( $protocol . $mapping, $port_mapping_text ) )
                    {
                        $port_mapping_text[] = $protocol . $mapping;

                        if( strpos($mapping, "-") !== FALSE )
                        {
                            $array[$protocol . $mapping] = $protocol . $mapping;
                            $range = explode("-", $mapping);
                            for( $i = $range[0]; $i <= $range[1]; $i++ )
                                $array[$protocol . $i] = $protocol . $i;
                        }
                        else
                            $array[$protocol . $mapping] = $protocol . $mapping;
                    }
                }
            }
        }

        return $port_mapping_text;
    }

    public function ApplicationResolveSummary( $rule, $returnString = false )
    {
        $app_mapping = array();

        /** @var SecurityRule $rule */
        if( $rule->isDecryptionRule() || $rule->isNatRule() || $rule->isAuthenticationRule() || $rule->isCaptivePortalRule() )
            return array( '' );
        if( $rule->isAppOverrideRule() )
            return $rule->application();

        if( $rule->apps->isAny() )
        {
            return array( 'any' );
        }


        $applications = $rule->apps->getAll();
        foreach( $applications as $app )
        {
            /** @var App $app */
            $this->appGetRecursive( $app, $returnString, $app_mapping );
        }

        if( $returnString )
            return $app_mapping;
        else
            return $app_mapping;
    }

    public function appGetRecursive( $app, $returnString = false, &$app_mapping = array() )
    {
        if( $app->isApplicationGroup() )
        {
            foreach( $app->groupApps() as $app1 )
                $this->appReturn( $app1, $returnString, $app_mapping );
        }
        elseif( $app->isApplicationFilter() )
        {
            foreach( $app->filteredApps() as $app1 )
                $this->appReturn( $app1, $returnString, $app_mapping );
        }
        elseif( $app->isApplicationCustom() )
        {
            $this->appReturn( $app, $returnString, $app_mapping );
        }
        elseif( $app->isContainer() )
        {
            foreach( $app->containerApps() as $app1 )
                $this->appReturn( $app1, $returnString, $app_mapping );
        }
        else
        {
            $this->appReturn( $app, $returnString, $app_mapping );
        }
    }

    public function appReturn( $app, $returnString = false, &$app_mapping = array() )
    {
        if( $app->isApplicationGroup() )
        {
            foreach( $app->groupApps() as $app1 )
                $this->appReturn( $app1, $returnString, $app_mapping );
        }
        elseif( $app->isContainer() )
        {
            foreach( $app->containerApps() as $app1 )
                $this->appReturn( $app1, $returnString, $app_mapping );
        }
        else
        {
            if( isset($app->app_filter_details['category']) )
                $string_category = implode( "|", $app->app_filter_details['category'] );
            else
                $string_category = $app->category;

            if( isset($app->app_filter_details['subcategory']) )
                $string_subcategory = implode( "|", $app->app_filter_details['subcategory'] );
            else
                $string_subcategory = $app->subCategory;

            if( isset($app->risk) )
                $risk = $app->risk;
            else
                $risk = "";

            if( $returnString )
                $app_mapping[] = $app->name().",".$string_category.",".$string_subcategory.",".$risk;
            else
                $app_mapping[] = array( "name" => $app->name(), "category" => $string_category, "subcatecory" => $string_subcategory, "risk" => $risk );
        }

    }

    public function ScheduleResolveSummary( $rule, $returnString = false )
    {
        if( !$rule->isSecurityRule() )
            return '';
        $schedule = $rule->schedule();
        if( $schedule == null )
            return '';

        /** @var Schedule $schedule */
        if( strlen($schedule->name()) > 0 )
        {
            $expired = false;
            $timestampString = array();
            $recurring = $schedule->getRecurring();
            foreach( $recurring['non-recurring'] as $member )
            {
                #$d2 = DateTime::createFromFormat('Y/m/d@H:i', $member['end']);
                #$timestamp = $d2->getTimestamp();
                $timestampString[] = $member['end'];
            }
            $timestampString = implode( ",", $timestampString );
            return $timestampString;
        }

        else
            return '';
    }

}


