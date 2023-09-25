<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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

    public $fields;
    public $ruleList;
    public $cachedList;

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


        $classToType = array('SecurityRule' => 'security', 'NatRule' => 'nat', 'DefaultSecurityRule' => 'defaultsecurity');
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
            if( $this->connector->isAPI() )
                $this->connector->sendSetRequest('/config/shared', $setString);

            PH::print_stdout( $text );
        }
        $setString = $this->generateRuleMergedApiChangeString(FALSE);
        if( $setString !== null )
        {
            $text = $this->padding . ' - sending API call for Device-Groups/VSYS... ';
            if( $this->connector->isAPI() )
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
            if( $this->connector->isAPI() )
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
                elseif( is_object($subValue) )
                    $output .= htmlspecialchars($subValue->name());
                else
                    $output .= "";
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
    public function ruleFieldHtmlExport($rule, $fieldName, $wrap = TRUE, $rule_hitcount_array = array())
    {
        if( $fieldName == 'ID' )
        {
            //already added outside
            return;
        }
        if( $fieldName == 'location' )
        {
            if( $rule->owner->owner->isPanorama() || $rule->owner->owner->isFirewall() )
                return self::enclose('shared');
            return self::enclose($rule->owner->owner->name(), $wrap);
        }

        if( $fieldName == 'rulebase' )
        {
            $string = "";
            if( $rule->isPreRule() )
                $string = "pre";
            elseif( $rule->isPostRule() )
                $string = "post";

            return self::enclose($string, $wrap);
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

        if( $fieldName == 'rule_type' )
            return self::enclose($rule->ruleNature(), $wrap);

        if( $fieldName == 'nat_rule_type' )
            return self::enclose($rule->getNatRuleType(), $wrap);

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
            /*
            $members = $rule->source->getAll();
            $string_array = array();
            foreach( $members as $member )
            {
                $string_array[] = $member->name()." [".$member->owner->owner->name()."]";
            }
            return self::enclose($string_array);
            */
        }

        if( $fieldName == 'destination' )
        {
            if( $rule->destination->isAny() )
                return self::enclose('any');
            return self::enclose($rule->destination->getAll(), $wrap);
        }

        if( $fieldName == 'dst_interface' )
        {
            if( $rule->destinationInterface() == null )
                return self::enclose('');
            return self::enclose($rule->destinationInterface());
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
            $port_mapping_text = $rule->ServiceResolveSummary( $rule->owner->owner );
            return self::enclose($port_mapping_text);
        }

        if( $fieldName == 'service_resolved_nested_name' )
        {
            $strMapping = $this->ServiceResolveNameNestedSummary( $rule );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'service_resolved_nested_value' )
        {
            $strMapping = $this->ServiceResolveValueNestedSummary( $rule );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'service_resolved_nested_location' )
        {
            $strMapping = $this->ServiceResolveLocationNestedSummary( $rule );
            return self::enclose($strMapping);
        }

        if( $fieldName == 'service_appdefault_resolved_sum' )
        {
            $port_mapping_text = $rule->ServiceAppDefaultResolveSummary( );
            return self::enclose($port_mapping_text);
        }

        if( $fieldName == 'service_count' )
        {
            $calculatedCounter = self::ServiceCount( $rule, "both" );
            return self::enclose((string)$calculatedCounter);
        }

        if( $fieldName == 'service_count_tcp' )
        {
            $calculatedCounter = self::ServiceCount( $rule, "tcp" );
            return self::enclose((string)$calculatedCounter);
        }

        if( $fieldName == 'service_count_udp' )
        {
            $calculatedCounter = self::ServiceCount( $rule, "udp" );
            return self::enclose((string)$calculatedCounter);
        }

        if( $fieldName == 'application' )
        {
            if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
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

        if( $fieldName == 'application_seen' )
        {
            $app_seen_text = "";
            $rule_array = $rule->API_apps_seen();
            if( !empty($rule_array ) )
            {
                #PH::print_stdout("apps: ".implode(", ", array_keys( $rule_array['apps-seen'])) );

                #$app_seen_text = implode("\n", array_keys( $rule_array['apps-seen']));

                #PH::print_stdout("apps-seen-count: ".$rule_array['apps-seen-count']);
                #PH::print_stdout( "apps allowed count: ". $rule_array['apps-allowed-count'] );
                #PH::print_stdout( "days_no_new_app_count: ". $rule_array['days-no-new-app-count'] );
                #PH::print_stdout( "last_app_seen_since_count: ". $rule_array['last-app-seen-since-count'] );

                return self::enclose(array_keys( $rule_array['apps-seen']));
            }
            return self::enclose( $app_seen_text );
        }

        if( $fieldName == 'security-profile' )
        {
            if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
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
            if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() && !$rule->isCaptivePortalRule() )
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
            if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
                return self::enclose('');
            return self::enclose(boolYesNo($rule->logStart()), $wrap);
        }
        if( $fieldName == 'log_end' )
        {
            if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
                return self::enclose('');
            return self::enclose(boolYesNo($rule->logEnd()), $wrap);
        }

        if( $fieldName == 'log_profile' )
        {
            if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
                return self::enclose('');

            return self::enclose(boolYesNo($rule->logSetting()), $wrap);
        }

        if( $fieldName == 'log_profile_name' )
        {
            if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
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
        if( $fieldName == 'snat_interface' )
        {
            if( $rule->snatinterface == null )
                return self::enclose('');
            return self::enclose($rule->snatinterface);
        }

        if( $fieldName == 'dnat_type' )
        {
            if( !$rule->isNatRule() )
                return self::enclose('');
            if( $rule->dnathost === null )
                return self::enclose('');
            return self::enclose($rule->dnattype, $wrap);
        }
        if( $fieldName == 'dnat_host' )
        {
            if( !$rule->isNatRule() )
                return self::enclose('');
            if( $rule->dnathost === null )
                return self::enclose('');
            return self::enclose(array($rule->dnathost), $wrap);
        }
        if( $fieldName == 'dnat_port' )
        {
            if( !$rule->isNatRule() )
                return self::enclose('');
            if( $rule->dnatports === null )
                return self::enclose('');
            return self::enclose(array($rule->dnatports), $wrap);
        }
        if( $fieldName == 'dnat_distribution' )
        {
            if( !$rule->isNatRule() )
                return self::enclose('');
            if( $rule->dnatdistribution === null )
                return self::enclose('');
            return self::enclose($rule->dnatdistribution, $wrap);
        }

        if( $fieldName == 'disabled' )
        {
            return self::enclose(boolYesNo($rule->isDisabled()));
        }

        if( $fieldName == 'src_resolved_value' )
        {
            $unresolvedArray = array();
            $resolve = $this->AddressResolveValueSummary($rule, "source", $unresolvedArray );

            return self::enclose($resolve);
        }
        if( $fieldName == 'src_resolved_sumOLD' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveSummary( $rule, "source", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'src_resolved_sum' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveSummaryNEW( $rule, "source", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'src_resolved_nested_name' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveNameNestedSummary( $rule, "source", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'src_resolved_nested_value' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveValueNestedSummary( $rule, "source", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'src_resolved_nested_location' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveLocationNestedSummary( $rule, "source", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'src_ip_count' )
        {
            //must NOT be done on addressresolvesummary; must be done on real objects
        }


        if( $fieldName == 'dst_resolved_value' )
        {
            $unresolvedArray = array();
            $resolve = $this->AddressResolveValueSummary($rule, "destination", $unresolvedArray );

            return self::enclose($resolve);
        }
        if( $fieldName == 'dst_resolved_sumOLD' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveSummary( $rule, "destination", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'dst_resolved_sum' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveSummaryNEW( $rule, "destination", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'dst_resolved_nested_name' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveNameNestedSummary( $rule, "destination", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'dst_resolved_nested_value' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveValueNestedSummary( $rule, "destination", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'dst_resolved_nested_location' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveLocationNestedSummary( $rule, "destination", $unresolvedArray );
            $strMapping = array_merge( $strMapping, $unresolvedArray );
            return self::enclose($strMapping);
        }
        if( $fieldName == 'dst_ip_count' )
        {
            //must NOT be done on addressresolvesummary; must be done on real objects
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

        if( $fieldName == 'first-hit' )
        {
            if( isset($rule_hitcount_array[$fieldName]) )
                return self::enclose( $rule_hitcount_array[$fieldName] );
            else
                return self::enclose( "" );
        }

        if( $fieldName == 'last-hit' )
        {
            if( isset($rule_hitcount_array[$fieldName]) )
                return self::enclose( $rule_hitcount_array[$fieldName] );
            else
                return self::enclose( "" );
        }
        if( $fieldName == 'hit-count' )
        {
            if( isset($rule_hitcount_array[$fieldName]) )
                return self::enclose( $rule_hitcount_array[$fieldName] );
            else
                return self::enclose( "" );
        }
        return self::enclose("unsupported: '$fieldName'");

    }

    public function AddressResolveSummary( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        if( $rule->$typeSrcDst->isAny() )
            return array( '0.0.0.0-255.255.255.255', '::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        $mapping = $rule->$typeSrcDst->getIP4Mapping( $rule->owner->owner );
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
    public function AddressResolveValueSummary( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        if( $rule->$typeSrcDst->isAny() )
            return array( '0.0.0.0-255.255.255.255', '::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        /*
        $mapping = $rule->$typeSrcDst->getIP4Mapping();
        $strMapping = explode(',', $mapping->dumpToString());

        foreach( array_keys($mapping->unresolved) as $unresolved )
        {
            #$strMapping[] = $unresolved;
            $unresolvedArray[] = $unresolved;
        }
        */

        $allMembers = $rule->$typeSrcDst->getAll();
        $strMapping = array();
        foreach($allMembers as $member)
        {
            if( $member->isGroup() )
                $strMapping[] = "group";
            else
                $strMapping[] = $member->value();
        }


        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }

    public function AddressResolveValueNestedSummary( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        if( $rule->$typeSrcDst->isAny() )
            return array( '0.0.0.0/0', '::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        $allMembers = $rule->$typeSrcDst->getAll();
        $strMapping = array();
        foreach($allMembers as $member)
        {
            if( $member->isGroup() )
            {
                /** @var AddressGroup $member */
                $tmp_array = array();
                $members = $member->expand(FALSE, $tmp_array, $rule->owner->owner);
                #foreach($tmp_array as $groups)
                #    $strMapping[] = "";
                foreach( $members as $member )
                {
                    $tmp_member = $rule->owner->owner->addressStore->find($member->name());
                    $strMapping[] = $tmp_member->value();
                    #$strMapping[] = "group";
                }
            }

            else
            {
                $tmp_member = $rule->owner->owner->addressStore->find($member->name());
                $strMapping[] = $tmp_member->value();
            }

        }


        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }

    public function AddressResolveSummaryNEW( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        $mapObject = new IP4Map();
        if( $rule->$typeSrcDst->isAny() )
        {
            $localMap = IP4Map::mapFromText('0.0.0.0-255.255.255.255');
            $mapObject->addMap($localMap, TRUE);
            #$localMap = IP4Map::mapFromText('::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
            #$mapObject->addMap($localMap, TRUE);
        }

        $allMembers = $rule->$typeSrcDst->getAll();
        $strMapping = array();
        foreach($allMembers as $member)
        {
            if( $member->isGroup() )
            {
                /** @var AddressGroup $member */
                $tmp_array = array();
                $members = $member->expand(FALSE, $tmp_array, $rule->owner->owner);
                foreach( $members as $member )
                {
                    $tmp_member = $rule->owner->owner->addressStore->find($member->name());
                    $localMap = $tmp_member->getIP4Mapping();
                    $mapObject->addMap($localMap, TRUE);
                }
            }

            else
            {
                $tmp_member = $rule->owner->owner->addressStore->find($member->name());
                $localMap = $tmp_member->getIP4Mapping();
                $mapObject->addMap($localMap, TRUE);
            }

        }

        $mapObject->sortAndRecalculate();
        $strMapping = explode(',', $mapObject->dumpToString());

        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }

    public function AddressResolveNameNestedSummary( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        if( $rule->$typeSrcDst->isAny() )
            return array( '0.0.0.0/0', '::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        $allMembers = $rule->$typeSrcDst->getAll();
        $strMapping = array();
        foreach($allMembers as $member)
        {
            if( $member->isGroup() )
            {
                $tmp_array = array();
                $members = $member->expand(FALSE, $tmp_array, $rule->owner->owner);
                #foreach($tmp_array as $groups)
                #    $strMapping[] = $groups->name();
                foreach( $members as $member )
                {
                    $strMapping[] = $member->name();
                }
            }

            else
                $strMapping[] = $member->name();
        }


        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }

    public function AddressResolveLocationNestedSummary( $rule, $typeSrcDst, &$unresolvedArray = array() )
    {
        if( $rule->$typeSrcDst->isAny() )
            return array( '0.0.0.0/0', '::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        $allMembers = $rule->$typeSrcDst->getAll();
        $strMapping = array();
        foreach($allMembers as $member)
        {
            if( $member->isGroup() )
            {
                $tmp_array = array();
                $members = $member->expand(FALSE, $tmp_array, $rule->owner->owner);
                /*
                foreach($tmp_array as $groups)
                {
                    $tmp_name = $groups->owner->owner->name();
                    if( empty($tmp_name) )
                        $tmp_name = "shared";

                    $strMapping[] = $tmp_name;
                }*/
                foreach( $members as $member )
                {
                    $tmp_name = $member->owner->owner->name();
                    if( empty($tmp_name) )
                        $tmp_name = "shared";

                    $strMapping[] = $tmp_name;
                }
            }
            else
            {
                $tmp_name = $member->owner->owner->name();
                if( empty($tmp_name) )
                    $tmp_name = "shared";

                $strMapping[] = $tmp_name;
            }
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

    public function ServiceCount( $rule, $type = "both" )
    {
        $calculatedCounter = "";
        if( get_class($rule) === "NatRule" )
        {
            /** @var NatRule $rule */
            if( is_object($rule->service ) )
                $calculatedCounter = 1;
            else
            {
                $maxPortcount = 65536;
                if( $type === "both" )
                    $calculatedCounter = ($maxPortcount * 2);
                elseif( $type === "tcp" || $type === "udp" )
                    $calculatedCounter = $maxPortcount;
            }
        }
        #if( get_class($rule) === "SecurityRule" )
        else
        {
            /** @var SecurityRule|Rule $rule */
            $objects = $rule->services->o;


            if( count($objects  ) > 0 )
            {
                $dst_port_mapping = new ServiceDstPortMapping();
                $dst_port_mapping->mergeWithArrayOfServiceObjects( $objects);

                $dst_port_mapping->countPortmapping();
                if( $type === "both" )
                    $calculatedCounter = $dst_port_mapping->PortCounter;
                elseif( $type === "tcp" )
                    $calculatedCounter = $dst_port_mapping->tcpPortCounter;
                elseif( $type === "udp" )
                    $calculatedCounter = $dst_port_mapping->udpPortCounter;
            }
            elseif( $rule->services->isApplicationDefault() )
                $calculatedCounter = "";
            else
            {
                $maxPortcount = 65536;
                if( $type === "both" )
                    $calculatedCounter = ($maxPortcount * 2);
                elseif( $type === "tcp" || $type === "udp" )
                    $calculatedCounter = $maxPortcount;
            }
        }


        return $calculatedCounter;
    }

    public function ServiceResolveValueNestedSummary( $rule )
    {
        if( $rule->services->isAny() )
            return array( '0.0.0.0/0', '::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        $allMembers = $rule->services->getAll();
        $strMapping = array();
        foreach($allMembers as $member)
        {
            if( $member->isGroup() )
            {
                $tmp_array = array();
                $members = $member->expand(FALSE, $tmp_array, $rule->owner->owner);
                foreach( $members as $member )
                {
                    $tmp_member = $rule->owner->owner->serviceStore->find($member->name());

                    $port_mapping = $tmp_member->dstPortMapping( array(), $rule->owner->owner );
                    $mapping_texts = $port_mapping->mappingToText();

                    //TODO: handle predefined service objects in a different way
                    if( $tmp_member->name() == 'service-http' )
                        $mapping_texts = 'tcp/80';
                    if( $tmp_member->name() == 'service-https' )
                        $mapping_texts = 'tcp/443';

                    $strMapping[] = $mapping_texts;
                    #$strMapping[] = "group";
                }
            }

            else
            {
                $tmp_member = $rule->owner->owner->serviceStore->find($member->name());

                $port_mapping = $tmp_member->dstPortMapping( array(), $rule->owner->owner );
                $mapping_texts = $port_mapping->mappingToText();

                //TODO: handle predefined service objects in a different way
                if( $tmp_member->name() == 'service-http' )
                    $mapping_texts = 'tcp/80';
                if( $tmp_member->name() == 'service-https' )
                    $mapping_texts = 'tcp/443';

                $strMapping[] = $mapping_texts;

            }

        }


        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }
    public function ServiceResolveNameNestedSummary( $rule )
    {
        /** @var SecurityRule $rule */
        if( $rule->services->isAny() )
            return array('tcp/0-65535', 'udp/0-65535');

        $allMembers = $rule->services->getAll();
        $strMapping = array();
        foreach($allMembers as $member1)
        {
            if( $member1->isGroup() )
            {
                $tmp_array = array();
                $members = $member1->expand(FALSE, $tmp_array, $rule->owner->owner);
                foreach( $members as $member2 )
                {
                    $strMapping[] = $member2->name();
                }
            }

            else
                $strMapping[] = $member1->name();
        }


        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
    }

    public function ServiceResolveLocationNestedSummary( $rule )
    {
        if( $rule->services->isAny() )
            return array('tcp/0-65535', 'udp/0-65535');

        $allMembers = $rule->services->getAll();
        $strMapping = array();
        foreach($allMembers as $member)
        {
            if( $member->isGroup() )
            {
                $tmp_array = array();
                $members = $member->expand(FALSE, $tmp_array, $rule->owner->owner);
                foreach( $members as $member )
                {
                    $tmp_name = $member->owner->owner->name();
                    if( empty($tmp_name) )
                        $tmp_name = "shared";

                    $strMapping[] = $tmp_name;
                }
            }
            else
            {
                $tmp_name = $member->owner->owner->name();
                if( empty($tmp_name) )
                    $tmp_name = "shared";

                $strMapping[] = $tmp_name;
            }
        }


        if( count( $strMapping) === 1 && empty( $strMapping[0] ) )
            $strMapping = array();

        return $strMapping;
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

        $app_array = array();

        $applications = $rule->apps->getAll();
        foreach( $applications as $app )
        {
            /** @var App $app */
            #$this->appGetRecursive( $app, $returnString, $app_mapping );

            $app_array = array_merge( $app_array, $app->getAppsRecursive() );
        }

        foreach( $app_array as $app )
            $app->getAppDetails( $returnString, $app_mapping );


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
            $app->getAppDetails( $returnString, $app_mapping );
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
            if( isset($recurring['non-recurring']) )
            {
                foreach( $recurring['non-recurring'] as $member )
                {
                    #$d2 = DateTime::createFromFormat('Y/m/d@H:i', $member['end']);
                    #$timestamp = $d2->getTimestamp();

                    #foreach( $member as $startEnd )
                    #    $timestampString[] = $startEnd['start'].'-'.$startEnd['end'];
                    $timestampString[] = $member['start'].'-'.$member['end'];
                }
                $timestampString = 'non-recurring | '.implode( ",", $timestampString );
            }
            elseif( isset($recurring['weekly']) )
            {
                foreach( $recurring['weekly'] as $key => $member )
                {
                    #$d2 = DateTime::createFromFormat('Y/m/d@H:i', $member['end']);
                    #$timestamp = $d2->getTimestamp();
                    foreach( $member as $startEnd )
                        $timestampString[] = $key."=>".$startEnd['start'].'-'.$startEnd['end'];
                }
                $timestampString = 'weekly | '.implode( ",", $timestampString );
            }
            elseif( isset($recurring['daily']) )
            {
                $timestampString = 'daily | '.$recurring['daily']['start'].'-'.$recurring['daily']['end'];
            }


            return $timestampString;
        }

        else
            return '';
    }

    public function API_apps_seen($rule)
    {
        $rule_array = array();

        $rule_uuid = $rule->uuid();
        $cmd = "<show><policy-app-details><rules><member>".$rule_uuid."</member></rules>
<resultfields><member>apps-seen</member><member>last-app-seen-since-count</member><member>days-no-new-app-count</member></resultfields><trafficTimeframe>30</trafficTimeframe><appsSeenTimeframe>any</appsSeenTimeframe><vsysName>vsys1</vsysName><type>security</type><position>main</position><summary>no</summary></policy-app-details></show>";

        $connector = findConnectorOrDie($rule);
        $res = $connector->sendOpRequest($cmd);
        $res = DH::findFirstElement( "result", $res);
        $res = DH::findFirstElement( "rules", $res);
        $rule = DH::findFirstElementByNameAttr( "entry", $rule->name(), $res );

        if( $rule !== null && $rule !== false )
        {
            $apps_seen = DH::findFirstElement( "apps-seen", $rule);
            $app_array = array();
            foreach( $apps_seen->childNodes as $app )
            {
                /** @var DOMElement $app */
                if( $app->nodeType != XML_ELEMENT_NODE )
                    continue;

                $application = DH::findFirstElement( "application", $app);
                $bytes = DH::findFirstElement( "bytes", $app);
                $first_seen = DH::findFirstElement( "first-seen", $app);
                $last_seen = DH::findFirstElement( "last-seen", $app);

                $app_array[$application->textContent] = array(
                    "name" => $application->textContent,
                    "bytes" => $bytes->textContent,
                    "first_seen" => $first_seen->textContent,
                    "last_seen" => $last_seen->textContent,
                );
                #print "APP: ".$application->textContent."\n";
                #DH::DEBUGprintDOMDocument( $app );
            }

            #print_r($app_array);
            $apps = array_keys($app_array);

            $apps_allowed_count = DH::findFirstElement( "apps-allowed-count", $rule);
            $days_no_new_app_count = DH::findFirstElement( "days-no-new-app-count", $rule);
            $last_app_seen_since_count = DH::findFirstElement( "last-app-seen-since-count", $rule);

            $rule_array = array( "apps-seen-count" =>  count($app_array),
                "apps-seen" => $app_array,
                "apps-allowed-count" => $apps_allowed_count->textContent,
                "days-no-new-app-count" => $days_no_new_app_count->textContent,
                "last-app-seen-since-count" => $last_app_seen_since_count->textContent,
            );
        }

        return $rule_array;
    }

    public function API_showRuleHitCount( $rule, $all = false, $print = TRUE )
    {
        $con = findConnectorOrDie($rule);

        $rule_hitcount_array = array();

        if( $con->info_PANOS_version_int >= 90 )
        {
            $system = $rule->owner->owner;
            $cmd = $rule->prepareRuleHitCount('show', $all);

            if( $cmd == null )
            {
                PH::print_stdout( "   * not working for Panorama/FW shared" );
                return;
            }


            $res = $con->sendOpRequest($cmd, TRUE);
            $res = DH::findFirstElement( "result", $res);


            $res = DH::findFirstElement( "rule-hit-count", $res);
            if( !$res )
                return;

            if( $system->isPanorama() )
            {
                DH::DEBUGprintDOMDocument($res);
            }
            elseif( $system->isDeviceGroup() && $system->name() !== ""  )
            {
                #DH::DEBUGprintDOMDocument($res);
                $res = DH::findFirstElement( "device-group", $res);
            }

            elseif( $system->isVirtualSystem() )
                $res = DH::findFirstElement( "vsys", $res);

            if( $system->isDeviceGroup() && $system->name() === ""  )
            {
                #$res = DH::findFirstElement( "entry", $res);
                $res = $res;
            }
            else
                $res = DH::findFirstElement( "entry", $res);

            $res = DH::findFirstElement( "rule-base", $res);
            $res = DH::findFirstElement( "entry", $res);
            $res = DH::findFirstElement( "rules", $res);
            $res = DH::findFirstElement( "entry", $res);


            if( $system->isDeviceGroup()  )
            {
                DH::DEBUGprintDOMDocument($res);
                //<rule-base><entry ...><rules><entry name="demo2-1"><device-vsys><entry name="child/1234567890/vsys1">
                $res = DH::findFirstElement( "device-vsys", $res);
                $res = DH::findFirstElement( "entry", $res);
            }

            $latest = DH::findFirstElement( "latest", $res);
            $hit_count = DH::findFirstElement( "hit-count", $res);
            $last_hit_timestamp = DH::findFirstElement( "last-hit-timestamp", $res);
            $last_reset_timestamp = DH::findFirstElement( "last-reset-timestamp", $res);

            $first_hit_timestamp = DH::findFirstElement( "first-hit-timestamp", $res);
            $rule_creation_timestamp = DH::findFirstElement( "rule-creation-timestamp", $res);
            $rule_modification_timestamp = DH::findFirstElement( "rule-modification-timestamp", $res);

            //create Array and return
            $padding = "    * ";
            if( $latest )
            {
                if( $print )
                    PH::print_stdout( $padding."latest: ".$latest->textContent );
                $rule_hitcount_array['latest'] = $latest->textContent;
            }

            if( $hit_count)
            {
                if( $print )
                    PH::print_stdout( $padding."hit-count: ".$hit_count->textContent );
                $rule_hitcount_array['hit-count'] = $hit_count->textContent;
            }

            if( $last_hit_timestamp )
            {
                $unixTimestamp = $last_hit_timestamp->textContent;
                if( $unixTimestamp === "0" || $unixTimestamp === "" )
                    $result = "0";
                else
                    $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                if( $print )
                    PH::print_stdout( $padding."last-hit: ".$result );
                $rule_hitcount_array['last-hit'] = $result;
            }

            if( $last_reset_timestamp )
            {
                $unixTimestamp = $last_reset_timestamp->textContent;
                if( $unixTimestamp === "0" || $unixTimestamp === "" )
                    $result = "0";
                else
                    $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                if( $print )
                    PH::print_stdout( $padding."last-reset: ".$result );
                $rule_hitcount_array['last-reset'] = $result;
            }

            if( $first_hit_timestamp )
            {
                $unixTimestamp = $first_hit_timestamp->textContent;
                if( $unixTimestamp === "0" || $unixTimestamp === "" )
                    $result = "0";
                else
                    $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                if( $print )
                    PH::print_stdout( $padding."first-hit: ".$result );
                $rule_hitcount_array['first-hit'] = $result;
            }

            if( $rule_creation_timestamp )
            {
                $unixTimestamp = $rule_creation_timestamp->textContent;
                if( $unixTimestamp === "" )
                    $result = 0;
                else
                    $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                if( $print )
                    PH::print_stdout( $padding."rule-creation: ".$result );
                $rule_hitcount_array['rule-creation'] = $result;
            }
            if( $rule_modification_timestamp )
            {
                $unixTimestamp = $rule_modification_timestamp->textContent;
                if( $unixTimestamp === "" )
                    $result = 0;
                else
                    $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                if( $print )
                    PH::print_stdout( $padding."rule-modification: ".$result );
                $rule_hitcount_array['rule-modification'] = $result;
            }

        }
        else
        {
            if( $print )
                PH::print_stdout( "  PAN-OS version must be 9.0 or higher" );
        }

        return $rule_hitcount_array;
    }
}


