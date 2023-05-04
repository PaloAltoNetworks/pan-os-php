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
    public function ruleFieldHtmlExport($rule, $fieldName, $wrap = TRUE, $rule_hitcount_array = array())
    {
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

        if( $fieldName == 'type' )
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
            $port_mapping_text = $rule->ServiceResolveSummary( );
            return self::enclose($port_mapping_text);
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
            print "application_seen\n";
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
        if( $fieldName == 'src_ip_count' )
        {
            //must NOT be done on addressresolvesummary; must be done on real objects
        }

        if( $fieldName == 'dst_resolved_sum' )
        {
            $unresolvedArray = array();
            $strMapping = $this->AddressResolveSummary( $rule, "destination", $unresolvedArray );
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

}


