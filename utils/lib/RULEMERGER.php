<?php
/**
 * ISC License
 *
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

class RULEMERGER extends UTIL
{
    public $location_array = array();

    public $UTIL_hashTable = array();
    public $UTIL_rulesArrayIndex = array();
    public $UTIL_denyRules = array();

    public $UTIL_rulesToProcess = array();


    public $UTIL_method = null;
    public $UTIL_additionalMatch = array();

    public $UTIL_stopMergingIfDenySeen = TRUE;
    public $UTIL_mergeAdjacentOnly = FALSE;
    public $UTIL_mergeDenyRules = FALSE;
    public $panoramaPreRuleSelected = TRUE;
    public $upperLevelSearch = FALSE;

    public $UTIL_filterQuery = null;
    public $supportedMethods = array();
    public $processedLocation = null;

    public $deletedObjects = array();
    public $skippedObjects = array();

    public $exportcsv = FALSE;
    public $exportcsvFile = null;

    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml|api://... location=shared|sub [out=outputfile.xml]" .
            " ['filter=(from has external) or (to has dmz)']";

        $actionProperties = "exportToExcel";
        $arguments = "";
        $this->context = new RuleCallContext( $actionProperties, $arguments);

        $this->add_supported_arguments();

        $this->prepareSupportedArgumentsArray();

        $this->supportedMethods();


        PH::processCliArgs();

        $this->arg_validation();
        $this->help(PH::$args);
        $this->inDebugapiArgument();
        $this->inputValidation();
        $this->location_provided();

        if( isset(PH::$args['actions']) )
        {
            $this->action = PH::$args['actions'];
            if( $this->action !== 'merge' && $this->action !== 'display' )
                derr( 'argument actions only support value: merge or display | actions=merge' );
        }
        else
            $this->action = "merge";

        if( isset(PH::$args['additionalmatch']) )
        {
            $tmp_additionalmatch = strtolower( PH::$args['additionalmatch'] );
            $this->UTIL_additionalMatch = explode( ",", $tmp_additionalmatch );

            $supportedAdditionalmatch = array( 'tag', 'secprof', 'user', 'urlcategory', 'target' );
            foreach( $this->UTIL_additionalMatch as $value )
            {
                if( !in_array( $value, $supportedAdditionalmatch ) )
                    derr( "additionalMatch argument support until now ONLY: ".implode(", ", $supportedAdditionalmatch) );
            }
            #if( $this->UTIL_additionalMatch != "tag" )
            #    derr( "additionalMatch argument support until now ONLY 'tag'" );
        }

        $errorMessage = '';
        if( isset(PH::$args['filter']) )
        {
            $this->UTIL_filterQuery = new RQuery('rule');
            if( !$this->UTIL_filterQuery->parseFromString(PH::$args['filter'], $errorMessage) )
                derr($errorMessage);
            PH::print_stdout( " - rule filter after sanitizing : ");
            $this->UTIL_filterQuery->display();
        }

        if( isset(PH::$args['projectfolder']) )
        {
            $this->projectFolder = PH::$args['projectfolder'];
            if (!file_exists($this->projectFolder)) {
                mkdir($this->projectFolder, 0777, true);
            }
        }

        if( isset(PH::$args['outputformatset']) )
        {
            $this->outputformatset = TRUE;

            if( !is_bool(PH::$args['outputformatset']) )
            {
                $this->outputformatsetFile = PH::$args['outputformatset'];

                if( $this->projectFolder !== null )
                    $this->outputformatsetFile = $this->projectFolder."/".$this->outputformatsetFile;
            }
            else
                $this->outputformatsetFile = null;
        }

        if( isset(PH::$args['exportcsv']) )
        {
            $this->exportcsv = TRUE;
            $this->exportcsvFile = PH::$args['exportcsv'];

            if( $this->projectFolder !== null )
                $this->exportcsvFile = $this->projectFolder."/".$this->exportcsvFile;
        }
        
        $this->load_config();

        $this->location_array = $this->merger_location_array($this->utilType, $this->objectsLocation, $this->pan);


        $this->mergerArguments();


        if( $this->action === "display" )
        {
            $this->apiMode = FALSE;
            $this->action = "merge";
        }

        ########################################################################################################################
        #      merging
        ########################################################################################################################

        if( count( $this->location_array ) > 1 )
        {
            PH::print_stdout();
            PH::print_stdout("#####################################");
            PH::print_stdout();

            $this->pan->display_statistics();

            PH::print_stdout();
            PH::print_stdout("#####################################");
            PH::print_stdout();
        }


        foreach( $this->location_array as $tmp_location )
        {
            $store = $tmp_location['store'];
            $sub = $tmp_location['findLocation'];
            $parentStore = $tmp_location['parentStore'];
            if( $this->upperLevelSearch )
                $childDeviceGroups = $tmp_location['childDeviceGroups'];
            else
                $childDeviceGroups = array();

            if( $store == null )
                continue;

            if( $this->pan->isPanorama() || ( $this->pan->isFawkes() && $sub->isContainer()) )
            {
                if( $this->panoramaPreRuleSelected )
                    $this->UTIL_rulesToProcess = $store->preRules();
                else
                    $this->UTIL_rulesToProcess = $store->postRules();
            }
            else
                $this->UTIL_rulesToProcess = $store->rules();


            if( is_object($sub) )
                $this->processedLocation = $sub;
            elseif( $sub == "shared" )
                $this->processedLocation = $this->pan;


            $this->UTIL_rulesArrayIndex = array();
            $this->UTIL_hashTable = array();
            $this->UTIL_denyRules = array();


            if( count( $this->UTIL_rulesToProcess ) === 0 )
            {
                if( is_object($sub) )
                    PH::print_stdout("Location: ".$sub->name()." skipped - empty");
                else
                    PH::print_stdout("Location: shared -  skipped - empty");
                continue;
            }



            $this->UTIL_calculate_rule_hash();


            PH::print_stdout();
            PH::print_stdout("Stats before merging :");
            $this->processedLocation->display_statistics();

            ##################

            $this->UTIL_rule_merging();

            ##################

            PH::print_stdout();
            PH::print_stdout("Stats after merging :");
            $this->processedLocation->display_statistics();

            PH::print_stdout();
            PH::print_stdout("#####################################");
            PH::print_stdout();
        }

        ##################
        #    save to file
        ##################
        $this->save_our_work( true );

        if( $this->exportcsv )
        {
            PH::print_stdout(" * script was called with argument 'exportCSV' - please wait for calculation");

            if( $this->exportcsvFile !== null )
            {
                self::exportCSVToHtml();
                #self::exportCSVToHtml( true );
            }
        }

        
    }
    
    /**
     * @param $rule SecurityRule
     * @param $method
     * @throws Exception
     */
    function UTIL_updateRuleHash($rule)
    {
        if( isset($rule->mergeHash) )
        {
            if( isset($this->UTIL_hashTable[$rule->mergeHash]) )
            {
                if( isset($this->UTIL_hashTable[$rule->mergeHash][$rule->serial]) )
                {
                    unset($this->UTIL_hashTable[$rule->mergeHash][$rule->serial]);
                }
            }
        }

        /*
        'matchFromToSrcDstApp'  => 1 ,
        'matchFromToSrcDstSvc'  => 2 ,
        'matchFromToSrcSvcApp'  => 3 ,
        'matchFromToDstSvcApp'  => 4 ,
        'matchFromSrcDstSvcApp' => 5 ,
        'matchToSrcDstSvcApp'   => 6 ,
        'matchToDstSvcApp'   => 7 ,
        'matchFromSrcSvcApp' => 8 ,
        'identical' => 9 ,
        */


        $additional_match = "";
        if( in_array( 'tag', $this->UTIL_additionalMatch ) )
            $additional_match .= $rule->tags->getFastHashComp();
        if( in_array( 'secprof', $this->UTIL_additionalMatch ) )
            $additional_match .= $rule->securityProfilHash();
        if( in_array( 'user', $this->UTIL_additionalMatch ) )
            $additional_match .= $rule->userID_Hash();
        if( in_array( 'urlcategory', $this->UTIL_additionalMatch ) )
            $additional_match .= $rule->urlCategories->getFastHashComp();
        if( in_array( 'target', $this->UTIL_additionalMatch ) )
            $additional_match .= $rule->target_Hash();


        if( $this->UTIL_method == 1 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
                $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
                $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 2 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
                $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
                $rule->services->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 3 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
                $rule->source->getFastHashComp() .
                $rule->services->getFastHashComp() . $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 4 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
                $rule->destination->getFastHashComp() .
                $rule->services->getFastHashComp() . $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 5 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->from->getFastHashComp() .
                $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
                $rule->services->getFastHashComp() . $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 6 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->to->getFastHashComp() .
                $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
                $rule->services->getFastHashComp() . $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 7 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->to->getFastHashComp() .
                $rule->destination->getFastHashComp() .
                $rule->services->getFastHashComp() . $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 8 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->from->getFastHashComp() .
                $rule->source->getFastHashComp() .
                $rule->services->getFastHashComp() . $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        elseif( $this->UTIL_method == 9 )
            $rule->mergeHash = md5('action:' . $rule->action() . '.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
                $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
                $rule->services->getFastHashComp() .
                $rule->apps->getFastHashComp() .
                $additional_match, TRUE);
        else
            derr("unsupported method #$this->UTIL_method");

        $this->UTIL_hashTable[$rule->mergeHash][$rule->serial] = $rule;
    }

    /**
     * @param $rule SecurityRule
     * @param $ruleToMerge SecurityRule
     * @param $method int
     * @throws Exception
     */
    function UTIL_mergeRules($rule, $ruleToMerge)
    {
        /*
            'matchFromToSrcDstApp'  => 1 ,
            'matchFromToSrcDstSvc'  => 2 ,
            'matchFromToSrcSvcApp'  => 3 ,
            'matchFromToDstSvcApp'  => 4 ,
            'matchFromSrcDstSvcApp' => 5 ,
            'matchToSrcDstSvcApp'   => 6 ,
            'matchToDstSvcApp'   => 7 ,
            'matchFromSrcSvcApp' => 8 ,
            'matchFromSrcSvcApp' => 9 ,
        */

        if( $this->UTIL_method == 1 )
        {
            $rule->services->merge($ruleToMerge->services);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 2 )
        {
            $rule->apps->merge($ruleToMerge->apps);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 3 )
        {
            $rule->destination->merge($ruleToMerge->destination);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 4 )
        {
            $rule->source->merge($ruleToMerge->source);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 5 )
        {
            $rule->to->merge($ruleToMerge->to);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 6 )
        {
            $rule->from->merge($ruleToMerge->from);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 7 )
        {
            $rule->from->merge($ruleToMerge->from);
            $rule->source->merge($ruleToMerge->source);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 8 )
        {
            $rule->to->merge($ruleToMerge->to);
            $rule->destination->merge($ruleToMerge->destination);
            $rule->tags->merge($ruleToMerge->tags);
            $rule->description_merge($ruleToMerge);
        }
        elseif( $this->UTIL_method == 9 )
        {
            //
        }
        else
            derr("unsupported method #$this->UTIL_method");

        // clean this rule from hash table
        unset($this->UTIL_hashTable[$ruleToMerge->mergeHash][$rule->serial]);
        if( $this->action === "merge" )
        {
            //$this->apiMode
            $mergedTag = $rule->owner->owner->tagStore->findOrCreate( "merged");
            if( $this->apiMode && $this->configOutput == null )
            {
                $mergedTag->API_sync();
                $ruleToMerge->owner->API_remove($ruleToMerge);

                $rule->tags->API_addTag( $mergedTag );
                $rule->API_setDescription( $rule->description()." |".$ruleToMerge->name() );
            }
            else
            {
                $ruleToMerge->owner->remove($ruleToMerge);

                $rule->tags->addTag( $mergedTag );
                $rule->setDescription( $rule->description()." |".$ruleToMerge->name() );
            }
            $ruleToMerge->alreadyMerged = TRUE;
        }

        //updateRuleHash($rule, $method);
    }



    /**
     * @param $rulesToProcess array
     * @param $method int
     * @param $stopMergingIfDenySeen bool
     * @param $denyRules SecurityRule[]
     * @throws Exception
     */
    function UTIL_calculate_rule_hash( )
    {

        PH::print_stdout( " - Calculating all rules hash, please be patient... " );
        foreach( array_keys($this->UTIL_rulesToProcess) as $index )
        {
            $rule = $this->UTIL_rulesToProcess[$index];

            if( $rule->isDisabled() )
            {
                unset($this->UTIL_rulesToProcess[$index]);
                continue;
            }

            $rule->serial = spl_object_hash($rule);
            $rule->indexPosition = $index;

            $this->UTIL_updateRuleHash($rule);

            if( $this->UTIL_stopMergingIfDenySeen && $rule->actionIsNegative() )
            {
                $this->UTIL_denyRules[] = $rule;
            }
        }
    }

    /**
     * @param $rule SecurityRule
     * @return bool
     */
    function UTIL_findNearestDenyRule($rule)
    {
        $foundRule = FALSE;

        $rulePosition = $this->UTIL_rulesArrayIndex[$rule->indexPosition];

        foreach( $this->UTIL_denyRules as $index => $denyRule )
        {
            //var_dump($rulesArrayIndex);
            $denyRulePosition = $this->UTIL_rulesArrayIndex[$denyRule->indexPosition];
            if( $rulePosition < $denyRulePosition )
            {
                return $denyRule;
            }
            else
                unset($this->UTIL_denyRules[$index]);
        }

        return $foundRule;
    }


    function UTIL_rule_merging( )
    {
        PH::print_stdout( "**** NOW STARTING TO MERGE RULES");


        $loopCount = -1;
        $this->UTIL_rulesArrayIndex = array_flip(array_keys($this->UTIL_rulesToProcess));
        $mergedRulesCount = 0;


        foreach( $this->UTIL_rulesToProcess as $index => $rule )
        {
            $loopCount++;

            if( isset($rule->alreadyMerged) )
                continue;

            if( !$this->UTIL_mergeDenyRules && $rule->actionIsNegative() )
                continue;


            if( $this->UTIL_filterQuery !== null && !$this->UTIL_filterQuery->matchSingleObject($rule) )
                continue;

            PH::print_stdout( "");

            /** @var SecurityRule[] $matchingHashTable */
            $matchingHashTable = $this->UTIL_hashTable[$rule->mergeHash];

            $rulePosition = $this->UTIL_rulesArrayIndex[$rule->indexPosition];

            // clean already merged rules
            foreach( $matchingHashTable as $ruleToCompare )
            {
                if( isset($ruleToCompare->alreadyMerged) )
                    unset($matchingHashTable[$ruleToCompare->serial]);
            }

            if( count($matchingHashTable) == 1 )
            {
                PH::print_stdout( "- no match for rule #$loopCount '{$rule->name()}''");
                continue;
            }

            PH::print_stdout( "- Processing rule #$loopCount");
            $rule->display(4);

            $this->context->fields = array(
                'location' => 'location',
                'rulebase' => 'rulebase',
                'type' => 'type',
                'name' => 'name',
                'tag' => 'tags',
                'from' => 'from',
                'to' => 'to',
                'src_negated' => 'source_negated',
                'src' => 'source',
                'dst_negated' => 'destination_negated',
                'dst' => 'destination',
                'service' => 'service',
                'application' => 'application',
                'action' => 'action',
                'security' => 'security-profile',
                'disabled' => 'disabled',
                'src user' => 'src-user',
                'log start' => 'log_start',
                'log end' => 'log_end',
                'log prof' => 'log_profile',
                'log prof name' => 'log_profile_name',
                'snat type' => 'snat_type',
                'snat_address' => 'snat_address',
                'dnat_host' => 'dnat_host',
                'description' => 'description',
                'schedule' => 'schedule',
                'target' => 'target'
            );


            $line = "";
            foreach( $this->context->fields as $fieldName => $fieldID )
                $line .= $this->context->ruleFieldHtmlExport($rule, $fieldID);
            $this->deletedObjects[$rule->name()]['manipulated'] = $line;

            $nextDenyRule = FALSE;
            if( $this->UTIL_stopMergingIfDenySeen )
            {
                $nextDenyRule = $this->UTIL_findNearestDenyRule($rule);
                if( $nextDenyRule !== FALSE )
                    $nextDenyRulePosition = $this->UTIL_rulesArrayIndex[$nextDenyRule->indexPosition];
            }

            // ignore rules that are placed before this one
            unset($matchingHashTable[$rule->serial]);

            $adjacencyPositionReference = $rulePosition;
            foreach( $matchingHashTable as $ruleToCompare )
            {
                $ruleToComparePosition = $this->UTIL_rulesArrayIndex[$ruleToCompare->indexPosition];
                if( $loopCount > $ruleToComparePosition )
                {
                    unset($matchingHashTable[$ruleToCompare->serial]);
                    PH::print_stdout( "    - ignoring rule #{$ruleToComparePosition} '{$ruleToCompare->name()}' because it's placed before");
                }
                else if( $nextDenyRule !== FALSE && $nextDenyRulePosition < $ruleToComparePosition )
                {
                    if( !$this->UTIL_mergeDenyRules )
                    {
                        unset($matchingHashTable[$ruleToCompare->serial]);
                        PH::print_stdout( "    - ignoring rule #{$ruleToComparePosition} '{$ruleToCompare->name()}' because DENY rule #{$nextDenyRulePosition} '{$nextDenyRule->name()}' is placed before");
                    }
                }
                elseif( $this->UTIL_filterQuery !== null && !$this->UTIL_filterQuery->matchSingleObject($ruleToCompare) )
                {
                    unset($matchingHashTable[$ruleToCompare->serial]);
                    PH::print_stdout( "    - ignoring rule #{$ruleToComparePosition} '{$ruleToCompare->name()}' because it's not matchin the filter query");
                }
                elseif( ($rule->sourceIsNegated() or $rule->destinationIsNegated()) or ($ruleToCompare->sourceIsNegated() or $ruleToCompare->destinationIsNegated()) )
                {
                    if( $rule->sourceIsNegated() && $ruleToCompare->sourceIsNegated() )
                        continue;
                    elseif( $rule->destinationIsNegated() && $ruleToCompare->destinationIsNegated() )
                        continue;
                    else
                    {
                        unset($matchingHashTable[$ruleToCompare->serial]);
                        PH::print_stdout( "    - ignoring rule #{$ruleToComparePosition} '{$ruleToCompare->name()}' because it's source / destination is not matching NEGATION of original Rule");
                    }
                }
            }

            if( count($matchingHashTable) == 0 )
            {
                PH::print_stdout( "    - no more rules to match with");
                unset($this->UTIL_hashTable[$rule->mergeHash][$rule->serial]);
                continue;
            }

            $adjacencyPositionReference = $rulePosition;


            PH::print_stdout( "       - Now merging with the following " . count($matchingHashTable) . " rules:");

            foreach( $matchingHashTable as $ruleToCompare )
            {
                if( $this->UTIL_mergeAdjacentOnly )
                {
                    $ruleToComparePosition = $this->UTIL_rulesArrayIndex[$ruleToCompare->indexPosition];
                    $adjacencyPositionDiff = $ruleToComparePosition - $adjacencyPositionReference;
                    if( $adjacencyPositionDiff < 1 )
                        derr('an unexpected event occured');

                    if( $adjacencyPositionDiff > 1 )
                    {
                        PH::print_stdout( "    - ignored '{$ruleToCompare->name()}' because of option 'mergeAdjacentOnly'");
                        break;
                    }
                    //PH::print_stdout( "    - adjacencyDiff={$adjacencyPositionDiff}" );

                    $adjacencyPositionReference = $ruleToComparePosition;
                }
                if( $this->UTIL_method == 1 )
                {
                    // merging on services requires extra checks for application-default vs non app default
                    if( $rule->services->isApplicationDefault() )
                    {
                        if( !$ruleToCompare->services->isApplicationDefault() )
                        {
                            PH::print_stdout( "    - ignored '{$ruleToCompare->name()}' because it is not Application-Default");
                            break;
                        }
                    }
                    else
                    {
                        if( $ruleToCompare->services->isApplicationDefault() )
                        {
                            PH::print_stdout( "    - ignored '{$ruleToCompare->name()}' because it is Application-Default");
                            break;
                        }
                    }
                }

                $ruleToCompare->display(9);
                #$this->deletedObjects[$rule->name()]['kept'] = $rule;
                #$this->deletedObjects[$rule->name()]['removed'][$ruleToCompare->name()] =  $ruleToCompare;



                $line = "";
                foreach( $this->context->fields as $fieldName => $fieldID )
                    $line .= $this->context->ruleFieldHtmlExport($ruleToCompare, $fieldID);
                $this->deletedObjects[$rule->name()]['removed'][$ruleToCompare->name()] = $line;

                #self::deletedObjectSetRemoved( $rule, $ruleToCompare );
                $this->UTIL_mergeRules($rule, $ruleToCompare);
                $mergedRulesCount++;
            }

            PH::print_stdout( "    - Rule after merge:");
            $rule->display(5);

            $line = "";
            foreach( $this->context->fields as $fieldName => $fieldID )
                $line .= $this->context->ruleFieldHtmlExport($rule, $fieldID);
            $this->deletedObjects[$rule->name()]['kept'] = $line;

            if( $this->action === "merge" )
            {
                if( $this->apiMode && $this->configOutput == null )
                    $rule->API_sync();
            }
            unset($this->UTIL_hashTable[$rule->mergeHash][$rule->serial]);
        }

        PH::print_stdout( "*** MERGING DONE : {$mergedRulesCount} rules merged over " . count($this->UTIL_rulesToProcess) . " in total (" . (count($this->UTIL_rulesToProcess) - $mergedRulesCount) . " remaining) ***");
    }
    
    function supportedMethods()
    {
        //
        //  methods array preparation
        //
        $supportedMethods_tmp = array(
            'matchFromToSrcDstApp' => 1,
            'matchFromToSrcDstSvc' => 2,
            'matchFromToSrcSvcApp' => 3,
            'matchFromToDstSvcApp' => 4,
            'matchFromSrcDstSvcApp' => 5,
            'matchToSrcDstSvcApp' => 6,
            'matchToDstSvcApp' => 7,
            'matchFromSrcSvcApp' => 8,
            'identical' => 9,
        );
        foreach( $supportedMethods_tmp as $methodName => $method )
        {
            $this->supportedMethods[strtolower($methodName)] = $method;
        }
        $methodsNameList = array_flip($supportedMethods_tmp);
        $this->supportedArguments['method']['shortHelp'] .= PH::list_to_string($methodsNameList);
    }

    function add_supported_arguments()
    {
        $this->supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments[] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes, API is not supported because it could be a heavy duty on management. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => 'sub1');
        $this->supportedArguments[] = array('niceName' => 'Method', 'shortHelp' => 'rules will be merged if they match given a specific method, available methods are: ', 'argDesc' => 'method1');
        $this->supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments[] = array('niceName' => 'panoramaPreRules', 'shortHelp' => 'when using panorama, select pre-rulebase for merging');
        $this->supportedArguments[] = array('niceName' => 'panoramaPostRules', 'shortHelp' => 'when using panorama, select post-rulebase for merging');
        $this->supportedArguments[] = array('niceName' => 'mergeDenyRules', 'shortHelp' => 'deny rules wont be merged', 'argDesc' => '[yes|no|true|false]');
        $this->supportedArguments[] = array('niceName' => 'stopMergingIfDenySeen', 'shortHelp' => 'deny rules wont be merged', 'argDesc' => '[yes|no|true|false]');
        $this->supportedArguments[] = array('niceName' => 'mergeAdjacentOnly', 'shortHelp' => 'merge only rules that are adjacent to each other', 'argDesc' => '[yes|no|true|false]');
        $this->supportedArguments[] = array('niceName' => 'filter', 'shortHelp' => 'filter rules that can be converted');
        $this->supportedArguments[] = array('niceName' => 'additionalMatch', 'shortHelp' => 'add additional matching criterial', 'argDesc' => '[tag,secprof,user,urlcategory,target]');
        $this->supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments[] = array('niceName' => 'exportCSV', 'shortHelp' => 'when this argument is specified, it instructs the script to display the kept and removed objects per value');
    }

    function mergerArguments()
    {
        if( $this->pan->isPanorama() )
        {
            if( !isset(PH::$args[strtolower('panoramaPreRules')]) && !isset(PH::$args[strtolower('panoramaPostRules')]) )
                $this->display_error_usage_exit("Panorama was detected but no Pre or Post rules were selected, use CLI argument 'panoramaPreRules' or 'panoramaPostRules'");

            if( isset(PH::$args[strtolower('panoramaPreRules')]) && isset(PH::$args[strtolower('panoramaPostRules')]) )
                $this->display_error_usage_exit("both panoramaPreRules and panoramaPostRules were selected, please choose one of them");

            if( isset(PH::$args[strtolower('panoramaPostRules')]) )
                $this->panoramaPreRuleSelected = FALSE;

        }
        elseif( $this->pan->isFawkes() )
        {
            $sub = $this->pan->findContainer($this->objectsLocation);
            if( $sub === null )
                $sub = $this->pan->findDeviceCloud($this->objectsLocation);
            if( $sub === null )
                $this->locationNotFound($this->objectsLocation);

            if( $sub->isContainer() )
            {
                if( !isset(PH::$args[strtolower('panoramaPreRules')]) && !isset(PH::$args[strtolower('panoramaPostRules')]) )
                    $this->display_error_usage_exit("Fawkes Container was detected but no Pre or Post rules were selected, use CLI argument 'panoramaPreRules' or 'panoramaPostRules'");

                if( isset(PH::$args[strtolower('panoramaPreRules')]) && isset(PH::$args[strtolower('panoramaPostRules')]) )
                    $this->display_error_usage_exit("both panoramaPreRules and panoramaPostRules were selected, please choose one of them");

                if( isset(PH::$args[strtolower('panoramaPostRules')]) )
                    $this->panoramaPreRuleSelected = FALSE;
            }
        }


        if( !isset(PH::$args['method']) )
            $this->display_error_usage_exit(' no method was provided');
        $this->UTIL_method = strtolower(PH::$args['method']);
        if( !isset($this->supportedMethods[$this->UTIL_method]) )
            $this->display_error_usage_exit("unsupported method '" . PH::$args['method'] . "' provided");
        $this->UTIL_method = $this->supportedMethods[$this->UTIL_method];


        if( !isset(PH::$args['mergedenyrules']) )
        {
            PH::print_stdout( " - No 'mergeDenyRule' argument provided, using default 'no'");
            $this->UTIL_mergeDenyRules = FALSE;
        }
        else
        {
            if( PH::$args['mergedenyrules'] === null || strlen(PH::$args['mergedenyrules']) == 0 )
                $this->UTIL_mergeDenyRules = TRUE;
            elseif( strtolower(PH::$args['mergedenyrules']) == 'yes' || strtolower(PH::$args['mergedenyrules']) == 'true' )
                $this->UTIL_mergeDenyRules = TRUE;
            elseif( strtolower(PH::$args['mergedenyrules']) == 'no' || strtolower(PH::$args['mergedenyrules']) == 'false' )
                $this->UTIL_mergeDenyRules = FALSE;
            else
                $this->display_error_usage_exit("'mergeDenyRules' argument was given unsupported value '" . PH::$args['mergedenyrules'] . "'");
        }


        if( !isset(PH::$args['stopmergingifdenyseen']) )
        {
            PH::print_stdout( " - No 'stopMergingIfDenySeen' argument provided, using default 'yes'");
            $this->UTIL_stopMergingIfDenySeen = TRUE;
        }
        else
        {
            if( PH::$args['stopmergingifdenyseen'] === null || strlen(PH::$args['stopmergingifdenyseen']) == 0 )
                $this->UTIL_stopMergingIfDenySeen = TRUE;
            elseif( strtolower(PH::$args['stopmergingifdenyseen']) == 'yes'
                || strtolower(PH::$args['stopmergingifdenyseen']) == 'true'
                || strtolower(PH::$args['stopmergingifdenyseen']) == 1 )
                $this->UTIL_stopMergingIfDenySeen = TRUE;
            elseif( strtolower(PH::$args['stopmergingifdenyseen']) == 'no'
                || strtolower(PH::$args['stopmergingifdenyseen']) == 'false'
                || strtolower(PH::$args['stopmergingifdenyseen']) == 0 )
                $this->UTIL_stopMergingIfDenySeen = FALSE;
            else
                $this->display_error_usage_exit("'stopMergingIfDenySeen' argument was given unsupported value '" . PH::$args['stopmergingifdenyseen'] . "'");
        }

        if( !isset(PH::$args['mergeadjacentonly']) )
        {
            PH::print_stdout( " - No 'mergeAdjacentOnly' argument provided, using default 'no'");
            $this->UTIL_mergeAdjacentOnly = FALSE;
        }
        else
        {
            if( PH::$args['mergeadjacentonly'] === null || strlen(PH::$args['mergeadjacentonly']) == 0 )
                $this->UTIL_mergeAdjacentOnly = TRUE;

            elseif( strtolower(PH::$args['mergeadjacentonly']) == 'yes'
                || strtolower(PH::$args['mergeadjacentonly']) == 'true'
                || strtolower(PH::$args['mergeadjacentonly']) == 1 )

                $this->UTIL_mergeAdjacentOnly = TRUE;

            elseif( strtolower(PH::$args['mergeadjacentonly']) == 'no'
                || strtolower(PH::$args['mergeadjacentonly']) == 'false'
                || strtolower(PH::$args['mergeadjacentonly']) == 0 )

                $this->UTIL_mergeAdjacentOnly = FALSE;
            else
                $this->display_error_usage_exit("(mergeAdjacentOnly' argument was given unsupported value '" . PH::$args['mergeadjacentonly'] . "'");
            PH::print_stdout( " - mergeAdjacentOnly = " . boolYesNo($this->UTIL_mergeAdjacentOnly) );
        }
    }

    function merger_location_array($utilType, $objectsLocation, $pan)
    {
        $this->utilType = $utilType;

        if( $objectsLocation == 'any' )
        {
            if( $pan->isPanorama() )
            {
                $alldevicegroup = $pan->deviceGroups;
            }
            elseif( $pan->isFawkes() )
            {
                $subGroups = $pan->getContainers();
                $subGroups2 = $pan->getDeviceClouds();

                $alldevicegroup = array_merge( $subGroups, $subGroups2 );

                $subGroups2 = $this->pan->getDeviceOnPrems();
                $alldevicegroup = array_merge( $alldevicegroup, $subGroups2 );
            }
            elseif( $pan->isFirewall() )
                $alldevicegroup = $pan->virtualSystems;
            else
                $alldevicegroup = $pan->virtualSystems;

            $location_array = array();
            foreach( $alldevicegroup as $key => $tmp_location )
            {
                $objectsLocation = $tmp_location->name();
                $findLocation = $pan->findSubSystemByName($objectsLocation);
                if( $findLocation === null )
                    $this->locationNotFound( $objectsLocation );

                if( $this->utilType == "rule-merger" )
                {
                    /** @var DeviceGroup $findLocation */
                    $store = $findLocation->securityRules;
                    if( isset( $findLocation->owner->securityRules ) )
                        $parentStore = $findLocation->owner->securityRules;
                    else
                        $parentStore = null;
                }

                if( get_class( $findLocation->owner ) == "FawkesConf" )
                    $parentStore = null;


                $location_array[$key]['findLocation'] = $findLocation;
                $location_array[$key]['store'] = $store;
                $location_array[$key]['parentStore'] = $parentStore;
                if( $pan->isPanorama() )
                {
                    $childDeviceGroups = $findLocation->childDeviceGroups(TRUE);
                    $location_array[$key]['childDeviceGroups'] = $childDeviceGroups;
                }
                elseif( $pan->isFawkes() )
                {
                    //child Container/CloudDevices
                    //Todo: swaschkut 20210414
                    $location_array[$key]['childDeviceGroups'] = array();
                }
                else
                    $location_array[$key]['childDeviceGroups'] = array();
            }

            $location_array = array_reverse($location_array);

            if( !$pan->isFawkes() )
            {
                $location_array[$key + 1]['findLocation'] = 'shared';
                if( $this->utilType == "rule-merger"  )
                {
                    if( isset( $pan->securityRules ) )
                        $location_array[$key + 1]['store'] = $pan->securityRules;
                    else
                        $location_array[$key + 1]['store'] = null;
                }


                $location_array[$key + 1]['parentStore'] = null;
                $location_array[$key + 1]['childDeviceGroups'] = $alldevicegroup;
            }
        }
        else
        {
            if( !$pan->isFawkes() && $objectsLocation == 'shared' )
            {
                if( $this->utilType == "rule-merger"  )
                    $store = $pan->securityRules;

                $parentStore = null;
                $location_array[0]['findLocation'] = $objectsLocation;
                $location_array[0]['store'] = $store;
                $location_array[0]['parentStore'] = $parentStore;
            }
            else
            {
                $findLocation = $pan->findSubSystemByName($objectsLocation);
                if( $findLocation === null )
                    $this->locationNotFound( $objectsLocation );

                if( $this->utilType == "rule-merger"  )
                {
                    $store = $findLocation->securityRules;

                    if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                        $parentStore = $findLocation->parentDeviceGroup->securityRules;
                    elseif( $pan->isFawkes() && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                        $parentStore = $findLocation->parentContainer->securityRules;
                    elseif( isset( $findLocation->owner->securityRules ) )
                        $parentStore = $findLocation->owner->securityRules;
                    else
                        $parentStore = null;
                }
                if( get_class( $findLocation->owner ) == "FawkesConf" )
                    $parentStore = null;

                $location_array[0]['findLocation'] = $findLocation;
                $location_array[0]['store'] = $store;
                $location_array[0]['parentStore'] = $parentStore;
            }

            if( $pan->isPanorama() )
            {
                if( $objectsLocation == 'shared' )
                    $childDeviceGroups = $pan->deviceGroups;
                else
                    $childDeviceGroups = $findLocation->childDeviceGroups(TRUE);
                $location_array[0]['childDeviceGroups'] = $childDeviceGroups;
            }
            elseif( $pan->isFawkes() )
            {
                //child Container/CloudDevices
                //Todo: swaschkut 20210414
                $location_array[0]['childDeviceGroups'] = array();
            }
            else
                $location_array[0]['childDeviceGroups'] = array();
        }

        return $location_array;
    }

    private function deletedObjectSetRemoved( $index, &$rule )
    {
        #if( !isset( $this->deletedObjects[$index]['removed'] ) )
        #    $this->deletedObjects[$index]['removed'] = "";

        $this->deletedObjects[$index->name()]['removed'][] =  &$rule;
    }

    function exportCSVToHtml( $skipped = FALSE)
    {
        if( !$skipped )
            $headers = '<th>ID</th><th>rule name</th>';
        else
            $headers = '<th>ID</th><th>rule name</th>';

        foreach( $this->context->fields as $tmpfield )
            $headers .= '<th>'.$tmpfield.'</th>';

        $lines = '';
        $encloseFunction = function ($value, $nowrap = TRUE) {
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
            {
                derr('unsupported: '.$value);
            }


            if( $nowrap )
                return '<td style="white-space: nowrap">' . $output . '</td>';

            return '<td>' . $output . '</td>';
        };

        $obj_Array = array();
        if( !$skipped )
        {
            if( isset($this->deletedObjects) )
                $obj_Array = $this->deletedObjects;
        }
        else
        {
            if( isset($this->skippedObjects) )
                $obj_Array = $this->skippedObjects;
        }

        $count = 0;
        foreach( $obj_Array as $index => $line )
        {
            $count++;

            if( $count % 2 == 1 )
            {
                $color = false;
                $lines .= "<tr>\n";
            }
            else
            {
                $lines .= "<tr bgcolor=\"#DDDDDD\">";
                $color = true;
            }


            $lines .= $encloseFunction( (string)$count );

            $lines .= $encloseFunction( (string)$index );
            #$lines .= $encloseFunction( $line['kept']->name() );

            #if( isset( $line['kept'] ) )
            #    $lines .= $encloseFunction( $line['kept'] );
            #else
            #    $lines .= $encloseFunction( "" );

            ##$removedArray = explode( "|", $line['removed'] );
            ##$lines .= $encloseFunction( $removedArray );
            #$lines .= $encloseFunction( $line['removed'] );

            $lines .= $line['kept'] ;


            $lines .= "</tr>\n";

            $first = true;
            foreach( $line['removed'] as  $removed )
            {
                if( $first )
                {
                    if( $color === false )
                        $lines .= "<tr>\n";
                    else
                        $lines .= "<tr bgcolor=\"#DDDDDD\">";

                    $lines .= $encloseFunction( "---" );
                    $lines .= $encloseFunction( "manipulated" );

                    #$lines .= $encloseFunction( (string)$index );

                    $lines .=  $line['manipulated'] ;

                    $lines .= "</tr>\n";
                    $first = false;
                }

                if( $color === false )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $encloseFunction( "---" );
                $lines .= $encloseFunction( "removed" );

                #$lines .= $encloseFunction( (string)$index );

                $lines .=  $removed ;




                $lines .= "</tr>\n";
            }


        }

        $content = file_get_contents(dirname(__FILE__) . '/../common/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/../common/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/../common/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        if( PH::$shadow_json )
            PH::$JSON_OUT['exportcsv'] = $content;

        if( !$skipped )
            $filename = $this->exportcsvFile;
        else
            $filename = "skipped-".$this->exportcsvFile;
        file_put_contents($filename, $content);
    }
}