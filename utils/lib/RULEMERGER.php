<?php

class RULEMERGER extends UTIL
{

    public $UTIL_hashTable;
    public $UTIL_method;
    public $UTIL_additionalMatch;
    public $UTIL_rulesToProcess;
    public $UTIL_stopMergingIfDenySeen;
    public $UTIL_denyRules;
    public $UTIL_mergeAdjacentOnly;
    public $UTIL_rulesArrayIndex;

    public $UTIL_mergeDenyRules;
    public $UTIL_filterQuery;

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

        if( $this->UTIL_additionalMatch == 'tag' )
            $additional_match = $rule->tags->getFastHashComp();
        else
            $additional_match = "";

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
        /*          'matchFromToSrcDstApp'  => 1 ,
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
        if( $this->configInput['type'] == 'api' && $this->configOutput == null )
            $ruleToMerge->owner->API_remove($ruleToMerge);
        else
            $ruleToMerge->owner->remove($ruleToMerge);
        $ruleToMerge->alreadyMerged = TRUE;

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
                $this->UTIL_mergeRules($rule, $ruleToCompare);
                $mergedRulesCount++;
            }

            PH::print_stdout( "    - Rule after merge:");
            $rule->display(5);

            if( $this->configInput['type'] == 'api' && $this->configOutput == null )
                $rule->API_sync();
            unset($this->UTIL_hashTable[$rule->mergeHash][$rule->serial]);

        }

        PH::print_stdout( "*** MERGING DONE : {$mergedRulesCount} rules merged over " . count($this->UTIL_rulesToProcess) . " in total (" . (count($this->UTIL_rulesToProcess) - $mergedRulesCount) . " remaining) ***");
    }

}