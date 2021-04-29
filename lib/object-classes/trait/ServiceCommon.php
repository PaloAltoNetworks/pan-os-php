<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

trait ServiceCommon
{
    use ReferenceableObject
    {
        removeReference as super_removeReference;
    }

    public function isService()
    {
        return FALSE;
    }

    public function isGroup()
    {
        return FALSE;
    }

    public function isTmpSrv()
    {
        return FALSE;
    }

    public function removeReference($ref)
    {
        $this->super_removeReference($ref);
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = FALSE, $outputPadding = '', $skipIfConflict = FALSE)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach( $this->refrules as $ref )
        {
            $refClass = get_class($ref);
            if( $refClass == 'ServiceGroup' )
            {
                /** @var ServiceGroup $ref */
                if( $displayOutput )
                    print $outputPadding . "- adding in {$ref->_PANC_shortName()}\n";
                $ref->addMember($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    derr('unsupported use case in ' . $ref->_PANC_shortName());
                }
                else
                    derr('unsupported owner_class: ' . $ruleClass);
            }
            else
                derr('unsupport class : ' . $refClass);
        }
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = FALSE, $outputPadding = '', $skipIfConflict = FALSE)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach( $this->refrules as $ref )
        {
            $refClass = get_class($ref);
            if( $refClass == 'ServiceGroup' )
            {
                /** @var ServiceGroup $ref */
                if( $displayOutput )
                    print $outputPadding . "- adding in {$ref->_PANC_shortName()}\n";
                $ref->API_addMember($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    derr('unsupported use case in ' . $ref->_PANC_shortName());
                }
                else
                    derr('unsupported owner_class: ' . $ruleClass);
            }
            else
                derr('unsupported class : ' . $refClass);
        }
    }

    /**
     * @param $displayOutput bool
     * @param $apiMode bool
     * @param $actionIfLastInRule string can be delete|setany|disable
     * @param $outputPadding string|int
     */
    private function __removeWhereIamUsed($apiMode, $displayOutput = FALSE, $outputPadding = '', $actionIfLastInRule = 'delete')
    {
        /** @var Service|ServiceGroup $this */

        if( is_numeric($outputPadding) )
            $outputPadding = str_pad(' ', $outputPadding);

        $allowedActionIfLastInRule = array('delete' => TRUE, 'setany' => TRUE, 'disable' => TRUE);
        if( !isset($allowedActionIfLastInRule[$actionIfLastInRule]) )
            derr('unsupported actionIfLastInRule=' . $actionIfLastInRule);

        foreach( $this->getReferences() as $ref )
        {
            $refClass = get_class($ref);
            if( $refClass == 'ServiceGroup' )
            {
                /** @var ServiceGroup $ref */
                if( $displayOutput )
                    print $outputPadding . "- removing from {$ref->_PANC_shortName()}\n";
                if( $apiMode )
                    $ref->API_removeMember($this);
                else
                    $ref->removeMember($this);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */
                if( $ref->count() <= 1 && $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so deleting {$ref->_PANC_shortName()}\n";
                    $rule = $ref->owner;
                    if( $apiMode )
                    {
                        $ref->owner->owner->API_remove($ref->owner, TRUE);
                        if( isset($rule->appConvertedRule) )
                        {
                            if( $displayOutput )
                                print $outputPadding . "  - due to rule: '".$rule->name()."' deleting, rename 'app' one with original rulename\n";
                            $rule->appConvertedRule->API_setName($rule->name());
                        }

                    }
                    else
                    {
                        $ref->owner->owner->remove($ref->owner, TRUE);
                        if( isset($rule->appConvertedRule) )
                        {
                            if( $displayOutput )
                                print $outputPadding . "  - due to rule: '".$rule->name()."' deleting, rename 'app' one with original rulename\n";
                            $rule->appConvertedRule->setName($rule->name());
                        }

                    }

                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so setting ANY {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setAny();
                    else
                        $ref->setAny();
                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so disabling rule {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->owner->API_setDisabled(TRUE);
                    else
                        $ref->owner->setDisabled(TRUE);
                }
                else
                {
                    if( $displayOutput )
                        print $outputPadding . "- removing from {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_remove($this);
                    else
                        $ref->remove($this);
                }
            }
            elseif( $refClass == 'NatRule' )
            {
                /** @var NatRule $ref */
                if( $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so deleting {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->owner->API_remove($ref, TRUE);
                    else
                        $ref->owner->remove($ref, TRUE);
                }
                elseif( $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so setting ANY {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setService(null);
                    else
                        $ref->setService(null);
                }
                elseif( $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so disabling rule {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setDisabled(TRUE);
                    else
                        $ref->setDisabled(TRUE);
                }
                else
                {
                    derr('unsupported');
                }
            }
            else
                derr("unsupported class '{$refClass}'");
        }
    }

    /**
     * @param $displayOutput bool
     * @param $actionIfLastInRule string can be delete|setany|disable
     * @param $outputPadding string|int
     */
    public function removeWhereIamUsed($displayOutput = FALSE, $outputPadding = '', $actionIfLastInRule = 'delete')
    {
        $this->__removeWhereIamUsed(FALSE, $displayOutput, $outputPadding, $actionIfLastInRule);
    }

    /**
     * @param bool $displayOutput
     * @param string $actionIfLastInRule can be delete|setany|disable
     * @param $outputPadding string|int
     */
    public function API_removeWhereIamUsed($displayOutput = FALSE, $outputPadding = '', $actionIfLastInRule = 'delete')
    {
        $this->__removeWhereIamUsed(TRUE, $displayOutput, $outputPadding, $actionIfLastInRule);
    }


    /**
     * @param bool $displayOutput
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function API_replaceWhereIamUsed($withObject, $displayOutput = FALSE, $outputPadding = '')
    {
        $this->__removeWhereIamUsed(TRUE, $withObject, $displayOutput, $outputPadding);
    }

    /**
     * @param bool $displayOutput
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function replaceWhereIamUsed($withObject, $displayOutput = FALSE, $outputPadding = '')
    {
        $this->__removeWhereIamUsed(FALSE, $withObject, $displayOutput, $outputPadding);
    }


    /**
     * @param bool $displayOutput
     * @param bool $apiMode
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function __replaceWhereIamUsed($apiMode, $withObject, $displayOutput = FALSE, $outputPadding = '')
    {
        /** @var Service|ServiceGroup $this */

        if( is_numeric($outputPadding) )
            $outputPadding = str_pad(' ', $outputPadding);

        /** @var ServiceGroup|ServiceRuleContainer $objectRef */

        foreach( $this->refrules as $objectRef )
        {
            if( $displayOutput )
                echo $outputPadding . "- replacing in {$objectRef->toString()}\n";
            if( $apiMode )
                $objectRef->API_replaceReferencedObject($this, $withObject);
            else
                $objectRef->replaceReferencedObject($this, $withObject);
        }

    }

}