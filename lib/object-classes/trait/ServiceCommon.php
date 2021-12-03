<?php
/**
 * ISC License
 *
  * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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
                    PH::print_stdout( $outputPadding . "- adding in {$ref->_PANC_shortName()}" );
                $ref->addMember($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        PH::print_stdout( $outputPadding . "- adding in {$ref->owner->_PANC_shortName()}" );

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
                    PH::print_stdout( $outputPadding . "- adding in {$ref->_PANC_shortName()}" );
                $ref->API_addMember($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        PH::print_stdout( $outputPadding . "- adding in {$ref->owner->_PANC_shortName()}" );

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
                    PH::print_stdout( $outputPadding . "- removing from {$ref->_PANC_shortName()}" );
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
                        PH::print_stdout( $outputPadding . "- last member so deleting {$ref->_PANC_shortName()}" );
                    $rule = $ref->owner;
                    if( $apiMode )
                    {
                        $ref->owner->owner->API_remove($ref->owner, TRUE);
                        if( isset($rule->appConvertedRule) )
                        {
                            if( $displayOutput )
                                PH::print_stdout( $outputPadding . "  - due to rule: '".$rule->name()."' deleting, rename 'app' one with original rulename" );
                            $rule->appConvertedRule->API_setName($rule->name());
                        }

                    }
                    else
                    {
                        $ref->owner->owner->remove($ref->owner, TRUE);
                        if( isset($rule->appConvertedRule) )
                        {
                            if( $displayOutput )
                                PH::print_stdout( $outputPadding . "  - due to rule: '".$rule->name()."' deleting, rename 'app' one with original rulename" );
                            $rule->appConvertedRule->setName($rule->name());
                        }

                    }

                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        PH::print_stdout( $outputPadding . "- last member so setting ANY {$ref->_PANC_shortName()}" );
                    if( $apiMode )
                        $ref->API_setAny();
                    else
                        $ref->setAny();
                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        PH::print_stdout( $outputPadding . "- last member so disabling rule {$ref->_PANC_shortName()}" );
                    if( $apiMode )
                        $ref->owner->API_setDisabled(TRUE);
                    else
                        $ref->owner->setDisabled(TRUE);
                }
                else
                {
                    if( $displayOutput )
                        PH::print_stdout( $outputPadding . "- removing from {$ref->_PANC_shortName()}" );
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
                        PH::print_stdout( $outputPadding . "- last member so deleting {$ref->_PANC_shortName()}" );
                    if( $apiMode )
                        $ref->owner->API_remove($ref, TRUE);
                    else
                        $ref->owner->remove($ref, TRUE);
                }
                elseif( $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        PH::print_stdout( $outputPadding . "- last member so setting ANY {$ref->_PANC_shortName()}" );
                    if( $apiMode )
                        $ref->API_setService(null);
                    else
                        $ref->setService(null);
                }
                elseif( $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        PH::print_stdout( $outputPadding . "- last member so disabling rule {$ref->_PANC_shortName()}" );
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

        $success = true;

        if( is_numeric($outputPadding) )
            $outputPadding = str_pad(' ', $outputPadding);

        /** @var ServiceGroup|ServiceRuleContainer $objectRef */

        foreach( $this->refrules as $objectRef )
        {

            if( ($this->isService() && $withObject->isService()) )
            {
                if( $this->type !== $withObject->type )
                {
                    PH::print_stdout("- SKIP: not possible due to different object type");
                    continue;
                }

                $tmp_store = null;
                if(  (get_class($objectRef) == "ServiceGroup") )
                    $tmp_store = $objectRef->owner;
                elseif(  (get_class($objectRef) == "NatRule") )
                    $tmp_store = $objectRef->owner->owner->serviceStore;
                elseif( (get_class($objectRef) == "ServiceRuleContainer") )
                    $tmp_store = $objectRef->owner->owner->owner->serviceStore;
                else
                    $tmp_store = $objectRef->owner->owner->owner->serviceStore;

                $tmp_addr = $tmp_store->find( $withObject->name() );
                if( $tmp_addr === null )
                    $tmp_addr = $tmp_store->parentCentralStore->find( $withObject->name() );

                if( !$tmp_addr->isService() )
                {
                    PH::print_stdout( "- SKIP: not possible due to different object type" );
                    $success = false;
                    continue;
                }

                if( $withObject->getDestPort() !== $tmp_addr->getDestPort() || $withObject->getSourcePort() !== $tmp_addr->getSourcePort()  )
                {
                    PH::print_stdout( "- SKIP: not possible to replace due to different value: {$objectRef->toString()}" );
                    PH::print_stdout( " - '".$withObject->getDestPort()."[".$withObject->getSourcePort()."]"."' | '".$tmp_addr->getDestPort()."[".$tmp_addr->getSourcePort()."]"."'" );
                    $success = false;
                    continue;
                }

            }

            if( $displayOutput )
                PH::print_stdout( $outputPadding . "- replacing in {$objectRef->toString()}" );
            if( $apiMode )
                $objectRef->API_replaceReferencedObject($this, $withObject);
            else
                $objectRef->replaceReferencedObject($this, $withObject);
        }

        return $success;
    }

}