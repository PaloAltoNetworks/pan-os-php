<?php


// <editor-fold desc=" ***** Rule filters *****" defaultstate="collapsed" >

//                                              //
//                Zone Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['from']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() && !$object->isZoneBased() )
            return $object->from->hasInterface($value) === TRUE;

        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->from->hasInterface($value) === TRUE;

        return $object->from->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"


);
RQuery::$defaultFilters['rule']['from']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() && !$object->isZoneBased() )
            return $object->from->hasInterface($value) === TRUE && $object->from->count() == 1;
        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->from->hasInterface($value) === TRUE && $object->from->count() == 1;

        return $object->from->count() == 1 && $object->from->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"
);


RQuery::$defaultFilters['rule']['to']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return FALSE;

        if( $object->isDoSRule() && !$object->isZoneBasedTo() )
            return $object->to->hasInterface($value) === TRUE;

        return $object->to->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => function ($object, $argument) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return FALSE;

        return $object->to->parentCentralStore->find($argument);
    },
    'help' => 'returns TRUE if field TO is using zone mentionned in argument. Ie: "(to has Untrust)"'
);
RQuery::$defaultFilters['rule']['to']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return FALSE;

        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->to->hasInterface($value) === TRUE && $object->to->count() == 1;

        return $object->to->count() == 1 && $object->to->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->to->parentCentralStore->find('!value!');"
);


RQuery::$defaultFilters['rule']['from']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        foreach( $context->object->from->zones() as $zone )
        {
            $matching = preg_match($context->value, $zone->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE,
);
RQuery::$defaultFilters['rule']['to']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isPbfRule() )
            return FALSE;

        foreach( $context->object->to->zones() as $zone )
        {
            $matching = preg_match($context->value, $zone->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE,
);

RQuery::$defaultFilters['rule']['from.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->from->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['to.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->to->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['from']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->from->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['to']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isPbfRule() )
            return FALSE;

        return $context->object->to->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['from']['operators']['is.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        $return = FALSE;
        foreach( $list as $zone => $truefalse )
        {
            if( $object->from->hasZone($zone) )
                $return = TRUE;
        }

        return $return;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);

RQuery::$defaultFilters['rule']['to']['operators']['is.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        $return = FALSE;
        foreach( $list as $zone => $truefalse )
        {
            if( $object->to->hasZone($zone) )
                $return = TRUE;
        }

        return $return;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);
//                                              //
//                NAT Dst/Src Based Actions     //
//                                              //
RQuery::$defaultFilters['rule']['snathost']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;

        return $object->snathosts->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->owner->owner->addressStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['snathost']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;

        if( $object->snathosts->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->snathosts->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(snathost has.from.query subquery1)\' \'subquery1=(netmask < 32)\'',
);
RQuery::$defaultFilters['rule']['snathost.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->isNatRule() && \$object->snathosts->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnathost === null ) return FALSE;

        return $object->dnathost === $value;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->owner->owner->addressStore->find('!value!');"
);

RQuery::$defaultFilters['rule']['dnathost']['operators']['included-in.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includedInIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'argDesc' => 'ie: 192.168.0.0/24 | 192.168.50.10/32 | 192.168.50.10 | 10.0.0.0-10.33.0.0',
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['included-in.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includedInIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includedInIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['includes.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includesIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['includes.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includesIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includesIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                SNAT Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['snat']['operators']['is.static'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( !$context->object->sourceNatTypeIs_Static() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['snat']['operators']['is.dynamic-ip'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( !$context->object->sourceNatTypeIs_Dynamic() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['snat']['operators']['is.dynamic-ip-and-port'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        if( !$context->object->sourceNatTypeIs_DIPP() )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['snat']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( $context->object->sourceNatTypeIs_None() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                SNAT interface Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['dst-interface']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        return $context->object->hasDestinationInterface();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                DNAT Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['dnat']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( !$context->object->destinationNatIsEnabled() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                Dst/Src Based Actions            //
//                                              //


RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.list'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $list = &$context->value;

    if( !isset($context->cachedIP4Mapping) )
    {
        $listMapping = new IP4Map();

        foreach( $list as $item )
            $listMapping->addMap(IP4Map::mapFromText($item), FALSE);

        $listMapping->sortAndRecalculate();

        $context->cachedIP4Mapping = $listMapping;
    }
    else
        $listMapping = $context->cachedIP4Mapping;

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) == 1;
};

RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.list'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $list = &$context->value;

    if( !isset($context->cachedIP4Mapping) )
    {
        $listMapping = new IP4Map();

        foreach( $list as $item )
            $listMapping->addMap(IP4Map::mapFromText($item), FALSE);

        $listMapping->sortAndRecalculate();

        $context->cachedIP4Mapping = $listMapping;
    }
    else
        $listMapping = $context->cachedIP4Mapping;

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) == 2;
};

RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.list'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $list = &$context->value;

    /** @var IP4Map $lisMapping */

    if( !isset($context->cachedIP4Mapping) )
    {
        $listMapping = new IP4Map();

        foreach( $list as $item )
            $listMapping->addMap(IP4Map::mapFromText($item), FALSE);

        $listMapping->sortAndRecalculate();

        $context->cachedIP4Mapping = $listMapping;
    }
    else
        $listMapping = $context->cachedIP4Mapping;

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) > 0;
};


RQuery::$defaultFilters['rule']['src']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['src']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->count() == 1 && $object->source->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->hasObjectRecursive($value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $members = $context->object->source->membersExpanded(TRUE);

        foreach( $members as $member )
        {
            $matching = preg_match($context->value, $member->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['dst']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->destination->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['dst']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->destination->count() == 1 && $object->destination->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive'] = array(
    'eval' => '$object->destination->hasObjectRecursive(!value!, false) === true',
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $members = $context->object->destination->membersExpanded(TRUE);

        foreach( $members as $member )
        {
            $matching = preg_match($context->value, $member->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['src']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->count() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->count() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['is.negated'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isNatRule() )
            return FALSE;

        return $context->object->sourceIsNegated();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.negated'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isNatRule() )
            return FALSE;

        return $context->object->destinationIsNegated();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['src']['operators']['included-in.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includedInIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['included-in.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includedInIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includedInIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includesIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includesIP4Network($context->value) == 2;
    },
    'arg' => TRUE
,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includesIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['src']['operators']['is.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.list'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['src']['operators']['is.partially.or.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.list'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['src']['operators']['is.partially.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.list'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);

RQuery::$defaultFilters['rule']['dst']['operators']['included-in.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includedInIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'argDesc' => 'ie: 192.168.0.0/24 | 192.168.50.10/32 | 192.168.50.10 | 10.0.0.0-10.33.0.0',
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['included-in.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includedInIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includedInIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includesIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includesIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includesIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->source->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->source->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(src has.from.query subquery1)\' \'subquery1=(value ip4.includes-full 10.10.0.1)\'',
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->destination->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->destination->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(dst has.from.query subquery1)\' \'subquery1=(value ip4.includes-full 10.10.0.1)\'',
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->source->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->source->membersExpanded() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->destination->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->destination->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['service']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->services->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('service');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->services->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(service has.from.query subquery1)\' \'subquery1=(value regex 8443)\'',
);
RQuery::$defaultFilters['rule']['service']['operators']['has.recursive.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->services->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('service');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->services->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE
);

RQuery::$defaultFilters['rule']['dst']['operators']['is.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.list'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.partially.or.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.list'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.partially.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.list'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);


//                                                //
//                Tag Based filters              //
//                                              //
RQuery::$defaultFilters['rule']['tag']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->tags->hasTag($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% test.tag)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['tag']['operators']['has.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->tags->hasTag($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% test.tag)',
        'input' => 'input/panorama-8.0.xml'
    )

);
RQuery::$defaultFilters['rule']['tag']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        foreach( $context->object->tags->tags() as $tag )
        {
            $matching = preg_match($context->value, $tag->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['tag.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);


//                                              //
//          Application properties              //
//                                              //
RQuery::$defaultFilters['rule']['app']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return ($rule->isSecurityRule() || $rule->isQoSRule()) && $rule->apps->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->apps->hasApp($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->apps->parentCentralStore->find('!value!');",
);
RQuery::$defaultFilters['rule']['app']['operators']['has.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return ($rule->isSecurityRule() || $rule->isQoSRule()) && $rule->apps->hasApp($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% icmp)',
        'input' => 'input/panorama-8.0.xml'
    )
    //'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['app']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() || $rule->isDecryptionRule() || $rule->isCaptivePortalRule() || $rule->isAuthenticationRule() || $rule->isDoSRule() )
            return FALSE;

        foreach( $context->object->apps->apps() as $app )
        {
            $matching = preg_match($context->value, $app->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() || $rule->isDecryptionRule() || $rule->isCaptivePortalRule() || $rule->isAuthenticationRule() || $rule->isDoSRule() )
            return FALSE;

        /** @var Rule|SecurityRule|AppOverrideRule|PbfRule|QoSRule $object */
        return $rule->apps->includesApp($context->value) === TRUE;
    },
    'arg' => TRUE,
    #'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->apps->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['includes.full.or.partial.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() || $rule->isDecryptionRule() || $rule->isCaptivePortalRule() || $rule->isAuthenticationRule() || $rule->isDoSRule() )
            return FALSE;

        return $rule->apps->includesApp($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() || $rule->isDecryptionRule() || $rule->isCaptivePortalRule() || $rule->isAuthenticationRule() || $rule->isDoSRule() )
            return FALSE;

        /** @var Rule|SecurityRule|AppOverrideRule|PbfRule|QoSRule $object */
        return $rule->apps->includedInApp($context->value) === TRUE;
    },
    'arg' => TRUE,
    #'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->apps->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['included-in.full.or.partial.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() || $rule->isDecryptionRule() || $rule->isCaptivePortalRule() || $rule->isAuthenticationRule() || $rule->isDoSRule() )
            return FALSE;

        return $rule->apps->includedInApp($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['custom.has.signature'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() || $rule->isDecryptionRule() || $rule->isCaptivePortalRule() || $rule->isAuthenticationRule() || $rule->isDoSRule() )
            return FALSE;

        /** @var Rule|SecurityRule|AppOverrideRule|PbfRule|QoSRule $object */
        return $rule->apps->customApphasSignature();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//          Services properties                 //
//                                              //
RQuery::$defaultFilters['rule']['service']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() )
            return $rule->service === null;

        return $rule->services->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service']['operators']['is.application-default'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isSecurityRule() && $context->object->services->isApplicationDefault();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->services->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->services->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['service']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isNatRule() )
        {
            if( $object->service === null )
                return FALSE;
            return $object->service === $value;
        }
        if( $object->services->count() != 1 || !$object->services->has($value) )
            return FALSE;

        return TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->services->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['service']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            if( $rule->service === null )
                return FALSE;
            $matching = preg_match($context->value, $rule->service->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
            return FALSE;
        }

        foreach( $rule->services->all() as $service )
        {
            $matching = preg_match($context->value, $service->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /tcp-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.recursive'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        /** @var Service|ServiceGroup $value */
        $value = $context->value;

        if( $rule->isNatRule() )
        {
            if( $rule->service === null )
                return FALSE;

            if( $rule->service->name() == $value )
                return TRUE;

            if( !$rule->service->isGroup() )
                return FALSE;

            return $rule->service->hasNamedObjectRecursive($value);
        }

        return $rule->services->hasNamedObjectRecursive($value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% tcp-80)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.tcp.only'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();

        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "udp") !== FALSE )
                    return FALSE;

                return TRUE;
            }

            if( $object->isUdp() )
                return FALSE;
        }

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.udp.only'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();
        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "tcp") !== FALSE )
                    return FALSE;

                return TRUE;
            }

            if( $object->isTcp() )
                return FALSE;
        }

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.tcp'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $isTCP = FALSE;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();

        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "tcp") !== FALSE )
                    $isTCP = TRUE;
                else
                    return FALSE;
            }
            elseif( $object->isTcp() )
                $isTCP = TRUE;
        }

        return $isTCP;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.udp'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $isUDP = FALSE;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();
        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "udp") !== FALSE )
                    return TRUE;
                else
                    return FALSE;
            }
            elseif( $object->isUdp() )
                $isUDP = TRUE;
        }

        return $isUDP;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.value.recursive'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $value = $context->value;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        return $rule->services->hasValue($value, TRUE);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.value'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $value = $context->value;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        return $rule->services->hasValue($value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.value.only'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $value = $context->value;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services->count() != 1 )
            return FALSE;

        return $rule->services->hasValue($value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                SecurityProfile properties    //
//                                              //
RQuery::$defaultFilters['rule']['secprof']['operators']['not.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;

        return $context->object->securityProfileIsBlank();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;

        return !$context->object->securityProfileIsBlank();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// @TODO Remove later / DEPRECATED
RQuery::$defaultFilters['rule']['secprof']['operators']['is.profile'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return $rule->isSecurityRule()
            && !$context->object->securityProfileIsBlank()
            && $context->object->securityProfileType() == "profile";
    },
    'arg' => FALSE,
    'deprecated' => 'this filter "secprof is.profile" is deprecated, you should use "secprof type.is.profile" instead!',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['type.is.profile'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return $rule->isSecurityRule()
            && !$context->object->securityProfileIsBlank()
            && $context->object->securityProfileType() == "profile";
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.group'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return $rule->isSecurityRule() && $context->object->isSecurityRule()
            && !$context->object->securityProfileIsBlank()
            && $context->object->securityProfileType() == "group";
    },
    'arg' => FALSE,
    'deprecated' => 'this filter "secprof is.group" is deprecated, you should use "secprof type.is.group" instead!',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// @TODO Remove later / DEPRECATED
RQuery::$defaultFilters['rule']['secprof']['operators']['type.is.group'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return $rule->isSecurityRule() && $context->object->isSecurityRule()
            && !$context->object->securityProfileIsBlank()
            && $context->object->securityProfileType() == "group";
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['group.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return $rule->isSecurityRule()
            && $rule->securityProfileType() == "group"
            && $rule->securityProfileGroup() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% secgroup-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['av-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['virus']) )
            return FALSE;

        return $profiles['virus'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% av-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['as-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['spyware']) )
            return FALSE;

        return $profiles['spyware'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% as-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['url-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['url-filtering']) )
            return FALSE;

        return $profiles['url-filtering'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% url-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['wf-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['wildfire-analysis']) )
            return FALSE;

        return $profiles['wildfire-analysis'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% wf-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['vuln-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['vulnerability']) )
            return FALSE;

        return $profiles['vulnerability'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['file-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['file-blocking']) )
            return FALSE;

        return $profiles['file-blocking'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['data-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['data-filtering']) )
            return FALSE;

        return $profiles['data-filtering'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['av-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();

        return isset($profiles['virus']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['as-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();

        return isset($profiles['spyware']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['url-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();

        return isset($profiles['url-filtering']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['wf-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();

        return isset($profiles['wildfire-analysis']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['vuln-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();

        return isset($profiles['vulnerability']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['file-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();

        return isset($profiles['file-blocking']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['data-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();

        return isset($profiles['data-filtering']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                Other properties              //
//                                              //
RQuery::$defaultFilters['rule']['action']['operators']['is.deny'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isSecurityRule() && $context->object->actionIsDeny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['action']['operators']['is.negative'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;
        return $context->object->actionIsNegative();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['action']['operators']['is.allow'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;
        return $context->object->actionIsAllow();
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['action']['operators']['is.drop'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;
        return $context->object->actionIsDrop();
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['log']['operators']['at.start'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;
        return $context->object->logStart();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['log']['operators']['at.end'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;
        return $context->object->logEnd();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['logprof']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->logSetting() === null || $rule->logSetting() == '' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['logprof']['operators']['is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->logSetting() === null )
            return FALSE;

        if( $rule->logSetting() == $context->value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'return true if Log Forwarding Profile is the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  log_to_panorama)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.prerule'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isPreRule();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.postrule'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isPostRule();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.disabled'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isDisabled();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.dsri'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;
        return $context->object->isDSRIEnabled();
    },
    'arg' => FALSE,
    'help' => 'return TRUE if Disable Server Response Inspection has been enabled'
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.bidir.nat'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        return $context->object->isBiDirectional();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['has.source.nat'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        if( !$context->object->sourceNatTypeIs_None() )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['has.destination.nat'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        if( $context->object->destinationNatIsEnabled() )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.universal'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return TRUE;

        if( $context->object->type() != 'universal' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.intrazone'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->owner->owner->version < 61 )
            return FALSE;

        if( !$context->object->isSecurityRule() )
            return FALSE;

        if( $context->object->type() != 'intrazone' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.interzone'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->owner->owner->version < 61 )
            return FALSE;

        if( !$context->object->isSecurityRule() )
            return FALSE;

        if( $context->object->type() != 'interzone' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['location']['operators']['is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $owner = $context->object->owner->owner;
        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }
        if( strtolower($context->value) == strtolower($owner->name()) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['location']['operators']['regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $name = $context->object->getLocationString();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the regular expression specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  /DC/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['location']['operators']['is.child.of'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "RuleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            print "ERROR: location '$context->value' was not found. Here is a list of available ones:\n";
            print " - shared\n";
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                print " - " . $sub1->name() . "\n";
            }
            print "\n\n";
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($rule_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $rule_location )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is child the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['location']['operators']['is.parent.of'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "RuleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.parent.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            print "ERROR: location '$context->value' was not found. Here is a list of available ones:\n";
            print " - shared\n";
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                print " - " . $sub1->name() . "\n";
            }
            print "\n\n";
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($rule_location) )
            return TRUE;

        if( $rule_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $rule_location )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is parent the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.unused.fast'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. " . $object->toString());

        $unused_flag = 'unused' . $object->ruleNature();
        $rule_base = $object->ruleNature();

        $sub = $object->owner->owner;
        if( !$sub->isVirtualSystem() && !$sub->isDeviceGroup() )
        {
            print PH::boldText("   **WARNING**:") . "this filter is only supported on non Shared rules " . $object->toString() . "\n";
            return null;
        }


        $connector = findConnector($sub);

        if( $connector === null )
            derr("this filter is available only from API enabled PANConf objects");

        if( !isset($sub->apiCache) )
            $sub->apiCache = array();

        // caching results for speed improvements
        if( !isset($sub->apiCache[$unused_flag]) )
        {
            $sub->apiCache[$unused_flag] = array();

            if( $context->object->owner->owner->version < 81 )
                $apiCmd = '<show><running><rule-use><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $sub->name() . '</vsys></rule-use></running></show>';
            else
            {
                $apiCmd = '<show><running><rule-use><highlight><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $sub->name() . '</vsys></highlight></rule-use></running></show>';


            }


            if( $sub->isVirtualSystem() )
            {
                print "Firewall: " . $connector->info_hostname . " (serial: '" . $connector->info_serial . "', PAN-OS: '" . $connector->info_PANOS_version . "') was rebooted '" . $connector->info_uptime . "' ago.\n";
                $apiResult = $connector->sendCmdRequest($apiCmd);

                $rulesXml = DH::findXPath('/result/rules/entry', $apiResult);
                for( $i = 0; $i < $rulesXml->length; $i++ )
                {
                    $ruleName = $rulesXml->item($i)->textContent;
                    $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                }

                if( $context->object->owner->owner->version >= 81 )
                {
                    $apiCmd2 = '<show><rule-hit-count><vsys><vsys-name><entry%20name="' . $sub->name() . '"><rule-base><entry%20name="' . $rule_base . '"><rules>';
                    $apiCmd2 .= '<all></all>';
                    $apiCmd2 .= '</rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>';

                    print "additional check needed as PAN-OS >= 8.1.X\n";

                    $apiResult = $connector->sendCmdRequest($apiCmd2);

                    $rulesXml = DH::findXPath('/result/rule-hit-count/vsys/entry/rule-base/entry/rules/entry', $apiResult);
                    for( $i = 0; $i < $rulesXml->length; $i++ )
                    {
                        $ruleName = $rulesXml->item($i)->getAttribute('name');

                        foreach( $rulesXml->item($i)->childNodes as $node )
                        {
                            if( $node->nodeName == "hit-count" )
                            {
                                $hitcount_value = $node->textContent;
                                if( $hitcount_value != 0 )
                                    unset($sub->apiCache[$unused_flag][$ruleName]);

                            }
                        }
                    }
                }
            }
            else
            {
                $devices = $sub->getDevicesInGroup(TRUE);

                $connectedDevices = $connector->panorama_getConnectedFirewallsSerials();
                foreach( $devices as $id => $device )
                {
                    if( !isset($connectedDevices[$device['serial']]) )
                    {
                        unset($devices[$id]);
                        print "\n  - firewall device with serial: " . $device['serial'] . " is not connected.\n";
                    }
                }

                $firstLoop = TRUE;

                foreach( $devices as $device )
                {
                    $newConnector = new PanAPIConnector($connector->apihost, $connector->apikey, 'panos-via-panorama', $device['serial']);
                    $newConnector->setShowApiCalls($connector->showApiCalls);
                    $newConnector->refreshSystemInfos();
                    print "Firewall: " . $newConnector->info_hostname . " (serial: '" . $newConnector->info_serial . "', PAN-OS: '" . $newConnector->info_PANOS_version . "') was rebooted '" . $newConnector->info_uptime . "' ago.\n";
                    $tmpCache = array();

                    foreach( $device['vsyslist'] as $vsys )
                    {
                        if( $newConnector->info_PANOS_version_int < 81 )
                            $apiCmd = '<show><running><rule-use><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $vsys . '</vsys></rule-use></running></show>';
                        else
                            $apiCmd = '<show><running><rule-use><highlight><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $vsys . '</vsys></highlight></rule-use></running></show>';

                        $apiResult = $newConnector->sendCmdRequest($apiCmd);

                        $rulesXml = DH::findXPath('/result/rules/entry', $apiResult);

                        for( $i = 0; $i < $rulesXml->length; $i++ )
                        {
                            $ruleName = $rulesXml->item($i)->textContent;
                            if( $firstLoop )
                                $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                            else
                            {
                                $tmpCache[$ruleName] = $ruleName;
                            }
                        }

                        if( $newConnector->info_PANOS_version_int >= 81 )
                        {
                            $apiCmd2 = '<show><rule-hit-count><vsys><vsys-name><entry%20name="' . $vsys . '"><rule-base><entry%20name="' . $rule_base . '"><rules>';
                            $apiCmd2 .= '<all></all>';
                            $apiCmd2 .= '</rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>';

                            print "additional check needed as PAN-OS >= 8.1.X\n";

                            $apiResult = $newConnector->sendCmdRequest($apiCmd2);

                            $rulesXml = DH::findXPath('/result/rule-hit-count/vsys/entry/rule-base/entry/rules/entry', $apiResult);
                            for( $i = 0; $i < $rulesXml->length; $i++ )
                            {
                                $ruleName = $rulesXml->item($i)->getAttribute('name');

                                foreach( $rulesXml->item($i)->childNodes as $node )
                                {
                                    if( $node->nodeName == "hit-count" )
                                    {
                                        $hitcount_value = $node->textContent;
                                        if( $hitcount_value != 0 )
                                        {
                                            if( isset($sub->apiCache[$unused_flag][$ruleName]) )
                                                unset($sub->apiCache[$unused_flag][$ruleName]);

                                            if( isset($tmpCache[$ruleName]) )
                                                unset($tmpCache[$ruleName]);
                                        }
                                    }
                                }
                            }
                        }

                        if( !$firstLoop )
                        {
                            foreach( $sub->apiCache[$unused_flag] as $unusedEntry )
                            {
                                if( !isset($tmpCache[$unusedEntry]) )
                                    unset($sub->apiCache[$unused_flag][$unusedEntry]);
                            }
                        }

                        $firstLoop = FALSE;
                    }
                }
            }
        }

        if( isset($sub->apiCache[$unused_flag][$object->name()]) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);


RQuery::$defaultFilters['rule']['name']['operators']['eq'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  rule1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['name']['operators']['regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $matching = preg_match($context->value, $context->object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the regular expression provided in argument',
    'ci' => array(
        'fString' => '(%PROP%  /^example/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['name']['operators']['eq.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%  rule1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['name']['operators']['contains'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return stripos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%  searchME)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['name']['operators']['is.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        return isset($list[$object->name()]);
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);

//                                              //
//                UserID properties             //
//                                              //
RQuery::$defaultFilters['rule']['user']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;

        return $rule->userID_IsAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['user']['operators']['is.known'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;

        return $rule->userID_IsKnown();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['user']['operators']['is.unknown'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;

        return $rule->userID_IsUnknown();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['user']['operators']['is.prelogon'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;

        return $rule->userID_IsPreLogon();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['user']['operators']['has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;

        $users = $rule->userID_getUsers();

        foreach( $users as $user )
            if( $user == $context->value )
                return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% CN=xyz,OU=Network)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['user']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;

        $users = $rule->userID_getUsers();

        foreach( $users as $user )
        {
            $matching = preg_match($context->value, $user);
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /^test/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['url.category']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return null;

        return $rule->urlCategoryIsAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['url.category']['operators']['has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return null;

        return $rule->urlCategoriesHas($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% adult)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['target']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->target_isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['target']['operators']['has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $vsys = null;

        $ex = explode('/', $context->value);

        if( count($ex) > 2 )
            derr("unsupported syntax for target: '{$context->value}'. Expected something like : 00F120CCC/vsysX");

        if( count($ex) == 1 )
            $serial = $context->value;
        else
        {
            $serial = $ex[0];
            $vsys = $ex[1];
        }

        return $context->object->target_hasDeviceAndVsys($serial, $vsys);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%  00YC25C)',
        'input' => 'input/panorama-8.0.xml'
    )
);


RQuery::$defaultFilters['rule']['description']['operators']['is.empty'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $desc = $context->object->description();

        if( $desc === null || strlen($desc) == 0 )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);


RQuery::$defaultFilters['rule']['description']['operators']['regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $matching = preg_match($context->value, $context->object->description());
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /input a string here/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['category.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['category'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->category == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% media)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['subcategory.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['subcategory'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->subCategory == $context->value )
                return TRUE;
        }

        if( $rule->apps->count() < 1 )
            return null;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% gaming)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['technology.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['technology'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->technology == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client-server)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['risk.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['risk'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->risk == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client-server)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['characteristic.has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        $sanitizedValue = strtolower($context->value);


        if( !isset(App::$_supportedCharacteristics[$sanitizedValue]) )
            derr("Characteristic named '{$sanitizedValue}' does not exist. Supported values are: " . PH::list_to_string(App::$_supportedCharacteristics));

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->_characteristics[$sanitizedValue] === TRUE )
                return TRUE;

        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% evasive) ',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['has.missing.dependencies'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        $app_depends_on = array();
        $app_array = array();
        $missing_dependencies = FALSE;
        foreach( $rule->apps->membersExpanded() as $app )
        {
            $app_array[$app->name()] = $app->name();
            foreach( $app->calculateDependencies() as $dependency )
            {
                $app_depends_on[$dependency->name()] = $dependency->name();
            }
        }

        $first = TRUE;
        foreach( $app_depends_on as $app => $dependencies )
        {
            if( !isset($app_array[$app]) )
            {
                if( $first )
                {
                    $first = FALSE;
                    print "   - app-id: ";
                }
                print $app . ", ";
                $missing_dependencies = TRUE;
            }
        }

        if( $missing_dependencies )
        {
            print " |  is missing in rule:\n";
            return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['rule']['schedule']['operators']['is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            if( $schedule->name() == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
);

RQuery::$defaultFilters['rule']['schedule']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            return TRUE;
        }

        return FALSE;
    },
    'arg' => false,
);

RQuery::$defaultFilters['rule']['schedule']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return FALSE;

        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            $matching = preg_match($context->value, $schedule->name() );
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
);
// </editor-fold>

