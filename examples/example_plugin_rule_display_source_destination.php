<?php

//usage:
//pan-os-php type=rule 'loadplugin=[fullpathto]/pan-os-php/examples/example_plugin_rule_display_source_destination.php' in=api://MGMT-IP 'actions=example_plugin_source_destination'

RuleCallContext::$supportedActions[] = Array(
    'name' => 'example_plugin_source_destination',
    'MainFunction' => function(RuleCallContext $context)
    {
        /*
         * @var securityRule $rule
         */
        $rule = $context->object;

        // get the list of rule source objects in an array
        $sources = $rule->source->getAll();
        foreach( $sources as $source )
        {
            PH::print_stdout("     - source address object '".$source->name()  );
        }

        // get the list of rule destination objects in an array
        $destinations = $rule->destination->getAll();
        foreach( $destinations as $destination )
        {
            PH::print_stdout("     - destination address object '".$destination->name()  );
        }
    }
);