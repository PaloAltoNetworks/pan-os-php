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

#####################################

trait lib_1_rule_marker
{

    function display_usage_and_exit_p1()
    {
        PH::print_stdout();
        PH::print_stdout(PH::boldText("USAGE: ")."pan-os-php type=appid-toolbox phase=rule-marker in=api://xxxx location=deviceGroup2 [OPTIONAL ARGS]" );
        PH::print_stdout("");

        PH::print_stdout("Listing optional arguments:");
        PH::print_stdout();

        exit(1);
    }


    function ruleMarker_Phase1_init()
    {
        if( isset(PH::$args['help']) )
            $this->display_usage_and_exit_p1();

        $supportedOptions = array('phase', 'in', 'out', 'help', 'location');
        $supportedOptions = array_flip($supportedOptions);

        foreach( PH::$args as $arg => $argvalue )
        {
            if( !isset($supportedOptions[strtolower($arg)]) )
                display_error_usage_exit("unknown argument '{$arg}'");
        }
        unset($arg);

        $debugAPI = FALSE;


        $return = AppIDToolbox_common::location();
        $configInput = $return['configInput'];
        $location = $return['location'];


        $return = AppIDToolbox_common::getConfig($configInput, $debugAPI);
        $xmlDoc = $return['xmlDoc'];
        $configOutput = $return['configOutput'];
        $inputConnector = $return['inputConnector'];


        $return = AppIDToolbox_common::determineConfig($xmlDoc, $configInput, $inputConnector, $location);
        $subSystem = $return['subSystem'];
        $pan = $return['pan'];

        PH::print_stdout(" - Found DG/Vsys '$location'");
        PH::print_stdout(" - Looking/creating for necessary Tags to mark rules");
        TH::createTags($pan, $configInput['type']);

        //
        // REAL JOB STARTS HERE
        //
        $this->ruleMarker_Phase1_main($subSystem, $configInput, $pan, $inputConnector, $configOutput);
    }

    function ruleMarker_Phase1_main($subSystem, $configInput, $pan, $inputConnector, $configOutput)
    {
        $rules = $subSystem->securityRules->rules('!(action is.negative) and (app is.any) and !(rule is.disabled) and !(tag has appid#ignore)');
        PH::print_stdout(" - Total number of rules: {$subSystem->securityRules->count()} vs " . count($rules) . " potentially taggable");

        $ridTagLibrary = new RuleIDTagLibrary();
        $ridTagLibrary->readFromRuleArray($subSystem->securityRules->rules());


        PH::print_stdout("\n\n*** BEGIN TAGGING RULES ***");

        $xmlPreRules = '';
        $xmlPostRules = '';

        $markedRules = 0;
        $alreadyMarked = 0;

        foreach( $rules as $rule )
        {
            PH::print_stdout(" - rule '{$rule->name()}'");

            if( $ridTagLibrary->ruleIsTagged($rule) )
            {
                PH::print_stdout(" SKIPPED : already tagged");
                $alreadyMarked++;
                continue;
            }

            $markedRules++;


            $newTagName = $ridTagLibrary->findAvailableTagName('appRID#');
            PH::print_stdout();
            PH::print_stdout("    * creating Virtual TAG '$newTagName' ... ");

            PH::print_stdout("    * applying tag to rule description... ");

            $newDescription = $rule->description() . ' ' . $newTagName;
            if( strlen($newDescription) > 253 )
                derr('description is too long, please review and edit');
            $ridTagLibrary->addRuleToTag($rule, $newTagName);
            $rule->setDescription($newDescription);

            if( $rule->isPostRule() )
                $xmlPostRules .= "<entry name=\"{$rule->name()}\"><description>" . htmlspecialchars($rule->description()) . "</description></entry>";
            else
                $xmlPreRules .= "<entry name=\"{$rule->name()}\"><description>" . htmlspecialchars($rule->description()) . "</description></entry>";
        }

        PH::print_stdout("\n\nNumber of rules marked: {$markedRules}    (vs already marked: {$alreadyMarked}");

        if( $markedRules < 1 )
            PH::print_stdout("\n\n No change to push as not rule is set to be marked");
        else
        {
            if( $configInput['type'] == 'api' )
                PH::print_stdout("\n\n**** Pushing all changes at once through API... ");


            if( $pan->isPanorama() )
                $xml = "<pre-rulebase><security><rules>{$xmlPreRules}</rules></security></pre-rulebase><post-rulebase><security><rules>{$xmlPostRules}</rules></security></post-rulebase>";
            else
                $xml = "<rulebase><security><rules>{$xmlPreRules}</rules></security></rulebase>";

            if( $configInput['type'] == 'api' )
                $inputConnector->sendSetRequest(DH::elementToPanXPath($subSystem->xmlroot), $xml);
            else
                // save our work !!!
                if( $configOutput !== null )
                {
                    if( $configOutput != '/dev/null' )
                    {
                        $pan->save_to_file($configOutput);
                    }
                }
        }

        PH::print_stdout("\n");
    }
}
