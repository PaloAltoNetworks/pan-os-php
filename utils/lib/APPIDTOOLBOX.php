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
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/common.php";

require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_1_rule_marker.php";

require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_2_report_generator.php";
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_3_rule_cloner.php";
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_4_rule_activation.php";
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_5_rule_cleaner.php";


class APPIDTOOLBOX extends UTIL
{
    use lib_1_rule_marker;
    use lib_2_report_generator;
    use lib_3_rule_cloner;
    use lib_4_rule_activation;
    use lib_5_rule_cleaner;

    private $phase = null;

    public function utilStart()
    {
        PH::processCliArgs();

        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input filename', 'argDesc' => '[filename]');
        $this->supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output filename ie: out=[PATH]/save-config.xml', 'argDesc' => '[filename]');
        #$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->supportedArguments['phase'] = Array('niceName' => 'help', 'shortHelp' => 'phase=report-generator');



        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." phase=";


        $this->prepareSupportedArgumentsArray();


        #$this->utilInit();


        $this->main();


    }

    public function main()
    {


        if( isset(PH::$args['phase']) )
        {
            $this->phase = PH::$args['phase'];

            $phase = PH::$args['phase'];

            if( $phase == "rule-marker" || $phase == "phase1" )
                $this->ruleMarker_Phase1_init();
            elseif( $phase == "report-generator" || $phase == "phase2" )
                $this->logAnalysis_Phase2();
            elseif( $phase == "rule-cloner" || $phase == "phase3" )
                $this->ruleCloner_Phase3_init();
            elseif( $phase == "rule-activation" || $phase == "phase4" )
                $this->ruleActivation_Phase4_init();
            elseif( $phase == "rule-cleaner" || $phase == "phase5" )
                $this->ruleCleaner_Phase5_init();
        }
        elseif( isset(PH::$args['help']) )
            $this->help(PH::$args);

    }

    public function endOfScript()
    {

    }
}