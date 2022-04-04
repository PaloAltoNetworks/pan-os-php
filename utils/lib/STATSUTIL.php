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

class STATSUTIL extends RULEUTIL
{
    function __construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "")
    {
        $_usageMsg =  PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] [location=vsys2]";;
        parent::__construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments, $_usageMsg);
    }

    public function utilStart()
    {

        $this->utilInit();
        //unique for RULEUTIL
        $this->ruleTypes();

        //no need to do actions on every single rule
        $this->doActions = array();

        $this->createRQuery();
        $this->load_config();
        $this->location_filter();


        $this->location_filter_object();
        $this->time_to_process_objects();




        PH::$args['stats'] = "stats";
        PH::$JSON_TMP = array();
        $this->stats();
        PH::print_stdout(PH::$JSON_TMP, false, "statistic");
        PH::$JSON_TMP = array();

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            //print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }

    /*
    public function supportedArguments()
    {
        parent::supportedArguments();
    }
    */
}