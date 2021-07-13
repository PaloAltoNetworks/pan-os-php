<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

//Todo: introduce actions:
//      display
//      set custom timeout, tcp-timeout, udp-timeout, tcp_half_closed_timeout, tcp_time_wait_timeout
//      enable app-id

ApplicationCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);



ApplicationCallContext::$supportedActions[] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (ApplicationCallContext $context) {
        $context->counter_containers = 0;
        $context->tmpcounter = 0;
        $context->counter_predefined = 0;
        $context->counter_dependencies = 0;

        $context->counter_custom_app = 0;
        $context->counter_app_filter = 0;
        $context->counter_app_group = 0;

        $context->print_container = true;
        $context->print_dependencies = true;
        $context->print_explicit = true;
        $context->print_implicit = true;
    },
    'MainFunction' => function (ApplicationCallContext $context) {
        $app = $context->object;

        PH::print_stdout( $context->padding . "* " . get_class($app) . " '{$app->name()}' " );
        if( $app->isContainer() )
        {
            $context->counter_containers++;
            if( $context->print_container )
            {
                $app->print_appdetails();

                print "is container: \n";
                foreach( $app->containerApps() as $app1 )
                {
                    if( $app1->isContainer() )
                    {
                        print "is container: \n";
                        foreach( $app1->containerApps() as $app2 )
                        {
                            print "     ->" . $app2->type . " | ";
                            $app2->print_appdetails();
                        }
                    }
                    else
                    {
                        print "     ->" . $app1->type . " | ";
                        $app1->print_appdetails();
                    }
                }
                print "\n";
            }
        }
        else
        {
            print $app->type . " |-> ";
            $app->print_appdetails();
            print "<-|\n";
        }

        if( $app->type == 'tmp' )
            $context->tmpcounter++;

        if( $app->type == 'predefined' )
            $context->counter_predefined++;


        if( $app->type == 'application-custom' )
        {
            $context->counter_custom_app++;
            if( $app->custom_signature )
                print "custom_signature is set\n";
        }

        if( $app->type != 'application-filter' )
            $context->counter_app_filter++;


        if( $app->type == 'application-group' )
            $context->counter_app_group++;


        // Explicit / Implicti difference
        $app_explicit = array();
        $app_implicit = array();
        if( isset($app->explicitUse) )
        {
            foreach( $app->explicitUse as $explApp )
            {
                $app_explicit[$explApp->name()] = $explApp;
            }
        }

        if( isset($app->implicitUse) )
        {
            foreach( $app->implicitUse as $implApp )
            {
                $app_implicit[$implApp->name()] = $implApp;
            }
        }

        $dependency_app = array();
        foreach( $app_implicit as $implApp )
        {
            if( isset($app_explicit[$implApp->name()]) )
            {
                print str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as explicit and implicit used\n";
                if( isset($app->implicitUse) && $context->print_dependencies )
                {
                    if( !isset($dependency_app[$app->name()]) )
                    {
                        if( count($app->calculateDependencies()) > 0 )
                        {
                            $dependency_app[$app->name()] = $app->name();
                            print str_pad($app->name(), 30);
                            print "     dependencies: ";
                            $context->counter_dependencies++;
                        }

                        foreach( $app->calculateDependencies() as $dependency )
                        {
                            print $dependency->name() . ",";
                        }
                        if( count($app->calculateDependencies()) > 0 )
                            print "\n";
                    }

                }

            }
        }


        foreach( $app_explicit as $implApp )
        {
            if( !isset($app_implicit[$implApp->name()]) )
            {
                if( count($app_implicit) > 0 )
                    print str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as explicit but NOT implicit used\n";
            }
        }

        foreach( $app_implicit as $implApp )
        {
            if( !isset($app_explicit[$implApp->name()]) )
            {
                print str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as implicit but NOT explicit used\n";

            }
        }

        print "#############################################\n";
    },
    'GlobalFinishFunction' => function (ApplicationCallContext $context) {
        print "tmp_counter: ".$context->tmpcounter."\n";
        print "predefined_counter: ".$context->counter_predefined."\n";
        print "dependency_app_counter: ".$context->counter_dependencies."\n";

        print "container_counter: ".$context->counter_containers."\n";

        print "custom_app_counter: ".$context->counter_custom_app."\n";
        print "app_filter_counter: ".$context->counter_app_filter."\n";
        print "app_group_counter: ".$context->counter_app_group."\n";
    }
);