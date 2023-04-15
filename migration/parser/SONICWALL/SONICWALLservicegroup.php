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

trait SONICWALLservicegroup
{

    function add_servicegroup( $servicegroup)
    {
        global $debug;
        global $print;

        $padding = "   ";
        $padding_name = substr($padding, 0, -1);

        $servicegroup_fix = array();

        foreach( $servicegroup as $key => $servicegroup_entry )
        {
            $servicegroup_entry = trim($servicegroup_entry);
            $servicegroup_entry = explode("\n", $servicegroup_entry);

            foreach( $servicegroup_entry as $key2 => $servicegroup )
            {
                if( $key2 == 0 )
                {
                    $servicegroup = preg_replace('#^"#m', "", $servicegroup);
                    $servicegroup = explode('"', $servicegroup);
                    if( count($servicegroup) == 1 )
                    {
                        $servicegroup = explode(' ', $servicegroup[0]);
                    }
                    $name = trim($servicegroup[0]);
                    $name = $this->truncate_names($this->normalizeNames($name));

                    $tmp_servicegroup = $this->sub->serviceStore->find($name);
                    if( $tmp_servicegroup == null )
                    {
                        if( $print )
                            print "\n" . $padding_name . "* name: " . $name . "\n";
                        $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($name);
                    }
                }
                else
                {
                    if( $servicegroup != "" )
                    {
                        $servicegroup = trim($servicegroup);
                        $servicegroup = str_replace("service-object ", "", $servicegroup);
                        $servicegroup = str_replace("service-group ", "", $servicegroup);
                        $servicegroup = str_replace('"', "", $servicegroup);

                        $name = $servicegroup;
                        $name = $this->truncate_names($this->normalizeNames($name));
                        $tmp_service = $this->sub->serviceStore->find($name);
                        if( $tmp_service == null )
                        {
                            $tmp_service = $this->sub->serviceStore->find("TMP_" . $name);
                            if( $tmp_service == null )
                            {
                                if( $print || $debug )
                                    print $padding . "X service object name: '" . $name . "' not found. Automatic try to fix in next step.\n";
                                $servicegroup_fix[$tmp_servicegroup->name()][] = $name;
                            }
                            else
                            {
                                if( $print )
                                    print $padding . "- member name: '" . $name . "'\n";
                                $tmp_servicegroup->addMember($tmp_service);
                            }
                        }
                        else
                        {
                            if( $print )
                                print $padding . "- member name: '" . $name . "'\n";
                            $tmp_servicegroup->addMember($tmp_service);
                        }
                    }
                }
            }
        }

        print PH::boldText("\nFIX servicegroups\n");

        foreach( $servicegroup_fix as $key => $servicegroup_array )
        {
            print "\n" . $padding_name . "* name: " . $key . "\n";
            $tmp_service_group = $this->sub->serviceStore->find($key);
            if( $tmp_service_group != null )
            {
                foreach( $servicegroup_array as $member )
                {
                    $tmp_service = $this->sub->serviceStore->find($member);
                    if( $tmp_service != null )
                    {
                        if( $print )
                            print $padding . "- member name: '" . $member . "'\n";
                        $tmp_service_group->addMember($tmp_service);
                    }
                    else
                    {
                        if( $print || $debug )
                            print $padding . "X service object name: '" . $member . "' still not possible to add.\n";
                        $tmp_service_group->set_node_attribute('error', "address object name: '" . $member . "' can not be added");
                    }
                }
            }
            else
            {
                print $padding_name . "X name: " . $key . " not found\n";
            }
        }

    }

}

