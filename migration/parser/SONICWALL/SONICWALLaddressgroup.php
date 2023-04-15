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

trait SONICWALLaddressgroup
{

    function add_addressgroup( $addressgroup)
    {
        global $debug;
        global $print;

        $padding = "   ";
        $padding_name = substr($padding, 0, -1);

        $addressgroup_fix = array();

        foreach( $addressgroup as $key => $addressgroup_entry )
        {
            $addressgroup_entry = trim($addressgroup_entry);
            $addressgroup_entry = explode("\n", $addressgroup_entry);

            foreach( $addressgroup_entry as $key2 => $addressgroup )
            {
                if( $key2 == 0 )
                {
                    $addressgroup = explode('"', $addressgroup);
                    if( count($addressgroup) == 1 )
                    {
                        $addressgroup = explode(' ', $addressgroup[0]);
                    }

                    $name = $addressgroup[1];
                    $name = $this->truncate_names($this->normalizeNames($name));

                    $tmp_addressgroup = $this->sub->addressStore->find($name);
                    if( $tmp_addressgroup == null )
                    {
                        if( $print )
                            print "\n" . $padding_name . "* name: " . $name . "\n";
                        $tmp_addressgroup = $this->sub->addressStore->newAddressgroup($name);
                    }
                }
                else
                {
                    if( $addressgroup != "" )
                    {
                        $addressgroup = trim($addressgroup);
                        $addressgroup = explode('"', $addressgroup);
                        if( count($addressgroup) == 1 )
                        {
                            #print_r( $addressgroup );
                            $addressgroup = explode(' ', $addressgroup[0]);
                            if( !isset($addressgroup[2]) )
                            {
                                print_r($addressgroup);
                                mwarning("problem with addressgroup", null, FALSE);
                                #derr( "problem with addressgroup" );
                            }
                            else
                            {
                                $name = $addressgroup[2];
                            }
                        }
                        else
                            $name = $addressgroup[1];
                        $name = $this->truncate_names($this->normalizeNames($name));
                        $tmp_address = $this->sub->addressStore->find($name);
                        if( $tmp_address == null )
                        {
                            if( $print || $debug )
                                print $padding . "X address object name:: '" . $name . "' not found. Automatic try to fix in next step.\n";
                            $addressgroup_fix[$tmp_addressgroup->name()][] = $name;
                        }
                        else
                        {
                            if( $print )
                                print $padding . "- member name: '" . $name . "'\n";
                            $tmp_addressgroup->addMember($tmp_address);
                        }
                    }
                }
            }
        }

        print PH::boldText("\nFIX addressgroups\n");

        foreach( $addressgroup_fix as $key => $addressgroup_array )
        {
            print "\n" . $padding_name . "* name: " . $key . "\n";
            $tmp_address_group = $this->sub->addressStore->find($key);
            if( $tmp_address_group != null )
            {
                #print "addrgroup: ".$tmp_address_group->name()."\n";
                $tmp_address = null;
                foreach( $addressgroup_array as $member )
                {
                    $tmp_address = $this->sub->addressStore->find($member);
                    if( $tmp_address != null )
                    {
                        #print "address: ".$tmp_address->name()."\n";
                        if( $print )
                            print $padding . "- member name: '" . $member . "'\n";
                        $tmp_address_group->addMember($tmp_address);
                    }
                    else
                    {
                        if( $print || $debug )
                            print $padding . "X address object name: '" . $member . "' still not possible to add.\n";
                        $tmp_address_group->set_node_attribute('error', "address object name: '" . $member . "' can not be added");
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

