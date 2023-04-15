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

trait FORTINETaddresses
{
    function tmp_address_validation($tmp_address, $name, $type, $value)
    {
        if( $tmp_address->type() == "$type" && $tmp_address->value() == $value )
        {
        }
        else
        {
            print "vsys: " . $tmp_address->owner->owner->name() . "\n";
            print "new - name: '" . $name . "'' | type: " . $type . " | value: " . $value . "\n";
            print "existing - name: '" . $tmp_address->name() . "' | type: " . $tmp_address->type() . " | value: " . $tmp_address->value() . "\n";

            $add_log = "object: " . $name . " already available. existing values| type: " . $tmp_address->type() . " | value: " . $tmp_address->value() . " new values: type: " . $type . " | value: " . $value . "\n";
            $tmp_address->set_node_attribute('warning', $add_log);
            mwarning($add_log, null, FALSE);
        }
    }


    #get_address_Fortinet($data, $source, $vsys_name, $ismultiornot, $regions);
    #function get_address_Fortinet($fortinet_config_file, $source, $vsys, $ismultiornot, &$regions) {
    function get_address_Fortinet( $ismultiornot, &$regions)
    {
        global $debug;
        global $print;
        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        global $projectdb;
        $isAddress = FALSE;
        $isObject = FALSE;
        $sql = array();
        $type = "ip-netmask";
        $ipaddress = "";
        $netmask = "";
        $cidr = "";
        $addressName = "";
        $addressNamePan = "";
        $description = "";
        $getRangeEnd = "";
        $getRangeStart = "";
        $fqdn = "";
        $country = "";

        $defaultRegions = array();
        $defaultRegions = $this->default_regions();


        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }
        $lastline = "";
        foreach( $this->data as $line => $names_line )
        {
            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {
                if( preg_match("/config firewall address/i", $names_line) )
                {
                    $isObject = TRUE;
                }


                if( $isObject )
                {
                    if( preg_match("/^\bend\b/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/\bedit\b/i", $names_line) )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        #$newname = str_replace('/', '-', $meta[1]);
                        $addressNamePan = $this->truncate_names($this->normalizeNames($meta[1]));
                        $addressName = trim($meta[1]);

                        if( $addressName == "all" )
                        {
                            $type = "";
                        }
                    }

                    if( $isAddress )
                    {
                        if( preg_match("/\bnext\b/i", $names_line) )
                        {
                            $isAddress = FALSE;

                            if( $type == "fqdn" )
                            {
                                #$sql[] = array($source,$addressName,$addressNamePan,$vsys,$type,'',$fqdn,$fqdn,$cidr,$description);
                                //newAddress($name , $type, $value, $description = '')
                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( $print )
                                        print " * create object: " . $addressNamePan . " type: " . $type . " value: " . $fqdn . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($addressNamePan, $type, $fqdn, $description);
                                }
                                else
                                {
                                    $this->tmp_address_validation($tmp_address, $addressNamePan, $type, $fqdn);
                                }

                                if( preg_match("/^\*/", $fqdn) )
                                {
                                    #add_log('error', 'FQDN Object', 'The Address [' . $addressName . '] contains an * [' . $fqdn . ']', $source, 'Wrong Content, replace this object by appropiate App-id');
                                }
                            }
                            elseif( $type == "ip-netmask" )
                            {
                                #$sql[] = array($source,$addressName,$addressNamePan,$vsys,$type,'',$fqdn,$ipaddress,$cidr,$description);
                                //newAddress($name , $type, $value, $description = '')
                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( $print )
                                        print " * create object: " . $addressNamePan . " type: " . $type . " value: " . $ipaddress . "/" . $cidr . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($addressNamePan, $type, $ipaddress . "/" . $cidr, $description);
                                }
                                else
                                {
                                    $this->tmp_address_validation($tmp_address, $addressNamePan, $type, $ipaddress . "/" . $cidr);
                                }

                            }
                            elseif( $type == "ip-range" )
                            {
                                $ipaddress = $getRangeStart . "-" . $getRangeEnd;
                                #$sql[] = array($source,$addressName,$addressNamePan,$vsys,$type,'',$fqdn,$ipaddress,$cidr,$description);
                                //newAddress($name , $type, $value, $description = '')
                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( $print )
                                        print " * create object: " . $addressNamePan . " type: " . $type . " value: " . $ipaddress . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($addressNamePan, $type, $ipaddress, $description);
                                }
                                else
                                {
                                    $this->tmp_address_validation($tmp_address, $addressNamePan, $type, $ipaddress);
                                }
                            }
                            elseif( $type == "region" )
                            {
                                $regions[$addressNamePan] = $country;

                                $type = "ip-netmask";
                                $value = "1.1.1.1/32";
                                $description = $country;

                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( !isset($defaultRegions[$country]) )
                                        mwarning("country: " . $country . " not available in defaultRegion", null, FALSE);

                                    if( $print )
                                        print " X create tmp region object: region-" . $addressNamePan . " type: " . $type . " value: " . $value . " description: " . $description . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress("region-" . $addressNamePan, $type, $value, $description);
                                    $addlog = "region object is not a valid address object - migration process try to replace it later on";
                                    $tmp_address->set_node_attribute('error', $addlog);
                                }
                            }
                            else
                            {
                                $tmp_address = $this->sub->addressStore->find("tmp-" . $addressNamePan);
                                if( $tmp_address === null )
                                {
                                    $type = "ip-netmask";
                                    if( $addressNamePan == "all" || $addressNamePan == "All" )
                                        $value = "0.0.0.0/0";
                                    else
                                        $value = "1.1.1.1/32";
                                    $description = "";
                                    if( $print )
                                        print " X create object: " . "tmp-" . $addressNamePan . " type: " . $type . " value: " . $value . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress("tmp-" . $addressNamePan, $type, $value, $description);
                                    $addlog = "no value or type available in original config file";
                                    $tmp_address->set_node_attribute('error', $addlog);
                                }
                                else
                                {
                                    if( $addressNamePan != "all" && $addressNamePan != "All" )
                                        mwarning("tmp object: 'tmp-" . $addressNamePan . "' already available. how to continue?????", null, FALSE);
                                }
                            }

                            $type = "";
                            $ipaddress = "";
                            $netmask = "";
                            $cidr = "";
                            $addressName = "";
                            $addressNamePan = "";
                            $description = "";
                            $getRangeEnd = "";
                            $getRangeStart = "";
                            $fqdn = "";
                            $country = "";
                        }

                        if( preg_match("/set subnet /i", $names_line) )
                        {
                            #print "Es RED: $routes_line\n";
                            $type = "ip-netmask";
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $ipaddress = $data1[2];
                            $netmask = trim($data1[3]);
                            $cidr = $this->mask2cidrv4($netmask);
                        }
                        if( preg_match("/set type iprange/i", $names_line) )
                        {
                            $type = "ip-range";
                        }
                        if( preg_match("/set type geography/i", $names_line) )
                        {
                            $type = "region";
                        }

                        if( preg_match("/set country /i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $country = $data1[2];
                        }

                        if( preg_match("/set end-ip/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $getRangeEnd = $data1[2];
                        }

                        if( preg_match("/set start-ip/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $getRangeStart = $data1[2];
                        }
                        if( preg_match("/set type fqdn/i", $names_line) )
                        {
                            $type = "fqdn";
                        }
                        if( preg_match("/set fqdn/i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $fqdn = $data1[2];
                        }
                        if( preg_match("/set wildcard /i", $names_line) )
                        {
                            #add_log2('warning', 'Reading Address objects', 'Type wildcard is not supported [' . $names_line . '] in Host [' . $addressName . ']', $source, 'Add the right Ip and Netmask', '', '', '');
                        }
                        if( preg_match("/set comment /i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $description = addslashes($data1[2]);
                        }
                    }
                }
            }


            $lastline = $names_line;
        }


        /*
        if (count($sql) > 0) {
            $projectdb->query("INSERT INTO address (source,name_ext,name,vsys,type,vtype,fqdn,ipaddress,cidr,description) VALUES " . implode(",", $sql) . ";");
        }
        */
    }

    function get_addressv6( $ismultiornot, &$regions)
    {
        global $debug;
        global $print;
        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        global $projectdb;
        $isAddress = FALSE;
        $isObject = FALSE;
        $sql = array();
        $type = "ip-netmask";
        $ipaddress = "";
        $netmask = "";
        $cidr = "";
        $addressName = "";
        $addressNamePan = "";
        $description = "";
        $getRangeEnd = "";
        $getRangeStart = "";
        $fqdn = "";
        $country = "";

        $source = "";

        $defaultRegions = array();
        $defaultRegions = $this->default_regions();


        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }
        $lastline = "";
        foreach( $this->data as $line => $names_line )
        {

            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {
                if( preg_match("/config firewall address6/i", $names_line) )
                {
                    $isObject = TRUE;
                }


                if( $isObject )
                {
                    if( preg_match("/^\bend\b/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/\bedit\b/i", $names_line) )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $newname = str_replace('/', '-', $meta[1]);
                        $addressNamePan = $this->truncate_names($this->normalizeNames($newname));
                        $addressName = trim($meta[1]);

                        if( $addressName == "all" )
                        {
                            $type = "";
                        }
                    }

                    if( $isAddress )
                    {
                        if( preg_match("/\bnext\b/i", $names_line) )
                        {
                            $isAddress = FALSE;

                            if( $type == "fqdn" )
                            {
                                $sql[] = array($source, $addressName, $addressNamePan, $vsys, $type, '', $fqdn, $fqdn, $cidr, $description, '0', '1');

                                //newAddress($name , $type, $value, $description = '')
                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( $print )
                                        print " * create object: " . $addressNamePan . " type: " . $type . " value: " . $fqdn . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($addressNamePan, $type, $fqdn, $description);
                                }
                                else
                                {
                                    $this->tmp_address_validation($tmp_address, $addressNamePan, $type, $fqdn);
                                }

                                if( preg_match("/^\*/", $fqdn) )
                                {
                                    #add_log('error', 'FQDN Object', 'The Address [' . $addressName . '] contains an * [' . $fqdn . ']', $source, 'Wrong Content, replace this object by appropiate App-id');
                                }
                            }
                            elseif( $type == "ip-netmask" )
                            {
                                #$sql[] = "('$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$ipaddress','$cidr','$description','0','1')";
                                $sql[] = array($source, $addressName, $addressNamePan, $vsys, $type, '', $fqdn, $ipaddress, $cidr, $description, '0', '1');

                                //newAddress($name , $type, $value, $description = '')
                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( $print )
                                        print " * create object: " . $addressNamePan . " type: " . $type . " value: " . $ipaddress . "/" . $cidr . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($addressNamePan, $type, $ipaddress . "/" . $cidr, $description);
                                }
                                else
                                {
                                    //Todo: swaschkut 20190920
                                    //IPv4 none always exist - how to fix it????
                                    //possible solution _> create none_IPv6 -> rename none to "none_IPv4" -> create addressgroup "none" add both "none_IPv4" and "none_IPv6"
                                    $this->tmp_address_validation($tmp_address, $addressNamePan, $type, $ipaddress . "/" . $cidr);
                                }

                            }
                            elseif( $type == "ip-range" )
                            {
                                $ipaddress = $getRangeStart . "-" . $getRangeEnd;
                                #$sql[] = "('$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$ipaddress','$cidr','$description','0','1')";
                                $sql[] = array($source, $addressName, $addressNamePan, $vsys, $type, '', $fqdn, $ipaddress, $cidr, $description, '0', '1');
                                //newAddress($name , $type, $value, $description = '')
                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( $print )
                                        print " * create object: " . $addressNamePan . " type: " . $type . " value: " . $ipaddress . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress($addressNamePan, $type, $ipaddress, $description);
                                }
                                else
                                {
                                    $this->tmp_address_validation($tmp_address, $addressNamePan, $type, $ipaddress);
                                }
                            }
                            elseif( $type == "region" )
                            {
                                $regions[$addressNamePan] = $country;

                                $type = "ip-netmask";
                                $value = "1.1.1.1/32";
                                $description = $country;

                                $tmp_address = $this->sub->addressStore->find($addressNamePan);
                                if( $tmp_address === null )
                                {
                                    if( $print )
                                        print " X create tmp region object: region-" . $addressNamePan . " type: " . $type . " value: " . $value . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress("region-" . $addressNamePan, $type, $value, $description);
                                    $addlog = "region object is not a valid address object - migration process try to replace it later on";
                                    $tmp_address->set_node_attribute('error', $addlog);
                                }
                            }
                            else
                            {
                                $tmp_address = $this->sub->addressStore->find("tmp-" . $addressNamePan);
                                if( $tmp_address === null )
                                {
                                    $type = "ip-netmask";
                                    if( $addressNamePan == "all" || $addressNamePan == "All" )
                                        $value = "0.0.0.0/0";
                                    else
                                        $value = "1.1.1.1/32";
                                    $description = "";
                                    if( $print )
                                        print " X create tmp object: " . "tmp-" . $addressNamePan . " type: " . $type . " value: " . $value . "\n";
                                    $tmp_address = $this->sub->addressStore->newAddress("tmp-" . $addressNamePan, $type, $value, $description);
                                    $addlog = "no value or type available in original config file";
                                    $tmp_address->set_node_attribute('error', $addlog);
                                }
                                else
                                {
                                    if( $addressNamePan != "all" && $addressNamePan != "All" )
                                        mwarning("tmp object: 'tmp-" . $addressNamePan . "' already available. how to continue?????", null, FALSE);
                                }
                            }

                            $type = "";
                            $ipaddress = "";
                            $netmask = "";
                            $cidr = "";
                            $addressName = "";
                            $addressNamePan = "";
                            $description = "";
                            $getRangeEnd = "";
                            $getRangeStart = "";
                            $fqdn = "";
                            $country = "";
                        }

                        if( preg_match("/set ip6 /i", $names_line) )
                        {
                            #print "Es RED: $routes_line\n";
                            $type = "ip-netmask";
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                            $ipaddressfull = explode("/", $data[2]);
                            $ipaddress = $ipaddressfull[0];
                            $cidr = $ipaddressfull[1];
                        }

                        if( preg_match("/set subnet /i", $names_line) )
                        {
                            #print "Es RED: $routes_line\n";
                            $type = "ip-netmask";
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $ipaddress = $data[2];
                            $netmask = trim($data[3]);
                            $cidr = $this->mask2cidrv4($netmask);
                        }
                        if( preg_match("/set type iprange/i", $names_line) )
                        {
                            $type = "ip-range";
                        }
                        if( preg_match("/set type geography/i", $names_line) )
                        {
                            $type = "region";
                        }

                        if( preg_match("/set country /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $country = $data[2];
                        }

                        if( preg_match("/set end-ip/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $getRangeEnd = $data[2];
                        }

                        if( preg_match("/set start-ip/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $getRangeStart = $data[2];
                        }
                        if( preg_match("/set type fqdn/i", $names_line) )
                        {
                            $type = "fqdn";
                        }
                        if( preg_match("/set fqdn/i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $fqdn = $data[2];
                        }
                        if( preg_match("/set wildcard /i", $names_line) )
                        {
                            #add_log2('warning', 'Reading Address objects', 'Type wildcard is not supported [' . $names_line . '] in Host [' . $addressName . ']', $source, 'Add the right Ip and Netmask', '', '', '');
                        }
                        if( preg_match("/set comment /i", $names_line) )
                        {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $description = addslashes($data[2]);
                        }
                    }
                }
            }


            $lastline = $names_line;
        }

        if( count($sql) > 0 )
        {
            #print_r(  $sql );

            #$projectdb->query("INSERT INTO address (source,name_ext,name,vsys,type,vtype,fqdn,ipaddress,cidr,description,v4,v6) VALUES " . implode(",", $sql) . ";");
        }
    }

    function get_address_groups( $ismultiornot, &$regions)
    {
        global $debug;
        global $print;
        global $tmp_template_vsys;

        if( $this->configType == "panos" )
            $vsys = $this->template_vsys->alternativeName();
        else
        {
            $tmp_search = str_replace( "vsys", "", $this->template_vsys->name() );
            $vsys = array_search( $tmp_search, $tmp_template_vsys);
        }

        global $projectdb;

        $isAddress = FALSE;
        $isObject = FALSE;
        $sql = array();
        $addressGroup = array();
        $defaultRegions = array();
        $addressNamePan = "";
        $addressName = "";
        $description = "";

        $source = "";

        #Load Default Regions
        /*
        $getDFRegions=$projectdb->query("SELECT id,name FROM default_regions;");
        if ($getDFRegions->num_rows>0){
            while($getDFRegionsData=$getDFRegions->fetch_assoc()){
                $defaultRegions[$getDFRegionsData['name']]=$getDFRegionsData['id'];
            }
        }
        */
        $defaultRegions = $this->default_regions();


        $lid = 0;
        //SWASCHKUT: not needed???
        /*
        $getMaxID = $projectdb->query("SELECT max(id) as max FROM address_groups_id;");
        if ($getMaxID->num_rows == 1) {
            $max1 = $getMaxID->fetch_assoc();
            $lid = $max1['max'];
            if (($lid == null) OR ($lid == '')){
                $lid=0;
            }
            $lid++;
        }
        */

        if( $ismultiornot == "singlevsys" )
        {
            $START = TRUE;
            $VDOM = FALSE;
            $VDOM = FALSE;
        }
        else
        {
            $START = FALSE;
            $VDOM = FALSE;
        }
        $lastline = "";
        foreach( $this->data as $line => $names_line )
        {

            $this->check_vdom_start($START, $VDOM, $names_line, $lastline, $vsys);

            if( $START )
            {
                if( preg_match("/config firewall addrgrp/i", $names_line) )
                {
                    $isObject = TRUE;
                }


                if( $isObject )
                {
                    if( preg_match("/^\bend\b/i", $names_line) )
                    {
                        $isObject = FALSE;
                        $START = FALSE;
                    }
                    if( preg_match("/^\s*edit /i", $names_line) )
                    {
                        $isAddress = TRUE;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $newname = str_replace('/', '-', $meta[1]);
                        $addressNamePan = $this->truncate_names($this->normalizeNames($newname));
                        $addressName = $meta[1];
                    }

                    if( $isAddress )
                    {
                        if( preg_match("/set member /i", $names_line) )
                        {
                            $data1 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            foreach( $data1 as $value => $datos )
                            {

                                if( ($datos == "set") or ($datos == "member") )
                                {
                                }
                                else
                                {
                                    $member_lid = "";
                                    $table_name = "";
                                    if( isset($regions[$datos]) )
                                    {
                                        $table_name = "default_regions";

                                        #print_r( $defaultRegions );
                                        if( isset($defaultRegions[$regions[$datos]]) )
                                        {
                                            $member_lid = $defaultRegions[$regions[$datos]];
                                        }
                                        else
                                        {
                                            mwarning("array: defaultRegions does not has: " . $regions[$datos] . " set\n", null, FALSE);
                                        }
                                    }

                                    $sql[] = array($datos, $source, $vsys, $lid, $member_lid, $table_name);
                                }
                            }
                        }
                        if( preg_match("/set comment /i", $names_line) )
                        {
                            if( preg_match('/"([^"]+)"/', $names_line, $match) )
                            {
                                $description = addslashes(trim($match[1]));
                            }
                        }
                        if( preg_match("/\bnext\b/i", $names_line) )
                        {
                            $isAddress = FALSE;
                            $addressGroup[] = array($lid, $addressName, $addressNamePan, $source, $vsys, $description, 'static');

                            $lid++;
                            $addressNamePan = "";
                            $addressName = "";
                            $description = "";
                        }
                    }
                }
            }


            $lastline = $names_line;
        }

        if( count($addressGroup) > 0 )
        {
            foreach( $addressGroup as $group )
            {
                $HostGroupNamePan = $group[2];
                $tmp_addressgroup = $this->sub->addressStore->find($HostGroupNamePan);
                if( $tmp_addressgroup === null )
                {
                    if( $print )
                        print "\n * create addressgroup: " . $HostGroupNamePan . "\n";
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($HostGroupNamePan);
                }
                else
                {
                    print PH::boldText("   * addressgroup: " . $HostGroupNamePan . " already available; VSYS: " . $this->sub->name() . " - using existing one\n");
                }

                foreach( $sql as $member )
                {
                    if( $group[0] == $member[3] )
                    {
                        #$member_name = str_replace('/', '-', $member[0]);
                        $member_name = $this->truncate_names($this->normalizeNames($member[0]));


                        $tmp_address = $this->sub->addressStore->find($member_name);
                        if( $tmp_address === null )
                        {
                            $tmp_address = $this->sub->addressStore->find("tmp-" . $member_name);

                            if( $tmp_address === null )
                            {
                                $tmp_address = $this->sub->addressStore->find("region-" . $member_name);

                                if( $tmp_address === null )
                                {
                                    mwarning("address object with name: " . $member_name . " not found\n", null, FALSE);
                                }
                            }
                        }

                        if( $tmp_address !== null )
                        {
                            if( $print )
                            {
                                print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                            }
                            $tmp_addressgroup->addMember($tmp_address);
                        }
                    }
                }
            }

            #print_r( $addressGroup );
            #$projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,source,vsys,description,type) VALUES ". implode(",",$addressGroup).";");
            unset($addressGroup);
            if( count($sql) > 0 )
            {

                #print "REGION:\n";
                #print_r( $sql );
                #$projectdb->query("INSERT INTO address_groups (member,source,vsys,lid,member_lid,table_name) VALUES " . implode(",", $sql).";");
                unset($sql);
            }
        }
    }

}

