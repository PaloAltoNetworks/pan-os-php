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


class PFSENSE extends PARSER
{

    use SHAREDNEW;

    public function vendor_main()
    {
        // This starts logging object (for console output)




        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        global $print;
        $print = TRUE;

        $path = "";
        $project = "";

        $config_path = $path . $this->configFile;
        $filename = $this->configFile;
        $filenameParts = pathinfo($this->configFile);
        $verificationName = $filenameParts['filename'];



        $data = $this->clean_config($config_path, $project, $this->configFile);




        $v = $this->import_config($data); //This should update the $source


        CONVERTER::validate_interface_names($this->template);

        CONVERTER::cleanup_unused_predefined_services($this->sub, "default");

        CONVERTER::deleteDirectory( );
    }


    function clean_config($config_path, $project, $config_filename)
    {
        $config_file = file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $data = array();
        foreach( $config_file as $line => $names_line )
        {

            $data[] = $names_line;
        }
        #file_put_contents("test_output.txt", $data);
        #file_put_contents('test_output.txt', print_r($data, true));
        return $data;
    }

    function hasLetters($string)
    {
        if( preg_match("/[a-z]/i", $string) )
        {
            return TRUE;
        }
        else
            return FALSE;
    }

    function hasNumbers($string)
    {
        function hasLetters($string)
        {
            if( preg_match("/[0-9]/i", $string) )
            {
                return TRUE;
            }
            else
                return FALSE;
        }
    }

    function isIPAddress($ip)
    {
        if( filter_var($ip, FILTER_VALIDATE_IP) )
        {
            return TRUE;
        }
        else
            return FALSE;
    }

    function isNetworkAddress($ip)
    {
        if( preg_match("/[a-z]/i", $ip) )
        {
            return FALSE;
        }
        else
        {
            if( strpos($ip, '/') !== FALSE )
                return TRUE;
        }
    }

    function map_services_to_port($service)
    {
        $file_path = __DIR__ . "/services";
        $services_file = fopen($file_path, "r") or die("Unable to open file!");
        $file = fread($services_file, filesize($file_path));
        fclose($services_file);
        $file = explode("\n", $file);
        $services_map = [];
        foreach( $file as $key => $value )
        {
            if( preg_match("([a-z].*[0-9]/)", $value) )
            {
                $tmp_arr = preg_split("/\s+/", $value);
                $port_arr = explode("/", $tmp_arr[1]);
                $services_map[$tmp_arr[0]] = $port_arr[0];
            }
        }

        $services_map = array_reverse($services_map);
        if( $service != "" )
        {
            return $services_map[$service];
        }
        else
            return $services_map;
    }

    function getAclInterface($line)
    {
        $interface_acl = "";
        $tmp_zone = null;
        if( preg_match('/on\s\$[A-z,0-9]+/', $line, $match) )
            $interface_acl = str_replace('$', "", str_replace("on ", "", $match[0]));
        if( $interface_acl != "" )
        {
            $tmp_zone = $this->template_vsys->zoneStore->find($interface_acl);
            if( $tmp_zone == null )
            {
                $tmp_name = $this->truncate_names($this->normalizeNames($interface_acl));
                $tmp_zone = $this->template_vsys->zoneStore->newZone($interface_acl, 'layer3');
            }
        }
        return $tmp_zone;
    }

    function getAclProto($line)
    {
        $proto_acl = "";
        if( preg_match('/(?:proto.*)(tcp|udp|icmp)/', $line, $match) )
            $proto_acl = str_replace("proto ", "", $match[0]);
        return $proto_acl;
    }

    function getAclDst($line)
    {
        $dst_acl = "";
        $tmp_address_arr = [];
        if( preg_match('/\s(?:to\s+)(<[A-z,0-9]+>|\$[A-z,0-9]+|{\s?+\$[A-z,0-9,\s,\$,-,\.,\/]+}|{\s?+[\<,A-z,0-9,\s,\$,\.,\>,-,\/]+}|\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d{1,2}|\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|any|{\s?+((\s)?\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(,)?)+(\s+)?}|{\s?+((\s)?\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d{1,2}(,)?)+(\s+)?})/', $line, $match) )
            $dst_acl = preg_replace("/(to\s+)|(\s+)/", "", $match[0]);
        #$dst_acl=preg_replace('/(to)|(\s+)|(<)|(>)|({)|(})/', "", $match[0]);
        $dst_acl = str_replace('$', "", preg_replace('/($)|({)|(})|(<)|(>)/', "", $dst_acl));
        $dst_elements = explode(',', $dst_acl);

        foreach( $dst_elements as $key => $value )
        {
            $prefix = "";
            if( $value !== "" )
            {
                $object = $value;
                if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                {
                    if( $this->isIPAddress($object) )
                    {
                        $prefix = "H_";
                    }
                    else if( $this->isNetworkAddress($object) )
                    {
                        $prefix = "N_";
                    }
                    $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                }

                $tmp_address = $this->sub->addressStore->find($object);
                if( $tmp_address === null )
                {
                    #this should not happen
                    print "WARNING CREATING FROM RULE     * create address object: " . $object . " " . $value . "\n";
                    if( $this->isIPAddress($value) || $this->isNetworkAddress($value) )
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($value), $value);
                    else
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($value), "None");
                }
                $tmp_address_arr[] = $tmp_address;
                unset($tmp_address);
            }
        }
        #if($src_acl=="")
        #{
        #    print($line."\n");
        #   print(print_r($src_elements,true)."\n");
        #}
        return $tmp_address_arr;
    }

    function getAclSrc($line)
    {
        $src_acl = "";
        $tmp_address_arr = [];
        if( preg_match('/(?:from\s+)(\!?<[A-z,0-9,\!]+>|\$[A-z,0-9]+|{(\s)?+\$?[A-z,0-9,\s,\$,\!,\<,\/,\.]+}|{\s?+[!,\<,A-z,0-9,\.,\/,\s,\$,\>]+}|\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d{1,2}|\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|any|{\s?+((\s)?\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(,)?)+\s?+}|{\s?+(\s?+\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d{1,2}(,)?)+\s?+)/', $line, $match) )
            $src_acl = preg_replace("/(from\s+)|(\s+)/", "", $match[0]);
        #$src_acl=preg_replace('/(\s+)|(from)|(<)|(>)|({)|(})/', "", $match[0]);
        $src_acl = str_replace('$', "", preg_replace('/($)|({)|(})|(<)|(>)/', "", $src_acl));
        $src_elements = explode(',', $src_acl);

        foreach( $src_elements as $key => $value )
        {
            $prefix = "";
            if( $value !== "" )
            {
                $object = $value;
                if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                {
                    if( $this->isIPAddress($object) )
                    {
                        $prefix = "H_";
                    }
                    else if( $this->isNetworkAddress($object) )
                    {
                        $prefix = "N_";
                    }
                    $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                }

                $tmp_address = $this->sub->addressStore->find($object);
                if( $tmp_address === null )
                {
                    #this should not happen
                    print "WARNING CREATING FROM RULE     * create address object: " . $object . " " . $value . "\n";
                    if( $this->isIPAddress($value) || $this->isNetworkAddress($value) )
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($value), $value);
                    else
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($value), "None");
                }
                $tmp_address_arr[] = $tmp_address;
                unset($tmp_address);
            }
        }
        #if($src_acl=="")
        #{
        #    print($line."\n");
        #print(print_r($src_elements,true)."\n");
        #}
        return $tmp_address_arr;
    }

    function getAclPorts($line)
    {
        $ports_acl = "";
        $ports_assoc = [];
        if( preg_match('/(?:port\s+)([\-,0-9,\d,a-z,:]+|{\s?+[[A-z,0-9,>=,\:,\,\s]+}|>=\s+[0-9]+)/', $line, $match) )
        {
            $ports_acl = preg_replace("/(port)|(\s+)|({)|(})/", "", $match[0]);
        }
        #print $line;
        $tmp_ports_arr = explode(",", $ports_acl);
        $services_map_arr = $this->map_services_to_port("");
        $port_map_arr = array_flip($services_map_arr);
        foreach( $tmp_ports_arr as $key => $value )
        {
            if( $this->hasLetters($value) )
            {
                $tmp_services_map = $services_map_arr[$value];
                if( preg_match("/tcp/i", $line) )
                    $ports_assoc["service-" . $value . "-tcp"] = $tmp_services_map;
                if( preg_match("/udp/i", $line) )
                    $ports_assoc["service-" . $value . "-udp"] = $tmp_services_map;
            }
            else if( strpos($value, ":") == !FALSE && $this->hasLetters($value) == FALSE )
            {
                if( preg_match("/tcp/i", $line) )
                    $ports_assoc["service-" . str_replace(":", "-", $value) . "-tcp"] = str_replace(":", "-", $value);
                if( preg_match("/udp/i", $line) )
                    $ports_assoc["service-" . str_replace(":", "-", $value) . "-udp"] = str_replace(":", "-", $value);

            }
            else if( $this->hasLetters($value) == FALSE && strpos($value, ":") == FALSE )
            {
                if( array_key_exists($value, $port_map_arr) )
                {
                    if( preg_match("/tcp/i", $line) )
                        $ports_assoc["service-" . $port_map_arr[$value] . "-tcp"] = $value;
                    if( preg_match("/udp/i", $line) )
                        $ports_assoc["service-" . $port_map_arr[$value] . "-udp"] = $value;
                }
                else
                {
                    if( preg_match("/tcp/i", $line) )
                        $ports_assoc["service-" . $value . "-tcp"] = $value;
                    if( preg_match("/udp/i", $line) )
                        $ports_assoc["service-" . $value . "-udp"] = $value;
                }
            }
        }
        #print_r($ports_assoc);
        foreach( $ports_assoc as $key => $value )
        {
            if( preg_match("/[uU][dD][pP]/", $key) )
            {
                $proto = "udp";
            }
            else
            {
                $proto = "tcp";
            }
            $service_name = $value;
            if( strpos($service_name, ">") !== FALSE )
            {
                $service_name = preg_replace("/>=|>/", "", $service_name);
                $service_name = $service_name . "-65535";
            }
            else if( strpos($service_name, "<") !== FALSE )
            {
                $service_name = preg_replace("/<=|</", "", $service_name);
                $service_name = "0-" . $service_name;
            }
            $tmp_service = $this->sub->serviceStore->find(preg_replace("/>=|>/", "gt-", preg_replace("/<=|</", "lt-", $key)));
            if( $tmp_service == null && $service_name !== "" )
            {
                $tmp_service = $this->sub->serviceStore->newService(preg_replace("/>=|>/", "gt-", preg_replace("/<=|</", "lt-", $key)), $proto, $service_name);
            } #else
            #unset($ports_assoc[$key]);
        }

        return $ports_assoc;
    }

    /*
                                                self::TypeIpNetmask => 'ip-netmask',
                                            self::TypeIpRange => 'ip-range',
                                            self::TypeFQDN => 'fqdn',
                                            self::TypeDynamic => 'dynamic',
                                            self::TypeIpWildcard =>  'ip-wildcard'
    */
    function returnHostType($object)
    {
        if( strpos($object, "-") )
        {
            return "ip-range";
        }
        else
            return "ip-netmask";
    }

    function get_interfaces($data)
    {
        $vsys = $this->template_vsys->name();
        #Check if THE VR is already created for this VSYS
        $vr = "vr_" . $vsys;


        $source = "";
        $template = "";
        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr === null )
        {
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
        }
        $interfaces_assoc = [];
        $subinterface_name_map_assoc = [];
        $subinterface_phy_map_assoc = [];
        $vlans_assoc = [];
        $phy_iface_assoc = [];

        foreach( $data as $key => $value )
        {
            $phy_iface = "";
            $vlan_id = "";
            $description = "";
            $ip_addr = "";
            $netmask = "";
            $carpdev_vlanid = "";
            $vlan_iface_name = "";
            if( preg_match("/#{1,3}\s/", $value) )
                $last_comment = $value;
            if( preg_match("/.*_if=.*/", $value) )
            {
                $tmp_interface_arr = explode("=", $value);
                $tmp = $tmp_interface_arr[1];
                if( preg_match("/vlan.*/", $tmp) )
                {
                    $subinterface_name_map_assoc[$tmp_interface_arr[0]] = $tmp_interface_arr[1];
                }
                else
                {
                    $interfaces_assoc[$tmp_interface_arr[0]] = $tmp_interface_arr[1];
                }
            }
            if( preg_match('/inet\s+\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\s+/', $value) )
            {
                if( preg_match('/^ifconfig/', $value) )
                {
                    if( preg_match('/(?<=vlan)(\s)?[0-9]+/', $value, $matches) )
                    {
                        $vlan_id = $matches[0];
                        if( preg_match('/(?<=vlandev\s)[a-z]+[0-9]{1,2}/', $value, $matches) )
                        {
                            $vlan_iface_name = $matches[0] . "." . $vlan_id;
                            $vlans_assoc[$vlan_iface_name]['physical_interface'] = $matches[0];
                            $vlans_assoc[$vlan_iface_name]['tag'] = $vlan_id;

                            if( array_key_exists($matches[0], $phy_iface_assoc) == FALSE )
                            {
                                $phy_iface_assoc[$matches[0]]['description'] = "";
                                $phy_iface_assoc[$matches[0]]['ip'] = "";
                                $phy_iface_assoc[$matches[0]]['netmask'] = "";
                            }
                        }
                        if( preg_match('/(?<=description\s)(\")?[A-z,0-9]+/', $value, $matches) )
                            $vlans_assoc[$vlan_iface_name]['description'] = $matches[0];
                        if( preg_match('/(?<=inet\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/', $value, $matches) )
                            $vlans_assoc[$vlan_iface_name]['ip'] = $matches[0];
                        if( preg_match('/(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(?=\sNONE))|(?<=netmask\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/', $value, $matches) )
                            $vlans_assoc[$vlan_iface_name]['netmask'] = $matches[0];
                    }
                    else if( preg_match('/(?<=ifconfig_)[a-z]+[0-9]+/', $value, $matches) )
                    {
                        #print $value . "\n";
                        $phy_iface_name = $matches[0];
                        if( preg_match('/(?<=description\s)(\")?[A-z,0-9]+/', $value, $matches) )
                            $phy_iface_assoc[$phy_iface_name]['description'] = $matches[0];
                        if( preg_match('/(?<=inet\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/', $value, $matches) )
                            $phy_iface_assoc[$phy_iface_name]['ip'] = $matches[0];
                        if( preg_match('/(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(?=\sNONE))|(?<=netmask\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/', $value, $matches) )
                            $phy_iface_assoc[$phy_iface_name]['netmask'] = $matches[0];
                    }
                }
                else if( preg_match('/^inet\s+\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\s+/', $value) )
                {
                    if( preg_match('/(?<=vlandev\s)[a-z]+[0-9]{1,2}/', $value) )
                    {
                        if( preg_match('/(?<=vlan\s)[0-9]+/', $value, $matches) )
                        {
                            $vlan_id = $matches[0];
                            if( preg_match('/(?<=vlandev\s)[a-z]+[0-9]{1,2}/', $value, $matches) )
                            {
                                $vlan_iface_name = $matches[0] . "." . $vlan_id;
                                $vlans_assoc[$vlan_iface_name]['physical_interface'] = $matches[0];
                                $vlans_assoc[$vlan_iface_name]['tag'] = $vlan_id;

                                if( array_key_exists($matches[0], $phy_iface_assoc) == FALSE )
                                {
                                    $phy_iface_assoc[$matches[0]]['description'] = "";
                                    $phy_iface_assoc[$matches[0]]['ip'] = "";
                                    $phy_iface_assoc[$matches[0]]['netmask'] = "";
                                }
                            }
                            if( preg_match('/(?<=description\s)(\")?[A-z,0-9]+/', $value, $matches) )
                                $vlans_assoc[$vlan_iface_name]['description'] = str_replace('"', '', $matches[0]);
                            if( preg_match('/(?<=inet\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/', $value, $matches) )
                                $vlans_assoc[$vlan_iface_name]['ip'] = $matches[0];
                            if( preg_match('/(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(?=\sNONE))|(?<=netmask\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/', $value, $matches) )
                                $vlans_assoc[$vlan_iface_name]['netmask'] = $matches[0];
                        }
                    }
                }
            }
        }
        $all_interfaces_assoc = array_merge($interfaces_assoc, $subinterface_name_map_assoc);
        $iface_to_zone_assoc = array_flip($all_interfaces_assoc);
        foreach( $all_interfaces_assoc as $key => $value )
        {
            if( $key != "" )
            {
                #print($key."\n");
                $tmp_zone = $this->template_vsys->zoneStore->find($key);
                if( $tmp_zone == null )
                {
                    $tmp_name = $this->truncate_names($this->normalizeNames($key));
                    $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                }
            }
            else
            {
                print "LINE: " . $key . "\n";
                mwarning("empty zone: why??", null, FALSE);
            }
        }
        foreach( $phy_iface_assoc as $key => $value )
        {
            $tmp_int_main = $this->template->network->findInterface($key);
            if( !is_object($tmp_int_main) )
            {
                $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($key, 'layer3');
                $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);
                if( $value['ip'] !== "" )
                {
                    # This is adding an address object.
                    $tmp_address = $this->sub->addressStore->find($key);
                    if( $tmp_address === null )
                    {
                        #print $key . " " . $value['ip'] . $value['description'];
                        $tmp_address = $this->sub->addressStore->newAddress($key, $this->returnHostType($value['ip'] . "/" . $this->mask2cidrv4($value['netmask'])), $value['ip'] . "/" . $this->mask2cidrv4($value['netmask']), $value['description']);
                    }
                    $tmp_int_main->addIPv4Address($tmp_address->name());
                }
            }
            $tmp_int_main->setDescription($value['description'], "comment");
            if( array_key_exists($key, $iface_to_zone_assoc) )
            {
                $tmp_zone = $this->template_vsys->zoneStore->find($iface_to_zone_assoc[$key]);
                if( $tmp_zone == null )
                {
                    $tmp_name = $this->truncate_names($this->normalizeNames($key));
                    $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                }
                $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                $tmp_vr->attachedInterfaces->addInterface($tmp_int_main);
            }
        }
        foreach( $vlans_assoc as $key => $value )
        {
            $tmp_int_main = $this->template->network->findInterface($value['physical_interface']);
            if( $tmp_int_main == null )
                print "ERROR: NO MAIN INTERFACE";
            $tmp_sub = $this->template->network->findInterface($key);
            if( $tmp_sub === null )
            {
                $tmp_sub = $tmp_int_main->addSubInterface($value['tag'], $key);
                $this->template_vsys->importedInterfaces->addInterface($tmp_sub);
            }

            if( $value['ip'] !== "" )
            {
                # This is adding an address object.
                $tmp_address = $this->sub->addressStore->find($key);
                if( $tmp_address === null )
                {
                    #print $key . " " . $value['ip'] . $value['description'];
                    $tmp_address = $this->sub->addressStore->newAddress($key, $this->returnHostType($value['ip'] . "/" . $this->mask2cidrv4($value['netmask'])), $value['ip'] . "/" . $this->mask2cidrv4($value['netmask']), $value['description']);
                }
                $tmp_sub->addIPv4Address($tmp_address->name());
            }
            #print("key:".$key." value:".$value['tag']."\n");
            if( array_key_exists("vlan" . $value['tag'], $iface_to_zone_assoc) )
            {
                $tmp_zone = $this->template_vsys->zoneStore->find($iface_to_zone_assoc["vlan" . $value['tag']]);
                if( $tmp_zone == null )
                {
                    $tmp_name = $this->truncate_names($this->normalizeNames("vlan" . $value['tag']));
                    $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                }
                $tmp_zone->attachedInterfaces->addInterface($tmp_sub);
            }
            $tmp_vr->attachedInterfaces->addInterface($tmp_sub);
            $tmp_sub->setDescription($value['description'], "comment");
        }
        #echo PH::boldText("\n".print_r($phy_iface_assoc,true).print_r($vlans_assoc,true).print_r($iface_to_zone_assoc,true)."\n");
    }

    function get_hosts($data)
    {
        $hosts_assoc = [];
        $hosts = [];
        $last_comment = "";
        foreach( $data as $key => $value )
        {
            if( preg_match("/#{1,3}\s/", $value) )
                $last_comment = $value;
            if( preg_match("(.*=.*\"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\"|.*=.*\"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}\")", $value) )
            {
                $tmp_hosts = explode("=", $value);
                $hosts_assoc[trim(str_replace(" ", "", $tmp_hosts[0]))][0] = preg_replace("/(\")|(\")|(\s)d/", "", $tmp_hosts[1]);
                $hosts_assoc[trim(str_replace(" ", "", $tmp_hosts[0]))][1] = $last_comment;
            }
        }
        #echo PH::boldText("\n".print_r($hosts_assoc,true)."\n");
        foreach( $hosts_assoc as $key => $value )
        {
            $prefix = "";
            if( $this->isIPAddress($key) )
            {
                $prefix = "H_";
            }
            else if( $this->isNetworkAddress($key) )
            {
                $prefix = "N_";
            }
            $object = $prefix . $key;
            $tmp_address = $this->sub->addressStore->find($object);
            if( $tmp_address === null )
            {
                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($value[0]), trim($value[0]), trim($value[1]));
            }
            else
                mwarning("object: " . $object . " already available\n", null, FALSE);
        }
    }

    function get_hostgroups($data)
    {
        $hostgroup_assoc = array();
        foreach( $data as $key => $value )
        {
            if( preg_match("/#{1,3}\s/", $value) )
                $last_comment = $value;
            if( preg_match("/table.*<.*>.*{.*}/", $value) )
            {
                $tmp_hostgroup = explode("{", $value);
                $hostgroup_assoc[preg_replace("/table|\s|<|>/", "", $tmp_hostgroup[0])][0] = str_replace("$", "", preg_replace("(\s|})", "", $tmp_hostgroup[1]));
                $hostgroup_assoc[preg_replace("/table|\s|<|>/", "", $tmp_hostgroup[0])][1] = $last_comment;
            }
        }
        #echo PH::boldText("\n". print_r($hostgroup_assoc) . "\n");
        foreach( $hostgroup_assoc as $key => $value )
        {
            $tmp_addressgroup = $this->sub->addressStore->find($key);
            if( $tmp_addressgroup === null )
            {
                $tmp_addressgroup = $this->sub->addressStore->newAddressGroup($key);
                $tmp_addressgroup->setDescription($value[1]);
            }
            else
            {
                #mwarning( "addressgroup: ".$key." already available\n" , null, false);
                if( $tmp_addressgroup->isAddress() )
                {
                    $addlog = "an addressgroup same name; member:" . $key . " " . $value[0];
                    $tmp_addressgroup->set_node_attribute('error', $addlog);
                    $tmp_addressgroup = $this->sub->addressStore->newAddressGroup("tmp_" . $key);
                }
            }
            foreach( explode(",", $value[0]) as $key2 => $member )
            {
                $prefix = "";
                if( $member != "" )
                {
                    if( $this->isIPAddress($member) )
                    {
                        $prefix = "H_";
                    }
                    else if( $this->isNetworkAddress($member) )
                    {
                        $prefix = "N_";
                    }
                }
                $address_name = $prefix . str_replace(".", "_", str_replace("/", "_", $member));
                #print($address_name . " " . $member ."\n");


                if( $address_name != "" )
                {
                    $tmp_address = $this->sub->addressStore->find($address_name);
                    if( $tmp_address === null )
                        $tmp_address = $this->sub->addressStore->newAddress($address_name, 'ip-netmask', $member);
                    #mwarning( $member, null, false);

                    if( $tmp_address !== null )
                    {
                        if( !$tmp_addressgroup->hasObjectRecursive($tmp_address) )
                        {
                            #print "    * add addressobject: " . $tmp_address->name() . " to addressgroup: " . $tmp_addressgroup->name() . "\n";
                            $tmp_addressgroup->addMember($tmp_address);
                        }
                        else
                        {
                            #print "address object with name: ". $tmp_address->name(). " is already a member or submember of addressgroup: ".$tmp_addressgroup->name()."\n";
                        }
                    }
                    unset($tmp_address);
                }

            }
            if( $tmp_addressgroup->count() == 0 )
            {
                $this->sub->addressStore->remove($tmp_addressgroup);
            }
        }


    }

    function get_ntps($data)
    {
        foreach( $data as $key => $value )
        {
            if( preg_match("/#/", $value) )
                $last_comment = $value;
            if( preg_match("/^server \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/", $value) )
                echo PH::boldText("\n $value \n");
        }
    }

    function get_acl($data)
    {
        $counter = "";
        foreach( $data as $key => $value )
        {
            if( preg_match("/#{2,3}\s/", $value) and preg_match("/pass in|block in/", $value) == FALSE )
                $last_comment = trim($value);
            if( preg_match("/^#\s/", $value) and preg_match("/pass in|block in/", $value) == FALSE )
                $last_section_comment = trim($value);
            if( preg_match("/pass in|block in/", $value) )
            {
                $rule_is_disabled = FALSE;
                if( substr($value, 0, 1) === '#' )
                    $rule_is_disabled = TRUE;
                if( strpos($value, "pass") > -1 )
                {
                    $rule_action = "allow";
                }
                else
                    $rule_action = "deny";
                $interface = $this->getAclInterface($value);
                $protocol = $this->getAclProto($value);
                $source = $this->getAclSrc($value);
                $destination = $this->getAclDst($value);
                $ports_arr = $this->getAclPorts($value);

                #echo PH::boldText("\nINTERFACE:".$interface." PROTO:".$protocol." DST:".$destination." SRC:".$source." PORTS:".$ports_arr."\n");
                $name = $this->normalizeNames($last_comment);
                if( $name == "" )
                    $name = $this->normalizeNames($last_section_comment);
                $name = trim(substr($name, 0, 53));
                #$name=$last_comment;
                #print $name."\n";
                if( $protocol !== "icmp" )
                {
                    $tmp_rule = $this->sub->securityRules->find($name);
                    if( $tmp_rule == null )
                    {
                        $counter = "";
                        $tmp_rule = $this->sub->securityRules->newSecurityRule($name);
                        $tmp_protocol = "";
                        $service_source = "";
                    }
                    else
                    {
                        if( $counter == "" )
                        {
                            $counter = "1_";
                        }
                        else
                        {
                            $count = substr($counter, 0, 1) + 1;
                            $counter = $count . "_";
                        }
                        if( substr($name, 0, 1) == " " )
                            $name = substr($name, 1, strlen($name) - 1);
                        $name = $counter . $name;
                        $tmp_rule = $this->sub->securityRules->find($name);
                        if( $tmp_rule !== null )
                            $name = $name . rand(1, 100);
                        $tmp_rule = $this->sub->securityRules->newSecurityRule($name);
                        $tmp_protocol = "";
                        $service_source = "";
                    }
                    foreach( $source as $key_src => $value_src )
                    {
                        $tmp_rule->source->addObject($value_src);
                    }
                    foreach( $destination as $key_dst => $value_dst )
                    {
                        $tmp_rule->destination->addObject($value_dst);
                    }
                    #set rule name
                    $tmp_rule->setName($name);
                    #setting the action
                    $tmp_rule->setAction($rule_action);
                    #disabilng the rule if it was commented out in the config #
                    $tmp_rule->setDisabled($rule_is_disabled);

                    if( $interface !== null )
                        $tmp_rule->from->addZone($interface);
                    #set rule description
                    $tmp_rule->setDescription($last_section_comment . "\n" . $last_comment . "\n" . $value);
                    #adding tags
                    $tagname = $this->truncate_tags($this->normalizeNames($last_comment));
                    if( $tagname != "" )
                    {
                        $tmp_tag = $this->sub->tagStore->find($tagname);
                        if( $tmp_tag == null )
                        {
                            $tmp_tag = $this->sub->tagStore->createTag($tagname);
                            #print"    Tag create: " . $tmp_tag->name() . "\n";
                        }
                        $tmp_tag->setColor("color" . rand(1, 16));
                    }
                    $tmp_rule->tags->addTag($tmp_tag);
                    $tagname = $this->truncate_tags($this->normalizeNames($last_section_comment));
                    if( $tagname != "" )
                    {
                        $tmp_tag = $this->sub->tagStore->find($tagname);
                        if( $tmp_tag == null )
                        {
                            $tmp_tag = $this->sub->tagStore->createTag($tagname);
                            #print"    Tag create: " . $tmp_tag->name() . "\n";
                        }
                        $tmp_tag->setColor("color" . rand(1, 16));
                    }
                    $tmp_rule->tags->addTag($tmp_tag);
                    #adding services
                    foreach( $ports_arr as $key => $value )
                    {
                        $tmp_service = $this->sub->serviceStore->find(preg_replace("/>=|>/", "gt-", $key));
                        if( $tmp_service === null )
                        {
                            print "BREAK:" . $key . "\n";
                            break;
                        }
                        $tmp_rule->services->add($tmp_service);
                    }
                }
            }
        }
    }

    function get_nat($data)
    {
        $counter = "";
        foreach( $data as $key => $value )
        {
            if( preg_match("/#{2,3}\s/", $value) and preg_match("/(?<=nat on\s)(.*)/", $value) == FALSE )
                $last_comment = $value;
            if( preg_match("/^#\s/", $value) and preg_match("/(?<=nat on\s)(.*)/", $value) == FALSE )
                $last_section_comment = $value;

            #dynamic-ip-and-port nat
            #- nat on $ras_if from { 10.72.251.11, 10.72.251.12, 10.72.251.13, 10.72.251.38, 10.72.251.37, 10.72.251.31, 10.72.251.32, 10.72.251.33, 10.72.251.40, 10.72.251.39 } to { 80.12.36.131 } -> 160.92.3.153
            #match out on $ras_if from { 10.72.251.11, 10.72.251.12, 10.72.251.13, 10.72.251.38, 10.72.251.37, 10.72.251.31, 10.72.251.32, 10.72.251.33, 10.72.251.40, 10.72.251.39 } to { 80.12.36.131 } -> 160.92.3.153
            if( preg_match("/(?<=^nat on\s)(.*)/", $value) )
            {
                #from
                preg_match("/(?<=from\s)({|<)(.*)(}|>)(?= to)/", $value, $from_addr);
                #destination zone
                preg_match("/(?<=nat on\s)(.*)(?=\sfrom)/", $value, $dst_zone);
                #to
                preg_match("/(?<=to\s{\s)(.*)(?=\s\})/", $value, $to_addr);
                #nat
                preg_match("/(?<=->\s)(.*)/", $value, $snat_addr);
                print(print_r($from_addr, TRUE) . print_r($dst_zone, TRUE) . print_r($to_addr) . print_r($snat_addr));

                $ruleName = trim($this->truncate_names($this->normalizeNames($last_comment . "-" . $last_section_comment)));
                if( $ruleName == "" )
                    $ruleName = trim($this->truncate_names($this->normalizeNames($last_comment)));
                print("RULENAME: " . $ruleName . "\n");
                $tmp_nat_rule = $this->sub->natRules->find($ruleName);
                #$tmp_rule = $this->sub->securityRules->find( $ruleName ) ;
                if( $tmp_nat_rule == null )
                {
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName);
                    #$tmp_rule = $this->sub->securityRules->newSecurityRule( $ruleName );
                }
                else
                {
                    $tmp_rand_no = rand(10, 1000);
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName . '_' . $tmp_rand_no);
                    #$tmp_rule = $this->sub->securityRules->newSecurityRule( $ruleName.'_'.$tmp_rand_no );
                    #print("\n".$ruleName."\n");
                }
                if( empty($from_addr) == FALSE )
                {
                    foreach( explode(',', $from_addr[0]) as $key => $from_addr_value )
                    {
                        $from_addr_value = trim(str_replace("$", "", preg_replace("/<|>|{|}/", "", $from_addr_value)));
                        if( $from_addr_value !== "" )
                        {
                            $object = $from_addr_value;
                            if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                            {
                                if( $this->isIPAddress($object) )
                                {
                                    $prefix = "H_";
                                }
                                else if( $this->isNetworkAddress($object) )
                                {
                                    $prefix = "N_";
                                }
                                $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                            }

                            $tmp_address = $this->sub->addressStore->find($object);
                            if( $tmp_address === null )
                            {
                                #this should not happen
                                print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                                if( $this->isIPAddress($from_addr_value) || $this->isNetworkAddress($from_addr_value) )
                                    $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($from_addr_value), $from_addr_value);
                                else
                                    $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($from_addr_value), "None");
                            }
                            $tmp_nat_rule->source->addObject($tmp_address);
                            #$tmp_rule->source->addObject( $tmp_address );
                            unset($tmp_address);
                        }
                    }
                }
                if( empty($to_addr) == FALSE )
                {
                    foreach( explode(',', $to_addr[0]) as $key => $to_addr_value )
                    {
                        $to_addr_value = trim(str_replace("$", "", preg_replace("/<|>|{|}/", "", $to_addr_value)));
                        if( $to_addr_value !== "" )
                        {
                            $object = $to_addr_value;
                            if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                            {
                                if( $this->isIPAddress($object) )
                                {
                                    $prefix = "H_";
                                }
                                else if( $this->isNetworkAddress($object) )
                                {
                                    $prefix = "N_";
                                }
                                $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                            }

                            $tmp_address = $this->sub->addressStore->find($object);
                            if( $tmp_address === null )
                            {
                                #this should not happen
                                print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                                if( $this->isIPAddress($to_addr_value) || $this->isNetworkAddress($to_addr_value) )
                                    $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), $to_addr_value);
                                else
                                    $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), "None");
                            }
                            $tmp_nat_rule->destination->addObject($tmp_address);
                            #$tmp_rule->destination->addObject( $tmp_address );
                            unset($tmp_address);
                        }
                    }
                }
                #$tmp_rule->setAction("allow");
                $object = trim(str_replace("$", "", $snat_addr[0]));
                if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                {
                    if( $this->isIPAddress($object) )
                    {
                        $prefix = "H_";
                    }
                    else if( $this->isNetworkAddress($object) )
                    {
                        $prefix = "N_";
                    }
                    $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                }
                $tmp_address = $this->sub->addressStore->find($object);;
                if( $tmp_address === null )
                {
                    #this should not happen
                    print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                    if( $this->isIPAddress($snat_addr[0]) || $this->isNetworkAddress($snat_addr[0]) )
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($snat_addr[0]), $snat_addr[0]);
                    else
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($snat_addr[0]), "None");
                }
                $tmp_nat_rule->snathosts->addObject($tmp_address);
                unset($tmp_address);
                $tmp_nat_rule->from->setAny();
                $object = trim(str_replace("$", "", $dst_zone[0]));
                $tmp_zone = $this->template_vsys->zoneStore->find($object);
                if( $tmp_zone == null )
                {
                    $tmp_name = $this->truncate_names($this->normalizeNames($object));
                    $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                }
                $tmp_nat_rule->to->addZone($tmp_zone);
                $tmp_nat_rule->from->addZone($tmp_zone);
                #$tmp_rule->to->addZone($tmp_zone);
                #$tmp_rule->from->addZone($tmp_zone);
                #$tmp_rule->setDescription($last_comment."\n".$last_section_comment."\n".$value);
                $tmp_nat_rule->setDescription($last_comment . "\n" . $last_section_comment . "\n" . $value);
                $tmp_nat_rule->changeSourceNAT('dynamic-ip-and-port');
            }
            if( preg_match("/(?<=rdr on\s)(.*)/", $value) )
            {
                #zone
                preg_match("/(?<=rdr on\s)(.*)(?=\s+from)/", $value, $to_zone);
                #to addr
                preg_match("/(?<=to\s)(.*)(?=\s+->)/", $value, $to_addr);
                #dnat to
                preg_match("/(?<=->\s)(.*)/", $value, $dnat_addr);

                $ruleName = trim($this->truncate_names($this->normalizeNames($last_comment . "-" . $last_section_comment)));
                if( $ruleName == "" )
                    $ruleName = trim($this->truncate_names($this->normalizeNames($last_comment)));
                $tmp_nat_rule = $this->sub->natRules->find($ruleName);
                if( $tmp_nat_rule == null )
                {
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName);
                }
                else
                {
                    $tmp_nat_rule = $this->sub->natRules->newNatRule(substr($ruleName, 0, 56) . '_' . rand(10, 1000));
                    #print("\n".$ruleName."\n");
                }

                foreach( explode(',', $to_addr[0]) as $key => $to_addr_value )
                {
                    $from_addr_value = trim($to_addr_value);
                    if( $from_addr_value !== "" )
                    {
                        $object = trim($to_addr_value);
                        if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                        {
                            if( $this->isIPAddress($object) )
                            {
                                $prefix = "H_";
                            }
                            else if( $this->isNetworkAddress($object) )
                            {
                                $prefix = "N_";
                            }
                            $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                        }

                        $tmp_address = $this->sub->addressStore->find($object);
                        if( $tmp_address === null )
                        {
                            #this should not happen
                            print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                            if( $this->isIPAddress($to_addr_value) || $this->isNetworkAddress($to_addr_value) )
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), $to_addr_value);
                            else
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), "None");
                        }
                        $tmp_nat_rule->source->setAny();
                        unset($tmp_address);
                    }
                }

                foreach( explode(',', $to_addr[0]) as $key => $to_addr_value )
                {
                    $to_addr_value = trim($to_addr_value);
                    if( $to_addr_value !== "" )
                    {
                        $object = $to_addr_value;
                        if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                        {
                            if( $this->isIPAddress($object) )
                            {
                                $prefix = "H_";
                            }
                            else if( $this->isNetworkAddress($object) )
                            {
                                $prefix = "N_";
                            }
                            $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                        }
                        $object = str_replace("$", "", $object);
                        $tmp_address = $this->sub->addressStore->find($object);
                        if( $tmp_address === null )
                        {
                            #this should not happen
                            print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                            if( $this->isIPAddress($to_addr_value) || $this->isNetworkAddress($to_addr_value) )
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), $to_addr_value);
                            else
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), "None");
                        }
                        $tmp_nat_rule->destination->addObject($tmp_address);
                        unset($tmp_address);
                    }
                }

                $object = trim(str_replace("$", "", $dnat_addr[0]));
                if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                {
                    if( $this->isIPAddress($object) )
                    {
                        $prefix = "H_";
                    }
                    else if( $this->isNetworkAddress($object) )
                    {
                        $prefix = "N_";
                    }
                    $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                }
                $tmp_address = $this->sub->addressStore->find($object);
                if( $tmp_address === null )
                {
                    #this should not happen
                    print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                    if( $this->isIPAddress($dnat_addr[0]) || $this->isNetworkAddress($dnat_addr[0]) )
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($dnat_addr[0]), $dnat_addr[0]);
                    else
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($dnat_addr[0]), "None");
                }
                $tmp_nat_rule->setDNAT($tmp_address);
                unset($tmp_address);
                $object = trim(str_replace('$', '', $to_zone[0]));
                $tmp_zone = $this->template_vsys->zoneStore->find($object);
                if( $tmp_zone == null )
                {
                    $tmp_name = $this->truncate_names($this->normalizeNames($object));
                    $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                }
                $tmp_nat_rule->to->addZone($tmp_zone);
                $tmp_nat_rule->from->addZone($tmp_zone);
                $tmp_nat_rule->setDescription($last_comment . "\n" . $last_section_comment . "\n" . $value);
                #$tmp_nat_rule->changeSourceNAT('dynamic-ip-and-port');
            }
            if( preg_match("/(?<=binat on\s)(.*)/", $value) )
            {
                #zone
                preg_match("/(?<=binat on\s)(.*)(?=\s+from)/", $value, $to_zone);
                #to addr
                preg_match("/(?<=to\s)(.*)(?=\s+->)/", $value, $to_addr);
                #dnat to
                preg_match("/(?<=->\s)(.*)/", $value, $binat_addr);

                $ruleName = trim($this->normalizeNames($last_comment . "-" . $last_section_comment));
                if( $ruleName == "" )
                    $ruleName = trim($this->normalizeNames($last_comment));
                $tmp_nat_rule = $this->sub->natRules->find($ruleName);
                if( $tmp_nat_rule == null )
                {
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName);
                }
                else
                {
                    $tmp_nat_rule = $this->sub->natRules->newNatRule($ruleName . '_' . rand(10, 1000));
                    #print("\n".$ruleName."\n");
                }

                foreach( explode(',', $to_addr[0]) as $key => $to_addr_value )
                {
                    $from_addr_value = trim($to_addr_value);
                    if( $from_addr_value !== "" )
                    {
                        $object = $to_addr_value;
                        if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                        {
                            if( $this->isIPAddress($object) )
                            {
                                $prefix = "H_";
                            }
                            else if( $this->isNetworkAddress($object) )
                            {
                                $prefix = "N_";
                            }
                            $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                        }

                        $tmp_address = $this->sub->addressStore->find($object);
                        if( $tmp_address === null )
                        {
                            #this should not happen
                            print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                            if( $this->isIPAddress($to_addr_value) || $this->isNetworkAddress($to_addr_value) )
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), $to_addr_value);
                            else
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), "None");
                        }
                        $tmp_nat_rule->source->addObject($tmp_address);
                        unset($tmp_address);
                    }
                }

                foreach( explode(',', $to_addr[0]) as $key => $to_addr_value )
                {
                    $to_addr_value = trim($to_addr_value);
                    if( $to_addr_value !== "" )
                    {
                        $object = $to_addr_value;
                        if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                        {
                            if( $this->isIPAddress($object) )
                            {
                                $prefix = "H_";
                            }
                            else if( $this->isNetworkAddress($object) )
                            {
                                $prefix = "N_";
                            }
                            $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                        }

                        $tmp_address = $this->sub->addressStore->find($object);
                        if( $tmp_address === null )
                        {
                            #this should not happen
                            print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                            if( $this->isIPAddress($to_addr_value) || $this->isNetworkAddress($to_addr_value) )
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), $to_addr_value);
                            else
                                $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($to_addr_value), "None");
                        }
                        $tmp_nat_rule->destination->addObject($tmp_address);
                        unset($tmp_address);
                    }
                }

                $object = trim($binat_addr[0]);
                if( $this->isIPAddress($object) || $this->isNetworkAddress($object) )
                {
                    if( $this->isIPAddress($object) )
                    {
                        $prefix = "H_";
                    }
                    else if( $this->isNetworkAddress($object) )
                    {
                        $prefix = "N_";
                    }
                    $object = $prefix . str_replace(".", "_", str_replace("/", "_", $object));
                }
                $tmp_address = $this->sub->addressStore->find($object);
                if( $tmp_address === null )
                {
                    #this should not happen
                    print "WARNING CREATING FROM RULE     * create address object: " . $object . "\n";
                    if( $this->isIPAddress($binat_addr[0]) || $this->isNetworkAddress($binat_addr[0]) )
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($binat_addr[0]), $binat_addr[0]);
                    else
                        $tmp_address = $this->sub->addressStore->newAddress($object, $this->returnHostType($binat_addr[0]), "None");
                }
                $tmp_nat_rule->snathosts->addObject($tmp_address);
                unset($tmp_address);
                $object = trim(str_replace('$', '', $to_zone[0]));
                $tmp_zone = $this->template_vsys->zoneStore->find($object);
                if( $tmp_zone == null )
                {
                    $tmp_name = $this->truncate_names($this->normalizeNames($object));
                    $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                }
                $tmp_nat_rule->to->addZone($tmp_zone);
                $tmp_nat_rule->from->addZone($tmp_zone);
                $tmp_nat_rule->setDescription($last_comment . "\n" . $last_section_comment . "\n" . $value);
                $tmp_nat_rule->changeSourceNAT('static-ip', null, TRUE);
                $tmp_nat_rule->setBiDirectional(TRUE);
            }
        }
    }

    function get_static_routes($data)
    {
        $static_routes_assoc = [];
        foreach( $data as $key => $value )
        {
            if( preg_match("/#{1,3}\s/", $value) )
                $last_comment = $value;
            if( preg_match("/(?<=route_)(.*)(?==)/", $value, $match) )
            {
                preg_match("/(?:-net\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d{1,2}\s\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/", $value, $match2);
                $static_routes_assoc[$match[1]] = $match2[1];
            }
            if( preg_match("/(?<=route add\s)(.*)/", $value, $match) )
            {
                $value = str_replace("default", "0.0.0.0/0", $value);
                preg_match("/(?<=route add\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d{1,2}\s\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/", $value, $match2);
                $static_routes_assoc[preg_replace("/#|\s/", "", $last_comment) . "_" . preg_replace("/\/|\.|\s/", "_", $match2[1])] = $match2[1];
            }
        }
        #print_r($static_routes_assoc);
        $vsys = $this->template_vsys->name();
        #Check if THE VR is already created for this VSYS
        $vr = "vr_" . $vsys;

        $source = "";
        $template = "";
        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr === null )
        {
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);
        }
        foreach( $static_routes_assoc as $key => $value )
        {
            $route = explode(" ", $value);
            $xmlString = "<entry name=\"" . $key . "\"><nexthop><ip-address>" . $route[1] . "</ip-address></nexthop><metric>10</metric><destination>" . $route[0] . "</destination></entry>";
            $newRoute = new StaticRoute('***tmp**', $tmp_vr);
            $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

            $tmp_vr->addstaticRoute($tmpRoute);
        }
        #print print_r($static_routes_assoc,true);
    }

    function get_services_group($data)
    {
        global $print;

        $services_map = $this->map_services_to_port("");
        $last_comment = "";
        $services_assoc = [];
        foreach( $data as $key => $value )
        {
            if( preg_match("/#{1,3}\s/", $value) )
                $last_comment = $value;
            if( preg_match("/.*=.*\"{.*}\"/", $value) )
            {
                $tmp_arr = explode('=', $value, 2);
                $services_assoc[trim($tmp_arr[0])][0] = str_replace(":", "-", str_replace(" ", "", str_replace(array_keys($services_map), $services_map, preg_replace('/("{)|(}")|(\s)d/', "", $tmp_arr[1]))));
                $services_assoc[trim($tmp_arr[0])][1] = $last_comment;
            }
        }
        #echo PH::boldText("\n" . print_r($services_assoc,true) . "\n");

        foreach( $services_assoc as $key => $value )
        {
            $tmp_servicegroup = $this->sub->serviceStore->find($key);
            if( $tmp_servicegroup == null )
            {
                $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup($key);
            }
            else
            {
                if( $print )
                    print "Found an already existing servicegroup " . $key;
            }
            foreach( explode(",", $value[0]) as $key2 => $value2 )
            {
                if( preg_match("/[uU][dD][pP]/", $key) )
                {
                    $proto = "udp";
                }
                else
                {
                    $proto = "tcp";
                }
                $service_name = $value2;
                if( strpos($service_name, ">") !== FALSE )
                {
                    $service_name = preg_replace("/>=|>/", "", $service_name);
                    $service_name = $service_name . "-65535";
                }
                else if( strpos($service_name, "<") !== FALSE )
                {
                    $service_name = preg_replace("/<=|</", "", $service_name);
                    $service_name = "0-" . $service_name;
                }
                $tmp_service = $this->sub->serviceStore->find("service-" . preg_replace("/>=|>/", "gt-", preg_replace("/<=|</", "lt-", $value2)) . "-" . $proto);
                if( $tmp_service == null )
                {

                    $tmp_service = $this->sub->serviceStore->newService("service-" . preg_replace("/>=|>/", "gt-", preg_replace("/<=|</", "lt-", $value2)) . "-" . $proto, $proto, $service_name, $value[1]);
                }
                $tmp_servicegroup->addMember($tmp_service);
            }
            unset($tmp_servicegroup);
            unset($tmp_service);
        }
    }

    /**
     * @param array $data
     * @param PANConf $pan
     */


    function import_config($data)
    {
        // We create/import a base-config first.

        // Use this vsys in the base config that was imported:
        $vsysName = "Example";
        $vsysID = 1;

        $this->template_vsys = $this->template->findVSYS_by_displayName($vsysName);
        if( $this->template_vsys === null )
        {
            $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            $this->template_vsys->setAlternativeName($vsysName);
        }
        else
        {
            //create new vsys, search for latest ID
            do
            {
                $vsysID++;
                $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            } while( $this->template_vsys !== null );

            if( $this->template_vsys === null )
            {
                $this->template_vsys = $this->template->createVirtualSystem(intval($vsysID), $vsysName . $vsysID);
                if( $this->template_vsys === null )
                {
                    derr("vsys" . $vsysID . " could not be created ? Exit\n");
                }
            }
        }

        echo PH::boldText("\n INTERFACES \n");
        $this->get_interfaces($data);

        echo PH::boldText("\n SERVICES \n");
        $this->get_services_group($data);


        echo PH::boldText("\n HOSTS \n");
        $this->get_hosts($data);

        echo PH::boldText("\n GROUPS \n");
        $this->get_hostgroups($data);

        echo PH::boldText("\n NTP \n");
        $this->get_ntps($data);

        echo PH::boldText("\n SECURITY POLICIES \n");
        $this->get_acl($data);

        echo PH::boldText("\n NAT RULES \n");
        $this->get_nat($data);

        print "NAT counter: " . $this->sub->natRules->count() . "\n";

        echo PH::boldText("\n STATIC ROUTES \n");
        $this->get_static_routes($data);

        $userObj = array();

        $this->pan->display_statistics();



        #clean_zone_any($source, $vsys);
        #CONVERTER::validate_interface_names($pan);
    }
}