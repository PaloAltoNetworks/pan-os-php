<?php

trait trait_address
{
    /*
 * This method is parsing the following objects:
 * 		address_range
 * 		host (it may include groups)
 * 		network
 */
    function get_Address_Stonesoft(SimpleXMLElement $configuration, STRING $vsys, STRING $source, $template)
    {
        global $projectdb;

        $ip_networks = array();
        $ip_address_ranges = array();
        $addresses = array();
        $address_groups = array();
        $addresses_groups_id = array();
        $tags = array();
        $addTag = array();
        $expectedTags = array('mgt_server', 'dns_server', 'dhcp_server', 'router', 'fw');

        $tagRelations = array();

        $query = "SELECT max(id) as lastID FROM tag";
        $result = $projectdb->query($query);
        if( $result->num_rows == 1 )
        {
            $data = $result->fetch_assoc();
            $lastTagID = $data['lastID'] + 1;
        }
        else
        {
            $lastTagID = 1;
        }

        $query = "SELECT max(id) as lastID FROM address";
        $result = $projectdb->query($query);
        if( $result->num_rows == 1 )
        {
            $data = $result->fetch_assoc();
            $lastAddressID = $data['lastID'] + 1;
        }
        else
        {
            $lastAddressID = 1;
        }

        $query = "SELECT max(id) as lastID FROM address_groups_id";
        $result = $projectdb->query($query);
        if( $result->num_rows == 1 )
        {
            $data = $result->fetch_assoc();
            $lastAddressGroupsID = $data['lastID'] + 1;
        }
        else
        {
            $lastAddressGroupsID = 1;
        }

        $query = "SELECT id, name FROM tag WHERE NAME in ('" . implode("','", $expectedTags) . "') AND vsys='$vsys' AND source='$source'";
        $result = $projectdb->query($query);
        while( $data = $result->fetch_assoc() )
        {
            $tagId = $data['id'];
            $tagName = $data['name'];
            $tags[$tagName] = $tagId;
        }

        foreach( $expectedTags as $expectedTag )
        {
            if( !array_key_exists($expectedTag, $tags) )
            {
                $addTag[] = "('$expectedTag', '$expectedTag', 'color6','$expectedTag from Stonesoft','$source', '$vsys','','0','','','','','','1')";
                $tags[$expectedTag] = $lastTagID;
                $lastTagID++;
            }
        }

        $mgt_servers = $configuration->xpath("//mgt_server");
        $mgt_serverTag = $tags['mgt_server'];
        foreach( $mgt_servers as $mgt_server )
        {
            $name_ext = trim(normalizeNames($mgt_server['name']));
            $name_int = truncate_names(normalizeNames($name_ext));
            $description = "";
            $ip_address = $mgt_server->multi_contact_mvia["address"];

            $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$ip_address', '32', 1, 0, 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $tagRelations[] = "('address', $lastAddressID, $mgt_serverTag)";
            $lastAddressID++;
        }

        /*
         * We look for defined ranges
         */
        $address_ranges = $configuration->xpath("//address_range");
        foreach( $address_ranges as $address_range )
        {
            $name_ext = trim(normalizeNames($address_range["name"]));
            $name_int = truncate_names(normalizeNames($name_ext));
            $value = $address_range["ip_range"];
            $description = normalizeNames($address_range["comment"]);
            $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$value', '', 1, 0,'ip-range', 'ip-range', '$source', '$vsys')";
            $lastAddressID++;
        }


        /*
         * We look for networks
         */
        $networks = $configuration->xpath("//network");
        foreach( $networks as $network )
        {
            $name_ext = trim(normalizeNames($network["name"]));
            $name_int = truncate_names(normalizeNames($name_ext));
            if( isset($network["ipv4_network"]) )
            {
                $value = $network["ipv4_network"];
                $isipv4 = 1;
                $isipv6 = 0;
            }
            else
            {
                if( isset($network["ipv6_network"]) )
                {
                    $value = $network["ipv6_network"];
                    $isipv6 = 1;
                    $isipv4 = 0;
                }
                else
                {
                    $value = '';
                    $isipv4 = 1;
                    $isipv6 = 0;
                }
            }
            $description = normalizeNames($network["comment"]);
            $broadcast_included = $network["broadcast"];

            list($network_address, $cidr) = explode("/", $value);

            if( $broadcast_included == "true" )
            {
                $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$network_address', '$cidr', '$isipv4', '$isipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $lastAddressID++;
            }
            else
            {
                //We should remove the broadcast in this range/group of IPs
                $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$network_address', '$cidr', '$isipv4', '$isipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $lastAddressID++;
            }
        }


        /*
         * Host could be single IP-ed or multiple IP-ed
         */
        $hosts = $configuration->xpath("//host");
        foreach( $hosts as $host )
        {
            $name_ext = trim(normalizeNames($host["name"]));
            $description = normalizeNames($host["comment"]);
            //Get the main IP
            $address_array = array($host->mvia_address["address"]);
            //If it has multiple IPs, these should be defined and grouped
            foreach( $host->secondary as $secondary_ip )
            {
                if( $secondary_ip["value"] != "0.0.0.0" )
                {
                    array_push($address_array, $secondary_ip["value"]);
                }
            }

            //We have a group of IPs, so we should create the group and add the IPs later
            if( count($address_array) > 1 )
            {
                $name_int = truncate_names(normalizeNames($name_ext));
//            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
                $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
                $lid = $lastAddressGroupsID;
                $lastAddressGroupsID++;

                foreach( $address_array as $ip_address )
                {
                    $name_int = truncate_names(normalizeNames($ip_address));

                    $ipversion = ip_version($ip_address);
                    if( $ipversion == "v4" )
                    {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    }
                    elseif( $ipversion == "v6" )
                    {
                        $ipv6 = 1;
                        $ipv4 = 0;
                        $netmask = "128";
                    }
                    else
                    {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    }

                    $addresses[] = "($lastAddressID, '$ip_address','$name_int', '','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                    $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys', $lastAddressID, 'address')";
                    $lastAddressID++;
                }
            }
            else
            {  //It is one single host.
                $array_values = array_values($address_array);
                $ip_address = $array_values[0];

                $ipversion = ip_version($ip_address);
                if( $ipversion == "v4" )
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }
                elseif( $ipversion == "v6" )
                {
                    $ipv6 = 1;
                    $ipv4 = 0;
                    $netmask = "128";
                }
                else
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }

                $name_int = truncate_names(normalizeNames($name_ext));
                $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $lastAddressID++;
            }
        }

        /*
         * DNS-Servers could be single IP-ed or multiple IP-ed
         */
        $dnsServers = $configuration->xpath("//dns_server");
        $dns_serverTag = $tags['dns_server'];
        foreach( $dnsServers as $dnsServer )
        {
            $name_ext = trim(normalizeNames($dnsServer["name"]));
            $description = normalizeNames($dnsServer["comment"]);
            //Get the main IP
            $address_array = array($dnsServer->mvia_address["address"]);
            //If it has multiple IPs, these should be defined and grouped
            foreach( $dnsServer->secondary as $secondary_ip )
            {
                if( $secondary_ip["value"] != "0.0.0.0" )
                {
                    array_push($address_array, $secondary_ip["value"]);
                }
            }

            //We have a group of IPs, so we should create the group and add the IPs later
            if( count($address_array) > 1 )
            {
                $name_int = truncate_names(normalizeNames($name_ext));
//            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
                $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
                $lid = $lastAddressGroupsID;
                $lastAddressGroupsID++;
                $tagRelations[] = "('address_groups_id', $lid, $dns_serverTag)";

                foreach( $address_array as $ip_address )
                {
                    $name_int = truncate_names(normalizeNames($ip_address));

                    $ipversion = ip_version($ip_address);
                    if( $ipversion == "v4" )
                    {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    }
                    elseif( $ipversion == "v6" )
                    {
                        $ipv6 = 1;
                        $ipv4 = 0;
                        $netmask = "128";
                    }
                    else
                    {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    }

                    $addresses[] = "($lastAddressID, '$ip_address','$name_int', '','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                    $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys', $lastAddressID, 'address')";
                    $tagRelations[] = "('address', $lastAddressID, $dns_serverTag)";
                    $lastAddressID++;
                }
            }
            else
            {  //It is one single host.
                $array_values = array_values($address_array);
                $ip_address = $array_values[0];

                $ipversion = ip_version($ip_address);
                if( $ipversion == "v4" )
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }
                elseif( $ipversion == "v6" )
                {
                    $ipv6 = 1;
                    $ipv4 = 0;
                    $netmask = "128";
                }
                else
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }

                $name_int = truncate_names(normalizeNames($name_ext));
                $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $tagRelations[] = "('address', $lastAddressID, $dns_serverTag)";
                $lastAddressID++;
            }
        }

        /*
         * DHCP-Servers could be single IP-ed or multiple IP-ed
         */
        $dhcpServers = $configuration->xpath("//dhcp_server");
        $dhcp_serverTag = $tags['dhcp_server'];
        foreach( $dhcpServers as $dhcpServer )
        {
            $name_ext = trim(normalizeNames($dhcpServer["name"]));
            $description = normalizeNames($dhcpServer["comment"]);
            //Get the main IP
            $address_array = array($dhcpServer->mvia_address["address"]);
            //If it has multiple IPs, these should be defined and grouped
            foreach( $dhcpServer->secondary as $secondary_ip )
            {
                if( $secondary_ip["value"] != "0.0.0.0" )
                {
                    array_push($address_array, $secondary_ip["value"]);
                }
            }

            //We have a group of IPs, so we should create the group and add the IPs later
            if( count($address_array) > 1 )
            {
                $name_int = truncate_names(normalizeNames($name_ext));
//            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
//            $lid = $projectdb->insert_id;
                $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
                $lid = $lastAddressGroupsID;
                $lastAddressGroupsID++;
                $tagRelations[] = "('address_groups_id',$lid,$dhcp_serverTag)";

                foreach( $address_array as $ip_address )
                {
                    $name_int = truncate_names(normalizeNames($ip_address));

                    $ipversion = ip_version($ip_address);
                    if( $ipversion == "v4" )
                    {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    }
                    elseif( $ipversion == "v6" )
                    {
                        $ipv6 = 1;
                        $ipv4 = 0;
                        $netmask = "128";
                    }
                    else
                    {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    }
                    $addresses[] = "($lastAddressID, '$ip_address','$name_int', '','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                    $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys',$lastAddressID, 'address')";
                    $tagRelations[] = "('address',$lastAddressID,$dhcp_serverTag)";
                    $lastAddressID++;
                }
            }
            else
            {  //It is one single host.
                $array_values = array_values($address_array);
                $ip_address = $array_values[0];

                $ipversion = ip_version($ip_address);
                if( $ipversion == "v4" )
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }
                elseif( $ipversion == "v6" )
                {
                    $ipv6 = 1;
                    $ipv4 = 0;
                    $netmask = "128";
                }
                else
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }

                $name_int = truncate_names(normalizeNames($name_ext));
                $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $tagRelations[] = "('address', $lastAddressID, $dhcp_serverTag)";
                $lastAddressID++;
            }
        }

        /*
         * Loading domain_names
         */
        $domain_names = $configuration->xpath("//domain_name");
        foreach( $domain_names as $domain_name )
        {
            $name_ext = trim($domain_name["name"]);
            $name_int = truncate_names(normalizeNames($name_ext));
            $description = normalizeNames($domain_name["comment"]);
            //Get the main IP
            //$ip_address = gethostbyname($name);
            $ip_address = $name_ext;
            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '', 1, 0, 'fqdn', '', '$source', '$vsys')";
            $lastAddressID++;
        }

        /*
         * Loading routers
         */
        $routers = $configuration->xpath("//router");
        $routerTag = $tags['router'];
        foreach( $routers as $router )
        {
            $name_ext = trim(normalizeNames($router["name"]));
            $name_int = truncate_names(normalizeNames($name_ext));
            $description = normalizeNames($router["comment"]);
            //Get the main IP
            $ip_address = $router->mvia_address["address"];

            $ipversion = ip_version($ip_address);
            if( $ipversion == "v4" )
            {
                $ipv4 = 1;
                $ipv6 = 0;
                $netmask = "32";
            }
            elseif( $ipversion == "v6" )
            {
                $ipv6 = 1;
                $ipv4 = 0;
                $netmask = "128";
            }
            else
            {
                $ipv4 = 1;
                $ipv6 = 0;
                $netmask = "32";
            }

            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $tagRelations[] = "('address',$lastAddressID,$routerTag)";
            $lastAddressID++;
        }

        /*
         * Loading FW_CLUSTERs
         */
        $fw_clusters = $configuration->xpath("//fw_cluster");
        $fwTag = $tags['fw'];
        foreach( $fw_clusters as $fw_cluster )
        {
            $name_ext = trim(normalizeNames($fw_cluster["name"]));
            $name_int = truncate_names(normalizeNames($name_ext));
            $description = "";

            //Creating a group that represents the FW_cluster
//        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
//        $lid = $projectdb->insert_id;
            $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
            $lid = $lastAddressGroupsID;
            $lastAddressGroupsID++;
            $tagRelations[] = "('address_groups_id',$lid,$fwTag)";

            $address_array = array();


            //Adding the IPs of the cluster virtual interfaces
            foreach( $fw_cluster->cluster_virtual_interface as $cluster_virtual_interface )
            {
                $fw_interface = new FwInterface($cluster_virtual_interface["name"], $cluster_virtual_interface->mvia_address["address"]);
                array_push($address_array, $fw_interface);
            }

            //Adding the IPs of the firewall node interfaces
            foreach( $fw_cluster->firewall_node as $firewall_node )
            {
                foreach( $firewall_node->node_interface as $node_interface )
                {
                    $fw_interface = new FwInterface($node_interface["name"], $node_interface->mvia_address["address"]);
                    array_push($address_array, $fw_interface);
                }
            }

            //Insert the different interfaces of the fw_cluster
            foreach( $address_array as $interface )
            {
                $name_ext = trim($interface->name);
                $name_int = truncate_names(normalizeNames($name_ext));
                $ip_address = $interface->address;

                $ipversion = ip_version($ip_address);
                if( $ipversion == "v4" )
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }
                elseif( $ipversion == "v6" )
                {
                    $ipv6 = 1;
                    $ipv4 = 0;
                    $netmask = "128";
                }
                else
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }

                // (name_ext,name,description, ipaddress,cidr,v4,v6,type,vtype,source,vsys)
                $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $tagRelations[] = "('address',$lastAddressID,$fwTag)";

                //(lid, name_ext,name,member,source,vsys)
                $address_groups[] = "('$lid','$name_ext','$name_int','$name_ext','$source', '$vsys', $lastAddressID, 'address')";
                $lastAddressID++;
            }
        }

        /*
         * Loading FW_SINGLE
         */
        $fw_singles = $configuration->xpath("//fw_single");
        $fwTag = $tags['fw'];
        foreach( $fw_singles as $fw_single )
        {
            $name_ext = trim(normalizeNames($fw_single["name"]));
            $name_int = truncate_names(normalizeNames($name_ext));
            $description = "";

//        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
//        $lid = $projectdb->insert_id;
            $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
            $lid = $lastAddressGroupsID;
            $lastAddressGroupsID++;
            $tagRelations[] = "('address_groups_id',$lid,$fwTag)";

            $address_array = array();

            foreach( $fw_single->fw_single_interface as $fw_single_interface )
            {
                $fw_interface = new FwInterface($fw_single_interface["name"], $fw_single_interface->mvia_address["address"]);
                array_push($address_array, $fw_interface);
            }

            //Insert the different interfaces of the fw_single
            foreach( $address_array as $interface )
            {
                $name_ext = trim(normalizeNames($interface->name));
                $name_int = truncate_names(normalizeNames($name_ext));
                $ip_address = $interface->address;
                $ipversion = ip_version($ip_address);
                if( $ipversion == "v4" )
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }
                elseif( $ipversion == "v6" )
                {
                    $ipv6 = 1;
                    $ipv4 = 0;
                    $netmask = "128";
                }
                else
                {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }
                // (name_ext,name,description, ipaddress,cidr,v4,v6,type,vtype,source,vsys)
                $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $tagRelations[] = "('address',$lastAddressID,$fwTag)";

                //(lid, name_ext,name,member,source,vsys)
                $address_groups[] = "('$lid','$name_ext','$name_int','$name_ext','$source', '$vsys',$lastAddressID, 'address')";
                $lastAddressID++;
            }

        }

        //Insert all the Groups
        if( count($addTag) > 0 )
        {
            $uniq = array_unique($addTag);
            $out = implode(",", $uniq);
            $query = "INSERT INTO tag (name, name_ext, color, comments, source, vsys, devicegroup, modified, vtype, dummy, checkit, disable_override, merge_as_primary, used) VALUES " . $out . ";";
        }

        //Done in the upper section, one by one
        if( count($addresses_groups_id) > 0 )
        {
            $uniq = array_unique($addresses_groups_id);
            $out = implode(",", $uniq);
            $projectdb->query("INSERT INTO address_groups_id (id, name_ext,name,description, source,vsys) VALUES " . $out . ";");
        }

        //Insert all the Members
        if( count($addresses) > 0 )
        {
            $uniq = array_unique($addresses);
            $out = implode(",", $uniq);
            $query = "INSERT INTO address (id, name_ext,name,description, ipaddress,cidr,v4,v6,type,vtype,source,vsys) VALUES " . $out . ";";
            $projectdb->query($query);
        }

        //Insert all the relations
        if( count($address_groups) > 0 )
        {
            $uniq = array_unique($address_groups);
            $out = implode(",", $uniq);
            $projectdb->query("INSERT INTO address_groups (lid, name_ext,name,member,source,vsys, member_lid, table_name) " .
                "VALUES " . $out . ";");
        }

        if( count($tagRelations) > 0 )
        {
            $uniq = array_unique($tagRelations);
            $out = implode(",", $uniq);
            $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES " . $out . ";";
            $projectdb->query($query);
        }
    }
}