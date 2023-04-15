<?php



trait STONESOFTaddress
{
#function get_XML_Zones_Address_All_new($configuration, $vsys, $source, $template, &$objectsInMemory) {
    /**
     * @param DomElement $configRoot
     * @param VirtualSystem $v
     * @return null
     */
    function get_XML_Zones_Address_All_new2($configRoot)
    {
        global $debug;
        global $print;
        //$configRoot /configuration/security/address-book


        $expectedTags = array('mgt_server', 'dns_server', 'dhcp_server', 'router', 'fw');


        $mgt_servers = $configRoot->getElementsByTagName('mgt_server');
        print "count(mgt_server): ".count( $mgt_servers  )."\n";
        foreach ($mgt_servers as $mgt_server)
        {
            if( $mgt_server->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = DH::findAttribute('name', $mgt_server);
            #print "NAME: ".$name."\n";

            foreach( $mgt_server->childNodes as $node )
            {
                /** @var DOMElement $node */

                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                if( $node->nodeName == "multi_contact_mvia" )
                {
                    $value = DH::findAttribute('address', $node);
                    $name = $this->truncate_names( $this->normalizeNames( $name ) );

                    $tmpaddress = $this->sub->addressStore->find($name);
                    if( $tmpaddress == null )
                    {
                        print "\n - create address object: " . $name . " Value: ".$value."\n";
                        $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $value );
                    }
                }
            }
        }



        /*
         * We look for defined ranges
         * $address_ranges = $configuration->xpath("//address_range");
         */


        $address_ranges = $configRoot->getElementsByTagName('address_range');
        print "count(address_range): ".count( $address_ranges  )."\n";
        foreach ($address_ranges as $address_range)
        {
            if( $address_range->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $address_range->getAttribute( 'name' );
            $comment = $address_range->getAttribute( 'comment' );
            $ip_range = $address_range->getAttribute( 'ip_range' );


            $name = $this->truncate_names( $this->normalizeNames( $name ) );

            $tmpaddress = $this->sub->addressStore->find($name);
            if( $tmpaddress == null )
            {
                print "\n - create address object: " . $name . " Value: ".$ip_range."\n";
                $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-range", $ip_range );
                $tmpaddress->setDescription( $comment );
            }
        }



        /*
         * We look for networks
        $networks = $configuration->xpath("//network");
         */
        $networks = $configRoot->getElementsByTagName('network');
        print "count(networks): ".count( $networks  )."\n";
        foreach ($networks as $network)
        {
            if( $network->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = DH::findAttribute('name', $network);
            $broadcast = DH::findAttribute('broadcast', $network);
            $comment = DH::findAttribute('comment', $network);
            $ipv4_network = DH::findAttribute('ipv4_network', $network);
            $ipv6_network = DH::findAttribute('ipv6_network', $network);

            if( $ipv4_network != null )
            {
                $value = $ipv4_network;
            }
            elseif( $ipv6_network != null )
            {
                $value = $ipv6_network;
            }

            //Todo: how to handle $broadcast??? swaschkut 20201003

            $name = $this->truncate_names( $this->normalizeNames( $name ) );

            $tmpaddress = $this->sub->addressStore->find($name);
            if( $tmpaddress == null )
            {
                print "\n - create address object: " . $name . " Value: ".$value."\n";
                $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $value );
                $tmpaddress->setDescription( $comment );
            }

        }


        /*
         * Host could be single IP-ed or multiple IP-ed
        $hosts = $configuration->xpath("//host");
         */
        $hosts = $configRoot->getElementsByTagName('host');
        print "count(host): ".count( $hosts  )."\n";
        foreach ($hosts as $host)
        {
            $this->createBasedOnDomElement( $host );
        }



        /*
         * DNS-Servers could be single IP-ed or multiple IP-ed
        dns_server = $configuration->xpath("//dns_server");
         */
        $dns_servers = $configRoot->getElementsByTagName('dns_server');
        print "count(dns_servers): ".count( $dns_servers  )."\n";
        foreach ($dns_servers as $dns_server)
        {
            $this->createBasedOnDomElement( $dns_server );
        }



        /*
    `     * DHCP-Servers could be single IP-ed or multiple IP-ed
        $dhcpServers = $configuration->xpath("//dhcp_server");
        $dhcp_serverTag = $tags['dhcp_server'];
         */

        $dhcp_servers = $configRoot->getElementsByTagName('dhcp_server');
        print "count(dhcp_servers): ".count( $dhcp_servers  )."\n";
        foreach ($dhcp_servers as $dhcp_server)
        {
            $this->createBasedOnDomElement( $dhcp_server );
        }


        /*
         * Loading domain_names
        $domain_names = $configuration->xpath("//domain_name");
         */
        $domain_names = $configRoot->getElementsByTagName('domain_name');
        print "count(domain_names): ".count( $domain_names  )."\n";
        foreach ($domain_names as $domain_name)
        {
            if( $domain_name->nodeType != XML_ELEMENT_NODE )
                continue;

            //<domain_name comment="FFE20141014" db_key="3317" name="yammer.com"></domain_name>

            $name = $host->getAttribute( 'name' );
            $comment = $host->getAttribute( 'comment' );
            $comment = $this->normalizeNames($comment);

            $name = $this->truncate_names( $this->normalizeNames( $name ) );

            $tmpaddress = $this->sub->addressStore->find($name);
            if( $tmpaddress == null )
            {
                print "\n - create address object: " . $name . "\n";
                $tmpaddress = $this->sub->addressStore->newAddress($name, "fqdn", $name);
                $tmpaddress->setDescription( $comment );

            }
        }


        /*
         * Loading routers
        $routers = $configuration->xpath("//router");
         */
        $routers = $configRoot->getElementsByTagName('router');
        print "count(routers): ".count( $routers  )."\n";
        foreach ($routers as $router)
        {
            if( $router->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $router->getAttribute( 'name' );

            foreach( $router->childNodes as $childNode )
            {
                if( $childNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                if( $childNode->nodeName == "mvia_address" )
                {
                    $address = $childNode->getAttribute( 'address' );
                    #print "ADDRESS: ".$address."\n";

                    $name = $this->truncate_names( $this->normalizeNames( $name ) );

                    $tmpaddress = $this->sub->addressStore->find($name);
                    if( $tmpaddress == null )
                    {
                        print "\n - create address object: " . $name . "\n";
                        $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $address);
                    }
                }
            }
        }

        #derr( 'STOP' );

        /*
         * Loading FW_CLUSTERs
        $fw_clusters = $configuration->xpath("//fw_cluster");
        $fwTag = $tags['fw'];
         */
        $fw_clusters = $configRoot->getElementsByTagName('fw_cluster');
        print "count(fw_clusters): ".count( $fw_clusters  )."\n";

        $tmpaddressgroup = null;
        $addr_array = array();

        foreach ($fw_clusters as $fw_cluster)
        {
            #echo $host->nodeValue, PHP_EOL;
            if( $fw_cluster->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $fw_cluster->getAttribute( 'name' );
            //Create addressgroup; and add all address to this group
            $name = $this->truncate_names( $this->normalizeNames( $name ) );
            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
            }


            //Todo: do I need to create Interface for each of the object found here????

            //cluster_virtual_interface
                //mvia_address
            $cluster_virtual_interfaces = $fw_cluster->getElementsByTagName('cluster_virtual_interface');
            foreach( $cluster_virtual_interfaces as $cluster_virtual_interface )
            {
                if( $cluster_virtual_interface->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = $cluster_virtual_interface->getAttribute( 'name' );
                #print "NAME: ".$name."\n";

                foreach( $cluster_virtual_interface->childNodes as $childNode )
                {
                    if( $childNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    if( $childNode->nodeName == "mvia_address" )
                    {
                        $address = $childNode->getAttribute( 'address' );
                        #print "ADDRESS: ".$address."\n";

                        $addr_array[] = array( $name, $address );
                    }
                }
            }



            //firewall_node
                //node_interface
                    //mvia_address

            $firewall_nodes = $fw_cluster->getElementsByTagName('firewall_node');
            foreach( $firewall_nodes as $firewall_node )
            {
                if( $firewall_node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $node_interfaces = $firewall_node->getElementsByTagName('node_interface');
                foreach( $node_interfaces as $node_interface )
                {
                    if( $node_interface->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $name = $node_interface->getAttribute( 'name' );
                    #print "NAME: ".$name."\n";

                    foreach( $node_interface->childNodes as $childNode )
                    {
                        if( $childNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        if( $childNode->nodeName == "mvia_address" )
                        {
                            $address = $childNode->getAttribute( 'address' );
                            #print "ADDRESS: ".$address."\n";

                            $addr_array[] = array( $name, $address );
                        }
                    }
                }
            }

            #print "ADDRGROUP: ".$tmpaddressgroup->name();
            #print_r( $addr_array );

            foreach( $addr_array as $addr )
            {
                $name = $addr[0];
                $address = $addr[1];

                $tmp_array = array();

                $this->calculateIpValue( $address, $tmp_array);
                $value = $tmp_array[0];

                $name = $this->truncate_names( $this->normalizeNames( $name ) );

                $tmpaddress = $this->sub->addressStore->find($name);
                if( $tmpaddress == null )
                {
                    print "\n - create address object: " . $name . "\n";
                    $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $value);

                }
                print "   - add address: ".$tmpaddress->name()."\n";
                $tmpaddressgroup->addMember( $tmpaddress );
            }
        }


        /*
        * Loading FW_SINGLE
         * $fw_singles = $configuration->xpath("//fw_single");
        $fwTag = $tags['fw'];
         */
        $fw_singles = $configRoot->getElementsByTagName('fw_single');
        print "count(fw_singles): ".count( $fw_singles  )."\n";
        foreach ($fw_singles as $fw_single)
        {
            //Todo: find config with fw_singles in
            //swaschkut 20201005

            if( $fw_single->nodeType != XML_ELEMENT_NODE )
                continue;

            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($fw_single, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;
        }

    }

    public function calculateIpValue( $value, &$addr_array)
    {
        $ipversion = $this->ip_version( $value );
        if( $ipversion == "v4" )
            $value = $value."/32";
        elseif( $ipversion == "v6" )
            $value = $value."/128";
        $addr_array[] = $value;
    }

    public function createBasedOnArray( $addr_array, $name, $comment)
    {
        if( count( $addr_array ) == 1 )
        {
            $name = $this->truncate_names( $this->normalizeNames( $name ) );

            $tmpaddress = $this->sub->addressStore->find($name);
            if( $tmpaddress == null )
            {
                print "\n - create address object: " . $name . " Value: ".$addr_array[0]."\n";
                $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $addr_array[0]);
                $tmpaddress->setDescription( $comment );
            }
        }
        else
        {
            $name = $this->truncate_names( $this->normalizeNames( $name ) );

            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup != null and $tmpaddressgroup->isGroup() )
            {
                //add addresses????
            }


            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
                $tmpaddressgroup->setDescription( $comment );
            }

            foreach( $addr_array as $addr )
            {
                $name = $this->truncate_names( $this->normalizeNames( $addr ) );

                $tmpaddress = $this->sub->addressStore->find($name);
                if( $tmpaddress == null )
                {
                    print "\n - create address object: " . $name . "\n";
                    $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $addr);

                }
                print "   - add address: ".$tmpaddress->name()."\n";
                $tmpaddressgroup->addMember( $tmpaddress );
            }
        }
    }

    public function createBasedOnDomElement( $domElement )
    {
        $addr_array = array();

        if( $domElement->nodeType != XML_ELEMENT_NODE )
            return null;

        $name = $domElement->getAttribute( 'name' );
        $comment = $domElement->getAttribute( 'comment' );

        foreach( $domElement->childNodes as $node )
        {
            /** @var DOMElement $node */

            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->nodeName == "mvia_address" )
            {
                $value = $node->getAttribute( 'address' );
                $this->calculateIpValue( $value, $addr_array );
            }
            elseif( $node->nodeName == "secondary" )
            {
                $value = $node->getAttribute( 'value' );
                if( $value != "0.0.0.0" )
                    $this->calculateIpValue( $value, $addr_array );
            }
        }

        #print_r( $addr_array );

        $this->createBasedOnArray( $addr_array, $name, $comment);
    }


    public function addDomainNames( $configRoot )
    {
        $domainNames = $configRoot->getElementsByTagName('domain_name');
        print "count(domain_name): " . count($domainNames) . "\n";


        foreach( $domainNames as $domainName )
        {
            if( $domainName->nodeType != XML_ELEMENT_NODE )
                continue;

            $origname = $domainName->getAttribute('name');
            $name = $this->truncate_names($this->normalizeNames($origname));
            $tmpaddress = $this->sub->addressStore->find($name);
            if( $tmpaddress == null )
            {
                print "\n - create address object: " . $name . " Value: ".$origname."\n";
                $tmpaddress = $this->sub->addressStore->newAddress($name, "fqdn", $origname );
            }
        }
    }




    public function addAddressGroups( $configRoot )
    {


        #$alias = $configuration->xpath("//alias");
        $aliases = $configRoot->getElementsByTagName('alias');
        print "count(alias): ".count( $aliases  )."\n";

        foreach ($aliases as $alias)
        {
            if( $alias->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $alias->getAttribute('name');
            $name = $this->truncate_names($this->normalizeNames($name));

            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
            }
            //Todo: add / create objects
            /*
            <alias comment="Redes destino cuya seguridad gestiona el firewall. scsdg10#20090121" db_key="2055" name="$ Managed Networks" type="other">
    <default_alias_value ne_ref="NONE"/>
  </alias>
*/
            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($alias, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;
        }



        #$server_pools = $configuration->xpath("//server_pool");
        $server_pools = $configRoot->getElementsByTagName('server_pool');
        print "count(server_pool): ".count( $server_pools  )."\n";

        foreach ($server_pools as $server_pool)
        {
            if( $server_pool->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $server_pool->getAttribute('name');
            $name = $this->truncate_names($this->normalizeNames($name));

            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
            }
            //Todo: add / create objects

            /*
               <server_pool comment="VPN-SSL Server Pool" db_key="14193" monitoring_frequency="10" monitoring_mode="ping" monitoring_port="443" name="VPN-SSL Server Pool" server_allocation="host">
                <category_ref ref="C.RFOP.VPN.SSL"></category_ref>
                <members_list member="SRV.DMZ.VPN_SSL_N1"></members_list>
                <members_list member="SRV.DMZ.VPN_SSL_N2"></members_list>
                <without_netlink arp_generate="false" ipaddress="213.144.48.194" weight="1"></without_netlink>
              </server_pool>
            */
            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($server_pool, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;
        }



        #$log_servers = $configuration->xpath("//log_server");
        $log_servers = $configRoot->getElementsByTagName('log_server');
        print "count(log_server): ".count( $log_servers  )."\n";

        foreach ($log_servers as $log_server)
        {
            if( $log_server->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $log_server->getAttribute('name');
            $name = $this->truncate_names($this->normalizeNames($name));

            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
            }
            //Todo: add / create objects
            /*
            <log_server channel_port="3020" comment="Log Server 02. scsgd18#20090306" db_key="2613" inactive="false" log_disk_space_handling_mode="stop_receiving" name="SLS02">
                <multi_contact_mvia address="10.245.6.68"></multi_contact_mvia>
                <secondary_log_server_ref class_id="7" value="SLS01"></secondary_log_server_ref>
                <secondary_log_server_ref class_id="7" value="SLS03"></secondary_log_server_ref>
                <netflow_collector data_context="FW" data_context_key="3" filter_ref="SLS02 PRUEBA ENVIO LOG SRV.SIEM.qradar01.sir.renfe.es.NEW 514 LEEF UDP 23" netflow_collector_host_ref="SRV.SIEM.qradar01.sir.renfe.es.NEW" netflow_collector_port="514" netflow_collector_service="udp" netflow_collector_version="leef"></netflow_collector>
                <netflow_collector data_context="All Log Data" data_context_key="2" netflow_collector_host_ref="Skybox_Server" netflow_collector_port="514" netflow_collector_service="udp" netflow_collector_version="cef"></netflow_collector>
              </log_server>

             */

            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($log_server, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;
        }

        #$expressions = $configuration->xpath("//expression");
        $expressions = $configRoot->getElementsByTagName('expression');
        print "count(expression): ".count( $expressions  )."\n";

        foreach ($expressions as $expression)
        {
            if( $expression->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $expression->getAttribute('name');
            $name = $this->truncate_names($this->normalizeNames($name));

            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
            }
            //Todo: add / create objects
            /*
            NTR.Intranet_Renfe
               <expression comment="Direccionamiento Intranet Renfe excepto accesos remotos SSL e IPsec. scsgd10#20090427" db_key="2743" name="NTR.Intranet_Renfe" operator="intersection">
             <expression_value operator="exclusion">
               <expression_value operator="union">
                 <expression_value operator="union">
                   <expression_value ne_ref="NTA.VPN.SSL.Extranet"/>
                   <expression_value ne_ref="NTR.VPN.IPsec"/>
                 </expression_value>
                 <expression_value ne_ref="NTR.VPN.SSL"/>
               </expression_value>
             </expression_value>
             <expression_value ne_ref="NET.RENFE_ADIF_INTRANET"/>
            </expression>
              */

            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($log_server, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;
        }




        #$firewall_alias_value = $configuration->xpath("//fw_cluster[@name='" . $firewall . "']/alias_value");



        //get_IPlist
        #$ip-list = $configuration->xpath("//ip-list");
        $ipLists = $configRoot->getElementsByTagName('ip_list');
        print "count(ip_list): ".count( $ipLists  )."\n";

        $missingGroup_members = array();

        foreach ($ipLists as $ipList)
        {
            if( $ipList->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $ipList->getAttribute('name');
            $name = $this->truncate_names($this->normalizeNames($name));
            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
            }

            $ips = $ipList->getElementsByTagName('ip');
            foreach ($ips as $ip)
            {
                $objName = $ip->getAttribute( 'value' );
                $name = $this->truncate_names( $this->normalizeNames( $objName ) );

                $tmpaddress = $this->sub->addressStore->find($name);
                if( $tmpaddress == null )
                {
                    print "\n - create address object: " . $name . " Value: ".$objName."\n";
                    $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $objName );
                }
                if( $tmpaddress != null )
                {
                    print "   - add address: ".$tmpaddress->name()."\n";
                    $tmpaddressgroup->addMember( $tmpaddress );
                }
            }
        }

        //get_Address_Group
        #$groups = $configuration->xpath("//group");
        $groups = $configRoot->getElementsByTagName('group');
        print "count(groups): ".count( $groups  )."\n";

        $missingGroup_members = array();

        foreach ($groups as $group)
        {
            if( $group->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = $group->getAttribute( 'name' );
            $name = $this->truncate_names( $this->normalizeNames( $name ) );
            $tmpaddressgroup = $this->sub->addressStore->find($name);
            if( $tmpaddressgroup == null )
            {
                print "\n - create addressgroup object: " . $name . "\n";
                $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
            }
            elseif( get_class($tmpaddressgroup) === "Address" )
            {
                $object = $tmpaddressgroup;
                $tag_string = "";
                if( count($object->tags->tags()) > 0 )
                {
                    $toStringInline = $object->tags->toString_inline();
                    TAG::revertreplaceNamewith( $toStringInline );
                    $tag_string = "tag: '".$toStringInline."'";
                }
                PH::print_stdout( "   * " . get_class($object) . " '{$object->name()}'  value: '{$object->value()}'  desc: '{$object->description()}' IPcount: '{$object->getIPcount()}' $tag_string" );
                derr( "object: ".$tmpaddressgroup->name()." is not an addressGroup" );
            }


            $ne_lists = $group->getElementsByTagName('ne_list');
            /*
            `<group db_key="20870" is_monitored="false" name="Telecontrol">
                <ne_list class_id="3" ref="USR.DGV.CE.Clot.CIC10.160.129.95"></ne_list>
                <ne_list class_id="3" ref="USR.p74388.viajeros.renfe.es"></ne_list>
              </group>`
             */
            foreach ($ne_lists as $ne_list)
            {
                if( $ne_list->nodeType != XML_ELEMENT_NODE )
                    continue;

                $objName = $ne_list->getAttribute( 'ref' );
                $name = $this->truncate_names( $this->normalizeNames( $objName ) );

                if( strpos( $name, "private-" ) !== FALSE )
                {
                    print "CHECK: ".$name."\n";
                    $tmpName = explode( "-", $name );
                    $tmpName = $this->truncate_names( $this->normalizeNames( $tmpName[1] ) );
                    $tmpaddress = $this->sub->addressStore->find($name);
                    if( $tmpaddress == null )
                    {
                        if( strpos( $tmpName, "_" ) !== FALSE )
                            $tmpName = str_replace(  "_", "/", $tmpName);
                        print "\n - create address object: " . $name . " Value: ".$tmpName."\n";
                        $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $tmpName );
                    }
                }

                $tmpaddress = $this->sub->addressStore->find($name);
                if( $tmpaddress == null )
                {
                    $missingGroup_members[ $tmpaddressgroup->name() ][] = $name;
                    mwarning( "object: ".$name." not found" );
                    #print "\n - create address object: " . $name . " Value: ".$value."\n";
                    #$tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $value );
                }
                if( $tmpaddress != null )
                {
                    print "   - add address: ".$tmpaddress->name()."\n";
                    $tmpaddressgroup->addMember( $tmpaddress );
                }

            }


            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($group, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;
        }

        $missingGroup_members2 = array();
        foreach( $missingGroup_members as $key => $missingGroup )
        {
            $tmpaddressgroup = $this->sub->addressStore->find($key);
            foreach( $missingGroup as $item )
            {
                $tmpaddress = $this->sub->addressStore->find($item);
                if( $tmpaddress != null )
                {
                    print "  - fix: ".$tmpaddressgroup->name()." add: ".$tmpaddress->name()."\n";
                    $tmpaddressgroup->addMember( $tmpaddress );
                }
                else
                {
                    $missingGroup_members2[ $tmpaddressgroup->name() ][] = $item;
                    #mwarning( "still missing object: ". $item." in Group: ". $tmpaddressgroup->name() );
                }
            }
        }
        print_r( $missingGroup_members2 );

    }






    ##########################################################
    //Todo:??????


    #$match_expressions = $configuration->xpath("//match_expression");
}