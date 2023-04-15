<?php



trait STONESOFTservice
{
    public function add_services( $configRoot )
    {
        //TCP services
        #$service_tcps = $configuration->xpath("//service_tcp");

        $service_tcps = $configRoot->getElementsByTagName('service_tcp');
        print "count(service_tcp): ".count( $service_tcps  )."\n";
        foreach ($service_tcps as $service_tcp)
        {
            if( $service_tcp->nodeType != XML_ELEMENT_NODE )
                continue;



            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($service_tcp, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;


            $this->create_service( $service_tcp, "tcp");
        }



        //UDP services
        #$service_udps = $configuration->xpath("//service_udp");

        $service_udps = $configRoot->getElementsByTagName('service_udp');
        print "count(service_udp): ".count( $service_udps  )."\n";
        foreach ($service_udps as $service_udp)
        {
            if( $service_tcp->nodeType != XML_ELEMENT_NODE )
                continue;

            $this->create_service( $service_udp, "udp");
        }

        $service_ips = $configRoot->getElementsByTagName('service_ip');
        print "count(service_ip): ".count( $service_ips  )."\n";
        foreach ($service_ips as $service_ip)
        {
            if( $service_ip->nodeType != XML_ELEMENT_NODE )
                continue;

            $protocol = DH::findAttribute('protocol_number', $service_ip);
            $this->create_service( $service_ip, $protocol);
        }
    }

    public function create_service(  $domElement, $protocol)
    {
        $name = DH::findAttribute('name', $domElement);
        $name = $this->truncate_names( $this->normalizeNames($name));

        $dport = DH::findAttribute('min_dst_port', $domElement);
        $maxDport = DH::findAttribute('max_dst_port', $domElement);
        $service_type = null;
        if( $maxDport != null && (int)$maxDport != (int)$dport )
        { //Checking is a range of ports is defined
            $dport = $dport . "-" . $maxDport;
            $service_type = "range";
            //if ($dport == "1-65535") 	$dport = "";
        }
        else
            $service_type = "service";


        $description = DH::findAttribute('comment', $domElement);


        $sport = DH::findAttribute('min_src_port', $domElement);
        $maxSport = DH::findAttribute('max_src_port', $domElement);
        if( $maxSport != null && (int)$maxSport != (int)$sport )
        { //Checking is a range of ports is defined
            $sport = $sport . "-" . $maxSport;
            if ($sport == "1-65535") 	$sport = null;
        }

        if( $protocol != "tcp" && $protocol != "udp" )
        {
            $name .= "proto_".$protocol;
            $protocol = "tcp";

        }

        $tmpservice = $this->sub->serviceStore->find($name);
        if( $tmpservice == null )
        {
            print "\n - create service object: " . $name . "\n";
            $tmpservice = $this->sub->serviceStore->newService($name, $protocol, $dport, $description, $sport);
        }
    }

    public function add_service_groups( $configRoot )
    {
        //Todo: servicegroups
        #$gen_service_groups = $configuration->xpath("//gen_service_group");
        #$tcp_service_groups = $configuration->xpath("//tcp_service_group");
        #$udp_service_groups = $configuration->xpath("//udp_service_group");

        $tcp_service_groups = $configRoot->getElementsByTagName('tcp_service_group');

        $udp_service_groups = $configRoot->getElementsByTagName('udp_service_group');

        $gen_service_groups = $configRoot->getElementsByTagName('gen_service_group');

        $missing_services = array();

        $this->createServiceGroups( $tcp_service_groups, $missing_services );
        $this->createServiceGroups( $udp_service_groups,$missing_services );
        $this->createServiceGroups( $gen_service_groups,$missing_services );


        print_r( $missing_services );


        /*
        <tcp_service_group db_key="687" name="ATLAS">
            <service_ref class_id="46" ref="8084"></service_ref>
            <service_ref class_id="46" ref="8085"></service_ref>
            <service_ref class_id="46" ref="8086"></service_ref>
          </tcp_service_group>
        <tcp_service_group db_key="690" name="CLARIS">
            <service_ref class_id="46" ref="8087"></service_ref>
            <service_ref class_id="46" ref="8088"></service_ref>
          </tcp_service_group>
        <tcp_service_group db_key="878" name="ORION DB ACCESS">
            <service_ref class_id="46" ref="http"></service_ref>
            <service_ref class_id="46" ref="17778"></service_ref>
            <service_ref class_id="46" ref="17779"></service_ref>
          </tcp_service_group>
        <tcp_service_group comment="it have been created for the ticket INC4528504" db_key="1066" name="PtoV by VM converter Standalone">
            <service_ref class_id="46" ref="NetBIOS-SSN" ref_key="356"></service_ref>
            <service_ref class_id="46" ref="NetBIOS-NS (TCP)" ref_key="355"></service_ref>
            <service_ref class_id="46" ref="NETBIOS-Datagram"></service_ref>
            <service_ref class_id="46" ref="445"></service_ref>
            <service_ref class_id="46" ref="9090"></service_ref>
          </tcp_service_group>
        <tcp_service_group db_key="693" name="cca">
            <service_ref class_id="46" ref="VM_Serveur-Console"></service_ref>
            <service_ref class_id="46" ref="910"></service_ref>
            <service_ref class_id="46" ref="980"></service_ref>
          </tcp_service_group>
         */

        #derr( "STOP" );
    }

    public function createServiceGroups( $domNodeList, &$missing_services )
    {


        print "count(service_ip): ".count( $domNodeList  )."\n";
        foreach ($domNodeList as $tcp_service_group)
        {
            if( $tcp_service_group->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = DH::findAttribute('name', $tcp_service_group);
            $name = $this->truncate_names( $this->normalizeNames($name));

            $tmpserivcegroup = $this->sub->serviceStore->find($name);
            if( $tmpserivcegroup == null )
            {
                print "\n - create servicegroup object: " . $name . "\n";
                $tmpserivcegroup = $this->sub->serviceStore->newServiceGroup($name);
            }

            foreach( $tcp_service_group->childNodes as $service )
            {
                if( $service->nodeType != XML_ELEMENT_NODE )
                    continue;

                if( $service->nodeName == "service_ref" )
                {
                    $tmpservice_name = $service->getAttribute( 'ref' );
                    $orig_name = $tmpservice_name;
                    $tmpservice_name = $this->truncate_names( $this->normalizeNames($tmpservice_name));

                    $tmpservice = $this->sub->serviceStore->find($tmpservice_name);
                    if( $tmpservice == null )
                    {
                        $tmpservice = $this->sub->serviceStore->find( "tmp-".$tmpservice_name);
                        if( $tmpservice == null )
                        {

                            $service2 = explode( "/", $tmpservice_name );
                            if( count( $service2) == 2 )
                            {
                                $protocol = $service2[0];
                                $dport = $service2[1];
                                $name = $protocol."-".$dport;

                                //validation if $dport are numbers
                                $dport_array = explode( "-", $dport );
                                foreach( $dport_array as $int )
                                {
                                    if( is_numeric( $int ) )
                                    {
                                        $tmpservice = $this->sub->serviceStore->find($name);
                                        if( $tmpservice == null )
                                        {
                                            print "\n - create service object: " . $name . "\n";
                                            $tmpservice = $this->sub->serviceStore->newService($name, $protocol, $dport);
                                        }
                                    }
                                }
                            }

                            if( $tmpservice == null )
                            {
                                mwarning("service: " . $tmpservice_name . " not found");
                                $missing_services[] = $orig_name;
                                continue;
                            }
                        }
                    }

                    if( $tmpservice != null )
                    {
                        /** @var ServiceGroup|Service $tmpserivcegroup*/
                        if( $tmpserivcegroup->isGroup() )
                        {
                            print "   - add service: ".$tmpservice->name()."\n";
                            $tmpserivcegroup->addMember( $tmpservice );
                        }
                        else{
                            print "not a group: ".$tmpserivcegroup->name()." create new group/add former service as member/ add tmpservice\n";
                        }

                    }

                }
            }
            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($tcp_service_group, true);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            #print $html;


        }
    }


}