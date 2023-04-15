<?php

trait SIDEWINDERnetwork
{
    #function get_interfaces($source,$vsys,$template,$config_path)
    function get_interfaces( $mcafee_config_file )
    {
        $source = "";
        $template = "";
        $vsys = "";
        /*
        #Create a VR
        $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
        if ($getVR->num_rows==0){
            $projectdb->query("INSERT INTO virtual_routers (name,source,template,vsys) VALUES ('mcafee-vr','$source','$template','$vsys');");
            $vr_id=$projectdb->insert_id;
        }
        elseif ($getVR->num_rows==1){
            $getVRData=$getVR->fetch_assoc();
            $vr_id=$getVRData['id'];
        }
        */

        $vr = "mcafee-vr";

        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr == null )
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);

        $addZone=array();
        $addInterface=array();
        $addRoutes=array();
        $routes=1;
        $vr_id = 1;

        foreach ($mcafee_config_file as $line2 => $names_line2)
        {
            if ( (preg_match("/^interface add entrytype=interface/i",$names_line2)) OR (preg_match("/^interface add entrytype=vlan/i",$names_line2)) )
            {
                $data=preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line2, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                /*
interface add entrytype=interface name=em0 hwdevice=1-0 enabled=yes
    v6_enabled=no v6_autoconf=static zone=internal addresses=10.11.200.44/24
    member_addresses=10.11.200.91/24 qos_profile='' mtu=1500
    description='Default external network interface'
    cluster_mac=01:00:5e:b:c8:2c l2_mode=multicast
    monitor_addrs=10.11.200.254 monitor_allowed_failures=3
    monitor_interval=30 monitor_link=1
                 */
                $name="";
                $mask="";
                $ipaddress="";
                $unitipaddress="";
                $unittag=0;
                $zoneName = "";

                #print_r( $data );

                foreach ($data as $key=>$option)
                {
                    $option=str_replace("'","",$option);
                    if (preg_match("/^name=/",$option))
                    {
                        $name_tmp=explode("=",$option);
                        $name=$this->normalizeNames($name_tmp[1]);
                    }
                    elseif (preg_match("/^burb=/",$option))
                    {
                        $zone_tmp=explode("=",$option);
                        $zoneName=$this->normalizeNames($zone_tmp[1]);
                        $addZone[]= array($source,$template,$vsys,$zoneName,'layer3',$name);
                    }
                    elseif (preg_match("/^zone=/",$option))
                    {
                        $zone_tmp=explode("=",$option);
                        $zoneName=$this->normalizeNames($zone_tmp[1]);
                        $addZone[] = array($source,$template,$vsys,$zoneName,'layer3',$name);
                    }
                    elseif (preg_match("/^ipaddr=/",$option))
                    {
                        $ipaddr_tmp=explode("=",$option);
                        $ipaddress=$ipaddr_tmp[1];
                    }
                    elseif (preg_match("/^mask=/",$option))
                    {
                        $mask_tmp=explode("=",$option);
                        $mask=$mask_tmp[1];
                    }
                    elseif (preg_match("/^vlan_id=/",$option))
                    {
                        $vlan_tmp=explode("=",$option);
                        $unittag=$vlan_tmp[1];
                    }
                    elseif (preg_match("/^addresses=/",$option))
                    {
                        $ipaddr_tmp=explode("=",$option);
                        $unitipaddress=$ipaddr_tmp[1];
                    }
                    if (preg_match("/^hwdevice=/",$option))
                    {
                        $hwdevice_tmp=explode("=",$option);
                        $hwdevice=$this->normalizeNames($hwdevice_tmp[1]);
                    }


                    if (($ipaddress!="") AND ($mask!=""))
                    {
                        #$mask1=mask2cidrv4($mask);
                        $mask1 = CIDR::netmask2cidr( $mask);
                        $unitipaddress=$ipaddress."/".$mask1;
                    }
                }

                if ($unittag!=0)
                {
                    $unitName=$name.".".$unittag;
                }
                else
                {
                    $unitName=$name;
                }

                $addInterface[]= array($name,'layer3','ethernet',$source,$template,$vsys,$vr_id,$unitipaddress,$unitName,$zoneName,$unittag,$hwdevice);

            }

        }

        if (count($addZone)>0)
        {
            #print "Zone:\n";
            #print_r( $addZone );

            //are create with  interfaces

            unset($addZone);
        }
        if (count($addInterface)>0)
        {
            #$projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ".implode(",",$addInterface).";");

            #print "Interface:\n";
            #print_r( $addInterface );

            foreach( $addInterface as $interface )
            {
                /*
                [0] => qa_dmz_private
                [1] => layer3
                [2] => ethernet
                [3] =>
                [4] =>
                [5] =>
                [6] => 1
                [7] => 167.168.85.13/25
                [8] => qa_dmz_private.93
                [9] => qa_dmz_private
                [10] => 93
                [11] => em2
                */
                $int_name = $interface[11];
                $int_description = $interface[0];
                $ip_value = $interface[7];
                $vlan = $interface[10];
                $zone_name = $interface[9];

                $tmp_int_main = $this->template->network->findInterface($int_name);
                if( !is_object($tmp_int_main) )
                {
                    print "\n    - create interface: " . $int_name . "\n";
                    $tmp_int_main = $this->template->network->ethernetIfStore->newEthernetIf($int_name, 'layer3');
                    $tmp_int_main->setDescription( $int_description );
                    $this->template_vsys->importedInterfaces->addInterface($tmp_int_main);

                    if( $vlan == 0 )
                    {
                        print "       - add IP: '" . $ip_value . "'\n";
                        if( $ip_value != "" )
                            $tmp_int_main->addIPv4Address( $ip_value );


                        if( $zone_name != "")
                        {
                            $tmp_zone = $this->template_vsys->zoneStore->find($zone_name);

                            if( $tmp_zone == null )
                            {
                                $tmp_name = $this->truncate_names($this->normalizeNames($zone_name));

                                $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                            }

                            print "       - add INT: " . $tmp_int_main->name() . " to Zone: ".$tmp_zone->name()."\n";
                            $tmp_zone->attachedInterfaces->addInterface($tmp_int_main);
                        }


                        print "       - add INT: " . $tmp_int_main->name() . " to VR: ".$tmp_vr->name()."\n";
                        $tmp_vr->attachedInterfaces->addInterface( $tmp_int_main );
                    }


                }

                if( $vlan != 0 )
                {
                    $tmp_sub = $this->template->network->findInterface($int_name . "." . $vlan);
                    if( $tmp_sub === null )
                    {

                        $tmp_sub = $tmp_int_main->addSubInterface($vlan, $int_name . "." . $vlan);
                        print "\n       - add SUBINT: " . $tmp_sub->name() ."\n";
                        $this->template_vsys->importedInterfaces->addInterface($tmp_sub);

                        print "       - add IP: " . $ip_value . "\n";
                        $tmp_sub->addIPv4Address( $ip_value );

                        $tmp_zone = $this->template_vsys->zoneStore->find($zone_name);
                        if( $tmp_zone == null )
                        {
                            $tmp_name = $this->truncate_names($this->normalizeNames($zone_name));
                            $tmp_zone = $this->template_vsys->zoneStore->newZone($tmp_name, 'layer3');
                        }

                        print "       - add INT: " . $tmp_sub->name() . " to Zone: ".$tmp_zone->name()."\n";
                        $tmp_zone->attachedInterfaces->addInterface($tmp_sub);

                        print "       - add INT: " . $tmp_sub->name() . " to VR: ".$tmp_vr->name()."\n";
                        $tmp_vr->attachedInterfaces->addInterface( $tmp_sub );
                    }
                }
            }

            unset($addInterface);
        }
    }

    function get_routes( $mcafee_config_file )
    {

        $source = "";
        $template = "";
        $vsys = "";
        /*
        #Create a VR
        $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
        if ($getVR->num_rows==0){
            $projectdb->query("INSERT INTO virtual_routers (name,source,template,vsys) VALUES ('mcafee-vr','$source','$template','$vsys');");
            $vr_id=$projectdb->insert_id;
        }
        elseif ($getVR->num_rows==1){
            $getVRData=$getVR->fetch_assoc();
            $vr_id=$getVRData['id'];
        }
        */

        $vr = "mcafee-vr";

        $tmp_vr = $this->template->network->virtualRouterStore->findVirtualRouter($vr);
        if( $tmp_vr == null )
            $tmp_vr = $this->template->network->virtualRouterStore->newVirtualRouter($vr);

        $addZone=array();
        $addInterface=array();
        $addRoutes=array();
        $routes=1;
        $vr_id = 1;

        foreach ($mcafee_config_file as $line2 => $names_line2)
        {
            if( (preg_match("/^route add route=/i",$names_line2)) OR (preg_match("/^static add route=/i",$names_line2)))
            {
                //static add route=161.202.158.0/255.255.255.0 gateway=199.53.234.94 description=''
                #print "LINE2: ".$names_line2."\n";
                $data=preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line2, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                $routeName = "Route ".$routes;$mask="";$destination="";$network="";$metric="1";$ip_version="v4";

                #print_r( $data );

                foreach ($data as $key=>$option)
                {
                    $option=str_replace("'","",$option);
                    if (preg_match("/^gateway=/",$option))
                    {
                        $gateway_tmp=explode("=",$option);
                        $gateway=$gateway_tmp[1];
                        $ip_version= $this->ip_version($gateway);
                    }
                    elseif (preg_match("/^route=/",$option))
                    {
                        $route_tmp=explode("=",$option);
                        if ($route_tmp[1] == "default")
                        {
                            $routeName="default";
                            $destination="0.0.0.0/0";
                        }
                        else{
                            $network_netmask=explode("/",$route_tmp[1]);
                            $network=$network_netmask[0];
                            #$mask=mask2cidrv4($network_netmask[1]);
                            $mask = CIDR::netmask2cidr($network_netmask[1]);
                            $destination=$network."/".$mask;
                        }
                        $routes++;
                    }
                }
                $addRoutes[]= array('',$source,$vr_id,$template,$ip_version,$routeName,$destination,'','ip-address',$gateway,$metric,$vsys);
            }
        }

        if (count($addRoutes)>0)
        {
            #$projectdb->query("INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES ".implode(",",$addRoutes).";");

            //zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys

            /*
            Zone[0] =>
            source[1] =>
            vr_id[2] => 1
            template[3] =>
            ip_version[4] => v4
            name[5] => Route 165
            destionation[6] => 167.168.0.0/16
            tointerface[7] =>
            nexthop[8] => ip-address
            nexthop_value[9] => 199.53.234.94
            metric[10] => 1
            vssys[11] =>
             */


            foreach( $addRoutes as $staticroute )
            {
                #print_r( $staticroute );

                $route_name = $staticroute[5];
                $network_and_mask = $staticroute[6];
                $preference = $staticroute[10];
                $interfaceto = $staticroute[7];

                $nexthop = $staticroute[8];
                $nexthop_value = $staticroute[9];


                $xml_gateway = "";
                if( $nexthop == "ip-address" )
                {
                    $xml_gateway = "<nexthop><ip-address>" . $nexthop_value . "</ip-address></nexthop>";
                }
                else
                {
                    derr( "check: ".$nexthop );
                }

                $xml_interface = "";
                if( $interfaceto !== "" )
                {
                    $xml_interface = "<interface>".$interfaceto."</interface>";
                    $tmp_interface = $this->template->network->find( $interfaceto );
                    if( $tmp_interface != null )
                    {
                        $tmp_vr->attachedInterfaces->addInterface( $tmp_interface);
                    }
                }

                $xmlString = "<entry name=\"".$route_name."\">".$xml_gateway."<metric>".$preference."</metric>".$xml_interface."<destination>".$network_and_mask."</destination></entry>";
                $tmpRoute = $this->add_route_to_vr( $xmlString, $tmp_vr );

                print "   - create route: ".$tmpRoute->name()."\n";

                $tmp_vr->addstaticRoute( $tmpRoute );
            }


            #print "Routing:\n";
            #print_r( $addRoutes );

            unset($addRoutes);
        }
    }

    function add_route_to_vr( $xmlString, $vr)
    {
        $newRoute = new StaticRoute('***tmp**', $vr);

        $xmlElement = DH::importXmlStringOrDie($vr->owner->owner->xmlroot->ownerDocument, $xmlString);
        $xmlElement = DH::importXmlStringOrDie($vr->owner->xmlroot->ownerDocument, $xmlString);
        $newRoute->load_from_xml($xmlElement);

        return $newRoute;
    }

}