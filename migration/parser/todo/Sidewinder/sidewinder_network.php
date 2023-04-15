<?php


function get_interfaces($source, $vsys, $template, $config_path)
{
    global $projectdb;

    $mcafee_config_file = file($config_path);

    #Create a VR
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    if( $getVR->num_rows == 0 )
    {
        $projectdb->query("INSERT INTO virtual_routers (name,source,template,vsys) VALUES ('mcafee-vr','$source','$template','$vsys');");
        $vr_id = $projectdb->insert_id;
    }
    elseif( $getVR->num_rows == 1 )
    {
        $getVRData = $getVR->fetch_assoc();
        $vr_id = $getVRData['id'];
    }
    $addZone = array();
    $addInterface = array();
    $addRoutes = array();
    $routes = 1;
    foreach( $mcafee_config_file as $line2 => $names_line2 )
    {

        if( (preg_match("/^interface add entrytype=interface/i", $names_line2)) or (preg_match("/^interface add entrytype=vlan/i", $names_line2)) )
        {

            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line2, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

            $name = "";
            $mask = "";
            $ipaddress = "";
            $unitipaddress = "";
            $unittag = 0;

            foreach( $data as $key => $option )
            {
                $option = str_replace("'", "", $option);
                if( preg_match("/^name=/", $option) )
                {
                    $name_tmp = explode("=", $option);
                    $name = normalizeNames($name_tmp[1]);
                }
                elseif( preg_match("/^burb=/", $option) )
                {
                    $zone_tmp = explode("=", $option);
                    $zoneName = normalizeNames($zone_tmp[1]);
                    $addZone[] = "('$source','$template','$vsys','$zoneName','layer3','$name')";
                }
                elseif( preg_match("/^zone=/", $option) )
                {
                    $zone_tmp = explode("=", $option);
                    $zoneName = normalizeNames($zone_tmp[1]);
                    $addZone[] = "('$source','$template','$vsys','$zoneName','layer3','$name')";
                }
                elseif( preg_match("/^ipaddr=/", $option) )
                {
                    $ipaddr_tmp = explode("=", $option);
                    $ipaddress = $ipaddr_tmp[1];
                }
                elseif( preg_match("/^mask=/", $option) )
                {
                    $mask_tmp = explode("=", $option);
                    $mask = $mask_tmp[1];
                }
                elseif( preg_match("/^vlan_id=/", $option) )
                {
                    $vlan_tmp = explode("=", $option);
                    $unittag = $vlan_tmp[1];
                }
                elseif( preg_match("/^addresses=/", $option) )
                {
                    $ipaddr_tmp = explode("=", $option);
                    $unitipaddress = $ipaddr_tmp[1];
                }


                if( ($ipaddress != "") and ($mask != "") )
                {
                    $mask1 = mask2cidrv4($mask);
                    $unitipaddress = $ipaddress . "/" . $mask1;
                }
            }
            if( $unittag != 0 )
            {
                $unitName = $name . "." . $unittag;
            }
            else
            {
                $unitName = $name;
            }
            $addInterface[] = "('$name','layer3','ethernet','$source','$template','$vsys','$vr_id','$unitipaddress','$unitName','$zoneName','$unittag')";


        }
        elseif( (preg_match("/^route add route=/i", $names_line2)) or (preg_match("/^static add route=/i", $names_line2)) )
        {

            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line2, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

            $routeName = "Route " . $routes;
            $mask = "";
            $destination = "";
            $network = "";
            $metric = "1";
            $ip_version = "v4";

            foreach( $data as $key => $option )
            {
                $option = str_replace("'", "", $option);
                if( preg_match("/^gateway=/", $option) )
                {
                    $gateway_tmp = explode("=", $option);
                    $gateway = $gateway_tmp[1];
                    $ip_version = ip_version($gateway);
                }
                elseif( preg_match("/^route=/", $option) )
                {
                    $route_tmp = explode("=", $option);
                    if( $route_tmp[1] == "default" )
                    {
                        $routeName = "default";
                        $destination = "0.0.0.0/0";
                    }
                    else
                    {
                        $network_netmask = explode("/", $route_tmp[1]);
                        $network = $network_netmask[0];
                        $mask = mask2cidrv4($network_netmask[1]);
                        $destination = $network . "/" . $mask;
                    }
                    $routes++;
                }
            }
            $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','$routeName','$destination','','ip-address','$gateway','$metric','$vsys')";
        }

    }

    if( count($addZone) > 0 )
    {
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES " . implode(",", $addZone) . ";");
        unset($addZone);
    }
    if( count($addInterface) > 0 )
    {
        $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES " . implode(",", $addInterface) . ";");
        unset($addInterface);
    }
    if( count($addRoutes) > 0 )
    {
        $projectdb->query("INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES " . implode(",", $addRoutes) . ";");
        unset($addRoutes);
    }
}
