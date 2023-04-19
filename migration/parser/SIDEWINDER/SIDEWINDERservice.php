<?php

trait SIDEWINDERservice
{
    function generateService( $mcafee_config_file )
    {
        /*
        * @param VirtualSystem $v
        */


        $source = "";
        $vsys = "";
        $grplid = 1;

        $addGroup = array();
        $addAddress = array();

        foreach ($mcafee_config_file as $line2 => $names_line2) {

            if ( (preg_match("/^service modify /i", $names_line2)) OR (preg_match("/^service add /i", $names_line2)) OR (preg_match("/^application modify /i", $names_line2)) OR (preg_match("/^application add /i", $names_line2)))
            {

                preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);

                $name = "";
                $tcp_ports = "";
                $description = "";
                $name_int = "";
                $udp_ports = "";
                $protocol="";
                $port="";

                #print_r( $matches[0] );

                foreach ($matches[0] as $key => $option)
                {
                    $option=str_replace("'","",$option);

                    if (preg_match("/^name=/", $option))
                    {
                        $name_tmp = explode("=", $option);
                        $name_int = $this->truncate_names( $this->normalizeNames($name_tmp[1]));
                        $name = $name_int;

                        #print "1name: ".$name."\n";

                    }
                    elseif (preg_match("/^udp_ports=/", $option)) {
                        $ipaddr_tmp = explode("=", $option);
                        if ($ipaddr_tmp[1]!="")
                        {
                            $udp_ports = $ipaddr_tmp[1];
                            $protocol="udp";
                            $port=$udp_ports;
                        }

                    }
                    elseif (preg_match("/^tcp_ports=/", $option)) {
                        $ipaddr_tmp = explode("=", $option);
                        if ($ipaddr_tmp[1]!=""){
                            $tcp_ports = $ipaddr_tmp[1];
                            $protocol="tcp";
                            $port=$tcp_ports;
                        }
                    }
                    elseif (preg_match("/^protocol=/", $option)) {
                        $ipaddr_tmp = explode("=", $option);
                        $protocol = $ipaddr_tmp[1];
                        $port="";
                        $port=$tcp_ports;
                    }
                    elseif (preg_match("/^description=/", $option)) {
                        $ipaddr_tmp = explode("=", $option);
                        $description = $this->normalizeComments($ipaddr_tmp[1]);
                    }

                }

                if( ($udp_ports!="") AND ($tcp_ports!="") )
                {
                    # Convert into Group
                    $addGroup[]= array($grplid,$name,$name_int,$source,$vsys,$description);

                    $newname= $this->truncate_names("tcp-".$name);
                    $addMember[]= array($grplid,$newname,$source,$vsys);
                    $addAddress[] = array($newname,$newname,0,$source,$vsys,'tcp',$tcp_ports,$description);

                    $newname= $this->truncate_names("udp-".$name);
                    $addMember[]= array($grplid,$newname,$source,$vsys);
                    $addAddress[] = array($newname,$newname,0,$source,$vsys,'udp',$udp_ports,$description);

                    $grplid++;
                }
                else{
                    $addAddress[] = array($name,$name_int,0,$source,$vsys,$protocol,$port,$description);
                }
            }
        }


        if (count($addAddress) > 0) {
            #$projectdb->query("INSERT INTO services (name_ext,name,checkit,source,vsys,protocol,dport,description) VALUES " . implode(",", $addAddress) . ";");

            //name_ext,name,checkit,source,vsys,protocol,dport,description
            print_r( $addAddress );

            foreach( $addAddress as $address )
            {
                $name = $address[1];
                $protocol = $address[5];
                $dport = $address[6];
                $description = $address[7];

                print "search for service: ".$name."\n";
                $tmp_service = $this->sub->serviceStore->find($name);
                if( $tmp_service == null )
                {
                    if( $protocol == "" )
                    {
                        $protocol = "tcp";
                        $name = "tmp-" . $name;
                        $dport = "65535";
                    }

                    if( $dport == "" )
                    {
                        $dport = "65535";
                        $name = "tmp-" . $name;
                    }

                    $tmp_service = $this->sub->serviceStore->find($name);
                    if( $tmp_service == null )
                    {
                        print "- create service: " . $name . " protocol: " . $protocol . " | dport: " . $dport . "\n";

                        $tmp_service = $this->sub->serviceStore->newService($name, $protocol, $dport);

                        $tmp_service->setDescription($description);

                        if( strpos( $name, "tmp-" ) === FALSE )
                        {
                            $this->replaceTMPservice( $name, $tmp_service);
                        }

                    }
                }
                else
                    mwarning("service : " . $name . " already available\n");
            }
        }

        print "\n\n";

        if (count($addGroup)>0){
            #$projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,source,vsys,description) VALUES ".implode(",",$addGroup).";");

            #print_r( $addGroup );

            //id,name_ext,name,source,vsys,description
            foreach( $addGroup as $group )
            {
                $name = $group[2];
                $id = $group[0];

                $tmp_servicegroup = $this->sub->serviceStore->find( $name );
                if( $tmp_servicegroup == null )
                {
                    print "  - create servicegroup: ".$name."\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup( $name );

                    if( strpos( $name, "tmp-" ) === FALSE )
                    {
                        $this->replaceTMPservice( $name, $tmp_servicegroup);
                    }

                    foreach( $addMember as $member )
                    {
                        //lid,member,source,vsys

                        $name = $member[1];
                        if( $member[0] == $id )
                        {
                            $tmp_service = $this->sub->serviceStore->find( $name );
                            if( $tmp_service == null )
                            {
                                $tmp_service = $this->sub->serviceStore->find( "tmp-".$name );
                            }

                            print "    - add member: ".$tmp_service->name()."\n";
                            $tmp_servicegroup->addmember( $tmp_service );
                        }
                    }


                }
            }





            if (count($addMember) > 0) {
                #$projectdb->query("INSERT INTO services_groups (lid,member,source,vsys) VALUES " . implode(",", $addMember) . ";");

                #print_r( $addMember );
            }

            unset($addAddress);
            unset($addGroup);
            unset($addMember);
        }
    }

    function generateServiceGroup( $mcafee_config_file )
    {
        /*
       * @param VirtualSystem $v
       */


        $source = "";
        $vsys = "";
        $grplid = 1;

        $addAddress = array();
        $addNewAddress = array();
        $addGroup=array();


        /*
        $getMaxid=$projectdb->query("SELECT max(id) as maxid FROM services_groups_id;");
        if ($getMaxid->num_rows>0){
            $getMaxidData=$getMaxid->fetch_assoc();
            $grplid=$getMaxidData['maxid']+1;
        }
        else{
            $grplid=1;
        }
*/

        foreach ($mcafee_config_file as $line2 => $names_line2) {

            if ((preg_match("/^servicegroup add/i", $names_line2)) OR (preg_match("/^appgroup add/i", $names_line2))) {

                preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);

                $name = "";
                $description = "";
                $name_int = "";

                foreach ($matches[0] as $key => $option) {
                    $option=str_replace("'","",$option);
                    if (preg_match("/^name=/", $option)) {
                        $name_tmp = explode("=", $option);
                        $name_int = $this->truncate_names( $this->normalizeNames($name_tmp[1]));
                        $name = $name_int;

                    } elseif (preg_match("/^members=/", $option)) {
                        //$option=str_replace("'","",$option);
                        $ipaddr_tmp = explode("=", $option);
                        $members = explode(",",$ipaddr_tmp[1]);
                        foreach ($members as $keyy=>$vvalue){

                            $vvalue=str_replace("application:","",$vvalue);
                            $vvalue=str_replace("custom:","",$vvalue);

                            $addAddress[] = array($grplid,$vvalue,$source,$vsys);
                        }
                    } elseif (preg_match("/^description=/", $option)) {
                        $ipaddr_tmp = explode("=", $option);
                        $description = $this->normalizeComments($ipaddr_tmp[1]);

                    }

                }
                $addGroup[]= array($grplid,$name,$name_int,$source,$vsys,$description);
                $grplid++;

            }
        }

        if (count($addGroup)>0)
        {
            #$projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,source,vsys,description) VALUES ".implode(",",$addGroup).";");
            //id,name_ext,name,source,vsys,description
            foreach( $addGroup as $group )
            {
                $name = $group[2];
                $id = $group[0];

                $tmp_servicegroup = $this->sub->serviceStore->find( $name );
                if( $tmp_servicegroup == null )
                {
                    print "  - create servicegroup: ".$name."\n";
                    $tmp_servicegroup = $this->sub->serviceStore->newServiceGroup( $name );

                    foreach( $addAddress as $member )
                    {
                        //lid,member,source,vsys

                        $name = $member[1];
                        if( $member[0] == $id )
                        {
                            $tmp_service = $this->sub->serviceStore->find( $name );
                            if( $tmp_service == null )
                            {
                                $tmp_service = $this->sub->serviceStore->find( "tmp-".$name );

                                if( $tmp_service == null )
                                {
                                    $name = "tmp-".$name;
                                    $protocol = 'tcp';
                                    $dport = "65000";
                                    print "- create service: " . $name . " protocol: " . $protocol . " | dport: " . $dport . "\n";

                                    $tmp_service = $this->sub->serviceStore->newService($name, $protocol, $dport);
                                    #mwarning( "service: ".$name." not found\n" );
                                }
                            }

                            if( $tmp_service != null )
                            {
                                print "    - add member: ".$tmp_service->name()."\n";
                                $tmp_servicegroup->addmember( $tmp_service );
                            }

                        }
                    }

                    if( strpos( $name, "tmp-" ) === FALSE )
                    {
                        $this->replaceTMPservice( $name, $tmp_servicegroup);

                    }
                }
            }

            if (count($addAddress) > 0) {
                #$projectdb->query("INSERT INTO services_groups (lid,member,source,vsys) VALUES " . implode(",", $addAddress) . ";");
            }
            unset($addGroup);unset($addAddress);
        }
    }

    function replaceTMPservice( $name, $service)
    {


        $tmp_service_toreplace = $this->sub->serviceStore->find("tmp-".$name);
        if( $tmp_service_toreplace !=  null )
        {
            print "found TMP service: ". $tmp_service_toreplace->name(). " this service will be replaced with: ".$service->name()."\n";

            $tmp_service_toreplace->owner->replaceServiceWith( $tmp_service_toreplace, $service->name(), "    ", false );

            $tmp_service_toreplace->owner->remove( $tmp_service_toreplace );
        }
    }
}