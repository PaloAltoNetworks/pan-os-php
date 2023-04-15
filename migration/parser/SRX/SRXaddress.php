<?php



trait SRXaddress
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

        $missingAddrGroup = array();
        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeName = $childNode->nodeName;

            if( $nodeName == 'name' )
            {
                $addressbookName = $childNode->textContent;
                print "Addressbook: " . $addressbookName . "\n";
            }
            elseif( $nodeName == "address" )
            {
                $name = "";
                $value = "1.1.1.1/32";
                $tmpaddress = null;

                foreach( $childNode->childNodes as $key => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $nodeName = $child->nodeName;

                    if( $nodeName == 'name' )
                    {
                        $name = $child->textContent;
                        #print "addressname: ".$name."\n";

                        $name = $this->truncate_names( $this->normalizeNames( $name ) );

                        $tmpaddress = $this->sub->addressStore->find($name);

                        if( $tmpaddress == null )
                        {
                            print "\n - create address object: " . $name . "\n";
                            $tmpaddress = $this->sub->addressStore->newAddress($name, "ip-netmask", $value);
                        }
                        else
                        {
                            mwarning("address object with name: " . $name . " already available\n");
                            continue;
                        }
                    }
                    elseif( $nodeName == 'description' )
                    {
                        $description = $child->textContent;

                        print "   - description: " . $description . "\n";
                        $tmpaddress->setDescription($description);

                    }
                    elseif( $nodeName == "ip-prefix" )
                    {
                        $value = $child->textContent;
                        #print "ip-prefix: ".$name."\n";

                        /*
                       <address>
                           <name>extEURODBEuroDB-37_58_40_40</name>
                           <ip-prefix>37.58.40.40/32</ip-prefix>
                       </address>
                        */
                        print "   - type: ip-netmask\n";
                        print "   - value: " . $value . "\n";

                        $tmpaddress->setType("ip-netmask");
                        $tmpaddress->setValue($value);

                    }
                    elseif( $nodeName == "range-address" )
                    {
                        /*
                        <address>
                            <name>Block_DNS-94_108_0_0_14</name>
                            <range-address>
                                <name>94.108.128.0</name>
                                <to>
                                    <range-high>94.111.255.255</range-high>
                                </to>
                            </range-address>
                        </address>
                        */

                        $rangestart = DH::findFirstElement('name', $child);
                        $rangestart = $rangestart->textContent;

                        $rangeend = DH::findFirstElement('to', $child);
                        $rangeend = DH::findFirstElement('range-high', $rangeend);
                        $rangeend = $rangeend->textContent;

                        print "   - type: ip-range\n";
                        print "   - value: " . $value . "\n";

                        $value = $rangestart . "-" . $rangeend;
                        $tmpaddress->setType("ip-range");
                        $tmpaddress->setValue($value);
                    }
                    elseif( $nodeName == "dns-name" )
                    {
                        $fqdn = DH::findFirstElement('name', $child);
                        if( $fqdn === FALSE )
                            derr("<name> was not found", $child);
                        $fqdn = $fqdn->textContent;

                        print "   - type: fqdn\n";
                        print "   - value: " . $fqdn . "\n";

                        $tmpaddress->setType("fqdn");
                        $tmpaddress->setValue($fqdn);
                    }
                    else
                        mwarning("was not found", $child);
                }
            }
            elseif( $nodeName == "address-set" )
            {
                /*
                 <address-set>
                            <name>extOCSFederationPartnersGrp</name>
                            <address>
                                <name>extAvanadeOCSEdgePool-12_129_10_202</name>
                            </address>
                <address-set>
                 */
                foreach( $childNode->childNodes as $key => $child )
                {
                    /** @var DOMElement $childNode */
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;


                    $nodeName = $child->nodeName;

                    if( $nodeName == 'name' )
                    {
                        $name = $child->textContent;
                        #print "addressname: ".$name."\n";

                        $name = $this->truncate_names( $this->normalizeNames( $name ) );

                        $tmpaddressgroup = $this->sub->addressStore->find($name);

                        if( $tmpaddressgroup != null and !$tmpaddressgroup->isGroup() )
                        {
                            $name = "g-".$name;
                            $tmpaddressgroup = $this->sub->addressStore->find( $name);
                        }


                        if( $tmpaddressgroup == null )
                        {
                            print "\n - create addressgroup object: " . $name . "\n";
                            $tmpaddressgroup = $this->sub->addressStore->newAddressGroup($name);
                        }
                        else
                        {
                            mwarning("address object with name: " . $name . " already available\n");
                            continue;
                        }


                    }
                    elseif( $nodeName == 'address' || $nodeName == 'address-set' )
                    {
                        $addressname = DH::findFirstElement('name', $child);
                        if( $addressname === FALSE )
                            derr("<name> was not found", $child);

                        $addressname = $addressname->textContent;
                        #print "addressname: ".$name."\n";

                        $addressname = $this->truncate_names( $this->normalizeNames( $addressname ) );

                        $tmpaddress = $this->sub->addressStore->find($addressname);
                        if( $tmpaddress != null )
                        {
                            print "   - add object: " . $tmpaddress->name() . "\n";
                            if( $tmpaddressgroup->isGroup() )
                                $tmpaddressgroup->addMember($tmpaddress);
                            else
                                derr( "can not add member to an address object: ".$tmpaddressgroup->name() );
                        }
                        else
                        {

                            if( $nodeName == 'address-set' )
                            {
                                mwarning("address-set object not found: " . $name." try to fix it later");
                                $missingAddrGroup[$name][$addressname] = $addressname;
                            }
                            else
                                mwarning("object not found: " . $name);

                        }

                    }
                    else
                        mwarning( $nodeName ." not supported yet" );
                }
            }
            else
                mwarning("was not found", $childNode);
        }


        print "fixing missing AddressGroup members\n";
        foreach( $missingAddrGroup as $key => $group )
        {
            /** @var AddressGroup $tmpaddressgroup */
            $tmpaddressgroup = $tmpaddress = $this->sub->addressStore->find($key);

            print "fix AddressGroup: ".$tmpaddressgroup->name()."\n";

            foreach( $group as $key2 => $member )
            {
                $tmpMember = $this->sub->addressStore->find($member);

                if( $tmpMember != null )
                {
                    print "  - add member: ".$tmpMember->name()."\n";
                    $tmpaddressgroup->addMember( $tmpMember );
                }
                else
                {
                    mwarning( "Member: ". $member." could NOT be added to AddressGroup: ".$tmpaddressgroup->name() );
                }

            }
        }

        # Load the new address-books like Globals
        #$allzones = $configuration->xpath("/configuration/security/address-book");

        /*
            foreach ($configRoot->childNodes as $child => $data2)
            {

                #The zone will be called global
                if (isset($data2->attach->zone->name)){
                    $zoneName = (string)  $data2->attach->zone->name;
                }
                else{
                    $zoneName = (string) $data2->name;
                }
                #Can be dynamic?
                $type = "layer3";
                if ($zoneName != "") {
                    #Read Address and Groups and Assign the Zone to it.

                    if (!isset($objectsInMemory[$zoneName])){
                        $objectsInMemory[$zoneName]['address']=array();
                        $objectsInMemory[$zoneName]['address_groups_id']=array();
                    }

                    $address = $data2->xpath("address");

                    foreach ($address as $child => $data) {
                        $name = (string) $data->name;

                        #Fix if the object was named as 1.1.1.1/30 then replace / by - => 1.1.1.1-30
                        $name = str_replace('/', '-', $name);

                        if (empty($name)) {
                            $name = (string) $data->{'address-name'};
                        }
                        $description = addslashes($data->description);

                        $name_int = truncate_names(normalizeNames($name));

                        if (!empty($data->{'ip-prefix'})) {
                            $prefix = (string)$data->{'ip-prefix'};
                            $theipaddress = explode("/", $prefix); #ip address
                            $ip=$theipaddress[0];
                            $mask=$theipaddress[1];
                            #Gotcha if the object comes without mask set to 32 bits
                            $ipversion = ip_version($ip);
                            if ($ipversion == "v4") {
                                if ($mask == "") {
                                    $mask = "32";
                                }
                            } elseif ($ipversion == "v6") {
                                if ($mask == "") {
                                    $mask = "128";
                                }
                            }
                            else{
                                $ipversion="v4";
                                if ($mask == "") {
                                    $mask = "32";
                                }
                            }

                            if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                                $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-netmask','ip-netmask','$ip','$mask','1','$source','$description','$zoneName')";
                                $objectsInMemory[$zoneName]['address'][$name]=$alid;
                                $alid++;
                            }

                        }
                        elseif (!empty($data->{'address-range'})) {
                            $value1 = (string)$data->{'address-range'}->low;
                            $value2 = (string)$data->{'address-range'}->high;
                            $value=$value1."-".$value2;

                            $ipversion = ip_version($value1);
                            if ($ipversion=="noip"){
                                $ipversion="v4";
                            }

                            if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                                $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                                $objectsInMemory[$zoneName]['address'][$name]=$alid;
                                $alid++;
                            }
                        }
                        elseif (!empty($data->{'range-address'})) {
                            $value1=(string)$data->{'range-address'}->name;
                            $value2=(string)$data->{'range-address'}->to->{'range-high'};
                            $value = $value1."-".$value2;

                            $ipversion = ip_version($value1);
                            if ($ipversion=="noip"){
                                $ipversion="v4";
                            }

                            if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                                $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                                $objectsInMemory[$zoneName]['address'][$name]=$alid;
                                $alid++;
                            }
                        }
                        elseif (!empty($data->{'dns-name'})) {
                            $value = $data->{'dns-name'};
                            $valueName=(string)$value->name;
                            $ipversion="v4";
                            if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                                $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','fqdn','fqdn','$valueName','','1','$source','$description','$zoneName')";
                                $objectsInMemory[$zoneName]['address'][$name]=$alid;
                                $alid++;
                            }
                        }
                    }

                    # ADDRESS GROUPS
                    $address = $data2->xpath("address-set");

                    #First read all the GRoups and assign a lid
                    foreach ($address as $child => $data) {
                        $name = (string)$data->name;
                        $name = str_replace('/', '-', $name);
                        if (empty($name)) {
                            $name = (string)$data->{'address-name'};
                        }
                        $name_int = truncate_names(normalizeNames($name));

                        if (!isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                            $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                            $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                            $aglid++;
                        }
                    }

                    foreach ($address as $child => $data) {
                        $name = (string)$data->name;
                        $name = str_replace('/', '-', $name);
                        if (empty($name)) {
                            $name = (string)$data->{'address-name'};
                        }
                        $name_int = truncate_names(normalizeNames($name));

                        if (isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                            $currentLid=$objectsInMemory[$zoneName]['address_groups_id'][$name];
                        }
                        else{
                            $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                            $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                            $currentLid=$aglid;
                            $aglid++;
                        }

                        if (isset($data->address)){
                            foreach ($data->address as $field => $value) {
                                $member = (string)$value->name;
                                $member = str_replace('/', '-', $member);
                                if (isset($objectsInMemory[$zoneName]['address'][$member])){
                                    $member_lid=$objectsInMemory[$zoneName]['address'][$member];
                                    $table_name="address";
                                    $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                                }
                                elseif (isset($objectsInMemory['global']['address'][$member])){
                                    $member_lid=$objectsInMemory['global']['address'][$member];
                                    $table_name="address";
                                    $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                                }
                                else{
                                    print "Unable to find this Member Object (address): $member on a Group: $name".PHP_EOL;
                                }
                            }
                        }

                        if (isset($data->{'address-set'})){
                            foreach ($data->{'address-set'} as $field => $value) {
                                $member = (string)$value->name;
                                $member = str_replace('/', '-', $member);
                                if (isset($objectsInMemory[$zoneName]['address_groups_id'][$member])){
                                    $member_lid=$objectsInMemory[$zoneName]['address_groups_id'][$member];
                                    $table_name="address_groups_id";
                                    $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                                }
                                elseif (isset($objectsInMemory['global']['address_groups_id'][$member])){
                                    $member_lid=$objectsInMemory['global']['address_groups_id'][$member];
                                    $table_name="address_groups_id";
                                    $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                                }
                                else{
                                    print "Unable to find this Member Object (Group): $member on a Group: $name".PHP_EOL;
                                }
                            }
                        }
                    }

                }
            }
        */


        /*
        # Load all the old address-books from zones
        $zones=array();
        $allzones = $configuration->xpath("/configuration/security/zones/security-zone");

        $zones = array();
        foreach ($allzones as $child => $data2) {
            if (isset($data2->attach->zone->name)){
                $zoneName = (string)$data2->attach->zone->name;
            }
            else{
                $zoneName = (string)$data2->name;
            }
            #Can be dynamic?
            $type = "layer3";
            if ($zoneName != "") {
                #Read Address and Groups and Assign the Zone to it.
                //$address=$data2->{'address-book'}->address;

                if (!isset($objectsInMemory[$zoneName])){
                    $objectsInMemory[$zoneName]['address']=array();
                    $objectsInMemory[$zoneName]['address_groups_id']=array();
                }

                $address = $data2->xpath("address-book/address");
                foreach ($address as $child => $data) {
                    $name = (string)$data->name;

                    #Fix if the object was named as 1.1.1.1/30 then replace / by - => 1.1.1.1-30
                    $name = str_replace('/', '-', $name);

                    if (empty($name)) {
                        $name = (string)$data->{'address-name'};
                    }
                    $description = addslashes($data->description);

                    $name_int = truncate_names(normalizeNames($name));

                    if (!empty($data->{'ip-prefix'})) {
                        $prefix = (string)$data->{'ip-prefix'};
                        $theipaddress = explode("/", $prefix); #ip address
                        $ip=$theipaddress[0];
                        $mask=$theipaddress[1];
                        #Gotcha if the object comes without mask set to 32 bits
                        $ipversion = ip_version($ip);
                        if ($ipversion == "v4") {
                            if ($mask == "") {
                                $mask = "32";
                            }
                        } elseif ($ipversion == "v6") {
                            if ($mask == "") {
                                $mask = "128";
                            }
                        }
                        else{
                            $ipversion="v4";
                            if ($mask == "") {
                                $mask = "32";
                            }
                        }

                        if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                            $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-netmask','ip-netmask','$ip','$mask','1','$source','$description','$zoneName')";
                            $objectsInMemory[$zoneName]['address'][$name]=$alid;
                            $alid++;
                        }

                    }
                    elseif (!empty($data->{'address-range'})) {
                        $value1 = (string)$data->{'address-range'}->low;
                        $value2 = (string)$data->{'address-range'}->high;
                        $value=$value1."-".$value2;

                        $ipversion = ip_version($value1);
                        if ($ipversion=="noip"){
                            $ipversion="v4";
                        }

                        if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                            $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                            $objectsInMemory[$zoneName]['address'][$name]=$alid;
                            $alid++;
                        }
                    }
                    elseif (!empty($data->{'range-address'})) {
                        $value1=(string)$data->{'range-address'}->name;
                        $value2=(string)$data->{'range-address'}->to->{'range-high'};
                        $value = $value1."-".$value2;

                        $ipversion = ip_version($value1);
                        if ($ipversion=="noip"){
                            $ipversion="v4";
                        }

                        if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                            $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                            $objectsInMemory[$zoneName]['address'][$name]=$alid;
                            $alid++;
                        }
                    }
                    elseif (!empty($data->{'dns-name'})) {
                        $value = $data->{'dns-name'};
                        $valueName=(string)$value->name;
                        $ipversion="v4";
                        if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                            $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','fqdn','fqdn','$valueName','','1','$source','$description','$zoneName')";
                            $objectsInMemory[$zoneName]['address'][$name]=$alid;
                            $alid++;
                        }
                    }
                }


                #ADDRESS GROUPS
                $address = $data2->xpath("address-book/address-set");

                foreach ($address as $child => $data) {
                    $name = (string)$data->name;
                    $name = str_replace('/', '-', $name);
                    if (empty($name)) {
                        $name = (string)$data->{'address-name'};
                    }
                    $name_int = truncate_names(normalizeNames($name));

                    if (!isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                        $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                        $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                        $aglid++;
                    }
                }


                foreach ($address as $child => $data) {
                    $name = (string)$data->name;
                    $name = str_replace('/', '-', $name);
                    if (empty($name)) {
                        $name = (string)$data->{'address-name'};
                    }
                    $name_int = truncate_names(normalizeNames($name));

                    if (isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                        $currentLid=$objectsInMemory[$zoneName]['address_groups_id'][$name];
                    }
                    else{
                        $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                        $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                        $currentLid=$aglid;
                        $aglid++;
                    }

                    if (isset($data->address)){
                        foreach ($data->address as $field => $value) {
                            $member = (string)$value->name;
                            $member = str_replace('/', '-', $member);

                            if (isset($objectsInMemory[$zoneName]['address'][$member])){
                                $member_lid=$objectsInMemory[$zoneName]['address'][$member];
                                $table_name="address";
                                $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                            }
                            elseif (isset($objectsInMemory['global']['address'][$member])){
                                $member_lid=$objectsInMemory['global']['address'][$member];
                                $table_name="address";
                                $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                            }
                            else{
                                print "Unable to find this Member Object (address): $member on a Group: $name".PHP_EOL;
                            }
                        }
                    }

                    if (isset($data->{'address-set'})){
                        foreach ($data->{'address-set'} as $field => $value) {
                            $member = (string)$value->name;
                            $member = str_replace('/', '-', $member);
                            if (isset($objectsInMemory[$zoneName]['address_groups_id'][$member])){
                                $member_lid=$objectsInMemory[$zoneName]['address_groups_id'][$member];
                                $table_name="address_groups_id";
                                $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                            }
                            elseif (isset($objectsInMemory['global']['address_groups_id'][$member])){
                                $member_lid=$objectsInMemory['global']['address_groups_id'][$member];
                                $table_name="address_groups_id";
                                $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                            }
                            else{
                                print "Unable to find this Member Object (Group): $member on a Group: $name".PHP_EOL;
                            }
                        }
                    }
                }

                #MAP Zone with Interfaces
                $interfacesin = $data2->xpath("interfaces");
                $getInterface = array();
                $getinterfacesall = "";
                foreach ($interfacesin as $kkkey => $vvvalue) {
                    $intName = (string)$vvvalue->name;
                    $exist = $projectdb->query("SELECT id FROM interfaces WHERE unitname='$intName' AND source='$source';");
                    if ($exist->num_rows > 0) {
                        $projectdb->query("UPDATE interfaces SET zone='$zoneName' WHERE source='$source' AND unitname='$intName'");
                    }
                    $getInterface[] = (string)$vvvalue->name;
                }
                $getinterfacesall = implode(",", $getInterface);
                $zones[] = "('$source','$zoneName','$vsys','$type','$getinterfacesall','$template')";
            }
        }


        if ( (isset($add_address['v4'])) AND (count($add_address['v4']) > 0) ){
            $unique=array_unique($add_address['v4']);
            $out = implode(",", $unique);
            $projectdb->query("INSERT INTO address (id,name_ext,name,vsys,type,vtype,ipaddress,cidr,v4,source,description,zone) VALUES " . $out.";");
        }
        if ( (isset($add_address['v6'])) AND (count($add_address['v6']) > 0) ){
            $unique=array_unique($add_address['v6']);
            $out = implode(",", $unique);
            $projectdb->query("INSERT INTO address (id,name_ext,name,vsys,type,vtype,ipaddress,cidr,v6,source,description,zone) VALUES " . $out.";");
            $projectdb->query("UPDATE address set v4=0 WHERE v6=1;");
        }

        unset($add_address);

        if (count($add_address_group) > 0) {

            $uniq = array_unique($add_address_group);
            $out = implode(",", $uniq);
            $projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,source,vsys,zone) VALUES ". $out .";");

            if (count($add_address_group_member)>0){
                $uniq = array_unique($add_address_group_member);
                $out = implode(",", $uniq);
                $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys,member_lid,table_name) VALUES ". $out .";");
            }
        }

        if (count($zones) > 0) {
            $out = implode(",", $zones);
            $projectdb->query("INSERT INTO zones (source,name,vsys,type,interfaces,template) VALUES " . $out . ";");
        }

        */

    }

}