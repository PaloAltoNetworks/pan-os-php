<?php

trait trait_service
{
    function add_stonesoft_services(STRING $source, STRING $vsys)
{
    global $projectdb;
    $exists = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND name_ext IN ('FTP','SSH','SMTP');");
    if( $exists->num_rows == 0 )
    {

        #Get Last lid from Services
        $getMaxSrv = $projectdb->query("SELECT max(id) as max FROM services;");
        $getMaxSrvData = $getMaxSrv->fetch_assoc();
        $srvLid = intval($getMaxSrvData['max']) + 1;

        #Get Last lid from ServicesGroups
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM services_groups_id;");
        $getLID1 = $getlastlid->fetch_assoc();
        $i = intval($getLID1['max']) + 1;

        $add_srv = array();
        $nameNorm = normalizeNames("DHCP (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '67','predefined')";  //Used for the DHCP Relay. Do not delete
        $srvLid++;

        $nameNorm = normalizeNames("DHCP (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '67','predefined')";  //Used for the DHCP Relay. Do not delete
        $srvLid++;

        $nameNorm = normalizeNames("FTP (Data)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '20','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("FTP");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '21','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SSH");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '22','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Telnet");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '23','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SMTP");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '25','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("TACACS (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '49','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("TACACS (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '49','predefined')";
        $srvLid++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','DNS','DNS','static');");

        $nameNorm = normalizeNames("DNS (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '53','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("DNS (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '53','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $nameNorm = normalizeNames("HTTP");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '80','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("HTTP (with URL Logging)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '80','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("POP3");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '110','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("NNTP");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '119','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("NTP (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '123','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("NTP (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '123','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("MSRPC Endpoint Mapper (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm','tcp', '135','predefined')";
        $srvLid++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','NetBIOS','NetBIOS','static');");

        $nameNorm = normalizeNames("NetBIOS-NS (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '137','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("NetBIOS-NS (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '137','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("NetBIOS Datagram");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '138','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("NetBIOS-SSN");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '139','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $nameNorm = normalizeNames("IMAP");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '143','predefined')";
        $srvLid++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SNMP','SNMP','static');");

        $nameNorm = normalizeNames("SNMP (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '161','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SNMP (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '161','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SNMP Trap (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '162','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','LDAP','LDAP','static');");

        $nameNorm = normalizeNames("LDAP (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '389','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("LDAP (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '389','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $nameNorm = normalizeNames("HTTPS");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '443','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Microsoft-DS");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '445','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("ISAKMP (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '500','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Exec");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '512','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Rlogin");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '513','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Shell (cmd)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '514','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Syslog (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '514','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Syslog (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '514','predefined')";
        $srvLid++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','LDAPS','LDAPS','static');");

        $nameNorm = normalizeNames("LDAPS (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '636','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("LDAPS (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '636','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Kerberos','Kerberos','static');");

        $nameNorm = normalizeNames("Kerberos-88 (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '88','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Kerberos-88 (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '88','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Kerberos-464 (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '464','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Kerberos-464 (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '464','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Kerberos-749 (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '749','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Kerberos-749 (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '749','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Kerberos-750 (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '750','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Kerberos-750 (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '750','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $nameNorm = normalizeNames("IMAPS");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '993','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("MSSQL (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1433','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("MSSQL (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1433','predefined')";
        $srvLid++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','T.120','T.120','static');");

        $nameNorm = normalizeNames("T.120 (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1503','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("T.120 (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1503','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $nameNorm = normalizeNames("Oracle TNS");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1521','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("H.323 (Call Signaling)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1720','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("MySQL");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3306','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("RDP");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3389','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("NAT-T (Destination)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '4500','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Any TCP Service");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1-65535','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Ping");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Echo Request (No Code)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("Echo Request (Any Code)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("ICMP");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("HTTP proxy");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8080','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("MS-Streaming (ms-streaming)");
        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");

        $nameNorm = normalizeNames("MS-Streaming (ms-streaming) (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '1755','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("MS-Streaming (ms-streaming) (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '1755','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SIP','SIP','static');");

        $nameNorm = normalizeNames("SIP (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '5060','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SIP (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '5060','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;


        $nameNorm = normalizeNames("FTPS (Control)");
        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");

        $nameNorm = normalizeNames("FTPS (Control) (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '990','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("FTPS (Control) (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '990','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','MSRPC ','MSRPC','static');");

        $nameNorm = normalizeNames("MSRPC (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("MSRPC (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SIP Control','SIP Control','static');");

        $nameNorm = normalizeNames("SIP Control (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '0','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SIP Control (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '0','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Remote Desktop','Remote Desktop','static');");

        $nameNorm = normalizeNames("Remote Desktop (TCP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3389','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("Remote Desktop (UDP)");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '3389','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;


        $nameNorm = normalizeNames("SG Log");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3020','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Log to Log Server");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3020','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG SOHO Firewall to Log");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3020','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Web Portal Server to Log");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp', '3020','predefined')";
        $srvLid++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Engine to Log','SG Engine to Log','static');");

        $nameNorm = normalizeNames("SG Engine to Engine");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8902-8913','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SG Engine to Log1");
        $add_srv[] = "('$srvLid','$source','$vsys',    '$nameNorm',       'SG Engine to Log1',            'tcp',      '8916-8917','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $nameNorm = normalizeNames("SG Initial Contact");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3021','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Web Portal Server to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '3021','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Client to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8902-8913','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Management to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp', '8902-8913','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG SOHO Firewall to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp','3021','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Reverse Monitoring");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3023','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Dynamic Control Firewall to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp','8906','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Dynamic Firewall to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp','8906','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Dynamic Control");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp','8906','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Engine to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8902-8913','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Log to Management");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm',    '$nameNorm', 'tcp', '8902-8913','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Client to Log");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8914-8918','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Management to Log");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8914-8918','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Management to Stonesoft");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '443','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Management to Firewall");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '636','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Firewall to Server Pool");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '7777','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Analyzer to Engine");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm',   '$nameNorm', 'tcp', '15000','predefined')";
        $srvLid++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Log to Log','SG Log to Log','static');");

        $nameNorm = normalizeNames("SG Log to Log1");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '514','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SG Log to Log2");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '5514','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Management to Sensor','SG Management to Sensor','static');");

        $nameNorm = normalizeNames("SG Management to Sensor1','SG Management to Sensor1");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '4950','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SG Management to Sensor2','SG Management to Sensor2");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '18888','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SG Management to Sensor3','SG Management to Sensor3");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '15000','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Management to Analyzer','SG Management to Analyzer','static');");

        $nameNorm = normalizeNames("SG Management to Analyzer1");
        $add_srv[] = "('$srvLid','$source','$vsys',    '$nameNorm','$nameNorm',   'tcp',      '4950','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;

        $nameNorm = normalizeNames("SG Management to Analyzer2");
        $add_srv[] = "('$srvLid','$source','$vsys',    '$nameNorm','$nameNorm',   'tcp',      '18889','predefined')";
        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
        $srvLid++;
        $i++;

        $nameNorm = normalizeNames("SG Sensor to Analyzer");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '18890','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG VPN Client to Firewall");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','udp', '500','predefined')";
        $srvLid++;

        $nameNorm = normalizeNames("SG Monitoring Client to Monitoring Server");
        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '161','predefined')";
        $srvLid++;


        $out = implode(",", $add_srv);
        $projectdb->query("INSERT INTO services (id,source,vsys, name_ext,name,protocol,dport,devicegroup) VALUES " . $out . ";");
        unset($add_srv);


        $nameNorm = normalizeNames("Printer Spooler (TCP)");
        $projectdb->query("INSERT INTO services (source,vsys, name_ext,name,protocol,dport) VALUES ('$source', '$vsys', '$nameNorm', '$nameNorm','tcp','1023-65535');");
        $service_id = $projectdb->insert_id;
        add_log2("warning", 'Reading Security Policy', 'Service[' . $service_id . ']. The service Printer Spooler TCP may be too permisive', $source, 'Manually check', 'services', $service_id, 'services');
        $nameNorm = normalizeNames("Printer Spooler (UDP)");
        $projectdb->query("INSERT INTO services (source,vsys, name_ext,name,protocol,dport) VALUES ('$source', '$vsys', '$nameNorm', '$nameNorm','udp','1023-65535');");
        $service_id = $projectdb->insert_id;
        add_log2("warning", 'Reading Security Policy', 'Service[' . $service_id . ']. The service Printer Spooler UDP may be too permisive', $source, 'Manually check', 'services', $service_id, 'services');


    }
}

}
