<?php

//PAN-OS at least available with version 7.1
///config/devices/entry[@name='localhost.localdomain']/platform/limits



//Todo: CN firewall (last enrtie) is wrong

function find_string_between($line, $needle1, $needle2 = "--END--")
{
    $needle_length = strlen($needle1);
    $pos1 = strpos($line, $needle1);

    if( $needle2 !== "--END--" )
        $pos2 = strpos($line, $needle2);
    else
        $pos2 = strlen($line);

    $finding = substr($line, $pos1 + $needle_length, $pos2 - ($pos1 + $needle_length));

    return $finding;
}

//this is copy past from Palo Alto networks product compare website
$string = "product_name
title
product_id
id
teaser
language
url
large-image-url
small-image-url
category
App-ID firewall throughput
Threat prevention throughput
IPSec VPN throughput
Connections per second
Max sessions (IPv4 or IPv6)
Security rules
Security rule schedules
NAT rules
Decryption rules
App override rules
Tunnel content inspection rules
SD-WAN rules
Policy based forwarding rules
Captive portal rules
DoS protection rules
Max security zones
Address objects
Address groups
Members per address group
Service objects
Service groups
Members per service group
FQDN address objects
Max DAG IP addresses
Tags per IP address
Security profiles
Custom App-ID signatures
Shared custom App-IDs
Custom App-IDs (virtual system specific)
IP-User mappings (management plane)
IP-User mappings (data plane)
Active and unique groups used in policy
Number of User-ID agents
Monitored servers for User-ID
Terminal server agents
Tags per User
Max SSL inbound certificates
SSL certificate cache (forward proxy)
Max concurrent decryption sessions
SSL Port Mirror
SSL Decryption Broker
HSM Supported
Total entries for allow list, block list and custom categories
Max custom categories
Max custom categories (virtual system specific)
Dataplane cache size for URL filtering
Management plane dynamic cache size
Max number of custom lists
Max number of IPs per system
Max number of DNS Domains per system
Max number of URL per system
Shortest check interval (min)
Mgmt - out-of-band
Mgmt - 10/100/1000 high availability
Mgmt - 40Gbps high availability
Mgmt - 10Gbps high availability
Traffic - 10/100/1000
Traffic - 100/1000/10000
Traffic - 1Gbps SFP
Traffic - 10Gbps SFP+
Traffic - 40/100Gbps QSFP+/QSFP28
802.1q tags per device
802.1q tags per physical interface
Max interfaces (logical and physical)
Maximum aggregate interfaces
Maximum SD-WAN virtual interfaces
Virtual routers
Virtual wires
Base virtual systems
Max virtual systems
IPv4 forwarding table size
IPv6 forwarding table size
System total forwarding table size
32,00050
Max routing peers (protocol dependent)
Static entries - DNS proxy
Bidirectional Forwarding Detection (BFD) Sessions
ARP table size per device
IPv6 neighbor table size
MAC table size per device
Max ARP entries per broadcast domain
Max MAC entries per broadcast domain
Total NAT rule capacity
Max NAT rules (static)
Max NAT rules (DIP)
Max NAT rules (DIPP)
Max translated IPs (DIP)
Max translated IPs (DIPP)
Default DIPP pool oversubscription
DHCP servers
DHCP relays
Max number of assigned addresses
Devices supported
Max virtual addresses
Number of QoS policies
Physical interfaces supporting QoS
Clear text nodes per physical interface
DSCP marking by policy
Subinterfaces supported
Max IKE Peers
Site to site (with proxy id)
SD-WAN IPSec tunnels
Max tunnels (SSL, IPSec, and IKE with XAUTH)
Max SSL tunnels
Replication (egress interfaces)
Routes
End-of-sale
A
B";


$headerarray = preg_split("/\r\n|\n|\r/", $string);
#print_r( $headerarray );


$rows = "40";

$protocol = "https://";
$server = "www.paloaltonetworks.com";
$site = "/apps/pan/public/solr/proxy";

$url_var = "corename=productcompare";
$url_var .= "&q=*%3A*";
$url_var .= "&fq=language%3A%22en_US%22";
$url_var .= "&rows=".$rows;
$url_var .= "&json.nl=map";
$url_var .= "&sort=position%20asc";
$url_var .= "&wt=json";
$url_var .= "&json.wrf=jQuery112208076986402974597_1636959058347&_=1636959058348";



$url = $protocol.$server.$site;
$urlSite = $url."?".$url_var;


$string =  file_get_contents($urlSite );


$string = find_string_between( $string, "({", "})" );
$your_json_string = "{".$string."}";
$data = json_decode($your_json_string, TRUE);


$jsonString = "{\n";
foreach( $data['response']['docs'] as $mainkey => $fw )
{

    $jsonString .= '  "'.$fw['product_name'].'":{'."\n";

    $key1 = 0;
    foreach( $fw as $key => $entries )
    {
        if( strpos( $entries, "and higher" ) !== false || strpos( $entries, " to " ) !== false || strpos( $entries, " - " ) !== false)
            continue;

        if( isset($headerarray[$key1]) )
        {
            $jsonString .=  '    "'.$headerarray[$key1].'":"'.$entries.'"';

            if( isset($headerarray[$key1+1]) )
                $jsonString .=  ",";

            $jsonString .= "\n";
        }


        $key1++;
    }
    $jsonString .=  "  }";

    if( $mainkey+1 < count( $data['response']['docs'] ))
        $jsonString .=  ",";

    $jsonString .=  "\n";
}
$jsonString .=  "}\n";


#print $jsonString;
$file = "pan_max_values.json";

file_put_contents($file, $jsonString);



