<?php
/**
 * ISC License
 *
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


//bug available; last entry has sometimes an additional ',' available, which produce non-valide JSON



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
32,000
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

$valueArray = array(
    'product_name' => 'product_name',
    'title' => 'title',
    'product_id' => 'product_id',
    'id' => 'id',
    'teaser' => 'teaser',
    'language' => 'language',
    'url' => 'url',
    'large-image-url' => 'large-image-url',
    'small-image-url' => 'small-image-url',
    'category' => 'category',
    '2-0-3-1_dfi' => 'App-ID firewall throughput',
    '2-0-4-1_dfi' => 'Threat prevention throughput',
    '2-0-5-1_dfi' => 'Threat prevention throughput',
    '2-0-6-1_dfi' => 'IPSec VPN throughput',
    '2-0-7-1_dfi' => 'IPSec VPN throughput',
    '2-0-8-1_dfi' => 'Connections per second',
    '2-0-9-1_dfi' => 'Max sessions (IPv4 or IPv6)',
    '11-0-12-1_dfi' => 'Max sessions (IPv4 or IPv6)',
    '11-0-13-1_dfi' => 'Security rules',
    '15-0-16-1_dfi' => 'Security rules',
    '15-0-17-1_dfi' => 'Security rule schedules',
    '15-0-18-1_dfi' => 'NAT rules',
    '15-0-19-1_dfi' => 'Decryption rules',
    '15-0-20-1_dfi' => 'App override rules',
    '15-0-21-1_dfi' => 'Tunnel content inspection rules',
    '15-0-22-1_dfi' => 'SD-WAN rules',
    '15-0-23-1_dfi' => 'Policy based forwarding rules',
    '15-0-24-1_dfi' => 'Captive portal rules',
    '15-0-25-1_dfi' => 'DoS protection rules',
    '27-0-28-1_dfi' => 'Max security zones',
    '30-0-31-1_dfi' => 'Address objects',
    '30-0-32-1_dfi' => 'Address groups',
    '30-0-33-1_dfi' => 'Members per address group',
    '30-0-34-1_dfi' => 'Service objects',
    '30-0-35-1_dfi' => 'Service groups',
    '30-0-36-1_dfi' => 'Members per service group',
    '30-0-37-1_dfi' => 'FQDN address objects',
    '30-0-38-1_dfi' => 'Max DAG IP addresses',
    '30-0-39-1_dfi' => 'Tags per IP address',
    '41-0-42-1_dfi' => 'Security profiles',
    '44-0-45-1_dfi' => 'Custom App-ID signatures',
    '44-0-46-1_dfi' => 'Shared custom App-IDs',
    '44-0-47-1_dfi' => 'Custom App-IDs (virtual system specific)',
    '49-0-50-1_dfi' => 'IP-User mappings (management plane)',
    '49-0-51-1_dfi' => 'IP-User mappings (data plane)',
    '49-0-52-1_dfi' => 'Active and unique groups used in policy',
    '49-0-53-1_dfi' => 'Number of User-ID agents',
    '49-0-54-1_dfi' => 'Monitored servers for User-ID',
    '49-0-55-1_dfi' => 'Terminal server agents',
    '49-0-56-1_dfi' => 'Tags per User',
    '58-0-59-1_dfi' => 'Max SSL inbound certificates',
    '58-0-60-1_dfi' => 'SSL certificate cache (forward proxy)',
    '58-0-61-1_dfi' => 'Max concurrent decryption sessions',
    '58-0-62-1_dfi' => 'SSL Port Mirror',
    '58-0-63-1_dfi' => 'SSL Decryption Broker',
    '58-0-64-1_dfi' => 'HSM Supported',
    '66-0-67-1_dfi' => 'Total entries for allow list, block list and custom categories',
    '66-0-68-1_dfi' => 'Max custom categories',
    '66-0-69-1_dfi' => 'Max custom categories (virtual system specific)',
    '66-0-70-1_dfi' => 'Dataplane cache size for URL filtering',
    '66-0-71-1_dfi' => 'Management plane dynamic cache size',
    '73-0-74-1_dfi' => 'Max number of custom lists',
    '73-0-75-1_dfi' => 'Max number of IPs per system',
    '73-0-76-1_dfi' => 'Max number of DNS Domains per system',
    '73-0-77-1_dfi' => 'Max number of URL per system',
    '73-0-78-1_dfi' => 'Shortest check interval (min)',
    '80-0-81-1_dfi' => 'Mgmt - out-of-band',
    '80-0-82-1_dfi' => 'Mgmt - 10/100/1000 high availability',
    '80-0-83-1_dfi' => 'Mgmt - 40Gbps high availability',
    '80-0-84-1_dfi' => 'Mgmt - 10Gbps high availability',
    '80-0-85-1_dfi' => 'Traffic - 10/100/1000',
    '80-0-86-1_dfi' => 'Traffic - 100/1000/10000',
    '80-0-87-1_dfi' => 'Traffic - 1Gbps SFP',
    '80-0-88-1_dfi' => 'Traffic - 10Gbps SFP+',
    '80-0-89-1_dfi' => 'Traffic - 40/100Gbps QSFP+/QSFP28',
    '80-0-90-1_dfi' => '802.1q tags per device',
    '80-0-91-1_dfi' => '802.1q tags per physical interface',
    '80-0-92-1_dfi' => 'Max interfaces (logical and physical)',
    '80-0-93-1_dfi' => 'Maximum aggregate interfaces',
    '80-0-94-1_dfi' => 'Maximum SD-WAN virtual interfaces',
    '96-0-97-1_dfi' => 'Virtual routers',
    '99-0-100-1_dfi' => 'Virtual wires',
    '102-0-103-1_dfi' => 'Base virtual systems',
    '102-0-104-1_dfi' => 'Max virtual systems',
    '106-0-107-1_dfi' => 'IPv4 forwarding table size',
    '106-0-108-1_dfi' => 'IPv6 forwarding table size',
    '106-0-109-1_dfi' => 'System total forwarding table size',
    '106-0-110-1_dfi' => '32,000',
    '106-0-111-1_dfi' => 'Max routing peers (protocol dependent)',
    '106-0-112-1_dfi' => 'Static entries - DNS proxy',
    '106-0-113-1_dfi' => 'Bidirectional Forwarding Detection (BFD) Sessions',
    '115-0-116-1_dfi' => 'ARP table size per device',
    '115-0-117-1_dfi' => 'IPv6 neighbor table size',
    '115-0-118-1_dfi' => 'MAC table size per device',
    '115-0-119-1_dfi' => 'Max ARP entries per broadcast domain',
    '115-0-120-1_dfi' => 'Max MAC entries per broadcast domain',
    '123-0-124-1_dfi' => 'Total NAT rule capacity',
    '123-0-125-1_dfi' => 'Max NAT rules (static)',
    '123-0-126-1_dfi' => 'Max NAT rules (DIP)',
    '123-0-127-1_dfi' => 'Max NAT rules (DIPP)',
    '123-0-128-1_dfi' => 'Max translated IPs (DIP)',
    '123-0-129-1_dfi' => 'Max translated IPs (DIPP)',
    '123-0-130-1_dfi' => 'Default DIPP pool oversubscription',
    '132-0-133-1_dfi' => 'DHCP servers',
    '132-0-134-1_dfi' => 'DHCP relays',
    '132-0-135-1_dfi' => 'Max number of assigned addresses',
    '137-0-138-1_dfi' => 'Devices supported',
    '137-0-139-1_dfi' => 'Max virtual addresses',
    '141-0-142-1_dfi' => 'Number of QoS policies',
    '141-0-143-1_dfi' => 'Physical interfaces supporting QoS',
    '141-0-144-1_dfi' => 'Clear text nodes per physical interface',
    '141-0-145-1_dfi' => 'DSCP marking by policy',
    '141-0-146-1_dfi' => 'Subinterfaces supported',
    '148-0-149-1_dfi' => 'Max IKE Peers',
    '148-0-150-1_dfi' => 'Site to site (with proxy id)',
    '148-0-151-1_dfi' => 'SD-WAN IPSec tunnels',
    '153-0-154-1_dfi' => 'Max tunnels (SSL, IPSec, and IKE with XAUTH)',
    '156-0-157-1_dfi' => 'Max SSL tunnels',
    '159-0-160-1_dfi' => 'Replication (egress interfaces)',
    '159-0-161-1_dfi' => 'Routes',
    '163-0-164-1_dfi' => 'End-of-sale',
    'position' => 'A',
    '_version_' => 'B'
);

$panosArray = array(
    'base-vsys' => '102-0-103-1_dfi',
    'licensed-vsys' => '',
    'max-address' => '30-0-31-1_dfi',
    'max-address-group' => '30-0-32-1_dfi',
    'max-address-per-group' => '30-0-33-1_dfi',
    'max-aeqosnet' => '',
    'max-auth-policy-rule' => '',
    'max-dos-policy-rule' => '',
    'max-edl-domain' => '',
    'max-edl-domain-filesize' => '',
    'max-edl-ip' => '',
    'max-edl-ip-filesize' => '',
    'max-edl-objs' => '',
    'max-edl-url' => '',
    'max-edl-url-filesize' => '',
    'max-ha-cluster-members' => '',
    'max-ifnet' => '',
    'max-ifnet-sdwan' => '',
    'max-ike-peers' => '',
    'max-nat-policy-rule' => '',
    'max-oride-policy-rule' => '',
    'max-pbf-policy-rule' => '',
    'max-policy-rule' => '',
    'max-profile' => '',
    'max-qos-policy-rule' => '',
    'max-qosbw' => '',
    'max-qosif' => '',
    'max-qosnet' => '',
    'max-sdwan-policy-rule' => '',
    'max-service' => '30-0-34-1_dfi',
    'max-service-per-group' => '30-0-36-1_dfi',
    'max-session' => '11-0-12-1_dfi',
    'max-shared-gateway' => '',
    'max-signature' => '',
    'max-ssl-policy-rule' => '',
    'max-ssl-portal' => '',
    'max-ssl-tunnel' => '',
    'max-sslvpn-ck-cache-size-mp' => '',
    'max-threat-signature' => '',
    'max-tsagents' => '',
    'max-tunnel' => '',
    'max-vlan' => '',
    'max-vrouter' => '96-0-97-1_dfi',
    'max-vsys' => '',
    'max-vwire' => '99-0-100-1_dfi',
    'max-zone' => ''
);

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

print $urlSite."\n";

$string =  file_get_contents($urlSite );


$string = find_string_between( $string, "({", "})" );
$your_json_string = "{".$string."}";
$data = json_decode($your_json_string, TRUE);


$jsonString = "{\n";
foreach( $data['response']['docs'] as $mainkey => $fw )
{
    $jsonString .= '  "'.$fw['product_name'].'":{'."\n";

    $key1 = 0;
    $countFW = count( $fw );
    foreach( $fw as $key => $entries )
    {
        #$testArray[$key] = $headerarray[ $key1];
        if( strpos( $entries, "and higher" ) !== false || strpos( $entries, " to " ) !== false || strpos( $entries, " - " ) !== false)
        {
            $countFW--;
            continue;
        }

        if( isset($headerarray[$key1]) )
        {
            #$jsonString .=  '    "'.$headerarray[$key1].'":"'.$entries.'"';
            $jsonString .=  '    "'.$valueArray[$key].'":"'.$entries.'"';

            if( isset($headerarray[$key1+1]) && $key1+1 < $countFW )
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

//compare files to check if something is new

