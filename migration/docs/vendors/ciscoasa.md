###CiscoASA

###migration Support for ASA versions:
- Cisco Pix
- Cisco ASA pre 8.3
- Cisco ASA post eq 8.3
- Cisco ASA FirePOWER

###notes
https://panw-gcs.slack.com/archives/CDP1XKYES/p1626227432198300?thread_ts=1626181500.192100&cid=CDP1XKYES

There are a couple of things you should know about access-lists on the ASA:
- When you create an ACL statement for "higher to lower security level" traffic then the source IP address is the real address of the host or network (not the NAT translated one).
- When you create an ACL statement for "lower to higher security level" traffic then the destination IP address has to be:
   - The translated address for any ASA version before 8.3.
   - The real address for ASA 8.3 and newer.
   - The access-list is always checked before NAT translation.


https://panw-gcs.slack.com/archives/CDP1XKYES/p1626244206209400?thread_ts=1626181500.192100&cid=CDP1XKYES

These are the commands related to the security levels.
- "same-security-traffic permit inter-interface"
- "same-security-traffic permit intra-interface"

###known NOT supported migration stuff
- dynamic Routing
- layer2 interfaces
- time-range (planned for integration)

###Cisco config export
```bash
pager 0
enable

terminal pager 0
more system:running-config
```
    
History for Cisco Objects		
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-objects.html#ID-2122-00000369

###Address
#####name //Pix
https://www.cisco.com/en/US/docs/security/pix/pix50/configuration/guide/commands.html#wp6704
```bash
name 127.0.0.1 DEMO description demo info collector in lower environment.
```
- "name"


#####Network Object
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-objects.html#ID-2122-0000001f
```bash
object network email-server
 host 10.2.2.2
```
- object network
    - host {IPv4_address | IPv6_address}—The IPv4 or IPv6 address of a single host. For example, 10.1.1.1 or 2001:DB8::0DB8:800:200C:417A.
    - subnet {IPv4_address IPv4_mask | IPv6_address/IPv6_prefix}—The address of a network. For IPv4 subnets, include the mask after a space, for example, 10.0.0.0 255.0.0.0. For IPv6, include the address and prefix as a single unit (no spaces), such as 2001:DB8:0:CD30::/60.
    - range start_address end_address—A range of addresses. You can specify IPv4 or IPv6 ranges. Do not include masks or prefixes.
    - fqdn [v4 | v6] fully_qualified_domain_name—A fully-qualified domain name, that is, the name of a host, such as www.example.com. Specify v4 to limit the address to IPv4, and v6 for IPv6. If you do not specify an address type, IPv4 is assumed.
    - description (Optional) Add a description: description string

#####Network Object Group
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-objects.html#ID-2122-0000007d
```bash
object-group network admin
 network-object 10.1.1.0 255.255.255.0
 network-object 2001:db8:0:cd30::/60
 network-object host 10.1.1.1
 network-object host 2001:DB8::0DB8:800:200C:417A
 network-object object existing-object-1
 group-object existing-network-object-group
```
- object-group network
    - network-object host {IPv4_address | IPv6_address}—The IPv4 or IPv6 address of a single host. For example, 10.1.1.1 or 2001:DB8::0DB8:800:200C:417A.
    - network-object {IPv4_address IPv4_mask | IPv6_address/IPv6_prefix}—The address of a network or host. For IPv4 subnets, include the mask after a space, for example, 10.0.0.0 255.0.0.0. For IPv6, include the address and prefix as a single unit (no spaces), such as 2001:DB8:0:CD30::/60.
    - network-object object object_name—The name of an existing network object.
    - group-object object_group_name—The name of an existing network object group.
    - description (Optional) Add a description: description string

###Services

Service translation to PAN-OS services:
- for all NONE tcp/udp => App-ID migration
- predefined Cisco service must be created at the beginning
- service protocol => App-ID migration 

As Service objects can be also used on Cisco ACL a temporary approach is need to do App-ID migration as an improvement step after the transformation to PAN-OS.

#####Service Object
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-objects.html#ID-2122-00000105
```bash
object service web
 service tcp destination eq 80
```
- object service
    - service protocol —The name or number (0-255) of an IP protocol. Specify ip to apply to all protocols.
    - service {icmp | icmp6} [icmp-type [icmp_code]] —For ICMP or ICMP version 6 messages. You can optionally specify the ICMP type by name or number (0-255) to limit the object to that message type. If you specify a type, you can optionally specify an ICMP code for that type (1-255). If you do not specify the code, then all codes are used.
    - service {tcp | udp | tcp-udp} [source operator port] [destination operator port] —For TCP or UDP. You can optionally specify ports for the source, destination, or both. You can specify the port by name or number. The operator can be one of the following:
        - lt — less than.
        - gt — greater than.
        - eq — equal to.
        - neq — not equal to.
        - range — an inclusive range of values. When you use this operator, specify two port numbers, for example, range 100 200.
    - service {[0-9]{1,3}}
    - service {[A-Za-z]*}
    - description (Optional) Add a description: description string

#####Service Object Group
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-objects.html#ID-2122-0000016f
```bash
object-group service general-services
 service-object ipsec
 service-object tcp destination eq domain
 service-object icmp echo
 service-object object my-service
 group-object Engineering_groups
```
- object-group service
    - service-object protocol —The name or number (0-255) of an IP protocol. Specify ip to apply to all protocols.
    - service-object {icmp | icmp6} [icmp-type [icmp_code]] —For ICMP or ICMP version 6 messages. You can optionally specify the ICMP type by name or number (0-255) to limit the object to that message type. If you specify a type, you can optionally specify an ICMP code for that type (1-255). If you do not specify the code, then all codes are used.
    - service-object {tcp | udp | tcp-udp} [source operator port] [destination operator port] —For TCP, UDP, or both. You can optionally specify ports for the source, destination, or both. You can specify the port by name or number. The operator can be one of the following:
        - lt — less than.
        - gt — greater than.
        - eq — equal to.
        - neq — not equal to.
        - range — an inclusive range of values. When you use this operator, specify two port numbers, for example, range 100 200.
    - service-object object object_name—The name of an existing service object.
    - group-object object_group_name—The name of an existing service object group.
    - description (Optional) Add a description: description string

#####object-group icmp-typ //ASA72
https://www.cisco.com/c/en/us/td/docs/security/asa/asa72/configuration/guide/conf_gd/traffic.html#wp1042252
```bash
object-group icmp-type grp_id
 icmp-object icmp_type
```
- object-group icmp-type
    - icmp-object
    - description (Optional) Add a description: description string

#####Protocol Object Group //ASA72
https://www.cisco.com/c/en/us/td/docs/security/asa/asa72/configuration/guide/conf_gd/traffic.html#wp1042249
```bash
object-group protocol tcp_udp_icmp
 protocol-object tcp
 protocol-object udp
 protocol-object icmp
```
- object-group protocol
    - protocol-object {1 to 254 | ip | keyword } - The protocol is the numeric identifier of the specific IP protocol (1 to 254) or a keyword identifier (for example, icmp, tcp, or udp). To include all IP protocols, use the keyword ip. For a list of protocols you can specify, see the "Protocols and Applications" section on page D-11.
    https://www.cisco.com/c/en/us/td/docs/security/asa/asa72/configuration/guide/conf_gd/ports.html#wpxref39421
    - description (Optional) Add a description: description string





###Object-group user
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-objects.html#ID-2122-00000208
```bash
object-group user admins
 user EXAMPLE\admin
 user-group EXAMPLE\\managers
 group-object local-admins
```
- object-group user
    - user [domain_NETBIOS_name\]username—A username. If there is a space in the domain name or username, you must enclose the domain name and user name in quotation marks. The domain name can be LOCAL (for users defined in the local database) or an Active Directory (AD) domain name as specified in the user -identity domain domain_NetBIOS_name aaa -server aaa_server_group_tag command. When adding users defined in an AD domain, the user_name must be the Active Directory sAMAccountName, which is unique, instead of the common name (cn), which might not be unique. If you do not specify a domain name, the default is used, which is either LOCAL or the one defined on the user-identity default-domain command.
    - user-group [domain_NETBIOS_name\\]username—A user group. If there is a space in the domain name or group name, you must enclose the domain name and group name in quotation marks. Note the double \\ that separates the domain and group names.
    - group-object object_group_name—The name of an existing user object group.

###predefined Services
- check JSON file: [service_predefined.json](/parser/service_predefined.json)

###Time Range
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-objects.html#ID-2122-000002ca
```bash
time-range contract-A-access
 absolute end 12:00 1 September 2025
 periodic weekdays 08:00 to 17:00
 periodic Monday Wednesday Friday 18:00 to 20:00
 periodic Tuesday Thursday 17:30 to 18:30
```
- Create the time range: time-range name	
- (Optional.) Add a start or end time (or both) to the time range.
absolute [start time date] [end time date]
If you do not specify a start time, the default start time is now.

   - The date is in the format day month year; for example, 1 January 2014.	
- (Optional.) Add recurring time periods.
periodic days-of-the-week time to [days-of-the-week] time
You can specify the following values for days-of-the-week. Note that you can specify a second day of the week only if you specify a single day for the first argument.
   - Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, or Sunday. You can specify more than one of these, separated by spaces, for the first days-of-the-week argument.
   - daily
   - weekdays
   - weekend

- The time is in the 24-hour format hh:mm. For example, 8:00 is 8:00 a.m. and 20:00 is 8:00 p.m.
You can repeat this command to configure more than one recurring period.

PAN-OS translation:
- if no start set -> 1970/01/01@00:00
- if no end set -> 2999/12/31@23:59

Not handleable for PAN-OS:
- absolute and periodic in same time-range; PAN-OS can only handle absolute or periodic
```bash
 absolute start 09:56 11 June 2015 end 09:56 15 June 2015
 periodic Monday Thursday 0:00 to 23:59
```

###network

#####interfaces
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/general/asa-94-general-config/interface-basic.html
- "/^interface /i"
- "/ethernet/i"
    - "/shutdown/i"
    - "/description /i"
    - "/nameif /i"
    - "/ip address /i"
    - "/ipv6 address /i"
    - "/ link-local/"
    - "/ vlan /"

###static routes
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/general/asa-94-general-config/route-overview.html
- "/^route /i"
- "/^ipv6 route /i"



###NAT
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/nat-basics.html
#####Examples
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/nat-reference.html

#####objects NAT
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/nat-reference.html#ID-2091-00000007

- "/^nat /i"
    - "/ after-object /"
    - "/ after-auto /"
    - "/^object network/i"
    
#####Twice Nat - before / after
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/nat-reference.html#ID-2091-00000161

- "/^nat \(/"
    - "/source static/"
    - "/source dynamic/"
    - "/destination static/"




###Cisco Security Rules - ACL
#####Access Control Lists
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-acls.html
#####Access Rules
https://www.cisco.com/c/en/us/td/docs/security/asa/asa94/config-guides/cli/firewall/asa-94-firewall-config/access-rules.html

- "/^access-group /i"
- "/crypto map /"

- "/^access-list /i"
- "/^ipv6 access-list /i"

- 'remark'
- 'advanced'
- 'standard'
- 'extended'

- 'ethertype' // layer2 rules are not supported

#####action
- 'permit'
- 'trust'
- 'deny'

#####Protocol
- 'object-group'
- 'object'
- 'ip'
- 'tcp'
- 'udp'
- 'icmp'
- 'ah'
- 'icmp6'
- 'gre'
- 'esp'
- 'igrp'
- 'ipinip'
- 'nos'
- 'pcp'
- 'eigrp'
- 'igmp'
- 'ipsec'
- 'ospf'
- 'pim'
- 'pptp'
- 'sctp'
- 'snp'
- '/^[0-9]{1,3}$/'

#####other fields
- 'webtype' //ignore
- 'ethertype' //ignore

- 'ifc'
- 'rule-id'
- 'any'
- 'any4'
- 'any6'
- 'object'
- 'object-group'
- 'host'
- 'interface'
- 'inactive'
- 'user-group'
- 'user'
- 'object-group-user'
//cases for SERVICES
- 'neq'
- 'eq'
- 'lt
- 'gt'
- 'range'

- 'echo'
- 'echo-reply'
- 'source-quench'
- 'traceroute'
- 'unreachable'
- 'log'
- 'disable'
- 'warnings'
- 'default'
- 'debugging'
- 'time-exceeded'
- 'notfications'
- 'critical'
- 'event-log'
- 'flwo-start'
- 'interval'
- 'time-range'


###Migration Cisco -> PAN-OS

###Improvement for migrated Cisco to PAN-OS XML config
- use PAN-OS NATPolicy [DNAT] information to fix SecurityPolicy destination,service