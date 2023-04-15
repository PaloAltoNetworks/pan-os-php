## Migration 

In general the following objects migrate from 3rd party vendor config to PAN-OS XML:
- address (both IPv4/IPv6)
  - ip-netmask
  - range
  - fqdn
- addressgroup
- service
  - add 3rd party vendor predefined services
  - tcp
  - udp
  - none tcp/udp service protocols are migrated as "tmp-XYZ" service-objects, these objects are tried to migrate to PAN-OS App-id 
- servicegroup
- L3 interface
  - ethernet
  - aggreagate-ethernet (Juniper JunOS)
  - subinterface for ethernet and aggreagate-ethernet (Juniper JunOS)
- static routing
  - destination
  - interface
  - next-hope ip-address
- security policy
- nat policy 

### partial supported on vendor configs
- IKE gateway (phase1)
  - IKEv1
- IPsec tunnel (phase2)
- use dynamic route information and migrate into static route only for PAN-OS zone calculation. These static routes are removed at the end.
---

Additional Improvements
---
To fit to PAN-OS config need, the following additional improvement is done:
- Zone calculation, used by:
  - SRC / DST mapping on policy
  - interface
  - static route
- pre-/post- NAT-IP/Zone validation and correction on Security Policies (NOT implemented yet)
- interface renaming to fit PAN-OS naming convention 
- if address/addressgroup objects with two characters are available, rename these to avoid conflict with PAN-OS predefined Region objects
- cleanup unused predefined services
---

JSON files for customise migration
---
### create PAN-OS custom ICMP App-id
[custom_appid_icmp.json]()
This file defines which custom App-id based on icmptype/icmpCode are created and can be used for PAN-OS app-id migration. 
### PAN-OS App-id migration
[appid_migration.json]()
is used to define which former generated "tmp-XYZ" service object is migrated into which single/multiple PAN-OS app-id.
###  Service predefined - 3rd party vendor
[service_predefined.json](/parser/service_predefined.json)
###  disable migration (improvement) feature
it is possible for testing purpose to set migration or migration improvement feature to false
[migration_features.json](/parser/migration_features.json)

---