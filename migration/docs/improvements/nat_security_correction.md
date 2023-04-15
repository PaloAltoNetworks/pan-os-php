## migrated configuration improvments

general explanation

### NAT / Security Policy
PAN-OS handle the destination NAT (DNAT) differently compare to other vendors
- [DNAT example](https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/networking/nat/nat-configuration-examples/destination-nat-exampleone-to-one-mapping.html)
  - from zone: untrust
  - to zone: untrust
  - SRC: ANY
  - DST: webserver-public
  - SNAT: ---
  - DNAT: webserver-private
- Security Policy
  - from zone: untrust
  - to zone: DMZ
  - SRC: ANY
  - DST: webserver-public

specifications:
- secPolicy:
  - to zone: **post-NAT**
  - DST: **pre-NAT**
### solution for DNAT / BidirNAT
- compare NAT and SecurityPolicy
  - start with NAT - 

  
### Link
https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/networking/nat/source-nat-and-destination-nat/destination-nat
