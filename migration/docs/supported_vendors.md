## Supported Vendors

## Cisco:
#### - [CiscoASA](vendors/ciscoasa.md)
- vendor specific:
  - replace DM_INLINE address-/service-group by members
  - bidir NAT rules, disable bidir if not possible (e.g. SRC IP has addressgroup) 
- Cisco Firepower
  - NO zone calculation
  - rule merging
  - only Cisco ASA format is supported

- Firepower (SourceFire [SF]) some script is available on [SPRING](https://spring.paloaltonetworks.com/glastra/fmc) from Gerardo Lastra (PS)
    - migration of SF L4 configuration; export process only support by SW version > FMC 5.4
    - export process describe how to download tar.gz.sfo file
      - Initial file is a .tar.gz with .sfo extention
      - rename to .tar.gz
      - script extract to .gz -> extract to export folder -> object.txt and .pol file -> rename .pol to .zip
        - export/CSMExportFile.pol -> export/CSMExportFile.zip
      - zip extract to config folder which include .obj files
        - object extraction (config/policy_data_objects_2.obj)
        - rule extraction (config/policy_data_policies_3.obj)
         
        
        
#### - [CiscoISR](vendors/ciscoisr.md)
#### - [CiscoIOS](vendors/ciscoios.md)

## CheckPoint:
#### - [CP lt R80](vendors/cp_lt_r80.md)
#### - [CP geq R80](vendors/cp_geq_r80.md)

## Juniper
#### - [JunOS](vendors/junos.md)
#### - [ScreenOS](vendors/screenos.md)

## Forcepoint (only the former config below)
#### - [Sidewinder](vendors/sidewinder.md)
#### - [Stonesoft](vendors/stonesoft.md)

## [Fortinet](vendors/fortinet.md)
## [Sonicwall](vendors/sonicwall.md)
## [Sophos](vendors/sophos.md)
## [Huawei](vendors/huawei.md)
## [Pfsense](vendors/pfsense.md) (only partial)