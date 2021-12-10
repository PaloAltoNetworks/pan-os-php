PAN-OS-PHP 'utils' directory contains scripts which can run out of the box and are based on PAN-OS-PHP classes.

All available UTIL scripts can be run against an PAN-OS XML configuration offline file or directly against PAN-OS XML API.

Index of scripts:
====
All these production UTIL script can now be triggered by using: (bash-autocomplition is available and must be installed)
**pan-os-php type=XYZ**
-----

- **address-edit.php** : to make changes to address/group, you can use filters to make changes only to objects of
 interest. Makes it easy to delete unused objects for example or replace. Use argument 'help' for details and usage.

- **address-merger.php** : merge address objects together. Useful when you want to do cleaning or reduce number of objects
because of firewall capacity problems for example. A collection of filters and algorithms will make this tool very flexible
 to bring you a tailored process for your customer.
 
- **addressgroup-merger.php** : merge address groups together. Useful when you want to do cleaning or reduce number of objects
 because of firewall capacity problems for example. A collection of filters and algorithms will make this tool very flexible
 to bring you a tailored process for your customer.

- **appid-enabler.php** : display and if needed enable all previous disabled PAN-OS app-id on a FW or via Panorama on all connected FWs

- **bpa-generator.php** : script to easily use Palo Alto Networks BPA API

- **csv-import.php** : import address / service / SecurityRules defined in CSV format

- **device-edit.php** : display, create e.g. VSYS, DeviceGroup, Templates, TemplateStack, Container, DeviceCloud

- **download_predefined.php** : possible to run against PAN-OS Firewall API to download and update the predefined.xml (e.g. appid) used offline in this framework

- **key-manager.php** : display, add, delete PAN-OS API keys stored in .panconfkeystore which are used for PAN-OS API authentication

- **override-finder.php** : find and display which parts of a firewall configuration are currently overriding
 the Template pushed by Panorama.

- **pan-diff.php** : display the XML difference of two PAN-OS XML config files

- **panos-xml-issue-detector** : display and if possible fix XML issues. example fix address-group with same member object names

- **panXML_op_JSON.php** : send PAN-OS operational commands via XML API - XML response is transformed into JSON

- **register-ip-mgr.php** :

- **rules-edit.php** : mass rule editor for PANOS and Panorama, it can work on backup files on your hard drive or with
 API. You can filter rules to modify with a query and then apply changes to all selected rules. Use 'php rules-edit.php
  help' for usage details.

- **rule-merger.php** : script to merge similar rules together. Various options to define common criteria, adjacency
 limits, stop after action deny aso. are also included.

- **rules-stats.php** : display object counters of a PAN-OS configuration 

- **schedule-edit.php** : to make changes to schedule objects. , you can use filters to make changes only to objects of interest. Makes it easy to delete unused objects for example.

- **securityprofile-edit.php** : to make changes to security-profile objects.

- **service-edit.php** : to make changes to service/group, you can use filters to make changes only to objects of
 interest. Makes it easy to delete unused objects for example.
 
- **service-merger.php** : merge service objects together. Useful when you want to clean or reduce number of objects
because of firewall capacity problems for example. A collection of filters and algorithms will make this tool very flexible
to bring you a tailored process for your customer.

- **servicegroup-merger.php** : merge service groups together. Useful when you want to clean or reduce number of objects
 because of firewall capacity problems for example. A collection of filters and algorithms will make this tool very flexible
 to bring you a tailored process for your customer.

- **tag-edit.php** : to make changes to tags, you can use filters to make changes only to objects of
 interest.

- **tag-merger.php** : merge tag objects together. Useful when you want to clean or reduce number of objects
                       because of firewall capacity problems for example.

- **upload-config.php** : tool for easy upload/download of configuration on a PANOS device. ie: if you want to
 replicate a config from a device to another but just keep management IP address. Use 'help' argument for more details.

- **userid-mgr.php** : allows you to register/unregister/dump UserID record through PANOS API

- **zone-edit.php** :


UTIL scripts under development
----------------------

- **checkpoint-exclude.php** : calculate a static value for checkpoint-exlusion groups out of the migration tool.
 Give it the name of the group and it will consider that member #1 is the 'include' group while member #2 is the
  'exclude' group and make numeric calculations to replace all members by a set of IP-ranges.

- **commit-config.php** : working against a Firewall, for full commit

- **download_config_all.php** : run against Panorama API, and download config from all Panorama connected Firewalls plus the Panorama config

- **grp-static-to-dynamic.php** : converts a static group to a dynamic group by tagging its objects and replacing the
 group members by a query on that tag.
   
- **ike.php** : display IKE / IPsec / IKE profiles / IPsec profiles available in a PAN-OS XML configuration file.

- **migration_playbook.php** : thoughts about calling multiple UTIL script to automate the full task

- **pan_get_user_info.php** : display Panorama or Firewall configured system user

- **pan_license.php** : Download Palo Alto Networks License for your device or full environment

- **pan_software_download_preparation.php** : AirGap preparation for script license.php / pan_software_downloader.php

- **pan_software_downloader.php** : Download Palo Alto Networks software / dynamic content for your device or full environment

- **reset-config.php** : very usefull for a LAB devices to reset configuration of objects and interfaces

- **sendGARP.php** : is preparing all IPs from Interface / DNAT-Rules/ SNAT-Rules to send 'test arp gratuitous ip XYZ' via PAN-OS API

- **software-remove.php** : is removing old Palo Alto Networks software / dynamic content to cleanup the device disk

- **spiffy.php** : extract Fawkes XML configuration, from a spiffy XML configuration file 

- **ssh_connector.php** : this script use SSH to connect to 3rd party vendor devices or also Palo Alto Networks to download the FW configuration which then can be used by Expedition-Converter for migration to a valid PAN-OS XML configuration file.

- **system-log.php** : display and filter of device system log  - please use 'shadow-json' for automation usage

- **traffic-log.php** : display and filter of traffic log - please use 'shadow-json' for automation usage
