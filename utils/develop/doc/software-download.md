Process for downloading PAN-OS software / dynamic content in a secure environment with PAN-OS-PHP
===

Requirements:
---
internal and external Server with PAN-OS-PHP version 2.0.26 prepared
internal Server has access to Panorama mgmt device
external Server has access to Internet

https://github.com/PaloAltoNetworks/pan-os-php



Steps for downloading PAN-OS Software:
---
1) internal Server:
---
 - go to folder **[pan-os-php_root]/utils/develop**
 - run: **php ​​pan_software_download_preparation.php in=api://Panorama_MGMT-IP** [script](../pan_software_download_preparation.php)
   - script is asking for username / password and store it in local system User folder file “.panconfkeystore” for future usage
   - script is creating XML file: [pan-os-php_root]/utils/develop/software/software_downloader_devices.txt
 - copy the created file to external Server in folder: [pan-os-php_root]/utils/develop/software

2) external Server:
---
 - go to folder [pan-os-php_root]/utils/develop
 - check if file is available **software/software_downloader_devices.txt**
 - check if additional settings are needed:
    - vi pan_software-downloader.php +38
    - $filter['All'] = false;//[=false => download only latest]
    - $filter['SWVersionInfo'] = true;
    - $filter['SignatureVersionInfo'] = true;
    - $filter['only_releaseNotes'] = false;
 - run: **php pan_software_downloader.php** [script](../pan_software_downloader.php)
    - this script is downloading all available software / content update based on the filter settings in folder **[pan-os-php_root]/utils/develop/software**

3) internal Server:
---
 - fetch software and dynamic content update from **external server** from folder: [pan-os-php_root]/utils/develop/software/*



Missing stuff:
---
step 3 Internal Server: 
there is no script yet available to upload and install the newest downloaded software / dynamic content version to Panorama, with 
