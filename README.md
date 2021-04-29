pan-os-php
================


PAN-OS-PHP is a PHP library aimed at making PANOS config changes easy (and XML free ;), maintainable and allowing complex scenarios like rule merging, unused object tracking, conversion of checkpoint exclusion groups, massive rule editing, AppID conversion … . It will work seamlessly on local config file or API.

**Homepage** : download latest sources on [GitHub](https://github.com/PaloAltoNetworks/pan-os-php). Windows package with PHP binaries here: [dev.zip] TBD (https://github.com/PaloAltoNetworks/pan-os-php-windows-tool/raw/master/dev.zip)

**Requirements** : PHP 7.1 with curl module

**Usage**: include the file lib/pan_php_framework.php in your own script to load the necessary classes.

File tree:
* **/lib/** contains library files source code
* **/utils/** contains ready to run scripts, more information in [utils/readme.txt](/utils)
* **/doc/index.html**  has all classes documentations
* **/example-xxx.php** are examples about using this library

Docker build
============

* **MacOS** : [run on MacOS terminal]
	```bash
	cd [pan-os-php Root folder]
	docker build -t pan-os-php .
	cd [go to the Folder you like to share with the Container]
	docker run -v ${PWD}:/share -it pan-os-php /usr/local/bin/bash
	```

* **WINDOWS** : [run on Windows terminal]
	```bash
	cd [pan-os-php Root folder]
	docker build -t pan-os-php .
	cd [go to the Folder you like to share with the Container]
	docker run -v %CD%:/share -it pan-os-php /usr/local/bin/bash
	```
