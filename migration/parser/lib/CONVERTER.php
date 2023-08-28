<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());

require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";

class CONVERTER extends UTIL
{
    public $debug = FALSE;
    public $print = FALSE;
    public $configFile = null;

    public $data = null;

    public $reduceXML = FALSE;

    public $vendor = null;

    private $myParserClass = '';

    public $appsToMigrate = array();
    public $routetable = "";
    public $mapping = null;

    public $mainfolder = "/tmp/expconverter";
    public $newfolder = null;
    public $folder_path = "";

    public $vendor_array = array();

    public $sub = null;
    public $template = null;
    public $template_vsys = null;

    public $interfaceRenaming = false;
    public $zoneCalculation = false;
    public $appidMigration = false;
    public $cleanupUnusedPredefinedService = false;
    public $validateAddressNameToRegionName = false;
    public $validateNatBidir = false;



    public function supportedVendors()
    {
        $this->vendor_array['ciscoasa'] = "CISCO/CISCO_parser.php";
        $this->vendor_array['pfsense'] = "PFSENSE/PFSENSE_parser.php";
        $this->vendor_array['sophos'] = "SOPHOS/SOPHOS_parser.php";
        $this->vendor_array['sonicwall'] = "SONICWALL/SONICWALL_parser.php";
        $this->vendor_array['netscreen'] = "SCREENOS/SCREENOS_parser.php";
        $this->vendor_array['fortinet'] = "FORTINET/FORTINET_parser.php";
        $this->vendor_array['srx'] = "SRX/SRX_parser.php";
        $this->vendor_array['cp-r80'] = "CP_R80/CP_R80.php";
        $this->vendor_array['cp'] = "CP/CP.php";
        $this->vendor_array['cp-beta'] = "CP/develop/CPnew.php";
        $this->vendor_array['huawei'] = "HUAWEI/HUAWEI_parser.php";
        $this->vendor_array['stonesoft'] = "STONESOFT/STONESOFT_parser.php";
        $this->vendor_array['sidewinder'] = "SIDEWINDER/SIDEWINDER_parser.php";

        //THIS is still needed; migration needed of ciscoISR and ciscoSWITCH to class based
        $this->vendor_array['ciscoswitch'] = "cisco_switch_acl/acl.php";
        $this->vendor_array['ciscoisr'] = "cisco_isr/isr_acl.php";
    }


    public function utilStart()
    {
        PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );
        $this->initial();
        $this->main();
    }

    public function supportedArguments()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file. Basic PAN-OS config, the migrated 3rd party config is merged with', 'argDesc' => '[filename]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after migration. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['file'] = array('niceName' => 'file', 'shortHelp' => 'original 3rd party vendor config file. ie: file=cisco_config-export.txt', 'argDesc' => '[filename]');
        $this->supportedArguments['vendor'] = array('niceName' => 'vendor', 'shortHelp' => 'vendor name ie: vendor=ciscoasa', 'argDesc' => '[vendor]');
        $this->supportedArguments['print'] = array('niceName' => 'print', 'shortHelp' => 'display migration information',);
        $this->supportedArguments['debug'] = array('niceName' => 'debug', 'shortHelp' => 'display debug migration information');
        $this->supportedArguments['expedition'] = array('niceName' => 'expedition', 'shortHelp' => 'only used if called from Expedition Tool');
        $this->supportedArguments['routetable'] = array('niceName' => 'RouteTable', 'shortHelp' => 'Routing table of: CheckPoint FW ["netstat -nr" or "show route all"] / Cisco [show routes] - create static routing for dynamic routes to calculate Zones', 'argDesc' => '[filename]');
        $this->supportedArguments['mapping'] = array('niceName' => 'Mapping', 'shortHelp' => 'e.g. STONESOFT -> mapping between FW-device and FWPOLICY; CP -> ');
        $this->supportedArguments['shadow-reducexml'] = array('niceName' => 'shadow-reduceXML', 'shortHelp' => 'remove NewLine and blank from migrated PAN-OS XML file');
        $this->supportedArguments['stats'] = array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
        $this->supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS or DG. By default location=vsys1 for PANOS', 'argDesc' => '[sub1]');
    }

    function display_usage_and_exit($shortMessage = FALSE, $warningString = '')
    {
        global $argv;
        global $vendor_array;


        $this->supportedVendors();

        print "\n";
        print PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " [in=inputfile.xml] out=outputfile.xml file=vendor_origfile vendor=ciscoasa \n";

        echo "          supported vendors: ";
        foreach( $this->vendor_array as $key => $vendor )
        {
            print " - " . $key . " ";
        }
        print "\n";

        if( !$shortMessage )
        {
            echo PH::boldText("\nListing available arguments\n\n");

            ksort($this->supportedArguments);
            foreach( $this->supportedArguments as &$arg )
            {
                echo " - " . PH::boldText($arg['niceName']);
                if( isset($arg['argDesc']) )
                    echo '=' . $arg['argDesc'];
                //."=";
                if( isset($arg['shortHelp']) )
                    echo "\n     " . $arg['shortHelp'];
                echo "\n\n";
            }

            echo "\n\n";
        }
        if( !empty($warningString) )
            mwarning( $warningString, null, false );

        exit(1);
    }

    private function vendor_require()
    {
        //DEFINE VENDOR specific RECUIRE
        if( $this->vendor == "ciscoasa" )
        {
            require_once(dirname(__FILE__)."/../CISCO/CISCOASA.php");
            $this->myParserClass = "CISCOASA";
        }
        elseif( $this->vendor == "ciscoisr" )
        {
            require_once(dirname(__FILE__)."/../CISCOISR/CISCOISR.php");
            $this->myParserClass = "CISCOISR";
        }
        elseif( $this->vendor == "ciscoswitch" )
        {
            require_once(dirname(__FILE__)."/../CISCOSWITCH/CISCOSWITCH.php");
            $this->myParserClass = "CISCOSWITCH";
        }
        elseif( $this->vendor == "netscreen" )
        {
            require_once(dirname(__FILE__)."/../SCREENOS/SCREENOS.php");
            $this->myParserClass = "SCREENOS";
        }
        elseif( $this->vendor == "fortinet" )
        {
            require_once(dirname(__FILE__)."/../FORTINET/FORTINET.php");
            $this->myParserClass = "FORTINET";
        }

        elseif( $this->vendor == "pfsense" )
        {
            require_once(dirname(__FILE__)."/../PFSENSE/PFSENSE.php");
            $this->myParserClass = "PFSENSE";
        }
        elseif( $this->vendor == "sonicwall" )
        {
            require_once(dirname(__FILE__)."/../SONICWALL/SONICWALL.php");
            $this->myParserClass = "SONICWALL";
        }
        elseif( $this->vendor == "sophos" )
        {
            require_once(dirname(__FILE__)."/../SOPHOS/SOPHOS.php");
            $this->myParserClass = "SOPHOS";
        }
        elseif( $this->vendor == "srx" )
        {
            require_once(dirname(__FILE__)."/../SRX/SRX.php");
            $this->myParserClass = "SRX";
        }
        elseif( $this->vendor == "cp-r80" )
        {
            require_once(dirname(__FILE__)."/../CP_R80/CP_R80.php");
            $this->myParserClass = "CP_R80";
        }
        elseif( $this->vendor == "cp" )
        {
            require_once(dirname(__FILE__)."/../CP/CP.php");
            $this->myParserClass = "CP";
        }
        elseif( $this->vendor == "cp-beta" )
        {
            require_once(dirname(__FILE__)."/../CP/develop/CPnew.php");
            $this->myParserClass = "CPnew";
        }
        elseif( $this->vendor == "huawei" )
        {
            require_once(dirname(__FILE__)."/../HUAWEI/HUAWEI.php");
            $this->myParserClass = "HUAWEI";
        }
        elseif( $this->vendor == "stonesoft" )
        {
            require_once(dirname(__FILE__)."/../STONESOFT/STONESOFT.php");
            $this->myParserClass = "STONESOFT";
        }
        elseif( $this->vendor == "sidewinder" )
        {
            require_once(dirname(__FILE__)."/../SIDEWINDER/SIDEWINDER.php");
            $this->myParserClass = "SIDEWINDER";
        }
        else
            derr("VENDOR: " . $this->vendor . " is not supported yet");
    }


    public function initial()
    {
        #PH::$args = array();
        PH::processCliArgs();
        $this->supportedArguments();


        if( isset(PH::$args['help']) )
        {
            $pos = array_search('help', PH::$argv);

            if( $pos === FALSE )
                $this->display_usage_and_exit(FALSE);

            $keys = array_keys(PH::$argv);

            if( $pos == end($keys) )
                $this->display_usage_and_exit(FALSE);

            $this->display_usage_and_exit(FALSE);

            print "\n\n";

            exit(0);
        }


        if( isset(PH::$args['out']) )
        {
            $this->configOutput = PH::$args['out'];
            $finalOUTPUT = PH::$args['out'];
        }
        elseif( !isset(PH::$args['expedition']) )
            $this->display_error_usage_exit('"out" is missing from arguments');

        if( isset(PH::$args['file']) )
        {
            $this->newfolder = $this->mainfolder . "/".uniqid();
            if( !file_exists($this->newfolder) )
                mkdir($this->newfolder, 0700, TRUE);


            if( isset(PH::$args['expedition']) )
            {
                if( !isset(PH::$args['testing']) )
                    $this->mainfolder = "/home/userSpace/tmp";
                else
                    $this->mainfolder = "/tmp/expapi/tmp";

                if( !file_exists($this->mainfolder) )
                    mkdir($this->mainfolder, 0700, TRUE);

                if( $this->newfolder !=  null && file_exists($this->newfolder) )
                    $this->delete_directory($this->newfolder);

                $this->newfolder = $this->mainfolder . "/".uniqid();
                if( !file_exists($this->newfolder) )
                    mkdir($this->newfolder, 0700, TRUE);



                $config_filename = PH::$args['file'];
                //Todo: check if file is ZIP file;
                if( strpos($config_filename, ".zip") === FALSE && strpos($config_filename, ".tgz") === FALSE )
                {
                    derr("expedition argument is used, but there is no ZIP file provide in file argument");
                }
                else
                {
                    $srcfile = $config_filename;
                    $destfile = $this->newfolder . '/'.uniqid().'.zip';

                    if( !copy($srcfile, $destfile) )
                        echo "File cannot be copied! \n";
                    else
                    {
                        #echo "File has been copied!\n";
                    }

                    exec('unzip -o ' . $destfile . " -d " . $this->newfolder);
                }


                $this->folder_path = $this->newfolder . "/";
                $config_path = "mapping.json";

                if( !file_exists($this->folder_path . $config_path) )
                {
                    derr($config_path . " not found");
                }
                else
                {
                    $string = file_get_contents($this->folder_path . $config_path);
                    $json_a = json_decode($string, TRUE);

                    
                    if( isset( $json_a['baseConfig'] ) )
                        print "BASECONFIG: " . $json_a['baseConfig'] . "\n"; // wrong in JSON file, must be .XML

                    if( isset( $json_a['version'] ) )
                        print "VERSION: " . $json_a['version'] . "\n";

                    $panorama_config = FALSE;
                    $new_in = "";

                    $config_counter = count($json_a['configs']);
                    print "config COUNTER: " . $config_counter . "\n";

                    $finalOUTPUT = $json_a['out'];

                    foreach( $json_a['configs'] as $key => $config )
                    {
                        print "VENDOR: '" . $config['vendor'] . "'\n";

                        print_r($config['mapping']);

                        if( isset( $config['object'] ) )
                            print "object: '" . $config['object'] . "'\n";
                        if( isset( $config['policy'] ) )
                            print "policy: '" . $config['policy'] . "'\n";
                        if( isset( $config['rulebase'] ) )
                            print "rulebase: '" . $config['rulebase'] . "'\n";

                        if( isset( $config['routes'] ) )
                            print_r($config['routes']);

                        if( isset( $config['name'] ) )
                            print "name: '" . $config['name'] . "'\n";

                        print "############################################\n";


                        PH::$args = array();
                        PH::$argv = array();
                        PH::$args['vendor'] = $config['vendor'];

                        #PH::$args['out'] = $arg_array['out'];
                        PH::$args['out'] = "/tmp/" . $config['vendor'] . ".xml";

                        if( $key == 0 )
                            PH::$args['in'] = $this->folder_path . $json_a['baseConfig'];
                        else
                            PH::$args['in'] = $new_in;

                        if( PH::$args['vendor'] == "cp" )
                        {
                            $folder_path_array = explode( "/", $config['policy']);
                            $folder_path = $folder_path_array[0];

                            PH::$args['file'] = $this->folder_path . $folder_path;

                            if( isset($config['routes']) && isset($config['routes'][0]) )
                                PH::$args['routetable'] = $this->folder_path . $config['routes'][0];
                        }
                        else
                        {
                            PH::$args['file'] = $this->folder_path . $config['policy'];

                            if( isset($config['routes']) && isset($config['routes'][0]) )
                            {
                                if( isset($config['routes'][0]) and $config['routes'][0] != "" and !isset($config['routes'][1]) )
                                    PH::$args['routetable'] = $this->folder_path . $config['routes'][0];
                            }
                        }

                        PH::$args['print'] = '1';
                        PH::$args['debug'] = '1';

                        PH::$args['location'] = $config['name'];
                        PH::$args['template'] = $config['name'];

                        if( isset($arg_array['ruleorder']) )
                            PH::$args['ruleorder'] = $arg_array['ruleorder'];

                        $converter = new CONVERTER();
                        $converter->newfolder = $this->newfolder;

                        $new_in = PH::$args['out'];
                    }

                    //all migrations are done
                    //copy last PAN XML config to finalOUTPUT
                    copy($new_in, $finalOUTPUT);
                    print "FINAL PAN-OS XML is copied to: ".$finalOUTPUT."\n";
                    $converter->deleteDirectory();
                    exit("all migrations DONE.\nThis part was called from Expedition-API\n\n");
                }
            }
            else
                $this->configFile = PH::$args['file'];
        }

        if( isset(PH::$args['vendor']) )
        {
            $this->vendor = strtolower(PH::$args['vendor']);
        }
        else
            $this->display_error_usage_exit('"vendor" is missing from arguments');

        if( isset(PH::$args['in']) )
            $this->configInput = PH::$args['in'];
        elseif( isset(PH::$args['template']) )
            $this->configInput = __DIR__ . "/../panorama_baseconfig.xml";
        else
            $this->configInput = __DIR__ . "/../panos_baseconfig.xml";

        $this->configInput = PH::processIOMethod($this->configInput, TRUE);



        if( isset(PH::$args['routetable']) )
        {
            $this->routetable = PH::$args['routetable'];
        }

        if( isset(PH::$args['mapping']) )
        {
            $this->mapping = PH::$args['mapping'];
        }

        if( isset(PH::$args['debug']) )
        {
            $this->debug = TRUE;
        }

        if( isset(PH::$args['print']) )
        {
            $this->print = TRUE;
        }


        if( isset(PH::$args['reducexml']) )
        {
            $this->reduceXML = TRUE;
        }

        if( isset(PH::$args['testing']) )
            unset( PH::$args['expedition'] );

        if( isset(PH::$args['expedition']) )
        {
            $this->expedition = PH::$args['expedition'];
            $tmp_expedition = explode(",", $this->expedition);

            if( isset($tmp_expedition[0]) && isset($tmp_expedition[1]) && isset($tmp_expedition[2]) && isset($tmp_expedition[3]) )
            {
                $this->expedition_db_ip = $tmp_expedition[0];
                $this->expedition_db_user = $tmp_expedition[1];
                $this->expedition_db_pw = $tmp_expedition[2];
                $this->taskId = $tmp_expedition[3];
            }
            else
            {
                $this->display_error_usage_exit('"expedition" argument has an invalid value. This argument can be only used directly from Expedition Tool');
            }
            unset($tmp_expedition);
        }


        $this->migrationImprovementFeatures();

    }


    public function global_start()
    {
        $this->utilLogger();

        $this->log->info("start PARSER: " . $this->vendor . " | " . implode(", ", PH::$args));

        $this->xmlDoc = new DOMDocument();
        if( !$this->xmlDoc->load($this->configInput['filename']) )
            derr("error while reading xml config file");


        $this->determineConfigType();

        $this->location_provided();

        $this->load_config();

        $this->loadStart();
        print "\n\n";
    }

    public function location_provided()
    {
        if( !isset(PH::$args['location']) )
        {
            if( $this->configType == 'panos' )
            {
                print " - No 'location' provided so using default ='vsys1'\n";
                $this->objectsLocation = 'vsys1';

                //search for vsys????
            }
            elseif( $this->configType == 'panorama' )
            {
                print " - No 'location' provided so using default ='DG_converter1'\n";
                $this->objectsLocation = 'DG_converter1';
                $this->objectsLocationCounter = 1;
            }
        }
        else
        {
            print " - 'location' provided using: ".PH::$args['location']."\n";

            if( $this->configType == 'panos' )
            {
                $loc_array =  explode( "vsys", PH::$args['location'] );
                if( $loc_array[0] != "" || !is_numeric( $loc_array[1] ) || $loc_array[1] >10  )
                    derr( "not possible to provide location: '".PH::$args['location']."' on a PAN-OS FW config. e.g. bring in 'location=vsys2' [max. vsys10]" );

                $this->objectsLocationCounter = 1;
            }
            else
                $this->objectsLocationCounter = 0;

            $this->objectsLocation = PH::$args['location'];

        }

        if( isset(PH::$args['template']) )
        {
            if( $this->configType == 'panos' )
            {
                unset( PH::$args['template'] );
                #derr( "'template: ".PH::$args['template']."' provided but using PANOS config; please remove argument template=\n");
            }
            elseif( $this->configType == 'panorama' )
            {
                print " - 'template' provided using: ".PH::$args['template']."\n";
                $this->templateName = PH::$args['template'];
                $this->templateNameCounter = 0;
            }

        }
        else
        {
            if( $this->configType == 'panorama' )
            {
                print " - No 'template' provided so using default ='TEMP_converter1'\n";
                $this->templateName = 'TEMP_converter1';
                $this->templateNameCounter = 1;
            }
        }
    }

    public function getDeviceConfig( &$tmp_sub, &$tmp_template, &$tmp_template_vsys)
    {
        //-------------------------------------------------------------------------------------------------------
        /** @var DeviceGroup|VirtualSystem $sub */
        /** @var PANConf|PanoramaConf $pan */
        /** @var PANConf|Template $template */
        if( $this->configType == "panos" )
        {
            print "find Location: ".$this->objectsLocation."\n";
            $this->sub = $this->pan->findVirtualSystem( $this->objectsLocation );

            $vsysID = explode( "vsys", $this->objectsLocation )[1];
            if( $this->sub == null )
                $this->sub = $this->pan->createVirtualSystem( $vsysID );
            else
            {
                //Todo: check if default vsys1 is empty
                #print "count addressstore: ".count( $sub->addressStore->all() )."\n";
                #print "count servicestore: ".count( $sub->serviceStore->all() )."\n";
                #print "count sercuritystore: ".count( $sub->securityRules->rules() )."\n";

                if(  count( $this->sub->addressStore->all() ) == 0 && count( $this->sub->serviceStore->all() ) == 0 && count( $this->sub->securityRules->rules() ) == 0 )
                {
                    //Todo: check if interface, routing is also empty
                    if( count( $this->pan->network->ethernetIfStore->getAll() ) != 0 )
                    {
                        //when is a PAN-OS config seen as blank???
                        #derr( "this BASE config file can not be used, it is not empty" );
                    }
                }
                else
                {
                    //if VSYS1 is not empty =>
                    //Todo: check if this is needed
                    #$this->objectsLocationCounter++;
                    #$this->sub = $this->pan->createVirtualSystem( $this->objectsLocationCounter );
                }
            }
            print "use VSYS: ".$this->sub->name()."\n";

            $this->template = $this->pan;
            $this->template_vsys = $this->template->findVirtualSystem( $this->sub->name() );
        }
        else
        {
            //panorama
            $this->sub = $this->pan->findDeviceGroup( $this->objectsLocation );
            if( $this->sub == null )
                $this->sub = $this->pan->createDeviceGroup( $this->objectsLocation );
            else
            {
                do
                {
                    $this->objectsLocationCounter++;
                    $this->sub = $this->pan->findDeviceGroup( $this->objectsLocation.$this->objectsLocationCounter );
                }
                while( $this->sub != null );

                $this->sub = $this->pan->createDeviceGroup(  $this->objectsLocation.$this->objectsLocationCounter );
            }


            print "use DG: ".$this->sub->name()."\n";

            $this->template = $this->pan->findTemplate( $this->templateName );
            if( $this->template == null )
            {
                $this->template = $this->pan->createTemplate( $this->templateName );
                $this->template = $this->template->deviceConfiguration;
            }
            else
            {
                do
                {
                    $this->templateNameCounter++;
                    $this->template = $this->pan->findTemplate( $this->templateName.$this->templateNameCounter );
                }
                while( $this->template != null );


                $this->template = $this->pan->createTemplate( $this->templateName.$this->templateNameCounter );
                $this->template = $this->template->deviceConfiguration;

            }
            $this->template_vsys = $this->template->findVirtualSystem( "vsys1" );
        }
        //$sub => VSYS or DG -> place for objects and policies
        //$template_vsys => VSYS of PAN-OS or Vsys of template
        //$template => $pan/device-config of PAN-OS or device config of template

        //-------------------------------------------------------------------------------------------------------
        $tmp_sub = &$this->sub;
        $tmp_template = &$this->template;
        $tmp_template_vsys = &$this->template_vsys;
    }

    public function global_end($lineReturn = TRUE, $indentingXml = 0, $indentingXmlIncreament = 1)
    {
        print "\n\n";
        $this->loadEnd();
        echo "OK! ($this->loadElapsedTime seconds, $this->loadUsedMem memory) used for migration\n";

        ##############################################

        print "\n\n\n";

        if( isset(PH::$args['stats']) )
        {
            $this->pan->display_statistics();
            echo "\n";
        }

        print "\n";

        $this->save_our_work(FALSE, TRUE, $lineReturn, $indentingXml, $indentingXmlIncreament);

        print "########################################################\n\n";
        print "MIGRATION configuration exported\n\n";
        print "########################################################\n\n";

        self::deleteDirectory( );

        $this->log->info("END PARSER: " . $this->vendor);
    }



    public function main()
    {
        #$this->vendor = $_vendor;

        if( empty($this->configInput) )
            derr("argument: 'IN=' is not set!", null, False);
        elseif( empty($this->configOutput) )
            derr("argument: 'OUT=' is not set!", null, False);
        elseif( empty($this->configFile) )
            derr("argument: 'FILE=' is not set!", null, False);


        self::global_start();


        #self::getDeviceConfig();

        self::vendor_require();
        //will be replace with the below one
        #vendor_main( $this->configFile, $this->pan );

        //Todo DIDAC
        $myParserObject = new $this->myParserClass($this->taskId, $this->expedition, $this->expedition_db_ip, $this->expedition_db_user, $this->expedition_db_pw);

        $myParserObject->newfolder = $this->newfolder;
        $myParserObject->configFile = $this->configFile;
        $myParserObject->pan = $this->pan;

        $myParserObject->objectsLocation = $this->objectsLocation;
        $myParserObject->templateName = $this->templateName;
        $myParserObject->configType = $this->configType;
        $myParserObject->objectsLocationCounter = $this->objectsLocationCounter;
        $myParserObject->templateNameCounter = $this->templateNameCounter;


        $myParserObject->interfaceRenaming = $this->interfaceRenaming;
        $myParserObject->zoneCalculation = $this->zoneCalculation;
        $myParserObject->appidMigration = $this->appidMigration;
        $myParserObject->cleanupUnusedPredefinedService = $this->cleanupUnusedPredefinedService;
        $myParserObject->validateAddressNameToRegionName = $this->validateAddressNameToRegionName;
        $myParserObject->validateNatBidir = $this->validateNatBidir;

        $myParserObject->routetable = $this->routetable;
        $myParserObject->mapping = $this->mapping;


        $myParserObject->vendor_main();



        if( PH::$shadow_reducexml )
            self::global_end(FALSE, -1, 0);
        else
            self::global_end();
    }


    static public function cleanup_unused_predefined_services($sub, $tag)
    {
        global $cleanupUnusedPredefinedService;

        if( !$cleanupUnusedPredefinedService )
            return null;

            foreach( $sub->serviceStore->all() as $tmp_service )
            {
                if( $tmp_service->tags->hasTag($tag) && $tmp_service->objectIsUnusedRecursive() )
                {
                    $sub->serviceStore->remove($tmp_service, TRUE);
                }
            }

    }

    /*
    public function correct_sec_rules_with_NAT(){
        //Collect all info of NAT
        //blablaba

        //Collect all info from Sec
        // blablaba

        $this->fix_Dst();

        $this->fix_Srv();
    }

    abstract protected function fix_Dst();
    abstract protected function fix_Srv();
*/
    public function validate_interface_names($template)
    {
        global $debug;
        global $print;
        #global $interfaceRenaming;

        if( !$this->interfaceRenaming )
        {
            print "\nNO interface renaming\n";
            return null;
        }


        $padding = "   ";
        $padding_name = substr($padding, 0, -1);


        $tmp_interfaces = $template->network->getAllInterfaces();

        $counter = 1;
        $tmp_int_name = array();
        foreach( $tmp_interfaces as $tmp_interface )
        {
            #if( $tmp_interface->type !== "tmp" && get_class( $tmp_interface ) == "EthernetInterface" )
            if( $tmp_interface->type !== "tmp" )
            {

                $int_name = $tmp_interface->name();
                if( get_class($tmp_interface) == "EthernetInterface" )
                {
                    if( strpos($int_name, "ethernet") === FALSE && strpos($int_name, "ae") === FALSE && strpos($int_name, "tunnel") === FALSE )
                    {
                        if( strpos($int_name, ".") === FALSE )
                        {
                            do
                            {
                                $new_name = "ethernet1/" . $counter;

                                $counter++;

                                $tmp_int = $template->network->findInterface($new_name);
                                $tmp_int_name[$int_name] = $new_name;
                            } while( $tmp_int !== null );

                        }
                        else
                        {
                            $tmp_tag = explode(".", $int_name);

                            if( isset( $tmp_int_name[$tmp_tag[0]] ) )
                                $new_name = $tmp_int_name[$tmp_tag[0]] . "." . $tmp_tag[1];
                            else
                            {
                                $new_name = null;
                                //Todo: swaschkut 20200930
                                //write Ethernetstore function remove
                                #$tmp_interface->owner->remove( $tmp_interface );
                            }
                        }



                        if( $new_name != null )
                        {
                            $addlog = "Interface: '" . $int_name . "' renamed to " . $new_name;
                            print $padding . "X " . $addlog . "\n";
                            $tmp_interface->display_references();
                            $tmp_interface->setName($new_name);

                            //todo: add description
                            #$tmp_interface->_description .= " renamed from '".$int_name."'";
                            //add migration log

                            $tmp_interface->set_node_attribute('warning', $addlog);
                        }
                    }

                }
                elseif( get_class($tmp_interface) == "TunnelInterface" )
                {
                    $tunnelcounter = 1;

                    $validate_name = explode( ".", $int_name);
                    if( $validate_name[0] == "tunnel" &&  is_numeric( $validate_name[1] ))
                        continue;

                    #if( strpos( $int_name, "." ) === false ){
                    do
                    {
                        $new_name = "tunnel." . $tunnelcounter;

                        $tunnelcounter++;

                        $tmp_int = $template->network->findInterface($new_name);
                        $tmp_int_name[$int_name] = $new_name;
                    } while( $tmp_int !== null );

                    /*}
                    else
                    {
                        $tmp_tag = explode( ".", $int_name);
                        $new_name = $tmp_int_name[ $tmp_tag[0] ].".". $tmp_tag[1];
                    }
                    */

                    $addlog = "Interface: '" . $int_name . "' renamed to " . $new_name;
                    print $padding . "X " . $addlog . "\n";
                    #$tmp_interface->display_references();
                    $tmp_interface->setName($new_name);
                    $tmp_interface->set_node_attribute('warning', $addlog);
                }
                else
                {
                    print " - migration for interface class: " . get_class($tmp_interface) . " not implemented yet! for interface: ".$int_name."\n";
                }

                //Todo: replace from routing
                /*
                                elseif( strpos( $int_name, "ethernet" ) !== false )
                                {
                                    //Todo: detailed check needed
                                    print "Interface: ".$int_name." not renamed!\n";
                                }
                                elseif( strpos( $int_name, "ae" ) !== false  )
                                {
                                    //Todo: detailed check needed
                                    print "Interface: ".$int_name." not renamed!\n";
                                }
                                elseif( strpos( $int_name, "tunnel" ) !== false  )
                                {
                                    //Todo: detailed check needed
                                    print "Interface: ".$int_name." not renamed!\n";
                                }*/

            }
            else
            {
                mwarning("interface: " . $tmp_interface->name() . " is of type: " . $tmp_interface->type . " and not renamed", null, FALSE);
            }
        }
    }

    /**
     * @param PANConf $pan
     */
    //Todo: bring in correct virtual router
    public function calculate_zones($template, $sub, $mode)
    {
        #global $zoneCalculation;

        if( !$this->zoneCalculation )
        {
            print "\nNO Zone calculation\n";
            return null;
        }


        //$template is always PANConf
        //if $template->owner!=null then TEMPLATE
        
        $vsyss = $template->virtualSystems;

        $tmp_virtualRouters = $template->network->virtualRouterStore->virtualRouters();

        foreach( $tmp_virtualRouters as $virtualRouter )
        {
            foreach( $virtualRouter->findConcernedVsys() as $virtualSystem )
            {
                foreach( $vsyss as $v )
                {
                    if( $v->name() === $virtualSystem->name() )
                    {
                        $vrouter = $virtualRouter->name();

                        foreach( $sub->securityRules->rules() as $rule )
                        {
                            print "check SecRule: " . $rule->name() . "\n";




                            if( $template->owner == null )
                            {
                                //$template class is PANConf
                                $rule->zoneCalculation('from', $mode, $vrouter);
                                $rule->zoneCalculation('to', $mode, $vrouter);
                            }
                            else
                            {
                                #print get_class( $template->owner )."\n";
                                //$template->owner class is Template
                                //zoneCalculation($fromOrTo, $mode = "append", $virtualRouter = "*autodetermine*", $template = "*notPanorama*", $vsys = "*notPanorama*")
                                $rule->zoneCalculation('from', $mode, $vrouter, $template->owner->name(), $v->name());
                                $rule->zoneCalculation('to', $mode, $vrouter, $template->owner->name(), $v->name());
                            }
                        }

                        foreach( $sub->natRules->rules() as $rule )
                        {
                            print "check NATRule: " . $rule->name() . "\n";

                            if( $template->owner == null )
                            {
                                //$template class is PANConf
                                $rule->zoneCalculation('from', $mode, $vrouter);
                                if( $rule->to->isAny() )
                                    $rule->zoneCalculation('to', $mode, $vrouter);
                            }
                            else
                            {
                                #print get_class( $template->owner )."\n";
                                //$template->owner class is Template
                                //zoneCalculation($fromOrTo, $mode = "append", $virtualRouter = "*autodetermine*", $template = "*notPanorama*", $vsys = "*notPanorama*")
                                $rule->zoneCalculation('from', $mode, $vrouter, $template->owner->name(), $v->name());
                                if( $rule->to->isAny() )
                                    $rule->zoneCalculation('to', $mode, $vrouter, $template->owner->name(), $v->name());
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @param PANConf $pan
     */
    public function validation_nat_bidir($template, $sub)
    {
        #global $validateNatBidir;

        if( !$this->validateNatBidir )
            return null;

        $vsyss = $template->virtualSystems;

        foreach( $vsyss as $sub )
        {
            foreach( $sub->natRules->rules() as $rule )
            {
                $hasgroup = FALSE;
                if( $rule->isBiDirectional() )
                {
                    print "NATRule: " . $rule->name() . " - bidirnat check\n";

                    //Todo: another validation is needed, if addressgroup has only one address member, then replace addressgroup with member
                    $sources = $rule->source->all();
                    if( count($sources) > 1 )
                    {
                        foreach( $sources as $source )
                            if( $source->isGroup() )
                                $hasgroup = TRUE;
                    }
                    elseif( count($sources) == 1 )
                    {
                        foreach( $sources as $source )
                        {
                            if( $source->isGroup() )
                            {
                                $tmp_members = $source->members();
                                if( count($tmp_members) == 1 && $tmp_members[0]->isAddress() )
                                {
                                    $rule->source->setAny();
                                    print "      - replace addressgroup: " . $source->name() . " with their single address object member: " . $tmp_members[0]->name() . "\n";
                                    $rule->source->addObject($tmp_members[0]);
                                }
                                else
                                    $hasgroup = TRUE;
                            }
                        }
                    }
                }

                if( $hasgroup )
                {
                    print "      - disabled bidir NAT\n";
                    $rule->setBiDirectional(FALSE);
                }

                if( $rule->isBiDirectional() && !$rule->sourceNatTypeIs_None() && $rule->destinationNatIsEnabled() )
                {
                    print "TODO:      - disabled bidir NAT - TMP\n";
                    #$rule->setBiDirectional( false );

                    print "TODO:      - create new rule and and swap information\n";
                }
            }
        }
    }

    /**
     * @param PANConf $pan
     */
    public function validation_region_object( $sub)
    {
        #global $validateAddressNameToRegionName;

        if( !$this->validateAddressNameToRegionName )
        {
            return null;
        }



            $addresses = $sub->addressStore->all();
            foreach( $addresses as $address )
            {
                $oldName = $address->name();
                if( strlen($oldName) == 2 )
                {
                    $tmp_default_region = SHAREDNEW::default_regions();
                    if( isset($tmp_default_region[$oldName]) )
                    {
                        $tmp_name_postfix = "_noRegion";
                        $newName = $oldName . $tmp_name_postfix;
                        $address->setName($newName);
                        $msg = "Address Region Validation - rename object: '" . $oldName . "' to: '" . $newName . "'";
                        print $msg . "\n";
                        $address->set_node_attribute('warning', $msg);
                    }
                }
            }
    }




    /**
     * @param PANConf|PanoramaConf $pan
     */
    public function AppMigration($pan, $configType)
    {
        global $appsToMigrate;
        #global $appidMigration;

        if( !$this->appidMigration )
        {
            print "no appid migraiton\n";
            return null;
        }


        //read appid_migraiton now from JSON file
        $someJSON = file_get_contents(dirname(__FILE__)."/../appid_migration.json");
        $someArray = json_decode($someJSON, TRUE);
        $appsToMigrate = $someArray['appid_migration'];

        //////////////////////////////////////////////////////////////////////////////////////


        if( $configType == "panos" )
        {
            $vsyss = $pan->owner->getVirtualSystems();
        }
        else
        {
            if( get_class( $pan ) == "PanoramaConf" )
                $vsyss = $pan->getDeviceGroups();
            else
                $vsyss = $pan->owner->getDeviceGroups();
        }


        foreach( $vsyss as $sub )
        {
            echo "\n************* SVC TO APP MIGRATION NOW **************\n\n";

            echo "\n *** PHASE 1 :LOOKING FOR SERVICES TO TRANSLATE AND BUILDING LIST OF RULES USING THEM\n\n";

            CONVERTER::AppMigrationPhase1($sub);


            echo "\n***********************************************\n";
            echo " *** PHASE 2 :LOOKING FOR RULES WITH appsToBeAdded\n\n";

            CONVERTER::AppMigrationPhase2($sub);

            echo "\n***********************************************\n";
            echo " *** PHASE 3 : ELIMINATE ANY REFERENCE TO THESE SERVICES \n\n";
            CONVERTER::AppMigrationPhase3($sub);
        }

    }

    /**
     * @param VirtualSystem $vsys1
     * @param PANConf $fw
     */
    public static function AppMigrationPhase1($vsys1)
    {
        global $appsToMigrate;

        $listTmpServices = array_merge($vsys1->serviceStore->serviceTmpObjects(), $vsys1->owner->serviceStore->serviceTmpObjects(), $vsys1->serviceStore->all('name regex /^tmp-/'));
        /**
         * @var Service[] $listTmpServices
         */
        foreach( $listTmpServices as $tmpService )
        {
            $tmp_app = null;
            echo "- tmp service '{$tmpService->name()}' found from ServiceStore\n";

            // is it part of the translation table ?
            if( !isset($appsToMigrate[$tmpService->name()]) )
            {
                $tmp_desc = $tmpService->description();
                if( strpos( $tmp_desc, "protocol-id:{" ) !== false )
                {
                    preg_match('/protocol-id:\{[0-9]{1,3}/', $tmp_desc, $output_array);
                    if( isset($output_array[0]) )
                    {
                        $tmp_prot = str_replace("protocol-id:{", "", $output_array[0]);

                        $tmp_app = $vsys1->appStore->get_app_by_ipprotocol($tmp_prot);
                        if( $tmp_app !==null )
                            $appsToMigrate[$tmpService->name()] = array('toApp' => array($tmp_app->name()));
                        else
                            mwarning( "no app-id mapping for ".$tmpService->name() );
                    }
                    else
                    {
                        preg_match('/protocol-id:\{[a-z]*}$/', $tmp_desc, $output_array);
                        if( isset($output_array[0]) )
                        {
                            $tmp_prot = str_replace("protocol-id:{", "", $output_array[0]);
                            $tmp_prot = str_replace("}", "", $tmp_prot);

                            $protocolID['ah'] = 'ipsec-ah';
                            $protocolID['eigrp'] = 'eigrp';
                            $protocolID['esp'] = 'ipsec-esp';
                            $protocolID['gre'] = 'gre';
                            $protocolID['icmp'] = 'icmp';
                            $protocolID['icmp6'] = 'ipv6-icmp';
                            $protocolID['igmp'] = 'igmp';
                            $protocolID['igrp'] = 'igp';
                            $protocolID['ip'] = 'ip-in-ip';
                            $protocolID['ipinip'] = 'ip-in-ip';
                            $protocolID['ipsec'] = 'ipsec';
                            $protocolID['nos'] = 'ipip';
                            $protocolID['ospf'] = 'ospf';
                            $protocolID['pcp'] = 'ipcomp';
                            $protocolID['pim'] = 'pim';
                            $protocolID['pptp'] = 'pptp';
                            $protocolID['sctp'] = 'sctp';
                            $protocolID['snp'] = 'snp';



                            if( is_numeric( $tmp_prot ) )
                            {
                                $tmp_app = $vsys1->appStore->get_app_by_ipprotocol($tmp_prot);
                            }
                            elseif( isset($protocolID[$tmp_prot]) )
                            {
                                $tmp_prot = $protocolID[$tmp_prot];
                                if( is_numeric( $tmp_prot ) )
                                    $tmp_app = $vsys1->appStore->get_app_by_ipprotocol($tmp_prot);
                                else
                                {
                                    $tmp_app = $vsys1->appStore->find($tmp_prot);
                                }
                            }
                            else
                                $tmp_app = $vsys1->appStore->find($tmp_prot);

                            if( $tmp_app !== null )
                                $appsToMigrate[$tmpService->name()] = array('toApp' => array($tmp_app->name()));
                            else
                            {
                                echo "\n\n **** THIS SERVICE '{$tmpService->name()}' IS NOT IN THE TABLE PLEASE REVIEW IT ****\n\n";
                                continue;
                            }

                        }
                    }
                }
                elseif( strpos( $tmp_desc, "icmp-type:{" ) !== false )
                {
                    preg_match('/icmp-type:\{[0-9]{1,2}/', $tmp_desc, $output_array);
                    if( isset($output_array[0]) )
                    {
                        $tmp_prot = str_replace("icmp-type:{", "", $output_array[0]);

                        $tmp_app = $vsys1->appStore->get_app_by_icmptype( "", $tmp_prot, "");
                        if( $tmp_app !== null )
                            $appsToMigrate[$tmpService->name()] = array('toApp' => array($tmp_app->name()));
                        else
                        {
                            echo "\n\n **** THIS SERVICE '{$tmpService->name()}' IS NOT IN THE TABLE PLEASE REVIEW IT ****\n\n";
                            continue;
                        }
                    }
                }
                else
                {
                    echo "\n\n **** THIS SERVICE '{$tmpService->name()}' IS NOT IN THE TABLE PLEASE REVIEW IT ****\n\n";
                    continue;
                }

            }

            $tmpService->migrated = TRUE;

            $foundAction = FALSE;
            if( isset( $appsToMigrate[$tmpService->name()]) )
                $appMigrateRecord = $appsToMigrate[$tmpService->name()];

            if( isset($appMigrateRecord['toApp']) )
            {
                $foundAction = TRUE;

                $rules = $vsys1->securityRules->rules();

                // go after all security rules and see if they are using this object
                foreach( $rules as $rule )
                {
                    if( $rule->services->hasObjectRecursive($tmpService) )
                    {
                        echo "  - Rule '{$rule->name()}' is using it\n";
                        foreach( $appMigrateRecord['toApp'] as $app )
                        {
                            echo "     - adding app '$app'' to the list of apps to add\n";
                            $rule->appsToAdd[$app] = TRUE;
                        }
                    }
                }
            }
            if( !$foundAction )
            {
                echo "\n\n **** THIS SERVICE '{$tmpService->name()}' HAS NO ASSOCIATED ACTION PLEASE FIX ****\n\n";
                exit(1);
            }

            echo "\n";
        }
    }

    /**
     * @param VirtualSystem $vsys1
     * @param PANConf $fw
     */
    public static function AppMigrationPhase2($vsys1)
    {
        $rules = $vsys1->securityRules->rules();

        foreach( $rules as $rule )
        {
            if( !isset($rule->appsToAdd) )
                continue;

            echo "- rule '{$rule->name()}' will be cloned and added the following " . count($rule->appsToAdd) . " apps : ";

            foreach( $rule->appsToAdd as $app => $value )
            {
                echo $app . ', ';
            }

            echo "\n";

            // find a name for the cloned rule
            $newRuleName = $vsys1->securityRules->findAvailableName($rule->name(), '-app');
            echo "   - cloned rule will be named '$newRuleName'\n";

            // clone said rule
            $newRule = $vsys1->securityRules->cloneRule($rule, $newRuleName);

            $rule->appConvertedRule = $newRule;

            // move it after the original one
            $vsys1->securityRules->moveRuleBefore($newRule, $rule);

            // add applications to that rule
            foreach( $rule->appsToAdd as $app => $value )
            {
                $findAppObject = $vsys1->appStore->findOrCreate($app);
                $newRule->apps->addApp($findAppObject);
                echo "   - added app '{$app}'\n";
            }

            // make rule use app-default
            $newRule->services->setApplicationDefault();

            echo "\n";
        }
    }

    /**
     * @param VirtualSystem $vsys1
     * @param PANConf $fw
     */
    public static function AppMigrationPhase3($vsys1)
    {
        $listTmpServices = array_merge($vsys1->serviceStore->serviceTmpObjects(), $vsys1->owner->serviceStore->serviceTmpObjects(), $vsys1->serviceStore->all('name regex /^tmp-/'));
        foreach( $listTmpServices as $tmpService )
        {
            if( !isset($tmpService->migrated) )
                continue;

            echo " - taking care of '{$tmpService->name()}'\n";
            $references = $tmpService->getReferences();

            foreach( $references as $ref )
            {
                $class = get_class($ref);
                echo "   - reference with class '$class' found\n";

                if( $class == 'ServiceRuleContainer' )
                {
                    /** @var ServiceRuleContainer $ref */
                    if( $ref->count() == 1 )
                    {
                        echo "     - it was the last object, we will remove rule '{$ref->owner->name()}' and rename 'app' one with original name\n";
                        $rule = $ref->owner;
                        $rule->owner->remove($rule, TRUE);
                        if( isset($rule->appConvertedRule) )
                            $rule->appConvertedRule->setName($rule->name());
                    }
                    else
                    {
                        echo "     - service '{$tmpService->name()}' to be removed from rule '{$ref->owner->name()}'\n";
                        $ref->remove($tmpService);
                    }
                }
                elseif( $class == 'ServiceGroup' )
                {
                    /** @var ServiceGroup $ref */
                    if( count( $ref->members() ) == 1 )
                    {
                        echo "     - service '{$tmpService->name()}' to be removed from Group '{$ref->name()}'\n";
                        if( !$ref->removeMember($tmpService) )
                        {
                            echo " **** ERROR : removal of service group failed !!! **** \n";
                            exit(1);
                        }
                        echo "     - it was the last member, we will remove service group '{$ref->name()}'\n";
                        $ref->removeWhereIamUsed( TRUE, '     ' );
                        $ref->owner->remove( $ref );
                    }
                    else
                    {
                        echo "     - service '{$tmpService->name()}' to be removed from Group '{$ref->name()}'\n";
                        if( !$ref->removeMember($tmpService) )
                        {
                            echo " **** ERROR : removal of service group failed !!! **** \n";
                            exit(1);
                        }
                    }

                    //unset also all other references from ref on $tmpService
                    /*foreach( $ref->getReferences() as $remove_ref )
                    {
                        foreach( $references as $key2 => $ref2 )
                        {
                            if( $remove_ref === $ref2 )
                                unset( $references[$key2] );
                        }
                        $tmpService->removeReference( $remove_ref );
                    }*/

                }
                else
                {
                    echo "\n\n **** THIS CLASS '$class' IS NOT SUPPORTED PLEASE IMPLEMENT USE CASE ****\n\n";
                    //exit(1);
                }
            }

            echo "\n";
        }
    }

    public function deleteDirectory( )
    {
        if( $this->newfolder !=  null && file_exists($this->newfolder) )
            $this->delete_directory($this->newfolder);
    }

    //CLEANUP function
    function delete_directory($mainfolder)
    {
        if( is_dir($mainfolder) )
            $dir_handle = opendir($mainfolder);
        if( !$dir_handle )
            return FALSE;

        while( $file = readdir($dir_handle) )
        {
            if( $file != "." && $file != ".." )
            {
                if( !is_dir($mainfolder . "/" . $file) )
                {
                    #print "unlink: ".$dirname.'/'.$file."\n";
                    unlink($mainfolder . "/" . $file);
                }

                else
                    $this->delete_directory($mainfolder . '/' . $file);
            }
        }
        closedir($dir_handle);
        #print "DEL folder: ".$dirname."\n";
        rmdir($mainfolder);
        return TRUE;
    }



    function rule_merging( $sub, $configInput, $stopMergingIfDenySeen = true, $mergeAdjacentOnly = false, $mergeDenyRules = false, $additionalMatch = "", $method_array = array() )
    {
        $rulemerger = new RULEMERGER("custom", array(), "fake-migration-parser");


        $rulemerger->UTIL_additionalMatch = $additionalMatch;

        $rulemerger->configInput = $configInput;
        $rulemerger->configOutput = null;

        $rulemerger->UTIL_rulesToProcess = $sub->securityRules->rules();


        $rulemerger->UTIL_stopMergingIfDenySeen = $stopMergingIfDenySeen;
        $rulemerger->UTIL_mergeAdjacentOnly = $mergeAdjacentOnly;
        $rulemerger->UTIL_mergeDenyRules = $mergeDenyRules;

        $rulemerger->UTIL_filterQuery = null;

        //1 matchFromToSrcDstApp
        //2 matchToSrcDstSvcApp
        //3 matchFromSrcDstSvcApp
        /*
        $supportedMethods_tmp = array(
            'matchFromToSrcDstApp' => 1,
            'matchFromToSrcDstSvc' => 2,
            'matchFromToSrcSvcApp' => 3,
            'matchFromToDstSvcApp' => 4,
            'matchFromSrcDstSvcApp' => 5,
            'matchToSrcDstSvcApp' => 6,
            'matchToDstSvcApp' => 7,
            'matchFromSrcSvcApp' => 8,
            'identical' => 9,
        );
         */



        foreach( $method_array as $method )
        {
            $rulemerger->UTIL_method = $method;
            $rulemerger->UTIL_hashTable = array();
            /** @var SecurityRule[] $denyRules */
            $rulemerger->UTIL_denyRules = array();

            $rulemerger->UTIL_calculate_rule_hash();



            $rulemerger->UTIL_rule_merging( );

            $rulemerger->UTIL_rulesToProcess = $sub->securityRules->rules();
        }

    }

    public function migrationImprovementFeatures()
    {
        //read appid_migraiton now from JSON file
        $someJSON = file_get_contents(dirname(__FILE__)."/../migration_features.json");
        $someArray = json_decode($someJSON, TRUE);
        $migrationFeatures = $someArray['migration_improvement_feature'];

        $featureArray = array(
            'interface-renaming' => 'interfaceRenaming',
            'zone-calculation' => 'zoneCalculation',
            'appid-migration' => 'appidMigration',
            'cleanup-unused-predefined-services' => 'cleanupUnusedPredefinedService',
            'validate-address-object-name-region-object' => 'validateAddressNameToRegionName',
            'validate-nat-bidir' => 'validateNatBidir'
        );

        foreach( $featureArray as $key => $feature )
        {
            if( isset( $migrationFeatures[ $key ] ) )
            {
                #print "check: ".$key." with featrue: ".$feature." | value: ||".$migrationFeatures[ $key ]."||\n";
                $this->$feature = filter_var(    $migrationFeatures[ $key ], FILTER_VALIDATE_BOOLEAN);
            }
        }


/*
        if( $this->interfaceRenaming )
            print "interfaceRenaming\n";

        if( $this->zoneCalculation )
            print "zoneCalculation\n";

        if( $this->appidMigration )
            print "appidMigration\n";

        if( $this->cleanupUnusedPredefinedService )
            print "cleanupUnusedPredefinedService\n";

        if( $this->validateAddressNameToRegionName )
            print "validateAddressNameToRegionName\n";

        if( $this->validateNatBidir )
            print "validateNatBidir\n";
*/
    }
}
