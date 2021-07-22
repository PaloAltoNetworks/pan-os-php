<?php

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once(dirname(__FILE__)."/../common/actions.php");

require_once(dirname(__FILE__)."/logWriter.php");
require_once(dirname(__FILE__)."/RULEUTIL.php");
require_once(dirname(__FILE__)."/STATSUTIL.php");
require_once(dirname(__FILE__)."/SECURITYPROFILEUTIL.php");
require_once(dirname(__FILE__)."/DEVICEUTIL.php");
require_once(dirname(__FILE__)."/NETWORKUTIL.php");

require_once(dirname(__FILE__)."/MERGER.php");
require_once(dirname(__FILE__)."/RULEMERGER.php");

class UTIL
{

    public $configType = null;
    public $configInput = null;
    public $configOutput = null;
    public $doActions = null;
    public $dryRun = FALSE;
    public $apiTimeoutValue = 60;
    public $objectsLocation = 'shared';

    public $objectsLocationCounter = 0;
    public $objectsTemplate = 'any';
    public $templateName = "";
    public $templateNameCounter = 0;

    public $objectsFilter = null;
    public $errorMessage = '';
    public $debugAPI = FALSE;

    /** @var DOMDocument $xmlDoc */
    public $xmlDoc = null;

    /** @var PANConf|PanoramaConf|FawkesConf $pan  */
    public $pan = null;

    public $nestedQueries = array();
    public $objectFilterRQuery = null;
    public $objectsToProcess = array();
    public $totalObjectsProcessed = 0;
    public $totalObjectsOfSelectedStores = 0;
    public $supportedArguments = array();
    public $usageMsg = "";
    public $apiMode = FALSE;

    public $loadStartTime = 0;
    public $loadStartMem = 0;
    public $loadElapsedTime = 0;
    public $loadUsedMem = 0;

    public $expedition = null;
    public $expedition_db_ip = null;
    public $expedition_db_user = null;
    public $expedition_db_pw = null;
    protected $taskId = 0;
    public $log = null;

    public $utilType = null;
    public $PHP_FILE = null;

    public $location = null;
    public $sub = null;
    public $template = null;

    function __construct($utilType, $argv, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "")
    {
        $argc = array();
        $tmp_ph = new PH($argv, $argc);

        $this->utilType = $utilType;
        $this->PHP_FILE = $PHP_FILE;

        if( empty($_supportedArguments) )
            $this->supportedArguments();
        else
            $this->supportedArguments = $_supportedArguments;

        if( !empty($_usageMsg) )
            $this->usageMsg = $_usageMsg;

        $this->utilLogger();
        $this->log->info("start UTIL: " . $this->PHP_FILE . " | " . implode(", ", $argv));

        if( $utilType != "custom" )
            $this->utilStart();
    }

    public function utilStart()
    {
        $this->utilInit();


        $this->utilActionFilter();


        $this->location_filter_object();


        $this->time_to_process_objects();


        $this->GlobalFinishAction();


        PH::print_stdout( "" );
        PH::print_stdout( "**** PROCESSING OF $this->totalObjectsProcessed OBJECTS DONE ****" );
        PH::print_stdout( "" );

        $this->stats();

        $this->save_our_work(TRUE);

        if( PH::$shadow_json )
            print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );


        $this->log->info("END UTIL: " . $this->PHP_FILE);
    }

    /*
     *
     */
    public function utilLogger()
    {
        $this->log = new logWriter();
    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
        $this->supportedArguments['listactions'] = array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
        $this->supportedArguments['listfilters'] = array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
        $this->supportedArguments['stats'] = array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
        $this->supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['filter'] = array('niceName' => 'Filter', 'shortHelp' => "filters objects based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator [value])');
        $this->supportedArguments['loadplugin'] = array('niceName' => 'loadPlugin', 'shortHelp' => 'a PHP file which contains a plugin to expand capabilities of this script');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->supportedArguments['expedition'] = array('niceName' => 'expedition', 'shortHelp' => 'only used if called from Expedition Tool');
        $this->supportedArguments['template'] = array('niceName' => 'template', 'shortHelp' => 'Panorama template');

        $this->supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
        $this->supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');



        $this->supportedArguments['shadow-disableoutputformatting'] = array('niceName' => 'shadow-disableoutputformatting', 'shortHelp' => 'XML output in offline config is not in cleaned PHP DOMDocument structure');
        $this->supportedArguments['shadow-enablexmlduplicatesdeletion']= array('niceName' => 'shadow-enablexmlduplicatesdeletion', 'shortHelp' => 'if duplicate objects are available, keep only one object of the same name');
        $this->supportedArguments['shadow-ignoreinvalidaddressobjects']= array('niceName' => 'shadow-ignoreinvalidaddressobjects', 'shortHelp' => 'PAN-OS allow to have invalid address objects available, like object without value or type');
        $this->supportedArguments['shadow-apikeynohidden'] = array('niceName' => 'shadow-apikeynohidden', 'shortHelp' => 'send API-KEY in clear text via URL. this is needed for all PAN-OS version <9.0 if API mode is used. ');
        $this->supportedArguments['shadow-apikeynosave']= array('niceName' => 'shadow-apikeynosave', 'shortHelp' => 'do not store API key in .panconfkeystore file');
        $this->supportedArguments['shadow-displaycurlrequest']= array('niceName' => 'shadow-displaycurlrequest', 'shortHelp' => 'display curl information if running in API mode');
        $this->supportedArguments['shadow-reducexml']= array('niceName' => 'shadow-reducexml', 'shortHelp' => 'store reduced XML, without newline and remove blank characters in offline mode');
        $this->supportedArguments['shadow-json']= array('niceName' => 'shadow-json', 'shortHelp' => 'BETA command to display output on stdout not in text but in JSON format');
    }

    public function utilInit()
    {
        PH::processCliArgs();


        $this->loadplugin();


        $this->help(PH::$args);

        $this->arg_validation();

        $this->listactions();

        $this->listfilters();

        $this->init_arguments();
    }

    public function utilActionFilter( $utilType = null)
    {
        $this->extracting_actions( $utilType );
        $this->createRQuery();


        $this->load_config();

        $this->location_filter();
    }

    public function listfilters()
    {
        if( isset(PH::$args['listfilters']) )
        {
            ksort(RQuery::$defaultFilters[$this->utilType]);

            PH::print_stdout( "Listing of supported filters:" );
            PH::print_stdout( "" );
            PH::print_stdout( "" );

            foreach( RQuery::$defaultFilters[$this->utilType] as $index => &$filter )
            {
                PH::print_stdout( "* " . $index . "" );
                ksort($filter['operators']);

                foreach( $filter['operators'] as $oindex => &$operator )
                {
                    //if( $operator['arg'] )
                    $output = "    - $oindex";

                    PH::print_stdout( $output . "" );
                }
                PH::print_stdout( "" );
            }

            exit(0);
        }
    }

    public function supportedActions()
    {
        $tmp_array = array();

        if( $this->utilType == 'tag' )
            $tmp_array = &TagCallContext::$supportedActions;
        elseif( $this->utilType == 'address' )
            $tmp_array = &AddressCallContext::$supportedActions;
        elseif( $this->utilType == 'service' )
            $tmp_array = &ServiceCallContext::$supportedActions;
        elseif( $this->utilType == 'rule' )
            $tmp_array = &RuleCallContext::$supportedActions;
        elseif( $this->utilType == 'zone' )
            $tmp_array = &ZoneCallContext::$supportedActions;
        elseif( $this->utilType == 'securityprofile' )
            $tmp_array = &SecurityProfileCallContext::$supportedActions;
        elseif( $this->utilType == 'securityprofilegroup' )
            $tmp_array = &SecurityProfileGroupCallContext::$supportedActions;
        elseif( $this->utilType == 'schedule' )
            $tmp_array = &ScheduleCallContext::$supportedActions;
        elseif( $this->utilType == 'application' )
            $tmp_array = &ApplicationCallContext::$supportedActions;
        
        elseif( $this->utilType == 'device' )
            $tmp_array = &DeviceCallContext::$supportedActions;
        elseif( $this->utilType == 'vsys' )
            $tmp_array = &VsysCallContext::$supportedActions;

        elseif( $this->utilType == 'virtualwire' )
            $tmp_array = &VirtualWireCallContext::$supportedActions;
        elseif( $this->utilType == 'routing' )
            $tmp_array = &RoutingCallContext::$supportedActions;
        elseif( $this->utilType == 'interface' )
            $tmp_array = &InterfaceCallContext::$supportedActions;

        return $tmp_array;
    }

    public function listactions()
    {
        if( isset(PH::$args['listactions']) )
        {
            $tmp_array = $this->supportedActions();

            ksort($tmp_array);

            PH::print_stdout( "Listing of supported actions:" );
            PH::print_stdout( "" );
            PH::print_stdout( "" );

            PH::print_stdout( str_pad('', 100, '-') . "" );
            PH::print_stdout( str_pad('Action name', 28, ' ', STR_PAD_BOTH) . "|" . str_pad("Argument:Type", 24, ' ', STR_PAD_BOTH) . " |" .
                str_pad("Def. Values", 12, ' ', STR_PAD_BOTH) . "|   Choices" );
            PH::print_stdout( str_pad('', 100, '-') );

            foreach( $tmp_array as &$action )
            {

                $output = "* " . $action['name'];

                $output = str_pad($output, 28) . '|';

                if( isset($action['args']) )
                {
                    $first = TRUE;
                    $count = 1;
                    foreach( $action['args'] as $argName => &$arg )
                    {
                        if( !$first )
                            $output .= "\n" . str_pad('', 28) . '|';

                        $output .= " " . str_pad("#$count $argName:{$arg['type']}", 24) . "| " . str_pad("{$arg['default']}", 12) . "| ";
                        if( isset($arg['choices']) )
                        {
                            $output .= PH::list_to_string($arg['choices']);
                        }

                        $count++;
                        $first = FALSE;
                    }
                }


                PH::print_stdout( $output );
                PH::print_stdout( str_pad('', 100, '=') );
            }

            exit(0);
        }

    }

    public function loadplugin()
    {
        if( isset(PH::$args['loadplugin']) )
        {
            $pluginFile = PH::$args['loadplugin'];
            PH::print_stdout( " * loadPlugin was used. Now loading file: '{$pluginFile}'..." );

            require_once $pluginFile;

            if( $this->utilType == 'tag' )
                TagCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'address' )
                AddressCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'service' )
                ServiceCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'rule' )
                RuleCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'zone' )
                ZoneCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'vsys' )
                VsysCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'securityprofile' )
                SecurityProfileCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'securityprofilegroup' )
                SecurityProfileGroupCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'schedule' )
                ScheduleCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'application' )
                ApplicationCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'device' )
                DeviceCallContext::prepareSupportedActions();

            PH::print_stdout( "OK!" );
        }
    }

    public function help($argv)
    {
        if( isset(PH::$args['help']) )
        {
            $tmp_array = self::supportedActions();

            $pos = array_search('help', PH::$args);

            if( $pos === FALSE )
                $this->display_usage_and_exit(FALSE);

            $keys = array_keys(PH::$args);

            if( $pos == end($keys) )
                $this->display_usage_and_exit(FALSE);

            $key_search = array_search($pos, $keys);
            #$action = PH::$args[(array_search($pos, $keys) +1)];
            $action = $keys[($key_search + 1)];

            if( !isset($tmp_array[strtolower($action)]) )
                derr("request help for action '{$action}' but it does not exist");

            $action = &$tmp_array[strtolower($action)];

            $args = array();
            if( isset($action['args']) )
            {
                foreach( $action['args'] as $argName => &$argDetails )
                {
                    if( $argDetails['default'] == '*nodefault*' )
                        $args[] = "{$argName}";
                    else
                        $args[] = "[{$argName}]";
                }
            }

            $args = PH::list_to_string($args);
            PH::print_stdout( "*** help for Action " . PH::boldText($action['name']) . ":" . $args );

            if( isset($action['help']) )
                PH::print_stdout( $action['help'] );

            if( !isset($args) || !isset($action['args']) )
            {
                PH::print_stdout( "\n\n**No arguments required**" );
            }
            else
            {
                PH::print_stdout( "\nListing arguments:" );
                PH::print_stdout( "" );
                PH::print_stdout( "" );
                foreach( $action['args'] as $argName => &$argDetails )
                {
                    PH::print_stdout( "-- " . PH::boldText($argName) . " :" );
                    if( $argDetails['default'] != "*nodefault" )
                        PH::print_stdout( " OPTIONAL" );
                    PH::print_stdout( " type={$argDetails['type']}" );
                    if( isset($argDetails['choices']) )
                    {
                        PH::print_stdout( "     choices: " . PH::list_to_string($argDetails['choices']) );
                    }
                    PH::print_stdout( "" );
                    if( isset($argDetails['help']) )
                        PH::print_stdout( " " . str_replace("\n", "\n ", $argDetails['help']) );
                    else
                        PH::print_stdout( "  *no help available*" );
                    PH::print_stdout( "" );
                    PH::print_stdout( "" );
                }
            }


            PH::print_stdout( "" );
            PH::print_stdout( "" );

            exit(0);
        }
    }

    public function arg_validation()
    {
        foreach( PH::$args as $index => &$arg )
        {
            if( !isset($this->supportedArguments[$index]) )
            {
                if( strpos($index, 'subquery') === 0 )
                {
                    $this->nestedQueries[$index] = &$arg;
                    continue;
                }
                //var_dump($supportedArguments);
                $this->display_error_usage_exit("unsupported argument provided: '$index'");
            }
        }
    }

    public function display_error_usage_exit($msg)
    {
        fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
        $this->display_usage_and_exit(TRUE);
    }

    public function usageMessage()
    {
        PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename($this->PHP_FILE) . " in=inputfile.xml out=outputfile.xml location=all|shared|sub " .
            "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']" );
        PH::print_stdout( "php " . basename($this->PHP_FILE) . " listactions   : list supported actions" );
        PH::print_stdout( "php " . basename($this->PHP_FILE) . " listfilters   : list supported filter" );
        PH::print_stdout( "php " . basename($this->PHP_FILE) . " help          : more help messages" );
        PH::print_stdout( PH::boldText("\nExamples:") );
        PH::print_stdout( " - php " . basename($this->PHP_FILE) . " type=panorama in=api://192.169.50.10 location=DMZ-Firewall-Group actions=displayReferences 'filter=(name eq Mail-Host1)'" );
        PH::print_stdout( " - php " . basename($this->PHP_FILE) . " type=panos in=config.xml out=output.xml location=any actions=delete" );
        PH::print_stdout( "" );
        PH::print_stdout( "" );
        PH::print_stdout( PH::boldText("PAN-OS API connections for version < 9.0 now need additional argument: 'shadow-apikeynohidden'") );
    }

    public function display_usage_and_exit($shortMessage = FALSE)
    {
        if( $this->usageMsg == "" )
            $this->usageMessage();
        else
            PH::print_stdout( $this->usageMsg );
        PH::print_stdout( "" );
        PH::print_stdout( "" );

        if( !$shortMessage )
        {
            PH::print_stdout( PH::boldText("\nListing available arguments") );
            PH::print_stdout( "" );
            PH::print_stdout( "" );

            ksort($this->supportedArguments);
            foreach( $this->supportedArguments as &$arg )
            {
                $tmp_text = " - " . PH::boldText($arg['niceName']);
                if( isset($arg['argDesc']) )
                    $tmp_text .= '=' . $arg['argDesc'] ;
                //."=";
                PH::print_stdout( $tmp_text );
                if( isset($arg['shortHelp']) )
                    PH::print_stdout( "     " . $arg['shortHelp'] );

                PH::print_stdout( "" );
            }

            PH::print_stdout( "" );

        }

        exit(1);
    }

    public function prepareSupportedArgumentsArray()
    {
        $tmpArgs = array();
        foreach( $this->supportedArguments as &$arg )
        {
            $tmpArgs[strtolower($arg['niceName'])] = $arg;
        }
        $this->supportedArguments = $tmpArgs;
    }

    public function init_arguments()
    {
        $this->inDebugapiArgument();


        if( !isset(PH::$args['actions']) )
        {
            #display_error_usage_exit('"actions" is missing from arguments');
            PH::$args['actions'] = "display";
        }

        $this->doActions = PH::$args['actions'];
        if( !is_string($this->doActions) || strlen($this->doActions) < 1 )
            $this->display_error_usage_exit('"actions" argument is not a valid string');


        if( isset(PH::$args['dryrun']) )
        {
            $this->dryRun = PH::$args['dryrun'];
            if( $this->dryRun === 'yes' ) $this->dryRun = TRUE;
            if( $this->dryRun !== TRUE || $this->dryRun !== FALSE )
                $this->display_error_usage_exit('"dryrun" argument has an invalid value');
        }

        //
        // Rule filter provided in CLI ?
        //
        if( isset(PH::$args['filter']) )
        {
            $this->objectsFilter = PH::$args['filter'];
            if( !is_string($this->objectsFilter) || strlen($this->objectsFilter) < 1 )
                $this->display_error_usage_exit('"filter" argument is not a valid string');
        }

        if( isset(PH::$args['apiTimeout']) )
            $this->apiTimeoutValue = PH::$args['apiTimeout'];


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


        $this->inputValidation();


        $this->location_provided();
    }

    public function inDebugapiArgument()
    {
        if( !isset(PH::$args['in']) )
            $this->display_error_usage_exit('"in" is missing from arguments');
        $this->configInput = PH::$args['in'];
        if( !is_string($this->configInput) || strlen($this->configInput) < 1 )
            $this->display_error_usage_exit('"in" argument is not a valid string');

        if( isset(PH::$args['debugapi']) )
        {
            $this->debugAPI = TRUE;
        }

    }

    public function inputValidation()
    {
        //
        // What kind of config input do we have.
        //     File or API ?
        //
        // <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
        $this->configInput = PH::processIOMethod($this->configInput, TRUE);

        if( $this->configInput['status'] == 'fail' )
        {
            if( isset( $_SERVER['REQUEST_METHOD'] ) )
            {
                throw new Exception( "**ERROR** " . $this->configInput['msg'], 404);
            }
            else
            {
                fwrite(STDERR, "\n\n**ERROR** " . $this->configInput['msg'] . "\n\n");
                exit(1);
            }
        }

        if( $this->configInput['type'] == 'file' )
        {
            if( !isset(PH::$args['out']) )
            {
                #display_error_usage_exit('"out" is missing from arguments');
                PH::$args['out'] = "/dev/null";
            }
            if( isset(PH::$args['out']) )
            {
                $this->configOutput = PH::$args['out'];
                if( !is_string($this->configOutput) || strlen($this->configOutput) < 1 )
                    $this->display_error_usage_exit('"out" argument is not a valid string');
            }

            $this->apiMode = FALSE;
            if( !file_exists($this->configInput['filename']) )
                derr("file '{$this->configInput['filename']}' not found");

            $this->xmlDoc = new DOMDocument();
            PH::print_stdout( " - Reading XML file from disk... ".$this->configInput['filename'] );
            if( !$this->xmlDoc->load($this->configInput['filename'], XML_PARSE_BIG_LINES) )
                derr("error while reading xml config file");
            PH::print_stdout( "OK!" );
        }
        elseif( $this->configInput['type'] == 'api' )
        {
            if( $this->debugAPI )
                $this->configInput['connector']->setShowApiCalls(TRUE);
            $this->apiMode = TRUE;
            PH::print_stdout( " - Downloading config from API... " );
            $this->xmlDoc = $this->configInput['connector']->getCandidateConfig( $this->apiTimeoutValue );
            PH::print_stdout( "OK!" );
        }
        else
            derr('not supported yet');

        $this->determineConfigType();

    }

    public function determineConfigType()
    {
        //
        // Determine if PANOS or Panorama
        //
        $xpathResult = DH::findXPath('/config', $this->xmlDoc);
        $xpathResult = $xpathResult->item(0);
        $fawkes_config_version = DH::findAttribute('fawkes-config-version', $xpathResult);
        if( $fawkes_config_version != null )
            print "FAWKES-CONFIG-VERSION: ".$fawkes_config_version."\n";
        else
        {
            $fawkes_config_version = DH::findAttribute('fawkes-config', $xpathResult);
            if( $fawkes_config_version != null )
                print "FAWKES-CONFIG-VERSION: ".$fawkes_config_version."\n";
        }



        $xpathResult = DH::findXPath('/config/devices/entry/vsys', $this->xmlDoc);
        if( $xpathResult === FALSE )
            derr('XPath error happened');
        if( $xpathResult->length < 1 )
        {
            if( $fawkes_config_version != null )
                $this->configType = 'fawkes';
            else
                $this->configType = 'panorama';
        }

        else
            $this->configType = 'panos';
        unset($xpathResult);


        if( $this->configType == 'panos' )
        {
            if( isset(PH::$args['loadpanoramapushedconfig']) )
            {
                $inputConnector = $this->configInput['connector'];

                PH::print_stdout( " - 'loadPanoramaPushedConfig' was requested, downloading it through API..." );
                $panoramaDoc = $inputConnector->getPanoramaPushedConfig( $this->apiTimeoutValue );

                $xpathResult = DH::findXPath('/panorama/vsys', $panoramaDoc);

                if( $xpathResult === FALSE )
                    derr("could not find any VSYS");

                if( $xpathResult->length != 1 )
                    derr("found more than 1 <VSYS>");

                $fakePanorama = new PanoramaConf();
                $fakePanorama->_fakeMode = TRUE;
                $inputConnector->refreshSystemInfos();
                $newDGRoot = $xpathResult->item(0);
                $panoramaString = "<config version=\"{$inputConnector->info_PANOS_version}\"><shared></shared><devices><entry name=\"localhost.localdomain\"><device-group>" . DH::domlist_to_xml($newDGRoot->childNodes) . "</device-group></entry></devices></config>";

                $fakePanorama->load_from_xmlstring($panoramaString);

                $this->pan = new PANConf($fakePanorama);
            }
            else
                $this->pan = new PANConf();
        }
        elseif( $this->configType == 'panorama' )
            $this->pan = new PanoramaConf();
        elseif( $this->configType == 'fawkes' )
            $this->pan = new FawkesConf();
        else
            derr( "configType: ".$this->configType." not supported." );

        PH::print_stdout( " - Detected platform type is '{$this->configType}'" );

        if( isset($this->configInput['type']) && $this->configInput['type'] == 'api' )
            $this->pan->connector = $this->configInput['connector'];
        // </editor-fold>
    }

    public function location_provided()
    {
        //
        // Location provided in CLI ?
        //
        if( isset(PH::$args['location']) )
        {
            $this->objectsLocation = PH::$args['location'];
            if( !is_string($this->objectsLocation) || strlen($this->objectsLocation) < 1 )
                $this->display_error_usage_exit('"location" argument is not a valid string');
        }
        else
        {
            if( $this->configType == 'panos' )
                $this->objectsLocation = 'vsys1';
            elseif( $this->configType == 'panorama' )
                $this->objectsLocation = 'shared';
            elseif( $this->configType == 'fawkes' )
                $this->objectsLocation = 'All';

            if( get_class( $this ) == "NETWORKUTIL" )
                $this->objectsLocation = 'any';

            PH::print_stdout( " - No 'location' provided so using default ='".$this->objectsLocation."'" );
        }

        //
        // Template provided in CLI ?
        //
        if( isset(PH::$args['template']) )
        {
            $this->objectsTemplate = PH::$args['template'];
            if( !is_string($this->objectsTemplate) || strlen($this->objectsTemplate) < 1 )
                $this->display_error_usage_exit('"location" argument is not a valid string');
        }
        else
        {
            if( $this->configType == 'panos' )
                $this->objectsTemplate = 'any';
            elseif( $this->configType == 'panorama' )
                $this->objectsTemplate = 'any';
            elseif( $this->configType == 'fawkes' )
                $this->objectsTemplate = 'any';

            if( get_class( $this ) == "NETWORKUTIL" )
                $this->objectsTemplate = 'any';

            PH::print_stdout( " - No 'template' provided so using default ='".$this->objectsTemplate."'" );
        }
    }

    public function extracting_actions( $utilType = null)
    {
        if( $utilType != null )
            $this->utilType = $utilType;

        $tmp_array = $this->supportedActions();

        //
        // Extracting actions
        //
        $tmp_doactions = str_replace( "//", "****", $this->doActions );
        $explodedActions = explode('/', $tmp_doactions);

        /** @var TagCallContext[] $doActions */
        $this->doActions = array();
        foreach( $explodedActions as &$exAction )
        {
            $exAction = str_replace( "****", "/", $exAction );

            $explodedAction = explode(':', $exAction);
            if( count($explodedAction) > 2 )
                $this->display_error_usage_exit('"actions" argument has illegal syntax: ' . PH::$args['actions']);

            $actionName = strtolower($explodedAction[0]);

            if( !isset($tmp_array[$actionName]) )
            {
                $this->display_error_usage_exit('unsupported Action: "' . $actionName . '"');
            }

            if( count($explodedAction) == 1 )
                $explodedAction[1] = '';

            //variable based on which util script is calling the method
            if( $this->utilType == 'tag' )
                $context = new TagCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'address' )
                $context = new AddressCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'service' )
                $context = new ServiceCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'rule' )
                $context = new RuleCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);

            elseif( $this->utilType == 'securityprofile' )
                $context = new SecurityProfileCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'securityprofilegroup' )
                $context = new SecurityProfileGroupCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'schedule' )
                $context = new ScheduleCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'application' )
                $context = new ApplicationCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            
            elseif( $this->utilType == 'device' )
                $context = new DeviceCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'vsys' )
                $context = new VsysCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);

            elseif( $this->utilType == 'zone' )
                $context = new ZoneCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'virtualwire' )
                $context = new VirtualWireCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'routing' )
                $context = new RoutingCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'interface' )
                $context = new InterfaceCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);

            $context->baseObject = $this->pan;
            if( isset($this->configInput['type']) && $this->configInput['type'] == 'api' )
            {
                $context->isAPI = TRUE;
                $context->connector = $this->pan->connector;
            }

            $this->doActions[] = $context;
        }
//
// ---------
    }


    public function createRQuery()
    {
        //
        // create a RQuery if a filter was provided
        //
        /**
         * @var RQuery $objectFilterRQuery
         */

        if( $this->objectsFilter !== null )
        {
            $this->objectFilterRQuery = new RQuery($this->utilType);
            $res = $this->objectFilterRQuery->parseFromString($this->objectsFilter, $errorMessage);
            if( $res === FALSE )
            {
                fwrite(STDERR, "\n\n**ERROR** Rule filter parser: " . $errorMessage . "\n\n");
                exit(1);
            }

            PH::print_stdout( " - filter after sanitization : " . $this->objectFilterRQuery->sanitizedString() );
        }
        // --------------------
    }

    #static public function load_config( $pan, $xmlDoc )
    public function load_config()
    {
        //
        // load the config
        //
        PH::print_stdout( " - Loading configuration through PAN-PHP-FRAMEWORK library... " );

        $this->loadStart();

        $this->pan->load_from_domxml($this->xmlDoc, XML_PARSE_BIG_LINES);

        $this->loadEnd();

        PH::print_stdout( "OK! ($this->loadElapsedTime seconds, $this->loadUsedMem memory)" );
        // --------------------
    }

    public function loadStart()
    {
        $this->loadStartMem = memory_get_usage(TRUE);
        $this->loadStartTime = microtime(TRUE);
    }

    public function loadEnd()
    {
        $this->loadEndTime = microtime(TRUE);
        $this->loadEndMem = memory_get_usage(TRUE);
        $this->loadElapsedTime = number_format(($this->loadEndTime - $this->loadStartTime), 2, '.', '');
        $this->loadUsedMem = convert($this->loadEndMem - $this->loadStartMem);
    }

    public function location_filter()
    {
        //
        // Location Filter Processing
        //

        // <editor-fold desc=" ****  Location Filter Processing  ****" defaultstate="collapsed" >
        /**
         * @var RuleStore[] $ruleStoresToProcess
         */
        $this->objectsLocation = explode(',', $this->objectsLocation);

        foreach( $this->objectsLocation as $key => &$location )
        {
            if( strtolower($location) == 'shared' )
                $this->objectsLocation[$key] = 'shared';
            else if( strtolower($location) == 'any' )
                $this->objectsLocation[$key] = 'any';
            else if( strtolower($location) == 'all' )
            {
                if( $this->configType == 'fawkes' )
                    $this->objectsLocation[$key] = 'All';
                else
                    $this->objectsLocation[$key] = 'any';
            }

        }
        unset($location);

        $this->objectsLocation = array_unique($this->objectsLocation);
        if( count( $this->objectsLocation ) == 1 )
        {
            $this->location = $this->objectsLocation[0];
            if( $this->location == 'shared' )
            {
                $this->sub = $this->pan;
            }
            elseif( $this->location == 'any' )
            {
                #
            }
            else
            {
                $this->sub = $this->pan->findSubSystemByName($this->location);
                if( $this->sub === null )
                {
                    $this->locationNotFound($this->location);
                }
            }
        }

        //
        // Template Filter Processing
        //

        // <editor-fold desc=" ****  Location Filter Processing  ****" defaultstate="collapsed" >
        $this->objectsTemplate = explode(',', $this->objectsTemplate);

        foreach( $this->objectsTemplate as $key => &$location )
        {
            if( strtolower($location) == 'any' )
                $this->objectsTemplate[$key] = 'any';
            else if( strtolower($location) == 'all' )
            {
                $this->objectsTemplate[$key] = 'any';
            }

        }
        unset($location);

        $this->objectsTemplate = array_unique($this->objectsTemplate);

        if( count( $this->objectsTemplate ) == 1 )
        {
            $this->templateName = $this->objectsTemplate[0];

            if( $this->templateName == 'shared' )
            {
                #$this->sub = $this->pan;
            }
            elseif( $this->templateName == 'any' )
            {
                #
            }
            else
            {
                $this->template = $this->pan->findTemplate($this->templateName);
                if( $this->template === null )
                {
                    derr("template: " . $this->template . " not found!");
                    #$this->locationNotFound($this->location);
                }
            }
        }
    }

    public function location_filter_object()
    {
        $sub = null;

        //location_filter() must run before;
        foreach( $this->objectsLocation as $location )
        {
            $locationFound = FALSE;

            if( $this->configType == 'panos' )
            {
                if( $location == 'shared' || $location == 'any' )
                {
                    if( $this->utilType == 'address' )
                        $this->objectsToProcess[] = array('store' => $this->pan->addressStore, 'objects' => $this->pan->addressStore->all(null, TRUE));
                    elseif( $this->utilType == 'service' )
                        $this->objectsToProcess[] = array('store' => $this->pan->serviceStore, 'objects' => $this->pan->serviceStore->all(null, TRUE));
                    elseif( $this->utilType == 'tag' )
                        $this->objectsToProcess[] = array('store' => $this->pan->tagStore, 'objects' => $this->pan->tagStore->getall());
                    elseif( $this->utilType == 'vsys' )
                        $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getVirtualSystems());
                    elseif( $this->utilType == 'securityprofilegroup' )
                        $this->objectsToProcess[] = array('store' => $this->pan->securityProfileGroupStore, 'objects' => $this->pan->securityProfileGroupStore->getAll());
                    elseif( $this->utilType == 'schedule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->scheduleStore, 'objects' => $this->pan->scheduleStore->getall());
                    elseif( $this->utilType == 'application' )
                        $this->objectsToProcess[] = array('store' => $this->pan->appStore, 'objects' => $this->pan->appStore->apps());
                    
                    $locationFound = TRUE;
                }
                foreach( $this->pan->getVirtualSystems() as $sub )
                {
                    if( isset(PH::$args['loadpanoramapushedconfig']) )
                    {
                        if( $this->utilType == 'address' )
                            $this->objectsToProcess[] = array('store' => $sub->addressStore, 'objects' => $sub->addressStore->resultingObjectSet());
                        elseif( $this->utilType == 'service' )
                            $this->objectsToProcess[] = array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->resultingObjectSet());
                        elseif( $this->utilType == 'tag' )
                            $this->objectsToProcess[] = array('store' => $sub->tagStore, 'objects' => $sub->tagStore->resultingObjectSet());
                        elseif( $this->utilType == 'securityprofilegroup' )
                            $this->objectsToProcess[] = array('store' => $sub->securityProfileGroupStore, 'objects' => $sub->securityProfileGroupStore->resultingObjectSet());
                        elseif( $this->utilType == 'schedule' )
                            $this->objectsToProcess[] = array('store' => $sub->scheduleStore, 'objects' => $sub->scheduleStore->resultingObjectSet());
                        elseif( $this->utilType == 'application' )
                            $this->objectsToProcess[] = array('store' => $sub->appStore, 'objects' => $sub->appStore->resultingObjectSet());
                        
                        $locationFound = TRUE;
                    }
                    elseif( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                    {
                        if( $this->utilType == 'address' )
                            $this->objectsToProcess[] = array('store' => $sub->addressStore, 'objects' => $sub->addressStore->all(null, TRUE));
                        elseif( $this->utilType == 'service' )
                            $this->objectsToProcess[] = array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all(null, TRUE));
                        elseif( $this->utilType == 'tag' )
                            $this->objectsToProcess[] = array('store' => $sub->tagStore, 'objects' => $sub->tagStore->getall());
                        elseif( $this->utilType == 'securityprofilegroup' )
                            $this->objectsToProcess[] = array('store' => $sub->securityProfileGroupStore, 'objects' => $sub->securityProfileGroupStore->getAll());
                        elseif( $this->utilType == 'schedule' )
                            $this->objectsToProcess[] = array('store' => $sub->scheduleStore, 'objects' => $sub->scheduleStore->getall());
                        elseif( $this->utilType == 'application' )
                            $this->objectsToProcess[] = array('store' => $sub->appStore, 'objects' => $sub->appStore->apps());


                        $locationFound = TRUE;
                    }
                    #}


                    self::GlobalInitAction($sub);
                }
            }
            else
            {
                if( $this->configType == 'panorama' && ($location == 'shared' || $location == 'any') )
                {
                    if( $this->utilType == 'address' )
                        $this->objectsToProcess[] = array('store' => $this->pan->addressStore, 'objects' => $this->pan->addressStore->all(null, TRUE));
                    elseif( $this->utilType == 'service' )
                        $this->objectsToProcess[] = array('store' => $this->pan->serviceStore, 'objects' => $this->pan->serviceStore->all(null, TRUE));

                    elseif( $this->utilType == 'tag' )
                        $this->objectsToProcess[] = array('store' => $this->pan->tagStore, 'objects' => $this->pan->tagStore->getall());
                    elseif( $this->utilType == 'securityprofilegroup' )
                        $this->objectsToProcess[] = array('store' => $this->pan->securityProfileGroupStore, 'objects' => $this->pan->securityProfileGroupStore->getAll());
                    elseif( $this->utilType == 'schedule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->scheduleStore, 'objects' => $this->pan->scheduleStore->getall());
                    elseif( $this->utilType == 'application' )
                        $this->objectsToProcess[] = array('store' => $this->pan->appStore, 'objects' => $this->pan->appStore->apps());

                    $locationFound = TRUE;
                }
                elseif( $this->configType == 'fawkes' && ($location == 'ANY' || $location == 'any') )
                {
                    if( $this->utilType == 'application' )
                        $this->objectsToProcess[] = array('store' => $this->pan->appStore, 'objects' => $this->pan->appStore->apps());

                    $locationFound = TRUE;
                }


                if( $this->configType == 'panorama' )
                    $subGroups = $this->pan->getDeviceGroups();
                elseif( $this->configType == 'fawkes' )
                {
                    $subGroups = $this->pan->getContainers();
                    $subGroups2 = $this->pan->getDeviceClouds();

                    $subGroups = array_merge( $subGroups, $subGroups2 );
                }


                foreach( $subGroups as $sub )
                {
                    #if( ($location == 'any' || $location == 'all' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name() . '%pre']) )
                    if( ($location == 'any' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name() . '%pre']) )
                    {
                        if( $this->utilType == 'address' )
                            $this->objectsToProcess[] = array('store' => $sub->addressStore, 'objects' => $sub->addressStore->all(null, TRUE));
                        elseif( $this->utilType == 'service' )
                            $this->objectsToProcess[] = array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all(null, TRUE));

                        elseif( $this->utilType == 'tag' )
                            $this->objectsToProcess[] = array('store' => $sub->tagStore, 'objects' => $sub->tagStore->getall());
                        elseif( $this->utilType == 'securityprofilegroup' )
                            $this->objectsToProcess[] = array('store' => $sub->securityProfileGroupStore, 'objects' => $sub->securityProfileGroupStore->getAll());
                        elseif( $this->utilType == 'schedule' )
                            $this->objectsToProcess[] = array('store' => $sub->scheduleStore, 'objects' => $sub->scheduleStore->getall());
                        elseif( $this->utilType == 'application' )
                            $this->objectsToProcess[] = array('store' => $sub->appStore, 'objects' => $sub->appStore->apps());
                        
                        $locationFound = TRUE;
                    }

                    $this->GlobalInitAction($sub);
                }
            }

            if( !$locationFound )
            {
                $this->locationNotFound($location);
            }
        }
    }

    public function locationNotFound($location, $configType = null, $pan = null)
    {
        if( $this->configType == null )
            $this->configType = $configType;
        if( $this->pan == null )
            $this->pan = $pan;

        PH::print_stdout( "" );
        PH::print_stdout( "ERROR: location '$location' was not found. Here is a list of available ones:" );
        if( $this->configType != 'fawkes' )
            PH::print_stdout( " - shared" );
        if( $this->configType == 'panos' )
        {
            foreach( $this->pan->getVirtualSystems() as $sub )
            {
                PH::print_stdout( " - " . $sub->name() );
            }
        }
        else
        {
            if( $this->configType == 'panorama' )
                $subGroups = $this->pan->getDeviceGroups();
            elseif( $this->configType == 'fawkes' )
            {
                $subGroups = $this->pan->getContainers();
                $subGroups2 = $this->pan->getDeviceClouds();

                $subGroups = array_merge( $subGroups, $subGroups2 );
            }

            foreach( $subGroups as $sub )
            {
                PH::print_stdout( " - " . $sub->name() );
            }
        }
        PH::print_stdout( "" );
        PH::print_stdout( "" );
        exit(1);
    }

    public function GlobalInitAction($sub)
    {
        foreach( $this->doActions as $doAction )
        {
            if( $doAction->hasGlobalInitAction() )
            {
                $doAction->subSystem = $sub;
                $doAction->executeGlobalInitAction();
            }
        }
    }

    public function time_to_process_objects()
    {
        //
        // It's time to process Rules !!!!
        //

        // <editor-fold desc=" *****  Object Processing  *****" defaultstate="collapsed" >
        foreach( $this->objectsToProcess as &$objectsRecord )
        {
            $subObjectsProcessed = 0;

            $store = $objectsRecord['store'];
            $objects = &$objectsRecord['objects'];

            PH::print_stdout( "" );
            PH::print_stdout( "* processing store '" . PH::boldText($store->toString()) . "' that holds " . count($objects) . " objects" );

            foreach( $this->doActions as $doAction )
            {
                if( is_object($store->owner) )
                    $doAction->subSystem = $store->owner;
                else
                    $doAction->subSystem = $store;
            }

            if( count($objects) > 0 )
            {
                foreach( $objects as $object )
                {
                    /** @var Address|AddressGroup $object */
                    if( $this->objectFilterRQuery !== null )
                    {
                        $queryResult = $this->objectFilterRQuery->matchSingleObject(array('object' => $object, 'nestedQueries' => &$this->nestedQueries));
                        if( !$queryResult )
                            continue;
                    }

                    $this->totalObjectsProcessed++;
                    $subObjectsProcessed++;

                    //mwarning($object->name());

                    foreach( $this->doActions as $doAction )
                    {
                        $doAction->padding = '     ';
                        $doAction->executeAction($object);
                        PH::print_stdout( "" );
                    }
                }
            }

            if( is_object($store->owner) )
                $tmp_name = $store->owner->name();
            elseif( is_object($store) )
                $tmp_name = $store->name();

            PH::print_stdout( "" );
            PH::print_stdout( "* objects processed in DG/Vsys '{$tmp_name}' : $subObjectsProcessed" );
            PH::print_stdout( "" );
        }
        // </editor-fold>
    }

    public function GlobalFinishAction()
    {
        $first = TRUE;
        foreach( $this->doActions as $doAction )
        {
            if( $doAction->hasGlobalFinishAction() )
            {
                $first = FALSE;
                $doAction->executeGlobalFinishAction();
            }
        }
    }

    public function stats()
    {
        if( isset(PH::$args['stats']) )
        {
            /** @var PANConf|PanoramaConf|FawkesConf $pan */
            $pan = $this->pan;

            $pan->display_statistics();


            $processedLocations = array();
            foreach( $this->objectsToProcess as &$record )
            {
                if( get_class($record['store']->owner) != 'PanoramaConf' && get_class($record['store']->owner) != 'PANConf' )
                {
                    /** @var DeviceGroup|VirtualSystem|Container|DeviceCloud $sub */
                    $sub = $record['store']->owner;
                    if( isset($processedLocations[$sub->name()]) )
                        continue;

                    $processedLocations[$sub->name()] = TRUE;

                    $sub->display_statistics();
                }
            }
        }
    }

    public function save_our_work($additional_output = FALSE, $printMessage = TRUE, $lineReturn = TRUE, $indentingXml = 0, $indentingXmlIncreament = 1)
    {
        if( PH::$shadow_reducexml )
        {
            $lineReturn = false;
            $indentingXml = -1;
            $indentingXmlIncreament = 0;
        }
        // save our work !!!
        if( $this->configOutput !== null )
        {
            if( $this->configOutput != '/dev/null' )
            {
                // destroy destination file if it exists
                if( file_exists($this->configOutput) && is_file($this->configOutput) )
                    unlink($this->configOutput);

                //          save_to_file($fileName, $printMessage=true, $lineReturn = true, $indentingXml = 0, $indentingXmlIncreament = 1 )
                $this->pan->save_to_file($this->configOutput, $printMessage, $lineReturn, $indentingXml, $indentingXmlIncreament);
            }
        }


        if( $additional_output )
        {
            if( $this->configInput['type'] != 'api' && $this->configOutput == "/dev/null" )
            {
                PH::print_stdout( "" );
                PH::print_stdout( "argument 'out' was used with '/dev/null' - nothing is saved to an output file" );
            }

            if( isset(PH::$args['actions']) && PH::$args['actions'] == "display" )
            {
                PH::print_stdout( "argument 'actions' was used with 'display'" );
            }
        }

        $this->log->info("END UTIL: " . $this->PHP_FILE);
    }

    static public function setTimezone()
    {
        if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
        {
            $system_timezone = exec('tzutil /g');

            $temp = explode(' ', $system_timezone);
            $result = '';
            foreach( $temp as $t )
                $result .= $t[0];

            $system_timezone = strtoupper($result);
        }
        else
        {
            $system_timezone = exec('date +%Z');
        }

        $timezone_name = timezone_name_from_abbr($system_timezone);
        if( !$timezone_name )
            $timezone_name = "GMT";
        date_default_timezone_set($timezone_name);
    }

    static public function shadow_ignoreInvalidAddressObjects()
    {
        PH::$ignoreInvalidAddressObjects = TRUE;
    }
}