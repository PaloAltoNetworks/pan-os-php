<?php

class PanSaseAPIConnector
{
    public $name = 'connector';

    /** @var string */
    public $apikey;
    /** @var string */
    public $apihost;

    /** @var string */
    public $client_id;
    /** @var string */
    public $client_secret;
    /** @var string */
    public $scope;

    public $access_token;

    /** @var bool */
    public $showApiCalls = FALSE;

    public $global_limit = 200;

    /**
     * @var PanAPIConnector[]
     */
    static public $savedConnectors = array();
    static public $projectfolder = "";
    static private $keyStoreFileName = '.panconfkeystore';
    static private $keyStoreInitialized = FALSE;

    private $utilType = null;
    private $utilAction = "";

    public $token_url = "https://auth.apps.paloaltonetworks.com/oauth2/access_token";
    public $test_api_url = "https://api.sase.paloaltonetworks.com";

    static public $folderArray = array(
        "Shared",
        "Mobile Users",
        "Remote Networks",
        "Service Connections",
        "Mobile Users Container",
        "Mobile Users Explicit Proxy"
    );

    static public $typeArrayOLD = array(
        "addresses",
        "addresse-groups"
    );

    private $typeArray = array();

    /**
     * @param string $host
     * @param string $key
     * @param string $type can be 'panos' 'panorama' or 'panos-via-panorama'
     * @param integer $port
     * @param string|null $serial
     */
    public function __construct($host, $key = null, $type = 'panos', $serial = null, $port = 443)
    {
        #$this->setType($type, $serial);

        $this->apikey = $key;
        $this->apihost = $host;

        $this->scope = "tsg_id:" . $host;
        if( $key != null )
        {
            $test = explode("%", $key);
            $this->client_id = $test[0];
            $this->client_secret = $test[1];
        }
    }

    public function findOrCreateConnectorFromHost($TSGid)
    {
        //$host must be "tsg_id".TSG_ID
        $host = "tsg_id" . $TSGid;

        foreach( PanAPIConnector::$savedConnectors as $connector )
        {
            if( strpos($connector->apihost, $host) !== FALSE )
            {
                $key = $connector->apikey;
                $test = explode("%", $key);
                $this->client_id = $test[0];
                $this->client_secret = $test[1];
                break;
            }
            else
                $connector = null;
        }
        if( $connector === null )
        {
            PH::print_stdout(" ** Please enter client_id");
            $handle = fopen("php://stdin", "r");
            $line = fgets($handle);
            $this->client_id = trim($line);

            PH::print_stdout(" ** Please enter client_secret");
            $handle = fopen("php://stdin", "r");
            $line = fgets($handle);
            $this->client_secret = trim($line);

            $addHost = "tsg_id" . $TSGid;
            $key = $this->client_id . "%" . $this->client_secret;

            foreach( PanAPIConnector::$savedConnectors as $cIndex => $connector )
            {
                if( $connector->apihost == $addHost )
                    unset(PanAPIConnector::$savedConnectors[$cIndex]);
            }

            PanAPIConnector::$savedConnectors[] = new PanAPIConnector($addHost, $key);
            PanAPIConnector::saveConnectorsToUserHome();
        }
    }

    public function getAccessToken()
    {
        /*
        curl -d "grant_type=client_credentials&scope=tsg_id:<tsg_id>" \
        -u <client_id>:<client_secret> \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -X POST https://auth.apps.paloaltonetworks.com/oauth2/access_token
        */
        $content = "grant_type=client_credentials&scope=" . $this->scope . "&client_id=" . $this->client_id . "&client_secret=" . $this->client_secret;
        $header = array("Content-Type: application/x-www-form-urlencoded");


        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $this->token_url,
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_SSL_VERIFYPEER => FALSE,
            CURLOPT_RETURNTRANSFER => TRUE,
            CURLOPT_POST => TRUE,
            CURLOPT_POSTFIELDS => $content

            #CURLOPT_POSTFIELDS => $content,
            #CURLOPT_FOLLOWLOCATION => TRUE,
            #CURLOPT_VERBOSE => TRUE
        ));
        $response = curl_exec($curl);

        if( empty($response) )
            derr("something wwent wrong - check internet connection", null, FALSE);

        curl_close($curl);


        $jsonArray = json_decode($response, TRUE);
        if( !isset($jsonArray['access_token']) )
            derr( "problem with SASE API connection - not possible to get 'access_token'", null, FALSE );

        $this->access_token = $jsonArray['access_token'];
    }

    function getTypeArray($utilType, $ruleType = "security")
    {
        $this->typeArray = array();
        if( $utilType == "address" )
        {
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";
        }
        elseif( $utilType == "service" )
        {
            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";
        }
        elseif( $utilType == "rule" )
        {
            $this->typeArray[] = "security-rules";
            #$this->typeArray[] = "authentication-rules"; //problems reading config also in Shared
            #$this->typeArray[] = "qos-policy-rules"; // Access denied
            #$this->typeArray[] = "app-override-rules"; //problems reading config also in Shared
            #"$this->typeArray[] = decryption-rules";
        }
        elseif( $utilType == "tag" )
        {
            $this->typeArray[] = "tags";
        }
        elseif( $utilType == "schedule" )
        {
            $this->typeArray[] = "schedules";
        }
        elseif( $utilType == "application" )
        {
            $this->typeArray[] = "applications";
            $this->typeArray[] = "application-filters";
            $this->typeArray[] = "application-groups";
        }
        elseif( $utilType == "upload" )
        {
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";

            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";

            $this->typeArray[] = "security-rules";
            #$this->typeArray[] = "authentication-rules"; //problems reading config also in Shared
            #$this->typeArray[] = "qos-policy-rules"; // Access denied
            #$this->typeArray[] = "app-override-rules"; //problems reading config also in Shared
            #"$this->typeArray[] = decryption-rules";

            $this->typeArray[] = "tags";

            $this->typeArray[] = "schedules";

            #$this->typeArray[] = "applications";
            $this->typeArray[] = "application-filters";
            $this->typeArray[] = "application-groups";
        }
        elseif( $utilType == "device" )
        {
            mwarning("only local offline config validation", null, FALSE);
        }
        elseif( $utilType == "custom" )
        {
        }
        else
        {
            derr("PAN-OS-PHP connection method 'sase-api://' - do not yet support this UTIL type: '" . $utilType . "'", null, FALSE);
        }

        #"hip-objects",
        #"hip-profiles",

        ######
        #"profile-groups",

        #"anti-spyware-profiles",
        #"wildfire-anti-virus-profiles",
        #"vulnerability-protection-profile",
        #"dns-security-profiles",
        #"file-blocking-profiles",
        #"decryption-profiles",

        return $this->typeArray;
    }

    function getResource($access_token, $type = "address", $folder = "Shared", $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1)
    {

        $url = $this->test_api_url;
        $url .= "/sse/config/v1/" . $type . "?folder=" . $folder;

        $url .= "&limit=" . $this->global_limit;

        if( $offset !== "" )
            $url .= "&offset=" . $offset;

        if( strpos($type, "-rule") !== FALSE )
            $url .= "&position=" . $prePost;

        $url = str_replace(' ', '%20', $url);

        if( $this->showApiCalls )
            PH::print_stdout($url);

        $header = array("Authorization: Bearer {$access_token}");

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_SSL_VERIFYPEER => FALSE,
            CURLOPT_RETURNTRANSFER => TRUE
        ));
        $response = curl_exec($curl);
        if( $this->showApiCalls )
            print $response . "\n";
        curl_close($curl);

        $jsonArray = json_decode($response, TRUE);

        if( isset($jsonArray['_error']) )
            derr($jsonArray['_error']['message'], null, FALSE);

        if( $jsonArray !== null
            && isset($jsonArray['total'])
            && $jsonArray['total'] > ($this->global_limit - 1)
            && $jsonArray['total'] > ($runtime * $this->global_limit)
        )
        {
            $offset = $this->global_limit * $runtime;
            $runtime++;
            $resource = $this->getResource($access_token, $type, $folder, $this->global_limit, $prePost, $offset, $runtime);

            foreach( $resource['data'] as $data )
                $jsonArray['data'][] = $data;
        }


        return $jsonArray;
    }

    function loadSaseConfig($folder, $sub, $utilType, $ruleType = "security")
    {
        $typeArray = $this->getTypeArray($utilType);
        foreach( $typeArray as $type )
        {
            $resource = $this->getResource($this->access_token, $type, $folder, $this->global_limit);

            if( $resource !== null )
            {
                if( $this->showApiCalls )
                {
                    PH::print_stdout("|" . $folder . " - " . $type);
                    print_r($resource);
                }

                $this->importConfig($sub, $folder, $type, $resource);

                if( $this->showApiCalls )
                    PH::print_stdout("------------------------------");
            }
            else
            {
                if( $this->showApiCalls )
                {
                    PH::print_stdout("|" . $folder . " - " . $type . "| empty");
                    PH::print_stdout("------------------------------");
                }
            }

            $json_string = json_encode($resource, JSON_PRETTY_PRINT);
            if( $this->showApiCalls )
                print $json_string . "\n";

            if( strpos($type, '-rules') !== FALSE )
            {
                $resource = $this->getResource($this->access_token, $type, $folder, $this->global_limit, 'post');

                if( $resource !== null )
                {
                    if( $this->showApiCalls )
                    {
                        PH::print_stdout("|" . $folder . " - " . $type);
                        print_r($resource);
                    }

                    $this->importConfig($sub, $folder, $type, $resource);

                    if( $this->showApiCalls )
                        PH::print_stdout("------------------------------");
                }

                $json_string = json_encode($resource, JSON_PRETTY_PRINT);
            }
        }
    }

    function importConfig($sub, $folder, $type, $jsonArray)
    {
        if( !isset($jsonArray['data']) )
            return null;

        /** @var Container|DeviceCloud $sub */
        foreach( $jsonArray['data'] as $object )
        {
            if( $object['folder'] === "predefined" )
                continue;

            if( $object['folder'] !== $folder )
                continue;

            if( $type === "addresses" )
            {
                if( isset($object['ip_netmask']) )
                    $tmp_address = $sub->addressStore->newAddress($object['name'], 'ip-netmask', $object['ip_netmask']);
                elseif( isset($object['fqdn']) )
                    $tmp_address = $sub->addressStore->newAddress($object['name'], 'fqdn', $object['fqdn']);

                if( isset($object['description']) )
                    $tmp_address->setDescription($object['description']);

                if( isset($object['tag']) )
                {
                    foreach( $object['tag'] as $tag )
                    {
                        $tmp_tag = $sub->tagStore->findOrCreate($tag);
                        $tmp_address->tags->addTag($tmp_tag);
                    }
                }
            }
            elseif( $type === "tags" )
            {
                #$tmp_tag = $sub->tagStore->createTag($object['name']);
                $tmp_tag = $sub->tagStore->findOrCreate($object['name']);

                if( isset($object['color']) )
                {
                    $tmp_tag->setColor($object['color']);
                }

            }
            elseif( $type === "address-groups" )
            {
                if( isset($object['static']) )
                {
                    $tmp_addressgroup = $sub->addressStore->newAddressGroup($object['name']);
                    foreach( $object['static'] as $member )
                    {
                        $tmp_address = $sub->addressStore->find($member);
                        $tmp_addressgroup->addMember($tmp_address);
                    }
                }
            }
            elseif( $type === "services" )
            {
                foreach( $object['protocol'] as $prot => $entry )
                {
                    $tmp_service = $sub->serviceStore->newService($object['name'], $prot, $entry['port']);
                }

                if( isset($object['description']) )
                    $tmp_service->setDescription($object['description']);
            }
            elseif( $type === "schedules" )
            {
                $tmp_schedule = $sub->scheduleStore->createSchedule($object['name']);

                if( isset($object['schedule_type']['non_recurring']) )
                {
                    foreach( $object['schedule_type']['non_recurring'] as $entry )
                        $tmp_schedule->setNonRecurring($entry);
                }
                elseif( isset($object['schedule_type']['recurring']) )
                {
                    if( isset($object['schedule_type']['recurring']['daily']) )
                    {
                        foreach( $object['schedule_type']['recurring']['daily'] as $entry )
                            $tmp_schedule->setRecurringDaily($entry);
                    }

                    if( isset($object['schedule_type']['recurring']['weekly']) )
                    {
                        foreach( $object['schedule_type']['recurring']['weekly'] as $day => $entry )
                        {
                            foreach( $entry as $entry2 )
                                $tmp_schedule->setRecurringWeekly($day, $entry2);
                        }
                    }
                }
            }
            elseif( $type === "application-groups" )
            {
                //pan-os-php has no newApplicationGroup method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "application-filters" )
            {
                //pan-os-php has no newApplicationFilters method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "regions" )
            {
                //pan-os-php has no newRegion method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "applications" )
            {
                //pan-os-php has no newApplication method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "hip-objects" )
            {
                //pan-os-php has no newhip-objects method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "hip-profiles" )
            {
                //pan-os-php has no newhip-profiles method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "security-rules" )
            {
                $tmp_rule = null;
                $position = $object['position'];
                if( $position === "post" )
                    $tmp_rule = $sub->securityRules->newSecurityRule($object['name'], TRUE);
                else
                    $tmp_rule = $sub->securityRules->newSecurityRule($object['name']);

                if( isset($object['id']) )
                    $tmp_rule->setUUID($object['id']);

                if( isset($object['action']) )
                    $tmp_rule->setAction($object['action']);
                if( isset($object['from']) )
                    foreach( $object['from'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_zone = $sub->zoneStore->findOrCreate($obj);
                        $tmp_rule->from->addZone($tmp_zone);
                    }
                if( isset($object['to']) )
                    foreach( $object['to'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_zone = $sub->zoneStore->findOrCreate($obj);
                        $tmp_rule->to->addZone($tmp_zone);
                    }

                if( isset($object['source']) )
                    foreach( $object['source'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_addr = $sub->addressStore->findOrCreate($obj, null, TRUE);
                        $tmp_rule->source->addObject($tmp_addr);
                    }

                if( isset($object['destination']) )
                    foreach( $object['destination'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_addr = $sub->addressStore->findOrCreate($obj, null, TRUE);
                        $tmp_rule->destination->addObject($tmp_addr);
                    }
                if( isset($object['service']) )
                    foreach( $object['service'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_addr = $sub->serviceStore->findOrCreate($obj, null, TRUE);
                        $tmp_rule->services->add($tmp_addr);
                    }
                if( isset($object['source-user']) )
                    foreach( $object['source-user'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_rule->userID_addUser($obj);
                    }
                if( isset($object['application']) )
                    foreach( $object['application'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_obj = $sub->appStore->findorCreate($obj);
                        $tmp_rule->apps->addApp($tmp_obj);
                    }
                if( isset($object['log-setting']) )
                    $tmp_rule->setLogSetting($object['log-setting']);
                if( isset($object['tag']) )
                    foreach( $object['tag'] as $obj )
                    {
                        $tmp_obj = $sub->tagStore->findOrCreate($obj);
                        $tmp_rule->tags->addTag($tmp_obj);
                    }
                if( isset($object['description']) )
                    $tmp_rule->setDescription($object['description']);
                if( isset($object['category']) )
                    foreach( $object['category'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_rule->setUrlCategories($obj);
                    }
                if( isset($object['disabled']) )
                    if( $object['disabled'] == "true" )
                        $tmp_rule->setDisabled(TRUE);
                if( isset($object['source_hip']) )
                    foreach( $object['source_hip'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        #$tmp_rule->setHipProfile($obj);
                    }
                if( isset($object['destination_hip']) )
                    foreach( $object['destination_hip'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        //destination-hip not implemented in pan-os-php
                        #$tmp_rule->setHipProfile($obj);
                    }
                if( isset($object['profile_setting']['group']) )
                {
                    foreach( $object['profile_setting']['group'] as $entry )
                        $tmp_rule->setSecurityProfileGroup($entry);
                }
                /*
                "profile_setting": {
                    "group": [
                        "best-practice"
                    ]
                },
                 */
            }
            else
            {
                PH::print_stdout($type . " - 2 not implemented yet");
            }
        }
    }

    public function testConnectivity($checkHost = "")
    {
        PH::print_stdout(" - Testing API connectivity... ");

        $this->getAccessToken();

        /*
        PH::print_stdout(" - PAN-OS version: " . $this->info_PANOS_version);
        PH::$JSON_TMP[$checkHost]['panos']['version'] = $this->info_PANOS_version;
        PH::$JSON_TMP[$checkHost]['panos']['type'] = $this->info_deviceType;
        PH::$JSON_TMP[$checkHost]['status'] = "success";
        */
    }

}
