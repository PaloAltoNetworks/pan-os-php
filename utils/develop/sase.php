<?php

require_once( "lib/pan_php_framework.php" );
require_once ( "utils/lib/UTIL.php" );

##########################################
##########################################

$supportedArguments = array();
//PREDEFINED arguments:
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=filename.xml | api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');

$supportedArguments['client_id'] = array('client_id' => 'client_id', 'shortHelp' => 'user name');
$supportedArguments['client_secret'] = array('client_secret' => 'client_secret', 'shortHelp' => 'user secret');
$supportedArguments['scope'] = array('scope' => 'scope', 'shortHelp' => 'tenante scope');



#$argv[] = "panorama-2fawkes.php";
$argv[] = "in=".dirname(__FILE__)."/fawkes_baseconfig.xml";
#$argv[] = "out=/tmp/sase.xml";


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=FAWKES_baseconfig.xml out=output.xml client_id={{USER}} client_secret={{SECRET}} scope={{tsg_id:TSGID}}";
/**
 * @var UTIL $util_fawkes
 */
$util_fawkes = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);
$util_fawkes->utilInit();

$util_fawkes->load_config();

#if( !isset(PH::$args['in']) )

if( !isset(PH::$args['client_id']) )
    derr( "argument: 'client_id' is missing")  ;
else
    $client_id = PH::$args['client_id'];

if( !isset(PH::$args['client_secret']) )
    derr( "argument: 'client_secret' is missing")  ;
else
    $client_secret = PH::$args['client_secret'];

if( !isset(PH::$args['scope']) )
    derr( "argument: 'scope' is missing")  ;
else
    #$scope = "tsg_id:".PH::$args['scope'];
    $scope = PH::$args['scope'];
##########################################
##########################################


$global_limit = 200;


$token_url = "https://auth.apps.paloaltonetworks.com/oauth2/access_token";
$test_api_url = "https://api.sase.paloaltonetworks.com";


$access_token = getAccessToken();

#getRunningConfig($access_token);
#exit();

#getAPIresponse($access_token);
#exit();

/*
$folderArray = array(
    "Shared",
    "Mobile Users",
    "Remote Networks",
    "Service Connections",
    "Mobile Users Container",
    "Mobile Users Explicit Proxy",
    "swg-container"
);
*/
$folderArray = array(
    "Shared",
    "Mobile Users",
    "Remote Networks",
    "Service Connections",
    "Mobile Users Container",
    "Mobile Users Explicit Proxy"
);


$typeArray = array(
    "tags",

    "addresses",
    "address-groups",
    "services",
    "service-groups",

    "schedules",

    "regions",
    #"applications",
    "application-filters",
    "application-groups",

    "hip-objects",
    "hip-profiles",

    //RULES
    "security-rules",
    "authentication-rules",
    "qos-policy-rules",
    "app-override-rules",
    "decryption-rules",



    "profile-groups",

    "anti-spyware-profiles",
    "wildfire-anti-virus-profiles",
    "vulnerability-protection-profile",
    "dns-security-profiles",
    "file-blocking-profiles",
    "decryption-profiles",

);
//missing:
//dynamic-user-groups
//authenticaiton-portals
//authentication-profiles

$typeArray = array(


    //RULES
    "security-rules"
);

/*
$typeArray = array(
    #"tags",
    "addresses",
    #"address-groups",
    #"services",
    #"service-groups",
    #"schedules",

    #"regions",
    #"applications",
    #"application-filters",
    #"application-groups",

    #"hip-objects",
    #"hip-profiles",

    #"security-rules",

    #"authentication-rules", //problems reading config also in Shared
    #"qos-policy-rules", // Access denied
    #"app-override-rules",////problems reading config also in Shared
    #"decryption-rules",


    ######
    #"profile-groups",

    #"anti-spyware-profiles",
    #"wildfire-anti-virus-profiles",
    #"vulnerability-protection-profile",
    #"dns-security-profiles",
    #"file-blocking-profiles",
    #"decryption-profiles",
);
*/

foreach( $folderArray as $folder )
{
    if( $folder === "Shared" )
        $sub = $util_fawkes->pan->findContainer( "Prisma Access");
    else
    {
        $sub = $util_fawkes->pan->findContainer( $folder);
        if( $sub === null )
        {
            $sub = $util_fawkes->pan->findDeviceCloud( $folder);
            if( $sub === null )
                $sub = $util_fawkes->pan->createDeviceCloud( $folder, "Prisma Access" );
        }

    }


    foreach( $typeArray as $type )
    {
        $resource = getResource($access_token, $type, $folder, $global_limit);


        if( $resource !== NULL )
        {
            PH::print_stdout( "|".$folder. " - ".$type);
            print_r( $resource );

            importConfig( $sub, $folder, $type, $resource );

            PH::print_stdout( "------------------------------");
        }
        else
        {
            #PH::print_stdout( "|".$folder. " - ".$type ."| empty");
            #PH::print_stdout( "------------------------------");
        }

        $json_string = json_encode($resource, JSON_PRETTY_PRINT);
        #print $json_string."\n";
    }
}
$util_fawkes->save_our_work();



####################################################################################
####################################################################################
####################################################################################
####################################################################################




//	step A, B - single call with client credentials as the basic auth header
//		will return access_token
function getAccessToken() {
    global $token_url, $client_id, $client_secret,$scope;

    /*
curl -d "grant_type=client_credentials&scope=tsg_id:<tsg_id>" \
-u <client_id>:<client_secret> \
-H "Content-Type: application/x-www-form-urlencoded" \
-X POST https://auth.apps.paloaltonetworks.com/oauth2/access_token
*/

    $content = "grant_type=client_credentials&scope=".$scope."&client_id=".$client_id."&client_secret=".$client_secret;

    $header = array("Content-Type: application/x-www-form-urlencoded");

    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => $token_url,
        CURLOPT_HTTPHEADER => $header,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $content
        //CURLOPT_FOLLOWLOCATION => TRUE,
        //CURLOPT_VERBOSE => TRUE
    ));
    $response = curl_exec($curl);

    #print $response."\n";

    curl_close($curl);


    $jsonArray = json_decode( $response, true );

    return $jsonArray['access_token'];
}

//	step B - with the returned access_token we can make as many calls as we want
function getResource($access_token, $type = "address", $folder = "Shared", $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1) {
    global $test_api_url;
    global $global_limit;

    $url = $test_api_url;
    $url .= "/sse/config/v1/".$type."?folder=".$folder;

    $url .= "&limit=".$global_limit;

    if( $offset !== "" )
        $url .= "&offset=".$offset;

    if( strpos( $type, "-rule" ) !== FALSE )
        $url .= "&position=".$prePost;

    $url = str_replace(' ', '%20', $url);
    PH::print_stdout( $url );
    $header = array("Authorization: Bearer {$access_token}");

    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => $url,
        CURLOPT_HTTPHEADER => $header,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_RETURNTRANSFER => true
    ));
    $response = curl_exec($curl);
    curl_close($curl);

    $jsonArray = json_decode($response, true);


    if( $jsonArray !== null
        && isset( $jsonArray['total'] )
        && $jsonArray['total'] > ($global_limit - 1)
        && $jsonArray['total'] > ($runtime * $global_limit)
    )
    {
        $offset = $global_limit * $runtime ;
        $runtime++;
        $resource = getResource($access_token, $type, $folder, $global_limit, $prePost, $offset, $runtime);

        foreach( $resource['data'] as $data )
            $jsonArray['data'][] = $data;
    }


    return $jsonArray;
}


///sse/config/v1/config-versions/running
function getRunningConfig($access_token, $type = "address", $folder = "Shared", $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1) {
    global $test_api_url;
    global $global_limit;

    $url = $test_api_url;
    #$url .= "/sse/config/v1/config-versions/running";
    $url .= "/sse/config/v1/config-versions";

    /*
    $url .= "&limit=".$global_limit;

    if( $offset !== "" )
        $url .= "&offset=".$offset;

    if( strpos( $type, "-rule" ) !== FALSE )
        $url .= "&position=".$prePost;
    */

    $url = str_replace(' ', '%20', $url);
    PH::print_stdout( $url );
    $header = array("Authorization: Bearer {$access_token}");

    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => $url,
        CURLOPT_HTTPHEADER => $header,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_RETURNTRANSFER => true
    ));
    $response = curl_exec($curl);
    print $response."\n";
    curl_close($curl);

    $jsonArray = json_decode($response, true);


    print_r( $jsonArray );
    /*
    if( $jsonArray !== null
        && isset( $jsonArray['total'] )
        && $jsonArray['total'] > ($global_limit - 1)
        && $jsonArray['total'] > ($runtime * $global_limit)
    )
    {
        $offset = $global_limit * $runtime ;
        $runtime++;
        $resource = getResource($access_token, $type, $folder, $global_limit, $prePost, $offset, $runtime);

        foreach( $resource['data'] as $data )
            $jsonArray['data'][] = $data;
    }


    return $jsonArray;
    */
}

function importConfig( $sub, $folder, $type, $jsonArray )
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
        elseif($type === "tags")
        {
            $tmp_tag = $sub->tagStore->createTag($object['name']);

            if( isset( $object['color'] ) )
            {
                $tmp_tag->setColor( $object['color'] );
            }

        }
        elseif($type === "address-groups")
        {
            if( isset($object['static']) )
            {
                $tmp_addressgroup = $sub->addressStore->newAddressGroup( $object['name'] );
                foreach( $object['static'] as $member )
                {
                    $tmp_address = $sub->addressStore->find( $member );
                    $tmp_addressgroup->addMember( $tmp_address );
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
                $tmp_service->setDescription( $object['description'] );
        }
        elseif( $type === "schedules" )
        {
            $tmp_schedule = $sub->scheduleStore->createSchedule( $object['name'] );

            if( isset( $object['schedule_type']['non_recurring'] ) )
            {
                foreach( $object['schedule_type']['non_recurring'] as $entry )
                    $tmp_schedule->setNonRecurring( $entry );
            }
            elseif( isset( $object['schedule_type']['recurring'] ) )
            {
                if( isset( $object['schedule_type']['recurring']['daily'] ) )
                {
                    foreach( $object['schedule_type']['recurring']['daily'] as $entry )
                        $tmp_schedule->setRecurringDaily( $entry );
                }

                if( isset( $object['schedule_type']['recurring']['weekly'] ) )
                {
                    foreach( $object['schedule_type']['recurring']['weekly'] as $day => $entry )
                    {
                        foreach( $entry as $entry2 )
                            $tmp_schedule->setRecurringWeekly( $day, $entry2 );
                    }
                }
            }
        }
        elseif( $type === "application-groups" )
        {
            //pan-os-php has no newApplicationGroup method
        }
        elseif( $type === "application-filters" )
        {
            //pan-os-php has no newApplicationFilters method
        }
        elseif( $type === "regions" )
        {
            //pan-os-php has no newRegion method
        }
        elseif( $type === "applications" )
        {
            //pan-os-php has no newApplication method
        }
        elseif( $type === "hip-objects" )
        {
            //pan-os-php has no newhip-objects method
        }
        elseif( $type === "hip-profiles" )
        {
            //pan-os-php has no newhip-profiles method
        }
        elseif( $type === "security-rules" )
        {
            $tmp_rule = null;
            $position = $object['position'];
            if( $position === "post" )
                $tmp_rule = $sub->securityRules->newSecurityRule($object['name'], true);
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
                    $tmp_rule->from->addZone( $tmp_zone );
                }
            if( isset($object['to']) )
                foreach( $object['to'] as $obj )
                {
                    if( $obj === "any" )
                        continue;
                    $tmp_zone = $sub->zoneStore->findOrCreate($obj);
                    $tmp_rule->to->addZone( $tmp_zone );
                }

            if( isset($object['source']) )
                foreach( $object['source'] as $obj )
                {
                    if( $obj === "any" )
                        continue;
                    $tmp_addr = $sub->addressStore->findOrCreate($obj, null, true);
                    $tmp_rule->source->addObject( $tmp_addr );
                }

            if( isset($object['destination']) )
                foreach( $object['destination'] as $obj )
                {
                    if( $obj === "any" )
                        continue;
                    $tmp_addr = $sub->addressStore->findOrCreate($obj, null, true);
                    $tmp_rule->destination->addObject( $tmp_addr );
                }
            if( isset($object['service']) )
                foreach( $object['service'] as $obj )
                {
                    if( $obj === "any" )
                        continue;
                    $tmp_addr = $sub->serviceStore->findOrCreate($obj, null, true);
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
            //log-setting
            //tag
            //description
            //category
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
                foreach($object['category'] as $obj)
                {
                    if( $obj === "any" )
                        continue;
                    $tmp_rule->setUrlCategories($obj);
                }
        }
    }
}


//https://api.sase.paloaltonetworks.com/sse/config/v1/config-versions/running
function getAPIresponse($access_token){
    global $test_api_url;
    global $global_limit;

    $url = $test_api_url."/sse";
    $url .= "/config/v1";

    $url .= "/config-versions/running";



    $url = str_replace(' ', '%20', $url);
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
    curl_close($curl);

    $jsonArray = json_decode($response, TRUE);
    print_r( $jsonArray );
}

?>