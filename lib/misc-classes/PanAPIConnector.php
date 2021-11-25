<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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

/**
 * This class will allow you interact with PANOS API
 *
 *
 * Code :
 *
 *  $con = PanAPIConnector::findOrCreateConnectorFromHost( 'fw1.company.com' );
 *  $infos = $con->getSoftwareVersion();
 *  PH::print_stdout( "Platform: ".$infos['type']." Version: ".$infos['version'] );
 *  $pan = new PANConf()
 *
 *  $pan->API_load_from_candidate();
 *
 */
class PanAPIConnector
{
    public $name = 'connector';

    /** @var string */
    public $apikey;
    /** @var string */
    public $apihost;

    public $isPANOS = 1;

    /** @var null */
    public $serial = null;

    /** @var integer */
    public $port = 443;

    /** @var bool */
    public $showApiCalls = FALSE;

    /**
     * @var PanAPIConnector[]
     */
    static public $savedConnectors = array();
    static private $keyStoreFileName = '.panconfkeystore';
    static private $keyStoreInitialized = FALSE;

    /** @var null|string $info_deviceType can be "panorama" or "panos" (firewall) */
    public $info_deviceType = null;
    /** @var null|string $info_PANOS_version ie: "7.1.2" */
    public $info_PANOS_version = null;
    /** @var null|int $info_PANOS_version_int integer that represents product OS version, bugfix release is ignore. ie: 7.1.4 -> 71 , 5.0.6 -> 50 */
    public $info_PANOS_version_int = null;
    /** @var null|bool $info_multiVSYS true if firewall multi-vsys is enabled */
    public $info_multiVSYS = null;
    /** @var null|string $info_serial product serial number. ie: "00C734556" */
    public $info_serial = null;
    /** @var null|string $info_hostname device hostname. ie: "PA-200" */
    public $info_hostname = null;
    /** @var null|string $info_mgmtip product mgmt interface IP. ie: "192.168.0.1" */
    public $info_mgmtip = null;
    /** @var null|string $info_uptime device uptime. ie: "57 days, 16:02:48" */
    public $info_uptime = null;
    /** @var string $info_model can be unknown|m100|m500|pa200|pa500|pa2020|PA2050|PA3020|PA3050|PA3060|PA4020|PA4060|PA..... */
    public $info_model = 'unknown';
    /** @var string $info_vmlicense can be unknown|VM-100|VM-200|VM-300|VM-1000 */
    public $info_vmlicense = null;
    public $info_vmuuid = null;
    public $info_vmcpuid = null;

    public $info_app_version = null;
    public $info_av_version = null;
    public $info_wildfire_version = null;
    public $info_threat_version = null;

    private $_curl_handle = null;
    private $_curl_count = 0;

    public $show_config_raw = null;
    public $show_system_info_raw = null;
    public $show_clock_raw = null;
    public $request_license_info_raw = null;

    /**
     * @param bool $force Force refresh instead of using cache
     * @throws Exception
     */
    public function refreshSystemInfos($force = FALSE)
    {
        if( $force )
        {
            $this->info_deviceType = null;
            $this->info_PANOS_version = null;
            $this->info_PANOS_version_int = null;
            $this->info_multiVSYS = null;
            $this->info_serial = null;
            $this->info_hostname = null;
            $this->info_uptime = null;
            $this->info_model = null;
            $this->info_vmlicense = null;
            $this->info_vmuuid = null;
            $this->info_vmcpuid = null;
            $this->info_app_version = null;
            $this->info_av_version = null;
            $this->info_wildfire_version = null;
            $this->info_threat_version = null;
        }

        if( $this->info_serial !== null )
            return;

        $cmd = '<show><system><info></info></system></show>';
        $res = $this->sendOpRequest($cmd, TRUE);

        $this->show_system_info_raw = $res;
        $res = DH::findFirstElement('result', $res);
        if( $res === FALSE )
            derr('cannot find <result>:' . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 2));
        $res = DH::findFirstElement('system', $res);
        if( $res === FALSE )
            derr('cannot find <system>');


        $version = DH::findFirstElement('sw-version', $res);
        if( $version === FALSE )
            derr("cannot find <sw-version>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_PANOS_version = $version->textContent;

        $serial = DH::findFirstElement('serial', $res);
        if( $serial === FALSE )
            derr("cannot find <serial>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_serial = $serial->textContent;

        $hostname = DH::findFirstElement('hostname', $res);
        if( $hostname === FALSE )
            derr("cannot find <hostname>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_hostname = $hostname->textContent;

        $mgmtip = DH::findFirstElement('ip-address', $res);
        if( $mgmtip === FALSE )
            derr("cannot find <ip-address>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_mgmtip = $mgmtip->textContent;

        $uptime = DH::findFirstElement('uptime', $res);
        if( $uptime === FALSE )
            derr("cannot find <uptime>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_uptime = $uptime->textContent;

        $model = DH::findFirstElement('model', $res);
        if( $model === FALSE )
            derr('cannot find <model>', $this->show_system_info_raw);
        $this->info_model = $model->nodeValue;

        $model = strtolower($this->info_model);

        if( $model === 'pa-vm' )
        {
            $vmlicense = DH::findFirstElement('vm-license', $res);
            if( $vmlicense === FALSE )
                derr('cannot find <vm-license>', $this->show_system_info_raw);
            $this->info_vmlicense = $vmlicense->nodeValue;

            $vmuuid = DH::findFirstElement('vm-uuid', $res);
            if( $vmuuid === FALSE )
                derr('cannot find <vm-uuid>', $this->show_system_info_raw);
            $this->info_vmuuid = $vmuuid->nodeValue;

            $vmcpuid = DH::findFirstElement('vm-cpuid', $res);
            if( $vmcpuid === FALSE )
                derr('cannot find <vm-cpuid>', $this->show_system_info_raw);
            $this->info_vmcpuid = $vmcpuid->nodeValue;
        }

        $app_version = DH::findFirstElement('app-version', $res);
        if( $app_version === FALSE )
            derr("cannot find <app-version>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_app_version = $app_version->textContent;

        $av_version = DH::findFirstElement('av-version', $res);
        if( $av_version === FALSE )
            derr("cannot find <av-version>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_av_version = $av_version->textContent;

        $wildfire_version = DH::findFirstElement('wildfire-version', $res);
        if( $wildfire_version === FALSE )
            derr("cannot find <wildfire-version>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
        $this->info_wildfire_version = $wildfire_version->textContent;

        if( $model == 'panorama' || $model == 'm-100' || $model == 'm-500' || $model == 'm-200' || $model == 'm-600' )
        {
            $this->info_deviceType = 'panorama';

            $this->info_threat_version = $this->info_app_version;
        }
        else
        {
            $this->info_deviceType = 'panos';

            $threat_version = DH::findFirstElement('threat-version', $res);
            if( $threat_version === FALSE )
                derr("cannot find <threat-version>:\n" . DH::dom_to_xml($this->show_system_info_raw, 0, TRUE, 4));
            $this->info_threat_version = $threat_version->textContent;
        }

        $vex = explode('.', $this->info_PANOS_version);
        if( count($vex) != 3 )
            derr("ERROR! Unsupported PANOS version :  " . $version . "\n\n");

        $this->info_PANOS_version_int = $vex[0] * 10 + $vex[1] * 1;

        if( $this->info_deviceType == 'panos' )
        {
            $multi = DH::findFirstElement('multi-vsys', $res);
            if( $multi === FALSE )
                derr('cannot find <multi-vsys>', $this->show_system_info_raw);

            $multi = strtolower($multi->textContent);
            if( $multi == 'on' )
                $this->info_multiVSYS = TRUE;
            elseif( $multi == 'off' )
                $this->info_multiVSYS = FALSE;
            else
                derr("unsupported multi-vsys mode: {$multi}");
        }
    }


    public function show_config()
    {
        $params = array();
        $params['type'] = 'config';
        $params['action'] = "show";

        $res = $this->sendRequest($params, TRUE);
        $this->show_config_raw = $res;
    }

    public function request_license_info()
    {
        $cmd = '<request><license><info></info></license></request>';
        $res = $this->sendOpRequest($cmd, TRUE);

        $this->request_license_info_raw = $res;
    }

    public function show_clock()
    {
        $cmd = '<show><clock></clock></show>';
        $res = $this->sendOpRequest($cmd, TRUE);

        $this->show_clock_raw = $res;
    }

    /**
     * @return string[]  Array('type'=> panos|panorama,  'version'=>61 ) (if PANOS=6.1)
     */
    public function getSoftwareVersion()
    {
        if( $this->info_PANOS_version === null )
            $this->refreshSystemInfos();

        return array('type' => $this->info_deviceType, 'version' => $this->info_PANOS_version_int);
    }

    static public function loadConnectorsFromUserHome( $debug = false)
    {
        if( self::$keyStoreInitialized )
            return;

        self::$keyStoreInitialized = TRUE;

        $file = self::findFileConnectorsUserHome();

        if( $debug )
            PH::print_stdout( " - FILE: ".$file );

        if( file_exists($file) )
        {
            $content = file_get_contents($file);
            $content = explode("\n", $content);
            foreach( $content as &$line )
            {
                if( strlen($line) < 1 ) continue;

                $parts = explode(':', $line);
                if( count($parts) != 2 )
                    continue;

                $host = explode('%', $parts[0]);

                if( count($host) > 1 )
                {
                    self::$savedConnectors[] = new PanAPIConnector($host[0], $parts[1], 'panos', null, $host[1]);
                }
                else
                    self::$savedConnectors[] = new PanAPIConnector($host[0], $parts[1]);
            }
        }
    }

    static public function saveConnectorsToUserHome()
    {
        $content = '';
        foreach( self::$savedConnectors as $conn )
        {
            if( $conn->port != 443 )
                $content = $content . $conn->apihost . '%' . $conn->port . ':' . $conn->apikey . "\n";
            else
                $content = $content . $conn->apihost . ':' . $conn->apikey . "\n";
        }

        $file = self::findFileConnectorsUserHome();

        file_put_contents($file, $content);
    }

    static public function findFileConnectorsUserHome()
    {
        if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
        {
            if( strlen(getenv('USERPROFILE')) > 0 )
                $file = getenv('USERPROFILE') . "\\" . self::$keyStoreFileName;
            elseif( strlen(getenv('HOMEDRIVE')) > 0 )
                $file = getenv('HOMEDRIVE') . "\\\\" . getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
            else
                $file = getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
        }
        elseif( !empty( getenv('HOME') ) )
            $file = getenv('HOME') . '/' . self::$keyStoreFileName;
        else
        {
            //optimise this for API usage
            $file = "project/" . self::$keyStoreFileName;
        }

        return $file;
    }

    /**
     * @param string $host
     * @param string $apiKey
     * @param bool $promptForKey
     * @param bool $checkConnectivity
     * @param bool $hiddenPW
     * @return PanAPIConnector
     */
    static public function findOrCreateConnectorFromHost($host, $apiKey = null, $promptForKey = TRUE, $checkConnectivity = TRUE, $hiddenPW = TRUE, $debugAPI = false, $cliUSER = null, $cliPW = null)
    {
        self::loadConnectorsFromUserHome();

        /** @var PanAPIConnector $connector */

        $host = strtolower($host);
        $port = 443;

        $hostExplode = explode(':', $host);
        if( count($hostExplode) > 1 )
        {
            $port = $hostExplode[1];
            $host = $hostExplode[0];
        }

        $wrongLogin = FALSE;

        foreach( self::$savedConnectors as $connector )
        {
            if( $connector->apihost == $host && ($port === null && $connector->port == 443 || $port !== null && $connector->port == $port) )
            {
                $exceptionUse = PH::$useExceptions;
                PH::$useExceptions = TRUE;

                try
                {
                    $connector->getSoftwareVersion();
                } catch(Exception $e)
                {
                    PH::$useExceptions = $exceptionUse;

                    if( $host != "bpa-apikey" && $host != "license-apikey" && $host != "ldap-password" && $host != "maxmind-licensekey" )
                    {
                        $wrongLogin = TRUE;
                        if( strpos($e->getMessage(), "Invalid credentials.") === FALSE )
                            derr($e->getMessage());
                    }
                }
                PH::$useExceptions = $exceptionUse;

                if( !$wrongLogin )
                    return $connector;

                break;
            }
        }

        if( $apiKey === null && $promptForKey === FALSE && $wrongLogin == TRUE )
            derr('API host/key not found and apiKey is blank + promptForKey is disabled');


        if( $apiKey !== null )
        {
            $connector = new PanAPIConnector($host, $apiKey, 'panos', null, $port);
        }
        elseif( $promptForKey )
        {
            if( $wrongLogin )
                PH::print_stdout( " ** Request API access to host '$host' but invalid credentials were detected'" );
            else
                PH::print_stdout( " ** Request API access to host '$host' but API was not found in cache." );

            if( $cliUSER === null )
            {
                if( PH::$shadow_json )
                    derr( "API key not available: please first use 'pa_key-manager add=".$host."'" );
                PH::print_stdout( " ** Please enter API key or username [or ldap password] below and hit enter:  " );
                $handle = fopen("php://stdin", "r");
                $line = fgets($handle);
                $apiKey = trim($line);
            }
            else
            {
                $apiKey = $cliUSER;
                $handle = fopen("php://stdin", "r");
            }


            if( strlen($apiKey) < 19 && !( $host == "bpa-apikey" || $host == "license-apikey" || $host == "ldap-password" || $host == "maxmind-licensekey" ) )
            {
                $user = $apiKey;

                if( $cliPW === null )
                    $password = self::hiddenPWvalidation($user, $hiddenPW, $handle);
                else
                    $password = $cliPW;

                PH::print_stdout( "" );

                PH::print_stdout( " * Now generating an API key from '$host'..." );
                $con = new PanAPIConnector($host, '', 'panos', null, $port);

                $url = "type=keygen&user=" . urlencode($user) . "&password=" . urlencode($password);
                if( $debugAPI )
                    $con->setShowApiCalls( $debugAPI );
                $res = $con->sendRequest($url);

                $res = DH::findFirstElement('response', $res);
                if( $res === FALSE )
                    derr('missing <response> from API answer');

                $res = DH::findFirstElement('result', $res);
                if( $res === FALSE )
                    derr('missing <result> from API answer');

                $res = DH::findFirstElement('key', $res);
                if( $res === FALSE )
                    derr('unsupported response from PANOS API');

                $apiKey = $res->textContent;

                PH::print_stdout( " OK, key is $apiKey");
                PH::$JSON_TMP[$host]['status'] = "OK";
                PH::$JSON_TMP[$host]['key'] = $apiKey;
                PH::print_stdout("");

            }

            fclose($handle);

            if( $wrongLogin )
                $connector->apikey = $apiKey;
            else
                $connector = new PanAPIConnector($host, $apiKey, 'panos', null, $port);
        }

        if( $host == "bpa-apikey" || $host == "license-apikey" || $host == "ldap-password" || $host == "maxmind-licensekey" )
        {
            $checkConnectivity = false;
            self::$savedConnectors[] = $connector;
            self::saveConnectorsToUserHome();
        }

        if( $checkConnectivity )
        {
            $connector->testConnectivity( $host );
            PH::print_stdout("");
            if( !$wrongLogin )
                self::$savedConnectors[] = $connector;
            if( PH::$saveAPIkey )
            {
                self::saveConnectorsToUserHome();
            }
        }

        return $connector;
    }

    public function testConnectivity( $checkHost = "" )
    {
        PH::print_stdout( " - Testing API connectivity... ");

        $this->refreshSystemInfos( true );

        PH::print_stdout( " - PAN-OS version: ".$this->info_PANOS_version );
        PH::$JSON_TMP[$checkHost]['panos']['version'] = $this->info_PANOS_version;
        PH::$JSON_TMP[$checkHost]['panos']['type'] = $this->info_deviceType;
    }


    public function toString()
    {
        if( $this->serial !== null )
            $ret = get_class($this) . ':' . $this->apihost . '@' . $this->serial;
        else
            $ret = get_class($this) . ':' . $this->apihost;

        return $ret;
    }

    public function setShowApiCalls($yes)
    {
        $this->showApiCalls = $yes;
    }

    public function setType($type, $serial = null)
    {
        $type = strtolower($type);

        if( $type == 'panos' || $type == 'panos-via-panorama' )
        {
            $this->isPANOS = 1;
            if( $type == 'panos-via-panorama' )
            {
                if( $serial === null )
                    derr('panos-via-panorama type requires a serial number');
            }
            $this->serial = $serial;
        }
        elseif( $type == 'panorama' )
        {
            $this->isPANOS = 0;
            $this->serial = null;
        }
        else
            derr('unsupported type: ' . $type);
    }

    /**
     * @param string $host
     * @param string $key
     * @param string $type can be 'panos' 'panorama' or 'panos-via-panorama'
     * @param integer $port
     * @param string|null $serial
     */
    public function __construct($host, $key, $type = 'panos', $serial = null, $port = 443)
    {
        $this->setType($type, $serial);

        $this->apikey = $key;
        $this->apihost = $host;
        $this->port = $port;
    }

    /**
     * @param string $serial serial of the firewall you want to reach through Panorama
     * @return PanAPIConnector
     */
    public function cloneForPanoramaManagedDevice($serial)
    {
        return new PanAPIConnector($this->apihost, $this->apikey, 'panos-via-panorama', $serial, $this->port);
    }


    /**
     * @param string|string[] $ips
     * @param string|string[] $users
     * @param string $vsys
     * @param int $timeout
     * @return mixed
     */
    public function userIDLogin($ips, $users, $vsys = 'vsys1', $timeout = 3600)
    {
        if( is_string($ips) && is_string($users) )
        {
            $ips = array($ips);
            $users = array($users);
        }
        elseif( is_string($ips) )
        {
            derr('single IP provided but several users');
        }
        elseif( is_string($ips) )
        {
            derr('single user provided but several IPs');
        }
        elseif( count($ips) != count($users) )
        {
            derr('IPs and Users are not same numbers');
        }

        $ipsIndex = array_keys($ips);
        $usersIndex = array_keys($users);

        $cmd = '<uid-message><version>1.0</version><type>update</type><payload><login>';

        for( $i = 0; $i < count($ips); $i++ )
        {
            $cmd .= '<entry name="' . $users[$usersIndex[$i]] . '" ip="' . $ips[$ipsIndex[$i]] . '" timeout="' . $timeout . '"></entry>';;
        }
        $cmd .= '</login></payload></uid-message>';

        $params = array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);

    }

    /**
     * @param string|string[] $ips
     * @param string|string[] $users
     * @param string $vsys
     * @param int $timeout
     * @return mixed
     */
    public function userIDLogout($ips, $users, $vsys = 'vsys1', $timeout = 3600)
    {
        if( is_string($ips) && is_string($users) )
        {
            $ips = array($ips);
            $users = array($users);
        }
        elseif( is_string($ips) )
        {
            derr('single IP provided but several users');
        }
        elseif( is_string($ips) )
        {
            derr('single user provided but several IPs');
        }
        elseif( count($ips) != count($users) )
        {
            derr('IPs and Users are not same numbers');
        }

        $ipsIndex = array_keys($ips);
        $usersIndex = array_keys($users);

        $cmd = '<uid-message><version>1.0</version><type>update</type><payload><logout>';

        for( $i = 0; $i < count($ips); $i++ )
        {
            $cmd .= '<entry name="' . $users[$usersIndex[$i]] . '" ip="' . $ips[$ipsIndex[$i]] . '" timeout="' . $timeout . '"></entry>';;
        }
        $cmd .= '</logout></payload></uid-message>';

        $params = array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);

    }

    /**
     * @param string $vsys
     * @return string[][] $registered ie: Array( '1.1.1.1' => Array('tag1', 'tag3'), '2.3.4.5' => Array('tag7') )
     */
    public function userid_getIp($vsys = 'vsys1')
    {
        $cmd = "<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>";

        $ip_array = array();

        $params = array();
        $params['type'] = 'op';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        $r = $this->sendRequest($params, TRUE);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $count = DH::findFirstElement('count', $configRoot);
        if( $count !== false )
            $count = $count->nodeValue;

        $entries = $configRoot->getElementsByTagName('entry');
        foreach( $entries as $entry )
        {

            /** @var DOMElement $entry */
            $ip = DH::findFirstElement( "ip", $entry);
            $vsys = DH::findFirstElement( "vsys", $entry);
            $type = DH::findFirstElement( "type", $entry);
            $user = DH::findFirstElement( "user", $entry);
            $idleTimeout = DH::findFirstElement( "idle_timeout", $entry);
            $timeout = DH::findFirstElement( "timeout", $entry);

            $ip = $ip->nodeValue;
            $ip_array[$ip] = array();
            $ip_array[$ip]['vsys'] = $vsys->nodeValue;
            $ip_array[$ip]['type'] = $type->nodeValue;
            $ip_array[$ip]['user'] = $user->nodeValue;
            $ip_array[$ip]['idle'] = $idleTimeout->nodeValue;
            $ip_array[$ip]['timeout'] = $timeout->nodeValue;
        }

        return $ip_array;
    }

    /**
     * @param string[] $ips
     * @param string[] $tags
     * @param string $vsys
     * @param int $timeout
     * @return DomDocument
     */
    public function register_tagIPsWithTags($ips, $tags, $vsys = 'vsys1', $timeout = 3600)
    {
        $cmd = '<uid-message><version>1.0</version><type>update</type><payload><register>';

        foreach( $ips as $ip )
        {
            $cmd .= "<entry ip=\"$ip\"><tag>";
            foreach( $tags as $tag )
            {
                $cmd .= "<member>$tag</member>";
            }
            $cmd .= '</tag></entry>';
        }
        $cmd .= '</register></payload></uid-message>';

        $params = array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);
    }

    /**
     * @param string[][] $register ie: Array( '1.1.1.1' => Array('tag1', 'tag3'), '2.3.4.5' => Array('tag7') )
     * @param string[][] $unregister ie: Array( '1.1.1.1' => Array('tag1', 'tag3'), '2.3.4.5' => Array('tag7') )
     * @param string $vsys
     * @param int $timeout
     * @return DomDocument
     */
    public function register_sendUpdate($register = null, $unregister = null, $vsys = 'vsys1', $timeout = 3600)
    {
        $cmd = '<uid-message><version>1.0</version><type>update</type><payload>';

        if( $register !== null )
        {
            $cmd .= '<register>';
            foreach( $register as $ip => &$tags )
            {
                $cmd .= "<entry ip=\"$ip\"><tag>";
                foreach( $tags as $tag )
                {
                    $cmd .= "<member>$tag</member>";
                }
                $cmd .= '</tag></entry>';
            }
            $cmd .= '</register>';
        }

        if( $unregister !== null )
        {
            $cmd .= '<unregister>';
            foreach( $unregister as $ip => &$tags )
            {
                $cmd .= "<entry ip=\"$ip\">";
                if( $tags !== null && count($tags) > 0 )
                {
                    $cmd .= '<tag>';
                    foreach( $tags as $tag )
                    {
                        $cmd .= "<member>$tag</member>";
                    }
                    $cmd .= '</tag>';
                }
                $cmd .= '</entry>';
            }
            $cmd .= '</unregister>';
        }

        $cmd .= '</payload></uid-message>';

        $params = array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);
    }

    /**
     * @param string $vsys
     * @return string[][] $registered ie: Array( '1.1.1.1' => Array('tag1', 'tag3'), '2.3.4.5' => Array('tag7') )
     */
    public function register_getIp($vsys = 'vsys1')
    {
        $counter = 0;

        $cmd = "<show><object><registered-ip><all><option>count</option></all></registered-ip></object></show>";

        $params = array();
        $params['type'] = 'op';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;


        $r = $this->sendRequest($params, TRUE);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $counter = $node->nodeValue;
            PH::print_stdout( " - registered-ip: " . $counter );
        }

        $start = 1;
        $end = 500;

        if( $this->info_PANOS_version_int < 80 )
        {
            $cmd = "<show><object><registered-ip><all></all></registered-ip></object></show>";

            if( $counter > 500 )
                derr("API for PAN-OS version < 8.0 can only display register-ip information if count <= 500");

            //output for PAN-OS < 8.0 is only max. 500
            $counter = 500;
        }
        else
            $cmd = "<show><object><registered-ip><start-point>" . $start . "</start-point><limit>" . $end . "</limit></registered-ip></object></show>";

        $ip_array = array();
        do
        {
            $params = array();
            $params['type'] = 'op';
            $params['vsys'] = $vsys;
            $params['cmd'] = &$cmd;

            $r = $this->sendRequest($params, TRUE);

            $configRoot = DH::findFirstElement('result', $r);
            if( $configRoot === FALSE )
                derr("<result> was not found", $r);

            foreach( $configRoot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                /** @var DOMElement $node */
                $ip = $node->getAttribute('ip');

                $members = $node->getElementsByTagName('member');
                foreach( $members as $member )
                {
                    /** @var DOMElement $member */
                    $ip_array[$ip][$member->nodeValue] = $member->nodeValue;
                }
            }

            $start = $start + 500;

        } while( $start < $counter );

        return $ip_array;
    }

    public function dynamicAddressGroup_get($vsys = 'vsys1', $configType = 'panos')
    {
        $cmd = "<show><object><dynamic-address-group><all></all></dynamic-address-group></object></show>";

        $params = array();
        $params['type'] = 'op';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        $r = $this->sendRequest($params, TRUE);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        if( $configType == 'panos' )
        {
            $configRoot = DH::findFirstElement('dyn-addr-grp', $configRoot);
            if( $configRoot === FALSE )
                derr("<dyn-addr-grp> was not found", $configRoot);

            $ip_array = array();
            $this->dynamicAddressGroup_print( $vsys, $configRoot, $ip_array );
        }
        else
        {
            $configRoot = DH::findFirstElement('device-groups', $configRoot);
            if( $configRoot === FALSE )
                derr("<device-groups> was not found", $configRoot);

            $ip_array = array();
            foreach( $configRoot->childNodes as $node )
            {
                $tmp_DG_name = $node->getAttribute('name');
                if( $tmp_DG_name == $vsys )
                    $this->dynamicAddressGroup_print( $vsys, $configRoot, $ip_array );
            }
        }



        return $ip_array;
    }

    private function dynamicAddressGroup_print( $vsys, $configRoot, &$ip_array)
    {

        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->nodeType == XML_TEXT_NODE && empty(trim($node->nodeValue)) )
                continue;

            /** @var DOMElement $node */
            foreach( $node->childNodes as $element )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                if( $element->nodeName == 'vsys' )
                    $tmp_vsys = $element->nodeValue;
                elseif( $element->nodeName == 'group-name' )
                    $tmp_group_name = $element->nodeValue;
                elseif( $element->nodeName == 'address-group' )
                    $tmp_group_name = $element->nodeValue;
                elseif( $element->nodeName == 'filter' )
                    $filter = $element->nodeValue;
                elseif( $element->nodeName == 'member-list' )
                {
                    foreach( $element->childNodes as $member )
                    {
                        $ip_array[$tmp_group_name]['name'] = $tmp_group_name;
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmp_ip = $member->getAttribute('name');
                        $type = $member->getAttribute('type');

                        $ip_array[$tmp_group_name][$tmp_ip] = $filter;
                    }
                }
            }
        }

    }

    private function _createOrRenewCurl()
    {
        if( (PHP_MAJOR_VERSION <= 5 && PHP_MINOR_VERSION < 5) || $this->_curl_handle === null || $this->_curl_count > 100 )
        {
            if( $this->_curl_handle !== null )
                curl_close($this->_curl_handle);

            $this->_curl_handle = curl_init();
            $this->_curl_count = 0;
        }
        else
        {
            curl_reset($this->_curl_handle);
            $this->_curl_count++;
        }
    }


    /**
     * @param string $parameters
     * @param bool $checkResultTag
     * @param string|null $filecontent
     * @param string $filename
     * @param array $moreOptions
     * @return DomDocument
     */
    public function sendRequest(&$parameters, $checkResultTag = FALSE, &$filecontent = null, $filename = '', $moreOptions = array())
    {
        $sendThroughPost = FALSE;

        if( is_array($parameters) )
            $sendThroughPost = TRUE;

        $this->_createOrRenewCurl();

        curl_setopt($this->_curl_handle, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYHOST, FALSE);
        if( defined('CURL_SSLVERSION_TLSv1') ) // for older versions of PHP/openssl bundle
            curl_setopt($this->_curl_handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);

        $host = $this->apihost;
        if( $this->port != 443 )
            $host .= ':' . $this->port;

        if( isset($this->serial) && $this->serial !== null )
        {
            if( $this->port == 80 )
                $finalUrl = 'http://' . $host . '/api/';
            else
                $finalUrl = 'https://' . $host . '/api/';

            if( !$sendThroughPost )
            {
                if( !PH::$sendAPIkeyviaHeader )
                    $finalUrl .= '?key=' . urlencode($this->apikey) . '&target=' . $this->serial;
                else
                {
                    //Todo: possible improvements for API security with PAN-OS 9.0 [20181030]
                    $finalUrl .= '?target=' . $this->serial;
                    curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, array('X-PAN-KEY: ' . $this->apikey));
                }
            }
        }
        else
        {
            if( $this->port == 80 )
                $finalUrl = 'http://' . $host . '/api/';
            else
                $finalUrl = 'https://' . $host . '/api/';
            if( !$sendThroughPost )
            {
                if( !PH::$sendAPIkeyviaHeader )
                    $finalUrl .= '?key=' . urlencode($this->apikey);
                else
                {
                    //Todo: possible improvements for API security with PAN-OS 9.0 [20181030]
                    $finalUrl .= '?';
                    curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, array('X-PAN-KEY: ' . $this->apikey));
                }

            }

        }

        if( !$sendThroughPost )
        {
            #print_r( $parameters );
            //$url = str_replace('#', '%23', $parameters);
            if( !PH::$sendAPIkeyviaHeader )
                $finalUrl .= '&' . $parameters;
            else
            {
                $finalUrl .= $parameters;
            }
        }

        curl_setopt($this->_curl_handle, CURLOPT_URL, $finalUrl);

        if( isset($moreOptions['timeout']) )
            curl_setopt($this->_curl_handle, CURLOPT_CONNECTTIMEOUT, $moreOptions['timeout']);
        else
            curl_setopt($this->_curl_handle, CURLOPT_CONNECTTIMEOUT, 7);

        curl_setopt($this->_curl_handle, CURLOPT_LOW_SPEED_LIMIT, 500);
        if( isset($moreOptions['lowSpeedTime']) )
            curl_setopt($this->_curl_handle, CURLOPT_LOW_SPEED_TIME, $moreOptions['lowSpeedTime']);
        else
            curl_setopt($this->_curl_handle, CURLOPT_LOW_SPEED_TIME, 60);


        if( $sendThroughPost )
        {
            if( isset($this->serial) && $this->serial !== null )
            {
                $parameters['target'] = $this->serial;
            }
            if( !PH::$sendAPIkeyviaHeader )
                $parameters['key'] = $this->apikey;
            else
            {
                //Todo: possible improvements for API security with PAN-OS 9.0 [20181030]
                curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, array('X-PAN-KEY: ' . $this->apikey));
            }

            $properParams = http_build_query($parameters);
            curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS, $properParams);
        }

        if( $filecontent !== null )
        {
            $encodedContent = "----ABC1234\r\n"
                . "Content-Disposition: form-data; name=\"file\"; filename=\"" . $filename . "\"\r\n"
                . "Content-Type: application/xml\r\n"
                . "\r\n"
                . $filecontent . "\r\n"
                . "----ABC1234--\r\n";

            #PH::print_stdout( "content length = ".strlen($encodedContent) );
            #PH::print_stdout( "content  = ".$encodedContent );
            if( !PH::$sendAPIkeyviaHeader )
                curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, array('Content-Type: multipart/form-data; boundary=--ABC1234'));
            else
                curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, array('Content-Type: multipart/form-data; boundary=--ABC1234', 'X-PAN-KEY: ' . $this->apikey));
            curl_setopt($this->_curl_handle, CURLOPT_POST, TRUE);
            curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS, $encodedContent);
        }

        //$this->showApiCalls = true;
        if( $this->showApiCalls )
        {
            if( PH::$displayCurlRequest )
            {
                curl_setopt($this->_curl_handle, CURLOPT_FOLLOWLOCATION, TRUE);
                curl_setopt($this->_curl_handle, CURLOPT_VERBOSE, TRUE);

                curl_setopt($this->_curl_handle, CURLOPT_HEADER, 1);
                curl_setopt($this->_curl_handle, CURLINFO_HEADER_OUT, true);
            }


            if( $sendThroughPost )
            {
                $paramURl = '?';
                foreach( $parameters as $paramIndex => &$param )
                {
                    $paramURl .= '&' . $paramIndex . '=' . str_replace('#', '%23', $param);
                }

                PH::print_stdout("API call through POST: \"" . $finalUrl . $paramURl . "\"");
                PH::print_stdout( "RAW HTTP POST Content: {$properParams}" );
            }
            else
                PH::print_stdout("API call: \"" . $finalUrl . "\"" );
        }

        $httpReplyContent = curl_exec($this->_curl_handle);

        if( $httpReplyContent === FALSE )
            derr('Could not retrieve URL: ' . $finalUrl . ' because of the following error: ' . curl_error($this->_curl_handle));

        $curlHttpStatusCode = curl_getinfo($this->_curl_handle, CURLINFO_HTTP_CODE);

        if( $curlHttpStatusCode != 200 )
        {
            PH::print_stdout( PH::boldText( "\n####################################") );
            PH::print_stdout( "For " . PH::boldText("PAN-OS version < 9.0") . " please use additional argument " . PH::boldText("'shadow-apikeynohidden'" ) . " in your script command" );
            PH::print_stdout( PH::boldText( "\n####################################") );
            derr("HTTP API returned (code : {$curlHttpStatusCode}); " . $httpReplyContent, null, false);
        }


        $xmlDoc = new DOMDocument();

        PH::enableExceptionSupport();
        try
        {
            if( !$xmlDoc->loadXML($httpReplyContent, XML_PARSE_BIG_LINES) )
                derr('Invalid xml input :' . $httpReplyContent);
        } catch(Exception $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
            PH::print_stdout("");
            PH::print_stdout(  $httpReplyContent );
            PH::print_stdout("");

            return;
        }
        PH::disableExceptionSupport();


        $firstElement = DH::firstChildElement($xmlDoc);
        if( $firstElement === FALSE )
            derr('cannot find any child Element in xml');

        $statusAttr = DH::findAttribute('status', $firstElement);

        if( $statusAttr === FALSE )
            derr('XML response has no "status" field: ' . DH::dom_to_xml($firstElement));

        if( $statusAttr != 'success' )
            derr('API reported a failure: "' . $statusAttr . "\" with the following addition infos: " . $firstElement->nodeValue);

        if( $filecontent !== null )
            return $xmlDoc;

        if( !$checkResultTag )
            return $xmlDoc;

        //$cursor = &searchForName('name', 'result', $xmlarr['children']);
        $cursor = DH::findFirstElement('result', $firstElement);

        if( $cursor === FALSE )
        {
            $cursor = DH::findFirstElement('msg', $firstElement);
            if( $cursor === FALSE )
                derr('XML API response has no <result> or <msg> field', $xmlDoc);
        }

        DH::makeElementAsRoot($cursor, $xmlDoc);

        return $xmlDoc;
    }

    /**
     * @param $category
     * @return string
     */
    public function & sendExportRequest($category)
    {
        $this->_createOrRenewCurl();

        curl_setopt($this->_curl_handle, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYHOST, FALSE);
        if( defined('CURL_SSLVERSION_TLSv1') ) // for older versions of PHP/openssl bundle
            curl_setopt($this->_curl_handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);

        $host = $this->apihost;
        if( $this->port != 443 )
            $host .= ':' . $this->port;

        if( isset($this->serial) && $this->serial !== null )
            $finalUrl = 'https://' . $host . '/api/';
        else
            $finalUrl = 'https://' . $host . '/api/';

        curl_setopt($this->_curl_handle, CURLOPT_URL, $finalUrl);


        if( isset($this->serial) && $this->serial !== null )
        {
            $parameters['target'] = $this->serial;
        }

        if( !PH::$sendAPIkeyviaHeader )
            $parameters['key'] = $this->apikey;
        else
        {
            //Todo: possible improvements for API security with PAN-OS 9.0 [20181030]
            curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, array('X-PAN-KEY: ' . $this->apikey));
        }
        $parameters['category'] = $category;
        $parameters['type'] = 'export';
        $properParams = http_build_query($parameters);


        curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS, $properParams);

        if( $this->showApiCalls )
        {
            $paramURl = '?';
            foreach( $parameters as $paramIndex => &$param )
            {
                $paramURl .= '&' . $paramIndex . '=' . str_replace('#', '%23', $param);
            }

            print("API call through POST: \"" . $finalUrl . '?' . $paramURl . "\"\r\n");
        }


        $httpReplyContent = curl_exec($this->_curl_handle);
        if( $httpReplyContent === FALSE )
            derr('Could not retrieve URL: ' . $finalUrl . ' because of the following error: ' . curl_error($this->_curl_handle));

        $curlHttpStatusCode = curl_getinfo($this->_curl_handle, CURLINFO_HTTP_CODE);
        if( $curlHttpStatusCode != 200 )
            derr("HTTP Status returned (code : {$curlHttpStatusCode}); " . $httpReplyContent);


        return $httpReplyContent;
    }


    public function &getReport($req)
    {
        $ret = $this->sendRequest($req);

        //PH::print_stdout( DH::dom_to_xml($ret, 0, true, 4) );

        $cursor = DH::findXPathSingleEntryOrDie('/response', $ret);
        $cursor = DH::findFirstElement('result', $cursor);

        if( $cursor === FALSE )
        {
            $cursor = DH::findFirstElement('report', DH::findXPathSingleEntryOrDie('/response', $ret));
            if( $cursor === FALSE )
                derr("unsupported API answer");

            $report = DH::findFirstElement('result', $cursor);
            if( $report === FALSE )
                derr("unsupported API answer");

        }

        if( !isset($report) )
        {

            $cursor = DH::findFirstElement('job', $cursor);

            if( $cursor === FALSE )
                derr("unsupported API answer, no JOB ID found");

            $jobid = $cursor->textContent;

            while( TRUE )
            {
                sleep(1);
                $query = '&type=report&action=get&job-id=' . $jobid;
                $ret = $this->sendRequest($query);
                //PH::print_stdout( DH::dom_to_xml($ret, 0, true, 5) );

                $cursor = DH::findFirstElement('result', DH::findXPathSingleEntryOrDie('/response', $ret));

                if( $cursor === FALSE )
                    derr("unsupported API answer", $ret);

                $jobcur = DH::findFirstElement('job', $cursor);

                if( $jobcur === FALSE )
                    derr("unsupported API answer", $ret);

                $percent = DH::findFirstElement('percent', $jobcur);

                if( $percent == FALSE )
                    derr("unsupported API answer", $cursor);

                if( $percent->textContent != '100' )
                {
                    sleep(9);
                    continue;
                }

                $cursor = DH::findFirstElement('report', $cursor);

                if( $cursor === FALSE )
                    derr("unsupported API answer", $ret);

                $report = $cursor;

                break;

            }
        }
        $ret = array();

        foreach( $report->childNodes as $line )
        {
            if( $line->nodeType != XML_ELEMENT_NODE )
                continue;

            $newline = array();

            foreach( $line->childNodes as $item )
            {
                if( $item->nodeType != XML_ELEMENT_NODE )
                    continue;
                /** @var DOMElement $item */

                $newline[$item->nodeName] = $item->textContent;
            }

            $ret[] = $newline;
        }

        //print_r($ret);

        return $ret;
    }


    public function getRunningConfig()
    {
        $url = 'action=show&type=config&xpath=/config';

        $r = $this->sendRequest($url, TRUE);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === FALSE )
        {
            $configRoot = $this->APIresponseValidation($r);
            //derr("<config> was not found", $r);
        }

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function getMergedConfig()
    {
        $r = $this->sendOpRequest('<show><config><merged/></config></show>', FALSE);

        $configRoot = DH::findFirstElement('response', $r);
        if( $configRoot === FALSE )
            derr("<response> was not found", $r);

        $configRoot = DH::findFirstElement('result', $configRoot);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === FALSE )
        {
            $configRoot = $this->APIresponseValidation($r);
            //derr("<config> was not found", $r);
        }


        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function getPanoramaPushedConfig( $apiTimeOut = 30 )
    {
        $url = '&action=get&type=config&xpath=/config/panorama';
        $moreOptions = array('timeout' => $apiTimeOut, 'lowSpeedTime' => 0);
        $filecontent = null;
        $r = $this->sendRequest($url, TRUE, $filecontent, '', $moreOptions);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('panorama', $configRoot);
        if( $configRoot === FALSE )
            derr("<panorama> was not found", $r);

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function getCandidateConfig($apiTimeOut = 60)
    {
        return $this->getSavedConfig('candidate-config', $apiTimeOut);
    }

    public function getCandidateConfigAlt()
    {
        $doc = new DOMDocument();
        $doc->loadXML($this->sendExportRequest('configuration'), XML_PARSE_BIG_LINES);

        return $doc;
    }

    public function getSavedConfig($configurationName, $apiTimeOut = 60)
    {
        //$url = 'action=get&type=config&xpath=/config';
        $url = "<show><config><saved>$configurationName</saved></config></show>";

        $r = $this->sendCmdRequest($url, TRUE, $apiTimeOut);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === FALSE )
        {
            $configRoot = $this->APIresponseValidation($r);
        }


        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function APIresponseValidation(DOMDocument $r)
    {
        //Todo: this is for a problem in PAN-OS until it is fixed in 8.1.16, 9.0.10 and 9.1.4
        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('response', $configRoot);
        if( $configRoot === FALSE )
            derr("<response> was not found", $r);
        $configRoot = DH::findFirstElement('result', $configRoot);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === FALSE )
        {
            derr("<config> was not found", $r);
        }

        //derr("<config> was not found", $r);

        return $configRoot;
    }

    /**
     * @param $xpath string|XmlConvertible
     * @param $element string
     * @param $useChildNodes bool if $element is an object then don't use its root but its childNodes to generate xml
     * @return DomDocument
     */
    public function sendSetRequest($xpath, $element, $useChildNodes = FALSE, $timeout = 30)
    {
        $params = array();
        $moreOptions = array('timeout' => $timeout, 'lowSpeedTime' => 0);

        if( is_string($element) )
        {

        }
        elseif( is_object($element) )
        {
            if( $useChildNodes )
                $element = &$element->getChildXmlText_inline();
            else
                $element = &$element->getXmlText_inline();
        }

        $params['type'] = 'config';
        $params['action'] = 'set';
        $params['xpath'] = &$xpath;
        $params['element'] = &$element;

        return $this->sendSimpleRequest($params, $moreOptions);
    }


    public function sendSimpleRequest(&$request, $options = array())
    {
        $file = null;
        return $this->sendRequest($request, FALSE, $file, '', $options);
    }

    /**
     * @param $xpath string
     * @param $element string|XmlConvertible|DOMElement
     * @param $useChildNodes bool if $element is an object then don't use its root but its childNodes to generate xml
     * @return DomDocument
     */
    public function sendEditRequest($xpath, $element, $useChildNodes = FALSE, $timeout = 30)
    {
        $params = array();
        $moreOptions = array('timeout' => $timeout, 'lowSpeedTime' => 0);

        if( is_object($xpath) )
            derr('unsupported yet');

        if( is_string($element) )
        {

        }
        elseif( is_object($element) )
        {
            $elementClass = get_class($element);

            if( $elementClass === 'DOMElement' )
            {
                /** @var DOMElement $element */
                if( $useChildNodes )
                    $element = DH::domlist_to_xml($element->childNodes, -1, FALSE);
                else
                    $element = DH::dom_to_xml($element, -1, FALSE);
            }
            else
            {
                if( $useChildNodes )
                    $element = $element->getChildXmlText_inline();
                else
                    $element = $element->getXmlText_inline();
            }
        }

        $params['type'] = 'config';
        $params['action'] = 'edit';
        $params['xpath'] = &$xpath;
        $params['element'] = &$element;

        return $this->sendSimpleRequest($params, $moreOptions);
    }

    public function sendDeleteRequest($xpath)
    {
        $params = array();

        $params['type'] = 'config';
        $params['action'] = 'delete';
        $params['xpath'] = &$xpath;

        return $this->sendRequest($params);
    }

    /**
     * @param string $xpath
     * @param string $newname
     * @return DomDocument
     */
    public function sendRenameRequest($xpath, $newname)
    {
        $params = array();

        $params['type'] = 'config';
        $params['action'] = 'rename';
        $params['xpath'] = &$xpath;
        $params['newname'] = &$newname;

        return $this->sendRequest($params);
    }

    /**
     * @param string $cmd operational command string
     * @param bool $stripResponseTag
     * @return DomDocument
     */
    public function sendOpRequest($cmd, $stripResponseTag = TRUE)
    {
        $params = array();

        $params['type'] = 'op';
        $params['cmd'] = $cmd;

        return $this->sendRequest($params, $stripResponseTag);
    }

    public function waitForJobFinished($jobID)
    {
        $res = $this->getJobResult($jobID);

        while( $res == 'PEND' )
        {
            sleep(20);
            $res = $this->getJobResult($jobID);
        }

        return $res;


    }

    /**
     * @param $cmd string
     * @param $checkResultTag bool
     * @param $maxWaitTime integer
     * @return DomDocument|string[]
     */
    public function sendCmdRequest($cmd, $checkResultTag = TRUE, $maxWaitTime = -1, $apiTimeOut = 7)
    {
        $req = "type=op&cmd=$cmd";
        if( $maxWaitTime == -1 )
            $moreOptions['lowSpeedTime'] = null;
        else
            $moreOptions['lowSpeedTime'] = $maxWaitTime;
        $moreOptions['timeout'] = $apiTimeOut;

        $nullVar = null;

        $ret = $this->sendRequest($req, $checkResultTag, $nullVar, '', $moreOptions);

        return $ret;
    }

    public function getJobResult($jobID, $apiTimeOut = 7)
    {
        $req = "type=op&cmd=<show><jobs><id>$jobID</id></jobs></show>";
        $moreOptions['timeout'] = $apiTimeOut;
        $filecontent = null;
        $ret = $this->sendRequest($req, false, $filecontent, '', $moreOptions);

        //TODO: 20180305 not working
        $found = &searchForName('name', 'result', $ret);

        if( $found === null )
        {
            derr('unsupported API answer');
        }

        $found = &searchForName('name', 'job', $found['children']);

        if( $found === null )
        {
            derr('no job id found!');
        }

        $found = &searchForName('name', 'result', $found['children']);

        if( $found === null )
        {
            derr('unsupported API answer');
        }

        return $found['content'];
    }

    public function sendJobRequest($request)
    {
        $ret = $this->sendRequest($request);

        //var_dump($ret);
        //TODO: 20180305 not working
        $found = &searchForName('name', 'result', $ret);

        if( $found === null )
        {
            derr('unsupported API answer');
        }

        $found = &searchForName('name', 'job', $found['children']);

        if( $found === null )
        {
            derr('no job id found!');
        }

        else return $found['content'];

    }

    /**
     *   send a config to the firewall and save under name $config_name
     *
     * @param DOMNode $configDomXml
     * @param string $configName
     * @param bool $verbose
     * @return DOMNode
     */
    public function uploadConfiguration($configDomXml, $configName = 'stage0.xml', $verbose = TRUE, $apiTimeOut = 7)
    {
        if( $verbose )
            PH::print_stdout( "Uploadig config to device {$this->apihost}/{$configName}...." );

        $url = "type=import&category=configuration&category=configuration";

        $answer = $this->sendRequest($url, FALSE, DH::dom_to_xml($configDomXml), $configName, array('timeout' => $apiTimeOut));

        return $answer;
    }

    /**
     * @return string[][]  ie: Array( Array('serial' => '000C12234', 'hostname' => 'FW-MUNICH4' ) )
     */
    public function & panorama_getConnectedFirewallsSerials()
    {
        $result = $this->sendCmdRequest('<show><devices><connected/></devices></show>');
        $devicesRoot = DH::findXPathSingleEntryOrDie('/result/devices', $result);

        $firewalls = array();

        foreach( $devicesRoot->childNodes as $entryNode )
        {
            $fw = array();

            if( $entryNode->nodeType != XML_ELEMENT_NODE )
                continue;
            /** @var DOMElement $entryNode */

            $hostnameNode = DH::findFirstElement('hostname', $entryNode);
            if( $hostnameNode !== FALSE )
                $fw['hostname'] = $hostnameNode->textContent;
            else
                $fw['hostname'] = $entryNode->getAttribute('name');

            $fw['serial'] = $entryNode->getAttribute('name');

            $modelNode = DH::findFirstElement('model', $entryNode);
            if( $modelNode !== FALSE )
                $fw['model'] = $modelNode->textContent;

            $ipaddressNode = DH::findFirstElement('ip-address', $entryNode);
            if( $ipaddressNode !== FALSE )
                $fw['ip-address'] = $ipaddressNode->textContent;

            $swversionNode = DH::findFirstElement('sw-version', $entryNode);
            if( $swversionNode !== FALSE )
                $fw['sw-version'] = $swversionNode->textContent;

            /*
            foreach( $entryNode->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $fw[$node->nodeName] = $node->textContent;
            }
            */

            $firewalls[$fw['serial']] = $fw;
        }

        return $firewalls;
    }

    public function loadPanoramaPushdedConfig( $apiTimeoutValue )
    {
        $panoramaDoc = $this->getPanoramaPushedConfig( $apiTimeoutValue );

        $xpathResult = DH::findXPath('/panorama/vsys', $panoramaDoc);

        if( $xpathResult === FALSE )
            derr("could not find any VSYS");

        if( $xpathResult->length != 1 )
            derr("found more than 1 <VSYS>");

        $fakePanorama = new PanoramaConf();
        $fakePanorama->_fakeMode = TRUE;
        $this->refreshSystemInfos();
        $newDGRoot = $xpathResult->item(0);
        $panoramaString = "<config version=\"{$this->info_PANOS_version}\"><shared></shared><devices><entry name=\"localhost.localdomain\"><device-group>" . DH::domlist_to_xml($newDGRoot->childNodes) . "</device-group></entry></devices></config>";

        $fakePanorama->load_from_xmlstring($panoramaString);


        return new PANConf($fakePanorama);
    }

    /**
     * @return string[][]  ie: Array( Array('serial' => '000C12234', 'hostname' => 'FW-MUNICH4' ) )
     */
    public function & panorama_getAllFirewallsSerials()
    {
        $result = $this->sendCmdRequest('<show><devices><all></all></devices></show>');
        $devicesRoot = DH::findXPathSingleEntryOrDie('/result/devices', $result);

        $firewalls = array();

        foreach( $devicesRoot->childNodes as $entryNode )
        {
            $fw = array();

            if( $entryNode->nodeType != XML_ELEMENT_NODE )
                continue;
            /** @var DOMElement $entryNode */

            $fw['serial'] = $entryNode->getAttribute('name');

            foreach( $entryNode->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;
                /** @var DOMElement $node */

                $fw[$node->nodeName] = $node->textContent;
            }

            $firewalls[$fw['serial']] = $fw;
        }

        /*
        $fields = array();
        foreach( $firewalls as $index => &$array )
        {
            foreach( $array as $key => $value )
                $fields[$key] = $key;
        }


        foreach( $firewalls as $index => &$array )
        {
            foreach( $fields as $key => $value )
            {
                if( !isset( $array[$key] ) )
                    $array[$key] = "- - -";
            }
        }
        */

        return $firewalls;
    }

    static public function hiddenPWvalidation($user, $hiddenPW, $handle)
    {
        $pw_prompt = "** you input user '" . $user . "' , please enter password now, password is ";
        if( $hiddenPW )
            $pw_prompt .= "hidden : ";
        else
            $pw_prompt .= "displayed in plaintext : ";
        if( $hiddenPW )
        {
            if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
            {
                $pwd = shell_exec('powershell.exe -Command "$Password=Read-Host -assecurestring ' . $pw_prompt . '; $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)); echo $PlainPassword;"');
                $pwd = explode("\n", $pwd);
                $password = $pwd[0];
            }
            else
            {
                PH::print_stdout( $pw_prompt );
                $oldStyle = shell_exec('stty -g');
                shell_exec('stty -icanon -echo min 1 time 0');

                $password = '';
                while( TRUE )
                {
                    $char = fgetc(STDIN);

                    if( $char === "\n" )
                        break;
                    elseif( ord($char) === 127 )
                    {
                        if( strlen($password) > 0 )
                        {
                            fwrite(STDOUT, "\x08 \x08");
                            $password = substr($password, 0, -1);
                        }
                    }
                    else
                    {
                        fwrite(STDOUT, "*");
                        $password .= $char;
                    }
                }
                shell_exec('stty ' . $oldStyle);
            }
        }
        else
        {
            PH::print_stdout( $pw_prompt );
            $line = fgets($handle);
            $password = trim($line);
        }

        return $password;
    }

    public function getShadowInfo( $countInfo, $panorama = false )
    {
        $cmd = "<show><shadow-warning><count>".$countInfo."</count></shadow-warning></show>";
        $response = $this->sendOpRequest( $cmd );

        $tmp = DH::findFirstElement( "result", $response);
        $tmp = DH::findFirstElement( "shadow-warnings-count", $tmp);
        $tmp = DH::findFirstElement( "entry", $tmp);

        $shadowedRule = array();

        //todo: if panorama - get
        $devicegroup = "";
        if( $panorama )
        {
            $name = $tmp->getAttribute( "dg" );
            $devicegroup = "<device-group>".$name."</device-group>";
        }
        else
        {
            $name = $tmp->getAttribute( "vsys" );
        }

        foreach( $tmp->childNodes as $entry )
        {
            if( $entry->nodeType != XML_ELEMENT_NODE )
                continue;

            $tmp_uid = $entry->getAttribute( "uuid" );
            $cmd = "<show><shadow-warning><warning-message>".$countInfo.$devicegroup."<uuid>".$tmp_uid."</uuid></warning-message></shadow-warning></show>";
            $response = $this->sendOpRequest( $cmd );

            #print $response->saveXML();

            $tmp = DH::findFirstElement( "result", $response);
            $tmp = DH::findFirstElement( "warning-msg", $tmp);

            foreach( $tmp->childNodes as $key => $entry )
            {
                if( $entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                if( $panorama )
                    $shadowedRule[$name][$tmp_uid][] = $entry->textContent;
                else
                    $shadowedRule[$name][$tmp_uid][] = $entry->textContent;
            }
        }

        return $shadowedRule;
    }
}



