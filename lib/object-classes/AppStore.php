<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class AppStore extends ObjStore
{
    /** @var array|App[] */
    public $apps = array();

    /** @var array|App[] */
    public $apps_custom = array();

    /** @var array|App[] */
    public $app_filters = array();

    /** @var array|App[] */
    public $app_groups = array();

    public $parentCentralStore = null;

    public static $childn = 'App';

    public $predefinedStore_appid_version = null;

    /** @var null|AppStore */
    public static $predefinedStore = null;

    /**
     * @return AppStore|null
     */
    public static function getPredefinedStore()
    {
        if( self::$predefinedStore !== null )
            return self::$predefinedStore;

        self::$predefinedStore = new AppStore(null);
        self::$predefinedStore->setName('predefined Apps');
        self::$predefinedStore->load_from_predefinedfile();

        return self::$predefinedStore;
    }


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = &$this->apps;

        $this->findParentCentralStore();
    }

    /**
     * @param $name string
     * @param $ref
     * @return null|App
     */
    public function find($name, $ref = null)
    {
        return $this->findByName($name, $ref);
    }

    /**
     * @param $name string
     * @param $ref
     * @return null|App
     */
    public function findorCreate($name, $ref = null)
    {
        $f = $this->findByName($name, $ref);

        if( $f !== null )
            return $f;

        $f = $this->createTmp($name, $ref);

        return $f;
    }


    /**
     * return an array with all Apps in this store
     *
     */
    public function apps()
    {
        return $this->o;
    }


    /**
     *
     * @ignore
     */
    protected function findParentCentralStore()
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $curo = $this;
            while( isset($curo->owner) && $curo->owner !== null )
            {

                if( isset($curo->owner->appStore) &&
                    $curo->owner->appStore !== null )
                {
                    $this->parentCentralStore = $curo->owner->appStore;
                    //print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
                    return;
                }
                $curo = $curo->owner;
            }
        }

        //print $this->toString().": no parent store found\n";

    }

    public function load_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("app name not found\n");

            $app = new App($appName, $this);
            $app->type = 'predefined';
            $this->add($app);
        }

        foreach( $xml->childNodes as $appx )
        {

            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("app name not found\n");

            if( !isset($this->nameIndex[$appName]) )
                derr("Inconsistency problem : cannot match an application to its XML", $appx);

            $app = $this->nameIndex[$appName];

            #xpath /predefined/default
            $timeoutcur = DH::findFirstElement('timeout', $appx);
            if( $timeoutcur !== FALSE )
            {
                $app->timeout = $timeoutcur->textContent;
            }
            $tcptimeoutcur = DH::findFirstElement('tcp-timeout', $appx);
            if( $tcptimeoutcur !== FALSE )
            {
                $app->tcp_timeout = $tcptimeoutcur->textContent;
            }
            $udptimeoutcur = DH::findFirstElement('udp-timeout', $appx);
            if( $udptimeoutcur !== FALSE )
            {
                $app->udp_timeout = $udptimeoutcur->textContent;
            }
            $tcp_half_timeoutcur = DH::findFirstElement('tcp-half-closed-timeout', $appx);
            if( $tcp_half_timeoutcur !== FALSE )
            {
                $app->tcp_half_closed_timeout = $tcp_half_timeoutcur->textContent;
            }
            $tcp_wait_timeoutcur = DH::findFirstElement('tcp-time-wait-timeout', $appx);
            if( $tcp_wait_timeoutcur !== FALSE )
            {
                $app->tcp_time_wait_timeout = $tcp_wait_timeoutcur->textContent;
            }

            $obsolete = DH::findFirstElement('obsolete', $appx);
            if( $obsolete !== FALSE )
            {
                $app->obsolete = $obsolete->textContent;
            }


            #xpath /predefined
            $tmp = DH::findFirstElement('category', $appx);
            if( $tmp !== FALSE )
            {
                $app->category = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('subcategory', $appx);
            if( $tmp !== FALSE )
            {
                $app->subCategory = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('technology', $appx);
            if( $tmp !== FALSE )
            {
                $app->technology = $tmp->textContent;
            }


            $tmp = DH::findFirstElement('evasive-behavior', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['evasive'] = TRUE;
            }
            $tmp = DH::findFirstElement('consume-big-bandwidth', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['excessive-bandwidth'] = TRUE;
            }
            $tmp = DH::findFirstElement('used-by-malware', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['used-by-malware'] = TRUE;
            }
            $tmp = DH::findFirstElement('able-to-transfer-file', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['transfers-files'] = TRUE;
            }
            $tmp = DH::findFirstElement('has-known-vulnerability', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['vulnerabilities'] = TRUE;
            }
            $tmp = DH::findFirstElement('tunnel-other-application', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['tunnels-other-apps'] = TRUE;
            }
            $tmp = DH::findFirstElement('prone-to-misuse', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['prone-to-misuse'] = TRUE;
            }
            $tmp = DH::findFirstElement('is-saas', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['saas'] = TRUE;
            }
            $tmp = DH::findFirstElement('pervasive-use', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['widely-used'] = TRUE;
            }


            $tmp = DH::findFirstElement('risk', $appx);
            if( $tmp !== FALSE )
            {
                $app->risk = $tmp->textContent;
            }
            $tmp = DH::findFirstElement('virusident-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->virusident = TRUE;
            }
            $tmp = DH::findFirstElement('filetype-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->filetypeident = TRUE;
            }
            $tmp = DH::findFirstElement('file-forward', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->fileforward = TRUE;
            }


            $cursor = DH::findFirstElement('use-applications', $appx);
            if( $cursor !== FALSE )
            {
                foreach( $cursor->childNodes as $depNode )
                {
                    if( $depNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $depName = $depNode->textContent;
                    if( strlen($depName) < 1 )
                        derr("dependency name length is < 0");
                    $depApp = $this->findOrCreate($depName);
                    $app->explicitUse[] = $depApp;
                }
            }

            $cursor = DH::findFirstElement('implicit-use-applications', $appx);
            if( $cursor !== FALSE )
            {
                foreach( $cursor->childNodes as $depNode )
                {
                    if( $depNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $depName = $depNode->textContent;
                    if( strlen($depName) < 1 )
                        derr("dependency name length is < 0");
                    $depApp = $this->findOrCreate($depName);
                    $app->implicitUse[] = $depApp;
                }
            }

            $cursor = DH::findFirstElement('default', $appx);
            if( $cursor === FALSE )
                continue;

            $protocur = DH::findFirstElement('ident-by-ip-protocol', $cursor);
            if( $protocur !== FALSE )
            {
                $app->proto = $protocur->textContent;
            }

            $icmpcur = DH::findFirstElement('ident-by-icmp-type', $cursor);
            if( $icmpcur !== FALSE )
            {
                $icmptype = DH::findFirstElement('type', $icmpcur);
                if( $icmptype !== FALSE )
                {
                    $app->icmpsub = $icmptype->textContent;
                }
                //TODO: <code>0</code>
                $icmpcode = DH::findFirstElement('code', $icmpcur);
                if( $icmpcode !== FALSE )
                {
                    $app->icmpcode = $icmpcode->textContent;
                }
            }

            $icmp6cur = DH::findFirstElement('ident-by-icmp6-type', $cursor);
            if( $icmp6cur !== FALSE )
            {
                $icmp6type = DH::findFirstElement('type', $icmp6cur);
                if( $icmp6type !== FALSE )
                {
                    $app->icmp6sub = $icmp6type->textContent;
                }
                //TODO: <code>0</code>
                $icmp6code = DH::findFirstElement('code', $icmp6cur);
                if( $icmp6code !== FALSE )
                {
                    $app->icmp6code = $icmp6code->textContent;
                }

            }

            $portcur = DH::findFirstElement('port', $cursor);
            if( $portcur !== FALSE )
            {
                foreach( $portcur->childNodes as $portx )
                {
                    if( $portx->nodeType != XML_ELEMENT_NODE )
                        continue;

                    /** @var  $portx DOMElement */

                    $ex = explode('/', $portx->textContent);

                    if( count($ex) != 2 )
                        derr('unsupported port description: ' . $portx->textContent);

                    if( $ex[0] == 'tcp' )
                    {
                        $exports = explode(',', $ex[1]);
                        $ports = array();

                        if( count($exports) < 1 )
                            derr('unsupported port description: ' . $portx->textContent);

                        foreach( $exports as &$sport )
                        {
                            if( $sport == 'dynamic' )
                            {
                                $ports[] = array(0 => 'dynamic');
                                continue;
                            }
                            $tmpex = explode('-', $sport);
                            if( count($tmpex) < 2 )
                            {
                                $ports[] = array(0 => 'single', 1 => $sport);
                                continue;
                            }

                            $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                        }
                        //print_r($ports);

                        if( $app->tcp === null )
                            $app->tcp = $ports;
                        else
                            $app->tcp = array_merge($app->tcp, $ports);
                    }
                    elseif( $ex[0] == 'udp' )
                    {
                        $exports = explode(',', $ex[1]);
                        $ports = array();

                        if( count($exports) < 1 )
                            derr('unsupported port description: ' . $portx->textContent);

                        foreach( $exports as &$sport )
                        {
                            if( $sport == 'dynamic' )
                            {
                                $ports[] = array(0 => 'dynamic');
                                continue;
                            }
                            $tmpex = explode('-', $sport);
                            if( count($tmpex) < 2 )
                            {
                                $ports[] = array(0 => 'single', 1 => $sport);
                                continue;
                            }

                            $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                        }
                        //print_r($ports);

                        if( $app->udp === null )
                            $app->udp = $ports;
                        else
                            $app->udp = array_merge($app->udp, $ports);
                    }
                    elseif( $ex[0] == 'icmp' )
                    {
                        $app->icmp = $ex[1];
                    }
                    elseif( $ex[0] == 'icmp6' )
                    {
                        $app->icmp6 = $ex[1];
                    }
                    else
                        derr('unsupported port description: ' . $portx->textContent);
                }
            }

            $ext_portcur = DH::findFirstElement('extended-port', $cursor);
            if( $ext_portcur !== FALSE )
            {
                foreach( $ext_portcur->childNodes as $portx )
                {
                    $port_secure = FALSE;

                    if( $portx->nodeType != XML_ELEMENT_NODE )
                        continue;

                    /** @var  $portx DOMElement */

                    $ex = explode('/', $portx->textContent);

                    if( count($ex) == 3 )
                    {
                        $port_secure = TRUE;
                        unset($ex[2]);
                    }
                    else
                    {
                        //not interested in the same ports as under <ports>
                        continue;
                    }

                    if( count($ex) != 2 )
                        derr('unsupported port description: ' . $portx->textContent);

                    if( $ex[0] == 'tcp' )
                    {
                        $exports = explode(',', $ex[1]);
                        $ports = array();

                        if( count($exports) < 1 )
                            derr('unsupported port description: ' . $portx->textContent);

                        foreach( $exports as &$sport )
                        {
                            if( $sport == 'dynamic' )
                            {
                                $ports[] = array(0 => 'dynamic');
                                continue;
                            }
                            $tmpex = explode('-', $sport);
                            if( count($tmpex) < 2 )
                            {
                                $ports[] = array(0 => 'single', 1 => $sport);
                                continue;
                            }

                            $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                        }
                        //print_r($ports);
                        if( !$port_secure )
                        {
                            if( $app->tcp === null )
                                $app->tcp = $ports;
                            else
                                $app->tcp = array_merge($app->tcp, $ports);
                        }
                        else
                        {
                            if( $app->tcp_secure === null )
                                $app->tcp_secure = $ports;
                            else
                                $app->tcp_secure = array_merge($app->tcp_secure, $ports);
                        }

                    }
                    elseif( $ex[0] == 'udp' )
                    {
                        $exports = explode(',', $ex[1]);
                        $ports = array();

                        if( count($exports) < 1 )
                            derr('unsupported port description: ' . $portx->textContent);

                        foreach( $exports as &$sport )
                        {
                            if( $sport == 'dynamic' )
                            {
                                $ports[] = array(0 => 'dynamic');
                                continue;
                            }
                            $tmpex = explode('-', $sport);
                            if( count($tmpex) < 2 )
                            {
                                $ports[] = array(0 => 'single', 1 => $sport);
                                continue;
                            }

                            $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                        }
                        //print_r($ports);
                        if( !$port_secure )
                        {
                            if( $app->udp === null )
                                $app->udp = $ports;
                            else
                                $app->udp = array_merge($app->udp, $ports);
                        }
                        else
                        {
                            if( $app->udp_secure === null )
                                $app->udp_secure = $ports;
                            else
                                $app->udp_secure = array_merge($app->udp_secure, $ports);
                        }

                    }
                    elseif( $ex[0] == 'icmp' )
                    {
                        if( !$port_secure )
                        {
                            $app->icmp = $ex[1];
                        }
                        else
                        {
                            $app->icmp_secure = $ex[1];
                        }
                    }
                    elseif( $ex[0] == 'icmp6' )
                    {
                        if( !$port_secure )
                        {
                            $app->icmp6 = $ex[1];
                        }
                        else
                        {
                            $app->icmp6_secure = $ex[1];
                        }
                    }
                    else
                        derr('unsupported port description: ' . $portx->textContent);
                }
            }

        }
    }

    public function loadcontainers_from_domxml(&$xmlDom)
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationContainer name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->type = 'predefined';
            $this->add($app);

            $app->subapps = array();

            $cursor = DH::findFirstElement('functions', $appx);
            if( $cursor === FALSE )
                continue;

            foreach( $cursor->childNodes as $function )
            {
                if( $function->nodeType != XML_ELEMENT_NODE )
                    continue;

                $subapp = $this->findOrCreate($function->textContent);
                $app->subapps[] = $subapp;
            }

        }
    }

    public function load_application_group_from_domxml($xmlDom)
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationGroup name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->type = 'application-group';

            $this->app_groups[] = $app;

            $this->add($app);


            $app->groupapps = array();

            $cursor = DH::findFirstElement('members', $appx);
            if( $cursor === FALSE )
                continue;

            foreach( $cursor->childNodes as $function )
            {
                if( $function->nodeType != XML_ELEMENT_NODE )
                    continue;

                $groupapp = $this->find($function->textContent);

                if( $groupapp !== null )
                    $app->groupapps[] = $groupapp;
                else
                {
                    $groupapp = $this->findOrCreate($function->textContent);
                    $app->groupapps[] = $groupapp;
                }
            }
        }
    }

    public function load_application_custom_from_domxml($xmlDom)
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationCustom name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->type = 'application-custom';
            $this->add($app);

            $this->apps_custom[] = $app;

            //TODO: not implemented yet: <description>custom_app</description>

            $signaturecur = DH::findFirstElement('signature', $appx);
            if( $signaturecur !== FALSE )
            {
                $app->custom_signature = TRUE;
            }

            $parentappcur = DH::findFirstElement('parent-app', $appx);
            if( $parentappcur !== FALSE )
            {
                //TODO: implementation needed of $app->parent_app
                #$app->parent_app = $parentappcur->textContent;
            }

            $timeoutcur = DH::findFirstElement('timeout', $appx);
            if( $timeoutcur !== FALSE )
            {
                $app->timeout = $timeoutcur->textContent;
            }
            $tcptimeoutcur = DH::findFirstElement('tcp-timeout', $appx);
            if( $tcptimeoutcur !== FALSE )
            {
                $app->tcp_timeout = $tcptimeoutcur->textContent;
            }
            $udptimeoutcur = DH::findFirstElement('udp-timeout', $appx);
            if( $udptimeoutcur !== FALSE )
            {
                $app->udp_timeout = $udptimeoutcur->textContent;
            }
            $tcp_half_timeoutcur = DH::findFirstElement('tcp-half-closed-timeout', $appx);
            if( $tcp_half_timeoutcur !== FALSE )
            {
                $app->tcp_half_closed_timeout = $tcp_half_timeoutcur->textContent;
            }
            $tcp_wait_timeoutcur = DH::findFirstElement('tcp-time-wait-timeout', $appx);
            if( $tcp_wait_timeoutcur !== FALSE )
            {
                $app->tcp_time_wait_timeout = $tcp_wait_timeoutcur->textContent;
            }

            $cursor = DH::findFirstElement('default', $appx);
            if( $cursor !== FALSE )
            {
                $protocur = DH::findFirstElement('ident-by-ip-protocol', $cursor);
                if( $protocur !== FALSE )
                {
                    $app->proto = $protocur->textContent;
                }

                $icmpcur = DH::findFirstElement('ident-by-icmp-type', $cursor);
                if( $icmpcur !== FALSE )
                {
                    $icmptype = DH::findFirstElement('type', $icmpcur);
                    if( $icmptype !== FALSE )
                    {
                        $app->icmpsub = $icmptype->textContent;
                    }

                    $icmpcode = DH::findFirstElement('code', $icmpcur);
                    if( $icmpcode !== FALSE )
                    {
                        $app->icmpcode = $icmpcode->textContent;
                    }
                }

                $icmp6cur = DH::findFirstElement('ident-by-icmp6-type', $cursor);
                if( $icmp6cur !== FALSE )
                {
                    $icmp6type = DH::findFirstElement('type', $icmp6cur);
                    if( $icmp6type !== FALSE )
                    {
                        $app->icmp6sub = $icmp6type->textContent;
                    }

                    $icmp6code = DH::findFirstElement('code', $icmp6cur);
                    if( $icmp6code !== FALSE )
                    {
                        $app->icmp6code = $icmp6code->textContent;
                    }
                }

                $cursor = DH::findFirstElement('port', $cursor);
                if( $cursor !== FALSE )
                {
                    foreach( $cursor->childNodes as $portx )
                    {
                        if( $portx->nodeType != XML_ELEMENT_NODE )
                            continue;

                        /** @var  $portx DOMElement */

                        $ex = explode('/', $portx->textContent);

                        if( count($ex) != 2 )
                            derr('unsupported port description: ' . $portx->textContent);

                        if( $ex[0] == 'tcp' )
                        {
                            $exports = explode(',', $ex[1]);
                            $ports = array();

                            if( count($exports) < 1 )
                                derr('unsupported port description: ' . $portx->textContent);

                            foreach( $exports as &$sport )
                            {
                                if( $sport == 'dynamic' )
                                {
                                    $ports[] = array(0 => 'dynamic');
                                    continue;
                                }
                                $tmpex = explode('-', $sport);
                                if( count($tmpex) < 2 )
                                {
                                    $ports[] = array(0 => 'single', 1 => $sport);
                                    continue;
                                }

                                $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                            }
                            //print_r($ports);

                            if( $app->tcp === null )
                                $app->tcp = $ports;
                            else
                                $app->tcp = array_merge($app->tcp, $ports);
                        }
                        elseif( $ex[0] == 'udp' )
                        {
                            $exports = explode(',', $ex[1]);
                            $ports = array();

                            if( count($exports) < 1 )
                                derr('unsupported port description: ' . $portx->textContent);

                            foreach( $exports as &$sport )
                            {
                                if( $sport == 'dynamic' )
                                {
                                    $ports[] = array(0 => 'dynamic');
                                    continue;
                                }
                                $tmpex = explode('-', $sport);
                                if( count($tmpex) < 2 )
                                {
                                    $ports[] = array(0 => 'single', 1 => $sport);
                                    continue;
                                }

                                $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                            }
                            //print_r($ports);

                            if( $app->udp === null )
                                $app->udp = $ports;
                            else
                                $app->udp = array_merge($app->udp, $ports);
                        }
                        elseif( $ex[0] == 'icmp' )
                        {
                            $app->icmp = $ex[1];
                        }
                        elseif( $ex[0] == 'icmp6' )
                        {
                            $app->icmp6 = $ex[1];
                        }
                        else
                            derr('unsupported port description: ' . $portx->textContent);
                    }
                }
            }


            $app->app_filter_details = array();

            $tmp = DH::findFirstElement('category', $appx);
            if( $tmp !== FALSE )
            {
                $app->category = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('subcategory', $appx);
            if( $tmp !== FALSE )
            {
                $app->subCategory = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('technology', $appx);
            if( $tmp !== FALSE )
            {
                $app->technology = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('risk', $appx);
            if( $tmp !== FALSE )
            {
                $app->risk = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('evasive-behavior', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['evasive'] = TRUE;
            }
            $tmp = DH::findFirstElement('consume-big-bandwidth', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['excessive-bandwidth'] = TRUE;
            }
            $tmp = DH::findFirstElement('used-by-malware', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['used-by-malware'] = TRUE;
            }
            $tmp = DH::findFirstElement('able-to-transfer-files', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['transfers-files'] = TRUE;
            }
            $tmp = DH::findFirstElement('has-known-vulnerabilities', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['vulnerabilities'] = TRUE;
            }
            $tmp = DH::findFirstElement('tunnels-other-apps', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['tunnels-other-apps'] = TRUE;
            }
            $tmp = DH::findFirstElement('prone-to-misuse', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['prone-to-misuse'] = TRUE;
            }

            $tmp = DH::findFirstElement('pervasive-use', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['widely-used'] = TRUE;
            }


            $tmp = DH::findFirstElement('virusident-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->virusident = TRUE;
            }
            $tmp = DH::findFirstElement('filetype-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->filetypeident = TRUE;
            }
            $tmp = DH::findFirstElement('data-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->fileforward = TRUE;
            }
        }
    }

    public function load_application_filter_from_domxml($xmlDom)
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationFilter name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->type = 'application-filter';
            $this->add($app);

            $this->app_filters[] = $app;

            //TODO: check if multiple selections are needed
            //only first FILTER is checked
            //what about second/third??
            //- if use array how to get the information via the app filter
            $app->app_filter_details = array();

            $tmp = DH::findFirstElement('category', $appx);
            if( $tmp !== FALSE )
            {
                $app->app_filter_details['category'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->category = $tmp1->textContent;
                    $app->app_filter_details['category'][$tmp1->textContent] = $tmp1->textContent;

                }
            }

            $tmp = DH::findFirstElement('subcategory', $appx);
            if( $tmp !== FALSE )
            {
                $app->app_filter_details['subcategory'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->subCategory = $tmp1->textContent;
                    $app->app_filter_details['subcategory'][$tmp1->textContent] = $tmp1->textContent;
                }
            }

            $tmp = DH::findFirstElement('technology', $appx);
            if( $tmp !== FALSE )
            {
                $app->app_filter_details['technology'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->technology = $tmp1->textContent;
                    $app->app_filter_details['technology'][$tmp1->textContent] = $tmp1->textContent;
                }
            }

            $tmp = DH::findFirstElement('risk', $appx);
            if( $tmp !== FALSE )
            {
                $app->app_filter_details['risk'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->risk = $tmp1->textContent;
                    $app->app_filter_details['risk'][$tmp1->textContent] = $tmp1->textContent;
                }
            }

            $tmp = DH::findFirstElement('evasive', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['evasive'] = TRUE;
            }
            $tmp = DH::findFirstElement('excessive-bandwidth-use', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['excessive-bandwidth'] = TRUE;
            }
            $tmp = DH::findFirstElement('used-by-malware', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['used-by-malware'] = TRUE;
            }
            $tmp = DH::findFirstElement('transfers-files', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['transfers-files'] = TRUE;
            }
            $tmp = DH::findFirstElement('has-known-vulnerabilities', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['vulnerabilities'] = TRUE;
            }
            $tmp = DH::findFirstElement('tunnels-other-apps', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['tunnels-other-apps'] = TRUE;
            }
            $tmp = DH::findFirstElement('prone-to-misuse', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['prone-to-misuse'] = TRUE;
            }

            $tmp = DH::findFirstElement('pervasive', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['widely-used'] = TRUE;
            }

        }
    }


    public function load_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/application', $xmlDoc);

        $this->load_from_domxml($cursor);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/application-container', $xmlDoc);

        $this->loadcontainers_from_domxml($cursor);


        $appid_version = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);
        self::$predefinedStore->predefinedStore_appid_version = $appid_version->nodeValue;

        // fixing someone mess ;)
        $app = $this->findOrCreate('ftp');
        $app->tcp[] = array(0 => 'dynamic');
    }


    public function get_app_by_ipprotocol($protocol)
    {
        if( !is_numeric($protocol) )
            return null;

        foreach( $this->apps() as $app )
        {
            if( $app->proto == $protocol )
                return $app;
        }

        return null;
    }

    public function get_app_by_icmptype( $version, $type, $code )
    {
        foreach( $this->apps() as $app )
        {
            #
            #$app->icmpcode
            #$app->icmp6sub
            #$app->icmp6code
            if( $version == "ipv6" && $app->icmp6sub == $type )
            {
                if( $code != '' )
                {
                    if( $app->icmp6code != $code )
                        return null;
                }
                return $app;
            }
            elseif( $app->icmpsub == $type )
            {
                if( $code != '' )
                {
                    if( $app->icmpcode != $code )
                        return null;
                }
                return $app;
            }
        }

        return null;
    }

    public function countAppCustom()
    {
        return count( $this->apps_custom );
    }

    public function countAppFilters()
    {
        return count( $this->app_filters );
    }

    public function countAppGroups()
    {
        return count( $this->app_groups );
    }
}





