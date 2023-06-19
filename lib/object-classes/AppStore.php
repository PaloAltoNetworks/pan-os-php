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

class AppStore extends ObjStore
{
    public $name;

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

    /** @var DOMElement */
    public $appCustomRoot;

    /** @var DOMElement */
    public $appFilterRoot;

    /** @var DOMElement */
    public $appGroupRoot;


    /**
     * @return AppStore|null
     */
    public static function getPredefinedStore( $owner )
    {
        if( self::$predefinedStore !== null )
            return self::$predefinedStore;

        self::$predefinedStore = new AppStore( $owner );
        self::$predefinedStore->setName('predefined Apps');
        self::$predefinedStore->load_from_predefinedfile();

        return self::$predefinedStore;
    }


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        #$this->o = &$this->apps;
        $this->o = array();

        $this->setParentCentralStore( 'appStore' );
    }

    /**
     * @param $name string
     * @param $ref
     * @return null|App
     */
    public function find($name, $ref = null, $nested = TRUE )
    {
        $f = $this->findByName($name, $ref, $nested);
        if( $f !== null )
            return $f;

        if( $nested && $this->parentCentralStore )
            return $this->parentCentralStore->find($name, $ref, $nested);

        return null;
    }

    /**
     * @param $name string
     * @param $ref
     * @return null|App
     */
    public function findorCreate($name, $ref = null, $nested = TRUE)
    {
        #$f = $this->findByName($name, $ref, $nested);
        $f = $this->find($name, $ref, $nested);

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
     * @return App[]
     */
    public function nestedPointOfView()
    {
        $current = $this;

        $objects = array();

        while( TRUE )
        {
            if( get_class( $current->owner ) == "PanoramaConf" )
                $location = "shared";
            else
                $location = $current->owner->name();

            foreach( $current->o as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    if( $tmp_ref_count == 0 )
                    {
                        //Todo: check if object value is same; if same to not add ref
                        if( $location != "shared" )
                            foreach( $o->refrules as $ref )
                                $tmp_o->addReference( $ref );
                    }
                }
            }

            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->appStore;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->appStore;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->appStore;
            else
                break;
        }

        return $objects;
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
            $app->xmlroot = $appx;
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

                if( $app->obsolete == "yes" )
                {
                    //Todo: 20211116 - not all obsolete apps are disabled on applipedia, WHY?
                    #$this->remove( $app );
                    #continue;
                }
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


            $tmp = DH::findFirstElement('tag', $appx);
            if( $tmp !== FALSE )
            {
                $tag_array = array();
                foreach( $tmp->childNodes as $tag )
                {
                    if( $tag->nodeType != XML_ELEMENT_NODE )
                        continue;

                    /** @var  $tag DOMElement */
                    $tag_text = str_replace( "[", "", $tag->textContent);
                    $tag_text = str_replace( "]", "", $tag_text);

                    $tag_array[$tag_text] = $tag_text;
                }
                $app->apptag = $tag_array;
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

            $cursor = DH::findFirstElement('tunnel-applications', $appx);
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
                    $app->tunnelApp[] = $depApp;
                }
            }

            $cursor = DH::findFirstElement('applicable-decoders', $appx);
            if( $cursor !== FALSE )
            {
                foreach( $cursor->childNodes as $depNode )
                {
                    if( $depNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $depName = $depNode->textContent;
                    if( strlen($depName) < 1 )
                        derr("dependency name length is < 0");

                    $app->decoder[$depName] = $depName;
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

    public function load_containers_from_domxml(&$xmlDom)
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationContainer name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->xmlroot = $appx;
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
                $subapp->addReference( $app );
            }

        }
    }

    public function load_application_group_from_domxml($xmlDom)
    {
        $this->appGroupRoot = $xmlDom;

        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationGroup name not found in XML: ", $appx);

            $app = new AppGroup($appName, $this);
            $app->xmlroot = $appx;
            $app->type = 'application-group';

            $this->app_groups[ $app->name() ] = $app;
            $this->add($app);

            $app->load_from_domxml( $app->xmlroot );
        }
    }

    public function load_application_custom_from_domxml($xmlDom)
    {
        $this->appCustomRoot = $xmlDom;

        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationCustom name not found in XML: ", $appx);

            $app = new AppCustom($appName, $this);
            $app->xmlroot = $appx;
            $app->type = 'application-custom';
            $this->add($app);

            $this->apps_custom[ $app->name() ] = $app;

            $app->load_from_domxml( $app->xmlroot );
        }
    }


    public function load_application_filter_from_domxml($xmlDom)
    {
        $this->appFilterRoot = $xmlDom;

        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationFilter name not found in XML: ", $appx);

            $app = new AppFilter($appName, $this);
            $app->xmlroot = $appx;
            $app->type = 'application-filter';
            $this->add($app);

            $this->app_filters[ $app->name() ] = $app;

            $app->load_from_domxml( $app->xmlroot );
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

        $this->load_containers_from_domxml($cursor);


        $appid_version = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);
        self::$predefinedStore->predefinedStore_appid_version = $appid_version->nodeValue;

        // fixing someone mess ;)
        $app = $this->findOrCreate('ftp');
        $app->tcp[] = array(0 => 'dynamic');
    }

    /**
     * @param App $Obj
     * @return bool if object was added. wrong if it was already there or another object with same name.
     *
     * @throws Exception
     */
    public function addApp( $Obj )
    {
        $objectName = $Obj->name();

        if( !in_array($Obj, $this->o, TRUE) )
        {
            $this->o[] = $Obj;
            $this->nameIndex[$Obj->name()] = $Obj;
        }
        else
        {
            derr('You cannot add object with same name in a store');
        }

        if( $Obj->isApplicationCustom() )
        {
            $this->apps_custom[$objectName] = $Obj;
            if( $this->appCustomRoot === null )
                $this->appCustomRoot = DH::findFirstElementOrCreate("application", $this->owner->xmlroot);
            $this->appCustomRoot->appendChild($Obj->xmlroot);
        }
        elseif( $Obj->isApplicationFilter() )
        {
            $this->app_filters[$objectName] = $Obj;
            if( $this->appFilterRoot === null )
                $this->appFilterRoot = DH::findFirstElementOrCreate("application-filter", $this->owner->xmlroot);
            $this->appFilterRoot->appendChild($Obj->xmlroot);
        }
        elseif( $Obj->isApplicationGroup() )
        {
            $this->app_groups[$objectName] = $Obj;
            if( $this->appGroupRoot === null )
                $this->appGroupRoot = DH::findFirstElementOrCreate("application-group", $this->owner->xmlroot);

            $this->appGroupRoot->appendChild($Obj->xmlroot);
        }
        else
            derr('invalid app type found');


        $Obj->owner = $this;


        return TRUE;

    }


    /**
     * @param App $s
     * @param bool $cleanInMemory
     * @return bool
     */
    public function API_remove($s, $cleanInMemory = FALSE)
    {
        $xpath = null;

        if( !$s->isTmp() )
            $xpath = $s->getXPath();

        $ret = $this->remove($s, $cleanInMemory);

        if( $ret && !$s->isTmp() )
        {
            $con = findConnectorOrDie($this);
            if( $con->isAPI() )
                $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    /**
     * @param App $Obj
     * @return bool if object was added. wrong if it was already there or another object with same name.
     *
     * @throws Exception
     */
    public function remove( $Obj )
    {
        if( $Obj->isApplicationCustom() || $Obj->isApplicationFilter() || $Obj->isApplicationGroup() )
        {
            parent::remove( $Obj );
            return True;
        }
        else
            return FALSE;

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

    private function &getBaseXPath()
    {
        $class = get_class($this->owner);

        if( $class == 'PanoramaConf' || $class == 'PANConf' )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();

        return $str;
    }

    public function &getAppCustomStoreXPath()
    {
        $path = $this->getBaseXPath() . '/application';
        return $path;
    }

    public function &getAppFilterStoreXPath()
    {
        $path = $this->getBaseXPath() . '/application-filter';
        return $path;
    }

    public function &getAppGroupStoreXPath()
    {
        $path = $this->getBaseXPath() . '/application-group';
        return $path;
    }
}





