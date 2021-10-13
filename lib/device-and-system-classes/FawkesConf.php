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
 * Your journey will start from PANConf or PanoramaConf
 *
 * Code:
 *
 *  $pan = new PanoramaConf();
 *
 *  $pan->load_from_file('config.txt');
 *
 *  $pan->display_statistics();
 *
 * And there you go !
 *
 */
class FawkesConf
{
    use PathableName;
    use PanSubHelperTrait;


    /** @var DOMElement */
    public $xmlroot;

    /** @var DOMDocument */
    public $xmldoc;

    /** @var DOMElement */
    public $devicesroot;
    public $localhostlocaldomain;

    /** @var DOMElement */
    public $localhostroot;

    /** @var string[]|DomNode */
    public $devicecloudroot;

    /** @var string[]|DomNode */
    public $cloudroot;



    /** @var string[]|DomNode */
    public $containerroot;

    public $version = null;

    public $managedFirewallsSerials = array();
    public $managedFirewallsStore;
    public $managedFirewallsSerialsModel = array();

    /** @var Container[] */
    public $containers = array();

    /** @var DeviceCloud[] */
    public $clouds = array();
    



    /** @var PANConf[] */
    public $managedFirewalls = array();


    /** @var PanAPIConnector|null $connector */
    public $connector = null;

    /** @var null|Template */
    public $owner = null;

    /** @var NetworkPropertiesContainer */
    public $network;

    /** @var AppStore */
    public $appStore;

    /** @var ThreatStore */
    public $threatStore;

    /** @var SecurityProfileStore */
    public $urlStore;

    /** @var ZoneStore */
    public $zoneStore = null;

    public $_fakeMode = FALSE;

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;

    public $name = '';

    public function name()
    {
        return $this->name;
    }

    public function __construct()
    {
        //Todo: zoneStore in Fawkes Config MUST not be there; this is normally handled in a different way
        // old usage from Panorama in Rulezonecontainer; fix it later
        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');


        $this->appStore = AppStore::getPredefinedStore( $this );

        $this->threatStore = ThreatStore::getPredefinedStore( $this );

        $this->urlStore = SecurityProfileStore::getPredefinedStore();

        $this->_fakeNetworkProperties = new NetworkPropertiesContainer($this);


        $this->managedFirewallsStore = new ManagedDeviceStore($this, 'managedFirewall', TRUE);
    }


    public function load_from_xmlstring(&$xml)
    {
        $this->xmldoc = new DOMDocument();

        if( $this->xmldoc->loadXML($xml, XML_PARSE_BIG_LINES) !== TRUE )
            derr('Invalid XML file found');

        $this->load_from_domxml($this->xmldoc);
    }

    /**
     * @param DOMElement|DOMDocument $xml
     * @throws Exception
     */
    public function load_from_domxml($xml)
    {
        if( $xml->nodeType == XML_DOCUMENT_NODE )
        {
            $this->xmldoc = $xml;
            $this->xmlroot = DH::findFirstElementOrDie('config', $this->xmldoc);
        }
        else
        {
            $this->xmldoc = $xml->ownerDocument;
            $this->xmlroot = $xml;
        }

        $versionAttr = DH::findAttribute('version', $this->xmlroot);
        if( $versionAttr !== FALSE )
        {
            $this->version = PH::versionFromString($versionAttr);
        }
        else
        {
            if( isset($this->connector) && $this->connector !== null )
            {
                $version = $this->connector->getSoftwareVersion();
                $this->version = $version['version'];
            }

            else
                $this->version = "not defined";


        }


        #$tmp = DH::findFirstElementOrCreate('mgt-config', $this->xmlroot);
        #$this->managedFirewallsSerials = $this->managedFirewallsStore->get_serial_from_xml($tmp, TRUE);


        if( is_object($this->connector) )
            $this->managedFirewallsSerialsModel = $this->connector->panorama_getConnectedFirewallsSerials();


        $this->devicesroot = DH::findFirstElementOrDie('devices', $this->xmlroot);

        $this->localhostroot = DH::findFirstElementByNameAttrOrDie('entry', 'localhost.localdomain', $this->devicesroot);
        /*
        $this->localhostroot = DH::findFirstElement('entry', $this->devicesroot);
        if( $this->localhostroot === false )
        {
            $this->localhostroot = DH::createElement($this->devicesroot, 'entry');
            $this->localhostroot->setAttribute('name', 'localhost.localdomain');
        }
        */


        $this->containerroot = DH::findFirstElementOrCreate('container', $this->localhostroot);
        $this->devicecloudroot = DH::findFirstElementOrCreate('device', $this->localhostroot);
        $this->cloudroot = DH::findFirstElementOrCreate('cloud', $this->devicecloudroot);
        




        //->devices/container
        //
        // loading Containers now
        //


        $containerMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry/container', $this->xmlroot);

        $containerToParent = array();
        $parentToDG = array();

        if( $containerMetaDataNode !== false )
            foreach( $containerMetaDataNode->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $containerName = DH::findAttribute('name', $node);
                if( $containerName === FALSE )
                    derr("Container name attribute not found in container-meta-data", $node);

                $containerLoadOrder[] = $containerName;
                //parent information not available in fawkes read-only; direct
            }



/*
        PH::print_stdout( "1Container loading order:" );
        foreach( $containerLoadOrder as &$dgName )
            PH::print_stdout(  " - {$dgName}" );
*/

        $containerNodes = array();

        foreach( $this->containerroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeNameAttr = DH::findAttribute('name', $node);
            if( $nodeNameAttr === FALSE )
                derr("Container 'name' attribute was not found", $node);

            if( !is_string($nodeNameAttr) || $nodeNameAttr == '' )
                derr("Container 'name' attribute has invalid value", $node);

            $parentContainer = DH::findFirstElement('parent', $node);
            if( $parentContainer === FALSE )
            {
                $containerToParent[$nodeNameAttr] = 'All';
                $parentToContainer['All'][] = $nodeNameAttr;
            }
            else
            {
                $containerToParent[$nodeNameAttr] = $parentContainer->textContent;
                $parentToContainer[$parentContainer->textContent][] = $nodeNameAttr;
            }

            $containerNodes[$nodeNameAttr] = $node;
        }


        $containerLoadOrder = array('All');


        while( count($parentToContainer) > 0 )
        {
            $containerLoadOrderCount = count($containerLoadOrder);

            foreach( $containerLoadOrder as &$dgName )
            {
                if( isset($parentToContainer[$dgName]) )
                {
                    foreach( $parentToContainer[$dgName] as &$newDGName )
                    {
                        if( $newDGName != 'All' )
                            $containerLoadOrder[] = $newDGName;
                    }
                    unset($parentToContainer[$dgName]);
                }
            }

            if( count($containerLoadOrder) <= $containerLoadOrderCount )
            {
                PH::print_stdout(  "Problems could be available with the following Container(s)" );
                PH::print_stdout(  "COUNT LoadOrder: ".count($containerLoadOrder) );
                PH::print_stdout(  "COUNT LoadOrderCount: ".$containerLoadOrderCount );
                print_r($containerLoadOrder);
                #derr('container-meta-data seems to be corrupted, parent.child template cannot be calculated ', $containerMetaDataNode);
            }


        }

        foreach( $containerLoadOrder as $containerIndex => &$containerName )
        {
            #if( $containerName == 'All' )
            #    continue;


            if( !isset($containerNodes[$containerName]) )
            {
                mwarning("Container '$containerName' is listed in dg-meta-data but doesn't exist in XML");
                //unset($dgLoadOrder[$dgIndex]);
                continue;
            }

            $ldv = new Container($this);
            if( !isset($containerToParent[$containerName]) )
            {
                mwarning("Container '$containerName' has not parent associated, assuming All");
            }
            elseif( $containerToParent[$containerName] == 'All' )
            {
                // do nothing
            }
            else
            {
                $parentContainer = $this->findContainer($containerToParent[$containerName]);
                if( $parentContainer === null )
                    mwarning("Container '$containerName' has Container '{$containerToParent[$containerName]}' listed as parent but it cannot be found in XML");
                else
                {
                    $parentContainer->_childContainers[$containerName] = $ldv;
                    $ldv->parentContainer = $parentContainer;
                    $ldv->addressStore->parentCentralStore = $parentContainer->addressStore;
                    $ldv->serviceStore->parentCentralStore = $parentContainer->serviceStore;
                    $ldv->tagStore->parentCentralStore = $parentContainer->tagStore;
                    $ldv->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
                    $ldv->appStore->parentCentralStore = $parentContainer->appStore;
                    $ldv->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
                    //Todo: swaschkut 20210505 - check if other Stores must be added
                    //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile
                }
            }
            
            $ldv->load_from_domxml($containerNodes[$containerName]);
            $this->containers[] = $ldv;

        }
        //
        // End of Container loading
        //

        //->devices/device/cloud
        //
        // loading clouds
        //
        foreach( $this->cloudroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $ldv = new DeviceCloud( $this );

            $ldv->load_from_domxml( $node );
            $this->clouds[] = $ldv;
        }
        //
        // end of DeviceCloud
        //

    }


    /**
     * @param string $name
     * @return Container|null
     */
    public function findContainer($name)
    {
        foreach( $this->containers as $dg )
        {
            if( $dg->name() == $name )
                return $dg;
        }

        return null;
    }

    /**
     * @param string $name
     * @return DeviceCloud|null
     */
    public function findDeviceCloud($name)
    {
        foreach( $this->clouds as $template )
        {
            if( $template->name() == $name )
                return $template;
        }

        return null;
    }


    /**
     * @param string $fileName
     * @param bool $printMessage
     * @param int $indentingXml
     */
    public function save_to_file($fileName, $printMessage = TRUE, $lineReturn = TRUE, $indentingXml = 0, $indentingXmlIncreament = 1)
    {
        if( $printMessage )
            PH::print_stdout( "Now saving FawkesConf to file '$fileName'..." );

        //Todo: swaschkut check
        //$indentingXmlIncreament was 2 per default for Panroama
        $xml = &DH::dom_to_xml($this->xmlroot, $indentingXml, $lineReturn, -1, $indentingXmlIncreament + 1);

        $path_parts = pathinfo($fileName);
        if (!is_dir($path_parts['dirname']))
            mkdir($path_parts['dirname'], 0777, true);

        file_put_contents($fileName, $xml);

        if( $printMessage )
            PH::print_stdout( "     done!" );
    }

    /**
     * @param string $fileName
     */
    public function load_from_file($fileName)
    {
        $filecontents = file_get_contents($fileName);

        $this->load_from_xmlstring($filecontents);

    }

    public function display_statistics( $return = false )
    {

        $container_all = $this->findContainer( "All");
        
        $gpreSecRules = $container_all->securityRules->countPreRules();
        $gpreNatRules = $container_all->natRules->countPreRules();
        $gpreDecryptRules = $container_all->decryptionRules->countPreRules();
        $gpreAppOverrideRules = $container_all->appOverrideRules->countPreRules();
        $gpreCPRules = $container_all->captivePortalRules->countPreRules();
        $gpreAuthRules = $container_all->authenticationRules->countPreRules();
        $gprePbfRules = $container_all->pbfRules->countPreRules();
        $gpreQoSRules = $container_all->qosRules->countPreRules();
        $gpreDoSRules = $container_all->dosRules->countPreRules();

        $gpostSecRules = $container_all->securityRules->countPostRules();
        $gpostNatRules = $container_all->natRules->countPostRules();
        $gpostDecryptRules = $container_all->decryptionRules->countPostRules();
        $gpostAppOverrideRules = $container_all->appOverrideRules->countPostRules();
        $gpostCPRules = $container_all->captivePortalRules->countPostRules();
        $gpostAuthRules = $container_all->authenticationRules->countPostRules();
        $gpostPbfRules = $container_all->pbfRules->countPostRules();
        $gpostQoSRules = $container_all->qosRules->countPostRules();
        $gpostDoSRules = $container_all->dosRules->countPostRules();

        $gnservices = $container_all->serviceStore->countServices();
        $gnservicesUnused = $container_all->serviceStore->countUnusedServices();
        $gnserviceGs = $container_all->serviceStore->countServiceGroups();
        $gnserviceGsUnused = $container_all->serviceStore->countUnusedServiceGroups();
        $gnTmpServices = $container_all->serviceStore->countTmpServices();

        $gnaddresss = $container_all->addressStore->countAddresses();
        $gnaddresssUnused = $container_all->addressStore->countUnusedAddresses();
        $gnaddressGs = $container_all->addressStore->countAddressGroups();
        $gnaddressGsUnused = $container_all->addressStore->countUnusedAddressGroups();
        $gnTmpAddresses = $container_all->addressStore->countTmpAddresses();

        $gTagCount = $container_all->tagStore->count();
        $gTagUnusedCount = $container_all->tagStore->countUnused();

        $gnsecprofgroups = $container_all->securityProfileGroupStore->count();


        $gnsecprofAS = $container_all->AntiSpywareProfileStore->count();
        $gnsecprofVB = $container_all->VulnerabilityProfileStore->count();
        $gnsecprofAVWF = $container_all->VirusAndWildfireProfileStore->count();
        $gnsecprofDNS = $container_all->DNSSecurityProfileStore->count();
        $gnsecprofSaas = $container_all->SaasSecurityProfileStore->count();
        $gnsecprofURL = $container_all->URLProfileStore->count();
        $gnsecprofFB = $container_all->FileBlockingProfileStore->count();

        $gnsecprofDecr = $container_all->DecryptionProfileStore->count();
        $gnsecprofHipProf = $container_all->HipProfilesProfileStore->count();
        $gnsecprofHipObj = $container_all->HipObjectsProfileStore->count();

        foreach( $this->containers as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $gpreSecRules += $cur->securityRules->countPreRules();
            $gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();
            $gpreAppOverrideRules += $cur->appOverrideRules->countPreRules();
            $gpreCPRules += $cur->captivePortalRules->countPreRules();
            $gpreAuthRules += $cur->authenticationRules->countPreRules();
            $gprePbfRules += $cur->pbfRules->countPreRules();
            $gpreQoSRules += $cur->qosRules->countPreRules();
            $gpreDoSRules += $cur->dosRules->countPreRules();

            $gpostSecRules += $cur->securityRules->countPostRules();
            $gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();
            $gpostAppOverrideRules += $cur->appOverrideRules->countPostRules();
            $gpostCPRules += $cur->captivePortalRules->countPostRules();
            $gpostAuthRules += $cur->authenticationRules->countPostRules();
            $gpostPbfRules += $cur->pbfRules->countPostRules();
            $gpostQoSRules += $cur->qosRules->countPostRules();
            $gpostDoSRules += $cur->dosRules->countPostRules();

            $gnservices += $cur->serviceStore->countServices();
            $gnservicesUnused += $cur->serviceStore->countUnusedServices();
            $gnserviceGs += $cur->serviceStore->countServiceGroups();
            $gnserviceGsUnused += $cur->serviceStore->countUnusedServiceGroups();
            $gnTmpServices += $cur->serviceStore->countTmpServices();

            $gnaddresss += $cur->addressStore->countAddresses();
            $gnaddresssUnused += $cur->addressStore->countUnusedAddresses();
            $gnaddressGs += $cur->addressStore->countAddressGroups();
            $gnaddressGsUnused += $cur->addressStore->countUnusedAddressGroups();
            $gnTmpAddresses += $cur->addressStore->countTmpAddresses();

            $gTagCount += $cur->tagStore->count();
            $gTagUnusedCount += $cur->tagStore->countUnused();

            $gnsecprofgroups += $cur->securityProfileGroupStore->count();

            $gnsecprofAS += $cur->AntiSpywareProfileStore->count();
            $gnsecprofVB += $cur->VulnerabilityProfileStore->count();
            $gnsecprofAVWF += $cur->VirusAndWildfireProfileStore->count();
            $gnsecprofDNS += $cur->DNSSecurityProfileStore->count();
            $gnsecprofSaas += $cur->SaasSecurityProfileStore->count();
            $gnsecprofURL += $cur->URLProfileStore->count();
            $gnsecprofFB += $cur->FileBlockingProfileStore->count();

            $gnsecprofDecr += $cur->DecryptionProfileStore->count();
            $gnsecprofHipProf += $cur->HipProfilesProfileStore->count();
            $gnsecprofHipObj += $cur->HipObjectsProfileStore->count();
        }

        foreach( $this->clouds as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $gpreSecRules += $cur->securityRules->count();
            $gpreNatRules += $cur->natRules->count();
            $gpreDecryptRules += $cur->decryptionRules->count();
            $gpreAppOverrideRules += $cur->appOverrideRules->count();
            $gpreCPRules += $cur->captivePortalRules->count();
            $gpreAuthRules += $cur->authenticationRules->count();
            $gprePbfRules += $cur->pbfRules->count();
            $gpreQoSRules += $cur->qosRules->count();
            $gpreDoSRules += $cur->dosRules->count();

            /*
            $gpreSecRules += $cur->securityRules->countPreRules();
            $gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();
            $gpreAppOverrideRules += $cur->appOverrideRules->countPreRules();
            $gpreCPRules += $cur->captivePortalRules->countPreRules();
            $gpreAuthRules += $cur->authenticationRules->countPreRules();
            $gprePbfRules += $cur->pbfRules->countPreRules();
            $gpreQoSRules += $cur->qosRules->countPreRules();
            $gpreDoSRules += $cur->dosRules->countPreRules();

            $gpostSecRules += $cur->securityRules->countPostRules();
            $gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();
            $gpostAppOverrideRules += $cur->appOverrideRules->countPostRules();
            $gpostCPRules += $cur->captivePortalRules->countPostRules();
            $gpostAuthRules += $cur->authenticationRules->countPostRules();
            $gpostPbfRules += $cur->pbfRules->countPostRules();
            $gpostQoSRules += $cur->qosRules->countPostRules();
            $gpostDoSRules += $cur->dosRules->countPostRules();
            */

            $gnservices += $cur->serviceStore->countServices();
            $gnservicesUnused += $cur->serviceStore->countUnusedServices();
            $gnserviceGs += $cur->serviceStore->countServiceGroups();
            $gnserviceGsUnused += $cur->serviceStore->countUnusedServiceGroups();
            $gnTmpServices += $cur->serviceStore->countTmpServices();

            $gnaddresss += $cur->addressStore->countAddresses();
            $gnaddresssUnused += $cur->addressStore->countUnusedAddresses();
            $gnaddressGs += $cur->addressStore->countAddressGroups();
            $gnaddressGsUnused += $cur->addressStore->countUnusedAddressGroups();
            $gnTmpAddresses += $cur->addressStore->countTmpAddresses();

            $gTagCount += $cur->tagStore->count();
            $gTagUnusedCount += $cur->tagStore->countUnused();

            $gnsecprofgroups += $cur->securityProfileGroupStore->count();

            $gnsecprofAS += $cur->AntiSpywareProfileStore->count();
            $gnsecprofVB += $cur->VulnerabilityProfileStore->count();
            $gnsecprofAVWF += $cur->VirusAndWildfireProfileStore->count();
            $gnsecprofDNS += $cur->DNSSecurityProfileStore->count();
            $gnsecprofSaas += $cur->SaasSecurityProfileStore->count();
            $gnsecprofURL += $cur->URLProfileStore->count();
            $gnsecprofFB += $cur->FileBlockingProfileStore->count();

            $gnsecprofDecr += $cur->DecryptionProfileStore->count();
            $gnsecprofHipProf += $cur->HipProfilesProfileStore->count();
            $gnsecprofHipObj += $cur->HipObjectsProfileStore->count();
        }

        $stdoutarray = array();

        $header = "Statistics for PanoramaConf '" . $this->name . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['pre security rules'] = array();
        $stdoutarray['pre security rules']['All'] = $container_all->securityRules->countPreRules();
        $stdoutarray['pre security rules']['total_DGs'] = $gpreSecRules;

        $stdoutarray['post security rules'] = array();
        $stdoutarray['post security rules']['All'] = $container_all->securityRules->countPostRules();
        $stdoutarray['post security rules']['total_DGs'] = $gpostSecRules;


        $stdoutarray['pre nat rules'] = array();
        $stdoutarray['pre nat rules']['All'] = $container_all->natRules->countPreRules();
        $stdoutarray['pre nat rules']['total_DGs'] = $gpreNatRules;

        $stdoutarray['post nat rules'] = array();
        $stdoutarray['post nat rules']['All'] = $container_all->natRules->countPostRules();
        $stdoutarray['post nat rules']['total_DGs'] = $gpostNatRules;


        $stdoutarray['pre qos rules'] = array();
        $stdoutarray['pre qos rules']['All'] = $container_all->qosRules->countPreRules();
        $stdoutarray['pre qos rules']['total_DGs'] = $gpreQoSRules;

        $stdoutarray['post qos rules'] = array();
        $stdoutarray['post qos rules']['All'] = $container_all->qosRules->countPostRules();
        $stdoutarray['post qos rules']['total_DGs'] = $gpostQoSRules;


        $stdoutarray['pre pbf rules'] = array();
        $stdoutarray['pre pbf rules']['All'] = $container_all->pbfRules->countPreRules();
        $stdoutarray['pre pbf rules']['total_DGs'] = $gprePbfRules;

        $stdoutarray['post pbf rules'] = array();
        $stdoutarray['post pbf rules']['All'] = $container_all->pbfRules->countPostRules();
        $stdoutarray['post pbf rules']['total_DGs'] = $gpostPbfRules;


        $stdoutarray['pre decryption rules'] = array();
        $stdoutarray['pre decryption rules']['All'] = $container_all->decryptionRules->countPreRules();
        $stdoutarray['pre decryption rules']['total_DGs'] = $gpreDecryptRules;

        $stdoutarray['post decryption rules'] = array();
        $stdoutarray['post decryption rules']['All'] = $container_all->decryptionRules->countPostRules();
        $stdoutarray['post decryption rules']['total_DGs'] = $gpostDecryptRules;


        $stdoutarray['pre app-override rules'] = array();
        $stdoutarray['pre app-override rules']['All'] = $container_all->appOverrideRules->countPreRules();
        $stdoutarray['pre app-override rules']['total_DGs'] = $gpreAppOverrideRules;

        $stdoutarray['post app-override rules'] = array();
        $stdoutarray['post app-override rules']['All'] = $container_all->appOverrideRules->countPostRules();
        $stdoutarray['post app-override rules']['total_DGs'] = $gpostAppOverrideRules;


        $stdoutarray['pre capt-portal rules'] = array();
        $stdoutarray['pre capt-portal rules']['All'] = $container_all->captivePortalRules->countPreRules();
        $stdoutarray['pre capt-portal rules']['total_DGs'] = $gpreCPRules;

        $stdoutarray['post capt-portal rules'] = array();
        $stdoutarray['post capt-portal rules']['All'] = $container_all->captivePortalRules->countPostRules();
        $stdoutarray['post capt-portal rules']['total_DGs'] = $gpostCPRules;


        $stdoutarray['pre authentication rules'] = array();
        $stdoutarray['pre authentication rules']['All'] = $container_all->authenticationRules->countPreRules();
        $stdoutarray['pre authentication rules']['total_DGs'] = $gpreAuthRules;

        $stdoutarray['post authentication rules'] = array();
        $stdoutarray['post authentication rules']['All'] = $container_all->authenticationRules->countPostRules();
        $stdoutarray['post authentication rules']['total_DGs'] = $gpostAuthRules;


        $stdoutarray['pre dos rules'] = array();
        $stdoutarray['pre dos rules']['All'] = $container_all->dosRules->countPreRules();
        $stdoutarray['pre dos rules']['total_DGs'] = $gpreDoSRules;

        $stdoutarray['post dos rules'] = array();
        $stdoutarray['post dos rules']['All'] = $container_all->dosRules->countPostRules();
        $stdoutarray['post dos rules']['total_DGs'] = $gpostDoSRules;



        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['All'] = $container_all->addressStore->countAddresses();
        $stdoutarray['address objects']['total_DGs'] = $gnaddresss;
        $stdoutarray['address objects']['unused'] = $gnaddresssUnused;

        $stdoutarray['addressgroup objects'] = array();
        $stdoutarray['addressgroup objects']['All'] = $container_all->addressStore->countAddressGroups();
        $stdoutarray['addressgroup objects']['total_DGs'] = $gnaddressGs;
        $stdoutarray['addressgroup objects']['unused'] = $gnaddressGsUnused;

        $stdoutarray['temporary address objects'] = array();
        $stdoutarray['temporary address objects']['All'] = $container_all->addressStore->countTmpAddresses();
        $stdoutarray['temporary address objects']['total_DGs'] = $gnTmpAddresses;


        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects']['All'] = $container_all->serviceStore->countServices();
        $stdoutarray['service objects']['total_DGs'] = $gnservices;
        $stdoutarray['service objects']['unused'] = $gnservicesUnused;

        $stdoutarray['servicegroup objects'] = array();
        $stdoutarray['servicegroup objects']['All'] = $container_all->serviceStore->countServiceGroups();
        $stdoutarray['servicegroup objects']['total_DGs'] = $gnserviceGs;
        $stdoutarray['servicegroup objects']['unused'] = $gnserviceGsUnused;

        $stdoutarray['temporary service objects'] = array();
        $stdoutarray['temporary service objects']['All'] = $container_all->serviceStore->countTmpServices();
        $stdoutarray['temporary service objects']['total_DGs'] = $gnTmpServices;


        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects']['All'] = $container_all->tagStore->count();
        $stdoutarray['tag objects']['total_DGs'] = $gTagCount;
        $stdoutarray['tag objects']['unused'] = $gTagUnusedCount;

        $stdoutarray['securityProfileGroup objects'] = array();
        $stdoutarray['securityProfileGroup objects']['All'] = $container_all->securityProfileGroupStore->count();
        $stdoutarray['securityProfileGroup objects']['total_DGs'] = $gnsecprofgroups;

        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile Anti-Spyware objects']['All'] = $container_all->AntiSpywareProfileStore->count();
        $stdoutarray['securityProfile Anti-Spyware objects']['total_DGs'] = $gnsecprofAS;

        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile Vulnerability objects']['All'] = $container_all->VulnerabilityProfileStore->count();
        $stdoutarray['securityProfile Vulnerability objects']['total_DGs'] = $gnsecprofVB;

        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile WildfireAndAnti-Virus objects']['All'] = $container_all->VirusAndWildfireProfileStore->count();
        $stdoutarray['securityProfile WildfireAndAnti-Virus objects']['total_DGs'] = $gnsecprofAVWF;

        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile DNS objects']['All'] = $container_all->DNSSecurityProfileStore->count();
        $stdoutarray['securityProfile DNS objects']['total_DGs'] = $gnsecprofDNS;

        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile Saas objects']['All'] = $container_all->SaasSecurityProfileStore->count();
        $stdoutarray['securityProfile Saas objects']['total_DGs'] = $gnsecprofSaas;

        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile URL objects']['All'] = $container_all->URLProfileStore->count();
        $stdoutarray['securityProfile URL objects']['total_DGs'] = $gnsecprofURL;


        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile File-Blocking objects']['All'] = $container_all->FileBlockingProfileStore->count();
        $stdoutarray['securityProfile File-Blocking objects']['total_DGs'] = $gnsecprofFB;


        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile Decryption objects']['All'] = $container_all->DecryptionProfileStore->count();
        $stdoutarray['securityProfile Decryption objects']['total_DGs'] = $gnsecprofDecr;


        $stdoutarray['zones'] = $this->zoneStore->count();
        #$stdoutarray['apps'] = $this->appStore->count();

        /*
        $stdoutarray['interfaces'] = array();
        $stdoutarray['interfaces']['total'] = $numInterfaces;
        $stdoutarray['interfaces']['ethernet'] = $this->network->ethernetIfStore->count();

        $stdoutarray['sub-interfaces'] = array();
        $stdoutarray['sub-interfaces']['total'] = $numSubInterfaces;
        $stdoutarray['sub-interfaces']['ethernet'] = $this->network->ethernetIfStore->countSubInterfaces();
        */

        $return = array();
        $return['PanoramaConf-stat'] = $stdoutarray;

        if( $return )
        {
            return $stdoutarray;
        }
        else
            {
            #PH::print_stdout( $return );
            PH::print_stdout( $stdoutarray, true  );
        }
    }


    /**
     * Create a blank device group. Return that DV object.
     * @param string $name
     * @return Container
     **/
    public function createContainer($name, $parentContainerName)
    {
        $newDG = new Container($this);
        $newDG->load_from_templateContainerXml();
        $newDG->setName($name);

        $parentNode = DH::findFirstElementOrCreate('parent', $newDG->xmlroot );
        DH::setDomNodeText($parentNode, $parentContainerName );

        $this->containers[] = $newDG;

        if( $this->version >= 70 )
        {
            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/max-internal-id', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/max-dg-id', $this->xmlroot);

            $dgMaxID = $dgMetaDataNode->textContent;
            $dgMaxID++;
            DH::setDomNodeText($dgMetaDataNode, "{$dgMaxID}");

            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/container', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id></entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }

        $parentContainer = $this->findContainer( $parentContainerName );
        if( $parentContainer === null )
            mwarning("Container '$name' has Container '{$parentContainerName}' listed as parent but it cannot be found in XML");
        else
        {
            $parentContainer->_childContainers[$name] = $newDG;
            $newDG->parentContainer = $parentContainer;
            $newDG->addressStore->parentCentralStore = $parentContainer->addressStore;
            $newDG->serviceStore->parentCentralStore = $parentContainer->serviceStore;
            $newDG->tagStore->parentCentralStore = $parentContainer->tagStore;
            $newDG->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
            $newDG->appStore->parentCentralStore = $parentContainer->appStore;
            $newDG->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
            //Todo: swaschkut 20210505 - check if other Stores must be added
            //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile
        }

        return $newDG;
    }

    /**
     * @return Container[]
     */
    public function getContainers()
    {
        return $this->containers;
    }


    /**
     * Create a blank template. Return that template object.
     * @param string $name
     * @return DeviceCloud
     **/
    public function createDeviceCloud($name, $parentContainer_txt )
    {
        $newDG = new DeviceCloud($this);

        $xmlNode = DH::importXmlStringOrDie($this->xmldoc, DeviceCloud::$templateXml);

        $xmlNode->setAttribute('name', $name);

        #$newDG->load_from_domxml($xmlNode);
        $newDG->load_from_templateCloudeXml();
        $newDG->setName($name);

        $parentNode = DH::findFirstElementOrCreate('parent', $newDG->xmlroot );
        DH::setDomNodeText($parentNode, $parentContainer_txt );

        $this->clouds[] = $newDG;

        if( $this->version >= 70 )
        {
            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/max-internal-id', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/max-dg-id', $this->xmlroot);

            $dgMaxID = $dgMetaDataNode->textContent;
            $dgMaxID++;
            DH::setDomNodeText($dgMetaDataNode, "{$dgMaxID}");

            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device/cloud', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id></entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }

        $parentContainer = $this->findContainer( $parentContainer_txt );
        if( $parentContainer === null )
            mwarning("Container '$name' has Container '{$parentContainer_txt}' listed as parent but it cannot be found in XML");
        else
        {
            $parentContainer->_childContainers[$name] = $newDG;
            $newDG->parentContainer = $parentContainer;
            $newDG->addressStore->parentCentralStore = $parentContainer->addressStore;
            $newDG->serviceStore->parentCentralStore = $parentContainer->serviceStore;
            $newDG->tagStore->parentCentralStore = $parentContainer->tagStore;
            $newDG->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
            $newDG->appStore->parentCentralStore = $parentContainer->appStore;
            $newDG->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
            //Todo: swaschkut 20210505 - check if other Stores must be added
            //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile
        }

        return $newDG;
    }

    /**
     * @return DeviceCloud[]
     */
    public function getDeviceClouds()
    {
        return $this->clouds;
    }


    public function isFawkes()
    {
        return TRUE;
    }

    public function findSubSystemByName($location)
    {
        $return = $this->findContainer($location);
        if( $return == null )
            $return = $this->findDeviceCloud($location);

        return $return;
    }

}



