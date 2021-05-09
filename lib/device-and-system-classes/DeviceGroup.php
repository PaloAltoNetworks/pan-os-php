<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


class DeviceGroup
{

    use PathableName;
    use PanSubHelperTrait;

    /** String */
    protected $name;

    /** @var PanoramaConf */
    public $owner = null;

    /** @var DOMElement */
    public $xmlroot;

    /** @var DOMElement */
    public $devicesRoot;

    /** @var AddressStore */
    public $addressStore = null;
    /** @var ServiceStore */
    public $serviceStore = null;


    protected $securityProfilebaseroot;

    /** @var SecurityProfileStore */
    public $URLProfileStore = null;

    /** @var SecurityProfileStore */
    public $customURLProfileStore = null;

    /** @var SecurityProfileStore */
    public $AntiVirusProfileStore = null;

    /** @var SecurityProfileStore */
    public $VulnerabilityProfileStore = null;

    /** @var SecurityProfileStore */
    public $AntiSpywareProfileStore = null;

    /** @var SecurityProfileStore */
    public $FileBlockingProfileStore = null;

    /** @var SecurityProfileStore */
    public $WildfireProfileStore = null;


    /** @var SecurityProfileGroupStore */
    public $securityProfileGroupStore = null;

    /** @var SecurityProfileStore */
    public $DecryptionProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipObjectsProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipProfilesProfileStore = null;

    /** @var ScheduleStore */
    public $scheduleStore = null;


    public static $templatexml = '<entry name="**Need a Name**"><address></address><post-rulebase><security><rules></rules></security><nat><rules></rules></nat></post-rulebase>
									<pre-rulebase><security><rules></rules></security><nat><rules></rules></nat></pre-rulebase>
									</entry>';


    /** @var AppStore */
    public $appStore;

    /** @var TagStore */
    public $tagStore = null;

    /** @var ZoneStore */
    public $zoneStore = null;

    /** @var RuleStore */
    public $securityRules = null;

    /** @var RuleStore */
    public $natRules = null;

    /** @var RuleStore */
    public $decryptionRules = null;

    /** @var RuleStore */
    public $appOverrideRules;

    /** @var RuleStore */
    public $captivePortalRules;

    /** @var RuleStore */
    public $authenticationRules;

    /** @var RuleStore */
    public $pbfRules;

    /** @var RuleStore */
    public $qosRules;

    /** @var RuleStore */
    public $dosRules;

    /**
     * @var null|DeviceGroup
     */
    public $parentDeviceGroup = null;

    /** @var DeviceGroup[] */
    public $_childDeviceGroups = array();

    /** @var Array */
    private $devices = array();

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;

    public $version = null;


    public function __construct($owner)
    {
        $this->owner = $owner;
        $this->version = &$owner->version;

        $this->device = array();

        $this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

        $this->zoneStore = $owner->zoneStore;
        $this->appStore = $owner->appStore;

        $this->serviceStore = new ServiceStore($this);
        $this->serviceStore->name = 'services';

        $this->addressStore = new AddressStore($this);
        $this->addressStore->name = 'address';


        $this->customURLProfileStore = new SecurityProfileStore($this, "CustomSecurityProfileURL");
        $this->customURLProfileStore->name = 'CustomURL';

        $this->URLProfileStore = new SecurityProfileStore($this, "SecurityProfileURL");
        $this->URLProfileStore->name = 'URL';

        $this->AntiVirusProfileStore = new SecurityProfileStore($this, "SecurityProfileAntiVirus");
        $this->AntiVirusProfileStore->name = 'AntiVirus';

        $this->VulnerabilityProfileStore = new SecurityProfileStore($this, "SecurityProfileVulnerability");
        $this->VulnerabilityProfileStore->name = 'Vulnerability';

        $this->AntiSpywareProfileStore = new SecurityProfileStore($this, "SecurityProfileAntiSpyware");
        $this->AntiSpywareProfileStore->name = 'AntiSpyware';

        $this->FileBlockingProfileStore = new SecurityProfileStore($this, "SecurityProfileFileBlocking");
        $this->FileBlockingProfileStore->name = 'FileBlocking';

        $this->WildfireProfileStore = new SecurityProfileStore($this, "SecurityProfileWildFire");
        $this->WildfireProfileStore->name = 'WildFire';


        $this->securityProfileGroupStore = new SecurityProfileGroupStore($this);
        $this->securityProfileGroupStore->name = 'SecurityProfileGroups';

        $this->DecryptionProfileStore = new SecurityProfileStore($this, "DecryptionProfile");
        $this->DecryptionProfileStore->name = 'Decryption';

        $this->HipObjectsProfileStore = new SecurityProfileStore($this, "HipObjectsProfile");
        $this->HipObjectsProfileStore->name = 'HipObjects';

        $this->HipProfilesProfileStore = new SecurityProfileStore($this, "HipProfilesProfile");
        $this->HipProfilesProfileStore->name = 'HipProfiles';

        $this->scheduleStore = new ScheduleStore($this);
        $this->scheduleStore->setName('scheduleStore');

        $this->securityRules = new RuleStore($this, 'SecurityRule', TRUE);
        $this->natRules = new RuleStore($this, 'NatRule', TRUE);
        $this->decryptionRules = new RuleStore($this, 'DecryptionRule', TRUE);
        $this->appOverrideRules = new RuleStore($this, 'AppOverrideRule', TRUE);
        $this->captivePortalRules = new RuleStore($this, 'CaptivePortalRule', TRUE);
        $this->authenticationRules = new RuleStore($this, 'AuthenticationRule', TRUE);
        $this->pbfRules = new RuleStore($this, 'PbfRule', TRUE);
        $this->qosRules = new RuleStore($this, 'QoSRule', TRUE);
        $this->dosRules = new RuleStore($this, 'DoSRule', TRUE);

        $this->_fakeNetworkProperties = $this->owner->_fakeNetworkProperties;
        $this->dosRules->_networkStore = $this->_fakeNetworkProperties;
        $this->pbfRules->_networkStore = $this->_fakeNetworkProperties;
    }

    public function load_from_templateXml()
    {
        if( $this->owner === null )
            derr('cannot be used if owner === null');

        $fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

        if( !$fragment->appendXML(self::$templatexml) )
            derr('error occured while loading device group template xml');

        $element = $this->owner->devicegrouproot->appendChild($fragment);

        $this->load_from_domxml($element);
    }


    /**
     * !! Should not be used outside of a PanoramaConf constructor. !!
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        // this VirtualSystem has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("VirtualSystem name not found\n");

        //
        // Extract Tag objects
        //
        if( $this->owner->version >= 60 )
        {
            $tmp = DH::findFirstElement('tag', $xml);
            if( $tmp !== FALSE )
                $this->tagStore->load_from_domxml($tmp);
        }
        // End of Tag objects extraction


        //
        // Extract address objects
        //
        $tmp = DH::findFirstElementOrCreate('address', $xml);
        $this->addressStore->load_addresses_from_domxml($tmp);
        //print "VirtualSystem '".$this->name."' address objectsloaded\n" ;
        // End of address objects extraction


        //
        // Extract address groups in this DV
        //
        $tmp = DH::findFirstElementOrCreate('address-group', $xml);
        $this->addressStore->load_addressgroups_from_domxml($tmp);
        //print "VirtualSystem '".$this->name."' address groups loaded\n" ;
        // End of address groups extraction


        //												//
        // Extract service objects in this VirtualSystem			//
        //												//
        $tmp = DH::findFirstElementOrCreate('service', $xml);
        $this->serviceStore->load_services_from_domxml($tmp);
        //print "VirtualSystem '".$this->name."' service objects\n" ;
        // End of <service> extraction


        //												//
        // Extract service groups in this VirtualSystem			//
        //												//
        $tmp = DH::findFirstElementOrCreate('service-group', $xml);
        $this->serviceStore->load_servicegroups_from_domxml($tmp);
        //print "VirtualSystem '".$this->name."' service groups loaded\n" ;
        // End of <service-group> extraction

        //
        // Extract application
        //
        $tmp = DH::findFirstElementOrCreate('application', $xml);
        $this->appStore->load_application_custom_from_domxml($tmp);
        // End of application extraction

        //
        // Extract application filter
        //
        $tmp = DH::findFirstElementOrCreate('application-filter', $xml);
        $this->appStore->load_application_filter_from_domxml($tmp);
        // End of application filter groups extraction

        //
        // Extract application groups
        //
        $tmp = DH::findFirstElementOrCreate('application-group', $xml);
        $this->appStore->load_application_group_from_domxml($tmp);
        // End of application groups extraction


        // Extract SecurityProfiles objects
        //
        $tmp = DH::findFirstElementOrCreate('profiles', $xml);


        $this->securityProfilebaseroot = DH::findFirstElement('profiles', $xml);
        if( $this->securityProfilebaseroot === FALSE )
            $this->securityProfilebaseroot = null;

        if( $this->securityProfilebaseroot !== null )
        {
            //
            // URL Profile extraction
            //
            $tmproot = DH::findFirstElement('url-filtering', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->URLProfileStore->load_from_domxml($tmproot);

            //
            // Nat Rules extraction
            //
            $tmproot = DH::findFirstElement('custom-url-category', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->customURLProfileStore->load_from_domxml($tmproot);

            //
            // AntiVirus Profile extraction
            //
            $tmproot = DH::findFirstElement('virus', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->AntiVirusProfileStore->load_from_domxml($tmproot);

            //
            // FileBlocking Profile extraction
            //
            $tmproot = DH::findFirstElement('file-blocking', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->FileBlockingProfileStore->load_from_domxml($tmproot);

            //
            // vulnerability Profile extraction
            //
            $tmproot = DH::findFirstElement('vulnerability', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->VulnerabilityProfileStore->load_from_domxml($tmproot);

            //
            // spyware Profile extraction
            //
            $tmproot = DH::findFirstElement('spyware', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->AntiSpywareProfileStore->load_from_domxml($tmproot);

            //
            // wildfire Profile extraction
            //
            $tmproot = DH::findFirstElement('wildfire-analysis', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->WildfireProfileStore->load_from_domxml($tmproot);

            //
            // Decryption Profile extraction
            //
            $tmproot = DH::findFirstElement('decryption', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->DecryptionProfileStore->load_from_domxml($tmproot);
            }

            //
            // HipObjects Profile extraction
            //
            $tmproot = DH::findFirstElement('hip-objects', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->HipObjectsProfileStore->load_from_domxml($tmproot);
            }

            //
            // HipProfiles Profile extraction
            //
            $tmproot = DH::findFirstElement('hip-profiles', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->HipProfilesProfileStore->load_from_domxml($tmproot);
            }
        }


        //
        // Extract SecurityProfile groups in this DV
        //
        $tmp = DH::findFirstElement('profile-group', $xml);
        if( $tmp !== FALSE )
            $this->securityProfileGroupStore->load_securityprofile_groups_from_domxml($tmp);
        // End of address groups extraction


        //
        // Extract schedule objects
        //
        $tmp = DH::findFirstElement('schedule', $xml);
        if( $tmp !== FALSE )
            $this->scheduleStore->load_from_domxml($tmp);
        // End of address groups extraction


        //
        // Extracting policies
        //
        $prerulebase = DH::findFirstElement('pre-rulebase', $xml);
        $postrulebase = DH::findFirstElement('post-rulebase', $xml);

        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('security', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('security', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->securityRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('nat', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('nat', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->natRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('decryption', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('decryption', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->decryptionRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('application-override', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('application-override', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->appOverrideRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('captive-portal', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('captive-portal', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->captivePortalRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('authentication', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('authentication', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->authenticationRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('pbf', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('pbf', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->pbfRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('qos', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('qos', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->qosRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('dos', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('dos', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->dosRules->load_from_domxml($tmp, $tmpPost);
        //
        // end of policies extraction
        //


        // Devices extraction
        $this->devicesRoot = DH::findFirstElementOrCreate('devices', $xml);

        foreach( $this->devicesRoot->childNodes as $device )
        {
            if( $device->nodeType != 1 ) continue;
            $devname = DH::findAttribute('name', $device);
            $vsyslist = array();

            $vsysChild = DH::firstChildElement($device);

            if( $vsysChild !== FALSE )
            {
                foreach( $vsysChild->childNodes as $vsysentry )
                {
                    if( $vsysentry->nodeType != 1 ) continue;
                    $vname = DH::findAttribute('name', $vsysentry);
                    $vsyslist[$vname] = $vname;
                }
            }
            else
            {
                //print "No vsys for device '$devname'\n";
                $vsyslist['vsys1'] = 'vsys1';
            }

            $this->devices[$devname] = array('serial' => $devname, 'vsyslist' => $vsyslist);
            foreach( $this->devices as $serial => $array )
            {
                $managedFirewall = $this->owner->managedFirewallsStore->find($serial);
                if( $managedFirewall !== null )
                    $managedFirewall->addDeviceGroup($this->name);
            }
        }

        $this->addressStore->nestedPointOfView();
        $this->serviceStore->nestedPointOfView();
        $this->tagStore->nestedPointOfView();
        $this->scheduleStore->nestedPointOfView();

    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $this->name . "']";

        return $str;
    }


    /**
     * @param bool $includeSubDeviceGroups look for device inside sub device-groups
     * @return array
     */
    public function getDevicesInGroup($includeSubDeviceGroups = FALSE)
    {
        $devices = $this->devices;

        if( $includeSubDeviceGroups )
        {
            foreach( $this->_childDeviceGroups as $childDG )
            {
                $subDevices = $childDG->getDevicesInGroup(TRUE);
                foreach( $subDevices as $subDevice )
                {
                    $serial = $subDevice['serial'];

                    if( isset($devices[$serial]) )
                    {
                        foreach( $subDevice['vsyslist'] as $vsys )
                        {
                            $devices[$serial]['vsyslist'][$vsys] = $vsys;
                        }
                    }
                    else
                        $devices[$serial] = $subDevice;
                }
            }
        }

        return $devices;
    }

    public function name()
    {
        return $this->name;
    }

    public function setName($newName)
    {
        $this->xmlroot->setAttribute('name', $newName);

        $this->name = $newName;
    }

    public function isDeviceGroup()
    {
        return TRUE;
    }


    public function display_statistics()
    {
        $stdoutarray = array();

        $header = "Statistics for DG '" . PH::boldText($this->name) . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = array();
        $stdoutarray['security rules']['pre'] = $this->securityRules->countPreRules();
        $stdoutarray['security rules']['post'] = $this->securityRules->countPostRules();

        $stdoutarray['nat rules'] = array();
        $stdoutarray['nat rules']['pre'] = $this->natRules->countPreRules();
        $stdoutarray['nat rules']['post'] = $this->natRules->countPostRules();

        $stdoutarray['qos rules'] = array();
        $stdoutarray['qos rules']['pre'] = $this->qosRules->countPreRules();
        $stdoutarray['qos rules']['post'] = $this->qosRules->countPostRules();

        $stdoutarray['pbf rules'] = array();
        $stdoutarray['pbf rules']['pre'] = $this->pbfRules->countPreRules();
        $stdoutarray['pbf rules']['post'] = $this->pbfRules->countPostRules();

        $stdoutarray['decrypt rules'] = array();
        $stdoutarray['decrypt rules']['pre'] = $this->decryptionRules->countPreRules();
        $stdoutarray['decrypt rules']['post'] = $this->decryptionRules->countPostRules();

        $stdoutarray['app-override rules'] = array();
        $stdoutarray['app-override rules']['pre'] = $this->appOverrideRules->countPreRules();
        $stdoutarray['app-override rules']['post'] = $this->appOverrideRules->countPostRules();

        $stdoutarray['captive-portal rules'] = array();
        $stdoutarray['captive-portal rules']['pre'] = $this->captivePortalRules->countPreRules();
        $stdoutarray['captive-portal rules']['post'] = $this->captivePortalRules->countPostRules();

        $stdoutarray['authentication rules'] = array();
        $stdoutarray['authentication rules']['pre'] = $this->authenticationRules->countPreRules();
        $stdoutarray['authentication rules']['post'] = $this->authenticationRules->countPostRules();

        $stdoutarray['dos rules'] = array();
        $stdoutarray['dos rules']['pre'] = $this->dosRules->countPreRules();
        $stdoutarray['dos rules']['post'] = $this->dosRules->countPostRules();

        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['total'] = $this->addressStore->count();
        $stdoutarray['address objects']['address'] = $this->addressStore->countAddresses();
        $stdoutarray['address objects']['group'] = $this->addressStore->countAddressGroups();
        $stdoutarray['address objects']['tmp'] = $this->addressStore->countTmpAddresses();
        $stdoutarray['address objects']['unused'] = $this->addressStore->countUnused();

        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects']['total'] = $this->serviceStore->count();
        $stdoutarray['service objects']['service'] = $this->serviceStore->countServices();
        $stdoutarray['service objects']['group'] = $this->serviceStore->countServiceGroups();
        $stdoutarray['service objects']['tmp'] = $this->serviceStore->countTmpServices();
        $stdoutarray['service objects']['unused'] = $this->serviceStore->countUnused();

        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects']['total'] = $this->tagStore->count();
        $stdoutarray['tag objects']['unused'] = $this->tagStore->countUnused();
        #$stdoutarray['zones'] = $this->zoneStore->count();
        #$stdoutarray['apps'] = $this->appStore->count();

        $return = array();
        $return['DG-stat'] = $stdoutarray;
        #PH::print_stdout( $return );
        PH::print_stdout( $stdoutarray );

    }

    /**
     * @param bool $nested
     * @return DeviceGroup[]
     */
    public function childDeviceGroups($nested = FALSE)
    {
        if( $nested )
        {
            $dgs = array();

            foreach( $this->_childDeviceGroups as $dg )
            {
                $dgs[$dg->name()] = $dg;
                $tmp = $dg->childDeviceGroups(TRUE);
                foreach( $tmp as $sub )
                    $dgs[$sub->name()] = $sub;
            }

            return $dgs;
        }

        return $this->_childDeviceGroups;
    }

    /**
     * @return DeviceGroup[]
     */
    public function parentDeviceGroups()
    {
        if( $this->name() == 'shared' )
        {
            $dgs[$this->name()] = $this;
            return $dgs;
        }

        $dg_tmp = $this;
        $dgs = array();

        while( $dg_tmp !== null )
        {
            $dgs[$dg_tmp->name()] = $dg_tmp;
            $dg_tmp = $dg_tmp->parentDeviceGroup;
        }

        return $dgs;
    }

}


