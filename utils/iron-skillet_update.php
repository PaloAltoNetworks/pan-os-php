<?php

$url = "https://raw.githubusercontent.com/PaloAltoNetworks/iron-skillet/";
#$url = "https://github.com/PaloAltoNetworks/iron-skillet/blob/";

$download_array = array();


//AS
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_spyware.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_spyware.xml
$download_array['as']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_spyware.xml";
$download_array['as']['10'] = "panos_v10.0/templates/panorama/snippets/profiles_spyware.xml";

//AV
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_virus.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_virus.xml
$download_array['av']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_virus.xml";
$download_array['av']['10'] = "panos_v10.0/templates/panorama/snippets/profiles_virus.xml";

//URL
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml
$download_array['url']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml";
$download_array['url']['10'] = "panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml";

//FB
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml
$download_array['fb']['10'] = "panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml";

//VB
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml
$download_array['vb']['10'] = "panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml";

//WF
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml
$download_array['wf']['10'] = "panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml";

//customerURL
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v8.1/templates/panorama/snippets/profiles_custom_url_category.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_custom_url_category.xml
$download_array['customURL']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_custom_url_category.xml";
$download_array['customURL']['10'] = "panos_v10.0/templates/panorama/snippets/profiles_custom_url_category.xml";

//SECgroup
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profile_group.xml
$download_array['secgroup']['10'] = "panos_v10.0/templates/panorama/snippets/profile_group.xml";


//LFP
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml
$download_array['lfp']['10'] = "panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml";

//ZPP
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml
$download_array['zpp']['10'] = "panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml";




foreach( $download_array as $type )
{
    $ironskillet_pathString = "../iron-skillet";
    foreach( $type as $version )
    {
        if (!is_dir($ironskillet_pathString )) {
            // dir doesn't exist, make it
            mkdir($ironskillet_pathString);
        }

        $filename = $ironskillet_pathString."/".$version;
        print "storefile: ".$filename."\n";

        $explodeArray = explode( "/", $version );

        $pathString = $ironskillet_pathString."/";
        for( $i = 0; $i < count( $explodeArray )-1; $i++ )
        {
            if (!is_dir( $pathString.$explodeArray[$i] )) {
                // dir doesn't exist, make it
                mkdir($pathString.$explodeArray[$i] );
            }

            $pathString = $pathString.$explodeArray[$i]."/";
        }



        $fullurl = $url.$version;
        print "urL: ".$fullurl."\n\n\n";

        $origFile = file_get_contents( $url.$version);
        $origFile = str_replace( "{{ SINKHOLE_IPV4 }}", "sinkhole.paloaltonetworks.com", $origFile);
        $origFile = str_replace( "{{ SINKHOLE_IPV6 }}", "2600:5200::1", $origFile);

        $origFile = "<root>".$origFile."</root>";

        file_put_contents( $ironskillet_pathString."/".$version, $origFile);
    }
}
