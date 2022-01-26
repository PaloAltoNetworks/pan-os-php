<?php
/**
 * ISC License
 *
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



class IRONSKILLET_UPDATE__
{
    function __construct()
    {

        $url = "https://raw.githubusercontent.com/PaloAltoNetworks/iron-skillet/";
#$url = "https://github.com/PaloAltoNetworks/iron-skillet/blob/";

        $download_array = array();


//AS
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_spyware.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_spyware.xml
        $download_array['as']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_spyware.xml";
        $download_array['as']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_spyware.xml";
        $download_array['as']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_spyware.xml";

//AV
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_virus.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_virus.xml
        $download_array['av']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_virus.xml";
        $download_array['av']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_virus.xml";
        $download_array['av']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_virus.xml";

//URL
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml
        $download_array['url']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_url_filtering.xml";
        $download_array['url']['91'] = "panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml";
        $download_array['url']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml";

//FB
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml
        $download_array['fb']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml";

//VB
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml
        $download_array['vb']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml";

//WF
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml
        $download_array['wf']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml";

//customerURL
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v8.1/templates/panorama/snippets/profiles_custom_url_category.xml
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profiles_custom_url_category.xml
        $download_array['customURL']['81'] = "panos_v8.1/templates/panorama/snippets/profiles_custom_url_category.xml";
        $download_array['customURL']['100'] = "panos_v10.0/templates/panorama/snippets/profiles_custom_url_category.xml";

//SECgroup
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/profile_group.xml
        $download_array['secgroup']['100'] = "panos_v10.0/templates/panorama/snippets/profile_group.xml";


//LFP
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml
        $download_array['lfp']['100'] = "panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml";

//ZPP
//https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml
        $download_array['zpp']['100'] = "panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml";




        foreach( $download_array as $type )
        {
            $ironskillet_pathString = dirname(__FILE__)."/../../iron-skillet";
            foreach( $type as $key => $version )
            {
                if (!is_dir($ironskillet_pathString )) {
                    // dir doesn't exist, make it
                    #print "FOLDER: ".$ironskillet_pathString."\n";
                    mkdir($ironskillet_pathString);
                }

                $filename = $ironskillet_pathString."/".$version;
                #print "storefile: ".$filename."\n";

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
                print "urL: ".$fullurl."\n";

                $arrContextOptions=array(
                    "ssl"=>array(
                        "verify_peer"=>false,
                        "verify_peer_name"=>false,
                    ),
                );


                $origFile = file_get_contents( $url.$version, false, stream_context_create($arrContextOptions));
                if( $key < 90 )
                {
                    $sinkholeIP = "72.5.65.111";
                    //Todo: why is URL category grayware not availalble in PAN-OS 8.1
                    $origFile = str_replace( "<member>grayware</member>", "", $origFile);
                }
                else
                    $sinkholeIP = "sinkhole.paloaltonetworks.com";


                $origFile = str_replace( "{{ SINKHOLE_IPV4 }}", $sinkholeIP, $origFile);
                $origFile = str_replace( "{{ SINKHOLE_IPV6 }}", "2600:5200::1", $origFile);

                $origFile = "<root>".$origFile."</root>";

                file_put_contents( $ironskillet_pathString."/".$version, $origFile);
            }
        }
    }

    function endOfScript()
    {
    }
}
