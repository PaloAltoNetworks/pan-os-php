<?php

require_once("parser/CISCOISR/CISCOISRmisc.php");

class CISCOISR extends PARSER
{
    use CISCOISRmisc;
    use SHAREDNEW;

    public $rule_count = 0;
    public $print_rule_array = TRUE;
    public $print = FALSE;
    public $debug = FALSE;

    public $found_eq = FALSE;
    public $found_eq_src = FALSE;
    public $found_timerange = FALSE;

    /*
     * CISCO ACL
    operator

    lt (less than), gt (greater than), eq (equal), neq (not equal), and range


    (Optional) Operator is used to compare source or destination ports. Possible operands are lt (less than), gt (greater than), eq (equal), neq (not equal), and range (inclusive range).

    If the operator is positioned after the source and source-wildcard values, it must match the source port.
    If the operator is positioned after the destination and destination-wildcard values, it must match the destination port.
    If the operator is positioned after the ttl keyword, it matches the TTL value.

    The range operator requires two port numbers. All other operators require one port number.
     */

    //Todo: list not complete
    //https://www.cisco.com/c/en/us/td/docs/security/asa/asa910/configuration/general/asa-910-general-config/ref-ports.html

    public $svcReplaceByOther = array();

    function cisco_service_replace()
    {
        $this->svcReplaceByOther["ip"] = array('any');
        $this->svcReplaceByOther['smtp'] = array('25');
        $this->svcReplaceByOther['snmp'] = array('161');
        $this->svcReplaceByOther['www'] = array('80');
        $this->svcReplaceByOther['netbios-ss'] = array('139');
        $this->svcReplaceByOther['netbios-ns'] = array('137');
        $this->svcReplaceByOther['netbios-dgm'] = array('138');
        $this->svcReplaceByOther['24962Replace'] = array('24962');
        $this->svcReplaceByOther['bootps'] = array('67');
        $this->svcReplaceByOther['tacacs'] = array('49');
        $this->svcReplaceByOther['msrpc'] = array('135');

        $this->svcReplaceByOther['bootpc'] = array('68');
        $this->svcReplaceByOther['domain'] = array('53');
        $this->svcReplaceByOther['isakmp'] = array('500');
        $this->svcReplaceByOther['ftp'] = array('21');
        $this->svcReplaceByOther['pop3'] = array('110');
        $this->svcReplaceByOther['ident'] = array('113');
        $this->svcReplaceByOther['ntp'] = array('123');
        $this->svcReplaceByOther['lpd'] = array('53');
        $this->svcReplaceByOther['sunrpc'] = array('111');
        $this->svcReplaceByOther['snmptrap'] = array('162');
        $this->svcReplaceByOther['sunrpc1'] = array('111');
        $this->svcReplaceByOther['sunrpc2'] = array('111');
        $this->svcReplaceByOther['sunrpc3'] = array('111');
        $this->svcReplaceByOther['sunrpc4'] = array('111');
        $this->svcReplaceByOther['sunrpc5'] = array('111');
        $this->svcReplaceByOther['bgp'] = array('179');

        $this->svcReplaceByOther['ftp-data'] = array('20');
        $this->svcReplaceByOther['telnet'] = array('23');
        $this->svcReplaceByOther['tftp'] = array('69');//but UDP how to fix????
        $this->svcReplaceByOther['nameserver'] = array('53');
        $this->svcReplaceByOther['daytime'] = array('13');
        $this->svcReplaceByOther['chargen'] = array('19');
        $this->svcReplaceByOther['echo'] = array('7');
    }


    function vendor_main()
    {



        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################

        //swaschkut - tmp, until class migration is done
        global $debug;
        global $print;
        $print = TRUE;
        $debug = TRUE;


        $this->cisco_service_replace();

        //CISCOISR specific
        //------------------------------------------------------------------------
        $natdst_content = array();
        $project = "";
        $path = "";


        $config_path = $path . $this->configFile;
        $filename = $this->configFile;
        $filenameParts = pathinfo($this->configFile);
        $verificationName = $filenameParts['filename'];



        $this->clean_config($config_path, $project, $this->configFile);




        $this->import_config(); //This should update the $source
        //------------------------------------------------------------------------

        CONVERTER::deleteDirectory( );
    }

    function clean_config($config_path, $project, $config_filename)
    {

        $config_file = file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->data = array();
        foreach( $config_file as $line => $names_line )
        {
            /*
            if( (preg_match("/description/", $names_line)) OR (preg_match("/remark/", $names_line)) )
            {
                #$data[] = $names_line;

                //Todo: SVEN 20191203 - problem with config "
                $tmp_array = explode("\r", $names_line);
                foreach( $tmp_array as $tmp_line )
                    $data[] = $tmp_line;
            }
            else
            {
                #"<--- More --->"
                if( preg_match("/^<--- More --->/", $names_line) || preg_match("/^              /", $names_line) )
                {

                }
                elseif( preg_match("/\'/", $names_line) )
                {
                    $data[] = str_replace("'", "_", $names_line);
                }
                elseif( preg_match("/\\r/", $names_line) )
                {
                    $tmp_array = explode("\r", $names_line);
                    foreach( $tmp_array as $tmp_line )
                        $data[] = $tmp_line;
                }
                else
                {
                    $data[] = $names_line;
                }
            }
            */
            $this->data[] = $names_line;

        }
    }

    function import_config()
    {

        global $debug;
        global $print;

        //CISCOISR specific functions


        echo PH::boldText("\nload custom app-id\n");
        $this->load_custom_application();

        echo PH::boldText("\nCisco Services loaded\n");
        $this->addServicePredefined( "cisco" );

        global $wildcard;


        $IpMaskTable = array();
        $NetworkGroupTable = array();


        $foundObject = array();
        $keyToCheck = 0;
        $accessList = "";
        $old_line_word = "";

        $ip_host_array = array();

        $found_objectgroup = FALSE;
        $objectgroup_key = 0;
        $objectgroup_array = array();

        $found_accesslist = FALSE;
        $accesslist_key = 0;
        $accesslist_array = array();

        foreach( $this->data as $index => &$line )
        {

            $line = $this->strip_hidden_chars($line);

            $line = trim($line, "\r");
            $line = trim($line, " ");

            $line = str_replace("   ", " ", $line);
            $line = str_replace("  ", " ", $line);

            #print "|".$line."|\n";
            $words = explode(' ', $line);

            if( $old_line_word == "!" )
            {
                $found_objectgroup = FALSE;
                $found_accesslist = FALSE;
            }


            #print "|".$line."|\n";
            #print_r( $words);


            if( $words[0] == 'ip' )
            {
                if( $words[1] == 'host' )
                {
                    $ip_host_array[] = $words;
                }
                elseif( $words[1] == 'route' )
                {

                }
                elseif( $words[1] == 'ospf' )
                {

                }
                elseif( $words[1] == 'vrf' )
                {

                }

                elseif( $words[1] == 'accounting' )
                {

                }
                elseif( $words[1] == 'access-list' )
                {

                    if( $words[2] == 'extended' || $words[2] == 'standard' )
                    {
                        //create access-list array; next list must include permit/deny/remark
                        $found_accesslist = TRUE;
                        $accesslist_key++;


                        $accesslist_type = $words[2];
                        $tmp_array = array('type' => $accesslist_type, 'value' => $words);

                        $accesslist_array[$accesslist_key] = $tmp_array;
                    }

                }
                elseif( $words[1] == 'nat' )
                {

                }
                elseif( $words[1] == 'address' )
                {
                    //only needed if $words[0] == "interface" already found before

                }
                elseif( $words[1] == 'access-group' )
                {
                    //only needed if $words[0] == "interface" already found before
                }
                elseif( $words[1] == 'sla' || $words[1] == 'prefix-list' ||
                    $words[1] == 'dns' || $words[1] == 'wccp' || $words[1] == 'tcp' || $words[1] == 'mtu'
                    || $words[1] == 'http' || $words[1] == 'policy' || $words[1] == 'nhrp'
                    || $words[1] == 'dhcp' || $words[1] == "forward-protocol" || $words[1] == "unnumbered" )
                {
                    if( $debug )
                        mwarning("'ip " . $words[1] . "' not of interest: " . $line . "\n", null, FALSE);
                }
                else
                {
                    #print "LINE#: ".$index."\n";
                    #print "|".$line."|\n";
                    if( $debug )
                    {
                        print_r($words);
                        mwarning("'ip " . $words[1] . "' not covered\n");
                    }

                }

            }
            elseif( $words[0] == "object-group" )
            {
                //object-group network globalprotect-gateways-object

                $found_objectgroup = TRUE;
                $objectgroup_key++;

                $objectgroup_array[$objectgroup_key]['name'] = $words[2];
                //next line host must befound
            }
            elseif( $words[0] == "host" && $found_objectgroup )
            {
                $tmp_array = array('type' => 'host', 'value' => $words[1]);
                $objectgroup_array[$objectgroup_key][] = $tmp_array;
            }
            elseif( $words[0] == "access-list" )
            {
                $found_accesslist = TRUE;
                $accesslist_key++;

                $accesslist_type = "outside";
                $tmp_array = array('type' => $accesslist_type, 'value' => $words);

                $accesslist_array[$accesslist_key] = $tmp_array;
            }
            elseif( $words[0] == "permit" || $words[0] == "deny" || $words[0] == "remark" && $found_accesslist )
            {
                $accesslist_array[$accesslist_key][] = $words;
            }
            else
            {
                $array[$words[0]] = "set";
                #$print_r( $words );
            }


            $old_line_word = $words[0];
        }

#print_r( $accesslist_array );
#print_r( $objectgroup_array );
#print_r( $array );


        print PH::boldText("\nadd ip host:\n");
        $this->create_address_host_objects( $ip_host_array);


        print PH::boldText("\nadd objectgroup:\n");
        $this->create_objectgroup( $objectgroup_array);

        print PH::boldText("\nadd accesslists:\n");
        $this->create_access_list( $accesslist_array);

    }

}