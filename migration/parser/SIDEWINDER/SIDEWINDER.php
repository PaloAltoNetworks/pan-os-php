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


require_once("SIDEWINDERaddress.php");
require_once("SIDEWINDERservice.php");
require_once ( "SIDEWINDERnetwork.php" );
require_once ("SIDEWINDERpolicy.php");






class SIDEWINDER extends PARSER
{
    /*
     * @param VirtualSystem $v
     */
    public $v = null;

    use SIDEWINDERaddress;
    use SIDEWINDERservice;
    use SIDEWINDERnetwork;
    use SIDEWINDERpolicy;

    use SHAREDNEW;

    function vendor_main()
    {





        //TODO: migration to Panorama not yet supported for Sidewinder
        //Todo: 20210119

        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        //swaschkut - tmp, until class migration is done
        global $print;
        $print = TRUE;


        $this->clean_config();

        #print_r( $data );




        $this->import_config( ); //This should update the $source
        //------------------------------------------------------------------------

/*
        //Todo: validation if GLOBAL rule
        echo PH::boldText( "Zone Calculation for Security and NAT policy" );
        Converter::calculate_zones( $pan, "append" );


        echo PH::boldText( "\nVALIDATION - interface name and change into PAN-OS confirm naming convention\n" );
        CONVERTER::validate_interface_names($pan);

        //Todo: where to place custom table for app-migration if needed
        echo PH::boldText( "\nVALIDATION - replace tmp services with APP-id if possible\n" );
        CONVERTER::AppMigration( $pan );
*/

        CONVERTER::deleteDirectory( );
    }

    function clean_config()
    {
        $file_content = file($this->configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        $i = 0;
        $j = 0;
        $k = 0;
        $string_array = array();
        foreach( $file_content as $line )
        {
            #print "line1|".$line."|\n";



            $line = str_replace(" \\\r","",$line);    #|-> \
            $line = str_replace(" \\\n","",$line);    #|-> \
            $line = str_replace(" \\\r\n","",$line);    #|-> \
            $line = str_replace(" \\\n\r","",$line);    #|-> \

            #print "line2|".$line."|\n";

            $line = $this->strip_hidden_chars( $line );

            $line = str_replace(" \\","",$line);    #|-> \
            $line = str_replace("\\\"","",$line);   #|->\"
            $line = str_replace("\"","",$line);     #|->"
            $line = str_replace("\\'","",$line);    #|->\'

            #print "line3|".$line."|\n";

            /*
            file_put_contents($config_path, implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));
            $kkk= str_replace("\r\n", "\n",
                str_replace("     ", " ",
                    str_replace("\\\r", "",
                        str_replace("\\\n", "",
                            str_replace("\\\r\n", "",
                                str_replace("\\\n\r", "",
        */


            //$findme = "    ";
            //$pos = strpos($line, $findme);


            #$needle_array = array( '    ', 'ipaddr', 'subnet', 'iprange', 'netgroup', 'service', 'servicegroup', 'policy', 'interface', 'static', 'route', 'netmap', 'domain', 'application', 'appgroup', 'host');
            #$needle_array = array( 'ipaddr', 'subnet', 'iprange', 'netgroup', 'service', 'servicegroup', 'policy', 'interface', 'static', 'route', 'netmap', 'domain', 'application', 'appgroup', 'host');
            //blank at end needed to find correct place
            $needle_array = array( 'ipaddr ', 'subnet ', 'iprange ', 'netgroup ', 'service ', 'servicegroup ', 'policy ', 'interface ', 'static ', 'route ', 'netmap ', 'domain ', 'application ', 'appgroup ', 'host');

            #print "LINE: |".$line."|\n";
            #print "POS: |".$this->strpos_arr($line, $needle_array)."\n";


            if( $this->strpos_arr($line, $needle_array) !== false && ( $this->strpos_arr($line, $needle_array) == 0 ) )
            {
                $k = 1;

                #print "1line|".$line."|\n";
                $string_array[$i][0] = $line;

                $j = $i;
                $i++;
            }
            else
            {
                $line = str_replace("    ","",$line);
                #print "2line|".$line."|\n";
                $string_array[$j][$k] = $line;
                #$string_array[$j][0] .= " ".$line;

                $k++;
            }

        }

        #print_r( $string_array );
        #exit;

        $this->data = $string_array;
    }


//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


    function import_config( )
    {
        global $projectdb;
        global $source;

        global $debug;
        global $print;

        global $tmp_template_vsys;


        $vsysName = "Sidewinder";
        $vsysID = 1;

        /*
        $this->template_vsys = $this->template->findVSYS_by_displayName($vsysName);
        if( $this->template_vsys === null )
        {
            #print "VSYS: ".$vsysID." already available - check displayName ".$vsysName."\n";
            $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            $this->template_vsys->setAlternativeName($vsysName);

            $tmp_template_vsys[ $vsysName ] = intval($vsysID);
        }
        else
        {
            //create new vsys, search for latest ID
            do
            {
                $vsysID++;
                $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            } while( $this->template_vsys !== null );

            if( $this->template_vsys === null )
            {
                $this->template_vsys = $this->template->createVirtualSystem(intval($vsysID), $vsysName . $vsysID);
                if( $this->template_vsys === null )
                {
                    derr("vsys" . $vsysID . " could not be created ? Exit\n");
                }
                #print "create VSYS: ".$vsysID." - ".$vsysName."\n";

                $tmp_template_vsys[ $vsysName ] = intval($vsysID);

            }
        }
        */
        $this->template_vsys = $this->template->findVSYS_by_displayName($vsysName);

        if( $this->template_vsys === null && $vsysID == 1 )
        {
            $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);

            if( $this->template_vsys !== null )
            {
                if( $print )
                    print "set vsys" . $vsysID . " alternativeName to: " . $vsysName . "\n";


                $this->template_vsys->setAlternativeName($vsysName);
                //carefull - not set if Panroama template vsys!!!! workarond
                $tmp_template_vsys[ $vsysName ] = intval($vsysID);
                $vsysID++;
            }
        }

        if( $this->template_vsys === null )
        {
            //Panorama template does not have vsys displayname:
            //workaround

            #if( isset( $tmp_template_vsys[ $vsysName ] ) )
                #continue;

            if( $print )
                print " * create vsys: " . $vsysID . " - " . $vsysName . "\n";
            $this->template_vsys = $this->template->createVirtualSystem(intval($vsysID), $vsysName);
            $tmp_template_vsys[ $vsysName ] = intval($vsysID);

            $vsysID++;
            if( $this->template_vsys === null )
            {
                derr("vsys" . $vsysID . " could not be created ? Exit\n");
            }
            //}
        }

        //vsys created

        //panorama DG
        //validation part 20201202 SVEN
        if( $this->configType == "panorama" )
        {
            $this->sub = $this->pan->findDeviceGroup( $vsysName );
            if( $this->sub == null )
            {
                print " * create DG: ".$vsysName."\n";
                $this->sub = $this->pan->createDeviceGroup( $vsysName );
            }
        }


        if( $this->routetable != "" )
        {
            echo PH::boldText( "\nimport dynamic Routing\n");
            #$ciscoFile = "/Users/swaschkut/Downloads/Show-Routes.log";
            $cisco = file_get_contents( $this->routetable);
            //todo: needed for Sidewinder
            #$this->importRoutes( $cisco);
        }


        $padding = "";
        $this->prepareArray( $this->data );

    }


    //cleanup preparation
    function prepareArray( $string_array)
    {
        global $debug;
        global $print;
        global $tmp_template_vsys;

        $cmd_array = array( 'ipaddr', 'subnet', 'iprange', 'netgroup', 'service', 'servicegroup', 'policy', 'interface', 'static', 'route', 'netmap', 'domain', 'application', 'appgroup', 'host');


        $line_array = array();
        $line_array['else'][0] = "EMPTY";
        foreach( $string_array as $line )
        {
            $count = count( $line );

            $oneline = "";
            for( $i=0; $i<$count;$i++)
            {
                if( $i == 0)
                    $oneline .= $line[$i];
                else
                    $oneline .= " ".$line[$i];

            }

            #print "|".$oneline."|\n\n";

            #fwrite($fp, $oneline."\n" );

            $pos_interface = strpos( $oneline, "interface " );
            $pos_service = strpos( $oneline, "service " );
            $pos_servicegroup = strpos( $oneline, "servicegroup " );
            $pos_policy = strpos( $oneline, "policy " );
            $pos_ipaddr = strpos( $oneline, "ipaddr " );
            $pos_subnet = strpos( $oneline, "subnet " );
            $pos_static = strpos( $oneline, "static " );
            $pos_netgroup = strpos( $oneline, "netgroup " );
            $pos_route = strpos( $oneline, "route " );
            $pos_iprange = strpos( $oneline, "iprange " );
            $pos_netmap = strpos( $oneline, "netmap " );
            $pos_domain = strpos( $oneline, "domain " );
            $pos_application = strpos( $oneline, "application " );
            $pos_appgroup = strpos( $oneline, "appgroup " );
            $pos_host = strpos( $oneline, "host " );




            if( $pos_policy === 0 )
                $line_array['policy'][] = $oneline;

            elseif( $pos_ipaddr === 0 )
                $line_array['ipaddr'][] = $oneline;
            elseif( $pos_subnet === 0 )
                $line_array['subnet'][] = $oneline;
            elseif( $pos_iprange === 0 )
                $line_array['iprange'][] = $oneline;

            elseif( $pos_netgroup === 0 )
                $line_array['netgroup'][] = $oneline;

            elseif( $pos_service === 0 )
                $line_array['service'][] = $oneline;
            elseif( $pos_servicegroup === 0 )
                $line_array['servicegroup'][] = $oneline;


            elseif( $pos_interface === 0 )
                $line_array['interface'][] = $oneline;

            elseif( $pos_static === 0 )
                $line_array['static'][] = $oneline;
            elseif( $pos_route === 0 )
                $line_array['route'][] = $oneline;

            elseif( $pos_netmap === 0 )
                $line_array['netmap'][] = $oneline;
            elseif( $pos_domain === 0 )
                $line_array['domain'][] = $oneline;
            elseif( $pos_application === 0 )
                $line_array['application'][] = $oneline;
            elseif( $pos_appgroup === 0 )
                $line_array['appgroup'][] = $oneline;
            elseif( $pos_host === 0 )
                $line_array['host'][] = $oneline;
            else
                $line_array['else'][] = $oneline;

        }




        print "\n";
        print "########################################################\n\n";
        print "Sidewinder configuration is now cleaned up\n\n";
        print "########################################################\n\n";


        print "\n";
        print "########################################################\n\n";
        print "Statistics for configuration file\n\n";
        print "########################################################\n\n";

        $count_address = 0;
        $pad = "     ";

        foreach( $cmd_array as $cmd )
        {
            $modify_count = 0;

            $policy_disabled = 0;
            $policy_nat_none = 0;
            $policy_nat_normal = 0;
            $policy_nat = 0;
            $policy_nat_normal_redir_empty = 0;
            $policy_nat_normal_redir = 0;
            $policy_rulegroup = 0;



            if( isset( $line_array[$cmd] ) )
            {
                if(  $cmd == 'subnet' ||  $cmd == 'iprange' || $cmd == 'netgroup' || $cmd == 'servicegroup')
                    print "";
                else
                    print "-  -  -  -  -  -  -  -  -  -  -\n";


                foreach( $line_array[$cmd] as $line)
                {
                    if( strpos( $line, "add " ) === false )
                    {
                        $modify_count++;
                    }

                    if( $debug ) {
                        #print "$pad".$line."\n";
                    }

                    if( $cmd == 'policy' )
                    {
                        if( strpos( $line, "disable=yes" ) != false )
                        {
                            $policy_disabled++;
                        }

                        if( strpos( $line, "nat_mode=normal" ) != false )
                        {
                            $policy_nat_normal++;

                            $policy_array = array( 'table','name','rulegroup','pos','action','appdefense','audit','authenticator','authgroups','dest',
                                'dest_burbs','disable','inspection_level','ispresponse','nat_addr','nat_mode','redir','redir_port',
                                'service','sign_category_grp','source','source_burbs','timeperiod','ts_enable','ts_reputation',
                                'description','last_changed_by');

                            $policy_print = array( 'name','dest','source','nat_addr', 'service','source_burbs','dest_burbs', 'redir','redir_port' );

                            $ii = 0;
                            $jj = 1;
                            $policy_string = "";
                            for($ii = 0; $ii < count($policy_array); $ii++)
                            {
                                if( $ii+1 != count($policy_array) )
                                {
                                    $jj = $ii +1;
                                    $search_string1 = $policy_array[$ii]."=";
                                    $search_string2 = $policy_array[$jj]."=";
                                }
                                else
                                {
                                    $search_string1 = $policy_array[$ii]."=";
                                    $search_string2 = "'";
                                }


                                $content = $this->find_string_between( $line, $search_string1,$search_string2 );
                                $content = trim($content, " =");

                                if( in_array( $policy_array[$ii], $policy_print ) )
                                    $policy_string .= str_pad($policy_array[$ii]."=".$content, 65, ' ', STR_PAD_RIGHT)."|";
                            }

                            #check if needed
                            #print $policy_string."\n";

                            #print $line."\n";

                            if( strpos( $line, "nat_mode=normal redir=" ) != false )
                            {
                                $policy_nat_normal_redir_empty++;
                            }

                            if(preg_match('/nat_mode=normal redir=[^ ]/', $line)){
                                $policy_nat_normal_redir++;
                            }

                        }

                        if( strpos( $line, "nat_mode=none" ) != false )
                            $policy_nat_none++;

                        if( strpos( $line, "nat_mode=" ) != false )
                            $policy_nat++;


                        if( strpos( $line, "table=rulegroup" ) != false )
                            $policy_rulegroup++;

                    }

                    if( $cmd == 'ipaddr' || $cmd == 'subnet' || $cmd == 'iprange' )
                    {
                        $count_address++;
                    }
                }

                if( $modify_count != 0 )
                {
                    #print $pad."  modified : ".$modify_count." [ finaly: ".(count( $line_array[$cmd])-$modify_count)." ]\n";
                    print "".str_pad($cmd, 17, ' ', STR_PAD_RIGHT)." : ".(count( $line_array[$cmd])-$modify_count)."\n";
                }
                elseif( $cmd == 'policy')
                    print "".str_pad($cmd, 17, ' ', STR_PAD_RIGHT)." : ".(count( $line_array[$cmd])-$policy_rulegroup)."\n";
                else
                {

                    print "".str_pad($cmd, 17, ' ', STR_PAD_RIGHT)." : ".count( $line_array[$cmd])."\n";
                }


                /*
3ipaddr            : 1937
3subnet            : 2799
3iprange           : 4
        addr count: 4740
3netgroup          : 643
-  -  -  -  -  -  -  -  -  -  -
1service           : 199
3servicegroup      : 84
-  -  -  -  -  -  -  -  -  -  -
2policy            : 272
        disabled  : 12
        s_nat     : 21
        proxy_nat : 2
-  -  -  -  -  -  -  -  -  -  -
1interface         : 14
-  -  -  -  -  -  -  -  -  -  -
3static            : 212
                 */
                if( $cmd == 'ipaddr')
                {
                    #print_r( $line_array[$cmd] );
                    $this->generateAddress( $line_array[$cmd] );
                }
                elseif( $cmd == 'subnet')
                {
                    $this->generateAddress( $line_array[$cmd] );
                }
                elseif( $cmd == 'iprange')
                {
                    $this->generateAddress( $line_array[$cmd] );
                }
                elseif( $cmd == 'netgroup')
                {
                    //create addressgroup
                    $this->generateAddressGroup( $line_array[$cmd] );
                }



                if( $cmd == 'service' || $cmd == 'application')
                {
                    //create services
                    $this->generateService( $line_array[$cmd] );

                }
                elseif( $cmd == 'servicegroup' || $cmd == 'appgroup')
                {
                    $this->generateServiceGroup( $line_array[$cmd] );
                }

                if( $cmd == 'policy')
                {
                    $this->get_policy( $line_array[$cmd] );
                }
                elseif( $cmd == 'interface')
                {
                    $this->get_interfaces( $line_array[$cmd] );
                }
                elseif( $cmd == 'static' || $cmd == 'route')
                {
                    $this->get_routes( $line_array[$cmd]);
                }

                #if( $policy_rulegroup != 0 )
                #    print $pad."   table=rulegroup : ".$policy_rulegroup." [ finaly: ".(count( $line_array[$cmd])-$policy_rulegroup)." ]\n";

                if( $policy_disabled != 0 )
                    print $pad."   disabled  : ".$policy_disabled."\n";

                #if( $policy_nat_none != 0 )
                #    print $pad."   nat_mode=none : ".$policy_nat_none."\n";

                #if( $policy_nat_normal != 0 )
                #    print $pad."   nat_mode=normal : ".$policy_nat_normal."\n";

                #if( $policy_nat != 0 )
                #    if( $debug )
                #        print $pad."   nat : ".$policy_nat." [normal+none=".($policy_nat_normal+$policy_nat_none)."]\n";

                if( $policy_nat_normal_redir_empty != 0 )
                    print "".$pad."   s_nat     : ".$policy_nat_normal_redir_empty."\n";

                if( $policy_nat_normal_redir != 0 )
                    print $pad."   proxy_nat : ".$policy_nat_normal_redir."\n";

                if( $count_address != 0 && $cmd == 'iprange')
                    print $pad.PH::boldText("   addr count: ".$count_address )."\n";

            }
            else
            {
                #print "".str_pad($cmd, 17, ' ', STR_PAD_RIGHT)." : 0\n";
                ########print "--- ERROR ---     no value for : ".$cmd." available in txt file\n";
            }

        }



        print "\n\n########################################################\n";
        print "########################################################\n\n\n";
    }




}


