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


class App
{

    use ReferenceableObject;
    use PathableName;

    public $type = 'tmp';

    public $tcp = null;
    public $udp = null;
    public $icmp = null;
    public $icmp6 = null;

    public $tcp_secure = null;
    public $udp_secure = null;
    public $icmp_secure = null;
    public $icmp6_secure = null;

    public $icmpsub = null;
    public $icmp6sub = null;
    public $icmpcode = null;
    public $icmp6code = null;
    public $proto = null;

    public $timeout = null;
    public $tcp_timeout = null;
    public $udp_timeout = null;
    public $tcp_half_closed_timeout = null;
    public $tcp_time_wait_timeout = null;

    /** @var null|array */
    public $app_filter_details = null;

    /** @var null|string */
    public $category = null;
    /** @var null|string */
    public $subCategory = null;
    /** @var null|string */
    public $technology = null;
    /** @var null|string */
    public $risk = null;

    /** @var null|string */
    public $apptag = array();

    /** @var bool */
    public $virusident = FALSE;
    /** @var bool */
    public $filetypeident = FALSE;
    /** @var bool */
    public $fileforward = FALSE;

    /** @var bool */
    public $custom_signature = FALSE;

    /** @var string[] */
    public $_characteristics = array();

    /** @var null|array */
    public $explicitUse = array();
    public $tunnelApp = array();
    public $decoder = array();

    //Todo: new dynamic content contains SAAS appid-saas-risk-fields
    static public $_supportedCharacteristics = array(
        'evasive' => 'evasive',
        'excessive-bandwidth' => 'excessive-bandwidth',
        'prone-to-misuse' => 'prone-to-misuse',
        'saas' => 'saas',
        'transfers-files' => 'transfers-files',
        'tunnels-other-apps' => 'tunnels-other-apps',
        'used-by-malware' => 'used-by-malware',
        'vulnerabilities' => 'vulnerabilities',
        'widely-used' => 'widely-used'
    );

    //public $type = 'notfound';

    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;

        #foreach( self::$_supportedCharacteristics as $characteristicName )
        #    $this->_characteristics[$characteristicName] = "0";
    }

    public function isUsingSpecialProto()
    {
        if( $this->isContainer() )
        {
            foreach( $this->subapps as $app )
            {
                if( $app->isUsingSpecialProto() )
                    return TRUE;
            }
            return FALSE;
        }

        if( $this->proto === null && $this->icmp === null && $this->icmpsub === null )
            return FALSE;

        return TRUE;
    }

    public function isContainer()
    {
        if( isset($this->subapps) )
            return TRUE;

        return FALSE;
    }

    /**
     * @return App[]
     * @throws Exception
     */
    public function containerApps()
    {
        if( !$this->isContainer() )
            derr('cannot be be called on a non container app');

        return $this->subapps;
    }

    public function groupApps()
    {
        if( !$this->isApplicationGroup() )
            derr('cannot be be called on a non ApplicationGroup app');

        return $this->groupapps;
    }

    public function filteredApps()
    {
        //Todo: actual only one filter value per category/ aso. is working
        //check how to validate correctly if two or more values are picked per e.g. category

        if( !$this->isApplicationFilter() )
            derr('cannot be be called on a non ApplicationFilter app');

        $app_array = array();
        //which filter options do we have?

        if( isset( $this->app_filter_details['category']) )
            $categories = $this->app_filter_details['category'];
        else
            $categories = array();

        if( isset( $this->app_filter_details['subcategory']) )
            $subcategories = $this->app_filter_details['subcategory'];
        else
            $subcategories = array();

        if( isset( $this->app_filter_details['risk']) )
            $risks = $this->app_filter_details['risk'];
        else
            $risks = array();

        if( isset( $this->app_filter_details['technology']) )
            $technologies = $this->app_filter_details['technology'];
        else
            $technologies = array();

        if( isset( $this->app_filter_details['tagging']) )
            $apptags = $this->app_filter_details['tagging'];
        else
            $apptags = array();

        if( isset( $this->_characteristics) )
            $characteristics = $this->_characteristics;
        else
            $characteristics = array();


        $appstore = $this->owner;
        $all = $appstore->getAll();

        while( get_class( $appstore->owner ) !== "PanoramaConf" && get_class( $appstore->owner ) !== "PANConf" && get_class( $appstore->owner ) !== "FawkesConf" )
        {
            $all = array_merge( $all, $appstore->owner->owner->appStore->getAll() );
            $appstore = $appstore->owner->owner->appStore;
        }

        foreach( $all as $app )
        {
            if( $app->isApplicationFilter() )
                continue;

            $hasCategory = TRUE;
            if( count( $categories ) > 0 )
            {
                $hasCategory = FALSE;
                foreach( $categories as $category )
                {
                    if( $category === $app->category )
                        $hasCategory = TRUE;
                }
            }

            $hasSubCategory = TRUE;
            if( count( $subcategories ) > 0 )
            {
                $hasSubCategory = FALSE;
                foreach( $subcategories as $subcategory )
                {
                    if( $subcategory === $app->subCategory )
                        $hasSubCategory = TRUE;
                }
            }

            $hasRisk = TRUE;
            if( count( $risks ) > 0 )
            {
                $hasRisk = FALSE;
                foreach( $risks as $risk )
                {
                    if( $risk === $app->risk )
                        $hasRisk = TRUE;
                }
            }

            $hasTechnology = TRUE;
            if( count( $technologies ) > 0 )
            {
                $hasTechnology = FALSE;
                foreach( $technologies as $technology )
                {
                    if( $technology === $app->technology )
                        $hasTechnology = TRUE;
                }
            }

            //cat,subcat,tech,risk are or creterium, app has x or y

            //apptag and characteristics are AND creterium app has apptag x and y; characeristic has x and y and....
            $hasAppTag = TRUE;
            if( count( $apptags ) > 0 )
            {
                $hasAppTag = FALSE;
                $hasAppTagArray = array();
                foreach( $apptags as $key => $apptag )
                {
                    if( in_array( $apptag, $app->apptag )  )
                        $hasAppTagArray[$key] = true;
                    else
                        $hasAppTagArray[$key] = false;
                }

                if(in_array(false, $hasAppTagArray, true) === false)
                    $hasAppTag = TRUE;
                else if(in_array(true, $hasAppTagArray, true) === false)
                    $hasAppTag = FALSE;
            }


            $hasCharacteristics = TRUE;
            if( count( $characteristics ) > 0 )
            {
                $hasCharacteristics = FALSE;
                $hasCharacteristicsArray = array();
                foreach( $characteristics as $characteristic => $bool )
                {
                    if( isset( $app->_characteristics[$characteristic] ) && $app->_characteristics[$characteristic] == $bool )
                        $hasCharacteristicsArray[$characteristic] = TRUE;
                    else
                        $hasCharacteristicsArray[$characteristic] = FALSE;
                }
                if(in_array(false, $hasCharacteristicsArray, true) === false)
                    $hasCharacteristics = TRUE;
                else if(in_array(true, $hasCharacteristicsArray, true) === false)
                    $hasCharacteristics = FALSE;
            }

            if( $hasCategory && $hasSubCategory && $hasRisk && $hasTechnology && $hasAppTag && $hasCharacteristics )
            #if( $hasCategory && $hasSubCategory && $hasRisk && $hasTechnology && $hasAppTag )
                $app_array[] = $app;
        }

        return $app_array;
    }


    /**
     * returns true if application is using dynamic ports
     * @return bool
     */
    public function useDynamicPorts()
    {

        if( $this->isContainer() )
        {
            foreach( $this->subapps as $app )
            {
                if( $app->useDynamicPorts() )
                    return TRUE;
            }
            return FALSE;
        }

        if( $this->tcp !== null )
        {
            foreach( $this->tcp as &$port )
            {
                if( $port[0] == 'dynamic' )
                    return TRUE;
            }
        }

        if( $this->udp !== null )
        {
            foreach( $this->udp as &$port )
            {
                if( $port[0] == 'dynamic' )
                    return TRUE;
            }
        }

        return FALSE;
    }

    public function matchPort($proto, $port)
    {

        if( $this->isContainer() )
        {
            foreach( $this->subapps as $app )
            {
                if( $app->matchPort($proto, $port) )
                    return TRUE;
            }
            return FALSE;
        }

        if( $proto === null || $port === null )
            derr('cannot be called with null arguments');

        if( $proto != 'tcp' && $proto != 'udp' )
            derr('unsupported procotol : ' . $proto);

        if( $this->$proto !== null )
        {
            foreach( $this->$proto as &$lport )
            {
                if( $lport[0] == 'single' && $lport[1] == $port )
                    return TRUE;
                if( $lport[0] == 'range' && $port >= $lport[1] && $port <= $lport[2] )
                    return TRUE;
            }
        }

        return FALSE;
    }

    /**
     * will return a list of dependencies and remove the 'implicit' ones
     * @return App[]
     */
    public function &calculateDependencies()
    {
        $ret = array();

        if( isset($this->explicitUse) )
            $plus = $this->explicitUse;
        else
            $plus = array();

        if( !isset($this->implicitUse) )
            return $plus;

        foreach( $plus as $plusApp )
        {
            $found = FALSE;
            foreach( $this->implicitUse as $implApp )
            {
                if( $implApp === $plusApp )
                {
                    $found = TRUE;
                    break;
                }
            }
            if( !$found )
                $ret[] = $plusApp;
        }

        return $ret;
    }

    public function isApplicationCustom()
    {
        if( $this->type == 'application-custom' )
            return TRUE;

        return FALSE;
    }

    public function isApplicationGroup()
    {
        if( $this->type == 'application-group' )
            return TRUE;

        return FALSE;
    }

    public function isApplicationFilter()
    {
        if( $this->type == 'application-filter' )
            return TRUE;

        return FALSE;
    }

    public function isTmp()
    {
        if( $this->type == 'tmp' )
            return TRUE;

        return FALSE;
    }

    public function isPredefined()
    {
        if( $this->type == 'predefined' )
            return TRUE;

        return FALSE;
    }

    public function type()
    {
        return $this->type;
    }

    public function CustomHasSignature()
    {
        if( $this->isApplicationCustom() )
            if( $this->custom_signature )
                return TRUE;

        return FALSE;
    }

    function print_appdetails( $padding_above, $printName = true, &$subarray = array()  )
    {
        global $print_explicit;
        global $print_implicit;

        $padding = 30;
        $padding_10 = "          ";

        $text = "";
        if( $printName )
        {
            #PH::print_stdout();
            $text .= $padding_above . " - " . str_pad(PH::boldText($this->name()), $padding) . " - ";
        }
        $subarray[$this->name()]['name'] = $this->name();


        if( isset($this->obsolete) )
        {
            $text .= $padding_above . "  - (obsolete) ";
            $subarray[$this->name()]['obsolete'] = "true";
        }

        $app_mapping = array();
        $this->getAppDetails( false, $app_mapping );
        $subarray[$this->name()] = $app_mapping[0];
        $flattened = $app_mapping[0];
        array_walk($flattened, function(&$value, $key) {
            $value = "{$key}=>{$value}";
        });
        if( !empty($flattened) )
            PH::print_stdout( $padding_10 . implode( ", ", $flattened ) );


        $port_mapping_text = array();
        $this->getAppServiceDefault( false, $port_mapping_text, $subarray );
        if( !empty($port_mapping_text) )
            PH::print_stdout( $padding_10 . implode( ", ", $port_mapping_text ) );

        $port_mapping_text = array();
        $this->getAppServiceDefault( true, $port_mapping_text, $subarray );
        if( !empty($port_mapping_text) )
            PH::print_stdout( $padding_10 . implode( ", ", $port_mapping_text ) );


        if( $this->proto != "" )
        {
            PH::print_stdout($padding_10 . "IP-Protocol: '" . $this->proto . "'");
            $subarray[$this->name()]['ipprotocol'] = $this->proto;
        }


        $text = "";
        if( isset($this->timeout) )
        {
            $text .= $padding_10 . "timeout|" . $this->timeout . " - ";
            $subarray[$this->name()]['timeout'] = $this->timeout;
        }

        if( isset($this->tcp_timeout) )
        {
            $text .= $padding_10 . "tcp-timeout|" . $this->tcp_timeout . " - ";
            $subarray[$this->name()]['tcp-timeout'] = $this->tcp_timeout;
        }
        if( isset($this->tcp_half_closed_timeout) )
        {
            $text .= $padding_10 . "tcp-half-closed-timeout|" . $this->tcp_half_closed_timeout . " - ";
            $subarray[$this->name()]['tcp-half-closed-timeout'] = $this->tcp_half_closed_timeout;
        }
        if( isset( $this->tcp_time_wait_timeout ) )
        {
            $text .= $padding_10."tcp-time-wait-timeout|".$this->tcp_time_wait_timeout . " - ";
            $subarray[$this->name()]['tcp-time-wait-timeout'] = $this->tcp_time_wait_timeout;
        }
        if( isset( $this->udp_timeout ) )
        {
            $text .= $padding_10."udp-timeout|".$this->udp_timeout . " - ";
            $subarray[$this->name()]['udp-timeout'] = $this->udp_timeout;
        }

        if( !empty($text))
            PH::print_stdout($text);

        if( isset( $this->explicitUse ) && $print_explicit )
        {
            foreach( $this->explicitUse as $app1 )
            {
                PH::print_stdout( "           explicit->" . $app1->type . " | " );

                $tmparray = array();
                $app1->print_appdetails( $padding_above, true, $tmparray );
                $subarray['implicit'][] = $tmparray;
            }
        }

        if( isset( $this->implicitUse ) && $print_implicit )
        {
            foreach( $this->implicitUse as $app2 )
            {
                PH::print_stdout( "           implicit->" . $app2->type . " | " );

                $tmparray = array();
                $app2->print_appdetails( $padding_above, true, $tmparray );
                $subarray['implicit'][] = $tmparray;
            }
        }

        if( isset( $this->tunnelApp) && count( $this->tunnelApp ) > 0 )
        {
            $tmpString = "";
            foreach( $this->tunnelApp as $tmpapp )
            {
                $tmpString .= $tmpapp->name().", ";
            }
            PH::print_stdout( $padding_above. "tunnelApps: ".$tmpString );
        }

        if( isset( $this->decoder) && count( $this->decoder ) > 0 )
        {
            PH::print_stdout( $padding_above. "decoders: ".implode( "|", $this->decoder) );
        }

        if( isset( $this->icmpsub )  )
        {
            PH::print_stdout( "               icmp type: ". $this->icmpsub );
            $subarray[$this->name()]['icmp'] = $this->icmpsub;
        }
        if( isset( $this->icmp6sub )  )
        {
            PH::print_stdout( "               icmpv6 type: ". $this->icmp6sub );
            $subarray[$this->name()]['icmpv6'] = $this->icmp6sub;
        }
        if( isset( $this->icmpcode )  )
        {
            PH::print_stdout( "               icmp code: ". $this->icmpcode );
            $subarray[$this->name()]['icmpcode'] = $this->icmpcode;
        }
        if( isset( $this->icmp6code )  )
        {
            PH::print_stdout( "               icmpv6 code: ". $this->icmp6code );
            $subarray[$this->name()]['icmpv6code'] = $this->icmp6code;
        }
        /*
            if( isset($app->_characteristics) )
            {
                #PH::print_stdout(  PH::list_to_string($app->_characteristics) );
                print_r( $app->_characteristics );
            }
        */

        if( isset($this->tmp_details) )
        {
            PH::print_stdout( "TMP details: -" );
            print_r( $this->tmp_details );
            derr('check');
        }


        if( $this->type == 'application-group' )
        {
            if( isset( $this->groupapps ) )
            {
                foreach( $this->groupapps as $tmpapp)
                {
                    /** @var App $tmpapp */
                    $tmparray = array();
                    $tmpapp->print_appdetails( $padding_above, true, $tmparray );
                    $subarray['application-group'][] = $tmparray;
                }
            }
        }
    }

    function getAppsRecursive( $app_array = array() )
    {
        if( $this->isApplicationGroup() )
        {
            foreach( $this->groupApps() as $app )
                $app_array = $app->getAppsRecursive( $app_array ) ;
        }
        elseif( $this->isApplicationFilter() )
        {
            foreach( $this->filteredApps() as $app )
                $app_array = $app->getAppsRecursive( $app_array ) ;
        }
        elseif( $this->isContainer() )
        {
            foreach( $this->containerApps() as $app )
                $app_array = $app->getAppsRecursive( $app_array ) ;
        }
        else
            $app_array[ $this->name() ] = $this;

        return $app_array;
    }

    function getAppDetails( $returnString = false, &$app_mapping = array() )
    {
        if( isset( $this->app_filter_details['category']) )
            $string_category = implode( "|", $this->app_filter_details['category'] );
        else
            $string_category = $this->category;

        if( isset($this->app_filter_details['subcategory']) )
            $string_subcategory = implode( "|", $this->app_filter_details['subcategory'] );
        else
            $string_subcategory = $this->subCategory;

        if( isset($this->app_filter_details['technology']) )
            $string_technology = implode( "|", $this->app_filter_details['technology'] );
        else
            $string_technology = $this->technology;

        if( isset($this->app_filter_details['tag']) )
            $string_apptag = implode( "|", $this->app_filter_details['tag'] );
        else
            $string_apptag = implode( "|", $this->apptag);

        if( isset($this->app_filter_details['risk']) )
            $string_risk = implode( "|", $this->app_filter_details['risk'] );
        else
            $string_risk = $this->risk;

        if( isset( $this->_characteristics) )
            $characteristics = $this->_characteristics;
        else
            $characteristics = array();

        $characterisiticArray = array();
        foreach( $characteristics as $key => $characteristic )
        {
            if( $characteristic )
                $characterisiticArray[$key] = $key;
        }
        $string_characteristic = implode( "|", $characterisiticArray );

        if( $returnString )
            $app_mapping[] = $this->name().",".$string_category.",".$string_subcategory.",".$string_technology.",".$string_risk.",".$string_apptag.",".$string_characteristic;
        else
            $app_mapping[] = array( "name" => $this->name(), "category" => $string_category, "subcatecory" => $string_subcategory, "technology" => $string_technology, "risk" => $string_risk, "tag" => $string_apptag, "characteristic" => $string_characteristic );
    }

    function getAppServiceDefault( $secure = false, &$port_mapping_text = array(), &$subarray = array() )
    {
        #$name = ",".$this->name();
        $name = "";

        if( $secure )
            $protocols = array( "tcp_secure", "udp_secure" );
        else
            $protocols = array( "tcp", "udp" );

        foreach( $protocols as $protocol )
        {
            if( isset($this->$protocol) )
            {
                if( $secure )
                {
                    $prot_tmp = explode( "_", $protocol);
                    $protocolTxt = $prot_tmp[1]." - ".$prot_tmp[0]."/";
                }
                else
                    $protocolTxt = $protocol."/";

                $text = $protocolTxt;
                $text = "";
                foreach( $this->$protocol as $port )
                {
                    $any = "0-65535";
                    $dynamic = "1025-65535";
                    if( $port[0] == "single" )
                    {
                        if( $port[1] == 'any' )
                            $port[1] = $any;
                        $port[1] = trim( $port[1] );
                        $tmp = $protocolTxt . $port[1]. $name;
                        $text .= $tmp. ",";
                        if( isset( $port_mapping_text[ $tmp ] ) )
                            $port_mapping_text[ $tmp ] .= ",".$this->name();
                        else
                            $port_mapping_text[ $tmp ] = $tmp.",".$this->name();
                    }
                    elseif( $port[0] == "dynamic" )
                    {
                        $tmp = $protocolTxt . $dynamic . $name;
                        $text .= $tmp. ",";
                        if( isset( $port_mapping_text[ $tmp ] ) )
                            $port_mapping_text[ $tmp ] .= ",".$this->name();
                        else
                            $port_mapping_text[ $tmp ] = $tmp.",".$this->name();
                    }
                    elseif( $port[0] == "range" )
                    {
                        $tmp = $protocolTxt . $port[1] . "-" . $port[2].$name;
                        $text .= $tmp. ",";
                        if( isset( $port_mapping_text[ $tmp ] ) )
                            $port_mapping_text[ $tmp ] .= ",".$this->name();
                        else
                            $port_mapping_text[ $tmp ] = $tmp.",".$this->name();
                    }
                    else
                    {
                        foreach( $port as $portValue )
                        {
                            if( $portValue == 'any' )
                                $portValue = $any;
                            $portValue = trim( $portValue );
                            $tmp = $protocolTxt . $portValue.$name;
                            $text .= $tmp. ",";
                            if( isset( $port_mapping_text[ $tmp ] ) )
                                $port_mapping_text[ $tmp ] .= ",".$this->name();
                            else
                                $port_mapping_text[ $tmp ] = $tmp.",".$this->name();
                        }
                    }
                }
                $subarray[$this->name()][$protocol] = $text;
            }
        }

        /*
        //check if ip-protocol
        if( $this->proto != null)
            //$subarray[$this->name()]['ipprotocol'] = $this->proto;
            $subarray[$this->name()]['tcp'] = $this->proto;

        if($this->icmpcode != null)
            //$subarray[$this->name()]['icmpcode'] = $this->icmpcode;
            $subarray[$this->name()]['tcp'] = $this->icmpcode;
        */
    }
}


