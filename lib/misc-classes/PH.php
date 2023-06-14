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

class PH
{
    function __construct($argv, $argc)
    {
        //print "FIRST\n";
        //print_r( $argv );

        PH::$argv = $argv;

        foreach( PH::$argv as $argIndex => $arg )
        {
            $arg = strtolower($arg);
            if( $arg == 'shadow-disableoutputformatting' )
            {
                PH::disableOutputFormatting();
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-enablexmlduplicatesdeletion' )
            {
                PH::$enableXmlDuplicatesDeletion = TRUE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-ignoreinvalidaddressobjects' )
            {
                PH::$ignoreInvalidAddressObjects = TRUE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-apikeynohidden' )
            {
                PH::$sendAPIkeyviaHeader = FALSE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-apikeyhidden' )
            {
                PH::$sendAPIkeyviaHeader = TRUE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-apikeynosave' )
            {
                PH::$saveAPIkey = FALSE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-displaycurlrequest' )
            {
                PH::$displayCurlRequest = TRUE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-reducexml' )
            {
                PH::$shadow_reducexml = TRUE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-json' )
            {
                PH::disableOutputFormatting();
                PH::$shadow_json = TRUE;
                PH::$PANC_WARN = FALSE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-nojson' )
            {
                PH::disableOutputFormatting();
                PH::$shadow_json = FALSE;
                PH::$PANC_WARN = FALSE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
            elseif( $arg == 'shadow-displayxmlnode' )
            {
                PH::$shadow_displayxmlnode = TRUE;
                unset(PH::$argv[$argIndex]);
                if( !isset( $_SERVER['REQUEST_METHOD'] ) )
                    $argc--;
                continue;
            }
        }
        unset($argIndex);
        unset($arg);
    }

    public static $UseDomXML = TRUE;

    /**
     * @var null|mixed[]
     */
    public static $args = array();

    public static $argv = array();

    public static $ignoreDestructors = FALSE;

    public static $useExceptions = FALSE;
    public static $doNotDisableExceptions = FALSE;

    public static $outputFormattingEnabled = TRUE;

    public static $enableXmlDuplicatesDeletion = FALSE;

    /** @var bool set to true if you want to ignore invalid address objects but print a warning instead */
    public static $ignoreInvalidAddressObjects = FALSE;

    /** @var bool set to true if you want to send API key via HEADER - possible starting with PAN-OS 9.0 */
    public static $sendAPIkeyviaHeader = FALSE;

    public static $saveAPIkey = TRUE;

    public static $displayCurlRequest = FALSE;

    public static $shadow_reducexml = FALSE;

    public static $shadow_json = FALSE;

    public static $shadow_displayxmlnode = FALSE;

    public static $JSON_OUT = array();
    public static $JSON_TMP = array();
    public static $JSON_OUTlog = "";

    public static $PANC_WARN = TRUE;

    public static $basedir;

    private static $library_version_major = 2;
    private static $library_version_sub = 1;
    private static $library_version_bugfix = 9;

    //BASIC AUTH PAN-OS 7.1
    public static $softwareupdate_key = "658d787f293e631196dac9fb29490f1cc1bb3827";
    public static $softwareupdate_user_encrypt = "NmPyrGw7WYXdu5cdgm2x7HEkDf4LTHob7M/JNNhS+3CIfV5DkV7Tne8xersHIRafbXV3vzgIRECsG06Hs+O80g==";
    public static $softwareupdate_pw_encrypt = "wbCEjb8jaYH36HHvB2PmLMNyaz27MvHgM+Bn64wnofCjrV/4G+25AkoqG+q41Cvigc9uUxBTbOUtW2EhQOPYjA==";

    //DIGEST AUTH
    public static $update_key_digest = "0e05fc22c2a11cdc50196ae8aa09cb38f7c0b5fe";
    public static $update_user_encrypt_digest = "MTJcbc7pFOrFs+rZ9uCISFxtT4dPA2dPy1HfRl7AE+yxsCc8n3Z/jvJNIVzXxZRQGGOtYxc0FarqLkPAd/O7q+JXHrcTr7L1kuubmJSRqQs=";
    public static $update_pw_encrypt_digest = "Ih+mfx64Mt4m7JX7xnMsCBE8lqfQynTKtiySA9nRD4ndViEOKFOIDemoT0LpTLfaAQWjEpPCU248KApeIUtmDvS3c7KVRyKC0qWXRNQ1Vmc=";

    public static $license_key_digest = "0b38638ba85f97482953570bec1f7e41fff7c533";
    public static $license_user_encrypt_digest = "6gtYixyTgBf/lBfxPzor8hqI8cmrvtn06UskXAb5EWBhQHuJm7/0J9WfZbH8lk3AAWnUhpaG/NWlGdDevT5PMKPSQUawo4V2Tl8IbNB2Nnw=";
    public static $license_pw_encrypt__digest = "hdRb8p8a8vKDpuhdfDnDkDWaZRUthNCE0EDqZSBx2mNy+gqakPa74GJJAINJfC+HCZqtYs0ut/uxs1nOAcEXQlRqppEXuy+s1MNoMULt4DM=";


    static public function decrypt($ciphertext, $key)
    {
        $c = base64_decode($ciphertext);
        $ivlen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len = 32);
        $ciphertext_raw = substr($c, $ivlen + $sha2len);
        $ciphertext_2 = openssl_decrypt($ciphertext_raw, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv);
        $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary = TRUE);

        return array($ciphertext_2, $calcmac);
    }

    static public function frameworkVersion()
    {
        return self::$library_version_major . '.' . self::$library_version_sub . '.' . self::$library_version_bugfix;
    }

    static public function frameworkInstalledOS()
    {
        $system = 'UNIX';
        if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
            $system = 'WIN';
        return $system;
    }

    /**
     * @param string $versionString ie: '1.2.3' or '1.5'
     * @return bool
     */
    static public function frameworkVersion_isGreaterThan($versionString)
    {
        $numbers = explode('.', $versionString);

        if( count($numbers) < 2 || count($numbers) > 3 )
            derr("'{$versionString}' is not a valid version syntax ( 'X.Y' or 'X.Y.Z' is accepted)");

        if( !is_numeric($numbers[0]) )
            derr("'{$numbers[0]}' is not a valid integer");

        if( !is_numeric($numbers[1]) )
            derr("'{$numbers[1]}' is not a valid integer");

        if( count($numbers) == 3 && !is_numeric($numbers[2]) )
            derr("'{$numbers[2]}' is not a valid integer");


        if( self::$library_version_major > intval($numbers[0]) )
            return TRUE;

        $frameWorkValue = self::$library_version_major * 1000 * 1000;
        $localValue = intval($numbers[0]) * 1000 * 1000;

        $frameWorkValue += self::$library_version_sub * 1000;
        $localValue += intval($numbers[1]) * 1000;

        $frameWorkValue += self::$library_version_bugfix;

        if( count($numbers) == 3 )
        {
            $localValue += intval($numbers[2]);
        }

        return $frameWorkValue > $localValue;
    }

    /**
     * @param string $versionString ie: '1.2.3' or '1.5'
     * @return bool
     */
    static public function frameworkVersion_isGreaterOrEqualThan($versionString)
    {
        $numbers = explode('.', $versionString);

        if( count($numbers) < 2 || count($numbers) > 3 )
            derr("'{$versionString}' is not a valid version syntax ( 'X.Y' or 'X.Y.Z' is accepted)");

        if( !is_numeric($numbers[0]) )
            derr("'{$numbers[0]}' is not a valid integer");

        if( !is_numeric($numbers[1]) )
            derr("'{$numbers[1]}' is not a valid integer");

        if( count($numbers) == 3 && !is_numeric($numbers[2]) )
            derr("'{$numbers[2]}' is not a valid integer");


        if( self::$library_version_major > intval($numbers[0]) )
            return TRUE;

        $frameWorkValue = self::$library_version_major * 1000 * 1000;
        $localValue = intval($numbers[0]) * 1000 * 1000;

        $frameWorkValue += self::$library_version_sub * 1000;
        $localValue += intval($numbers[1]) * 1000;

        $frameWorkValue += self::$library_version_bugfix;

        if( count($numbers) == 3 )
        {
            $localValue += intval($numbers[2]);
        }

        return $frameWorkValue >= $localValue;
    }


    /**
     * will throw Exceptions instead of print errors (useful for web embeded or scrips that want
     * to support errors handling without quiting.
     */
    static public function enableExceptionSupport()
    {
        PH::$doNotDisableExceptions = FALSE;
        if( PH::$useExceptions )
            PH::$doNotDisableExceptions = TRUE;

        PH::$useExceptions = TRUE;
    }

    static public function disableExceptionSupport()
    {
        if( !PH::$doNotDisableExceptions )
            PH::$useExceptions = FALSE;
    }


    static public function enableOutputFormatting()
    {
        PH::$outputFormattingEnabled = TRUE;
    }

    static public function disableOutputFormatting()
    {
        PH::$outputFormattingEnabled = FALSE;
    }

    public static function processCliArgs()
    {
        //print "SECOND\n";
        //print_r( PH::$argv );

        $first = TRUE;

        foreach( PH::$argv as &$arg )
        {
            if( $first )
            {
                $first = FALSE;
                continue;
            }
            $nameExplode = explode('=', $arg, 2);
            if( count($nameExplode) != 2 )
                $value = TRUE;
            else
                $value = $nameExplode[1];

            $nameExplode[0] = strtolower($nameExplode[0]);
            $nameExplode[0] = preg_replace('#^-#m', '', $nameExplode[0]);

            if( isset(PH::$args[$nameExplode[0]]) )
                derr("argument '" . $nameExplode[0] . "' was input twice in command line", null, false);

            PH::$args[$nameExplode[0]] = $value;
        }

        //print "THIRD\n";
        //print_r(PH::$args);
    }

    public static function resetCliArgs( $arguments )
    {
        $argv = $arguments;
        PH::$args = array();
        PH::$argv = array();

        PH::$argv = $argv;

        //print_r( $argv );
    }

    public static function generate_arguments($in = "", $out = "", $location = "", $actions = "", $filter = "", $subquery = "", $additional = "")
    {
        $i = 0;
        $argv_array = array();
        $argv_array[0] = "-";

        if( $in != "" )
        {
            $i++;
            $argv_array[$i] = "in=" . $in;
        }
        if( $out != "" )
        {
            $i++;
            $argv_array[$i] = "out=" . $out;
        }
        if( $location != "" )
        {
            $i++;
            $argv_array[$i] = "location=" . $location;
        }
        if( $actions != "" )
        {
            $i++;
            $argv_array[$i] = "actions=" . $actions;
        }
        if( $filter != "" )
        {
            $i++;
            $argv_array[$i] = "filter=" . $filter;
        }
        if( $subquery != "" )
        {
            $i++;
            $argv_array[$i] = "subquery=" . $subquery;
        }
        if( $additional != "" )
        {
            $tmp_args = explode(",", $additional);
            foreach( $tmp_args as $tmp_arg )
            {
                $i++;
                $argv_array[$i] = $tmp_arg;
            }

        }


        return $argv_array;
    }


    /**
     * @param $str
     * @param bool $checkFileExists
     * @return string[]
     */
    public static function &processIOMethod($str, $checkFileExists)
    {
        $ret = array('status' => 'fail');
        $ret['filename'] = null;

        $pos_sase = strpos($str, 'sase-api://');
        $pos = strpos($str, 'api://');
        if( $pos !== FALSE )
        {
            if( $pos_sase !== FALSE )
            {
                PanAPIConnector::loadConnectorsFromUserHome();
                $host = substr($str, strlen('sase-api://'));

                $connector = PanAPIConnector::findOrCreateConnectorFromHost("tsg_id".$host);
                #$connector->setType($connector->info_deviceType);
            }
            else
            {
                PanAPIConnector::loadConnectorsFromUserHome();
                $host = substr($str, strlen('api://'));
                $hostExplode = explode('@', $host);
                if( count($hostExplode) == 1 )
                {
                    $fileExplode = explode('/', $host);
                    if( count($fileExplode) == 2 )
                    {
                        $ret['filename'] = $fileExplode[1];
                        $host = $fileExplode[0];
                    }
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($host);
                    $connector->setType($connector->info_deviceType);
                }
                else
                {
                    $fileExplode = explode('/', $hostExplode[1]);
                    if( count($fileExplode) == 2 )
                    {
                        $ret['filename'] = $fileExplode[1];
                        $hostExplode[1] = $fileExplode[0];
                    }

                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($hostExplode[1]);
                    $connector->setType('panos-via-panorama', $hostExplode[0]);
                }


                $ret['status'] = 'ok';
                $ret['type'] = 'api';
                $ret['connector'] = $connector;
            }
        }
        else
        {
            //assuming it's a file
            if( $checkFileExists && !file_exists($str) )
            {
                $ret['msg'] = 'file "' . $str . '" does not exist';
                return $ret;
            }
            $ret['status'] = 'ok';
            $ret['type'] = 'file';
            $ret['filename'] = $str;
        }

        return $ret;

    }

    /**
     * @param string $text
     * @return int
     */
    static public function versionFromString($text)
    {
        if( $text === null )
            derr('null is not supported');

        if( !is_string($text) )
            derr('only string is supported as input');


        $explode = explode('.', $text);
        if( count($explode) != 3 )
            derr('unsupported versioning: ' . $text);

        $ret = $explode[0] * 10 + $explode[1];

        return $ret;
    }

    /**
     * @param string|ReferenceableObject[] $array
     * @return string
     */
    static public function list_to_string(&$array, $separator = ', ')
    {
        $ret = '';
        $first = TRUE;

        foreach( $array as &$el )
        {
            if( $first )
            {
                $first = FALSE;
                if( is_string($el) )
                    $ret .= $el;
                else
                    $ret .= $el->name();
            }
            else
            {
                if( is_string($el) )
                    $ret .= $separator . $el;
                else
                    $ret .= $separator . $el->name();
            }

        }

        return $ret;

    }

    static public function print_stdout( $text = "", $printArray = false, $arrayKey = null  )
    {
        if( is_array( $text ) )
        {
            if( PH::$shadow_json )
            {
                /*
                reset($text);
                $first_key = key($text);

                PH::$JSON_OUT[ $first_key ] = $text[ $first_key ];
                */

                if( $arrayKey != null )
                {
                    PH::$JSON_OUT[$arrayKey][] = $text;
                }
                else
                {
                    //FAWKES???
                    //at least rule-stats
                    PH::$JSON_OUT[] = $text;
                }
            }

            if( $printArray )
            {
                // until now only for pa_rule-stats
                #$stdoutarray = reset($text);
                $stdoutarray = $text;

                if( isset( $stdoutarray['header'] ) )
                    $string =  $stdoutarray['header']."\n";
                else
                    $string = "";

                if( !PH::$shadow_json )
                {
                    print $string;
                }
                else
                {
                    #PH::$JSON_OUTlog .= $string;
                }

                unset( $stdoutarray['header'] );
                foreach( $stdoutarray as $key => $entry )
                {
                    if( is_array( $entry ) )
                    {
                        $tmp_entry2 = "";
                        $tmp_key2 = "";
                        $i = 0;
                        foreach( $entry as $key2 => $entry2 )
                        {
                            if( $i == 0 )
                            {
                                if( !is_array($entry2) )
                                {
                                    $tmp_entry2 = $entry2;
                                    $tmp_key2 = $key2;
                                }
                            }
                            else
                            {
                                if( !is_array($entry2) )
                                {
                                    $tmp_entry2 .= "/".$entry2;
                                    $tmp_key2 .= "/".$key2;
                                }

                            }
                            $i++;
                        }
                        $string =  " - ".$tmp_entry2." ".$tmp_key2." - ".$key."\n";
                        if( !PH::$shadow_json )
                        {
                            print $string;
                        }
                        else
                        {
                            #PH::$JSON_OUTlog .= $string;
                        }
                    }
                    else
                    {
                        $string =  " - " . $entry . " ". $key . "\n";
                        if( !PH::$shadow_json )
                        {
                            print $string;
                        }
                        else
                        {
                            #PH::$JSON_OUTlog .= $string;
                        }
                    }
                }
                $string =  "\n";
                if( !PH::$shadow_json )
                {
                    print $string;
                }
                else
                {
                    #PH::$JSON_OUTlog .= $string;
                }
            }
        }
        else
        {
            $string = $text."\n";
            if( !PH::$shadow_json )
                print $string;
            else
                PH::$JSON_OUTlog .= $string;

        }

    }

    static public function ACTIONstatus( $context, $status, $string )
    {
        PH::print_stdout( $context->padding . " *** ".$status." : ".$string );
        PH::$JSON_TMP['sub']['object'][$context->object->name()]['status']['type'] = $status;
        PH::$JSON_TMP['sub']['object'][$context->object->name()]['status']['message'] = $string;
    }

    static public function ACTIONlog( $context, $string )
    {
        PH::print_stdout( $context->padding . " * ". $string );
        if( $context->object !== null )
            PH::$JSON_TMP['sub']['object'][$context->object->name()]['log'][] = $string;
    }

    static public function &boldText($msg)
    {
        $term = getenv('TERM');

        if( $term === FALSE || strpos($term, 'xterm') === FALSE || !PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[1m" . $msg . "\033[0m";

        return $msg;
    }

    static public function &underlineText($msg)
    {
        $term = getenv('TERM');

        if( $term === FALSE || strpos($term, 'xterm') === FALSE || !PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[4m" . $msg . "\033[0m";

        return $msg;
    }

    static public function &italicText($msg)
    {
        $term = getenv('TERM');

        if( $term === FALSE || strpos($term, 'xterm') === FALSE || !PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[3m" . $msg . "\033[0m";

        return $msg;
    }

    static public function &strikethroughText($msg)
    {
        $term = getenv('TERM');

        if( $term === FALSE || strpos($term, 'xterm') === FALSE || !PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[9m" . $msg . "\033[0m";

        return $msg;
    }

    static public function &coloredText($msg, $foreground_color = 'red', $background_color = 'grey')
    {
        $term = getenv('TERM');

        $color_array = array("black" => "\033[30m",
            "red" => "\033[31m",
            "green" => "\033[32m",
            "yellow" => "\033[33m",
            "blue" => "\033[34m",
            "magenta" => "\033[35m",
            "cyan" => "\033[36m",
            "white" => "\033[37m",
            "grey" => "\033[47m"
        );

        if( $term === FALSE || strpos($term, 'xterm') === FALSE || !PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = $color_array[$foreground_color] . $color_array[$background_color] . $msg . "\033[0m";

        return $msg;
    }


    /**
     * @param $panConfObject
     * @return PANConf|PanoramaConf
     * @throws Exception
     */
    public static function findRootObjectOrDie($panConfObject)
    {
        while( TRUE )
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' )
                return $panConfObject;

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                break;

        }

        derr("cannot find PanoramaConf or PANConf object");
    }

    /**
     * @param $panConfObject
     * @return PANConf|PanoramaConf|DeviceGroup|VirtualSystem|FawkesConf|Container
     * @throws Exception
     */
    public static function findLocationObjectOrDie($panConfObject)
    {
        while( TRUE )
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' || $class == 'DeviceGroup' || $class == 'VirtualSystem' )
                return $panConfObject;

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                break;

        }

        derr("cannot find PanoramaConf or PANConf object");
    }

    /**
     * @param $panConfObject
     * @return PANConf|PanoramaConf|DeviceGroup|VirtualSystem|FawkesConf|Container
     * @throws Exception
     */
    public static function findLocationObject($panConfObject)
    {
        while( TRUE )
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' || $class == 'DeviceGroup' || $class == 'VirtualSystem' )
                return $panConfObject;

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                return null;

        }
    }

    /**
     * @param PathableName $panConfObject
     * @return string
     * @throws Exception
     */
    public static function getLocationString($panConfObject)
    {
        /** @var PANConf|PanoramaConf|DeviceGroup|VirtualSystem|FawkesConf|Container $panConfObject */
        while( TRUE )
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' )
                return 'shared';
            if( $class == 'DeviceGroup' || $class == 'VirtualSystem' )
                return $panConfObject->name();

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                return FALSE;

        }
    }

    /**
     * @param string $filename
     * @return PANConf|PanoramaConf
     */
    public static function getPanObjectFromConf($filename)
    {
        if( !file_exists($filename) )
            derr("cannot find file '{$filename}'");

        $doc = new DOMDocument();

        if( $doc->load($filename, XML_PARSE_BIG_LINES) !== TRUE )
            derr('Invalid XML file found');

        $xpathResults = DH::findXPath('/config/panorama', $doc);

        $panObject = null;

        if( $xpathResults->length > 0 )
            $panObject = new PanoramaConf();
        else
            $panObject = new PANConf();

        $panObject->load_from_domxml($doc);

        return $panObject;
    }

    public static function getFilesInFolder( $folder )
    {
        $files = scandir($folder);
        foreach( $files as $key => $file )
        {
            $path = realpath($folder . DIRECTORY_SEPARATOR . $file);
            if( is_dir($path) || strpos($file, ".") === 0 )
            {
                unset( $files[$key] );
            }
        }
        PH::print_stdout( "'".$folder."' with files: ".(count($files)) );

        return $files;
    }

    public static function UTILdeprecated( $type, $argv, $argc, $PHP_FILE)
    {
        $TESTargv = $argv;
        unset( $TESTargv[0] );
        $argString = " type=".$type." '".implode( "' '", $TESTargv)."'";

        mwarning( 'this script '.basename($PHP_FILE).' is deprecated, please use: pan-os-php.php', null, FALSE );
        PH::print_stdout( PH::boldText("pan-os-php".$argString) );

        PH::print_stdout( PH::boldText("sleeping now 600 seconds") );
        #sleep(600);

        PH::callPANOSPHP( $type, $argv, $argc, $PHP_FILE );

    }

    public static $supportedUTILTypes = array(
        "stats",
        "address", "service", "tag", "schedule", "application", "threat",
        "rule",
        "device", "securityprofile", "securityprofilegroup",
        "zone",  "interface", "virtualwire", "routing", "dhcp", "certificate",
        "key-manager",
        "address-merger", "addressgroup-merger",
        "service-merger", "servicegroup-merger",
        "tag-merger",
        "rule-merger",
        "override-finder",
        "diff",
        "upload",
        "xml-issue",
        "appid-enabler",
        "config-size",
        "download-predefined",
        "register-ip-mgr",
        "userid-mgr",
        "xml-op-json",
        "bpa-generator",
        "playbook",
        "ironskillet-update",
        "maxmind-update",
        "util_get-action-filter",
        "software-remove",
        "traffic-log",
        "system-log",
        "gratuitous-arp",
        "software-download",
        "software-preparation",
        "license",
        "config-download-all",
        "spiffy",
        "config-commit",
        "protocoll-number-download",
        "html-merger",
        "tsf",
        "xpath",
        "certificate",
        "ssh-connector",
        "custom-report",
        "gcp",
        "vendor-migration",
        "appid-toolbox",
        "rule-compare"
        );


    public static $in_exclude = array(
        'ironskillet-update',
        "maxmind-update",
        "util_get-action-filter",
        "protocoll-number-download",
        "gcp"
    );

    public static $out_exclude = array(
        'stats',
        'download-predefined',
        'config-size',
        "xml-op-json",
        "bpa-generator",
        "ironskillet-update",
        "maxmind-update",
        "util_get-action-filter",
        "software-remove",
        "software-download",
        "software-preparation",
        "license",
        "config-download-all",
        "spiffy",
        'config-commit',
        "protocoll-number-download",
        "html-merger",
        "tsf",
        "xpath",
        "gcp"
    );

    public static function callPANOSPHP( $type, $argv, $argc, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "", $projectfolder = "" )
    {
        if( $type == "rule" )
            $util = new RULEUTIL($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "stats" )
            $util = new STATSUTIL( $type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "securityprofile" )
            $util = new SECURITYPROFILEUTIL($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "zone"
            || $type == "interface"
            || $type == "routing"
            || $type == "virtualwire"
            || $type == "dhcp"
            || $type == "certificate"
        )
            $util = new NETWORKUTIL($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "device" )
            $util = new DEVICEUTIL($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "key-manager" )
            $util = new KEYMANGER($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "address-merger"
            || $type == "addressgroup-merger"
            || $type == "service-merger"
            || $type == "servicegroup-merger"
            || $type == "tag-merger"
        )
            $util = new MERGER($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "rule-merger" )
            $util = new RULEMERGER($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "override-finder" )
            $util = new OVERRIDEFINDER($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);
        elseif( $type == "diff" )
            $util = new DIFF($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);
        elseif( $type == "upload" )
            $util = new UPLOAD($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);
        elseif( $type == "xml-issue" )
            $util = new XMLISSUE($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "appid-enabler" )
            $util = new APPIDENABLER($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);
        elseif( $type == "config-size" )
            $util = new CONFIGSIZE($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "download-predefined" )
            $util = new PREDEFINED($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "register-ip-mgr" )
            $util = new REGISTERIP($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "userid-mgr" )
            $util = new USERIDMGR($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "xml-op-json" )
            $util = new XMLOPJSON($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "bpa-generator" )
            $util = new BPAGENERATOR($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "playbook" )
            $util = new PLAYBOOK__( $argv, $argc );

        elseif( $type == "util_get-action-filter" )
            $util = new UTIL_GET_ACTION_FILTER( $argv, $argc );

        elseif( $type == "ironskillet-update" )
            $util = new IRONSKILLET_UPDATE__( );

        elseif( $type == "maxmind-update" )
            $util = new MAXMIND__( );

        elseif( $type == "protocoll-number-download" )
            $util = new PROTOCOLL_NUMBERS__( );

        elseif( $type == "software-remove" )
            $util = new SOFTWAREREMOVE($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "traffic-log" )
            $util = new TRAFFICLOG($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "system-log" )
            $util = new SYSTEMLOG($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "custom-report" )
            $util = new CUSTOMREPORT($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "gratuitous-arp" )
            $util = new GARPSEND($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "software-download" )
            $util = new SOFTWARE_DOWNLOAD($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "software-preparation" )
            #$util = new SOFTWARE_PREPARATION__($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);
            $util = new SOFTWARE_PREPARATION__( $argv, $argc );

        elseif( $type == "license" )
            #$util = new SOFTWARE_PREPARATION__($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);
            $util = new LICENSE__( $argv, $argc );

        elseif( $type == "config-download-all" )
            $util = new CONFIG_DOWNLOAD_ALL__($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "spiffy" )
            $util = new SPIFFY__( $argv, $argc );

        elseif( $type == "config-commit" )
            $util = new CONFIG_COMMIT__( $type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "html-merger" )
            $util = new HTMLmerger__( $argv, $argc);

        elseif( $type == "tsf" )
            $util = new TSF__( $argv, $argc);

        elseif( $type == "xpath" )
            $util = new XPATH($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "ssh-connector" )
            $util = new SSH_CONNECTOR__( $type, $argv, $argc, $PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "gcp" )
            $util = new GCP($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == 'address'
            || $type == 'service'
            || $type == 'tag'
            || $type == 'schedule'
            || $type == 'securityprofilegroup'
            || $type == 'application'
            || $type == 'threat'
        )
            $util = new UTIL($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "vendor-migration" )
            $util = new CONVERTER($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "appid-toolbox" )
            $util = new AppIDToolbox($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        elseif( $type == "rule-compare" )
            $util = new RULE_COMPARE($type, $argv, $argc,$PHP_FILE." type=".$type, $_supportedArguments, $_usageMsg, $projectfolder);

        $util->endOfScript();

        return $util;
    }

    public static function find_string_between($line, $needle1, $needle2 = "--END--")
    {
        $needle_length = strlen($needle1);
        $pos1 = strpos($line, $needle1);

        if( $needle2 !== "--END--" )
            $pos2 = strpos($line, $needle2);
        else
            $pos2 = strlen($line);

        $finding = substr($line, $pos1 + $needle_length, $pos2 - ($pos1 + $needle_length));

        return $finding;
    }
}