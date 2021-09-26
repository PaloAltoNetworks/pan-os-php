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

class PH
{
    function __construct($argv, $argc)
    {
        #print "FIRST\n";
        #print_r( $argv );

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
                PH::$shadow_json = TRUE;
                PH::$PANC_WARN = FALSE;
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

    public static $outputFormattingEnabled = TRUE;

    public static $enableXmlDuplicatesDeletion = FALSE;

    /** @var bool set to true if you want to ignore invalid address objects but print a warning instead */
    public static $ignoreInvalidAddressObjects = FALSE;

    /** @var bool set to true if you want to send API key via HEADER - possible starting with PAN-OS 9.0 */
    public static $sendAPIkeyviaHeader = TRUE;

    public static $saveAPIkey = TRUE;

    public static $displayCurlRequest = FALSE;

    public static $shadow_reducexml = FALSE;

    public static $shadow_json = FALSE;
    public static $JSON_OUT = array();
    public static $JSON_OUTlog = "";

    public static $PANC_WARN = TRUE;

    public static $basedir;

    private static $library_version_major = 2;
    private static $library_version_sub = 0;
    private static $library_version_bugfix = 12;

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
        $system = 'UNIX';
        if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
            $system = 'WIN';
        return self::$library_version_major . '.' . self::$library_version_sub . '.' . self::$library_version_bugfix . ' ['.$system.']';
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
        PH::$useExceptions = TRUE;
    }

    static public function disableExceptionSupport()
    {
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
        #print "SECOND\n";
        #print_r( PH::$argv );

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
                derr("argument '" . $nameExplode[0] . "' was input twice in command line");

            PH::$args[$nameExplode[0]] = $value;
        }

        #print "THIRD\n";
        #print_r(PH::$args);
    }

    public static function resetCliArgs( $arguments )
    {
        $argv = $arguments;
        PH::$args = array();
        PH::$argv = array();

        PH::$argv = $argv;

        #print_r( $argv );
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

        $pos = strpos($str, 'api://');
        if( $pos !== FALSE )
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

    static public function print_stdout( $text  )
    {
        if( is_array( $text ) )
        {
            if( PH::$shadow_json )
            {
                PH::$JSON_OUT[] = $text;
            }

            #else{

                #$stdoutarray = reset($text);
                $stdoutarray = $text;

                $string =  $stdoutarray['header']."\n";
                if( !PH::$shadow_json )
                    print $string;
                else
                    PH::$JSON_OUTlog .= $string;
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
                                $tmp_entry2 = $entry2;
                                $tmp_key2 = $key2;
                            }
                            else
                            {
                                $tmp_entry2 .= "/".$entry2;
                                $tmp_key2 .= "/".$key2;
                            }
                            $i++;
                        }
                        $string =  "- ".$tmp_entry2." ".$tmp_key2." - ".$key."\n";
                        if( !PH::$shadow_json )
                            print $string;
                        else
                            PH::$JSON_OUTlog .= $string;
                    }
                    else
                    {
                        $string =  "- " . $entry . " ". $key . "\n";
                        if( !PH::$shadow_json )
                            print $string;
                        else
                            PH::$JSON_OUTlog .= $string;
                    }
                }
                $string =  "\n";
                if( !PH::$shadow_json )
                    print $string;
                else
                    PH::$JSON_OUTlog .= $string;
            #}
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

}