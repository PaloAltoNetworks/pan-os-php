<?php

trait CPtest
{
    #public $print = TRUE;
    public $objectArray = array();

    //print out all available ARRAY information from JSON
    function print_array($array, $padding)
    {
        global $policyPackages_found;

        if( !is_array($array) )
        {
            print "not an array";
            $array = array();
        }


        $padding .= "    ";
        foreach( $array as $key => $value )
        {
            if( $key == "policyPackages" )
            {
                $policyPackages_found = TRUE;

            }

            elseif( $key == "objects" )
            {
                $this->checkObjects($key, $value, $padding);
                continue;
            }
            elseif( $key == "htmlGatewaysFileName" )
            {
                $this->checkGateway($key, $value, $padding);
                continue;
            }
            elseif( $key == "accessLayers" )
            {
                $this->checkAccessLayer($key, $value, $padding);
                continue;
            }
            elseif( $key == "threatLayers" )
            {

            }
            elseif( $key == "natLayer" )
            {
                $this->checkNatLayer($key, $value, $padding);
                continue;
            }

            $this->print_array2($key, $value, $padding);

        }
    }

    function print_array2($key, $array, $padding)
    {

        if( is_array($array) )
        {
            //only additional information - no print out needed
            #print $padding."[".$key."]\n";

            $this->print_array($array, $padding);
        }

        else
        {
            //only additional information - no print out needed
            #print $padding."[".$key."] => ".$array."\n";

            if( strpos($key, "FileName") !== FALSE )
            {
                //get additional JSON file
                $this->loadJSONfile($key, $array, $padding);
            }
        }
    }

    function jsonERROR()
    {
        switch (json_last_error())
        {
            case JSON_ERROR_NONE:
                echo ' - No errors';
                break;
            case JSON_ERROR_DEPTH:
                echo ' - Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                echo ' - Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                echo ' - Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                echo ' - Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                echo ' - Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                echo ' - Unknown error';
                break;
        }

        echo PHP_EOL;
    }


    function loadJSONfile($key, $array, $padding)
    {

        $tmp_name = explode(".", $array);
        #$tmp_name = rawurlencode( $tmp_name[0] ).".json";
        $tmp_name = $tmp_name[0] . ".json";


        print "load FILE: " . $this->folder_path . $tmp_name . " - KEY: " . $key . " | " . strpos($key, "htmlFileName") . "\n\n";


        $check = file_exists($this->folder_path . $tmp_name);
        if( !$check )
        {
            mwarning("FILE: " . $this->folder_path . $tmp_name . " why is not available\n");
            return null;
        }


        $someJSON = file_get_contents($this->folder_path . $tmp_name);


        # Add the brackets at the end and begining of the file and decode correctly.
        $myRules[] = "[";
        $myRules[] = $someJSON;
        $myRules[] = "]";
        $json = implode("", $myRules);
        $someJSON = $this->anything_to_utf8($json);

        $someArray = json_decode($someJSON, TRUE);
        $this->jsonERROR();

        if( !is_array($someArray) )
            derr("json_decode not working");


        if( strpos($key, "htmlGatewaysFileName") === 0 )
        {
            #
            #$this->print_array( $someArray, $padding );
        }
        elseif( strpos($key, "objects") === 0 )
        {
            #
            #print_r( $someArray );
            $this->print_array($someArray, $padding);

            $this->print_object_array($someArray, $padding);
        }
        elseif( strpos($key, "accessLayers") === 0 )
        {
            #
            $this->print_array($someArray, $padding);

            $this->accesslayer_array($someArray);
        }
        elseif( strpos($key, "natLayer") === 0 )
        {
            #
            $this->print_array($someArray, $padding);

            $this->natlayer_array($someArray);
        }
        else
        {
            print "do nothing for KEY: " . $key . "\n";
        }
    }


    //CHECK parts

    function checkObjects($key, $array, $padding)
    {
        print "\n##################################################\n";
        print PH::boldText("OBJECTS\n");

        if( isset($array['htmlObjectsFileName']) )
        {
            $fileName = $array['htmlObjectsFileName'];
            print $fileName . "\n";


            $this->loadJSONfile($key, $fileName, $padding);
        }
        else
        {
            #print_r( $array );
            #derr( " something not found");
        }

    }

    function checkGateway($key, $array, $padding)
    {
        print "\n##################################################\n";
        print PH::boldText("GATEWAY\n");

        $fileName = $array;
        #print $fileName."\n";

        #print_r( $array );
        $this->loadJSONfile($key, $fileName, $padding);
    }

    function checkAccessLayer($key, $value, $padding)
    {
        print "\n##################################################\n";
        print PH::boldText("ACCESSLayer\n");

        foreach( $value as $subarray )
        {
            $fileName = $subarray['htmlFileName'];
            $domain = $subarray['domain'];

            #print $fileName."\n";

            $this->loadJSONfile($key, $fileName, $padding);
        }


    }

    function checkNatLayer($key, $value, $padding)
    {
        print "\n##################################################\n";
        print PH::boldText("NATLayer\n");
        #print_r( $value );

        if( isset($value['htmlFileName']) )
        {
            $fileName = $value['htmlFileName'];
            #print $fileName."\n";

            $this->loadJSONfile($key, $fileName, $padding);
        }
    }

    function check_vsys( $domain, $type = 'object' )
    {
        /** @var PANConf|PanoramaConf $pan */
        $vsysID = 1;
        $vsysName = 'vsys';


        if( ($domain == "Global" || $domain == "Check Point Data") && $type == 'object' )
        {
            $this->sub = $this->pan;
        }
        else
        {

            $this->template_vsys = $this->template->findVSYS_by_displayName($domain);
            if( $this->template_vsys !== null )
            {
                #print "VSYS: ".$vsysID." already available - check displayName ".$vsysName."\n";
                #$this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
                #$this->template_vsys->setAlternativeName($domain);
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
                    $this->template_vsys->setAlternativeName($domain);

                    if( $this->template_vsys === null )
                    {
                        derr("vsys" . $vsysID . " could not be created ? Exit\n");
                    }
                    print "create VSYS: " . $this->template_vsys->name() . " - " . $this->template_vsys->alternativeName() . "\n";
                }
            }

            if( $this->configType == "panos" )
            {
                $this->sub = $this->template_vsys;
            }
            else
            {
                if( $this->objectsLocationCounter == 0 )
                {
                    $this->sub = $this->pan->findDeviceGroup($domain);
                    $this->objectsLocationCounter++;
                }
                else
                {
                    $this->sub = $this->pan->findDeviceGroup($domain);
                    if( $this->sub == null )
                    {
                        $this->sub = $this->pan->createDeviceGroup($domain);
                        $this->objectsLocationCounter++;
                    }

                }
            }
        }
    }

}




