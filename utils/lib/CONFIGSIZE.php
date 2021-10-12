<?php


class CONFIGSIZE extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] [out=]";

        #$this->prepareSupportedArgumentsArray();

        $this->utilInit();

        $this->main();


        $this->endOfScript();
    }

    public function main()
    {
        $file = null;
##########################################
##########################################
        $pad_length = 60;
        if( isset(PH::$args['minkilobyte'])  )
        {
            $minKiloByte = PH::$args['minkilobyte'];
            if( $minKiloByte <= 5 )
                $pad_length = 80;
        }
        else
        {
            $minKiloByte = 1000;
        }
        #$minKiloByte = $minKiloByte*1000;
        PH::print_stdout( " - display only XML content which is greater then: ".$minKiloByte."kB");

        if( isset(PH::$args['padlength'])  )
            $pad_length = PH::$args['padlength'];

        if( isset(PH::$args['showalldg'])  )
            $showalldg = true;
        else
            $showalldg = false;

        $this->load_config();
        $this->location_filter();


        if( $this->configType == 'panos' )
        {
            // Did we find VSYS1 ?
            $v = $this->pan->findVirtualSystem( $this->objectsLocation[0] );
            if( $v === null )
                derr( $this->objectsLocation[0]." was not found ? Exit\n");
        }
        elseif( $this->configType == 'panorama' )
        {
            $v = $this->pan->findDeviceGroup( $this->objectsLocation[0] );
            if( $v == null )
                $v = $this->pan->createDeviceGroup( $this->objectsLocation[0] );
        }
        elseif( $this->configType == 'fawkes' )
        {
            $v = $this->pan->findContainer( $this->objectsLocation[0] );
            if( $v == null )
                $v = $this->pan->createContainer( $this->objectsLocation[0] );
        }


##########################################
//Todo start writing here

        $this->xmlDoc->preserveWhiteSpace = false;
        $this->xmlDoc->formatOutput = true;

        $lineReturn = false;
        $indentingXml = -1;
        $indentingXmlIncreament = 0;

        $xml = &DH::dom_to_xml( $this->xmlDoc );
        $xml_reduced = &DH::dom_to_xml( $this->xmlDoc, $indentingXml, $lineReturn, -1, $indentingXmlIncreament );

        $len_xml = strlen( $xml );
        $len_xml_reduced = strlen( $xml_reduced );
        $len_overhead = $len_xml-$len_xml_reduced;
        $len_overhead_percent = round( ( $len_overhead / $len_xml ) * 100, 0);

#PH::print_stdout( "\nLENGTH str:".$len_xml." [ reduced: ".$len_xml_reduced." | overhead: ".($len_xml-$len_xml_reduced)." ]");





        PH::print_stdout( "LENGTH str:".$len_xml_reduced." [xml overhead: ".($len_overhead)." (".$len_overhead_percent."%) ]");

        $this->print_length( $this->xmlDoc );



##########################################


        $this->save_our_work();

        PH::print_stdout("");

        //Todo: what about API mode - filename is empty
        if( !$this->apiMode )
        {
            $filesize = filesize( $this->configInput['filename'] );

            $reduce_percent = round( ($len_xml_reduced/$filesize)*100 );
            PH::print_stdout( "The size of your original file is ".convert($filesize )." [100%]. It can be reduces to ".convert($len_xml_reduced)." [".$reduce_percent."%] (which is a reduction of ".convert($filesize-$len_xml_reduced)." [".(100-$reduce_percent)."%])");
        }

        PH::print_stdout( PH::boldText( "Please be aware of that PAN-OS is automatically adding the xml overhead again during the next configuration load to the device" ) );

    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
        $this->supportedArguments['minkilobyte'] = Array('niceName' => 'MinKilobyte', 'shortHelp' => 'the amount of kB, where script start displaying XML information');
        $this->supportedArguments['padlength'] = Array('niceName' => 'PadLength', 'shortHelp' => 'this is extending the padding for the middle line');
        $this->supportedArguments['showalldg'] = Array('niceName' => 'ShowAllDG', 'shortHelp' => 'display all DG / template also if size is smaller as MinKiloByte');
    }

    function print_length( $xmlRoot, $depth = -1, $padding = "", $previousNode = "" )
    {
        global $minKiloByte;
        global $pad_length;
        global $util;
        global $showalldg;
        global $lineReturn;
        global $indentingXml;
        global $indentingXmlIncreament;

        $depth++;
        foreach( $xmlRoot->childNodes as $node )
        {
            if ($node->nodeType != XML_ELEMENT_NODE)
                continue;

            $nodeName = $node->nodeName;
            $nodeValue = $node->nodeValue;

            $xml = &DH::dom_to_xml( $node );
            $xml_reduced = &DH::dom_to_xml( $node, $indentingXml, $lineReturn, -1, $indentingXmlIncreament );

            $length2 = strlen( $xml );
            $length2 = round( $length2/1000 );

            $length_reduced = strlen( $xml_reduced );
            $length_reduced = round( $length_reduced/1000 );

            if( $depth <= 1
                || $length2 > $minKiloByte
                || ( ( $previousNode == "device-group" || $previousNode == "template" || $previousNode == "container" ) && $showalldg )
            )
            {
                #PH::print_stdout( "");
                #PH::print_stdout( $padding.$depth."<".$nodeName.">");

                if( $depth > 2 && $depth < 5 )
                    PH::print_stdout( $padding."----------------------------------------------------------------------------------------");


                if( $nodeName == "entry" )
                {
                    $attname = DH::findAttribute('name', $node);
                    $nodeName = $nodeName." name=".$attname;

                    if( $this->configType != 'panos' && $depth == 4 )
                    {
                        if( $this->configType == 'fawkes' )
                            $v = $this->pan->findContainer( $attname );
                        else
                            $v = $this->pan->findDeviceGroup( $attname );
                    }
                }

                $string = str_pad( $padding."<".$nodeName.">", $pad_length);


                $length2_overhead = $length2-$length_reduced;
                $length2_overhead_percent = round( ( $length2_overhead / $length2 ) * 100, 0);
                PH::print_stdout( $string." | " .$padding.str_pad( $length_reduced. "kB [xml overhead:".($length2_overhead)."kB (".$length2_overhead_percent."%)]" , 10, " ", STR_PAD_LEFT));

                if( $depth == 3 )
                    $previousNode = $nodeName;

                $this->print_length( $node, $depth++, str_pad( $padding, strlen($padding)+5 ), $nodeName );
                $depth--;
            }
        }
    }

}