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

class PREDEFINED extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=api://[MGMT-IP-Address] ";


        $this->prepareSupportedArgumentsArray();


        PH::processCliArgs();

        $this->help(PH::$args);

        $this->arg_validation();
        $this->init_arguments();

        $this->main();


        
    }

    public function main()
    {
        #$request = 'type=config&action=get&xpath=%2Fconfig%2Fpredefined';
        $request = 'type=op&cmd=<show><predefined><xpath>%2Fpredefined<%2Fxpath><%2Fpredefined><%2Fshow>';

        try
        {
            $candidateDoc = $this->configInput['connector']->sendSimpleRequest($request);
        } catch(Exception $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
        }

        //make XMLroot for <predefined>
        $response = DH::findFirstElement('response', $candidateDoc);
        if( $response === FALSE )
            derr("<response> was not found", $candidateDoc);

        $result = DH::findFirstElement('result', $response);
        if( $result === FALSE )
            derr("<result> was not found", $response);


        $predefinedRoot = DH::findFirstElement('predefined', $result);
        if( $predefinedRoot === FALSE )
        {
            //Todo: this is for a problem in PAN-OS until it is fixed in 8.1.16, 9.0.10 and 9.1.4, 10.0.1
            $response = DH::findFirstElement('response', $result);
            if( $response === FALSE )
                derr("<response> was not found", $candidateDoc);

            $result = DH::findFirstElement('result', $response);
            if( $result === FALSE )
                derr("<result> was not found", $response);

            $predefinedRoot = DH::findFirstElement('predefined', $result);
            if( $predefinedRoot === FALSE )
                derr("<predefined> was not found", $result);

            //origin
            //derr("<predefined> was not found", $result);
        }



        $xmlDoc = new DomDocument;
        $xmlDoc->appendChild($xmlDoc->importNode($predefinedRoot, TRUE));


################################################################################################


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);
        $exernal_version = $cursor->nodeValue;

        $panc_version = $this->pan->appStore->predefinedStore_appid_version;


        $external_appid = explode("-", $exernal_version);
        $pan_c_appid = explode("-", $panc_version);


        if( intval($pan_c_appid[0]) > intval($external_appid[0]) )
        {
            PH::print_stdout( "\n\n - PAN-OS-PHP has already a newer APP-id version '" . $panc_version . "' installed. Device App-ID version: " . $exernal_version );
        }
        elseif( intval($pan_c_appid[0]) == intval($external_appid[0]) )
        {
            PH::print_stdout( " - same app-id version '" . $panc_version . "' available => do nothing");
        }
        else
        {
            PH::print_stdout( " - PAN-OS-PHP has an old app-id version '" . $panc_version . "' available. Device App-ID version: " . $exernal_version );

            #$predefined_path = __DIR__ . '/../lib/object-classes/predefined.xml';
            $predefined_path = __DIR__ . '/../../lib/object-classes/predefined.xml';

            PH::print_stdout( " *** predefined.xml is saved to '" . $predefined_path . "''" );
            file_put_contents( $predefined_path, $xmlDoc->saveXML());
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['location'] = array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => 'sub1[,sub2]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
    }

}