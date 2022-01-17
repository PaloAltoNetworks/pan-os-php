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

class SPIFFY__
{
    public $utilType = null;

    function __construct( $argv, $argc )
    {
        $file = null;

        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] file=[csv_text file] [out=]";

        $this->main( $argv, $argc );
    }


    public function main( $argv, $argc )
    {
        $m_array = preg_grep('/^in=*/', $argv);
        if( !isset( $m_array[1] ) )
        {
            derr( "argument 'in=' not found.", null, false  );
        }

        $filename = str_replace( "in=", "", $m_array[1]);

        $newdoc = new DOMDocument;
        $newdoc->load( $filename );
        $cursor = DH::findXPathSingleEntryOrDie('/spiffy-cfg', $newdoc);
        $cursor = DH::findFirstElement('config', $cursor);



        $newdoc = new DOMDocument;
        $node = $newdoc->importNode($cursor, true);
        $newdoc->appendChild($node);
        $fileString = $newdoc->saveXML();
        $filename = "/tmp/spiffy_tmp.xml";
        file_put_contents( $filename, $fileString);


        $argv = array();
        $argv[] = "spiffy.php";
        $argv[] = "in=".$filename;
        $argv[] = "location=any";
        $argv[] = "actions=display:ResolveAddressSummary|ResolveServiceSummary|ResolveApplicationSummary";
        $argv[] = "shadow-json";
        $argv[] = "shadow-ignoreInvalidAddressObjects";


        $util = new RULEUTIL( "rule", $argv, $argc, __FILE__ );

    }
}







