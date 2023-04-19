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

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../pan-os-php/lib/pan_php_framework.php";

PH::print_stdout( "***********************************************" );
PH::print_stdout(  "************ XML error attribute finder ****************" );


PH::processCliArgs();


if( isset(PH::$args['in']) )
{
    $configInput = PH::$args['in'];
}

if( isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
}

if( isset(PH::$args['action']) )
{
    $action = PH::$args['action'];
}
else
{
    $action = 'display';
}

if( $action != "display" && $action != "remove" )
{
    derr("action argument support only: action=display or action=delete");
}
elseif( $action == "remove" && !isset($configOutput) )
{
    derr("action=remove argument is used but no argument 'out=[filename]' is set");
}

$padding = "     ";
$padding_name = substr($padding, 0, -1);

$xmlDoc = new DOMDocument;
$xmlDoc->load($configInput);


/**
 * @param DOMNode $node
 * @param int $indenting
 * @param bool $lineReturn
 * @param int $limitSubLevels
 * @return string
 */
function &dom_to_xml_removeATT(DOMNode $node, $nodeName = "", $indenting = 0, $lineReturn = TRUE, $limitSubLevels = -1, $indentingIncrement = 1)
{
    global $charsToConvert;
    global $charsToConvertInto;
    global $action;

    $lineReturn = TRUE;

    $ind = '';
    $out = '';

    if( $limitSubLevels >= 0 && $limitSubLevels == $indenting )
        return $ind;

    $ind = str_pad('', $indenting, ' ');

    $firstTag = $ind . '<' . $node->nodeName;

    if( get_class($node) != 'DOMDocument' )
        foreach( $node->attributes as $at )
        {
            if( $at->name == "error" || $at->name == "warning" || $at->name == "info" )
            {
                $string = " - " . $nodeName . " object: ";
                $string .= " '" . PH::boldText($node->getAttribute('name')) . "'";

                if( $action == "remove" )
                {
                    $string .= " - remove attribute: " . $at->name . " with value: ";
                }
                else
                {
                    $firstTag .= ' ' . $at->name . '="' . str_replace($charsToConvert, $charsToConvertInto, $at->value) . '"';
                }
                $string .= "'" . str_replace($charsToConvertInto, $charsToConvert, $at->value) . "'";
                PH::print_stdout( $string );

            }
            else
                $firstTag .= ' ' . $at->name . '="' . str_replace($charsToConvert, $charsToConvertInto, $at->value) . '"';
        }

    //$firsttag .= '>';

    $c = 0;
    $wroteChildren = FALSE;

    $tmpout = '';

    if( DH::firstChildElement($node) !== FALSE )
    {
        foreach( $node->childNodes as $n )
        {
            if( $n->nodeType != 1 ) continue;

            if( $indenting != -1 )
                $tmpout .= dom_to_xml_removeATT($n, $node->nodeName, $indenting + $indentingIncrement, $lineReturn, $limitSubLevels, $indentingIncrement);
            else
                $tmpout .= dom_to_xml_removeATT($n, $node->nodeName, -1, $lineReturn, $limitSubLevels);
            $wroteChildren = TRUE;
        }
    }


    if( $wroteChildren == FALSE )
    {
        if( DH::firstChildElement($node) !== FALSE || $node->textContent === null || strlen($node->textContent) < 1 )
        {
            $out .= $firstTag . "/>";
            if( $lineReturn )
                $out .= "\n";
        }
        else
        {
            $out .= $firstTag . '>' . str_replace($charsToConvert, $charsToConvertInto, $node->nodeValue) . '</' . $node->nodeName . ">";
            if( $lineReturn )
                $out .= "\n";
        }
    }
    else
    {
        $out .= $firstTag . ">";
        if( $lineReturn )
            $out .= "\n";

        $out .= $tmpout . $ind . '</' . $node->nodeName . ">";
        if( $lineReturn )
            $out .= "\n";
    }

    return $out;
}

$charsToConvert = array('&', '>', '<', '"');
$charsToConvertInto = array('&amp;', '&gt;', '&lt;', '&quot;');

/*
#$searchNode = $xmlDoc->getElementsByTagName( "entry" );
$searchNode1 =$xmlDoc->getElementsByTagName("*");

$att_finder = array( 'error', 'warning', 'info' );

foreach( $searchNode1 as $searchNode )
{
    foreach( $att_finder as $att )
    {
        $first = true;
        #if( $action == "display" )
        #PH::print_stdout( "\n".PH::boldText( "DISPLAY '".$att."' atrribute:\n\n" );


        if( $searchNode->hasAttribute( $att) )
        {
            $error_att = $searchNode->getAttribute($att);
            $name_att = $searchNode->getAttribute('name');
            if( $name_att == "" )
            {
                $name_att = $searchNode->nodeName;
            }

            $parent_nodename =  $searchNode->parentNode->nodeName;

            if( $searchNode->nodeName == "entry" )
                PH::print_stdout( $padding_name."* ".PH::boldText( strtoupper($parent_nodename)) . " - ";
            else
            {
                $tmp_searchNode = $searchNode;
                while( $tmp_searchNode->nodeName != "entry" )
                {
                    $tmp_searchNode = $tmp_searchNode->parentNode;
                }
                $tmp_name_att = $tmp_searchNode->getAttribute('name');
                $tmp_node = $tmp_searchNode;
                $tmp_searchNode = $tmp_searchNode->parentNode;

                PH::print_stdout( $padding_name."* ".PH::boldText( strtoupper($tmp_searchNode->nodeName)) . " - ";
                PH::print_stdout( "'".$tmp_name_att."' - ";
                if( $action == "display" )
                {
                    #PH::print_stdout( "\n   ".$padding.$xmlDoc->saveXML( $tmp_node );

                    PH::print_stdout( "\n";
                    PH::print_stdout( $padding."  - ". strtoupper($parent_nodename)." - ";
                }
            }

            PH::print_stdout( "'" . $name_att . "'";

            $json = html_entity_decode( $error_att );


            if( $action == "display" )
            {
                PH::print_stdout( "\n".$padding.$padding.PH::boldText( "'".$att."' attribute: " );
                PH::print_stdout( " - ";
                PH::print_stdout( '"' . $json . '"';

                //Todo: is the plain XML element needed
                #PH::print_stdout( "\n   " . $padding . $xmlDoc->saveXML($searchNode);
            }
            elseif( $action == "remove" )
            {
                PH::print_stdout( " (removed attribute: ".$att." ) \n";

                PH::print_stdout( $padding_name."      ".'"' . $json . '"'."\n";
                $searchNode->removeAttribute ( $att );
            }

            PH::print_stdout( "\n";
            $first = false;
        }
    }

}
*/
//$this->pan->
$pan = new PANConf();
$pan->load_from_domxml($xmlDoc);

$xml = &dom_to_xml_removeATT($pan->xmlroot);


$xmlDoc = new DOMDocument;
$xmlDoc->loadXML($xml);


// save our work !!!
if( isset($configOutput) )
{
    if( $configOutput != '/dev/null' )
    {
        $xmlDoc->save($configOutput);
    }
}

PH::print_stdout( "\n\n***********************************************" );
PH::print_stdout( "************ END - XML error attribute finder ****************" );