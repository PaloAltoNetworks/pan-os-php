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


trait XmlConvertible
{
    /** @var DOMElement|null $xmlroot */
    public $xmlroot = null;

    protected $warning;
    protected $error;
    protected $info;

    function &getXmlText_inline()
    {
        return DH::dom_to_xml($this->xmlroot, -1, FALSE);
    }

    /**
     * @param bool|true $indenting
     * @return string
     */
    function &getXmlText($indenting = TRUE)
    {

        if( $indenting )
            return DH::dom_to_xml($this->xmlroot, 0, TRUE);
        return DH::dom_to_xml($this->xmlroot, -1, TRUE);
    }

    /**
     * @return string
     */
    function &getChildXmlText_inline()
    {
        return DH::domlist_to_xml($this->xmlroot->childNodes, -1, FALSE);
    }

    public function API_sync()
    {
        $xpath = DH::elementToPanXPath($this->xmlroot);
        $con = findConnectorOrDie($this);

        if( $con->isAPI() )
            $con->sendEditRequest($xpath, $this->getXmlText_inline());
        elseif( $con->isSaseAPI() )
            $con->sendPUTRequest($this);
    }


    public function set_node_attribute($att_name, $message, $type_message = "", $subtype_message = "", $comment = "")
    {
        $tmp_att_array = array("error", "warning", "info");
        if( !in_array($att_name, $tmp_att_array) )
            derr($att_name . " message - for object: " . $this->name() . " can not be set");


        if( !isset($this->{$att_name}) )
        {
            $this->{$att_name} = array();
            $this->{$att_name}['tool'] = "pan-os-php";
            $this->{$att_name}['version'] = PH::frameworkVersion();
        }

        $this->{$att_name}[] = $message;

        $myJSON = json_encode($this->{$att_name});
        $a = htmlentities($myJSON);

        $this->xmlroot->setAttribute($att_name, $a);
    }


    /*
     * not working due to validation problems in PAN-OS
    #public function addExpeditionElement( $att_name, $message, $type_message, $subtype_message, $comment )
    public function set_node_attribute( $att_name, $message, $type_message = "", $subtype_message="", $comment="" )
    {
        $att_name = "expedition-".$att_name;

        $element = DH::findFirstElementOrCreate( $att_name, $this->xmlroot, $withText = null);
        $element->setAttribute( "app", "converter" );

        $converter_version = PH::frameworkVersion();
        $element->setAttribute( "version", $converter_version );

        $entry = DH::createElement( $element, 'item', $message );


        $entry->setAttribute( 'type', $type_message );
        $entry->setAttribute( 'subtype', $subtype_message );
        $entry->setAttribute( 'comment', $comment );

    }
    */

}

