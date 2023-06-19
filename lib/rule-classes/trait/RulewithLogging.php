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

/**
 *
 * @property DOMElement $xmlroot
 */
trait RulewithLogging
{
    protected $logSetting = FALSE;

    /**
     * return log forwarding profile if any
     * @return string
     */
    public function logSetting()
    {
        return $this->logSetting;
    }


    protected function _readLogSettingFromXml()
    {
        $xml = $this->xmlroot;


        foreach( $xml->childNodes as $node )
        {

            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            /** @var DOMElement $node */
            if( $node->nodeName == 'log-setting' )
            {
                $this->logSetting = $node->textContent;
            }
        }
    }


    /**
     * @param string $newLogSetting
     * @return bool true if value changed
     */
    public function setLogSetting($newLogSetting)
    {
        if( $newLogSetting === null || strlen($newLogSetting) < 1 )
        {
            if( $this->logSetting == FALSE )
                return FALSE;

            $this->logSetting = FALSE;

            $logXmlRoot = DH::findFirstElement('log-setting', $this->xmlroot);

            if( $logXmlRoot !== FALSE )
                $this->xmlroot->removeChild($logXmlRoot);

            return TRUE;
        }

        if( $this->logSetting == $newLogSetting )
            return FALSE;

        $this->logSetting = $newLogSetting;
        DH::createOrResetElement($this->xmlroot, 'log-setting', $newLogSetting);

        return TRUE;
    }


    public function API_setLogSetting($newLogSetting)
    {
        if( !$this->setLogSetting($newLogSetting) )
            return FALSE;

        $con = findConnectorOrDie($this);

        if( $this->logSetting === FALSE )
        {
            if( $con->isAPI() )
                $con->sendDeleteRequest($this->getXPath() . '/log-setting');
        }
        else
        {
            if( $con->isAPI() )
                $con->sendSetRequest($this->getXPath(), "<log-setting>$newLogSetting</log-setting>");
        }

        return TRUE;
    }

    public function logSettingHash()
    {
        $string = "";
        if( $this->logSetting !== False )
            $string = $this->logSetting;

        return md5( $string );
    }

}