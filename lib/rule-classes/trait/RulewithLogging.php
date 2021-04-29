<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
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
            $con->sendDeleteRequest($this->getXPath() . '/log-setting');
        }
        else
        {
            $con->sendSetRequest($this->getXPath(), "<log-setting>$newLogSetting</log-setting>");
        }

        return TRUE;
    }



}