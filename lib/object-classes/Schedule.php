<?php

/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

class Schedule
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var TagStore|null */
    public $owner = null;

//Todo:
//- read schedule type
//- read members
//- set schedule type
//- add member
/*
          <schedule>
            <entry name="test_daily_00-01">
              <schedule-type>
                <recurring>
                  <daily>
                    <member>00:00-00:01</member>
                    <member>01:00-01:01</member>
                  </daily>
                </recurring>
              </schedule-type>
            </entry>
            <entry name="test-weekly">
              <schedule-type>
                <recurring>
                  <weekly>
                    <sunday>
                      <member>00:00-00:01</member>
                    </sunday>
                    <monday>
                      <member>01:00-01:01</member>
                    </monday>
                  </weekly>
                </recurring>
              </schedule-type>
            </entry>
            <entry name="test-non">
              <schedule-type>
                <non-recurring>
                  <member>2021/01/01@00:00-2021/12/31@23:59</member>
                  <member>2021/01/02@00:00-2021/01/02@23:59</member>
                </non-recurring>
              </schedule-type>
            </entry>
          </schedule>
 */

    /**
     * @param string $name
     * @param ScheduleStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            if( $owner->owner->version < 60 )
                derr('tag stores were introduced in v6.0');
            else
                $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElement('entry', $doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
        }

        $this->owner = $owner;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();
        $c->sendRenameRequest($xpath, $newName);
        $this->setName($newName);
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getTagStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function isTmp()
    {
        if( $this->xmlroot === null )
            return TRUE;
        return FALSE;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("schedule name not found\n", $xml);


        if( strlen($this->name) < 1 )
            derr("schedule name '" . $this->name . "' is not valid.", $xml);
    }



    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isSchedule()
    {
        return TRUE;
    }

    /**
     * @param $otherObject Schedule
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isSchedule() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(Schedule $otherObject)
    {
        if( $this->isTmp() && !$otherObject->isTmp() )
            return FALSE;

        if( $otherObject->isTmp() && !$this->isTmp() )
            return FALSE;


        return TRUE;
    }
}

