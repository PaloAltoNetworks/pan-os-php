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

    protected $recurring_type = null;
    //possible recurring setting daily/weekly/non-recurring

    //daily/non-recurring could have multiple <member> XML tags
    //weekly could have different day entried
    protected $recurring_array = array();

//Todo:
//newSchedule => ScheduleStore
//- set schedule type
//- add member

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
        $str = $this->owner->getScheduleStoreXPath() . "/entry[@name='" . $this->name . "']";

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

        $tmp = DH::findFirstElement('schedule-type', $xml);


        foreach( $tmp->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->nodeName == "recurring" )
            {
                foreach( $node->childNodes as $node2 )
                {
                    if( $node2->nodeType != XML_ELEMENT_NODE )
                        continue;



                    if( $node2->nodeName == "daily" )
                    {
                        $this->recurring_type = "daily";

                        foreach( $node2->childNodes as $childNode )
                        {
                            if( $childNode->nodeType != XML_ELEMENT_NODE )
                                continue;

                            $startEnd = explode( "-", $childNode->textContent );
                            $tmp = array();
                            $tmp['start'] = $startEnd[0];
                            $tmp['end'] = $startEnd[1];

                            $this->recurring_array['daily'][] = $tmp;
                        }
                    }
                    elseif( $node2->nodeName == "weekly" )
                    {
                        $this->recurring_type = "weekly";

                        foreach( $node2->childNodes as $childNode )
                        {
                            if( $childNode->nodeType != XML_ELEMENT_NODE )
                                continue;

                            /*
                            if( $childNode != null )
                            {
                                $newdoc = new DOMDocument;
                                $node = $newdoc->importNode($childNode, true);
                                $newdoc->appendChild($node);
                                print $newdoc->saveXML();
                            }*/

                            foreach( $childNode->childNodes as $member )
                            {
                                if( $member->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $startEnd = explode( "-", $member->textContent );
                                $tmp = array();
                                $tmp['start'] = $startEnd[0];
                                $tmp['end'] = $startEnd[1];

                                $this->recurring_array['weekly'][$childNode->nodeName][] = $tmp;
                            }

                        }
                    }
                    else
                        mwarning( "recurringType: ".$node2->nodeName." not supported" );
                }
            }
            elseif( $node->nodeName == "non-recurring" )
            {
                $this->recurring_type = "non-recurring";

                foreach( $node->childNodes as $childNode )
                {
                    if( $childNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $startEnd = explode( "-", $childNode->textContent );
                    $tmp = array();
                    $tmp['start'] = $startEnd[0];
                    $tmp['end'] = $startEnd[1];

                    $this->recurring_array['non-recurring'][] = $tmp;
                }
            }
            else
            {
                mwarning( "recurringType: ".$node->nodeName." not supported" );
            }
        }
    }



    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isSchedule()
    {
        return TRUE;
    }


    public function getRecurring()
    {
        return $this->recurring_array;
    }

    public function getRecurringType()
    {
        return $this->recurring_type;
    }

    public function isExpired( )
    {
        if( $this->recurring_type != 'non-recurring' )
            return false;

        $d = time();
        $expired = false;
        foreach( $this->recurring_array['non-recurring'] as $member )
        {
            $d2 = DateTime::createFromFormat('Y/m/d@H:i', $member['end']);
            $timestamp = $d2->getTimestamp();

            if( $timestamp < $d )
                $expired = true;
            else
                $expired = false;
        }

        return $expired;
    }

    function validateDate($date, $format = 'Y-m-d@H:i')
    {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) == $date;
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

