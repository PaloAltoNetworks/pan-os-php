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
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

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

        if( $tmp !== false )
        {
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

                                $startEnd = explode("-", $childNode->textContent);
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

                                foreach( $childNode->childNodes as $member )
                                {
                                    if( $member->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $startEnd = explode("-", $member->textContent);
                                    $tmp = array();
                                    $tmp['start'] = $startEnd[0];
                                    $tmp['end'] = $startEnd[1];

                                    $this->recurring_array['weekly'][$childNode->nodeName][] = $tmp;
                                }

                            }
                        }
                        else
                            mwarning("recurringType: " . $node2->nodeName . " not supported");
                    }
                }
                elseif( $node->nodeName == "non-recurring" )
                {
                    $this->recurring_type = "non-recurring";

                    foreach( $node->childNodes as $childNode )
                    {
                        if( $childNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $startEnd = explode("-", $childNode->textContent);
                        $tmp = array();
                        $tmp['start'] = $startEnd[0];
                        $tmp['end'] = $startEnd[1];

                        $this->recurring_array['non-recurring'][] = $tmp;
                    }
                }
                else
                {
                    mwarning("recurringType: " . $node->nodeName . " not supported");
                }
            }
        }
    }

    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function setRecurringDaily($newValue, $rewriteXml = TRUE)
    {
        if( !is_string($newValue) )
            derr('value can be text only');

        //validation needed
        #if( $newValue == $this->value )
        #    return FALSE;

        $startEnd = explode("-", $newValue);
        $tmp = array();
        $tmp['start'] = $startEnd[0];
        $tmp['end'] = $startEnd[1];

        $this->recurring_array['daily'][] = $tmp;

        if( $rewriteXml )
        {
            $valueRoot = DH::findFirstElementOrCreate("schedule-type", $this->xmlroot);
            $valueRoot = DH::findFirstElementOrCreate("recurring", $valueRoot);
            $valueRoot = DH::findFirstElementOrCreate("daily", $valueRoot);

            DH::clearDomNodeChilds($valueRoot);

            foreach( $this->recurring_array['daily'] as $entry )
            {
                DH::createElement($valueRoot, 'member', $entry['start']."-".$entry['end']);
            }
        }

        return TRUE;
    }

    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function setRecurringWeekly( $day, $newValue, $rewriteXml = TRUE)
    {
        if( !is_string($newValue) )
            derr('value can be text only');

        //validation needed
        #if( $newValue == $this->value )
        #    return FALSE;

        $startEnd = explode("-", $newValue);
        $tmp = array();
        $tmp['start'] = $startEnd[0];
        $tmp['end'] = $startEnd[1];

        $this->recurring_array['weekly'][$day][] = $tmp;

        if( $rewriteXml )
        {
            $valueRoot = DH::findFirstElementOrCreate("schedule-type", $this->xmlroot);
            $valueRoot = DH::findFirstElementOrCreate("recurring", $valueRoot);
            $valueRoot = DH::findFirstElementOrCreate("weekly", $valueRoot);
            $valueRoot = DH::findFirstElementOrCreate($day, $valueRoot);

            DH::clearDomNodeChilds($valueRoot);

            foreach( $this->recurring_array['weekly'][$day] as $entry )
            {
                DH::createElement($valueRoot, 'member', $entry['start']."-".$entry['end']);
            }
        }

        return TRUE;
    }


    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function setNonRecurring($newValue, $rewriteXml = TRUE)
    {
        if( !is_string($newValue) )
            derr('value can be text only');

        //validation needed
        #if( $newValue == $this->value )
        #    return FALSE;

        $startEnd = explode("-", $newValue);
        $tmp = array();
        $tmp['start'] = $startEnd[0];
        $tmp['end'] = $startEnd[1];

        $this->recurring_array['non-recurring'][] = $tmp;

        if( $rewriteXml )
        {
            $valueRoot = DH::findFirstElementOrCreate("schedule-type", $this->xmlroot);
            $valueRoot = DH::findFirstElementOrCreate("non-recurring", $valueRoot);

            DH::clearDomNodeChilds($valueRoot);
            
            foreach( $this->recurring_array['non-recurring'] as $entry )
            {
                DH::createElement($valueRoot, 'member', $entry['start']."-".$entry['end']);
            }
        }

        return TRUE;
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

    public function isExpired( $futuredate = 0, $operator = "<" )
    {
        if( $this->recurring_type != 'non-recurring' )
            return false;

        $d_actual = time();
        if( $futuredate !== 0 )
        {
            $d = $d_actual + ($futuredate)*24*3600;
        }
        $expired = false;
        foreach( $this->recurring_array['non-recurring'] as $member )
        {
            $d2 = DateTime::createFromFormat('Y/m/d@H:i', $member['end']);
            $timestamp = $d2->getTimestamp();

            if( $operator === "<" )
                $operator_string = "(".$timestamp." ".$operator." ".$d.") && (".$timestamp." > ".$d_actual.")";
            else
                $operator_string = $timestamp." ".$operator." ".$d;

            if( eval("return $operator_string;" ) )
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

