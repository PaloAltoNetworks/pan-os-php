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


trait RuleWithSchedule
{
    protected $schedule = null;

    function schedule_loadFromXml()
    {
        $xml = DH::findFirstElement('schedule', $this->xmlroot);

        if( $xml !== FALSE )
        {
            $f = $this->owner->owner->scheduleStore->find($xml->textContent, $this);
            if( $f == null && is_object($this->owner->owner->scheduleStore->parentCentralStore))
                $f = $this->owner->owner->scheduleStore->parentCentralStore->find($xml->textContent, $this);
            if( $f != null )
            {
                $f->addReference( $this );
                $this->schedule = $f;
            }
        }
    }

    public function referencedObjectRenamed($h, $oldname = "")
    {
        if( $this->schedule === $h )
        {
            $this->rewriteSchedule_XML();
            return;
        }
    }

    public function rewriteSchedule_XML()
    {
        if( $this->schedule === null )
        {
            $tmpRoot = DH::findFirstElement('schedule', $this->xmlroot);

            if( $tmpRoot === FALSE )
                return TRUE;

            $this->xmlroot->removeChild($tmpRoot);
        }
        else
        {
            $tmpRoot = DH::findFirstElementOrCreate('schedule', $this->xmlroot);
            DH::setDomNodeText($tmpRoot, $this->schedule->name());
        }
    }

    /**
     * return schedule txt if rule has scheduler set
     * @return null
     */
    public function schedule()
    {
        return $this->schedule;
    }

    /**
     * @param null|string $newSchedule empty or null description will erase existing one
     * @return bool false if no update was made to description (already had same value)
     */
    function setSchedule($newSchedule = null)
    {
        if( is_object( $newSchedule ) )
            $newSchedule = $newSchedule->name();

        if( $newSchedule === null || strlen($newSchedule) < 1 )
        {
            if( $this->schedule === null )
                return FALSE;

            if( is_object($this->schedule) )
                $this->schedule->removeReference($this);

            $this->schedule = null;
        }
        else
        {
            $newSchedule = utf8_encode($newSchedule);
            if( is_object( $this->schedule ) && $this->schedule->name() == $newSchedule )
                return FALSE;

            if( is_object($this->schedule) )
                $this->schedule->removeReference($this);

            $f = $this->owner->owner->scheduleStore->findOrCreate($newSchedule, $this);
            if( $f != null )
                $f->addReference( $this );

            $this->schedule = $f;
        }

        $this->rewriteSchedule_XML();



        return TRUE;
    }

    /**
     * @return bool true if value was changed
     */
    public function API_setSchedule($newSchedule)
    {
        $ret = $this->setSchedule($newSchedule);
        if( $ret )
        {
            $xpath = $this->getXPath() . '/schedule';
            $con = findConnectorOrDie($this);

            if( !is_object( $this->schedule )  )
                $con->sendDeleteRequest($xpath);
            else
                $con->sendSetRequest($this->getXPath(), '<schedule>' . htmlspecialchars($this->schedule->name()) . '</schedule>');

        }

        return $ret;
    }

    /**
     * @return bool false if no update was made to description (already had same value)
     */
    function removeSchedule()
    {
        if( $this->schedule === null )
            return TRUE;

        $this->schedule = null;
        $tmpRoot = DH::findFirstElement('schedule', $this->xmlroot);

        if( $tmpRoot === FALSE )
            return TRUE;

        $this->xmlroot->removeChild($tmpRoot);


        return TRUE;
    }

    /**
     * @param string $newSchedule
     * @return bool true if value was changed
     */
    public function API_removeSchedule()
    {
        $ret = $this->removeSchedule();
        if( $ret )
        {
            $xpath = $this->getXPath() . '/schedule';
            $con = findConnectorOrDie($this);

            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }
}
