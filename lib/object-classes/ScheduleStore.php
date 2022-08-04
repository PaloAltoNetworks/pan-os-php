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
 * Class ScheduleStore
 * @property Schedule[] $o
 * @property VirtualSystem|DeviceGroup|PanoramaConf|PANConf|Container|DeviceCloud $owner
 * @method Schedule[] getAll()
 */
class ScheduleStore extends ObjStore
{
    /** @var null|ScheduleStore */
    public $parentCentralStore = null;

    public static $childn = 'Schedule';


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->scheduleStore;
        elseif( isset($owner->parentContainer) && $owner->parentContainer !== null )
        {
            $this->parentCentralStore = $owner->parentContainer->scheduleStore;
        }
        else
            $this->findParentCentralStore( 'scheduleStore' );

    }

    /**
     * @param $name
     * @param null $ref
     * @param bool $nested
     * @return null|Schedule
     */
    public function find($name, $ref = null, $nested = TRUE)
    {
        $f = $this->findByName($name, $ref, $nested);

        if( $f !== null )
            return $f;

        if( $nested && $this->parentCentralStore !== null )
            return $this->parentCentralStore->find($name, $ref, $nested);

        return null;
    }

    public function removeAllSchedules()
    {
        $this->removeAll();
        $this->rewriteXML();
    }

    /**
     * add a Schedule to this store. Use at your own risk.
     * @param Schedule $Obj
     * @param bool
     * @return bool
     */

    public function addSchedule( $Obj, $rewriteXML = TRUE)
    {
        $ret = $this->add($Obj);
        if( $ret && $rewriteXML )
        {
            if( $this->xmlroot === null )
                $this->xmlroot = DH::findFirstElementOrCreate('schedule', $this->owner->xmlroot);

            $this->xmlroot->appendChild($Obj->xmlroot);
        }
        return $ret;
    }


    /**
     * @param string $base
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
     */
    public function findAvailableScheduleName($base, $suffix, $startCount = '')
    {
        $maxl = 31;
        $basel = strlen($base);
        $suffixl = strlen($suffix);
        $inc = $startCount;
        $basePlusSuffixL = $basel + $suffixl;

        while( TRUE )
        {
            $incl = strlen(strval($inc));

            if( $basePlusSuffixL + $incl > $maxl )
            {
                $newname = substr($base, 0, $basel - $suffixl - $incl) . $suffix . $inc;
            }
            else
                $newname = $base . $suffix . $inc;

            if( $this->find($newname) === null )
                return $newname;

            if( $startCount == '' )
                $startCount = 0;
            $inc++;
        }
    }


    /**
     * return schedules in this store
     * @return Schedule[]
     */
    public function schedules()
    {
        return $this->o;
    }

    function createSchedule($name, $ref = null)
    {
        if( $this->find($name, null, FALSE) !== null )
            derr('Schedule named "' . $name . '" already exists, cannot create');

        if( $this->xmlroot === null )
        {
            if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
                $this->xmlroot = DH::findFirstElementOrCreate('schedule', $this->owner->xmlroot);
            else
                $this->xmlroot = DH::findFirstElementOrCreate('schedule', $this->owner->sharedroot);
        }

        $newSchedule = new Schedule($name, $this, TRUE);

        if( $ref !== null )
            $newSchedule->addReference($ref);

        $this->addSchedule($newSchedule);

        return $newSchedule;
    }

    function findOrCreate($name, $ref = null, $nested = TRUE)
    {
        $f = $this->find($name, $ref, $nested);

        if( $f !== null )
            return $f;

        return $this->createSchedule($name, $ref);
    }

    function API_createSchedule($name, $ref = null)
    {
        $newSchedule = $this->createSchedule($name, $ref);

        if( !$newSchedule->isTmp() )
        {
            $xpath = $this->getXPath();
            $con = findConnectorOrDie($this);
            $element = $newSchedule->getXmlText_inline();
            $con->sendSetRequest($xpath, $element);
        }

        return $newSchedule;
    }


    /**
     * @param Schedule $schedule
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeSchedule(Schedule $schedule)
    {
        $ret = $this->remove($schedule);

        if( $ret && !$schedule->isTmp() && $this->xmlroot !== null )
        {
            if( $this->count() > 0 )
                $this->xmlroot->removeChild($schedule->xmlroot);
            else
                DH::clearDomNodeChilds($this->xmlroot);
        }

        return $ret;
    }

    /**
     * @param Schedule $schedule
     * @return bool
     */
    public function API_removeSchedule(Schedule $schedule)
    {
        $xpath = null;

        if( !$schedule->isTmp() )
            $xpath = $schedule->getXPath();

        $ret = $this->removeSchedule($schedule);

        if( $ret && !$schedule->isTmp() )
        {
            $con = findConnectorOrDie($this);
            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
            $str = '/config/shared';
        else
            derr('unsupported');

        $str = $str . '/schedule';

        return $str;
    }


    private function &getBaseXPath()
    {
        if( $this->owner->isPanorama() || $this->owner->isFirewall() )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();


        return $str;
    }

    public function &getScheduleStoreXPath()
    {
        $path = $this->getBaseXPath() . '/schedule';
        return $path;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
                DH::findFirstElementOrCreate('schedule', $this->owner->xmlroot);
        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            if( !$o->isTmp() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
    }



    /**
     * @return Schedule[]
     */
    public function nestedPointOfView()
    {
        $current = $this;

        $objects = array();

        while( TRUE )
        {
            if( get_class( $current->owner ) == "PanoramaConf" )
                $location = "shared";
            else
                $location = $current->owner->name();

            foreach( $current->o as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    if( $tmp_ref_count == 0 )
                    {
                        //Todo: check if object value is same; if same to not add ref
                        if( $location != "shared" )
                            foreach( $o->refrules as $ref )
                                $tmp_o->addReference( $ref );
                    }
                }
            }

            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->scheduleStore;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->scheduleStore;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->scheduleStore;
            else
                break;
        }

        return $objects;
    }

    public function storeName()
    {
        return "scheduleStore";
    }

}


