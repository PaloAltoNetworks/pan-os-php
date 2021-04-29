<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */

/**
 * Class PathableName
 * @property AppStore|AddressStore|ServiceStore|RuleStore|Rule|PanoramaConf|PANConf|DeviceGroup|VirtualSystem $owner
 * @property string $name
 */
trait PathableName
{
    /**
     *
     * @return String
     */
    public function toString()
    {
        if( isset($this->name) )
            if( isset($this->_alternativeName) && $this->_alternativeName != "" )
                $ret = get_class($this) . ':' . $this->name . " *" . $this->_alternativeName . "*";
            else
                $ret = get_class($this) . ':' . $this->name;
        else
            $ret = get_class($this);

        if( isset($this->owner) && $this->owner !== null )
            $ret = $this->owner->toString() . ' / ' . $ret;

        return $ret;
    }

    public function _PANC_shortName()
    {
        $str = '';

        $owner = $this;

        while( $owner !== null )
        {
            if( is_subclass_of($owner, 'ObjRuleContainer') ||
                get_class($owner) == 'DeviceGroup' || get_class($owner) == 'VirtualSystem' )
                $str = $owner->name() . $str;
            elseif( is_subclass_of($owner, 'Rule') )
            {
                $str = $owner->ruleNature() . ':' . $owner->name() . $str;
                $owner = $owner->owner;
            }
            else
            {
                if( method_exists($owner, 'name') )
                    $str = get_class($owner) . ':' . $owner->name() . $str;
                else
                    $str = get_class($owner) . $str;
            }

            $str = '/' . $str;

            if( !isset($owner->owner) )
                break;
            if( get_class($owner) == 'DeviceGroup' || get_class($owner) == 'VirtualSystem' )
                break;
            $owner = $owner->owner;
        }

        return $str;
    }

    public function getLocationString()
    {
        $obj = PH::findLocationObjectOrDie($this);
        return PH::getLocationString($obj);
    }
}
