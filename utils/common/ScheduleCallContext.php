<?php

class ScheduleCallContext extends CallContext
{
    /** @var  Schedule */
    public $object;


    public static $commonActionFunctions = array();
    public static $supportedActions = array();

    static public function prepareSupportedActions()
    {
        $tmpArgs = array();
        foreach( self::$supportedActions as &$arg )
        {
            $tmpArgs[strtolower($arg['name'])] = $arg;
        }
        ksort($tmpArgs);
        self::$supportedActions = $tmpArgs;
    }
}