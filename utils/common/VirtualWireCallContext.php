<?php

class VirtualWireCallContext extends CallContext
{
    /** @var  VirtualWire */
    public $object;



    public static $commonActionFunctions = Array();
    public static $supportedActions = Array();

    static public function prepareSupportedActions()
    {
        $tmpArgs = Array();
        foreach( self::$supportedActions as &$arg )
        {
            $tmpArgs[strtolower($arg['name'])] = $arg;
        }
        ksort($tmpArgs);
        self::$supportedActions = $tmpArgs;
    }
}
require_once  "actions-virtualwire.php";
VirtualWireCallContext::prepareSupportedActions();