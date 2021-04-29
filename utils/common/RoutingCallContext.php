<?php

class RoutingCallContext extends CallContext
{
    /** @var  Routing */
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
require_once  "actions-routing.php";
RoutingCallContext::prepareSupportedActions();

