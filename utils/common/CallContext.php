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

/** @ignore */
class CallContext
{
    public $arguments = array();
    public $rawArguments = array();

    /** @var  Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
    public $object;

    public $actionRef;

    public $isAPI = FALSE;

    /** @var  $baseObject PANConf|PanoramaConf */
    public $baseObject;

    /** @var  $subSystem VirtualSystem|PANConf|PanoramaConf|DeviceGroup */
    public $subSystem;

    /** @var  $ruletype array */
    public $ruletype;

    /** @var PanAPIConnector */
    public $connector = null;

    public $padding = '';

    public $nestedQueries;

    /** @var UTIL $util */
    public $util = null;

    public function __construct($actionProperties, $arguments, $nestedQueries = null, $util = null)
    {
        $this->util = $util;

        $this->actionRef = $actionProperties;
        $this->prepareArgumentsForAction($arguments);

        if( $nestedQueries === null )
            $this->nestedQueries = array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object Address|AddressGroup|Service|ServiceGroup|Rule
     */
    public function executeAction($object)
    {
        $this->object = $object;

        $name = $object->name();

        $tmp_txt = "   - object '" . PH::boldText($name) . "' passing through Action='{$this->actionRef['name']}'";

        PH::$JSON_TMP['sub']['object'][$name]['name'] = $name;
        PH::$JSON_TMP['sub']['object'][$name]['actions'][$this->actionRef['name']]['name'] = $this->actionRef['name'];

        if( count($this->arguments) != 0 )
        {
            $tmp_txt .= " Args: ";
            foreach( $this->arguments as $argName => $argValue )
            {
                $tmp_arg = "";
                if( is_bool($argValue) )
                    $tmp_arg = boolYesNo($argValue);
                elseif( is_array($argValue) )
                    $tmp_arg = PH::list_to_string($argValue, '|');
                else
                    $tmp_arg = $argValue;

                PH::$JSON_TMP['sub']['object'][$object->name()]['actions'][$this->actionRef['name']]['arg'][$argName] = $tmp_arg;
                $tmp_txt .= $argName . "=" . $tmp_arg . ", ";
            }
        }

        PH::print_stdout( $tmp_txt );

        $this->actionRef['MainFunction']($this);
    }

    public function hasGlobalInitAction()
    {
        return isset($this->actionRef['GlobalInitFunction']);
    }

    public function executeGlobalInitAction()
    {
        PH::print_stdout("   - action '{$this->actionRef['name']}' has tasks to process before start." );
        $this->actionRef['GlobalInitFunction']($this);
    }

    public function hasGlobalFinishAction()
    {
        return isset($this->actionRef['GlobalFinishFunction']);
    }

    public function executeGlobalFinishAction()
    {
        PH::print_stdout("   - action '{$this->actionRef['name']}' has tasks to process before shutdown." );
        $this->actionRef['GlobalFinishFunction']($this);
    }

    public function prepareArgumentsForAction($arguments)
    {
        $this->arguments = array();
        $this->rawArguments = array();

        if( strlen($arguments) != 0 && !isset($this->actionRef['args']) )
            $this->util->display_error_usage_exit("error while processing argument '{$this->actionRef['name']}' : arguments were provided while they are not supported by this action");

        if( !isset($this->actionRef['args']) || $this->actionRef['args'] === FALSE )
            return;

        $ex = explode(',', $arguments);

        if( count($ex) > count($this->actionRef['args']) )
            $this->util->display_error_usage_exit("error while processing argument '{$this->actionRef['name']}' : too many arguments provided");

        $count = -1;
        foreach( $this->actionRef['args'] as $argName => &$properties )
        {
            $count++;

            $argValue = null;
            if( isset($ex[$count]) )
                $argValue = $ex[$count];

            $this->rawArguments[$argName] = $argValue;

            if( (!isset($properties['default']) || $properties['default'] == '*nodefault*') && ($argValue === null || strlen($argValue)) == 0 )
                derr("action '{$this->actionRef['name']}' argument#{$count} '{$argName}' requires a value, it has no default one");

            if( $argValue !== null && strlen($argValue) > 0 )
            {
                if (ctype_space($argValue))
                {

                }
                else
                    $argValue = trim($argValue);
            }
            else
                $argValue = $properties['default'];

            if( $properties['type'] == 'string' )
            {
                if( isset($properties['choices']) )
                {
                    foreach( $properties['choices'] as $choice )
                    {
                        $tmpChoice[strtolower($choice)] = TRUE;
                    }
                    $argValue = strtolower($argValue);
                    if( !isset($tmpChoice[$argValue]) )
                        derr("unsupported value '{$argValue}' for action '{$this->actionRef['name']}' arg#{$count} '{$argName}'");
                }
            }
            elseif( $properties['type'] == 'pipeSeparatedList' )
            {
                $tmpArray = array();

                if( $argValue != $properties['default'] )
                {
                    if( isset($properties['choices']) )
                    {
                        $tmpChoices = array();
                        foreach( $properties['choices'] as $choice )
                        {
                            $tmpChoices[strtolower($choice)] = $choice;
                        }

                        $inputChoices = explode('|', $argValue);

                        foreach( $inputChoices as $inputValue )
                        {
                            $inputValue = strtolower(trim($inputValue));

                            if( !isset($tmpChoices[$inputValue]) )
                                derr("unsupported value '{$argValue}' for action '{$this->actionRef['name']}' arg#{$count} '{$argName}'. Available choices are:" . PH::list_to_string($properties['choices']));

                            $tmpArray[$tmpChoices[$inputValue]] = $tmpChoices[$inputValue];
                        }
                    }
                    else
                    {
                        $inputChoices = explode('|', $argValue);

                        foreach( $inputChoices as $inputValue )
                        {
                            $tmpArray[$inputValue] = $inputValue;
                        }
                    }
                }

                $argValue = &$tmpArray;
            }
            elseif( $properties['type'] == 'boolean' || $properties['type'] == 'bool' )
            {
                if( $argValue == '1' || strtolower($argValue) == 'true' || strtolower($argValue) == 'yes' )
                    $argValue = TRUE;
                elseif( $argValue == '0' || strtolower($argValue) == 'false' || strtolower($argValue) == 'no' )
                    $argValue = FALSE;
                else
                    derr("unsupported argument value '{$argValue}' which should of type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            elseif( $properties['type'] == 'integer' )
            {
                if( !is_integer($argValue) )
                    derr("unsupported argument value '{$argValue}' which should of type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            else
            {
                derr("unsupported argument type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            $this->arguments[$argName] = $argValue;
        }

    }

    public function toString()
    {
        $ret = '';

        $ret .= "Action:'{$this->actionRef['name']}'";

        if( count($this->arguments) != 0 )
        {
            $ret .= " / Args: ";
            foreach( $this->arguments as $argName => $argValue )
            {
                if( is_bool($argValue) )
                    $ret .= "$argName=" . boolYesNo($argValue) . ", ";
                if( is_array($argValue) )
                    $ret .= "$argName=" . PH::list_to_string($argValue) . ", ";
                else
                    $ret .= "$argName=$argValue, ";
            }
        }

        return $ret;
    }
}
