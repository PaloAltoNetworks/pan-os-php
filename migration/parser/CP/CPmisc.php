<?php

trait CPmisc
{
    function jsonERROR()
    {
        switch (json_last_error())
        {
            case JSON_ERROR_NONE:
                echo ' - No errors';
                break;
            case JSON_ERROR_DEPTH:
                echo ' - Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                echo ' - Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                echo ' - Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                echo ' - Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                echo ' - Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                echo ' - Unknown error';
                break;
        }

        echo PHP_EOL;
    }

}




