<?php

function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars,"",$str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}

function delete_directory($mainfolder)
{
    if( is_dir($mainfolder) )
        $dir_handle = opendir($mainfolder);
    if( !$dir_handle )
        return FALSE;

    while( $file = readdir($dir_handle) )
    {
        if( $file != "." && $file != ".." )
        {
            if( !is_dir($mainfolder . "/" . $file) )
            {
                #print "unlink: ".$dirname.'/'.$file."\n";
                unlink($mainfolder . "/" . $file);
            }

            else
                delete_directory($mainfolder . '/' . $file);
        }
    }
    closedir($dir_handle);
    #print "DEL folder: ".$dirname."\n";
    rmdir($mainfolder);
    return TRUE;
}