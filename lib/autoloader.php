<?php

/* AUTOLOADING METHODS */
/*
 * Scans for folders recursively for the files within a defined folder
 */

function getDirContents($dir, &$results = array())
{
    $files = scandir($dir);

    foreach( $files as $key => $value )
    {
        $path = realpath($dir . DIRECTORY_SEPARATOR . $value);
        if( !is_dir($path) )
        {
        }
        else if( $value != "." && $value != ".." )
        {
            getDirContents($path, $results);
            $results[] = $path . '/';
        }
    }

    return $results;
}


/*
 * Looks and loads via a require_once the desired Class given its name
 */

function myAutoloader($className)
{
    echo "Checking: $className\n";

    //not working as DIR is using by the actual CLI dir, and not using the expedition installation folder;
    #$classPaths = array( './',); //'lib/', './parser/', './utils/');
    $classPaths = array(__DIR__ . "/../",);
    $sources = array();
    foreach( $classPaths as $classPath )
    {
        $sources = getDirContents($classPath);
        $sources[] = $classPath;
    }

    #print_r($sources);

    foreach( $sources as $source )
    {
        if( file_exists($source . str_replace("\\", "/", $className) . '.php') )
        {
            require_once $source . str_replace("\\", "/", $className) . '.php';
        }
    }

}