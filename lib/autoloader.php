<?php

/**
 * ISC License
 *
  * Copyright (c) 2014-2016, Palo Alto Networks Inc.
 * Copyright (c) 2017-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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
    print "Checking: $className\n";

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