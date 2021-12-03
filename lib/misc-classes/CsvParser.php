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

class CsvParser
{
    /**
     * @param string $fileName
     * @param string $errorMessage
     * @param bool $hasHeaders
     * @param bool $skipEmptyLines
     * @param null|string[] $customHeaders
     * @return false|string[]
     */
    static public function &parseFile($fileName, &$errorMessage, $hasHeaders = TRUE, $skipEmptyLines = FALSE, $customHeaders = null)
    {
        $ret = FALSE;

        if( !file_exists($fileName) )
        {
            $errorMessage = "file '$fileName' doesn't exists";
            return $ret;
        }

        $content = file_get_contents($fileName);

        if( $content === FALSE )
        {
            $errorMessage = "file '$fileName' could not be open (permission problem?)";
            return $ret;
        }

        $ret = CsvParser::parseString($content, $errorMessage, $hasHeaders, $skipEmptyLines, $customHeaders);

        return $ret;
    }

    /**
     * @param string $content
     * @param string $errorMessage
     * @param bool $hasHeaders
     * @param bool $skipEmptyLines
     * @param null|string[] $customHeaders
     * @return false|string[]
     */
    static public function &parseString($content, &$errorMessage, $hasHeaders = TRUE, $skipEmptyLines = FALSE, $customHeaders = null)
    {
        $ret = FALSE;

        $content = explode("\n", $content);

        if( $hasHeaders )
        {
            if( $customHeaders === null )
            {
                // first line is headers, let's get it.
                if( count($content) < 1 )
                {
                    $errorMessage = 'file is empty, no header to parse';
                    return $ret;
                }

                $headerLine = trim($content[0]);
                unset($content[0]);

                if( strlen($headerLine) < 1 )
                {
                    $errorMessage = 'header is empty line';
                    return $ret;
                }

                $headers = explode(',', $headerLine);
                if( count($headers) < 1 )
                {
                    $errorMessage = 'file is empty or header malformed';
                    return $ret;
                }

                $uniqueCheck = array();

                foreach( $headers as $key => &$h )
                {
                    if( strlen($h) < 1 )
                    {
                        if( $key == 0 )
                        {
                            $h = "#";
                        }
                        else{
                            $errorMessage = 'one of the header column name is empty';
                            return $ret;
                        }

                    }
                    if( isset($uniqueCheck[$h]) )
                    {
                        $errorMessage = "two or more headers columns have same name '$h'";
                        return $ret;
                    }

                    $uniqueCheck[$h] = TRUE;
                }

            }
            else
            {
                if( !is_array($customHeaders) )
                {
                    $errorMessage = "two or more headers columns have same name";
                    return $ret;
                }

                $headers = array();

                foreach( $customHeaders as &$h )
                {
                    if( strlen($h) < 1 )
                    {
                        $errorMessage = 'one of the header column name is empty';
                        return $ret;
                    }

                    $headers[] = $h;
                }
            }

            $response = array('header' => &$headers);
        }

        $records = array();
        $response['records'] = &$records;

        $countLines = -1;
        foreach( $content as &$line )
        {
            $countLines++;
            $line = trim($line);
            if( isset($csvRecord) )
                unset($csvRecord);

            $csvRecord = array();
            $records[] = &$csvRecord;

            if( strlen($line) < 1 )
            {
                if( $skipEmptyLines == TRUE )
                    continue;

                $errorMessage = "line #{$countLines} is empty";
                return $ret;
            }

            $explodedLine = str_getcsv($line);


            for( $i = 0; $i < count($explodedLine); $i++ )
            {
                if( isset($headers[$i]) )
                {
                    $csvRecord[$headers[$i]] = $explodedLine[$i];
                }
                else
                {
                    $csvRecord['col#' . $i] = $explodedLine[$i];
                }
            }

        }

        $response['count'] = $countLines + 1;

        return $records;
    }
} 